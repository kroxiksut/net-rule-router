//! Application and device routes (the GUI's app-group dialog and its virtual
//! machines screen): the programs of known groups found on this computer —
//! hypervisors, emulators, torrent and peer-to-peer clients — and the
//! hypervisors' machines, each with the route the rules give it now and a way
//! to send it over the main or the additional route.
//!
//! What is found comes from the platform's discovery and inventory ports, run
//! as the user and only when this screen opens or on `r`. A choice is an
//! ordinary edit of the Rules screen's working copy (the same plan the GUI
//! carries out, `nrr_client_logic::app_routes`): nothing reaches the service
//! until the list is reviewed and applied.

mod keys;
mod machines;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use crossterm::event::{KeyCode, KeyEvent};
use nrr_client_logic::app_routes::{group_route, AppRule};
use nrr_ipc_client::IpcClient;
use nrr_platform_api::{
    AppDiscoverySource, AppGroupKind, DiscoveredApp, Hypervisor, HypervisorInventory,
};
use nrr_shared::display_text::display_text;
use nrr_shared::rules_json::FREE_MAX_RULES;

use super::rules::app_routes::{self, Assigned};
use super::{rules, Screen, ScreenId};
use crate::backend::Reply;
use crate::i18n::{Key, Texts};
use crate::state::{AppState, Focus};
use crate::view::{Panel, ScreenView, Segment, ViewLine};

/// More entries than this are not listed: a scan reports what a dictionary
/// matched, and nothing on this machine should be able to fill the screen.
const MAX_ENTRIES: usize = 200;
/// The longest program name taken for a rule.
const MAX_PROGRAM_BYTES: usize = 260;
/// Machine names shown per hypervisor before "+N".
const MACHINES_SHOWN: usize = 3;
/// Lines one entry takes in the list.
const ENTRY_LINES: usize = 2;

/// The group slugs, for the comment a new rule carries.
const KINDS: [&str; 7] = [
    "hypervisor",
    "kernel-virtual-net",
    "android-emulator",
    "console-emulator",
    "bittorrent",
    "p2p-file-sharing",
    "crypto-node",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Badge {
    None,
    Running,
    Installed,
    Feature,
}

/// One row: a group's program, or a hypervisor with its machines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The group, by the slug of its `app-groups.group.*` text.
    slug: &'static str,
    hypervisor: Option<Hypervisor>,
    /// What the program is called, as discovery gave it.
    name: String,
    path: Option<String>,
    badge: Badge,
    machines: Vec<String>,
    /// The program names the rules say the route for.
    programs: Vec<String>,
    /// A route can be given: some application rule reaches its traffic.
    assignable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Note {
    NoItem(usize),
    NotAssignable(usize),
    Locked,
    NoRules,
    Updated(usize),
    Unchanged,
    Limit,
    NotHypervisor(usize),
    NoTarget(usize),
    /// Line mode: the item printed under that number has left the list.
    Gone(usize),
    PinBusy,
    PinUnchanged,
    PinNoAdditional,
}

#[derive(Debug, Default)]
pub struct AppGroups {
    scanning: bool,
    scanned: bool,
    /// A newer scan supersedes an older one still running.
    generation: u64,
    entries: Vec<Entry>,
    selected: usize,
    note: Option<Note>,
    /// The note a new rule carries, by group slug, in the reader's language.
    comments: BTreeMap<String, String>,
    /// What the last scan read of the hypervisors, pins settled.
    inventory: Vec<HypervisorInventory>,
    /// The hypervisor whose machines are open in place of the list.
    machines: Option<Hypervisor>,
    /// The adapter under the cursor, among those a pin can be given.
    pin_selected: usize,
    /// The adapter whose pin the hypervisor is changing now.
    pinning: Option<machines::PinKey>,
    pin_failure: Option<machines::PinFailure>,
    /// Line mode: the list and the pinnable adapters as last printed, so a
    /// typed number names what was printed under it.
    printed: Vec<String>,
    printed_pins: Vec<String>,
}

/// The texts were loaded or changed language.
pub fn on_texts(app: &mut AppState, texts: &Texts) {
    app.app_groups.comments = KINDS
        .iter()
        .map(|slug| {
            (
                (*slug).to_owned(),
                texts.dynamic(&format!("app-groups.group.{slug}"), slug),
            )
        })
        .collect();
}

fn kind_slug(kind: AppGroupKind) -> &'static str {
    match kind {
        AppGroupKind::Hypervisor => "hypervisor",
        AppGroupKind::KernelVirtualNet => "kernel-virtual-net",
        AppGroupKind::AndroidEmulator => "android-emulator",
        AppGroupKind::ConsoleEmulator => "console-emulator",
        AppGroupKind::BitTorrent => "bittorrent",
        AppGroupKind::P2pFileSharing => "p2p-file-sharing",
        AppGroupKind::CryptoNode => "crypto-node",
    }
}

/// The GUI's order: the virtualization tab, then the peer-to-peer one;
/// the machines of a hypervisor lead.
fn rank(slug: &str) -> usize {
    KINDS.iter().position(|k| *k == slug).unwrap_or(KINDS.len())
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// A name that can stand in a rule: bounded and free of control characters,
/// since discovery reports what other programs named themselves.
fn usable(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_PROGRAM_BYTES && !name.chars().any(char::is_control)
}

fn entry_of_app(app: &DiscoveredApp) -> Option<Entry> {
    let path = app.exe_path.as_deref().filter(|p| !p.is_empty());
    let program = path.map_or(app.display_name.as_str(), basename);
    let assignable = app.kind.is_route_assignable();
    if !usable(program) {
        return None;
    }
    Some(Entry {
        slug: kind_slug(app.kind),
        hypervisor: None,
        name: app.display_name.clone(),
        path: path.map(str::to_owned),
        badge: if app.running {
            Badge::Running
        } else {
            match app.source {
                AppDiscoverySource::InstalledProgram => Badge::Installed,
                AppDiscoverySource::SystemFeature => Badge::Feature,
                AppDiscoverySource::RunningProcess => Badge::None,
            }
        },
        machines: Vec::new(),
        programs: vec![program.to_owned()],
        assignable,
    })
}

fn entry_of_hypervisor(inventory: &HypervisorInventory) -> Entry {
    let programs: Vec<String> = inventory
        .traffic_processes
        .iter()
        .filter(|p| usable(p))
        .cloned()
        .collect();
    Entry {
        slug: "hypervisor",
        hypervisor: Some(inventory.hypervisor),
        name: String::new(),
        path: None,
        badge: Badge::None,
        machines: inventory.machines.iter().map(|m| m.name.clone()).collect(),
        assignable: !programs.is_empty(),
        programs,
    }
}

/// What a scan found, in the order the screen lists it.
fn entries_of(apps: &[DiscoveredApp], inventory: &[HypervisorInventory]) -> Vec<Entry> {
    let mut entries: Vec<Entry> = inventory.iter().map(entry_of_hypervisor).collect();
    entries.extend(apps.iter().filter_map(entry_of_app));
    // Stable: discovery's order holds inside a group, machines lead.
    entries.sort_by_key(|e| (e.hypervisor.is_none(), rank(e.slug)));
    entries.truncate(MAX_ENTRIES);
    entries
}

/// Look again; one scan at a time owns the list.
pub fn scan(app: &mut AppState) {
    let state = &mut app.app_groups;
    state.scanning = true;
    state.generation += 1;
    let generation = state.generation;
    app.outbox.push(Box::new(move |_client: &dyn IpcClient| {
        let apps = crate::platform::app_group_discovery().discover_app_groups();
        let inventory = crate::platform::vm_inventory().inventory();
        Reply::new(move |app| scanned(app, generation, &apps, &inventory))
    }));
}

fn scanned(
    app: &mut AppState,
    generation: u64,
    apps: &[DiscoveredApp],
    inventory: &[HypervisorInventory],
) {
    let state = &mut app.app_groups;
    if state.generation != generation {
        return;
    }
    let mut inventory = inventory.to_vec();
    machines::classify(app, &mut inventory);
    let state = &mut app.app_groups;
    state.scanning = false;
    state.scanned = true;
    state.entries = entries_of(apps, &inventory);
    state.selected = state.selected.min(state.entries.len().saturating_sub(1));
    if state
        .machines
        .is_some_and(|h| !inventory.iter().any(|i| i.hypervisor == h))
    {
        state.machines = None;
    }
    state.inventory = inventory;
}

/// The route the rules on screen give the entry: what its programs share,
/// `mixed` when they differ.
fn current_route(app: &AppState, entry: &Entry) -> String {
    let slugs: Vec<(&str, &str, bool)> = app
        .rules
        .table
        .rules()
        .filter(|rule| rule.rule_type == nrr_client_logic::rules_table::RuleType::Application)
        .map(|rule| {
            (
                rule.match_value.as_str(),
                rule.target_route.as_str(),
                rule.enabled,
            )
        })
        .collect();
    let rules: Vec<AppRule<'_>> = slugs
        .iter()
        .map(|&(value, route, enabled)| AppRule {
            value,
            route,
            enabled,
        })
        .collect();
    let programs: Vec<&str> = entry.programs.iter().map(String::as_str).collect();
    group_route(&rules, &programs).to_owned()
}

fn has_rules(app: &AppState) -> bool {
    app.rules.table.is_loaded() || !app.rules.table.rows.is_empty()
}

/// Send entry `index` over `route` (`primary` or `secondary`).
fn choose(app: &mut AppState, index: usize, route: &'static str) {
    let Some(entry) = app.app_groups.entries.get(index).cloned() else {
        app.app_groups.note = Some(Note::NoItem(index + 1));
        return;
    };
    app.app_groups.selected = index;
    app.app_groups.note = Some(if !entry.assignable {
        Note::NotAssignable(index + 1)
    } else if rules::edits_locked(app) {
        Note::Locked
    } else if !has_rules(app) {
        Note::NoRules
    } else {
        let comment = app
            .app_groups
            .comments
            .get(entry.slug)
            .cloned()
            .unwrap_or_default();
        match app_routes::assign(app, &entry.programs, route, &comment) {
            Assigned::Limit => Note::Limit,
            Assigned::Changed => Note::Updated(entry.programs.len()),
            Assigned::Unchanged => Note::Unchanged,
        }
    });
}

/// Space: the other route than the one it has now.
fn switch(app: &mut AppState, index: usize) {
    let Some(entry) = app.app_groups.entries.get(index) else {
        app.app_groups.note = Some(Note::NoItem(index + 1));
        return;
    };
    let to = if current_route(app, entry) == "secondary" {
        "primary"
    } else {
        "secondary"
    };
    choose(app, index, to);
}

fn move_to(app: &mut AppState, index: usize) {
    let count = app.app_groups.entries.len();
    app.app_groups.selected = index.min(count.saturating_sub(1));
    app.scroll = u16::try_from(app.app_groups.selected * ENTRY_LINES).unwrap_or(u16::MAX);
}

pub struct AppGroupsScreen;

impl Screen for AppGroupsScreen {
    fn view(&self, app: &AppState, texts: &Texts) -> ScreenView {
        let (list_title, list) = match (machines::title(app, texts), machines::lines(app, texts)) {
            (Some(title), Some(lines)) => (title, lines),
            _ => (texts.get(keys::LIST_TITLE), list_lines(app, texts)),
        };
        ScreenView {
            title: texts.get(ScreenId::AppGroups.title()),
            panels: vec![
                Panel {
                    title: texts.get(keys::TITLE),
                    lines: head_lines(app, texts),
                    feed: false,
                },
                Panel {
                    title: list_title,
                    lines: list,
                    feed: true,
                },
            ],
        }
    }

    fn help(&self) -> &'static [Key] {
        keys::HELP_KEYS
    }

    fn plain_help(&self) -> &'static [Key] {
        keys::PLAIN_KEYS
    }

    /// The rules are read for the routes shown; the machine is scanned anew.
    fn on_show(&self, app: &mut AppState) {
        rules::load_if_needed(app);
        scan(app);
    }

    fn takes_focus(&self) -> bool {
        true
    }

    fn on_key(&self, app: &mut AppState, key: KeyEvent) -> bool {
        if app.app_groups.machines.is_some() {
            return machines::on_key(app, key);
        }
        let selected = app.app_groups.selected;
        let count = app.app_groups.entries.len();
        if matches!(key.code, KeyCode::Char('p' | 's' | ' '))
            && crate::screens::focus_list_first(app)
        {
            return true;
        }
        match key.code {
            KeyCode::Up => move_to(app, selected.saturating_sub(1)),
            KeyCode::Down => move_to(app, selected + 1),
            KeyCode::Home => move_to(app, 0),
            KeyCode::End => move_to(app, count.saturating_sub(1)),
            KeyCode::Char('p') => choose(app, selected, "primary"),
            KeyCode::Char('s') => choose(app, selected, "secondary"),
            KeyCode::Char(' ') | KeyCode::Enter => switch(app, selected),
            KeyCode::Char('m') => machines::open(app, selected),
            KeyCode::Char('r') => scan(app),
            _ => return false,
        }
        true
    }

    fn on_line(&self, app: &mut AppState, line: &str) -> bool {
        let (command, number) = line.trim().split_once(' ').unwrap_or((line.trim(), ""));
        if app.app_groups.machines.is_some() && machines::on_line(app, command, number) {
            return true;
        }
        if command == "r" && number.is_empty() {
            scan(app);
            return true;
        }
        if !matches!(command, "m" | "p" | "s") {
            return false;
        }
        let Some(n) = number.trim().parse::<usize>().ok().filter(|n| *n >= 1) else {
            return false;
        };
        let Some(at) = numbered_entry(app, n) else {
            return true;
        };
        match command {
            "m" => machines::open(app, at),
            "p" => choose(app, at, "primary"),
            _ => choose(app, at, "secondary"),
        }
        true
    }

    fn on_printed(&self, app: &mut AppState) {
        app.app_groups.printed = app.app_groups.entries.iter().map(entry_key).collect();
        app.app_groups.printed_pins = machines::pin_keys(app);
    }
}

fn entry_key(entry: &Entry) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}",
        entry.slug,
        entry.name,
        entry.path.as_deref().unwrap_or_default()
    )
}

/// Line mode's item `n` where it stands now, by what was printed under it;
/// `None` with the reason noted.
fn numbered_entry(app: &mut AppState, n: usize) -> Option<usize> {
    let now: Vec<String> = app.app_groups.entries.iter().map(entry_key).collect();
    match super::numbered_now(&app.app_groups.printed, &now, n) {
        super::Numbered::At(at) => Some(at),
        super::Numbered::Gone => {
            app.app_groups.note = Some(Note::Gone(n));
            None
        }
        super::Numbered::NoSuch => {
            app.app_groups.note = Some(Note::NoItem(n));
            None
        }
    }
}

fn route_word(slug: &str, texts: &Texts) -> String {
    match slug {
        "primary" => texts.get(keys::ROUTE_PRIMARY),
        "secondary" => texts.get(keys::ROUTE_SECONDARY),
        "block" => texts.get(keys::ROUTE_BLOCK),
        "mixed" => texts.get(keys::ROUTE_MIXED),
        other => display_text(other).into_owned(),
    }
}

fn hypervisor_name(hypervisor: Hypervisor, texts: &Texts) -> String {
    texts.get(match hypervisor {
        Hypervisor::VirtualBox => keys::HYPERVISOR_VIRTUALBOX,
        Hypervisor::VMware => keys::HYPERVISOR_VMWARE,
    })
}

fn title_of(entry: &Entry, texts: &Texts) -> String {
    entry.hypervisor.map_or_else(
        || display_text(&entry.name).into_owned(),
        |h| hypervisor_name(h, texts),
    )
}

fn head_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let state = &app.app_groups;
    let mut lines = vec![
        ViewLine::text(texts.get(keys::INTRO)),
        ViewLine::new(vec![Segment::muted(texts.get(keys::SUBTITLE))]),
    ];
    let any = |wanted: &dyn Fn(&str) -> bool| state.entries.iter().any(|e| wanted(e.slug));
    if any(&|slug| matches!(slug, "hypervisor" | "android-emulator" | "console-emulator")) {
        lines.push(ViewLine::text(texts.get(keys::VM_NOTE)));
    }
    if any(&|slug| matches!(slug, "bittorrent" | "p2p-file-sharing" | "crypto-node")) {
        lines.push(ViewLine::text(texts.get(keys::P2P_NOTE)));
    }
    if any(&|slug| slug == "kernel-virtual-net") {
        lines.push(ViewLine::text(texts.get(keys::KERNEL_NAT_NOTE)));
    }
    if state.scanning {
        lines.push(ViewLine::text(texts.get(keys::SCANNING)));
    }
    if !has_rules(app) {
        lines.push(ViewLine::new(vec![Segment::strong(
            texts.get(keys::NO_RULES),
        )]));
    }
    if let Some(note) = &state.note {
        lines.extend(note_lines(note, texts));
    }
    lines.push(ViewLine::text(texts.get(keys::FOOTER_NOTE)));
    lines
}

fn note_lines(note: &Note, texts: &Texts) -> Vec<ViewLine> {
    let item = |key: Key, n: &usize| texts.fill(key, &[("n", n.to_string())]);
    let strong = |text: String| vec![ViewLine::new(vec![Segment::strong(text)])];
    match note {
        Note::NoItem(n) => strong(item(keys::NO_ITEM, n)),
        Note::NotAssignable(n) => strong(item(keys::NOT_ASSIGNABLE, n)),
        Note::Locked => strong(texts.get(keys::LOCKED)),
        Note::NoRules => strong(texts.get(keys::NO_RULES)),
        Note::Unchanged => strong(texts.get(keys::UNCHANGED)),
        Note::Limit => {
            strong(texts.fill(keys::LIMIT_REACHED, &[("max", FREE_MAX_RULES.to_string())]))
        }
        Note::NotHypervisor(n) => strong(item(keys::NOT_HYPERVISOR, n)),
        Note::NoTarget(n) => strong(item(keys::NO_TARGET, n)),
        Note::Gone(n) => strong(item(crate::keys::PLAIN_NUMBER_GONE, n)),
        Note::PinBusy => strong(texts.get(keys::PIN_BUSY)),
        Note::PinUnchanged => strong(texts.get(keys::PIN_UNCHANGED)),
        Note::PinNoAdditional => strong(texts.fill(
            keys::VM_PIN_NO_ADDITIONAL,
            &[("route", texts.get(keys::ROUTE_SECONDARY))],
        )),
        Note::Updated(count) => vec![
            ViewLine::new(vec![Segment::strong(texts.counted(keys::UPDATED, *count))]),
            ViewLine::text(texts.get(keys::IN_RULES)),
        ],
    }
}

fn list_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let state = &app.app_groups;
    if state.entries.is_empty() {
        return if state.scanned && !state.scanning {
            vec![ViewLine::text(texts.get(keys::EMPTY))]
        } else {
            Vec::new()
        };
    }
    let focused = app.focus == Focus::Feed;
    state
        .entries
        .iter()
        .enumerate()
        .flat_map(|(i, entry)| entry_lines(app, entry, i, focused && i == state.selected, texts))
        .collect()
}

/// Exactly [`ENTRY_LINES`] lines: the scroll position counts on it.
fn entry_lines(
    app: &AppState,
    entry: &Entry,
    index: usize,
    selected: bool,
    texts: &Texts,
) -> Vec<ViewLine> {
    let marker = if selected { "> " } else { "" };
    let number = format!("{marker}{}. ", index + 1);
    let title = title_of(entry, texts);
    let route = if entry.slug == "kernel-virtual-net" {
        Some(Segment::route_slug(
            texts.get(keys::ROUTE_LOCKED),
            "primary",
        ))
    } else if entry.assignable {
        let slug = current_route(app, entry);
        Some(Segment::route_slug(route_word(&slug, texts), &slug))
    } else {
        None
    };
    let mut first = if selected {
        vec![Segment::selected(format!("{number}{title}"))]
    } else {
        vec![Segment::plain(number), Segment::strong(title)]
    };
    if let Some(route) = route {
        first.push(Segment::plain(" \u{2014} "));
        first.push(route);
    }
    vec![
        ViewLine::new(first),
        ViewLine::text(format!("   {}", detail_of(entry, texts))),
    ]
}

fn detail_of(entry: &Entry, texts: &Texts) -> String {
    let group = texts.dynamic(&format!("app-groups.group.{}", entry.slug), entry.slug);
    let mut parts = vec![group];
    if let Some(hypervisor) = entry.hypervisor {
        let name = hypervisor_name(hypervisor, texts);
        if !entry.assignable {
            parts.push(texts.fill(keys::ROUTE_NONE, &[("hypervisor", name)]));
        } else if entry.machines.is_empty() {
            parts.push(texts.fill(keys::NO_MACHINES, &[("hypervisor", name)]));
        } else {
            let shown: Vec<_> = entry
                .machines
                .iter()
                .take(MACHINES_SHOWN)
                .map(|m| display_text(m).into_owned())
                .collect();
            let more = entry.machines.len().saturating_sub(MACHINES_SHOWN);
            let mut machines = format!("{}: {}", texts.get(keys::MACHINES), shown.join(", "));
            if more > 0 {
                machines.push_str(&format!(" +{more}"));
            }
            parts.push(machines);
        }
        return parts.join(" \u{00b7} ");
    }
    if !entry.assignable {
        parts.push(texts.get(keys::DISPLAY_ONLY));
    }
    let badge = match entry.badge {
        Badge::None => None,
        Badge::Running => Some(keys::BADGE_RUNNING),
        Badge::Installed => Some(keys::BADGE_INSTALLED),
        Badge::Feature => Some(keys::BADGE_FEATURE),
    };
    parts.extend(badge.map(|b| texts.get(b)));
    if let Some(path) = &entry.path {
        parts.push(display_text(path).into_owned());
    }
    parts.join(" \u{00b7} ")
}
