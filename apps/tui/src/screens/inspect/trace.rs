//! «Connection trace»: recent outbound connections, the route each took and
//! why. The same `conn-trace.entries.list` the GUI reads, drained when the
//! screen first opens and again on `r`; it never refreshes by itself, so a
//! line is not pulled from under someone reading it. `h` swaps in the user's
//! kept history (`conn-history.list`) for a period, as the GUI's switch does.
//! `g` groups the list by program or by program folder, as the GUI's choice
//! does, and remembers it in the terminal's own settings.

use std::cell::RefCell;

use crossterm::event::{KeyCode, KeyEvent};
use nrr_client_logic::conn_trace::{
    conn_trace_learned_routes, group_trace_rows, is_ipv6_endpoint, is_non_internet_address,
    TraceGroup, TraceGroupKind, TraceGrouping, TraceOutcomeRef, TraceRowRef,
};
use nrr_client_logic::rule_value_class::path_style_for_os;
use nrr_client_logic::rules_table::RuleType;
use nrr_ipc_client::IpcClient;
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    ConnHistoryEntryDto, ConnHistoryListRequest, ConnHistoryListResponse,
    ConnTraceEntriesListRequest, ConnTraceEntriesListResponse, ConnTraceEntryDto,
};
use nrr_shared::pagination::{PaginationParams, MAX_PAGE_SIZE};
use nrr_shared::platform_profile::PlatformProfile;

use super::{
    bad_response, call, command, edit, error_text, fill_numbered, keys, page_lines, queue,
    typing_lines, unencodable, wall_clock, yes_no, Edit, Pager,
};
use crate::backend::Reply;
use crate::i18n::{Key, Texts};
use crate::screens::settings::Clock;
use crate::screens::{Screen, ScreenId};
use crate::state::AppState;
use crate::view::{Panel, ScreenView, Segment, ViewLine};

/// The service keeps at most this many; reading them all lets the search
/// cover the whole ring, as the GUI's open-time drain does.
const DRAIN_CAP: usize = 1000;

/// Kept-history rows read in one go, as the GUI does; the rest of a long
/// period is one `r` with a narrower search away.
const HISTORY_DRAIN_CAP: usize = 2000;

/// What the kept history covers, as the GUI's period picker.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Period {
    #[default]
    Hour,
    Today,
    Week,
}

impl Period {
    fn next(self) -> Self {
        match self {
            Self::Hour => Self::Today,
            Self::Today => Self::Week,
            Self::Week => Self::Hour,
        }
    }

    fn from_word(word: &str) -> Option<Self> {
        match word {
            "hour" => Some(Self::Hour),
            "today" => Some(Self::Today),
            "week" => Some(Self::Week),
            _ => None,
        }
    }

    fn label(self) -> Key {
        match self {
            Self::Hour => keys::HISTORY_HOUR,
            Self::Today => keys::HISTORY_TODAY,
            Self::Week => keys::HISTORY_WEEK,
        }
    }

    /// Where the period starts, in Unix milliseconds; "today" from local
    /// midnight.
    fn start_ms(self, clock: &Clock) -> i64 {
        let now = clock.now();
        match self {
            Self::Hour => now.saturating_sub(3_600_000),
            Self::Week => now.saturating_sub(7 * 86_400_000),
            Self::Today => {
                // The offset in force at midnight, not now: on the day the
                // clocks change they differ, and the GUI counts from the real
                // midnight.
                let offset_ms = |at: i64| i64::from((clock.utc_offset)(at)).saturating_mul(1000);
                let day_start = clock.local_day().saturating_mul(86_400_000);
                let guess = day_start.saturating_sub(offset_ms(now));
                day_start.saturating_sub(offset_ms(guess))
            }
        }
    }
}

#[derive(Debug)]
pub struct TraceState {
    asked: bool,
    loading: bool,
    entries: Vec<ConnTraceEntryDto>,
    observer_active: bool,
    stream_enabled: bool,
    error: Option<String>,
    query: String,
    typing: Option<String>,
    // Off by default, as in the GUI: what the user sees first is
    // internet-bound traffic that was let out.
    show_blocked: bool,
    show_local: bool,
    only_ipv6: bool,
    pager: Pager,
    generation: u64,
    /// What the last picture listed, in order: rows and group headers. The
    /// search matches the words on screen, which only the renderer has; keys
    /// act on what was seen.
    visible: RefCell<Vec<Item>>,
    /// The OS that observed the trace (`PlatformProfile.os`), which decides how
    /// its program paths are spelled and compared.
    pub(super) os: &'static str,
    /// Why the grouping chosen last was not saved; it still applies until the
    /// program ends.
    grouping_unsaved: Option<String>,
    /// Reading the kept history rather than the latest connections.
    history: bool,
    period: Period,
    /// Per kept row, beside `entries`: attempts and the first time.
    kept: Vec<(u64, i64)>,
    /// Per live row, beside `entries`: when its connection was first held
    /// while the address was learned, or 0.
    held_at: Vec<i64>,
    history_enabled: bool,
    history_available: bool,
    removed: u64,
    skipped: u64,
}

impl Default for TraceState {
    fn default() -> Self {
        Self {
            asked: false,
            loading: false,
            entries: Vec::new(),
            observer_active: true,
            stream_enabled: true,
            error: None,
            query: String::new(),
            typing: None,
            show_blocked: false,
            show_local: false,
            only_ipv6: false,
            pager: Pager::default(),
            generation: 0,
            visible: RefCell::new(Vec::new()),
            // The service on the other end of the pipe runs on this machine.
            os: PlatformProfile::current().os,
            grouping_unsaved: None,
            history: false,
            period: Period::default(),
            kept: Vec::new(),
            held_at: Vec::new(),
            history_enabled: true,
            history_available: true,
            removed: 0,
            skipped: 0,
        }
    }
}

impl TraceState {
    /// The rows to list: view filters first, then the search, so the counts
    /// match what is listed.
    fn shown(&self, texts: &Texts) -> Vec<usize> {
        let query = self.query.trim().to_lowercase();
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| self.show_blocked || !e.verdict.starts_with("block"))
            .filter(|(_, e)| self.show_local || !is_non_internet_address(&e.remote))
            .filter(|(_, e)| !self.only_ipv6 || is_ipv6_endpoint(&e.remote))
            .filter(|(_, e)| query.is_empty() || blob(texts, e).contains(&query))
            .map(|(i, _)| i)
            .collect()
    }

    /// The rows to list grouped as `grouping` asks (`connTraceGroups`): each
    /// group's header, where it has one, then its rows.
    fn items(&self, texts: &Texts, grouping: TraceGrouping) -> Vec<Item> {
        let shown = self.shown(texts);
        let rows: Vec<TraceRowRef<'_>> = shown
            .iter()
            .filter_map(|&i| self.entries.get(i))
            .map(|e| TraceRowRef {
                process: &e.process,
                process_path: &e.process_path,
            })
            .collect();
        let groups = group_trace_rows(&rows, grouping, path_style_for_os(self.os));
        if groups.is_empty() {
            return shown.into_iter().map(Item::Row).collect();
        }
        let mut items = Vec::with_capacity(shown.len() + groups.len());
        for group in groups {
            let members: Vec<Item> = group
                .rows
                .iter()
                .filter_map(|&r| shown.get(r).copied().map(Item::Row))
                .collect();
            if group.header {
                items.push(Item::Header(group));
            }
            items.extend(members);
        }
        items
    }

    fn visible_len(&self) -> usize {
        self.visible.borrow().len()
    }

    fn selected_entry(&self) -> Option<ConnTraceEntryDto> {
        match self.visible.borrow().get(self.pager.selected)? {
            Item::Row(index) => self.entries.get(*index).cloned(),
            Item::Header(_) => None,
        }
    }

    fn selected_folder_rule(&self) -> Option<String> {
        folder_rule_at(&self.visible.borrow(), self.pager.selected)
    }

    fn set_query(&mut self, query: String) {
        self.query = query;
        self.pager = Pager::default();
    }

    /// Swap what is listed; the rows of the other view are not this one's.
    fn set_view(&mut self, history: bool, period: Period) {
        self.history = history;
        self.period = period;
        self.entries.clear();
        self.kept.clear();
        self.held_at.clear();
        self.pager = Pager::default();
    }

    fn toggle(&mut self, which: char) {
        match which {
            'b' => self.show_blocked = !self.show_blocked,
            'l' => self.show_local = !self.show_local,
            _ => self.only_ipv6 = !self.only_ipv6,
        }
        self.pager = Pager::default();
    }
}

/// One line of the list: a connection, by its index in the entries, or the
/// header of a group.
#[derive(Clone, Debug)]
enum Item {
    Row(usize),
    Header(TraceGroup),
}

/// The folder rule of the group the line at `at` belongs to: its header, or
/// the nearest header above a row. A program seen once has no header, but no
/// program group carries a folder rule either.
fn folder_rule_at(items: &[Item], at: usize) -> Option<String> {
    items.get(..=at)?.iter().rev().find_map(|item| match item {
        Item::Header(group) => Some(group.rule_value.clone()),
        Item::Row(_) => None,
    })?
}

/// "C:\Apps  ·  2 programs  ·  5 connections:" — a heading, by its colon.
fn header_text(texts: &Texts, group: &TraceGroup) -> String {
    format!(
        "{}  ·  {}:",
        group_label(texts, group),
        group_counts(texts, group)
    )
}

fn group_label(texts: &Texts, group: &TraceGroup) -> String {
    match group.kind {
        TraceGroupKind::NoPath => texts.get(keys::TRACE_GROUP_NO_PATH),
        TraceGroupKind::Program | TraceGroupKind::Folder => display_text(&group.label).into_owned(),
    }
}

fn group_counts(texts: &Texts, group: &TraceGroup) -> String {
    let connections = texts.counted(keys::TRACE_GROUP_CONNECTIONS, group.rows.len());
    match group.kind {
        TraceGroupKind::Program => connections,
        TraceGroupKind::Folder | TraceGroupKind::NoPath => format!(
            "{}  ·  {connections}",
            texts.counted(keys::TRACE_GROUP_PROGRAMS, group.programs)
        ),
    }
}

fn header_detail(texts: &Texts, group: &TraceGroup) -> Vec<ViewLine> {
    let first = match group.kind {
        TraceGroupKind::Program => format!(
            "{}: {}",
            texts.get(keys::COL_PROCESS),
            group_label(texts, group)
        ),
        TraceGroupKind::Folder => {
            texts.fill(keys::TRACE_PATH, &[("path", group_label(texts, group))])
        }
        TraceGroupKind::NoPath => group_label(texts, group),
    };
    vec![
        ViewLine::text(first),
        ViewLine::text(group_counts(texts, group)),
    ]
}

/// The grouping after `current`, in the order the GUI offers them.
fn next_grouping(current: TraceGrouping) -> TraceGrouping {
    let all = TraceGrouping::ALL;
    let at = all.iter().position(|g| *g == current).unwrap_or(0);
    all[(at + 1) % all.len()]
}

/// The list grouped as asked, the choice remembered in the terminal's own
/// settings file.
fn set_grouping(app: &mut AppState, grouping: TraceGrouping) {
    app.settings.prefs.trace_grouping = grouping;
    app.inspect.trace.pager = Pager::default();
    // Without a configuration folder there is nowhere to remember it.
    app.inspect.trace.grouping_unsaved = app
        .settings
        .save_prefs()
        .and_then(Result::err)
        .map(|error| error.to_string());
}

/// "Rule for this folder…": the Rules screen's add form holding the folder
/// and every folder below it.
fn rule_for_selected_folder(app: &mut AppState) -> bool {
    let Some(value) = app.inspect.trace.selected_folder_rule() else {
        return false;
    };
    crate::screens::rules::add_prefilled(app, RuleType::Application, value)
}

/// "Rule for this address…": the add form holding the chosen connection's
/// IPv4 address, as the GUI offers it.
fn rule_for_selected_address(app: &mut AppState) -> bool {
    let Some(e) = app.inspect.trace.selected_entry() else {
        return false;
    };
    // A kept row carries the address alone.
    let address = if app.inspect.trace.history {
        e.remote.as_str()
    } else {
        remote_address(&e.remote)
    };
    let Ok(ip) = address.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    crate::screens::rules::add_prefilled(app, RuleType::ExactIp, ip.to_string())
}

/// "Rule for this application…": application rules match the program's file
/// name, which is what the trace names.
fn rule_for_selected_program(app: &mut AppState) -> bool {
    let Some(e) = app.inspect.trace.selected_entry() else {
        return false;
    };
    if e.process.is_empty() || e.process == "?" {
        return false;
    }
    crate::screens::rules::add_prefilled(app, RuleType::Application, e.process)
}

struct Drained {
    entries: Vec<ConnTraceEntryDto>,
    observer_active: bool,
    stream_enabled: bool,
}

fn drain(client: &dyn IpcClient) -> Result<Drained, String> {
    let mut out = Drained {
        entries: Vec::new(),
        observer_active: true,
        stream_enabled: true,
    };
    let mut cursor = None;
    loop {
        let request = ConnTraceEntriesListRequest {
            pagination: PaginationParams {
                cursor,
                page_size: MAX_PAGE_SIZE,
            },
        };
        let payload = serde_json::to_value(&request).map_err(unencodable)?;
        let answer = call(client, IpcOperationName::ConnTraceEntriesList, payload)?;
        let page: ConnTraceEntriesListResponse =
            serde_json::from_value(answer).map_err(bad_response)?;
        out.observer_active = page.observer_active;
        out.stream_enabled = page.gui_stream_enabled;
        out.entries.extend(page.page.items);
        cursor = page.page.next_cursor;
        if cursor.is_none() || out.entries.len() >= DRAIN_CAP {
            return Ok(out);
        }
    }
}

struct Kept {
    entries: Vec<ConnTraceEntryDto>,
    meta: Vec<(u64, i64)>,
    enabled: bool,
    available: bool,
    removed: u64,
    skipped: u64,
}

/// A kept row in the live row's shape, so the filters, the search and the
/// detail read it the way they read a live one.
fn as_trace_row(h: ConnHistoryEntryDto) -> ConnTraceEntryDto {
    ConnTraceEntryDto {
        process: h.process,
        process_path: h.process_path,
        proto: String::new(),
        local: String::new(),
        remote: h.remote_ip,
        egress_role: h.route,
        egress_ifindex: 0,
        verdict: h.verdict,
        blocked_by: h.blocked_by,
        block_reason: h.block_reason,
        expected_route: String::new(),
        observed_at_ms: h.last_seen_ms,
        relay_for: String::new(),
        rule_host: String::new(),
        remote_host_count: u32::from(!h.host.is_empty()),
        remote_hosts: if h.host.is_empty() {
            Vec::new()
        } else {
            vec![h.host]
        },
        remote_host_floor: String::new(),
        remote_fake_ip: false,
    }
}

fn drain_history(client: &dyn IpcClient, from_ms: i64) -> Result<Kept, String> {
    let mut out = Kept {
        entries: Vec::new(),
        meta: Vec::new(),
        enabled: true,
        available: true,
        removed: 0,
        skipped: 0,
    };
    let mut cursor = None;
    loop {
        let request = ConnHistoryListRequest {
            from_unix_ms: from_ms,
            pagination: PaginationParams {
                cursor,
                page_size: MAX_PAGE_SIZE,
            },
            ..ConnHistoryListRequest::default()
        };
        let payload = serde_json::to_value(&request).map_err(unencodable)?;
        let answer = call(client, IpcOperationName::ConnHistoryList, payload)?;
        let page: ConnHistoryListResponse = serde_json::from_value(answer).map_err(bad_response)?;
        out.enabled = page.enabled;
        out.available = page.available;
        out.removed = page.removed;
        out.skipped = page.skipped;
        for row in page.page.items {
            out.meta.push((row.attempts, row.first_seen_ms));
            out.entries.push(as_trace_row(row));
        }
        cursor = page.page.next_cursor;
        if cursor.is_none() || out.entries.len() >= HISTORY_DRAIN_CAP {
            return Ok(out);
        }
    }
}

enum Read {
    Now(Drained),
    History(Kept),
}

fn load(app: &mut AppState) {
    let from_ms = app.inspect.trace.period.start_ms(&app.settings.clock);
    let state = &mut app.inspect.trace;
    state.asked = true;
    state.loading = true;
    state.error = None;
    state.generation += 1;
    let generation = state.generation;
    let history = state.history;
    queue(app, move |client| {
        let result = if history {
            drain_history(client, from_ms).map(Read::History)
        } else {
            drain(client).map(Read::Now)
        };
        Reply::new(move |app| {
            let state = &mut app.inspect.trace;
            // A newer read supersedes this one.
            if state.generation != generation {
                return;
            }
            state.loading = false;
            match result {
                Ok(Read::Now(drained)) => {
                    (state.entries, state.held_at) = fold_learned(drained.entries);
                    state.kept.clear();
                    state.observer_active = drained.observer_active;
                    state.stream_enabled = drained.stream_enabled;
                    state.pager.clamp(state.entries.len());
                }
                Ok(Read::History(kept)) => {
                    state.entries = kept.entries;
                    state.kept = kept.meta;
                    state.held_at.clear();
                    state.history_enabled = kept.enabled;
                    state.history_available = kept.available;
                    state.removed = kept.removed;
                    state.skipped = kept.skipped;
                    state.pager.clamp(state.entries.len());
                }
                Err(slug) => state.error = Some(slug),
            }
        })
    });
}

/// A connection held while its address was being learned, then sent over the
/// additional route, is kept as the one that went through, beside when it was
/// first held (`conn_trace_learned_routes`, the GUI's fold too). A hold nothing
/// followed stays a block. Kept history is per hour and is not folded.
fn fold_learned(entries: Vec<ConnTraceEntryDto>) -> (Vec<ConnTraceEntryDto>, Vec<i64>) {
    let pairs = {
        let rows: Vec<TraceOutcomeRef<'_>> = entries
            .iter()
            .map(|e| TraceOutcomeRef {
                process: &e.process,
                process_path: &e.process_path,
                remote: &e.remote,
                verdict: &e.verdict,
                blocked_by: &e.blocked_by,
                block_reason: &e.block_reason,
                egress_role: &e.egress_role,
                observed_at_ms: e.observed_at_ms,
            })
            .collect();
        conn_trace_learned_routes(&rows)
    };
    let mut held = vec![false; entries.len()];
    let mut held_at = vec![0_i64; entries.len()];
    for pair in pairs {
        let Some(t) = entries.get(pair.held).map(|e| e.observed_at_ms) else {
            continue;
        };
        if let (Some(flag), Some(at)) = (held.get_mut(pair.held), held_at.get_mut(pair.routed)) {
            *flag = true;
            if *at == 0 || t < *at {
                *at = t;
            }
        }
    }
    entries
        .into_iter()
        .zip(held_at)
        .zip(held)
        .filter(|(_, held)| !held)
        .map(|(row, _)| row)
        .unzip()
}

/// Switch between the latest connections and the kept history, then read.
fn show(app: &mut AppState, history: bool, period: Period) {
    app.inspect.trace.set_view(history, period);
    load(app);
}

fn label(texts: &Texts, family: &str, slug: &str) -> String {
    texts.dynamic(&format!("diag.conn-trace.{family}.{slug}"), slug)
}

/// A drop is NetRuleRouter's only when its own filter did it.
fn verdict_label(texts: &Texts, e: &ConnTraceEntryDto) -> String {
    if e.verdict == "block" {
        match e.blocked_by.as_str() {
            "netrulerouter" => return texts.get(keys::TRACE_BLOCK_BY_NRR),
            "other" => return texts.get(keys::TRACE_BLOCK_BY_OTHER),
            _ => {}
        }
    }
    label(texts, "verdict", &e.verdict)
}

/// A rule routes the address to the additional link, yet the flow was let
/// out over the main one: the GUI's leak indicator.
fn is_leak(e: &ConnTraceEntryDto) -> bool {
    e.expected_route == "secondary" && e.egress_role == "primary" && e.verdict == "permit"
}

fn host_count(e: &ConnTraceEntryDto) -> usize {
    (e.remote_host_count as usize).max(e.remote_hosts.len())
}

/// "address · name (+N)", as the GUI's Remote column.
fn remote_text(texts: &Texts, e: &ConnTraceEntryDto) -> String {
    let address = if e.remote.is_empty() {
        "—"
    } else {
        e.remote.as_str()
    };
    let Some(first) = e.remote_hosts.first() else {
        return if e.remote_fake_ip {
            format!("{address} · {}", texts.get(keys::TRACE_FAKE_IP))
        } else {
            address.to_owned()
        };
    };
    let first = display_text(first);
    let name = if host_count(e) > 1 {
        let others = (host_count(e) - 1).to_string();
        fill_numbered(&texts.get(keys::TRACE_HOST_OTHERS), &[&first, &others])
    } else {
        first.into_owned()
    };
    format!("{address} · {name}")
}

/// The GUI's search blob: every field as shown, lowercased.
fn blob(texts: &Texts, e: &ConnTraceEntryDto) -> String {
    let fake = if e.remote_fake_ip {
        texts.get(keys::TRACE_FAKE_IP)
    } else {
        String::new()
    };
    [
        e.process.clone(),
        label(texts, "proto", &e.proto),
        e.local.clone(),
        e.remote.clone(),
        e.remote_hosts.join(" "),
        fake,
        label(texts, "egress", &e.egress_role),
        label(texts, "verdict", &e.verdict),
        wall_clock(e.observed_at_ms),
    ]
    .join(" ")
    .to_lowercase()
}

/// The address of a remote without its port, as the GUI's row menu takes it.
fn remote_address(remote: &str) -> &str {
    match remote.rfind(':') {
        Some(at) if at > 0 => &remote[..at],
        _ => remote,
    }
}

/// "Why this route?": asked in Diagnostics by the rule host, else the name the
/// trace saw, else the address, with the address and program along so the
/// probe answers for this connection.
fn explain_selected(app: &mut AppState) {
    let Some(e) = app.inspect.trace.selected_entry() else {
        return;
    };
    // A kept row carries the address alone.
    let address = if app.inspect.trace.history {
        e.remote.clone()
    } else {
        remote_address(&e.remote).to_owned()
    };
    let first_name = e.remote_hosts.first().map_or("", String::as_str);
    let subject = [e.rule_host.as_str(), first_name, address.as_str()]
        .into_iter()
        .find(|s| !s.is_empty())
        .unwrap_or_default()
        .to_owned();
    if subject.is_empty() {
        return;
    }
    let process = if e.process == "?" {
        ""
    } else {
        e.process.as_str()
    };
    app.open(ScreenId::Diagnostics);
    super::diagnostics::probe(app, &subject, &address, process);
}

/// "Is it us or the site?" for the name the chosen connection was for, else
/// its rule host; checked in Diagnostics. `false` when the row names none.
fn check_selected(app: &mut AppState) -> bool {
    let Some(e) = app.inspect.trace.selected_entry() else {
        return false;
    };
    let site = e
        .remote_hosts
        .first()
        .cloned()
        .filter(|h| !h.is_empty())
        .unwrap_or(e.rule_host);
    if site.is_empty() {
        return false;
    }
    app.open(ScreenId::Diagnostics);
    super::diagnostics::check_site(app, &site);
    true
}

pub struct TraceScreen;

impl Screen for TraceScreen {
    fn view(&self, app: &AppState, texts: &Texts) -> ScreenView {
        let state = &app.inspect.trace;
        let items = state.items(texts, app.settings.prefs.trace_grouping);
        let rows = items
            .iter()
            .filter(|item| matches!(item, Item::Row(_)))
            .count();
        let mut pager = state.pager;
        pager.clamp(items.len());
        let mut detail = match items.get(pager.selected) {
            Some(Item::Row(i)) => detail_lines(
                texts,
                &state.entries[*i],
                state.kept.get(*i),
                state.held_at.get(*i).copied().unwrap_or(0),
            ),
            Some(Item::Header(group)) => header_detail(texts, group),
            None => Vec::new(),
        };
        if folder_rule_at(&items, pager.selected).is_some() {
            detail.push(ViewLine::text(format!(
                "f: {}",
                texts.get(keys::TRACE_RULE_FOR_FOLDER)
            )));
        }
        let list = page_lines(texts, pager, items.len(), false, |row| match &items[row] {
            Item::Row(i) => row_text(texts, &state.entries[*i], state.kept.get(*i)),
            Item::Header(group) => header_text(texts, group),
        });
        let summary = summary_lines(app, texts, rows);
        *state.visible.borrow_mut() = items;
        let title = texts.get(crate::keys::SCREEN_TRACE);
        ScreenView {
            title: title.clone(),
            panels: vec![
                Panel {
                    title,
                    lines: summary,
                    feed: false,
                },
                Panel {
                    title: texts.get(keys::TRACE_LIST),
                    lines: list,
                    feed: false,
                },
                Panel {
                    title: texts.get(keys::TRACE_DETAIL),
                    lines: detail,
                    feed: false,
                },
            ],
        }
    }

    fn help(&self) -> &'static [Key] {
        &[
            keys::TRACE_HELP_EXPLAIN,
            keys::TRACE_HELP_CHECK,
            keys::TRACE_HELP_SEARCH,
            keys::TRACE_HELP_FILTERS,
            keys::HELP_PAGES,
            keys::HELP_REFRESH,
            keys::TRACE_HELP_OUTAGE,
            keys::TRACE_HELP_HISTORY,
            keys::TRACE_HELP_GROUPING,
            keys::TRACE_HELP_RULE,
            keys::TRACE_SUBTITLE,
            keys::TRACE_VERDICT_NOTE,
        ]
    }

    fn plain_help(&self) -> &'static [Key] {
        &[
            keys::PLAIN_PAGES,
            keys::TRACE_PLAIN_DETAILS,
            keys::TRACE_PLAIN_EXPLAIN,
            keys::TRACE_PLAIN_CHECK,
            keys::TRACE_PLAIN_SEARCH,
            keys::TRACE_HELP_FILTERS,
            keys::HELP_REFRESH,
            keys::TRACE_HELP_OUTAGE,
            keys::TRACE_PLAIN_HISTORY,
            keys::TRACE_PLAIN_GROUPING,
            keys::TRACE_PLAIN_RULE,
        ]
    }

    fn on_show(&self, app: &mut AppState) {
        let state = &app.inspect.trace;
        if app.link.is_connected() && !state.loading && (!state.asked || state.error.is_some()) {
            load(app);
        }
    }

    fn takes_focus(&self) -> bool {
        true
    }

    fn captures_keys(&self, app: &AppState) -> bool {
        app.inspect.trace.typing.is_some()
    }

    fn text_target(&self, app: &AppState) -> crate::paste::TextTarget {
        if app.inspect.trace.typing.is_some() {
            crate::paste::TextTarget::Line
        } else {
            crate::paste::TextTarget::None
        }
    }

    fn on_key(&self, app: &mut AppState, key: KeyEvent) -> bool {
        let state = &mut app.inspect.trace;
        if let Some(buffer) = state.typing.as_mut() {
            match edit(buffer, key) {
                Edit::Typing => {}
                Edit::Done(text) => {
                    state.typing = None;
                    state.set_query(text);
                }
                Edit::Cancelled => state.typing = None,
            }
            return true;
        }
        match key.code {
            KeyCode::Char('/') => state.typing = Some(state.query.clone()),
            KeyCode::Char('r') => load(app),
            KeyCode::Char('o') => app.open(ScreenId::OutageBlocks),
            KeyCode::Char('h') => {
                let (history, period) = (!state.history, state.period);
                show(app, history, period);
            }
            KeyCode::Char('t') if state.history => {
                let period = state.period.next();
                show(app, true, period);
            }
            KeyCode::Char(c @ ('b' | 'l' | 'v')) => state.toggle(c),
            KeyCode::Char('g') => {
                let next = next_grouping(app.settings.prefs.trace_grouping);
                set_grouping(app, next);
            }
            KeyCode::Char('f') => {
                rule_for_selected_folder(app);
            }
            KeyCode::Char('i') => {
                rule_for_selected_address(app);
            }
            KeyCode::Char('a') => {
                rule_for_selected_program(app);
            }
            KeyCode::Char('c') => {
                check_selected(app);
            }
            KeyCode::Enter => explain_selected(app),
            code => {
                let len = state.visible_len();
                return state.pager.on_key(code, len);
            }
        }
        true
    }

    fn on_line(&self, app: &mut AppState, line: &str) -> bool {
        let state = &mut app.inspect.trace;
        let len = state.visible_len();
        match command(line) {
            ("n", "") => {
                state.pager.next_page(len);
            }
            ("p", "") => state.pager.previous_page(),
            ("r", "") => load(app),
            ("o", "") => app.open(ScreenId::OutageBlocks),
            ("h", "") => {
                let (history, period) = (!state.history, state.period);
                show(app, history, period);
            }
            ("h", "now") => {
                let period = state.period;
                show(app, false, period);
            }
            ("h", word) => match Period::from_word(word.trim()) {
                Some(period) => show(app, true, period),
                None => return false,
            },
            ("t", "") if state.history => {
                let period = state.period.next();
                show(app, true, period);
            }
            ("/", text) => state.set_query(text.to_owned()),
            ("b", "") => state.toggle('b'),
            ("l", "") => state.toggle('l'),
            ("v", "") => state.toggle('v'),
            ("g", "") => {
                let next = next_grouping(app.settings.prefs.trace_grouping);
                set_grouping(app, next);
            }
            ("g", word) => match TraceGrouping::from_slug(word.trim()) {
                Some(grouping) => set_grouping(app, grouping),
                None => return false,
            },
            ("f", "") => return rule_for_selected_folder(app),
            ("f", number) => {
                if !state.pager.pick(number, len) {
                    return false;
                }
                return rule_for_selected_folder(app);
            }
            ("i", "") => return rule_for_selected_address(app),
            ("a", "") => return rule_for_selected_program(app),
            ("i", number) => {
                if !state.pager.pick(number, len) {
                    return false;
                }
                return rule_for_selected_address(app);
            }
            ("a", number) => {
                if !state.pager.pick(number, len) {
                    return false;
                }
                return rule_for_selected_program(app);
            }
            ("d", number) => return state.pager.pick(number, len),
            ("c", number) => {
                if !state.pager.pick(number, len) {
                    return false;
                }
                return check_selected(app);
            }
            ("e", number) => {
                if !state.pager.pick(number, len) {
                    return false;
                }
                explain_selected(app);
            }
            _ => return false,
        }
        true
    }
}

fn summary_lines(app: &AppState, texts: &Texts, shown: usize) -> Vec<ViewLine> {
    let state = &app.inspect.trace;
    let mut lines = Vec::new();
    if !app.link.is_connected() {
        let word = if state.asked {
            keys::STALE
        } else {
            keys::NO_DATA
        };
        lines.push(ViewLine::text(texts.get(word)));
    }
    if state.history {
        lines.push(ViewLine::text(format!(
            "{}: {}",
            texts.get(keys::HISTORY_MODE),
            texts.get(state.period.label())
        )));
    }
    if let Some(slug) = &state.error {
        let failed = if state.history {
            keys::HISTORY_FAILED
        } else {
            keys::TRACE_FAILED
        };
        lines.push(ViewLine::text(format!(
            "{}{}",
            texts.get(failed),
            error_text(texts, slug)
        )));
    }
    if state.history && !state.loading && state.error.is_none() {
        // The history says what it could not keep.
        for (count, key) in [
            (state.removed, keys::HISTORY_REMOVED),
            (state.skipped, keys::HISTORY_SKIPPED),
        ] {
            if count > 0 {
                let count = count.to_string();
                lines.push(ViewLine::text(fill_numbered(&texts.get(key), &[&count])));
            }
        }
    }
    if state.loading && state.entries.is_empty() {
        lines.push(ViewLine::text(texts.get(keys::TRACE_LOADING)));
    } else if state.asked
        && !state.loading
        && state.error.is_none()
        && state.entries.is_empty()
        && state.history
    {
        let why = if !state.history_available {
            keys::HISTORY_UNAVAILABLE
        } else if !state.history_enabled {
            keys::HISTORY_OFF
        } else {
            keys::HISTORY_EMPTY
        };
        lines.push(ViewLine::text(texts.get(why)));
    } else if state.asked && !state.loading && state.error.is_none() && state.entries.is_empty() {
        // Three different silences, never presented as one.
        let why = if !state.stream_enabled {
            keys::TRACE_STREAM_OFF
        } else if state.observer_active {
            keys::TRACE_EMPTY
        } else {
            keys::TRACE_NOT_OBSERVING
        };
        lines.push(ViewLine::text(texts.get(why)));
    } else if !state.entries.is_empty() {
        lines.push(ViewLine::text(texts.fill(
            keys::TRACE_SHOWN,
            &[
                ("shown", shown.to_string()),
                ("total", state.entries.len().to_string()),
            ],
        )));
        if shown == 0 {
            lines.push(ViewLine::text(texts.get(keys::TRACE_NO_MATCH)));
        }
    }
    lines.push(ViewLine::text(format!(
        "{}: {} · {}: {} · {}: {}",
        texts.get(keys::TRACE_SHOW_BLOCKED),
        yes_no(texts, state.show_blocked),
        texts.get(keys::TRACE_SHOW_LOCAL),
        yes_no(texts, state.show_local),
        texts.get(keys::TRACE_ONLY_IPV6),
        yes_no(texts, state.only_ipv6),
    )));
    let grouping = match app.settings.prefs.trace_grouping {
        TraceGrouping::None => keys::TRACE_GROUP_NONE,
        TraceGrouping::Program => keys::TRACE_GROUP_PROGRAM,
        TraceGrouping::Folder => keys::TRACE_GROUP_FOLDER,
    };
    lines.push(ViewLine::text(format!(
        "{}: {}",
        texts.get(keys::TRACE_GROUP_BY),
        texts.get(grouping)
    )));
    if let Some(error) = &state.grouping_unsaved {
        lines.push(ViewLine::text(
            texts.fill(keys::TRACE_GROUPING_NOT_SAVED, &[("error", error)]),
        ));
    }
    match &state.typing {
        Some(buffer) => {
            let label = texts.get(keys::TRACE_SEARCH_LABEL);
            lines.extend(typing_lines(texts, label.trim_end_matches('…'), buffer));
        }
        None if !state.query.is_empty() => lines.push(ViewLine::text(
            texts.fill(keys::TRACE_SEARCH, &[("text", &state.query)]),
        )),
        None => {}
    }
    lines
}

fn row_text(texts: &Texts, e: &ConnTraceEntryDto, kept: Option<&(u64, i64)>) -> String {
    let process = if e.process.is_empty() {
        "—".into()
    } else {
        display_text(&e.process)
    };
    let mut row = format!(
        "{process} → {} — {} · {}",
        remote_text(texts, e),
        label(texts, "egress", &e.egress_role),
        verdict_label(texts, e),
    );
    if let Some((attempts, _)) = kept {
        row.push_str(&format!(" · {}: {attempts}", texts.get(keys::COL_ATTEMPTS)));
    }
    row
}

fn detail_lines(
    texts: &Texts,
    e: &ConnTraceEntryDto,
    kept: Option<&(u64, i64)>,
    held_at_ms: i64,
) -> Vec<ViewLine> {
    let or_dash = |s: &str| {
        if s.is_empty() {
            "—".to_owned()
        } else {
            display_text(s).into_owned()
        }
    };
    let mut lines = vec![ViewLine::text(format!(
        "{}: {}",
        texts.get(keys::COL_PROCESS),
        or_dash(&e.process)
    ))];
    if !e.process_path.is_empty() {
        let path = display_text(&e.process_path);
        lines.push(ViewLine::text(
            texts.fill(keys::TRACE_PATH, &[("path", &path)]),
        ));
    }
    lines.push(ViewLine::text(format!(
        "{}: {}",
        texts.get(keys::COL_REMOTE),
        remote_text(texts, e)
    )));
    if !e.remote_hosts.is_empty() {
        let mut names = String::new();
        if e.remote_fake_ip {
            names.push_str(&texts.get(keys::TRACE_VIA_FAKE_IP));
            names.push(' ');
        }
        let count = host_count(e).to_string();
        names.push_str(&fill_numbered(&texts.get(keys::TRACE_NAMES), &[&count]));
        names.push(' ');
        let shown: Vec<_> = e.remote_hosts.iter().map(|h| display_text(h)).collect();
        names.push_str(&shown.join(", "));
        lines.push(ViewLine::text(names));
    }
    lines.push(ViewLine::new(vec![
        Segment::plain(format!("{}: ", texts.get(keys::COL_EGRESS))),
        Segment::route_slug(label(texts, "egress", &e.egress_role), &e.egress_role),
    ]));
    if is_leak(e) {
        lines.push(ViewLine::text(texts.get(keys::TRACE_LEAK)));
    }
    let mut verdict = format!(
        "{}: {}",
        texts.get(keys::COL_VERDICT),
        verdict_label(texts, e)
    );
    // Which of our filters dropped it, in the block notice's words.
    if !e.block_reason.is_empty() {
        let id = format!("notifications.block-notice.reason.{}", e.block_reason);
        let reason = texts.dynamic(&id, "");
        if !reason.is_empty() {
            verdict.push_str(" — ");
            verdict.push_str(&reason);
        }
    }
    lines.push(ViewLine::text(verdict));
    if let Some((attempts, first_ms)) = kept {
        let (attempts, first, last) = (
            attempts.to_string(),
            wall_clock(*first_ms),
            wall_clock(e.observed_at_ms),
        );
        lines.push(ViewLine::text(fill_numbered(
            &texts.get(keys::HISTORY_ROW_DETAIL),
            &[&attempts, &first, &last],
        )));
        lines.push(ViewLine::text(format!(
            "Enter / e: {}",
            texts.get(keys::TRACE_WHY)
        )));
        return lines;
    }
    let mut facts = format!(
        "{} · {} {} · {}",
        label(texts, "proto", &e.proto),
        texts.get(keys::TRACE_FROM),
        or_dash(&e.local),
        wall_clock(e.observed_at_ms)
    );
    // Without it the relay reads as the service going out on its own account.
    if !e.relay_for.is_empty() {
        facts.push_str(" · ");
        facts.push_str(&fill_numbered(
            &texts.get(keys::TRACE_RELAY_FOR),
            &[&e.relay_for],
        ));
    }
    lines.push(ViewLine::text(facts));
    if held_at_ms > 0 {
        lines.push(ViewLine::text(fill_numbered(
            &texts.get(keys::TRACE_LEARNED_ROUTE),
            &[&wall_clock(held_at_ms)],
        )));
    }
    lines.push(ViewLine::text(format!(
        "Enter / e: {}",
        texts.get(keys::TRACE_WHY)
    )));
    lines
}

#[cfg(test)]
mod period_tests {
    use super::*;

    /// 2024-03-31T01:00Z, when central Europe moves from UTC+1 to UTC+2.
    const SPRING_FORWARD: i64 = 1_711_846_800_000;

    fn central_europe(ms: i64) -> i32 {
        if ms < SPRING_FORWARD {
            3_600
        } else {
            7_200
        }
    }

    /// Noon local time on the day of the change.
    fn noon_after_the_change() -> i64 {
        1_711_879_200_000
    }

    #[test]
    fn today_starts_at_the_real_local_midnight_on_the_day_the_clocks_change() {
        let clock = Clock {
            now_ms: noon_after_the_change,
            utc_offset: central_europe,
        };
        // 00:00 at UTC+1, the offset still in force at midnight.
        assert_eq!(Period::Today.start_ms(&clock), 1_711_839_600_000);
    }
}
