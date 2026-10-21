//! One hypervisor's machines (the GUI's virtual machines screen): what each
//! network adapter means for routing and for site rules inside the guest, and
//! for a VirtualBox NAT adapter a pin of all its traffic to the additional
//! adapter's address. A pin is made in the hypervisor itself, as the user, and
//! the machines are read again afterwards so the screen shows what took.

use std::net::Ipv4Addr;

use crossterm::event::{KeyCode, KeyEvent};
use nrr_ipc_client::IpcClient;
use nrr_platform_api::{
    classify_bindings, GuestDnsAdvice, Hypervisor, HypervisorInventory, NatBinding, VmAdapter,
    VmAttachment, VmControlError,
};
use nrr_shared::display_text::display_text;

use super::{choose, current_route, hypervisor_name, keys, scan, Note};
use crate::backend::Reply;
use crate::i18n::Texts;
use crate::state::{AppState, Focus};
use crate::view::{Segment, ViewLine};

/// One adapter of one machine, as the hypervisor names them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinKey {
    machine_id: String,
    slot: u32,
}

/// Why the last pin did not happen, by the adapter it was for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinFailure {
    key: PinKey,
    error: &'static str,
    /// The hypervisor tool's own words, when it gave any.
    message: String,
}

/// What the machines panel lists, line by line, before any text: the cursor
/// and the scroll position count on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Row {
    RouteNone,
    RouteScope,
    RouteNow,
    NoMachines,
    Machine(usize),
    NoAdapters,
    AdapterTitle(usize, usize),
    AdapterText(usize, usize),
    Command(usize, usize),
    Pin(usize, usize),
    Failure,
    PinNote,
}

/// The host's IPv4 addresses and the additional adapter's, as the service's
/// last snapshot lists them.
struct Addresses {
    host: Vec<Ipv4Addr>,
    additional: Option<Ipv4Addr>,
    /// An additional adapter is chosen at all; a pin needs one.
    chosen: bool,
}

fn first_ipv4(local_ip: &str) -> Option<Ipv4Addr> {
    local_ip
        .split(|c: char| c == ',' || c.is_whitespace())
        .find_map(|part| part.parse().ok())
}

fn addresses(app: &AppState) -> Addresses {
    let Some(snapshot) = app.snapshot.as_ref() else {
        return Addresses {
            host: Vec::new(),
            additional: None,
            chosen: false,
        };
    };
    let rows = &snapshot.adapters.rows;
    let binding = snapshot
        .route_policy
        .as_ref()
        .and_then(|p| p.secondary.as_ref());
    Addresses {
        host: rows
            .iter()
            .filter_map(|r| first_ipv4(&r.local_ip))
            .collect(),
        additional: binding
            .and_then(|b| crate::screens::status::bound_row(rows, b))
            .and_then(|r| first_ipv4(&r.local_ip)),
        chosen: binding.is_some(),
    }
}

/// Settles what each NAT pin means against the addresses the host has now.
pub(super) fn classify(app: &AppState, inventory: &mut [HypervisorInventory]) {
    let found = addresses(app);
    classify_bindings(inventory, &found.host, found.additional);
}

fn open_inventory(app: &AppState) -> Option<&HypervisorInventory> {
    let wanted = app.app_groups.machines?;
    app.app_groups
        .inventory
        .iter()
        .find(|i| i.hypervisor == wanted)
}

/// Only VirtualBox lets a NAT adapter be tied to a host address.
fn pinnable(inventory: &HypervisorInventory, adapter: &VmAdapter) -> bool {
    inventory.hypervisor == Hypervisor::VirtualBox
        && matches!(adapter.attachment, VmAttachment::Nat(_))
}

/// The adapters a pin can be given, `(machine, adapter)`, in the order listed.
fn targets(inventory: &HypervisorInventory) -> Vec<(usize, usize)> {
    inventory
        .machines
        .iter()
        .enumerate()
        .flat_map(|(m, machine)| {
            machine
                .adapters
                .iter()
                .enumerate()
                .filter(|(_, adapter)| pinnable(inventory, adapter))
                .map(move |(a, _)| (m, a))
        })
        .collect()
}

fn layout(app: &AppState, inventory: &HypervisorInventory) -> Vec<Row> {
    let mut rows = Vec::new();
    if inventory.traffic_processes.is_empty() {
        rows.push(Row::RouteNone);
    } else {
        rows.extend([Row::RouteScope, Row::RouteNow]);
    }
    if inventory.machines.is_empty() {
        rows.push(Row::NoMachines);
    }
    let failure = app.app_groups.pin_failure.as_ref();
    for (m, machine) in inventory.machines.iter().enumerate() {
        rows.push(Row::Machine(m));
        if machine.adapters.is_empty() {
            rows.push(Row::NoAdapters);
        }
        for (a, adapter) in machine.adapters.iter().enumerate() {
            rows.extend([Row::AdapterTitle(m, a), Row::AdapterText(m, a)]);
            if let VmAttachment::Nat(nat) = &adapter.attachment {
                if matches!(
                    nat.guest_dns,
                    GuestDnsAdvice::EnableHostLoopbackFirst {
                        command: Some(_),
                        ..
                    }
                ) {
                    rows.push(Row::Command(m, a));
                }
            }
            if pinnable(inventory, adapter) {
                rows.push(Row::Pin(m, a));
                let key = key_of(inventory, m, a);
                if failure.is_some_and(|f| Some(&f.key) == key.as_ref()) {
                    rows.push(Row::Failure);
                }
            }
        }
    }
    if !targets(inventory).is_empty() {
        rows.push(Row::PinNote);
    }
    rows
}

fn key_of(inventory: &HypervisorInventory, machine: usize, slot_at: usize) -> Option<PinKey> {
    let machine = inventory.machines.get(machine)?;
    let adapter = machine.adapters.get(slot_at)?;
    Some(PinKey {
        machine_id: machine.id.clone(),
        slot: adapter.slot,
    })
}

/// Open the machines of list item `index`.
pub(super) fn open(app: &mut AppState, index: usize) {
    let Some(entry) = app.app_groups.entries.get(index) else {
        app.app_groups.note = Some(Note::NoItem(index + 1));
        return;
    };
    let Some(hypervisor) = entry.hypervisor else {
        app.app_groups.note = Some(Note::NotHypervisor(index + 1));
        return;
    };
    let state = &mut app.app_groups;
    state.selected = index;
    state.machines = Some(hypervisor);
    state.pin_selected = 0;
    state.note = None;
    app.scroll = 0;
}

pub(super) fn close(app: &mut AppState) {
    app.app_groups.machines = None;
    let selected = app.app_groups.selected;
    super::move_to(app, selected);
}

fn move_pin(app: &mut AppState, to: usize) {
    let Some(inventory) = open_inventory(app) else {
        return;
    };
    let all = targets(inventory);
    let at = to.min(all.len().saturating_sub(1));
    let line = all.get(at).and_then(|&(m, a)| {
        layout(app, inventory)
            .iter()
            .position(|row| *row == Row::AdapterTitle(m, a))
    });
    app.app_groups.pin_selected = at;
    if let Some(line) = line {
        app.scroll = u16::try_from(line).unwrap_or(u16::MAX);
    }
}

/// The open hypervisor over `route`, as its list item would be.
fn route_open(app: &mut AppState, route: &'static str) {
    let wanted = app.app_groups.machines;
    if let Some(index) = app
        .app_groups
        .entries
        .iter()
        .position(|e| e.hypervisor.is_some() && e.hypervisor == wanted)
    {
        choose(app, index, route);
    }
}

/// Pin adapter `target` (from 0, as numbered) to the additional route, or let
/// it follow the rules again.
fn pin(app: &mut AppState, target: usize, additional: bool) {
    let Some(inventory) = open_inventory(app) else {
        return;
    };
    let hypervisor = inventory.hypervisor;
    let Some(&(m, a)) = targets(inventory).get(target) else {
        app.app_groups.note = Some(Note::NoTarget(target + 1));
        return;
    };
    let binding = match &inventory.machines[m].adapters[a].attachment {
        VmAttachment::Nat(nat) => nat.binding,
        _ => return,
    };
    let Some(key) = key_of(inventory, m, a) else {
        return;
    };
    app.app_groups.pin_selected = target;
    if app.app_groups.pinning.is_some() {
        app.app_groups.note = Some(Note::PinBusy);
        return;
    }
    let already = if additional {
        binding == NatBinding::AdditionalRoute
    } else {
        binding == NatBinding::Unbound
    };
    if already {
        app.app_groups.note = Some(Note::PinUnchanged);
        return;
    }
    let address = if additional {
        let found = addresses(app);
        if !found.chosen {
            app.app_groups.note = Some(Note::PinNoAdditional);
            return;
        }
        let Some(address) = found.additional else {
            app.app_groups.pin_failure = Some(PinFailure {
                key,
                error: "no-additional-address",
                message: String::new(),
            });
            return;
        };
        Some(address)
    } else {
        None
    };
    app.app_groups.note = None;
    app.app_groups.pin_failure = None;
    app.app_groups.pinning = Some(key.clone());
    app.outbox.push(Box::new(move |_client: &dyn IpcClient| {
        let result = crate::platform::vm_inventory().bind_nat(
            hypervisor,
            &key.machine_id,
            key.slot,
            address,
        );
        Reply::new(move |app| pinned(app, key, result))
    }));
}

pub(super) fn pinned(app: &mut AppState, key: PinKey, result: Result<(), VmControlError>) {
    let state = &mut app.app_groups;
    state.pinning = None;
    state.pin_failure = result.err().map(|error| PinFailure {
        key,
        error: error.slug(),
        message: match error {
            VmControlError::Failed(text) => text,
            _ => String::new(),
        },
    });
    scan(app);
}

/// A key while the machines are open; `true` when used.
pub(super) fn on_key(app: &mut AppState, key: KeyEvent) -> bool {
    let selected = app.app_groups.pin_selected;
    match key.code {
        KeyCode::Esc | KeyCode::Char('m') => close(app),
        KeyCode::Up => move_pin(app, selected.saturating_sub(1)),
        KeyCode::Down => move_pin(app, selected + 1),
        KeyCode::Home => move_pin(app, 0),
        KeyCode::End => move_pin(app, usize::MAX),
        KeyCode::Char('a') => pin(app, selected, true),
        KeyCode::Char('f') => pin(app, selected, false),
        KeyCode::Char('p') => route_open(app, "primary"),
        KeyCode::Char('s') => route_open(app, "secondary"),
        KeyCode::Char('r') => scan(app),
        _ => return false,
    }
    true
}

/// A line-mode command while the machines are open; `true` when used.
pub(super) fn on_line(app: &mut AppState, command: &str, number: &str) -> bool {
    let n = number.trim().parse::<usize>().ok().filter(|n| *n >= 1);
    match (command, n) {
        ("m", None) if number.trim().is_empty() => close(app),
        ("p", None) if number.trim().is_empty() => route_open(app, "primary"),
        ("s", None) if number.trim().is_empty() => route_open(app, "secondary"),
        ("a", Some(n)) => pin(app, n - 1, true),
        ("f", Some(n)) => pin(app, n - 1, false),
        _ => return false,
    }
    true
}

// ── Text ─────────────────────────────────────────────────────────────────────

fn secondary(texts: &Texts) -> String {
    texts.get(keys::ROUTE_SECONDARY)
}

fn mode_slug(attachment: &VmAttachment) -> &'static str {
    match attachment {
        VmAttachment::Nat(_) => "nat",
        VmAttachment::Bridged => "bridged",
        VmAttachment::HostOnly => "host-only",
        VmAttachment::Internal => "internal",
        VmAttachment::NatNetwork => "nat-network",
        VmAttachment::ServiceNat => "service-nat",
        VmAttachment::Other => "other",
    }
}

fn adapter_text(adapter: &VmAdapter, texts: &Texts) -> String {
    let n = (u64::from(adapter.slot) + 1).to_string();
    match &adapter.attachment {
        VmAttachment::Nat(nat) => match &nat.guest_dns {
            GuestDnsAdvice::UseHostAddress { address } => {
                texts.fill(keys::VM_NAT_DNS, &[("address", address.to_string())])
            }
            GuestDnsAdvice::EnableHostLoopbackFirst {
                address,
                command: Some(_),
            } => texts.fill(
                keys::VM_NAT_ENABLE_FIRST,
                &[("address", address.to_string())],
            ),
            GuestDnsAdvice::EnableHostLoopbackFirst {
                address,
                command: None,
            } => texts.fill(
                keys::VM_NAT_ENABLE_FIRST_NO_TOOL,
                &[("n", n), ("address", address.to_string())],
            ),
        },
        VmAttachment::Bridged => texts.get(keys::VM_BRIDGED),
        VmAttachment::HostOnly => texts.get(keys::VM_HOST_ONLY),
        VmAttachment::Internal => texts.get(keys::VM_INTERNAL),
        VmAttachment::ServiceNat => texts.get(keys::VM_SERVICE_NAT),
        VmAttachment::NatNetwork => texts.get(keys::VM_NAT_NETWORK),
        VmAttachment::Other => texts.get(keys::VM_OTHER),
    }
}

fn pin_text(adapter: &VmAdapter, texts: &Texts) -> (String, bool) {
    let VmAttachment::Nat(nat) = &adapter.attachment else {
        return (String::new(), false);
    };
    let bound = nat.bound_address.map(|a| a.to_string()).unwrap_or_default();
    match nat.binding {
        NatBinding::AdditionalRoute => (
            texts.fill(keys::VM_PIN_ADDITIONAL, &[("route", secondary(texts))]),
            false,
        ),
        NatBinding::Missing => (
            texts.fill(keys::VM_PIN_MISSING, &[("address", bound)]),
            true,
        ),
        NatBinding::OtherAddress => (texts.fill(keys::VM_PIN_OTHER, &[("address", bound)]), false),
        NatBinding::Unbound => (
            texts.fill(
                keys::VM_PIN_RULES,
                &[("route", texts.get(keys::ROUTE_PRIMARY))],
            ),
            false,
        ),
    }
}

fn failure_text(failure: &PinFailure, texts: &Texts) -> String {
    match failure.error {
        "machine-not-mutable" => texts.get(keys::VM_PIN_NOT_MUTABLE),
        "tool-missing" => texts.get(keys::VM_PIN_TOOL_MISSING),
        "no-additional-address" => {
            texts.fill(keys::VM_PIN_NO_ADDRESS, &[("route", secondary(texts))])
        }
        _ if !failure.message.is_empty() => texts.fill(
            keys::VM_PIN_REFUSED,
            &[("message", display_text(&failure.message).into_owned())],
        ),
        _ => texts.get(keys::VM_PIN_FAILED),
    }
}

fn route_now(app: &AppState, inventory: &HypervisorInventory, texts: &Texts) -> ViewLine {
    let name = hypervisor_name(inventory.hypervisor, texts);
    let entry = app
        .app_groups
        .entries
        .iter()
        .find(|e| e.hypervisor == Some(inventory.hypervisor));
    let route = entry.map_or_else(|| "primary".to_owned(), |e| current_route(app, e));
    let text = match route.as_str() {
        "mixed" => texts.fill(keys::VM_ROUTE_NOW_MIXED, &[("hypervisor", name)]),
        "block" => texts.fill(keys::VM_ROUTE_NOW_BLOCK, &[("hypervisor", name)]),
        other => texts.fill(
            keys::VM_ROUTE_NOW,
            &[
                ("hypervisor", name),
                ("route", super::route_word(other, texts)),
            ],
        ),
    };
    ViewLine::new(vec![Segment::route_slug(text, &route)])
}

/// The title of the machines panel.
pub(super) fn title(app: &AppState, texts: &Texts) -> Option<String> {
    let inventory = open_inventory(app)?;
    Some(texts.fill(
        keys::MACHINES_TITLE,
        &[("hypervisor", hypervisor_name(inventory.hypervisor, texts))],
    ))
}

/// The machines panel, or `None` when none is open.
pub(super) fn lines(app: &AppState, texts: &Texts) -> Option<Vec<ViewLine>> {
    let inventory = open_inventory(app)?;
    let focused = app.focus == Focus::Feed;
    let all = targets(inventory);
    let name = hypervisor_name(inventory.hypervisor, texts);
    let pinning = app.app_groups.pinning.as_ref();
    let lines = layout(app, inventory)
        .into_iter()
        .map(|row| match row {
            Row::RouteNone => ViewLine::new(vec![Segment::muted(
                texts.fill(keys::ROUTE_NONE, &[("hypervisor", name.clone())]),
            )]),
            Row::RouteScope => ViewLine::new(vec![Segment::muted(texts.fill(
                keys::VM_ROUTE_SCOPE,
                &[
                    ("hypervisor", name.clone()),
                    (
                        "processes",
                        display_text(&inventory.traffic_processes.join(", ")).into_owned(),
                    ),
                ],
            ))]),
            Row::RouteNow => route_now(app, inventory, texts),
            Row::NoMachines => {
                ViewLine::text(texts.fill(keys::NO_MACHINES, &[("hypervisor", name.clone())]))
            }
            Row::Machine(m) => ViewLine::new(vec![Segment::accent(format!(
                "{}: {}",
                texts.get(keys::VM_MACHINE),
                display_text(&inventory.machines[m].name)
            ))]),
            Row::NoAdapters => ViewLine::text(format!("  {}", texts.get(keys::VM_NO_ADAPTERS))),
            Row::AdapterTitle(m, a) => {
                let adapter = &inventory.machines[m].adapters[a];
                let title = texts.fill(
                    keys::VM_ADAPTER_TITLE,
                    &[
                        ("n", (u64::from(adapter.slot) + 1).to_string()),
                        (
                            "mode",
                            texts.dynamic(
                                &format!("rules.vm.mode.{}", mode_slug(&adapter.attachment)),
                                mode_slug(&adapter.attachment),
                            ),
                        ),
                    ],
                );
                match all.iter().position(|t| *t == (m, a)) {
                    Some(at) if focused && at == app.app_groups.pin_selected => {
                        ViewLine::new(vec![Segment::selected(format!("> {}. {title}", at + 1))])
                    }
                    Some(at) => ViewLine::new(vec![
                        Segment::plain(format!("  {}. ", at + 1)),
                        Segment::strong(title),
                    ]),
                    None => ViewLine::new(vec![Segment::plain("  "), Segment::strong(title)]),
                }
            }
            Row::AdapterText(m, a) => {
                let adapter = &inventory.machines[m].adapters[a];
                let text = format!("     {}", adapter_text(adapter, texts));
                if matches!(adapter.attachment, VmAttachment::Bridged) {
                    ViewLine::new(vec![Segment::state(text, crate::view::StateTone::Bad)])
                } else {
                    ViewLine::text(text)
                }
            }
            Row::Command(m, a) => {
                let command = match &inventory.machines[m].adapters[a].attachment {
                    VmAttachment::Nat(nat) => match &nat.guest_dns {
                        GuestDnsAdvice::EnableHostLoopbackFirst {
                            command: Some(command),
                            ..
                        } => display_text(command).into_owned(),
                        _ => String::new(),
                    },
                    _ => String::new(),
                };
                ViewLine::new(vec![Segment::strong(format!("     {command}"))])
            }
            Row::Pin(m, a) => {
                let adapter = &inventory.machines[m].adapters[a];
                let busy = key_of(inventory, m, a).is_some_and(|k| pinning == Some(&k));
                if busy {
                    return ViewLine::text(format!("     {}", texts.get(keys::VM_PINNING)));
                }
                let (text, bad) = pin_text(adapter, texts);
                let text = format!("     {text}");
                if bad {
                    ViewLine::new(vec![Segment::state(text, crate::view::StateTone::Bad)])
                } else {
                    ViewLine::text(text)
                }
            }
            Row::Failure => {
                let text = app
                    .app_groups
                    .pin_failure
                    .as_ref()
                    .map(|f| failure_text(f, texts))
                    .unwrap_or_default();
                ViewLine::new(vec![Segment::state(
                    format!("     {text}"),
                    crate::view::StateTone::Bad,
                )])
            }
            Row::PinNote => {
                let key = if addresses(app).chosen {
                    keys::VM_PIN_NOTE
                } else {
                    keys::VM_PIN_NO_ADDITIONAL
                };
                ViewLine::new(vec![Segment::muted(
                    texts.fill(key, &[("route", secondary(texts))]),
                )])
            }
        })
        .collect();
    Some(lines)
}
