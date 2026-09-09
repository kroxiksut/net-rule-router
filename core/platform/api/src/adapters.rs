//! Adapter availability monitoring with debounce.
//!
//! ## Architecture
//!
//! ```text
//! Win32 NotifyIpInterfaceChange  ──►  AdapterEventSource  ──►  AdapterMonitor
//!                                           (trait)          (debounce + classify)
//!                                                                    │
//!                                     polling fallback ─────────────┘
//! ```
//!
//! `AdapterEventSource` abstracts over both realtime Win32 notifications and
//! polling. All business logic lives in `AdapterMonitor`, which is fully
//! testable via `MockAdapterEventSource`.
//!
//! ## Debounce
//!
//! Per-adapter debounce window of `debounce_ms` (default 500 ms). Events
//! arriving within the window reset the timer rather than emitting immediately.
//! This smooths over Wi-Fi roaming bursts (5+ events in 1 second) while still
//! reacting to genuine state changes.
//!
//! ## Virtual adapter filtering
//!
//! Adapters with `InterfaceType::Tunnel`, `InterfaceType::Loopback`, or
//! known virtual manufacturer strings (Hyper-V, WSL, Docker, VMware,
//! VirtualBox) are excluded from availability tracking. The
//! `AdapterMonitor` skips them silently.
//!
//! ## IPv6
//!
//! IPv6 adapters and addresses are out-of-scope.
//! `AdapterInfo` only carries IPv4 addresses. `classify_availability`
//! works on IPv4 state only.

use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use crate::error::PlatformError;

// ── IfOperStatus ──────────────────────────────────────────────────────────────

/// Operational status of a network interface.
/// Mirrors `IF_OPER_STATUS` in `IfMib.h`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IfOperStatus {
    Up,
    Down,
    Testing,
    Unknown,
    Dormant,
    NotPresent,
    LowerLayerDown,
}

impl IfOperStatus {
    /// Returns `true` when the interface is actively passing traffic.
    pub fn is_up(self) -> bool {
        matches!(self, Self::Up)
    }
}

// ── InterfaceType ─────────────────────────────────────────────────────────────

/// Interface type from `MIB_IF_ROW2::Type`.
/// Only the values relevant to filtering are listed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceType {
    /// Regular Ethernet or Wi-Fi (IF_TYPE_ETHERNET_CSMACD = 6, 71 = IEEE80211).
    Ethernet,
    /// IEEE 802.11 Wi-Fi.
    Wireless,
    /// Software loopback (IF_TYPE_SOFTWARE_LOOPBACK = 24).
    Loopback,
    /// Tunnel / VPN interface (IF_TYPE_TUNNEL = 131).
    Tunnel,
    /// Other / unknown type.
    Other(u32),
}

impl InterfaceType {
    /// Returns `true` for types that should be excluded from availability
    /// tracking (loopback, tunnels).
    pub fn is_excluded(self) -> bool {
        matches!(self, Self::Loopback | Self::Tunnel)
    }

    pub fn from_raw(v: u32) -> Self {
        match v {
            6 | 71 => Self::Ethernet,
            24 => Self::Loopback,
            131 => Self::Tunnel,
            _ => Self::Other(v),
        }
    }
}

// ── AdapterInfo ───────────────────────────────────────────────────────────────

/// Platform-level snapshot of one network adapter's current state.
///
/// Populated by `WindowsApiPort::get_adapter_infos()`. IPv6 addresses are
/// excluded (out-of-scope).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterInfo {
    /// Windows `IfIndex`.
    pub index: u32,
    /// Adapter GUID string (e.g. `"{12AB...}"`).
    pub adapter_name: String,
    /// Driver description (e.g. `"TAP-Windows Adapter V9"`).
    pub description: String,
    /// The connection name the user sees and renames (Windows `FriendlyName`,
    /// Linux link name). A VPN client commonly renames the connection while
    /// keeping the stock driver, so this is the only name that matches what the
    /// GUI showed when the binding was saved. Empty when the OS reports none.
    pub friendly_name: String,
    /// Physical MAC address, if available.
    pub mac: Option<[u8; 6]>,
    pub interface_type: InterfaceType,
    pub oper_status: IfOperStatus,
    /// All IPv4 unicast addresses currently assigned.
    pub ipv4_addresses: Vec<Ipv4Addr>,
    /// Default gateways via this adapter (IPv4 only).
    pub gateways: Vec<Ipv4Addr>,
}

impl AdapterInfo {
    pub fn has_ipv4_address(&self) -> bool {
        !self.ipv4_addresses.is_empty()
    }

    pub fn has_gateway(&self) -> bool {
        !self.gateways.is_empty()
    }

    /// Stable identity string: MAC hex if available, else adapter_name.
    pub fn stable_id(&self) -> String {
        match self.mac {
            Some(mac) => format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            ),
            None => self.adapter_name.clone(),
        }
    }
}

// ── Virtual adapter detection ─────────────────────────────────────────────────

/// Returns `true` if this adapter should be excluded from availability
/// tracking (loopback, tunnel, or known virtual adapter software).
pub fn is_virtual_adapter(info: &AdapterInfo) -> bool {
    if info.interface_type.is_excluded() {
        return true;
    }
    // Description-based detection for common virtual adapter software.
    description_matches_virtual_software(&info.description)
}

/// `true` when the adapter DESCRIPTION matches known virtual-adapter software
/// (Hyper-V / WSL / Docker / VMware / VirtualBox / …).
///
/// Unlike [`is_virtual_adapter`], this does NOT treat loopback/tunnel *types* as
/// virtual — the Block T traffic counter classifies loopback and tunnel via
/// their own flags (`is_loopback` / `is_tunnel`) and needs the software-only
/// signal for the `is_virtual` bucket.
pub fn description_matches_virtual_software(description: &str) -> bool {
    let desc = description.to_lowercase();
    VIRTUAL_ADAPTER_SUBSTRINGS.iter().any(|s| desc.contains(s))
}

/// Lowercase substrings that indicate a virtual adapter.
const VIRTUAL_ADAPTER_SUBSTRINGS: &[&str] = &[
    "hyper-v",
    "wsl",
    "docker",
    "vmware",
    "virtualbox",
    "loopback",
    "pseudo",
    "teredo",
    "isatap",
    "6to4",
];

/// Lowercase substrings that, found in an adapter's name/description/type
/// string, indicate a VPN/tunnel adapter. Single source of truth shared by
/// the "Interfaces & routes" `vpn_tunnel_likelihood` heuristic
/// (`interface_rows::derive_assessment`) and the traffic counter's
/// tunnel-overlap classification (block T) — both must agree on what counts
/// as "this is a VPN adapter", or the double-counting fix could subtract
/// against a different notion of "tunnel" than what the GUI labels as one.
pub const VPN_TUNNEL_ADAPTER_MARKERS: &[&str] =
    &["vpn", "wireguard", "tunnel", "ppp", "tap", "tun", "openvpn"];

/// Whether `haystack` (any case) contains a VPN/tunnel marker. `MIB_IF_ROW2::
/// Type == IF_TYPE_TUNNEL` alone under-detects real VPN adapters: a
/// TAP-Windows adapter presents as plain Ethernet, and a wintun (WireGuard)
/// adapter presents as `IF_TYPE_PROP_VIRTUAL` — neither trips the raw-type
/// check, so callers that need to recognize a VPN adapter reliably should
/// combine the raw type with this name/description heuristic.
pub fn text_indicates_vpn_tunnel(haystack: &str) -> bool {
    let text = haystack.to_ascii_lowercase();
    VPN_TUNNEL_ADAPTER_MARKERS.iter().any(|m| text.contains(m))
}

/// Is this the host side of a LOCAL virtual-machine network — a hypervisor's
/// host-only / NAT / bridged adapter — as opposed to a tunnel?
///
/// The distinction matters because both live in RFC1918 space: a WireGuard link
/// is as much a `10.x` as a VirtualBox host-only network, and treating "private
/// address" as "local and safe" would hand a VPN's address range the exemption
/// meant for a virtual machine. So the two name sets decide, and the VPN one
/// wins ties: a TAP adapter is a tunnel even though a hypervisor may have
/// installed it.
pub fn is_virtual_machine_adapter(info: &AdapterInfo) -> bool {
    if matches!(info.interface_type, InterfaceType::Loopback) {
        return false;
    }
    names_indicate_virtual_machine_network(&info.description, &info.friendly_name)
}

/// Name-only twin of [`is_virtual_machine_adapter`], for callers that read the
/// adapter's text straight out of an OS query and never build an [`AdapterInfo`]
/// — the upstream-DNS enumeration is one. Same rule and same tie-break, so a
/// second notion of "this is a VM network" cannot drift into existence.
pub fn names_indicate_virtual_machine_network(description: &str, friendly_name: &str) -> bool {
    let names = format!("{description} {friendly_name}");
    if text_indicates_vpn_tunnel(&names) {
        return false;
    }
    description_matches_virtual_software(description)
        || description_matches_virtual_software(friendly_name)
}

// ── AdapterAvailability ───────────────────────────────────────────────────────

/// Availability classification of one network adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterAvailability {
    /// Interface up and holding an IPv4 address. Traffic can flow.
    ///
    /// A gateway is deliberately NOT required. A tunnel link (OpenVPN,
    /// WireGuard) routinely exposes none: it installs split-default routes via
    /// its peer instead of setting a gateway on the adapter, and the route
    /// coordinator derives that peer from the OS route table. Demanding a
    /// gateway here would classify a working tunnel as unusable and arm
    /// fail-closed against the very link the user routes through.
    Available,
    /// Interface up but no IPv4 address (e.g. DHCP pending or no lease).
    /// This is the **Fail-Closed signal**: secondary has no IP →
    /// traffic for secondary-bound rules must be blocked locally.
    PresentNoIp,
    /// Interface down or disconnected.
    PresentDown,
    /// Adapter not found in the system.
    Absent,
}

impl AdapterAvailability {
    /// Returns `true` when traffic can route through this adapter.
    pub fn is_usable(self) -> bool {
        matches!(self, Self::Available)
    }

    /// Returns `true` when Fail-Closed blocking must be applied.
    pub fn needs_fail_closed(self) -> bool {
        !matches!(self, Self::Available)
    }
}

/// Classify a single adapter's availability.
///
/// `None` means EXCLUDED FROM TRACKING (virtual, loopback, tunnel) — not
/// "unusable". The two readings are opposite in effect: a caller that treats
/// `None` as unusable tears down the routing for a tunnel that is working
/// perfectly well, which is the normal shape of a secondary link.
pub fn classify_availability(info: &AdapterInfo) -> Option<AdapterAvailability> {
    if is_virtual_adapter(info) {
        return None;
    }
    Some(match info.oper_status {
        IfOperStatus::Up if info.has_ipv4_address() => AdapterAvailability::Available,
        IfOperStatus::Up => AdapterAvailability::PresentNoIp,
        _ => AdapterAvailability::PresentDown,
    })
}

// ── AdapterAvailabilityChange ─────────────────────────────────────────────────

/// An availability change that has passed the debounce window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterAvailabilityChange {
    pub index: u32,
    pub stable_id: String,
    pub old: AdapterAvailability,
    pub new: AdapterAvailability,
}

// ── AdapterEventSource ────────────────────────────────────────────────────────

/// Abstraction over the source of adapter state information. Each OS backend
/// provides its own concrete source (Windows: polling `GetAdaptersAddresses`
/// plus `NotifyIpInterfaceChange` push; Linux/macOS: their own enumeration).
/// Tests inject [`MockAdapterEventSource`].
pub trait AdapterEventSource: Send + Sync {
    /// Enumerate all adapters with their current state.
    fn enumerate_all(&self) -> Result<Vec<AdapterInfo>, PlatformError>;
}

/// Configurable mock source for tests.
pub struct MockAdapterEventSource {
    pub adapters: std::sync::Mutex<Vec<AdapterInfo>>,
}

// Test-only mock: `Mutex::lock().unwrap()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl MockAdapterEventSource {
    pub fn new() -> Self {
        Self {
            adapters: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn set(&self, infos: Vec<AdapterInfo>) {
        *self.adapters.lock().unwrap() = infos;
    }
}

impl Default for MockAdapterEventSource {
    fn default() -> Self {
        Self::new()
    }
}

// Test-only mock: lock-poisoning `unwrap()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl AdapterEventSource for MockAdapterEventSource {
    fn enumerate_all(&self) -> Result<Vec<AdapterInfo>, PlatformError> {
        Ok(self.adapters.lock().unwrap().clone())
    }
}

// ── AdapterMonitor ────────────────────────────────────────────────────────────

/// Polls the `AdapterEventSource`, applies debounce, and classifies
/// adapter availability.
///
/// ## Usage in service-runtime
///
/// ```rust,ignore
/// let monitor = AdapterMonitor::new(source, 500 /* debounce_ms */);
/// // On each supervisor tick:
/// let changes = monitor.update(now_ms);
/// // Use changes to update RouteAvailabilitySnapshot.
/// ```
pub struct AdapterMonitor {
    source: Arc<dyn AdapterEventSource>,
    debounce_ms: u64,
    // Per-adapter debounce state, keyed by ifindex.
    confirmed: std::sync::Mutex<HashMap<u32, ConfirmedEntry>>,
    pending: std::sync::Mutex<HashMap<u32, (AdapterAvailability, u64)>>,
    // Which identity each connection name last carried, and which name each
    // identity last answered to — see `note_identity_drift`.
    identity_seen: std::sync::Mutex<IdentityLedger>,
}

/// Bounded name-to-identity memory behind [`AdapterMonitor::note_identity_drift`].
///
/// Two maps rather than one because the two drifts are different facts and a
/// reader needs to know WHICH happened. Bounded and insertion-ordered: a client
/// that creates a fresh adapter per connect would otherwise grow this without
/// end, and the oldest pairing is the one least likely to still matter.
#[derive(Default)]
struct IdentityLedger {
    id_of_name: HashMap<String, String>,
    name_of_id: HashMap<String, String>,
    order: std::collections::VecDeque<(String, String)>,
}

/// How many (name, identity) pairings the drift ledger remembers.
const IDENTITY_LEDGER_CAP: usize = 64;

impl IdentityLedger {
    /// Record a pairing, evicting the oldest once the cap is reached.
    fn remember(&mut self, name: String, id: String) {
        let already = self.id_of_name.get(&name) == Some(&id);
        self.id_of_name.insert(name.clone(), id.clone());
        self.name_of_id.insert(id.clone(), name.clone());
        if already {
            return;
        }
        self.order.push_back((name, id));
        while self.order.len() > IDENTITY_LEDGER_CAP {
            if let Some((old_name, old_id)) = self.order.pop_front() {
                // Only drop what still points at the evicted pairing: a name
                // reused under a newer identity must keep the newer one.
                if self.id_of_name.get(&old_name) == Some(&old_id) {
                    self.id_of_name.remove(&old_name);
                }
                if self.name_of_id.get(&old_id) == Some(&old_name) {
                    self.name_of_id.remove(&old_id);
                }
            }
        }
    }
}

/// One observed identity drift. Named rather than boolean because the two
/// directions call for opposite designs downstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityDrift {
    /// The connection name stayed, the identity behind it changed — a client
    /// that recreates its adapter. Keying on the identity splits history here.
    SameNameNewIdentity {
        name: String,
        was: String,
        now: String,
    },
    /// The identity stayed, the name changed — a rename, or a client version
    /// bump that relabels the same adapter. Keying on the name splits history
    /// here.
    SameIdentityNewName {
        id: String,
        was: String,
        now: String,
    },
}

#[derive(Clone)]
struct ConfirmedEntry {
    stable_id: String,
    availability: AdapterAvailability,
}

// `Mutex::lock().unwrap()` propagates lock poisoning as a panic (a poisoned
// debounce lock means a prior panic — unrecoverable), and the `confirmed`/
// `pending` map lookups are guarded by membership checks just above each call,
// so the `unwrap()`s here are invariant-safe.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl AdapterMonitor {
    pub fn new(source: Arc<dyn AdapterEventSource>, debounce_ms: u64) -> Self {
        Self {
            source,
            debounce_ms,
            confirmed: std::sync::Mutex::new(HashMap::new()),
            pending: std::sync::Mutex::new(HashMap::new()),
            identity_seen: std::sync::Mutex::new(IdentityLedger::default()),
        }
    }

    /// Report an adapter that came back wearing a different identity, or the
    /// same identity under a different name.
    ///
    /// Both halves are load-bearing and the product currently answers them
    /// differently in two places: route bindings anchor on the identity and
    /// heal by name, while the traffic ledger keys on the name outright. Which
    /// is right depends on a fact nobody measured — whether a tunnel adapter
    /// keeps its identity across a reconnect — so the monitor states it when it
    /// happens instead of leaving both designs to argue from assumption.
    ///
    /// Returns the drifts observed this call, so a test can assert on them
    /// without reading the log.
    fn note_identity_drift(&self, infos: &[AdapterInfo]) -> Vec<IdentityDrift> {
        let mut ledger = self.identity_seen.lock().unwrap();
        let mut drifts = Vec::new();
        for info in infos {
            let name = info.friendly_name.trim();
            let id = info.stable_id();
            // A nameless adapter carries no pairing worth remembering: the
            // whole question is what happens to the name and the id TOGETHER.
            if name.is_empty() || id.is_empty() {
                continue;
            }
            if let Some(previous) = ledger.id_of_name.get(name) {
                if previous != &id {
                    drifts.push(IdentityDrift::SameNameNewIdentity {
                        name: name.to_string(),
                        was: previous.clone(),
                        now: id.clone(),
                    });
                }
            }
            if let Some(previous) = ledger.name_of_id.get(&id) {
                if previous != name {
                    drifts.push(IdentityDrift::SameIdentityNewName {
                        id: id.clone(),
                        was: previous.clone(),
                        now: name.to_string(),
                    });
                }
            }
            ledger.remember(name.to_string(), id);
        }
        for drift in &drifts {
            match drift {
                IdentityDrift::SameNameNewIdentity { name, was, now } => tracing::info!(
                    target: "nrr::adapters",
                    adapter = %name, was = %was, now = %now,
                    "adapter kept its name and changed identity",
                ),
                IdentityDrift::SameIdentityNewName { id, was, now } => tracing::info!(
                    target: "nrr::adapters",
                    identity = %id, was = %was, now = %now,
                    "adapter kept its identity and was renamed",
                ),
            }
        }
        drifts
    }

    /// Poll the source and advance the debounce state machine.
    ///
    /// `now_ms` is a monotonic millisecond counter (wall clock or injected in
    /// tests). Returns changes whose debounce window has elapsed.
    pub fn update(&self, now_ms: u64) -> Vec<AdapterAvailabilityChange> {
        let infos = match self.source.enumerate_all() {
            Ok(v) => v,
            Err(_) => return Vec::new(), // source unavailable — no changes
        };
        self.note_identity_drift(&infos);

        // Classify current state from the fresh enumeration.
        let mut current: HashMap<u32, (String, AdapterAvailability)> = HashMap::new();
        for info in &infos {
            if let Some(avail) = classify_availability(info) {
                current.insert(info.index, (info.stable_id(), avail));
            }
        }

        let mut confirmed = self.confirmed.lock().unwrap();
        let mut pending = self.pending.lock().unwrap();
        let mut changes = Vec::new();

        // Mark adapters that disappeared from the enumeration as Absent.
        let all_indices: Vec<u32> = confirmed.keys().copied().collect();
        for idx in all_indices {
            if !current.contains_key(&idx) {
                let entry = confirmed.get(&idx).unwrap().clone();
                if entry.availability != AdapterAvailability::Absent {
                    pending
                        .entry(idx)
                        .or_insert((AdapterAvailability::Absent, now_ms));
                }
            }
        }

        // Process current enumeration.
        for (&idx, (_stable_id, new_avail)) in &current {
            let confirmed_avail = confirmed
                .get(&idx)
                .map(|e| e.availability)
                .unwrap_or(AdapterAvailability::Absent);

            if *new_avail == confirmed_avail {
                // Stable — cancel any pending transition for this adapter.
                pending.remove(&idx);
                continue;
            }

            // State differs from confirmed — update or start debounce.
            match pending.get_mut(&idx) {
                Some((candidate, _first_seen)) if *candidate == *new_avail => {
                    // Same candidate still active — debounce ticking.
                }
                _ => {
                    // New candidate (or different candidate) — reset timer.
                    pending.insert(idx, (*new_avail, now_ms));
                }
            }
        }

        // Emit any pending transitions whose quiet period has elapsed.
        let expired: Vec<u32> = pending
            .iter()
            .filter(|(_, (_, first_ms))| now_ms.saturating_sub(*first_ms) >= self.debounce_ms)
            .map(|(&idx, _)| idx)
            .collect();

        for idx in expired {
            if let Some((new_avail, _)) = pending.remove(&idx) {
                let old = confirmed
                    .get(&idx)
                    .map(|e| e.availability)
                    .unwrap_or(AdapterAvailability::Absent);

                let stable_id = current
                    .get(&idx)
                    .map(|(id, _)| id.clone())
                    .or_else(|| confirmed.get(&idx).map(|e| e.stable_id.clone()))
                    .unwrap_or_default();

                confirmed.insert(
                    idx,
                    ConfirmedEntry {
                        stable_id: stable_id.clone(),
                        availability: new_avail,
                    },
                );

                changes.push(AdapterAvailabilityChange {
                    index: idx,
                    stable_id,
                    old,
                    new: new_avail,
                });
            }
        }

        changes
    }

    /// Synchronous snapshot of currently confirmed availability for a set of
    /// adapter indices. Returns `Absent` for indices not yet confirmed.
    pub fn availability_for(&self, index: u32) -> AdapterAvailability {
        self.confirmed
            .lock()
            .unwrap()
            .get(&index)
            .map(|e| e.availability)
            .unwrap_or(AdapterAvailability::Absent)
    }

    /// Force an immediate re-enumeration, bypassing the debounce window.
    /// Used after sleep/resume to quickly re-establish state.
    /// Returns all adapters that changed compared to last confirmed state.
    pub fn force_refresh(&self, _now_ms: u64) -> Vec<AdapterAvailabilityChange> {
        // Clear any pending debounce state.
        self.pending.lock().unwrap().clear();

        let infos = match self.source.enumerate_all() {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };

        let mut current: HashMap<u32, (String, AdapterAvailability)> = HashMap::new();
        for info in &infos {
            if let Some(avail) = classify_availability(info) {
                current.insert(info.index, (info.stable_id(), avail));
            }
        }

        let mut confirmed = self.confirmed.lock().unwrap();
        let mut changes = Vec::new();

        // Emit changes for all adapters that differ from confirmed state.
        for (&idx, (stable_id, new_avail)) in &current {
            let old = confirmed
                .get(&idx)
                .map(|e| e.availability)
                .unwrap_or(AdapterAvailability::Absent);
            if *new_avail != old {
                confirmed.insert(
                    idx,
                    ConfirmedEntry {
                        stable_id: stable_id.clone(),
                        availability: *new_avail,
                    },
                );
                changes.push(AdapterAvailabilityChange {
                    index: idx,
                    stable_id: stable_id.clone(),
                    old,
                    new: *new_avail,
                });
            }
        }

        // Emit Absent for adapters that disappeared.
        let gone: Vec<u32> = confirmed
            .keys()
            .filter(|&&k| !current.contains_key(&k))
            .copied()
            .collect();
        for idx in gone {
            if let Some(entry) = confirmed.remove(&idx) {
                if entry.availability != AdapterAvailability::Absent {
                    changes.push(AdapterAvailabilityChange {
                        index: idx,
                        stable_id: entry.stable_id,
                        old: entry.availability,
                        new: AdapterAvailability::Absent,
                    });
                }
            }
        }

        changes
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn adapter(
        idx: u32,
        name: &str,
        desc: &str,
        itype: InterfaceType,
        status: IfOperStatus,
        ips: Vec<Ipv4Addr>,
        gws: Vec<Ipv4Addr>,
    ) -> AdapterInfo {
        AdapterInfo {
            index: idx,
            adapter_name: name.to_string(),
            description: desc.to_string(),
            friendly_name: desc.to_string(),
            mac: Some([0xAA, 0xBB, 0xCC, 0, 0, idx as u8]),
            interface_type: itype,
            oper_status: status,
            ipv4_addresses: ips,
            gateways: gws,
        }
    }

    /// A tunnel adapter with NO MAC, so `stable_id()` falls back to the GUID —
    /// the shape a VPN client actually presents, and the only shape where the
    /// identity question has two possible answers.
    fn tun(idx: u32, guid: &str, name: &str) -> AdapterInfo {
        AdapterInfo {
            index: idx,
            adapter_name: guid.to_string(),
            description: "TAP-Windows Adapter V9".to_string(),
            friendly_name: name.to_string(),
            mac: None,
            interface_type: InterfaceType::Tunnel,
            oper_status: IfOperStatus::Up,
            ipv4_addresses: vec![Ipv4Addr::new(10, 8, 0, 2)],
            gateways: vec![Ipv4Addr::new(10, 8, 0, 1)],
        }
    }

    fn monitor_with(source: Arc<MockAdapterEventSource>) -> AdapterMonitor {
        AdapterMonitor::new(source, 0)
    }

    #[test]
    fn an_adapter_that_keeps_its_name_and_changes_identity_is_reported() {
        let source = Arc::new(MockAdapterEventSource::new());
        let monitor = monitor_with(Arc::clone(&source));
        source.set(vec![tun(30, "{OLD-GUID}", "swiftvpn")]);
        assert!(
            monitor
                .note_identity_drift(&source.enumerate_all().unwrap())
                .is_empty(),
            "the first sighting establishes the pairing, it does not drift from anything"
        );

        // Reconnect: same connection name, adapter recreated under a new GUID.
        source.set(vec![tun(31, "{NEW-GUID}", "swiftvpn")]);
        let drifts = monitor.note_identity_drift(&source.enumerate_all().unwrap());
        assert_eq!(
            drifts,
            vec![IdentityDrift::SameNameNewIdentity {
                name: "swiftvpn".to_string(),
                was: "{OLD-GUID}".to_string(),
                now: "{NEW-GUID}".to_string(),
            }]
        );
    }

    #[test]
    fn an_adapter_that_keeps_its_identity_and_is_renamed_is_reported() {
        let source = Arc::new(MockAdapterEventSource::new());
        let monitor = monitor_with(Arc::clone(&source));
        source.set(vec![tun(30, "{SAME-GUID}", "swiftvpn v2")]);
        monitor.note_identity_drift(&source.enumerate_all().unwrap());

        source.set(vec![tun(30, "{SAME-GUID}", "swiftvpn v3")]);
        let drifts = monitor.note_identity_drift(&source.enumerate_all().unwrap());
        assert_eq!(
            drifts,
            vec![IdentityDrift::SameIdentityNewName {
                id: "{SAME-GUID}".to_string(),
                was: "swiftvpn v2".to_string(),
                now: "swiftvpn v3".to_string(),
            }]
        );
    }

    #[test]
    fn a_steady_adapter_never_reports_drift() {
        // Positive control for the two above: the detector must be silent on
        // the case that happens every tick, or its reports mean nothing.
        let source = Arc::new(MockAdapterEventSource::new());
        let monitor = monitor_with(Arc::clone(&source));
        source.set(vec![tun(30, "{SAME-GUID}", "swiftvpn")]);
        for _ in 0..5 {
            assert!(monitor
                .note_identity_drift(&source.enumerate_all().unwrap())
                .is_empty());
        }
    }

    #[test]
    fn the_drift_ledger_stays_bounded() {
        let source = Arc::new(MockAdapterEventSource::new());
        let monitor = monitor_with(Arc::clone(&source));
        for i in 0..(IDENTITY_LEDGER_CAP as u32 * 3) {
            source.set(vec![tun(i, &format!("{{GUID-{i}}}"), &format!("link-{i}"))]);
            monitor.note_identity_drift(&source.enumerate_all().unwrap());
        }
        let ledger = monitor.identity_seen.lock().unwrap();
        assert!(ledger.order.len() <= IDENTITY_LEDGER_CAP);
        assert!(ledger.id_of_name.len() <= IDENTITY_LEDGER_CAP);
        assert!(ledger.name_of_id.len() <= IDENTITY_LEDGER_CAP);
    }

    fn eth_up_with_ip(idx: u32) -> AdapterInfo {
        adapter(
            idx,
            &format!("{{{idx}}}"),
            "Intel Ethernet",
            InterfaceType::Ethernet,
            IfOperStatus::Up,
            vec![Ipv4Addr::new(192, 168, 1, idx as u8)],
            vec![Ipv4Addr::new(192, 168, 1, 1)],
        )
    }

    fn eth_up_no_ip(idx: u32) -> AdapterInfo {
        adapter(
            idx,
            &format!("{{{idx}}}"),
            "Realtek WiFi",
            InterfaceType::Ethernet,
            IfOperStatus::Up,
            vec![],
            vec![],
        )
    }

    fn eth_down(idx: u32) -> AdapterInfo {
        adapter(
            idx,
            &format!("{{{idx}}}"),
            "Ethernet",
            InterfaceType::Ethernet,
            IfOperStatus::Down,
            vec![],
            vec![],
        )
    }

    fn loopback() -> AdapterInfo {
        adapter(
            1,
            "{LOOPBACK}",
            "Loopback",
            InterfaceType::Loopback,
            IfOperStatus::Up,
            vec![Ipv4Addr::new(127, 0, 0, 1)],
            vec![],
        )
    }

    fn hyper_v() -> AdapterInfo {
        adapter(
            2,
            "{HV}",
            "Hyper-V Virtual Ethernet",
            InterfaceType::Ethernet,
            IfOperStatus::Up,
            vec![Ipv4Addr::new(172, 16, 0, 1)],
            vec![Ipv4Addr::new(172, 16, 0, 254)],
        )
    }

    fn tunnel_vpn() -> AdapterInfo {
        adapter(
            3,
            "{VPN}",
            "WireGuard Tunnel",
            InterfaceType::Tunnel,
            IfOperStatus::Up,
            vec![Ipv4Addr::new(10, 0, 0, 2)],
            vec![Ipv4Addr::new(10, 0, 0, 1)],
        )
    }

    fn monitor(debounce: u64) -> (Arc<MockAdapterEventSource>, AdapterMonitor) {
        let src = Arc::new(MockAdapterEventSource::new());
        let mon = AdapterMonitor::new(Arc::clone(&src) as Arc<dyn AdapterEventSource>, debounce);
        (src, mon)
    }

    // ── classify_availability ─────────────────────────────────────────────

    #[test]
    fn available_adapter_classified_correctly() {
        let avail = classify_availability(&eth_up_with_ip(5)).unwrap();
        assert_eq!(avail, AdapterAvailability::Available);
    }

    #[test]
    fn up_with_no_ip_is_present_no_ip() {
        let avail = classify_availability(&eth_up_no_ip(5)).unwrap();
        assert_eq!(avail, AdapterAvailability::PresentNoIp);
    }

    #[test]
    fn down_adapter_is_present_down() {
        let avail = classify_availability(&eth_down(5)).unwrap();
        assert_eq!(avail, AdapterAvailability::PresentDown);
    }

    #[test]
    fn loopback_is_excluded() {
        assert!(classify_availability(&loopback()).is_none());
    }

    #[test]
    fn tunnel_is_excluded() {
        assert!(classify_availability(&tunnel_vpn()).is_none());
    }

    #[test]
    fn hyper_v_is_virtual_and_excluded() {
        assert!(is_virtual_adapter(&hyper_v()));
        assert!(classify_availability(&hyper_v()).is_none());
    }

    #[test]
    fn present_no_ip_needs_fail_closed() {
        assert!(AdapterAvailability::PresentNoIp.needs_fail_closed());
        assert!(!AdapterAvailability::Available.needs_fail_closed());
    }

    // ── AdapterMonitor debounce ───────────────────────────────────────────

    #[test]
    fn no_changes_emitted_within_debounce_window() {
        let (src, mon) = monitor(500);
        src.set(vec![eth_up_with_ip(5)]);
        let changes = mon.update(0);
        assert!(changes.is_empty(), "first poll must not emit immediately");
        let changes = mon.update(400); // 400ms < 500ms debounce
        assert!(changes.is_empty(), "within debounce window");
    }

    #[test]
    fn change_emitted_after_debounce_window() {
        let (src, mon) = monitor(500);
        src.set(vec![eth_up_with_ip(5)]);
        mon.update(0); // detect change
        let changes = mon.update(600); // 600ms > 500ms → emit
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].index, 5);
        assert_eq!(changes[0].new, AdapterAvailability::Available);
        assert_eq!(changes[0].old, AdapterAvailability::Absent);
    }

    #[test]
    fn rapid_toggle_resets_debounce_timer() {
        let (src, mon) = monitor(500);
        src.set(vec![eth_up_with_ip(5)]);
        mon.update(0); // detect → start timer

        // Change state again at t=300 → timer resets
        src.set(vec![eth_down(5)]);
        let changes = mon.update(300); // 300 < 500, and state changed again
        assert!(changes.is_empty(), "timer must reset on state change");

        // Now wait full 500ms from the reset (t=300+500=800)
        let changes = mon.update(800);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].new, AdapterAvailability::PresentDown);
    }

    #[test]
    fn stable_state_cancels_pending_transition() {
        let (src, mon) = monitor(500);
        src.set(vec![eth_up_with_ip(5)]);
        mon.update(0); // detect change, start debounce

        // Revert to "confirmed" state (Absent) before debounce elapses
        src.set(vec![]); // adapter disappeared
                         // But then it comes back right away
        src.set(vec![eth_up_with_ip(5)]);
        let changes = mon.update(100);
        // State matches confirmed (Absent → Available → ... Absent again?)
        // Actually after update(0) confirmed=Absent, pending=Available@0
        // At t=100: source=Available; pending.candidate=Available, timer still running
        // No emit yet
        assert!(changes.is_empty());
    }

    #[test]
    fn adapter_disappears_becomes_absent() {
        let (src, mon) = monitor(100);
        src.set(vec![eth_up_with_ip(5)]);
        mon.update(0);
        mon.update(200); // confirm Available

        // Now adapter disappears
        src.set(vec![]);
        mon.update(200); // detect disappearance
        let changes = mon.update(400); // 200ms after detection > 100ms debounce
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].new, AdapterAvailability::Absent);
    }

    #[test]
    fn multiple_adapters_tracked_independently() {
        let (src, mon) = monitor(100);
        src.set(vec![eth_up_with_ip(5), eth_up_with_ip(7)]);
        mon.update(0);
        let changes = mon.update(200);
        assert_eq!(changes.len(), 2);
    }

    #[test]
    fn secondary_no_ip_is_detected_as_present_no_ip() {
        let (src, mon) = monitor(100);
        src.set(vec![eth_up_no_ip(5)]);
        mon.update(0);
        let changes = mon.update(200);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].new, AdapterAvailability::PresentNoIp);
        assert!(changes[0].new.needs_fail_closed());
    }

    #[test]
    fn force_refresh_skips_debounce() {
        let (src, mon) = monitor(5000); // very long debounce
        src.set(vec![eth_up_with_ip(5)]);
        mon.update(0); // detect, start debounce (would need 5000ms)
                       // force_refresh skips the window
        let changes = mon.force_refresh(0);
        assert_eq!(changes.len(), 1, "force_refresh must bypass debounce");
    }

    #[test]
    fn availability_for_returns_absent_before_first_confirm() {
        let (_, mon) = monitor(100);
        assert_eq!(mon.availability_for(99), AdapterAvailability::Absent);
    }

    #[test]
    fn availability_for_returns_confirmed_state() {
        let (src, mon) = monitor(100);
        src.set(vec![eth_up_with_ip(5)]);
        mon.update(0);
        mon.update(200);
        assert_eq!(mon.availability_for(5), AdapterAvailability::Available);
    }

    // ── text_indicates_vpn_tunnel (block T Feature 1 strengthening) ─────────

    #[test]
    fn recognizes_common_vpn_adapter_strings() {
        // TAP-Windows presents its `Type` as plain Ethernet — only the name/
        // description text says "this is a VPN adapter".
        assert!(text_indicates_vpn_tunnel("TAP-Windows Adapter V9"));
        assert!(text_indicates_vpn_tunnel("WireGuard Tunnel"));
        assert!(text_indicates_vpn_tunnel("OpenVPN Data Channel Offload"));
        assert!(text_indicates_vpn_tunnel(
            "Local Area Connection* 9 (WAN Miniport PPP)"
        ));
        assert!(text_indicates_vpn_tunnel("My Company VPN"));
        // Case-insensitive.
        assert!(text_indicates_vpn_tunnel("wintun TUNNEL"));
    }

    #[test]
    fn ordinary_adapter_text_is_not_flagged() {
        assert!(!text_indicates_vpn_tunnel("Intel(R) Ethernet Connection"));
        assert!(!text_indicates_vpn_tunnel("Realtek Wi-Fi 6E"));
        assert!(!text_indicates_vpn_tunnel(""));
    }
}
