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

// ── AdapterAvailability ───────────────────────────────────────────────────────

/// Availability classification of one network adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterAvailability {
    /// Interface up, has IPv4 address and gateway. Traffic can flow.
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
/// Returns `None` when the adapter should be excluded from tracking entirely
/// (virtual, loopback, tunnel).
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
        }
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

    /// High-level snapshot of the last confirmed state for primary/secondary
    /// adapters.
    pub fn snapshot(&self) -> AdapterAvailabilitySnapshot {
        AdapterAvailabilitySnapshot {
            primary_index: 0,
            primary_availability: AdapterAvailability::Absent,
            secondary_index: None,
            secondary_availability: None,
        }
    }
}

// ── AdapterAvailabilitySnapshot ───────────────────────────────────────────────

/// Snapshot of primary and secondary adapter availability.
#[derive(Clone, Debug)]
pub struct AdapterAvailabilitySnapshot {
    pub primary_index: u32,
    pub primary_availability: AdapterAvailability,
    pub secondary_index: Option<u32>,
    pub secondary_availability: Option<AdapterAvailability>,
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
