//! Neutral per-interface byte-counter port.
//!
//! Reads cumulative RX/TX octets per network interface. The mechanism is per-OS
//! (`GetIfTable2` / `MIB_IF_ROW2` on Windows, `/proc/net/dev` on Linux,
//! `if_data` on macOS); this module holds only the neutral value type and the
//! port trait. Reading a counter is O(number of adapters), independent of
//! traffic volume — the driver already maintains the tally, we only read it.
//!
//! ## Identity anchor
//!
//! Counters are keyed on the interface's **stable friendly name**, not its
//! GUID / LUID / ifindex. A VPN/TUN adapter rotates its GUID on every reconnect
//! while its name stays put, so the churning id is unusable as a ledger key.
//! `stable_name` carries that anchor; `display_name` is a UI hint only.

use crate::adapters::InterfaceType;
use crate::error::PlatformError;

// ── InterfaceCounters ─────────────────────────────────────────────────────────

/// One interface's cumulative octet counters plus the classification bits the
/// traffic accountant needs to bucket it (route the numbers by role / detect
/// tunnel / loopback / virtual).
///
/// `in_octets` / `out_octets` are cumulative since the interface came up (the
/// OS resets them on adapter re-up); the neutral `TrafficAccountant`
/// (`nrr-domain`) turns them into per-interval deltas with reset detection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceCounters {
    /// Stable identity anchor — the friendly name, NOT the churning GUID/LUID.
    pub stable_name: String,
    /// Human-readable label for display. Not an identity key.
    pub display_name: String,
    /// Interface type (Ethernet / Wireless / Loopback / Tunnel / Other).
    pub interface_type: InterfaceType,
    /// `true` for known virtual-adapter software (Hyper-V / WSL / Docker / …),
    /// computed by the backend via [`crate::adapters::is_virtual_adapter`].
    pub is_virtual: bool,
    /// `true` for a VPN/tunnel adapter (block T — feeds the tunnel-overlap
    /// double-counting fix in `nrr_domain::traffic_accountant`). Computed by
    /// the backend from the raw interface type OR a name/description keyword
    /// match — see [`crate::adapters::text_indicates_vpn_tunnel`]; the raw
    /// type alone under-detects (TAP-Windows presents as Ethernet, wintun as
    /// `IF_TYPE_PROP_VIRTUAL`).
    pub is_tunnel: bool,
    /// `true` when the interface is operationally up (passing traffic).
    pub is_up: bool,
    /// Cumulative octets received since the interface came up.
    pub in_octets: u64,
    /// Cumulative octets sent since the interface came up.
    pub out_octets: u64,
}

// ── InterfaceCounterSource ────────────────────────────────────────────────────

/// Port over the OS mechanism that reads per-interface octet counters.
///
/// Windows: `GetIfTable2`. Linux: `/proc/net/dev`. macOS: `getifaddrs` +
/// `if_data`. Tests inject [`MockInterfaceCounterSource`].
pub trait InterfaceCounterSource: Send + Sync {
    /// Snapshot every interface's current cumulative counters.
    fn read_counters(&self) -> Result<Vec<InterfaceCounters>, PlatformError>;
}

// ── Mock / Noop ───────────────────────────────────────────────────────────────

/// Configurable mock source for tests.
pub struct MockInterfaceCounterSource {
    pub counters: std::sync::Mutex<Vec<InterfaceCounters>>,
}

// Test-only mock: `Mutex::lock().unwrap()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl MockInterfaceCounterSource {
    pub fn new() -> Self {
        Self {
            counters: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn set(&self, counters: Vec<InterfaceCounters>) {
        *self.counters.lock().unwrap() = counters;
    }
}

impl Default for MockInterfaceCounterSource {
    fn default() -> Self {
        Self::new()
    }
}

// Test-only mock: lock-poisoning `unwrap()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl InterfaceCounterSource for MockInterfaceCounterSource {
    fn read_counters(&self) -> Result<Vec<InterfaceCounters>, PlatformError> {
        Ok(self.counters.lock().unwrap().clone())
    }
}

/// No-op source that reports no interfaces — used where an OS backend is not
/// wired yet (Linux/macOS scaffolding) so callers still compile and degrade.
pub struct NoopInterfaceCounterSource;

impl InterfaceCounterSource for NoopInterfaceCounterSource {
    fn read_counters(&self) -> Result<Vec<InterfaceCounters>, PlatformError> {
        Ok(Vec::new())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn counters(name: &str, in_o: u64, out_o: u64) -> InterfaceCounters {
        InterfaceCounters {
            stable_name: name.to_string(),
            display_name: name.to_string(),
            interface_type: InterfaceType::Ethernet,
            is_virtual: false,
            is_tunnel: false,
            is_up: true,
            in_octets: in_o,
            out_octets: out_o,
        }
    }

    #[test]
    fn mock_round_trips_set_counters() {
        let src = MockInterfaceCounterSource::new();
        src.set(vec![counters("eth0", 100, 50)]);
        let got = src.read_counters().expect("read");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].stable_name, "eth0");
        assert_eq!(got[0].in_octets, 100);
        assert_eq!(got[0].out_octets, 50);
    }

    #[test]
    fn noop_reports_no_interfaces() {
        let src = NoopInterfaceCounterSource;
        assert!(src.read_counters().expect("read").is_empty());
    }
}
