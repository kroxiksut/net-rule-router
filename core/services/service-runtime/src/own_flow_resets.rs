//! Connections the service itself tore down, remembered briefly.
//!
//! The stack reports the close of a connection the service reset exactly like
//! one it gave up on, so without this memory the log would say the network
//! killed a connection we cut. Written once per reset batch, read only when a
//! close is about to be blamed on the far side.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use nrr_platform_api::fake_ip::stale_flows::{EstablishedFlow, StaleFlowReset};

use crate::boot_clock::BootInstant;

/// Far longer than a close takes to be observed after the reset.
const ENTRY_TTL: Duration = Duration::from_secs(120);
/// A reset batch past this keeps its newest connections.
const MAX_ENTRIES: usize = 2048;

type FlowKey = (SocketAddr, SocketAddr);

/// A dual-stack socket to an IPv4 host is the IPv4 connection it carries.
fn key(local: SocketAddr, remote: SocketAddr) -> FlowKey {
    let canonical = |a: SocketAddr| SocketAddr::new(a.ip().to_canonical(), a.port());
    (canonical(local), canonical(remote))
}

#[derive(Debug, Default)]
pub struct OwnFlowResets {
    entries: Mutex<HashMap<FlowKey, BootInstant>>,
}

impl OwnFlowResets {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The service is about to tear `flows` down. Recorded first, because the
    /// stack may report the close before the teardown call returns.
    pub fn record(&self, flows: &[EstablishedFlow]) {
        self.record_at(flows, BootInstant::now());
    }

    /// Tear `flows` down, remembering them here as ours.
    pub fn reset(&self, reset: &dyn StaleFlowReset, flows: &[EstablishedFlow]) -> usize {
        self.record(flows);
        reset.reset_established(flows)
    }

    /// Did the service tear this connection down a moment ago?
    #[must_use]
    pub fn contains(&self, local: SocketAddr, remote: SocketAddr) -> bool {
        self.contains_at(local, remote, BootInstant::now())
    }

    fn record_at(&self, flows: &[EstablishedFlow], now: BootInstant) {
        if flows.is_empty() {
            return;
        }
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.retain(|_, at| now.saturating_duration_since(*at) < ENTRY_TTL);
        for flow in flows {
            entries.insert(key(flow.local, flow.remote), now);
        }
        let excess = entries.len().saturating_sub(MAX_ENTRIES);
        if excess == 0 {
            return;
        }
        // One batch shares one stamp, so which of its own survive is arbitrary.
        let mut by_age: Vec<(BootInstant, FlowKey)> =
            entries.iter().map(|(k, at)| (*at, *k)).collect();
        by_age.select_nth_unstable(excess - 1);
        for (_, k) in &by_age[..excess] {
            entries.remove(k);
        }
    }

    fn contains_at(&self, local: SocketAddr, remote: SocketAddr, now: BootInstant) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&key(local, remote))
            .is_some_and(|at| now.saturating_duration_since(*at) < ENTRY_TTL)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

/// The one memory every teardown path of the service writes to.
#[must_use]
pub fn global_own_flow_resets() -> Arc<OwnFlowResets> {
    static GLOBAL: OnceLock<Arc<OwnFlowResets>> = OnceLock::new();
    Arc::clone(GLOBAL.get_or_init(|| Arc::new(OwnFlowResets::new())))
}

/// Tear `flows` down, remembering them as ours. Every per-connection teardown
/// of the service goes through here.
pub fn reset_as_ours(reset: &dyn StaleFlowReset, flows: &[EstablishedFlow]) -> usize {
    global_own_flow_resets().reset(reset, flows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn flow(port: u16) -> EstablishedFlow {
        EstablishedFlow {
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), port),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 3389),
            owner: None,
            pid: None,
            image: None,
        }
    }

    #[test]
    fn a_torn_down_connection_is_ours_for_a_while_and_then_forgotten() {
        let ledger = OwnFlowResets::new();
        let t0 = BootInstant::now();
        ledger.record_at(&[flow(50_000)], t0);
        let f = flow(50_000);
        assert!(ledger.contains_at(f.local, f.remote, t0 + Duration::from_secs(1)));
        assert!(!ledger.contains_at(f.local, f.remote, t0 + ENTRY_TTL));
        let other = flow(50_001);
        assert!(!ledger.contains_at(other.local, other.remote, t0));
    }

    /// The table lists a dual-stack socket by its mapped address; the stack may
    /// report the same connection as plain IPv4.
    #[test]
    fn a_mapped_address_is_the_same_connection() {
        let ledger = OwnFlowResets::new();
        let t0 = BootInstant::now();
        let mapped = |a: SocketAddr| match a.ip() {
            IpAddr::V4(v4) => SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), a.port()),
            IpAddr::V6(_) => a,
        };
        let f = flow(50_000);
        ledger.record_at(
            &[EstablishedFlow {
                local: mapped(f.local),
                remote: mapped(f.remote),
                ..f.clone()
            }],
            t0,
        );
        assert!(ledger.contains_at(f.local, f.remote, t0));
        assert!(!ledger.contains_at(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 50_000),
            f.remote,
            t0
        ));
    }

    /// A tunnel coming up resets every connection steered onto it at once;
    /// the memory of it stays bounded and keeps the latest batch.
    #[test]
    fn a_reset_storm_stays_within_the_cap_and_keeps_the_newest() {
        let ledger = OwnFlowResets::new();
        let t0 = BootInstant::now();
        let old: Vec<EstablishedFlow> = (0..MAX_ENTRIES as u16).map(flow).collect();
        ledger.record_at(&old, t0);
        let newest: Vec<EstablishedFlow> = (0..100).map(|p| flow(60_000 + p)).collect();
        let later = t0 + Duration::from_secs(5);
        ledger.record_at(&newest, later);
        assert!(ledger.len() <= MAX_ENTRIES);
        assert!(newest
            .iter()
            .all(|f| ledger.contains_at(f.local, f.remote, later)));
    }
}
