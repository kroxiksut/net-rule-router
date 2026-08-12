//! Keep a user-confirmed VPN client's own traffic off the relay's secondary
//! egress.
//!
//! A VPN client's connections ARE the tunnel's transport. Carrying one over the
//! secondary link means carrying the tunnel through itself: while the adapter is
//! coming up the dialer's source policy refuses (correctly — dialing would leak
//! via the primary), so the client's own connectivity/external-address probe
//! fails on every reconnect — observed as refusals clustered one-for-one on
//! the adapter's unavailable windows.
//!
//! So when a relayed flow belongs to a confirmed VPN client, it leaves over the
//! PRIMARY link — direct, which is the only way a tunnel can be established in
//! the first place.
//!
//! # Why the verdict is per-FLOW, not per-hostname
//!
//! Overriding by hostname would be cheaper (one classification per host, like
//! the self-heal exclusion set), but it would mean a host the user routed to the
//! secondary could silently egress the primary for EVERY process merely because
//! a VPN client once touched it — a leak. Keying on the flow's owning process
//! keeps the exemption exactly as wide as its justification: this process's
//! traffic, because this process is the link itself.
//!
//! # Hot path
//!
//! [`RelayCore::decide`](super::relay::RelayCore::decide) runs on the stack's
//! single poll thread, so the owner lookup — a connection-table read plus a
//! process query — must not be paid per flow unconditionally. Three guards, in
//! order of cost:
//!
//! 1. nothing confirmed → one relaxed atomic load, and that is the whole cost
//!    for every user who never confirmed a client;
//! 2. the flow is already leaving over the primary → the override cannot change
//!    anything, so nothing is looked up;
//! 3. a minimum interval between lookups bounds the worst case (a burst of new
//!    flows) to a few probes per second. A skipped probe is not a failure: the
//!    flow keeps today's routing, and the client's next attempt gets a probe.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nrr_platform_api::FlowOwnerLookup;

use crate::vpn_client_registry::ConfirmedVpnClients;

/// Asked, per relayed flow, whether the flow belongs to a confirmed VPN client.
pub trait VpnClientFlowBypass: Send + Sync {
    /// `client` is the application's own endpoint, `fake` the pool address it
    /// dialed — the same pair the OS connection table is keyed by.
    fn owned_by_confirmed_client(&self, client: SocketAddr, fake: SocketAddr) -> bool;
}

/// The inert default: nothing is ever bypassed (tests, and any composition that
/// has no owner lookup).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoVpnClientBypass;

impl VpnClientFlowBypass for NoVpnClientBypass {
    fn owned_by_confirmed_client(&self, _client: SocketAddr, _fake: SocketAddr) -> bool {
        false
    }
}

/// Default floor between two owner lookups. A VPN client opens its probe flows
/// seconds apart, so it is never the one throttled; a browser opening a burst of
/// flows pays at most one lookup per interval.
pub const DEFAULT_MIN_PROBE_INTERVAL: Duration = Duration::from_millis(20);

/// Production [`VpnClientFlowBypass`]: names the flow's owner through the OS
/// connection table and matches it against the user-confirmed set.
pub struct OwnerLookupVpnClientBypass {
    owner: Arc<dyn FlowOwnerLookup>,
    confirmed: Arc<ConfirmedVpnClients>,
    min_probe_interval: Duration,
    /// Monotonic base plus the elapsed-millis stamp of the last probe. An
    /// `Instant` cannot live in an atomic, so the pair is: `started` (fixed) and
    /// `last_probe_ms` (relative). `u64::MAX` means "never probed".
    started: Instant,
    last_probe_ms: AtomicU64,
}

impl OwnerLookupVpnClientBypass {
    #[must_use]
    pub fn new(owner: Arc<dyn FlowOwnerLookup>, confirmed: Arc<ConfirmedVpnClients>) -> Self {
        Self {
            owner,
            confirmed,
            min_probe_interval: DEFAULT_MIN_PROBE_INTERVAL,
            started: Instant::now(),
            last_probe_ms: AtomicU64::new(u64::MAX),
        }
    }

    /// Override the rate-limit floor. Builder-style; tests use [`Duration::ZERO`]
    /// so every call probes.
    #[must_use]
    pub fn with_min_probe_interval(mut self, interval: Duration) -> Self {
        self.min_probe_interval = interval;
        self
    }

    /// Claim the right to run one lookup now, or decline because the previous
    /// one was too recent. Lock-free: a lost race just means the other caller
    /// probes and this one does not.
    fn claim_probe_slot(&self) -> bool {
        if self.min_probe_interval.is_zero() {
            return true;
        }
        let now_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let floor = u64::try_from(self.min_probe_interval.as_millis()).unwrap_or(u64::MAX);
        let last = self.last_probe_ms.load(Ordering::Relaxed);
        if last != u64::MAX && now_ms.saturating_sub(last) < floor {
            return false;
        }
        self.last_probe_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }
}

impl VpnClientFlowBypass for OwnerLookupVpnClientBypass {
    fn owned_by_confirmed_client(&self, client: SocketAddr, fake: SocketAddr) -> bool {
        if !self.confirmed.is_armed() || !self.claim_probe_slot() {
            return false;
        }
        let Some(image) = self.owner.owner_image_name(client, fake) else {
            return false;
        };
        let matched = self.confirmed.matches_image(&image);
        if matched {
            tracing::debug!(
                target: "nrr::fake-ip",
                image = %image,
                "relayed flow belongs to a confirmed VPN client — routing it over the primary link, never the tunnel it is establishing",
            );
        }
        matched
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::MockFlowOwnerLookup;

    const HIDEMY: &str = r"C:\Program Files\hidemy.name VPN 3.0\hidemy.name VPN 3.0.exe";

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("addr")
    }

    fn bypass(
        owner: Arc<dyn FlowOwnerLookup>,
        confirmed: Arc<ConfirmedVpnClients>,
    ) -> OwnerLookupVpnClientBypass {
        OwnerLookupVpnClientBypass::new(owner, confirmed).with_min_probe_interval(Duration::ZERO)
    }

    #[test]
    fn a_confirmed_client_flow_is_bypassed() {
        let client = addr("10.88.1.41:51000");
        let fake = addr("198.18.0.7:443");
        let owner = MockFlowOwnerLookup::new();
        owner.set_owner(client, fake, "hidemy.name vpn 3.0.exe");
        let confirmed = Arc::new(ConfirmedVpnClients::new());
        confirmed.publish("S-1-5-21-1", &[HIDEMY.to_string()]);

        let gate = bypass(Arc::new(owner), confirmed);
        assert!(gate.owned_by_confirmed_client(client, fake));
    }

    #[test]
    fn an_ordinary_process_is_not_bypassed() {
        let client = addr("10.88.1.41:51001");
        let fake = addr("198.18.0.8:443");
        let owner = MockFlowOwnerLookup::new();
        owner.set_owner(client, fake, "chrome.exe");
        let confirmed = Arc::new(ConfirmedVpnClients::new());
        confirmed.publish("S-1-5-21-1", &[HIDEMY.to_string()]);

        let gate = bypass(Arc::new(owner), confirmed);
        assert!(!gate.owned_by_confirmed_client(client, fake));
    }

    #[test]
    fn a_vpn_named_process_the_user_never_confirmed_is_not_bypassed() {
        // The exemption keys on the user's confirmation, NOT on the `looks_like_vpn`
        // keyword heuristic — a process is not handed a way around our routing
        // just for having "vpn" in its name.
        let client = addr("10.88.1.41:51002");
        let fake = addr("198.18.0.9:443");
        let owner = MockFlowOwnerLookup::new();
        owner.set_owner(client, fake, "somevpn.exe");
        let confirmed = Arc::new(ConfirmedVpnClients::new());
        confirmed.publish("S-1-5-21-1", &[HIDEMY.to_string()]);

        let gate = bypass(Arc::new(owner), confirmed);
        assert!(!gate.owned_by_confirmed_client(client, fake));
    }

    #[test]
    fn an_unarmed_registry_never_looks_the_owner_up() {
        struct PanickingLookup;
        impl FlowOwnerLookup for PanickingLookup {
            fn owner_image_name(&self, _l: SocketAddr, _r: SocketAddr) -> Option<String> {
                panic!("the unarmed hot path must not read the connection table");
            }
        }
        let gate = bypass(
            Arc::new(PanickingLookup),
            Arc::new(ConfirmedVpnClients::new()),
        );
        assert!(!gate.owned_by_confirmed_client(addr("10.88.1.41:51003"), addr("198.18.0.10:443")));
    }

    #[test]
    fn an_unknown_owner_keeps_todays_routing() {
        let confirmed = Arc::new(ConfirmedVpnClients::new());
        confirmed.publish("S-1-5-21-1", &[HIDEMY.to_string()]);
        // No entries → the lookup answers None (the row vanished / no rights).
        let gate = bypass(Arc::new(MockFlowOwnerLookup::new()), confirmed);
        assert!(!gate.owned_by_confirmed_client(addr("10.88.1.41:51004"), addr("198.18.0.11:443")));
    }

    #[test]
    fn the_rate_limit_declines_a_second_probe_inside_the_window() {
        let client = addr("10.88.1.41:51005");
        let fake = addr("198.18.0.12:443");
        let owner = MockFlowOwnerLookup::new();
        owner.set_owner(client, fake, "hidemy.name vpn 3.0.exe");
        let confirmed = Arc::new(ConfirmedVpnClients::new());
        confirmed.publish("S-1-5-21-1", &[HIDEMY.to_string()]);
        // A very long floor makes the second call deterministically declined.
        let gate = OwnerLookupVpnClientBypass::new(Arc::new(owner), confirmed)
            .with_min_probe_interval(Duration::from_secs(3600));

        assert!(gate.owned_by_confirmed_client(client, fake));
        assert!(
            !gate.owned_by_confirmed_client(client, fake),
            "a declined probe falls back to today's routing rather than blocking the poll thread",
        );
    }
}
