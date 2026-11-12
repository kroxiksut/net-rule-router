//! A confirmed tunnel client's TCP transport leaves over its user's main link.
//! Authorization belongs to one authenticated flow, never a hostname or UDP bind.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nrr_platform_api::{AppPathResolver, FlowOwnerLookup};

use crate::vpn_client_registry::ConfirmedVpnClients;

/// Asked, per relayed flow, whether the flow belongs to a confirmed VPN client.
pub trait VpnClientFlowBypass: Send + Sync {
    /// `client` is the application's own endpoint, `fake` the pool address it
    /// dialed — the same pair the OS connection table is keyed by.
    fn owned_by_confirmed_client(
        &self,
        client: SocketAddr,
        fake: SocketAddr,
        principal: &str,
        allow_service_owner: bool,
    ) -> bool;
}

/// The inert default: nothing is ever bypassed (tests, and any composition that
/// has no owner lookup).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoVpnClientBypass;

impl VpnClientFlowBypass for NoVpnClientBypass {
    fn owned_by_confirmed_client(&self, _: SocketAddr, _: SocketAddr, _: &str, _: bool) -> bool {
        false
    }
}

/// Bound process-table reads on the shared packet-processing thread.
pub const DEFAULT_MIN_PROBE_INTERVAL: Duration = Duration::from_millis(20);

/// Production [`VpnClientFlowBypass`]: names the flow's owner through the OS
/// connection table and matches it against the user-confirmed set.
pub struct OwnerLookupVpnClientBypass {
    owner: Arc<dyn FlowOwnerLookup>,
    confirmed: Arc<ConfirmedVpnClients>,
    service_programs: Option<Arc<dyn AppPathResolver>>,
    min_probe_interval: Duration,
    /// `u64::MAX` means no probe has claimed the monotonic clock yet.
    started: Instant,
    last_probe_ms: AtomicU64,
}

impl OwnerLookupVpnClientBypass {
    /// Service identities qualify only where the platform verifies a protected install.
    #[must_use]
    pub fn with_service_programs(mut self, programs: Arc<dyn AppPathResolver>) -> Self {
        self.service_programs = Some(programs);
        self
    }

    #[must_use]
    pub fn new(owner: Arc<dyn FlowOwnerLookup>, confirmed: Arc<ConfirmedVpnClients>) -> Self {
        Self {
            owner,
            confirmed,
            service_programs: None,
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

    /// A lost race leaves the existing route in force.
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
    fn owned_by_confirmed_client(
        &self,
        client: SocketAddr,
        fake: SocketAddr,
        principal: &str,
        allow_service_owner: bool,
    ) -> bool {
        if principal.is_empty() || !self.confirmed.is_armed() || !self.claim_probe_slot() {
            return false;
        }
        let Some((owner, image)) = self.owner.owner_identity(client, fake) else {
            return false;
        };
        if !self.confirmed.matches_path_for(principal, &image) {
            return false;
        }
        let matched = owner.eq_ignore_ascii_case(principal)
            || (allow_service_owner
                && nrr_platform_api::types::is_service_account_sid(&owner)
                && self.service_programs.as_ref().is_some_and(|programs| {
                    programs.is_protected_install(std::path::Path::new(&image))
                }));
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

    const VPN_CLIENT: &str = r"C:\Program Files\ExampleVPN 3.0\examplevpn 3.0.exe";
    const PRINCIPAL: &str = "S-1-5-21-1";

    struct IdentityOwner(&'static str);

    impl FlowOwnerLookup for IdentityOwner {
        fn owner_identity(&self, _: SocketAddr, _: SocketAddr) -> Option<(String, String)> {
            Some((PRINCIPAL.into(), self.0.into()))
        }

        fn owner_image_name(&self, _: SocketAddr, _: SocketAddr) -> Option<String> {
            panic!("authorization must use one authenticated identity");
        }
    }

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
        let owner = IdentityOwner(VPN_CLIENT);
        let confirmed = Arc::new(ConfirmedVpnClients::new());
        confirmed.publish("S-1-5-21-1", &[VPN_CLIENT.to_string()]);

        let gate = bypass(Arc::new(owner), confirmed);
        assert!(gate.owned_by_confirmed_client(client, fake, PRINCIPAL, false));
    }

    #[test]
    fn an_ordinary_process_is_not_bypassed() {
        let client = addr("10.88.1.41:51001");
        let fake = addr("198.18.0.8:443");
        let owner = IdentityOwner(r"C:\Program Files\Browser\chrome.exe");
        let confirmed = Arc::new(ConfirmedVpnClients::new());
        confirmed.publish("S-1-5-21-1", &[VPN_CLIENT.to_string()]);

        let gate = bypass(Arc::new(owner), confirmed);
        assert!(!gate.owned_by_confirmed_client(client, fake, PRINCIPAL, false));
    }

    #[test]
    fn a_vpn_named_process_the_user_never_confirmed_is_not_bypassed() {
        // A VPN-looking name alone authorizes nothing.
        let client = addr("10.88.1.41:51002");
        let fake = addr("198.18.0.9:443");
        let owner = IdentityOwner(r"C:\Program Files\Other\somevpn.exe");
        let confirmed = Arc::new(ConfirmedVpnClients::new());
        confirmed.publish("S-1-5-21-1", &[VPN_CLIENT.to_string()]);

        let gate = bypass(Arc::new(owner), confirmed);
        assert!(!gate.owned_by_confirmed_client(client, fake, PRINCIPAL, false));
    }

    #[test]
    fn an_unarmed_registry_never_looks_the_owner_up() {
        struct PanickingLookup;
        impl FlowOwnerLookup for PanickingLookup {
            fn owner_identity(&self, _: SocketAddr, _: SocketAddr) -> Option<(String, String)> {
                panic!("the unarmed hot path must not read the connection table");
            }

            fn owner_image_name(&self, _l: SocketAddr, _r: SocketAddr) -> Option<String> {
                panic!("the unarmed hot path must not read the connection table");
            }
        }
        let gate = bypass(
            Arc::new(PanickingLookup),
            Arc::new(ConfirmedVpnClients::new()),
        );
        assert!(!gate.owned_by_confirmed_client(
            addr("10.88.1.41:51003"),
            addr("198.18.0.10:443"),
            PRINCIPAL,
            false
        ));
    }

    #[test]
    fn an_unknown_owner_keeps_todays_routing() {
        let confirmed = Arc::new(ConfirmedVpnClients::new());
        confirmed.publish("S-1-5-21-1", &[VPN_CLIENT.to_string()]);
        // No entries → the lookup answers None (the row vanished / no rights).
        let gate = bypass(Arc::new(MockFlowOwnerLookup::new()), confirmed);
        assert!(!gate.owned_by_confirmed_client(
            addr("10.88.1.41:51004"),
            addr("198.18.0.11:443"),
            PRINCIPAL,
            false
        ));
    }

    #[test]
    fn the_rate_limit_declines_a_second_probe_inside_the_window() {
        let client = addr("10.88.1.41:51005");
        let fake = addr("198.18.0.12:443");
        let owner = IdentityOwner(VPN_CLIENT);
        let confirmed = Arc::new(ConfirmedVpnClients::new());
        confirmed.publish("S-1-5-21-1", &[VPN_CLIENT.to_string()]);
        // A very long floor makes the second call deterministically declined.
        let gate = OwnerLookupVpnClientBypass::new(Arc::new(owner), confirmed)
            .with_min_probe_interval(Duration::from_secs(3600));

        assert!(gate.owned_by_confirmed_client(client, fake, PRINCIPAL, false));
        assert!(
            !gate.owned_by_confirmed_client(client, fake, PRINCIPAL, false),
            "a declined probe falls back to today's routing rather than blocking the poll thread",
        );
    }
}
