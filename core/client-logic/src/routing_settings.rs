//! Which routing settings a window offers (`offeredRoutingSettings` in
//! `pure.js`).
//!
//! One answer for every client, so the GUI and the terminal UI cannot drift
//! apart on what they show. A row is offered exactly where the service acts on
//! it: the leak-protection refinements under the levels that use them, the
//! routing refinements whatever the level.

use serde_json::{Map, Value};

use crate::route_policy::KILL_SWITCH_PROTOCOLS_KEY;
use crate::stability::profile_supports;

pub const ALLOW_DNS_OVER_PRIMARY: &str = "allow-dns-over-primary";
pub const ENFORCEMENT_MODE: &str = "enforcement-mode";
pub const DNS_VIA_SECONDARY: &str = "dns-via-secondary";
pub const DNS_FAST_ANSWERS: &str = "dns-fast-answers";
pub const FAKE_IP_ENABLED: &str = "fake-ip-enabled";
/// Fake-IP named and explained where the platform opens no TUN adapter.
pub const FAKE_IP_UNAVAILABLE: &str = "fake-ip-unavailable";
pub const FAKE_IP_UDP_RELAY: &str = "fake-ip-udp-relay";
pub const FAKE_IP_INSTANT_RST: &str = "fake-ip-instant-rst";
pub const SHARED_IP_POLICY: &str = "shared-ip-policy";
pub const STRICT_SHARED_IPS: &str = "kill-switch-strict-shared-ips";
pub const LIVENESS_WINDOW: &str = "secondary-liveness-window-secs";
/// The service-stability row has no handler here: one note stands in for
/// every setting it carries.
pub const STABILITY_UNAVAILABLE: &str = "service-stability-unavailable";
/// The local networks list: kept reachable under leak protection, and never
/// sent down a route at any level.
pub const LOCAL_NETWORKS: &str = "local-networks";

/// What the offer depends on, as the client last read it.
#[derive(Clone, Copy, Debug)]
pub struct RoutingContext<'a> {
    /// The platform profile's capability map; absent reads as supported.
    pub supports: Option<&'a Map<String, Value>>,
    /// The effective `enforcement-mode`.
    pub enforcement_mode: &'a str,
    /// The effective leak-protection level, settled against the default route.
    pub leak_protection: &'a str,
    /// Whether an additional connection is bound.
    pub secondary_bound: bool,
    /// The effective `fake-ip-enabled`.
    pub fake_ip_enabled: bool,
}

/// The rows offered, in display order.
pub fn offered(ctx: &RoutingContext<'_>) -> Vec<&'static str> {
    let guards = profile_supports(ctx.supports, "killSwitch");
    let stability = profile_supports(ctx.supports, "serviceStabilityConfig");
    let fake_ip = profile_supports(ctx.supports, "fakeIp");
    let local_networks = profile_supports(ctx.supports, "localNetworkExceptions");
    let everything = ctx.leak_protection == "everything";
    let leak_on = everything || ctx.leak_protection == "sites";
    // The local resolver is what answers fast and hands out virtual addresses.
    let resolver = ctx.enforcement_mode == "resolver";
    [
        (KILL_SWITCH_PROTOCOLS_KEY, guards && leak_on),
        (ALLOW_DNS_OVER_PRIMARY, guards && everything),
        (ENFORCEMENT_MODE, stability),
        (DNS_VIA_SECONDARY, stability && ctx.secondary_bound),
        (DNS_FAST_ANSWERS, stability && resolver),
        (FAKE_IP_ENABLED, stability && resolver && fake_ip),
        (FAKE_IP_UNAVAILABLE, stability && resolver && !fake_ip),
        (
            FAKE_IP_UDP_RELAY,
            stability && resolver && fake_ip && ctx.fake_ip_enabled,
        ),
        (
            FAKE_IP_INSTANT_RST,
            stability && resolver && fake_ip && ctx.fake_ip_enabled,
        ),
        (SHARED_IP_POLICY, true),
        (STRICT_SHARED_IPS, guards && leak_on),
        // A tunnel found dead stops carrying routed traffic at any level.
        (LIVENESS_WINDOW, stability && ctx.secondary_bound),
        (STABILITY_UNAVAILABLE, !stability),
        (LOCAL_NETWORKS, local_networks),
    ]
    .into_iter()
    .filter_map(|(row, shown)| shown.then_some(row))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx<'a>(supports: Option<&'a Map<String, Value>>, leak: &'a str) -> RoutingContext<'a> {
        RoutingContext {
            supports,
            enforcement_mode: "resolver",
            leak_protection: leak,
            secondary_bound: true,
            fake_ip_enabled: true,
        }
    }

    #[test]
    fn routing_refinements_do_not_wait_for_leak_protection() {
        let rows = offered(&ctx(None, "off"));
        for row in [
            ENFORCEMENT_MODE,
            DNS_VIA_SECONDARY,
            DNS_FAST_ANSWERS,
            FAKE_IP_ENABLED,
            SHARED_IP_POLICY,
            LOCAL_NETWORKS,
        ] {
            assert!(rows.contains(&row), "{row} hidden with leak protection off");
        }
        assert!(!rows.contains(&KILL_SWITCH_PROTOCOLS_KEY));
        assert!(!rows.contains(&STRICT_SHARED_IPS));
    }

    #[test]
    fn a_platform_without_the_row_gets_one_note() {
        let supports = json!({ "serviceStabilityConfig": false });
        let rows = offered(&ctx(supports.as_object(), "sites"));
        assert_eq!(
            rows,
            vec![
                KILL_SWITCH_PROTOCOLS_KEY,
                SHARED_IP_POLICY,
                STRICT_SHARED_IPS,
                STABILITY_UNAVAILABLE,
                LOCAL_NETWORKS
            ]
        );
    }
}
