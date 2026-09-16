//! Unit tests for [`super`] — SecondaryRouteCoordinator.
//!
//! 1825 of the module's lines were this block. Moved out verbatim (one
//! level of indentation removed and nothing else) so the file one reads to
//! understand the code is the code.

use super::*;
use std::net::IpAddr;

use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
use crate::per_sid_orchestrator::ActiveRulesSnapshot;
use nrr_domain::canonical::{
    CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
};
use nrr_domain::{RouteBehaviorMode, RuleId};
use nrr_platform_api::MockWindowsApi;
use std::collections::HashSet;
use std::sync::Mutex;

/// Fake provider returning a per-SID snapshot from an in-memory map,
/// with read-through to a baseline entry under the `"__baseline__"`
/// key (mirrors the production provider's contract closely enough for
/// the coordinator's purposes).
struct FakeRules {
    by_sid: Mutex<std::collections::HashMap<String, CanonicalRuleSet>>,
}
impl FakeRules {
    fn new() -> Self {
        Self {
            by_sid: Mutex::new(std::collections::HashMap::new()),
        }
    }
    fn set_secondary(&self, sid: &str, secondary: CanonicalRuleSet) {
        self.by_sid
            .lock()
            .unwrap()
            .insert(sid.to_string(), secondary);
    }
}
impl RulesProvider for FakeRules {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        self.active_rules_for("__baseline__")
    }
    fn active_rules_for(&self, principal: &str) -> Option<ActiveRulesSnapshot> {
        let g = self.by_sid.lock().unwrap();
        let secondary = g
            .get(principal)
            .or_else(|| g.get("__baseline__"))
            .cloned()?;
        Some(ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(vec![]),
                secondary,
            },
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        })
    }
}

fn ip_rule(id: &str, a: u8, b: u8, c: u8, d: u8) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(
            a, b, c, d,
        )))),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

fn target() -> SecondaryRouteTarget {
    SecondaryRouteTarget {
        gateway: Ipv4Addr::new(10, 0, 0, 1),
        gateway_v6: None,
        interface_index: 7,
    }
}

/// Mode-A resolution with the given secondary target (no primary), for the
/// `recompute_for` tests that exercise the secondary `/32` path.
fn res(secondary: Option<SecondaryRouteTarget>) -> RouteResolution {
    RouteResolution {
        mode: RouteBehaviorMode::PreferPrimary,
        primary: None,
        secondary,
    }
}

fn table_dests(api: &MockWindowsApi) -> HashSet<Ipv4Addr> {
    api.get_ip_forward_table()
        .unwrap()
        .iter()
        .filter_map(|r| match r.destination {
            IpAddr::V4(d) => Some(d),
            IpAddr::V6(_) => None,
        })
        .collect()
}

/// In-memory `RoutePolicySource` mapping SID → secondary `stable_id`.
struct FakePolicy {
    by_sid: Mutex<std::collections::HashMap<String, String>>,
    primary_by_sid: Mutex<std::collections::HashMap<String, String>>,
    secondary_names: Mutex<std::collections::HashMap<String, String>>,
}
impl FakePolicy {
    fn new() -> Self {
        Self {
            by_sid: Mutex::new(std::collections::HashMap::new()),
            primary_by_sid: Mutex::new(std::collections::HashMap::new()),
            secondary_names: Mutex::new(std::collections::HashMap::new()),
        }
    }
    fn bind_secondary(&self, sid: &str, stable_id: &str) {
        self.by_sid
            .lock()
            .unwrap()
            .insert(sid.to_string(), stable_id.to_string());
    }
    /// Bind a secondary with a saved display_name (drives the stale-id
    /// auto-heal, which matches by name).
    fn bind_secondary_named(&self, sid: &str, stable_id: &str, display_name: &str) {
        self.bind_secondary(sid, stable_id);
        self.secondary_names
            .lock()
            .unwrap()
            .insert(sid.to_string(), display_name.to_string());
    }
    fn bind_primary(&self, sid: &str, stable_id: &str) {
        self.primary_by_sid
            .lock()
            .unwrap()
            .insert(sid.to_string(), stable_id.to_string());
    }
}
impl RoutePolicySource for FakePolicy {
    fn load_for_sid(&self, sid: &str) -> Option<crate::per_sid_orchestrator::PerSidPolicySnapshot> {
        use crate::per_sid_orchestrator::{PerSidBinding, PerSidPolicySnapshot};
        let stable = self.by_sid.lock().unwrap().get(sid).cloned()?;
        let primary = self
            .primary_by_sid
            .lock()
            .unwrap()
            .get(sid)
            .cloned()
            .map(|id| PerSidBinding {
                stable_id: id,
                display_name: String::new(),
                user_confirmed: true,
                known_stable_ids: Vec::new(),
            });
        let secondary_name = self
            .secondary_names
            .lock()
            .unwrap()
            .get(sid)
            .cloned()
            .unwrap_or_default();
        Some(PerSidPolicySnapshot {
            primary,
            secondary: Some(PerSidBinding {
                stable_id: stable,
                display_name: secondary_name,
                user_confirmed: true,
                known_stable_ids: Vec::new(),
            }),
            mode: crate::per_sid_orchestrator::PerSidBehaviorMode::PreferPrimary,
            block_secondary_when_unavailable: false,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            // this fake feeds route-coordinator tests that assert the
            // armed leak-guard path; keep the master toggle ON so their
            // expectations hold under the new opt-in gate.
            kill_switch_enabled: true,
            allow_dns_over_primary: false,
            shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
            kill_switch_strict_shared_ips: true,
            mode_a_coverage_strategy: nrr_domain::mode_a_coverage::ModeACoverageStrategy::default(),
            link_provider_exe_paths: Vec::new(),
            doh_lockdown_enabled: false,
            doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
            doh_resolver_ips: Vec::new(),
            auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
            primary_probe_auto: false,
            primary_probe_timeout_ms: 1500,
            primary_probe_max_targets: 8,
            primary_probe_repeat_secs: 300,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
        })
    }
}

fn coordinator(api: Arc<MockWindowsApi>, rules: Arc<FakeRules>) -> SecondaryRouteCoordinator {
    SecondaryRouteCoordinator::new(
        api as Arc<dyn RouteTablePort>,
        rules as Arc<dyn RulesProvider>,
        Arc::new(FakePolicy::new()) as Arc<dyn RoutePolicySource>,
        Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
        Arc::new(|| false) as RuleScopeProvider,
    )
}

fn coordinator_with_policy(
    api: Arc<MockWindowsApi>,
    rules: Arc<FakeRules>,
    policy: Arc<FakePolicy>,
) -> SecondaryRouteCoordinator {
    SecondaryRouteCoordinator::new(
        api as Arc<dyn RouteTablePort>,
        rules as Arc<dyn RulesProvider>,
        policy as Arc<dyn RoutePolicySource>,
        Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
        Arc::new(|| false) as RuleScopeProvider,
    )
}

fn coordinator_with_scope(
    api: Arc<MockWindowsApi>,
    rules: Arc<FakeRules>,
    service_driven: bool,
) -> SecondaryRouteCoordinator {
    SecondaryRouteCoordinator::new(
        api as Arc<dyn RouteTablePort>,
        rules as Arc<dyn RulesProvider>,
        Arc::new(FakePolicy::new()) as Arc<dyn RoutePolicySource>,
        Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
        Arc::new(move || service_driven) as RuleScopeProvider,
    )
}

// ── Fixtures shared by more than one theme ───────────────────────────────

fn adapter(stable_seed: &str, idx: u32, up: bool, ipv4: bool, gw: Option<[u8; 4]>) -> AdapterInfo {
    use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
    AdapterInfo {
        index: idx,
        adapter_name: stable_seed.into(),
        description: format!("desc {stable_seed}"),
        // Fixture default: the connection carries the driver name, so tests
        // that do not care about the distinction see one name.
        friendly_name: format!("desc {stable_seed}"),
        mac: Some([0, 1, 2, 3, 4, idx as u8]),
        interface_type: InterfaceType::Ethernet,
        oper_status: if up {
            IfOperStatus::Up
        } else {
            IfOperStatus::Down
        },
        ipv4_addresses: if ipv4 {
            vec![Ipv4Addr::new(192, 168, 1, 50)]
        } else {
            vec![]
        },
        ipv6_addresses: Vec::new(),
        gateways: gw.map(|g| vec![Ipv4Addr::from(g)]).unwrap_or_default(),
    }
}

mod binding_identity;
mod first_contact_and_probe;
mod offers_and_paused;
mod recompute;
mod sid_and_notices;
