//! Unit tests for [`super::PerSidApplyOrchestrator`].
//!
//! Half of `per_sid_orchestrator.rs` was this module: 4126 lines of tests under
//! 4341 lines of code. Moved out verbatim (one level of indentation removed and
//! nothing else) so the file one reads to understand the orchestrator is the
//! orchestrator.

use super::*;
use std::net::{IpAddr, Ipv4Addr};

// a leak-guard-ARMED SID whose secondary is unresolved (the `None`
// fail-closed branch = VPN down) also gets the built-in VPN-client exemption
// permits so a VPN can bootstrap through the block. Fixtures built with
// `snap_full` (secondary bound + kill-switch enabled) hit that path.
//
// those exemptions are now the built-in globs RESOLVED
// to on-disk exe paths via the orchestrator's `AppPathResolver`. These fixtures
// wire no resolver, so the default `NoopAppPathResolver` resolves every built-in
// glob to nothing → ZERO exempt permits. Hence EXEMPT = 0 here. The resolution
// path (a real path yields a real permit, a glob never leaks) has dedicated
// coverage in `builtin_vpn_globs_resolve_to_paths_no_glob_in_fail_closed_set`.
const EXEMPT: usize = 0;

use nrr_domain::canonical::{
    CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
};
use nrr_domain::RuleId;
use nrr_platform_api::types::{WfpAction, WfpLayerKey};
use nrr_platform_api::windows_api::{MockWindowsApi, WindowsApiPort};

use crate::fqdn_cache_lookup::MockFqdnCacheLookup;

/// Trivial scripted `RoutePolicySource` for tests.
#[derive(Default)]
struct ScriptedSource {
    per_sid: Mutex<HashMap<String, PerSidPolicySnapshot>>,
}
impl ScriptedSource {
    fn set(&self, sid: &str, snap: PerSidPolicySnapshot) {
        self.per_sid.lock().unwrap().insert(sid.to_string(), snap);
    }
}
impl RoutePolicySource for ScriptedSource {
    fn load_for_sid(&self, sid: &str) -> Option<PerSidPolicySnapshot> {
        self.per_sid.lock().unwrap().get(sid).cloned()
    }
}

/// Scripted `RulesProvider` for tests. Holds an `Option` so tests
/// can flip between "no active rules" and "rules X". `set_*`
/// helpers below construct test rule books that produce the
/// filter counts each test asserts on.
#[derive(Default)]
struct ScriptedRules {
    snapshot: Mutex<Option<ActiveRulesSnapshot>>,
}
impl ScriptedRules {
    fn set(&self, snap: ActiveRulesSnapshot) {
        *self.snapshot.lock().unwrap() = Some(snap);
    }
    #[allow(dead_code)]
    fn clear(&self) {
        *self.snapshot.lock().unwrap() = None;
    }
}
impl RulesProvider for ScriptedRules {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        self.snapshot.lock().unwrap().clone()
    }
}

/// Build a rule book with `n` ExactIp rules in the primary set
/// and 0 in the secondary set. Each rule pins a distinct IPv4 so
/// the codegen emits exactly `n` filters per SID under `PreferPrimary`
/// mode.
fn rules_with_n_primary_ips(n: u8) -> ActiveRulesSnapshot {
    let primary: Vec<CanonicalRule> = (0..n)
        .map(|i| CanonicalRule {
            id: RuleId(format!("r-{i}")),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(
                10, 0, 0, i,
            )))),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        })
        .collect();
    ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(primary),
            secondary: CanonicalRuleSet::default(),
        },
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    }
}

fn snap_full(primary: &str, secondary: &str) -> PerSidPolicySnapshot {
    PerSidPolicySnapshot {
        primary: Some(PerSidBinding {
            stable_id: primary.into(),
            display_name: String::new(),
            user_confirmed: true,
            known_stable_ids: Vec::new(),
        }),
        secondary: Some(PerSidBinding {
            stable_id: secondary.into(),
            display_name: String::new(),
            user_confirmed: true,
            known_stable_ids: Vec::new(),
        }),
        mode: PerSidBehaviorMode::PreferPrimary,
        block_secondary_when_unavailable: false,
        kill_switch_fail_closed: true,
        kill_switch_protocols: 0x7F,
        kill_switch_block_all: false,
        // these fixtures drive the existing kill-switch behaviour
        // tests, which assert the ARMED leak-guard path; keep the master
        // toggle ON so those expectations hold under the new opt-in gate.
        kill_switch_enabled: true,
        allow_dns_over_primary: false,
        shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
        kill_switch_strict_shared_ips: true,
        // Pinned to the per-IP path these fixtures were written for. This is
        // once again the product default (HW-0718 flip); the FailClosedUnknown
        // escalation has its own dedicated tests.
        mode_a_coverage_strategy: nrr_domain::mode_a_coverage::ModeACoverageStrategy::PerIp,
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
    }
}

fn snap_primary_only(primary: &str) -> PerSidPolicySnapshot {
    PerSidPolicySnapshot {
        primary: Some(PerSidBinding {
            stable_id: primary.into(),
            display_name: String::new(),
            user_confirmed: false,
            known_stable_ids: Vec::new(),
        }),
        secondary: None,
        mode: PerSidBehaviorMode::PreferPrimary,
        block_secondary_when_unavailable: false,
        kill_switch_fail_closed: true,
        kill_switch_protocols: 0x7F,
        kill_switch_block_all: false,
        kill_switch_enabled: true,
        allow_dns_over_primary: false,
        shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
        kill_switch_strict_shared_ips: true,
        // Pinned per-IP for the same reason as `snap_full` above (HW-0714).
        mode_a_coverage_strategy: nrr_domain::mode_a_coverage::ModeACoverageStrategy::PerIp,
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
    }
}

/// Audit collector for tests. Records every `emit` call.
#[derive(Default)]
struct CollectAudit {
    records: Mutex<Vec<PerSidApplyAuditRecord>>,
}
impl CollectAudit {
    fn snapshot(&self) -> Vec<PerSidApplyAuditRecord> {
        self.records.lock().unwrap().clone()
    }
}
impl PerSidApplyAudit for CollectAudit {
    fn emit(&self, record: PerSidApplyAuditRecord) {
        self.records.lock().unwrap().push(record);
    }
}

/// Shared fixture: orchestrator wired with the scripted
/// policy/rules sources and an empty FQDN cache. By default the
/// rules snapshot is seeded with **two** ExactIp rules so
/// `install_for_sid` produces 2 filters per SID — matching the
/// pre-16.12.A.3 placeholder count and letting most lifecycle
/// tests keep their `len() == 2` assertions. Tests that need a
/// different filter count call `rules.set(rules_with_n_primary_ips(n))`
/// themselves.
#[allow(clippy::type_complexity)]
fn fixture() -> (
    Arc<MockWindowsApi>,
    Arc<PerSidApplyOrchestrator>,
    Arc<ScriptedSource>,
    Arc<ScriptedRules>,
    Arc<CollectAudit>,
) {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    rules.set(rules_with_n_primary_ips(2));
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let orch = Arc::new(PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    ));
    (api, orch, source, rules, audit)
}

/// Build a rule book with a single `Application` rule whose pattern is
/// `app_name` and no address match. Under the default
/// `NoopAppPathResolver` the exe resolves to nothing, so the codegen
/// records an `AppUnresolved` diagnostic.
fn rules_with_one_app(app_name: &str) -> ActiveRulesSnapshot {
    let rule = CanonicalRule {
        id: RuleId("app-1".into()),
        enabled: true,
        address_match: None,
        app_match: Some(nrr_domain::canonical::CanonicalAppMatch {
            pattern: nrr_domain::canonical::CanonicalAppPattern::Exact(app_name.to_string()),
            include_child_processes: false,
        }),
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    };
    ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![rule]),
            secondary: CanonicalRuleSet::default(),
        },
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    }
}

// ── Fixtures shared by more than one theme ───────────────────────────────
//
// A fixture two themes call belongs to neither of them.

const KS_LUID: u64 = 0xABCD_0000_0000_0001;

/// Orchestrator wired with a scripted kill-switch resolver carrying
/// just a LUID (no exemptions), so the per-destination (mode A)
/// kill-switch path can be exercised deterministically.
#[allow(clippy::type_complexity)]
fn fixture_with_luid(
    luid: Option<u64>,
) -> (
    Arc<MockWindowsApi>,
    Arc<PerSidApplyOrchestrator>,
    Arc<ScriptedSource>,
    Arc<ScriptedRules>,
) {
    fixture_with_resolution(luid.map(|l| KillSwitchResolution {
        secondary_luid: l,
        ..Default::default()
    }))
}

/// Orchestrator wired with a scripted kill-switch resolution (full
/// control over LUID + exemptions for catch-all / mode-B tests).
#[allow(clippy::type_complexity)]
fn fixture_with_resolution(
    resolution: Option<KillSwitchResolution>,
) -> (
    Arc<MockWindowsApi>,
    Arc<PerSidApplyOrchestrator>,
    Arc<ScriptedSource>,
    Arc<ScriptedRules>,
) {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(move |_| resolution.clone())),
    );
    (api, orch, source, rules)
}

/// Same as [`fixture_with_luid`], but with a cache that resolves `host` to
/// both families and a machine whose links can carry IPv6.
#[allow(clippy::type_complexity)]
fn fixture_with_ipv6(
    luid: Option<u64>,
    host: &str,
    addrs: Vec<std::net::IpAddr>,
) -> (
    Arc<MockWindowsApi>,
    Arc<PerSidApplyOrchestrator>,
    Arc<ScriptedSource>,
    Arc<ScriptedRules>,
) {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let mock_cache = Arc::new(MockFqdnCacheLookup::new());
    mock_cache.set_addresses(host, addrs);
    let cache: Arc<dyn FqdnCacheLookup> = mock_cache;
    let audit = Arc::new(CollectAudit::default());
    let resolution = luid.map(|l| KillSwitchResolution {
        secondary_luid: l,
        ..Default::default()
    });
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(move |_| resolution.clone()))
        // The tunnel carries IPv6: policy may name and steer the family.
        .with_ipv6_guard_resolver(Arc::new(|_| {
            crate::enforcement_planner::Ipv6Guard::FiltersAndRoutes
        })),
    );
    (api, orch, source, rules)
}

/// One secondary FQDN rule — the only shape that can bring an IPv6 address
/// under a rule, since a rule literal is still IPv4.
fn rules_with_secondary_host(host: &str) -> ActiveRulesSnapshot {
    ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                id: RuleId("r-sec".into()),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::ExactFqdn(host.into())),
                app_match: None,
                comment: String::new(),
                action: nrr_domain::RuleAction::Route,
                origin: None,
            }]),
        },
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    }
}

/// One secondary ExactIp rule → exactly one secondary destination
/// for the kill-switch to protect.
/// A primary-route ExactIp rule (16.HW-0716 P1b test helper).
fn primary_ip_rule(id: &str, ip: Ipv4Addr) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(ip))),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

fn rules_with_secondary_ip(ip: Ipv4Addr) -> ActiveRulesSnapshot {
    ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                id: RuleId("r-sec".into()),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(ip))),
                app_match: None,
                comment: String::new(),
                action: nrr_domain::RuleAction::Route,
                origin: None,
            }]),
        },
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    }
}

fn snap_block(primary: &str, secondary: &str) -> PerSidPolicySnapshot {
    let mut s = snap_full(primary, secondary);
    s.block_secondary_when_unavailable = true;
    s
}

fn snap_block_mode_b(primary: &str, secondary: &str) -> PerSidPolicySnapshot {
    let mut s = snap_block(primary, secondary);
    s.mode = PerSidBehaviorMode::PreferSecondaryWhenAvailable;
    s
}

/// Strict mode with the leak-guard switched OFF.
fn snap_strict_guard_off(primary: &str, secondary: &str) -> PerSidPolicySnapshot {
    let mut s = snap_block(primary, secondary);
    s.mode = PerSidBehaviorMode::StrictSecondaryFailClosed;
    s.kill_switch_enabled = false;
    s
}

fn full_ks_resolution() -> KillSwitchResolution {
    KillSwitchResolution {
        secondary_luid: KS_LUID,
        bootstrap_server_ips: vec![Ipv4Addr::new(203, 0, 113, 7)],
        bootstrap_server_ips_v6: Vec::new(),
        local_subnets: vec![(Ipv4Addr::new(192, 168, 1, 0), 24)],
        local_subnets_v6: Vec::new(),
        foreign_tunnel_luids: Vec::new(),
    }
}

/// `is_destination_block` over an ENUMERATED filter (what the mock engine
/// hands back) rather than a spec. Same predicate, different type.
fn record_is_destination_block(f: &nrr_platform_api::types::WfpFilterRecord) -> bool {
    f.action == WfpAction::Block
        && ((f.remote_ip.is_some() || !f.remote_ip_set.is_empty())
            || f.remote_subnet.is_some()
            || f.remote_subnet_v6.is_some())
}

/// `is_app_only_block` over an ENUMERATED filter.
fn record_is_app_only_block(f: &nrr_platform_api::types::WfpFilterRecord) -> bool {
    f.action == WfpAction::Block
        && f.app_pattern.is_some()
        && (f.remote_ip.is_none() && f.remote_ip_set.is_empty())
        && f.remote_subnet.is_none()
        && f.remote_subnet_v6.is_none()
}

/// Two secondary `ExactIp` rules, so a coverage reconcile can grow the
/// destination pin set from one address to two.
fn rules_with_secondary_ips(ips: &[Ipv4Addr]) -> ActiveRulesSnapshot {
    let rules: Vec<CanonicalRule> = ips
        .iter()
        .enumerate()
        .map(|(i, ip)| CanonicalRule {
            id: RuleId(format!("r-sec-{i}")),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(*ip))),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        })
        .collect();
    ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(rules),
        },
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    }
}

mod apply;
mod audit;
mod blocking_scope;
mod cleanup;
mod kill_switch;
mod preview;
mod route_before_block;
mod vpn_exempt;
