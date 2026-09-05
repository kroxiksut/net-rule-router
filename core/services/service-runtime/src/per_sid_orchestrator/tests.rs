//! Unit tests for [`super::PerSidApplyOrchestrator`].
//!
//! Half of `per_sid_orchestrator.rs` was this module: 4126 lines of tests under
//! 4341 lines of code. Moved out verbatim (one level of indentation removed and
//! nothing else) so the file one reads to understand the orchestrator is the
//! orchestrator.

use super::*;
use std::net::Ipv4Addr;

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

// The IPv6 cut that rides along with an armed leak guard: three exemption
// permits plus a block-all, at each of the two v6 layers. `snap_full`
// fixtures arm the guard with an unresolvable secondary, so their filter
// counts carry it.
const V6_CUT: usize = 8;

use nrr_domain::canonical::{
    CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
};
use nrr_domain::RuleId;
use nrr_platform_api::types::WfpAction;
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
            address_match: Some(CanonicalAddressMatch::ExactIp(Ipv4Addr::new(10, 0, 0, i))),
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
        block_ipv6_when_protected: true,
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
        block_ipv6_when_protected: true,
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

#[test]
fn compute_records_unresolved_app_rules_into_status() {
    // an app rule whose exe resolves to no path (the
    // default NoopAppPathResolver) must publish the app pattern into the
    // shared `AppEnforcementStatus` for the GUI banner, while still
    // computing a (possibly empty) filter set.
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    source.set("S-1-5-21-APP", snap_primary_only("Wi-Fi"));
    let rules = Arc::new(ScriptedRules::default());
    rules.set(rules_with_one_app("vk.exe"));
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let status = crate::app_enforcement_status::AppEnforcementStatus::new();
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    )
    .with_app_enforcement_status(status.clone());

    // Empty before any compute.
    assert!(status.unresolved().is_empty());

    orch.compute_filters_for_sid("S-1-5-21-APP", true, None, ComputeIntent::Apply)
        .unwrap();

    assert_eq!(status.unresolved(), vec!["vk.exe".to_string()]);
}

#[test]
fn doh_lockdown_emits_blocks_when_enabled_and_in_scope() {
    use nrr_storage::doh_lockdown::DohLockdownScope;
    let build = |scope: DohLockdownScope, kill_switch: bool| {
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let mut snap = snap_primary_only("Wi-Fi");
        snap.doh_lockdown_enabled = true;
        snap.doh_lockdown_scope = scope;
        snap.kill_switch_enabled = kill_switch;
        snap.doh_resolver_ips = vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)];
        source.set("S-1-5-21-DOH", snap);
        let rules = Arc::new(ScriptedRules::default());
        rules.set(rules_with_n_primary_ips(1));
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        let orch = PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        );
        let set = orch
            .compute_filters_for_sid("S-1-5-21-DOH", false, None, ComputeIntent::Apply)
            .unwrap();
        let plan = match set {
            ComputedFilterSet::Install(plan) => plan,
            _ => panic!("expected Install filter set"),
        };
        plan.filters
            .iter()
            .filter(|f| f.remote_port == Some(443) || f.remote_port == Some(853))
            .count()
    };
    // Always scope → blocks regardless of the kill-switch: 2 IPs × (443 TCP+UDP)
    // + DoT (853 TCP+UDP) = 6.
    assert_eq!(build(DohLockdownScope::Always, false), 6);
    // Leak-protection-only + kill-switch ON → applies.
    assert_eq!(build(DohLockdownScope::LeakProtectionOnly, true), 6);
    // Leak-protection-only + kill-switch OFF → does NOT apply.
    assert_eq!(build(DohLockdownScope::LeakProtectionOnly, false), 0);
}

/// A resolver drop must be explainable as the lockdown that caused it. The
/// notice path can only tell it from a rule by id, so the band has to be
/// published — and published SEPARATELY: landing in `all` would role-verify
/// it and report a working tunnel as unavailable.
#[test]
fn doh_lockdown_blocks_are_published_in_their_own_band() {
    use nrr_storage::doh_lockdown::DohLockdownScope;
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let mut snap = snap_full("Wi-Fi", "TAP");
    snap.doh_lockdown_enabled = true;
    snap.doh_lockdown_scope = DohLockdownScope::Always;
    snap.doh_resolver_ips = vec![Ipv4Addr::new(8, 8, 4, 4)];
    source.set("S-1-5-21-DOHBAND", snap);
    let rules = Arc::new(ScriptedRules::default());
    rules.set(rules_with_n_primary_ips(1));
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let registry = Arc::new(crate::killswitch_drop_registry::KillswitchBlockFilterRegistry::new());
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    )
    .with_kill_switch_resolver(Arc::new(|_| Some(full_ks_resolution())))
    .with_killswitch_drop_registry(Arc::clone(&registry));

    let set = orch
        .compute_filters_for_sid("S-1-5-21-DOHBAND", false, None, ComputeIntent::Apply)
        .unwrap();
    let plan = match set {
        ComputedFilterSet::Install(plan) => plan,
        _ => panic!("expected Install filter set"),
    };
    let doh_blocks: Vec<u64> = plan
        .filters
        .iter()
        .filter(|f| {
            f.action == WfpAction::Block
                && (f.remote_port == Some(443) || f.remote_port == Some(853))
        })
        .map(|f| f.id.raw)
        .collect();
    assert!(
        !doh_blocks.is_empty(),
        "the lockdown must have emitted blocks"
    );
    for id in doh_blocks {
        assert!(registry.is_dns_lockdown(id), "id {id} is not in the band");
        assert!(
            !registry.contains(id),
            "a resolver drop must not role-verify the tunnel"
        );
    }
}

/// The neutral pipeline must describe the same enforcement as the one that
/// actually installs — measured through the orchestrator's own compute, not
/// a hand-built plan.
///
/// The oracle tests in `enforcement_planner` already compare the two over
/// rule books written for the purpose. This one asks the question the way it
/// will be asked in production: whatever the orchestrator just computed for
/// this SID, does the plan agree with it? That is the check that has to hold
/// before the neutral path may take over the apply.
// Windows-only for the same reason the comparison is: it measures against a
// WFP filter set, and off-Windows there is none to measure against.
#[cfg(windows)]
#[test]
fn the_neutral_plan_agrees_with_the_filters_the_orchestrator_computes() {
    let (_api, orch, src, rules, _audit) = fixture();
    let sid = "S-1-5-21-NEUTRAL";
    src.set(sid, snap_full("Wi-Fi", "TAP"));
    let book = rules_with_n_primary_ips(3);
    rules.set(book.clone());

    // Drive the real compute, then compare against what it produced.
    let computed = orch
        .compute_filters_for_sid(sid, true, None, ComputeIntent::Preview)
        .expect("compute succeeds");
    let live = match computed {
        ComputedFilterSet::Install(plan) => plan.filters,
        _ => unreachable!("the fixture's rule book is installable"),
    };

    let verdict = orch
        .neutral_plan_verdict(
            sid,
            nrr_domain::RouteBehaviorMode::PreferPrimary,
            &book.rule_book,
            &live,
        )
        .expect("a well-formed SID yields a verdict");

    assert!(
        verdict.same_set,
        "neutral plan installs a different filter set: live={} neutral={}",
        verdict.live, verdict.neutral
    );
    assert!(
        verdict.same_order,
        "neutral plan installs the same filters in a different arbitration order — \
         WFP resolves overlaps by weight, so that is a different policy"
    );
}

#[test]
fn install_for_sid_with_no_policy_records_empty_state() {
    let (api, orch, _src, _rules, _audit) = fixture();
    let count = orch.install_for_sid("S-1-5-21-X").unwrap();
    assert_eq!(count, 0);
    assert_eq!(orch.installed_sids(), vec!["S-1-5-21-X".to_string()]);
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 0);
}

#[test]
fn install_for_sid_refuses_the_baseline_principal() {
    // the baseline is a per-user default, never a
    // routable per-SID target of its own. Refused with no side effects.
    let (api, orch, src, _rules, _audit) = fixture();
    src.set(
        nrr_domain::user_principal::BASELINE_PRINCIPAL,
        snap_full("Wi-Fi", "TAP"),
    );
    let err = orch
        .install_for_sid(nrr_domain::user_principal::BASELINE_PRINCIPAL)
        .expect_err("baseline must not be routable");
    assert!(matches!(err, OrchestratorError::BaselineNotRoutable));
    assert!(orch.installed_sids().is_empty());
    assert!(api.wfp_filters.lock().unwrap().is_empty());
}

#[test]
fn m1_no_active_user_means_no_enforcement_and_no_baseline_floor() {
    // when nobody is logged in the active-SID set
    // is empty: nothing is installed (routing is passthrough), and the
    // baseline is NOT applied as a machine-wide floor.
    let (api, orch, src, _rules, _audit) = fixture();
    src.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));

    // Empty active set on a fresh orchestrator → nothing installed.
    orch.reconcile(&[]).unwrap();
    assert!(orch.installed_sids().is_empty());
    assert!(api.wfp_filters.lock().unwrap().is_empty());

    // A user's tray connects → their filters appear.
    orch.reconcile(&["S-1-5-21-A".to_string()]).unwrap();
    assert_eq!(orch.installed_sids(), vec!["S-1-5-21-A".to_string()]);
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2 + EXEMPT);

    // Everyone logs off (empty set again) → filters torn down; no
    // baseline floor is left enforcing on the wire.
    orch.reconcile(&[]).unwrap();
    assert!(orch.installed_sids().is_empty());
    assert!(api.wfp_filters.lock().unwrap().is_empty());
}

#[test]
fn install_for_sid_with_policy_pushes_filters_to_wfp() {
    let (api, orch, src, _rules, _audit) = fixture();
    src.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));
    let count = orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(count, 2 + EXEMPT);
    let filters = api.wfp_filters.lock().unwrap();
    assert_eq!(filters.len(), 2 + EXEMPT);
    // The v6 packet layer has no ALE_USER_ID, so those filters are
    // machine-wide by construction; everything else is this SID's.
    assert!(filters
        .iter()
        .filter(|f| f.layer != nrr_platform_api::types::WfpLayerKey::OutboundIpPacketV6)
        .all(|f| f.user_sid.as_deref() == Some("S-1-5-21-A")));
}

/// A socket opened before the rule keeps its interface for life, so an
/// activation has to break the connections to the destinations it just
/// started enforcing — otherwise the page the user added a rule for
/// finishes over the old link and only a manual reload fixes it.
#[test]
fn activation_tears_down_connections_to_the_destinations_it_starts_enforcing() {
    let (_api, orch, src, _rules, _audit) = fixture();
    let reset = Arc::new(nrr_platform_api::fake_ip::stale_flows::MockStaleFlowReset::new());
    let orch = Arc::new(
        Arc::try_unwrap(orch)
            .unwrap_or_else(|_| panic!("sole owner"))
            .with_stale_flow_reset(Arc::clone(&reset)
                as Arc<dyn nrr_platform_api::fake_ip::stale_flows::StaleFlowReset>),
    );
    src.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let first: Vec<Ipv4Addr> = reset.calls().into_iter().map(|(ip, _)| ip).collect();
    assert!(
        !first.is_empty(),
        "the destinations of a first install are all newly enforced"
    );
    assert!(
        reset.calls().iter().all(|(_, prefix)| *prefix == 32),
        "a destination is torn down as a single address, not as a subnet"
    );

    // Re-applying the same policy must NOT tear the same connections down
    // again — those are the ones the first teardown just re-established.
    let before = reset.calls().len();
    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(
        reset.calls().len(),
        before,
        "an unchanged destination set is not re-torn-down"
    );
}

/// A coverage reconcile maintains the SAME record an install does. It used
/// to leave the coverage fields alone, so the destinations it started
/// enforcing were never swept — the sockets already running to them
/// finished on the old link — and the next install then saw them as new and
/// swept connections that had already been re-established.
#[test]
fn a_coverage_reconcile_records_and_sweeps_what_it_starts_covering() {
    let first_ip = Ipv4Addr::new(203, 0, 113, 9);
    let second_ip = Ipv4Addr::new(203, 0, 113, 10);
    let (_api, orch, src, rules) = fixture_with_luid(Some(0x0001_0000_0000_0007));
    rules.set(rules_with_secondary_ip(first_ip));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    let reset = Arc::new(nrr_platform_api::fake_ip::stale_flows::MockStaleFlowReset::new());
    let orch = Arc::new(
        Arc::try_unwrap(orch)
            .unwrap_or_else(|_| panic!("sole owner"))
            .with_stale_flow_reset(Arc::clone(&reset)
                as Arc<dyn nrr_platform_api::fake_ip::stale_flows::StaleFlowReset>),
    );

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let after_install: Vec<Ipv4Addr> = reset.calls().into_iter().map(|(ip, _)| ip).collect();
    assert!(after_install.contains(&first_ip));

    // A rule appears between passes; the coverage reconcile is what installs
    // its filters, so it is also what must break the flows already running
    // to that address.
    rules.set(rules_with_secondary_ips(&[first_ip, second_ip]));
    orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();
    let swept: Vec<Ipv4Addr> = reset.calls().into_iter().map(|(ip, _)| ip).collect();
    assert!(
        swept.contains(&second_ip),
        "the address this pass started enforcing must be swept by it"
    );

    // And the install that follows must not re-sweep what the reconcile
    // already recorded as covered.
    let before = reset.calls().len();
    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(
        reset.calls().len(),
        before,
        "an unchanged coverage set is not re-torn-down"
    );
}

/// The tunnel coming up changes no address, so the "only new destinations"
/// rule would sweep nothing — and every socket the browser opened while the
/// link was down would finish on the main link. The edge itself has to
/// count as a reason to sweep.
#[test]
fn the_additional_link_coming_up_sweeps_every_pinned_destination() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let src = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    // The adapter appears between the two installs, exactly as a tunnel
    // that finishes connecting does.
    let live = Arc::new(Mutex::new(None::<KillSwitchResolution>));
    let resolver_state = Arc::clone(&live);
    let reset = Arc::new(nrr_platform_api::fake_ip::stale_flows::MockStaleFlowReset::new());
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&src) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(move |_| {
            resolver_state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        }))
        .with_stale_flow_reset(
            Arc::clone(&reset) as Arc<dyn nrr_platform_api::fake_ip::stale_flows::StaleFlowReset>
        ),
    );
    rules.set(rules_with_secondary_ip(ip));
    src.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let after_first = reset.calls().len();

    *live.lock().unwrap_or_else(|p| p.into_inner()) = Some(full_ks_resolution());
    orch.install_for_sid("S-1-5-21-A").unwrap();

    let swept: Vec<Ipv4Addr> = reset
        .calls()
        .into_iter()
        .skip(after_first)
        .map(|(addr, _)| addr)
        .collect();
    assert!(
        swept.contains(&ip),
        "the destination was pinned before and after, so only the up-edge can explain sweeping it: {swept:?}"
    );

    // Steady state afterwards: the same install must not keep tearing the
    // reconnected sockets down.
    let before_third = reset.calls().len();
    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(
        reset.calls().len(),
        before_third,
        "an unchanged, already-up link sweeps nothing"
    );
}

/// Without the port wired, the activation edge is silent and the reactive
/// path in the connection observer stays the only repair — no panic, no
/// difference in what installs.
#[test]
fn an_unwired_flow_reset_changes_nothing_about_the_install() {
    let (api, orch, src, _rules, _audit) = fixture();
    src.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));
    let count = orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(count, 2 + EXEMPT);
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2 + EXEMPT);
}

// ── Preview (pre-flight / dry run) ──────────────────────────────────────

/// The whole reason a preview path did not exist before: the compute is also
/// where the live status the GUI reads gets refreshed. A preview that wrote
/// it would make the app describe a policy nobody applied.
#[test]
fn a_preview_publishes_nothing_about_the_live_policy() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let app_status = crate::app_enforcement_status::AppEnforcementStatus::new();
    let shared_status = crate::app_enforcement_status::SharedIpExemptionStatus::new();
    let requests = Arc::new(crate::power_resume::RebindRequests::new());
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
    )
    .with_app_enforcement_status(app_status.clone())
    .with_shared_ip_exemption_status(shared_status.clone())
    // Secondary unresolved → the compute would arm fail-closed, latch the
    // posture and ask for a re-resolve. A preview must do none of it.
    .with_kill_switch_resolver(Arc::new(|_| None))
    .with_rebind_requests(Arc::clone(&requests));
    source.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    let candidate = rules_with_one_app("nowhere.exe");

    let preview = orch
        .preview_for_sid("S-1-5-21-A", &candidate)
        .expect("preview");

    assert!(preview.enforceable);
    assert_eq!(
        preview.unresolved_apps,
        vec!["nowhere.exe".to_string()],
        "the preview itself must still report what it found"
    );
    assert!(
        app_status.unresolved().is_empty(),
        "the GUI's unresolved-app list belongs to the APPLIED policy"
    );
    assert_eq!(
        shared_status.count(),
        0,
        "no shared-IP warning from a preview"
    );
    assert_eq!(requests.take(), None, "a preview asks for no re-resolve");
    assert_eq!(
        api.wfp_filters.lock().unwrap().len(),
        0,
        "a preview installs nothing"
    );
    // The posture latch must be untouched: the next REAL compute has to be
    // able to log its transition, which it cannot if a preview claimed it.
    assert!(
        orch.posture_changed("S-1-5-21-A", "unresolved-fail-closed-block-all"),
        "the posture latch must still see the first real arming as a change"
    );
}

/// A preview states the CHANGE, not just the destination — the review
/// summary showed zeros because nothing computed this.
#[test]
fn a_preview_counts_the_filters_an_apply_would_install() {
    let (_api, orch, src, rules) = fixture_with_luid(Some(KS_LUID));
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    rules.set(rules_with_secondary_ip(ip));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    let before = orch
        .preview_for_sid("S-1-5-21-A", &rules_with_secondary_ip(ip))
        .expect("preview");
    assert!(before.filters > 0);
    assert_eq!(before.installed_now, 0, "nothing installed yet");
    assert!(
        before.colliding_filter_ids.is_empty(),
        "a sane rule set must not collide with itself"
    );

    assert_eq!(
        (before.additions, before.removals),
        (before.filters, 0),
        "with nothing installed, every planned filter is an addition"
    );

    let installed = orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(
        before.filters, installed,
        "the preview must predict the real install exactly"
    );
    let after = orch
        .preview_for_sid("S-1-5-21-A", &rules_with_secondary_ip(ip))
        .expect("preview");
    assert_eq!(after.installed_now, installed);
    // The same policy again is not "replace everything" — it is nothing to
    // do, and the review flow reads exactly this to say "already on
    // baseline" instead of opening a confirm dialog.
    assert_eq!(
        (after.additions, after.removals),
        (0, 0),
        "an unchanged policy must preview as a zero diff"
    );
}

/// A SID with no policy row enforces nothing, and the preview says so
/// instead of reporting a plausible zero.
#[test]
fn a_preview_of_a_sid_without_policy_reports_it_as_unenforceable() {
    let (_api, orch, _src, _rules) = fixture_with_luid(Some(KS_LUID));
    let candidate = rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 9));
    let preview = orch
        .preview_for_sid("S-1-5-21-NOPOLICY", &candidate)
        .expect("preview");
    assert!(!preview.enforceable);
    assert_eq!(preview.filters, 0);
}

/// A configured secondary the OS cannot resolve is why a leak guard sits
/// fail-closed; the preview names it so the review can say so before the
/// user applies.
#[test]
fn a_preview_reports_a_binding_the_os_cannot_resolve() {
    let (_api, orch, src, rules) = fixture_with_luid(None);
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    rules.set(rules_with_secondary_ip(ip));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    let preview = orch
        .preview_for_sid("S-1-5-21-A", &rules_with_secondary_ip(ip))
        .expect("preview");
    assert!(preview.secondary_binding_unresolved);

    let (_api2, orch2, src2, rules2) = fixture_with_luid(Some(KS_LUID));
    rules2.set(rules_with_secondary_ip(ip));
    src2.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    let resolved = orch2
        .preview_for_sid("S-1-5-21-A", &rules_with_secondary_ip(ip))
        .expect("preview");
    assert!(!resolved.secondary_binding_unresolved);
}

// ── WFP cleanup (persist-on-stop feature) ───────────────────────────────

/// Build an orchestrator that shares `session` with the caller so a test
/// can seed the live WFP table directly (as an orphaned prior instance
/// would leave it) and then exercise the cleanup entrypoints.
fn orch_sharing_session(session: Arc<WfpSession>) -> Arc<PerSidApplyOrchestrator> {
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    Arc::new(PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    ))
}

#[test]
fn only_permitted_addresses_are_published_as_enforced() {
    let spec = |action: WfpAction, ip: Option<Ipv4Addr>, set: Vec<Ipv4Addr>| WfpFilterSpec {
        layer: nrr_platform_api::types::WfpLayerKey::AleAuthConnectV4,
        action,
        remote_ip: ip,
        remote_ip_set: set,
        remote_port: None,
        weight: 0,
        id: WfpFilterId { raw: 1 },
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    };
    let permitted = Ipv4Addr::new(172, 64, 154, 50);
    let packed = Ipv4Addr::new(104, 18, 33, 206);
    let doh_blocked = Ipv4Addr::new(8, 8, 4, 4);
    let sid = "S-1-5-21-publish-test";

    PerSidApplyOrchestrator::publish_enforced_addresses(
        sid,
        &[
            spec(WfpAction::Permit, Some(permitted), Vec::new()),
            // The packed form: one filter guarding a whole address set.
            spec(WfpAction::Permit, None, vec![packed]),
            // The DoH lockdown names ~85 addresses it BLOCKS. Answering a
            // client with one of them would be the opposite of enforced.
            spec(WfpAction::Block, Some(doh_blocked), Vec::new()),
            // A catch-all carries no address and contributes nothing.
            spec(WfpAction::Permit, None, Vec::new()),
        ],
    );

    let register = crate::enforced_addresses::global_enforced_addresses();
    assert!(register.is_enforced(sid, permitted));
    assert!(register.is_enforced(sid, packed), "packed sets count too");
    assert!(!register.is_enforced(sid, doh_blocked));
    assert_eq!(register.snapshot(sid).len(), 2);
}

fn seeded_block_permit_block(session: &WfpSession, api: &MockWindowsApi) {
    let block = |raw: u64| WfpFilterSpec {
        layer: nrr_platform_api::types::WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: Some(Ipv4Addr::new(9, 9, 9, raw as u8)),
        remote_ip_set: Vec::new(),
        remote_port: None,
        weight: 0x10_0000 + raw,
        id: WfpFilterId { raw },
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    };
    let permit = |raw: u64| WfpFilterSpec {
        action: WfpAction::Permit,
        ..block(raw)
    };
    session
        .execute_wfp_plan(&[
            WfpFilterAction::AddFilter(block(1)),
            WfpFilterAction::AddFilter(permit(2)),
            WfpFilterAction::AddFilter(block(3)),
        ])
        .unwrap();
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 3);
}

#[test]
fn cleanup_wfp_blocks_only_strips_blocks_and_keeps_permits() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let orch = orch_sharing_session(Arc::clone(&session));
    seeded_block_permit_block(&session, &api);

    let removed = orch.cleanup_wfp_blocks_only().unwrap();
    assert_eq!(removed, 2, "only the two block filters must be stripped");
    let remaining = api.wfp_filters.lock().unwrap().clone();
    assert_eq!(remaining.len(), 1, "the permit filter must survive");
    assert_eq!(remaining[0].action, WfpAction::Permit);
}

#[test]
fn cleanup_wfp_strips_all_filters_and_clears_state() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let orch = orch_sharing_session(Arc::clone(&session));
    seeded_block_permit_block(&session, &api);

    let removed = orch.cleanup_wfp().unwrap();
    assert_eq!(removed, 3, "cleanup_wfp strips block AND permit filters");
    assert!(api.wfp_filters.lock().unwrap().is_empty());
    assert!(
        orch.installed_sids().is_empty(),
        "cleanup_wfp must clear the in-memory SID→filter map"
    );
}

// ── Kill-switch (block 16.18.vpn slice D) ───────────────────────────────

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

/// Same as [`fixture_with_resolution`], plus a wired kill-switch drop
/// registry, for tests that verify the reactive VPN-endpoint learner's
/// registry publish.
#[allow(clippy::type_complexity)]
fn fixture_with_resolution_and_registry(
    resolution: Option<KillSwitchResolution>,
) -> (
    Arc<MockWindowsApi>,
    Arc<PerSidApplyOrchestrator>,
    Arc<ScriptedSource>,
    Arc<ScriptedRules>,
    Arc<crate::killswitch_drop_registry::KillswitchBlockFilterRegistry>,
) {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let registry = Arc::new(crate::killswitch_drop_registry::KillswitchBlockFilterRegistry::new());
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(move |_| resolution.clone()))
        .with_killswitch_drop_registry(Arc::clone(&registry)),
    );
    (api, orch, source, rules, registry)
}

/// One secondary ExactIp rule → exactly one secondary destination
/// for the kill-switch to protect.
/// A primary-route ExactIp rule (16.HW-0716 P1b test helper).
fn primary_ip_rule(id: &str, ip: Ipv4Addr) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactIp(ip)),
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
                address_match: Some(CanonicalAddressMatch::ExactIp(ip)),
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

/// Kill-switch on, but posture set to fail-OPEN (legacy behaviour:
/// allow + warn when the secondary can't be resolved).
fn snap_block_fail_open(primary: &str, secondary: &str) -> PerSidPolicySnapshot {
    let mut s = snap_block(primary, secondary);
    s.kill_switch_fail_closed = false;
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
        local_subnets: vec![(Ipv4Addr::new(192, 168, 1, 0), 24)],
    }
}

#[test]
fn mode_b_arms_catch_all_kill_switch() {
    let (api, orch, src, rules) = fixture_with_resolution(Some(full_ks_resolution()));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
    src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    // 0704 (P2): the catch-all arms at BOTH the ALE (TCP/UDP) and the
    // packet layers. 16.HW-0716: the packet side is one NAMED block per
    // ICMP/IGMP/GRE/ESP (4) instead of one agnostic block-all; IPv6 adds a
    // V6 ALE + V6 packet block-all → 1 + 4 + 2 = 7 block filters.
    assert_eq!(
        filters
            .iter()
            .filter(|f| f.action == WfpAction::Block)
            .count(),
        7,
        "mode B: V4 ALE block + 4 named V4 packet blocks + V6 ALE + V6 packet"
    );
    assert_eq!(
        filters
            .iter()
            .filter(|f| f.local_interface_luid == Some(KS_LUID))
            .count(),
        2,
        "egress-via-secondary exemption present at both layers"
    );
    assert!(
        filters.iter().filter(|f| f.remote_subnet.is_some()).count() >= 3,
        "loopback + link-local + LAN subnet exemptions present"
    );
}

#[test]
fn killswitch_registry_publishes_exactly_the_armed_block_ids() {
    let (api, orch, src, rules, registry) =
        fixture_with_resolution_and_registry(Some(full_ks_resolution()));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
    src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    let is_v6 = |layer: WfpLayerKey| {
        matches!(
            layer,
            WfpLayerKey::AleAuthConnectV6 | WfpLayerKey::OutboundIpPacketV6
        )
    };
    let block_ids: Vec<u64> = filters
        .iter()
        .filter(|f| f.action == WfpAction::Block && !is_v6(f.layer))
        .map(|f| f.id.raw)
        .collect();
    assert!(!block_ids.is_empty());
    for id in &block_ids {
        assert!(
            registry.contains(*id),
            "every armed kill-switch/fail-closed Block id must be published",
        );
    }
    // The IPv6 cut is published under its own scope: it proves nothing
    // about the tunnel, so it must never role-verify a drop.
    let v6_block_ids: Vec<u64> = filters
        .iter()
        .filter(|f| f.action == WfpAction::Block && is_v6(f.layer))
        .map(|f| f.id.raw)
        .collect();
    assert_eq!(v6_block_ids.len(), 2, "one v6 block per v6 layer");
    for id in &v6_block_ids {
        assert!(registry.is_ipv6_cut(*id));
        assert!(!registry.contains(*id));
    }
    // Nothing outside the armed set is falsely reported as ours.
    assert!(!registry.contains(u64::MAX));
}

#[test]
fn killswitch_registry_clears_when_leak_guard_disarms() {
    let (api, orch, src, rules, registry) =
        fixture_with_resolution_and_registry(Some(full_ks_resolution()));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
    src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();
    let armed_ids: Vec<u64> = api
        .wfp_filters
        .lock()
        .unwrap()
        .iter()
        .filter(|f| f.action == WfpAction::Block)
        .map(|f| f.id.raw)
        .collect();
    assert!(!armed_ids.is_empty());

    // Active rules withdrawn (e.g. the revision was cleared) → the
    // compute takes the `NoActiveRules` path, which must retract this
    // SID's entry rather than leaving its Block ids published forever.
    rules.clear();
    orch.install_for_sid("S-1-5-21-A").unwrap();
    for id in &armed_ids {
        assert!(
            !registry.contains(*id),
            "a disarmed SID's stale Block ids must not linger in the registry",
        );
    }
}

#[test]
fn mode_b_catch_all_fails_open_without_server_exemption() {
    let (api, orch, src, rules) = fixture_with_resolution(Some(KillSwitchResolution {
        secondary_luid: KS_LUID,
        bootstrap_server_ips: vec![], // unknown server → must not arm
        local_subnets: vec![],
    }));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
    // Fail-OPEN posture: the catch-all refusing to arm without a server
    // exemption (to avoid a reconnect deadlock) is the fail-open contract.
    // Under fail-closed the user has explicitly opted to cut everything,
    // so it DOES arm — that path is covered by
    // `kill_switch_fail_closed_mode_b_blocks_all_when_unresolved`.
    let mut s = snap_block_mode_b("Wi-Fi", "TAP");
    s.kill_switch_fail_closed = false;
    src.set("S-1-5-21-A", s);

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    assert_eq!(
        filters
            .iter()
            .filter(|f| f.action == WfpAction::Block)
            .count(),
        0,
        "fail-open + no server exemption → catch-all must not arm (avoid reconnect deadlock)"
    );
}

#[test]
fn kill_switch_appends_egress_pair_over_secondary_destination() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, src, rules) = fixture_with_luid(Some(KS_LUID));
    rules.set(rules_with_secondary_ip(ip));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    let count = orch.install_for_sid("S-1-5-21-A").unwrap();
    // 1 rule permit + ALE pair (permit+block) + packet pair (egress
    // permit + block per named packet protocol) = 1 + 2 + 4×2 = 11, plus
    // the IPv6 closure (loopback, link-local and link-local-multicast
    // exemptions, a tunnel-egress permit and a block, at both v6 layers
    // = 10): a pinned host with an AAAA record would otherwise keep an
    // unpinned way out, and the egress permit is what keeps a tunnel whose
    // endpoint is v6 able to reconnect through its own cut.
    assert_eq!(count, 21);

    let filters = api.wfp_filters.lock().unwrap();
    assert_eq!(filters.len(), 21);
    // Egress-conditional permits carry the LUID: the v4 ones (ALE plus one
    // per named packet protocol) are scoped to the protected destination;
    // the two v6 ones are not - the v6 cut is family-wide, so what it
    // permits through the tunnel is family-wide too.
    let egress_permits: Vec<_> = filters
        .iter()
        .filter(|f| f.local_interface_luid == Some(KS_LUID))
        .collect();
    assert_eq!(egress_permits.len(), 7);
    assert!(egress_permits.iter().all(|f| f.action == WfpAction::Permit));
    assert_eq!(
        egress_permits.iter().filter(|f| f.covers_v4(ip)).count(),
        5,
        "the v4 egress permits are destination-scoped",
    );
    // Blocks over the pinned address: 1 ALE + 4 named packet, unconditional
    // on the egress interface. The two IPv6 blocks are counted apart — they
    // close a family, not a destination, so they carry no `remote_ip`.
    let blocks: Vec<_> = filters
        .iter()
        .filter(|f| f.action == WfpAction::Block)
        .collect();
    let v4_blocks = blocks.iter().filter(|f| f.covers_v4(ip)).count();
    let v6_blocks = blocks
        .iter()
        .filter(|f| f.remote_ip.is_none() && f.remote_ip_set.is_empty())
        .count();
    assert_eq!(v4_blocks, 5);
    assert_eq!(v6_blocks, 2, "one per IPv6 layer");
    assert!(blocks
        .iter()
        .filter(|f| f.covers_v4(ip))
        .all(|f| f.local_interface_luid.is_none()));
}

#[test]
fn reconcile_swaps_stale_luid_permit_and_keeps_blocks() {
    // regression: a secondary adapter reconnect that changes the
    // secondary LUID must install the new-LUID egress permits and reap the
    // dead old-LUID ones, WITHOUT touching the (LUID-free) block filters —
    // window-free (the guard is never lifted).
    use std::sync::atomic::{AtomicU64, Ordering};
    const LUID_A: u64 = 0xAAAA_0000_0000_0001;
    const LUID_B: u64 = 0xBBBB_0000_0000_0002;
    let ip = Ipv4Addr::new(203, 0, 113, 9);

    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let luid_cell = Arc::new(AtomicU64::new(LUID_A));
    let luid_for_resolver = Arc::clone(&luid_cell);
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(move |_| {
            Some(KillSwitchResolution {
                secondary_luid: luid_for_resolver.load(Ordering::SeqCst),
                ..Default::default()
            })
        })),
    );
    rules.set(rules_with_secondary_ip(ip));
    source.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    // Initial install with LUID_A.
    orch.install_for_sid("S-1-5-21-A").unwrap();
    let block_ids_before: std::collections::HashSet<u64> = api
        .wfp_filters
        .lock()
        .unwrap()
        .iter()
        .filter(|f| f.action == WfpAction::Block)
        .map(|f| f.id.raw)
        .collect();
    assert_eq!(
        block_ids_before.len(),
        7,
        "blocks armed: 1 ALE + 4 named packet over the pinned address, plus one IPv6 block per v6 layer (a pinned host with an AAAA record must not keep an unpinned way out)"
    );
    assert_eq!(
        api.wfp_filters
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f.local_interface_luid == Some(LUID_A))
            .count(),
        7,
        "egress permits pinned to LUID_A: 1 ALE + 4 named packet + one per v6 layer"
    );

    // Secondary adapter reconnect: the resolver now yields a new LUID.
    luid_cell.store(LUID_B, Ordering::SeqCst);
    let added = orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();
    assert_eq!(
        added, 7,
        "reconcile installs the new-LUID egress permits: 5 over v4 plus one per v6 layer"
    );

    let after = api.wfp_filters.lock().unwrap();
    assert_eq!(
        after
            .iter()
            .filter(|f| f.local_interface_luid == Some(LUID_B))
            .count(),
        7,
        "new-LUID egress permits installed: 5 over v4 plus one per v6 layer"
    );
    assert_eq!(
        after
            .iter()
            .filter(|f| f.local_interface_luid == Some(LUID_A))
            .count(),
        0,
        "dead old-LUID permits reaped (gap #2 fix)"
    );
    let block_ids_after: std::collections::HashSet<u64> = after
        .iter()
        .filter(|f| f.action == WfpAction::Block)
        .map(|f| f.id.raw)
        .collect();
    assert_eq!(
        block_ids_after, block_ids_before,
        "block filters unchanged across the swap — window-free, guard never lifted"
    );
}

#[test]
fn reconcile_is_noop_when_luid_and_ips_unchanged() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, src, rules) = fixture_with_luid(Some(KS_LUID));
    rules.set(rules_with_secondary_ip(ip));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();
    let before = api.wfp_filters.lock().unwrap().len();

    let added = orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();
    assert_eq!(added, 0, "stable LUID + IP set → reconcile is a no-op");
    assert_eq!(
        api.wfp_filters.lock().unwrap().len(),
        before,
        "filter set unchanged when nothing changed"
    );
}

#[test]
fn reconcile_is_noop_for_uninstalled_sid() {
    let (_api, orch, _src, _rules) = fixture_with_luid(Some(KS_LUID));
    // No install_for_sid → the SID is unknown; reconcile must not panic or
    // install anything (that path is owned by `reconcile`).
    assert_eq!(orch.reconcile_secondary_coverage("S-1-5-21-Z").unwrap(), 0);
}

#[test]
fn kill_switch_arms_when_secondary_bound_even_without_flag() {
    // binding a secondary adapter is itself the
    // request to protect its traffic, so the leak-guard now arms on the
    // bound secondary alone, even with the opt-in
    // `block_secondary_when_unavailable` toggle OFF. Before 0706 this SID
    // carried only the bare rule permit and leaked to the primary the
    // instant the secondary adapter dropped (HW test #2/#8: zero kill-switch codegen
    // log lines for the whole run because the gate was toggle-only).
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, src, rules) = fixture_with_luid(Some(KS_LUID));
    rules.set(rules_with_secondary_ip(ip));
    // block_secondary_when_unavailable is false in snap_full — the bound
    // secondary must arm the guard regardless of the opt-in toggle.
    let s = snap_full("Wi-Fi", "TAP");
    assert!(!s.block_secondary_when_unavailable);
    src.set("S-1-5-21-A", s);

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    // The LUID-conditional egress pair (permit-via-secondary + block-off-secondary) is
    // the kill-switch's signature — its presence proves the guard armed off
    // the bound secondary alone, with the toggle still off.
    assert!(
        filters
            .iter()
            .any(|f| f.local_interface_luid == Some(KS_LUID)),
        "a bound secondary must arm the LUID-pinned kill-switch even with the toggle off",
    );
    assert!(
        filters.iter().any(|f| f.action == WfpAction::Block),
        "the kill-switch must install the off-secondary block half",
    );
}

#[test]
fn strict_mode_arms_leak_guard_even_without_explicit_flag() {
    // regression for the Strict-mode leak.
    // Choosing StrictSecondaryFailClosed as the default-route mode must
    // install block filters on its own: the Fail-Closed banner probe
    // already reports this mode as "protected", so if enforcement gated
    // only on `block_secondary_when_unavailable` the real IP would leak
    // while the UI claimed protection.
    let (api, orch, src, rules) = fixture_with_resolution(Some(full_ks_resolution()));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
    let mut s = snap_full("Wi-Fi", "TAP");
    s.mode = PerSidBehaviorMode::StrictSecondaryFailClosed;
    // The separate toggle stays OFF on purpose — the strict MODE alone
    // must arm the guard.
    assert!(!s.block_secondary_when_unavailable);
    src.set("S-1-5-21-A", s);

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    // The catch-all kill-switch is the only source of an egress-via-secondary
    // exemption (LUID-conditional permit) and the loopback/link-local/LAN
    // subnet exemptions — their presence proves the guard armed off the
    // strict MODE alone (the toggle was off). Before the fix this SID would
    // carry none of them.
    assert_eq!(
        filters
            .iter()
            .filter(|f| f.local_interface_luid == Some(KS_LUID))
            .count(),
        2,
        "strict mode arms the catch-all: egress-via-secondary exemption at both layers (0704 P2)",
    );
    assert!(
        filters.iter().filter(|f| f.remote_subnet.is_some()).count() >= 3,
        "strict mode arms the catch-all: loopback + link-local + LAN exemptions present",
    );
}

#[test]
fn reconcile_swaps_block_shape_on_vpn_loss_without_uncovering() {
    // the secondary adapter disappears
    // (resolver Some→None) under fail-closed. reconcile swaps the per-dest
    // block SHAPE (block_off_secondary → fail-closed ale_block) make-before-
    // break: the destination stays covered by a block after the swap, and
    // the dead egress permit is reaped.
    use std::sync::atomic::{AtomicBool, Ordering};
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let vpn_up = Arc::new(AtomicBool::new(true));
    let vpn_for_resolver = Arc::clone(&vpn_up);
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(move |_| {
            if vpn_for_resolver.load(Ordering::SeqCst) {
                Some(KillSwitchResolution {
                    secondary_luid: KS_LUID,
                    ..Default::default()
                })
            } else {
                None // secondary adapter gone
            }
        })),
    );
    rules.set(rules_with_secondary_ip(ip));
    let mut s = snap_block("Wi-Fi", "TAP");
    s.kill_switch_fail_closed = true;
    source.set("S-1-5-21-A", s);

    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert!(
        api.wfp_filters
            .lock()
            .unwrap()
            .iter()
            .any(|f| f.action == WfpAction::Block && f.covers_v4(ip)),
        "dest covered by a block while secondary adapter up"
    );

    // Secondary adapter disappears → fail-closed branch.
    vpn_up.store(false, Ordering::SeqCst);
    orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();
    let after = api.wfp_filters.lock().unwrap();
    assert!(
        after.iter().any(|f| f.action == WfpAction::Block
            && (f.covers_v4(ip) || (f.remote_ip.is_none() && f.remote_ip_set.is_empty()))),
        "dest still covered by a block after secondary adapter loss — no uncovering window"
    );
    assert_eq!(
        after
            .iter()
            .filter(|f| f.local_interface_luid == Some(KS_LUID))
            .count(),
        0,
        "dead-LUID egress permit reaped on the transition"
    );
}

#[test]
fn builtin_vpn_globs_resolve_to_paths_no_glob_in_fail_closed_set() {
    // with the secondary unresolved (VPN down) the
    // `None` fail-closed branch installs the built-in VPN-client exemption
    // permits so the client can bootstrap through the block. Those permits must
    // carry RESOLVED on-disk paths, never the raw `DEFAULT_VPN_EXEMPT_PATTERNS`
    // globs — a glob in `ALE_APP_ID` is silently dropped at apply, so a
    // verbatim glob would trap the client under its own kill-switch.
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    // Map the built-in `openvpn*` glob to a concrete exe; the other built-ins
    // resolve to nothing (client not installed) and simply drop out.
    let resolver = nrr_platform_api::MockAppPathResolver::new().with(
        "openvpn.exe",
        vec![std::path::PathBuf::from(r"C:\Tools\openvpn.exe")],
    );
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_app_resolver(Arc::new(resolver))
        // Secondary unresolved → the `None` fail-closed branch (VPN down).
        .with_kill_switch_resolver(Arc::new(|_| None)),
    );
    rules.set(rules_with_n_primary_ips(1));
    source.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();

    // The resolved openvpn path is present as an exempt Permit (no remote ip).
    assert!(
        filters.iter().any(|f| f.action == WfpAction::Permit
            && (f.remote_ip.is_none() && f.remote_ip_set.is_empty())
            && f.app_pattern.as_deref() == Some(r"C:\Tools\openvpn.exe")),
        "built-in openvpn glob installed an exempt permit stamped with the resolved path",
    );
    // The core HW-0716 assertion: NO installed filter carries a glob in
    // `app_pattern` — a verbatim glob would never enforce.
    assert!(
        filters.iter().all(|f| f
            .app_pattern
            .as_deref()
            .map(|p| !p.contains('*') && !p.contains('?'))
            .unwrap_or(true)),
        "no glob may leave the orchestrator's fail-closed exempt set",
    );
}

#[test]
fn reconcile_reaps_dead_permits_even_when_new_permit_add_skips() {
    // a SKIPPED PERMIT must NOT defer the delete:
    // skipping a permit only tightens (the block half stays), so the dead-LUID
    // permits are still reaped. This keeps gap #2 working on reconnects even
    // when a secondary rule's app is unresolvable — the over-broad "any skip
    // defers" gate would have re-defeated the fix here.
    use std::sync::atomic::{AtomicU64, Ordering};
    const LUID_A: u64 = 0xAAAA_0000_0000_0001;
    const LUID_B: u64 = 0xBBBB_0000_0000_0002;
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let luid_cell = Arc::new(AtomicU64::new(LUID_A));
    let luid_for_resolver = Arc::clone(&luid_cell);
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(move |_| {
            Some(KillSwitchResolution {
                secondary_luid: luid_for_resolver.load(Ordering::SeqCst),
                ..Default::default()
            })
        })),
    );
    rules.set(rules_with_secondary_ip(ip));
    source.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();

    // Force every LUID_B egress PERMIT's ADD to skip (blocks add fine).
    let luid_b_permit_ids: Vec<u64> = crate::killswitch_codegen::kill_switch_filters(
        "S-1-5-21-A",
        &[ip],
        LUID_B,
        crate::killswitch_codegen::KillSwitchProtocols::from_bits(0x7F),
    )
    .iter()
    .filter(|s| s.action == WfpAction::Permit)
    .map(|s| s.id.raw)
    .collect();
    assert!(!luid_b_permit_ids.is_empty());
    api.set_fail_add_unmaterializable(&luid_b_permit_ids);

    // Reconnect: LUID flips to B; the new permits skip but no BLOCK skipped.
    luid_cell.store(LUID_B, Ordering::SeqCst);
    orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();

    let after = api.wfp_filters.lock().unwrap();
    // The dead LUID_A permits WERE reaped (permit skip does not defer).
    assert_eq!(
        after
            .iter()
            .filter(|f| f.local_interface_luid == Some(LUID_A))
            .count(),
        0,
        "gap #2 preserved: dead-LUID permits reaped despite a skipped replacement permit"
    );
    // The block still covers the dest (fail-safe — no leak while the new
    // permit is absent).
    assert!(
        after
            .iter()
            .any(|f| f.action == WfpAction::Block && f.covers_v4(ip)),
        "dest stays covered by its block"
    );
}

#[test]
fn reconcile_defers_delete_when_replacement_block_add_skipped() {
    // (gap #2 leak-safety — the DEFECT the adversarial verify
    // found): if a replacement BLOCK's ADD is best-effort-SKIPPED, the
    // superseded block must NOT be deleted (else its dest is uncovered → leak).
    // Here the rule's dest changes IP1→IP2 on a reconnect and IP2's new block
    // is forced to skip, so IP1's OLD block must survive (delete deferred).
    use std::sync::atomic::{AtomicU64, Ordering};
    const LUID_A: u64 = 0xAAAA_0000_0000_0001;
    const LUID_B: u64 = 0xBBBB_0000_0000_0002;
    let ip1 = Ipv4Addr::new(203, 0, 113, 9);
    let ip2 = Ipv4Addr::new(198, 51, 100, 7);
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let luid_cell = Arc::new(AtomicU64::new(LUID_A));
    let luid_for_resolver = Arc::clone(&luid_cell);
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(move |_| {
            Some(KillSwitchResolution {
                secondary_luid: luid_for_resolver.load(Ordering::SeqCst),
                ..Default::default()
            })
        })),
    );
    rules.set(rules_with_secondary_ip(ip1));
    source.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();

    // Force IP2's new BLOCK adds to be unmaterializable (its permits add fine).
    let ip2_block_ids: Vec<u64> = crate::killswitch_codegen::kill_switch_filters(
        "S-1-5-21-A",
        &[ip2],
        LUID_B,
        crate::killswitch_codegen::KillSwitchProtocols::from_bits(0x7F),
    )
    .iter()
    .filter(|s| s.action == WfpAction::Block)
    .map(|s| s.id.raw)
    .collect();
    assert!(!ip2_block_ids.is_empty());
    api.set_fail_add_unmaterializable(&ip2_block_ids);

    // Rule dest changes IP1→IP2 and the secondary adapter reconnects to LUID_B.
    rules.set(rules_with_secondary_ip(ip2));
    luid_cell.store(LUID_B, Ordering::SeqCst);
    orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();

    // IP2's block add skipped → the whole delete pass is deferred, so IP1's
    // OLD block survives (over-coverage) rather than being torn down while a
    // replacement block is missing.
    assert!(
        api.wfp_filters
            .lock()
            .unwrap()
            .iter()
            .any(|f| f.action == WfpAction::Block && f.covers_v4(ip1)),
        "delete deferred: old block survives when a replacement block add was skipped"
    );
}

#[test]
fn is_app_only_block_classifies_only_appscoped_dest_less_blocks() {
    // the deferral gate must arm on destination-covering block
    // skips (leak risk) but NOT on app-only block skips (a missing exe
    // covers no destination and otherwise deferred the delete pass forever).
    use nrr_platform_api::types::WfpLayerKey;
    fn spec(
        action: WfpAction,
        remote_ip: Option<Ipv4Addr>,
        app: Option<&str>,
        subnet: Option<(Ipv4Addr, u8)>,
    ) -> WfpFilterSpec {
        WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action,
            remote_ip,
            remote_ip_set: Vec::new(),
            remote_port: None,
            weight: 0,
            id: WfpFilterId::from_raw(1),
            user_sid: None,
            app_pattern: app.map(str::to_string),
            local_interface_luid: None,
            remote_subnet: subnet,
            remote_subnet_v6: None,
            ip_protocol: None,
        }
    }
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    // App-scoped block with no destination → app-only (gate must NOT arm).
    assert!(is_app_only_block(&spec(
        WfpAction::Block,
        None,
        Some("C:/app.exe"),
        None
    )));
    // App-scoped block that ALSO pins a destination IP → not app-only.
    assert!(!is_app_only_block(&spec(
        WfpAction::Block,
        Some(ip),
        Some("C:/app.exe"),
        None
    )));
    // Catch-all block (no remote, no app) → not app-only (must arm the gate).
    assert!(!is_app_only_block(&spec(
        WfpAction::Block,
        None,
        None,
        None
    )));
    // Destination block (remote_ip, no app) → not app-only.
    assert!(!is_app_only_block(&spec(
        WfpAction::Block,
        Some(ip),
        None,
        None
    )));
    // Subnet block → not app-only.
    assert!(!is_app_only_block(&spec(
        WfpAction::Block,
        None,
        None,
        Some((ip, 24))
    )));
    // A PERMIT is never a "block", regardless of app scope.
    assert!(!is_app_only_block(&spec(
        WfpAction::Permit,
        None,
        Some("C:/app.exe"),
        None
    )));
}

#[test]
fn kill_switch_fails_open_when_luid_unresolved_and_posture_is_fail_open() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    // Flag is ON but posture is fail-OPEN, and the LUID can't resolve.
    let (api, orch, src, rules) = fixture_with_luid(None);
    rules.set(rules_with_secondary_ip(ip));
    src.set("S-1-5-21-A", snap_block_fail_open("Wi-Fi", "TAP"));

    let count = orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(count, 1, "fail-open → no kill-switch, no black hole");
    let filters = api.wfp_filters.lock().unwrap();
    assert!(
        filters
            .iter()
            .all(|f| f.action == WfpAction::Permit && f.local_interface_luid.is_none()),
        "fail-open leaves only the rule permit — no block, no egress condition"
    );
}

#[test]
fn kill_switch_fail_closed_blocks_secondary_dest_when_luid_unresolved() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    // Flag ON, posture fail-CLOSED (the default), LUID unresolvable
    // (secondary adapter gone / never bound) → the protected destination must be
    // BLOCKED, not leaked. This is HW-test finding #4.
    let (api, orch, src, rules) = fixture_with_luid(None);
    rules.set(rules_with_secondary_ip(ip));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    let count = orch.install_for_sid("S-1-5-21-A").unwrap();
    // rule permit (1) + fail-closed blocks over the dest: 1 ALE (TCP/UDP)
    // + 4 named packet blocks (ICMP/IGMP/GRE/ESP) = 5 blocks, plus the
    // IPv6 cut that now rides along with the per-IP path.
    assert_eq!(count, 6 + EXEMPT + V6_CUT);
    let filters = api.wfp_filters.lock().unwrap();
    // v4 only: the IPv6 half of the set is the family cut, checked in its
    // own test — here the subject is the per-destination block.
    let blocks: Vec<_> = filters
        .iter()
        .filter(|f| f.action == WfpAction::Block)
        .filter(|f| {
            !matches!(
                f.layer,
                nrr_platform_api::types::WfpLayerKey::AleAuthConnectV6
                    | nrr_platform_api::types::WfpLayerKey::OutboundIpPacketV6
            )
        })
        .collect();
    assert_eq!(
        blocks.len(),
        5,
        "fail-closed blocks the secondary dest at the ALE + named packet layers"
    );
    for b in &blocks {
        assert!(b.covers_v4(ip));
        assert_eq!(
            b.local_interface_luid, None,
            "no tunnel to permit through — the block is unconditional"
        );
    }
}

/// A delete that fails must not erase the accounting for the filters it
/// failed to delete: `cleanup_wfp` removes tracked filters BY ID, so an
/// untracked block survives even a graceful stop.
#[test]
fn a_failed_remove_keeps_the_filters_on_the_books() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, src, rules) = fixture_with_luid(Some(0x0001_0000_0000_0007));
    rules.set(rules_with_secondary_ip(ip));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    let installed = orch.install_for_sid("S-1-5-21-A").unwrap();
    assert!(installed > 0);
    assert_eq!(orch.installed_sids(), vec!["S-1-5-21-A".to_string()]);

    api.set_force_error(Some(nrr_platform_api::PlatformError::Transient {
        operation: "delete_filter",
        detail: "wfp busy".into(),
    }));
    assert!(orch.remove_for_sid("S-1-5-21-A").is_err());
    assert_eq!(
        orch.installed_sids(),
        vec!["S-1-5-21-A".to_string()],
        "the SID must stay on the books while its filters are still installed"
    );

    // With the platform back, the tracked ids are still there to delete.
    api.set_force_error(None);
    assert!(orch.cleanup_wfp().unwrap() > 0);
}

/// The per-IP posture is the DEFAULT one, and it leaves the block-all latch
/// disarmed — so a reader that keys on the block-all flag believes nothing
/// is being blocked while rule destinations are. The wider latch is what
/// the DNS handler and the seeder read.
#[test]
fn the_wider_fail_closed_latch_arms_on_the_per_ip_posture_too() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let (_api, orch, src, rules) = fixture_with_luid(None);
    rules.set(rules_with_secondary_ip(ip));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert!(
        !orch.any_block_all_armed(),
        "per-IP posture: the catch-all is not what armed"
    );
    assert!(
        orch.any_fail_closed_armed(),
        "but the guard IS blocking, and that is what a DNS answer must key on"
    );

    // Removing the set disarms it — a later re-arm must read as a real edge.
    orch.remove_for_sid("S-1-5-21-A").unwrap();
    assert!(!orch.any_fail_closed_armed());
}

#[test]
fn link_provider_app_earns_app_exempt_permit_under_fail_closed() {
    // the user-confirmed link-provider app (VPN client)
    // must be permitted through the fail-closed kill-switch by app id, so
    // the app that establishes the secondary link can always (re)connect
    // (the C4 self-blocking class from HW-0717/0718: the client could not
    // reach its server until the kill-switch was disabled).
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, src, rules) = fixture_with_luid(None); // secondary unresolved
    rules.set(rules_with_secondary_ip(ip));
    let mut snap = snap_block("Wi-Fi", "TAP");
    snap.link_provider_exe_paths = vec!["C:\\Apps\\tunnel-client.exe".into()];
    src.set("S-1-5-21-A", snap);

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    let exempt = filters
        .iter()
        .find(|f| {
            f.action == WfpAction::Permit
                && f.app_pattern.as_deref() == Some("C:\\Apps\\tunnel-client.exe")
        })
        .expect("configured link-provider app must earn an ALE app-id permit");
    assert!(
        exempt.weight >= 0x0060_0000,
        "the provider permit must sit in the APP_EXEMPT band above every kill-switch block (got {:#x})",
        exempt.weight
    );
    assert_eq!(
        exempt.user_sid.as_deref(),
        Some("S-1-5-21-A"),
        "ALE app exemption stays scoped to the caller SID"
    );
}

// ── Proactive VPN-client app exemption ─────────────────────

/// [`fixture_with_resolution`] plus a wired verified-VPN-client provider,
/// for the proactive app-exemption tests.
#[allow(clippy::type_complexity)]
fn fixture_with_resolution_and_vpn_clients(
    resolution: Option<KillSwitchResolution>,
    client_paths: Vec<String>,
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
        .with_kill_switch_resolver(Arc::new(move |_| resolution.clone()))
        .with_vpn_client_apps_provider(Arc::new(move || client_paths.clone())),
    );
    (api, orch, source, rules)
}

const VPN_CLIENT_PATH: &str = r"C:\Apps\hidemy.name vpn 3.0.exe";

/// Find the app-exempt permit for [`VPN_CLIENT_PATH`], if any installed.
fn find_client_exempt(
    filters: &[nrr_platform_api::WfpFilterRecord],
) -> Option<nrr_platform_api::WfpFilterRecord> {
    filters
        .iter()
        .find(|f| {
            f.action == WfpAction::Permit
                && f.app_pattern.as_deref() == Some(VPN_CLIENT_PATH)
                && f.local_interface_luid.is_none()
        })
        .cloned()
}

#[test]
fn verified_vpn_client_exempt_installed_when_mode_b_catch_all_arms() {
    // The core proactive guarantee: the catch-all arms with the tunnel UP,
    // and the verified client's app permit is installed IN THE SAME
    // compute — before any drop of the session. Its connectivity checks
    // against rotating provider IPs over the primary link then always
    // escape by app id, so the reactive per-IP learner is no longer on the
    // critical path.
    let (api, orch, src, rules) = fixture_with_resolution_and_vpn_clients(
        Some(full_ks_resolution()),
        vec![VPN_CLIENT_PATH.to_string()],
    );
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
    src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    let exempt = find_client_exempt(&filters)
        .expect("verified VPN client must earn an app permit when the catch-all arms");
    assert!(
        exempt.weight >= 0x0060_0000,
        "client permit must sit in the APP_EXEMPT band above the catch-all block (got {:#x})",
        exempt.weight
    );
    assert_eq!(
        exempt.user_sid.as_deref(),
        Some("S-1-5-21-A"),
        "app exemption stays scoped to the caller SID"
    );
    assert_eq!(
        exempt.remote_ip, None,
        "app-scoped, not destination-scoped — IP rotation must not matter"
    );
}

#[test]
fn verified_vpn_client_exempt_installed_when_pair_cannot_arm_fail_closed() {
    // Resolution exists (LUID known) but carries no bootstrap server IPs,
    // so the mode-B catch-all cannot arm and the posture falls back to
    // fail-closed blocking — the client app must be permitted through that
    // block too (this branch historically emitted no app exemptions).
    let resolution = KillSwitchResolution {
        secondary_luid: KS_LUID,
        bootstrap_server_ips: Vec::new(),
        local_subnets: Vec::new(),
    };
    let (api, orch, src, rules) = fixture_with_resolution_and_vpn_clients(
        Some(resolution),
        vec![VPN_CLIENT_PATH.to_string()],
    );
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
    src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    let exempt = find_client_exempt(&filters)
        .expect("verified VPN client must be permitted through the fail-closed block");
    assert!(exempt.weight >= 0x0060_0000);
}

#[test]
fn verified_vpn_client_exempt_not_emitted_for_mode_a_pinning() {
    // Mode A with the tunnel UP arms only per-destination pins — there is
    // no catch-all, so an unconditional app permit would only weaken the
    // pinned-destination guarantee. The proactive exemption must stay out.
    let (api, orch, src, rules) = fixture_with_resolution_and_vpn_clients(
        Some(full_ks_resolution()),
        vec![VPN_CLIENT_PATH.to_string()],
    );
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP")); // PreferPrimary

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    assert!(
        find_client_exempt(&filters).is_none(),
        "mode A per-destination pinning must not carry an app-wide permit"
    );
}

#[test]
fn fail_closed_block_all_permits_what_the_main_link_names_and_nothing_else() {
    // Under a Mode-A FailClosedUnknown block-all (secondary unresolved) a
    // host matched by a primary rule earns a packet-layer permit, so ping
    // survives — INCLUDING one the secondary rules also name. Two of the
    // user's rules pointing one address in opposite directions is not a
    // reason to block it: blocking is a third outcome neither rule asked
    // for, and the main link is the one the user can still see and correct.
    // A host only the SECONDARY names is the leak case, and stays blocked.
    use nrr_domain::mode_a_coverage::ModeACoverageStrategy;
    let primary_only = Ipv4Addr::new(203, 0, 113, 20);
    let shared = Ipv4Addr::new(203, 0, 113, 21);
    let secondary_only = Ipv4Addr::new(203, 0, 113, 22);
    let (api, orch, src, rules) = fixture_with_luid(None); // secondary unresolved
    rules.set(ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![
                primary_ip_rule("r-pri", primary_only),
                primary_ip_rule("r-shared-pri", shared),
            ]),
            secondary: CanonicalRuleSet::from_rules(vec![
                primary_ip_rule("r-shared-sec", shared),
                primary_ip_rule("r-sec-only", secondary_only),
            ]),
        },
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    });
    let mut snap = snap_block("Wi-Fi", "TAP");
    snap.mode_a_coverage_strategy = ModeACoverageStrategy::FailClosedUnknown;
    src.set("S-1-5-21-A", snap);

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    use nrr_platform_api::types::WfpLayerKey;
    let has_primary_permit = |ip: Ipv4Addr| {
        filters.iter().any(|f| {
            f.layer == WfpLayerKey::OutboundTransportV4
                && f.action == WfpAction::Permit
                && f.covers_v4(ip)
                && f.ip_protocol.is_none()
        })
    };
    assert!(
        has_primary_permit(primary_only),
        "a primary-only host gets a transport permit so ping survives the block-all (HW-0718)"
    );
    assert!(
        has_primary_permit(shared),
        "an address the main link's own rule names is never blocked, in either mode"
    );
    assert!(
        !has_primary_permit(secondary_only),
        "an address only the secondary names must fail closed while the tunnel is down"
    );
}

/// [`FqdnCacheLookup`] wrapper with a scripted shared-IP census — for the
/// smart-kill-switch exemption tests.
struct CensusCache {
    inner: MockFqdnCacheLookup,
    shared: std::collections::HashSet<Ipv4Addr>,
}
impl FqdnCacheLookup for CensusCache {
    fn ips_for_hostname(&self, hostname: &str) -> Vec<Ipv4Addr> {
        self.inner.ips_for_hostname(hostname)
    }
    fn hostnames_under_suffix(&self, suffix: &str, limit: usize) -> Vec<String> {
        self.inner.hostnames_under_suffix(suffix, limit)
    }
    fn direct_host_count_for_ip(&self, ip: Ipv4Addr) -> u32 {
        u32::from(self.shared.contains(&ip))
    }
    fn shared_direct_ips(&self) -> std::collections::HashSet<Ipv4Addr> {
        self.shared.clone()
    }
}

/// Like [`fixture_with_resolution`], but with a scripted shared-IP census
/// and an optional known-direct registry. `fake_ip_effective` scripts the
/// live "hostname enforcement is active" signal the smart shared-IP
/// exemption gates on: while `true` the fake-IP context
/// provider yields an enabled scope, mirroring the production provider's
/// toggle-AND-Resolver-AND-running condition; flip it between installs to
/// model a datapath transition.
#[allow(clippy::type_complexity)]
fn fixture_with_census(
    resolution: Option<KillSwitchResolution>,
    shared: &[Ipv4Addr],
    known_direct: Option<Arc<crate::known_direct::KnownDirectRegistry>>,
    fake_ip_effective: Arc<std::sync::atomic::AtomicBool>,
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
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(CensusCache {
        inner: MockFqdnCacheLookup::new(),
        shared: shared.iter().copied().collect(),
    });
    let audit = Arc::new(CollectAudit::default());
    let mut orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    )
    .with_kill_switch_resolver(Arc::new(move |_| resolution.clone()))
    .with_fake_ip_context_provider(Arc::new(move || {
        fake_ip_effective
            .load(std::sync::atomic::Ordering::Relaxed)
            .then(|| crate::fake_ip::FakeIpEnforcementContext {
                scope: nrr_platform_api::fake_ip::FakeIpScope::enabled(Vec::<String>::new()),
                pool: nrr_platform_api::fake_ip::FakeIpPoolConfig::default(),
            })
    }));
    if let Some(reg) = known_direct {
        orch = orch.with_known_direct_registry(reg);
    }
    (api, Arc::new(orch), source, rules)
}

/// An address the user named in a MAIN-route rule stays reachable under the
/// block-all in BOTH modes.
///
/// Re-based deliberately. This test used to assert that strict mode blocks
/// such an address — the historic pin-everything posture. A live machine
/// showed what that costs: two of the user's own rules named one address in
/// opposite directions, and the outcome was neither route but a block, dead
/// for every process on the machine. Strict mode governs whether SHARED
/// addresses are pinned; it cannot turn an explicit main-route rule into a
/// block, because a block is not one of the two things the user asked for.
#[test]
fn a_main_route_named_ip_is_spared_by_the_block_all_in_both_modes() {
    use nrr_domain::mode_a_coverage::ModeACoverageStrategy;
    use std::sync::atomic::AtomicBool;
    let shared = Ipv4Addr::new(209, 85, 233, 84);
    for (strict, expect_permit) in [(false, true), (true, true)] {
        let (api, orch, src, rules) = fixture_with_census(
            None,
            &[shared],
            None,
            Arc::new(AtomicBool::new(true)), // fake-IP effective
        );
        rules.set(ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(vec![primary_ip_rule("r-pri", shared)]),
                secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                    id: RuleId("r-sec".into()),
                    enabled: true,
                    address_match: Some(CanonicalAddressMatch::ExactIp(shared)),
                    app_match: None,
                    comment: String::new(),
                    action: nrr_domain::RuleAction::Route,
                    origin: None,
                }]),
            },
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        });
        let mut snap = snap_block("Wi-Fi", "TAP");
        snap.mode_a_coverage_strategy = ModeACoverageStrategy::FailClosedUnknown;
        snap.kill_switch_strict_shared_ips = strict;
        src.set("S-1-5-21-A", snap);

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        use nrr_platform_api::types::WfpLayerKey;
        let has_permit = filters.iter().any(|f| {
            f.layer == WfpLayerKey::OutboundTransportV4
                && f.action == WfpAction::Permit
                && f.covers_v4(shared)
                && f.ip_protocol.is_none()
        });
        assert_eq!(
            has_permit, expect_permit,
            "strict={strict}: an address a main-route rule names must stay reachable",
        );
    }
}

#[test]
fn known_direct_exemption_keeps_census_shared_ip_under_mode_b_block_all() {
    //  — the known-direct subtraction removes only PINNED IPs. A
    // census-shared IP (pin skipped while the secondary is unusable) stays
    // exemptible, so a direct co-tenant registered by a Mode-B answer
    // survives the block-all; a pinned (non-shared) secondary destination
    // is still subtracted and stays blocked. Requires an effective fake-IP
    // datapath since  (the rule host is then enforced by name).
    use std::sync::atomic::AtomicBool;
    let shared = Ipv4Addr::new(209, 85, 233, 84);
    let pinned = Ipv4Addr::new(203, 0, 113, 9);
    let registry = Arc::new(crate::known_direct::KnownDirectRegistry::default());
    registry.register(&[shared, pinned]);
    let (api, orch, src, rules) = fixture_with_census(
        None,
        &[shared],
        Some(Arc::clone(&registry)),
        Arc::new(AtomicBool::new(true)), // fake-IP effective
    );
    rules.set(ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(vec![
                primary_ip_rule("r-sec-1", shared),
                primary_ip_rule("r-sec-2", pinned),
            ]),
        },
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    });
    let mut snap = snap_block_mode_b("Wi-Fi", "TAP");
    snap.kill_switch_strict_shared_ips = false;
    src.set("S-1-5-21-A", snap);

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    use nrr_platform_api::types::WfpLayerKey;
    // Only filters in the catch-all EXEMPT band (0x0050_0000+) count —
    // the rule's own ALE permit sits in a lower band and exists for both
    // IPs regardless of the known-direct exemption.
    let exempt_permit = |ip: Ipv4Addr| {
        filters.iter().any(|f| {
            f.layer == WfpLayerKey::AleAuthConnectV4
                && f.action == WfpAction::Permit
                && f.covers_v4(ip)
                && f.weight >= 0x0050_0000
        })
    };
    assert!(
        exempt_permit(shared),
        "census-shared known-direct IP earns its block-all exemption (pin skipped)"
    );
    assert!(
        !exempt_permit(pinned),
        "a pinned secondary destination is still subtracted from the exemption"
    );
}

/// The rule book shared by the fake-IP-gate tests below: one census-shared
/// IP a SECONDARY rule names, reachable on the primary only through the
/// known-direct rescue.
///
/// No main-link rule on that address on purpose — an address both links
/// name never reaches the kill-switch as a secondary destination at all
/// (the arbiter settles it in the codegen), so putting one here would test
/// a state production cannot be in.
fn shared_ip_rule_book(shared: Ipv4Addr) -> ActiveRulesSnapshot {
    ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(vec![primary_ip_rule("r-sec", shared)]),
        },
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    }
}

#[test]
fn smart_exemption_requires_fake_ip_datapath() {
    //  — with the fake-IP datapath NOT effective the IP pin/block
    // set is the ONLY enforcement, so the smart shared-IP relaxation must
    // fall back to the strict subtraction: a census-shared secondary
    // destination earns NO known-primary permit under the block-all (in
    // the  run, 39 chatgpt.com connections egressed the primary
    // through this exemption while the rule host was fail-closed).
    use nrr_domain::mode_a_coverage::ModeACoverageStrategy;
    use std::sync::atomic::AtomicBool;
    let shared = Ipv4Addr::new(209, 85, 233, 84);
    let (api, orch, src, rules) = fixture_with_census(
        None,
        &[shared],
        None,
        Arc::new(AtomicBool::new(false)), // fake-IP NOT effective
    );
    rules.set(shared_ip_rule_book(shared));
    let mut snap = snap_block("Wi-Fi", "TAP");
    snap.mode_a_coverage_strategy = ModeACoverageStrategy::FailClosedUnknown;
    snap.kill_switch_strict_shared_ips = false; // smart mode requested
    src.set("S-1-5-21-A", snap);

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    use nrr_platform_api::types::WfpLayerKey;
    assert!(
        !filters.iter().any(|f| {
            f.layer == WfpLayerKey::OutboundTransportV4
                && f.action == WfpAction::Permit
                && f.covers_v4(shared)
                && f.ip_protocol.is_none()
        }),
        "without an effective fake-IP datapath a census-shared secondary \
         destination must stay blocked under the block-all (strict subtraction)"
    );
}

#[test]
fn known_direct_exemption_denied_for_shared_ip_when_fake_ip_not_effective() {
    //  — the known-direct rescue path (the proven
    // egress route) must apply the same fake-IP gate: with the datapath
    // down, a census-shared known-direct IP is subtracted like any other
    // secondary destination and earns no block-all exemption.
    use std::sync::atomic::AtomicBool;
    let shared = Ipv4Addr::new(209, 85, 233, 84);
    let registry = Arc::new(crate::known_direct::KnownDirectRegistry::default());
    registry.register(&[shared]);
    let (api, orch, src, rules) = fixture_with_census(
        None,
        &[shared],
        Some(Arc::clone(&registry)),
        Arc::new(AtomicBool::new(false)), // fake-IP NOT effective
    );
    rules.set(ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(vec![primary_ip_rule("r-sec", shared)]),
        },
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    });
    let mut snap = snap_block_mode_b("Wi-Fi", "TAP");
    snap.kill_switch_strict_shared_ips = false;
    src.set("S-1-5-21-A", snap);

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    use nrr_platform_api::types::WfpLayerKey;
    assert!(
        !filters.iter().any(|f| {
            f.layer == WfpLayerKey::AleAuthConnectV4
                && f.action == WfpAction::Permit
                && f.covers_v4(shared)
                && f.weight >= 0x0050_0000
        }),
        "known-direct must not rescue a census-shared secondary destination \
         while fake-IP is not covering the rule host by name"
    );
}

#[test]
fn fake_ip_datapath_flip_retightens_shared_ip_exemption_on_recompute() {
    // The gate is read LIVE on every compute, so the replan fired on a
    // fake-IP toggle/datapath transition (the composition root's fake-IP
    // replan hook, which runs the window-free `recompile_for_sid` diff) is
    // sufficient to tighten or loosen the known-direct rescue: same SID,
    // same rules, only the datapath signal flips between passes. The
    // tightening pass must also DELETE the superseded permit — an add-only
    // pass would leave the leak installed.
    use std::sync::atomic::{AtomicBool, Ordering};
    let shared = Ipv4Addr::new(209, 85, 233, 84);
    let effective = Arc::new(AtomicBool::new(true));
    let registry = Arc::new(crate::known_direct::KnownDirectRegistry::default());
    registry.register(&[shared]);
    let (api, orch, src, rules) = fixture_with_census(
        None,
        &[shared],
        Some(Arc::clone(&registry)),
        Arc::clone(&effective),
    );
    rules.set(shared_ip_rule_book(shared));
    let mut snap = snap_block_mode_b("Wi-Fi", "TAP");
    snap.kill_switch_strict_shared_ips = false;
    src.set("S-1-5-21-A", snap);

    use nrr_platform_api::types::WfpLayerKey;
    // Only the catch-all EXEMPT band counts — the rule's own ALE permit
    // sits lower and exists either way.
    let shared_permitted = |api: &MockWindowsApi| {
        api.wfp_filters.lock().unwrap().iter().any(|f| {
            f.layer == WfpLayerKey::AleAuthConnectV4
                && f.action == WfpAction::Permit
                && f.covers_v4(shared)
                && f.weight >= 0x0050_0000
        })
    };

    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert!(
        shared_permitted(&api),
        "datapath effective: the smart exemption spares the shared IP"
    );

    effective.store(false, Ordering::Relaxed); // datapath died / toggle off
    orch.recompile_for_sid("S-1-5-21-A").unwrap();
    assert!(
        !shared_permitted(&api),
        "recompute after the datapath flip must retighten to the strict subtraction"
    );

    effective.store(true, Ordering::Relaxed); // datapath recovered
    orch.recompile_for_sid("S-1-5-21-A").unwrap();
    assert!(
        shared_permitted(&api),
        "recovery replan restores the smart exemption"
    );
}

#[test]
fn kill_switch_disabled_disarms_leak_guard_even_when_secondary_unresolved() {
    // the MASTER kill-switch toggle is OFF (full opt-in).
    // Even with a secondary bound, the fail-CLOSED posture, and the secondary
    // adapter unresolvable (LUID None) — the exact conditions that block in
    // `kill_switch_fail_closed_blocks_secondary_dest_when_luid_unresolved` —
    // NO fail-closed block may be installed. Any leak is then the user's
    // deliberate choice; only the rule's own permit survives.
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, src, rules) = fixture_with_luid(None);
    rules.set(rules_with_secondary_ip(ip));
    let mut snap = snap_block("Wi-Fi", "TAP");
    snap.kill_switch_enabled = false; // master OFF
    src.set("S-1-5-21-A", snap);

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    assert!(
        filters.iter().all(|f| f.action != WfpAction::Block),
        "kill-switch OFF must install ZERO block filters even with the secondary \
         unresolved (full opt-in — leak-guard fully disarmed)"
    );
}

/// The posture that used to leave the family open: mode A, secondary gone,
/// per-IP blocking (no block-all). v4 destinations are cut, so a host with
/// an AAAA record must not keep an open way out over v6.
#[test]
fn the_per_ip_fail_closed_path_cuts_ipv6_too() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, src, rules) = fixture_with_luid(None);
    rules.set(rules_with_secondary_ip(ip));
    let snap = snap_block("Wi-Fi", "TAP");
    assert!(snap.block_ipv6_when_protected);
    assert!(!snap.kill_switch_block_all, "per-IP path, not block-all");
    src.set("S-1-5-21-A", snap);

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    for layer in [
        nrr_platform_api::types::WfpLayerKey::AleAuthConnectV6,
        nrr_platform_api::types::WfpLayerKey::OutboundIpPacketV6,
    ] {
        assert!(
            filters
                .iter()
                .any(|f| f.layer == layer && f.action == WfpAction::Block),
            "{layer:?}: the v6 family must be closed on the per-IP path too",
        );
    }
}

/// …and the opt-out still holds there: a principal who turned the family
/// switch off keeps IPv6 running, per-IP path included.
#[test]
fn the_per_ip_fail_closed_path_honours_the_ipv6_opt_out() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, src, rules) = fixture_with_luid(None);
    rules.set(rules_with_secondary_ip(ip));
    let mut snap = snap_block("Wi-Fi", "TAP");
    snap.block_ipv6_when_protected = false;
    src.set("S-1-5-21-A", snap);

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    assert!(
        filters.iter().all(|f| !matches!(
            f.layer,
            nrr_platform_api::types::WfpLayerKey::AleAuthConnectV6
                | nrr_platform_api::types::WfpLayerKey::OutboundIpPacketV6
        )),
        "the family switch is off — no v6 filter may be installed",
    );
}

#[test]
fn kill_switch_arms_with_no_secondary_bound_at_all() {
    // Turning the kill-switch on before any additional adapter exists is a
    // posture, not a mistake: the destinations rules send to the additional
    // route must be blocked rather than quietly leak to the main link.
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, src, rules) = fixture_with_luid(None);
    rules.set(rules_with_secondary_ip(ip));
    let mut snap = snap_full("Wi-Fi", "TAP");
    snap.secondary = None;
    snap.block_secondary_when_unavailable = false;
    assert!(snap.kill_switch_enabled);
    src.set("S-1-5-21-A", snap);

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    assert!(
        filters
            .iter()
            .any(|f| f.action == WfpAction::Block && f.covers_v4(ip)),
        "with the kill-switch on and no secondary bound, the routed destination must be blocked",
    );
}

#[test]
fn kill_switch_fail_closed_mode_b_blocks_all_when_unresolved() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    // Mode B (everything-via-secondary), fail-closed, secondary gone →
    // a catch-all block (plus the safe exemptions) must be installed.
    let (api, orch, src, rules) = fixture_with_luid(None);
    rules.set(rules_with_secondary_ip(ip));
    src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    let blocks: Vec<_> = filters
        .iter()
        .filter(|f| {
            f.action == WfpAction::Block
                && (f.remote_ip.is_none() && f.remote_ip_set.is_empty())
                && f.remote_subnet.is_none()
        })
        .collect();
    assert_eq!(
        blocks.len(),
        7,
        "mode-B fail-closed: V4 ALE block-all + 4 named V4 packet blocks (16.HW-0716) + V6 ALE + V6 packet block-all"
    );
}

/// Three things drive a recompute concurrently (the leak-guard tick, the
/// fake-IP replan, the IPC trigger). Without a per-SID lock the one that
/// started with the older reading finished last and reinstalled what the
/// other had just taken down.
/// The mode-B catch-all drops everything that does not leave through the
/// tunnel - that IS a block-all, and the service has to say so: the DNS
/// gate reads this to stop handing out answers for direct hosts, and the
/// GUI banner reads it to stay up while the block is live.
/// The Windows half of the same limitation the Linux cycle announces: the
/// WFP packet layers carry no `ALE_USER_ID`, so a cut one principal armed
/// takes ICMP and IPv6 from everyone. Before this the others just lost them.
#[test]
fn a_machine_wide_cut_is_announced_to_the_principal_who_did_not_ask_for_it() {
    use nrr_shared::ipc_payloads::StatusUpdateEvent;

    let bus = Arc::new(crate::ipc_handlers::event_bus::EventBus::new());
    let asked = bus.subscribe_as("gui-a".into(), Some("S-1-5-21-A".into()), Some(0));
    let bystander = bus.subscribe_as("gui-b".into(), Some("S-1-5-21-B".into()), Some(0));

    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let src = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let resolution = Some(full_ks_resolution());
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&src) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
        Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
    )
    .with_kill_switch_resolver(Arc::new(move |_| resolution.clone()))
    .with_events(Arc::clone(&bus));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));

    // B is on the primary with no cut of its own; A then arms the mode-B
    // catch-all, which is a packet-layer block-all.
    let mut bystander_policy = snap_primary_only("Wi-Fi");
    bystander_policy.block_ipv6_when_protected = false;
    src.set("S-1-5-21-B", bystander_policy);
    orch.install_for_sid("S-1-5-21-B").unwrap();
    src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();

    let is_notice = |e: &crate::ipc_handlers::event_bus::EventEntry| {
        matches!(
            &e.event,
            StatusUpdateEvent::ProtectionCoverageChanged { reason }
                if reason == "machine-wide-cut-by-another-user"
        )
    };
    assert!(
        bus.peek_pending_for(&bystander.subscription_id, 8)
            .iter()
            .any(is_notice),
        "the bystander must be told why their IPv6 and ICMP stopped",
    );
    assert!(
        !bus.peek_pending_for(&asked.subscription_id, 8)
            .iter()
            .any(is_notice),
        "the principal who armed the cut needs no notice",
    );
}

#[test]
fn a_live_catch_all_reports_itself_as_a_block_all() {
    let (_api, orch, src, rules) = fixture_with_resolution(Some(full_ks_resolution()));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
    src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert!(
        orch.any_block_all_armed(),
        "the catch-all is armed, so the posture must read as a block-all",
    );
}

#[test]
fn two_triggers_for_one_sid_do_not_interleave() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (api, orch, src, rules) = fixture_with_resolution(Some(full_ks_resolution()));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    let orch = Arc::new(orch);

    let inflight = Arc::new(AtomicUsize::new(0));
    let overlapped = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let orch = Arc::clone(&orch);
        let inflight = Arc::clone(&inflight);
        let overlapped = Arc::clone(&overlapped);
        handles.push(std::thread::spawn(move || {
            for _ in 0..8 {
                let lock = orch.apply_lock_for("S-1-5-21-A");
                let _g = lock.lock().unwrap_or_else(|p| p.into_inner());
                if inflight.fetch_add(1, Ordering::SeqCst) != 0 {
                    overlapped.fetch_add(1, Ordering::SeqCst);
                }
                std::thread::yield_now();
                inflight.fetch_sub(1, Ordering::SeqCst);
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    assert_eq!(
        overlapped.load(Ordering::SeqCst),
        0,
        "two applies for the same SID were in flight at once",
    );
    // And the orchestrator still works through that lock.
    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert!(!api.wfp_filters.lock().unwrap().is_empty());
}

#[test]
fn turning_the_guard_off_in_strict_does_not_cut_the_machine_off() {
    // The Strict default block belongs to the MODE, so it is emitted with
    // the guard off too. Its exemptions used to live inside the guard's
    // branch, so switching the kill-switch off left a bare block-all with
    // no loopback, no LAN, no DHCP and no route to the VPN server.
    let resolution = KillSwitchResolution {
        secondary_luid: KS_LUID,
        bootstrap_server_ips: vec![Ipv4Addr::new(9, 9, 9, 9)],
        local_subnets: vec![(Ipv4Addr::new(192, 168, 1, 0), 24)],
    };
    let (api, orch, src, rules) = fixture_with_resolution(Some(resolution));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 9)));
    src.set("S-1-5-21-A", snap_strict_guard_off("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    assert!(
        filters.iter().any(|f| f.action == WfpAction::Block
            && (f.remote_ip.is_none() && f.remote_ip_set.is_empty())
            && f.layer == WfpLayerKey::AleAuthConnectV4),
        "fixture guard: Strict must still emit its default block",
    );
    assert!(
        filters.iter().any(|f| f.action == WfpAction::Permit
            && f.remote_subnet == Some((Ipv4Addr::new(127, 0, 0, 0), 8))),
        "loopback must survive the default block",
    );
    assert!(
        filters.iter().any(|f| f.action == WfpAction::Permit
            && f.remote_subnet == Some((Ipv4Addr::new(192, 168, 1, 0), 24))),
        "the local network must survive it too",
    );
    assert!(
        filters
            .iter()
            .any(|f| f.action == WfpAction::Permit && f.covers_v4(Ipv4Addr::new(9, 9, 9, 9))),
        "and so must the way to the VPN server",
    );
}

#[test]
fn a_device_on_the_machines_own_lan_is_never_pinned_to_the_tunnel() {
    // An application rule learns destinations by watching, so a NAS, a
    // printer or the hypervisor's host address is exactly what it touches.
    // Pinned, that address is unreachable for the whole SID the moment the
    // tunnel drops - for a device one hop away on a cable.
    const NAS: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
    const REMOTE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
    let resolution = KillSwitchResolution {
        secondary_luid: KS_LUID,
        bootstrap_server_ips: vec![Ipv4Addr::new(9, 9, 9, 9)],
        local_subnets: vec![(Ipv4Addr::new(192, 168, 1, 0), 24)],
    };
    let (api, orch, src, rules) = fixture_with_resolution(Some(resolution));
    rules.set(rules_with_secondary_ips(&[NAS, REMOTE]));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    assert!(
        !filters
            .iter()
            .any(|f| f.covers_v4(NAS) && f.action == WfpAction::Block),
        "a host on the machine's own subnet must not be blocked when the tunnel drops",
    );
    assert!(
        filters
            .iter()
            .any(|f| f.covers_v4(REMOTE) && f.action == WfpAction::Block),
        "an ordinary remote destination is still protected",
    );
}

#[test]
fn a_healthy_tunnel_is_never_cut_by_the_guard_in_the_tunnel_default_modes() {
    // The tunnel is UP (LUID resolved) but the leak-proof pair cannot arm —
    // no bootstrap server IP to exempt, the everyday cold-cache case for
    // zone/suffix rules. The caller states it must NOT escalate here, and
    // passes `block_all: false`; the guard used to ignore that in the
    // tunnel-default modes and install a catch-all anyway, cutting every
    // egress on a healthy tunnel and deadlocking the cache warm-up that
    // would have lifted it.
    let resolution = KillSwitchResolution {
        secondary_luid: KS_LUID,
        bootstrap_server_ips: Vec::new(),
        local_subnets: Vec::new(),
    };
    let (api, orch, src, rules) = fixture_with_resolution(Some(resolution));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 9)));
    src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    let catch_all_v4 = filters.iter().any(|f| {
        f.action == WfpAction::Block
            && (f.remote_ip.is_none() && f.remote_ip_set.is_empty())
            && f.remote_subnet.is_none()
            && f.layer == WfpLayerKey::AleAuthConnectV4
    });
    assert!(
        !catch_all_v4,
        "a live tunnel must not be cut by a catch-all the caller explicitly declined",
    );
    // The per-IP guard is still there: declining to escalate is not
    // declining to guard.
    assert!(
        filters
            .iter()
            .any(|f| f.action == WfpAction::Block && f.covers_v4(Ipv4Addr::new(203, 0, 113, 9))),
        "the enumerated destination must still be blocked",
    );
}

/// A host that just became a rule host is, in every cache on the machine,
/// still an ordinary host with a real address — and that address is now
/// pinned to the tunnel. Unless the lookup is repeated, the application
/// keeps dialling an address that no longer has a path, which is what
/// "I added the rule and the site broke" actually is. Activation therefore
/// flushes the OS resolver cache.
#[test]
fn activating_a_rule_change_flushes_the_os_dns_cache() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let flusher = Arc::new(nrr_platform_api::MockDnsCacheControl::new());
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
    )
    .with_dns_cache_control(Arc::clone(&flusher) as Arc<dyn nrr_platform_api::DnsCacheControlPort>);
    let snapshot = rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 9));
    rules.set(snapshot.clone());
    source.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();
    let before = flusher.flush_count();

    orch.recompile_for_sid_with_rules("S-1-5-21-A", &snapshot)
        .unwrap();

    assert_eq!(
        flusher.flush_count(),
        before + 1,
        "activation must force a re-query for the hosts whose routing just changed"
    );
}

#[test]
fn block_all_arming_edge_flushes_os_dns_cache_once_per_transition() {
    // the OS resolver-cache flush fires exactly
    // once on the disarmed→armed edge and once on armed→disarmed; the
    // steady-state reconcile (same compute, every few seconds on HW) must
    // never flush, or the OS cache would be permanently defeated.
    use nrr_domain::mode_a_coverage::ModeACoverageStrategy;
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let flusher = Arc::new(nrr_platform_api::MockDnsCacheControl::new());
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
    )
    .with_kill_switch_resolver(Arc::new(|_| None)) // secondary unresolved
    .with_dns_cache_control(Arc::clone(&flusher) as Arc<dyn nrr_platform_api::DnsCacheControlPort>);
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 9)));
    let armed_snap = || {
        let mut s = snap_block("Wi-Fi", "TAP");
        s.mode_a_coverage_strategy = ModeACoverageStrategy::FailClosedUnknown;
        s
    };
    source.set("S-1-5-21-A", armed_snap());

    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(flusher.flush_count(), 1, "arming edge must flush once");
    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(
        flusher.flush_count(),
        1,
        "steady-state re-apply (reconcile tick) must NOT flush"
    );

    let mut disarmed = armed_snap();
    disarmed.kill_switch_enabled = false; // master OFF → block-all gone
    source.set("S-1-5-21-A", disarmed);
    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(flusher.flush_count(), 2, "disarming edge must flush once");
    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(
        flusher.flush_count(),
        2,
        "disarmed steady state must NOT flush"
    );
}

#[test]
fn posture_change_latch_reports_transitions_only() {
    // the kill-switch posture log throttle: full-
    // level lines fire only on a posture CHANGE per SID; the ~5 s reconcile
    // re-deriving the same posture must not re-log (NDJSON flood).
    let (_api, orch, _src, _rules) = fixture_with_luid(None);
    assert!(orch.posture_changed("S-A", "active"), "first sighting logs");
    assert!(
        !orch.posture_changed("S-A", "active"),
        "steady state is quiet"
    );
    assert!(
        orch.posture_changed("S-A", "unresolved-fail-closed-block-all"),
        "a posture flip re-logs"
    );
    assert!(
        orch.posture_changed("S-B", "active"),
        "per-SID latches are independent"
    );
    assert!(!orch.posture_changed("S-A", "unresolved-fail-closed-block-all"));
}

#[test]
fn evaluate_posture_log_transitions_on_first_sighting_and_on_change() {
    let t0 = Instant::now();
    // Nothing latched yet → transition.
    let (event, latch) = evaluate_posture_log(None, "block-all", t0, POSTURE_HEARTBEAT_INTERVAL);
    assert_eq!(event, PostureLogEvent::Transition);
    assert_eq!(latch.posture, "block-all");

    // Same posture, no time elapsed → steady.
    let (event, latch) =
        evaluate_posture_log(Some(latch), "block-all", t0, POSTURE_HEARTBEAT_INTERVAL);
    assert_eq!(event, PostureLogEvent::Steady);

    // Posture flips (entering a different state) → transition again,
    // even though the interval has not elapsed — a state change is
    // always worth a line, symmetric for entering and leaving.
    let (event, latch) = evaluate_posture_log(
        Some(latch),
        "active",
        t0 + Duration::from_secs(1),
        POSTURE_HEARTBEAT_INTERVAL,
    );
    assert_eq!(event, PostureLogEvent::Transition);
    assert_eq!(latch.posture, "active");
}

#[test]
fn evaluate_posture_log_heartbeats_while_posture_persists() {
    let t0 = Instant::now();
    let (_event, latch) = evaluate_posture_log(None, "block-all", t0, POSTURE_HEARTBEAT_INTERVAL);

    // Well before the interval elapses: steady, no line.
    let just_under = t0 + POSTURE_HEARTBEAT_INTERVAL - Duration::from_secs(1);
    let (event, latch) = evaluate_posture_log(
        Some(latch),
        "block-all",
        just_under,
        POSTURE_HEARTBEAT_INTERVAL,
    );
    assert_eq!(event, PostureLogEvent::Steady);

    // Interval elapsed since the posture was entered: heartbeat, with
    // elapsed time measured from entry, not from the last steady check.
    let due = t0 + POSTURE_HEARTBEAT_INTERVAL;
    let (event, latch) =
        evaluate_posture_log(Some(latch), "block-all", due, POSTURE_HEARTBEAT_INTERVAL);
    match event {
        PostureLogEvent::Heartbeat { elapsed } => {
            assert_eq!(elapsed, POSTURE_HEARTBEAT_INTERVAL)
        }
        other => panic!("expected heartbeat, got {other:?}"),
    }

    // Right after a heartbeat fires, the interval resets from that
    // heartbeat (not from the original entry) — no immediate re-fire.
    let (event, _latch) = evaluate_posture_log(
        Some(latch),
        "block-all",
        due + Duration::from_secs(1),
        POSTURE_HEARTBEAT_INTERVAL,
    );
    assert_eq!(event, PostureLogEvent::Steady);
}

#[test]
fn posture_log_event_heartbeats_via_orchestrator_latch() {
    // End-to-end through the orchestrator's own posture_log_event: a
    // long block-all session (the same posture recomputed every ~5 s by
    // the leak-guard reconcile) must not go completely silent between
    // its opening line and whenever it eventually clears.
    let (_api, orch, _src, _rules) = fixture_with_luid(None);
    assert_eq!(
        orch.posture_log_event("S-A", "unresolved-fail-closed-block-all"),
        PostureLogEvent::Transition,
        "entering block-all logs immediately"
    );
    assert_eq!(
        orch.posture_log_event("S-A", "unresolved-fail-closed-block-all"),
        PostureLogEvent::Steady,
        "the very next re-derivation is quiet"
    );
    assert_eq!(
        orch.posture_log_event("S-A", "active"),
        PostureLogEvent::Transition,
        "leaving block-all (posture flip) logs immediately, symmetric with entering"
    );
}

/// Entering fail-closed must ask for a re-resolve immediately.
///
/// The usual cause is a tunnel adapter recreated with a new GUID: the name
/// heal finds it at once, and until it runs the user's traffic is blocked
/// for a reason that no longer exists. Waiting for the minute-scale posture
/// heartbeat is what made that window fifteen seconds and longer.
#[test]
fn arming_fail_closed_asks_for_a_re_resolve_at_once() {
    let requests = Arc::new(crate::power_resume::RebindRequests::new());
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
    )
    // Secondary unresolved → the fail-closed posture arms.
    .with_kill_switch_resolver(Arc::new(|_| None))
    .with_rebind_requests(Arc::clone(&requests));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 9)));
    source.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();

    assert_eq!(
        requests.take(),
        Some("fail-closed-armed"),
        "the arming edge itself must request the re-resolve"
    );
}

/// The IPv6 closure is what keeps a pinned host from having a second,
/// unpinned way out — but a network that genuinely needs v6 must be able to
/// say no, and saying no must actually remove the filters.
#[test]
fn turning_off_the_ipv6_closure_removes_its_filters() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, src, rules) = fixture_with_luid(Some(KS_LUID));
    rules.set(rules_with_secondary_ip(ip));
    let mut snapshot = snap_block("Wi-Fi", "TAP");
    snapshot.block_ipv6_when_protected = false;
    src.set("S-1-5-21-A", snapshot);

    let count = orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(count, 11, "the v4 set is unchanged");
    let filters = api.wfp_filters.lock().unwrap();
    assert!(
        filters.iter().all(|f| f.covers_v4(ip)),
        "with the closure off, every filter is destination-scoped v4 again"
    );
}

#[test]
fn kill_switch_protects_only_secondary_not_primary_destinations() {
    let primary_ip = Ipv4Addr::new(10, 0, 0, 1);
    let secondary_ip = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, src, rules) = fixture_with_luid(Some(KS_LUID));
    rules.set(ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                id: RuleId("r-pri".into()),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::ExactIp(primary_ip)),
                app_match: None,
                comment: String::new(),
                action: nrr_domain::RuleAction::Route,
                origin: None,
            }]),
            secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                id: RuleId("r-sec".into()),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::ExactIp(secondary_ip)),
                app_match: None,
                comment: String::new(),
                action: nrr_domain::RuleAction::Route,
                origin: None,
            }]),
        },
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    });
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    let count = orch.install_for_sid("S-1-5-21-A").unwrap();
    // 2 rule permits (primary + secondary) + kill-switch ALE pair + one
    // packet pair per named protocol = 2 + 2 + 8 = 12, plus the IPv6
    // closure (3 exemptions + a tunnel-egress permit + 1 block, at each of
    // the two v6 layers = 10).
    assert_eq!(count, 22);
    let filters = api.wfp_filters.lock().unwrap();
    // The kill-switch never targets the primary destination.
    // Every DESTINATION-scoped kill-switch filter names the secondary
    // address and only it. The IPv6 closure is not destination-scoped — it
    // shuts a whole family the pins cannot reach — so it is excluded here
    // and checked for exactly that below.
    assert!(
        filters
            .iter()
            .filter(|f| f.local_interface_luid == Some(KS_LUID) || f.action == WfpAction::Block)
            .filter(|f| f.remote_ip.is_some() || !f.remote_ip_set.is_empty())
            .all(|f| f.covers_v4(secondary_ip)),
        "kill-switch filters must only target the secondary destination"
    );
    assert!(
        filters
            .iter()
            .filter(|f| (f.remote_ip.is_none() && f.remote_ip_set.is_empty())
                && f.action == WfpAction::Block)
            .all(|f| f.local_interface_luid.is_none()),
        "the IPv6 closure blocks a family, so it is bound to no interface"
    );
}

#[test]
fn remove_for_sid_drops_the_installed_filter_set() {
    let (api, orch, src, _rules, _audit) = fixture();
    src.set("A", snap_full("Wi-Fi", "TAP"));
    orch.install_for_sid("A").unwrap();
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2 + EXEMPT);
    let removed = orch.remove_for_sid("A").unwrap();
    assert_eq!(removed, 2 + EXEMPT);
    assert!(api.wfp_filters.lock().unwrap().is_empty());
    assert!(orch.installed_sids().is_empty());
}

#[test]
fn remove_for_sid_unknown_sid_is_idempotent() {
    let (_api, orch, _src, _rules, _audit) = fixture();
    let removed = orch.remove_for_sid("ghost").unwrap();
    assert_eq!(removed, 0);
}

#[test]
fn empty_sid_is_rejected() {
    let (_api, orch, _src, _rules, _audit) = fixture();
    assert!(matches!(
        orch.install_for_sid(""),
        Err(OrchestratorError::EmptySid)
    ));
    assert!(matches!(
        orch.remove_for_sid(""),
        Err(OrchestratorError::EmptySid)
    ));
}

#[test]
fn recompile_for_sid_replaces_filter_set() {
    let (api, orch, src, _rules, _audit) = fixture();
    src.set("A", snap_full("Wi-Fi", "TAP"));
    orch.install_for_sid("A").unwrap();
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2 + EXEMPT);
    // filter count is rule-driven, not
    // binding-driven. Recompile picks up updated *rules*, not
    // updated bindings — switch the active rule book to a
    // single-rule shape to verify the recompile path replaces
    // the live filter set.
    _rules.set(rules_with_n_primary_ips(1));
    src.set("A", snap_primary_only("Ethernet"));
    let count = orch.recompile_for_sid("A").unwrap();
    assert_eq!(count, 1);
    let filters = api.wfp_filters.lock().unwrap();
    assert_eq!(filters.len(), 1);
    assert!(filters[0].user_sid.as_deref() == Some("A"));
}

#[test]
fn recompile_with_unchanged_rules_touches_nothing() {
    //  — the window-free recompile: an apply that changes
    // nothing must be a no-op diff (no removes, no adds), never a
    // remove-then-reinstall of the identical set. One `Updated` audit
    // records the pass; the live WFP set is byte-identical.
    let (api, orch, src, _rules, audit) = fixture();
    src.set("A", snap_full("Wi-Fi", "TAP"));
    orch.install_for_sid("A").unwrap();
    let before: Vec<u64> = api
        .wfp_filters
        .lock()
        .unwrap()
        .iter()
        .map(|f| f.id.raw)
        .collect();
    assert!(!before.is_empty());

    let count = orch.recompile_for_sid("A").unwrap();
    assert_eq!(count, before.len(), "reports the full live set size");
    let after: Vec<u64> = api
        .wfp_filters
        .lock()
        .unwrap()
        .iter()
        .map(|f| f.id.raw)
        .collect();
    assert_eq!(
        after, before,
        "identical desired set → the installed filters are untouched"
    );
    let records = audit.snapshot();
    let last = records.last().expect("audit record");
    assert_eq!(last.kind, PerSidApplyAuditKind::Updated);
    assert!(
        last.message.contains("+0 -0"),
        "no-op diff is audited as such, got: {}",
        last.message
    );
}

#[test]
fn recompile_with_rules_uses_the_supplied_snapshot_not_the_provider() {
    // activation dispatches BEFORE the active
    // pointer commits, so the provider (storage read) must NOT be
    // consulted when the caller hands the revision content. Model the
    // exact 0716 failure: provider says "no active rules" (pointer not
    // committed yet) while the dispatcher holds the new revision.
    let (api, orch, src, rules, _audit) = fixture();
    src.set("A", snap_primary_only("Ethernet"));
    rules.clear();

    // Storage-read path installs nothing (this WAS the 0716 bug's shape).
    assert_eq!(orch.recompile_for_sid("A").unwrap(), 0);
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 0);

    // Pass-through path installs the handed rules.
    let handed = rules_with_n_primary_ips(3);
    let count = orch.recompile_for_sid_with_rules("A", &handed).unwrap();
    assert_eq!(count, 3);
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 3);
}

#[test]
fn policy_apply_trigger_recompiles_for_console_fallback_sid_without_tray() {
    // a policy update from a GUI-only connection
    // (empty registry = dead tray subscription) must still recompile for
    // the console user; without the fallback it was silently skipped.
    use crate::ipc_handlers::providers::RoutePolicyApplyTrigger as _;
    let (api, orch, src, _rules, _audit) = fixture();
    src.set("S-CONSOLE", snap_primary_only("Ethernet"));
    let registry = Arc::new(ActiveSidRegistry::new());

    // Without the fallback the trigger skips (pre-0716 behaviour).
    let bare = OrchestratorRoutePolicyApplyTrigger::new(Arc::clone(&orch), Arc::clone(&registry));
    bare.on_policy_changed("S-CONSOLE");
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 0);

    // With the fallback naming this SID, the recompile runs.
    let trigger =
        OrchestratorRoutePolicyApplyTrigger::new(Arc::clone(&orch), Arc::clone(&registry))
            .with_fallback_routing_sid(Arc::new(|| Some("S-CONSOLE".to_string())));
    trigger.on_policy_changed("S-CONSOLE");
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2);

    // A different SID than the fallback still skips.
    trigger.on_policy_changed("S-OTHER");
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2);
}

#[test]
fn policy_apply_trigger_skips_a_routing_paused_sid() {
    // a policy edit by a PAUSED user must
    // not reinstall their filters (pause = no enforcement). Also fail-closed
    // to "paused" on a read error.
    use crate::ipc_handlers::providers::RoutePolicyApplyTrigger as _;
    use nrr_shared::ipc::IpcClientProfile;
    use std::sync::atomic::{AtomicBool, Ordering};
    let (api, orch, src, _rules, _audit) = fixture();
    src.set("S-TRAY", snap_primary_only("Ethernet"));
    let registry = Arc::new(ActiveSidRegistry::new());
    registry.on_connect("S-TRAY", IpcClientProfile::TrayLightweight);

    // Paused → the trigger installs nothing even though the SID is tray-active.
    let paused = Arc::new(AtomicBool::new(true));
    let p = Arc::clone(&paused);
    let trigger =
        OrchestratorRoutePolicyApplyTrigger::new(Arc::clone(&orch), Arc::clone(&registry))
            .with_paused_check(Arc::new(move |_sid: &str| p.load(Ordering::SeqCst)));
    trigger.on_policy_changed("S-TRAY");
    assert_eq!(
        api.wfp_filters.lock().unwrap().len(),
        0,
        "a paused SID's filters must not be (re)installed by a policy edit"
    );

    // Un-paused → the same edit now recompiles.
    paused.store(false, Ordering::SeqCst);
    trigger.on_policy_changed("S-TRAY");
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2);
}

#[test]
fn verify_after_apply_confirms_live_and_detects_phantom() {
    // after an install, every
    // recorded id must be live in WFP (0 phantom); an id that was never
    // added is flagged as a phantom.
    let (api, orch, src, _rules, _audit) = fixture();
    src.set("A", snap_primary_only("Ethernet"));
    let count = orch.install_for_sid("A").unwrap();
    let installed: Vec<WfpFilterId> = api
        .wfp_filters
        .lock()
        .unwrap()
        .iter()
        .map(|f| f.id)
        .collect();
    assert_eq!(
        orch.verify_installed_filters_live("A", &installed, count),
        Some(0),
        "all installed filters are live in the engine",
    );
    // An id never added → phantom detected.
    let bogus = vec![WfpFilterId { raw: 0xDEAD_BEEF }];
    assert_eq!(
        orch.verify_installed_filters_live("A", &bogus, 1),
        Some(1),
        "an id not present in the live engine is a phantom",
    );
}

#[test]
fn two_sids_have_independent_filter_sets() {
    let (api, orch, src, _rules, _audit) = fixture();
    src.set("A", snap_full("Wi-Fi", "TAP"));
    src.set("B", snap_primary_only("Ethernet"));
    orch.install_for_sid("A").unwrap();
    orch.install_for_sid("B").unwrap();
    // filter count is rule-driven (2 ExactIp
    // rules in the fixture's primary set), not binding-driven.
    // Both SIDs see the same active rule book, so both get the
    // same filter count — what makes them independent is the
    // per-filter `user_sid` tag, not the count.
    assert_eq!(orch.filter_count_for("A"), 2 + EXEMPT);
    assert_eq!(orch.filter_count_for("B"), 2);
    let total = api.wfp_filters.lock().unwrap();
    assert_eq!(total.len(), 4 + EXEMPT);
    let a_filters: Vec<_> = total
        .iter()
        .filter(|f| f.user_sid.as_deref() == Some("A"))
        .collect();
    let b_filters: Vec<_> = total
        .iter()
        .filter(|f| f.user_sid.as_deref() == Some("B"))
        .collect();
    assert_eq!(a_filters.len(), 2 + EXEMPT);
    assert_eq!(b_filters.len(), 2);
}

#[test]
fn reconcile_installs_new_sids_and_removes_departed_ones() {
    let (api, orch, src, _rules, _audit) = fixture();
    src.set("A", snap_primary_only("Wi-Fi"));
    src.set("B", snap_primary_only("TAP"));

    // Initial reconcile from empty → A,B → both installed. Each
    // SID gets the rule-book-driven filter count (fixture = 2).
    orch.reconcile(&["A".into(), "B".into()]).unwrap();
    assert_eq!(orch.installed_sids(), vec!["A", "B"]);
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 4);

    // A drops out → only B.
    orch.reconcile(&["B".into()]).unwrap();
    assert_eq!(orch.installed_sids(), vec!["B"]);
    let filters = api.wfp_filters.lock().unwrap();
    assert_eq!(filters.len(), 2);
    assert!(filters.iter().all(|f| f.user_sid.as_deref() == Some("B")));
}

#[test]
fn wire_orchestrator_to_registry_drives_install_remove_via_listener() {
    use nrr_shared::ipc::IpcClientProfile;
    let (api, orch, src, _rules, _audit) = fixture();
    src.set("A", snap_primary_only("Wi-Fi"));

    let registry = ActiveSidRegistry::new();
    wire_orchestrator_to_registry(Arc::clone(&orch), &registry);

    // M-1: only `TrayLightweight` connects fire the
    // routing-active listener. A `GuiInteractive` connect is
    // tracked but does NOT trigger filter installation. Filter
    // count is rule-driven (fixture = 2 ExactIp rules).
    registry.on_connect("A", IpcClientProfile::TrayLightweight);
    assert_eq!(orch.installed_sids(), vec!["A".to_string()]);
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2);

    registry.on_disconnect("A", IpcClientProfile::TrayLightweight);
    assert!(orch.installed_sids().is_empty());
    assert!(api.wfp_filters.lock().unwrap().is_empty());
}

// ── Audit + multi-user fixture tests ────────────────────────────────

#[test]
fn install_emits_applied_audit_record() {
    let (_api, orch, src, _rules, audit) = fixture();
    src.set("A", snap_full("Wi-Fi", "TAP"));
    orch.install_for_sid("A").unwrap();
    let records = audit.snapshot();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].sid, "A");
    assert_eq!(records[0].kind, PerSidApplyAuditKind::Applied);
    assert_eq!(records[0].filter_count, (2 + EXEMPT) as u32);
    assert_eq!(records[0].message, "ok");
}

#[test]
fn second_install_for_same_sid_emits_updated_kind() {
    let (_api, orch, src, _rules, audit) = fixture();
    src.set("A", snap_primary_only("Wi-Fi"));
    orch.install_for_sid("A").unwrap();
    // Same SID, different policy → next install is "Updated".
    src.set("A", snap_full("Wi-Fi", "TAP"));
    orch.install_for_sid("A").unwrap();
    let records = audit.snapshot();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].kind, PerSidApplyAuditKind::Applied);
    assert_eq!(records[1].kind, PerSidApplyAuditKind::Updated);
    assert_eq!(records[1].filter_count, (2 + EXEMPT) as u32);
}

#[test]
fn a_second_install_deletes_the_filters_the_new_set_supersedes() {
    // A full-replace install only ADDS. Without an explicit delete pass the
    // filters the new set drops stay live in the engine while leaving our
    // accounting — they keep dropping traffic that no recompute explains
    // and no teardown reaches (observed in the field as a pinned address
    // still being blocked long after its rule was gone).
    let (api, orch, src, rules, _audit) = fixture();
    src.set("A", snap_full("Wi-Fi", "TAP"));
    rules.set(rules_with_n_primary_ips(3));
    orch.install_for_sid("A").unwrap();
    let after_wide = api.wfp_filters.lock().unwrap().len();

    // Narrower rule set: some of the previous filters are no longer wanted.
    rules.set(rules_with_n_primary_ips(1));
    orch.install_for_sid("A").unwrap();

    let live = api.wfp_filters.lock().unwrap().len();
    assert!(
        live < after_wide,
        "the narrower set must leave fewer filters live, got {live} vs {after_wide}"
    );
    // The invariant that actually matters: what the engine holds for this
    // SID is exactly what we think we installed.
    // The destinations the narrower set dropped must be gone from the
    // engine, not merely gone from our bookkeeping. (`filter_count_for` is
    // not comparable here: the mock re-adds an identical id instead of
    // answering FWP_E_ALREADY_EXISTS the way the real engine does.)
    let live_ips: Vec<Option<Ipv4Addr>> = api
        .wfp_filters
        .lock()
        .unwrap()
        .iter()
        .map(|f| f.remote_ip)
        .collect();
    for dropped in [Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)] {
        assert!(
            !live_ips.contains(&Some(dropped)),
            "{dropped} left the rule set, so its filter must not survive in the engine; live: {live_ips:?}"
        );
    }
}

#[test]
fn losing_the_policy_takes_down_the_filters_the_sid_was_carrying() {
    // `NoPolicy` / `NoActiveRules` used to record an empty set while
    // leaving every installed filter alive.
    let (api, orch, src, rules, _audit) = fixture();
    src.set("A", snap_full("Wi-Fi", "TAP"));
    rules.set(rules_with_n_primary_ips(2));
    orch.install_for_sid("A").unwrap();
    assert!(!api.wfp_filters.lock().unwrap().is_empty());

    rules.set(rules_with_n_primary_ips(0));
    orch.install_for_sid("A").unwrap();
    assert!(
        api.wfp_filters.lock().unwrap().is_empty(),
        "no active rules must leave nothing behind in the engine"
    );
    assert_eq!(orch.filter_count_for("A"), 0);
}

#[test]
fn remove_emits_withdrawn_audit_record() {
    let (_api, orch, src, _rules, audit) = fixture();
    src.set("A", snap_full("Wi-Fi", "TAP"));
    orch.install_for_sid("A").unwrap();
    orch.remove_for_sid("A").unwrap();
    let records = audit.snapshot();
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].kind, PerSidApplyAuditKind::Withdrawn);
    assert_eq!(records[1].filter_count, (2 + EXEMPT) as u32);
}

#[test]
fn audit_kind_slugs_are_stable_for_telemetry() {
    // Slugs are part of the audit wire contract — locking them in
    // prevents accidental rename in future cleanup.
    assert_eq!(
        PerSidApplyAuditKind::Applied.slug(),
        "per-sid-policy-applied"
    );
    assert_eq!(
        PerSidApplyAuditKind::Updated.slug(),
        "per-sid-policy-updated"
    );
    assert_eq!(
        PerSidApplyAuditKind::Withdrawn.slug(),
        "per-sid-policy-withdrawn"
    );
    assert_eq!(PerSidApplyAuditKind::Failed.slug(), "per-sid-policy-failed");
}

/// Multi-user scenario: User A and User B simultaneously have GUI
/// connections; their filters live in the same WFP session,
/// distinguished by `user_sid`. When User A submits
/// `RoutePolicyUpdate`, only A's filters are recompiled.
#[test]
fn two_users_concurrent_with_independent_recompile() {
    let (api, orch, src, _rules, audit) = fixture();
    src.set("A", snap_primary_only("Wi-Fi"));
    src.set("B", snap_full("Ethernet", "TAP-B"));
    orch.install_for_sid("A").unwrap();
    orch.install_for_sid("B").unwrap();
    assert_eq!(orch.installed_sids(), vec!["A", "B"]);
    // 2 rule-driven filters per SID, regardless
    // of bindings. B (snap_full) additionally carries the VPN-exempt permits.
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 4 + EXEMPT);

    // User A's recompile pass: bindings change but rules stay,
    // so the rule-driven filter set is unchanged. The lifecycle
    // path (remove + install) still runs end-to-end; what we
    // verify here is that B's filter set isn't disturbed.
    src.set("A", snap_full("Wi-Fi", "TAP-A"));
    orch.recompile_for_sid("A").unwrap();

    let filters = api.wfp_filters.lock().unwrap();
    let a_count = filters
        .iter()
        .filter(|f| f.user_sid.as_deref() == Some("A"))
        .count();
    let b_count = filters
        .iter()
        .filter(|f| f.user_sid.as_deref() == Some("B"))
        .count();
    assert_eq!(a_count, 2 + EXEMPT, "A's filters after recompile");
    assert_eq!(
        b_count,
        2 + EXEMPT,
        "B's filters preserved during A's recompile"
    );

    // Audit chain: a recompile of an already-installed SID is the
    // window-free MAKE-then-BREAK diff, so it surfaces as a
    // single `Updated` record — never a Withdrawn/Applied pair, because
    // the old filter set is no longer torn down before the new one lands.
    let records = audit.snapshot();
    let kinds: Vec<_> = records.iter().map(|r| (r.sid.as_str(), r.kind)).collect();
    assert_eq!(
        kinds,
        vec![
            ("A", PerSidApplyAuditKind::Applied),
            ("B", PerSidApplyAuditKind::Applied),
            ("A", PerSidApplyAuditKind::Updated),
        ],
    );
}

/// RDP simulation: a user disconnects (their session goes idle) →
/// orchestrator removes their filter set. Reconnect → reinstall.
/// Validates the production lifecycle when an RDP user signs in,
/// works for a while, signs out, and a different user signs in.
#[test]
fn rdp_user_lifecycle_install_remove_install_different_user() {
    use nrr_shared::ipc::IpcClientProfile;
    let (api, orch, src, _rules, audit) = fixture();
    src.set("RDP-USER-1", snap_primary_only("Wi-Fi"));
    src.set("RDP-USER-2", snap_full("Ethernet", "TAP"));

    let registry = ActiveSidRegistry::new();
    wire_orchestrator_to_registry(Arc::clone(&orch), &registry);

    // RDP-USER-1 connects. Filter count is rule-driven (fixture
    // = 2 ExactIp rules) regardless of `snap_primary_only`'s
    // binding shape.
    registry.on_connect("RDP-USER-1", IpcClientProfile::TrayLightweight);
    assert_eq!(orch.installed_sids(), vec!["RDP-USER-1".to_string()]);
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2);

    // RDP-USER-1 disconnects.
    registry.on_disconnect("RDP-USER-1", IpcClientProfile::TrayLightweight);
    assert!(orch.installed_sids().is_empty());
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 0);

    // RDP-USER-2 connects from a different RDP session.
    registry.on_connect("RDP-USER-2", IpcClientProfile::TrayLightweight);
    assert_eq!(orch.installed_sids(), vec!["RDP-USER-2".to_string()]);
    // RDP-USER-2 = snap_full → armed None branch → +VPN-exempt permits.
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2 + EXEMPT);
    let filters = api.wfp_filters.lock().unwrap();
    assert!(filters
        .iter()
        .all(|f| f.user_sid.as_deref() == Some("RDP-USER-2")));
    drop(filters);

    // Audit shows the full lifecycle.
    let records = audit.snapshot();
    assert!(records
        .iter()
        .any(|r| r.sid == "RDP-USER-1" && r.kind == PerSidApplyAuditKind::Applied));
    assert!(records
        .iter()
        .any(|r| r.sid == "RDP-USER-1" && r.kind == PerSidApplyAuditKind::Withdrawn));
    assert!(records
        .iter()
        .any(|r| r.sid == "RDP-USER-2" && r.kind == PerSidApplyAuditKind::Applied));
}

/// Performance smoke at modest scale: 10 SIDs × 2 filters each.
/// Validates the orchestrator does not silently drop filters when
/// many users are active simultaneously, and that audit records
/// every SID. Production performance ceiling (50 RDP × 100 rules
/// = 5000 filters) is documented in TASKS_RU; smaller smoke test
/// here confirms the linear scaling is correct at least at the
/// small end.
#[test]
fn smoke_ten_sids_each_with_two_filters() {
    let (api, orch, src, _rules, audit) = fixture();
    for i in 0..10 {
        let sid = format!("S-1-5-21-{i:02}");
        src.set(&sid, snap_full("Wi-Fi", "TAP"));
        orch.install_for_sid(&sid).unwrap();
    }
    assert_eq!(orch.installed_sids().len(), 10);
    // 10 SIDs × snap_full (armed None branch) = 10 × (2 rule filters + VPN exempt).
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 10 * (2 + EXEMPT));
    // Every WFP filter has a non-None user_sid.
    assert!(api
        .wfp_filters
        .lock()
        .unwrap()
        .iter()
        .all(|f| f.user_sid.is_some()));
    // Every audit record is `Applied` (no failures, no updates).
    let records = audit.snapshot();
    assert_eq!(records.len(), 10);
    assert!(records
        .iter()
        .all(|r| r.kind == PerSidApplyAuditKind::Applied));
}

// ── Route before block ─────────────────────────────────────

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
            address_match: Some(CanonicalAddressMatch::ExactIp(*ip)),
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

/// Fixture whose route-sync hook records how many filters were live in WFP
/// at the instant it ran. A recorded `0` therefore proves the route pass
/// ran BEFORE any pin reached the engine — the ordering under test, without
/// a real route table or a real WFP engine.
#[allow(clippy::type_complexity)]
fn fixture_with_route_sync(
    resolution: Option<KillSwitchResolution>,
) -> (
    Arc<MockWindowsApi>,
    Arc<PerSidApplyOrchestrator>,
    Arc<ScriptedSource>,
    Arc<ScriptedRules>,
    Arc<Mutex<Vec<usize>>>,
) {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let observed: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
    let hook = {
        let api = Arc::clone(&api);
        let observed = Arc::clone(&observed);
        let hook: RouteSyncHook = Arc::new(move || {
            let live = api
                .wfp_filters
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .len();
            observed
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(live);
        });
        hook
    };
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(move |_| resolution.clone()))
        .with_route_sync(hook),
    );
    (api, orch, source, rules, observed)
}

#[test]
fn route_sync_runs_before_a_cold_install_lands_destination_pins() {
    let (api, orch, src, rules, observed) = fixture_with_route_sync(Some(full_ks_resolution()));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 10)));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();

    let live = api.wfp_filters.lock().unwrap().clone();
    assert!(
        live.iter().any(record_is_destination_block),
        "the install must have landed at least one destination-scoped block",
    );
    let calls = observed.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![0],
        "the route pass ran, and ran on an empty engine"
    );
}

#[test]
fn route_sync_is_skipped_when_nothing_destination_scoped_is_blocked() {
    // A primary-only policy emits rule permits and no leak-guard at all —
    // no destination block, so the ordering hook must not fire and the
    // steady state costs nothing.
    let (_api, orch, src, rules, observed) = fixture_with_route_sync(None);
    rules.set(rules_with_n_primary_ips(1));
    src.set("S-1-5-21-A", snap_primary_only("Wi-Fi"));

    orch.install_for_sid("S-1-5-21-A").unwrap();

    assert!(
        observed.lock().unwrap().is_empty(),
        "no new destination block ⇒ no route sync",
    );
}

#[test]
fn route_sync_runs_before_a_reconcile_pins_a_newly_covered_destination() {
    let (api, orch, src, rules, observed) = fixture_with_route_sync(Some(full_ks_resolution()));
    rules.set(rules_with_secondary_ips(&[Ipv4Addr::new(203, 0, 113, 10)]));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();
    let after_install = api.wfp_filters.lock().unwrap().len();
    observed.lock().unwrap().clear();

    // The FQDN/app stores growing a destination is what the reconcile sees;
    // a second rule address is the deterministic stand-in for it.
    rules.set(rules_with_secondary_ips(&[
        Ipv4Addr::new(203, 0, 113, 10),
        Ipv4Addr::new(203, 0, 113, 11),
    ]));
    let added = orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();

    assert!(added > 0, "the reconcile must have grown the pin set");
    let calls = observed.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![after_install],
        "the route pass ran exactly once, before the new pins reached the engine",
    );
}

#[test]
fn route_sync_is_skipped_when_a_reconcile_changes_nothing() {
    let (_api, orch, src, rules, observed) = fixture_with_route_sync(Some(full_ks_resolution()));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 10)));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();
    observed.lock().unwrap().clear();

    let added = orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();

    assert_eq!(added, 0, "coverage is unchanged");
    assert!(
        observed.lock().unwrap().is_empty(),
        "an unchanged reconcile must not drive the route pass",
    );
}

// ── Blocking-scope classification ──────────────────────────

#[test]
fn registry_marks_app_only_blocks_as_app_scoped_and_destination_blocks_as_not() {
    // The per-app pin blocks EVERY destination its process talks to, the
    // per-destination pin only the address it names. The drop detector
    // needs to tell them apart, so the published registry must too.
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let registry = Arc::new(crate::killswitch_drop_registry::KillswitchBlockFilterRegistry::new());
    let resolver = nrr_platform_api::MockAppPathResolver::new()
        .with("tg.exe", vec![std::path::PathBuf::from(r"C:\Apps\tg.exe")]);
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    )
    .with_app_resolver(Arc::new(resolver))
    .with_kill_switch_resolver(Arc::new(|_| Some(full_ks_resolution())))
    .with_killswitch_drop_registry(Arc::clone(&registry));

    // One secondary address rule (destination pin) + one secondary app
    // rule (app pin) — the exact shape of the  run.
    let secondary = CanonicalRuleSet::from_rules(vec![
        CanonicalRule {
            id: RuleId("r-ip".into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactIp(Ipv4Addr::new(
                203, 0, 113, 10,
            ))),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        },
        CanonicalRule {
            id: RuleId("r-app".into()),
            enabled: true,
            address_match: None,
            app_match: Some(nrr_domain::canonical::CanonicalAppMatch {
                pattern: nrr_domain::canonical::CanonicalAppPattern::Exact("tg.exe".into()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        },
    ]);
    rules.set(ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary,
        },
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    });
    source.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();

    let live = api.wfp_filters.lock().unwrap().clone();
    let app_block = live
        .iter()
        .find(|f| record_is_app_only_block(f))
        .expect("the secondary app rule must have armed an app-scoped pin");
    let dest_block = live
        .iter()
        .find(|f| record_is_destination_block(f))
        .expect("the secondary address rule must have armed a destination pin");

    // Both halves stay role-verified — the learner's gate is unchanged.
    assert!(registry.contains(app_block.id.raw));
    assert!(registry.contains(dest_block.id.raw));
    // Only the app-only block is app-scoped.
    assert!(registry.is_app_scoped(app_block.id.raw));
    assert!(!registry.is_app_scoped(dest_block.id.raw));
}

/// Builds the registry-test fixture with an observation store attached:
/// one secondary address rule, one secondary app rule whose process was
/// observed on `observed_ip`.
fn fixture_with_app_observation(
    resolution: Option<KillSwitchResolution>,
    observed_ip: Ipv4Addr,
) -> (Arc<MockWindowsApi>, PerSidApplyOrchestrator) {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let resolver = nrr_platform_api::MockAppPathResolver::new()
        .with("tg.exe", vec![std::path::PathBuf::from(r"C:\Apps\tg.exe")]);
    let observations = Arc::new(crate::app_observation_lookup::AppObservationStore::new());
    observations.record("tg.exe", observed_ip);
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    )
    .with_app_resolver(Arc::new(resolver))
    .with_app_observations(observations)
    .with_kill_switch_resolver(Arc::new(move |_| resolution.clone()));
    let secondary = CanonicalRuleSet::from_rules(vec![
        CanonicalRule {
            id: RuleId("r-ip".into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactIp(Ipv4Addr::new(
                203, 0, 113, 10,
            ))),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        },
        CanonicalRule {
            id: RuleId("r-app".into()),
            enabled: true,
            address_match: None,
            app_match: Some(nrr_domain::canonical::CanonicalAppMatch {
                pattern: nrr_domain::canonical::CanonicalAppPattern::Exact("tg.exe".into()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        },
    ]);
    rules.set(ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary,
        },
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    });
    source.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    (api, orch)
}

#[test]
fn an_app_observed_destination_is_not_pinned_per_destination() {
    // The BFE volume class: every observed P2P peer used to earn ~12
    // standing filters (ALE pair + packet pairs). The app's own pair is
    // the leak-guard now; the observed IP keeps its /32 permit mirror but
    // no destination-scoped block.
    let observed = Ipv4Addr::new(198, 51, 100, 7);
    let (api, orch) = fixture_with_app_observation(Some(full_ks_resolution()), observed);
    orch.install_for_sid("S-1-5-21-A").unwrap();

    let live = api.wfp_filters.lock().unwrap().clone();
    assert!(
        !live
            .iter()
            .any(|f| record_is_destination_block(f) && f.covers_v4(observed)),
        "an app-observed destination must not carry a destination-scoped block"
    );
    assert!(
        live.iter()
            .any(|f| record_is_destination_block(f) && f.covers_v4(Ipv4Addr::new(203, 0, 113, 10))),
        "the address-rule destination keeps its pin"
    );
    assert!(
        live.iter()
            .any(|f| f.action == WfpAction::Permit && f.covers_v4(observed)),
        "the observed destination still has its /32 permit mirror"
    );
    assert!(
        live.iter().any(record_is_app_only_block),
        "the per-app pair is what guards the app now"
    );
}

#[test]
fn an_unresolved_secondary_blocks_the_routed_app_itself() {
    // The link is unresolved, so there is no LUID for the egress pair —
    // and the per-IP set no longer carries the app's observed
    // destinations. The unconditional fail-closed app block is what keeps
    // the app from egressing the primary.
    let observed = Ipv4Addr::new(198, 51, 100, 7);
    let (api, orch) = fixture_with_app_observation(None, observed);
    orch.install_for_sid("S-1-5-21-A").unwrap();

    let live = api.wfp_filters.lock().unwrap().clone();
    assert!(
        live.iter().any(record_is_app_only_block),
        "fail-closed must cut the routed app whole while its link is unresolved"
    );
    assert!(
        !live
            .iter()
            .any(|f| record_is_destination_block(f) && f.covers_v4(observed)),
        "no destination-scoped block for the app-observed address here either"
    );
}
