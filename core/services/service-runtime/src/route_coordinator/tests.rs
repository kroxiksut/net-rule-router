//! Unit tests for [`super`] — SecondaryRouteCoordinator.
//!
//! 1825 of the module's lines were this block. Moved out verbatim (one
//! level of indentation removed and nothing else) so the file one reads to
//! understand the code is the code.

use super::*;
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
        address_match: Some(CanonicalAddressMatch::ExactIp(Ipv4Addr::new(a, b, c, d))),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

fn target() -> SecondaryRouteTarget {
    SecondaryRouteTarget {
        gateway: Ipv4Addr::new(10, 0, 0, 1),
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
        .map(|r| r.destination)
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
            block_ipv6_when_protected: true,
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

#[test]
fn fail_closed_exemptions_seed_persisted_server_ips_before_reconnect() {
    // after a restart the in-memory server_ip_cache is
    // empty (the VPN has not reconnected), but the persisted loader seeds the
    // fail-closed exemptions so the block-all can still arm with a server hole.
    let api = Arc::new(MockWindowsApi::new());
    let persisted = Ipv4Addr::new(203, 0, 113, 77);
    let coord = coordinator(Arc::clone(&api), Arc::new(FakeRules::new()))
        .with_bootstrap_server_persistence(
            Arc::new(|_ips: &[Ipv4Addr]| {}),
            Arc::new(move || vec![persisted]),
        );
    let ex = coord.fail_closed_exemptions("S-1-5-21-A");
    assert!(
        ex.bootstrap_server_ips.contains(&persisted),
        "persisted server IP seeds the fail-closed exemption before any live observation",
    );
}

#[test]
fn fail_closed_exemptions_without_persistence_is_unchanged() {
    // No persistence wired → empty exemption server set (prior behaviour).
    let api = Arc::new(MockWindowsApi::new());
    let coord = coordinator(api, Arc::new(FakeRules::new()));
    let ex = coord.fail_closed_exemptions("S-1-5-21-A");
    assert!(ex.bootstrap_server_ips.is_empty());
    assert!(ex.probe_target_ips.is_empty());
}

#[test]
fn fail_closed_exemptions_carry_probe_target_even_when_liveness_dead() {
    //  HW — the block-all must keep a hole for the liveness
    // probe's ICMP target (the tunnel next-hop). A probe-DEAD verdict
    // empties the GATED resolution — which is exactly when the block-all
    // arms — so the exemption must come from the RAW binding resolution,
    // or the armed block eats the probe's echo and the DEAD verdict can
    // never flip back (the kill-switch would stay fail-closed through
    // every VPN reconnect until service restart).
    let sid = "S-1-5-21-A";
    let gw = Ipv4Addr::new(10, 0, 0, 1);
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("hidemyvpn", 78, true, true, Some([10, 0, 0, 1]));
    let vpn_id = vpn.stable_id();
    api.set_adapter_infos(vec![vpn]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary(sid, &vpn_id);

    // Alive tunnel (liveness disabled) → the gated resolution carries the
    // target and so must the exemptions.
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    );
    assert_eq!(coord.fail_closed_exemptions(sid).probe_target_ips, vec![gw]);

    // Probe-DEAD tunnel: a failure run older than the whole window makes
    // `is_dead` true, the gated resolution loses the secondary, and the
    // exemptions must still carry the raw next-hop.
    let tracker = Arc::new(SecondaryLivenessTracker::new(1));
    let dead_since = Instant::now()
        .checked_sub(std::time::Duration::from_secs(10))
        .expect("test host has been up for at least ten seconds");
    // Baseline first: a DEAD verdict requires the peer to have answered
    // at least once (silent-from-birth gateways are unprobeable, not
    // dead) — and the evidence must be FRESH (records within the
    // evidence gap of "now"), so the failing run is recorded up to the
    // present rather than left in the past.
    tracker.record(78, true, dead_since);
    tracker.record(78, false, dead_since);
    tracker.record(78, false, Instant::now());
    assert!(tracker.is_dead(78, Instant::now()), "fixture must be DEAD");
    let coord_dead = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy)
        .with_liveness_probe(
            tracker,
            Arc::new(nrr_platform_api::reachability::AlwaysReachableProbe),
        );
    assert_eq!(
        coord_dead.fail_closed_exemptions(sid).probe_target_ips,
        vec![gw],
        "DEAD verdict must not drop the probe-target exemption",
    );
}

#[test]
fn probe_tick_forgets_the_failing_run_when_the_binding_stops_resolving() {
    //  HW — while a VPN reconnects, its adapter enumerates Down
    // (no IPv4) and the probe cannot run. The failing run accumulated just
    // before the outage must be dropped the moment the binding stops
    // resolving, or the stale window declares the tunnel DEAD the instant
    // it comes back Up and the kill-switch fail-closes a freshly
    // reconnected, working tunnel.
    let sid = "S-1-5-21-A";
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("hidemyvpn", 60, true, true, Some([10, 88, 0, 1]));
    let vpn_id = vpn.stable_id();
    api.set_adapter_infos(vec![vpn]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary(sid, &vpn_id);
    let tracker = Arc::new(SecondaryLivenessTracker::new(10));
    let probe = Arc::new(nrr_platform_api::reachability::MockReachabilityProbe::new(
        false,
    ));
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy)
        .with_liveness_probe(Arc::clone(&tracker), probe);
    let sids = vec![sid.to_string()];
    coord.probe_active_secondaries(&sids);
    assert!(
        tracker.in_failing_run(60),
        "a failed probe starts a failing run"
    );
    // The adapter drops (VPN mid-reconnect) → the binding stops resolving.
    api.set_adapter_infos(vec![adapter("hidemyvpn", 60, false, false, None)]);
    coord.probe_active_secondaries(&sids);
    assert!(
        !tracker.in_failing_run(60),
        "an unprobeable binding must forget the stale failing run"
    );
}

#[test]
fn probe_tick_forgets_the_failing_run_when_the_adapter_comes_back_under_a_new_ifindex() {
    // A recreated tunnel adapter keeps its NAME and gets a NEW ifindex, and
    // the liveness window is keyed by index. Left alone the old index keeps
    // its failing run forever (nothing probes it again), and the new index
    // inherits whatever an unrelated adapter left there — which would
    // declare a healthy tunnel dead on its first probe.
    let sid = "S-1-5-21-A";
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("hidemyvpn", 60, true, true, Some([10, 88, 0, 1]));
    let vpn_id = vpn.stable_id();
    api.set_adapter_infos(vec![vpn]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary(sid, &vpn_id);
    let tracker = Arc::new(SecondaryLivenessTracker::new(10));
    let probe = Arc::new(nrr_platform_api::reachability::MockReachabilityProbe::new(
        false,
    ));
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy)
        .with_liveness_probe(Arc::clone(&tracker), probe);
    let sids = vec![sid.to_string()];
    coord.probe_active_secondaries(&sids);
    assert!(tracker.in_failing_run(60), "a failed probe starts a run");

    // Same adapter name, new ifindex — and the new index already carries a
    // failing run from whoever held it before.
    tracker.record(61, false, Instant::now());
    assert!(tracker.in_failing_run(61));
    api.set_adapter_infos(vec![adapter(
        "hidemyvpn",
        61,
        true,
        true,
        Some([10, 88, 0, 1]),
    )]);
    coord.probe_active_secondaries(&sids);
    assert!(
        !tracker.in_failing_run(60),
        "the abandoned index must not keep a run nobody will ever clear"
    );
}

#[test]
fn no_next_hop_warn_latch_dedups_until_cleared() {
    let api = Arc::new(MockWindowsApi::new());
    let coord = coordinator(api, Arc::new(FakeRules::new()));
    assert!(coord.note_no_next_hop_once("S", "secondary"));
    assert!(
        !coord.note_no_next_hop_once("S", "secondary"),
        "same spell stays deduped"
    );
    assert!(
        coord.note_no_next_hop_once("S", "primary"),
        "latch is per (sid, role)"
    );
    coord.clear_no_next_hop("S", "secondary");
    assert!(
        coord.note_no_next_hop_once("S", "secondary"),
        "a successful resolution re-arms the warn"
    );
}

#[test]
fn effective_routing_sid_prefers_registry_then_console_under_service_driven() {
    // 1. A connected-tray SID always wins, regardless of scope/console.
    let api = Arc::new(MockWindowsApi::new());
    api.set_console_user_sid(Some("S-CONSOLE"));
    let coord_app = coordinator_with_scope(Arc::clone(&api), Arc::new(FakeRules::new()), false);
    assert_eq!(
        coord_app.effective_routing_sid(&["S-TRAY".to_string()]),
        Some("S-TRAY".to_string()),
    );

    // 2. No tray + app-driven scope → None (the console is never consulted).
    assert_eq!(coord_app.effective_routing_sid(&[]), None);

    // 3. No tray + service-driven scope + a console session → the console user.
    let coord_sd = coordinator_with_scope(Arc::clone(&api), Arc::new(FakeRules::new()), true);
    assert_eq!(
        coord_sd.effective_routing_sid(&[]),
        Some("S-CONSOLE".to_string()),
    );

    // 4. No tray + service-driven scope + no console session → None.
    let api_no_console = Arc::new(MockWindowsApi::new());
    let coord_sd2 = coordinator_with_scope(api_no_console, Arc::new(FakeRules::new()), true);
    assert_eq!(coord_sd2.effective_routing_sid(&[]), None);
}

#[test]
fn effective_enforcement_sids_falls_back_to_console_only_when_no_tray() {
    // the WFP orchestrator's SID set.
    let api = Arc::new(MockWindowsApi::new());
    api.set_console_user_sid(Some("S-CONSOLE"));
    let coord = coordinator_with_scope(Arc::clone(&api), Arc::new(FakeRules::new()), true);

    // 1. Connected trays pass through unchanged (incl. multi-tray) —
    //    the fallback never overrides them.
    let trays = vec!["S-TRAY-1".to_string(), "S-TRAY-2".to_string()];
    assert_eq!(coord.effective_enforcement_sids(&trays), trays);

    // 2. No tray + service-driven scope → the console user.
    assert_eq!(
        coord.effective_enforcement_sids(&[]),
        vec!["S-CONSOLE".to_string()],
    );

    // 3. No tray + app-driven scope → empty (nothing to enforce).
    let coord_app = coordinator_with_scope(Arc::clone(&api), Arc::new(FakeRules::new()), false);
    assert!(coord_app.effective_enforcement_sids(&[]).is_empty());

    // 4. No tray + service-driven + no console session → empty.
    let coord_no_console = coordinator_with_scope(
        Arc::new(MockWindowsApi::new()),
        Arc::new(FakeRules::new()),
        true,
    );
    assert!(coord_no_console.effective_enforcement_sids(&[]).is_empty());
}

#[test]
fn note_heal_once_dedups_until_mapping_changes() {
    let coord = coordinator(Arc::new(MockWindowsApi::new()), Arc::new(FakeRules::new()));
    let sid = "S-1-5-21-x-1001";
    // First sighting of a stale→healed mapping logs.
    assert!(coord.note_heal_once(sid, "secondary", "win-adapter:{old}", "win-adapter:{new}"));
    // Same mapping repeats → silent (the heal re-fires every reconcile).
    assert!(!coord.note_heal_once(sid, "secondary", "win-adapter:{old}", "win-adapter:{new}"));
    // Healed id changes (adapter reinstalled again) → logs once more.
    assert!(coord.note_heal_once(sid, "secondary", "win-adapter:{old}", "win-adapter:{new2}"));
    assert!(!coord.note_heal_once(sid, "secondary", "win-adapter:{old}", "win-adapter:{new2}"));
    // A different role under the same sid is tracked independently.
    assert!(coord.note_heal_once(sid, "primary", "win-adapter:{old}", "win-adapter:{new2}"));
}

#[test]
fn note_not_usable_once_dedups_until_cleared_or_changed() {
    let coord = coordinator(Arc::new(MockWindowsApi::new()), Arc::new(FakeRules::new()));
    let sid = "S-1-5-21-x-1002";
    // First sighting of the not-usable state logs.
    assert!(coord.note_not_usable_once(sid, "secondary", "win-adapter:{tap}"));
    // Same not-usable spell (adapter still down) repeats → silent.
    assert!(!coord.note_not_usable_once(sid, "secondary", "win-adapter:{tap}"));
    assert!(!coord.note_not_usable_once(sid, "secondary", "win-adapter:{tap}"));
    // Adapter resolves usable again → re-arm.
    coord.clear_not_usable(sid, "secondary");
    // Next not-usable transition for the SAME adapter logs again.
    assert!(coord.note_not_usable_once(sid, "secondary", "win-adapter:{tap}"));
    // A different role under the same sid is tracked independently.
    assert!(coord.note_not_usable_once(sid, "primary", "win-adapter:{tap}"));
}

#[test]
fn auto_heal_persists_corrected_binding_once() {
    // The stored secondary id is stale (adapter reinstalled → new GUID) but
    // the saved name still matches exactly one live adapter → auto-heal +
    // persist the corrected id, ONCE per distinct mapping (HW-0705).
    let api = Arc::new(MockWindowsApi::new());
    // Live adapter: new name/GUID "newguid", description "desc newguid",
    // up + IPv4 + gateway → Available and usable.
    let live = adapter("newguid", 59, true, true, Some([10, 0, 0, 1]));
    api.set_adapter_infos(vec![live]);

    let policy = Arc::new(FakePolicy::new());
    // Stale stored id; saved name "desc newguid" is a token-subset of the
    // live description, so the heal matches it.
    policy.bind_secondary_named("S-HEAL", "win-adapter:{oldguid}", "desc newguid");

    // Capture each persist as one "sid|role|id|name" line (a flat Vec keeps
    // the closure type simple for clippy::type_complexity).
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = Arc::clone(&captured);
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    )
    .with_binding_heal_persist(Arc::new(move |sid, role, id, name| {
        cap.lock()
            .unwrap()
            .push(format!("{sid}|{role}|{id}|{name}"));
    }));

    // First resolution heals and persists exactly once.
    let r1 = coord.resolve("S-HEAL");
    assert!(r1.secondary.is_some(), "heal should yield a usable target");
    {
        let c = captured.lock().unwrap();
        assert_eq!(c.len(), 1, "persist fires once on first heal");
        assert_eq!(
            c[0], "S-HEAL|secondary|win-adapter:newguid|desc newguid",
            "healed id + name persisted for the secondary role"
        );
    }
    // Re-resolving the SAME stale→healed mapping must NOT persist again
    // (note_heal_once dedup) — no per-reconcile write storm.
    let _ = coord.resolve("S-HEAL");
    assert_eq!(
        captured.lock().unwrap().len(),
        1,
        "repeated heal of the same mapping does not re-persist"
    );
}

#[test]
fn a_tunnel_adapter_whose_mac_follows_its_guid_gets_no_anchor() {
    // Taken from a live run: TAP-Windows reported MAC 00:FF:0C:93:B1:CC under
    // GUID {0C93B1CC-9269-4F48-B0E8-EEE8918BBECC}. The two rotate together on
    // every reconnect, so the MAC is not an identity of its own.
    let mut tap = adapter(
        "{0C93B1CC-9269-4F48-B0E8-EEE8918BBECC}",
        14,
        true,
        true,
        None,
    );
    tap.mac = Some([0x00, 0xFF, 0x0C, 0x93, 0xB1, 0xCC]);
    tap.description = "TAP-Windows Adapter V9".into();
    assert_eq!(mac_anchor_id(&tap), None);
}

#[test]
fn a_physical_adapter_anchors_on_its_mac_and_is_found_by_it_after_a_guid_change() {
    let mut nic = adapter(
        "{282A0045-3DE1-4BFE-8296-B000D7F933ED}",
        18,
        true,
        true,
        None,
    );
    nic.mac = Some([0xD8, 0xC4, 0x97, 0x14, 0xBA, 0x2E]);
    nic.description = "Realtek(R) PCI(e) Ethernet Controller".into();
    let anchor = mac_anchor_id(&nic).expect("a burned-in MAC is an anchor");
    assert_eq!(anchor, "win-mac:D8-C4-97-14-BA-2E");

    // Same card, new GUID and new ifindex (came back on another port): the
    // anchor still names it, which is the whole point.
    let mut moved = adapter(
        "{99999999-0000-0000-0000-000000000000}",
        41,
        true,
        true,
        None,
    );
    moved.mac = nic.mac;
    assert!(adapter_binding_matches(&moved, &anchor));
    // A different card must not answer to it.
    let mut other = adapter(
        "{88888888-0000-0000-0000-000000000000}",
        42,
        true,
        true,
        None,
    );
    other.mac = Some([0xD8, 0xC4, 0x97, 0x14, 0xBA, 0x2F]);
    assert!(!adapter_binding_matches(&other, &anchor));
}

#[test]
fn a_virtual_software_adapter_gets_no_anchor() {
    let mut vswitch = adapter(
        "{11111111-0000-0000-0000-000000000000}",
        20,
        true,
        true,
        None,
    );
    vswitch.mac = Some([0x00, 0x15, 0x5D, 0x01, 0x02, 0x03]);
    vswitch.description = "Hyper-V Virtual Ethernet Adapter".into();
    assert_eq!(mac_anchor_id(&vswitch), None);
}

#[test]
fn the_mac_anchor_is_persisted_once_per_binding() {
    let api = Arc::new(MockWindowsApi::new());
    let mut nic = adapter("boundnic", 7, true, true, Some([10, 0, 0, 1]));
    nic.mac = Some([0xD8, 0xC4, 0x97, 0x14, 0xBA, 0x2E]);
    api.set_adapter_infos(vec![nic]);

    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary_named("S-ANCHOR", "win-adapter:boundnic", "desc boundnic");

    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = Arc::clone(&captured);
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    )
    .with_binding_anchor_persist(Arc::new(move |sid, role, anchor| {
        cap.lock().unwrap().push(format!("{sid}|{role}|{anchor}"));
    }));

    let _ = coord.resolve("S-ANCHOR");
    let _ = coord.resolve("S-ANCHOR");
    let c = captured.lock().unwrap();
    assert_eq!(
        *c,
        vec!["S-ANCHOR|secondary|win-mac:D8-C4-97-14-BA-2E".to_string()],
        "the anchor is learned on resolve and written once, not every reconcile"
    );
}

#[test]
fn two_live_adapters_answering_to_the_saved_name_ask_the_user_instead_of_guessing() {
    use crate::ipc_handlers::event_bus::EventBus;
    use nrr_shared::ipc_payloads::StatusUpdateEvent;

    let api = Arc::new(MockWindowsApi::new());
    // Two usable adapters of the same family — the bound GUID is gone.
    let mut a = adapter("tap-a", 21, true, true, Some([10, 0, 0, 1]));
    a.description = "vpn adapter".into();
    a.friendly_name = "vpn adapter".into();
    let mut b = adapter("tap-b", 22, true, true, Some([10, 0, 0, 2]));
    b.description = "vpn adapter".into();
    b.friendly_name = "vpn adapter".into();
    api.set_adapter_infos(vec![a, b]);

    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary_named("S-AMBIG", "win-adapter:{gone}", "vpn adapter");

    let bus = Arc::new(EventBus::new());
    // The notice names this SID, so it is delivered to that principal;
    // an unnamed subscriber is shown machine-wide events only.
    let sub = bus
        .subscribe_as("test".into(), Some("S-AMBIG".into()), None)
        .subscription_id;
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    )
    .with_event_bus(Arc::clone(&bus));

    let r = coord.resolve("S-AMBIG");
    assert!(
        r.secondary.is_none(),
        "an ambiguous name must not be resolved by guessing"
    );
    // Re-resolving the same state must not re-publish.
    let _ = coord.resolve("S-AMBIG");

    let events = bus.peek_pending_for(&sub, 16);
    let published: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.event {
            StatusUpdateEvent::EnforcementStatusChanged {
                status,
                role,
                candidates,
                ..
            } => Some((status.clone(), role.clone(), candidates.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        published,
        vec![(
            "adapter-choice-needed".to_string(),
            "secondary".to_string(),
            vec!["vpn adapter".to_string(), "vpn adapter".to_string()]
        )],
        "the choice is announced once, with the adapters to choose from"
    );
}

#[test]
fn a_binding_that_resolves_clears_the_standing_enforcement_notice() {
    use crate::ipc_handlers::event_bus::EventBus;
    use nrr_shared::ipc_payloads::StatusUpdateEvent;

    let api = Arc::new(MockWindowsApi::new());
    api.set_adapter_infos(vec![adapter("nic", 30, true, true, Some([10, 0, 0, 1]))]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary_named("S-OK", "win-adapter:nic", "desc nic");

    let bus = Arc::new(EventBus::new());
    // The notice names this SID, so it is delivered to that principal;
    // an unnamed subscriber is shown machine-wide events only.
    let sub = bus
        .subscribe_as("test".into(), Some("S-OK".into()), None)
        .subscription_id;
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    )
    .with_event_bus(Arc::clone(&bus));

    let _ = coord.resolve("S-OK");
    let _ = coord.resolve("S-OK");
    let statuses: Vec<(String, String)> = bus
        .peek_pending_for(&sub, 16)
        .iter()
        .filter_map(|e| match &e.event {
            StatusUpdateEvent::EnforcementStatusChanged { status, role, .. } => {
                Some((role.clone(), status.clone()))
            }
            _ => None,
        })
        .collect();
    // The secondary resolves; this fixture has no primary and no OS default
    // route to derive one, so the two roles report independently — and each
    // reports once, however many times the reconcile runs.
    assert_eq!(
        statuses,
        vec![
            ("secondary".to_string(), "ok".to_string()),
            ("primary".to_string(), "no-primary-route".to_string()),
        ],
        "published on change only, per role"
    );
}

#[test]
fn found_but_down_bound_adapter_heals_to_available_same_name_sibling() {
    // the bound GUID is still ENUMERATED but DOWN (a GUID-churning
    // VPN can leave a stale/down TAP instance visible while the freshly-connected
    // one carries traffic). The resolver must heal to the live same-name SIBLING
    // instead of failing closed on the down instance.
    let api = Arc::new(MockWindowsApi::new());
    // `down` = the bound (present-but-down) instance; `sibling` = a live
    // same-family adapter whose version token differs.
    let mut down = adapter("oldtap", 1, false, false, None);
    down.description = "hidemy vpn 3.0 adapter".into();
    down.friendly_name = down.description.clone();
    let mut sibling = adapter("newtap", 2, true, true, Some([10, 0, 0, 1]));
    sibling.description = "hidemy vpn adapter".into();
    sibling.friendly_name = sibling.description.clone();
    api.set_adapter_infos(vec![down, sibling]);

    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary_named("S-DOWN", "win-adapter:oldtap", "hidemy vpn 3.0 adapter");

    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = Arc::clone(&captured);
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    )
    .with_binding_heal_persist(Arc::new(move |sid, role, id, name| {
        cap.lock()
            .unwrap()
            .push(format!("{sid}|{role}|{id}|{name}"));
    }));

    let r = coord.resolve("S-DOWN");
    assert!(
        r.secondary.is_some(),
        "a present-but-down bound adapter must heal to the live same-name sibling, not fail closed"
    );
    let c = captured.lock().unwrap();
    assert_eq!(c.len(), 1, "the healed sibling id is persisted once");
    assert_eq!(
        c[0],
        "S-DOWN|secondary|win-adapter:newtap|hidemy vpn adapter"
    );
}

#[test]
fn recompute_applies_active_users_secondary_routes() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1), ip_rule("r2", 2, 2, 2, 2)]),
    );
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));

    let delta = coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .unwrap();
    assert_eq!(delta.added, 2);
    assert_eq!(
        table_dests(&api),
        HashSet::from([Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)])
    );
}

#[test]
fn switching_active_user_replaces_the_route_table() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1)]),
    );
    rules.set_secondary(
        "S-PETROV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r2", 2, 2, 2, 2)]),
    );
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));

    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .unwrap();
    assert_eq!(
        table_dests(&api),
        HashSet::from([Ipv4Addr::new(1, 1, 1, 1)])
    );

    // Petrov logs in (becomes active) → Ivanov's routes torn down,
    // Petrov's installed. The machine-wide table follows the active user.
    coord
        .recompute_for("S-PETROV", &res(Some(target())))
        .unwrap();
    assert_eq!(
        table_dests(&api),
        HashSet::from([Ipv4Addr::new(2, 2, 2, 2)])
    );
}

#[test]
fn no_secondary_target_tears_down_routes() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1)]),
    );
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));
    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .unwrap();
    assert_eq!(coord.owned_count(), 1);

    // Secondary goes away (unbound / adapter down) → routes removed.
    let delta = coord.recompute_for("S-IVANOV", &res(None)).unwrap();
    assert_eq!(delta.removed, 1);
    assert!(table_dests(&api).is_empty());
}

/// An admin edits the shared baseline while the user has a tray connected.
/// The user has not diverged, so the baseline IS their rule book — and the
/// route half must follow, not wait for the periodic safety recompute.
#[test]
fn a_baseline_edit_re_drives_routes_with_a_tray_connected() {
    use crate::ipc_handlers::providers::RoutePolicyApplyTrigger;

    #[derive(Default)]
    struct CountingInner(std::sync::atomic::AtomicUsize);
    impl RoutePolicyApplyTrigger for CountingInner {
        fn on_policy_changed(&self, _sid: &str) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let api = Arc::new(MockWindowsApi::new());
    let live = adapter("vpn", 7, true, true, Some([10, 0, 0, 1]));
    let bind_id = format!("win-adapter:{}", live.adapter_name);
    api.set_adapter_infos(vec![live]);
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &bind_id);
    let coord = Arc::new(coordinator_with_policy(
        Arc::clone(&api),
        Arc::clone(&rules),
        policy,
    ));

    // A tray is connected: the registry is NOT empty.
    let registry = Arc::new(crate::active_sid_registry::ActiveSidRegistry::new());
    registry.on_connect(
        "S-IVANOV",
        nrr_shared::ipc::IpcClientProfile::TrayLightweight,
    );
    assert!(!registry.active_sids().is_empty());

    let inner = Arc::new(CountingInner::default());
    let trigger = RouteAndFilterApplyTrigger::new(
        Arc::clone(&inner) as Arc<dyn RoutePolicyApplyTrigger>,
        Arc::clone(&coord),
        registry,
    );
    trigger.on_policy_changed(nrr_domain::user_principal::BASELINE_PRINCIPAL);

    assert_eq!(
        table_dests(&api),
        HashSet::from([Ipv4Addr::new(1, 1, 1, 1)]),
        "the baseline edit must reach the route table, not stop at the filters"
    );
    assert_eq!(inner.0.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn recompute_active_tears_down_when_effective_sid_paused() {
    // Safe-disable ROUTE-half — when the pause predicate reports the
    // effective routing SID paused, `recompute_active` returns a clear()
    // delta and installs no routes, even though rules + a usable secondary
    // would otherwise produce a /32. The gate sits in the single re-drive
    // choke point (recompute_active), so every trigger honours it.
    use std::sync::atomic::{AtomicBool, Ordering};
    let api = Arc::new(MockWindowsApi::new());
    // A live, usable secondary adapter so resolve() yields a route target.
    let live = adapter("vpn", 7, true, true, Some([10, 0, 0, 1]));
    let bind_id = format!("win-adapter:{}", live.adapter_name);
    api.set_adapter_infos(vec![live]);

    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &bind_id);

    let paused = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&paused);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy)
        .with_pause_state(Arc::new(move |_sid: &str| {
            if flag.load(Ordering::SeqCst) {
                PausedRouteDisposition::ClearAll
            } else {
                PausedRouteDisposition::Active
            }
        }));

    // Not paused → the /32 secondary route installs.
    coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert_eq!(coord.owned_count(), 1);
    assert_eq!(
        table_dests(&api),
        HashSet::from([Ipv4Addr::new(1, 1, 1, 1)])
    );

    // Pause the effective routing user (teardown policy) → the next recompute
    // (via ANY re-drive path) tears the route table down instead of
    // reinstalling.
    paused.store(true, Ordering::SeqCst);
    let delta = coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert_eq!(delta.removed, 1);
    assert_eq!(coord.owned_count(), 0);
    assert!(table_dests(&api).is_empty());
}

#[test]
fn recompute_active_keeps_slash32_when_paused_persist() {
    // Safe-disable ROUTE-half — when the paused user's stop-policy is
    // Persist, the recompute gate must KEEP the
    // /32 secondary rule-routes (it drops only overlays), NOT full-clear them.
    // Before the fix the 30 s safety tick returned clear() unconditionally,
    // silently deleting the /32s `teardown_routes` deliberately kept and
    // defeating the Persist opt-in within ~30 s of pausing.
    use std::sync::atomic::{AtomicBool, Ordering};
    let api = Arc::new(MockWindowsApi::new());
    let live = adapter("vpn", 7, true, true, Some([10, 0, 0, 1]));
    let bind_id = format!("win-adapter:{}", live.adapter_name);
    api.set_adapter_infos(vec![live]);

    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &bind_id);

    let paused = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&paused);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy)
        .with_pause_state(Arc::new(move |_sid: &str| {
            if flag.load(Ordering::SeqCst) {
                PausedRouteDisposition::KeepSecondaryHosts
            } else {
                PausedRouteDisposition::Active
            }
        }));

    // Not paused → the /32 secondary route installs.
    coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert_eq!(coord.owned_count(), 1);

    // Pause with Persist policy → the safety-tick recompute KEEPS the /32.
    paused.store(true, Ordering::SeqCst);
    coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert_eq!(
        coord.owned_count(),
        1,
        "Persist keeps the /32 rule-route across a paused re-drive"
    );
    assert_eq!(
        table_dests(&api),
        HashSet::from([Ipv4Addr::new(1, 1, 1, 1)]),
        "the matched host still egresses the secondary under Persist pause"
    );
}

/// A VPN client that renamed only the connection is the common case; the
/// driver description stays generic, so both names have to be read.
#[test]
fn a_renamed_connection_still_reads_as_a_personal_tunnel() {
    let mut tun = adapter("tap", 7, true, true, None);
    tun.description = "TAP-Windows Adapter V9".into();
    tun.friendly_name = "hidemy.name VPN OpenVPN Adapter".into();
    assert_eq!(
        personal_tunnel_name(&[adapter("wifi", 3, true, true, Some([192, 168, 0, 1])), tun]),
        Some("hidemy.name VPN OpenVPN Adapter".to_string())
    );
}

/// A corporate client belongs to an employer; telling that user to make it
/// their additional route would be the product guessing at IT policy.
#[test]
fn a_corporate_client_raises_no_offer() {
    let mut tun = adapter("fort", 8, true, true, None);
    tun.friendly_name = "FortiClient VPN".into();
    tun.description = "FortiClient Virtual Ethernet Adapter".into();
    assert_eq!(personal_tunnel_name(&[tun]), None);
}

/// An installed-but-disconnected client is not a tunnel the user is
/// waiting on.
#[test]
fn a_tunnel_that_is_down_raises_no_offer() {
    let mut tun = adapter("tap", 9, false, false, None);
    tun.friendly_name = "Mullvad VPN".into();
    assert_eq!(personal_tunnel_name(&[tun]), None);
}

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
        gateways: gw.map(|g| vec![Ipv4Addr::from(g)]).unwrap_or_default(),
    }
}

fn route_entry(
    dest: [u8; 4],
    prefix: u8,
    next_hop: [u8; 4],
    ifindex: u32,
    metric: u32,
) -> RouteEntry {
    RouteEntry {
        destination: Ipv4Addr::from(dest),
        prefix_length: prefix,
        next_hop: Ipv4Addr::from(next_hop),
        interface_index: ifindex,
        metric,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    }
}

#[test]
fn derives_tunnel_next_hop_from_redirect_gateway_split_routes() {
    // Mirrors a live hidemy.name OpenVPN table: split-default via the
    // peer 10.91.192.1, no adapter gateway, on ifindex 78.
    let routes = vec![
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
        route_entry([128, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
        route_entry([10, 91, 193, 99], 32, [0, 0, 0, 0], 78, 256), // on-link → ignored
        route_entry([0, 0, 0, 0], 0, [192, 168, 1, 1], 12, 25),    // other ifindex → ignored
    ];
    assert_eq!(
        derive_secondary_next_hop(&routes, 78),
        Some(Ipv4Addr::new(10, 91, 192, 1))
    );
    // No default-style route on an unrelated ifindex → None.
    assert_eq!(derive_secondary_next_hop(&routes, 999), None);
}

#[test]
fn derive_prefers_real_default_over_split_halves() {
    let routes = vec![
        route_entry([0, 0, 0, 0], 1, [10, 0, 0, 1], 5, 1), // /1 split half
        route_entry([0, 0, 0, 0], 0, [10, 0, 0, 9], 5, 50), // real /0 default — wins despite higher metric
    ];
    assert_eq!(
        derive_secondary_next_hop(&routes, 5),
        Some(Ipv4Addr::new(10, 0, 0, 9))
    );
}

#[test]
fn derive_ignores_on_link_and_loopback_but_falls_back_to_gateway_style_routes() {
    // On-link and loopback rows can never name a peer.
    let dead_ends = vec![
        route_entry([0, 0, 0, 0], 1, [0, 0, 0, 0], 5, 1), // on-link (unspecified next-hop)
        route_entry([0, 0, 0, 0], 0, [127, 0, 0, 1], 5, 1), // loopback next-hop
    ];
    assert_eq!(derive_secondary_next_hop(&dead_ends, 5), None);
    //  — a non-default gateway-style route IS a last resort:
    // on a point-to-point tunnel it names the same single peer the
    // stripped catch-alls did.
    let with_host_route = vec![
        route_entry([10, 0, 0, 0], 8, [10, 0, 0, 1], 5, 1),
        route_entry([0, 0, 0, 0], 1, [0, 0, 0, 0], 5, 1),
    ];
    assert_eq!(
        derive_secondary_next_hop(&with_host_route, 5),
        Some(Ipv4Addr::new(10, 0, 0, 1))
    );
}

#[test]
fn derive_primary_target_picks_lowest_metric_default_off_secondary() {
    let routes = vec![
        route_entry([0, 0, 0, 0], 0, [192, 168, 1, 1], 12, 25), // real default on eth (ifx 12)
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),  // VPN /1 half → wrong prefix
        route_entry([0, 0, 0, 0], 0, [10, 91, 192, 1], 78, 1),  // VPN /0 on secondary → excluded
        route_entry([0, 0, 0, 0], 0, [192, 168, 1, 254], 12, 5), // lower-metric default → wins
    ];
    let t = derive_primary_target(&routes, 78).expect("primary derived from OS default");
    assert_eq!(t.interface_index, 12);
    assert_eq!(t.gateway, Ipv4Addr::new(192, 168, 1, 254));
}

#[test]
fn derive_primary_target_none_when_only_secondary_has_default() {
    // The VPN replaced /0 itself; nothing left to derive → None (caller warns).
    let routes = vec![route_entry([0, 0, 0, 0], 0, [10, 91, 192, 1], 78, 1)];
    assert!(derive_primary_target(&routes, 78).is_none());
}

#[test]
fn recompute_mode_a_emits_counter_overlay_via_derived_primary() {
    // The footgun: user binds ONLY the secondary (VPN), picks "direct"
    // (mode A). The /2 counter-overlay (so unmatched → real link) needs a
    // primary; we derive it from the OS default route. Without this fix,
    // unmatched traffic silently rode the VPN's redirect.
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("hidemyvpn", 78, true, true, Some([10, 0, 0, 1]));
    let vpn_id = vpn.stable_id();
    api.set_adapter_infos(vec![vpn]);
    api.set_route_table(vec![
        route_entry([0, 0, 0, 0], 0, [192, 168, 1, 1], 12, 25), // OS default on eth
    ]);
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 93, 184, 216, 34)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &vpn_id); // ONLY secondary bound
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();

    let table = api.get_ip_forward_table().unwrap();
    let counter: Vec<_> = table.iter().filter(|r| r.prefix_length == 2).collect();
    assert_eq!(
        counter.len(),
        4,
        "four /2 counter-overlay routes must be installed via the derived primary"
    );
    assert!(
        counter
            .iter()
            .all(|r| r.interface_index == 12 && r.next_hop == Ipv4Addr::new(192, 168, 1, 1)),
        "counter-overlay must route via the derived primary gateway, not the secondary"
    );
}

#[test]
fn recompute_active_routes_via_derived_next_hop_for_gatewayless_vpn() {
    // End-to-end: a gateway-less VPN adapter (the round-6 dead end) must
    // now route — resolve_target derives the tunnel peer from the route
    // table and the /32 overlay is installed via it.
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("hidemyvpn", 78, true, true, None); // up, IPv4, NO gateway
    let bound_id = vpn.stable_id();
    api.set_adapter_infos(vec![vpn]);
    api.set_route_table(vec![
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
        route_entry([128, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
    ]);

    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 93, 184, 216, 34)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &bound_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    let delta = coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert_eq!(delta.added, 1, "the /32 overlay must be installed");

    let table = api.get_ip_forward_table().unwrap();
    let ours = table
        .iter()
        .find(|r| r.destination == Ipv4Addr::new(93, 184, 216, 34))
        .expect("our /32 overlay must be present");
    assert_eq!(
        ours.next_hop,
        Ipv4Addr::new(10, 91, 192, 1),
        "must use the derived tunnel next-hop, not a (missing) adapter gateway"
    );
    assert_eq!(ours.interface_index, 78);
}

#[test]
fn cache_keeps_routes_when_vpn_catch_all_vanishes() {
    // Add-only world (the C2 strip is disabled): if the VPN's catch-all
    // routes briefly vanish — e.g. a reconnect blip — derivation fails, but
    // the cached next-hop keeps our /32 routes alive instead of tearing them
    // down. Guards the gateway-less-VPN next-hop cache.
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("hidemyvpn", 78, true, true, None); // up, IPv4, NO gateway
    let bound_id = vpn.stable_id();
    api.set_adapter_infos(vec![vpn]);
    api.set_route_table(vec![
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
        route_entry([128, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
    ]);
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 93, 184, 216, 34)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &bound_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    // Cycle 1: derive the peer from the VPN's /1 (cached) + install the /32.
    coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert!(
        api.get_ip_forward_table()
            .unwrap()
            .iter()
            .any(|r| r.destination == Ipv4Addr::new(93, 184, 216, 34)),
        "our /32 installed in cycle 1"
    );

    // The VPN's catch-all routes vanish (reconnect blip) — only our /32 left.
    api.set_route_table(vec![route_entry(
        [93, 184, 216, 34],
        32,
        [10, 91, 192, 1],
        78,
        5,
    )]);

    // Cycle 2: derivation fails (no catch-all) → cache fallback keeps the /32.
    coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert!(
        api.get_ip_forward_table()
            .unwrap()
            .iter()
            .any(|r| r.destination == Ipv4Addr::new(93, 184, 216, 34)),
        "our /32 survives via the cached next-hop (NOT cleared)"
    );
}

#[test]
fn resolve_secondary_luid_returns_luid_for_bound_usable_secondary() {
    // the coordinator hands the WFP
    // orchestrator the secondary interface LUID to pin its egress
    // condition to.
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("hidemyvpn", 78, true, true, Some([10, 0, 0, 1]));
    let bound_id = vpn.stable_id();
    api.set_adapter_infos(vec![vpn]);
    let rules = Arc::new(FakeRules::new());
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &bound_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    assert_eq!(
        coord.resolve_secondary_luid("S-IVANOV"),
        Some(nrr_platform_api::windows_api::mock_luid_for_index(78)),
        "must resolve the bound secondary's ifindex to its LUID",
    );
}

#[test]
fn resolve_secondary_luid_none_when_no_usable_secondary() {
    // No secondary bound at all → None (fail-open: no kill-switch).
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    let policy = Arc::new(FakePolicy::new());
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);
    assert_eq!(coord.resolve_secondary_luid("S-NOBODY"), None);
}

#[test]
fn resolve_egress_source_ips_returns_the_adapters_own_addresses() {
    // The fake-IP relay binds its dials to these; each role must yield the
    // resolved adapter's OWN unicast address, and a down secondary must
    // yield None (the relay then refuses instead of leaking).
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("hidemyvpn", 78, true, true, Some([10, 0, 0, 1]));
    let eth = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
    let vpn_id = vpn.stable_id();
    let eth_id = eth.stable_id();
    api.set_adapter_infos(vec![vpn, eth]);
    let rules = Arc::new(FakeRules::new());
    let policy = Arc::new(FakePolicy::new());
    policy.bind_primary("S-IVANOV", &eth_id);
    policy.bind_secondary("S-IVANOV", &vpn_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    let (primary, secondary) = coord.resolve_egress_source_ips("S-IVANOV");
    assert_eq!(primary, Some(Ipv4Addr::new(192, 168, 1, 50)));
    assert_eq!(secondary, Some(Ipv4Addr::new(192, 168, 1, 50)));

    // The secondary goes down → its source disappears, the primary stays.
    let vpn_down = adapter("hidemyvpn", 78, false, true, Some([10, 0, 0, 1]));
    let eth_up = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
    api.set_adapter_infos(vec![vpn_down, eth_up]);
    let (primary, secondary) = coord.resolve_egress_source_ips("S-IVANOV");
    assert_eq!(primary, Some(Ipv4Addr::new(192, 168, 1, 50)));
    assert_eq!(secondary, None);
}

#[test]
fn kill_switch_exemptions_resolves_luid_servers_and_subnets() {
    // the coordinator derives the catch-all
    // exemptions: the secondary LUID, the VPN server IP (bootstrap host
    // route via the primary gateway), and the primary's connected subnet.
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("hidemyvpn", 78, true, true, Some([10, 0, 0, 1]));
    let eth = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
    let vpn_id = vpn.stable_id();
    let eth_id = eth.stable_id();
    api.set_adapter_infos(vec![vpn, eth]);
    api.set_route_table(vec![
        route_entry([203, 0, 113, 7], 32, [192, 168, 1, 1], 12, 5), // VPN server bootstrap via eth gw
        route_entry([192, 168, 1, 0], 24, [0, 0, 0, 0], 12, 5),     // primary connected subnet
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),      // VPN redirect half
    ]);
    let rules = Arc::new(FakeRules::new());
    let policy = Arc::new(FakePolicy::new());
    policy.bind_primary("S-IVANOV", &eth_id);
    policy.bind_secondary("S-IVANOV", &vpn_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    let ex = coord
        .kill_switch_exemptions("S-IVANOV")
        .expect("exemptions resolve when secondary + primary are usable");
    assert_eq!(
        ex.secondary_luid,
        nrr_platform_api::windows_api::mock_luid_for_index(78)
    );
    assert_eq!(ex.bootstrap_server_ips, vec![Ipv4Addr::new(203, 0, 113, 7)]);
    assert_eq!(ex.local_subnets, vec![(Ipv4Addr::new(192, 168, 1, 0), 24)]);
}

/// Mode B pulls primary-bound rules back to the primary NIC as `/32`
/// exceptions — which is byte-for-byte the shape of a VPN bootstrap host
/// route. Collected as "server IPs" they were exempted from the block-all
/// permanently, and cached, so they outlived the rule that made them.
#[test]
fn our_own_exception_routes_are_not_mistaken_for_vpn_server_ips() {
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("hidemyvpn", 78, true, true, Some([10, 0, 0, 1]));
    let eth = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
    let vpn_id = vpn.stable_id();
    let eth_id = eth.stable_id();
    api.set_adapter_infos(vec![vpn, eth]);
    let ours = route_entry([198, 51, 100, 5], 32, [192, 168, 1, 1], 12, 5);
    api.set_route_table(vec![
        route_entry([203, 0, 113, 7], 32, [192, 168, 1, 1], 12, 5), // the real bootstrap route
        ours.clone(),                                               // our mode-B exception
        route_entry([192, 168, 1, 0], 24, [0, 0, 0, 0], 12, 5),
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
    ]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_primary("S-IVANOV", &eth_id);
    policy.bind_secondary("S-IVANOV", &vpn_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy);

    let before = coord
        .kill_switch_exemptions("S-IVANOV")
        .expect("exemptions resolve");
    assert!(
        before
            .bootstrap_server_ips
            .contains(&Ipv4Addr::new(198, 51, 100, 5)),
        "fixture check: unowned, it looks like a server IP"
    );

    coord.reconciler.adopt_owned(vec![ours]);
    let after = coord
        .kill_switch_exemptions("S-IVANOV")
        .expect("exemptions resolve");
    assert_eq!(
        after.bootstrap_server_ips,
        vec![Ipv4Addr::new(203, 0, 113, 7)],
        "our own route must not become a permanent hole in the block-all"
    );
}

/// An empty route table and an unreadable one used to be the same value.
/// Armed on the empty reading, the kill-switch exempts no LAN, no DHCP and
/// no printers — and says nothing about why.
#[test]
fn an_unreadable_route_table_keeps_the_kill_switch_off() {
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("hidemyvpn", 78, true, true, Some([10, 0, 0, 1]));
    let eth = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
    let vpn_id = vpn.stable_id();
    let eth_id = eth.stable_id();
    api.set_adapter_infos(vec![vpn, eth]);
    api.set_route_table(vec![
        route_entry([192, 168, 1, 0], 24, [0, 0, 0, 0], 12, 5),
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
    ]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_primary("S-IVANOV", &eth_id);
    policy.bind_secondary("S-IVANOV", &vpn_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy);
    assert!(
        coord.kill_switch_exemptions("S-IVANOV").is_some(),
        "the fixture itself must resolve"
    );

    api.set_route_table_read_error(Some("enumeration failed"));
    assert!(
        coord.kill_switch_exemptions("S-IVANOV").is_none(),
        "an unknown set of local subnets must not arm a kill-switch"
    );
}

/// The fail-closed path cannot decline — the block-all is armed either way —
/// so it falls back to what the link was last seen with rather than cutting
/// the user's own network.
#[test]
fn fail_closed_falls_back_to_the_last_known_local_subnets() {
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("hidemyvpn", 78, true, true, Some([10, 0, 0, 1]));
    let eth = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
    let vpn_id = vpn.stable_id();
    let eth_id = eth.stable_id();
    api.set_adapter_infos(vec![vpn, eth]);
    api.set_route_table(vec![
        route_entry([192, 168, 1, 0], 24, [0, 0, 0, 0], 12, 5),
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
    ]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_primary("S-IVANOV", &eth_id);
    policy.bind_secondary("S-IVANOV", &vpn_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy);

    let warm = coord.fail_closed_exemptions("S-IVANOV");
    assert_eq!(
        warm.local_subnets,
        vec![(Ipv4Addr::new(192, 168, 1, 0), 24)]
    );

    api.set_route_table_read_error(Some("enumeration failed"));
    let degraded = coord.fail_closed_exemptions("S-IVANOV");
    assert_eq!(
        degraded.local_subnets,
        vec![(Ipv4Addr::new(192, 168, 1, 0), 24)],
        "the block-all must keep the LAN it knew about"
    );
}

#[test]
fn kill_switch_exemptions_cache_keeps_server_ip_after_bootstrap_route_vanishes() {
    // The VPN client drops the bootstrap route while disconnected; the
    // last-known server IP must survive (else reconnection deadlocks).
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("hidemyvpn", 78, true, true, Some([10, 0, 0, 1]));
    let eth = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
    let vpn_id = vpn.stable_id();
    let eth_id = eth.stable_id();
    api.set_adapter_infos(vec![vpn, eth]);
    api.set_route_table(vec![route_entry(
        [203, 0, 113, 7],
        32,
        [192, 168, 1, 1],
        12,
        5,
    )]);
    let rules = Arc::new(FakeRules::new());
    let policy = Arc::new(FakePolicy::new());
    policy.bind_primary("S-IVANOV", &eth_id);
    policy.bind_secondary("S-IVANOV", &vpn_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    // Cycle 1: server IP present → cached.
    let ex1 = coord.kill_switch_exemptions("S-IVANOV").unwrap();
    assert_eq!(
        ex1.bootstrap_server_ips,
        vec![Ipv4Addr::new(203, 0, 113, 7)]
    );

    // Bootstrap route vanishes (VPN disconnected).
    api.set_route_table(vec![]);

    // Cycle 2: live table empty → cache fallback keeps the server IP.
    let ex2 = coord.kill_switch_exemptions("S-IVANOV").unwrap();
    assert_eq!(
        ex2.bootstrap_server_ips,
        vec![Ipv4Addr::new(203, 0, 113, 7)],
        "cached server IP must survive a bootstrap-route blip"
    );
}

#[test]
fn description_matches_display_name_version_robust_and_symmetric() {
    // Live description carries an extra version token vs the saved name.
    assert!(description_matches_display_name(
        "hidemy.name VPN 3.0 OpenVPN Adapter",
        "hidemy.name VPN OpenVPN Adapter",
    ));
    // regression: the SAVED name carries the version token and the
    // live adapter dropped it — the "every other day" heal failure. The old
    // directional subset returned false here; symmetric containment heals it.
    assert!(description_matches_display_name(
        "hidemy.name VPN OpenVPN Adapter",
        "hidemy.name VPN 3.0 OpenVPN Adapter",
    ));
    // Both sides versioned, different versions → same family.
    assert!(description_matches_display_name(
        "hidemy.name VPN 4.1 OpenVPN Adapter",
        "hidemy.name VPN 3.0 OpenVPN Adapter",
    ));
    // Survives a version bump (saved has no version).
    assert!(description_matches_display_name(
        "hidemy.name VPN 4.1 OpenVPN Adapter",
        "hidemy.name VPN OpenVPN Adapter",
    ));
    // Case-insensitive.
    assert!(description_matches_display_name(
        "HIDEMY.NAME vpn openvpn ADAPTER",
        "hidemy.name VPN OpenVPN Adapter",
    ));
    // Different adapter → no match, both directions.
    assert!(!description_matches_display_name(
        "Intel(R) Ethernet Connection (2) I219-V",
        "hidemy.name VPN OpenVPN Adapter",
    ));
    assert!(!description_matches_display_name(
        "hidemy.name VPN OpenVPN Adapter",
        "Intel(R) Ethernet Connection (2) I219-V",
    ));
    // Empty / whitespace-only display_name never matches.
    assert!(!description_matches_display_name("anything at all", "   "));
    // A name reduced to ONLY a version token has an empty core → no match
    // (never heal to an adapter whose family is unidentifiable).
    assert!(!description_matches_display_name("3.0", "hidemy.name VPN"));
}

#[test]
fn a_renamed_connection_on_a_stock_driver_still_answers_to_its_saved_name() {
    // The Windows 11 case: hidemy.name renames the CONNECTION but ships the
    // stock TAP driver, so the saved name shares no token with the driver
    // description and only the friendly name can identify the adapter.
    let mut vpn = adapter("tap", 9, true, true, Some([10, 88, 0, 1]));
    vpn.description = "TAP-Windows Adapter V9".into();
    vpn.friendly_name = "hidemy.name VPN OpenVPN Adapter".into();

    assert!(!description_matches_display_name(
        &vpn.description,
        "hidemy.name VPN OpenVPN Adapter"
    ));
    assert!(adapter_answers_to_saved_name(
        &vpn,
        "hidemy.name VPN OpenVPN Adapter"
    ));
    // The stored name follows the connection, so the GUI keeps the label
    // the user recognises.
    assert_eq!(
        preferred_display_name(&vpn),
        "hidemy.name VPN OpenVPN Adapter"
    );

    // An unrelated adapter must not be adopted through either name.
    let mut wifi = adapter("wifi", 17, true, true, Some([192, 168, 0, 1]));
    wifi.description = "Intel(R) Dual Band Wireless-AC 7265".into();
    wifi.friendly_name = "Wi-Fi".into();
    assert!(!adapter_answers_to_saved_name(
        &wifi,
        "hidemy.name VPN OpenVPN Adapter"
    ));
}

#[test]
fn a_blank_friendly_name_falls_back_to_the_driver_description() {
    let mut vpn = adapter("tap", 9, true, true, Some([10, 88, 0, 1]));
    vpn.description = "TAP-Windows Adapter V9".into();
    vpn.friendly_name = "   ".into();
    assert_eq!(preferred_display_name(&vpn), "TAP-Windows Adapter V9");
    assert!(adapter_answers_to_saved_name(
        &vpn,
        "TAP-Windows Adapter V9"
    ));
}

#[test]
fn recompute_active_resolves_target_and_routes_for_the_active_user() {
    // End-to-end through the wiring entry point: active SID → its
    // secondary binding → live adapter → target → routes.
    let api = Arc::new(MockWindowsApi::new());
    let sec = adapter("vpn", 9, true, true, Some([10, 0, 0, 1]));
    let sec_id = sec.stable_id();
    api.set_adapter_infos(vec![sec.clone()]);

    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &sec_id);

    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);
    let delta = coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert_eq!(delta.added, 1);
    let table = api.get_ip_forward_table().unwrap();
    let r = table
        .iter()
        .find(|r| r.destination == Ipv4Addr::new(1, 1, 1, 1))
        .unwrap();
    assert_eq!(r.interface_index, 9);
    assert_eq!(r.next_hop, Ipv4Addr::new(10, 0, 0, 1));
}

#[test]
fn adopt_orphans_picks_our_signature_then_recompute_purges_unwanted() {
    // Two of our /32 @metric5 orphans + one foreign route survive a
    // crash. Adoption claims only the two; a recompute that desires just
    // .1 deletes .2 but leaves the foreign route untouched.
    let api = Arc::new(MockWindowsApi::new());
    let ours_a = RouteEntry {
        destination: Ipv4Addr::new(1, 1, 1, 1),
        prefix_length: 32,
        next_hop: Ipv4Addr::new(10, 0, 0, 1),
        interface_index: 9,
        metric: 5,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    };
    let ours_b = RouteEntry {
        destination: Ipv4Addr::new(2, 2, 2, 2),
        ..ours_a.clone()
    };
    // Foreign: a /24 at a different metric — must NOT be adopted.
    let foreign = RouteEntry {
        destination: Ipv4Addr::new(8, 8, 8, 0),
        prefix_length: 24,
        next_hop: Ipv4Addr::new(192, 168, 0, 1),
        interface_index: 3,
        metric: 256,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    };
    api.set_route_table(vec![ours_a.clone(), ours_b, foreign.clone()]);

    let sec = adapter("vpn", 9, true, true, Some([10, 0, 0, 1]));
    let sec_id = sec.stable_id();
    api.set_adapter_infos(vec![sec]);
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &sec_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    coord.adopt_orphans_from_table();
    assert_eq!(coord.owned_count(), 2, "both /32 @5 orphans adopted");

    // Active user wants only .1 → .2 is purged, foreign stays.
    coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    let dests = table_dests(&api);
    assert!(
        dests.contains(&Ipv4Addr::new(1, 1, 1, 1)),
        "desired route kept"
    );
    assert!(!dests.contains(&Ipv4Addr::new(2, 2, 2, 2)), "orphan purged");
    assert!(
        dests.contains(&Ipv4Addr::new(8, 8, 8, 0)),
        "foreign route untouched"
    );
}

#[test]
fn adopt_orphans_claims_mode_a_counter_overlay_not_just_slash32() {
    // Regression (block 16, : a crash/kill (not a graceful stop)
    // can strand the mode-A `/2` counter-overlay (metric 5, on the primary
    // NIC) in the OS table. Adoption must claim it alongside the `/32`
    // host routes — previously only `/32` was adopted, so the `/2` lingered
    // forever and could keep forcing all non-rule traffic to the primary
    // after the owning service was gone (the kill-during-rebuild leftover).
    let api = Arc::new(MockWindowsApi::new());
    // Our /2 counter-overlay half @metric5 (primary NIC ifindex 12).
    let overlay = RouteEntry {
        destination: Ipv4Addr::new(0, 0, 0, 0),
        prefix_length: 2,
        next_hop: Ipv4Addr::new(192, 168, 0, 1),
        interface_index: 12,
        metric: 5,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    };
    // Our /32 secondary host route @metric5.
    let host = RouteEntry {
        destination: Ipv4Addr::new(1, 1, 1, 1),
        prefix_length: 32,
        next_hop: Ipv4Addr::new(10, 0, 0, 1),
        interface_index: 9,
        metric: 5,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    };
    // Foreign /2 at a different metric — must NOT be adopted.
    let foreign_overlay = RouteEntry {
        destination: Ipv4Addr::new(64, 0, 0, 0),
        prefix_length: 2,
        next_hop: Ipv4Addr::new(192, 168, 0, 1),
        interface_index: 12,
        metric: 256,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    };
    api.set_route_table(vec![overlay, host, foreign_overlay]);

    let rules = Arc::new(FakeRules::new());
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));

    coord.adopt_orphans_from_table();
    assert_eq!(
        coord.owned_count(),
        2,
        "the /2 counter-overlay and the /32 host route are both adopted; the foreign /2 @256 is not"
    );
}

#[test]
fn recompute_active_with_no_active_user_clears_table() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));
    let delta = coord.recompute_active(&[]).unwrap();
    assert!(delta.is_noop());
    assert!(table_dests(&api).is_empty());
}

#[test]
fn principal_with_no_rules_clears_routes_via_read_through_miss() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new()); // nothing set, no baseline
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));
    let delta = coord
        .recompute_for("S-UNKNOWN", &res(Some(target())))
        .unwrap();
    assert!(delta.is_noop());
    assert!(table_dests(&api).is_empty());
}
