use super::*;

/// A first contact routes only what the planner would, from the last
/// recompute's resolution, and the next recompute finds it in place.
#[test]
fn a_first_contact_routes_only_what_the_planner_would() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("a", 203, 0, 113, 1)]),
    );
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));
    let second = Ipv4Addr::new(203, 0, 113, 2);
    let unnamed = Ipv4Addr::new(198, 51, 100, 9);
    assert_eq!(
        coord.route_first_contact("S-IVANOV", &[second]),
        0,
        "nothing recomputed yet, so no resolution to plan from"
    );
    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .expect("recompute");

    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![
            ip_rule("a", 203, 0, 113, 1),
            ip_rule("b", 203, 0, 113, 2),
        ]),
    );
    assert_eq!(coord.route_first_contact("S-IVANOV", &[second, unnamed]), 1);
    let dests = table_dests(&api);
    assert!(dests.contains(&second), "{dests:?}");
    assert!(!dests.contains(&unnamed), "no rule names it: {dests:?}");

    let delta = coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .expect("recompute");
    assert!(delta.is_noop(), "{delta:?}");

    coord
        .recompute_for("S-IVANOV", &res(None))
        .expect("teardown");
    assert_eq!(
        coord.route_first_contact("S-IVANOV", &[second]),
        0,
        "no link, nothing to route"
    );
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
    // No persistence wired → empty exemption server set.
    let api = Arc::new(MockWindowsApi::new());
    let coord = coordinator(api, Arc::new(FakeRules::new()));
    let ex = coord.fail_closed_exemptions("S-1-5-21-A");
    assert!(ex.bootstrap_server_ips.is_empty());
    assert!(ex.probe_target_ips.is_empty());
}

#[test]
fn fail_closed_exemptions_carry_probe_target_even_when_liveness_dead() {
    // The block-all must keep a hole for the liveness
    // probe's ICMP target (the tunnel next-hop). A probe-DEAD verdict
    // empties the GATED resolution — which is exactly when the block-all
    // arms — so the exemption must come from the RAW binding resolution,
    // or the armed block eats the probe's echo and the DEAD verdict can
    // never flip back (the kill-switch would stay fail-closed through
    // every VPN reconnect until service restart).
    let sid = "S-1-5-21-A";
    let gw = Ipv4Addr::new(10, 0, 0, 1);
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("swiftvpnvpn", 78, true, true, Some([10, 0, 0, 1]));
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
    // While a VPN reconnects, its adapter enumerates Down
    // (no IPv4) and the probe cannot run. The failing run accumulated just
    // before the outage must be dropped the moment the binding stops
    // resolving, or the stale window declares the tunnel DEAD the instant
    // it comes back Up and the kill-switch fail-closes a freshly
    // reconnected, working tunnel.
    let sid = "S-1-5-21-A";
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("swiftvpnvpn", 60, true, true, Some([10, 88, 0, 1]));
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
    api.set_adapter_infos(vec![adapter("swiftvpnvpn", 60, false, false, None)]);
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
    let vpn = adapter("swiftvpnvpn", 60, true, true, Some([10, 88, 0, 1]));
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
        "swiftvpnvpn",
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
