use super::*;

// ── Kill-switch ───────────────────────────────

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
        .with_kill_switch_resolver(Arc::new(move |_, _| resolution.clone()))
        .with_killswitch_drop_registry(Arc::clone(&registry)),
    );
    (api, orch, source, rules, registry)
}

/// The blanket posture blocks the whole of IPv6 too, so what the resolution
/// says must survive it has to REACH the emitter. It once did not: the
/// exemptions the orchestrator builds from the resolution dropped the v6
/// halves on the floor, which trapped a tunnel whose endpoint is v6 and cut
/// the v6 LAN — the exact pair of failures the v4 exemptions exist to avoid.
#[test]
fn mode_b_carries_the_resolutions_v6_exemptions_into_the_block() {
    let server: std::net::Ipv6Addr = "2001:db8:ffff::7".parse().expect("literal");
    let lan: std::net::Ipv6Addr = "2001:db8:1::".parse().expect("literal");
    let (api, orch, src, rules) = fixture_with_resolution(Some(KillSwitchResolution {
        bootstrap_server_ips_v6: vec![server],
        local_subnets_v6: vec![(lan, 64)],
        ..full_ks_resolution()
    }));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(198, 51, 100, 8)));
    src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    for (net, prefix, what) in [
        (server, 128u8, "the tunnel's own v6 endpoint"),
        (lan, 64, "the v6 LAN"),
    ] {
        assert!(
            filters.iter().any(|f| f.action == WfpAction::Permit
                && f.remote_subnet_v6 == Some((net, prefix))),
            "{what} is not exempt from the v6 block",
        );
    }
}

#[test]
fn mode_b_arms_catch_all_kill_switch() {
    let (api, orch, src, rules) = fixture_with_resolution(Some(full_ks_resolution()));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(198, 51, 100, 8)));
    src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    // 0704 (P2): the catch-all arms at BOTH the ALE (TCP/UDP) and the
    // packet layers. The packet side is one NAMED block per
    // ICMP/IGMP/GRE/ESP (4) instead of one agnostic block-all; IPv6 adds the
    // V6 ALE block-all and ICMPv6/GRE/ESP at the V6 transport layer → 1 + 4 +
    // 1 + 3 = 9 block filters.
    assert_eq!(
        filters
            .iter()
            .filter(|f| f.action == WfpAction::Block)
            .count(),
        9,
        "mode B: V4 ALE block + 4 named V4 packet blocks + V6 ALE + 3 V6 transport"
    );
    assert_eq!(
        filters
            .iter()
            .filter(|f| f.local_interface_luid == Some(KS_LUID))
            .count(),
        4,
        "egress-via-secondary exemption at both layers, IPv4 and IPv6"
    );
    assert!(
        filters.iter().filter(|f| f.remote_subnet.is_some()).count() >= 3,
        "loopback + link-local + LAN subnet exemptions present"
    );
}

/// The "internet waits for the additional connection" banner stands only while
/// that connection is gone: the catch-all over a live tunnel is armed but holds
/// nothing back, and the banner there said the VPN was down while it worked.
#[test]
fn only_a_lost_tunnel_reads_as_holding_everything() {
    let posture = crate::app_enforcement_status::BlockAllPostureStatus::new();
    let run = |resolution: Option<KillSwitchResolution>| {
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(198, 51, 100, 8)));
        source.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));
        let orch = PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
            Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(move |_, _| resolution.clone()))
        .with_block_all_posture_status(posture.clone());
        orch.install_for_sid("S-1-5-21-A").unwrap();
        (posture.armed(), posture.holding_for_outage())
    };
    assert_eq!(
        run(Some(full_ks_resolution())),
        (true, false),
        "a live tunnel"
    );
    assert_eq!(run(None), (true, true), "the tunnel is gone");
}

#[test]
fn killswitch_registry_publishes_exactly_the_armed_block_ids() {
    let (api, orch, src, rules, registry) =
        fixture_with_resolution_and_registry(Some(full_ks_resolution()));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(198, 51, 100, 8)));
    src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    // The family cut is a v6 block that names NO destination. A v6 block that
    // DOES name one is an ordinary pin and belongs in the role-verifying set.
    let is_family_cut = |f: &&nrr_platform_api::types::WfpFilterRecord| {
        f.layer.is_v6()
            && f.remote_ip.is_none()
            && f.remote_ip_set.is_empty()
            && f.remote_ip_set_v6.is_empty()
            && f.remote_subnet.is_none()
            && f.remote_subnet_v6.is_none()
    };
    let block_ids: Vec<u64> = filters
        .iter()
        .filter(|f| f.action == WfpAction::Block && !is_family_cut(f))
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
        .filter(|f| f.action == WfpAction::Block && is_family_cut(f))
        .map(|f| f.id.raw)
        .collect();
    assert_eq!(
        v6_block_ids.len(),
        4,
        "the v6 ALE block-all and three v6 protocol blocks"
    );
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
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(198, 51, 100, 8)));
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

    // A cleared revision is an empty book: "Everything" still waits for the
    // tunnel, so its guard stays armed and registered.
    rules.clear();
    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert!(orch.any_block_all_armed(), "no revision dropped the guard");

    // The guard itself switched off → its Block ids must leave the registry.
    src.set(
        "S-1-5-21-A",
        snap_with(
            "Wi-Fi",
            "TAP",
            PerSidBehaviorMode::PreferSecondaryWhenAvailable,
            nrr_domain::LeakProtection::Off,
        ),
    );
    orch.install_for_sid("S-1-5-21-A").unwrap();
    for id in &armed_ids {
        assert!(
            !registry.contains(*id),
            "a disarmed SID's stale Block ids must not linger in the registry",
        );
    }
}

/// The catch-all cannot arm without a server address or a trusted client: it
/// would seal the tunnel's own reconnect. With the tunnel UP, what it falls
/// back to is the pins of "routed sites" — the rule destination may still
/// leave through the tunnel — never an unconditional block of the rule hosts,
/// and the user is told the rest is not covered.
#[test]
fn a_catch_all_that_cannot_arm_falls_back_to_pins_on_a_live_tunnel() {
    use nrr_shared::ipc_payloads::StatusUpdateEvent;
    let ip = Ipv4Addr::new(198, 51, 100, 8);
    let bus = Arc::new(crate::ipc_handlers::event_bus::EventBus::new());
    let gui = bus.subscribe_as("gui-a".into(), Some("S-1-5-21-A".into()), Some(0));
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let src = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let no_server = KillSwitchResolution {
        bootstrap_server_ips: Vec::new(),
        ..full_ks_resolution()
    };
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&src) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
        Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
    )
    .with_kill_switch_resolver(Arc::new(move |_, _| Some(no_server.clone())))
    .with_events(Arc::clone(&bus));
    rules.set(rules_with_secondary_ip(ip));
    src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

    let filters = match orch
        .compute_filters_for_sid("S-1-5-21-A", false, None, ComputeIntent::Apply)
        .unwrap()
    {
        ComputedFilterSet::Install(plan) => plan.filters,
        _ => panic!("expected an installable filter set"),
    };
    assert!(
        connect_allowed(&filters, ip, KS_LUID),
        "the rule destination still leaves through the live tunnel"
    );
    assert!(
        !connect_allowed(&filters, ip, PRIMARY_LUID),
        "and never over the main link"
    );
    assert!(
        connect_allowed(&filters, Ipv4Addr::new(203, 0, 113, 50), PRIMARY_LUID),
        "nothing pretends to be a blanket"
    );
    assert!(!orch.any_block_all_armed());
    assert!(
        bus.peek_pending_for(&gui.subscription_id, 8)
            .iter()
            .any(|e| matches!(
                &e.event,
                StatusUpdateEvent::ProtectionCoverageChanged { reason }
                    if reason == "blanket-block-not-armed"
            )),
        "the user hears that everything else is not covered"
    );
}

#[test]
fn kill_switch_appends_egress_pair_over_secondary_destination() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, src, rules) = fixture_with_luid(Some(KS_LUID));
    rules.set(rules_with_secondary_ip(ip));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    let count = orch.install_for_sid("S-1-5-21-A").unwrap();
    // 1 rule permit + ALE pair (permit+block) + packet pair (egress permit +
    // block per named packet protocol) = 1 + 2 + 4×2 = 11. Nothing else: this
    // rule names an IPv4 address, and the family is no longer cut wholesale
    // just because SOME rule points at the tunnel.
    assert_eq!(count, 11);

    let filters = api.wfp_filters.lock().unwrap();
    assert_eq!(filters.len(), 11);
    assert!(
        filters.iter().all(|f| !f.layer.is_v6()),
        "an IPv4-only rule set must not install a single v6 filter",
    );
    // Egress-conditional permits carry the LUID: the v4 ones (ALE plus one
    // per named packet protocol) are scoped to the protected destination;
    // the two v6 ones are not - the v6 cut is family-wide, so what it
    // permits through the tunnel is family-wide too.
    let egress_permits: Vec<_> = filters
        .iter()
        .filter(|f| f.local_interface_luid == Some(KS_LUID))
        .collect();
    assert_eq!(egress_permits.len(), 5);
    assert!(egress_permits.iter().all(|f| f.action == WfpAction::Permit));
    assert_eq!(
        egress_permits.iter().filter(|f| f.covers_v4(ip)).count(),
        5,
        "every egress permit is destination-scoped",
    );
    // Blocks over the pinned address: 1 ALE + 4 named packet, unconditional
    // on the egress interface.
    let blocks: Vec<_> = filters
        .iter()
        .filter(|f| f.action == WfpAction::Block)
        .collect();
    assert_eq!(blocks.iter().filter(|f| f.covers_v4(ip)).count(), 5);
    assert_eq!(blocks.len(), 5, "no block that names no destination");
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
        .with_kill_switch_resolver(Arc::new(move |_, _| {
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
        5,
        "blocks armed: 1 ALE + 4 named packet over the pinned address"
    );
    assert_eq!(
        api.wfp_filters
            .lock()
            .unwrap()
            .iter()
            .filter(|f| f.local_interface_luid == Some(LUID_A))
            .count(),
        5,
        "egress permits pinned to LUID_A: 1 ALE + 4 named packet"
    );

    // Secondary adapter reconnect: the resolver now yields a new LUID.
    luid_cell.store(LUID_B, Ordering::SeqCst);
    let added = orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();
    assert_eq!(added, 5, "reconcile installs the new-LUID egress permits");

    let after = api.wfp_filters.lock().unwrap();
    assert_eq!(
        after
            .iter()
            .filter(|f| f.local_interface_luid == Some(LUID_B))
            .count(),
        5,
        "new-LUID egress permits installed"
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
    // request to protect its traffic, so the leak-guard arms on the bound
    // secondary alone; without it this SID leaked to the primary the instant
    // the secondary adapter dropped.
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, src, rules) = fixture_with_luid(Some(KS_LUID));
    rules.set(rules_with_secondary_ip(ip));
    let s = snap_full("Wi-Fi", "TAP");
    src.set("S-1-5-21-A", s);

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    // The LUID-conditional egress pair (permit-via-secondary + block-off-secondary) is
    // the kill-switch's signature — its presence proves the guard armed off
    // the bound secondary alone.
    assert!(
        filters
            .iter()
            .any(|f| f.local_interface_luid == Some(KS_LUID)),
        "a bound secondary must arm the LUID-pinned kill-switch alone",
    );
    assert!(
        filters.iter().any(|f| f.action == WfpAction::Block),
        "the kill-switch must install the off-secondary block half",
    );
}

/// "Routed sites" is not offered under the additional default route, and a
/// stored one means "everything" there: the catch-all arms.
#[test]
fn routed_sites_under_the_additional_default_route_protects_everything() {
    let (api, orch, src, rules) = fixture_with_resolution(Some(full_ks_resolution()));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(198, 51, 100, 8)));
    src.set(
        "S-1-5-21-A",
        snap_with(
            "Wi-Fi",
            "TAP",
            PerSidBehaviorMode::PreferSecondaryWhenAvailable,
            nrr_domain::LeakProtection::Sites,
        ),
    );

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    assert_eq!(
        filters
            .iter()
            .filter(|f| f.local_interface_luid == Some(KS_LUID))
            .count(),
        4,
        "the catch-all's egress-via-secondary exemption at both layers, both families",
    );
    assert!(orch.any_block_all_armed());
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
        .with_kill_switch_resolver(Arc::new(move |_, _| {
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
    source.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

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
    let resolver = nrr_platform_api::MockAppPathResolver::new()
        .with(
            "openvpn.exe",
            vec![std::path::PathBuf::from(r"C:\Tools\openvpn.exe")],
        )
        .with_protected_root(r"C:\Tools");
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
        .with_kill_switch_resolver(Arc::new(|_, _| None)),
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
    // The core assertion: NO installed filter carries a glob in
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

/// The exemption keys on a file name, and a name is something anyone can give
/// a file: `x-vpn.exe` in a download folder matched `*vpn*` and walked around
/// the leak guard with no rule and no confirmation. Only a client from a place
/// the user could not have written to is exempt by name; the rest is listed
/// for the user to confirm, and exempted from nothing until they do.
#[test]
fn a_vpn_named_binary_outside_the_program_folders_waits_for_confirmation() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    const INSTALLED: &str = r"C:\Program Files\vendor vpn\vendor vpn.exe";
    const PLANTED: &str = r"C:\Users\someone\Downloads\x-vpn.exe";
    // Both match the built-in `*vpn*` glob by file name; only one sits where
    // an administrator put it.
    let resolver = nrr_platform_api::MockAppPathResolver::new()
        .with("vendor vpn.exe", vec![std::path::PathBuf::from(INSTALLED)])
        .with("x-vpn.exe", vec![std::path::PathBuf::from(PLANTED)])
        .with_protected_root(r"C:\Program Files");
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_app_resolver(Arc::new(resolver))
        // Secondary unresolved → the fail-closed branch that emits exemptions.
        .with_kill_switch_resolver(Arc::new(|_, _| None)),
    );
    rules.set(rules_with_n_primary_ips(1));
    source.set("S-1-5-21-K5A", snap_full("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-K5A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    let exempt_paths: Vec<String> = filters
        .iter()
        .filter(|f| f.action == WfpAction::Permit && f.weight >= 0x0060_0000)
        .filter_map(|f| f.app_pattern.clone())
        .collect();

    assert!(
        exempt_paths.iter().any(|p| p == INSTALLED),
        "positive control: the installed client is exempt: {exempt_paths:?}",
    );
    assert!(
        !exempt_paths.iter().any(|p| p == PLANTED),
        "a VPN-named file in a user folder must not be exempt by name: {exempt_paths:?}",
    );
    assert_eq!(
        crate::vpn_client_trust::global_pending_vpn_clients().for_sid("S-1-5-21-K5A"),
        vec![PLANTED.to_string()],
        "the planted one is listed for the user to confirm",
    );

    // The user's word is the way in: confirmed as the link provider, the
    // same file is exempt wherever it sits, and leaves the pending list.
    let mut confirmed = snap_full("Wi-Fi", "TAP");
    confirmed.link_provider_exe_paths = vec![PLANTED.to_string()];
    source.set("S-1-5-21-K5A", confirmed);
    drop(filters);
    orch.install_for_sid("S-1-5-21-K5A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    assert!(
        filters.iter().any(|f| f.action == WfpAction::Permit
            && f.weight >= 0x0060_0000
            && f.app_pattern.as_deref() == Some(PLANTED)),
        "a confirmed client is exempt whatever its folder",
    );
    assert!(crate::vpn_client_trust::global_pending_vpn_clients()
        .for_sid("S-1-5-21-K5A")
        .is_empty());
}

/// An address a rule names belongs to that rule, whatever program dials it. A
/// program routed to the MAIN link used to sit in the exemption band above
/// every block, so while the tunnel was down it reached the tunnel's own
/// rule hosts over the main link. Now its pass-through is its rule permit,
/// below the block lane: the catch-all lets it out, the pins do not.
#[test]
fn a_main_link_app_cannot_reach_a_tunnel_host_while_the_tunnel_is_down() {
    const MAIL: &str = r"C:\Program Files\mail\mail.exe";
    let tunnel_host = Ipv4Addr::new(203, 0, 113, 9);
    for mode_b in [false, true] {
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        // In a protected folder on purpose: place is not what decides here,
        // the name matches no VPN pattern and the user confirmed nothing.
        let resolver = nrr_platform_api::MockAppPathResolver::new()
            .with("mail.exe", vec![std::path::PathBuf::from(MAIL)])
            .with_protected_root(r"C:\Program Files");
        let orch = Arc::new(
            PerSidApplyOrchestrator::new(
                session,
                Arc::clone(&source) as Arc<dyn RoutePolicySource>,
                Arc::clone(&rules) as Arc<dyn RulesProvider>,
                cache,
                Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
            )
            .with_app_resolver(Arc::new(resolver))
            .with_kill_switch_resolver(Arc::new(|_, _| None)), // tunnel down
        );
        let mut book = rules_with_one_app("mail.exe").rule_book;
        book.secondary = CanonicalRuleSet::from_rules(vec![primary_ip_rule("r-sec", tunnel_host)]);
        rules.set(ActiveRulesSnapshot { rule_book: book });
        let snap = if mode_b {
            snap_block_mode_b("Wi-Fi", "TAP")
        } else {
            snap_with(
                "Wi-Fi",
                "TAP",
                PerSidBehaviorMode::PreferPrimary,
                nrr_domain::LeakProtection::Everything,
            )
        };
        source.set("S-1-5-21-A", snap);

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        let app_permit = filters
            .iter()
            .filter(|f| f.action == WfpAction::Permit && f.app_pattern.as_deref() == Some(MAIL))
            .max_by_key(|f| f.weight)
            .unwrap_or_else(|| panic!("mode_b={mode_b}: the app's own rule permit exists"));
        assert!(
            app_permit.weight < 0x0030_0000,
            "mode_b={mode_b}: a main-link app is not a tunnel client and gets no exemption ({:#x})",
            app_permit.weight
        );
        let host_block = filters
            .iter()
            .filter(|f| {
                f.layer == WfpLayerKey::AleAuthConnectV4
                    && f.action == WfpAction::Block
                    && f.covers_v4(tunnel_host)
            })
            .max_by_key(|f| f.weight)
            .unwrap_or_else(|| {
                panic!("mode_b={mode_b}: the tunnel's host is pinned by name under the block-all")
            });
        assert!(
            host_block.weight > app_permit.weight,
            "mode_b={mode_b}: the pin must outrank the app's permit, or the app reaches the host over the main link",
        );
    }
}

/// The same for a NETWORK the tunnel's rules name: the blanket block sits
/// below the main-link rule band, so only a hold above it keeps a main-link
/// program off the tunnel's subnet while the tunnel is down.
#[test]
fn a_main_link_app_cannot_reach_a_tunnel_subnet_while_the_tunnel_is_down() {
    use nrr_shared::ip_block::IpBlock;
    const MAIL: &str = r"C:\Program Files\mail\mail.exe";
    let subnet = (Ipv4Addr::new(198, 51, 100, 0), 24u8);
    for mode_b in [false, true] {
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let rules = Arc::new(ScriptedRules::default());
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        let resolver = nrr_platform_api::MockAppPathResolver::new()
            .with("mail.exe", vec![std::path::PathBuf::from(MAIL)])
            .with_protected_root(r"C:\Program Files");
        let orch = Arc::new(
            PerSidApplyOrchestrator::new(
                session,
                Arc::clone(&source) as Arc<dyn RoutePolicySource>,
                Arc::clone(&rules) as Arc<dyn RulesProvider>,
                cache,
                Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
            )
            .with_app_resolver(Arc::new(resolver))
            .with_kill_switch_resolver(Arc::new(|_, _| None)), // tunnel down
        );
        let mut book = rules_with_one_app("mail.exe").rule_book;
        book.secondary = CanonicalRuleSet::from_rules(vec![CanonicalRule {
            id: RuleId("r-net".into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::Subnet(
                IpBlock::parse("198.51.100.0/24").expect("subnet"),
            )),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }]);
        rules.set(ActiveRulesSnapshot { rule_book: book });
        let snap = if mode_b {
            snap_block_mode_b("Wi-Fi", "TAP")
        } else {
            snap_with(
                "Wi-Fi",
                "TAP",
                PerSidBehaviorMode::PreferPrimary,
                nrr_domain::LeakProtection::Everything,
            )
        };
        source.set("S-1-5-21-A", snap);

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let filters = api.wfp_filters.lock().unwrap();
        let app_permit = filters
            .iter()
            .filter(|f| f.action == WfpAction::Permit && f.app_pattern.as_deref() == Some(MAIL))
            .max_by_key(|f| f.weight)
            .unwrap_or_else(|| panic!("mode_b={mode_b}: the app's own rule permit exists"));
        let hold = filters
            .iter()
            .filter(|f| {
                f.layer == WfpLayerKey::AleAuthConnectV4
                    && f.action == WfpAction::Block
                    && f.remote_subnet == Some(subnet)
            })
            .max_by_key(|f| f.weight)
            .unwrap_or_else(|| {
                panic!("mode_b={mode_b}: the tunnel's subnet is held under the block-all")
            });
        assert!(
            hold.weight > app_permit.weight,
            "mode_b={mode_b}: the hold must outrank the app's permit, or the app reaches the subnet over the main link",
        );
    }
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
        .with_kill_switch_resolver(Arc::new(move |_, _| {
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
        &[std::net::IpAddr::V4(ip)],
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
        .with_kill_switch_resolver(Arc::new(move |_, _| {
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
        &[std::net::IpAddr::V4(ip2)],
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
            remote_ip_set_v6: Vec::new(),
            remote_port: None,
            weight: 0,
            id: WfpFilterId::from_raw(1),
            user_sid: None,
            app_pattern: app.map(str::to_string),
            local_interface_luid: None,
            remote_subnet: subnet,
            remote_subnet_v6: None,
            ip_protocol: None,
            remote_subnet_set: Vec::new(),
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

/// With leak protection off, a tunnel that is gone leaves the rule permit
/// alone: no block, no egress condition. The ordinary "additional connection
/// is down" notice is the warning.
#[test]
fn protection_off_installs_no_guard_when_the_tunnel_is_unresolved() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, src, rules) = fixture_with_luid(None);
    rules.set(rules_with_secondary_ip(ip));
    src.set(
        "S-1-5-21-A",
        snap_with(
            "Wi-Fi",
            "TAP",
            PerSidBehaviorMode::PreferPrimary,
            nrr_domain::LeakProtection::Off,
        ),
    );

    let count = orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(count, 1, "only the rule permit");
    let filters = api.wfp_filters.lock().unwrap();
    assert!(filters
        .iter()
        .all(|f| f.action == WfpAction::Permit && f.local_interface_luid.is_none()));
    assert!(!orch.any_fail_closed_armed());
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
    // + 4 named packet blocks (ICMP/IGMP/GRE/ESP) = 5 blocks. The rule
    // names IPv4, so nothing else is installed.
    assert_eq!(count, 6 + EXEMPT);
    let filters = api.wfp_filters.lock().unwrap();
    let blocks: Vec<_> = filters
        .iter()
        .filter(|f| f.action == WfpAction::Block)
        .filter(|f| {
            !matches!(
                f.layer,
                nrr_platform_api::types::WfpLayerKey::AleAuthConnectV6
                    | nrr_platform_api::types::WfpLayerKey::OutboundTransportV6
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
    // (the C4 self-blocking class: the client could not
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

// ── The floor under a destination-less block ─────────────────────────────

const PINNED_APP: &str = r"C:\Apps\tg.exe";
const PRIMARY_LUID: u64 = 0x0006_0000_0000_0002;

/// A secondary-routed app, with `snap` as the policy and `resolution` as the
/// kill-switch's view of the links.
fn pinned_app_filters(
    snap: PerSidPolicySnapshot,
    resolution: KillSwitchResolution,
) -> Vec<WfpFilterSpec> {
    let mut book = rules_with_one_app("tg.exe").rule_book;
    std::mem::swap(&mut book.primary, &mut book.secondary);
    filters_for(snap, resolution, book)
}

fn filters_for(
    snap: PerSidPolicySnapshot,
    resolution: KillSwitchResolution,
    book: CanonicalRuleBook,
) -> Vec<WfpFilterSpec> {
    filters_observing(
        snap,
        resolution,
        book,
        Arc::new(crate::app_observation_lookup::AppObservationStore::new()),
    )
}

fn filters_observing(
    snap: PerSidPolicySnapshot,
    resolution: KillSwitchResolution,
    book: CanonicalRuleBook,
    observations: Arc<crate::app_observation_lookup::AppObservationStore>,
) -> Vec<WfpFilterSpec> {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let resolver = nrr_platform_api::MockAppPathResolver::new()
        .with("tg.exe", vec![std::path::PathBuf::from(PINNED_APP)])
        .with("mail.exe", vec![std::path::PathBuf::from(OTHER_PINNED_APP)]);
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    )
    .with_app_resolver(Arc::new(resolver))
    .with_app_observations(observations)
    .with_kill_switch_resolver(Arc::new(move |_, _| Some(resolution.clone())));
    rules.set(ActiveRulesSnapshot { rule_book: book });
    source.set("S-1-5-21-A", snap);
    match orch
        .compute_filters_for_sid("S-1-5-21-A", false, None, ComputeIntent::Apply)
        .unwrap()
    {
        ComputedFilterSet::Install(plan) => plan.filters,
        _ => panic!("expected an installable filter set"),
    }
}

fn in_subnet(ip: Ipv4Addr, (net, prefix): (Ipv4Addr, u8)) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    u32::from(ip) & mask == u32::from(net) & mask
}

/// The ALE connect verdict for a TCP connect by the pinned app to `ip` leaving
/// through `egress`: the highest-weight matching filter wins, none means allow.
fn app_may_connect(filters: &[WfpFilterSpec], ip: Ipv4Addr, egress: u64) -> bool {
    program_may_connect(filters, PINNED_APP, ip, egress)
}

/// [`app_may_connect`] for any program; a tie in weight goes to the block.
fn program_may_connect(
    filters: &[WfpFilterSpec],
    program: &str,
    ip: Ipv4Addr,
    egress: u64,
) -> bool {
    filters
        .iter()
        .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
        .filter(|f| f.app_pattern.as_deref().is_none_or(|a| a == program))
        .filter(|f| f.local_interface_luid.is_none_or(|l| l == egress))
        .filter(|f| f.remote_port.is_none() && f.ip_protocol.is_none_or(|p| p == 6))
        .filter(|f| {
            let names_one = f.remote_ip.is_some() || !f.remote_ip_set.is_empty();
            let in_set = f.remote_subnet_set.is_empty()
                || f.remote_subnet_set.iter().any(|(net, prefix)| match net {
                    IpAddr::V4(v4) => in_subnet(ip, (*v4, *prefix)),
                    IpAddr::V6(_) => false,
                });
            in_set
                && match f.remote_subnet {
                    Some(subnet) => in_subnet(ip, subnet),
                    None if names_one => f.covers_v4(ip),
                    None => true,
                }
        })
        .max_by_key(|f| (f.weight, f.action == WfpAction::Block))
        .is_none_or(|f| f.action == WfpAction::Permit)
}

const OTHER_PINNED_APP: &str = r"C:\Apps\mail.exe";

/// Telegram on the owner's PC: another program rode the tunnel to an address
/// the app rule had pinned, so the pin was withdrawn and may not be relearnt
/// this session. The app's own traffic there must take the main link, as the
/// withdrawal promises; the per-app block dropped it for good instead.
#[test]
fn a_withdrawn_app_destination_reaches_the_main_link_under_leak_protection() {
    const WITHDRAWN: Ipv4Addr = Ipv4Addr::new(149, 154, 167, 51);
    const STILL_PINNED: Ipv4Addr = Ipv4Addr::new(149, 154, 175, 50);
    let mut rules = rules_with_one_app("tg.exe")
        .rule_book
        .primary
        .rules()
        .to_vec();
    let mut mail = rules_with_one_app("mail.exe")
        .rule_book
        .primary
        .rules()
        .to_vec();
    mail[0].id = RuleId("app-2".into());
    rules.extend(mail);
    let book = CanonicalRuleBook {
        primary: CanonicalRuleSet::default(),
        secondary: CanonicalRuleSet::from_rules(rules),
    };
    for takeover in [false, true] {
        let observations = Arc::new(crate::app_observation_lookup::AppObservationStore::new());
        for program in [PINNED_APP, OTHER_PINNED_APP] {
            observations.record(program, WITHDRAWN);
            observations.record(program, STILL_PINNED);
        }
        assert!(observations.retract("tg.exe", WITHDRAWN));
        let snap = PerSidPolicySnapshot {
            app_rules_take_all_addresses: takeover,
            ..snap_block("Wi-Fi", "TAP")
        };
        let filters = filters_observing(snap, full_ks_resolution(), book.clone(), observations);

        assert!(
            program_may_connect(&filters, PINNED_APP, WITHDRAWN, PRIMARY_LUID),
            "takeover {takeover}: the withdrawn destination is black-holed for its app"
        );
        // Only that app, only that address: everything else it pinned, and the
        // other routed app on the same address, stay held to the tunnel.
        assert!(
            !program_may_connect(&filters, PINNED_APP, STILL_PINNED, PRIMARY_LUID),
            "takeover {takeover}: the app's other destinations leak off the tunnel"
        );
        assert!(
            !program_may_connect(&filters, OTHER_PINNED_APP, WITHDRAWN, PRIMARY_LUID),
            "takeover {takeover}: another routed app leaks through the withdrawal"
        );
        assert!(program_may_connect(
            &filters, PINNED_APP, WITHDRAWN, KS_LUID
        ));
    }
}

/// A withdrawn address the user's own additional-link rule names is the rule's
/// to hold: the fallback must not open it on the main link when the tunnel goes.
#[test]
fn a_withdrawn_destination_an_additional_rule_names_stays_held() {
    const NAMED: Ipv4Addr = Ipv4Addr::new(149, 154, 167, 99);
    let mut rules = rules_with_one_app("tg.exe")
        .rule_book
        .primary
        .rules()
        .to_vec();
    rules.push(CanonicalRule {
        id: RuleId("ip-1".into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(NAMED))),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    });
    let book = CanonicalRuleBook {
        primary: CanonicalRuleSet::default(),
        secondary: CanonicalRuleSet::from_rules(rules),
    };
    let observations = Arc::new(crate::app_observation_lookup::AppObservationStore::new());
    observations.record(PINNED_APP, NAMED);
    observations.retract("tg.exe", NAMED);
    let filters = filters_observing(
        snap_block("Wi-Fi", "TAP"),
        full_ks_resolution(),
        book,
        observations,
    );
    assert!(!program_may_connect(
        &filters,
        PINNED_APP,
        NAMED,
        PRIMARY_LUID
    ));
    assert!(program_may_connect(&filters, PINNED_APP, NAMED, KS_LUID));
}

#[test]
fn a_pinned_app_keeps_loopback_and_the_lan_while_the_tunnel_is_up() {
    let filters = pinned_app_filters(snap_block("Wi-Fi", "TAP"), full_ks_resolution());
    assert!(
        filters.iter().any(|f| f.action == WfpAction::Block
            && f.app_pattern.as_deref() == Some(PINNED_APP)
            && f.remote_ip.is_none()
            && f.remote_subnet.is_none()),
        "the app rule must arm its per-app block"
    );

    for local in [
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(169, 254, 10, 1),
        Ipv4Addr::new(192, 168, 1, 20),
        Ipv4Addr::new(203, 0, 113, 7),
    ] {
        assert!(
            app_may_connect(&filters, local, PRIMARY_LUID),
            "{local} is local or the tunnel's own server; the per-app block must not cut it"
        );
    }
    // Positive control: everything else off the tunnel is still cut, and the
    // tunnel itself still carries it.
    let remote = Ipv4Addr::new(203, 0, 113, 50);
    assert!(!app_may_connect(&filters, remote, PRIMARY_LUID));
    assert!(app_may_connect(&filters, remote, KS_LUID));
}

#[test]
fn a_pinned_app_keeps_loopback_and_the_lan_when_the_pair_cannot_arm() {
    // A zero LUID leaves the egress pair unarmable, and the fail-closed
    // branch cuts the app outright instead.
    let resolution = KillSwitchResolution {
        secondary_luid: 0,
        ..full_ks_resolution()
    };
    let filters = pinned_app_filters(snap_block("Wi-Fi", "TAP"), resolution);

    for local in [Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(192, 168, 1, 20)] {
        assert!(app_may_connect(&filters, local, PRIMARY_LUID), "{local}");
    }
    assert!(!app_may_connect(
        &filters,
        Ipv4Addr::new(203, 0, 113, 50),
        PRIMARY_LUID
    ));
}

/// Under the catch-all the pinned app needs no floor of its own (the blanket
/// carries it); when the catch-all cannot arm, the app pair falls back and
/// brings the floor. Either way loopback and the LAN stay open, nothing lands
/// twice, and the app reaches nothing else over the main link.
#[test]
fn a_pinned_app_keeps_its_floor_whether_or_not_the_catch_all_arms() {
    let everything = snap_block_mode_b("Wi-Fi", "TAP");
    let no_server = KillSwitchResolution {
        bootstrap_server_ips: Vec::new(),
        ..full_ks_resolution()
    };
    for resolution in [full_ks_resolution(), no_server] {
        let filters = pinned_app_filters(everything.clone(), resolution.clone());
        let mut ids = std::collections::HashSet::new();
        assert!(
            filters.iter().all(|f| ids.insert(f.id)),
            "a filter id appears twice (servers: {:?})",
            resolution.bootstrap_server_ips
        );
        for local in [Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(192, 168, 1, 20)] {
            assert!(
                app_may_connect(&filters, local, PRIMARY_LUID),
                "{local} cut (servers: {:?})",
                resolution.bootstrap_server_ips
            );
        }
        let remote = Ipv4Addr::new(203, 0, 113, 50);
        assert!(!app_may_connect(&filters, remote, PRIMARY_LUID));
        assert!(app_may_connect(&filters, remote, KS_LUID));
    }
}

/// The ALE connect verdict for a TCP connect by an ordinary program (no app
/// rule of its own) to `ip` leaving through `egress`.
fn connect_allowed(filters: &[WfpFilterSpec], ip: Ipv4Addr, egress: u64) -> bool {
    filters
        .iter()
        .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
        .filter(|f| f.app_pattern.is_none())
        .filter(|f| f.local_interface_luid.is_none_or(|l| l == egress))
        .filter(|f| f.remote_port.is_none() && f.ip_protocol.is_none_or(|p| p == 6))
        .filter(|f| {
            let names_one = f.remote_ip.is_some() || !f.remote_ip_set.is_empty();
            let in_set = f.remote_subnet_set.is_empty()
                || f.remote_subnet_set.iter().any(|(net, prefix)| match net {
                    IpAddr::V4(v4) => in_subnet(ip, (*v4, *prefix)),
                    IpAddr::V6(_) => false,
                });
            in_set
                && match f.remote_subnet {
                    Some(subnet) => in_subnet(ip, subnet),
                    None if names_one => f.covers_v4(ip),
                    None => f.remote_subnet_v6.is_none() && f.remote_ip_set_v6.is_empty(),
                }
        })
        .max_by_key(|f| (f.weight, f.action == WfpAction::Block))
        .is_none_or(|f| f.action == WfpAction::Permit)
}

// ── The table: default route × leak protection × tunnel up/down ──────────

/// What one cell of the table must do, asked as verdicts rather than filter
/// counts: a rule destination and an unrouted host, over the main link and
/// through the tunnel, plus the two latches the DNS gate and the banner read.
#[test]
fn every_cell_of_the_protection_table_behaves_as_promised() {
    use nrr_domain::LeakProtection::{Everything, Off, Sites};
    use PerSidBehaviorMode::{PreferPrimary as Main, PreferSecondaryWhenAvailable as Additional};
    const ROUTED: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 8);
    const UNROUTED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 50);

    // (mode, protection, tunnel up) → (routed host over main, unrouted over
    // main, unrouted through the tunnel, a blanket armed, blocking while down)
    #[allow(clippy::type_complexity)]
    let table: [(
        PerSidBehaviorMode,
        nrr_domain::LeakProtection,
        bool,
        (bool, bool, bool, bool, bool),
    ); 12] = [
        (Main, Off, true, (true, true, true, false, false)),
        (Main, Off, false, (true, true, true, false, false)),
        (Additional, Off, true, (true, true, true, false, false)),
        (Additional, Off, false, (true, true, true, false, false)),
        // Pins: the routed host only through the tunnel, the rest untouched.
        (Main, Sites, true, (false, true, true, false, false)),
        // Per-destination block: the routed host waits, the rest flows.
        (Main, Sites, false, (false, true, true, false, true)),
        // "Everything" under the main default route pins while the tunnel is
        // up: unmatched traffic belongs on the main link.
        (Main, Everything, true, (false, true, true, false, false)),
        (Main, Everything, false, (false, false, false, true, true)),
        // "Routed sites" means "everything" under the additional route.
        (Additional, Sites, true, (false, false, true, true, false)),
        (Additional, Sites, false, (false, false, false, true, true)),
        (
            Additional,
            Everything,
            true,
            (false, false, true, true, false),
        ),
        (
            Additional,
            Everything,
            false,
            (false, false, false, true, true),
        ),
    ];
    for (mode, protection, tunnel_up, expected) in table {
        let (routed_main, unrouted_main, unrouted_tunnel, blanket, waiting) = expected;
        let cell = format!("{mode:?}/{protection}/tunnel up = {tunnel_up}");
        let (_api, orch, src, rules) = fixture_with_resolution(tunnel_up.then(full_ks_resolution));
        rules.set(rules_with_secondary_ip(ROUTED));
        src.set("S-1-5-21-A", snap_with("Wi-Fi", "TAP", mode, protection));
        let filters = match orch
            .compute_filters_for_sid("S-1-5-21-A", false, None, ComputeIntent::Apply)
            .unwrap()
        {
            ComputedFilterSet::Install(plan) => plan.filters,
            _ => panic!("{cell}: expected an installable filter set"),
        };
        assert_eq!(
            connect_allowed(&filters, ROUTED, PRIMARY_LUID),
            routed_main,
            "{cell}: routed host over the main link"
        );
        assert_eq!(
            connect_allowed(&filters, UNROUTED, PRIMARY_LUID),
            unrouted_main,
            "{cell}: unrouted host over the main link"
        );
        if tunnel_up {
            assert!(
                connect_allowed(&filters, ROUTED, KS_LUID),
                "{cell}: the tunnel always carries the routed host"
            );
            assert_eq!(
                connect_allowed(&filters, UNROUTED, KS_LUID),
                unrouted_tunnel,
                "{cell}: unrouted host through the tunnel"
            );
        }
        assert!(
            connect_allowed(&filters, Ipv4Addr::new(127, 0, 0, 1), PRIMARY_LUID),
            "{cell}: loopback is never cut"
        );
        assert_eq!(orch.any_block_all_armed(), blanket, "{cell}: blanket latch");
        assert_eq!(
            orch.any_fail_closed_armed(),
            waiting,
            "{cell}: tunnel-down latch"
        );
        if !protection.is_on() {
            assert!(
                filters.iter().all(|f| f.action == WfpAction::Permit),
                "{cell}: protection off blocks nothing"
            );
        }
    }
}

/// "Start empty" or a reset with no baseline leaves a user with settings but
/// no rule revision at all. "Everything" asks nothing of the rules, so it
/// must hold exactly as over an emptied book: the internet waits for the
/// tunnel, and the whole guard does not come off.
#[test]
fn everything_with_no_rule_revision_still_waits_for_the_tunnel() {
    use nrr_domain::LeakProtection::Everything;
    use PerSidBehaviorMode::{PreferPrimary as Main, PreferSecondaryWhenAvailable as Additional};
    const ANY_HOST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 50);
    for mode in [Main, Additional] {
        let (api, orch, src, rules) = fixture_with_resolution(None);
        rules.clear();
        src.set("S-1-5-21-A", snap_with("Wi-Fi", "TAP", mode, Everything));

        let filters = match orch
            .compute_filters_for_sid("S-1-5-21-A", false, None, ComputeIntent::Apply)
            .unwrap()
        {
            ComputedFilterSet::Install(plan) => plan.filters,
            _ => panic!("{mode:?}: no rule revision dropped the whole guard"),
        };
        assert!(
            !connect_allowed(&filters, ANY_HOST, PRIMARY_LUID),
            "{mode:?}: the main link carries traffic while the tunnel is down"
        );

        orch.install_for_sid("S-1-5-21-A").unwrap();
        assert!(orch.any_block_all_armed(), "{mode:?}: blanket latch");
        assert!(orch.any_fail_closed_armed(), "{mode:?}: tunnel-down latch");
        assert!(
            api.wfp_filters
                .lock()
                .unwrap()
                .iter()
                .any(|f| f.action == WfpAction::Block),
            "{mode:?}: nothing blocks in the engine"
        );
    }
}

/// A rule address on the main link's own segment keeps its direct route, so
/// with the tunnel unresolved it is not blocked: the floor's LAN is read even
/// though no tunnel resolution names it. A host elsewhere is still blocked.
#[test]
fn a_rule_address_on_the_home_network_is_not_blocked_while_the_tunnel_is_unresolved() {
    let nas = Ipv4Addr::new(192, 168, 1, 5);
    let far = Ipv4Addr::new(198, 51, 100, 8);
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let src = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&src) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        Arc::new(MockFqdnCacheLookup::new()),
        Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
    )
    .with_kill_switch_resolver(Arc::new(|_, _| None))
    .with_fail_closed_exemptions_resolver(Arc::new(|_, _| {
        crate::killswitch_codegen::FailClosedExemptions {
            bootstrap_server_ips: vec![Ipv4Addr::new(203, 0, 113, 7)],
            local_subnets: vec![(Ipv4Addr::new(192, 168, 1, 0), 24)],
            ..Default::default()
        }
    }));
    rules.set(rules_with_secondary_ips(&[nas, far]));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    let blocked = |ip: Ipv4Addr| {
        filters
            .iter()
            .any(|f| record_is_destination_block(f) && f.covers_v4(ip))
    };
    assert!(blocked(far), "fixture guard: the far host is held");
    assert!(
        !blocked(nas),
        "the home device is cut while the tunnel is down"
    );
}

/// Narrow beats wide in protection too: a tunnel host inside a main-link
/// network is held while the tunnel is unresolved, and the network's other
/// addresses are not.
#[test]
fn a_tunnel_host_inside_a_main_link_network_is_held_while_the_tunnel_is_unresolved() {
    let host = Ipv4Addr::new(203, 0, 113, 5);
    let neighbour = Ipv4Addr::new(203, 0, 113, 9);
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let src = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache = Arc::new(MockFqdnCacheLookup::new());
    cache.set_ips("secret.example", vec![host]);
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&src) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
    )
    .with_kill_switch_resolver(Arc::new(|_, _| None));
    let network = nrr_shared::ip_block::IpBlock::parse("203.0.113.0/24").unwrap();
    let mut main_network = primary_ip_rule("p-net", host);
    main_network.address_match = Some(CanonicalAddressMatch::Subnet(network));
    let mut tunnel_host = primary_ip_rule("s-host", host);
    tunnel_host.address_match = Some(CanonicalAddressMatch::ExactFqdn("secret.example".into()));
    rules.set(ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![main_network]),
            secondary: CanonicalRuleSet::from_rules(vec![tunnel_host]),
        },
    });
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    let blocked = |ip: Ipv4Addr| {
        filters
            .iter()
            .any(|f| record_is_destination_block(f) && f.covers_v4(ip))
    };
    assert!(blocked(host), "the tunnel host leaks over the main link");
    assert!(!blocked(neighbour), "the main link's network is cut");
}

fn deny_ids(api: &MockWindowsApi, denied: Ipv4Addr) -> Vec<u64> {
    api.wfp_filters
        .lock()
        .unwrap()
        .iter()
        .filter(|f| {
            f.action == WfpAction::Block
                && (f.remote_ip == Some(denied) || f.remote_ip_set.contains(&denied))
        })
        .map(|f| f.id.raw)
        .collect()
}

fn deny_rule(id: &str, ip: Ipv4Addr) -> CanonicalRule {
    CanonicalRule {
        action: nrr_domain::RuleAction::Block,
        ..primary_ip_rule(id, ip)
    }
}

/// A deny's filters are published as the user's own, so its drops are never
/// reverse-named, and they never pass for the leak guard's.
#[test]
fn a_deny_rules_filters_are_published_as_rule_blocks_beside_the_guard() {
    let denied = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, src, rules, registry) =
        fixture_with_resolution_and_registry(Some(full_ks_resolution()));
    let mut book = rules_with_secondary_ip(Ipv4Addr::new(198, 51, 100, 8));
    book.rule_book.primary = CanonicalRuleSet::from_rules(vec![deny_rule("deny-1", denied)]);
    rules.set(book);
    src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();

    let denies = deny_ids(&api, denied);
    assert!(!denies.is_empty());
    for id in &denies {
        assert!(registry.is_rule_block(*id));
        assert!(!registry.contains(*id), "a deny never role-verifies");
    }
    let guard: Vec<u64> = api
        .wfp_filters
        .lock()
        .unwrap()
        .iter()
        .filter(|f| f.action == WfpAction::Block && registry.contains(f.id.raw))
        .map(|f| f.id.raw)
        .collect();
    assert!(!guard.is_empty());
    assert!(guard.iter().all(|id| !registry.is_rule_block(*id)));
}

#[test]
fn a_deny_without_connections_is_published_and_withdrawn_with_its_rule() {
    let denied = Ipv4Addr::new(203, 0, 113, 9);
    let (api, orch, _src, rules, registry) = fixture_with_resolution_and_registry(None);
    rules.set(ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![deny_rule("deny-1", denied)]),
            secondary: CanonicalRuleSet::default(),
        },
    });
    orch.install_for_sid("S-1-5-21-A").unwrap();
    let denies = deny_ids(&api, denied);
    assert!(!denies.is_empty());
    assert!(denies.iter().all(|id| registry.is_rule_block(*id)));

    rules.set(rules_with_n_primary_ips(1));
    orch.recompile_for_sid("S-1-5-21-A").unwrap();
    assert!(denies.iter().all(|id| !registry.is_rule_block(*id)));
}
