use super::*;

// ── Kill-switch (block 16.18.vpn slice D) ───────────────────────────────

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

/// Kill-switch on, but posture set to fail-OPEN (legacy behaviour:
/// allow + warn when the secondary can't be resolved).
fn snap_block_fail_open(primary: &str, secondary: &str) -> PerSidPolicySnapshot {
    let mut s = snap_block(primary, secondary);
    s.kill_switch_fail_closed = false;
    s
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
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(8, 8, 8, 8)));
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
        bootstrap_server_ips_v6: Vec::new(),
        secondary_luid: KS_LUID,
        bootstrap_server_ips: vec![], // unknown server → must not arm
        local_subnets: vec![],
        local_subnets_v6: Vec::new(),
        foreign_tunnel_luids: Vec::new(),
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

/// A client's TRANSPORT is a different process from the binary we resolved, and
/// it is the transport that talks to the server. Exempting only the resolved
/// one is why an observed outage held for 88 minutes: every protocol the
/// user tried ran from a nested executable no permit named.
#[test]
fn a_clients_nested_transport_is_exempt_while_an_unrelated_app_is_not() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    const CLIENT: &str = r"C:\Program Files\vendor vpn\vendor vpn.exe";
    // The nested directory is a placeholder; the file name is the functional
    // subject — it must NOT match the built-in `*vpn*` glob.
    const TRANSPORT: &str = r"C:\Program Files\vendor vpn\dir-c\xray.exe";
    const UNRELATED: &str = r"C:\Program Files\mail\mail.exe";
    let resolver = nrr_platform_api::MockAppPathResolver::new()
        // The built-in `*vpn*` glob recognises the client by its file name.
        .with("vendor vpn.exe", vec![std::path::PathBuf::from(CLIENT)])
        // …and this is what actually ships beside it.
        .with_siblings(CLIENT, vec![std::path::PathBuf::from(TRANSPORT)])
        // An ordinary application's tree must stay out of the exemption, so
        // seed one and assert its sibling never appears.
        .with_siblings(
            UNRELATED,
            vec![std::path::PathBuf::from(
                r"C:\Program Files\mail\updater.exe",
            )],
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
        // Secondary unresolved → the fail-closed branch that emits exemptions.
        .with_kill_switch_resolver(Arc::new(|_| None)),
    );
    rules.set(rules_with_n_primary_ips(1));
    source.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    let exempt_paths: Vec<String> = filters
        .iter()
        .filter(|f| {
            f.action == WfpAction::Permit && f.remote_ip.is_none() && f.remote_ip_set.is_empty()
        })
        .filter_map(|f| f.app_pattern.clone())
        .collect();

    assert!(
        exempt_paths.iter().any(|p| p == CLIENT),
        "positive control: the confirmed client itself is exempt: {exempt_paths:?}",
    );
    assert!(
        exempt_paths.iter().any(|p| p == TRANSPORT),
        "the process that performs the handshake must be exempt too: {exempt_paths:?}",
    );
    assert!(
        !exempt_paths.iter().any(|p| p.contains("updater.exe")),
        "an ordinary app's install tree is not a tunnel client's: {exempt_paths:?}",
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
