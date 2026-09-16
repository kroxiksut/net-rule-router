use super::*;

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

const VPN_CLIENT_PATH: &str = r"C:\Apps\swiftvpn 3.0.exe";

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
        bootstrap_server_ips_v6: Vec::new(),
        local_subnets: Vec::new(),
        local_subnets_v6: Vec::new(),
        foreign_tunnel_luids: Vec::new(),
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
    fn ips_for_hostname(&self, hostname: &str) -> Vec<IpAddr> {
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
    let shared = Ipv4Addr::new(23, 10, 20, 163);
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
                    address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(shared))),
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
    let shared = Ipv4Addr::new(23, 10, 20, 163);
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
    // the  run, 39 assistant.example connections egressed the primary
    // through this exemption while the rule host was fail-closed).
    use nrr_domain::mode_a_coverage::ModeACoverageStrategy;
    use std::sync::atomic::AtomicBool;
    let shared = Ipv4Addr::new(23, 10, 20, 163);
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
    let shared = Ipv4Addr::new(23, 10, 20, 163);
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
    let shared = Ipv4Addr::new(23, 10, 20, 163);
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

/// Mode A, secondary gone, per-IP blocking: the rule host's v6 addresses are
/// blocked BY NAME. This used to be a blanket `::/0` cut, which also took
/// every v6 destination the user's rules say nothing about.
#[test]
fn the_per_ip_fail_closed_path_blocks_the_rule_hosts_v6_addresses() {
    let v6: std::net::Ipv6Addr = "2001:db8::9".parse().expect("literal");
    let (api, orch, src, rules) = fixture_with_ipv6(
        None,
        "example.test",
        vec![
            std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            std::net::IpAddr::V6(v6),
        ],
    );
    rules.set(rules_with_secondary_host("example.test"));
    let snap = snap_block("Wi-Fi", "TAP");
    assert!(!snap.kill_switch_block_all, "per-IP path, not block-all");
    src.set("S-1-5-21-A", snap);

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    assert!(
        filters.iter().any(
            |f| f.layer == nrr_platform_api::types::WfpLayerKey::AleAuthConnectV6
                && f.action == WfpAction::Block
                && f.covers_v6(v6)
        ),
        "the rule host's v6 address is not blocked while its v4 one is",
    );
    assert!(
        filters
            .iter()
            .filter(|f| f.layer.is_v6())
            .all(|f| f.covers_v6(v6)),
        "a v6 filter that names no destination is the family cut coming back",
    );
}

/// A machine no link of which can carry IPv6 gets no v6 filter at all: there
/// is nothing to leak, and a filter nothing matches is standing volume the
/// BFE host pays for.
#[test]
fn a_machine_without_ipv6_installs_no_v6_filter() {
    let (api, orch, src, rules) = fixture_with_luid(None);
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 9)));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap();
    assert!(filters.iter().all(|f| !f.layer.is_v6()));
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
    src.set("S-1-5-21-B", snap_primary_only("Wi-Fi"));
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
        bootstrap_server_ips_v6: Vec::new(),
        local_subnets: vec![(Ipv4Addr::new(192, 168, 1, 0), 24)],
        local_subnets_v6: Vec::new(),
        foreign_tunnel_luids: Vec::new(),
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
        bootstrap_server_ips_v6: Vec::new(),
        local_subnets: vec![(Ipv4Addr::new(192, 168, 1, 0), 24)],
        local_subnets_v6: Vec::new(),
        foreign_tunnel_luids: Vec::new(),
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
        bootstrap_server_ips_v6: Vec::new(),
        local_subnets: Vec::new(),
        local_subnets_v6: Vec::new(),
        foreign_tunnel_luids: Vec::new(),
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
                address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(primary_ip))),
                app_match: None,
                comment: String::new(),
                action: nrr_domain::RuleAction::Route,
                origin: None,
            }]),
            secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                id: RuleId("r-sec".into()),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(secondary_ip))),
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
    // packet pair per named protocol = 2 + 2 + 8 = 12.
    assert_eq!(count, 12);
    let filters = api.wfp_filters.lock().unwrap();
    // The kill-switch never targets the primary destination: every
    // destination-scoped filter it installs names the secondary address and
    // only it.
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
            .filter(|f| f.action == WfpAction::Block)
            .all(|f| f.remote_ip.is_some() || !f.remote_ip_set.is_empty()),
        "every block this posture arms names the destination it guards"
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
