use super::*;

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
            address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(
                203, 0, 113, 10,
            )))),
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
            address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(
                203, 0, 113, 10,
            )))),
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
