use super::*;

const SID: &str = "S-1-5-21-NOROLES";

fn deny_ip_rules(ip: Ipv4Addr) -> ActiveRulesSnapshot {
    let mut rule = primary_ip_rule("deny-1", ip);
    rule.action = nrr_domain::RuleAction::Block;
    ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![rule]),
            secondary: CanonicalRuleSet::default(),
        },
    }
}

fn live_actions(api: &MockWindowsApi) -> Vec<WfpAction> {
    api.wfp_filters
        .lock()
        .unwrap()
        .iter()
        .map(|f| f.action)
        .collect()
}

#[test]
fn a_deny_is_enforced_for_a_user_with_no_connections_assigned() {
    let (api, orch, _src, rules, _audit) = fixture();
    rules.set(deny_ip_rules(Ipv4Addr::new(203, 0, 113, 9)));
    let count = orch.install_for_sid(SID).unwrap();
    assert!(count > 0, "the deny must install without a route policy");
    let actions = live_actions(&api);
    assert_eq!(actions.len(), count);
    assert!(actions.iter().all(|a| *a == WfpAction::Block));
}

#[test]
fn routing_rules_alone_still_install_nothing_without_connections() {
    let (api, orch, _src, rules, _audit) = fixture();
    rules.set(rules_with_n_primary_ips(2));
    assert_eq!(orch.install_for_sid(SID).unwrap(), 0);
    assert!(api.wfp_filters.lock().unwrap().is_empty());
}

#[test]
fn a_routing_rule_beside_a_deny_adds_no_filter_without_connections() {
    let (api, orch, _src, rules, _audit) = fixture();
    let mut book = deny_ip_rules(Ipv4Addr::new(203, 0, 113, 9)).rule_book;
    book.secondary = CanonicalRuleSet::from_rules(vec![primary_ip_rule(
        "route-1",
        Ipv4Addr::new(198, 51, 100, 4),
    )]);
    rules.set(ActiveRulesSnapshot { rule_book: book });
    let count = orch.install_for_sid(SID).unwrap();
    assert!(count > 0);
    assert!(live_actions(&api).iter().all(|a| *a == WfpAction::Block));
}

#[test]
fn removing_the_last_deny_leaves_no_filter_behind() {
    let (api, orch, _src, rules, _audit) = fixture();
    rules.set(deny_ip_rules(Ipv4Addr::new(203, 0, 113, 9)));
    assert!(orch.install_for_sid(SID).unwrap() > 0);

    rules.set(rules_with_n_primary_ips(1));
    orch.recompile_for_sid(SID).unwrap();
    assert!(api.wfp_filters.lock().unwrap().is_empty());
    assert_eq!(orch.filter_count_for(SID), 0);
}

#[test]
fn assigning_connections_later_keeps_the_deny_and_adds_the_routes() {
    let (api, orch, src, rules, _audit) = fixture();
    let mut book = deny_ip_rules(Ipv4Addr::new(203, 0, 113, 9)).rule_book;
    book.secondary = CanonicalRuleSet::from_rules(vec![primary_ip_rule(
        "route-1",
        Ipv4Addr::new(198, 51, 100, 4),
    )]);
    rules.set(ActiveRulesSnapshot { rule_book: book });
    let denies = orch.install_for_sid(SID).unwrap();
    assert!(denies > 0);

    src.set(SID, snap_full("Wi-Fi", "TAP"));
    orch.recompile_for_sid(SID).unwrap();
    let after = live_actions(&api);
    assert!(
        after.iter().filter(|a| **a == WfpAction::Block).count() >= denies,
        "the deny survives the policy arriving"
    );
    assert!(after.len() > denies, "the route rule now installs too");
}

#[test]
fn losing_the_connections_keeps_only_the_deny() {
    let (api, orch, src, rules, _audit) = fixture();
    let mut book = deny_ip_rules(Ipv4Addr::new(203, 0, 113, 9)).rule_book;
    book.secondary = CanonicalRuleSet::from_rules(vec![primary_ip_rule(
        "route-1",
        Ipv4Addr::new(198, 51, 100, 4),
    )]);
    rules.set(ActiveRulesSnapshot { rule_book: book });
    src.set(SID, snap_full("Wi-Fi", "TAP"));
    orch.install_for_sid(SID).unwrap();

    src.per_sid.lock().unwrap().remove(SID);
    orch.recompile_for_sid(SID).unwrap();
    let after = live_actions(&api);
    assert!(!after.is_empty());
    assert!(after.iter().all(|a| *a == WfpAction::Block));
}

/// A policy store that fails to answer is not a user with no connections: what
/// is installed stays, protection included.
#[test]
fn an_unreadable_policy_keeps_the_installed_set() {
    let (api, orch, src, rules, _audit) = fixture();
    rules.set(rules_with_n_primary_ips(2));
    src.set(SID, snap_full("Wi-Fi", "TAP"));
    let installed = orch.install_for_sid(SID).unwrap();
    assert!(installed > 0);
    let before = api.wfp_filters.lock().unwrap().len();

    src.fail_reads_of(SID);
    assert!(matches!(
        orch.recompile_for_sid(SID),
        Err(OrchestratorError::PolicyUnreadable(_))
    ));
    assert_eq!(api.wfp_filters.lock().unwrap().len(), before);
    assert_eq!(orch.filter_count_for(SID), installed);
}

/// A rule book that does not read is not "no rules": what is installed stays.
#[test]
fn an_unreadable_rule_book_keeps_the_installed_set() {
    let (api, orch, src, rules, _audit) = fixture();
    rules.set(rules_with_n_primary_ips(2));
    src.set(SID, snap_full("Wi-Fi", "TAP"));
    let installed = orch.install_for_sid(SID).unwrap();
    assert!(installed > 0);
    let before = api.wfp_filters.lock().unwrap().len();

    rules.fail_reads("damaged row");
    assert!(matches!(
        orch.recompile_for_sid(SID),
        Err(OrchestratorError::RulesUnreadable(_))
    ));
    assert_eq!(api.wfp_filters.lock().unwrap().len(), before);
    assert_eq!(orch.filter_count_for(SID), installed);
}

/// A user with rules but no policy row has nothing routing or pinning their
/// IPv6, so the board reads `Off` for them, never "first plan pending": the
/// DNS path would otherwise withhold every AAAA of their rule hosts.
#[test]
fn a_user_without_a_policy_row_reads_ipv6_off_on_the_board() {
    const NO_ROW: &str = "S-1-5-21-NOROW-V6";
    let board = crate::ipv6_disposition::global_ipv6_dispositions();
    board.set(NO_ROW, crate::enforcement_planner::Ipv6Guard::FiltersOnly);
    let (_api, orch, _src, rules, _audit) = fixture();
    rules.set(rules_with_n_primary_ips(2));
    orch.install_for_sid(NO_ROW).unwrap();
    assert_eq!(
        board.of(NO_ROW),
        Some(crate::enforcement_planner::Ipv6Guard::Off)
    );
}

/// A program deny for a user with no connections keeps its loopback permits:
/// the program still reaches a local proxy or dev server, as it does with a
/// policy.
#[test]
fn a_program_deny_without_connections_keeps_loopback_open() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let resolver = nrr_platform_api::MockAppPathResolver::new().with(
        "evil.exe",
        vec![std::path::PathBuf::from(r"C:\Apps\evil.exe")],
    );
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    )
    .with_app_resolver(Arc::new(resolver));
    let deny = CanonicalRule {
        id: RuleId("deny-app".into()),
        enabled: true,
        address_match: None,
        app_match: Some(nrr_domain::canonical::CanonicalAppMatch {
            pattern: nrr_domain::canonical::CanonicalAppPattern::Exact("evil.exe".into()),
            include_child_processes: false,
            override_requested: false,
        }),
        comment: String::new(),
        action: nrr_domain::RuleAction::Block,
        origin: None,
    };
    rules.set(ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![deny]),
            secondary: CanonicalRuleSet::default(),
        },
    });

    assert!(orch.install_for_sid(SID).unwrap() > 0);
    let live = api.wfp_filters.lock().unwrap().clone();
    let app = |f: &&nrr_platform_api::types::WfpFilterRecord| {
        f.app_pattern.as_deref() == Some(r"C:\Apps\evil.exe")
    };
    assert!(live
        .iter()
        .filter(app)
        .any(|f| f.action == WfpAction::Block));
    let permits: Vec<_> = live
        .iter()
        .filter(app)
        .filter(|f| f.action == WfpAction::Permit)
        .collect();
    assert!(
        permits
            .iter()
            .any(|f| f.remote_subnet == Some((Ipv4Addr::new(127, 0, 0, 0), 8))),
        "v4 loopback stays open: {live:?}"
    );
    assert!(
        permits
            .iter()
            .any(|f| f.remote_subnet_v6 == Some((std::net::Ipv6Addr::LOCALHOST, 128))),
        "v6 loopback stays open: {live:?}"
    );
    assert_eq!(permits.len(), 2, "nothing but loopback is permitted");
}
