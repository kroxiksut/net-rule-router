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
