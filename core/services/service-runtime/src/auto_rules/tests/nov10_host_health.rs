use super::*;

#[test]
fn healthy_parent_is_not_auto_routed_because_another_name_beneath_it_fails() {
    let parent = "healthy-parent-scope.example";
    let child = "api.healthy-parent-scope.example";
    let registry = Arc::new(crate::primary_stall_registry::PrimaryStallRegistry::new());
    registry.note(SID, parent, PrimaryHealthEvent::Completed);
    for _ in 0..3 {
        registry.note(SID, child, PrimaryHealthEvent::Stalled);
    }
    let mut f = fixture(AutoRulesMode::Auto);
    f.engine = f.engine.with_primary_health_registry(registry);
    two_visits(&f.engine, &[parent]);
    f.engine.tick(SID, later());
    assert!(
        f.author.calls().is_empty(),
        "a child's failure cannot authorize automatic rerouting of its healthy parent"
    );
}

#[test]
fn a_child_response_cannot_mark_a_parent_without_its_own_health_evidence_as_served() {
    let parent = "unmeasured-parent-scope.example";
    let child = "api.unmeasured-parent-scope.example";
    let registry = Arc::new(crate::primary_stall_registry::PrimaryStallRegistry::new());
    registry.note(SID, child, PrimaryHealthEvent::Completed);
    let mut f = fixture(AutoRulesMode::Suggest);
    f.engine = f.engine.with_primary_health_registry(registry);
    two_visits(&f.engine, &[parent]);
    f.engine.tick(SID, later());
    let rows = f.engine.candidates(SID);
    let row = rows
        .iter()
        .find(|row| row.proposed_match == parent)
        .unwrap_or_else(|| panic!("the observed parent remains its own question"));
    assert!(
        !row.served_by_main_link,
        "a successful child is not a successful exchange with this actual host"
    );
    assert_ne!(row.primary_behavior, AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS);
}

#[test]
fn an_observed_child_address_does_not_authorize_a_parent_sni_probe() {
    use crate::ipc_handlers::providers::AutoRuleProbeRunner;
    use crate::path_probe::{MockPathProbe, PathProber, PathVerdict, ProbeLimits};
    use crate::production_auto_rule_probe::{EgressSources, ProductionAutoRuleProbe};
    use std::net::Ipv4Addr;
    struct MainOnly;
    impl EgressSources for MainOnly {
        fn egress_source_ips(&self, _: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
            (Some(Ipv4Addr::new(192, 0, 2, 10)), None)
        }
    }
    let parent = "not-resolved-parent-scope.example";
    let child = "api.not-resolved-parent-scope.example";
    let address = Ipv4Addr::new(203, 0, 113, 49);
    let f = fixture(AutoRulesMode::Suggest);
    let mut dto = main_link_dto("site.example", parent, AUTO_RULE_SIGNAL_CO_ACTIVITY, "");
    dto.id = candidate_id(SID, AUTO_RULE_MATCH_KIND_EXACT, parent);
    dto.match_kind = AUTO_RULE_MATCH_KIND_EXACT.into();
    f.engine.park(
        SID,
        vec![PendingCandidate {
            dto,
            route: RouteRole::Secondary,
            match_kind: AuthoredMatchKind::ExactHost,
        }],
        unix_ms(later()),
    );
    let engine = Arc::new(f.engine);
    let names = Arc::new(crate::observed_host_names::ObservedHostNames::new());
    names.record_for(SID, child, &[address]);
    names.record_for("S-B", parent, &[address]);
    let transport = Arc::new(MockPathProbe::new(PathVerdict::Answered));
    let runner = ProductionAutoRuleProbe::over(
        Arc::clone(&engine),
        Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::new()),
        Arc::new(MainOnly),
        Arc::new(PathProber::new(transport.clone())),
        Arc::new(|_| ProbeLimits::default()),
    )
    .with_observed_names(Arc::clone(&names));
    assert_eq!(runner.probe(SID, &[], &[]).accepted, 0, "neither this owner's child DNS nor another owner's parent DNS is authority to probe this exact parent name");
    assert!(transport.attempts().is_empty());
    names.record_for(SID, parent, &[address]);
    assert_eq!(
        runner.probe(SID, &[], &[]).accepted,
        1,
        "an actual fresh DNS witness for this owner and this exact name remains usable"
    );
    let until = Instant::now() + Duration::from_secs(3);
    while transport.attempts().is_empty() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(transport.attempts().len(), 1);
}

#[test]
fn newer_child_addresses_cannot_hide_an_older_exact_host_dns_witness() {
    use crate::ipc_handlers::providers::AutoRuleProbeRunner;
    use crate::path_probe::{MockPathProbe, PathProber, PathVerdict, ProbeLimits};
    use crate::production_auto_rule_probe::{EgressSources, ProductionAutoRuleProbe};
    use std::net::Ipv4Addr;
    struct MainOnly;
    impl EgressSources for MainOnly {
        fn egress_source_ips(&self, _: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
            (Some(Ipv4Addr::new(192, 0, 2, 10)), None)
        }
    }
    let parent = "older-exact-dns.example";
    let exact = Ipv4Addr::new(203, 0, 113, 60);
    let f = fixture(AutoRulesMode::Suggest);
    let mut dto = main_link_dto("site.example", parent, AUTO_RULE_SIGNAL_CO_ACTIVITY, "");
    dto.id = candidate_id(SID, AUTO_RULE_MATCH_KIND_EXACT, parent);
    dto.match_kind = AUTO_RULE_MATCH_KIND_EXACT.into();
    f.engine.park(
        SID,
        vec![PendingCandidate {
            dto,
            route: RouteRole::Secondary,
            match_kind: AuthoredMatchKind::ExactHost,
        }],
        unix_ms(later()),
    );
    let names = Arc::new(crate::observed_host_names::ObservedHostNames::new());
    names.record_for(SID, parent, &[exact]);
    std::thread::sleep(Duration::from_millis(2));
    for n in 0..4 {
        names.record_for(
            SID,
            &format!("child{n}.{parent}"),
            &[Ipv4Addr::new(203, 0, 113, 61 + n)],
        );
    }
    let transport = Arc::new(MockPathProbe::new(PathVerdict::Answered));
    let runner = ProductionAutoRuleProbe::over(
        Arc::new(f.engine),
        Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::new()),
        Arc::new(MainOnly),
        Arc::new(PathProber::new(transport.clone())),
        Arc::new(|_| ProbeLimits::default()),
    )
    .with_observed_names(names);
    assert_eq!(runner.probe(SID, &[], &[]).accepted, 1, "fresh child traffic must not evict the exact parent's valid DNS witness from this bounded check");
    let until = Instant::now() + Duration::from_secs(3);
    while transport.attempts().is_empty() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    let attempts = transport.attempts();
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].0, exact);
}
