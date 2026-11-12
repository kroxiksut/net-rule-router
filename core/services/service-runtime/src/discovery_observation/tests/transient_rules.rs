use super::*;
use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRule, CanonicalRuleSet};

struct AvailableRules {
    ready: AtomicBool,
    inner: Arc<Rules>,
    memory: Mutex<Option<std::sync::Weak<Mutex<Memory>>>>,
}

impl RulesProvider for AvailableRules {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        if !self.ready.load(Ordering::Acquire) {
            if let Some(memory) = self
                .memory
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
            {
                assert!(
                    memory.try_lock().is_ok(),
                    "a rule-provider callback must run outside the queue mutex"
                );
            }
            return None;
        }
        self.inner.active_rules()
    }
}

fn unavailable(host: &str, ready: bool) -> (Fixture, Arc<AvailableRules>) {
    let mut f = fixture(host);
    let rules = Arc::new(AvailableRules {
        ready: AtomicBool::new(ready),
        inner: Arc::clone(&f.rules),
        memory: Mutex::new(Some(Arc::downgrade(&f.pipeline.memory))),
    });
    let engine = Arc::new(
        AutoRulesEngine::new(
            rules.clone(),
            Arc::new(|_| nrr_storage::auto_rules::AutoRulesMode::Suggest),
            Arc::new(InMemoryDismissalStore::new()),
            Arc::new(InMemoryPendingStore::new()),
            SystemTime::now(),
        )
        .with_primary_behavior_source(Arc::new(|owner, host| {
            crate::primary_stall_registry::global_primary_stalls().behavior_of_subtree(owner, host)
        })),
    );
    let wiring =
        Arc::get_mut(&mut f.pipeline.wiring).unwrap_or_else(|| panic!("unshared fixture wiring"));
    wiring.rules = rules.clone();
    wiring.engine = Arc::clone(&engine);
    f.engine = engine;
    (f, rules)
}

fn begin(pipeline: &DiscoveryObservationPipeline, shared: bool) {
    pipeline.observe(
        &observation(Some(OWNER), ConnectionProgress::Attempt),
        EgressRole::Primary,
    );
    if !shared {
        pipeline.observe(
            &observation(None, ConnectionProgress::ClosedUnknown),
            EgressRole::Primary,
        );
    }
    wait_for_workers(pipeline);
}

fn waiting(engine: &AutoRulesEngine, host: &str) -> serde_json::Value {
    let wire = serde_json::to_value(engine.discovery_snapshot(OWNER, SystemTime::now()))
        .unwrap_or_else(|error| panic!("snapshot: {error}"));
    wire["episodes"]
        .as_array()
        .unwrap_or_else(|| panic!("episodes array"))
        .iter()
        .find(|row| row["host"] == host)
        .unwrap_or_else(|| panic!("owned episode retained"))
        .clone()
}

#[test]
fn a_missing_rule_snapshot_keeps_new_work_until_an_empty_tick_can_evaluate_it() {
    for shared in [false, true] {
        for tee in [false, true] {
            let host = "rules-unavailable-new-work.example";
            let (f, rules) = unavailable(host, false);
            if shared {
                f.pipeline
                    .wiring
                    .names
                    .record("foreign-rules-neighbour.example", &[TARGET]);
            }
            let pipeline = Arc::new(f.pipeline);
            begin(&pipeline, shared);
            idle_discovery_tick(&pipeline, tee);
            assert!(
                f.probe
                    .calls
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .is_empty(),
                "unknown rules never authorize a network call"
            );
            rules.ready.store(true, Ordering::Release);
            idle_discovery_tick(&pipeline, tee);
            assert!(f.engine.candidates(OWNER).iter().any(|candidate| candidate.proposed_match == host),
                "a recovered rule snapshot must resume the original work without another browser flow (shared={shared}, tee={tee})");
            assert!(f.engine.candidates(OTHER).is_empty());
        }
    }
}

#[test]
fn a_queued_name_survives_a_rule_snapshot_outage_without_spending_network_credits() {
    let first = "a-before-rules-outage.example";
    let later = "b-after-rules-outage.example";
    let (mut f, rules) = unavailable(first, true);
    f.pipeline.wiring.names.record_for(OWNER, later, &[TARGET]);
    f.probe
        .primary_answering_hosts
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .push(first.into());
    Arc::get_mut(&mut f.pipeline.wiring)
        .unwrap_or_else(|| panic!("unshared wiring"))
        .limits =
        Arc::new(|_| ProbeLimits::new(Duration::from_millis(300), 1, Duration::from_secs(300)));
    let pipeline = Arc::new(f.pipeline);
    shared_attempt(&pipeline, TARGET);
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        1
    );
    rules.ready.store(false, Ordering::Release);
    idle_discovery_tick(&pipeline, false);
    idle_discovery_tick(&pipeline, true);
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        1
    );
    rules.ready.store(true, Ordering::Release);
    idle_discovery_tick(&pipeline, false);
    assert!(
        f.engine
            .candidates(OWNER)
            .iter()
            .any(|candidate| candidate.proposed_match == later),
        "a rule-provider read failure must not discard an already queued owner name"
    );
}

#[test]
fn unavailable_rules_are_reported_without_a_guessed_start_time_or_other_owners_data() {
    let host = "rules-pause-explanation.example";
    let (f, _) = unavailable(host, false);
    f.pipeline
        .wiring
        .names
        .record("foreign-rules-explanation.example", &[TARGET]);
    let pipeline = Arc::new(f.pipeline);
    begin(&pipeline, true);
    let row = waiting(&f.engine, host);
    assert_eq!(row["reason"], "rules-unavailable");
    assert_eq!(row["probe-queue"]["wait-kind"], "rules");
    assert!(
        row["probe-queue"]["eligible-in-ms"].is_null(),
        "a missing rule snapshot has no knowable completion deadline"
    );
    assert_eq!(row["probe-queue"]["queued-ahead"], 0);
    assert!(f
        .engine
        .discovery_snapshot(OTHER, SystemTime::now())
        .episodes
        .iter()
        .all(|episode| episode.host.as_deref() != Some(host)));
}

#[test]
fn rules_recovery_does_not_override_a_new_rule_revocation_or_missing_secondary() {
    for denial in [
        "secondary-rule",
        "block-rule",
        "consent",
        "secondary-gone",
        "dns-withdrawn",
    ] {
        struct LinksWithSecondary(Arc<AtomicBool>);
        impl EgressSources for LinksWithSecondary {
            fn egress_source_ips(&self, _: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
                (
                    Some(PRIMARY),
                    self.0.load(Ordering::Acquire).then_some(SECONDARY),
                )
            }
        }
        let host = "guarded-rules-recovery.example";
        let (mut f, rules) = unavailable(host, false);
        f.pipeline
            .wiring
            .names
            .record("foreign-guarded-rules.example", &[TARGET]);
        let secondary = Arc::new(AtomicBool::new(true));
        Arc::get_mut(&mut f.pipeline.wiring)
            .unwrap_or_else(|| panic!("unshared wiring"))
            .egress = Arc::new(LinksWithSecondary(Arc::clone(&secondary)));
        let pipeline = Arc::new(f.pipeline);
        begin(&pipeline, true);
        assert_eq!(
            waiting(&f.engine, host)["probe-queue"]["wait-kind"],
            "rules",
            "the guard must be tested against retained work"
        );
        match denial {
            "secondary-rule" | "block-rule" => {
                f.rules
                    .0
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .rule_book
                    .secondary = CanonicalRuleSet::from_rules(vec![CanonicalRule {
                    id: nrr_domain::RuleId("recovered-policy".into()),
                    enabled: true,
                    address_match: Some(CanonicalAddressMatch::ExactFqdn(host.into())),
                    app_match: None,
                    action: if denial == "block-rule" {
                        nrr_domain::RuleAction::Block
                    } else {
                        nrr_domain::RuleAction::Route
                    },
                    comment: String::new(),
                    origin: None,
                }]);
            }
            "consent" => f.enabled.store(false, Ordering::Release),
            "secondary-gone" => secondary.store(false, Ordering::Release),
            _ => {
                for n in 0..8 {
                    pipeline.wiring.names.record_for(
                        OWNER,
                        &format!("replacement-{n}.example"),
                        &[TARGET],
                    );
                }
            }
        }
        rules.ready.store(true, Ordering::Release);
        idle_discovery_tick(&pipeline, false);
        assert!(
            f.probe
                .calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty(),
            "recovering rules must recheck {denial} before any send"
        );
        assert!(f.engine.candidates(OWNER).is_empty());
        if denial == "secondary-gone" {
            secondary.store(true, Ordering::Release);
            idle_discovery_tick(&pipeline, true);
            assert_eq!(
                f.engine.candidates(OWNER).len(),
                1,
                "restoring the actual secondary resumes the same retained job"
            );
        }
    }
}

#[test]
fn waiting_for_rules_does_not_extend_the_original_dns_flow_witness_lifetime() {
    let host = "expired-rules-witness.example";
    let (f, rules) = unavailable(host, false);
    f.pipeline
        .wiring
        .names
        .record("foreign-expired-rules.example", &[TARGET]);
    let pipeline = Arc::new(f.pipeline);
    begin(&pipeline, true);
    assert_eq!(
        waiting(&f.engine, host)["probe-queue"]["wait-kind"],
        "rules"
    );
    for _ in 0..3 {
        crate::boot_clock::simulate_sleep(Duration::from_secs(600));
        idle_discovery_tick(&pipeline, false);
    }
    pipeline.wiring.names.record_for(OWNER, host, &[TARGET]);
    pipeline
        .wiring
        .names
        .record("fresh-neighbour-after-expiry.example", &[TARGET]);
    rules.ready.store(true, Ordering::Release);
    idle_discovery_tick(&pipeline, true);
    assert!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty(),
        "fresh DNS alone cannot revive an expired connection witness"
    );
    assert!(f.engine.candidates(OWNER).is_empty());
    assert!(waiting(&f.engine, host)["probe-queue"].is_null());
}

#[test]
fn losing_rules_after_a_real_send_retains_the_job_but_not_a_free_early_retry() {
    struct LoseRulesOnce {
        rules: Arc<AvailableRules>,
        calls: AtomicUsize,
    }
    impl PathProbe for LoseRulesOnce {
        fn probe(&self, _: Ipv4Addr, _: u16, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
            panic!("name-specific TLS is required")
        }
        fn probe_tls(
            &self,
            _: Ipv4Addr,
            _: &str,
            source: Option<Ipv4Addr>,
            _: Duration,
        ) -> PathVerdict {
            if self.calls.fetch_add(1, Ordering::AcqRel) == 0 {
                self.rules.ready.store(false, Ordering::Release);
            }
            if source == Some(SECONDARY) {
                PathVerdict::Answered
            } else {
                PathVerdict::Silent
            }
        }
    }
    let host = "rules-lost-after-first-send.example";
    let (mut f, rules) = unavailable(host, true);
    f.pipeline
        .wiring
        .names
        .record("foreign-mid-flight-rules.example", &[TARGET]);
    let probe = Arc::new(LoseRulesOnce {
        rules: Arc::clone(&rules),
        calls: AtomicUsize::new(0),
    });
    Arc::get_mut(&mut f.pipeline.wiring)
        .unwrap_or_else(|| panic!("unshared wiring"))
        .probe = probe.clone();
    let pipeline = Arc::new(f.pipeline);
    begin(&pipeline, true);
    assert_eq!(
        probe.calls.load(Ordering::Acquire),
        1,
        "loss of rules stops the remaining sends"
    );
    assert!(f.engine.candidates(OWNER).is_empty());
    rules.ready.store(true, Ordering::Release);
    idle_discovery_tick(&pipeline, false);
    let recovered = waiting(&f.engine, host);
    assert_eq!(recovered["probe-queue"]["wait-kind"], "cooldown");
    assert_eq!(
        recovered["reason"], "probe-queued",
        "recovered rules must not remain the current explanation while the real cooldown runs"
    );
    assert!(
        recovered["history"]
            .as_array()
            .unwrap_or_else(|| panic!("retained history"))
            .iter()
            .any(|step| step["reason"] == "rules-unavailable"),
        "the current view must preserve the observed rule outage in history"
    );
    assert_eq!(
        probe.calls.load(Ordering::Acquire),
        1,
        "a measured attempt retains its per-host cooldown"
    );
    crate::boot_clock::simulate_sleep(Duration::from_secs(299));
    idle_discovery_tick(&pipeline, true);
    assert_eq!(probe.calls.load(Ordering::Acquire), 1);
    crate::boot_clock::simulate_sleep(Duration::from_secs(1));
    idle_discovery_tick(&pipeline, false);
    assert_eq!(
        f.engine.candidates(OWNER).len(),
        1,
        "after the real cooldown, the original witness must resume without a new flow"
    );
    assert_eq!(probe.calls.load(Ordering::Acquire), 5);
}
