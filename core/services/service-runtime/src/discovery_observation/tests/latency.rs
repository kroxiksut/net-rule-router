use super::*;
use std::sync::Condvar;

struct CostProbe(Arc<Probe>, Arc<Mutex<HashMap<String, BootInstant>>>);
impl PathProbe for CostProbe {
    fn probe(&self, _: Ipv4Addr, _: u16, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
        panic!("TLS evidence is required")
    }
    fn probe_tls(
        &self,
        target: Ipv4Addr,
        host: &str,
        source: Option<Ipv4Addr>,
        timeout: Duration,
    ) -> PathVerdict {
        let verdict = self.0.probe_tls(target, host, source, timeout);
        crate::boot_clock::simulate_sleep(if verdict == PathVerdict::Silent {
            Duration::from_millis(1500)
        } else {
            Duration::from_millis(100)
        });
        self.1
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(host.to_owned(), BootInstant::now());
        verdict
    }
}

fn consumer(
    pipeline: &Arc<DiscoveryObservationPipeline>,
) -> Arc<crate::conn_observation_consumer::ConnectionObservationConsumer> {
    Arc::new(
        crate::conn_observation_consumer::ConnectionObservationConsumer::with_egress(
            Arc::new(nrr_platform_api::windows_api::MockWindowsApi::new()),
            Arc::new(|_| (None, None)),
            Arc::new(|| None),
            false,
        )
        .with_discovery_observation(Arc::clone(pipeline)),
    )
}

fn attempt(target: Ipv4Addr, owner: &str) -> ConnectionObservation {
    let mut seen = observation(Some(owner), ConnectionProgress::Attempt);
    seen.remote.set_ip(target.into());
    seen.local.set_port(44000 + u16::from(target.octets()[3]));
    seen
}

fn queue_json(engine: &AutoRulesEngine, owner: &str, host: &str) -> serde_json::Value {
    let snapshot = serde_json::to_value(engine.discovery_snapshot(owner, SystemTime::now()))
        .unwrap_or_else(|error| panic!("snapshot must serialize: {error}"));
    snapshot["episodes"]
        .as_array()
        .unwrap_or_else(|| panic!("episodes array"))
        .iter()
        .find(|episode| episode["host"] == host)
        .unwrap_or_else(|| panic!("episode for {host}"))
        .clone()
}

fn warm_names(f: &Fixture) -> Vec<String> {
    let names: Vec<_> = (0..8)
        .map(|n| format!("a-latency-warm-{n}.example"))
        .collect();
    for name in &names {
        f.pipeline.wiring.names.record_for(OWNER, name, &[TARGET]);
    }
    *f.probe
        .primary_answering_hosts
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = names.clone();
    names
}

#[test]
fn a_normal_browser_burst_does_not_leave_a_fresh_blocked_site_waiting_for_minutes() {
    for (healthy_count, deadline_secs) in [(16, 30), (32, 60)] {
        let mut f = fixture("a-browser-0.example");
        let mut batch = Vec::new();
        let mut healthy = Vec::new();
        for group in 0..healthy_count / 8 {
            let target = Ipv4Addr::new(203, 0, 120, group as u8 + 1);
            for n in 0..8 {
                let host = format!("a-browser-{}.example", group * 8 + n);
                f.pipeline.wiring.names.record_for(OWNER, &host, &[target]);
                healthy.push(host);
            }
            batch.push(attempt(target, OWNER));
        }
        *f.probe
            .primary_answering_hosts
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = healthy;
        let host = "fresh-browser-site.example";
        let target = Ipv4Addr::new(203, 0, 121, 1);
        remember_shared_name(&f.pipeline, host, target);
        batch.push(attempt(target, OWNER));
        let finished = Arc::new(Mutex::new(HashMap::new()));
        Arc::get_mut(&mut f.pipeline.wiring)
            .unwrap_or_else(|| panic!("unshared wiring"))
            .probe = Arc::new(CostProbe(Arc::clone(&f.probe), Arc::clone(&finished)));
        let pipeline = Arc::new(f.pipeline);
        let source =
            Arc::new(nrr_platform_api::conn_observe::MockConnectionObservationSource::new());
        for seen in batch {
            source.push(seen);
        }
        let progress = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&progress);
        let mut task = crate::service_tasks::build_conn_observe_task_reporting(
            source,
            consumer(&pipeline),
            Some(Arc::new(move || {
                count.fetch_add(1, Ordering::Relaxed);
            })),
            None,
        );
        let began = BootInstant::now();
        for _ in 0..deadline_secs / 5 {
            crate::boot_clock::simulate_sleep(Duration::from_secs(5));
            (task.tick)(&crate::lifecycle::StopToken::new());
            wait_for_workers(&pipeline);
            if f.engine
                .candidates(OWNER)
                .iter()
                .any(|candidate| candidate.proposed_match == host)
            {
                break;
            }
        }
        assert!(f.engine.candidates(OWNER).iter().any(|candidate| candidate.proposed_match == host),
            "{healthy_count} healthy names must not keep a fresh blocked site queued beyond {deadline_secs}s under the controlled 100ms/1.5s probe scenario");
        let completion = finished
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(host)
            .copied()
            .unwrap_or_else(|| panic!("H must have completed its TLS evidence"));
        assert!(completion.saturating_duration_since(began) <= Duration::from_secs(deadline_secs),
            "the bound includes the 5s initial observer phase and the worker's complete simulated TLS cost");
        assert_eq!(
            progress.load(Ordering::Relaxed),
            0,
            "diagnostic progress must not apply routes"
        );
        assert!(f.engine.seen_with(OWNER, host, 8).is_empty());
    }
}

#[test]
fn several_users_cannot_multiply_the_machines_initial_probe_burst() {
    let f = fixture("a-latency-warm-0.example");
    warm_names(&f);
    let other = "other-user-new-site.example";
    let other_target = Ipv4Addr::new(203, 0, 122, 1);
    f.pipeline
        .wiring
        .names
        .record_for(OTHER, other, &[other_target]);
    f.pipeline
        .wiring
        .names
        .record("other-user-neighbour.example", &[other_target]);
    let pipeline = Arc::new(f.pipeline);
    shared_attempt(&pipeline, TARGET);
    pipeline.observe(&attempt(other_target, OTHER), EgressRole::Primary);
    wait_for_workers(&pipeline);
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        8,
        "the machine burst is shared; a second principal must not mint another eight credits"
    );
    assert!(f.engine.candidates(OTHER).is_empty());
    assert!(f.engine.candidates(OWNER).is_empty());
}

#[test]
fn a_third_owners_fresh_site_gets_a_turn_within_the_machine_burst() {
    let f = fixture("owner-rr-a-0.example");
    let third = "S-1-5-21-3212-1003";
    let mut healthy = Vec::new();
    let groups = [
        (OWNER, TARGET),
        (OTHER, Ipv4Addr::new(203, 0, 125, 1)),
        (third, Ipv4Addr::new(203, 0, 125, 2)),
    ];
    for (index, (owner, target)) in groups.iter().enumerate() {
        for n in 0..if index == 2 { 1 } else { 8 } {
            let host = format!("owner-rr-{}-{n}.example", ['a', 'b', 'c'][index]);
            f.pipeline.wiring.names.record_for(owner, &host, &[*target]);
            healthy.push(host);
        }
        f.pipeline
            .wiring
            .names
            .record("foreign-rr-neighbour.example", &[*target]);
    }
    *f.probe
        .primary_answering_hosts
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = healthy;
    let pipeline = Arc::new(f.pipeline);
    let batch: Vec<_> = groups
        .iter()
        .map(|(owner, target)| attempt(*target, owner))
        .collect();
    consumer(&pipeline).consume(&batch, SystemTime::now());
    wait_for_workers(&pipeline);
    let calls = f.probe.calls.lock().unwrap_or_else(|p| p.into_inner());
    assert!(
        calls
            .iter()
            .take(8)
            .any(|(host, _)| host == "owner-rr-c-0.example"),
        "alternating only the first two owners must not strand a third owner's fresh name"
    );
}

#[derive(Default)]
struct GateProbe {
    gate: Mutex<bool>,
    ready: Condvar,
    started: AtomicUsize,
}
impl GateProbe {
    fn release(&self) {
        *self.gate.lock().unwrap_or_else(|p| p.into_inner()) = true;
        self.ready.notify_all();
    }
}
struct ReleaseGate(Arc<GateProbe>);
impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.release();
    }
}
impl PathProbe for GateProbe {
    fn probe(&self, _: Ipv4Addr, _: u16, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
        panic!("TLS only")
    }
    fn probe_tls(&self, _: Ipv4Addr, _: &str, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
        self.started.fetch_add(1, Ordering::AcqRel);
        let mut gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        while !*gate {
            gate = self.ready.wait(gate).unwrap_or_else(|p| p.into_inner());
        }
        PathVerdict::Answered
    }
}

fn gated() -> (Fixture, Arc<GateProbe>, ReleaseGate) {
    let mut f = fixture("a-latency-warm-0.example");
    warm_names(&f);
    let probe = Arc::new(GateProbe::default());
    Arc::get_mut(&mut f.pipeline.wiring)
        .unwrap_or_else(|| panic!("unshared wiring"))
        .probe = probe.clone();
    let release = ReleaseGate(Arc::clone(&probe));
    (f, probe, release)
}

#[test]
fn one_check_uses_both_workers_without_hiding_unstarted_names_in_a_serial_batch() {
    let (f, probe, _release) = gated();
    let pipeline = Arc::new(f.pipeline);
    consumer(&pipeline).consume(&[attempt(TARGET, OWNER)], SystemTime::now());
    let deadline = Instant::now() + Duration::from_secs(1);
    while probe.started.load(Ordering::Acquire) < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    let started = probe.started.load(Ordering::Acquire);
    let held = pipeline
        .memory
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .in_flight
        .len();
    probe.release();
    wait_for_workers(&pipeline);
    assert_eq!(
        started, 2,
        "a slow first name must not leave the other worker idle"
    );
    assert_eq!(
        held, 2,
        "only the two active names may reserve machine and owner tokens"
    );
    assert_eq!(
        probe.started.load(Ordering::Acquire),
        8,
        "one logical check must obey the configured per-check target cap"
    );
}

#[test]
fn queued_rate_wait_has_a_real_eligibility_delay_and_no_foreign_identity() {
    let f = fixture("a-latency-warm-0.example");
    warm_names(&f);
    let target = Ipv4Addr::new(203, 0, 123, 1);
    let host = "rate-waiting-site.example";
    remember_shared_name(&f.pipeline, host, target);
    let pipeline = Arc::new(f.pipeline);
    shared_attempt(&pipeline, TARGET);
    shared_attempt(&pipeline, target);
    let row = queue_json(&f.engine, OWNER, host);
    assert_eq!(
        row["probe-queue"]["wait-kind"], "rate",
        "queued must distinguish rate capacity from occupied workers"
    );
    let delay = row["probe-queue"]["eligible-in-ms"]
        .as_u64()
        .unwrap_or_else(|| panic!("rate eligibility is measured"));
    assert!(
        delay > 0 && delay <= 1875,
        "eligibility is the next refill, not a fabricated completion ETA"
    );
    assert!(row["probe-queue"]["last-probe-started-unix-ms"].is_null());
    assert!(f
        .engine
        .discovery_snapshot(OTHER, SystemTime::now())
        .episodes
        .iter()
        .all(|episode| episode.host.as_deref() != Some(host)));
}

#[test]
fn queued_cooldown_preserves_the_last_probe_time_and_does_not_send_early() {
    let f = fixture("cooldown-latency-site.example");
    f.pipeline
        .wiring
        .names
        .record("foreign-cooldown-neighbour.example", &[TARGET]);
    f.probe.primary_answers.store(true, Ordering::Release);
    let pipeline = Arc::new(f.pipeline);
    shared_attempt(&pipeline, TARGET);
    shared_attempt(&pipeline, TARGET);
    let row = queue_json(&f.engine, OWNER, "cooldown-latency-site.example");
    assert_eq!(row["probe-queue"]["wait-kind"], "cooldown");
    assert!(row["probe-queue"]["last-probe-started-unix-ms"]
        .as_i64()
        .is_some_and(|at| at > 0));
    assert!(row["probe-queue"]["eligible-in-ms"]
        .as_u64()
        .is_some_and(|ms| ms > 290_000 && ms <= 300_000));
    crate::boot_clock::simulate_sleep(Duration::from_secs(15));
    idle_discovery_tick(&pipeline, false);
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        1
    );
    assert!(row["history"].as_array().is_some_and(|steps| steps
        .iter()
        .any(|step| step["reason"] == "primary-responds")));
}

#[test]
fn waiting_workers_and_older_owned_names_are_distinct_without_foreign_queue_counts() {
    let (f, probe, _release) = gated();
    let pipeline = Arc::new(f.pipeline);
    consumer(&pipeline).consume(&[attempt(TARGET, OWNER)], SystemTime::now());
    let deadline = Instant::now() + Duration::from_secs(1);
    while probe.started.load(Ordering::Acquire) < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    let head = queue_json(&f.engine, OWNER, "a-latency-warm-2.example");
    let later = queue_json(&f.engine, OWNER, "a-latency-warm-3.example");
    probe.release();
    wait_for_workers(&pipeline);
    assert_eq!(head["probe-queue"]["wait-kind"], "workers");
    assert_eq!(head["probe-queue"]["queued-ahead"], 0);
    assert_eq!(later["probe-queue"]["wait-kind"], "ahead");
    assert_eq!(later["probe-queue"]["queued-ahead"], 1);
    assert!(
        head["probe-queue"]["eligible-in-ms"].is_null(),
        "worker completion time is not known"
    );
}

#[test]
fn queued_positions_ignore_revoked_dns_and_current_secondary_rules_without_waiting_for_a_tick() {
    let (f, probe, _release) = gated();
    let pipeline = Arc::new(f.pipeline);
    consumer(&pipeline).consume(&[attempt(TARGET, OWNER)], SystemTime::now());
    let deadline = Instant::now() + Duration::from_secs(1);
    while probe.started.load(Ordering::Acquire) < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    // Fill the bounded DNS window with new names, retaining only this queued host.
    for n in 0..8 {
        pipeline
            .wiring
            .names
            .record_for(OWNER, &format!("new-dns-{n}.example"), &[TARGET]);
    }
    let kept = "a-latency-warm-3.example";
    pipeline.wiring.names.record_for(OWNER, kept, &[TARGET]);
    let head = queue_json(&f.engine, OWNER, kept);
    assert_eq!(
        head["probe-queue"]["queued-ahead"], 0,
        "stale DNS predecessors are not real queued work ahead"
    );
    assert_eq!(head["probe-queue"]["wait-kind"], "workers");
    assert!(queue_json(&f.engine, OWNER, "a-latency-warm-2.example")["probe-queue"].is_null());
    use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRule, CanonicalRuleSet};
    f.rules
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .rule_book
        .secondary = CanonicalRuleSet::from_rules(vec![CanonicalRule {
        id: nrr_domain::RuleId("new-queued-secondary-rule".into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactFqdn(kept.into())),
        app_match: None,
        action: nrr_domain::RuleAction::Route,
        comment: String::new(),
        origin: None,
    }]);
    assert!(
        queue_json(&f.engine, OWNER, kept)["probe-queue"].is_null(),
        "a changed route rule invalidates the live queue view before any next tick or send"
    );
    probe.release();
    wait_for_workers(&pipeline);
}

#[test]
fn consent_revoked_while_waiting_clears_the_queue_without_sending() {
    let f = fixture("a-latency-warm-0.example");
    warm_names(&f);
    let target = Ipv4Addr::new(203, 0, 124, 1);
    let host = "revoked-latency-site.example";
    remember_shared_name(&f.pipeline, host, target);
    let pipeline = Arc::new(f.pipeline);
    shared_attempt(&pipeline, TARGET);
    shared_attempt(&pipeline, target);
    f.enabled.store(false, Ordering::Release);
    crate::boot_clock::simulate_sleep(Duration::from_secs(15));
    idle_discovery_tick(&pipeline, false);
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        8
    );
    assert!(f.engine.candidates(OWNER).is_empty());
    assert!(queue_json(&f.engine, OWNER, host)["probe-queue"].is_null());
}

#[test]
fn a_busy_connection_trace_cannot_evict_an_active_owners_queued_site_from_the_snapshot() {
    let f = fixture("a-latency-warm-0.example");
    warm_names(&f);
    let target = Ipv4Addr::new(203, 0, 126, 1);
    let host = "queued-during-busy-trace.example";
    remember_shared_name(&f.pipeline, host, target);
    let pipeline = Arc::new(f.pipeline);
    shared_attempt(&pipeline, TARGET);
    shared_attempt(&pipeline, target);
    let unrelated: Vec<_> = (0..300)
        .map(|n| {
            let mut seen = attempt(Ipv4Addr::new(198, 51, 100, (n % 250) as u8 + 1), OWNER);
            seen.local.set_port(45000 + n as u16);
            seen.process_path = None;
            seen
        })
        .collect();
    consumer(&pipeline).consume(&unrelated, SystemTime::now());
    wait_for_workers(&pipeline);
    let snapshot = f.engine.discovery_snapshot(OWNER, SystemTime::now());
    assert!(
        snapshot.episodes.len() <= 128,
        "queue visibility must stay bounded"
    );
    assert!(snapshot.episodes.iter().any(|episode| episode.host.as_deref() == Some(host)),
        "busy unrelated flows must not hide pending work even after its historical episode was evicted");
    let wire = serde_json::to_value(&snapshot).unwrap_or_else(|error| panic!("snapshot: {error}"));
    let active = wire["episodes"]
        .as_array()
        .unwrap_or_else(|| panic!("episodes array"))
        .iter()
        .filter(|episode| episode["probe-queue"].is_object())
        .count();
    assert!(
        active <= 64,
        "only bounded own pending work is added to the reply"
    );
    assert!(
        snapshot.episodes.len().saturating_sub(active) <= 64,
        "recent history retains its independent bounded allowance"
    );
    assert_eq!(
        queue_json(&f.engine, OWNER, host)["probe-queue"]["wait-kind"],
        "rate"
    );
    assert!(f
        .engine
        .discovery_snapshot(OTHER, SystemTime::now())
        .episodes
        .iter()
        .all(|episode| episode.host.as_deref() != Some(host)));
}
