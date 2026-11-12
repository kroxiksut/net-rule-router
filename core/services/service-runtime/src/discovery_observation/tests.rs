use super::*;
use crate::auto_rules::{InMemoryDismissalStore, InMemoryPendingStore};
use crate::per_sid_orchestrator::ActiveRulesSnapshot;
use nrr_platform_api::conn_observe::{ConnectionVerdict, TransportProtocol};
use std::sync::atomic::AtomicBool;
use std::time::Instant;

mod history_capacity;
mod latency;
mod nov10_http;
mod nov10_regressions;
mod queue_races;
mod spawn_failure;
mod transient_rules;

const OWNER: &str = "S-1-5-21-3212-1001";
const OTHER: &str = "S-1-5-21-3212-1002";
const PRIMARY: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const SECONDARY: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const TARGET: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

#[derive(Default)]
struct Rules(Mutex<ActiveRulesSnapshot>);
impl RulesProvider for Rules {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        Some(self.0.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }
}
struct Links;
impl EgressSources for Links {
    fn egress_source_ips(&self, _: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        (Some(PRIMARY), Some(SECONDARY))
    }
}
#[derive(Default)]
struct Probe {
    calls: Mutex<Vec<(String, Ipv4Addr)>>,
    primary_answers: AtomicBool,
    secondary_silent: AtomicBool,
    primary_answering_hosts: Mutex<Vec<String>>,
    after_secondary: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    primary_verdicts: Mutex<std::collections::VecDeque<PathVerdict>>,
}
impl PathProbe for Probe {
    fn probe(&self, _: Ipv4Addr, _: u16, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
        panic!("hostname confirmation must speak TLS")
    }
    fn probe_tls(
        &self,
        _: Ipv4Addr,
        host: &str,
        source: Option<Ipv4Addr>,
        _: Duration,
    ) -> PathVerdict {
        let Some(source) = source else {
            return PathVerdict::Indeterminate;
        };
        self.calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((host.to_owned(), source));
        if source == PRIMARY {
            if let Some(verdict) = self
                .primary_verdicts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pop_front()
            {
                return verdict;
            }
            if self.primary_answers.load(Ordering::Acquire)
                || self
                    .primary_answering_hosts
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .iter()
                    .any(|answering| answering == host)
            {
                PathVerdict::Answered
            } else {
                PathVerdict::Silent
            }
        } else {
            let callback = self
                .after_secondary
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            if let Some(callback) = callback {
                callback();
            }
            if self.secondary_silent.load(Ordering::Acquire) {
                PathVerdict::Silent
            } else {
                PathVerdict::Answered
            }
        }
    }
}

struct Fixture {
    pipeline: DiscoveryObservationPipeline,
    engine: Arc<AutoRulesEngine>,
    probe: Arc<Probe>,
    rules: Arc<Rules>,
    enabled: Arc<AtomicBool>,
}

fn fixture(host: &str) -> Fixture {
    fixture_in_mode(host, nrr_storage::auto_rules::AutoRulesMode::Suggest)
}

fn fixture_in_mode(host: &str, mode: nrr_storage::auto_rules::AutoRulesMode) -> Fixture {
    let rules = Arc::new(Rules::default());
    let engine = Arc::new(
        AutoRulesEngine::new(
            rules.clone(),
            Arc::new(move |_| mode),
            Arc::new(InMemoryDismissalStore::new()),
            Arc::new(InMemoryPendingStore::new()),
            SystemTime::now(),
        )
        .with_primary_behavior_source(Arc::new(|owner, host| {
            crate::primary_stall_registry::global_primary_stalls().behavior_of_subtree(owner, host)
        })),
    );
    let names = Arc::new(ObservedHostNames::new());
    names.record_for(OWNER, host, &[TARGET]);
    names.record_for(OTHER, host, &[TARGET]);
    let probe = Arc::new(Probe::default());
    let enabled = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&enabled);
    let pipeline = DiscoveryObservationPipeline::new(DiscoveryObservationWiring {
        engine: Arc::clone(&engine),
        rules: rules.clone(),
        names,
        egress: Arc::new(Links),
        probe: probe.clone(),
        cadence: Arc::new(move |_| AutoProbeCadence {
            enabled: flag.load(Ordering::Acquire),
            repeat: Duration::from_secs(300),
        }),
        limits: Arc::new(|_| ProbeLimits::default()),
        primary_default: Arc::new(|_| true),
        passive_reset_available: false,
        os_cache_available: true,
    });
    Fixture {
        pipeline,
        engine,
        probe,
        rules,
        enabled,
    }
}

fn observation(owner: Option<&str>, progress: ConnectionProgress) -> ConnectionObservation {
    ConnectionObservation {
        pid: 32,
        process_path: (progress == ConnectionProgress::Attempt)
            .then(|| "C:\\Browser\\browser.exe".to_owned()),
        user_sid: owner.map(str::to_owned),
        protocol: TransportProtocol::Tcp,
        local: SocketAddr::new(PRIMARY.into(), 42000),
        remote: SocketAddr::new(TARGET.into(), 443),
        verdict: ConnectionVerdict::Unknown,
        drop_filter_id: None,
        blocked_by_nrr: None,
        nrr_drop_spec_id: None,
        observed_unix_ms: None,
        progress,
    }
}

fn wait_for_workers(pipeline: &DiscoveryObservationPipeline) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while pipeline.workers.load(Ordering::Acquire) > 0 {
        assert!(
            Instant::now() < deadline,
            "the bounded probe worker must finish"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn idle_discovery_tick(pipeline: &Arc<DiscoveryObservationPipeline>, tee: bool) {
    use crate::conn_observation_consumer::{
        ConnTraceTee, ConnectionObservationConsumer, ConnectionTraceRing,
    };
    struct NoBindings;
    impl nrr_platform_api::enforcement::EgressBindingSource for NoBindings {
        fn bindings_for(
            &self,
            _: &nrr_platform_api::enforcement::UserPrincipal,
        ) -> nrr_platform_api::enforcement::EgressBinding {
            nrr_platform_api::enforcement::EgressBinding::default()
        }
    }
    let api = Arc::new(nrr_platform_api::windows_api::MockWindowsApi::new());
    if tee {
        ConnTraceTee::new(
            Arc::new(ConnectionTraceRing::new(8)),
            api,
            Arc::new(NoBindings),
        )
        .with_discovery_observation(Arc::clone(pipeline))
        .record(&[], 0);
    } else {
        let consumer = ConnectionObservationConsumer::with_egress(
            api,
            Arc::new(|_| (None, None)),
            Arc::new(|| None),
            false,
        )
        .with_discovery_observation(Arc::clone(pipeline));
        let summary = consumer.consume(&[], SystemTime::now());
        assert_eq!(
            summary.total, 0,
            "an idle pump must not invent connection activity"
        );
    }
    wait_for_workers(pipeline);
}

fn shared_attempt(pipeline: &DiscoveryObservationPipeline, target: Ipv4Addr) {
    let mut seen = observation(Some(OWNER), ConnectionProgress::Attempt);
    seen.remote.set_ip(target.into());
    seen.local.set_port(43000 + u16::from(target.octets()[3]));
    pipeline.observe(&seen, EgressRole::Primary);
    wait_for_workers(pipeline);
}

fn remember_shared_name(pipeline: &DiscoveryObservationPipeline, host: &str, target: Ipv4Addr) {
    pipeline.wiring.names.record_for(OWNER, host, &[target]);
    pipeline
        .wiring
        .names
        .record("foreign-shared-tenant.example", &[target]);
}

#[test]
fn a_new_shared_site_is_not_starved_by_previously_healthy_names_at_the_next_budget_window() {
    let first = "a-fair-warm-0.example";
    let f = fixture(first);
    let healthy: Vec<_> = (0..8).map(|n| format!("a-fair-warm-{n}.example")).collect();
    for host in &healthy {
        f.pipeline.wiring.names.record_for(OWNER, host, &[TARGET]);
    }
    *f.probe
        .primary_answering_hosts
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = healthy;
    let pipeline = Arc::new(f.pipeline);
    shared_attempt(&pipeline, TARGET);
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        8
    );
    let fresh = "himalayas-fair-queue.example";
    let fresh_target = Ipv4Addr::new(203, 0, 113, 88);
    remember_shared_name(&pipeline, fresh, fresh_target);
    shared_attempt(&pipeline, fresh_target);
    assert!(f.engine.candidates(OWNER).is_empty());
    crate::boot_clock::simulate_sleep(Duration::from_secs(300));
    shared_attempt(&pipeline, TARGET);
    idle_discovery_tick(&pipeline, false);
    assert!(
        f.engine
            .candidates(OWNER)
            .iter()
            .any(|candidate| candidate.proposed_match == fresh),
        "fresh deferred work must run before another round of healthy refreshes"
    );
}

#[test]
fn deferred_work_progresses_on_empty_ticks_without_using_the_hosts_day_long_cooldown_as_a_global_budget(
) {
    for tee in [false, true] {
        let mut f = fixture("a-idle-warm-0.example");
        let healthy: Vec<_> = (0..8).map(|n| format!("a-idle-warm-{n}.example")).collect();
        for host in &healthy {
            f.pipeline.wiring.names.record_for(OWNER, host, &[TARGET]);
        }
        *f.probe
            .primary_answering_hosts
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = healthy;
        let wiring = Arc::get_mut(&mut f.pipeline.wiring).expect("unshared wiring");
        wiring.cadence = Arc::new(|_| AutoProbeCadence {
            enabled: true,
            repeat: Duration::from_secs(86400),
        });
        wiring.limits = Arc::new(|_| {
            ProbeLimits::new(Duration::from_millis(300), 8, Duration::from_secs(86400))
        });
        let pipeline = Arc::new(f.pipeline);
        shared_attempt(&pipeline, TARGET);
        let target = Ipv4Addr::new(203, 0, 113, 89);
        let fresh = if tee {
            "idle-tee-new-site.example"
        } else {
            "idle-consumer-new-site.example"
        };
        remember_shared_name(&pipeline, fresh, target);
        shared_attempt(&pipeline, target);
        assert!(f.engine.candidates(OWNER).is_empty());
        crate::boot_clock::simulate_sleep(Duration::from_secs(40));
        idle_discovery_tick(&pipeline, tee);
        assert!(
            f.engine
                .candidates(OWNER)
                .iter()
                .any(|candidate| candidate.proposed_match == fresh),
            "new queued names need an independent refill and an idle pump (tee={tee})"
        );
        crate::boot_clock::simulate_sleep(Duration::from_secs(400));
        shared_attempt(&pipeline, TARGET);
        assert_eq!(
            f.probe
                .calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .filter(|(host, _)| host == "a-idle-warm-0.example")
                .count(),
            1,
            "a day-long per-host cooldown must remain intact"
        );
    }
}

#[test]
fn addresses_per_check_does_not_discard_later_names_from_the_only_observed_connection() {
    for tee in [false, true] {
        let mut f = fixture("a-one-check-0.example");
        for index in 1..4 {
            f.pipeline.wiring.names.record_for(
                OWNER,
                &format!("a-one-check-{index}.example"),
                &[TARGET],
            );
        }
        Arc::get_mut(&mut f.pipeline.wiring)
            .expect("unshared wiring")
            .limits =
            Arc::new(|_| ProbeLimits::new(Duration::from_millis(300), 1, Duration::from_secs(300)));
        let pipeline = Arc::new(f.pipeline);
        shared_attempt(&pipeline, TARGET);
        assert_eq!(f.engine.candidates(OWNER).len(), 1);
        for _ in 0..3 {
            crate::boot_clock::simulate_sleep(Duration::from_secs(2));
            idle_discovery_tick(&pipeline, tee);
        }
        assert_eq!(
            f.engine.candidates(OWNER).len(),
            4,
            "one address per check must leave the rest queued for later empty ticks (tee={tee})"
        );
    }
}

#[test]
fn expired_short_cooldowns_do_not_stop_discovery_after_a_long_running_session() {
    let f = fixture("unused-long-session.example");
    f.probe.primary_answers.store(true, Ordering::Release);
    let pipeline = Arc::new(f.pipeline);
    for index in 0..=MAX_RECENT {
        crate::boot_clock::simulate_sleep(Duration::from_secs(40));
        let target = Ipv4Addr::new(203, 0, (index / 200) as u8, (index % 200 + 1) as u8);
        remember_shared_name(&pipeline, &format!("long-session-{index}.example"), target);
        shared_attempt(&pipeline, target);
    }
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        MAX_RECENT + 1,
        "expired five-minute cooldowns must not occupy the bounded history for a full day"
    );
}

#[test]
fn repeated_pending_observations_keep_fifo_order_without_multiplying_work() {
    let f = fixture("a-fifo-warm-0.example");
    let healthy: Vec<_> = (0..8).map(|n| format!("a-fifo-warm-{n}.example")).collect();
    for host in &healthy {
        f.pipeline.wiring.names.record_for(OWNER, host, &[TARGET]);
    }
    *f.probe
        .primary_answering_hosts
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = healthy;
    let pipeline = Arc::new(f.pipeline);
    shared_attempt(&pipeline, TARGET);
    let first = "z-fifo-first.example";
    let second = "a-fifo-second.example";
    let first_ip = Ipv4Addr::new(203, 0, 113, 90);
    let second_ip = Ipv4Addr::new(203, 0, 113, 91);
    remember_shared_name(&pipeline, first, first_ip);
    remember_shared_name(&pipeline, second, second_ip);
    shared_attempt(&pipeline, first_ip);
    shared_attempt(&pipeline, second_ip);
    for _ in 0..10 {
        shared_attempt(&pipeline, first_ip);
    }
    crate::boot_clock::simulate_sleep(Duration::from_millis(1900));
    idle_discovery_tick(&pipeline, false);
    let offered = f.engine.candidates(OWNER);
    assert!(
        offered
            .iter()
            .any(|candidate| candidate.proposed_match == first),
        "refreshing metadata must not move the oldest waiting name behind a later one"
    );
    assert!(
        !offered
            .iter()
            .any(|candidate| candidate.proposed_match == second),
        "one refill must not turn repeated events into extra network budget"
    );
    crate::boot_clock::simulate_sleep(Duration::from_millis(1900));
    idle_discovery_tick(&pipeline, false);
    assert!(f
        .engine
        .candidates(OWNER)
        .iter()
        .any(|candidate| candidate.proposed_match == second));
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|(host, _)| host == first)
            .count(),
        4
    );
}

#[test]
fn deferred_names_cannot_send_a_probe_after_primary_permission_or_consent_is_revoked() {
    for revoke_consent in [false, true] {
        let mut f = fixture("a-revoked-warm-0.example");
        let healthy: Vec<_> = (0..8)
            .map(|n| format!("a-revoked-warm-{n}.example"))
            .collect();
        for host in &healthy {
            f.pipeline.wiring.names.record_for(OWNER, host, &[TARGET]);
        }
        *f.probe
            .primary_answering_hosts
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = healthy;
        let primary_allowed = Arc::new(AtomicBool::new(true));
        let read = Arc::clone(&primary_allowed);
        Arc::get_mut(&mut f.pipeline.wiring)
            .expect("unshared wiring")
            .primary_default = Arc::new(move |_| read.load(Ordering::Acquire));
        let pipeline = Arc::new(f.pipeline);
        shared_attempt(&pipeline, TARGET);
        let target = Ipv4Addr::new(203, 0, 113, 92);
        remember_shared_name(&pipeline, "deferred-revoked-name.example", target);
        shared_attempt(&pipeline, target);
        if revoke_consent {
            f.enabled.store(false, Ordering::Release);
        } else {
            primary_allowed.store(false, Ordering::Release);
        }
        crate::boot_clock::simulate_sleep(Duration::from_secs(40));
        idle_discovery_tick(&pipeline, false);
        assert_eq!(
            f.probe
                .calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .len(),
            8,
            "a queued diagnostic never overrides current primary privacy or consent"
        );
        assert!(f.engine.candidates(OWNER).is_empty());
    }
}

#[test]
fn the_periodic_observer_pumps_queued_discovery_on_an_empty_drain_without_reapplying_routes() {
    use crate::conn_observation_consumer::{
        ConnTraceTee, ConnectionObservationConsumer, ConnectionTraceRing,
    };
    use crate::service_tasks::{build_app_observation_task, AppObservationWiring};
    struct NoBindings;
    impl nrr_platform_api::enforcement::EgressBindingSource for NoBindings {
        fn bindings_for(
            &self,
            _: &nrr_platform_api::enforcement::UserPrincipal,
        ) -> nrr_platform_api::enforcement::EgressBinding {
            nrr_platform_api::enforcement::EgressBinding::default()
        }
    }
    for tee in [false, true] {
        let mut f = fixture("a-periodic-pump.example");
        f.pipeline
            .wiring
            .names
            .record_for(OWNER, "b-periodic-pump.example", &[TARGET]);
        Arc::get_mut(&mut f.pipeline.wiring)
            .expect("unshared wiring")
            .limits =
            Arc::new(|_| ProbeLimits::new(Duration::from_millis(300), 1, Duration::from_secs(300)));
        let pipeline = Arc::new(f.pipeline);
        shared_attempt(&pipeline, TARGET);
        assert_eq!(f.engine.candidates(OWNER).len(), 1);
        let api = Arc::new(nrr_platform_api::windows_api::MockWindowsApi::new());
        let ring = Arc::new(ConnectionTraceRing::new(8));
        let (consumer, trace) = if tee {
            (
                None,
                Some(Arc::new(
                    ConnTraceTee::new(Arc::clone(&ring), api, Arc::new(NoBindings))
                        .with_discovery_observation(Arc::clone(&pipeline)),
                )),
            )
        } else {
            (
                Some(Arc::new(
                    ConnectionObservationConsumer::with_egress(
                        api,
                        Arc::new(|_| (None, None)),
                        Arc::new(|| None),
                        false,
                    )
                    .with_discovery_observation(Arc::clone(&pipeline)),
                )),
                None,
            )
        };
        let store = Arc::new(crate::app_observation_lookup::AppObservationStore::new());
        let wiring = AppObservationWiring {
            source: Arc::new(
                nrr_platform_api::conn_observe::MockConnectionObservationSource::new(),
            ),
            store: Arc::clone(&store),
            consumer,
            trace,
            scripts: None,
        };
        let applied = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&applied);
        let mut task = build_app_observation_task(
            wiring,
            Some(Arc::new(move || {
                count.fetch_add(1, Ordering::Relaxed);
            })),
        );
        crate::boot_clock::simulate_sleep(Duration::from_secs(2));
        assert_eq!(
            (task.tick)(&crate::lifecycle::StopToken::new()),
            crate::runtime_loop::TaskOutcome::Continue
        );
        wait_for_workers(&pipeline);
        assert_eq!(f.engine.candidates(OWNER).len(), 2, "the periodic task must reach pending discovery even when its source is empty (tee={tee})");
        assert_eq!(
            applied.load(Ordering::Relaxed),
            0,
            "an idle diagnostic does not apply routing policy"
        );
        assert_eq!(
            ring.snapshot(0, 8).1,
            0,
            "an idle diagnostic does not invent trace rows"
        );
    }
}

fn close(f: &Fixture, owner: Option<&str>, progress: ConnectionProgress) {
    f.pipeline.observe(
        &observation(owner, ConnectionProgress::Attempt),
        EgressRole::Primary,
    );
    f.pipeline
        .observe(&observation(None, progress), EgressRole::Primary);
    let deadline = Instant::now() + Duration::from_secs(3);
    while f.pipeline.workers.load(Ordering::Acquire) > 0 {
        assert!(
            Instant::now() < deadline,
            "confirmation must finish off the observation path"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn an_unknown_close_confirms_a_ruleless_site_before_any_candidate_exists() {
    let host = "close-without-candidate.example";
    let f = fixture(host);
    let stalls = crate::primary_stall_registry::global_primary_stalls();
    stalls.note(
        OWNER,
        host,
        nrr_domain::companion_affinity::PrimaryHealthEvent::Completed,
    );
    assert!(f.engine.candidates(OWNER).is_empty());
    close(&f, Some(OWNER), ConnectionProgress::ClosedUnknown);
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        4
    );
    assert_eq!(
        stalls.behavior_of(OWNER, host),
        nrr_domain::companion_affinity::PrimaryBehavior::Stalls
    );
    let candidates = f.engine.candidates(OWNER);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].secondary_reach, Some(true));
    assert!(f.engine.candidates(OTHER).is_empty());
}

#[test]
fn a_tls_response_leaves_the_real_browser_failure_unsettled() {
    let host = "tls-recovered.example";
    let f = fixture(host);
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    assert_eq!(f.engine.candidates(OWNER).len(), 1);
    f.probe.primary_answers.store(true, Ordering::Release);
    DiscoveryObservationPipeline::confirm(
        &f.pipeline.wiring,
        Confirmation {
            owner: OWNER.into(),
            host: host.into(),
            destination: "flow".into(),
            target: TARGET,
            source: PRIMARY,
            secondary: Some(SECONDARY),
            timeout: Duration::from_millis(300),
            process: Some("C:\\Browser\\browser.exe".into()),
            shared_address: false,
        },
    );
    assert_eq!(
        f.engine.candidates(OWNER).len(),
        1,
        "TLS reachability does not prove recovery of the browser's HTTP exchange"
    );
}

#[test]
fn resets_do_not_probe_without_consent_or_a_known_connection_owner() {
    let f = fixture("no-consent.example");
    f.enabled.store(false, Ordering::Release);
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    assert!(f
        .probe
        .calls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty());
    assert!(f.engine.candidates(OWNER).is_empty());
    let f = fixture("unowned-closure.example");
    close(&f, None, ConnectionProgress::Reset);
    assert!(f
        .probe
        .calls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty());
}

#[test]
fn a_foreign_shared_name_never_becomes_the_owners_probe_or_offer() {
    let f = fixture("ambiguous-closure.example");
    f.pipeline
        .wiring
        .names
        .record("other-cdn-tenant.example", &[TARGET]);
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    let candidates = f.engine.candidates(OWNER);
    assert_eq!(
        candidates.len(),
        1,
        "the owner's name gets its own independent TLS check"
    );
    assert_eq!(candidates[0].proposed_match, "ambiguous-closure.example");
    assert_eq!(candidates[0].match_kind, "exact");
    assert!(f
        .probe
        .calls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .all(|(host, _)| host == "ambiguous-closure.example"));
    assert_eq!(f.pipeline.name_for_owner(Some(OWNER), TARGET), None);
}

#[test]
fn our_own_block_never_starts_confirmation() {
    for mode in [
        nrr_storage::auto_rules::AutoRulesMode::Suggest,
        nrr_storage::auto_rules::AutoRulesMode::Off,
    ] {
        let f = fixture_in_mode("own-block-closure.example", mode);
        f.pipeline
            .wiring
            .names
            .record_for(OWNER, "own-block-shared-neighbor.example", &[TARGET]);
        let mut dropped = observation(Some(OWNER), ConnectionProgress::Attempt);
        dropped.blocked_by_nrr = Some(true);
        f.pipeline.observe(&dropped, EgressRole::Primary);
        f.pipeline.observe(
            &observation(None, ConnectionProgress::Reset),
            EgressRole::Primary,
        );
        assert!(f
            .probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty());
        let snapshot = f.engine.discovery_snapshot(OWNER, SystemTime::now());
        assert_eq!(
            snapshot.episodes[0].reason, "own-block",
            "our own filter remains the cause even with discovery off"
        );
    }
}

#[test]
fn an_owned_shared_address_offers_only_the_name_with_independently_verified_path_failure() {
    let host = "shared-path-failure.example";
    let neighbor = "working-shared-neighbor.example";
    let f = fixture(host);
    f.pipeline
        .wiring
        .names
        .record_for(OWNER, neighbor, &[TARGET]);
    f.probe
        .primary_answering_hosts
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .push(neighbor.into());
    close(&f, Some(OWNER), ConnectionProgress::ClosedUnknown);
    let candidates = f.engine.candidates(OWNER);
    assert_eq!(
        candidates.len(),
        1,
        "shared IP must not silence a verified name-specific failure"
    );
    let candidate = &candidates[0];
    assert_eq!(candidate.proposed_match, host);
    assert_eq!(
        candidate.match_kind, "exact",
        "a measured name must not widen to a suffix"
    );
    assert_eq!(candidate.signal, "shared-address-reachability");
    assert_eq!(candidate.secondary_reach, Some(true));
    assert_eq!(
        candidate.observations, None,
        "probing is not a browser visit"
    );
    assert!(candidate.consumers.is_empty());
    assert!(candidate.observed_members.is_empty());
    assert!(f.engine.candidates(OTHER).is_empty());
    assert_eq!(
        f.pipeline.name_for_owner(Some(OWNER), TARGET),
        None,
        "the connection remains unnamed"
    );
    let calls = f.probe.calls.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(
        calls
            .iter()
            .filter(|(name, source)| name == host && *source == PRIMARY)
            .count(),
        3
    );
    assert_eq!(
        calls
            .iter()
            .filter(|(name, source)| name == host && *source == SECONDARY)
            .count(),
        1
    );
    assert_eq!(calls.iter().filter(|(name, _)| name == neighbor).count(), 1);
}

#[test]
fn independently_verified_shared_names_stay_review_only_in_automatic_mode() {
    let host = "shared-review-only.example";
    let f = fixture_in_mode(host, nrr_storage::auto_rules::AutoRulesMode::Auto);
    f.pipeline
        .wiring
        .names
        .record_for(OWNER, "shared-review-neighbor.example", &[TARGET]);
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    let candidates = f.engine.candidates(OWNER);
    assert_eq!(
        candidates.len(),
        2,
        "each name has its own verified path finding"
    );
    assert!(candidates
        .iter()
        .all(|candidate| candidate.match_kind == "exact"));
    assert_eq!(f.engine.tick(OWNER, SystemTime::now()).authored, 0);
    assert_eq!(
        f.engine.candidates(OWNER).len(),
        2,
        "automatic mode must retain findings for review"
    );
}

#[test]
fn shared_path_findings_do_not_credit_browser_health_or_navigation() {
    let host = "shared-no-visit-credit.example";
    let f = fixture(host);
    f.pipeline
        .wiring
        .names
        .record_for(OWNER, "shared-no-credit-neighbor.example", &[TARGET]);
    let stalls = crate::primary_stall_registry::global_primary_stalls();
    let before = stalls.behavior_of(OWNER, host);
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    assert_eq!(f.engine.candidates(OWNER).len(), 2);
    assert_eq!(
        stalls.behavior_of(OWNER, host),
        before,
        "a diagnostic probe is not the browser's health event"
    );
    assert!(f.engine.seen_with(OWNER, host, 8).is_empty());
}

#[test]
fn a_shared_address_with_both_links_failing_cannot_offer_any_name() {
    let f = fixture("shared-both-fail.example");
    f.pipeline
        .wiring
        .names
        .record_for(OWNER, "shared-both-fail-neighbor.example", &[TARGET]);
    f.probe.secondary_silent.store(true, Ordering::Release);
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    assert!(f.engine.candidates(OWNER).is_empty());
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        8
    );
}

#[test]
fn a_single_shared_failure_investigates_all_bounded_names_without_dropping_later_tenants() {
    let f = fixture("shared-batch-0.example");
    for index in 1..8 {
        f.pipeline.wiring.names.record_for(
            OWNER,
            &format!("shared-batch-{index}.example"),
            &[TARGET],
        );
    }
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    assert_eq!(
        f.engine.candidates(OWNER).len(),
        8,
        "worker limit must not lose later names from the same investigation"
    );
    assert_eq!(f.pipeline.workers.load(Ordering::Acquire), 0);
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        32
    );
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        32,
        "each name keeps its own cooldown"
    );
}

#[test]
fn an_attempted_shared_address_can_be_verified_without_unavailable_close_events() {
    struct Bound;
    impl nrr_platform_api::enforcement::EgressBindingSource for Bound {
        fn bindings_for(
            &self,
            _: &nrr_platform_api::enforcement::UserPrincipal,
        ) -> nrr_platform_api::enforcement::EgressBinding {
            nrr_platform_api::enforcement::EgressBinding {
                primary: Some("primary".into()),
                secondary: None,
            }
        }
    }
    for tee_path in [false, true] {
        let host = format!("shared-attempt-tee-{tee_path}.example");
        let f = fixture(&host);
        f.pipeline
            .wiring
            .names
            .record("foreign-timeout-neighbor.example", &[TARGET]);
        let pipeline = Arc::new(f.pipeline);
        let api = nrr_platform_api::windows_api::MockWindowsApi::new();
        api.set_adapter_infos(vec![nrr_platform_api::adapters::AdapterInfo {
            index: 7,
            adapter_name: "primary".into(),
            description: "primary".into(),
            friendly_name: "primary".into(),
            mac: None,
            interface_type: nrr_platform_api::adapters::InterfaceType::Ethernet,
            oper_status: nrr_platform_api::adapters::IfOperStatus::Up,
            ipv4_addresses: vec![PRIMARY],
            ipv6_addresses: Vec::new(),
            gateways: vec![Ipv4Addr::new(192, 0, 2, 1)],
        }]);
        let batch = [observation(Some(OWNER), ConnectionProgress::Attempt)];
        if tee_path {
            let tee = crate::conn_observation_consumer::ConnTraceTee::new(
                Arc::new(crate::conn_observation_consumer::ConnectionTraceRing::new(
                    8,
                )),
                Arc::new(api),
                Arc::new(Bound),
            )
            .with_discovery_observation(Arc::clone(&pipeline));
            tee.record(&batch, 3_000);
        } else {
            let consumer =
                crate::conn_observation_consumer::ConnectionObservationConsumer::with_egress(
                    Arc::new(api),
                    Arc::new(|_| (Some(7), None)),
                    Arc::new(|| Some(OWNER.into())),
                    false,
                )
                .with_discovery_observation(Arc::clone(&pipeline));
            consumer.consume(&batch, SystemTime::now());
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while pipeline.workers.load(Ordering::Acquire) > 0 {
            assert!(
                Instant::now() < deadline,
                "bounded timeout investigation must finish"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(f.engine.candidates(OWNER).len(), 1, "an independently verified shared name must not depend on unavailable close events (tee={tee_path})");
    }
}

#[test]
fn a_shared_probe_cannot_publish_after_policy_or_consent_changes_during_the_secondary_probe() {
    for consent_changes in [false, true] {
        let host = if consent_changes {
            "shared-revoked-consent.example"
        } else {
            "shared-revoked-primary.example"
        };
        let mut f = fixture(host);
        f.pipeline
            .wiring
            .names
            .record("foreign-policy-neighbor.example", &[TARGET]);
        let permission = Arc::new(AtomicBool::new(true));
        let read = Arc::clone(&permission);
        Arc::get_mut(&mut f.pipeline.wiring)
            .expect("unshared fixture wiring")
            .primary_default = Arc::new(move |_| read.load(Ordering::Acquire));
        let revoke = if consent_changes {
            Arc::clone(&f.enabled)
        } else {
            permission
        };
        *f.probe
            .after_secondary
            .lock()
            .unwrap_or_else(|p| p.into_inner()) =
            Some(Arc::new(move || revoke.store(false, Ordering::Release)));
        close(&f, Some(OWNER), ConnectionProgress::Reset);
        assert_eq!(
            f.probe
                .calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .len(),
            4
        );
        assert!(
            f.engine.candidates(OWNER).is_empty(),
            "publication must recheck the owner's current permissions"
        );
    }
}

#[test]
fn global_dns_cache_names_cannot_be_borrowed_for_an_owners_shared_probe() {
    let mut f = fixture("unused-owned-name.example");
    let names = Arc::new(ObservedHostNames::new());
    names.record("global-only-first.example", &[TARGET]);
    names.record("global-only-second.example", &[TARGET]);
    Arc::get_mut(&mut f.pipeline.wiring)
        .expect("unshared fixture wiring")
        .names = names;
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    assert!(f
        .probe
        .calls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty());
    assert!(f.engine.candidates(OWNER).is_empty());
}

#[test]
fn a_shared_finding_is_withdrawn_when_primary_recovers_or_secondary_stops_answering() {
    for primary_recovers in [false, true] {
        let host = if primary_recovers {
            "shared-primary-recovers.example"
        } else {
            "shared-secondary-stops.example"
        };
        let f = fixture(host);
        f.pipeline
            .wiring
            .names
            .record("foreign-recovery-neighbor.example", &[TARGET]);
        close(&f, Some(OWNER), ConnectionProgress::Reset);
        assert_eq!(f.engine.candidates(OWNER).len(), 1);
        f.probe
            .primary_answers
            .store(primary_recovers, Ordering::Release);
        f.probe
            .secondary_silent
            .store(!primary_recovers, Ordering::Release);
        DiscoveryObservationPipeline::confirm(
            &f.pipeline.wiring,
            Confirmation {
                owner: OWNER.into(),
                host: host.into(),
                destination: "recheck".into(),
                target: TARGET,
                source: PRIMARY,
                secondary: Some(SECONDARY),
                timeout: Duration::from_millis(300),
                process: Some("C:\\Browser\\browser.exe".into()),
                shared_address: true,
            },
        );
        assert!(
            f.engine.candidates(OWNER).is_empty(),
            "both route measurements must still support a pending finding"
        );
    }
}

#[test]
fn an_answer_on_a_repeated_primary_probe_withdraws_the_shared_finding() {
    for silences in [1, 2] {
        let host = format!("shared-primary-repeat-{silences}-recovers.example");
        let f = fixture(&host);
        f.pipeline
            .wiring
            .names
            .record("foreign-repeat-neighbor.example", &[TARGET]);
        close(&f, Some(OWNER), ConnectionProgress::Reset);
        assert_eq!(f.engine.candidates(OWNER).len(), 1);
        f.probe
            .primary_verdicts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend(
                std::iter::repeat_n(PathVerdict::Silent, silences).chain([PathVerdict::Answered]),
            );
        DiscoveryObservationPipeline::confirm(
            &f.pipeline.wiring,
            Confirmation {
                owner: OWNER.into(),
                host,
                destination: "recheck".into(),
                target: TARGET,
                source: PRIMARY,
                secondary: Some(SECONDARY),
                timeout: Duration::from_millis(300),
                process: Some("C:\\Browser\\browser.exe".into()),
                shared_address: true,
            },
        );
        assert!(
            f.engine.candidates(OWNER).is_empty(),
            "one primary answer contradicts the shared-path finding even after an initial silence"
        );
    }
}

#[test]
fn a_secondary_failure_does_not_turn_repeated_resets_into_a_route_offer() {
    let f = fixture("both-routes-fail.example");
    f.probe.secondary_silent.store(true, Ordering::Release);
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    assert!(f.engine.candidates(OWNER).is_empty());
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        4,
        "retries obey the per-host cadence"
    );
}

#[test]
fn another_user_has_their_own_confirmation_budget() {
    let f = fixture("separate-budget.example");
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    close(&f, Some(OTHER), ConnectionProgress::Reset);
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        8
    );
    assert_eq!(f.engine.candidates(OWNER).len(), 1);
    assert_eq!(f.engine.candidates(OTHER).len(), 1);
}

#[test]
fn an_ip_rule_prevents_a_service_probe_from_bypassing_the_users_route() {
    use nrr_domain::canonical::{
        CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalRule,
        CanonicalRuleSet,
    };
    let subnet = nrr_shared::ip_block::IpBlock::parse("203.0.113.0/24")
        .unwrap_or_else(|| panic!("valid subnet fixture"));
    for (address_match, app_match, action) in [
        (
            Some(CanonicalAddressMatch::ExactIp(TARGET.into())),
            None,
            nrr_domain::RuleAction::Route,
        ),
        (
            Some(CanonicalAddressMatch::Subnet(subnet)),
            None,
            nrr_domain::RuleAction::Route,
        ),
        (
            Some(CanonicalAddressMatch::Zone("example".into())),
            None,
            nrr_domain::RuleAction::Route,
        ),
        (
            None,
            Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact("browser.exe".into()),
                include_child_processes: false,
                override_requested: false,
            }),
            nrr_domain::RuleAction::Route,
        ),
        (
            Some(CanonicalAddressMatch::ExactIp(TARGET.into())),
            None,
            nrr_domain::RuleAction::Block,
        ),
    ] {
        let f = fixture("address-owned.example");
        f.rules
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .rule_book
            .secondary = CanonicalRuleSet::from_rules(vec![CanonicalRule {
            id: nrr_domain::RuleId("guard-address".into()),
            enabled: true,
            address_match,
            app_match,
            comment: String::new(),
            action,
            origin: None,
        }]);
        close(&f, Some(OWNER), ConnectionProgress::Reset);
        assert!(f
            .probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty());
    }
}

#[test]
fn a_default_secondary_policy_never_sends_the_name_over_primary() {
    for shared in [false, true] {
        let mut f = fixture(if shared {
            "shared-default-secondary.example"
        } else {
            "default-secondary.example"
        });
        if shared {
            f.pipeline
                .wiring
                .names
                .record("foreign-secondary-neighbor.example", &[TARGET]);
        }
        let Some(wiring) = Arc::get_mut(&mut f.pipeline.wiring) else {
            panic!("unshared fixture wiring");
        };
        wiring.primary_default = Arc::new(|_| false);
        close(&f, Some(OWNER), ConnectionProgress::Reset);
        assert!(f
            .probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty());
        assert!(f.engine.candidates(OWNER).is_empty());
    }
}

#[test]
fn automatic_probe_consent_is_checked_for_the_flow_owner() {
    let mut f = fixture("per-owner-consent.example");
    let Some(wiring) = Arc::get_mut(&mut f.pipeline.wiring) else {
        panic!("unshared fixture wiring");
    };
    wiring.cadence = Arc::new(|owner| AutoProbeCadence {
        enabled: owner == OTHER,
        repeat: Duration::from_secs(300),
    });
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    assert!(f
        .probe
        .calls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty());
    close(&f, Some(OTHER), ConnectionProgress::Reset);
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        4
    );
    assert!(f.engine.candidates(OWNER).is_empty());
    assert_eq!(f.engine.candidates(OTHER).len(), 1);
}

#[test]
fn a_connection_flood_cannot_exceed_the_safety_bucket_or_two_workers() {
    let f = fixture("budget-flood.example");
    let now = BootInstant::now();
    let repeat = Duration::from_secs(300);
    let mut reservations = Vec::new();
    for index in 0..scheduler::SAFETY_BURST {
        reservations.push(
            f.pipeline
                .reserve_for_batch(
                    OWNER,
                    &format!("warm-{index}.example"),
                    repeat,
                    now,
                    index == 0,
                )
                .expect("initial safety allowance"),
        );
    }
    assert_eq!(
        f.pipeline
            .reserve(OWNER, "second.example", repeat, now)
            .err(),
        Some(ReservationRefusal::BudgetExhausted)
    );
    assert_eq!(
        f.pipeline
            .reserve(OTHER, "third.example", repeat, now)
            .err(),
        Some(ReservationRefusal::BudgetExhausted)
    );
    for reservation in &reservations {
        f.pipeline
            .memory
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .release(reservation, true, now, false);
    }
    f.pipeline.workers.store(0, Ordering::Release);
    assert_eq!(
        f.pipeline
            .reserve(
                OWNER,
                "warm-0.example",
                repeat,
                now.checked_sub(Duration::from_secs(1)).unwrap_or(now)
            )
            .err(),
        Some(ReservationRefusal::Cooldown)
    );
    assert!(
        f.pipeline
            .reserve(
                OWNER,
                "second.example",
                repeat,
                now + Duration::from_secs(40)
            )
            .is_ok(),
        "the independent safety budget refills continuously"
    );
    assert!(f
        .pipeline
        .reserve(
            OTHER,
            "third.example",
            repeat,
            now + Duration::from_secs(40)
        )
        .is_ok());
    assert_eq!(
        f.pipeline
            .reserve(
                "S-1-5-21-3212-1003",
                "fourth.example",
                repeat,
                now + Duration::from_secs(40)
            )
            .err(),
        Some(ReservationRefusal::WorkersBusy)
    );
}

#[test]
fn a_reused_tuple_never_borrows_another_users_process_or_a_retired_flow() {
    let f = fixture("reused-flow-owner.example");
    f.enabled.store(false, Ordering::Release);
    f.pipeline.observe(
        &observation(Some(OWNER), ConnectionProgress::Attempt),
        EgressRole::Primary,
    );
    f.enabled.store(true, Ordering::Release);
    f.pipeline.observe(
        &observation(Some(OTHER), ConnectionProgress::Reset),
        EgressRole::Primary,
    );
    assert!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty(),
        "Bob supplied no process context; Alice's browser must not authorize his probe"
    );
    assert!(f
        .pipeline
        .memory
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .flows
        .is_empty());
    f.pipeline.observe(
        &observation(None, ConnectionProgress::Reset),
        EgressRole::Primary,
    );
    assert!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty(),
        "an already closed flow cannot name a later tuple reuse"
    );
}

#[test]
fn an_unidentified_new_connection_cannot_inherit_the_previous_users_probe_authority() {
    let f = fixture("unidentified-tuple-reuse.example");
    f.pipeline.observe(
        &observation(Some(OWNER), ConnectionProgress::Attempt),
        EgressRole::Primary,
    );
    let mut unknown = observation(None, ConnectionProgress::Attempt);
    unknown.pid = 0;
    unknown.process_path = None;
    f.pipeline.observe(&unknown, EgressRole::Primary);
    unknown.progress = ConnectionProgress::Reset;
    f.pipeline.observe(&unknown, EgressRole::Primary);
    let deadline = Instant::now() + Duration::from_secs(3);
    while f.pipeline.workers.load(Ordering::Acquire) > 0 {
        assert!(Instant::now() < deadline, "confirmation must finish");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(f.probe.calls.lock().unwrap_or_else(|p| p.into_inner()).is_empty(),
        "a new connection with no owner must not probe using the previous user's identity or process");
    assert!(f.engine.candidates(OWNER).is_empty());
}

#[test]
fn a_udp_socket_cannot_replace_the_owner_of_a_tcp_confirmation() {
    let f = fixture("udp-cannot-own-tcp.example");
    f.enabled.store(false, Ordering::Release);
    f.pipeline.observe(
        &observation(Some(OWNER), ConnectionProgress::Attempt),
        EgressRole::Primary,
    );
    let mut datagram = observation(Some(OTHER), ConnectionProgress::Attempt);
    datagram.protocol = TransportProtocol::Udp;
    f.pipeline.observe(&datagram, EgressRole::Primary);
    let memory = f.pipeline.memory.lock().unwrap_or_else(|p| p.into_inner());
    assert!(memory.flows.values().all(|flow| flow.owner == OWNER));
    assert!(f
        .probe
        .calls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty());
}

#[test]
fn a_sleep_expired_flow_cannot_attribute_a_new_ownerless_close() {
    let f = fixture("expired-flow.example");
    f.pipeline.observe(
        &observation(Some(OWNER), ConnectionProgress::Attempt),
        EgressRole::Primary,
    );
    crate::boot_clock::simulate_sleep(FLOW_TTL + Duration::from_secs(1));
    f.pipeline.observe(
        &observation(None, ConnectionProgress::Reset),
        EgressRole::Primary,
    );
    assert!(f
        .probe
        .calls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty());
    assert!(f
        .pipeline
        .memory
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .flows
        .is_empty());
}

#[test]
fn disabled_discovery_remains_the_final_reason_for_a_reset_even_without_auto_probes() {
    let f = fixture_in_mode(
        "disabled-reset.example",
        nrr_storage::auto_rules::AutoRulesMode::Off,
    );
    f.enabled.store(false, Ordering::Release);
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    assert!(f
        .probe
        .calls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty());
    let snapshot = f.engine.discovery_snapshot(OWNER, SystemTime::now());
    assert_eq!(snapshot.episodes.len(), 1);
    assert_eq!(snapshot.episodes[0].reason, "discovery-disabled");
    assert_eq!(snapshot.episodes[0].state, "not-created");
}

#[test]
fn busy_confirmation_workers_keep_work_queued_instead_of_claiming_a_running_probe() {
    let f = fixture("worker-capacity.example");
    f.pipeline.workers.store(MAX_WORKERS, Ordering::Release);
    f.pipeline.observe(
        &observation(Some(OWNER), ConnectionProgress::Attempt),
        EgressRole::Primary,
    );
    f.pipeline.observe(
        &observation(None, ConnectionProgress::Reset),
        EgressRole::Primary,
    );
    let snapshot = f.engine.discovery_snapshot(OWNER, SystemTime::now());
    assert_eq!(snapshot.episodes[0].reason, "probe-queued");
    assert!(f
        .probe
        .calls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty());
    assert_eq!(f.pipeline.workers.load(Ordering::Acquire), MAX_WORKERS);
}

#[test]
fn a_recent_success_explains_why_a_new_reset_did_not_start_another_probe() {
    let f = fixture("recent-answer-reset.example");
    f.probe.primary_answers.store(true, Ordering::Release);
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    close(&f, Some(OWNER), ConnectionProgress::Reset);
    let snapshot = f.engine.discovery_snapshot(OWNER, SystemTime::now());
    assert_eq!(snapshot.episodes[0].reason, "probe-queued");
    assert_eq!(
        f.probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        1
    );
}

#[test]
fn a_full_rate_budget_or_history_keeps_valid_work_queued() {
    for memory_full in [false, true] {
        let host = if memory_full {
            "full-probe-memory.example"
        } else {
            "full-probe-budget.example"
        };
        let f = fixture(host);
        let now = BootInstant::now();
        {
            let mut memory = f.pipeline.memory.lock().unwrap_or_else(|p| p.into_inner());
            if memory_full {
                for index in 0..MAX_RECENT {
                    memory.recent.insert(
                        (OWNER.to_owned(), format!("h{index}.example")),
                        Recent {
                            at: now,
                            repeat: Duration::from_secs(300),
                            last_probe_started_unix_ms: None,
                        },
                    );
                }
            } else {
                memory.budgets.insert(OWNER.to_owned(), Bucket::empty(now));
            }
        }
        close(&f, Some(OWNER), ConnectionProgress::Reset);
        let snapshot = f.engine.discovery_snapshot(OWNER, SystemTime::now());
        assert_eq!(snapshot.episodes[0].reason, "probe-queued");
        assert!(f
            .probe
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty());
    }
}

#[test]
fn a_thread_start_failure_reports_the_error_and_does_not_spend_the_retry_budget() {
    let host = "failed-probe-thread.example";
    let f = fixture(host);
    let now = BootInstant::now();
    let repeat = Duration::from_secs(300);
    let reservation = f
        .pipeline
        .reserve(OWNER, host, repeat, now)
        .unwrap_or_else(|reason| panic!("initial reservation: {reason:?}"));
    f.pipeline.start_confirmation(
        Confirmation {
            owner: OWNER.to_owned(),
            host: host.to_owned(),
            destination: "controlled-flow".to_owned(),
            target: TARGET,
            source: PRIMARY,
            secondary: Some(SECONDARY),
            timeout: Duration::from_millis(300),
            process: Some("C:\\Browser\\browser.exe".to_owned()),
            shared_address: false,
        },
        reservation,
        |_| Err(std::io::Error::other("thread creation refused")),
    );
    let snapshot = f.engine.discovery_snapshot(OWNER, SystemTime::now());
    assert_eq!(snapshot.episodes[0].reason, "probe-start-failed");
    assert_eq!(snapshot.episodes[0].state, "not-created");
    assert_eq!(f.pipeline.workers.load(Ordering::Acquire), 0);
    assert!(f
        .probe
        .calls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty());
    let retry = f
        .pipeline
        .reserve(OWNER, host, repeat, now)
        .unwrap_or_else(|reason| {
            panic!("a probe that never started must remain retryable: {reason:?}")
        });
    f.pipeline.rollback_reservation(retry);
}
