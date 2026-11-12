use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use nrr_service_runtime::auto_rules::{
    AutoRulesEngine, InMemoryDismissalStore, InMemoryPendingStore,
};
use nrr_service_runtime::discovery_observation::{
    DiscoveryObservationPipeline, DiscoveryObservationWiring,
};
use nrr_service_runtime::observed_host_names::ObservedHostNames;
use nrr_service_runtime::path_probe::{PathProbe, PathVerdict, ProbeLimits};
use nrr_service_runtime::per_sid_orchestrator::{ActiveRulesSnapshot, RulesProvider};
use nrr_service_runtime::production_auto_rule_probe::EgressSources;
use nrr_service_runtime::service_tasks::{build_app_observation_task, AutoProbeCadence};

const MAIN: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 5);
const SECONDARY: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);
const TARGET: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 77);

struct Rules;
impl RulesProvider for Rules {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        Some(ActiveRulesSnapshot::default())
    }
}

struct Links(Arc<AtomicBool>);
impl EgressSources for Links {
    fn egress_source_ips(&self, owner: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        if owner == bob() {
            (
                Some(MAIN),
                self.0.load(Ordering::Acquire).then_some(SECONDARY),
            )
        } else {
            (Some(MAIN), None)
        }
    }
}

#[derive(Default)]
struct Probe(Mutex<Vec<(String, Ipv4Addr)>>);
impl PathProbe for Probe {
    fn probe(&self, _: Ipv4Addr, _: u16, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
        panic!("a shared address needs a name-specific TLS check")
    }

    fn probe_tls(
        &self,
        target: Ipv4Addr,
        host: &str,
        source: Option<Ipv4Addr>,
        _: Duration,
    ) -> PathVerdict {
        assert_eq!(target, TARGET);
        let Some(source) = source else {
            panic!("the check must bind its configured route");
        };
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((host.into(), source));
        match source {
            MAIN => PathVerdict::Silent,
            SECONDARY => PathVerdict::Answered,
            _ => panic!("an unconfigured source must never be probed"),
        }
    }
}

fn pipeline() -> (
    Arc<DiscoveryObservationPipeline>,
    Arc<AutoRulesEngine>,
    Arc<Probe>,
    Arc<AtomicBool>,
) {
    let rules = Arc::new(Rules);
    let engine = Arc::new(AutoRulesEngine::new(
        rules.clone(),
        Arc::new(|_| nrr_storage::auto_rules::AutoRulesMode::Auto),
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::now(),
    ));
    let names = Arc::new(ObservedHostNames::new());
    for host in ["a-nflog-owned.example", "b-nflog-owned.example"] {
        names.record_for(&bob(), host, &[TARGET]);
    }
    names.record_for(&alice(), "foreign-owner.example", &[TARGET]);
    let probe = Arc::new(Probe::default());
    let secondary = Arc::new(AtomicBool::new(true));
    let pipeline = Arc::new(DiscoveryObservationPipeline::new(
        DiscoveryObservationWiring {
            engine: Arc::clone(&engine),
            rules,
            names,
            egress: Arc::new(Links(Arc::clone(&secondary))),
            probe: probe.clone(),
            cadence: Arc::new(|_| AutoProbeCadence {
                enabled: true,
                repeat: Duration::from_secs(300),
            }),
            limits: Arc::new(|_| {
                ProbeLimits::new(Duration::from_millis(300), 1, Duration::from_secs(300))
            }),
            primary_default: Arc::new(|_| true),
            passive_reset_available: false,
            os_cache_available: true,
        },
    ));
    (pipeline, engine, probe, secondary)
}

fn wait_until(mut ready: impl FnMut() -> bool, promise: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !ready() {
        assert!(Instant::now() < deadline, "{promise}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn discovery_survives_wiring(reports_start: bool) {
    // Each case starts with one queued name after the per-check cap of one.
    for unrelated_udp in [false, true] {
        let (pipeline, engine, probe, _) = pipeline();
        let rig = rig_with_discovery(reports_start, Some(Arc::clone(&pipeline)));
        // A plan must read the application before learning can change its routes.
        assert!(rig.store.ips_for_app("browser").is_empty());
        let source = Arc::clone(&rig.socket_table);
        let ring = Arc::clone(&rig.ring);
        let progress = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&progress);
        let mut task = build_app_observation_task(
            rig.wiring,
            Some(Arc::new(move || {
                count.fetch_add(1, Ordering::Relaxed);
            })),
        );
        let tick = |task: &mut nrr_service_runtime::runtime_loop::ServiceTask| {
            (task.tick)(&nrr_service_runtime::lifecycle::StopToken::new());
        };
        source.push(connection(&bob(), 77));
        tick(&mut task);
        wait_until(
            || engine.candidates(&bob()).len() == 1,
            "the actual Linux wiring must retain discovery when NFLOG starts or fails",
        );
        assert_eq!(
            progress.load(Ordering::Relaxed),
            1,
            "only learning the real application destination re-drives policy"
        );
        progress.store(0, Ordering::Relaxed);
        if unrelated_udp {
            let mut unrelated = connection(&bob(), 88);
            unrelated.protocol = TransportProtocol::Udp;
            unrelated.process_path = None;
            source.push(unrelated);
        }
        // Retry periodic ticks if the previous worker is still releasing its slot.
        wait_until(
            || {
                tick(&mut task);
                engine.candidates(&bob()).len() == 2
            },
            "empty and unrelated ticks must advance the same persistent queue",
        );
        assert_eq!(
            progress.load(Ordering::Relaxed),
            0,
            "diagnostic progress must not apply routes"
        );
        assert!(
            engine.candidates(&alice()).is_empty(),
            "a DNS neighbour belongs to its own user"
        );
        for candidate in engine.candidates(&bob()) {
            assert_eq!(
                candidate.signal,
                nrr_shared::ipc_payloads::AUTO_RULE_SIGNAL_SHARED_ADDRESS_REACHABILITY
            );
            assert_eq!(
                candidate.match_kind,
                nrr_shared::ipc_payloads::AUTO_RULE_MATCH_KIND_EXACT
            );
            assert!(engine
                .seen_with(&bob(), &candidate.proposed_match, 8)
                .is_empty());
        }
        assert_eq!(
            ring.snapshot(0, 64).1,
            if unrelated_udp { 2 } else { 1 },
            "idle ticks must not invent trace rows"
        );
        let calls = probe.0.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(
            calls.len(),
            8,
            "one primary/secondary investigation per owned name, with persistent cooldown"
        );
        assert!(calls
            .iter()
            .all(|(host, _)| host.ends_with("nflog-owned.example")));
    }
}

#[test]
fn nflog_start_keeps_owner_discovery_and_periodic_queue_progress() {
    discovery_survives_wiring(true);
}

#[test]
fn nflog_failure_keeps_owner_discovery_and_periodic_queue_progress() {
    discovery_survives_wiring(false);
}

#[test]
fn nflog_wiring_cannot_confirm_a_shared_name_without_a_secondary() {
    for reports_start in [false, true] {
        let (pipeline, engine, probe, secondary) = pipeline();
        secondary.store(false, Ordering::Release);
        let rig = rig_with_discovery(reports_start, Some(pipeline));
        rig.socket_table.push(connection(&bob(), 77));
        rig.fold();
        rig.fold();
        assert!(engine.candidates(&bob()).is_empty());
        assert!(
            probe.0.lock().unwrap_or_else(|p| p.into_inner()).is_empty(),
            "no primary attempt may substitute for unavailable secondary evidence"
        );
    }
}
