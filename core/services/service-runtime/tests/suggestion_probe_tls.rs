use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use nrr_service_runtime::auto_rules::{
    AutoRulesEngine, InMemoryDismissalStore, InMemoryPendingStore,
};
use nrr_service_runtime::fqdn_cache_lookup::MockFqdnCacheLookup;
use nrr_service_runtime::ipc_handlers::providers::AutoRuleProbeRunner;
use nrr_service_runtime::path_probe::{PathProbe, PathProber, PathVerdict, ProbeLimits};
use nrr_service_runtime::per_sid_orchestrator::{ActiveRulesSnapshot, RulesProvider};
use nrr_service_runtime::production_auto_rule_probe::{EgressSources, ProductionAutoRuleProbe};
use nrr_service_runtime::site_check::{HeadFailure, HttpsHead};

const OWNER: &str = "S-1-5-21-3212-3001";
const MAIN: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const SECONDARY: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
struct Book;
impl RulesProvider for Book {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        Some(ActiveRulesSnapshot::default())
    }
}
struct Links;
impl EgressSources for Links {
    fn egress_source_ips(&self, _: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        (Some(MAIN), Some(SECONDARY))
    }
}
#[derive(Default)]
struct TcpAnswersButTlsResets {
    tcp: AtomicUsize,
    secondary_tls: AtomicUsize,
}
#[derive(Default)]
struct HttpByRoute {
    primary: AtomicUsize,
    secondary: AtomicUsize,
    primary_answers: bool,
}
impl HttpsHead for HttpByRoute {
    fn fetch(
        &self,
        _: Ipv4Addr,
        _: &str,
        source: Ipv4Addr,
        _: &[u8],
        _: Duration,
    ) -> Result<Vec<u8>, HeadFailure> {
        if source == SECONDARY {
            self.secondary.fetch_add(1, Ordering::AcqRel);
            return Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec());
        }
        self.primary.fetch_add(1, Ordering::AcqRel);
        if self.primary_answers {
            Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec())
        } else {
            Err(HeadFailure::NoAnswer)
        }
    }
}
impl PathProbe for TcpAnswersButTlsResets {
    fn probe(&self, _: Ipv4Addr, _: u16, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
        self.tcp.fetch_add(1, Ordering::AcqRel);
        PathVerdict::Answered
    }
    fn probe_tls(
        &self,
        _: Ipv4Addr,
        _: &str,
        source: Option<Ipv4Addr>,
        _: Duration,
    ) -> PathVerdict {
        if source == Some(SECONDARY) {
            self.secondary_tls.fetch_add(1, Ordering::AcqRel);
            PathVerdict::Answered
        } else {
            PathVerdict::Silent
        }
    }
}

#[test]
fn tcp_connect_cannot_cancel_a_suggestion_for_a_hostname_whose_tls_is_reset() {
    let engine = Arc::new(AutoRulesEngine::new(
        Arc::new(Book),
        Arc::new(|_| nrr_storage::auto_rules::AutoRulesMode::Suggest),
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::now(),
    ));
    assert!(engine.note_main_link_blocked_host(
        OWNER,
        "candidate-tls-reset.example",
        nrr_service_runtime::navigation_registry::HostCounts::default(),
        SystemTime::now()
    ));
    let cache = Arc::new(MockFqdnCacheLookup::new());
    cache.set_ips(
        "candidate-tls-reset.example",
        vec![Ipv4Addr::new(203, 0, 113, 31)],
    );
    let mechanism = Arc::new(TcpAnswersButTlsResets::default());
    let https = Arc::new(HttpByRoute::default());
    let runner = ProductionAutoRuleProbe::over(
        Arc::clone(&engine),
        cache,
        Arc::new(Links),
        Arc::new(PathProber::new(mechanism.clone())),
        Arc::new(|_| ProbeLimits::default()),
    )
    .with_secondary_prober(Arc::new(PathProber::new(mechanism.clone())))
    .with_https(Some(https.clone()));
    assert_eq!(runner.probe(OWNER, &[], &[]).accepted, 1);
    let deadline = Instant::now() + Duration::from_secs(3);
    while https.primary.load(Ordering::Acquire) == 0
        && https.secondary.load(Ordering::Acquire) == 0
    {
        assert!(Instant::now() < deadline, "hostname probe failed to finish");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        mechanism.tcp.load(Ordering::Acquire),
        0,
        "TCP success cannot stand in for a TLS answer"
    );
    while engine
        .candidates(OWNER)
        .first()
        .is_none_or(|candidate| candidate.secondary_reach != Some(true))
    {
        assert!(
            Instant::now() < deadline,
            "verified secondary result must reach its owner"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(https.secondary.load(Ordering::Acquire), 1);
}

#[test]
fn a_working_tls_site_is_not_announced_before_automatic_confirmation_finishes() {
    use nrr_service_runtime::ipc_handlers::event_bus::EventBus;
    use nrr_shared::ipc_payloads::StatusUpdateEvent;
    let bus = Arc::new(EventBus::new());
    let subscription = bus
        .subscribe_as("own-tray".into(), Some(OWNER.into()), None)
        .subscription_id;
    let engine = Arc::new(
        AutoRulesEngine::new(
            Arc::new(Book),
            Arc::new(|_| nrr_storage::auto_rules::AutoRulesMode::Suggest),
            Arc::new(InMemoryDismissalStore::new()),
            Arc::new(InMemoryPendingStore::new()),
            SystemTime::now(),
        )
        .with_event_bus(Arc::clone(&bus))
        .with_main_link_pass_enabled(Arc::new(|_| true))
        .with_primary_behavior_source(Arc::new(|sid, host| {
            nrr_service_runtime::primary_stall_registry::global_primary_stalls()
                .behavior_of_subtree(sid, host)
        })),
    );
    assert!(engine.note_main_link_blocked_host(
        OWNER,
        "working-before-popup.example",
        nrr_service_runtime::navigation_registry::HostCounts::default(),
        SystemTime::now()
    ));
    let announcements = || {
        bus.peek_pending_for(&subscription, 64)
            .into_iter()
            .filter(|event| {
                matches!(
                    event.event,
                    StatusUpdateEvent::AutoRuleCandidatesChanged {
                        announces: true,
                        ..
                    }
                )
            })
            .count()
    };
    assert_eq!(
        announcements(),
        0,
        "an unverified stall cannot flash a popup before the opt-in TLS check"
    );
    let cache = Arc::new(MockFqdnCacheLookup::new());
    cache.set_ips(
        "working-before-popup.example",
        vec![Ipv4Addr::new(203, 0, 113, 32)],
    );
    let mechanism = Arc::new(nrr_service_runtime::path_probe::MockPathProbe::new(
        PathVerdict::Answered,
    ));
    let https = Arc::new(HttpByRoute {
        primary_answers: true,
        ..HttpByRoute::default()
    });
    let runner = ProductionAutoRuleProbe::over(
        Arc::clone(&engine),
        cache,
        Arc::new(Links),
        Arc::new(PathProber::new(mechanism.clone())),
        Arc::new(|_| ProbeLimits::default()),
    )
    .with_https(Some(https.clone()));
    assert_eq!(runner.probe(OWNER, &[], &[]).accepted, 1);
    let deadline = Instant::now() + Duration::from_secs(3);
    while https.primary.load(Ordering::Acquire) == 0 || !engine.candidates(OWNER).is_empty() {
        assert!(
            Instant::now() < deadline,
            "TLS recovery must clear the pending offer"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(announcements(), 0);
}

#[test]
fn a_verified_tls_answer_replaces_old_failure_only_for_the_checked_user() {
    use nrr_domain::companion_affinity::PrimaryBehavior;
    const OTHER: &str = "S-1-5-21-3212-3002";
    const HOST: &str = "old-verified-failure-recovered.example";
    let registry = nrr_service_runtime::primary_stall_registry::global_primary_stalls();
    registry.note_verified_tls(OWNER, HOST, false, 3);
    registry.note_verified_tls(OTHER, HOST, false, 3);
    let engine = Arc::new(
        AutoRulesEngine::new(
            Arc::new(Book),
            Arc::new(|_| nrr_storage::auto_rules::AutoRulesMode::Suggest),
            Arc::new(InMemoryDismissalStore::new()),
            Arc::new(InMemoryPendingStore::new()),
            SystemTime::now(),
        )
        .with_primary_behavior_source(Arc::new(|sid, host| {
            nrr_service_runtime::primary_stall_registry::global_primary_stalls()
                .behavior_of_subtree(sid, host)
        })),
    );
    assert!(engine.note_main_link_blocked_host(
        OWNER,
        HOST,
        nrr_service_runtime::navigation_registry::HostCounts::default(),
        SystemTime::now()
    ));
    assert_eq!(engine.candidates(OWNER).len(), 1);
    let cache = Arc::new(MockFqdnCacheLookup::new());
    cache.set_ips(HOST, vec![Ipv4Addr::new(203, 0, 113, 33)]);
    let mechanism = Arc::new(nrr_service_runtime::path_probe::MockPathProbe::new(
        PathVerdict::Answered,
    ));
    let https = Arc::new(HttpByRoute {
        primary_answers: true,
        ..HttpByRoute::default()
    });
    let runner = ProductionAutoRuleProbe::over(
        Arc::clone(&engine),
        cache,
        Arc::new(Links),
        Arc::new(PathProber::new(mechanism)),
        Arc::new(|_| ProbeLimits::default()),
    )
    .with_https(Some(https));
    assert_eq!(runner.probe(OWNER, &[], &[]).accepted, 1);
    let deadline = Instant::now() + Duration::from_secs(3);
    while registry.behavior_of(OWNER, HOST) != PrimaryBehavior::Responds
        || !engine.candidates(OWNER).is_empty()
    {
        assert!(
            Instant::now() < deadline,
            "the verified TLS answer must supersede the old failure epoch"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(registry.behavior_of(OTHER, HOST), PrimaryBehavior::Stalls);
}

#[test]
fn a_single_silent_primary_probe_does_not_create_a_verified_failure_epoch() {
    use nrr_domain::companion_affinity::PrimaryBehavior;
    const HOST: &str = "one-silent-probe.example";
    let registry = nrr_service_runtime::primary_stall_registry::global_primary_stalls();
    assert_eq!(registry.behavior_of(OWNER, HOST), PrimaryBehavior::Unknown);
    let engine = Arc::new(
        AutoRulesEngine::new(
            Arc::new(Book),
            Arc::new(|_| nrr_storage::auto_rules::AutoRulesMode::Suggest),
            Arc::new(InMemoryDismissalStore::new()),
            Arc::new(InMemoryPendingStore::new()),
            SystemTime::now(),
        )
        .with_primary_behavior_source(Arc::new(|sid, host| {
            nrr_service_runtime::primary_stall_registry::global_primary_stalls()
                .behavior_of_subtree(sid, host)
        })),
    );
    assert!(engine.note_main_link_blocked_host(
        OWNER,
        HOST,
        nrr_service_runtime::navigation_registry::HostCounts::default(),
        SystemTime::now()
    ));
    let cache = Arc::new(MockFqdnCacheLookup::new());
    cache.set_ips(HOST, vec![Ipv4Addr::new(203, 0, 113, 34)]);
    let mechanism = Arc::new(TcpAnswersButTlsResets::default());
    let https = Arc::new(HttpByRoute::default());
    let runner = ProductionAutoRuleProbe::over(
        Arc::clone(&engine),
        cache,
        Arc::new(Links),
        Arc::new(PathProber::new(mechanism.clone())),
        Arc::new(|_| ProbeLimits::default()),
    )
    .with_secondary_prober(Arc::new(PathProber::new(mechanism.clone())))
    .with_https(Some(https.clone()));
    assert_eq!(runner.probe(OWNER, &[], &[]).accepted, 1);
    let deadline = Instant::now() + Duration::from_secs(3);
    while engine
        .candidates(OWNER)
        .first()
        .is_none_or(|candidate| candidate.secondary_reach != Some(true))
    {
        assert!(
            Instant::now() < deadline,
            "the ordinary paired probe must complete"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(https.secondary.load(Ordering::Acquire), 1);
    assert_eq!(registry.behavior_of(OWNER, HOST), PrimaryBehavior::Unknown);
}
