use super::*;
use crate::ipc_handlers::providers::AutoRuleProbeRunner;
use crate::path_probe::{MockPathProbe, PathProber, PathVerdict, ProbeLimits};
use crate::production_auto_rule_probe::{EgressSources, ProductionAutoRuleProbe};
use crate::site_check::{HeadFailure, HttpsHead};
use std::net::Ipv4Addr;
use std::sync::atomic::AtomicUsize;

#[test]
fn nov10_http_answer_survives_fresh_automatic_proposals_without_erasing_passive_health() {
    const HOST: &str = "healthy-through-current-http.example";
    struct Links;
    impl EgressSources for Links {
        fn egress_source_ips(&self, _: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
            (
                Some(Ipv4Addr::new(192, 0, 2, 10)),
                Some(Ipv4Addr::new(198, 51, 100, 7)),
            )
        }
    }
    struct Heads {
        answered: AtomicBool,
        calls: AtomicUsize,
    }
    impl HttpsHead for Heads {
        fn fetch(
            &self,
            _: Ipv4Addr,
            _: &str,
            _: Ipv4Addr,
            _: &[u8],
            _: Duration,
        ) -> Result<Vec<u8>, HeadFailure> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            if self.answered.load(Ordering::Acquire) {
                Ok(b"HTTP/1.1 200 OK\r\n\r\n".to_vec())
            } else {
                Err(HeadFailure::NoAnswer)
            }
        }
    }
    let mut f = fixture(AutoRulesMode::Auto);
    let passive = Arc::new(crate::primary_stall_registry::PrimaryStallRegistry::new());
    let observed = Arc::clone(&passive);
    f.engine = f
        .engine
        .with_primary_behavior_source(Arc::new(move |owner, host| {
            observed.behavior_of(owner, host)
        }));
    let mut dto = main_link_dto("site.example", HOST, AUTO_RULE_SIGNAL_CO_ACTIVITY, "");
    dto.id = candidate_id(SID, AUTO_RULE_MATCH_KIND_EXACT, HOST);
    dto.match_kind = AUTO_RULE_MATCH_KIND_EXACT.into();
    f.engine.park(
        SID,
        vec![PendingCandidate {
            dto: dto.clone(),
            route: RouteRole::Secondary,
            match_kind: AuthoredMatchKind::ExactHost,
        }],
        unix_ms(later()),
    );
    two_visits(&f.engine, &[HOST]);
    let engine = Arc::new(f.engine);
    let cache = Arc::new(crate::fqdn_cache_lookup::MockFqdnCacheLookup::new());
    cache.set_ips(HOST, vec![Ipv4Addr::new(203, 0, 113, 35)]);
    let tls = Arc::new(MockPathProbe::new(PathVerdict::Answered));
    let heads = Arc::new(Heads {
        answered: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
    });
    let runner = ProductionAutoRuleProbe::over(
        Arc::clone(&engine),
        cache,
        Arc::new(Links),
        Arc::new(PathProber::new(tls.clone())),
        Arc::new(|_| ProbeLimits {
            timeout: Duration::from_millis(300),
            max_targets: 1,
            repeat_after: Duration::ZERO,
        }),
    )
    .with_https(Some(heads.clone()));
    let probe = || {
        let references = Arc::strong_count(&engine);
        let before = tls.attempts().len() + heads.calls.load(Ordering::Acquire);
        assert_eq!(runner.probe(SID, &[dto.id.clone()], &[]).accepted, 1);
        let until = Instant::now() + Duration::from_secs(3);
        while (tls.attempts().len() + heads.calls.load(Ordering::Acquire) == before
            || Arc::strong_count(&engine) > references)
            && Instant::now() < until
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            Instant::now() < until,
            "the bounded measurement worker must settle before the next automatic tick"
        );
    };
    probe();
    engine.tick(SID, later());
    assert!(f.author.calls().is_empty(), "a fresh ledger proposal must not forget the actual HTTP200 and silently route its healthy host onto the anchor's link");
    assert_eq!(heads.calls.load(Ordering::Acquire), 1);
    passive.note(SID, HOST, PrimaryHealthEvent::Completed);
    heads.answered.store(false, Ordering::Release);
    probe();
    engine.tick(SID, later() + Duration::from_secs(1));
    assert!(
        f.author.calls().is_empty(),
        "one active HTTP failure cannot erase an actual passive completion"
    );
    assert_eq!(passive.behavior_of(SID, HOST), PrimaryBehavior::Responds);
}
