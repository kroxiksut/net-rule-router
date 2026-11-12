use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use nrr_service_runtime::fqdn_cache_lookup::MockFqdnCacheLookup;
use nrr_service_runtime::path_probe::{MockPathProbe, PathVerdict};
use nrr_service_runtime::production_auto_rule_probe::EgressSources;
use nrr_service_runtime::site_check::{
    HeadFailure, HttpsHead, SiteCheckWiring, SiteChecker, SiteRoutes,
};
use nrr_shared::ipc_payloads::SITE_CHECK_VERDICT_NOT_ANSWERING;

struct Primary;
impl EgressSources for Primary {
    fn egress_source_ips(&self, _: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        (Some(Ipv4Addr::new(192, 0, 2, 10)), None)
    }
}
struct Rules;
impl SiteRoutes for Rules {
    fn route_for(&self, _: &str, _: &str, _: Option<Ipv4Addr>) -> String {
        "primary".into()
    }
    fn covers(&self, _: &str, _: &str) -> bool {
        true
    }
}
struct HttpsNeverAnswers;
impl HttpsHead for HttpsNeverAnswers {
    fn fetch(
        &self,
        _: Ipv4Addr,
        _: &str,
        _: Ipv4Addr,
        _: &[u8],
        _: Duration,
    ) -> Result<Vec<u8>, HeadFailure> {
        Err(HeadFailure::NoAnswer)
    }
}

#[test]
fn a_tls_response_does_not_claim_that_a_silent_https_site_loaded() {
    let cache = Arc::new(MockFqdnCacheLookup::new());
    cache.set_ips("https-silent.example", vec![Ipv4Addr::new(203, 0, 113, 31)]);
    let checker = SiteChecker::new(SiteCheckWiring {
        probe: Arc::new(MockPathProbe::new(PathVerdict::Answered)),
        egress: Arc::new(Primary),
        cache,
        routes: Arc::new(Rules),
        engine: None,
        trace: None,
        https: Some(Arc::new(HttpsNeverAnswers)),
        traffic_held: None,
    });
    let report = checker.check("S-1-5-21-3212-1001", "https-silent.example");
    assert_eq!(
        report.verdict, SITE_CHECK_VERDICT_NOT_ANSWERING,
        "TCP/TLS connectivity is not an HTTPS response"
    );
    assert!(report.reads_answer);
}
