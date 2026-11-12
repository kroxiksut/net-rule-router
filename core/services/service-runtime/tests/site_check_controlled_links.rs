//! Explicit test-laptop fixture: loopback aliases model two independently bound paths.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use nrr_domain::decision_matching::{RequestedRouteDecision, ZonePriorityPolicy};
use nrr_service_runtime::auto_rules::{
    AutoRulesEngine, InMemoryDismissalStore, InMemoryPendingStore, ProductionAutoRuleAuthor,
};
use nrr_service_runtime::fqdn_cache_lookup::MockFqdnCacheLookup;
use nrr_service_runtime::ipc_handlers::mutation_token_store::StoredMutation;
use nrr_service_runtime::ipc_handlers::operation_status_store::OperationError;
use nrr_service_runtime::ipc_handlers::providers::{MutationExecutor, MutationOutcome};
use nrr_service_runtime::path_probe::{PathProbe, PathVerdict};
use nrr_service_runtime::per_sid_orchestrator::{ActiveRulesSnapshot, RulesProvider};
use nrr_service_runtime::production_auto_rule_probe::EgressSources;
use nrr_service_runtime::site_check::{
    ManualSiteCheckWiring, SiteCheckWiring, SiteChecker, SiteRoutes,
};
use nrr_shared::ipc_payloads::{
    MutationKind, ReviewSummaryResponse, RollbackTargetDto, SafeDisableTerm,
    SITE_CHECK_VERDICT_FINE, SITE_CHECK_VERDICT_ROUTE_DOWN,
};

const ALICE: &str = "S-1-5-21-3212-2001";
const BOB: &str = "S-1-5-21-3212-2002";
const HOST: &str = "controlled-links.example";
const PRIMARY: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const SECONDARY: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);

#[cfg(target_os = "linux")]
struct LoopbackAliases(Vec<Ipv4Addr>);

#[cfg(target_os = "linux")]
impl LoopbackAliases {
    fn ensure() -> Result<Self, Box<dyn std::error::Error>> {
        let output = Command::new("ip")
            .args(["-4", "-o", "addr", "show", "dev", "lo"])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "could not inspect loopback addresses: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let present = String::from_utf8_lossy(&output.stdout);
        let mut aliases = Self(Vec::new());
        for address in [PRIMARY, SECONDARY] {
            let cidr = format!("{address}/32");
            if present.split_whitespace().any(|field| field == cidr) {
                continue;
            }
            let added = Command::new("ip")
                .args(["addr", "add", &cidr, "dev", "lo"])
                .output()?;
            if !added.status.success() {
                return Err(format!(
                    "could not add {cidr} to lo: {}",
                    String::from_utf8_lossy(&added.stderr)
                )
                .into());
            }
            aliases.0.push(address);
        }
        Ok(aliases)
    }
}

#[cfg(target_os = "linux")]
impl Drop for LoopbackAliases {
    fn drop(&mut self) {
        for address in self.0.drain(..) {
            let _ = Command::new("ip")
                .args(["addr", "del", &format!("{address}/32"), "dev", "lo"])
                .status();
        }
    }
}

#[derive(Default)]
struct Books(Mutex<HashMap<String, ActiveRulesSnapshot>>);
impl RulesProvider for Books {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        self.active_rules_for(ALICE)
    }
    fn active_rules_for(&self, sid: &str) -> Option<ActiveRulesSnapshot> {
        Some(
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(sid)
                .cloned()
                .unwrap_or_default(),
        )
    }
}
impl SiteRoutes for Books {
    fn route_for(&self, sid: &str, host: &str, ip: Option<Ipv4Addr>) -> String {
        let snapshot = self.active_rules_for(sid).unwrap_or_default();
        match nrr_domain::decision_engine_input::match_sample(
            &snapshot.rule_book,
            Some(host),
            ip.map(IpAddr::V4),
            None,
            ZonePriorityPolicy::default(),
            nrr_domain::RouteBehaviorMode::PreferPrimary,
        ) {
            RequestedRouteDecision::MatchedRoute { candidate } => {
                candidate.route_role.slug().into()
            }
            RequestedRouteDecision::DefaultRoute { .. } => "primary".into(),
        }
    }
    fn covers(&self, sid: &str, host: &str) -> bool {
        self.route_for(sid, host, None) == "secondary"
    }
}

struct Activate(Arc<Books>);
impl MutationExecutor for Activate {
    fn preview(&self, _: MutationKind, _: &serde_json::Value, _: &str) -> ReviewSummaryResponse {
        panic!("acceptance uses the confirmed mutation path")
    }
    fn execute(&self, mutation: StoredMutation, principal: &str) -> MutationOutcome {
        assert_eq!(mutation.issuer_sid, principal);
        assert!(!mutation.caller_is_elevated);
        let text = mutation
            .payload
            .get("rules-json")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("production author rules payload"));
        let dto = nrr_shared::rules_json::from_canonical_string(text)
            .unwrap_or_else(|error| panic!("canonical payload: {error}"));
        let content = nrr_domain::rules_json_codec::decode(
            dto,
            nrr_domain::rules_file::HostPlatform::compiled(),
        )
        .unwrap_or_else(|error| panic!("production payload decode: {error}"));
        self.0 .0.lock().unwrap_or_else(|p| p.into_inner()).insert(
            principal.to_owned(),
            ActiveRulesSnapshot {
                rule_book: content.rule_book,
            },
        );
        MutationOutcome::Completed(serde_json::json!({}))
    }
    fn rollback(&self, _: &str, _: Option<&str>) -> MutationOutcome {
        panic!("no rollback in fixture")
    }
    fn rollback_target(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> Result<Option<RollbackTargetDto>, OperationError> {
        panic!("no rollback in fixture")
    }
    fn safe_disable(&self, _: &str, _: &str, _: SafeDisableTerm) -> MutationOutcome {
        panic!("no policy disable in fixture")
    }
}

struct Links(AtomicBool);
impl EgressSources for Links {
    fn egress_source_ips(&self, _: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        (
            Some(PRIMARY),
            self.0.load(Ordering::Acquire).then_some(SECONDARY),
        )
    }
}

struct BoundProbe;
impl PathProbe for BoundProbe {
    fn probe(&self, _: Ipv4Addr, _: u16, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
        panic!("hostname confirmation must exchange TLS")
    }
    fn probe_tls(
        &self,
        target: Ipv4Addr,
        host: &str,
        source: Option<Ipv4Addr>,
        timeout: Duration,
    ) -> PathVerdict {
        #[cfg(target_os = "linux")]
        {
            let Some(source) = source else {
                return PathVerdict::Indeterminate;
            };
            match nrr_platform_linux::link_probe::socket_over_link(target, 443, source, timeout) {
                Ok(socket) => {
                    nrr_service_runtime::path_probe::tls_exchange(&mut socket.into(), host, timeout)
                }
                Err(nrr_platform_linux::link_probe::LinkProbeOutcome::NoAnswer) => {
                    PathVerdict::Silent
                }
                Err(_) => PathVerdict::Indeterminate,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            nrr_service_runtime::path_probe::SystemPathProbe
                .probe_tls(target, host, source, timeout)
        }
    }
}

struct Server {
    stop: Arc<AtomicBool>,
    peers: Arc<Mutex<Vec<IpAddr>>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let finished = Arc::clone(&stop);
        let observed = Arc::clone(&peers);
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !finished.load(Ordering::Acquire) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, peer)) => {
                        observed
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .push(peer.ip());
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                        let mut header = [0u8; 5];
                        if stream.read_exact(&mut header).is_err() {
                            continue;
                        }
                        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                        if length > 4096 {
                            continue;
                        }
                        let mut hello = vec![0u8; length];
                        if stream.read_exact(&mut hello).is_err() {
                            continue;
                        }
                        if peer.ip() == IpAddr::V4(PRIMARY) {
                            let _ =
                                socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));
                        } else if peer.ip() == IpAddr::V4(SECONDARY) {
                            let _ = stream.write_all(&[22, 3, 3, 0, 4, 2, 0, 0, 0]);
                            let _ = stream.read(&mut [0u8; 1]);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            stop,
            peers,
            worker: Some(worker),
        })
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
#[ignore = "requires a free loopback TCP/443 and permission to add Linux loopback aliases"]
fn controlled_links_confirm_accept_and_keep_the_accepted_site_off_primary(
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    let _aliases = LoopbackAliases::ensure()?;
    let server = Server::start()?;
    let books = Arc::new(Books::default());
    let engine = Arc::new(
        AutoRulesEngine::new(
            books.clone(),
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
    engine.attach_author(Arc::new(ProductionAutoRuleAuthor::new(
        books.clone(),
        Arc::new(Activate(Arc::clone(&books))),
    )));
    let cache = Arc::new(MockFqdnCacheLookup::new());
    cache.set_ips(HOST, vec![Ipv4Addr::LOCALHOST]);
    let links = Arc::new(Links(AtomicBool::new(true)));
    let checker = SiteChecker::new(SiteCheckWiring {
        probe: Arc::new(BoundProbe),
        egress: links.clone(),
        cache,
        routes: books.clone(),
        engine: Some(Arc::clone(&engine)),
        trace: None,
        https: None,
        traffic_held: None,
    });
    checker.attach_manual(ManualSiteCheckWiring {
        limits: Arc::new(|_| nrr_service_runtime::path_probe::ProbeLimits::default()),
        rules: books.clone(),
        primary_default: Arc::new(|_| true),
        os_cache: Arc::new(nrr_platform_api::dns::NoopDnsCacheRead),
        resolver_for: Arc::new(|_| panic!("controlled addresses must never emit DNS")),
    });
    let first = checker.check(ALICE, HOST);
    assert_eq!(first.names[0].answer, "silent");
    let offers = engine.candidates(ALICE);
    assert_eq!(
        offers.len(),
        1,
        "three primary resets and secondary TLS response confirm the narrow offer"
    );
    assert_eq!(offers[0].secondary_reach, Some(true));
    assert!(engine.candidates(BOB).is_empty());
    let accepted = engine
        .accept(ALICE, &[offers[0].id.clone()], false, SystemTime::now())
        .unwrap_or_else(|error| panic!("accept: {error:?}"));
    assert_eq!(accepted.applied, 1);
    assert_eq!(
        books.route_for(ALICE, HOST, Some(Ipv4Addr::LOCALHOST)),
        "secondary"
    );
    assert_eq!(
        books.route_for(ALICE, "unrelated.example", Some(Ipv4Addr::LOCALHOST)),
        "primary"
    );
    assert_eq!(
        books.route_for(BOB, HOST, Some(Ipv4Addr::LOCALHOST)),
        "primary"
    );
    let after = checker.check(ALICE, HOST);
    assert_eq!(after.site_route, "secondary");
    assert_eq!(
        after.verdict, SITE_CHECK_VERDICT_FINE,
        "the controlled TLS record arrives on the accepted path"
    );
    links.0.store(false, Ordering::Release);
    let held = checker.check(ALICE, HOST);
    assert_eq!(held.verdict, SITE_CHECK_VERDICT_ROUTE_DOWN);
    assert_eq!(held.site_route, "secondary");
    let peers = server
        .peers
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    assert_eq!(
        peers,
        vec![
            IpAddr::V4(PRIMARY),
            IpAddr::V4(PRIMARY),
            IpAddr::V4(PRIMARY),
            IpAddr::V4(SECONDARY),
            IpAddr::V4(SECONDARY)
        ]
    );
    println!("controlled loopback: three primary resets, two secondary TLS responses; accepted rule never fell back to primary");
    Ok(())
}
