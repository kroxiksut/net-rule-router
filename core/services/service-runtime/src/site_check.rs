//! User-requested checks over known real addresses on their assigned routes.
//! Cached addresses never prove that fresh DNS or the browser's path works.

pub mod http_answer;
pub mod https_head;
mod manual;
mod manual_http;
pub use manual::{captured_dns_upstream, ManualSiteCheckWiring, SiteResolverFactory};
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use nrr_domain::companion_affinity::{registrable_domain, site_shared_across_zones};
use nrr_domain::decision_engine_input::hostname_ace;
use nrr_domain::decision_matching::match_suffix_domain;
use nrr_shared::ipc_payloads::{
    SiteCheckNameDto, SiteCheckReport, SiteCheckStatus, SITE_CHECK_MAX_HOST_LEN,
    SITE_CHECK_MAX_NAMES, SITE_CHECK_MAX_REDIRECTS, SITE_CHECK_SIGN_IN_LABELS,
    SITE_CHECK_STATE_DONE, SITE_CHECK_STATE_IDLE, SITE_CHECK_STATE_RUNNING,
    SITE_CHECK_VERDICT_BLOCKED, SITE_CHECK_VERDICT_CERTIFICATE_UNTRUSTED,
    SITE_CHECK_VERDICT_DNS_UNAVAILABLE, SITE_CHECK_VERDICT_FINE, SITE_CHECK_VERDICT_NOT_ANSWERING,
    SITE_CHECK_VERDICT_ROUTE_DOWN, SITE_CHECK_VERDICT_SERVER_ERROR,
    SITE_CHECK_VERDICT_SIGN_IN_SPLIT, SITE_CHECK_VERDICT_UNCLEAR,
};

use crate::auto_rules::AutoRulesEngine;
use crate::conn_observation_consumer::ConnectionTraceRing;
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::path_probe::{PathProbe, PathVerdict};
use crate::production_auto_rule_probe::EgressSources;

/// Bounds each connect, write and read of one probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// The whole check, however many names it holds.
const CHECK_BUDGET: Duration = Duration::from_secs(12);
/// Names probed at once.
const WORKERS: usize = 4;
/// Names taken from the caller's trace and from the ledger.
const TRACE_NAMES: usize = 32;
const SEEN_WITH: usize = 16;
/// Callers whose latest check is kept.
const MAX_PRINCIPALS: usize = 64;
/// Checks running at once, all callers together.
const MAX_RUNNING: usize = 2;

/// The route `sid`'s rules give `name` (at `address`, when one is known):
/// `primary`, `secondary`, `blocked` or `none`.
pub trait SiteRoutes: Send + Sync {
    fn route_for(&self, sid: &str, name: &str, address: Option<Ipv4Addr>) -> String;

    fn evidence_for(&self, sid: &str, name: &str, address: Option<Ipv4Addr>) -> RouteEvidence {
        RouteEvidence {
            route: self.route_for(sid, name, address),
            ..RouteEvidence::default()
        }
    }

    /// Whether one of `sid`'s own rules names `name`. The machine's name cache
    /// is everybody's: only such a name, or one the caller's own traffic saw,
    /// may take an address from it.
    fn covers(&self, _sid: &str, _name: &str) -> bool {
        false
    }
}

#[derive(Clone, Debug, Default)]
pub struct RouteEvidence {
    pub route: String,
    pub rule_id: Option<String>,
    pub revision: Option<String>,
}

#[derive(Default)]
struct EvidenceSources {
    fake_ip: Option<crate::fake_ip::FakeIpBindingView>,
    dns: Option<Arc<crate::dns_compatibility::DnsCompatibilityCenter>>,
}

/// The head of an HTTPS answer: `request` sent over TLS to `target:443` from
/// `source`, naming `server_name`, and the bytes that came back, at most
/// [`http_answer::MAX_HEAD_BYTES`].
pub trait HttpsHead: Send + Sync {
    fn fetch(
        &self,
        target: Ipv4Addr,
        server_name: &str,
        source: Ipv4Addr,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, HeadFailure>;
}

/// Why an HTTPS head could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadFailure {
    /// Nothing usable came back in time.
    NoAnswer,
    /// The certificate did not verify against the bundled roots: something on
    /// this route answers in the site's place.
    Untrusted,
    /// Local setup or capability failed; no remote outcome was measured.
    Unavailable,
}

/// The answer for a name whose certificate does not verify on its route.
const ANSWER_UNTRUSTED: &str = "certificate-untrusted";

/// Whether leak protection currently holds all of one user's traffic.
pub type TrafficHeld = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// [`TrafficHeld`] where the guard reports per user whether it holds: only
/// `everything` holds what no rule names, so `sites` alone does not count.
pub fn held_under_everything(
    posture: crate::app_enforcement_status::FailClosedPostureStatus,
    policies: Arc<dyn crate::RoutePolicySource>,
) -> TrafficHeld {
    Arc::new(move |sid: &str| {
        posture.armed_for(sid)
            && policies
                .load_for_sid(sid)
                .is_some_and(|p| p.leak_protection == nrr_domain::LeakProtection::Everything)
    })
}

/// What the check reads and connects with; attached at the composition root.
pub struct SiteCheckWiring {
    pub probe: Arc<dyn PathProbe>,
    pub egress: Arc<dyn EgressSources>,
    pub cache: Arc<dyn FqdnCacheLookup>,
    pub routes: Arc<dyn SiteRoutes>,
    /// The caller's own observation: what it saw together with a site.
    pub engine: Option<Arc<AutoRulesEngine>>,
    /// The caller's own recent connections and the names they were for.
    pub trace: Option<Arc<ConnectionTraceRing>>,
    /// Reads the status code and `Location`; `None` where no TLS client is
    /// linked, and the report then says it did not read them.
    pub https: Option<Arc<dyn HttpsHead>>,
    /// While the caller's traffic is held, the service's own exempt socket
    /// must not answer in its place: every route reads as down and nothing
    /// is sent. `None` where the platform has no such posture.
    pub traffic_held: Option<TrafficHeld>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Site,
    SignIn,
    SeenWith,
}

impl Role {
    fn slug(self) -> &'static str {
        match self {
            Self::Site => "site",
            Self::SignIn => "sign-in",
            Self::SeenWith => "seen-with",
        }
    }
}

/// A name the check examines, and whether traffic named it (a sign-in name
/// only guessed from the site's own is dropped when it says nothing).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Planned {
    pub name: String,
    pub role: Role,
    pub observed: bool,
}

/// The site a name belongs to: its registrable domain, else the name itself.
pub(crate) fn site_root(site: &str) -> &str {
    registrable_domain(site).unwrap_or(site)
}

/// The site's own name: under its domain, or the same brand in another zone.
pub(crate) fn same_site(root: &str, name: &str) -> bool {
    match_suffix_domain(name, root) || site_shared_across_zones(root, name).is_some()
}

/// A name of the site whose first label says sign-in: `login`, `id2`, `auth-x`.
pub(crate) fn is_sign_in(root: &str, name: &str) -> bool {
    let first = name.split('.').next().unwrap_or_default();
    same_site(root, name)
        && SITE_CHECK_SIGN_IN_LABELS.iter().any(|label| {
            first.strip_prefix(label).is_some_and(|rest| {
                rest.is_empty()
                    || rest.starts_with('-')
                    || rest.starts_with(|c: char| c.is_ascii_digit())
            })
        })
}

/// The names one check examines, the site first and at most
/// [`SITE_CHECK_MAX_NAMES`]: its sign-in names, guessed and seen, then the
/// site's other names its traffic carried, then what the ledger saw with it.
pub(crate) fn plan_names(site: &str, traced: &[String], seen: &[String]) -> Vec<Planned> {
    let root = site_root(site);
    let mut out = vec![Planned {
        name: site.to_owned(),
        role: Role::Site,
        observed: true,
    }];
    fn add(name: &str, role: Role, observed: bool, out: &mut Vec<Planned>) {
        if out.len() < SITE_CHECK_MAX_NAMES && !out.iter().any(|p| p.name == name) {
            out.push(Planned {
                name: name.to_owned(),
                role,
                observed,
            });
        }
    }
    for name in traced.iter().chain(seen).filter(|n| is_sign_in(root, n)) {
        add(name, Role::SignIn, true, &mut out);
    }
    for label in SITE_CHECK_SIGN_IN_LABELS {
        add(&format!("{label}.{root}"), Role::SignIn, false, &mut out);
    }
    for name in traced.iter().filter(|n| same_site(root, n)) {
        add(name, Role::SeenWith, true, &mut out);
    }
    for name in seen {
        add(name, Role::SeenWith, true, &mut out);
    }
    out
}

/// One examined name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Examined {
    pub planned: Planned,
    pub address: Option<Ipv4Addr>,
    pub route: String,
    pub answer: &'static str,
}

/// The verdict for what was found, and the sign-in names to move.
pub(crate) fn decide(site_route: &str, examined: &[Examined]) -> (&'static str, Vec<String>) {
    let Some(site) = examined.iter().find(|e| e.planned.role == Role::Site) else {
        return (SITE_CHECK_VERDICT_UNCLEAR, Vec::new());
    };
    match site.answer {
        "blocked" => return (SITE_CHECK_VERDICT_BLOCKED, Vec::new()),
        "route-down" => return (SITE_CHECK_VERDICT_ROUTE_DOWN, Vec::new()),
        "silent" | "https-unconfirmed" => return (SITE_CHECK_VERDICT_NOT_ANSWERING, Vec::new()),
        _ => {}
    }
    let sign_in = || examined.iter().filter(|e| e.planned.role == Role::SignIn);
    // A sign-in name in use (it has an address) or ruled onto another route.
    let elsewhere: Vec<String> = sign_in()
        .filter(|e| e.route != site_route && e.route != "blocked")
        .filter(|e| e.address.is_some() || e.planned.observed)
        .map(|e| e.planned.name.clone())
        .collect();
    if !elsewhere.is_empty() {
        return (SITE_CHECK_VERDICT_SIGN_IN_SPLIT, elsewhere);
    }
    if site.answer == ANSWER_UNTRUSTED || sign_in().any(|e| e.answer == ANSWER_UNTRUSTED) {
        return (SITE_CHECK_VERDICT_CERTIFICATE_UNTRUSTED, Vec::new());
    }
    if sign_in().any(|e| matches!(e.answer, "silent" | "https-unconfirmed" | "route-down")) {
        return (SITE_CHECK_VERDICT_NOT_ANSWERING, Vec::new());
    }
    if site.answer == "answered" {
        return (SITE_CHECK_VERDICT_FINE, Vec::new());
    }
    (SITE_CHECK_VERDICT_UNCLEAR, Vec::new())
}

/// Lower-case ACE form of a requested host, or `None` for anything that is
/// not a dotted host name. A pasted address bar is read for its host.
pub fn normalise_host(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > SITE_CHECK_MAX_HOST_LEN {
        return None;
    }
    let raw = raw.split_once("://").map_or(raw, |(_, rest)| rest);
    let raw = raw.strip_prefix("//").unwrap_or(raw);
    // A rule's own spelling of the site.
    let raw = raw.strip_prefix("*.").unwrap_or(raw);
    let raw = &raw[..raw.find(['/', '?', '#']).unwrap_or(raw.len())];
    if raw.contains('@') {
        return None;
    }
    let raw = match raw.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => raw,
    };
    let raw = raw.trim_end_matches('.');
    if raw.is_empty() {
        return None;
    }
    let host = hostname_ace(raw)?;
    (host.contains('.') && host.parse::<std::net::IpAddr>().is_err()).then_some(host)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartRefused {
    /// This caller's check, or as many as run at once, is still running.
    Busy,
    /// The thread could not be started.
    Unavailable,
}

/// Runs checks and keeps each caller's latest.
pub struct SiteChecker {
    wiring: SiteCheckWiring,
    evidence: RwLock<EvidenceSources>,
    manual: RwLock<Option<Arc<ManualSiteCheckWiring>>>,
    latest: Mutex<HashMap<String, SiteCheckStatus>>,
    running: AtomicUsize,
}

impl SiteChecker {
    pub fn new(wiring: SiteCheckWiring) -> Self {
        Self {
            wiring,
            evidence: RwLock::new(EvidenceSources::default()),
            manual: RwLock::new(None),
            latest: Mutex::new(HashMap::new()),
            running: AtomicUsize::new(0),
        }
    }

    pub fn attach_diagnostics(
        &self,
        fake_ip: Option<crate::fake_ip::FakeIpBindingView>,
        dns: Option<Arc<crate::dns_compatibility::DnsCompatibilityCenter>>,
    ) {
        *self.evidence.write().unwrap_or_else(|p| p.into_inner()) =
            EvidenceSources { fake_ip, dns };
    }

    /// `sid`'s latest check.
    pub fn status(&self, sid: &str) -> SiteCheckStatus {
        let latest = self.latest.lock().unwrap_or_else(|p| p.into_inner());
        latest.get(sid).cloned().unwrap_or_else(|| SiteCheckStatus {
            state: SITE_CHECK_STATE_IDLE.to_owned(),
            ..SiteCheckStatus::default()
        })
    }

    /// Start checking `host` (already normalised) for `sid` on a thread of its
    /// own; the answer is the running status.
    pub fn start(
        self: &Arc<Self>,
        sid: &str,
        host: String,
    ) -> Result<SiteCheckStatus, StartRefused> {
        let running = SiteCheckStatus {
            state: SITE_CHECK_STATE_RUNNING.to_owned(),
            host: host.clone(),
            report: None,
        };
        {
            let mut latest = self.latest.lock().unwrap_or_else(|p| p.into_inner());
            if latest
                .get(sid)
                .is_some_and(|s| s.state == SITE_CHECK_STATE_RUNNING)
                || self.running.load(Ordering::Acquire) >= MAX_RUNNING
            {
                return Err(StartRefused::Busy);
            }
            if latest.len() >= MAX_PRINCIPALS && !latest.contains_key(sid) {
                let done = latest
                    .iter()
                    .find(|(_, s)| s.state != SITE_CHECK_STATE_RUNNING)
                    .map(|(k, _)| k.clone());
                match done {
                    Some(k) => {
                        latest.remove(&k);
                    }
                    None => return Err(StartRefused::Busy),
                }
            }
            latest.insert(sid.to_owned(), running.clone());
            self.running.fetch_add(1, Ordering::AcqRel);
        }
        let me = Arc::clone(self);
        let owner = sid.to_owned();
        let spawned = std::thread::Builder::new()
            .name("nrr-site-check".into())
            .spawn(move || {
                // Contained: whatever a hostile answer did to one check, the
                // caller gets a report and the service carries on.
                let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    me.check(&owner, &host)
                }))
                .unwrap_or_else(|_| SiteCheckReport {
                    site: host.clone(),
                    verdict: SITE_CHECK_VERDICT_UNCLEAR.to_owned(),
                    ..SiteCheckReport::default()
                });
                me.finish(&owner, host, report);
            });
        if spawned.is_err() {
            let mut latest = self.latest.lock().unwrap_or_else(|p| p.into_inner());
            latest.remove(sid);
            self.running.fetch_sub(1, Ordering::AcqRel);
            return Err(StartRefused::Unavailable);
        }
        Ok(running)
    }

    fn finish(&self, sid: &str, host: String, report: SiteCheckReport) {
        tracing::info!(
            target: "nrr::site-check",
            msg_key = "site-check-done",
            sid = %sid,
            host = %host,
            verdict = %report.verdict,
            names = report.names.len(),
            "site check finished",
        );
        let mut latest = self.latest.lock().unwrap_or_else(|p| p.into_inner());
        latest.insert(
            sid.to_owned(),
            SiteCheckStatus {
                state: SITE_CHECK_STATE_DONE.to_owned(),
                host,
                report: Some(report),
            },
        );
        self.running.fetch_sub(1, Ordering::AcqRel);
    }

    /// The check itself, on the calling thread.
    pub fn check(&self, sid: &str, site: &str) -> SiteCheckReport {
        let deadline = Instant::now() + CHECK_BUDGET;
        let w = &self.wiring;
        let root = site_root(site).to_owned();
        let traced: Vec<(String, Option<Ipv4Addr>)> = w
            .trace
            .as_ref()
            .map(|t| t.names_for(sid, |n| same_site(&root, n), TRACE_NAMES))
            .unwrap_or_default();
        let traced_names: Vec<String> = traced.iter().map(|(n, _)| n.clone()).collect();
        let seen = w
            .engine
            .as_ref()
            .map(|e| e.seen_with(sid, &root, SEEN_WITH))
            .unwrap_or_default();
        let mut planned = plan_names(site, &traced_names, &seen);
        let evidence = self.evidence.read().unwrap_or_else(|p| p.into_inner());
        let fake_ip = evidence.fake_ip.clone();
        let dns_center = evidence.dns.clone();
        let resolver_unavailable = evidence.dns.as_ref().is_some_and(|center| {
            let state = center.snapshot(Some(sid), crate::dns_compatibility::now_ms());
            state.resolver.listener == "unavailable"
                || state.resolver.redirect == "unavailable"
                || state.resolver.upstream == "unavailable"
        });
        drop(evidence);
        let held = w.traffic_held.as_ref().is_some_and(|held| held(sid));
        let manual = self
            .manual
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(manual) = manual.as_ref() {
            planned.truncate((manual.limits)(sid).max_targets);
        }
        let next_timeout = || {
            budget_left(deadline).map(|left| {
                manual
                    .as_ref()
                    .map_or(left, |manual| left.min((manual.limits)(sid).timeout))
            })
        };
        let entered_addresses = if held {
            Vec::new()
        } else if let Some(manual) = manual.as_ref() {
            let cached = w.cache.ips_for_hostname(site);
            if cached.is_empty() {
                let route = normalised_route(&w.routes.route_for(sid, site, None));
                next_timeout()
                    .map(|budget| manual.resolve(sid, site, budget, route == "primary"))
                    .unwrap_or_default()
            } else {
                crate::dns_wire::only_v4(&cached)
            }
        } else {
            Vec::new()
        };
        let real_addresses = |name: &str| -> Vec<std::net::IpAddr> {
            let own = traced.iter().find(|(n, _)| n == name);
            let entered = manual.is_some() && name == site;
            let known = entered
                || own.is_some()
                || seen.iter().any(|n| n == name)
                || w.routes.covers(sid, name);
            if !known {
                return Vec::new();
            }
            let mut addresses = w.cache.ips_for_hostname(name);
            if entered {
                addresses.extend(entered_addresses.iter().copied().map(std::net::IpAddr::V4));
            }
            if let Some(address) = own.and_then(|(_, a)| *a) {
                addresses.insert(0, std::net::IpAddr::V4(address));
            }
            addresses.retain(|ip| {
                fake_ip
                    .as_ref()
                    .is_none_or(|view| view.domain_for_address(*ip).is_none())
                    && !nrr_platform_api::fake_ip::FakeIpPoolConfig::is_default_pool_addr(*ip)
            });
            addresses.truncate(32);
            let mut unique = std::collections::HashSet::new();
            addresses.retain(|address| unique.insert(*address));
            addresses
        };
        let address_of = |name: &str| -> Option<Ipv4Addr> {
            crate::dns_wire::only_v4(&real_addresses(name))
                .first()
                .copied()
        };
        // The probe leaves from the service's own exempt socket: while the
        // caller's traffic is held it must not reach the site in their place.
        let (main, additional) = if held {
            (None, None)
        } else {
            w.egress.egress_source_ips(sid)
        };
        // Source binding cannot distinguish two roles with the same address.
        // A required additional route is unavailable rather than substituted.
        let additional = additional.filter(|address| Some(*address) != main);
        let source_for = |route: &str| match route {
            "secondary" => additional,
            "primary" => main,
            _ => None,
        };

        let mut route_evidence = HashMap::new();
        let mut examined: Vec<Examined> = planned
            .into_iter()
            .map(|p| {
                let address = address_of(&p.name);
                let evidence = w.routes.evidence_for(sid, &p.name, address);
                let route = normalised_route(&evidence.route);
                route_evidence.insert(p.name.clone(), evidence);
                Examined {
                    planned: p,
                    address,
                    route,
                    answer: "unclear",
                }
            })
            .collect();
        if !held {
            if let (Some(center), Some(site)) = (
                dns_center.as_ref(),
                examined.iter().find(|e| e.planned.role == Role::Site),
            ) {
                let required = match site.route.as_str() {
                    "primary" => Some(nrr_shared::RouteRole::Primary),
                    "secondary" => Some(nrr_shared::RouteRole::Secondary),
                    _ => None,
                };
                if let Some(required) = required {
                    center.arm_browser_confirmation(sid, &site.planned.name, required);
                    center.request_recheck(sid);
                }
            }
        }
        let probe = |e: &Examined| -> &'static str {
            if e.route == "blocked" {
                return "blocked";
            }
            if e.route == "unknown" {
                return "unclear";
            }
            if held {
                return "route-down";
            }
            if e.route == "primary"
                && manual.as_ref().is_some_and(|manual| {
                    !manual.permits_primary_probe(sid, &e.planned.name, e.address)
                })
            {
                return "unclear";
            }
            let Some(target) = e.address else {
                return "no-address";
            };
            let Some(source) = source_for(&e.route) else {
                return "route-down";
            };
            let Some(timeout) = next_timeout() else {
                return "unclear";
            };
            match w
                .probe
                .probe_tls(target, &e.planned.name, Some(source), timeout)
            {
                PathVerdict::Answered => "answered",
                PathVerdict::Silent => "silent",
                PathVerdict::Indeterminate => "unclear",
            }
        };
        let answers: Vec<&'static str> = {
            let next = AtomicUsize::new(0);
            let found = Mutex::new(vec!["unclear"; examined.len()]);
            std::thread::scope(|scope| {
                for _ in 0..WORKERS.min(examined.len()) {
                    scope.spawn(|| loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(e) = examined.get(i) else { break };
                        let answer = probe(e);
                        found.lock().unwrap_or_else(|p| p.into_inner())[i] = answer;
                    });
                }
            });
            found.into_inner().unwrap_or_else(|p| p.into_inner())
        };
        for (e, answer) in examined.iter_mut().zip(answers) {
            e.answer = answer;
        }
        let mut chain = http_answer::ChainReport::default();
        let mut untrusted: Vec<String> = Vec::new();
        let mut http_unconfirmed: Vec<String> = Vec::new();
        let mut http_unavailable: Vec<String> = Vec::new();
        let mut http_statuses = HashMap::new();
        let site_answered = examined.first().is_some_and(|e| e.answer == "answered");
        if let Some(https) = w.https.as_ref() {
            if site_answered {
                let fetch = |host: &str| {
                    let target = address_of(host)?;
                    let route = normalised_route(&w.routes.route_for(sid, host, Some(target)));
                    if route == "primary"
                        && manual.as_ref().is_some_and(|manual| {
                            !manual.permits_primary_probe(sid, host, Some(target))
                        })
                    {
                        return None;
                    }
                    let source = source_for(&route)?;
                    let request = http_answer::request_for(host)?;
                    let timeout = next_timeout()?;
                    match https.fetch(target, host, source, &request, timeout) {
                        Ok(bytes) => {
                            let answer = match http_answer::parse_head(&bytes) {
                                Ok(answer) => answer,
                                Err(_) => {
                                    http_unconfirmed.push(host.to_owned());
                                    return None;
                                }
                            };
                            http_statuses.insert(host.to_owned(), answer.status);
                            Some(answer)
                        }
                        // Nothing more is read from a name whose certificate
                        // does not verify here.
                        Err(HeadFailure::Untrusted) => {
                            untrusted.push(host.to_owned());
                            None
                        }
                        Err(HeadFailure::NoAnswer) => {
                            http_unconfirmed.push(host.to_owned());
                            None
                        }
                        Err(HeadFailure::Unavailable) => {
                            http_unavailable.push(host.to_owned());
                            None
                        }
                    }
                };
                chain = http_answer::follow(
                    site,
                    SITE_CHECK_MAX_REDIRECTS,
                    |h| same_site(&root, h),
                    fetch,
                );
                // Where the site sends a visitor is its sign-in, whatever the
                // name says.
                for host in chain.hosts.iter().filter(|h| same_site(&root, h)) {
                    if examined.len() >= SITE_CHECK_MAX_NAMES
                        || examined.iter().any(|e| &e.planned.name == host)
                    {
                        continue;
                    }
                    let address = address_of(host);
                    let evidence = w.routes.evidence_for(sid, host, address);
                    let route = normalised_route(&evidence.route);
                    route_evidence.insert(host.clone(), evidence);
                    let mut e = Examined {
                        planned: Planned {
                            name: host.clone(),
                            role: Role::SignIn,
                            observed: true,
                        },
                        address,
                        route,
                        answer: "unclear",
                    };
                    e.answer = probe(&e);
                    examined.push(e);
                }
            }
        }
        if site_answered
            && w.https.is_some()
            && !http_statuses.contains_key(site)
            && !untrusted.iter().any(|host| host == site)
        {
            http_unconfirmed.push(site.to_owned());
        }
        for e in examined.iter_mut() {
            if http_unavailable.contains(&e.planned.name) && e.answer == "answered" {
                e.answer = "unclear";
            } else if untrusted.contains(&e.planned.name) && e.answer == "answered" {
                e.answer = ANSWER_UNTRUSTED;
            } else if http_unconfirmed.contains(&e.planned.name) && e.answer == "answered" {
                e.answer = "https-unconfirmed";
            }
        }

        if !held {
            if let (Some(manual), Some(site)) = (manual.as_ref(), examined.first_mut()) {
                if w.https.is_some() {
                    let initial_status = http_statuses.get(&site.planned.name).copied();
                    if let Some(status) = self.manual_http_pair(
                        sid,
                        site,
                        (main, additional),
                        initial_status,
                        deadline,
                        manual,
                    ) {
                        http_statuses.insert(site.planned.name.clone(), status);
                    }
                } else {
                    self.manual_pair(sid, site, main, additional, deadline, manual);
                }
            }
        }

        let site_route = examined
            .first()
            .map(|e| e.route.clone())
            .unwrap_or_else(|| "primary".to_owned());
        // A guessed sign-in name nothing uses, on the site's own route, says
        // nothing about the problem.
        examined.retain(|e| {
            e.planned.observed
                || e.planned.role != Role::SignIn
                || e.address.is_some()
                || e.route != site_route
        });
        let (mut verdict, move_names) = decide(&site_route, &examined);
        if verdict == SITE_CHECK_VERDICT_FINE && http_statuses.values().any(|code| *code >= 500) {
            verdict = SITE_CHECK_VERDICT_SERVER_ERROR;
        }
        if verdict == SITE_CHECK_VERDICT_FINE
            && http_statuses.values().any(|code| (400..500).contains(code))
        {
            verdict = nrr_shared::ipc_payloads::SITE_CHECK_VERDICT_HTTP_REFUSED;
        }
        let report = SiteCheckReport {
            site: site.to_owned(),
            verdict: if resolver_unavailable
                && !matches!(
                    verdict,
                    SITE_CHECK_VERDICT_BLOCKED | SITE_CHECK_VERDICT_ROUTE_DOWN
                ) {
                SITE_CHECK_VERDICT_DNS_UNAVAILABLE
            } else {
                verdict
            }
            .to_owned(),
            site_route,
            names: examined
                .iter()
                .enumerate()
                .map(|(i, e)| SiteCheckNameDto {
                    name: e.planned.name.clone(),
                    role: e.planned.role.slug().to_owned(),
                    address: e.address.map(|a| a.to_string()).unwrap_or_default(),
                    route: e.route.clone(),
                    answer: e.answer.to_owned(),
                    not_run_reason: if http_unavailable.contains(&e.planned.name) {
                        Some("probe-unavailable".to_owned())
                    } else if e.answer == "unclear" && e.route == "primary" {
                        manual
                            .as_ref()
                            .and_then(|manual| {
                                manual.primary_probe_refusal(sid, &e.planned.name, e.address)
                            })
                            .map(str::to_owned)
                    } else {
                        None
                    },
                    status: http_statuses.get(&e.planned.name).copied(),
                    redirects: if i == 0 {
                        chain.hosts.clone()
                    } else {
                        Vec::new()
                    },
                    rule_id: route_evidence
                        .get(&e.planned.name)
                        .and_then(|v| v.rule_id.clone()),
                    revision: route_evidence
                        .get(&e.planned.name)
                        .and_then(|v| v.revision.clone()),
                    real_addresses: real_addresses(&e.planned.name)
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                    fake_address: fake_ip
                        .as_ref()
                        .filter(|_| {
                            w.routes.covers(sid, &e.planned.name)
                                || traced.iter().any(|(name, _)| name == &e.planned.name)
                        })
                        .and_then(|view| view.fake_v4_for(&e.planned.name))
                        .map(|ip| ip.to_string()),
                    dns: if resolver_unavailable {
                        "unavailable"
                    } else if real_addresses(&e.planned.name).is_empty() {
                        "not-observed"
                    } else {
                        "cached"
                    }
                    .to_owned(),
                })
                .collect(),
            move_names,
            reads_answer: !http_statuses.is_empty(),
        };
        self.record_manual_report(sid, &report);
        report
    }
}

/// `primary`, `secondary` or `blocked`: an unmatched name takes the main route.
fn normalised_route(route: &str) -> String {
    match route {
        "secondary" | "blocked" | "unknown" => route.to_owned(),
        _ => "primary".to_owned(),
    }
}

/// What one probe step may take before the deadline, `None` once it passed.
fn budget_left(deadline: Instant) -> Option<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    // Each probe step gets the same bound; the last one must still fit.
    (left >= Duration::from_millis(300)).then(|| PROBE_TIMEOUT.min(left / 3))
}

/// [`SiteRoutes`] through the explain probe: the same matcher, overlay and
/// subdomain coverage the routing check in Diagnostics answers with.
pub struct ExplainRoutes {
    diagnostics: Arc<dyn nrr_diagnostics::facade::service::DiagnosticsFacade>,
}

impl ExplainRoutes {
    pub fn new(diagnostics: Arc<dyn nrr_diagnostics::facade::service::DiagnosticsFacade>) -> Self {
        Self { diagnostics }
    }
}

impl SiteRoutes for ExplainRoutes {
    fn route_for(&self, sid: &str, name: &str, address: Option<Ipv4Addr>) -> String {
        self.evidence_for(sid, name, address).route
    }

    fn evidence_for(&self, sid: &str, name: &str, address: Option<Ipv4Addr>) -> RouteEvidence {
        use nrr_diagnostics::explain::{ExplainQuery, RuntimeInputSample};
        let mut sample = RuntimeInputSample::new().with_hostname(name.to_owned());
        if let Some(ip) = address {
            sample = sample.with_ip(ip.to_string());
        }
        let query = ExplainQuery::Synthetic {
            input_sample: sample,
        };
        self.diagnostics
            .get_explain(
                &query,
                nrr_diagnostics::redaction::ExplainDetailLevel::CompactUi,
                sid,
            )
            .map(|r| RouteEvidence {
                route: if r.is_available() {
                    crate::ipc_handlers::diagnostics_handlers::explained_route(&r)
                } else {
                    "unknown".to_owned()
                },
                rule_id: r.match_section.and_then(|m| m.matched_rule_id),
                revision: r.correlation.revision_id,
            })
            .unwrap_or_else(|_| RouteEvidence {
                route: "unknown".to_owned(),
                ..RouteEvidence::default()
            })
    }

    fn covers(&self, sid: &str, name: &str) -> bool {
        use nrr_diagnostics::explain::{ExplainQuery, RuntimeInputSample};
        // By name alone: an address rule matching a cached address would let
        // the cache answer for a name no rule of the caller's names.
        let query = ExplainQuery::Synthetic {
            input_sample: RuntimeInputSample::new().with_hostname(name.to_owned()),
        };
        self.diagnostics
            .get_explain(
                &query,
                nrr_diagnostics::redaction::ExplainDetailLevel::CompactUi,
                sid,
            )
            .ok()
            .and_then(|r| r.final_action_section)
            .is_some_and(|f| rule_matched_reason(&f.reason_key))
    }
}

/// An explain reason saying a rule on the name itself decided. Address and
/// network rules match through the cache, so they do not count; a pause
/// routes by no rule.
fn rule_matched_reason(reason_key: &str) -> bool {
    matches!(
        reason_key.strip_prefix("diag.explain.reason.rule-matched-"),
        Some("exact-fqdn" | "suffix-domain" | "zone")
    )
}
