//! "Is it us or the site?" — one site's names checked over the caller's own
//! routes, when the caller asks.
//!
//! A site that loops between its page and its sign-in looks broken while the
//! network is fine; a sign-in that leaves by another route than the site does
//! breaks for real, because the address changes in the middle of signing in.
//! The check tells the two apart: for the site, its sign-in names and the names
//! the caller's own observation saw with it, it shows the address, the route
//! the caller's rules give it, and whether the name answers over that route.
//!
//! Nothing here sits on a connection's path. It reads what the trace and the
//! auto-rules ledger already hold, resolves nothing (a name the browser never
//! asked for is not part of the problem), connects only to addresses the
//! caller's own traffic or the cache know, and is bounded in names and time.
//! It changes no state: a failure can neither lift Fail-Closed nor touch DNS.

pub mod http_answer;
pub mod https_head;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nrr_domain::companion_affinity::{registrable_domain, site_shared_across_zones};
use nrr_domain::decision_engine_input::hostname_ace;
use nrr_domain::decision_matching::match_suffix_domain;
use nrr_shared::ipc_payloads::{
    SiteCheckNameDto, SiteCheckReport, SiteCheckStatus, SITE_CHECK_MAX_HOST_LEN,
    SITE_CHECK_MAX_NAMES, SITE_CHECK_MAX_REDIRECTS, SITE_CHECK_SIGN_IN_LABELS,
    SITE_CHECK_STATE_DONE, SITE_CHECK_STATE_IDLE, SITE_CHECK_STATE_RUNNING,
    SITE_CHECK_VERDICT_BLOCKED, SITE_CHECK_VERDICT_CERTIFICATE_UNTRUSTED, SITE_CHECK_VERDICT_FINE,
    SITE_CHECK_VERDICT_NOT_ANSWERING, SITE_CHECK_VERDICT_ROUTE_DOWN,
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
}

/// The answer for a name whose certificate does not verify on its route.
const ANSWER_UNTRUSTED: &str = "certificate-untrusted";

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
        "silent" => return (SITE_CHECK_VERDICT_NOT_ANSWERING, Vec::new()),
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
    if sign_in().any(|e| e.answer == "silent" || e.answer == "route-down") {
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
    latest: Mutex<HashMap<String, SiteCheckStatus>>,
    running: AtomicUsize,
}

impl SiteChecker {
    pub fn new(wiring: SiteCheckWiring) -> Self {
        Self {
            wiring,
            latest: Mutex::new(HashMap::new()),
            running: AtomicUsize::new(0),
        }
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
        let planned = plan_names(site, &traced_names, &seen);
        let address_of = |name: &str| -> Option<Ipv4Addr> {
            traced
                .iter()
                .find(|(n, _)| n == name)
                .and_then(|(_, a)| *a)
                .or_else(|| {
                    crate::dns_wire::only_v4(&w.cache.ips_for_hostname(name))
                        .first()
                        .copied()
                })
        };
        let (main, additional) = w.egress.egress_source_ips(sid);
        let source_for = |route: &str| match route {
            "secondary" => additional,
            _ => main,
        };

        let mut examined: Vec<Examined> = planned
            .into_iter()
            .map(|p| {
                let address = address_of(&p.name);
                let route = normalised_route(&w.routes.route_for(sid, &p.name, address));
                Examined {
                    planned: p,
                    address,
                    route,
                    answer: "unclear",
                }
            })
            .collect();
        let probe = |e: &Examined| -> &'static str {
            if e.route == "blocked" {
                return "blocked";
            }
            let Some(target) = e.address else {
                return "no-address";
            };
            let Some(source) = source_for(&e.route) else {
                return "route-down";
            };
            let Some(timeout) = budget_left(deadline) else {
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
        let site_answered = examined.first().is_some_and(|e| e.answer == "answered");
        if let Some(https) = w.https.as_ref() {
            if site_answered {
                let fetch = |host: &str| {
                    let target = address_of(host)?;
                    let route = normalised_route(&w.routes.route_for(sid, host, Some(target)));
                    let source = source_for(&route)?;
                    let request = http_answer::request_for(host)?;
                    let timeout = budget_left(deadline)?;
                    match https.fetch(target, host, source, &request, timeout) {
                        Ok(bytes) => http_answer::parse_head(&bytes).ok(),
                        // Nothing more is read from a name whose certificate
                        // does not verify here.
                        Err(HeadFailure::Untrusted) => {
                            untrusted.push(host.to_owned());
                            None
                        }
                        Err(HeadFailure::NoAnswer) => None,
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
                    let route = normalised_route(&w.routes.route_for(sid, host, address));
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
        for e in examined.iter_mut() {
            if untrusted.contains(&e.planned.name) && e.answer == "answered" {
                e.answer = ANSWER_UNTRUSTED;
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
        let (verdict, move_names) = decide(&site_route, &examined);
        SiteCheckReport {
            site: site.to_owned(),
            verdict: verdict.to_owned(),
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
                    status: if i == 0 { chain.status } else { None },
                    redirects: if i == 0 {
                        chain.hosts.clone()
                    } else {
                        Vec::new()
                    },
                })
                .collect(),
            move_names,
            reads_answer: w.https.is_some(),
        }
    }
}

/// `primary`, `secondary` or `blocked`: an unmatched name takes the main route.
fn normalised_route(route: &str) -> String {
    match route {
        "secondary" | "blocked" => route.to_owned(),
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
            .map(|r| crate::ipc_handlers::diagnostics_handlers::explained_route(&r))
            .unwrap_or_else(|_| "primary".to_owned())
    }
}
