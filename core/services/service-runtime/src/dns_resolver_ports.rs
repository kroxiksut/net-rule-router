//! production port impls for the local
//! DNS resolver.
//!
//! Thin adapters wiring the pure [`crate::dns_resolver`] handler to the real
//! service components — all already used by the seeder / observer, so the
//! resolver reuses the existing enforcement path rather than inventing one:
//!
//! - [`ActiveRuleHostOracle`] — rule matching via `rule_set_matches` (SSOT).
//! - [`PortUpstreamResolver`] — upstream via the platform [`DnsResolverPort`].
//! - [`CacheFactSink`] — FQDN-cache upsert via [`CacheRepository`].
//!
//! The listener (increment 1b-ii) constructs these and hands them to
//! [`crate::dns_resolver::handle_a_query`].

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use nrr_platform_api::dns::{DnsResolverError, DnsResolverPort, ResolvedRecord};
use nrr_storage::dto::ResolutionEntry;
use nrr_storage::repository::CacheRepository;
use nrr_storage::resolution_source::StorageResolutionSource;

use crate::dns_address_sanity::{classify_answer, AnswerSanity};
use crate::dns_observation_consumer::rule_set_matches;
use crate::dns_resolver::{
    FactSink, ReconcileOutcome, ResolveError, ResolvedA, RuleHostOracle, SyncReconciler,
    UpstreamResolver,
};
use crate::net_filter::is_non_routable_v4;
use crate::per_sid_orchestrator::RulesProvider;
use crate::recent_rule_addresses::RecentRuleAddressIndex;
use crate::supervised_runtime::RouteRecomputeHook;

/// TTL (seconds) applied when the upstream record carries none — short, so a
/// rotating host re-installs enforcement soon after via TTL-driven re-query.
const DEFAULT_TTL_SECS: u32 = 300;

/// [`RuleHostOracle`] backed by the active rule book: a query is a rule host iff
/// it matches an enabled **secondary** rule for the routing-active principal
/// (same `rule_set_matches` the DNS observer uses — single source of truth). A
/// non-matching host, or no routing-active user, takes the resolver's fail-open
/// path. Only secondary rules are enforced destinations, so a primary-only
/// match is deliberately NOT a rule host here.
pub struct ActiveRuleHostOracle {
    rules_provider: Arc<dyn RulesProvider>,
    active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync>,
}

impl ActiveRuleHostOracle {
    pub fn new(
        rules_provider: Arc<dyn RulesProvider>,
        active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    ) -> Self {
        Self {
            rules_provider,
            active_sid,
        }
    }
}

impl RuleHostOracle for ActiveRuleHostOracle {
    fn is_rule_host(&self, hostname: &str) -> bool {
        let Some(sid) = (self.active_sid)() else {
            return false;
        };
        let Some(snapshot) = self.rules_provider.active_rules_for(&sid) else {
            return false;
        };
        rule_set_matches(hostname, &snapshot.rule_book.secondary)
    }
}

/// [`UpstreamResolver`] over the platform [`DnsResolverPort`]. The upstream is
/// the system-configured resolver (`DnsQuery_W` today; hickory later), which
/// honours the hosts file + configured servers — so split-horizon / corporate
/// zones resolve correctly, provided it is the resolver captured *before* any
/// DNS redirect (increment 1c).
pub struct PortUpstreamResolver {
    resolver: Arc<dyn DnsResolverPort>,
}

impl PortUpstreamResolver {
    pub fn new(resolver: Arc<dyn DnsResolverPort>) -> Self {
        Self { resolver }
    }
}

impl UpstreamResolver for PortUpstreamResolver {
    fn resolve_a(&self, hostname: &str) -> Result<ResolvedA, ResolveError> {
        match self.resolver.resolve_a(hostname) {
            Ok(ResolvedRecord {
                addresses,
                ttl_seconds,
                ..
            }) => Ok(ResolvedA {
                addresses,
                ttl_seconds: ttl_seconds.unwrap_or(DEFAULT_TTL_SECS),
            }),
            // NXDOMAIN / invalid name = authoritative "no answer".
            Err(e) if e.is_authoritative() => Err(ResolveError::NoRecords),
            // Timeout / refused / network / unsupported = transient/unavailable.
            Err(e) => Err(ResolveError::Unavailable(format!("{e:?}"))),
        }
    }
}

/// [`DnsResolverPort`] over an [`UpstreamResolver`] — the inverse of
/// [`PortUpstreamResolver`].
///
/// It exists so a decorator written for the intercept path can also protect the
/// callers that speak the platform port. Concretely: the rule-host seeder and
/// the DNS refresh populate the FQDN cache the relay dials from, and without
/// this they take a filtering provider's placeholder at face value — the
/// intercept path's second-source confirmation never sees their queries.
pub struct UpstreamResolverPort {
    upstream: Arc<dyn UpstreamResolver>,
}

impl UpstreamResolverPort {
    #[must_use]
    pub fn new(upstream: Arc<dyn UpstreamResolver>) -> Self {
        Self { upstream }
    }
}

impl DnsResolverPort for UpstreamResolverPort {
    fn resolve_a(&self, hostname: &str) -> Result<ResolvedRecord, DnsResolverError> {
        match self.upstream.resolve_a(hostname) {
            Ok(resolved) if !resolved.addresses.is_empty() => {
                // The confirmation above already tried to replace a placeholder
                // with a real answer. One that still looks like a placeholder
                // was not confirmed by anyone, and writing it to the cache would
                // point the rule at nowhere — worse than having no address,
                // because nothing would ever re-query it.
                let addresses = match classify_answer(&resolved.addresses) {
                    AnswerSanity::Clean => resolved.addresses,
                    AnswerSanity::Sanitized { keep } => keep,
                    AnswerSanity::Unusable => {
                        tracing::info!(
                            target: "nrr::dns-resolver",
                            host = %hostname,
                            "no source could answer this host with a usable address — not caching a placeholder",
                        );
                        // Transient, NOT NXDOMAIN: the name almost certainly
                        // exists, we were simply not told where it lives. A
                        // negative entry would also stop the retry that
                        // succeeds the moment the tunnel is up.
                        return Err(DnsResolverError::Timeout {
                            hostname: hostname.to_string(),
                        });
                    }
                };
                Ok(ResolvedRecord {
                    canonical_hostname: hostname.to_ascii_lowercase(),
                    addresses,
                    ttl_seconds: Some(resolved.ttl_seconds),
                })
            }
            // The port's contract: an empty answer IS NXDOMAIN.
            Ok(_) | Err(ResolveError::NoRecords) => Err(DnsResolverError::NxDomain {
                hostname: hostname.to_string(),
            }),
            // The inner layers do not distinguish timeout from refusal, and the
            // callers treat both as "retry later" — the honest mapping is the
            // transient one.
            Err(ResolveError::Unavailable(_)) => Err(DnsResolverError::Timeout {
                hostname: hostname.to_string(),
            }),
        }
    }
}

/// [`UpstreamResolver`] that speaks RFC 1035 wire format straight to
/// ONE upstream server over a raw UDP socket ([`crate::dns_wire`] client codec).
///
/// This is the Mode-B upstream PIN: the OS resolver (`DnsQuery_W`) honours the
/// very NRPT catch-all Mode B installs, so resolving a rule host through it
/// loops back into our own loopback listener and times out (HW-0712 C10-a —
/// "Mode B rubs ALL DNS"). A raw socket is invisible to NRPT by construction
/// (NRPT steers only the Windows DNS Client service), and it never consults
/// the hosts file — which is also the enforcement mechanism behind the
/// `resolve_hosts_bypass` posture for rule hosts. OS-neutral: std sockets, no
/// Win32 (the *choice* of upstream address stays with the caller, which is
/// where the per-OS capture lives).
pub struct DirectUdpUpstreamResolver {
    server: std::net::SocketAddr,
    timeout: Duration,
    attempts: u32,
    /// Optional live egress policy (DNS-over-secondary). When wired, it decides
    /// per attempt which upstream is asked and which local address the socket
    /// binds to; when absent, every attempt uses `server` unbound — the
    /// historical behaviour.
    egress: Option<Arc<dyn crate::dns_egress::DnsEgressPolicy>>,
}

/// Process-wide message-id sequence, seeded from the clock so ids differ
/// across service restarts. Sequential ids are fine here: the socket is
/// connected to ONE trusted upstream and every response is matched on
/// id + question before acceptance.
static NEXT_QUERY_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
static QUERY_ID_SEEDED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn next_query_id() -> u16 {
    use std::sync::atomic::Ordering;
    if !QUERY_ID_SEEDED.swap(true, Ordering::Relaxed) {
        let seed = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u16)
            .unwrap_or(0);
        NEXT_QUERY_ID.store(seed, Ordering::Relaxed);
    }
    NEXT_QUERY_ID.fetch_add(1, Ordering::Relaxed)
}

impl DirectUdpUpstreamResolver {
    /// `timeout` is the per-attempt receive window; `attempts` bounds the
    /// send+wait cycles (so worst case ≈ `attempts × timeout`).
    pub fn new(server: std::net::SocketAddr, timeout: Duration, attempts: u32) -> Self {
        Self {
            server,
            timeout,
            attempts: attempts.max(1),
            egress: None,
        }
    }

    /// Attach the live DNS-egress policy so each attempt can be sent through
    /// the secondary link to a public resolver instead of the primary
    /// provider's. Chain after [`Self::new`].
    pub fn with_egress(mut self, egress: Arc<dyn crate::dns_egress::DnsEgressPolicy>) -> Self {
        self.egress = Some(egress);
        self
    }

    /// The upstream + source binding for one attempt. No policy — or a policy
    /// that declines (feature off, secondary unusable) — means this resolver's
    /// own configured server, unbound.
    fn egress_for(&self, attempt: u32) -> crate::dns_egress::DnsEgress {
        self.egress
            .as_ref()
            .and_then(|policy| policy.decide(attempt))
            .unwrap_or_else(|| crate::dns_egress::DnsEgress::primary(self.server))
    }

    /// Open the query socket for one attempt: bound to the egress policy's
    /// local address when it names one, else to the unspecified address.
    ///
    /// A bind failure on a specific source is NOT fatal by itself — the
    /// adapter may have just dropped its address — but it must not silently
    /// fall back to an unbound socket: that would leak the query over the
    /// primary link, which is exactly what the setting exists to prevent. The
    /// attempt fails instead and the policy re-decides on the next one.
    fn open_socket(
        egress: &crate::dns_egress::DnsEgress,
    ) -> Result<std::net::UdpSocket, ResolveError> {
        match egress.bind {
            Some(src) => std::net::UdpSocket::bind((src, 0))
                .map_err(|e| ResolveError::Unavailable(format!("bind {src}: {e}"))),
            None => std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                .map_err(|e| ResolveError::Unavailable(format!("bind: {e}"))),
        }
    }

    /// One send + receive window. Loops on non-matching datagrams (late replies
    /// of a previous query, off-path noise) until the window elapses.
    fn attempt(
        &self,
        query: &[u8],
        id: u16,
        hostname: &str,
        egress: &crate::dns_egress::DnsEgress,
    ) -> Result<ResolvedA, ResolveError> {
        use crate::dns_wire::{parse_a_response, AResponseOutcome};
        let sock = Self::open_socket(egress)?;
        sock.send_to(query, egress.server)
            .map_err(|e| ResolveError::Unavailable(format!("send: {e}")))?;
        let started = std::time::Instant::now();
        let mut buf = [0u8; 2048];
        loop {
            let remaining = self.timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(ResolveError::Unavailable("timeout".into()));
            }
            sock.set_read_timeout(Some(remaining))
                .map_err(|e| ResolveError::Unavailable(format!("timeout cfg: {e}")))?;
            let n = match sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(ResolveError::Unavailable("timeout".into()))
                }
                // Port-unreachable & co. — same per-datagram noise the listener
                // loop tolerates; keep waiting out the window.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(ResolveError::Unavailable(format!("recv: {e}"))),
            };
            match parse_a_response(id, hostname, &buf[..n]) {
                AResponseOutcome::Answers { addresses, min_ttl } => {
                    return Ok(ResolvedA {
                        addresses,
                        // A 0-TTL record still needs a positive cache horizon;
                        // 1 s keeps "do not cache" spirit without a special case.
                        ttl_seconds: min_ttl.max(1),
                    });
                }
                AResponseOutcome::NoRecords => return Err(ResolveError::NoRecords),
                AResponseOutcome::Truncated => {
                    // No TCP fallback in phase 1 — surface as transient so the
                    // listener fail-opens (forwards raw) instead of NXDOMAIN-ing.
                    return Err(ResolveError::Unavailable("truncated (TC=1)".into()));
                }
                AResponseOutcome::Failed(rcode) => {
                    return Err(ResolveError::Unavailable(format!("rcode {rcode}")));
                }
                AResponseOutcome::Mismatch => continue,
            }
        }
    }
}

impl DirectUdpUpstreamResolver {
    /// one PTR send + receive window for `ip`.
    /// Loops on non-matching datagrams within the window like [`attempt`].
    fn attempt_ptr(
        &self,
        query: &[u8],
        id: u16,
        ip: Ipv4Addr,
        egress: &crate::dns_egress::DnsEgress,
    ) -> Result<Vec<String>, ResolveError> {
        use crate::dns_wire::{parse_ptr_response, PtrResponseOutcome};
        let sock = Self::open_socket(egress)?;
        sock.send_to(query, egress.server)
            .map_err(|e| ResolveError::Unavailable(format!("send: {e}")))?;
        let started = std::time::Instant::now();
        let mut buf = [0u8; 2048];
        loop {
            let remaining = self.timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(ResolveError::Unavailable("timeout".into()));
            }
            sock.set_read_timeout(Some(remaining))
                .map_err(|e| ResolveError::Unavailable(format!("timeout cfg: {e}")))?;
            let n = match sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(ResolveError::Unavailable("timeout".into()))
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(ResolveError::Unavailable(format!("recv: {e}"))),
            };
            match parse_ptr_response(id, ip, &buf[..n]) {
                PtrResponseOutcome::Names(names) => return Ok(names),
                PtrResponseOutcome::NoRecords => return Err(ResolveError::NoRecords),
                PtrResponseOutcome::Truncated => {
                    return Err(ResolveError::Unavailable("truncated (TC=1)".into()))
                }
                PtrResponseOutcome::Failed(rcode) => {
                    return Err(ResolveError::Unavailable(format!("rcode {rcode}")))
                }
                PtrResponseOutcome::Mismatch => continue,
            }
        }
    }

    /// Reverse-resolve `ip` to its PTR name(s) over the trusted upstream. Empty
    /// vec on NXDOMAIN / no records; `Err` only on transient transport failure
    /// (the FCrDNS learner treats both as "no name").
    pub fn resolve_ptr(&self, ip: Ipv4Addr) -> Result<Vec<String>, ResolveError> {
        use crate::dns_wire::build_ptr_query;
        let id = next_query_id();
        let Some(query) = build_ptr_query(id, ip) else {
            return Err(ResolveError::NoRecords);
        };
        let mut last = ResolveError::Unavailable("no attempts".into());
        for attempt in 0..self.attempts {
            let egress = self.egress_for(attempt);
            match self.attempt_ptr(&query, id, ip, &egress) {
                Ok(names) => return Ok(names),
                Err(ResolveError::NoRecords) => return Err(ResolveError::NoRecords),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

impl UpstreamResolver for DirectUdpUpstreamResolver {
    fn resolve_a(&self, hostname: &str) -> Result<ResolvedA, ResolveError> {
        use crate::dns_wire::build_a_query;
        let id = next_query_id();
        // An unencodable name (empty/oversized label, non-ASCII — IDN arrives
        // here already punycoded) can never resolve: authoritative no-answer.
        let Some(query) = build_a_query(id, hostname) else {
            return Err(ResolveError::NoRecords);
        };
        let mut last = ResolveError::Unavailable("no attempts".into());
        for attempt in 0..self.attempts {
            let egress = self.egress_for(attempt);
            match self.attempt(&query, id, hostname, &egress) {
                Ok(resolved) => {
                    tracing::debug!(
                        target: "nrr::dns-resolver",
                        host = %hostname,
                        upstream = %egress.server,
                        via_secondary = egress.via_secondary,
                        addresses = resolved.addresses.len(),
                        ttl = resolved.ttl_seconds,
                        attempt,
                        "direct upstream A query answered",
                    );
                    return Ok(resolved);
                }
                Err(ResolveError::NoRecords) => return Err(ResolveError::NoRecords),
                Err(e) => {
                    tracing::debug!(
                        target: "nrr::dns-resolver",
                        host = %hostname,
                        upstream = %egress.server,
                        via_secondary = egress.via_secondary,
                        attempt,
                        error = %match &e {
                            ResolveError::Unavailable(msg) => msg.as_str(),
                            ResolveError::NoRecords => "no records",
                        },
                        "direct upstream A query attempt failed",
                    );
                    last = e;
                }
            }
        }
        Err(last)
    }
}

/// Second-source confirmation for a suspect RULE-host answer.
///
/// The captured ISP upstream is what preserves split-horizon zones, but a
/// filtering provider answers rule hosts with a placeholder rather than a
/// destination: loopback/unspecified stubs, a bare NXDOMAIN (observed on
/// rotating `googlevideo.com` video nodes), or a synthetic address pair handed
/// to every blocked name alike. Such an answer is worthless to enforcement, so
/// this decorator re-asks the public resolvers
/// ([`crate::dns_egress::PUBLIC_DNS_SERVERS`]). It fires only when the captured
/// upstream's answer is already unusable, so there is nothing to lose by
/// asking. When an egress policy is wired (see [`Self::with_egress`]) the
/// confirming query leaves through the tunnel — on the primary link the same
/// interception that produced the placeholder also answers the confirmation.
///
/// Two triggers, both cheap and both requiring an actual suspicion — the
/// ordinary answer never leaves the primary path:
///
/// 1. **Nothing in the answer could be a destination** (see
///    [`crate::dns_address_sanity`]), NXDOMAIN included.
/// 2. **The whole address set already belongs to an unrelated hostname** — one
///    upstream cache entry serving every filtered name at once. Read from the
///    recent-resolution memory the resolver already maintains, so it costs no
///    extra work.
///
/// What counts as confirmation differs per trigger. An unusable answer is
/// settled by any usable one. A reuse collision is settled by *agreement*: an
/// upstream serving one cache entry for many names cannot make an independent
/// resolver repeat it, so a second source returning the same addresses proves
/// the set genuine. Demanding that the second answer raise no suspicion would
/// reject every honest one, since a truthful answer carries the very address
/// set that raised the alarm.
///
/// When nothing confirms — or the confirmation budget runs out — the original
/// outcome is returned unchanged (split horizon keeps working: an internal-zone
/// host resolves fine upstream and never reaches the fallback at all).
pub struct PoisonFallbackUpstreamResolver {
    inner: Arc<dyn UpstreamResolver>,
    fallbacks: Vec<Arc<dyn UpstreamResolver>>,
    /// Memory of what other rule hostnames recently resolved to. `None` = the
    /// reuse trigger is not wired (tests / non-resolver callers).
    recent: Option<Arc<RecentRuleAddressIndex>>,
}

/// Why an upstream answer is not taken at face value.
#[derive(Clone, Debug)]
enum Suspicion {
    /// Not one address in it could be a destination.
    NoUsableAddress,
    /// The whole address set is already spoken for by an unrelated hostname.
    AlsoAnsweredFor(String),
}

impl Suspicion {
    fn as_str(&self) -> &'static str {
        match self {
            Self::NoUsableAddress => "no usable address",
            Self::AlsoAnsweredFor(_) => "same address set as an unrelated host",
        }
    }
}

/// How an independent resolver settled a suspicion.
#[derive(Clone, Copy, Debug)]
enum Confirmation {
    /// It named the same addresses — the alarm was a false positive.
    Agreed,
    /// It named different, usable addresses — those are answered instead.
    Replaced,
}

impl PoisonFallbackUpstreamResolver {
    /// Per-attempt timeout for one public resolver. A working link answers a
    /// public resolver in tens of milliseconds; this only bounds a dead one.
    const FALLBACK_TIMEOUT: Duration = Duration::from_millis(700);

    /// Wall-clock cap on the whole confirmation, checked before each attempt.
    /// Two attempts fit inside it, so the client's answer is delayed by at most
    /// this much — comfortably under the listener's forward timeout. Past the
    /// cap the upstream answer is returned unconfirmed, and the downstream
    /// sanity gate then refuses to pin it.
    const CONFIRM_BUDGET: Duration = Duration::from_millis(1400);

    #[must_use]
    pub fn new(inner: Arc<dyn UpstreamResolver>) -> Self {
        Self {
            inner,
            fallbacks: Self::public_fallbacks(None),
            recent: None,
        }
    }

    /// Send the confirming query through the tunnel whenever the egress policy
    /// says one is available.
    ///
    /// Asking a public resolver over plain UDP/53 on the primary link does not
    /// escape a provider that answers for names it filters — the same
    /// interception that produced the placeholder answers the confirmation too,
    /// so the second source agrees with the first and the host is never pinned.
    /// The tunnel is what makes the second source independent. Degrades on its
    /// own: with the feature off or the tunnel down the policy returns nothing
    /// and the query takes the primary path exactly as before.
    #[must_use]
    pub fn with_egress(mut self, egress: Arc<dyn crate::dns_egress::DnsEgressPolicy>) -> Self {
        self.fallbacks = Self::public_fallbacks(Some(egress));
        self
    }

    fn public_fallbacks(
        egress: Option<Arc<dyn crate::dns_egress::DnsEgressPolicy>>,
    ) -> Vec<Arc<dyn UpstreamResolver>> {
        crate::dns_egress::PUBLIC_DNS_SERVERS
            .iter()
            .map(|ip| {
                let mut resolver = DirectUdpUpstreamResolver::new(
                    std::net::SocketAddr::from((*ip, crate::dns_egress::DNS_PORT)),
                    Self::FALLBACK_TIMEOUT,
                    1,
                );
                if let Some(policy) = egress.clone() {
                    resolver = resolver.with_egress(policy);
                }
                Arc::new(resolver) as Arc<dyn UpstreamResolver>
            })
            .collect()
    }

    /// Replace the fallback resolvers (tests).
    #[must_use]
    pub fn with_fallbacks(mut self, fallbacks: Vec<Arc<dyn UpstreamResolver>>) -> Self {
        self.fallbacks = fallbacks;
        self
    }

    /// Wire the recent-resolution memory that arms the address-reuse trigger.
    #[must_use]
    pub fn with_recent_addresses(mut self, recent: Arc<RecentRuleAddressIndex>) -> Self {
        self.recent = Some(recent);
        self
    }

    /// Is the whole answer already remembered for ONE other hostname that
    /// shares no origin with this one? Two unrelated names cannot honestly
    /// resolve to an identical set.
    ///
    /// Bails on the first address nobody remembers, so an ordinary answer costs
    /// a single map lookup.
    fn reused_by_another_host(&self, hostname: &str, addresses: &[Ipv4Addr]) -> Option<String> {
        let recent = self.recent.as_ref()?;
        let mut owner: Option<String> = None;
        for ip in addresses {
            let previous = recent.lookup(*ip)?;
            if crate::dns_resolver::hosts_share_origin(hostname, &previous) {
                return None;
            }
            match &owner {
                None => owner = Some(previous),
                // More than one prior owner means a shared front end, not a
                // wholesale reassignment.
                Some(seen) if *seen != previous => return None,
                Some(_) => {}
            }
        }
        owner
    }

    /// Why `resolved` needs a second source, or `None` when it stands alone.
    fn suspicion(&self, hostname: &str, resolved: &ResolvedA) -> Option<Suspicion> {
        if matches!(classify_answer(&resolved.addresses), AnswerSanity::Unusable) {
            return Some(Suspicion::NoUsableAddress);
        }
        self.reused_by_another_host(hostname, &resolved.addresses)
            .map(Suspicion::AlsoAnsweredFor)
    }

    /// How `candidate` settles `suspicion`, or `None` when it does not.
    fn confirmation(
        &self,
        hostname: &str,
        suspicion: &Suspicion,
        primary: Option<&ResolvedA>,
        candidate: &ResolvedA,
    ) -> Option<Confirmation> {
        if candidate.addresses.is_empty()
            || matches!(
                classify_answer(&candidate.addresses),
                AnswerSanity::Unusable
            )
        {
            return None;
        }
        let agreed = matches!(suspicion, Suspicion::AlsoAnsweredFor(_))
            && primary.is_some_and(|p| same_address_set(&p.addresses, &candidate.addresses));
        if agreed {
            return Some(Confirmation::Agreed);
        }
        self.reused_by_another_host(hostname, &candidate.addresses)
            .is_none()
            .then_some(Confirmation::Replaced)
    }
}

/// Do two answers name the same addresses, order aside? Answer sets are a
/// handful of entries, so the quadratic scan beats allocating a set.
fn same_address_set(a: &[Ipv4Addr], b: &[Ipv4Addr]) -> bool {
    a.len() == b.len() && a.iter().all(|ip| b.contains(ip))
}

impl UpstreamResolver for PoisonFallbackUpstreamResolver {
    fn resolve_a(&self, hostname: &str) -> Result<ResolvedA, ResolveError> {
        let primary = self.inner.resolve_a(hostname);
        let suspicion = match &primary {
            Ok(resolved) => self.suspicion(hostname, resolved),
            Err(ResolveError::NoRecords) => Some(Suspicion::NoUsableAddress),
            // Transport failure: the egress policy / attempt rotation already
            // handles availability; adding more timeouts here would only stall
            // the client.
            Err(ResolveError::Unavailable(_)) => None,
        };
        let Some(suspicion) = suspicion else {
            return primary;
        };
        if let Suspicion::AlsoAnsweredFor(other) = &suspicion {
            tracing::warn!(
                target: "nrr::dns-resolver",
                host = %hostname,
                also_answered_for = %other,
                "upstream handed this host the exact address set of an unrelated one — asking a second source",
            );
        }
        let started = std::time::Instant::now();
        for fallback in &self.fallbacks {
            if started.elapsed() >= Self::CONFIRM_BUDGET {
                break;
            }
            let Ok(candidate) = fallback.resolve_a(hostname) else {
                continue;
            };
            match self.confirmation(hostname, &suspicion, primary.as_ref().ok(), &candidate) {
                Some(Confirmation::Agreed) => {
                    tracing::info!(
                        target: "nrr::dns-resolver",
                        host = %hostname,
                        addresses = candidate.addresses.len(),
                        "an independent resolver named the same addresses — the reuse alarm was a false alarm",
                    );
                    return Ok(candidate);
                }
                Some(Confirmation::Replaced) => {
                    tracing::info!(
                        target: "nrr::dns-resolver",
                        host = %hostname,
                        reason = %suspicion.as_str(),
                        addresses = candidate.addresses.len(),
                        "captured upstream answered a rule host with an unusable answer — a public resolver answered clean",
                    );
                    return Ok(candidate);
                }
                None => {}
            }
        }
        // Two different outcomes, so two messages: an unusable answer really is
        // dropped by the downstream sanity gate, a reuse collision is not.
        match &suspicion {
            Suspicion::NoUsableAddress => tracing::warn!(
                target: "nrr::dns-resolver",
                host = %hostname,
                reason = %suspicion.as_str(),
                "no second source could confirm this host's addresses — returning the upstream answer unconfirmed (it will not be pinned)",
            ),
            Suspicion::AlsoAnsweredFor(other) => tracing::warn!(
                target: "nrr::dns-resolver",
                host = %hostname,
                also_answered_for = %other,
                "no second source could confirm this host's addresses — answering with the upstream set as-is",
            ),
        }
        primary
    }
}

/// hosts-bypass decorator over the platform [`DnsResolverPort`].
///
/// The seeder / DNS-refresh resolve rule hosts through the OS resolver, which
/// honours the hosts/adblock file — so a pinned rule host (`musical.ly →
/// 127.0.0.1`, 332× in the 0712 log) never yields a routable public IP and the
/// rule never enforces. When the per-SID `resolve_hosts_bypass` posture is ON
/// (the default), this decorator resolves rule hosts DIRECTLY against the
/// captured upstream server over raw UDP instead, skipping the hosts file by
/// construction. Degrades gracefully: bypass off, no captured upstream, or a
/// transient direct failure all fall back to the system resolver (whose
/// loopback answers the downstream `is_non_routable_v4` filter already drops).
///
/// OS-neutral: the *mechanism* for capturing the upstream address and reading
/// the per-SID posture is injected as closures by the per-OS composition root.
pub struct HostsBypassDnsResolver {
    system: Arc<dyn DnsResolverPort>,
    bypass_enabled: Arc<dyn Fn() -> bool + Send + Sync>,
    /// Full upstream address (the composition root supplies `captured_ip:53`;
    /// tests supply an ephemeral fake). `None` = no upstream available.
    upstream: Arc<dyn Fn() -> Option<std::net::SocketAddr> + Send + Sync>,
    timeout: Duration,
    /// Optional DNS-over-secondary policy, handed to each direct query so the
    /// seeder and refresh take the same egress path as the Mode-B resolver.
    egress: Option<Arc<dyn crate::dns_egress::DnsEgressPolicy>>,
}

impl HostsBypassDnsResolver {
    pub fn new(
        system: Arc<dyn DnsResolverPort>,
        bypass_enabled: Arc<dyn Fn() -> bool + Send + Sync>,
        upstream: Arc<dyn Fn() -> Option<std::net::SocketAddr> + Send + Sync>,
        timeout: Duration,
    ) -> Self {
        Self {
            system,
            bypass_enabled,
            upstream,
            timeout,
            egress: None,
        }
    }

    /// Attach the DNS-over-secondary policy so the direct (hosts-bypassing)
    /// queries this resolver makes leave over the same link as the Mode-B
    /// resolver's. Chain after [`Self::new`].
    pub fn with_egress(mut self, egress: Arc<dyn crate::dns_egress::DnsEgressPolicy>) -> Self {
        self.egress = Some(egress);
        self
    }
}

impl DnsResolverPort for HostsBypassDnsResolver {
    fn resolve_a(&self, hostname: &str) -> Result<ResolvedRecord, DnsResolverError> {
        if !(self.bypass_enabled)() {
            return self.system.resolve_a(hostname);
        }
        let Some(server) = (self.upstream)() else {
            // No captured upstream (capture failed / not yet available) —
            // resolve through the system rather than not at all.
            return self.system.resolve_a(hostname);
        };
        let canonical = nrr_platform_api::dns::canonicalize_hostname(hostname);
        if canonical.is_empty() {
            return Err(DnsResolverError::InvalidName { name: canonical });
        }
        let mut direct = DirectUdpUpstreamResolver::new(server, self.timeout, 2);
        if let Some(policy) = &self.egress {
            direct = direct.with_egress(Arc::clone(policy));
        }
        match direct.resolve_a(&canonical) {
            Ok(ResolvedA {
                addresses,
                ttl_seconds,
            }) => Ok(ResolvedRecord {
                canonical_hostname: canonical,
                addresses,
                ttl_seconds: Some(ttl_seconds),
            }),
            Err(ResolveError::NoRecords) => Err(DnsResolverError::NxDomain {
                hostname: canonical,
            }),
            // Transient direct failure → system fallback. A hosts-poisoned
            // loopback answer is filtered downstream; an unreachable upstream
            // must not zero out general rule seeding.
            Err(ResolveError::Unavailable(reason)) => {
                tracing::debug!(
                    target: "nrr::dns-resolver",
                    host = %canonical,
                    upstream = %server,
                    reason = %reason,
                    "hosts-bypass direct resolve failed — falling back to the system resolver",
                );
                self.system.resolve_a(hostname)
            }
        }
    }
}

/// Build the FQDN-cache entry for a resolver fact, dropping non-routable
/// addresses first (an ad-block hosts pin to `127.0.0.1` / `0.0.0.0` must never
/// become a `/32` route out the secondary link). `None` when nothing routable
/// remains — the caller then records nothing. Pure; the injected `now` keeps it
/// deterministic for tests.
fn build_resolution_entry(
    hostname: &str,
    resolved: &ResolvedA,
    now: SystemTime,
) -> Option<ResolutionEntry> {
    let routable: Vec<Ipv4Addr> = resolved
        .addresses
        .iter()
        .copied()
        .filter(|ip| !is_non_routable_v4(ip))
        .collect();
    if routable.is_empty() {
        return None;
    }
    Some(ResolutionEntry {
        canonical_hostname: hostname.to_string(),
        raw_hostname_sample: None,
        resolved_ips: routable,
        ttl_seconds: Some(resolved.ttl_seconds),
        source: StorageResolutionSource::Dns,
        resolved_at: now,
        active_revision_id: None,
    })
}

/// [`FactSink`] that upserts resolver-learned facts into the FQDN cache with
/// `source = Dns` (union semantics via the `UNIQUE(hostname, ip, source)`
/// constraint), mirroring the seeder's proven upsert path.
pub struct CacheFactSink {
    cache: Arc<Mutex<dyn CacheRepository + Send>>,
    /// П0-D — read-side view over the same cache for the stable-answer
    /// preference ([`FactSink::cached_routable_ips`]).
    lookup: crate::fqdn_cache_lookup::SqliteFqdnCacheLookup,
}

impl CacheFactSink {
    pub fn new(cache: Arc<Mutex<dyn CacheRepository + Send>>) -> Self {
        let lookup = crate::fqdn_cache_lookup::SqliteFqdnCacheLookup::new(
            Arc::clone(&cache),
            nrr_domain::decision_lookup::FreshnessThresholds::default_production(),
        );
        Self { cache, lookup }
    }
}

impl FactSink for CacheFactSink {
    fn record(&self, hostname: &str, resolved: &ResolvedA) {
        let Some(entry) = build_resolution_entry(hostname, resolved, SystemTime::now()) else {
            return; // nothing routable to enforce
        };
        let guard = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(e) = guard.upsert_resolution(entry) {
            tracing::warn!(
                target: "nrr::dns-resolver",
                error = %e,
                "upsert_resolution failed while recording resolver fact",
            );
        }
    }

    fn cached_routable_ips(&self, hostname: &str) -> Vec<Ipv4Addr> {
        use crate::fqdn_cache_lookup::FqdnCacheLookup;
        self.lookup.ips_for_hostname(hostname)
    }
}

/// production [`SecondaryOwnedIps`]: the pinned
/// address set of the routing-active principal's secondary rules, derived from
/// the same rule-book × FQDN-cache join the DNS observer uses
/// ([`crate::dns_observation_consumer::build_secondary_ip_owners`]). Memoized
/// for a few seconds — the listener consults it on every direct-host `A`
/// answer, and the underlying join walks the whole secondary rule fan-out.
///
/// ## Why this set is NOT gated on the secondary being usable
///
/// A  change emptied this set whenever the secondary could not carry
/// traffic, on the premise that "nothing is pinned to a dead link, so there is
/// nothing to steer away from". The premise is inverted: an unusable secondary
/// is exactly when the fail-closed posture installs a BLOCK over these
/// addresses, so they go from "would take a detour" to "will be dropped" — the
/// moment a direct host most needs to be steered off them. The  run
/// showed the consequence: with the secondary down, a direct host sharing
/// front-end addresses with a secondary rule host received those addresses
/// verbatim and lost connectivity, while the steering that would have handed it
/// clean ones stood down. Steering is therefore unconditional.
///
/// Steering away can never leak rule-host traffic: it only ever REMOVES
/// addresses from a NON-rule host's answer (rule hosts are intercepted and
/// answered upstream of this path), and it removes nothing from the enforced
/// pin/block set. The worst case is over-caution — a direct host is offered a
/// smaller address set than it strictly needed, and a fully-shared answer falls
/// through to the unchanged fail-open reply.
pub struct ActiveSecondaryOwnedIps {
    rules_provider: Arc<dyn RulesProvider>,
    active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    fqdn: Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
    memo: Mutex<Option<(std::time::Instant, std::collections::HashSet<Ipv4Addr>)>>,
}

/// How long one computed owned-set snapshot serves steering before a rebuild.
/// Short enough to follow rule edits / cache growth promptly; long enough that
/// a burst of DNS queries costs one join, not one per query.
const OWNED_SET_MEMO_TTL: Duration = Duration::from_secs(3);

impl ActiveSecondaryOwnedIps {
    pub fn new(
        rules_provider: Arc<dyn RulesProvider>,
        active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync>,
        fqdn: Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
    ) -> Self {
        Self {
            rules_provider,
            active_sid,
            fqdn,
            memo: Mutex::new(None),
        }
    }

    fn rebuild(&self) -> std::collections::HashSet<Ipv4Addr> {
        let Some(sid) = (self.active_sid)() else {
            return std::collections::HashSet::new();
        };
        let Some(snapshot) = self.rules_provider.active_rules_for(&sid) else {
            return std::collections::HashSet::new();
        };
        crate::dns_observation_consumer::build_secondary_ip_owners(
            &snapshot.rule_book.secondary,
            self.fqdn.as_ref(),
        )
        .into_keys()
        .collect()
    }

    /// Memoized read with an injected `now` — the trait impl passes
    /// `Instant::now()`; tests advance `now` to cross the memo TTL without
    /// sleeping.
    fn owned_ips_at(&self, now: std::time::Instant) -> std::collections::HashSet<Ipv4Addr> {
        let mut guard = self.memo.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((at, set)) = guard.as_ref() {
            if now.saturating_duration_since(*at) < OWNED_SET_MEMO_TTL {
                return set.clone();
            }
        }
        let set = self.rebuild();
        *guard = Some((now, set.clone()));
        set
    }
}

impl crate::dns_resolver::SecondaryOwnedIps for ActiveSecondaryOwnedIps {
    fn secondary_owned_ips(&self) -> std::collections::HashSet<Ipv4Addr> {
        self.owned_ips_at(std::time::Instant::now())
    }
}

/// [`SyncReconciler`] that drives the existing route/WFP reconcile — the
/// `RouteRecomputeHook` (seed + `recompute_active` + leak-guard coverage) — and
/// blocks until it finishes, bounded by the caller's deadline. The reconcile is
/// synchronous and idempotent, so "it returned" means the routes + filters are
/// installed; running it inline is the "awaitable" the resolver needs.
///
/// To honour the deadline without a cancellable reconcile, the hook runs on ONE
/// dedicated worker thread and callers wait on a generation counter: if the
/// deadline elapses first we report [`ReconcileOutcome::DeadlineExceeded`]
/// (fail-open on latency — the app gets its answer while the reconcile finishes
/// in the background and the async safety tick converges). A slow enforcement
/// beats a stalled browser.
///
/// Coalescing (HW-0722, the §9 refinement, promoted from "future"): the 0722
/// boot log showed thread-per-call reconciles convoying on the orchestrator
/// lock under the armed block-all — each new direct host spawned another full
/// reconcile, every one slower than the last, and 92% of the direct-answer
/// gates blew their budget. Now a caller registers its generation (its facts
/// are already recorded/registered by then) and is satisfied by the first hook
/// run that STARTS after its registration; concurrent callers share that run.
/// The worker lives for the reconciler's lifetime and exits on drop.
pub struct HookSyncReconciler {
    hook: RouteRecomputeHook,
    state: Arc<(Mutex<ReconcileWorkerState>, std::sync::Condvar)>,
}

#[derive(Default)]
struct ReconcileWorkerState {
    /// Highest generation any caller has requested.
    requested: u64,
    /// Highest generation the worker has fully reconciled (the hook run that
    /// completed it started no earlier than the request).
    completed: u64,
    worker_spawned: bool,
    shutdown: bool,
}

impl HookSyncReconciler {
    pub fn new(hook: RouteRecomputeHook) -> Self {
        Self {
            hook,
            state: Arc::new((
                Mutex::new(ReconcileWorkerState::default()),
                std::sync::Condvar::new(),
            )),
        }
    }

    /// Single worker loop: run the hook once per outstanding batch of requests,
    /// crediting every caller whose request preceded the run's start.
    fn worker_loop(
        hook: RouteRecomputeHook,
        state: Arc<(Mutex<ReconcileWorkerState>, std::sync::Condvar)>,
    ) {
        let (lock, cv) = &*state;
        loop {
            let target = {
                let mut guard = lock.lock().unwrap_or_else(|p| p.into_inner());
                loop {
                    if guard.shutdown {
                        return;
                    }
                    if guard.requested > guard.completed {
                        break guard.requested;
                    }
                    guard = cv.wait(guard).unwrap_or_else(|p| p.into_inner());
                }
            };
            // Hook runs OUTSIDE the lock — new requests keep registering while
            // it works; they will be covered by the NEXT run (their facts may
            // have landed mid-run, so this run cannot vouch for them).
            let started = std::time::Instant::now();
            hook();
            let took = started.elapsed();
            let mut guard = lock.lock().unwrap_or_else(|p| p.into_inner());
            let credited = target.saturating_sub(guard.completed);
            let queued = guard.requested.saturating_sub(target);
            guard.completed = guard.completed.max(target);
            cv.notify_all();
            drop(guard);
            // The answer gate's budget is spent waiting for this, and a waiter
            // that arrived mid-run pays for this run PLUS the next one. Without
            // the duration, a run of unenforced answers cannot be told apart
            // from a resolver that never asked.
            tracing::debug!(
                target: "nrr::dns",
                took_ms = took.as_millis() as u64,
                credited,
                queued,
                "route/WFP reconcile run finished",
            );
        }
    }
}

impl Drop for HookSyncReconciler {
    fn drop(&mut self) {
        let (lock, cv) = &*self.state;
        let mut guard = lock.lock().unwrap_or_else(|p| p.into_inner());
        guard.shutdown = true;
        cv.notify_all();
    }
}

impl SyncReconciler for HookSyncReconciler {
    fn reconcile_now(&self, deadline: Duration) -> ReconcileOutcome {
        let (lock, cv) = &*self.state;
        let my_gen = {
            let mut guard = lock.lock().unwrap_or_else(|p| p.into_inner());
            guard.requested += 1;
            if !guard.worker_spawned {
                guard.worker_spawned = true;
                let hook = Arc::clone(&self.hook);
                let state = Arc::clone(&self.state);
                std::thread::spawn(move || Self::worker_loop(hook, state));
            }
            cv.notify_all();
            guard.requested
        };
        let start = std::time::Instant::now();
        let mut guard = lock.lock().unwrap_or_else(|p| p.into_inner());
        loop {
            if guard.completed >= my_gen {
                return ReconcileOutcome::Installed;
            }
            let Some(remaining) = deadline
                .checked_sub(start.elapsed())
                .filter(|d| !d.is_zero())
            else {
                return ReconcileOutcome::DeadlineExceeded;
            };
            let (next, timeout) = cv
                .wait_timeout(guard, remaining)
                .unwrap_or_else(|p| p.into_inner());
            guard = next;
            if timeout.timed_out() && guard.completed < my_gen {
                return ReconcileOutcome::DeadlineExceeded;
            }
        }
    }
}

// ── FCrDNS learner adapters (HW-0719, killswitch-B) ─────────────────────────

use crate::dns_observation_consumer::DnsObservationConsumer;
use crate::fcrdns_learner::{ConfirmedHostSink, ReverseDnsResolver};

/// Production [`ReverseDnsResolver`]: PTR + forward-`A` over the captured trusted
/// upstream (raw UDP), reusing [`DirectUdpUpstreamResolver`]. The upstream address
/// is injected as a closure (the composition root supplies `captured_ip:53`) so
/// the same split-horizon server the OS uses answers — never a hardcoded public
/// resolver. Both calls are best-effort: any failure yields an empty result, so
/// the FCrDNS learner simply does not learn that IP.
pub struct FcrdnsUpstreamResolver {
    upstream: Arc<dyn Fn() -> Option<std::net::SocketAddr> + Send + Sync>,
    timeout: Duration,
}

impl FcrdnsUpstreamResolver {
    pub fn new(
        upstream: Arc<dyn Fn() -> Option<std::net::SocketAddr> + Send + Sync>,
        timeout: Duration,
    ) -> Self {
        Self { upstream, timeout }
    }
}

impl ReverseDnsResolver for FcrdnsUpstreamResolver {
    fn resolve_ptr(&self, ip: Ipv4Addr) -> Vec<String> {
        let Some(server) = (self.upstream)() else {
            return Vec::new();
        };
        DirectUdpUpstreamResolver::new(server, self.timeout, 2)
            .resolve_ptr(ip)
            .unwrap_or_default()
    }

    fn resolve_a(&self, hostname: &str) -> Vec<Ipv4Addr> {
        let Some(server) = (self.upstream)() else {
            return Vec::new();
        };
        match DirectUdpUpstreamResolver::new(server, self.timeout, 2).resolve_a(hostname) {
            Ok(ResolvedA { addresses, .. }) => addresses,
            Err(_) => Vec::new(),
        }
    }
}

/// Production [`ConfirmedHostSink`]: feeds an FCrDNS-confirmed `(hostname, IPs)`
/// fact into [`DnsObservationConsumer::learn_reverse_confirmed`], so the same
/// rule/SID gate + cache upsert path runs (source `ReverseConfirmed`). Returns
/// whether the host matched a rule and was cached.
/// Reports a hostname reverse lookup named, which no rule covers.
pub type CompanionNameSink = Arc<dyn Fn(&str) + Send + Sync>;

pub struct ConsumerConfirmedHostSink {
    consumer: Arc<DnsObservationConsumer>,
    /// Companion discovery. A forward-confirmed name that matches no rule is
    /// the one thing reverse lookup is uniquely good for here: the browser
    /// resolved it over DoH or from its own cache, so nothing else in the
    /// service ever learned it existed. If it loaded beside a routed site, it
    /// is exactly what the user is asked about.
    companion_sink: Option<CompanionNameSink>,
}

impl ConsumerConfirmedHostSink {
    pub fn new(consumer: Arc<DnsObservationConsumer>) -> Self {
        Self {
            consumer,
            companion_sink: None,
        }
    }

    /// Report forward-confirmed non-rule names to companion discovery as well
    /// as to the known-direct registry. Unwired keeps the historic behaviour.
    #[must_use]
    pub fn with_companion_sink(mut self, sink: CompanionNameSink) -> Self {
        self.companion_sink = Some(sink);
        self
    }
}

impl ConfirmedHostSink for ConsumerConfirmedHostSink {
    fn record_confirmed(&self, hostname: &str, addresses: &[Ipv4Addr]) -> bool {
        self.consumer
            .learn_reverse_confirmed(hostname, addresses, SystemTime::now())
    }

    /// a forward-confirmed non-rule name registers as a
    /// known-DIRECT destination (block-all exemption; see
    /// [`DnsObservationConsumer::learn_reverse_confirmed_direct`]). Inert until
    /// the consumer is built with a known-direct registry.
    fn record_confirmed_direct(&self, hostname: &str, addresses: &[Ipv4Addr]) -> bool {
        // Reported regardless of what the known-direct registry decides: the
        // two answer different questions. "Stop blocking this" is about the
        // address; "should this go over the tunnel with the site that needed
        // it" is about the name, and only the user can settle it.
        if let Some(sink) = self.companion_sink.as_ref() {
            sink(hostname);
        }
        self.consumer
            .learn_reverse_confirmed_direct(hostname, addresses)
    }
}

// ── Direct-answer gate (HW-0721, block-all direct-host exemptions) ───────────

/// Production [`crate::dns_resolver::DirectAnswerGate`]: while the kill-switch
/// block-all is armed, register a steered direct answer's addresses as
/// known-direct and drive the SAME bounded synchronous reconcile the rule-host
/// path uses, so the exemption is installed BEFORE the client receives the
/// answer (its first connect would otherwise race the catch-all and be dropped
/// with no retry — the habr.com case, HW-0721).
///
/// Hot-path discipline: `armed()` is a latch read; when the block-all is not
/// armed (the overwhelming majority of Mode-B traffic) the gate is two loads
/// and out. The reconcile fires only when a NEW address was registered, so a
/// re-queried host answers at full speed.
pub struct ReconcilingDirectAnswerGate {
    registry: Arc<crate::known_direct::KnownDirectRegistry>,
    reconciler: Arc<dyn SyncReconciler>,
    /// Whether any SID's fail-closed catch-all block-all is currently armed.
    armed: Arc<dyn Fn() -> bool + Send + Sync>,
    deadline: Duration,
}

impl ReconcilingDirectAnswerGate {
    pub fn new(
        registry: Arc<crate::known_direct::KnownDirectRegistry>,
        reconciler: Arc<dyn SyncReconciler>,
        armed: Arc<dyn Fn() -> bool + Send + Sync>,
        deadline: Duration,
    ) -> Self {
        Self {
            registry,
            reconciler,
            armed,
            deadline,
        }
    }
}

impl crate::dns_resolver::DirectAnswerGate for ReconcilingDirectAnswerGate {
    fn gate(&self, hostname: &str, addresses: &[Ipv4Addr]) {
        if addresses.is_empty() || !(self.armed)() {
            return;
        }
        let added = self.registry.register(addresses);
        if added == 0 {
            return; // already exempt (or capped) — nothing new to install
        }
        let outcome = self.reconciler.reconcile_now(self.deadline);
        tracing::info!(
            target: "nrr::dns-resolver",
            host = %hostname,
            added,
            outcome = ?outcome,
            "Mode B: direct host under block-all — known-direct exemption installed before answering",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_domain::canonical::{
        CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
    };
    use nrr_domain::{RouteBehaviorMode, RuleId};
    use nrr_platform_api::dns::DnsResolverError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::per_sid_orchestrator::ActiveRulesSnapshot;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    // ── PortUpstreamResolver ──────────────────────────────────────────────────

    struct FakeResolver {
        answer: Result<ResolvedRecord, DnsResolverError>,
    }
    impl DnsResolverPort for FakeResolver {
        fn resolve_a(&self, _hostname: &str) -> Result<ResolvedRecord, DnsResolverError> {
            self.answer.clone()
        }
    }

    // ── PoisonFallbackUpstreamResolver ────────────────────────────────────────

    struct FixedUpstream {
        answer: Result<ResolvedA, ResolveError>,
        calls: AtomicUsize,
    }
    impl FixedUpstream {
        fn new(answer: Result<ResolvedA, ResolveError>) -> Arc<Self> {
            Arc::new(Self {
                answer,
                calls: AtomicUsize::new(0),
            })
        }
        fn ok(addresses: Vec<Ipv4Addr>) -> Arc<Self> {
            Self::new(Ok(ResolvedA {
                addresses,
                ttl_seconds: 60,
            }))
        }
    }
    impl UpstreamResolver for FixedUpstream {
        fn resolve_a(&self, _hostname: &str) -> Result<ResolvedA, ResolveError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.answer.clone()
        }
    }

    #[test]
    fn poison_fallback_leaves_clean_answers_alone() {
        let inner = FixedUpstream::ok(vec![ip(142, 250, 74, 78)]);
        let fallback = FixedUpstream::ok(vec![ip(1, 2, 3, 4)]);
        let r =
            PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
                .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>]);
        assert_eq!(
            r.resolve_a("youtube.com").expect("clean").addresses,
            vec![ip(142, 250, 74, 78)]
        );
        assert_eq!(
            fallback.calls.load(Ordering::SeqCst),
            0,
            "no fallback fired"
        );
    }

    #[test]
    fn the_port_adapter_refuses_to_hand_a_placeholder_to_the_cache() {
        // What the seeder and the DNS refresh write goes straight into the
        // cache the relay dials from, so an unconfirmed placeholder there is a
        // rule pointing at nowhere that nothing re-queries.
        let port =
            UpstreamResolverPort::new(FixedUpstream::ok(vec![ip(8, 47, 69, 0), ip(8, 6, 112, 0)])
                as Arc<dyn UpstreamResolver>);
        assert_eq!(
            port.resolve_a("signal.me"),
            Err(DnsResolverError::Timeout {
                hostname: "signal.me".to_string()
            }),
            "transient, not NXDOMAIN — the name exists, we were not told where"
        );
    }

    #[test]
    fn the_port_adapter_passes_a_real_answer_through() {
        let port = UpstreamResolverPort::new(
            FixedUpstream::ok(vec![ip(157, 240, 1, 35)]) as Arc<dyn UpstreamResolver>
        );
        let record = port.resolve_a("WWW.Facebook.com").expect("resolved");
        assert_eq!(record.canonical_hostname, "www.facebook.com");
        assert_eq!(record.addresses, vec![ip(157, 240, 1, 35)]);
    }

    #[test]
    fn the_confirming_query_follows_the_egress_policy() {
        // On the primary link the interception that produced the placeholder
        // answers the confirmation too, so the second source agrees with the
        // first and nothing is ever pinned. The policy is what moves the query
        // somewhere the provider is not.
        let tunnel_resolver = spawn_fake_dns(|query| {
            vec![build_a_response(query, &[ip(157, 240, 1, 35)], 60).expect("resp")]
        });
        struct ViaTunnel(std::net::SocketAddr);
        impl crate::dns_egress::DnsEgressPolicy for ViaTunnel {
            fn decide(&self, _attempt: u32) -> Option<crate::dns_egress::DnsEgress> {
                Some(crate::dns_egress::DnsEgress {
                    server: self.0,
                    bind: None,
                    via_secondary: true,
                })
            }
        }

        // The pair the provider hands to every name it filters.
        let inner = FixedUpstream::ok(vec![ip(8, 47, 69, 0), ip(8, 6, 112, 0)]);
        let r =
            PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
                .with_egress(Arc::new(ViaTunnel(tunnel_resolver)));

        assert_eq!(
            r.resolve_a("www.facebook.com")
                .expect("confirmed")
                .addresses,
            vec![ip(157, 240, 1, 35)]
        );
    }

    #[test]
    fn poison_fallback_rescues_loopback_stub_answers() {
        // A filtering upstream answers the rule host with 127.0.0.1 — the
        // fallback's clean answer must win.
        let inner = FixedUpstream::ok(vec![ip(127, 0, 0, 1)]);
        let fallback = FixedUpstream::ok(vec![ip(142, 250, 74, 78)]);
        let r =
            PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
                .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>]);
        assert_eq!(
            r.resolve_a("www.youtube.com").expect("rescued").addresses,
            vec![ip(142, 250, 74, 78)]
        );
    }

    #[test]
    fn poison_fallback_rescues_nxdomain() {
        // The provider NXDOMAINs a rotating googlevideo node; a public resolver
        // knows it.
        let inner = FixedUpstream::new(Err(ResolveError::NoRecords));
        let fallback = FixedUpstream::ok(vec![ip(172, 217, 132, 74)]);
        let r =
            PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
                .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>]);
        assert_eq!(
            r.resolve_a("rr5.example").expect("rescued").addresses,
            vec![ip(172, 217, 132, 74)]
        );
    }

    #[test]
    fn poison_fallback_returns_the_original_when_fallbacks_fail_too() {
        let inner = FixedUpstream::ok(vec![ip(127, 0, 0, 1)]);
        let dead = FixedUpstream::new(Err(ResolveError::Unavailable("down".into())));
        let poisoned_too = FixedUpstream::ok(vec![ip(0, 0, 0, 0)]);
        let r =
            PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
                .with_fallbacks(vec![
                    Arc::clone(&dead) as Arc<dyn UpstreamResolver>,
                    Arc::clone(&poisoned_too) as Arc<dyn UpstreamResolver>,
                ]);
        // Original poisoned answer comes back unchanged (downstream
        // sanitization refuses to cache/route it — behaviour unchanged).
        assert_eq!(
            r.resolve_a("musical.ly").expect("original").addresses,
            vec![ip(127, 0, 0, 1)]
        );
        assert_eq!(dead.calls.load(Ordering::SeqCst), 1);
        assert_eq!(poisoned_too.calls.load(Ordering::SeqCst), 1);
    }

    /// The observed provider placeholder — a pair of `.0` addresses. It is not
    /// loopback, so only the address-sanity screen catches it.
    #[test]
    fn poison_fallback_rescues_a_trailing_zero_placeholder() {
        let inner = FixedUpstream::ok(vec![ip(8, 47, 69, 0), ip(8, 6, 112, 0)]);
        let fallback = FixedUpstream::ok(vec![ip(76, 223, 92, 165)]);
        let r =
            PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
                .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>]);
        assert_eq!(
            r.resolve_a("signal.me").expect("rescued").addresses,
            vec![ip(76, 223, 92, 165)]
        );
    }

    /// A `.0` address travelling with a normal one is ordinary enough — no
    /// second source, no added latency.
    #[test]
    fn poison_fallback_ignores_a_single_suspicious_address() {
        let inner = FixedUpstream::ok(vec![ip(8, 47, 69, 0), ip(142, 250, 74, 78)]);
        let fallback = FixedUpstream::ok(vec![ip(1, 2, 3, 4)]);
        let r =
            PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
                .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>]);
        assert_eq!(r.resolve_a("x.example").expect("clean").addresses.len(), 2);
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn address_reuse_by_an_unrelated_host_asks_a_second_source() {
        let recent = Arc::new(RecentRuleAddressIndex::new());
        let shared = vec![ip(203, 0, 55, 7), ip(203, 0, 55, 8)];
        recent.record("signal.me", &shared);

        let inner = FixedUpstream::ok(shared.clone());
        let fallback = FixedUpstream::ok(vec![ip(172, 64, 155, 209)]);
        let r =
            PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
                .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>])
                .with_recent_addresses(Arc::clone(&recent));
        assert_eq!(
            r.resolve_a("chatgpt.com").expect("rescued").addresses,
            vec![ip(172, 64, 155, 209)]
        );
    }

    /// Re-resolving a host, and a genuinely shared front end, must not drag the
    /// public resolvers in — that is the common case.
    #[test]
    fn re_resolution_and_shared_front_ends_do_not_ask_a_second_source() {
        let recent = Arc::new(RecentRuleAddressIndex::new());
        let shared = vec![ip(203, 0, 55, 7), ip(203, 0, 55, 8)];
        recent.record("static.whatsapp.net", &shared);

        let inner = FixedUpstream::ok(shared.clone());
        let fallback = FixedUpstream::ok(vec![ip(1, 2, 3, 4)]);
        let r =
            PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
                .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>])
                .with_recent_addresses(Arc::clone(&recent));
        // Same origin, two labels deep.
        assert_eq!(
            r.resolve_a("crashlogs.whatsapp.net")
                .expect("clean")
                .addresses,
            shared
        );
        // An address nobody remembers ends the scan on the first lookup.
        let fresh = FixedUpstream::ok(vec![ip(203, 0, 55, 7), ip(198, 41, 30, 9)]);
        let r2 = PoisonFallbackUpstreamResolver::new(fresh as Arc<dyn UpstreamResolver>)
            .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>])
            .with_recent_addresses(recent);
        assert_eq!(
            r2.resolve_a("other.example")
                .expect("clean")
                .addresses
                .len(),
            2
        );
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    /// One operator, two registrable domains (`claude.ai` / `api.anthropic.com`,
    /// `whatsapp.com` / `whatsapp.net`) legitimately share a front end, and the
    /// origin check cannot see it. The honest second source then answers with
    /// the very address set that raised the alarm — testing IT for the same
    /// suspicion would make confirmation impossible and tax every such query
    /// with the full budget. Agreement is the proof.
    #[test]
    fn a_second_source_that_agrees_settles_the_reuse_alarm() {
        let recent = Arc::new(RecentRuleAddressIndex::new());
        let shared = vec![ip(160, 79, 104, 10)];
        recent.record("claude.ai", &shared);

        let inner = FixedUpstream::ok(shared.clone());
        // Same set, listed the other way round: agreement is about the set.
        let agrees = FixedUpstream::ok(shared.clone());
        let never = FixedUpstream::ok(vec![ip(1, 2, 3, 4)]);
        let r =
            PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
                .with_fallbacks(vec![
                    Arc::clone(&agrees) as Arc<dyn UpstreamResolver>,
                    Arc::clone(&never) as Arc<dyn UpstreamResolver>,
                ])
                .with_recent_addresses(recent);

        assert_eq!(
            r.resolve_a("api.anthropic.com")
                .expect("confirmed")
                .addresses,
            shared
        );
        // The first agreement ends it — no walking the whole fallback list.
        assert_eq!(agrees.calls.load(Ordering::SeqCst), 1);
        assert_eq!(never.calls.load(Ordering::SeqCst), 0);
    }

    /// Agreement only rescues a set that could carry traffic — a second source
    /// repeating a loopback placeholder confirms nothing.
    #[test]
    fn agreement_on_an_unusable_set_confirms_nothing() {
        let recent = Arc::new(RecentRuleAddressIndex::new());
        let shared = vec![ip(127, 0, 0, 1)];
        recent.record("signal.me", &shared);

        let inner = FixedUpstream::ok(shared.clone());
        let agrees = FixedUpstream::ok(shared.clone());
        let r =
            PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
                .with_fallbacks(vec![Arc::clone(&agrees) as Arc<dyn UpstreamResolver>])
                .with_recent_addresses(recent);

        assert_eq!(
            r.resolve_a("musical.ly").expect("original").addresses,
            shared
        );
        assert_eq!(agrees.calls.load(Ordering::SeqCst), 1);
    }

    /// Without the memory wired the reuse trigger is simply off — it must never
    /// fire on a fresh index and never panic.
    #[test]
    fn the_reuse_trigger_is_inert_when_the_memory_is_not_wired() {
        let inner = FixedUpstream::ok(vec![ip(203, 0, 55, 7)]);
        let fallback = FixedUpstream::ok(vec![ip(1, 2, 3, 4)]);
        let r =
            PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
                .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>]);
        assert_eq!(
            r.resolve_a("anything.example").expect("clean").addresses,
            vec![ip(203, 0, 55, 7)]
        );
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    /// A second source that repeats the placeholder confirms nothing — the
    /// upstream answer comes back and the downstream gate refuses to pin it.
    #[test]
    fn a_second_source_repeating_the_placeholder_is_not_a_confirmation() {
        let stub = vec![ip(8, 47, 69, 0), ip(8, 6, 112, 0)];
        let inner = FixedUpstream::ok(stub.clone());
        let echo = FixedUpstream::ok(stub.clone());
        let r =
            PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
                .with_fallbacks(vec![Arc::clone(&echo) as Arc<dyn UpstreamResolver>]);
        assert_eq!(r.resolve_a("signal.me").expect("original").addresses, stub);
        assert_eq!(echo.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn poison_fallback_does_not_fire_on_transport_failure() {
        // Unavailable = the attempt/egress machinery's job; the fallback must
        // not add three more timeouts on top.
        let inner = FixedUpstream::new(Err(ResolveError::Unavailable("timeout".into())));
        let fallback = FixedUpstream::ok(vec![ip(1, 2, 3, 4)]);
        let r =
            PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
                .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>]);
        assert!(r.resolve_a("x.example").is_err());
        assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn upstream_maps_record_ttl_and_default() {
        // TTL present → carried through.
        let r = PortUpstreamResolver::new(Arc::new(FakeResolver {
            answer: Ok(ResolvedRecord {
                canonical_hostname: "chatgpt.com".into(),
                addresses: vec![ip(172, 64, 155, 209)],
                ttl_seconds: Some(42),
            }),
        }));
        assert_eq!(
            r.resolve_a("chatgpt.com"),
            Ok(ResolvedA {
                addresses: vec![ip(172, 64, 155, 209)],
                ttl_seconds: 42,
            })
        );
        // TTL absent → default.
        let r = PortUpstreamResolver::new(Arc::new(FakeResolver {
            answer: Ok(ResolvedRecord {
                canonical_hostname: "x.com".into(),
                addresses: vec![ip(1, 2, 3, 4)],
                ttl_seconds: None,
            }),
        }));
        assert_eq!(r.resolve_a("x.com").unwrap().ttl_seconds, DEFAULT_TTL_SECS);
    }

    #[test]
    fn upstream_maps_authoritative_vs_transient_errors() {
        // NXDOMAIN (authoritative) → NoRecords.
        let r = PortUpstreamResolver::new(Arc::new(FakeResolver {
            answer: Err(DnsResolverError::NxDomain {
                hostname: "nope.example".into(),
            }),
        }));
        assert_eq!(r.resolve_a("nope.example"), Err(ResolveError::NoRecords));
        // Timeout (transient) → Unavailable.
        let r = PortUpstreamResolver::new(Arc::new(FakeResolver {
            answer: Err(DnsResolverError::Timeout {
                hostname: "slow.example".into(),
            }),
        }));
        assert!(matches!(
            r.resolve_a("slow.example"),
            Err(ResolveError::Unavailable(_))
        ));
    }

    // ── ActiveRuleHostOracle ──────────────────────────────────────────────────

    struct FakeRules {
        primary: CanonicalRuleSet,
        secondary: CanonicalRuleSet,
    }
    impl RulesProvider for FakeRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            Some(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: self.primary.clone(),
                    secondary: self.secondary.clone(),
                },
                behavior_mode: RouteBehaviorMode::PreferPrimary,
            })
        }
    }

    fn exact_rule(id: &str, host: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn(host.into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    #[test]
    fn oracle_matches_secondary_rule_only() {
        let rules = Arc::new(FakeRules {
            primary: CanonicalRuleSet::from_rules(vec![exact_rule("r-p", "example.com")]),
            secondary: CanonicalRuleSet::from_rules(vec![exact_rule("r-s", "chatgpt.com")]),
        });
        let oracle = ActiveRuleHostOracle::new(rules, Arc::new(|| Some("S-1-5-21-1".to_string())));
        assert!(oracle.is_rule_host("chatgpt.com"), "secondary rule host");
        assert!(
            !oracle.is_rule_host("example.com"),
            "primary-only match is not a secondary rule host"
        );
        assert!(!oracle.is_rule_host("random.net"), "unmatched host");
    }

    #[test]
    fn oracle_fails_open_when_no_active_user() {
        let rules = Arc::new(FakeRules {
            primary: CanonicalRuleSet::from_rules(vec![]),
            secondary: CanonicalRuleSet::from_rules(vec![exact_rule("r-s", "chatgpt.com")]),
        });
        // No routing-active SID → nothing is a rule host (fail-open).
        let oracle = ActiveRuleHostOracle::new(rules, Arc::new(|| None));
        assert!(!oracle.is_rule_host("chatgpt.com"));
    }

    // ── ActiveSecondaryOwnedIps — direct-answer steering set ─────────────────

    /// The  case: `workspace.google.com` (direct) shares every
    /// front-end address with `aistudio.google.com` (secondary rule). While the
    /// secondary cannot carry traffic those addresses are BLOCKED by the
    /// fail-closed posture, so the steering set must stay armed — an empty set
    /// here is what handed the direct host a set of addresses that could only
    /// be dropped.
    #[test]
    fn steering_set_stays_armed_so_a_shared_direct_host_is_not_strangled() {
        use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
        use std::time::Instant;
        let shared = ip(209, 85, 233, 102);
        let fqdn = Arc::new(MockFqdnCacheLookup::new());
        fqdn.set_ips("aistudio.google.com", vec![shared]);
        let rules = Arc::new(FakeRules {
            primary: CanonicalRuleSet::from_rules(vec![]),
            secondary: CanonicalRuleSet::from_rules(vec![exact_rule("r-s", "aistudio.google.com")]),
        });
        let owned =
            ActiveSecondaryOwnedIps::new(rules, Arc::new(|| Some("S-1-5-21-1".to_string())), fqdn);
        let t0 = Instant::now();
        assert!(owned.owned_ips_at(t0).contains(&shared));
        // The posture the  gate used to blank: still armed, so the
        // listener strips the shared address from the direct host's answer (and,
        // when every address is shared, flags the reply for the collateral
        // rescue) instead of relaying addresses that will be dropped.
        let t1 = t0 + OWNED_SET_MEMO_TTL + Duration::from_millis(1);
        assert!(
            owned.owned_ips_at(t1).contains(&shared),
            "steering must not stand down while the secondary is unusable"
        );
    }

    /// An address the cache holds but no live resolution has confirmed inside
    /// the enforcement window is not enforced, so it must not be steered away
    /// from either — the steering set and the pin/block set read the same port
    /// and therefore narrow together.
    #[test]
    fn steering_set_follows_the_enforcement_confirmation_window() {
        use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
        use std::time::Instant;
        let fqdn = Arc::new(MockFqdnCacheLookup::new());
        // The mock models "the port answered nothing for this host", which is
        // what the SQLite adapter does once every row falls out of the window.
        fqdn.set_ips("aistudio.google.com", vec![]);
        let rules = Arc::new(FakeRules {
            primary: CanonicalRuleSet::from_rules(vec![]),
            secondary: CanonicalRuleSet::from_rules(vec![exact_rule("r-s", "aistudio.google.com")]),
        });
        let owned =
            ActiveSecondaryOwnedIps::new(rules, Arc::new(|| Some("S-1-5-21-1".to_string())), fqdn);
        assert!(owned.owned_ips_at(Instant::now()).is_empty());
    }

    // ── build_resolution_entry ────────────────────────────────────────────────

    #[test]
    fn entry_drops_non_routable_and_keeps_ttl_and_source() {
        let now = SystemTime::UNIX_EPOCH;
        let resolved = ResolvedA {
            addresses: vec![ip(127, 0, 0, 1), ip(203, 0, 113, 7), ip(0, 0, 0, 0)],
            ttl_seconds: 77,
        };
        let entry = build_resolution_entry("chatgpt.com", &resolved, now).expect("routable IP");
        assert_eq!(entry.canonical_hostname, "chatgpt.com");
        assert_eq!(entry.resolved_ips, vec![ip(203, 0, 113, 7)]); // loopback + unspecified dropped
        assert_eq!(entry.ttl_seconds, Some(77));
        assert_eq!(entry.source, StorageResolutionSource::Dns);
    }

    #[test]
    fn entry_is_none_when_all_non_routable() {
        // An ad-block hosts pin to 127.0.0.1 must NOT become a /32 out the secondary adapter.
        let resolved = ResolvedA {
            addresses: vec![ip(127, 0, 0, 1)],
            ttl_seconds: 60,
        };
        assert!(
            build_resolution_entry("blocked.example", &resolved, SystemTime::UNIX_EPOCH).is_none()
        );
    }

    // ── HookSyncReconciler ────────────────────────────────────────────────────

    #[test]
    fn reconciler_installs_when_hook_completes_within_deadline() {
        let ran = Arc::new(AtomicUsize::new(0));
        let r = Arc::clone(&ran);
        let hook: RouteRecomputeHook = Arc::new(move || {
            r.fetch_add(1, Ordering::SeqCst);
        });
        let out = HookSyncReconciler::new(hook).reconcile_now(Duration::from_secs(2));
        assert_eq!(out, ReconcileOutcome::Installed);
        // `Installed` is only returned after the completion signal, which the
        // worker sends AFTER running the hook — so the reconcile really ran.
        assert_eq!(ran.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn reconciler_reports_deadline_exceeded_for_a_slow_hook() {
        // Hook far slower than the deadline → fail open on latency.
        let hook: RouteRecomputeHook = Arc::new(|| {
            std::thread::sleep(Duration::from_millis(300));
        });
        let out = HookSyncReconciler::new(hook).reconcile_now(Duration::from_millis(30));
        assert_eq!(out, ReconcileOutcome::DeadlineExceeded);
    }

    #[test]
    fn concurrent_reconciles_coalesce_onto_a_shared_run() {
        // under the armed block-all a burst of direct-host answers
        // used to spawn a full reconcile EACH, convoying on the orchestrator
        // lock. Now concurrent callers must share hook runs: with 8 callers and
        // a 40 ms hook, thread-per-call would take 8 runs; coalescing needs at
        // most a handful (a run in flight when a caller registers cannot vouch
        // for it, so up to ~2-3 runs may still start).
        let ran = Arc::new(AtomicUsize::new(0));
        let r = Arc::clone(&ran);
        let hook: RouteRecomputeHook = Arc::new(move || {
            r.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(40));
        });
        let reconciler = Arc::new(HookSyncReconciler::new(hook));
        let callers: Vec<_> = (0..8)
            .map(|_| {
                let rc = Arc::clone(&reconciler);
                std::thread::spawn(move || rc.reconcile_now(Duration::from_secs(5)))
            })
            .collect();
        for caller in callers {
            assert_eq!(
                caller.join().expect("caller thread"),
                ReconcileOutcome::Installed,
                "a generous deadline must always confirm install"
            );
        }
        let runs = ran.load(Ordering::SeqCst);
        assert!(
            (1..=4).contains(&runs),
            "8 concurrent callers coalesced into {runs} hook runs (expected ≤4)"
        );
    }

    #[test]
    fn a_caller_is_only_satisfied_by_a_run_that_started_after_its_request() {
        // The first call's run is already in flight when the second call
        // registers — the second must NOT be credited by it (its facts landed
        // mid-run) and instead waits for the next run. Observable effect: both
        // calls Installed, and the hook ran twice.
        let ran = Arc::new(AtomicUsize::new(0));
        let r = Arc::clone(&ran);
        let hook: RouteRecomputeHook = Arc::new(move || {
            r.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(60));
        });
        let reconciler = Arc::new(HookSyncReconciler::new(hook));
        let rc = Arc::clone(&reconciler);
        let first = std::thread::spawn(move || rc.reconcile_now(Duration::from_secs(5)));
        // Let the first run actually start before registering the second.
        std::thread::sleep(Duration::from_millis(20));
        let second = reconciler.reconcile_now(Duration::from_secs(5));
        assert_eq!(
            first.join().expect("first caller"),
            ReconcileOutcome::Installed
        );
        assert_eq!(second, ReconcileOutcome::Installed);
        assert_eq!(
            ran.load(Ordering::SeqCst),
            2,
            "the in-flight run must not satisfy a request registered after it started"
        );
    }

    // ── DirectUdpUpstreamResolver (HW-0714) ───────────────────────────────────

    use crate::dns_wire::{build_a_response, build_error_response, RCODE_NXDOMAIN};
    use std::net::UdpSocket;

    /// One-shot fake DNS server on 127.0.0.1: receives a single query and sends
    /// back every frame `reply` produces for it.
    fn spawn_fake_dns(
        reply: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
    ) -> std::net::SocketAddr {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake dns");
        let addr = sock.local_addr().expect("fake dns addr");
        sock.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("cfg fake dns");
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            if let Ok((n, src)) = sock.recv_from(&mut buf) {
                for frame in reply(&buf[..n]) {
                    let _ = sock.send_to(&frame, src);
                }
            }
        });
        addr
    }

    #[test]
    fn direct_udp_resolves_answers_and_ttl_from_fake_server() {
        let addr = spawn_fake_dns(|query| {
            // The response builders echo the query's id + question, so the
            // client's id/question match passes without knowing the id here.
            vec![build_a_response(query, &[ip(1, 2, 3, 4), ip(5, 6, 7, 8)], 90).expect("resp")]
        });
        let r = DirectUdpUpstreamResolver::new(addr, Duration::from_secs(2), 1);
        let resolved = r.resolve_a("chatgpt.com").expect("resolved");
        assert_eq!(resolved.addresses, vec![ip(1, 2, 3, 4), ip(5, 6, 7, 8)]);
        assert_eq!(resolved.ttl_seconds, 90);
    }

    #[test]
    fn direct_udp_resolves_ptr_names_from_fake_server() {
        // Fake server replies to the PTR query with one PTR RR (owner = pointer
        // to the question, RDATA = uncompressed target name).
        let addr = spawn_fake_dns(|query| {
            let q = crate::dns_wire::parse_question(query).expect("question");
            let mut resp = query[..q.question_end].to_vec();
            resp[2] = 0x80; // QR=1
            resp[3] = 0x80; // RA, RCODE 0
            resp[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
            resp.extend_from_slice(&[0xC0, 0x0C]); // owner → question
            resp.extend_from_slice(&crate::dns_wire::QTYPE_PTR.to_be_bytes());
            resp.extend_from_slice(&[0x00, 0x01]); // CLASS IN
            resp.extend_from_slice(&3600u32.to_be_bytes());
            let mut rdata = Vec::new();
            for label in ["dzen", "ru"] {
                rdata.push(label.len() as u8);
                rdata.extend_from_slice(label.as_bytes());
            }
            rdata.push(0);
            resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            resp.extend_from_slice(&rdata);
            vec![resp]
        });
        let r = DirectUdpUpstreamResolver::new(addr, Duration::from_secs(2), 1);
        let names = r.resolve_ptr(ip(5, 45, 202, 100)).expect("ptr names");
        assert_eq!(names, vec!["dzen.ru".to_string()]);
    }

    #[test]
    fn direct_udp_nxdomain_is_authoritative_no_records() {
        let addr =
            spawn_fake_dns(|query| vec![build_error_response(query, RCODE_NXDOMAIN).expect("nx")]);
        let r = DirectUdpUpstreamResolver::new(addr, Duration::from_secs(2), 3);
        assert_eq!(
            r.resolve_a("gone.example"),
            Err(ResolveError::NoRecords),
            "NXDOMAIN must not be retried as transient"
        );
    }

    #[test]
    fn direct_udp_ignores_mismatched_datagram_then_accepts_answer() {
        let addr = spawn_fake_dns(|query| {
            let good = build_a_response(query, &[ip(9, 9, 9, 9)], 60).expect("resp");
            let mut wrong_id = good.clone();
            wrong_id[0] ^= 0xFF; // late reply of some other query
            vec![wrong_id, good]
        });
        let r = DirectUdpUpstreamResolver::new(addr, Duration::from_secs(2), 1);
        let resolved = r.resolve_a("chatgpt.com").expect("resolved");
        assert_eq!(resolved.addresses, vec![ip(9, 9, 9, 9)]);
    }

    #[test]
    fn direct_udp_reports_unavailable_when_nothing_answers() {
        // Bind-then-drop reserves a port that is closed by the time we query:
        // the ICMP port-unreachable surfaces as a transient recv error, the
        // window drains, and the resolver reports Unavailable (never hangs).
        let addr = {
            let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
            sock.local_addr().expect("addr")
        };
        let r = DirectUdpUpstreamResolver::new(addr, Duration::from_millis(120), 2);
        match r.resolve_a("chatgpt.com") {
            Err(ResolveError::Unavailable(_)) => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn direct_udp_unencodable_name_is_no_records_without_network() {
        // Never resolvable → authoritative, and no socket traffic is attempted
        // (the server address is irrelevant/unroutable here).
        let r = DirectUdpUpstreamResolver::new(
            std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
            Duration::from_millis(50),
            1,
        );
        assert_eq!(r.resolve_a("a..b"), Err(ResolveError::NoRecords));
    }

    // ── HostsBypassDnsResolver (HW-0714) ──────────────────────────────────────

    use nrr_platform_api::dns::MockDnsResolver;

    fn system_with(host: &str, ips: &[Ipv4Addr]) -> Arc<dyn DnsResolverPort> {
        let mock = MockDnsResolver::new();
        mock.set_response(
            host,
            ResolvedRecord {
                canonical_hostname: host.to_string(),
                addresses: ips.to_vec(),
                ttl_seconds: Some(300),
            },
        );
        Arc::new(mock)
    }

    #[test]
    fn hosts_bypass_off_uses_the_system_resolver() {
        let r = HostsBypassDnsResolver::new(
            system_with("pinned.example", &[ip(10, 0, 0, 1)]),
            Arc::new(|| false),
            Arc::new(|| panic!("upstream must not be consulted when bypass is off")),
            Duration::from_millis(200),
        );
        let rec = r.resolve_a("pinned.example").expect("system answer");
        assert_eq!(rec.addresses, vec![ip(10, 0, 0, 1)]);
    }

    #[test]
    fn hosts_bypass_on_resolves_directly_past_the_system() {
        let addr = spawn_fake_dns(|query| {
            vec![build_a_response(query, &[ip(203, 0, 113, 7)], 120).expect("resp")]
        });
        let r = HostsBypassDnsResolver::new(
            // System would answer with the hosts-file pin — must NOT be used.
            system_with("pinned.example", &[ip(127, 0, 0, 1)]),
            Arc::new(|| true),
            Arc::new(move || Some(addr)),
            Duration::from_secs(2),
        );
        let rec = r.resolve_a("pinned.example").expect("direct answer");
        assert_eq!(
            rec.addresses,
            vec![ip(203, 0, 113, 7)],
            "hosts pin bypassed"
        );
        assert_eq!(rec.ttl_seconds, Some(120));
        assert_eq!(rec.canonical_hostname, "pinned.example");
    }

    #[test]
    fn hosts_bypass_falls_back_to_system_when_no_upstream() {
        let r = HostsBypassDnsResolver::new(
            system_with("host.example", &[ip(198, 51, 100, 4)]),
            Arc::new(|| true),
            Arc::new(|| None),
            Duration::from_millis(200),
        );
        let rec = r.resolve_a("host.example").expect("fallback answer");
        assert_eq!(rec.addresses, vec![ip(198, 51, 100, 4)]);
    }

    #[test]
    fn hosts_bypass_falls_back_to_system_on_direct_timeout() {
        // Upstream present but nothing answers there (bind-then-drop reserves
        // a closed port) → transient direct failure → system fallback.
        let dead = {
            let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
            sock.local_addr().expect("addr")
        };
        let r = HostsBypassDnsResolver::new(
            system_with("host.example", &[ip(198, 51, 100, 9)]),
            Arc::new(|| true),
            Arc::new(move || Some(dead)),
            Duration::from_millis(120),
        );
        let rec = r.resolve_a("host.example").expect("fallback answer");
        assert_eq!(rec.addresses, vec![ip(198, 51, 100, 9)]);
    }
}
