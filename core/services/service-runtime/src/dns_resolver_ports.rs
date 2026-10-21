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
//! The listener constructs these and hands them to
//! [`crate::dns_resolver::handle_a_query`].

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use nrr_platform_api::dns::{DnsResolverError, DnsResolverPort, ResolvedRecord};
use nrr_storage::dto::ResolutionEntry;
use nrr_storage::repository::CacheRepository;
use nrr_storage::resolution_source::StorageResolutionSource;

use crate::dns_address_sanity::{classify_answer, AnswerSanity};
use crate::dns_observation_consumer::rule_set_matches;
use crate::dns_resolver::{
    FactSink, ReconcileOutcome, ResolveError, ResolvedAddresses, RuleHostOracle, SyncReconciler,
    UpstreamResolver,
};
use crate::net_filter::is_non_routable;
use crate::per_sid_orchestrator::RulesProvider;
use crate::recent_rule_addresses::RecentRuleAddressIndex;
use crate::secondary_address_owners::SecondaryAddressOwners;
use crate::supervised_runtime::RouteRecomputeHook;
use nrr_platform_api::dns::AddressFamily;

/// TTL (seconds) applied when the upstream record carries none — short, so a
/// rotating host re-installs enforcement soon after via TTL-driven re-query.
const DEFAULT_TTL_SECS: u32 = 300;

/// The users whose books the local resolver answers by, routing user first.
pub type ResolverPrincipalsFn = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// The routing user alone, for a wiring that names no served set.
pub fn principals_of_routing_user(
    active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync>,
) -> ResolverPrincipalsFn {
    Arc::new(move || active_sid().into_iter().collect())
}

/// [`RuleHostOracle`] over the served users' books: a query is a rule host iff
/// an enabled **secondary** rule of ANY served user matches it (same
/// `rule_set_matches` the DNS observer uses). A query carries no trace of who
/// asked — on Windows every program's query comes from the DNS Client service —
/// so the host's owners are the users whose rules name it. Only secondary rules
/// are enforced destinations, so a primary-only match is NOT a rule host.
pub struct ActiveRuleHostOracle {
    rules_provider: Arc<dyn RulesProvider>,
    principals: ResolverPrincipalsFn,
}

impl ActiveRuleHostOracle {
    pub fn new(
        rules_provider: Arc<dyn RulesProvider>,
        active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    ) -> Self {
        Self {
            rules_provider,
            principals: principals_of_routing_user(active_sid),
        }
    }

    /// Answer for every user in `served`, not only the routing one.
    #[must_use]
    pub fn with_served(mut self, served: ResolverPrincipalsFn) -> Self {
        self.principals = served;
        self
    }

    /// The served users whose secondary rules name `hostname`.
    pub fn owners_of(&self, hostname: &str) -> Vec<String> {
        (self.principals)()
            .into_iter()
            .filter(|sid| {
                self.rules_provider
                    .active_rules_for(sid)
                    .is_some_and(|s| rule_set_matches(hostname, &s.rule_book.secondary))
            })
            .collect()
    }
}

impl RuleHostOracle for ActiveRuleHostOracle {
    fn is_rule_host(&self, hostname: &str) -> bool {
        (self.principals)().iter().any(|sid| {
            self.rules_provider
                .active_rules_for(sid)
                .is_some_and(|s| rule_set_matches(hostname, &s.rule_book.secondary))
        })
    }
}

/// The leak guard as each served user's own: a rule host is withheld while the
/// guard of a user whose rule names it holds, so one user's tunnel going down
/// fails nobody else's names.
pub struct HostOwnersLeakGuard {
    oracle: Arc<ActiveRuleHostOracle>,
    principals: ResolverPrincipalsFn,
    armed_for: crate::dns_stack::PrincipalFlag,
}

impl HostOwnersLeakGuard {
    pub fn new(
        oracle: Arc<ActiveRuleHostOracle>,
        principals: ResolverPrincipalsFn,
        armed_for: crate::dns_stack::PrincipalFlag,
    ) -> Self {
        Self {
            oracle,
            principals,
            armed_for,
        }
    }
}

impl crate::dns_resolver::LeakGuardPosture for HostOwnersLeakGuard {
    fn blocking(&self) -> bool {
        (self.principals)().iter().any(|sid| (self.armed_for)(sid))
    }

    fn blocking_for_host(&self, hostname: &str) -> bool {
        // The latch read first: a disarmed machine costs no book match.
        self.blocking()
            && self
                .oracle
                .owners_of(hostname)
                .iter()
                .any(|sid| (self.armed_for)(sid))
    }
}

/// [`UpstreamResolver`] over the platform [`DnsResolverPort`]. The upstream is
/// the system-configured resolver (`DnsQuery_W` today; hickory later), which
/// honours the hosts file + configured servers — so split-horizon / corporate
/// zones resolve correctly, provided it is the resolver captured *before* any
/// DNS redirect.
pub struct PortUpstreamResolver {
    resolver: Arc<dyn DnsResolverPort>,
}

impl PortUpstreamResolver {
    pub fn new(resolver: Arc<dyn DnsResolverPort>) -> Self {
        Self { resolver }
    }
}

impl UpstreamResolver for PortUpstreamResolver {
    // The budget is not ours to divide: the port behind this is already wrapped
    // in `BudgetedDnsResolver`, which caps one call and hands the caller back a
    // `Timeout`. Narrowing it further would mean a second timer over a call we
    // cannot cancel.
    fn resolve_within(
        &self,
        hostname: &str,
        family: AddressFamily,
        _budget: Duration,
    ) -> Result<ResolvedAddresses, ResolveError> {
        match self.resolver.resolve(hostname, family) {
            Ok(ResolvedRecord {
                addresses,
                ttl_seconds,
                ..
            }) => Ok(ResolvedAddresses {
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
    fn resolve(
        &self,
        hostname: &str,
        family: AddressFamily,
    ) -> Result<ResolvedRecord, DnsResolverError> {
        match self.upstream.resolve(hostname, family) {
            Ok(resolved) if !resolved.addresses.is_empty() => {
                // The confirmation above already tried to replace a placeholder
                // with a real answer. One that still looks like a placeholder
                // was not confirmed by anyone, and writing it to the cache would
                // point the rule at nowhere — worse than having no address,
                // because nothing would ever re-query it.
                let usable: Option<Vec<IpAddr>> = match family {
                    AddressFamily::Ipv4 => {
                        let answered = crate::dns_wire::only_v4(&resolved.addresses);
                        match classify_answer(&answered) {
                            AnswerSanity::Clean => Some(answered),
                            AnswerSanity::Sanitized { keep } => Some(keep),
                            AnswerSanity::Unusable => None,
                        }
                        .map(|v4| v4.into_iter().map(IpAddr::V4).collect())
                    }
                    AddressFamily::Ipv6 => {
                        let v6: Vec<IpAddr> =
                            resolved.addresses.into_iter().filter(usable_v6).collect();
                        (!v6.is_empty()).then_some(v6)
                    }
                };
                let addresses = match usable {
                    Some(addresses) => addresses,
                    None => {
                        tracing::info!(
                            target: "nrr::dns-resolver",
                            msg_key = "dns-resolver-no-usable-address",
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
/// loops back into our own loopback listener and times out. A raw socket is
/// invisible to NRPT by construction
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
    /// Live upstream choice for the primary path. When wired it supersedes
    /// `server`, so a resolver that stops answering is retired here too and not
    /// only on the listener's forward path.
    pool: Option<Arc<crate::dns_upstream::UpstreamDnsPool>>,
}

/// A fresh, unguessable id for each query.
///
/// A predictable id (e.g. a counter) would make every id after the first one
/// guessable from a single observed query. The socket is connected and the
/// answer is matched on id plus question, so a forger already has to guess the
/// ephemeral port and spoof the server's source address — but randomizing the
/// id costs nothing and removes one more barrier a forger would otherwise not
/// need to clear, protecting the cache the routes, the pins and the
/// kill-switch exemptions are all derived from.
///
/// A failed draw falls back to the clock rather than to a constant: worse than
/// random, still not fixed, and it cannot fail the resolution.
pub(crate) fn next_query_id() -> u16 {
    let mut bytes = [0u8; 2];
    match getrandom::fill(&mut bytes) {
        Ok(()) => u16::from_ne_bytes(bytes),
        Err(_) => SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u16)
            .unwrap_or(0),
    }
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
            pool: None,
        }
    }

    /// Attach the live DNS-egress policy so each attempt can be sent through
    /// the secondary link to a public resolver instead of the primary
    /// provider's. Chain after [`Self::new`].
    pub fn with_egress(mut self, egress: Arc<dyn crate::dns_egress::DnsEgressPolicy>) -> Self {
        self.egress = Some(egress);
        self
    }

    /// Take the primary-path upstream from the live pool rather than the fixed
    /// address given to [`Self::new`].
    pub fn with_upstream_pool(mut self, pool: Arc<crate::dns_upstream::UpstreamDnsPool>) -> Self {
        self.pool = Some(pool);
        self
    }

    /// The primary-path server: the pool's current pick when wired, else the
    /// fixed address.
    fn primary_server(&self) -> std::net::SocketAddr {
        self.pool
            .as_ref()
            .and_then(|pool| pool.current())
            .unwrap_or(self.server)
    }

    /// The upstream + source binding for one attempt. No policy — or a policy
    /// that declines (feature off, secondary unusable) — means the primary
    /// server, unbound.
    fn egress_for(&self, attempt: u32) -> crate::dns_egress::DnsEgress {
        self.egress
            .as_ref()
            .and_then(|policy| policy.decide(attempt))
            .unwrap_or_else(|| crate::dns_egress::DnsEgress::primary(self.primary_server()))
    }

    /// Report an attempt's outcome to the pool — but only for attempts that
    /// actually went to the pool's server. A failure on the secondary link (or
    /// to a public resolver) says nothing about the primary upstream's health.
    fn note_attempt(&self, egress: &crate::dns_egress::DnsEgress, ok: bool) {
        // The policy needs its own attempts back, whichever way they went: it
        // is the only thing that can stop feeding a tunnel that has stopped
        // carrying traffic.
        if let Some(policy) = self.egress.as_ref() {
            policy.note_outcome(egress.via_secondary, ok);
        }
        let Some(pool) = self.pool.as_ref() else {
            return;
        };
        if egress.via_secondary || Some(egress.server) != pool.current() {
            return;
        }
        if ok {
            pool.note_success();
        } else {
            pool.note_failure();
        }
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
        let wildcard: std::net::SocketAddr = match egress.server {
            std::net::SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            std::net::SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let sock = match egress.bind {
            Some(src) => std::net::UdpSocket::bind((src, 0))
                .map_err(|e| ResolveError::Unavailable(format!("bind {src}: {e}")))?,
            None => std::net::UdpSocket::bind(wildcard)
                .map_err(|e| ResolveError::Unavailable(format!("bind: {e}")))?,
        };
        nrr_platform_api::own_traffic::mark_own_socket(&sock);
        // Connected, so the kernel drops every datagram that did not come from
        // the server we asked. An unconnected socket accepts an answer from
        // anyone who guesses the ephemeral port, and what it answers into is the
        // cache the routes, pins and kill-switch exemptions are built from.
        sock.connect(egress.server)
            .map_err(|e| ResolveError::Unavailable(format!("connect {}: {e}", egress.server)))?;
        Ok(sock)
    }

    /// One send + receive window, `window` long. Loops on non-matching
    /// datagrams (late replies of a previous query, off-path noise) until it
    /// elapses. The caller narrows the window when a shared budget leaves less
    /// than the configured per-attempt timeout.
    fn attempt(
        &self,
        query: &[u8],
        id: u16,
        hostname: &str,
        qtype: u16,
        egress: &crate::dns_egress::DnsEgress,
        window: Duration,
    ) -> Result<ResolvedAddresses, ResolveError> {
        let sock = Self::open_socket(egress)?;
        sock.send(query)
            .map_err(|e| ResolveError::Unavailable(format!("send: {e}")))?;
        let started = std::time::Instant::now();
        let mut buf = [0u8; MAX_REPLY_DATAGRAM];
        loop {
            let remaining = window.saturating_sub(started.elapsed());
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
            match Self::interpret(id, hostname, qtype, &buf[..n]) {
                Some(Err(ResolveError::Unavailable(reason))) if reason == TRUNCATED => {
                    // The answer did not fit a datagram: ask again over TCP,
                    // on the same link, within what is left of the window.
                    let left = window.saturating_sub(started.elapsed());
                    return Self::attempt_tcp(query, id, hostname, qtype, egress, left);
                }
                Some(outcome) => return outcome,
                None => continue,
            }
        }
    }

    /// What one reply means: `None` for a datagram that is not ours.
    fn interpret(
        id: u16,
        hostname: &str,
        qtype: u16,
        reply: &[u8],
    ) -> Option<Result<ResolvedAddresses, ResolveError>> {
        use crate::dns_wire::{parse_address_response, AddressResponseOutcome};
        Some(match parse_address_response(id, hostname, qtype, reply) {
            AddressResponseOutcome::Answers { addresses, min_ttl } => Ok(ResolvedAddresses {
                addresses,
                // A 0-TTL record still needs a positive cache horizon; 1 s
                // keeps the "do not cache" spirit without a special case.
                ttl_seconds: min_ttl.max(1),
            }),
            AddressResponseOutcome::NoRecords => Err(ResolveError::NoRecords),
            AddressResponseOutcome::Truncated => Err(ResolveError::Unavailable(TRUNCATED.into())),
            AddressResponseOutcome::Failed(rcode) => {
                Err(ResolveError::Unavailable(format!("rcode {rcode}")))
            }
            AddressResponseOutcome::Mismatch => return None,
        })
    }

    /// The same question over TCP: one connection from the same source, one
    /// framed exchange, all inside `window`. A reply over TCP cannot be
    /// truncated, so a TC here is simply a failure.
    fn attempt_tcp(
        query: &[u8],
        id: u16,
        hostname: &str,
        qtype: u16,
        egress: &crate::dns_egress::DnsEgress,
        window: Duration,
    ) -> Result<ResolvedAddresses, ResolveError> {
        use crate::dns_wire::{read_tcp_message, write_tcp_message, DNS_TCP_MAX_MESSAGE};
        if window.is_zero() {
            return Err(ResolveError::Unavailable("timeout".into()));
        }
        let started = std::time::Instant::now();
        let unavailable =
            |what: &str, e: std::io::Error| ResolveError::Unavailable(format!("tcp {what}: {e}"));
        let mut stream = match egress.bind {
            // `std` cannot bind before connecting; `socket2` can, and the bind
            // is what keeps the query on the link the policy chose.
            Some(src) => {
                let domain = match egress.server {
                    std::net::SocketAddr::V4(_) => socket2::Domain::IPV4,
                    std::net::SocketAddr::V6(_) => socket2::Domain::IPV6,
                };
                let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None)
                    .map_err(|e| unavailable("socket", e))?;
                socket
                    .bind(&std::net::SocketAddr::from((src, 0)).into())
                    .map_err(|e| unavailable("bind", e))?;
                socket
                    .connect_timeout(&egress.server.into(), window)
                    .map_err(|e| unavailable("connect", e))?;
                std::net::TcpStream::from(socket)
            }
            None => std::net::TcpStream::connect_timeout(&egress.server, window)
                .map_err(|e| unavailable("connect", e))?,
        };
        nrr_platform_api::own_traffic::mark_own_socket(&stream);
        let left = window.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err(ResolveError::Unavailable("timeout".into()));
        }
        stream
            .set_read_timeout(Some(left))
            .and_then(|()| stream.set_write_timeout(Some(left)))
            .map_err(|e| unavailable("timeout cfg", e))?;
        write_tcp_message(&mut stream, query).map_err(|e| unavailable("send", e))?;
        let reply = read_tcp_message(&mut stream, DNS_TCP_MAX_MESSAGE)
            .map_err(|e| unavailable("recv", e))?
            .ok_or_else(|| ResolveError::Unavailable("tcp: closed without a reply".into()))?;
        match Self::interpret(id, hostname, qtype, &reply) {
            Some(outcome) => outcome,
            None => Err(ResolveError::Unavailable(
                "tcp: reply to another question".into(),
            )),
        }
    }
}

/// The `Unavailable` reason a truncated datagram carries.
const TRUNCATED: &str = "truncated (TC=1)";

/// The largest datagram an upstream can send. A smaller buffer fails the
/// receive on Windows, and an oversized answer counted against the server.
const MAX_REPLY_DATAGRAM: usize = 65_535;

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
        sock.send(query)
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
    fn resolve_within(
        &self,
        hostname: &str,
        family: AddressFamily,
        budget: Duration,
    ) -> Result<ResolvedAddresses, ResolveError> {
        self.resolve_via(hostname, family, budget, false)
    }

    fn resolve_tunnel_only_within(
        &self,
        hostname: &str,
        family: AddressFamily,
        budget: Duration,
    ) -> Result<ResolvedAddresses, ResolveError> {
        self.resolve_via(hostname, family, budget, true)
    }
}

impl DirectUdpUpstreamResolver {
    /// The query loop. With `tunnel_only`, an attempt the egress policy would
    /// send over the main link is not made at all: the name must not get there.
    fn resolve_via(
        &self,
        hostname: &str,
        family: AddressFamily,
        budget: Duration,
        tunnel_only: bool,
    ) -> Result<ResolvedAddresses, ResolveError> {
        use crate::dns_wire::{build_address_query, QTYPE_A, QTYPE_AAAA};
        let qtype = match family {
            AddressFamily::Ipv4 => QTYPE_A,
            AddressFamily::Ipv6 => QTYPE_AAAA,
        };
        let id = next_query_id();
        // An unencodable name (empty/oversized label, non-ASCII — IDN arrives
        // here already punycoded) can never resolve: authoritative no-answer.
        let Some(query) = build_address_query(id, hostname, qtype) else {
            return Err(ResolveError::NoRecords);
        };
        let mut last = ResolveError::Unavailable("no attempts".into());
        let started = std::time::Instant::now();
        for attempt in 0..self.attempts {
            // The retry exists to survive one lost datagram, not to spend a
            // budget the caller has already promised to its own client.
            let window = budget.saturating_sub(started.elapsed()).min(self.timeout);
            if window.is_zero() {
                return Err(ResolveError::Unavailable("budget exhausted".into()));
            }
            let egress = self.egress_for(attempt);
            if tunnel_only && !egress.via_secondary {
                last = ResolveError::Unavailable("tunnel not available for the query".into());
                continue;
            }
            match self.attempt(&query, id, hostname, qtype, &egress, window) {
                Ok(resolved) => {
                    tracing::debug!(
                        target: "nrr::dns-resolver",
                        host = %hostname,
                        upstream = %egress.server,
                        via_secondary = egress.via_secondary,
                        addresses = resolved.addresses.len(),
                        ttl = resolved.ttl_seconds,
                        attempt,
                        family = family.as_str(),
                        "direct upstream address query answered",
                    );
                    self.note_attempt(&egress, true);
                    return Ok(resolved);
                }
                Err(ResolveError::NoRecords) => {
                    self.note_attempt(&egress, true); // an answer, just an empty one
                    return Err(ResolveError::NoRecords);
                }
                Err(e) => {
                    self.note_attempt(&egress, false);
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
                        family = family.as_str(),
                        "direct upstream address query attempt failed",
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
/// rotating `videocdn.test` video nodes), or a synthetic address pair handed
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
    /// Hosts whose upstream answer was recently found unusable, so the next
    /// query skips the doomed round-trip.
    verdicts: Mutex<HostVerdicts>,
}

/// What a confirmation round last learned about a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostVerdict {
    /// The captured upstream's answer was unusable and a public resolver
    /// answered clean.
    UpstreamUnusable,
    /// Every source agreed the name has nothing to pin.
    NothingToPin,
}

/// Bounded, short-lived memory of [`HostVerdict`]s. A wrong entry costs at
/// most one TTL of the old behaviour, so a provider that stops filtering is
/// noticed within it.
#[derive(Default)]
struct HostVerdicts {
    entries: std::collections::HashMap<(Box<str>, bool), (Instant, HostVerdict)>,
}

impl HostVerdicts {
    const TTL: Duration = Duration::from_secs(120);
    const CAPACITY: usize = 512;

    fn key(hostname: &str, family: AddressFamily) -> (Box<str>, bool) {
        (
            hostname.to_ascii_lowercase().into_boxed_str(),
            family == AddressFamily::Ipv6,
        )
    }

    fn recall(
        &mut self,
        hostname: &str,
        family: AddressFamily,
        now: Instant,
    ) -> Option<HostVerdict> {
        let key = Self::key(hostname, family);
        match self.entries.get(&key) {
            Some((until, verdict)) if *until > now => Some(*verdict),
            Some(_) => {
                self.entries.remove(&key);
                None
            }
            None => None,
        }
    }

    fn remember(
        &mut self,
        hostname: &str,
        family: AddressFamily,
        verdict: HostVerdict,
        now: Instant,
    ) {
        if self.entries.len() >= Self::CAPACITY {
            self.entries.retain(|_, (until, _)| *until > now);
            if self.entries.len() >= Self::CAPACITY {
                return;
            }
        }
        self.entries
            .insert(Self::key(hostname, family), (now + Self::TTL, verdict));
    }

    fn forget(&mut self, hostname: &str, family: AddressFamily) {
        self.entries.remove(&Self::key(hostname, family));
    }
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
            verdicts: Mutex::new(HostVerdicts::default()),
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
    fn suspicion(
        &self,
        hostname: &str,
        resolved: &ResolvedAddresses,
        family: AddressFamily,
    ) -> Option<Suspicion> {
        match family {
            AddressFamily::Ipv4 => {
                let answered = crate::dns_wire::only_v4(&resolved.addresses);
                if matches!(classify_answer(&answered), AnswerSanity::Unusable) {
                    return Some(Suspicion::NoUsableAddress);
                }
                self.reused_by_another_host(hostname, &answered)
                    .map(Suspicion::AlsoAnsweredFor)
            }
            // The reuse memory holds IPv4 fronts only. An empty AAAA answer is
            // the ordinary one, so only a non-empty set of placeholders is a doubt.
            AddressFamily::Ipv6 => (!resolved.addresses.is_empty()
                && carries_nothing_to_pin(resolved, family))
            .then_some(Suspicion::NoUsableAddress),
        }
    }

    fn recall_verdict(&self, hostname: &str, family: AddressFamily) -> Option<HostVerdict> {
        let mut verdicts = self.verdicts.lock().unwrap_or_else(|p| p.into_inner());
        verdicts.recall(hostname, family, Instant::now())
    }

    fn remember_verdict(&self, hostname: &str, family: AddressFamily, verdict: HostVerdict) {
        let mut verdicts = self.verdicts.lock().unwrap_or_else(|p| p.into_inner());
        verdicts.remember(hostname, family, verdict, Instant::now());
    }

    fn forget_verdict(&self, hostname: &str, family: AddressFamily) {
        let mut verdicts = self.verdicts.lock().unwrap_or_else(|p| p.into_inner());
        verdicts.forget(hostname, family);
    }

    /// Straight to the public resolvers for a host whose upstream answer was
    /// recently unusable. `None` sends the caller down the ordinary path.
    fn ask_fallbacks_directly(
        &self,
        hostname: &str,
        family: AddressFamily,
        budget: Duration,
    ) -> Option<ResolvedAddresses> {
        let started = Instant::now();
        let budget = budget.min(Self::CONFIRM_BUDGET);
        for fallback in &self.fallbacks {
            let left = budget.saturating_sub(started.elapsed());
            if left.is_zero() {
                break;
            }
            let Ok(candidate) = fallback.resolve_within(hostname, family, left) else {
                continue;
            };
            if self
                .confirmation(
                    hostname,
                    &Suspicion::NoUsableAddress,
                    None,
                    &candidate,
                    family,
                )
                .is_some()
            {
                crate::dns_tamper_summary::record(hostname);
                return Some(candidate);
            }
        }
        None
    }

    /// How `candidate` settles `suspicion`, or `None` when it does not.
    fn confirmation(
        &self,
        hostname: &str,
        suspicion: &Suspicion,
        primary: Option<&ResolvedAddresses>,
        candidate: &ResolvedAddresses,
        family: AddressFamily,
    ) -> Option<Confirmation> {
        if carries_nothing_to_pin(candidate, family) {
            return None;
        }
        let agreed = matches!(suspicion, Suspicion::AlsoAnsweredFor(_))
            && primary.is_some_and(|p| same_address_set(&p.addresses, &candidate.addresses));
        if agreed {
            return Some(Confirmation::Agreed);
        }
        if family == AddressFamily::Ipv6 {
            return Some(Confirmation::Replaced);
        }
        self.reused_by_another_host(hostname, &crate::dns_wire::only_v4(&candidate.addresses))
            .is_none()
            .then_some(Confirmation::Replaced)
    }
}

/// What kept a confirmation round from confirming, as the log says it.
fn unconfirmed_because(out_of_time: bool, failure: Option<&str>) -> String {
    match (failure, out_of_time) {
        (Some(why), true) => format!("{why}; then out of time"),
        (Some(why), false) => why.to_string(),
        (None, true) => "out of time".to_string(),
        (None, false) => "no usable answer".to_string(),
    }
}

/// An IPv6 address a route or a filter could name.
fn usable_v6(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if !crate::dns_address_sanity::is_unreachable_v6(v6))
}

/// Whether an answer holds no address of `family` that could ever be pinned —
/// either it names none at all, or every one of them is a placeholder.
///
/// The two are the same for the caller (there is nothing to enforce on) but
/// they are NOT the same evidence, which is why the loop below asks who
/// answered rather than only what they said.
fn carries_nothing_to_pin(answer: &ResolvedAddresses, family: AddressFamily) -> bool {
    answer.addresses.is_empty()
        || match family {
            AddressFamily::Ipv4 => matches!(
                classify_answer(&crate::dns_wire::only_v4(&answer.addresses)),
                AnswerSanity::Unusable
            ),
            AddressFamily::Ipv6 => !answer.addresses.iter().any(usable_v6),
        }
}

/// Do two answers name the same addresses, order aside? Answer sets are a
/// handful of entries, so the quadratic scan beats allocating a set.
fn same_address_set(a: &[IpAddr], b: &[IpAddr]) -> bool {
    a.len() == b.len() && a.iter().all(|ip| b.contains(ip))
}

impl UpstreamResolver for PoisonFallbackUpstreamResolver {
    /// No second opinion: the public resolvers' queries would be made by
    /// resolvers of their own, and only the inner one is held to the tunnel.
    fn resolve_tunnel_only_within(
        &self,
        hostname: &str,
        family: AddressFamily,
        budget: Duration,
    ) -> Result<ResolvedAddresses, ResolveError> {
        self.inner
            .resolve_tunnel_only_within(hostname, family, budget)
    }

    fn resolve_within(
        &self,
        hostname: &str,
        family: AddressFamily,
        budget: Duration,
    ) -> Result<ResolvedAddresses, ResolveError> {
        let call_started = std::time::Instant::now();
        let verdict = self.recall_verdict(hostname, family);
        if verdict == Some(HostVerdict::UpstreamUnusable) {
            if let Some(answer) = self.ask_fallbacks_directly(hostname, family, budget) {
                return Ok(answer);
            }
            self.forget_verdict(hostname, family);
        }
        let primary = self.inner.resolve_within(hostname, family, budget);
        // Everyone agreed last time that there is nothing to pin: the ordinary
        // answer goes out without another confirmation round.
        if verdict == Some(HostVerdict::NothingToPin) {
            return primary;
        }
        let suspicion = match &primary {
            Ok(resolved) => self.suspicion(hostname, resolved, family),
            // A filtering provider's refusal shows on the A answer, asked
            // beside this one; a host without AAAA is the common case, and
            // doubting it would put a second round-trip on nearly every one.
            Err(ResolveError::NoRecords) => {
                (family == AddressFamily::Ipv4).then_some(Suspicion::NoUsableAddress)
            }
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
                msg_key = "dns-resolver-reuse-suspected",
                host = %hostname,
                also_answered_for = %other,
                "upstream handed this host the exact address set of an unrelated one — asking a second source",
            );
        }
        let started = std::time::Instant::now();
        // The confirmation round gets what the primary resolve left, capped at
        // its own budget: a doubt worth a second opinion is not worth the
        // client's whole wait.
        let confirm_budget = budget
            .saturating_sub(call_started.elapsed())
            .min(Self::CONFIRM_BUDGET);
        // Did anyone answer at all, and did they see what we saw? A second
        // source that replies "this name has no address" has CONFIRMED the
        // doubt, not failed to resolve it — and most rule hosts are zone
        // suffixes whose apex legitimately carries no A record.
        let mut second_source_saw_nothing_either = false;
        // Why nothing confirmed, for the log: a round cut short and a source
        // that failed call for different fixes.
        let mut out_of_time = false;
        let mut failure: Option<String> = None;
        for fallback in &self.fallbacks {
            let left = confirm_budget.saturating_sub(started.elapsed());
            if left.is_zero() {
                out_of_time = true;
                break;
            }
            let candidate = match fallback.resolve_within(hostname, family, left) {
                Ok(candidate) => candidate,
                // NXDOMAIN or an empty answer is the second source's answer,
                // not its failure.
                Err(ResolveError::NoRecords) => {
                    second_source_saw_nothing_either = true;
                    continue;
                }
                Err(ResolveError::Unavailable(why)) => {
                    failure = Some(why);
                    continue;
                }
            };
            second_source_saw_nothing_either |= carries_nothing_to_pin(&candidate, family);
            match self.confirmation(
                hostname,
                &suspicion,
                primary.as_ref().ok(),
                &candidate,
                family,
            ) {
                Some(Confirmation::Agreed) => {
                    tracing::info!(
                        target: "nrr::dns-resolver",
                        msg_key = "dns-resolver-confirmation-agreed",
                        host = %hostname,
                        addresses = candidate.addresses.len(),
                        "an independent resolver named the same addresses — the reuse alarm was a false alarm",
                    );
                    return Ok(candidate);
                }
                Some(Confirmation::Replaced) => {
                    crate::dns_tamper_summary::record(hostname);
                    if matches!(suspicion, Suspicion::NoUsableAddress) {
                        self.remember_verdict(hostname, family, HostVerdict::UpstreamUnusable);
                    }
                    tracing::info!(
                        target: "nrr::dns-resolver",
                        msg_key = "dns-resolver-fallback-answered-clean",
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
            // Everyone agrees the name has nothing to pin. On a rule book full
            // of zone suffixes that is the ORDINARY answer for the apex, and
            // reporting it as a failed confirmation buried the real alarms:
            // measured at ten a minute on a live machine, every one of them a
            // CDN zone with no A record of its own.
            Suspicion::NoUsableAddress if second_source_saw_nothing_either => {
                self.remember_verdict(hostname, family, HostVerdict::NothingToPin);
                tracing::debug!(
                    target: "nrr::dns-resolver",
                    host = %hostname,
                    "a second source agrees this host has no address of its own — nothing to pin",
                );
            }
            Suspicion::NoUsableAddress => tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "dns-resolver-unconfirmed-answer",
                host = %hostname,
                reason = %suspicion.as_str(),
                second_source = %unconfirmed_because(out_of_time, failure.as_deref()),
                "no second source could confirm this host's addresses — returning the upstream answer unconfirmed (it will not be pinned)",
            ),
            Suspicion::AlsoAnsweredFor(other) => tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "dns-resolver-reuse-unconfirmed",
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
/// honours the hosts/adblock file — so a pinned rule host (an adblock entry
/// mapping it to `127.0.0.1`) never yields a routable public IP and the
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
    fn resolve(
        &self,
        hostname: &str,
        family: AddressFamily,
    ) -> Result<ResolvedRecord, DnsResolverError> {
        if !(self.bypass_enabled)() {
            return self.system.resolve(hostname, family);
        }
        let Some(server) = (self.upstream)() else {
            // No captured upstream (capture failed / not yet available) —
            // resolve through the system rather than not at all.
            return self.system.resolve(hostname, family);
        };
        let canonical = nrr_platform_api::dns::canonicalize_hostname(hostname);
        if canonical.is_empty() {
            return Err(DnsResolverError::InvalidName { name: canonical });
        }
        let mut direct = DirectUdpUpstreamResolver::new(server, self.timeout, 2);
        if let Some(policy) = &self.egress {
            direct = direct.with_egress(Arc::clone(policy));
        }
        match direct.resolve(&canonical, family) {
            Ok(ResolvedAddresses {
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
                self.system.resolve(hostname, family)
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
    resolved: &ResolvedAddresses,
    now: SystemTime,
) -> Option<ResolutionEntry> {
    let routable: Vec<IpAddr> = resolved
        .addresses
        .iter()
        .copied()
        .filter(|ip| !is_non_routable(ip))
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
    /// Read-side view over the same cache for the stable-answer
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
    fn record(&self, hostname: &str, resolved: &ResolvedAddresses) {
        let Some(entry) = build_resolution_entry(hostname, resolved, SystemTime::now()) else {
            return; // nothing routable to enforce
        };
        let guard = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(e) = guard.upsert_resolution(entry) {
            tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "dns-resolver-cache-upsert-failed",
                error = %e,
                "upsert_resolution failed while recording resolver fact",
            );
        }
    }

    fn cached_routable_ips(&self, hostname: &str) -> Vec<Ipv4Addr> {
        use crate::fqdn_cache_lookup::FqdnCacheLookup;
        // This feeds an `A` answer, so it is the v4 half by construction; the
        // AAAA answer gets its own selection when the family is enforced.
        crate::dns_wire::only_v4(&self.lookup.ips_for_hostname(hostname))
    }
}

/// production [`SecondaryOwnedIps`]: what the routing-active principal's
/// secondary rules send over the additional link — the rule-book × FQDN-cache
/// join the DNS observer uses, plus the networks the arbiter gives that link
/// ([`crate::secondary_address_owners::SecondaryAddressOwners`]). Memoized
/// for a few seconds — the listener consults it on every direct-host `A`
/// answer, and the underlying join walks the whole secondary rule fan-out.
///
/// ## Why this set is NOT gated on the secondary being usable
///
/// Gating this set on the secondary being usable is tempting: "nothing is
/// pinned to a dead link, so there is nothing to steer away from." The premise
/// is inverted: an unusable secondary is exactly when the fail-closed posture
/// installs a BLOCK over these addresses, so they go from "would take a
/// detour" to "will be dropped" — the moment a direct host most needs to be
/// steered off them. Gating on usability would let a direct host that shares
/// front-end addresses with a secondary rule host receive those addresses
/// verbatim while the secondary is down, losing connectivity instead of being
/// steered onto clean ones. Steering is therefore unconditional.
///
/// Steering away can never leak rule-host traffic: it only ever REMOVES
/// addresses from a NON-rule host's answer (rule hosts are intercepted and
/// answered upstream of this path), and it removes nothing from the enforced
/// pin/block set. The worst case is over-caution — a direct host is offered a
/// smaller address set than it strictly needed, and a fully-shared answer falls
/// through to the unchanged fail-open reply.
pub struct ActiveSecondaryOwnedIps {
    rules_provider: Arc<dyn RulesProvider>,
    principals: ResolverPrincipalsFn,
    fqdn: Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
    memo: Mutex<Option<(std::time::Instant, Arc<SecondaryAddressOwners>)>>,
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
            principals: principals_of_routing_user(active_sid),
            fqdn,
            memo: Mutex::new(None),
        }
    }

    /// Steer away from any served user's additional-link addresses: on a
    /// machine-wide route table, each of them is somebody's tunnel.
    #[must_use]
    pub fn with_served(mut self, served: ResolverPrincipalsFn) -> Self {
        self.principals = served;
        self
    }

    fn rebuild(&self) -> SecondaryAddressOwners {
        let parts = (self.principals)()
            .iter()
            .filter_map(|sid| self.rules_provider.active_rules_for(sid))
            .map(|snapshot| SecondaryAddressOwners::build(&snapshot.rule_book, self.fqdn.as_ref()))
            .collect();
        SecondaryAddressOwners::union(parts)
    }

    /// Memoized read with an injected `now` — the trait impl passes
    /// `Instant::now()`; tests advance `now` to cross the memo TTL without
    /// sleeping.
    fn owned_ips_at(&self, now: std::time::Instant) -> std::sync::Arc<SecondaryAddressOwners> {
        let mut guard = self.memo.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((at, set)) = guard.as_ref() {
            if now.saturating_duration_since(*at) < OWNED_SET_MEMO_TTL {
                // An `Arc` clone: every direct answer takes this path, and the
                // set is the whole pinned address space.
                return std::sync::Arc::clone(set);
            }
        }
        let set = std::sync::Arc::new(self.rebuild());
        *guard = Some((now, std::sync::Arc::clone(&set)));
        set
    }
}

impl crate::dns_resolver::SecondaryOwnedIps for ActiveSecondaryOwnedIps {
    fn secondary_owned_ips(&self) -> std::sync::Arc<SecondaryAddressOwners> {
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
/// Coalescing: without it, thread-per-call reconciles convoy on the
/// orchestrator lock under an armed block-all — each new direct host spawns
/// another full reconcile, each one slower than the last, and the
/// direct-answer gates blow their budget. A caller instead registers its
/// generation (its facts are already recorded/registered by then) and is
/// satisfied by the first hook run that STARTS after its registration;
/// concurrent callers share that run. The worker lives for the reconciler's
/// lifetime and exits on drop.
pub struct HookSyncReconciler {
    hook: RouteRecomputeHook,
    state: Arc<(Mutex<ReconcileWorkerState>, std::sync::Condvar)>,
    /// Duration of the last completed hook run, in milliseconds; `0` until one
    /// has finished. Read by [`SyncReconciler::typical_run`].
    last_run_ms: Arc<std::sync::atomic::AtomicU64>,
    first_contact: Option<FirstContactFn>,
    first_contact_v6: Option<FirstContactV6Fn>,
    /// What the first-contact routes cost the answers that waited on them.
    first_contact_timing: FirstContactTiming,
    /// Where the worker reports; a hook running past
    /// [`RECONCILE_WORK_DEADLINE`] is a hang every waiter pays for.
    liveness: Option<Arc<crate::task_liveness::TaskLiveness>>,
    /// What a forced request runs instead of `hook`.
    forced_hook: Option<RouteRecomputeHook>,
}

/// A run shorter than this was an idle pass, not a plan and an apply.
const SKIPPED_PASS: Duration = Duration::from_millis(20);

/// One reconcile run longer than this is stuck, not slow: waiters give up on
/// it after a fraction of a second.
const RECONCILE_WORK_DEADLINE: Duration = Duration::from_secs(60);

/// A first contact above this held its DNS answer long enough to count.
const FIRST_CONTACT_SLOW: Duration = Duration::from_millis(5);
/// How often the cost of first contacts is written down, at most.
const FIRST_CONTACT_REPORT_EVERY: Duration = Duration::from_secs(60);

/// The time first-contact routes add to the DNS answers that wait on them,
/// summed and written down once a minute: the answer path is where a slow
/// route is paid, and one line per query would cost more than it tells.
#[derive(Default)]
struct FirstContactTiming {
    acc: Mutex<FirstContactAcc>,
}

#[derive(Default)]
struct FirstContactAcc {
    calls: u64,
    slow: u64,
    total: Duration,
    max: Duration,
    since: Option<Instant>,
}

/// One minute of first contacts, as written down.
#[derive(Debug, PartialEq, Eq)]
struct FirstContactSummary {
    calls: u64,
    slow: u64,
    avg_us: u64,
    max_us: u64,
}

impl FirstContactTiming {
    fn record(&self, elapsed: Duration, now: Instant) {
        if let Some(summary) = self.add(elapsed, now) {
            tracing::info!(
                target: "nrr::dns-resolver",
                msg_key = "dns-first-contact-timing",
                calls = summary.calls,
                slow = summary.slow,
                avg_us = summary.avg_us,
                max_us = summary.max_us,
                "first-contact routes: time added to DNS answers over the last minute",
            );
        }
    }

    /// Add one call; the summary once a report is due, which starts the next.
    fn add(&self, elapsed: Duration, now: Instant) -> Option<FirstContactSummary> {
        let mut acc = self.acc.lock().unwrap_or_else(|p| p.into_inner());
        let since = *acc.since.get_or_insert(now);
        acc.calls += 1;
        acc.total += elapsed;
        acc.max = acc.max.max(elapsed);
        if elapsed > FIRST_CONTACT_SLOW {
            acc.slow += 1;
        }
        if now.saturating_duration_since(since) < FIRST_CONTACT_REPORT_EVERY {
            return None;
        }
        let done = std::mem::take(&mut *acc);
        let micros = |d: Duration| u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
        Some(FirstContactSummary {
            calls: done.calls,
            slow: done.slow,
            avg_us: micros(done.total) / done.calls.max(1),
            max_us: micros(done.max),
        })
    }
}

/// Routes a first contact's addresses ahead of the full run; returns how many
/// got their route. See [`SyncReconciler::install_first_contact`].
pub type FirstContactFn = Arc<dyn Fn(&[std::net::Ipv4Addr]) -> usize + Send + Sync>;

/// The same for an AAAA answer's addresses. A platform without a v6
/// first-contact route leaves it unset and its AAAA answers wait for the
/// full run, as before.
pub type FirstContactV6Fn = Arc<dyn Fn(&[std::net::Ipv6Addr]) -> usize + Send + Sync>;

#[derive(Default)]
struct ReconcileWorkerState {
    /// Highest generation any caller has requested.
    requested: u64,
    /// Highest generation the worker has fully reconciled (the hook run that
    /// completed it started no earlier than the request).
    completed: u64,
    /// Highest generation whose covering run panicked. Its waiters are
    /// answered at once instead of waiting out their deadline, and the worker
    /// does not re-run for it — a hook that always panics must not spin.
    failed: u64,
    /// Highest generation requested with the forced run.
    forced: u64,
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
            last_run_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            first_contact: None,
            first_contact_v6: None,
            first_contact_timing: FirstContactTiming::default(),
            liveness: None,
            forced_hook: None,
        }
    }

    /// The run a [`SyncReconciler::reconcile_forced`] request gets; without
    /// it a forced request is a plain one.
    #[must_use]
    pub fn with_forced_hook(mut self, hook: RouteRecomputeHook) -> Self {
        self.forced_hook = Some(hook);
        self
    }

    /// Report the worker to `liveness`.
    #[must_use]
    pub fn with_liveness(
        mut self,
        liveness: Option<Arc<crate::task_liveness::TaskLiveness>>,
    ) -> Self {
        self.liveness = liveness;
        self
    }

    #[must_use]
    pub fn with_first_contact(mut self, route: FirstContactFn) -> Self {
        self.first_contact = Some(route);
        self
    }

    #[must_use]
    pub fn with_first_contact_v6(mut self, route: FirstContactV6Fn) -> Self {
        self.first_contact_v6 = Some(route);
        self
    }

    /// Single worker loop: run the hook once per outstanding batch of requests,
    /// crediting every caller whose request preceded the run's start.
    fn worker_loop(
        hook: RouteRecomputeHook,
        forced_hook: Option<RouteRecomputeHook>,
        state: Arc<(Mutex<ReconcileWorkerState>, std::sync::Condvar)>,
        last_run: Arc<std::sync::atomic::AtomicU64>,
        liveness: Option<Arc<crate::task_liveness::TaskLiveness>>,
    ) {
        use crate::task_liveness::{ThreadExit, ThreadLease, Watch};
        let lease = liveness.as_ref().map(|liveness| {
            liveness.lease(
                crate::service_tasks::ServiceTaskKind::DnsReconcileWorker,
                None,
                Watch::Work(RECONCILE_WORK_DEADLINE),
            )
        });
        let (lock, cv) = &*state;
        loop {
            let (target, forced) = {
                let mut guard = lock.lock().unwrap_or_else(|p| p.into_inner());
                loop {
                    if guard.shutdown {
                        drop(guard);
                        if let Some(lease) = lease {
                            lease.finish(ThreadExit::Stopped);
                        }
                        return;
                    }
                    let done = guard.completed.max(guard.failed);
                    if guard.requested > done {
                        break (guard.requested, guard.forced > done);
                    }
                    guard = cv.wait(guard).unwrap_or_else(|p| p.into_inner());
                }
            };
            // Hook runs OUTSIDE the lock — new requests keep registering while
            // it works; they will be covered by the NEXT run (their facts may
            // have landed mid-run, so this run cannot vouch for them).
            let started = std::time::Instant::now();
            let run = lease.as_ref().map(ThreadLease::work);
            // A panic must not take the worker with it: the flag would still
            // say "spawned" and every later reconcile would wait out its
            // deadline, withholding every rule host until a restart.
            let run_hook = match (&forced_hook, forced) {
                (Some(forced_hook), true) => forced_hook,
                _ => &hook,
            };
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_hook()));
            drop(run);
            if let Err(panic) = outcome {
                let detail = panic
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_default();
                tracing::error!(
                    target: "nrr::dns",
                    panic = %detail,
                    "route/WFP reconcile panicked — its waiters are told it did not install",
                );
                let mut guard = lock.lock().unwrap_or_else(|p| p.into_inner());
                guard.failed = guard.failed.max(target);
                cv.notify_all();
                continue;
            }
            let took = started.elapsed();
            // Published so the answer gate can tell a wait that can succeed
            // from one that cannot — see `SyncReconciler::typical_run`.
            // A pass skipped as unchanged says nothing about what a real one costs.
            if took >= SKIPPED_PASS {
                last_run.store(
                    took.as_millis().min(u128::from(u64::MAX)) as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
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

impl HookSyncReconciler {
    fn wait_for_run(&self, deadline: Duration, forced: bool) -> ReconcileOutcome {
        let (lock, cv) = &*self.state;
        let my_gen = {
            let mut guard = lock.lock().unwrap_or_else(|p| p.into_inner());
            guard.requested += 1;
            if forced {
                guard.forced = guard.requested;
            }
            if !guard.worker_spawned {
                guard.worker_spawned = true;
                let hook = Arc::clone(&self.hook);
                let forced_hook = self.forced_hook.clone();
                let state = Arc::clone(&self.state);
                let last_run = Arc::clone(&self.last_run_ms);
                let liveness = self.liveness.clone();
                std::thread::spawn(move || {
                    Self::worker_loop(hook, forced_hook, state, last_run, liveness)
                });
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
            // The run that covered this request panicked: not installed, and
            // the consumers already treat that like a missed deadline.
            if guard.failed >= my_gen {
                return ReconcileOutcome::DeadlineExceeded;
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

impl Drop for HookSyncReconciler {
    fn drop(&mut self) {
        let (lock, cv) = &*self.state;
        let mut guard = lock.lock().unwrap_or_else(|p| p.into_inner());
        guard.shutdown = true;
        cv.notify_all();
    }
}

impl SyncReconciler for HookSyncReconciler {
    fn reconcile_forced(&self, deadline: Duration) -> ReconcileOutcome {
        self.wait_for_run(deadline, self.forced_hook.is_some())
    }

    fn reconcile_now(&self, deadline: Duration) -> ReconcileOutcome {
        self.wait_for_run(deadline, false)
    }

    fn request_reconcile_forced(&self) {
        let _ = self.reconcile_forced(Duration::ZERO);
    }

    fn typical_run(&self) -> Option<Duration> {
        match self.last_run_ms.load(std::sync::atomic::Ordering::Relaxed) {
            0 => None,
            ms => Some(Duration::from_millis(ms)),
        }
    }

    fn install_first_contact(&self, addresses: &[std::net::Ipv4Addr]) -> usize {
        let Some(route) = self.first_contact.as_ref() else {
            return 0;
        };
        let started = Instant::now();
        let routed = route(addresses);
        self.first_contact_timing
            .record(started.elapsed(), Instant::now());
        routed
    }

    fn install_first_contact_v6(&self, addresses: &[std::net::Ipv6Addr]) -> usize {
        let Some(route) = self.first_contact_v6.as_ref() else {
            return 0;
        };
        let started = Instant::now();
        let routed = route(addresses);
        self.first_contact_timing
            .record(started.elapsed(), Instant::now());
        routed
    }
}

/// Production [`crate::dns_resolver::EnforcedAddressView`]: the routing-active
/// principal's slice of what the last apply installed.
///
/// Keyed on the active SID rather than a union across principals — an address
/// enforced for somebody else says nothing about the connection this answer is
/// about to enable. With nobody routing-active nothing is enforced, which is
/// the truth: no principal's filters are installed.
pub struct ActiveSidEnforcedAddresses {
    active_sid: crate::supervised_runtime::ActiveRoutingSidFn,
    register: Arc<crate::enforced_addresses::EnforcedAddressRegister>,
    /// With several users served, a host's answer is held until it is carried
    /// for each user whose rule names it.
    owners: Option<Arc<ActiveRuleHostOracle>>,
}

impl ActiveSidEnforcedAddresses {
    pub fn new(active_sid: crate::supervised_runtime::ActiveRoutingSidFn) -> Self {
        Self {
            active_sid,
            register: crate::enforced_addresses::global_enforced_addresses(),
            owners: None,
        }
    }

    /// Judge each answer by the users whose rules name its host.
    #[must_use]
    pub fn with_host_owners(mut self, oracle: Arc<ActiveRuleHostOracle>) -> Self {
        self.owners = Some(oracle);
        self
    }
}

impl crate::dns_resolver::EnforcedAddressView for ActiveSidEnforcedAddresses {
    fn is_enforced(&self, ip: std::net::Ipv4Addr) -> bool {
        (self.active_sid)().is_some_and(|sid| self.register.is_enforced(&sid, ip))
    }

    fn unenforced_for_host(
        &self,
        hostname: &str,
        answered: &[std::net::Ipv4Addr],
    ) -> Vec<std::net::Ipv4Addr> {
        let owners = self
            .owners
            .as_ref()
            .map(|oracle| oracle.owners_of(hostname))
            .unwrap_or_default();
        if owners.is_empty() {
            return answered
                .iter()
                .copied()
                .filter(|ip| !self.is_enforced(*ip))
                .collect();
        }
        answered
            .iter()
            .copied()
            .filter(|ip| !owners.iter().all(|sid| self.register.is_enforced(sid, *ip)))
            .collect()
    }
}

// ── FCrDNS learner adapters ──────────────────────────────────────────────────

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
        match DirectUdpUpstreamResolver::new(server, self.timeout, 2)
            .resolve(hostname, AddressFamily::Ipv4)
        {
            Ok(ResolvedAddresses { addresses, .. }) => crate::dns_wire::only_v4(&addresses),
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

// ── Direct-answer gate (block-all direct-host exemptions) ────────────────────

/// Production [`crate::dns_resolver::DirectAnswerGate`]: while the kill-switch
/// block-all is armed, register a steered direct answer's addresses as
/// known-direct and drive the SAME bounded synchronous reconcile the rule-host
/// path uses, so the exemption is installed BEFORE the client receives the
/// answer (its first connect would otherwise race the catch-all and be dropped
/// with no retry — the observed first-contact drop).
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
        let outcome = self.reconciler.reconcile_forced(self.deadline);
        tracing::info!(
            target: "nrr::dns-resolver",
            msg_key = "dns-resolver-block-all-exemption-installed",
            host = %hostname,
            added,
            outcome = ?outcome,
            "Mode B: direct host under block-all — known-direct exemption installed before answering",
        );
    }
}

#[cfg(test)]
mod tests;
