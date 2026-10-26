//! loopback DNS intercept listener.
//!
//! Ties the wire codec ([`crate::dns_wire`]) and the query handler
//! ([`crate::dns_resolver`]) to a blocking UDP socket. For an `A` query whose
//! name is a rule host it runs the enforce-before-answer handler and builds the
//! response from OUR resolved IPs (so the app gets exactly what we enforced).
//! EVERYTHING else — `AAAA`, non-rule `A`, other record types, unparseable
//! packets — is forwarded to the upstream DNS server as **raw bytes** and
//! relayed back, so redirecting system DNS to this listener never breaks general
//! name resolution (fail-open by construction).
//!
//! Blocking + thread-based (no tokio) to match the service supervisor's task
//! model. Binding the socket is neutral (std UDP); *pointing the OS at* this
//! listener is a separate, per-OS concern behind `SystemDnsRedirectPort`.
//! DNS over TCP is served on the same address through the same answer path,
//! so a truncated (`TC=1`) answer the OS retries over TCP comes back whole.
//!
//! Every byte read here is shaped by another party — a local process or an
//! upstream — so each stage is bounded (queue, per-source share, connection
//! count, frame size, time), and a failure in one query, a panic included,
//! costs that query alone.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::TrySendError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::dns_resolver::{
    handle_a_query, AaaaOutcome, CompanionCandidateLookup, CompanionRescueObserver,
    DirectFakeIpAnswerer, FactSink, FakeIpAnswerer, NoopCompanionCandidates, NoopCompanionRescue,
    NoopDirectFakeIp, NoopFakeIpAnswerer, NoopSecondaryOwnedIps, NoopUnresolvedRuleHosts,
    QueryOutcome, ResolveError, RuleHostOracle, SecondaryOwnedIps, SyncReconciler,
    UnresolvedRuleHostObserver, UpstreamResolver,
};
use crate::dns_wire::{
    build_a_response, build_error_response, build_negative_response, only_v4,
    parse_address_response, parse_question, AddressResponseOutcome, ParsedQuestion, QTYPE_A,
    QTYPE_AAAA, RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_SERVFAIL,
};

/// TTL (seconds) stamped on resolver-built `A` responses. Deliberately SHORT so
/// the app re-queries through us soon — every re-query re-installs enforcement
/// on the freshest IPs, which is exactly how rotation coverage stays current.
/// (The FQDN cache still records the real upstream TTL via the [`FactSink`]; this
/// is only the value handed to the client.)
pub const RESPONSE_TTL_SECS: u32 = 60;

/// datagram workers per listener. DNS on one machine is bursty but
/// small; eight workers cover a page-load burst of new hosts (each possibly
/// holding a bounded reconcile budget) without serializing the system's DNS.
const SERVE_WORKER_THREADS: usize = 8;

/// Bounded hand-off queue between the receive loop and the workers. On
/// overflow the datagram is answered SERVFAIL at once: backpressure into the
/// receive loop turned one program's flood into everybody's lost queries.
const SERVE_QUEUE_DEPTH: usize = 512;

/// Steady share of the listener one source (one socket, by address and port)
/// may take, and how far it may burst past it. Beyond that its queries are
/// failed on the spot, so the queue stays open to everyone else. On Windows
/// the DNS Client service is the one source for every program, so this is
/// also the machine-wide ceiling there; a page load stays well inside the burst.
const SOURCE_RATE_PER_SEC: f64 = 200.0;
const SOURCE_BURST: f64 = 400.0;
/// Sources remembered at once; a source quiet for a second is forgotten.
const SOURCE_TABLE_CAP: usize = 1024;
const SOURCE_IDLE: Duration = Duration::from_secs(1);

/// DNS over TCP: how many connections are served at once, what one may send,
/// and how long it may hold a thread. Every one of these is set by the peer.
const TCP_MAX_CONNECTIONS: usize = 16;
const TCP_MAX_QUERY_BYTES: usize = 4096;
const TCP_MAX_QUERIES_PER_CONNECTION: usize = 8;
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_CONNECTION_LIFETIME: Duration = Duration::from_secs(10);
const TCP_ACCEPT_POLL: Duration = Duration::from_millis(50);

/// Which transport a query arrived on; the forward to the upstream uses the
/// same one, so a TCP client's answer is never cut to datagram size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
}

/// Token buckets per source, owned by the receive thread: one map lookup and
/// a subtraction per datagram.
#[derive(Default)]
struct SourceLimiter {
    buckets: HashMap<SocketAddr, (f64, Instant)>,
    /// The full table is swept at most once per [`SOURCE_IDLE`]: a sweep per
    /// newcomer cost every datagram of a many-socket flood a pass over the table.
    swept: Option<Instant>,
}

impl SourceLimiter {
    fn admit(&mut self, src: SocketAddr, now: Instant) -> bool {
        if self.buckets.len() >= SOURCE_TABLE_CAP && !self.buckets.contains_key(&src) {
            if self
                .swept
                .is_none_or(|at| now.duration_since(at) >= SOURCE_IDLE)
            {
                self.swept = Some(now);
                self.buckets
                    .retain(|_, (_, seen)| now.duration_since(*seen) < SOURCE_IDLE);
            }
            if self.buckets.len() >= SOURCE_TABLE_CAP {
                // A flood from thousands of sockets has filled the table; the
                // queue bound still holds, and a newcomer is not refused for it.
                return true;
            }
        }
        let (tokens, seen) = self.buckets.entry(src).or_insert((SOURCE_BURST, now));
        let refill = now.duration_since(*seen).as_secs_f64() * SOURCE_RATE_PER_SEC;
        *tokens = (*tokens + refill).min(SOURCE_BURST);
        *seen = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShedReason {
    QueueFull,
    SourceShare,
}

/// Buffers the workers hand back, so the receive loop copies each datagram
/// into one it already owns instead of allocating a fresh one per query.
#[derive(Default)]
struct QueryBuffers {
    spare: Mutex<Vec<Vec<u8>>>,
}

/// Spare buffers kept: a page-load burst, not the whole queue.
const SPARE_QUERY_BUFFERS: usize = 64;
/// A buffer a rare oversized datagram grew is let go rather than kept.
const SPARE_QUERY_BUFFER_BYTES: usize = 4096;

impl QueryBuffers {
    /// `datagram` in a buffer of its own.
    fn filled(&self, datagram: &[u8]) -> Vec<u8> {
        let spare = self.spare.lock().unwrap_or_else(|p| p.into_inner()).pop();
        let mut buffer = spare.unwrap_or_default();
        buffer.clear();
        buffer.extend_from_slice(datagram);
        buffer
    }

    fn give_back(&self, buffer: Vec<u8>) {
        if buffer.capacity() > SPARE_QUERY_BUFFER_BYTES {
            return;
        }
        let mut spare = self.spare.lock().unwrap_or_else(|p| p.into_inner());
        if spare.len() < SPARE_QUERY_BUFFERS {
            spare.push(buffer);
        }
    }
}

/// Counts shed datagrams and says so once per interval: the shedding itself
/// is per datagram, the line about it must not be.
#[derive(Default)]
struct ShedLog {
    shed: u64,
    last_log: Option<Instant>,
}

impl ShedLog {
    fn note(&mut self, reason: ShedReason, src: SocketAddr) {
        self.shed += 1;
        if self
            .last_log
            .is_some_and(|at| at.elapsed() < RECV_NOISE_LOG_INTERVAL)
        {
            return;
        }
        self.last_log = Some(Instant::now());
        tracing::warn!(
            target: "nrr::dns-resolver",
            msg_key = "dns-listener-query-shed",
            reason = ?reason,
            source = %src,
            shed = self.shed,
            "Mode B: a DNS query was failed at once instead of queued — the listener is saturated or one source is past its share",
        );
    }
}

/// What every thread of one serve loop watches: the caller's `stop`, or the
/// receive loop having ended on its own (an error streak, a panic).
#[derive(Clone, Copy)]
struct StopSignal<'a> {
    stop: &'a AtomicBool,
    ended: &'a AtomicBool,
}

impl StopSignal<'_> {
    fn is_set(self) -> bool {
        self.stop.load(Ordering::Relaxed) || self.ended.load(Ordering::Relaxed)
    }
}

/// Dropped when the receive loop ends, by return or by unwind.
struct ServeEnd<'a> {
    ended: &'a AtomicBool,
    on_stop: &'a dyn Fn(),
}

impl Drop for ServeEnd<'_> {
    fn drop(&mut self) {
        // Caught: a panic here while already unwinding would abort the service.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.on_stop)()));
        self.ended.store(true, Ordering::Relaxed);
    }
}

/// Everything one client datagram may cost, end to end. The per-stage timeouts
/// (rule-host resolve, second opinion, fail-open forward, rotation retry,
/// reconcile) are independent and sum past seven seconds, while the client's
/// stub resolver gives up and re-asks after about one. The stage timeouts stay
/// as they are; every branch divides this instead of adding them up.
const QUERY_BUDGET: Duration = Duration::from_secs(3);

/// How many workers may sit in the enforce-before-answer path at once.
///
/// The budget bounds ONE query; this bounds how many of them may be in that
/// path together. Uncapped it takes the whole pool: while the additional link was down, the
/// machine's resolver censored exactly the names the secondary rules cover,
/// every worker sat in one of them, and names with no rule at all stopped
/// resolving machine-wide (the client gave up first, which is what the
/// `client port closed` storm in the service log counts). The three workers
/// this leaves are what keeps the rest of the system's DNS moving.
const MAX_CONCURRENT_RULE_HOST_RESOLVES: usize = 5;

/// How long a worker waits for a rule-host slot before answering without one.
/// A page-load burst frees slots in tens of milliseconds, so a healthy burst
/// never reaches the fallback; a stuck upstream does, and then the worker is
/// back in the pool well inside the second the client's stub resolver waits.
const RULE_HOST_LANE_WAIT: Duration = Duration::from_millis(400);

/// What the listener should do with one datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenerAction {
    /// Send these bytes straight back to the client (an intercepted rule-host
    /// `A` answer, or an `NXDOMAIN` for a rule host with no records).
    Respond(Vec<u8>),
    /// Not intercepted — forward the raw query upstream and relay the reply.
    Forward,
    /// a DIRECT (non-rule) host `A` query: forward
    /// upstream, then steer the reply through
    /// [`DnsInterceptListener::steer_parsed`] so the client never gets
    /// an address the kill-switch pins to the secondary (shared-CDN
    /// collateral). Degrades to a plain relay whenever steering has nothing
    /// to do or cannot produce a clean answer.
    ForwardFiltered,
    /// Answer nothing at all. Reached only when a response the handler decided
    /// to send could not be built — the caller times out, which is the safe
    /// direction here: every reachable case that produces it is one where
    /// forwarding would hand over addresses the leak guard is holding back.
    Drop,
}

/// Lists the machine's private resolvers, newest answer each call; empty when
/// the list is not known within the given budget.
pub type PrivateResolversFn = Arc<dyn Fn(Duration) -> Vec<std::net::Ipv4Addr> + Send + Sync>;

/// The network domain the user named for short names, for a connection that
/// announces none. `None` when the setting is off.
pub type ShortNameSuffixFn = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// How many private resolvers are re-asked before a "no such name" stands.
/// Enough for a corporate resolver that is not first by metric; the datagram's
/// time budget, not this count, is the real bound on the burst.
const MAX_PRIVATE_RETRIES: usize = 4;

/// What policy may do about IPv6 for the routing principal right now; `None`
/// while its first plan is still to come.
pub type Ipv6DispositionFn =
    Arc<dyn Fn() -> Option<crate::enforcement_planner::Ipv6Guard> + Send + Sync>;

/// Negative TTL of the AAAA withheld before the first plan: short, so the
/// family comes back soon after a plan says what carries it.
const UNPLANNED_AAAA_TTL_SECS: u32 = 5;

/// Admission control for the enforce-before-answer path — see
/// [`MAX_CONCURRENT_RULE_HOST_RESOLVES`]. A worker that cannot get in within
/// [`RULE_HOST_LANE_WAIT`] answers the query without the upstream instead of
/// queueing behind a resolver that may never come back.
#[derive(Default)]
struct RuleHostLane {
    in_flight: Mutex<usize>,
    freed: std::sync::Condvar,
}

impl RuleHostLane {
    fn enter(&self, wait: Duration) -> Option<RuleHostLanePermit<'_>> {
        let started = Instant::now();
        let mut in_flight = self.in_flight.lock().unwrap_or_else(|p| p.into_inner());
        while *in_flight >= MAX_CONCURRENT_RULE_HOST_RESOLVES {
            let left = wait.checked_sub(started.elapsed())?;
            let (guard, wait_result) = self
                .freed
                .wait_timeout(in_flight, left)
                .unwrap_or_else(|p| p.into_inner());
            in_flight = guard;
            if wait_result.timed_out() && *in_flight >= MAX_CONCURRENT_RULE_HOST_RESOLVES {
                return None;
            }
        }
        *in_flight += 1;
        Some(RuleHostLanePermit { lane: self })
    }
}

struct RuleHostLanePermit<'a> {
    lane: &'a RuleHostLane,
}

impl Drop for RuleHostLanePermit<'_> {
    fn drop(&mut self) {
        let mut in_flight = self
            .lane
            .in_flight
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        *in_flight = in_flight.saturating_sub(1);
        self.lane.freed.notify_one();
    }
}

/// The intercept listener. Holds the resolver ports plus the upstream DNS server
/// to forward non-intercepted queries to (captured *before* the DNS redirect,
/// so split-horizon keeps working).
pub struct DnsInterceptListener {
    oracle: Arc<dyn RuleHostOracle>,
    /// Keeps a slow upstream from holding every worker — see [`RuleHostLane`].
    rule_host_lane: RuleHostLane,
    /// Latches the saturated state so entering and leaving it are each said
    /// once, instead of one line per query while it lasts.
    rule_lane_saturated: AtomicBool,
    /// Rule hosts whose AAAA we have already reported as leaving policy,
    /// so a repeated lookup does not repeat the warning. Bounded: a suffix
    /// rule can match unboundedly many names, and a diagnostic must not be
    /// the thing that grows without limit.
    aaaa_outside_policy_reported: Mutex<HashSet<String>>,
    upstream: Arc<dyn UpstreamResolver>,
    sink: Arc<dyn FactSink>,
    reconciler: Arc<dyn SyncReconciler>,
    /// What the installed policy carries right now — the answer gate's source
    /// of truth for "is this address enforced". The default reports nothing as
    /// enforced, which is the truth for a listener with no apply behind it.
    enforced_view: Arc<dyn crate::dns_resolver::EnforcedAddressView>,
    /// Secondary-owned (pinned) addresses for direct-answer steering.
    /// The default no-op (empty set) leaves every direct reply untouched.
    secondary_owned: Arc<dyn SecondaryOwnedIps>,
    /// The machine's private resolvers, re-asked when one server calls a name
    /// non-existent. `None` keeps the single-server behaviour the listener had.
    private_resolvers: Option<PrivateResolversFn>,
    /// Namespaces connections claim, as the resolver's guard last read them —
    /// the set the redirect steps aside for, so the two cannot disagree.
    /// `None` leaves single-label names exactly as they arrive.
    claimed_namespaces: Option<crate::dns_resolver_service::ClaimsSnapshot>,
    short_name_suffix: Option<ShortNameSuffixFn>,
    /// Port the resolvers named by a connection listen on. Always 53 outside
    /// tests, which cannot bind it.
    resolver_port: u16,
    /// Fake-IP — answers scope hosts with virtual addresses.
    /// The default no-op returns the real per-IP path for every host.
    fake_ip: Arc<dyn FakeIpAnswerer>,
    /// Collateral rescue — a DIRECT host whose steered answer is STILL fully
    /// secondary-pinned (shared-CDN address the census committed to the
    /// secondary link) is answered with a virtual address while the fake-IP
    /// stack is live, instead of the old fail-open "relay the pinned answer"
    /// (which sent the host out the VPN link — geo captchas when it is up,
    /// a kill-switch block when it is down). Armed on "stack running" alone.
    /// The default no-op keeps the fail-open path.
    collateral_fake: Arc<dyn DirectFakeIpAnswerer>,
    /// Vetoes the collateral rescue for a host the companion detector already
    /// parked as a suggestion for the additional link. See
    /// [`CompanionCandidateLookup`].
    companion_candidates: Arc<dyn CompanionCandidateLookup>,
    /// Reports a rescued host to the suggestion engine under its own name. See
    /// [`CompanionRescueObserver`].
    companion_rescue: Arc<dyn CompanionRescueObserver>,
    /// Whether the leak guard is blocking with the additional link unresolved.
    /// A rule-host answer that missed its reconcile deadline is withheld while
    /// it is — see [`crate::dns_resolver::LeakGuardPosture`]. The default never
    /// blocks, keeping the historic fail-open.
    leak_guard: Arc<dyn crate::dns_resolver::LeakGuardPosture>,
    /// Told about a rule host this listener answered with no address. The
    /// default keeps nothing.
    unresolved: Arc<dyn UnresolvedRuleHostObserver>,
    /// The default is `Off`, which handles every AAAA exactly as before IPv6
    /// could be routed.
    ipv6_disposition: Ipv6DispositionFn,
    /// Live choice of forwarding upstream — rotates itself when the server it
    /// points at stops answering.
    upstream_dns: Arc<crate::dns_upstream::UpstreamDnsPool>,
    deadline: Duration,
    forward_timeout: Duration,
    response_ttl: u32,
    /// When a handler panic was last reported; see [`Self::note_handler_panic`].
    last_panic_log: Mutex<Option<Instant>>,
    /// DNS-over-TCP connections being served right now.
    tcp_active: AtomicUsize,
}

/// Receive buffer for both directions of the DNS path: the largest UDP payload
/// there is, so no datagram is ever cut. Undersized, the two failure modes were
/// worse than a truncated packet: on Windows the receive fails with "message
/// too long" and a healthy upstream collected a failure for an answer we could
/// not hold (three of those rotated it away); on Linux the answer was relayed
/// cut short without the TC bit. Stack-only; the copy is the bytes received.
const DNS_DATAGRAM_BUFFER_BYTES: usize = 65_535;

/// How many consecutive receive errors of a kind we do not recognise are
/// tolerated before the serve loop gives up.
///
/// Returning on the first unrecognised error would switch DNS interception
/// off machine-wide over a single unusual datagram, until the watchdog
/// noticed (~50 s). A genuinely dead socket fails every time, so a run of
/// them still ends the loop; one odd packet does not.
const DNS_RECV_ERROR_TOLERANCE: u32 = 16;

/// Minimum spacing between per-datagram receive-noise log lines: any local
/// process can produce that noise at will.
const RECV_NOISE_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// What one failed `recv_from` means for the serve loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecvErrorClass {
    /// The read timeout — a chance to look at `stop`.
    Idle,
    /// About one datagram, not the socket: skip it, never count it.
    PerDatagram,
    /// Unknown; a run of these means the socket is dead.
    Unrecognised,
}

/// WSAEMSGSIZE: Windows reports a datagram larger than the buffer as an error
/// (the truncated datagram is discarded). Linux and macOS truncate silently
/// and return the length read, so there is no counterpart to recognise.
#[cfg(windows)]
const OS_ERROR_DATAGRAM_TOO_LARGE: Option<i32> = Some(10040);
#[cfg(not(windows))]
const OS_ERROR_DATAGRAM_TOO_LARGE: Option<i32> = None;

/// Classify a receive error. A UDP server must never die on one datagram:
/// counting per-datagram conditions toward the fatal streak let any local
/// process switch interception off by sending sixteen of them.
fn classify_recv_error(error: &std::io::Error) -> RecvErrorClass {
    use std::io::ErrorKind;
    match error.kind() {
        // A signal (resume from sleep among them) interrupts a waiting
        // receive; nothing arrived and nothing is wrong.
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted => {
            RecvErrorClass::Idle
        }
        // Windows surfaces the ICMP port-unreachable for a reply to a client
        // whose port already closed (WSAECONNRESET) on the NEXT receive.
        ErrorKind::ConnectionReset
        | ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionAborted => RecvErrorClass::PerDatagram,
        _ if OS_ERROR_DATAGRAM_TOO_LARGE.is_some()
            && error.raw_os_error() == OS_ERROR_DATAGRAM_TOO_LARGE =>
        {
            RecvErrorClass::PerDatagram
        }
        _ => RecvErrorClass::Unrecognised,
    }
}

impl DnsInterceptListener {
    pub fn new(
        oracle: Arc<dyn RuleHostOracle>,
        upstream: Arc<dyn UpstreamResolver>,
        sink: Arc<dyn FactSink>,
        reconciler: Arc<dyn SyncReconciler>,
        upstream_dns: SocketAddr,
        deadline: Duration,
        forward_timeout: Duration,
    ) -> Self {
        Self {
            aaaa_outside_policy_reported: Mutex::new(HashSet::new()),
            rule_host_lane: RuleHostLane::default(),
            rule_lane_saturated: AtomicBool::new(false),
            oracle,
            upstream,
            sink,
            reconciler,
            secondary_owned: Arc::new(NoopSecondaryOwnedIps),
            private_resolvers: None,
            claimed_namespaces: None,
            short_name_suffix: None,
            resolver_port: 53,
            fake_ip: Arc::new(NoopFakeIpAnswerer),
            collateral_fake: Arc::new(NoopDirectFakeIp),
            companion_candidates: Arc::new(NoopCompanionCandidates),
            companion_rescue: Arc::new(NoopCompanionRescue),
            leak_guard: Arc::new(crate::dns_resolver::OpenLeakGuard),
            unresolved: Arc::new(NoopUnresolvedRuleHosts),
            ipv6_disposition: Arc::new(|| Some(crate::enforcement_planner::Ipv6Guard::Off)),
            enforced_view: Arc::new(crate::dns_resolver::NoEnforcement),
            upstream_dns: Arc::new(crate::dns_upstream::UpstreamDnsPool::fixed(upstream_dns)),
            deadline,
            forward_timeout,
            response_ttl: RESPONSE_TTL_SECS,
            last_panic_log: Mutex::new(None),
            tcp_active: AtomicUsize::new(0),
        }
    }

    /// The pool the forward path reads; the resolver service watches it for
    /// "nothing answers".
    pub(crate) fn upstream_pool(&self) -> &Arc<crate::dns_upstream::UpstreamDnsPool> {
        &self.upstream_dns
    }

    /// Forward through a self-healing pool instead of the fixed address passed
    /// to [`Self::new`]. Production always wires this; the fixed address stays
    /// the shape tests use.
    pub fn with_upstream_pool(mut self, pool: Arc<crate::dns_upstream::UpstreamDnsPool>) -> Self {
        self.upstream_dns = pool;
        self
    }

    /// Read the live leak-guard posture, so a rule-host answer whose enforcement
    /// did not install in time is withheld rather than leaked to the main link.
    /// Supply what the installed policy actually carries, so the answer gate
    /// can tell an enforced address from one the FQDN cache merely remembers.
    /// Default: [`crate::dns_resolver::NoEnforcement`].
    pub fn with_enforced_view(
        mut self,
        view: Arc<dyn crate::dns_resolver::EnforcedAddressView>,
    ) -> Self {
        self.enforced_view = view;
        self
    }

    pub fn with_leak_guard_posture(
        mut self,
        posture: Arc<dyn crate::dns_resolver::LeakGuardPosture>,
    ) -> Self {
        self.leak_guard = posture;
        self
    }

    /// Report every rule host this listener could not give an address, so the
    /// outage list can name a site that failed before any connection.
    pub fn with_unresolved_observer(
        mut self,
        observer: Arc<dyn UnresolvedRuleHostObserver>,
    ) -> Self {
        self.unresolved = observer;
        self
    }

    /// Read the routing principal's IPv6 disposition: a rule host's AAAA is
    /// routed when the tunnel carries the family, withheld when only the main
    /// link does.
    pub fn with_ipv6_disposition(mut self, disposition: Ipv6DispositionFn) -> Self {
        self.ipv6_disposition = disposition;
        self
    }

    /// enable direct-answer steering: replies to
    /// non-rule `A` queries are filtered against this secondary-owned set.
    pub fn with_direct_answer_steering(mut self, owned: Arc<dyn SecondaryOwnedIps>) -> Self {
        self.secondary_owned = owned;
        self
    }

    /// Fake-IP — answer in-scope rule hosts with virtual
    /// addresses so the flow is caught by the TUN and steered by the relay.
    pub fn with_fake_ip(mut self, fake_ip: Arc<dyn FakeIpAnswerer>) -> Self {
        self.fake_ip = fake_ip;
        self
    }

    /// Collateral rescue — answer a DIRECT host with a virtual address when its
    /// steered reply is still fully secondary-pinned (every address it resolves
    /// to is committed to the secondary link). Consulted only on that degraded
    /// path; the answerer should arm on "fake-IP stack running" alone, so the
    /// rescue works with or without the block-all.
    pub fn with_collateral_fake_ip(mut self, fake: Arc<dyn DirectFakeIpAnswerer>) -> Self {
        self.collateral_fake = fake;
        self
    }

    /// Source of "this direct host is already a parked suggestion for the
    /// additional link", which vetoes the collateral rescue for it.
    pub fn with_companion_candidates(mut self, lookup: Arc<dyn CompanionCandidateLookup>) -> Self {
        self.companion_candidates = lookup;
        self
    }

    /// Sink for "the rescue just carried this host on the primary" — the only
    /// place a shared-address companion can be reported under its own name.
    pub fn with_companion_rescue_observer(
        mut self,
        observer: Arc<dyn CompanionRescueObserver>,
    ) -> Self {
        self.companion_rescue = observer;
        self
    }

    /// Wire the machine's private resolvers so a "no such name" from one
    /// server is re-asked of the resolvers that could hold an internal
    /// namespace. Without it the listener keeps its single-server behaviour.
    #[must_use]
    pub fn with_private_resolvers(mut self, servers: PrivateResolversFn) -> Self {
        self.private_resolvers = Some(servers);
        self
    }

    /// Wire the namespaces connections claim, so a single-label name can be
    /// completed the way the OS would have completed it. Crate-private: the
    /// resolver service hands its own snapshot down, so no factory can wire
    /// one and forget the other.
    #[must_use]
    pub(crate) fn with_claimed_namespaces(
        mut self,
        namespaces: crate::dns_resolver_service::ClaimsSnapshot,
    ) -> Self {
        self.claimed_namespaces = Some(namespaces);
        self
    }

    /// Complete short names with a domain the user named, asked of the
    /// machine's private resolvers first and the upstream last.
    #[must_use]
    pub fn with_short_name_suffix(mut self, suffix: ShortNameSuffixFn) -> Self {
        self.short_name_suffix = Some(suffix);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_resolver_port(mut self, port: u16) -> Self {
        self.resolver_port = port;
        self
    }

    #[cfg(test)]
    pub(crate) fn completes_short_names(&self) -> bool {
        self.claimed_namespaces.is_some()
    }

    /// Answer a single-label name by completing it with a claimed namespace,
    /// then with the domain the user named.
    ///
    /// The OS completes a bare label with the connection's own DNS suffix;
    /// loopback carries none, so pointing every name at us took that away.
    /// The reply is rebuilt against the ORIGINAL question — a client discards
    /// an answer about a different name — and the completion is remembered so
    /// an offer can name the full host. Only address questions are completed,
    /// each probed with its own type: an answer of another type would be
    /// cached by the client as a positive it never asked for.
    pub(crate) fn complete_single_label(
        &self,
        query: &[u8],
        label: &str,
        budget: Duration,
    ) -> Option<Vec<u8>> {
        let qtype = parse_question(query)?.qtype;
        if qtype != QTYPE_A && qtype != QTYPE_AAAA {
            return None;
        }
        // Before the server list: waiting for it spends this answer's budget.
        let started = Instant::now();
        let mut attempts: Vec<(String, Vec<SocketAddr>)> = self
            .claimed_namespaces
            .as_ref()
            .map(|claims| {
                claims
                    .current()
                    .iter()
                    .map(|claim| {
                        let servers = claim
                            .servers
                            .iter()
                            .map(|s| SocketAddr::from((*s, self.resolver_port)))
                            .collect();
                        (claim.suffix.clone(), servers)
                    })
                    .collect()
            })
            .unwrap_or_default();
        // A domain the user named has no servers of its own. Private resolvers
        // go first: such a domain is usually internal, and on a split-horizon
        // one the public upstream answers with the outside address.
        if let Some(suffix) = self.short_name_suffix.as_ref().and_then(|named| named()) {
            if !attempts.iter().any(|(claimed, _)| *claimed == suffix) {
                let mut servers: Vec<SocketAddr> = Vec::new();
                if let Some(private) = self.private_resolvers.as_ref() {
                    servers.extend(
                        private(budget.saturating_sub(started.elapsed()))
                            .into_iter()
                            .take(MAX_PRIVATE_RETRIES)
                            .map(|s| SocketAddr::from((s, self.resolver_port))),
                    );
                }
                servers.extend(self.upstream_dns.current());
                attempts.push((suffix, first_occurrences(servers)));
            }
        }
        for (suffix, servers) in attempts {
            let left = budget.saturating_sub(started.elapsed());
            if left.is_zero() {
                break;
            }
            let full = format!("{label}.{suffix}");
            let id = crate::dns_resolver_ports::next_query_id();
            let Some(probe) = crate::dns_wire::build_address_query(id, &full, qtype) else {
                continue;
            };
            for target in servers {
                let left = budget.saturating_sub(started.elapsed());
                if left.is_zero() {
                    break;
                }
                let Some(reply) = self.forward_to(&probe, target, self.forward_timeout.min(left))
                else {
                    continue;
                };
                if let crate::dns_wire::AddressResponseOutcome::Answers { addresses, min_ttl } =
                    crate::dns_wire::parse_address_response(id, &full, qtype, &reply)
                {
                    if addresses.is_empty() {
                        continue;
                    }
                    tracing::info!(
                        target: "nrr::dns-resolver",
                        msg_key = "dns-listener-short-name-completed",
                        label = %label,
                        completed = %full,
                        server = %target,
                        "completed a short name with its network domain",
                    );
                    crate::short_name_completions::global_short_name_completions()
                        .record(label, &full);
                    let ttl = min_ttl.max(1);
                    if qtype == QTYPE_AAAA {
                        let v6: Vec<std::net::Ipv6Addr> = addresses
                            .iter()
                            .filter_map(|a| match a {
                                std::net::IpAddr::V6(v6) => Some(*v6),
                                std::net::IpAddr::V4(_) => None,
                            })
                            .collect();
                        return crate::dns_wire::build_aaaa_response(query, &v6, ttl);
                    }
                    return build_a_response(query, &only_v4(&addresses), ttl);
                }
            }
        }
        None
    }

    /// Decide what to do with one raw query datagram — pure, no I/O, so the
    /// intercept-vs-forward policy is unit-tested independently of sockets.
    ///
    /// Intercepts ONLY `A` queries whose name is a rule host; for those it runs
    /// the enforce-before-answer handler and builds the response from the
    /// resolved IPs. Anything else (including a rule host our own resolver could
    /// not reach) is forwarded raw — general DNS never depends on us succeeding.
    /// Bound on remembered names. Past it the warning repeats rather than
    /// the set growing — a noisy log is recoverable, unbounded memory in the
    /// service is not.
    const AAAA_REPORT_MEMORY: usize = 256;

    fn report_aaaa_outside_policy(&self, qname: &str) {
        {
            let mut seen = self
                .aaaa_outside_policy_reported
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if !seen.insert(qname.to_string()) {
                return;
            }
            if seen.len() > Self::AAAA_REPORT_MEMORY {
                seen.clear();
            }
        }
        tracing::warn!(
            target: "nrr::dns",
            msg_key = "dns-listener-rule-host-ipv6-uncovered",
            host = %qname,
            "a rule host was asked for over IPv6 and IPv4 cannot carry it — its \
             v6 traffic leaves outside the rule",
        );
    }

    /// AAAA for a rule host, by what the routing principal's links carry.
    ///
    /// The tunnel carries IPv6: the host's v6 is routed like its v4. Only the
    /// main link does: NODATA, so the client uses the family the tunnel
    /// carries. Nothing carries it: forwarded untouched — suppressing it would
    /// make a v6-only destination unreachable for no protection at all. No
    /// plan yet: NODATA, briefly cached.
    ///
    /// The fake-IP probe is [`FakeIpAnswerer::carries_on_v4`], never
    /// `fake_answer`: the latter allocates a lease and records health.
    fn aaaa_action(
        &self,
        query: &[u8],
        qname: &str,
        lane_wait: Duration,
        budget: Duration,
    ) -> ListenerAction {
        use crate::enforcement_planner::Ipv6Guard;
        if !self.oracle.is_rule_host(qname) {
            return ListenerAction::Forward; // not a name any rule claims
        }
        let nodata = || {
            build_negative_response(query, RCODE_NOERROR, self.response_ttl)
                .map_or(ListenerAction::Forward, ListenerAction::Respond)
        };
        // A virtual address carries the host on IPv4 and the relay routes it;
        // a real v6 answer would go around both.
        if self.fake_ip.carries_on_v4(qname) {
            return nodata();
        }
        match (self.ipv6_disposition)() {
            // No plan yet (boot, sign-in): nothing routes the host's v6 or pins
            // it, so a forwarded answer opens the first connection on the main
            // link. Its IPv4 is answered and routed meanwhile.
            None => build_negative_response(query, RCODE_NOERROR, UNPLANNED_AAAA_TTL_SECS)
                .map_or(ListenerAction::Forward, ListenerAction::Respond),
            Some(Ipv6Guard::FiltersAndRoutes) => self.route_aaaa(query, qname, lane_wait, budget),
            // The tunnel cannot carry the family, so the host's v6 addresses
            // are pinned to it and blocked. Handing one out would only make the
            // client wait on it; its IPv4 rides the tunnel.
            Some(Ipv6Guard::FiltersOnly) => nodata(),
            // Nothing pins the family and the tunnel is gone: a forward asks
            // the main link for the name, and its CNAME chain hands the A
            // lookup a target no rule names.
            Some(Ipv6Guard::Off) if self.leak_guard.blocking_for_host(qname) => {
                self.withheld(query)
            }
            Some(Ipv6Guard::Off) => {
                // A hole, not a routine forward: the user wrote a rule for
                // this host and its IPv6 traffic is about to ignore it. Said
                // once per name — silence is what makes "the rule did not
                // work" undiagnosable.
                self.report_aaaa_outside_policy(qname);
                ListenerAction::Forward
            }
        }
    }

    /// The tunnel carries IPv6: resolve, enforce, then answer.
    /// A slot in the enforce-before-answer path, or `None` when the wait ran
    /// out. Saturation is worth a line — it means name resolution is degraded
    /// for everything this listener serves, not just for the host that asked.
    fn enter_rule_host_lane(&self, wait: Duration) -> Option<RuleHostLanePermit<'_>> {
        match self.rule_host_lane.enter(wait) {
            Some(permit) => {
                if self.rule_lane_saturated.swap(false, Ordering::Relaxed) {
                    tracing::info!(
                        target: "nrr::dns-resolver",
                        msg_key = "dns-listener-modeb-resolves-caught-up",
                        "Mode B: rule-host resolves are keeping up again — answering from the upstream as usual",
                    );
                }
                Some(permit)
            }
            None => {
                if !self.rule_lane_saturated.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        target: "nrr::dns-resolver",
                        msg_key = "dns-listener-modeb-resolve-slots-saturated",
                        concurrent = MAX_CONCURRENT_RULE_HOST_RESOLVES,
                        "Mode B: every rule-host resolve slot is taken by an upstream that is not answering — serving rule hosts from the cache so the rest of the machine's DNS keeps working",
                    );
                }
                None
            }
        }
    }

    /// Answer a rule host without going upstream. The addresses the cache holds
    /// are the ones enforcement was built from, so handing them back is the
    /// same answer the slow path would most likely produce — and the
    /// kill-switch still decides what may leave. Nothing cached: SERVFAIL, so
    /// the client re-asks in a moment rather than waiting out its own timeout.
    fn rule_host_answer_without_upstream(&self, query: &[u8], qname: &str) -> ListenerAction {
        // While the guard holds, an address the census spared would carry the
        // connection over the main link: withhold, as the slow path does.
        let cached = if self.leak_guard.blocking_for_host(qname) {
            Vec::new()
        } else {
            self.sink.cached_routable_ips(qname)
        };
        if cached.is_empty() {
            self.unresolved.note_unresolved(qname);
            return build_error_response(query, RCODE_SERVFAIL)
                .map_or(ListenerAction::Drop, ListenerAction::Respond);
        }
        let answered: Vec<Ipv4Addr> = cached
            .into_iter()
            .take(crate::dns_resolver::MAX_RULE_ANSWER_IPS)
            .collect();
        tracing::debug!(
            target: "nrr::dns-resolver",
            host = %qname,
            addresses = ?answered,
            "Mode B: rule-host lane saturated — answered from the cache, no upstream and no reconcile this round",
        );
        build_a_response(query, &answered, self.response_ttl)
            .map_or(ListenerAction::Forward, ListenerAction::Respond)
    }

    fn withheld(&self, query: &[u8]) -> ListenerAction {
        build_error_response(query, RCODE_SERVFAIL)
            .map_or(ListenerAction::Drop, ListenerAction::Respond)
    }

    fn route_aaaa(
        &self,
        query: &[u8],
        qname: &str,
        lane_wait: Duration,
        budget: Duration,
    ) -> ListenerAction {
        let waited_from = Instant::now();
        let Some(_lane) = self.enter_rule_host_lane(lane_wait) else {
            // NODATA costs nothing and sends the client to the family our rules
            // route anyway, which beats holding a worker for a AAAA.
            return build_negative_response(query, RCODE_NOERROR, self.response_ttl)
                .map_or(ListenerAction::Forward, ListenerAction::Respond);
        };
        let hold = crate::dns_resolver::AnswerHold {
            // What the wait for a slot left of it.
            budget: budget.saturating_sub(waited_from.elapsed()),
            deadline: self.deadline,
            fast_answers: crate::dns_resolver::global_dns_fast_answers()
                .load(std::sync::atomic::Ordering::Relaxed),
        };
        match crate::dns_resolver::handle_aaaa_query(
            qname,
            hold,
            self.upstream.as_ref(),
            self.sink.as_ref(),
            self.reconciler.as_ref(),
            self.leak_guard.as_ref(),
        ) {
            AaaaOutcome::Answer(ips) if !ips.is_empty() => {
                crate::dns_wire::build_aaaa_response(query, &ips, self.response_ttl)
                    .map_or(ListenerAction::Forward, ListenerAction::Respond)
            }
            AaaaOutcome::Answer(_) | AaaaOutcome::Upstream(ResolveError::NoRecords) => {
                build_negative_response(query, RCODE_NOERROR, self.response_ttl)
                    .map_or(ListenerAction::Forward, ListenerAction::Respond)
            }
            // Withheld deliberately, as on the A path: forwarding would hand
            // over the very addresses the guard is holding back.
            AaaaOutcome::Withheld => build_error_response(query, RCODE_SERVFAIL)
                .map_or(ListenerAction::Drop, ListenerAction::Respond),
            AaaaOutcome::Upstream(ResolveError::Unavailable(_))
                if self.leak_guard.blocking_for_host(qname) =>
            {
                build_error_response(query, RCODE_SERVFAIL)
                    .map_or(ListenerAction::Drop, ListenerAction::Respond)
            }
            AaaaOutcome::Upstream(ResolveError::Unavailable(_)) => ListenerAction::Forward,
        }
    }

    pub fn answer_query(&self, query: &[u8]) -> ListenerAction {
        let Some(q) = parse_question(query) else {
            return ListenerAction::Forward; // unparseable → transparent proxy
        };
        self.answer_query_within(query, &q, RULE_HOST_LANE_WAIT, QUERY_BUDGET)
    }

    /// `lane_wait` is how long this caller may block for a rule-host slot. A
    /// pool worker can afford the wait; the receive loop, which handles a
    /// datagram itself when the hand-off queue is full, cannot — waiting there
    /// stops the loop from receiving anything at all.
    ///
    /// `budget` is what is left of [`QUERY_BUDGET`] for this datagram. The
    /// enforce-before-answer branch divides it across its stages, so the client
    /// hears back at a moment the listener declares rather than at the sum of
    /// whatever the upstream, the second opinion and the reconcile each took.
    fn answer_query_within(
        &self,
        query: &[u8],
        q: &ParsedQuestion,
        lane_wait: Duration,
        budget: Duration,
    ) -> ListenerAction {
        // answer the Firefox DoH canary with
        // NXDOMAIN for ANY qtype, BEFORE the rule-host gate (the canary is not a
        // rule host, so it would otherwise be forwarded raw and Firefox would keep
        // DoH on). NXDOMAIN makes Firefox fall back to the system resolver, which
        // our observer can see. Mode B is only active while enforcement is armed,
        // so this is correctly scoped to "leak protection engaged".
        if crate::dns_resolver::is_doh_canary(&q.qname) {
            return negative_answer(query).map_or(ListenerAction::Forward, ListenerAction::Respond);
        }
        if q.qtype == QTYPE_AAAA {
            return self.aaaa_action(query, &q.qname, lane_wait, budget);
        }
        if q.qtype != QTYPE_A {
            // An HTTPS record carries address hints; while the guard holds, a
            // rule host's name is not asked of the main link in any type.
            if self.oracle.is_rule_host(&q.qname) && self.leak_guard.blocking_for_host(&q.qname) {
                return self.withheld(query);
            }
            return ListenerAction::Forward;
        }
        let rule_covered = self.oracle.is_rule_host(&q.qname);
        if !rule_covered {
            // Direct host: forward, but steer the reply so the client
            // never receives a secondary-pinned address (shared-CDN collateral).
            return ListenerAction::ForwardFiltered;
        }
        // Admission control before the only unbudgeted wait in this listener:
        // a rule host that cannot get a slot is answered from what we already
        // know, so a resolver that stopped answering cannot take name
        // resolution down for every other name on the machine.
        let waited_from = Instant::now();
        let Some(_lane) = self.enter_rule_host_lane(lane_wait) else {
            return self.rule_host_answer_without_upstream(query, &q.qname);
        };
        match handle_a_query(
            &q.qname,
            crate::dns_resolver::AnswerHold {
                // What the wait for a slot left of it.
                budget: budget.saturating_sub(waited_from.elapsed()),
                deadline: self.deadline,
                // Read per query (not captured at construction) so the settings
                // toggle takes effect live, matching the DNS-over-secondary flag.
                fast_answers: crate::dns_resolver::global_dns_fast_answers()
                    .load(std::sync::atomic::Ordering::Relaxed),
            },
            self.oracle.as_ref(),
            self.upstream.as_ref(),
            self.sink.as_ref(),
            self.reconciler.as_ref(),
            self.fake_ip.as_ref(),
            self.leak_guard.as_ref(),
            self.enforced_view.as_ref(),
        ) {
            QueryOutcome::Answer { ips, .. } => build_a_response(query, &ips, self.response_ttl)
                .map(ListenerAction::Respond)
                // Empty answer set (nothing to route) → NXDOMAIN, else forward.
                .unwrap_or_else(|| {
                    negative_answer(query).map_or(ListenerAction::Forward, ListenerAction::Respond)
                }),
            // Withheld deliberately: SERVFAIL, never a forward. Forwarding here
            // would hand the caller the very addresses the guard is holding
            // back, over the OS's own resolver.
            QueryOutcome::Withheld => {
                self.unresolved.note_unresolved(&q.qname);
                build_error_response(query, RCODE_SERVFAIL)
                    .map_or(ListenerAction::Drop, ListenerAction::Respond)
            }
            QueryOutcome::Upstream(ResolveError::NoRecords) => {
                negative_answer(query).map_or(ListenerAction::Forward, ListenerAction::Respond)
            }
            // The guard is blocking: a raw forward would carry this rule host's
            // name over the main link, the very thing it holds back.
            QueryOutcome::Upstream(ResolveError::Unavailable(_))
                if self.leak_guard.blocking_for_host(&q.qname) =>
            {
                self.unresolved.note_unresolved(&q.qname);
                build_error_response(query, RCODE_SERVFAIL)
                    .map_or(ListenerAction::Drop, ListenerAction::Respond)
            }
            // Our resolver could not reach upstream — fail open by forwarding the
            // raw query (the OS's configured server may still answer). No
            // enforcement installed this round, but general DNS keeps working.
            QueryOutcome::Upstream(ResolveError::Unavailable(reason)) => {
                tracing::debug!(
                    target: "nrr::dns-resolver",
                    host = %q.qname,
                    reason = %reason,
                    "Mode B: rule host upstream unavailable — forwarding raw query (fail-open, no enforcement this round)",
                );
                ListenerAction::Forward
            }
        }
    }

    /// Blocking serve loop over `socket`. Returns when `stop` is set. Datagrams
    /// are handed to a worker pool; a per-datagram failure — a panic included —
    /// costs that datagram and nothing else.
    pub fn serve_udp(&self, socket: &UdpSocket, stop: &AtomicBool) -> std::io::Result<()> {
        self.serve_observed(socket, None, stop, &|| {}, &|| {})
    }

    /// [`Self::serve_udp`] calling `beat` once per receive, timeout included,
    /// so a watcher can tell a stuck loop from an idle one.
    pub fn serve_udp_observed(
        &self,
        socket: &UdpSocket,
        stop: &AtomicBool,
        beat: &dyn Fn(),
    ) -> std::io::Result<()> {
        self.serve_observed(socket, None, stop, beat, &|| {})
    }

    /// The full serve loop: UDP on `socket`, DNS over TCP on `tcp` when given
    /// (the OS retries a truncated answer there), `beat` once per receive, and
    /// `on_stop` the moment the receive loop ends — BEFORE the workers are
    /// joined, so whatever must happen at stop (restoring the system's DNS)
    /// does not wait for queued datagrams.
    ///
    /// The loop itself does no per-datagram work beyond admission: handling a
    /// datagram inline serialized the whole machine's DNS behind one slow
    /// answer, and even a wait for a rule-host slot there was a wait for every
    /// client at once. A datagram the pool cannot take right now, or one past
    /// its source's share, is answered SERVFAIL on the spot: the client re-asks
    /// in a moment, and the kernel's receive buffer never fills up with
    /// everybody else's queries behind one program's flood.
    pub fn serve_observed(
        &self,
        socket: &UdpSocket,
        tcp: Option<&TcpListener>,
        stop: &AtomicBool,
        beat: &dyn Fn(),
        on_stop: &dyn Fn(),
    ) -> std::io::Result<()> {
        // A read timeout lets the loop observe `stop` promptly instead of
        // blocking forever in `recv_from`.
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        let (tx, rx) = std::sync::mpsc::sync_channel::<(Vec<u8>, SocketAddr)>(SERVE_QUEUE_DEPTH);
        let rx = Mutex::new(rx);
        let buffers = QueryBuffers::default();
        let ended = AtomicBool::new(false);
        let signal = StopSignal {
            stop,
            ended: &ended,
        };
        std::thread::scope(|scope| {
            for _ in 0..SERVE_WORKER_THREADS {
                scope.spawn(|| loop {
                    // Hold the receiver lock only across the dequeue: one idle
                    // worker waits in `recv`, the rest park on the mutex; a
                    // dequeued datagram is processed with the lock released.
                    let msg = {
                        let guard = rx.lock().unwrap_or_else(|p| p.into_inner());
                        guard.recv()
                    };
                    match msg {
                        // Stopping: the system's DNS is restored already and
                        // nobody is waiting on us; the queue is thrown away.
                        Ok(_) if signal.is_set() => continue,
                        Ok((query, src)) => {
                            self.handle_datagram_contained(socket, &query, src);
                            buffers.give_back(query);
                        }
                        // Sender dropped — the serve loop exited; drain is done.
                        Err(_) => return,
                    }
                });
            }
            if let Some(tcp) = tcp {
                scope.spawn(move || self.accept_tcp(tcp, signal, scope));
            }
            // However the receive loop ends, a panic included, the stop hook
            // runs before the scope joins anything, and the TCP side is told
            // to quit: it would otherwise wait for a `stop` that never comes.
            let end = ServeEnd {
                ended: &ended,
                on_stop,
            };
            let mut buf = [0u8; DNS_DATAGRAM_BUFFER_BYTES];
            let mut consecutive_errors = 0u32;
            let mut last_noise_log: Option<Instant> = None;
            let mut sources = SourceLimiter::default();
            let mut shed = ShedLog::default();
            let result = loop {
                if stop.load(Ordering::Relaxed) {
                    break Ok(());
                }
                beat();
                let (n, src) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e) => match classify_recv_error(&e) {
                        RecvErrorClass::Idle => continue,
                        // Neither counts toward the streak nor resets it.
                        RecvErrorClass::PerDatagram => {
                            if last_noise_log
                                .is_none_or(|at| at.elapsed() >= RECV_NOISE_LOG_INTERVAL)
                            {
                                last_noise_log = Some(Instant::now());
                                tracing::debug!(
                                    target: "nrr::dns_resolver",
                                    error = %e,
                                    "Mode B: skipped a per-datagram receive error — continuing to serve",
                                );
                            }
                            continue;
                        }
                        // Keep serving through a few: a dead socket fails
                        // every time, one odd packet does not.
                        RecvErrorClass::Unrecognised => {
                            consecutive_errors += 1;
                            if consecutive_errors >= DNS_RECV_ERROR_TOLERANCE {
                                break Err(e);
                            }
                            tracing::warn!(
                                target: "nrr::dns_resolver",
                                msg_key = "dns-listener-modeb-unrecognised-recv-error",
                                error = %e,
                                consecutive_errors,
                                "Mode B: unrecognised receive error; continuing to serve",
                            );
                            continue;
                        }
                    },
                };
                consecutive_errors = 0;
                if !sources.admit(src, Instant::now()) {
                    shed.note(ShedReason::SourceShare, src);
                    self.answer_servfail(socket, &buf[..n], src);
                    continue;
                }
                match tx.try_send((buffers.filled(&buf[..n]), src)) {
                    Ok(()) => {}
                    Err(TrySendError::Full((query, src))) => {
                        shed.note(ShedReason::QueueFull, src);
                        self.answer_servfail(socket, &query, src);
                        buffers.give_back(query);
                    }
                    // Unreachable while workers live inside this scope; treat
                    // as shutdown just in case.
                    Err(TrySendError::Disconnected(_)) => break Ok(()),
                }
            };
            drop(end);
            drop(tx); // disconnect → workers drain the queue and exit
            result
        })
    }

    /// One datagram, with its failure contained: a panic in the handler costs
    /// this query a SERVFAIL and the worker nothing.
    fn handle_datagram_contained(&self, socket: &UdpSocket, query: &[u8], src: SocketAddr) {
        let handled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.handle_datagram(socket, query, src, RULE_HOST_LANE_WAIT)
        }));
        if handled.is_err() {
            self.note_handler_panic(query.len());
            self.answer_servfail(socket, query, src);
        }
    }

    /// Said at most once per interval: any local process can make it happen.
    fn note_handler_panic(&self, bytes: usize) {
        let mut last = self
            .last_panic_log
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if last.is_some_and(|at| at.elapsed() < RECV_NOISE_LOG_INTERVAL) {
            return;
        }
        *last = Some(Instant::now());
        tracing::error!(
            target: "nrr::dns-resolver",
            msg_key = "dns-listener-handler-panicked",
            bytes,
            "Mode B: handling one DNS query panicked — the query was failed and the listener goes on serving",
        );
    }

    /// Accept DNS-over-TCP connections until serving ends. Each connection is
    /// one scoped thread, at most [`TCP_MAX_CONNECTIONS`] at a time; anything
    /// past that is closed unread. Polling with a short sleep keeps the signal
    /// honoured: `accept` has no timeout of its own.
    fn accept_tcp<'scope, 'env: 'scope>(
        &'scope self,
        tcp: &'scope TcpListener,
        signal: StopSignal<'scope>,
        scope: &'scope std::thread::Scope<'scope, 'env>,
    ) {
        if tcp.set_nonblocking(true).is_err() {
            return;
        }
        let active = &self.tcp_active;
        while !signal.is_set() {
            let stream = match tcp.accept() {
                Ok((stream, _)) => stream,
                Err(_) => {
                    // Nothing pending, or one bad accept: neither ends serving.
                    std::thread::sleep(TCP_ACCEPT_POLL);
                    continue;
                }
            };
            if active.fetch_add(1, Ordering::AcqRel) >= TCP_MAX_CONNECTIONS {
                active.fetch_sub(1, Ordering::AcqRel);
                drop(stream);
                continue;
            }
            scope.spawn(move || {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.serve_tcp_connection(stream, signal);
                }));
                active.fetch_sub(1, Ordering::AcqRel);
            });
        }
    }

    /// One client connection: a few framed queries, each answered through the
    /// same path as a datagram, with the upstream asked over TCP so a large
    /// answer comes back whole. Bounded in idle time, lifetime, query size and
    /// query count; the peer shapes every byte read here.
    fn serve_tcp_connection(&self, mut stream: TcpStream, signal: StopSignal<'_>) {
        use crate::dns_wire::{read_tcp_message, write_tcp_message};
        if stream.set_nonblocking(false).is_err() {
            return;
        }
        let _ = stream.set_nodelay(true);
        let opened = Instant::now();
        let mut stream =
            DeadlineStream::new(&mut stream, TCP_CONNECTION_LIFETIME, TCP_IDLE_TIMEOUT);
        for _ in 0..TCP_MAX_QUERIES_PER_CONNECTION {
            if signal.is_set() || opened.elapsed() >= TCP_CONNECTION_LIFETIME {
                return;
            }
            let Ok(Some(query)) = read_tcp_message(&mut stream, TCP_MAX_QUERY_BYTES) else {
                return;
            };
            let reply = self
                .answer_bytes(&query, Transport::Tcp)
                .or_else(|| build_error_response(&query, RCODE_SERVFAIL));
            let Some(reply) = reply else {
                return;
            };
            if write_tcp_message(&mut stream, &reply).is_err() {
                return;
            }
        }
    }

    /// Fully process one query datagram and send its response (if any) back to
    /// `src` over the shared listener socket. Runs on a pool worker —
    /// everything here may block for its own bounded budgets without stalling
    /// other queries.
    fn handle_datagram(
        &self,
        socket: &UdpSocket,
        query: &[u8],
        src: SocketAddr,
        lane_wait: Duration,
    ) {
        if let Some(reply) = self.answer_bytes_within(query, Transport::Udp, lane_wait) {
            let _ = socket.send_to(&reply, src);
        }
    }

    /// The bytes one query is answered with, whatever transport it came on.
    /// `None` only where silence is the deliberate answer.
    fn answer_bytes(&self, query: &[u8], transport: Transport) -> Option<Vec<u8>> {
        self.answer_bytes_within(query, transport, RULE_HOST_LANE_WAIT)
    }

    fn answer_bytes_within(
        &self,
        query: &[u8],
        transport: Transport,
        lane_wait: Duration,
    ) -> Option<Vec<u8>> {
        crate::dns_resolver_ports::one_query(|| self.answer_one_query(query, transport, lane_wait))
    }

    fn answer_one_query(
        &self,
        query: &[u8],
        transport: Transport,
        lane_wait: Duration,
    ) -> Option<Vec<u8>> {
        let started = Instant::now();
        let left = || QUERY_BUDGET.saturating_sub(started.elapsed());
        // Parsed once: the direct path below reads the question at every step.
        let question = parse_question(query);
        let action = match &question {
            Some(q) => self.answer_query_within(query, q, lane_wait, left()),
            None => ListenerAction::Forward, // unparseable → transparent proxy
        };
        match action {
            ListenerAction::Respond(resp) => Some(resp),
            ListenerAction::Forward => match self.forward_within(query, left(), transport) {
                Some(resp) => Some(resp),
                // Silence costs the client its own timeout on top of ours.
                None => {
                    self.note_failed_rule_host_forward(question.as_ref());
                    build_error_response(query, RCODE_SERVFAIL)
                }
            },
            ListenerAction::Drop => None,
            ListenerAction::ForwardFiltered => {
                // Only a parsed question yields this action.
                let q = question.as_ref()?;
                let Some(resp) = self.forward_within(query, left(), transport) else {
                    return build_error_response(query, RCODE_SERVFAIL);
                };
                Some(self.answer_direct(query, q, resp, left()))
            }
        }
    }

    /// What a DIRECT host's client hears, given the upstream's reply to its
    /// `A` question. `budget` pays for the one re-query steering may make.
    fn answer_direct(
        &self,
        query: &[u8],
        q: &ParsedQuestion,
        upstream_reply: Vec<u8>,
        budget: Duration,
    ) -> Vec<u8> {
        // One parse of the upstream answer; every step below reads its addresses.
        let answers = direct_answers(query, q, &upstream_reply);
        let (steered, answers, still_pinned) =
            self.steer_parsed(query, q, upstream_reply, answers, budget);
        let answers = answers.as_deref();
        // Collateral rescue — steering could not produce a clean
        // answer (every address is committed to the secondary
        // link). With the fake-IP stack live, a virtual address
        // routes the host by NAME out the primary; the old
        // fail-open answer sent it out the VPN link instead
        // (geo captcha / kill-switch block).
        if still_pinned {
            // Reported here, not inside the rescue, so the evidence
            // is the same with or without the fake-IP stack.
            self.note_collateral_host(q);
            if !self.companion_is_pending(q) {
                if let Some(fake) = self.fake_collateral_from(query, q, answers) {
                    return fake;
                }
            }
        }
        steered
    }

    /// steer one upstream reply for a DIRECT
    /// (non-rule) host: drop `A` records the kill-switch pins to the secondary
    /// (by host, literal or network) so the client connects via addresses that
    /// stay on the primary/default path. A CDN front-end's answers rotate over a large pool, so filtering
    /// usually leaves usable addresses; when the whole answer is pinned, ONE
    /// upstream re-query is tried (a fresh answer usually rotates), and if
    /// that is also fully pinned the ORIGINAL reply is returned unchanged —
    /// fail-open; the smart kill-switch is the safety net that keeps
    /// such a host reachable. Every degraded path returns a valid reply.
    ///
    /// The second element is `true` ONLY on that terminal fail-open path —
    /// "this reply still carries nothing but secondary-pinned addresses" — so
    /// the caller can offer the host to the collateral fake-IP rescue instead
    /// of relaying an answer that egresses the wrong link.
    #[cfg(test)]
    fn steer_direct_answer(
        &self,
        query: &[u8],
        q: &ParsedQuestion,
        reply: Vec<u8>,
        budget: Duration,
    ) -> (Vec<u8>, bool) {
        let answers = direct_answers(query, q, &reply);
        let (reply, _, still_pinned) = self.steer_parsed(query, q, reply, answers, budget);
        (reply, still_pinned)
    }

    /// The steering above over an answer already parsed into
    /// `answers`; hands back the addresses of the reply it returns, so the
    /// fake-IP and gate steps never parse it again.
    fn steer_parsed(
        &self,
        query: &[u8],
        q: &ParsedQuestion,
        reply: Vec<u8>,
        answers: Option<Vec<IpAddr>>,
        budget: Duration,
    ) -> (Vec<u8>, Option<Vec<IpAddr>>, bool) {
        // NXDOMAIN / error / truncated / mismatch → relay as-is
        let Some(addresses) = answers else {
            return (reply, None, false);
        };
        let owned = self.secondary_owned.secondary_owned_ips();
        if owned.is_empty() {
            return (reply, Some(addresses), false);
        }
        let answered = only_v4(&addresses);
        let clean: Vec<Ipv4Addr> = answered
            .iter()
            .copied()
            .filter(|ip| !owned.contains(ip))
            .collect();
        if clean.len() == answered.len() {
            return (reply, Some(addresses), false); // nothing shared → untouched upstream answer
        }
        if !clean.is_empty() {
            tracing::debug!(
                target: "nrr::dns-resolver",
                host = %q.qname,
                dropped = answered.len() - clean.len(),
                kept = clean.len(),
                "Mode B: steered a direct-host answer away from secondary-pinned addresses",
            );
            return match build_a_response(query, &clean, self.response_ttl) {
                Some(rebuilt) => (rebuilt, Some(v4_addresses(&clean)), false),
                None => (reply, Some(addresses), false),
            };
        }
        // Every address lies in a network the user routes over the additional
        // link: the rule asked for this host, so there is no co-tenant to
        // rescue and no re-query worth its round trip.
        if answered.iter().all(|ip| owned.owned_by_network_only(ip)) {
            return (reply, Some(addresses), false);
        }
        // Whole answer pinned — try ONE fresh upstream answer (pools rotate).
        if let Some(retry) = self.forward_within(query, budget, Transport::Udp) {
            if let Some(retried) = direct_answers(query, q, &retry) {
                let clean: Vec<Ipv4Addr> = only_v4(&retried)
                    .into_iter()
                    .filter(|ip| !owned.contains(ip))
                    .collect();
                if !clean.is_empty() {
                    tracing::debug!(
                        target: "nrr::dns-resolver",
                        host = %q.qname,
                        kept = clean.len(),
                        "Mode B: direct-host answer fully pinned — re-query yielded clean addresses",
                    );
                    return match build_a_response(query, &clean, self.response_ttl) {
                        Some(rebuilt) => (rebuilt, Some(v4_addresses(&clean)), false),
                        None => (reply, Some(addresses), false),
                    };
                }
            }
        }
        tracing::debug!(
            target: "nrr::dns-resolver",
            host = %q.qname,
            "Mode B: direct-host answer fully secondary-pinned even after re-query — relaying unchanged (fail-open; smart kill-switch covers)",
        );
        (reply, Some(addresses), true)
    }

    /// Collateral rescue — answer a DIRECT host whose reply is still fully
    /// secondary-pinned with a virtual address, so the relay routes it by NAME
    /// out the primary. Reached only from the terminal fail-open steering path;
    /// `None` (stack down / exclusion / pool full / parse failure) keeps the
    /// old fail-open behaviour byte-for-byte.
    /// Is this query's host a suggestion already waiting for the user?
    ///
    /// Then it is not collateral: it keeps turning up as part of a site the
    /// user routes over the additional link, and steering it onto the primary
    /// breaks that site — the shape of "I added the CDN and the page still does
    /// not load". Leaving it pinned sends it where accepting the suggestion
    /// would have sent it anyway.
    /// Report a host whose whole answer belongs to the additional route. The
    /// name comes from the question — that is the point.
    fn note_collateral_host(&self, q: &ParsedQuestion) {
        self.companion_rescue.note_rescued_companion(&q.qname);
    }

    fn companion_is_pending(&self, q: &ParsedQuestion) -> bool {
        if !self
            .companion_candidates
            .is_pending_secondary_companion(&q.qname)
        {
            return false;
        }
        tracing::info!(
            target: "nrr::dns-resolver",
            msg_key = "dns-listener-direct-host-parked-suggestion",
            host = %q.qname,
            "direct host is a parked suggestion for the additional route — left on it instead of being steered onto the primary",
        );
        true
    }

    #[cfg(test)]
    fn fake_collateral_response(
        &self,
        query: &[u8],
        q: &ParsedQuestion,
        reply: &[u8],
    ) -> Option<Vec<u8>> {
        let answers = direct_answers(query, q, reply);
        self.fake_collateral_from(query, q, answers.as_deref())
    }

    fn fake_collateral_from(
        &self,
        query: &[u8],
        q: &ParsedQuestion,
        answers: Option<&[IpAddr]>,
    ) -> Option<Vec<u8>> {
        let addresses = answers.filter(|a| !a.is_empty())?;
        let fake = self
            .collateral_fake
            .fake_direct_answer(&q.qname, &only_v4(addresses))?;
        let resp = build_a_response(query, &fake, self.response_ttl)?;
        tracing::info!(
            target: "nrr::dns-resolver",
            msg_key = "dns-listener-modeb-direct-host-shared-address",
            host = %q.qname,
            fake = ?fake,
            real = ?addresses,
            "Mode B: direct host shares every address with a secondary rule — answered with a virtual address so it stays on the primary link",
        );
        Some(resp)
    }

    /// Forward `query` to the upstream DNS server over a fresh ephemeral UDP
    /// socket and return the raw reply. `None` on any I/O error / timeout (the
    /// caller drops the datagram — a lost forward is a client retry, never a
    /// listener stall).
    ///
    /// A failure is reported to the pool, and when that retires the server the
    /// query is retried once against the replacement: every name on the machine
    /// comes through here, so waiting for the client's own timeout to expose a
    /// dead upstream would read as "the internet is down".
    /// Forward within what is left of this datagram's budget. The rotation
    /// retry only runs if the budget can still pay for it — an answer nobody is
    /// waiting for is worth less than the client's own retry.
    fn forward_within(
        &self,
        query: &[u8],
        budget: Duration,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        let started = Instant::now();
        let left = || budget.saturating_sub(started.elapsed());
        if left().is_zero() {
            return None;
        }
        let upstream = self.upstream_dns.current()?;
        let forward = |target: SocketAddr, window: Duration| match transport {
            Transport::Udp => self.forward_to(query, target, window),
            Transport::Tcp => self.forward_tcp_to(query, target, window),
        };
        if let Some(reply) = forward(upstream, self.forward_timeout.min(left())) {
            self.upstream_dns.note_success();
            // "No such name" from ONE server is not "no such name". The
            // machine may hold a resolver for a namespace the public
            // internet never heard of, and Windows would have asked it —
            // that is what asking every interface's server means. Pointing
            // the whole system at us took that away, and a corporate host
            // or a machine on the LAN stopped resolving.
            if reply_is_nxdomain(&reply) {
                // A name with no dot was never going to be found by a
                // resolver that answers for the public internet. Complete it
                // first — that is the step the OS lost when every name was
                // pointed at loopback — and only then ask around.
                if let Some(label) = single_label_of(query) {
                    if let Some(done) = self.complete_single_label(query, &label, left()) {
                        return Some(done);
                    }
                }
                if let Some(better) = self.ask_private_resolvers(query, upstream, left()) {
                    return Some(better);
                }
                // Nobody we can ask knows it. "No such name" would be a
                // claim about the whole of DNS, and for a bare label we are
                // not the one who gets to make it: the OS still has ways of
                // its own — the multicast and broadcast lookups that find a
                // machine on the local link, which never touch a DNS server.
                // Saying "I cannot answer" hands the question back intact,
                // and unlike a non-existence it is not remembered as a fact.
                if single_label_of(query).is_some() {
                    if let Some(servfail) = build_error_response(query, RCODE_SERVFAIL) {
                        return Some(servfail);
                    }
                }
            }
            return Some(reply);
        }
        if left().is_zero() {
            return None;
        }
        // Rotation probes the candidates, which costs time of its own.
        let replacement = self.upstream_dns.note_failure()?;
        let window = self.forward_timeout.min(left());
        if window.is_zero() {
            return None;
        }
        let reply = forward(replacement, window)?;
        self.upstream_dns.note_success();
        Some(reply)
    }

    /// Re-ask the machine's PRIVATE resolvers for a name one server called
    /// non-existent. `None` when nobody had a better answer.
    ///
    /// Private only: a public resolver answers from the same global data as
    /// the one already asked, so re-asking buys latency and no knowledge. A
    /// resolver on a private address is the one that can hold an internal
    /// namespace — a corporate domain, or the names of machines on the LAN.
    ///
    /// Costs nothing on the answered path: this runs only for names that
    /// already came back as non-existent.
    fn ask_private_resolvers(
        &self,
        query: &[u8],
        already_asked: SocketAddr,
        budget: Duration,
    ) -> Option<Vec<u8>> {
        self.ask_private_resolvers_via(already_asked, budget, Instant::now, |target, window| {
            self.forward_to(query, target, window)
        })
    }

    /// [`Self::ask_private_resolvers`] with the clock and the network passed
    /// in, so a test can spend a budget without waiting it out.
    fn ask_private_resolvers_via(
        &self,
        already_asked: SocketAddr,
        budget: Duration,
        now: impl Fn() -> Instant,
        mut ask: impl FnMut(SocketAddr, Duration) -> Option<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        let servers = self.private_resolvers.as_ref()?;
        let started = now();
        let mut tried = 0usize;
        for server in servers(budget) {
            let left = budget.saturating_sub(now().saturating_duration_since(started));
            if left.is_zero() || tried >= MAX_PRIVATE_RETRIES {
                break;
            }
            let target = SocketAddr::from((server, self.resolver_port));
            if target == already_asked {
                continue;
            }
            tried += 1;
            // A mute resolver costs its own window, not the rest of the list.
            let Some(reply) = ask(target, self.forward_timeout.min(left)) else {
                continue;
            };
            if !reply_is_nxdomain(&reply) {
                tracing::info!(
                    target: "nrr::dns-resolver",
                    msg_key = "dns-listener-local-resolver-knows-name",
                    server = %server,
                    "a resolver on this machine knows a name the upstream called non-existent",
                );
                return Some(reply);
            }
        }
        None
    }

    /// A rule host's `A` reaches the raw forward only when our own resolve
    /// could not reach upstream; the forward failing too leaves the client
    /// with no address. Asked after the SERVFAIL went out.
    fn note_failed_rule_host_forward(&self, question: Option<&ParsedQuestion>) {
        if let Some(q) = question.filter(|q| q.qtype == QTYPE_A) {
            if self.oracle.is_rule_host(&q.qname) {
                self.unresolved.note_unresolved(&q.qname);
            }
        }
    }

    /// Tell the client the lookup failed instead of leaving it to time out.
    /// Under an armed block-all the wait is pure loss: the address it is
    /// waiting for would not have connected anyway.
    fn answer_servfail(&self, socket: &UdpSocket, query: &[u8], src: SocketAddr) {
        if let Some(resp) = build_error_response(query, RCODE_SERVFAIL) {
            let _ = socket.send_to(&resp, src);
        }
    }

    /// One send + receive against a named server.
    ///
    /// The socket is CONNECTED, so the kernel drops anything that did not come
    /// from the server we asked, and the datagram is still checked against the
    /// query before it is relayed: this path hands bytes straight back to the
    /// client's stub resolver, so an accepted forgery poisons the OS cache and,
    /// through it, the rule host cache that routes and pins are derived from.
    fn forward_to(&self, query: &[u8], upstream: SocketAddr, window: Duration) -> Option<Vec<u8>> {
        let key = crate::dns_upstream_sockets::UpstreamKey {
            bind: None,
            server: upstream,
        };
        let lease = crate::dns_upstream_sockets::shared()
            .checkout(key, || -> std::io::Result<UdpSocket> {
                let sock = UdpSocket::bind(unspecified_for(upstream))?;
                nrr_platform_api::own_traffic::mark_own_socket(&sock);
                sock.connect(upstream)?;
                Ok(sock)
            })
            .ok()?;
        let sock = lease.socket();
        sock.send(query).ok()?;
        let mut buf = [0u8; DNS_DATAGRAM_BUFFER_BYTES];
        let started = std::time::Instant::now();
        loop {
            let remaining = window.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return None;
            }
            sock.set_read_timeout(Some(remaining)).ok()?;
            let n = sock.recv(&mut buf).ok()?;
            if reply_answers_query(query, &buf[..n]) {
                let reply = buf[..n].to_vec();
                lease.release();
                return Some(reply);
            }
            // A late reply to an earlier query, or noise the kernel could not
            // filter. Keep waiting for ours rather than relaying somebody
            // else's answer.
        }
    }

    /// The same exchange over TCP: one connection, one framed query, one framed
    /// reply, all inside `window`. The reply is bounded by the frame and still
    /// checked against the query — a stream is no more trusted than a datagram.
    fn forward_tcp_to(
        &self,
        query: &[u8],
        upstream: SocketAddr,
        window: Duration,
    ) -> Option<Vec<u8>> {
        use crate::dns_wire::{read_tcp_message, write_tcp_message, DNS_TCP_MAX_MESSAGE};
        let started = Instant::now();
        let mut stream = TcpStream::connect_timeout(&upstream, window).ok()?;
        nrr_platform_api::own_traffic::mark_own_socket(&stream);
        let left = window.saturating_sub(started.elapsed());
        let mut stream = DeadlineStream::new(&mut stream, left, left);
        write_tcp_message(&mut stream, query).ok()?;
        let reply = read_tcp_message(&mut stream, DNS_TCP_MAX_MESSAGE).ok()??;
        reply_answers_query(query, &reply).then_some(reply)
    }
}

/// A stream whose every read and write ends by one deadline, however the peer
/// paces it. A timeout set once bounds each call, not the exchange: a peer
/// sending one byte per timeout held a thread for hours.
struct DeadlineStream<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
    idle: Duration,
}

impl<'a> DeadlineStream<'a> {
    fn new(stream: &'a mut TcpStream, within: Duration, idle: Duration) -> Self {
        Self {
            stream,
            deadline: Instant::now() + within,
            idle,
        }
    }

    /// What is left before the deadline, capped by the idle bound.
    fn window(&self) -> std::io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        Ok(left.min(self.idle))
    }
}

impl std::io::Read for DeadlineStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.window()?))?;
        std::io::Read::read(self.stream, buf)
    }
}

impl std::io::Write for DeadlineStream<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.window()?))?;
        std::io::Write::write(self.stream, buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(self.stream)
    }
}

/// The wildcard address of `target`'s family, so a v6 upstream is reached
/// from a v6 socket.
fn unspecified_for(target: SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

/// Whether `reply` is an answer to `query`: same transaction id, the response
/// bit set, and the same question echoed back.
///
/// Matching on the id alone is not enough — the id is 16 bits and, on this
/// path, sequential.
fn reply_answers_query(query: &[u8], reply: &[u8]) -> bool {
    use crate::dns_wire::question_key;
    if reply.len() < 12 || query.len() < 12 {
        return false;
    }
    if reply[0..2] != query[0..2] {
        return false;
    }
    // QR bit — a query echoed back is not an answer.
    if reply[2] & 0x80 == 0 {
        return false;
    }
    // Compared as raw labels, pointers followed: a question the product would
    // not learn from (an SRV name, say) still has to be echoed, and a server
    // that compresses the echoed name is not thereby excused from echoing it.
    match (question_key(query), question_key(reply)) {
        (Some(q), Some(r)) => q == r,
        // A server answers a query it could not read (FORMERR) with no
        // question section, and only then; anything else without one is
        // somebody else's answer.
        (Some(_), None) => {
            u16::from_be_bytes([reply[4], reply[5]]) == 0 && (reply[3] & 0x0F) != RCODE_NOERROR
        }
        // Our own query has no readable question, so the server cannot echo a
        // readable one: a reply that carries one answers an earlier query of
        // the same id, whatever its rcode, and the id is the client's to repeat.
        (None, Some(_)) => false,
        (None, None) => {
            u16::from_be_bytes([reply[4], reply[5]]) == 0 || (reply[3] & 0x0F) != RCODE_NOERROR
        }
    }
}

/// The bare label of a single-label question, or `None` when the name has a
/// dot (and is therefore already complete) or cannot be parsed.
///
/// A name with no dot cannot be covered by a rule either — rules name
/// domains — so this is exactly the class the product has no business
/// answering for, and exactly the class the OS used to complete for itself.
#[must_use]
fn single_label_of(query: &[u8]) -> Option<String> {
    let q = parse_question(query)?;
    let name = q.qname.trim_end_matches('.');
    (!name.is_empty() && !name.contains('.')).then(|| name.to_ascii_lowercase())
}

/// Does this reply say the name does not exist?
///
/// Read straight off the header's low nibble, which is where the response code
/// lives. A short or malformed buffer is not an answer at all, so it is not a
/// non-existence either.
#[must_use]
fn reply_is_nxdomain(reply: &[u8]) -> bool {
    reply.len() >= 4 && (reply[3] & 0x0F) == RCODE_NXDOMAIN
}

/// One "no such name" answer, carrying the SOA that lets the client remember it.
///
/// Every synthetic NXDOMAIN here goes through this: without the authority
/// record a stub resolver cannot cache the negative answer and re-asks on every
/// lookup — which for the DoH canary means a query per page load.
fn negative_answer(query: &[u8]) -> Option<Vec<u8>> {
    crate::dns_wire::build_negative_response(
        query,
        RCODE_NXDOMAIN,
        crate::dns_wire::NEGATIVE_TTL_SECS,
    )
}

/// `servers` without repeats, in the order given. A resolver list is a handful
/// long, so a linear scan beats hashing.
fn first_occurrences(servers: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut unique = Vec::with_capacity(servers.len());
    for server in servers {
        if !unique.contains(&server) {
            unique.push(server);
        }
    }
    unique
}

/// The addresses of an `A` reply to `q`, or `None` when it is not an answer
/// (NXDOMAIN, error, truncated, another question) and so is relayed as-is.
fn direct_answers(query: &[u8], q: &ParsedQuestion, reply: &[u8]) -> Option<Vec<IpAddr>> {
    let id = u16::from_be_bytes([query[0], query[1]]);
    match parse_address_response(id, &q.qname, QTYPE_A, reply) {
        AddressResponseOutcome::Answers { addresses, .. } => Some(addresses),
        _ => None,
    }
}

/// What parsing a reply built from `v4` would give back.
fn v4_addresses(v4: &[Ipv4Addr]) -> Vec<IpAddr> {
    v4.iter().copied().map(IpAddr::V4).collect()
}

#[cfg(test)]
mod tests;
