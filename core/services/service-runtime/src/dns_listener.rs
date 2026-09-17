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
//! TCP fallback for truncated (`TC=1`) answers is a known gap — classic UDP
//! DNS fits the vast majority of rule-host `A` answers, and the passive
//! observer remains a backstop.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::TrySendError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::dns_resolver::{
    handle_a_query, AaaaOutcome, CompanionCandidateLookup, CompanionRescueObserver,
    DirectAnswerGate, DirectFakeIpAnswerer, FactSink, FakeIpAnswerer, NoopCompanionCandidates,
    NoopCompanionRescue, NoopDirectAnswerGate, NoopDirectFakeIp, NoopFakeIpAnswerer,
    NoopSecondaryOwnedIps, QueryOutcome, ResolveError, RuleHostOracle, SecondaryOwnedIps,
    SyncReconciler, UpstreamResolver,
};
use crate::dns_wire::{
    build_a_response, build_error_response, build_negative_response, only_v4,
    parse_address_response, parse_question, AddressResponseOutcome, QTYPE_A, QTYPE_AAAA,
    RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_SERVFAIL,
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
/// overflow the loop handles the datagram inline (backpressure, old serial
/// behaviour) rather than dropping it.
const SERVE_QUEUE_DEPTH: usize = 128;

/// Everything one client datagram may cost, end to end. The per-stage timeouts
/// (rule-host resolve, fail-open forward, rotation retry) are independent and
/// can sum past seven seconds, while the client's stub resolver gives up and
/// re-asks after about one. The stage timeouts stay as they are; this caps
/// their sum.
const QUERY_BUDGET: Duration = Duration::from_secs(3);

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
    /// [`DnsInterceptListener::steer_direct_answer`] so the client never gets
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

/// The intercept listener. Holds the resolver ports plus the upstream DNS server
/// to forward non-intercepted queries to (captured *before* the DNS redirect,
/// so split-horizon keeps working).
/// Lists the machine's private resolvers, newest answer each call.
pub type PrivateResolversFn = Arc<dyn Fn() -> Vec<std::net::Ipv4Addr> + Send + Sync>;

/// Lists the namespaces connections claim, with the servers that answer for
/// them. Read fresh: a VPN that connects brings its namespace with it.
pub type ClaimedNamespacesFn =
    Arc<dyn Fn() -> Vec<(String, Vec<std::net::Ipv4Addr>)> + Send + Sync>;

/// How many private resolvers are re-asked before a "no such name" stands.
/// A machine has one or two; the bound only stops a strange configuration
/// from turning one failed lookup into a burst.
const MAX_PRIVATE_RETRIES: usize = 2;

/// What policy may do about IPv6 for the routing principal right now.
pub type Ipv6DispositionFn = Arc<dyn Fn() -> crate::enforcement_planner::Ipv6Guard + Send + Sync>;

pub struct DnsInterceptListener {
    oracle: Arc<dyn RuleHostOracle>,
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
    /// Namespaces connections claim, used to complete a single-label name.
    /// `None` leaves such names exactly as they arrive.
    claimed_namespaces: Option<ClaimedNamespacesFn>,
    /// Fake-IP — answers scope hosts with virtual addresses.
    /// The default no-op returns the real per-IP path for every host.
    fake_ip: Arc<dyn FakeIpAnswerer>,
    /// gates a steered direct answer on the block-all: the
    /// production impl installs a known-direct exemption before the answer is
    /// sent. The default no-op keeps the strict posture.
    direct_gate: Arc<dyn DirectAnswerGate>,
    /// while the block-all is armed and fake-IP is
    /// active, DIRECT hosts are answered with a virtual address too: the relay
    /// carries them out the primary, so nothing is compiled on the answer path
    /// and the first connect cannot race the catch-all. The default no-op keeps
    /// the gate-based path.
    direct_fake: Arc<dyn DirectFakeIpAnswerer>,
    /// Collateral rescue — a DIRECT host whose steered answer is STILL fully
    /// secondary-pinned (shared-CDN address the census committed to the
    /// secondary link) is answered with a virtual address while the fake-IP
    /// stack is live, instead of the old fail-open "relay the pinned answer"
    /// (which sent the host out the VPN link — geo captchas when it is up,
    /// a kill-switch block when it is down). Armed on "stack running" alone —
    /// unlike [`Self::direct_fake`], it does NOT wait for the block-all. The
    /// default no-op keeps the fail-open path.
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
    /// The default is `Off`, which handles every AAAA exactly as before IPv6
    /// could be routed.
    ipv6_disposition: Ipv6DispositionFn,
    /// Live choice of forwarding upstream — rotates itself when the server it
    /// points at stops answering.
    upstream_dns: Arc<crate::dns_upstream::UpstreamDnsPool>,
    deadline: Duration,
    forward_timeout: Duration,
    response_ttl: u32,
}

/// Receive buffer for both directions of the DNS path.
///
/// 1500 was the old value, chosen for an Ethernet frame - but EDNS lets a
/// client advertise 4096, and this listener forwards the query verbatim, OPT
/// record included, so the answer can legitimately be that big. Undersized, the
/// two failure modes are worse than a truncated packet: on Windows the receive
/// fails with "message too long" instead of truncating, and on the upstream
/// path a healthy server got a `note_failure` for an answer we could not hold -
/// three of those rotate it away.
const DNS_DATAGRAM_BUFFER_BYTES: usize = 4096;

/// How many consecutive receive errors of a kind we do not recognise are
/// tolerated before the serve loop gives up.
///
/// Returning on the first unrecognised error would switch DNS interception
/// off machine-wide over a single unusual datagram, until the watchdog
/// noticed (~50 s). A genuinely dead socket fails every time, so a run of
/// them still ends the loop; one odd packet does not.
const DNS_RECV_ERROR_TOLERANCE: u32 = 16;

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
            oracle,
            upstream,
            sink,
            reconciler,
            secondary_owned: Arc::new(NoopSecondaryOwnedIps),
            private_resolvers: None,
            claimed_namespaces: None,
            fake_ip: Arc::new(NoopFakeIpAnswerer),
            direct_gate: Arc::new(NoopDirectAnswerGate),
            direct_fake: Arc::new(NoopDirectFakeIp),
            collateral_fake: Arc::new(NoopDirectFakeIp),
            companion_candidates: Arc::new(NoopCompanionCandidates),
            companion_rescue: Arc::new(NoopCompanionRescue),
            leak_guard: Arc::new(crate::dns_resolver::OpenLeakGuard),
            ipv6_disposition: Arc::new(|| crate::enforcement_planner::Ipv6Guard::Off),
            enforced_view: Arc::new(crate::dns_resolver::NoEnforcement),
            upstream_dns: Arc::new(crate::dns_upstream::UpstreamDnsPool::fixed(upstream_dns)),
            deadline,
            forward_timeout,
            response_ttl: RESPONSE_TTL_SECS,
        }
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

    /// gate steered direct answers: while the block-all is
    /// armed, install a known-direct exemption BEFORE the answer is sent so the
    /// client's first connect is not cut by the catch-all.
    pub fn with_direct_answer_gate(mut self, gate: Arc<dyn DirectAnswerGate>) -> Self {
        self.direct_gate = gate;
        self
    }

    /// answer DIRECT hosts with a virtual address
    /// while the block-all is armed and fake-IP is active. Takes precedence
    /// over [`Self::with_direct_answer_gate`] for the answers it claims; the
    /// gate remains the fallback for hosts the fake path declines (feature
    /// off, disarmed, exclusions, pool exhausted).
    pub fn with_direct_fake_ip(mut self, fake: Arc<dyn DirectFakeIpAnswerer>) -> Self {
        self.direct_fake = fake;
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
    /// completed the way the OS would have completed it.
    #[must_use]
    pub fn with_claimed_namespaces(mut self, namespaces: ClaimedNamespacesFn) -> Self {
        self.claimed_namespaces = Some(namespaces);
        self
    }

    /// Answer a single-label name by completing it with a claimed namespace.
    ///
    /// Windows completes a bare label using the connection's own DNS
    /// suffix, then asks the server that connection named. Pointing
    /// every name at a loopback listener takes that away: loopback carries no
    /// suffix, so nothing is completed and the bare label reaches a resolver
    /// that was never going to know it. An internal host stops resolving
    /// while its full name still works.
    ///
    /// The reply is rebuilt against the ORIGINAL question. A client that asked
    /// for a bare label discards an answer about a different name, so the
    /// completed lookup stays an implementation detail — the same thing the
    /// OS resolver does on its own.
    fn complete_single_label(
        &self,
        query: &[u8],
        label: &str,
        budget: Duration,
    ) -> Option<Vec<u8>> {
        let namespaces = self.claimed_namespaces.as_ref()?();
        let started = Instant::now();
        for (suffix, servers) in namespaces {
            let left = budget.saturating_sub(started.elapsed());
            if left.is_zero() {
                break;
            }
            let full = format!("{label}.{suffix}");
            let id = crate::dns_resolver_ports::next_query_id();
            let Some(probe) = crate::dns_wire::build_address_query(id, &full, QTYPE_A) else {
                continue;
            };
            for server in servers {
                let left = budget.saturating_sub(started.elapsed());
                if left.is_zero() {
                    break;
                }
                let target = SocketAddr::from((server, 53));
                let Some(reply) = self.forward_to(&probe, target, self.forward_timeout.min(left))
                else {
                    continue;
                };
                if let crate::dns_wire::AddressResponseOutcome::Answers { addresses, min_ttl } =
                    crate::dns_wire::parse_address_response(id, &full, QTYPE_A, &reply)
                {
                    if addresses.is_empty() {
                        continue;
                    }
                    tracing::info!(
                        target: "nrr::dns-resolver",
                        label = %label,
                        completed = %full,
                        server = %server,
                        "completed a short name with the namespace its connection claims",
                    );
                    return build_a_response(query, &only_v4(&addresses), min_ttl.max(1));
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
    /// make a v6-only destination unreachable for no protection at all.
    ///
    /// The fake-IP probe is [`FakeIpAnswerer::carries_on_v4`], never
    /// `fake_answer`: the latter allocates a lease and records health.
    fn aaaa_action(&self, query: &[u8], qname: &str) -> ListenerAction {
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
            Ipv6Guard::FiltersAndRoutes => self.route_aaaa(query, qname),
            // The tunnel cannot carry the family, so the host's v6 addresses
            // are pinned to it and blocked. Handing one out would only make the
            // client wait on it; its IPv4 rides the tunnel.
            Ipv6Guard::FiltersOnly => nodata(),
            Ipv6Guard::Off => {
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
    fn route_aaaa(&self, query: &[u8], qname: &str) -> ListenerAction {
        let hold = crate::dns_resolver::AnswerHold {
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
            AaaaOutcome::Upstream(ResolveError::Unavailable(_)) => ListenerAction::Forward,
        }
    }

    pub fn answer_query(&self, query: &[u8]) -> ListenerAction {
        let Some(q) = parse_question(query) else {
            return ListenerAction::Forward; // unparseable → transparent proxy
        };
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
            return self.aaaa_action(query, &q.qname);
        }
        if q.qtype != QTYPE_A {
            return ListenerAction::Forward; // not an A query
        }
        let rule_covered = self.oracle.is_rule_host(&q.qname);
        if !rule_covered {
            // Direct host: forward, but steer the reply so the client
            // never receives a secondary-pinned address (shared-CDN collateral).
            return ListenerAction::ForwardFiltered;
        }
        match handle_a_query(
            &q.qname,
            crate::dns_resolver::AnswerHold {
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
            QueryOutcome::Withheld => build_error_response(query, RCODE_SERVFAIL)
                .map_or(ListenerAction::Drop, ListenerAction::Respond),
            QueryOutcome::Upstream(ResolveError::NoRecords) => {
                negative_answer(query).map_or(ListenerAction::Forward, ListenerAction::Respond)
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
    /// are handed to a small worker pool; a per-datagram failure is logged and
    /// skipped — the loop never dies on one bad packet or a slow upstream.
    ///
    /// The loop itself does no per-datagram work: handling a datagram inline
    /// would serialize the WHOLE system's DNS behind one slow answer, since
    /// under the armed block-all every new direct host holds the pipeline for
    /// the full direct-answer-gate budget — a page touching twenty new hosts
    /// would stall name resolution for everything for seconds. Workers instead
    /// carry the slow parts (upstream forward, bounded reconcile, gate)
    /// concurrently; the loop only receives and dispatches. When the hand-off
    /// queue is full the datagram is handled inline — backpressure degrades to
    /// serial handling instead of dropping queries.
    pub fn serve_udp(&self, socket: &UdpSocket, stop: &AtomicBool) -> std::io::Result<()> {
        // A read timeout lets the loop observe `stop` promptly instead of
        // blocking forever in `recv_from`.
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        let (tx, rx) = std::sync::mpsc::sync_channel::<(Vec<u8>, SocketAddr)>(SERVE_QUEUE_DEPTH);
        let rx = Mutex::new(rx);
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
                        Ok((query, src)) => self.handle_datagram(socket, &query, src),
                        // Sender dropped — the serve loop exited; drain is done.
                        Err(_) => return,
                    }
                });
            }
            let mut buf = [0u8; DNS_DATAGRAM_BUFFER_BYTES];
            let mut consecutive_errors = 0u32;
            while !stop.load(Ordering::Relaxed) {
                let (n, src) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue
                    }
                    // a UDP server must NEVER die on one datagram.
                    // On Windows `recv_from` surfaces WSAECONNRESET (os error 10054) as
                    // a PER-DATAGRAM condition: after we `send_to` a DNS client whose
                    // ephemeral port already closed, the loopback ICMP port-unreachable
                    // arrives on the NEXT `recv_from`. Treating that as fatal would
                    // terminate the whole Mode-B resolver serve loop (with no watchdog
                    // to re-arm it), silently stopping zone/suffix rules from resolving.
                    // Skip these transient connection-level errors and keep serving;
                    // only a genuinely dead socket ends the loop. Platform-neutral:
                    // correct on every OS (see the cross-platform seam — no Win32 here;
                    // SIO_UDP_CONNRESET suppression, if ever wanted, belongs behind the
                    // platform socket port).
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        tracing::debug!(
                            target: "nrr::dns_resolver",
                            error = %e,
                            "Mode B: skipped a transient per-datagram recv error (client port closed) — continuing to serve",
                        );
                        continue;
                    }
                    // Anything else: log and keep serving. Returning here is
                    // what made one oversized datagram take DNS interception
                    // down for the whole machine.
                    Err(e) => {
                        consecutive_errors += 1;
                        if consecutive_errors >= DNS_RECV_ERROR_TOLERANCE {
                            return Err(e);
                        }
                        tracing::warn!(
                            target: "nrr::dns_resolver",
                            error = %e,
                            consecutive_errors,
                            "Mode B: unrecognised receive error; continuing to serve",
                        );
                        continue;
                    }
                };
                consecutive_errors = 0;
                match tx.try_send((buf[..n].to_vec(), src)) {
                    Ok(()) => {}
                    Err(TrySendError::Full((query, src))) => {
                        self.handle_datagram(socket, &query, src);
                    }
                    // Unreachable while workers live inside this scope; treat
                    // as shutdown just in case.
                    Err(TrySendError::Disconnected(_)) => break,
                }
            }
            drop(tx); // disconnect → workers drain the queue and exit
            Ok(())
        })
    }

    /// Fully process one query datagram and send its response (if any) back to
    /// `src` over the shared listener socket. Runs on a pool worker (or inline
    /// under backpressure) — everything here may block for its own bounded
    /// budgets without stalling other queries.
    fn handle_datagram(&self, socket: &UdpSocket, query: &[u8], src: SocketAddr) {
        let started = Instant::now();
        let left = || QUERY_BUDGET.saturating_sub(started.elapsed());
        match self.answer_query(query) {
            ListenerAction::Respond(resp) => {
                let _ = socket.send_to(&resp, src);
            }
            ListenerAction::Forward => {
                match self.forward_within(query, left()) {
                    Some(resp) => {
                        let _ = socket.send_to(&resp, src);
                    }
                    // Silence costs the client its own timeout on top of ours.
                    None => self.answer_servfail(socket, query, src),
                }
            }
            ListenerAction::Drop => {}
            ListenerAction::ForwardFiltered => {
                let Some(resp) = self.forward_within(query, left()) else {
                    self.answer_servfail(socket, query, src);
                    return;
                };
                let (steered, still_pinned) = self.steer_direct_answer(query, resp, left());
                // under the armed block-all with
                // fake-IP active, hand the client a virtual address instead:
                // the relay carries the flow out the primary, nothing is
                // compiled on the answer path, no race to lose.
                if let Some(fake) = self.fake_direct_response(query, &steered) {
                    // Gate before answering: the app may already hold these
                    // real addresses (own cache / in-app DoH) and will not
                    // re-resolve, so the virtual answer never reaches it and
                    // its first connect meets the armed block-all.
                    self.gate_direct_answer(query, &steered);
                    let _ = socket.send_to(&fake, src);
                    return;
                }
                // Collateral rescue — steering could not produce a clean
                // answer (every address is committed to the secondary
                // link). With the fake-IP stack live, a virtual address
                // routes the host by NAME out the primary; the old
                // fail-open answer sent it out the VPN link instead
                // (geo captcha / kill-switch block).
                if still_pinned {
                    // Reported here, not inside the rescue, so the evidence
                    // is the same with or without the fake-IP stack.
                    self.note_collateral_host(query);
                    if !self.companion_is_pending(query) {
                        if let Some(fake) = self.fake_collateral_response(query, &steered) {
                            // Same reason as above: a cached real address
                            // bypasses the virtual answer entirely.
                            self.gate_direct_answer(query, &steered);
                            let _ = socket.send_to(&fake, src);
                            return;
                        }
                    }
                }
                // while the block-all is armed, install the
                // known-direct exemption BEFORE the client learns these
                // addresses (its first connect would otherwise race
                // the catch-all and be dropped with no retry).
                self.gate_direct_answer(query, &steered);
                let _ = socket.send_to(&steered, src);
            }
        }
    }

    /// steer one upstream reply for a DIRECT
    /// (non-rule) host: drop `A` records the kill-switch pins to the secondary
    /// so the client connects via addresses that stay on the primary/default
    /// path. Google's front-end answers rotate over a large pool, so filtering
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
    fn steer_direct_answer(
        &self,
        query: &[u8],
        reply: Vec<u8>,
        budget: Duration,
    ) -> (Vec<u8>, bool) {
        let owned = self.secondary_owned.secondary_owned_ips();
        if owned.is_empty() {
            return (reply, false);
        }
        let Some(q) = parse_question(query) else {
            return (reply, false);
        };
        let id = u16::from_be_bytes([query[0], query[1]]);
        let AddressResponseOutcome::Answers { addresses, .. } =
            parse_address_response(id, &q.qname, QTYPE_A, &reply)
        else {
            return (reply, false); // NXDOMAIN / error / truncated / mismatch → relay as-is
        };
        let answered = only_v4(&addresses);
        let clean: Vec<Ipv4Addr> = answered
            .iter()
            .copied()
            .filter(|ip| !owned.contains(ip))
            .collect();
        if clean.len() == answered.len() {
            return (reply, false); // nothing shared → untouched upstream answer
        }
        if !clean.is_empty() {
            tracing::debug!(
                target: "nrr::dns-resolver",
                host = %q.qname,
                dropped = answered.len() - clean.len(),
                kept = clean.len(),
                "Mode B: steered a direct-host answer away from secondary-pinned addresses",
            );
            return (
                build_a_response(query, &clean, self.response_ttl).unwrap_or(reply),
                false,
            );
        }
        // Whole answer pinned — try ONE fresh upstream answer (pools rotate).
        if let Some(retry) = self.forward_within(query, budget) {
            if let AddressResponseOutcome::Answers { addresses, .. } =
                parse_address_response(id, &q.qname, QTYPE_A, &retry)
            {
                let clean: Vec<Ipv4Addr> = only_v4(&addresses)
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
                    return (
                        build_a_response(query, &clean, self.response_ttl).unwrap_or(reply),
                        false,
                    );
                }
            }
        }
        tracing::debug!(
            target: "nrr::dns-resolver",
            host = %q.qname,
            "Mode B: direct-host answer fully secondary-pinned even after re-query — relaying unchanged (fail-open; smart kill-switch covers)",
        );
        (reply, true)
    }

    /// hand the FINAL direct-host answer's addresses to the
    /// [`DirectAnswerGate`] so a known-direct exemption can be installed before
    /// the client receives them. Steering has already removed secondary-pinned
    /// addresses from `reply` on every non-degraded path, so the gate only ever
    /// sees addresses that are safe to permit on the primary; the orchestrator
    /// additionally subtracts secondary-destined IPs (defense in depth for the
    /// fully-pinned fail-open path). Parse failures are a silent no-op — the
    /// reply is relayed regardless.
    fn gate_direct_answer(&self, query: &[u8], reply: &[u8]) {
        let Some(q) = parse_question(query) else {
            return;
        };
        let id = u16::from_be_bytes([query[0], query[1]]);
        let AddressResponseOutcome::Answers { addresses, .. } =
            parse_address_response(id, &q.qname, QTYPE_A, reply)
        else {
            return;
        };
        if !addresses.is_empty() {
            self.direct_gate.gate(&q.qname, &only_v4(&addresses));
        }
    }

    /// try to answer a DIRECT host with a virtual
    /// address. Parses the final (already steered) upstream reply, offers its
    /// addresses to the [`DirectFakeIpAnswerer`] (which registers the real
    /// addresses for the relay and allocates the fake), and rebuilds the
    /// response around the fake address. `None` on any parse failure or when
    /// the answerer declines (feature off / disarmed / exclusion / pool full)
    /// — the caller then falls back to the gate + steered-reply path.
    fn fake_direct_response(&self, query: &[u8], reply: &[u8]) -> Option<Vec<u8>> {
        let q = parse_question(query)?;
        let id = u16::from_be_bytes([query[0], query[1]]);
        let AddressResponseOutcome::Answers { addresses, .. } =
            parse_address_response(id, &q.qname, QTYPE_A, reply)
        else {
            return None; // NXDOMAIN / error / truncated → not ours to rewrite
        };
        if addresses.is_empty() {
            return None;
        }
        let fake = self
            .direct_fake
            .fake_direct_answer(&q.qname, &only_v4(&addresses))?;
        let resp = build_a_response(query, &fake, self.response_ttl)?;
        tracing::debug!(
            target: "nrr::dns-resolver",
            host = %q.qname,
            fake = ?fake,
            real = ?addresses,
            "Mode B: direct host under block-all — answered with a virtual address (relay carries the flow; no reconcile on the answer path)",
        );
        Some(resp)
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
    fn note_collateral_host(&self, query: &[u8]) {
        let Some(q) = parse_question(query) else {
            return;
        };
        self.companion_rescue.note_rescued_companion(&q.qname);
    }

    fn companion_is_pending(&self, query: &[u8]) -> bool {
        let Some(q) = parse_question(query) else {
            return false;
        };
        if !self
            .companion_candidates
            .is_pending_secondary_companion(&q.qname)
        {
            return false;
        }
        tracing::info!(
            target: "nrr::dns-resolver",
            host = %q.qname,
            "direct host is a parked suggestion for the additional route — left on it instead of being steered onto the primary",
        );
        true
    }

    fn fake_collateral_response(&self, query: &[u8], reply: &[u8]) -> Option<Vec<u8>> {
        let q = parse_question(query)?;
        let id = u16::from_be_bytes([query[0], query[1]]);
        let AddressResponseOutcome::Answers { addresses, .. } =
            parse_address_response(id, &q.qname, QTYPE_A, reply)
        else {
            return None;
        };
        if addresses.is_empty() {
            return None;
        }
        let fake = self
            .collateral_fake
            .fake_direct_answer(&q.qname, &only_v4(&addresses))?;
        let resp = build_a_response(query, &fake, self.response_ttl)?;
        tracing::info!(
            target: "nrr::dns-resolver",
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
    fn forward_within(&self, query: &[u8], budget: Duration) -> Option<Vec<u8>> {
        let started = Instant::now();
        let left = || budget.saturating_sub(started.elapsed());
        if left().is_zero() {
            return None;
        }
        let upstream = self.upstream_dns.current()?;
        if let Some(reply) = self.forward_to(query, upstream, self.forward_timeout.min(left())) {
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
        let reply = self.forward_to(query, replacement, window)?;
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
        let servers = self.private_resolvers.as_ref()?;
        let mut tried = 0usize;
        for server in servers() {
            if budget.is_zero() || tried >= MAX_PRIVATE_RETRIES {
                break;
            }
            let target = SocketAddr::from((server, 53));
            if target == already_asked {
                continue;
            }
            tried += 1;
            let reply = self.forward_to(query, target, self.forward_timeout.min(budget))?;
            if !reply_is_nxdomain(&reply) {
                tracing::info!(
                    target: "nrr::dns-resolver",
                    server = %server,
                    "a resolver on this machine knows a name the upstream called non-existent",
                );
                return Some(reply);
            }
        }
        None
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
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        sock.set_read_timeout(Some(window)).ok()?;
        sock.connect(upstream).ok()?;
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
                return Some(buf[..n].to_vec());
            }
            // A late reply to an earlier query, or noise the kernel could not
            // filter. Keep waiting for ours rather than relaying somebody
            // else's answer.
        }
    }
}

/// Whether `reply` is an answer to `query`: same transaction id, the response
/// bit set, and the same question echoed back.
///
/// Matching on the id alone is not enough — the id is 16 bits and, on this
/// path, sequential.
fn reply_answers_query(query: &[u8], reply: &[u8]) -> bool {
    use crate::dns_wire::parse_question;
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
    match (parse_question(query), parse_question(reply)) {
        (Some(q), Some(r)) => q.qtype == r.qtype && q.qname.eq_ignore_ascii_case(&r.qname),
        // A server may answer a malformed or empty-question query (FORMERR)
        // with no question section; the id plus the connected socket is all
        // there is to go on there.
        (None, _) | (_, None) => true,
    }
}

/// One "no such name" answer, carrying the SOA that lets the client remember it.
///
/// Every synthetic NXDOMAIN here goes through this: without the authority
/// record a stub resolver cannot cache the negative answer and re-asks on every
/// lookup — which for the DoH canary means a query per page load.
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
fn negative_answer(query: &[u8]) -> Option<Vec<u8>> {
    crate::dns_wire::build_negative_response(
        query,
        RCODE_NXDOMAIN,
        crate::dns_wire::NEGATIVE_TTL_SECS,
    )
}

#[cfg(test)]
mod tests;
