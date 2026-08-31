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
//! listener is a separate, per-OS concern behind `SystemDnsRedirectPort`
//! (increment 1c). TCP fallback for truncated (`TC=1`) answers is a documented
//! phase-1 gap — classic UDP DNS fits the vast majority of rule-host `A`
//! answers, and the passive observer remains a backstop.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::TrySendError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::dns_resolver::{
    handle_a_query, CompanionCandidateLookup, CompanionRescueObserver, DirectAnswerGate,
    DirectFakeIpAnswerer, FactSink, FakeIpAnswerer, NoopCompanionCandidates, NoopCompanionRescue,
    NoopDirectAnswerGate, NoopDirectFakeIp, NoopFakeIpAnswerer, NoopSecondaryOwnedIps,
    QueryOutcome, ResolveError, RuleHostOracle, SecondaryOwnedIps, SyncReconciler,
    UpstreamResolver,
};
use crate::dns_wire::{
    build_a_response, build_error_response, parse_a_response, parse_question, AResponseOutcome,
    QTYPE_A, RCODE_NXDOMAIN, RCODE_SERVFAIL,
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

/// Everything one client datagram may cost, end to end. The stages used to
/// budget independently — rule-host resolve, then the fail-open forward, then
/// its rotation retry — and summed past seven seconds, while the client's stub
/// resolver gives up and re-asks after about one. The stage timeouts stay as
/// they are; this caps their sum.
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
/// to forward non-intercepted queries to (captured *before* the DNS redirect —
/// increment 1c — so split-horizon keeps working).
pub struct DnsInterceptListener {
    oracle: Arc<dyn RuleHostOracle>,
    upstream: Arc<dyn UpstreamResolver>,
    sink: Arc<dyn FactSink>,
    reconciler: Arc<dyn SyncReconciler>,
    /// П0-D — secondary-owned (pinned) addresses for direct-answer steering.
    /// The default no-op (empty set) leaves every direct reply untouched.
    secondary_owned: Arc<dyn SecondaryOwnedIps>,
    /// Block D (fake-IP, slice 4) — answers scope hosts with virtual addresses.
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
    /// Sees every `A` query and whether a rule covers its name, which is what
    /// the operator-notice-page detector needs. The default no-op observes
    /// nothing, so the feature is absent until wired.
    resolution_observer: Arc<dyn ResolutionObserver>,
    /// Whether the leak guard is blocking with the additional link unresolved.
    /// A rule-host answer that missed its reconcile deadline is withheld while
    /// it is — see [`crate::dns_resolver::LeakGuardPosture`]. The default never
    /// blocks, keeping the historic fail-open.
    leak_guard: Arc<dyn crate::dns_resolver::LeakGuardPosture>,
    /// Live choice of forwarding upstream — rotates itself when the server it
    /// points at stops answering.
    upstream_dns: Arc<crate::dns_upstream::UpstreamDnsPool>,
    deadline: Duration,
    forward_timeout: Duration,
    response_ttl: u32,
}

/// Watches names as they are resolved. Production feeds
/// [`crate::isp_block_page_learner`]; nothing here decides anything.
pub trait ResolutionObserver: Send + Sync {
    fn note_resolution(&self, hostname: &str, rule_covered: bool);
}

/// The default: sees nothing.
pub struct NoopResolutionObserver;

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
/// The loop used to return on the first one, so a single unusual datagram
/// switched DNS interception off machine-wide until the watchdog noticed
/// (~50 s). A genuinely dead socket fails every time, so a run of them still
/// ends the loop; one odd packet no longer does.
const DNS_RECV_ERROR_TOLERANCE: u32 = 16;

impl ResolutionObserver for NoopResolutionObserver {
    fn note_resolution(&self, _hostname: &str, _rule_covered: bool) {}
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
            oracle,
            upstream,
            sink,
            reconciler,
            secondary_owned: Arc::new(NoopSecondaryOwnedIps),
            fake_ip: Arc::new(NoopFakeIpAnswerer),
            direct_gate: Arc::new(NoopDirectAnswerGate),
            direct_fake: Arc::new(NoopDirectFakeIp),
            collateral_fake: Arc::new(NoopDirectFakeIp),
            companion_candidates: Arc::new(NoopCompanionCandidates),
            companion_rescue: Arc::new(NoopCompanionRescue),
            resolution_observer: Arc::new(NoopResolutionObserver),
            leak_guard: Arc::new(crate::dns_resolver::OpenLeakGuard),
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

    /// Watch resolved names (operator-notice-page detection).
    pub fn with_resolution_observer(mut self, observer: Arc<dyn ResolutionObserver>) -> Self {
        self.resolution_observer = observer;
        self
    }

    /// Read the live leak-guard posture, so a rule-host answer whose enforcement
    /// did not install in time is withheld rather than leaked to the main link.
    pub fn with_leak_guard_posture(
        mut self,
        posture: Arc<dyn crate::dns_resolver::LeakGuardPosture>,
    ) -> Self {
        self.leak_guard = posture;
        self
    }

    /// enable direct-answer steering: replies to
    /// non-rule `A` queries are filtered against this secondary-owned set.
    pub fn with_direct_answer_steering(mut self, owned: Arc<dyn SecondaryOwnedIps>) -> Self {
        self.secondary_owned = owned;
        self
    }

    /// Block D (fake-IP, slice 4) — answer in-scope rule hosts with virtual
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

    /// Decide what to do with one raw query datagram — pure, no I/O, so the
    /// intercept-vs-forward policy is unit-tested independently of sockets.
    ///
    /// Intercepts ONLY `A` queries whose name is a rule host; for those it runs
    /// the enforce-before-answer handler and builds the response from the
    /// resolved IPs. Anything else (including a rule host our own resolver could
    /// not reach) is forwarded raw — general DNS never depends on us succeeding.
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
            return build_error_response(query, RCODE_NXDOMAIN)
                .map_or(ListenerAction::Forward, ListenerAction::Respond);
        }
        if q.qtype != QTYPE_A {
            return ListenerAction::Forward; // not an A query
        }
        let rule_covered = self.oracle.is_rule_host(&q.qname);
        // Both halves of the notice-page signal are ordinary lookups — the site
        // that was cut and the operator's page that followed it.
        self.resolution_observer
            .note_resolution(&q.qname, rule_covered);
        if !rule_covered {
            // П0-D — direct host: forward, but steer the reply so the client
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
        ) {
            QueryOutcome::Answer { ips, .. } => build_a_response(query, &ips, self.response_ttl)
                .map(ListenerAction::Respond)
                // Empty answer set (nothing to route) → NXDOMAIN, else forward.
                .unwrap_or_else(|| {
                    build_error_response(query, RCODE_NXDOMAIN)
                        .map_or(ListenerAction::Forward, ListenerAction::Respond)
                }),
            // Withheld deliberately: SERVFAIL, never a forward. Forwarding here
            // would hand the caller the very addresses the guard is holding
            // back, over the OS's own resolver.
            QueryOutcome::Withheld => build_error_response(query, RCODE_SERVFAIL)
                .map_or(ListenerAction::Drop, ListenerAction::Respond),
            QueryOutcome::Upstream(ResolveError::NoRecords) => {
                build_error_response(query, RCODE_NXDOMAIN)
                    .map_or(ListenerAction::Forward, ListenerAction::Respond)
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
    /// the loop itself no longer does per-datagram work. The 0722
    /// boot log showed the previous inline handling serializing the WHOLE
    /// system's DNS behind one slow answer: under the armed block-all every
    /// new direct host held the pipeline for the full direct-answer-gate
    /// budget (events landed exactly one budget apart), so a page touching
    /// twenty new hosts stalled name resolution for everything for ~10 s.
    /// Workers now carry the slow parts (upstream forward, bounded reconcile,
    /// gate) concurrently; the loop only receives and dispatches. When the
    /// hand-off queue is full the datagram is handled inline — backpressure
    /// degrades to the old serial behaviour instead of dropping queries.
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
                    // arrives on the NEXT `recv_from`. The 0710 build treated this as
                    // fatal, so the whole Mode-B resolver serve loop terminated (with no
                    // watchdog to re-arm it) and zone/suffix rules silently stopped
                    // resolving (HW-0711 finding #3). Skip these transient
                    // connection-level errors and keep serving; only a genuinely dead
                    // socket ends the loop. Platform-neutral: correct on every OS (see
                    // the cross-platform seam — no Win32 here; SIO_UDP_CONNRESET
                    // suppression, if ever wanted, belongs behind the platform socket port).
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
    /// fail-open; the smart kill-switch (П0-A) is the safety net that keeps
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
        let AResponseOutcome::Answers { addresses, .. } = parse_a_response(id, &q.qname, &reply)
        else {
            return (reply, false); // NXDOMAIN / error / truncated / mismatch → relay as-is
        };
        let clean: Vec<Ipv4Addr> = addresses
            .iter()
            .copied()
            .filter(|ip| !owned.contains(ip))
            .collect();
        if clean.len() == addresses.len() {
            return (reply, false); // nothing shared → untouched upstream answer
        }
        if !clean.is_empty() {
            tracing::debug!(
                target: "nrr::dns-resolver",
                host = %q.qname,
                dropped = addresses.len() - clean.len(),
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
            if let AResponseOutcome::Answers { addresses, .. } =
                parse_a_response(id, &q.qname, &retry)
            {
                let clean: Vec<Ipv4Addr> = addresses
                    .iter()
                    .copied()
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
        let AResponseOutcome::Answers { addresses, .. } = parse_a_response(id, &q.qname, reply)
        else {
            return;
        };
        if !addresses.is_empty() {
            self.direct_gate.gate(&q.qname, &addresses);
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
        let AResponseOutcome::Answers { addresses, .. } = parse_a_response(id, &q.qname, reply)
        else {
            return None; // NXDOMAIN / error / truncated → not ours to rewrite
        };
        if addresses.is_empty() {
            return None;
        }
        let fake = self.direct_fake.fake_direct_answer(&q.qname, &addresses)?;
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
        let AResponseOutcome::Answers { addresses, .. } = parse_a_response(id, &q.qname, reply)
        else {
            return None;
        };
        if addresses.is_empty() {
            return None;
        }
        let fake = self
            .collateral_fake
            .fake_direct_answer(&q.qname, &addresses)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The forward path relays bytes straight to the client's stub resolver, so
    /// what it accepts becomes the OS cache and, downstream, the rule host cache
    /// the routes and kill-switch exemptions are built from.
    #[test]
    fn a_forwarded_reply_is_accepted_only_when_it_answers_our_query() {
        use crate::dns_wire::build_a_query;
        let query = build_a_query(0x1234, "example.com").expect("query");

        let mut good = query.clone();
        good[2] |= 0x80; // QR = response
        assert!(reply_answers_query(&query, &good));

        // Somebody else's transaction.
        let mut wrong_id = good.clone();
        wrong_id[0] = 0xFF;
        assert!(!reply_answers_query(&query, &wrong_id));

        // Right id, different question - the shape a blind forger produces
        // when it guesses the id but not what was asked.
        let mut other = build_a_query(0x1234, "evil.example").expect("query");
        other[2] |= 0x80;
        assert!(!reply_answers_query(&query, &other));

        // A query echoed back is not an answer.
        assert!(!reply_answers_query(&query, &query));

        // Case differences in the echoed name are legal (0x20 encoding).
        let mut mixed = build_a_query(0x1234, "ExAmPlE.CoM").expect("query");
        mixed[2] |= 0x80;
        assert!(reply_answers_query(&query, &mixed));
    }
    use crate::dns_resolver::{ReconcileOutcome, ResolvedA};
    use crate::dns_wire::{parse_question, QTYPE_HTTPS};
    use std::net::Ipv4Addr;

    // ── Fake ports ────────────────────────────────────────────────────────────

    struct Oracle(Vec<String>);
    impl RuleHostOracle for Oracle {
        fn is_rule_host(&self, hostname: &str) -> bool {
            self.0.iter().any(|h| h.as_str() == hostname)
        }
    }
    struct Upstream(Result<ResolvedA, ResolveError>);
    impl UpstreamResolver for Upstream {
        fn resolve_a(&self, _h: &str) -> Result<ResolvedA, ResolveError> {
            self.0.clone()
        }
    }
    struct NoopSink;
    impl FactSink for NoopSink {
        fn record(&self, _h: &str, _r: &ResolvedA) {}
    }
    struct OkReconciler;
    impl SyncReconciler for OkReconciler {
        fn reconcile_now(&self, _d: Duration) -> ReconcileOutcome {
            ReconcileOutcome::Installed
        }
    }

    fn listener(
        rule_hosts: &[&str],
        upstream: Result<ResolvedA, ResolveError>,
    ) -> DnsInterceptListener {
        DnsInterceptListener::new(
            Arc::new(Oracle(rule_hosts.iter().map(|s| s.to_string()).collect())),
            Arc::new(Upstream(upstream)),
            Arc::new(NoopSink),
            Arc::new(OkReconciler),
            // TEST-NET-1 (RFC 5737): a forwarder that can never answer. Pointing
            // at 127.0.0.1:53 made these tests consult whatever resolver the
            // machine runs — our own service, when it is up.
            "192.0.2.1:53".parse().unwrap(),
            Duration::from_millis(150),
            Duration::from_millis(150),
        )
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut p = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x01]);
        p
    }

    fn resolved(ips: &[Ipv4Addr]) -> ResolvedA {
        ResolvedA {
            addresses: ips.to_vec(),
            ttl_seconds: 300,
        }
    }

    #[test]
    fn intercepts_a_rule_host_and_builds_answer() {
        let l = listener(
            &["chatgpt.com"],
            Ok(resolved(&[Ipv4Addr::new(172, 64, 155, 209)])),
        );
        match l.answer_query(&query("chatgpt.com", QTYPE_A)) {
            ListenerAction::Respond(resp) => {
                let q = parse_question(&resp).expect("response parses");
                assert_eq!(q.qname, "chatgpt.com");
                assert_eq!(resp[2] & 0x80, 0x80, "QR set");
                assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "one answer");
                // RDATA is the resolved IP.
                assert_eq!(&resp[resp.len() - 4..], &[172, 64, 155, 209]);
            }
            other => panic!("expected Respond, got {other:?}"),
        }
    }

    #[test]
    fn forwards_aaaa_and_steers_non_rule_a() {
        let l = listener(&["chatgpt.com"], Ok(resolved(&[Ipv4Addr::new(1, 2, 3, 4)])));
        // AAAA for a rule host → not an A query → plain forward.
        assert_eq!(
            l.answer_query(&query("chatgpt.com", 28)),
            ListenerAction::Forward
        );
        // A for a non-rule host → forward WITH direct-answer steering (П0-D).
        assert_eq!(
            l.answer_query(&query("example.com", QTYPE_A)),
            ListenerAction::ForwardFiltered
        );
    }

    #[test]
    fn https_rr_is_forwarded_raw_for_rule_and_direct_hosts() {
        // Pins today's behaviour, which is a known hole rather than a decision:
        // an HTTPS answer's `ipv4hint` carries real addresses past both the
        // rule-host interception and the direct-answer steering. Cloudflare-fronted
        // names populate that hint in practice.
        let l = listener(&["chatgpt.com"], Ok(resolved(&[Ipv4Addr::new(1, 2, 3, 4)])));
        assert_eq!(
            l.answer_query(&query("chatgpt.com", QTYPE_HTTPS)),
            ListenerAction::Forward,
            "rule host: not intercepted"
        );
        assert_eq!(
            l.answer_query(&query("example.com", QTYPE_HTTPS)),
            ListenerAction::Forward,
            "direct host: not even steered"
        );
    }

    // ── П0-D — direct-answer steering ────────────────────────────────────────

    struct OwnedSet(Arc<std::collections::HashSet<Ipv4Addr>>);
    impl crate::dns_resolver::SecondaryOwnedIps for OwnedSet {
        fn secondary_owned_ips(&self) -> Arc<std::collections::HashSet<Ipv4Addr>> {
            Arc::clone(&self.0)
        }
    }

    fn steering_listener(owned: &[Ipv4Addr]) -> DnsInterceptListener {
        listener(&["chatgpt.com"], Ok(resolved(&[Ipv4Addr::new(1, 2, 3, 4)])))
            .with_direct_answer_steering(Arc::new(OwnedSet(Arc::new(
                owned.iter().copied().collect(),
            ))))
    }

    /// Build an upstream-style reply to `query(name, A)` carrying `ips`.
    fn reply_for(name: &str, ips: &[Ipv4Addr]) -> Vec<u8> {
        crate::dns_wire::build_a_response(&query(name, QTYPE_A), ips, 300).expect("reply")
    }

    #[test]
    fn steering_passes_clean_answers_through_untouched() {
        let l = steering_listener(&[Ipv4Addr::new(9, 9, 9, 9)]);
        let q = query("www.google.com", QTYPE_A);
        let reply = reply_for("www.google.com", &[Ipv4Addr::new(142, 250, 1, 1)]);
        assert_eq!(
            l.steer_direct_answer(&q, reply.clone(), QUERY_BUDGET),
            (reply, false)
        );
    }

    #[test]
    fn steering_drops_secondary_pinned_addresses() {
        let pinned = Ipv4Addr::new(142, 251, 150, 119);
        let clean = Ipv4Addr::new(64, 233, 165, 99);
        let l = steering_listener(&[pinned]);
        let q = query("www.google.com", QTYPE_A);
        let reply = reply_for("www.google.com", &[pinned, clean]);
        let (steered, still_pinned) = l.steer_direct_answer(&q, reply, QUERY_BUDGET);
        assert!(!still_pinned, "a partially clean answer is not pinned");
        let out = crate::dns_wire::parse_a_response(0x1234, "www.google.com", &steered);
        match out {
            crate::dns_wire::AResponseOutcome::Answers { addresses, .. } => {
                assert_eq!(addresses, vec![clean], "pinned address filtered out");
            }
            other => panic!("expected Answers, got {other:?}"),
        }
    }

    #[test]
    fn steering_with_empty_owned_set_is_a_no_op() {
        let l = steering_listener(&[]);
        let q = query("www.google.com", QTYPE_A);
        let pinned = Ipv4Addr::new(142, 251, 150, 119);
        let reply = reply_for("www.google.com", &[pinned]);
        assert_eq!(
            l.steer_direct_answer(&q, reply.clone(), QUERY_BUDGET),
            (reply, false)
        );
    }

    #[test]
    fn steering_relays_error_replies_unchanged() {
        let l = steering_listener(&[Ipv4Addr::new(1, 1, 1, 1)]);
        let q = query("www.google.com", QTYPE_A);
        let nx = crate::dns_wire::build_error_response(&q, RCODE_NXDOMAIN).expect("nx");
        assert_eq!(
            l.steer_direct_answer(&q, nx.clone(), QUERY_BUDGET),
            (nx, false)
        );
    }

    #[test]
    fn steering_reports_a_fully_pinned_reply() {
        // Every address is secondary-pinned, and the test forwarder (127.0.0.1
        // with a 150 ms budget) cannot produce a clean re-query → the terminal
        // fail-open path must hand the reply back flagged, so the caller can
        // offer it to the collateral fake-IP rescue.
        let pinned = Ipv4Addr::new(64, 233, 163, 100);
        let l = steering_listener(&[pinned]);
        let q = query("workspace.google.com", QTYPE_A);
        let reply = reply_for("workspace.google.com", &[pinned]);
        assert_eq!(
            l.steer_direct_answer(&q, reply.clone(), QUERY_BUDGET),
            (reply, true)
        );
    }

    #[test]
    fn doh_canary_gets_nxdomain_before_rule_gate_for_any_qtype() {
        // the Firefox DoH canary is NOT a rule host, yet must
        // be answered NXDOMAIN (not forwarded) so Firefox disables DoH. Verify for
        // both A and HTTPS (type 65) qtypes and a subdomain.
        let l = listener(&["chatgpt.com"], Ok(resolved(&[Ipv4Addr::new(1, 2, 3, 4)])));
        for (name, qtype) in [
            ("use-application-dns.net", QTYPE_A),
            ("use-application-dns.net", QTYPE_HTTPS),
            ("x.use-application-dns.net", QTYPE_A),
        ] {
            match l.answer_query(&query(name, qtype)) {
                ListenerAction::Respond(resp) => {
                    assert_eq!(resp[3] & 0x0F, RCODE_NXDOMAIN, "{name}/{qtype} → NXDOMAIN");
                    assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "no answers");
                }
                other => panic!("expected NXDOMAIN Respond for {name}, got {other:?}"),
            }
        }
    }

    #[test]
    fn rule_host_no_records_returns_nxdomain() {
        let l = listener(&["gone.example"], Err(ResolveError::NoRecords));
        match l.answer_query(&query("gone.example", QTYPE_A)) {
            ListenerAction::Respond(resp) => {
                assert_eq!(resp[3] & 0x0F, RCODE_NXDOMAIN);
                assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "no answers");
            }
            other => panic!("expected NXDOMAIN Respond, got {other:?}"),
        }
    }

    #[test]
    fn rule_host_upstream_unavailable_fails_open_to_forward() {
        let l = listener(
            &["chatgpt.com"],
            Err(ResolveError::Unavailable("timeout".into())),
        );
        // Our resolver failed — forward raw so the OS server can still answer.
        assert_eq!(
            l.answer_query(&query("chatgpt.com", QTYPE_A)),
            ListenerAction::Forward
        );
    }

    #[test]
    fn unparseable_datagram_is_forwarded() {
        let l = listener(&["chatgpt.com"], Ok(resolved(&[Ipv4Addr::new(1, 2, 3, 4)])));
        assert_eq!(l.answer_query(&[0u8; 3]), ListenerAction::Forward);
    }

    // ── S4.8 — direct-host fake-IP under block-all (variant A) ───────────────

    /// Claims every host: returns one fixed fake address and records what the
    /// listener offered (host + the steered real set).
    struct ClaimingFake {
        fake: Ipv4Addr,
        seen: std::sync::Mutex<Vec<(String, Vec<Ipv4Addr>)>>,
    }
    impl DirectFakeIpAnswerer for ClaimingFake {
        fn fake_direct_answer(&self, hostname: &str, real: &[Ipv4Addr]) -> Option<Vec<Ipv4Addr>> {
            self.seen
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((hostname.to_string(), real.to_vec()));
            Some(vec![self.fake])
        }
    }

    #[test]
    fn direct_fake_rewrites_the_reply_and_sees_the_steered_addresses() {
        let fake = Ipv4Addr::new(198, 18, 0, 7);
        let claiming = Arc::new(ClaimingFake {
            fake,
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let l = listener(&["chatgpt.com"], Ok(resolved(&[Ipv4Addr::new(1, 2, 3, 4)])))
            .with_direct_fake_ip(Arc::clone(&claiming) as Arc<dyn DirectFakeIpAnswerer>);
        let q = query("habr.com", QTYPE_A);
        let real = Ipv4Addr::new(178, 248, 237, 68);
        let reply = reply_for("habr.com", &[real]);
        let out = l.fake_direct_response(&q, &reply).expect("claimed");
        match crate::dns_wire::parse_a_response(0x1234, "habr.com", &out) {
            crate::dns_wire::AResponseOutcome::Answers { addresses, .. } => {
                assert_eq!(
                    addresses,
                    vec![fake],
                    "client is handed the virtual address"
                );
            }
            other => panic!("expected Answers, got {other:?}"),
        }
        // The answerer saw the FINAL (steered) real set — what the relay dials.
        let seen = claiming.seen.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(seen.as_slice(), &[("habr.com".to_string(), vec![real])]);
    }

    #[test]
    fn direct_fake_declines_leave_the_gate_path_in_charge() {
        // Default (Noop) answerer → never claims → caller falls back to the
        // gate + steered-reply path.
        let l = listener(&["chatgpt.com"], Ok(resolved(&[Ipv4Addr::new(1, 2, 3, 4)])));
        let q = query("habr.com", QTYPE_A);
        let reply = reply_for("habr.com", &[Ipv4Addr::new(178, 248, 237, 68)]);
        assert_eq!(l.fake_direct_response(&q, &reply), None);
        // Even a claiming answerer must not rewrite an NXDOMAIN / error reply.
        let claiming = Arc::new(ClaimingFake {
            fake: Ipv4Addr::new(198, 18, 0, 7),
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let l = listener(&["chatgpt.com"], Ok(resolved(&[Ipv4Addr::new(1, 2, 3, 4)])))
            .with_direct_fake_ip(claiming as Arc<dyn DirectFakeIpAnswerer>);
        let nx = crate::dns_wire::build_error_response(&q, RCODE_NXDOMAIN).expect("nx");
        assert_eq!(l.fake_direct_response(&q, &nx), None);
    }

    // ── Collateral rescue — fully pinned direct host → virtual address ───────

    struct StubCompanions(&'static str);
    impl CompanionCandidateLookup for StubCompanions {
        fn is_pending_secondary_companion(&self, hostname: &str) -> bool {
            hostname == self.0
        }
    }

    #[test]
    fn a_parked_companion_suggestion_vetoes_the_collateral_rescue() {
        let l = listener(
            &["instagram.com"],
            Ok(resolved(&[Ipv4Addr::new(1, 2, 3, 4)])),
        )
        .with_companion_candidates(Arc::new(StubCompanions("static.cdninstagram.com")));
        // The CDN of a site routed over the additional link: it belongs there,
        // not on the primary, whatever addresses it shares.
        assert!(l.companion_is_pending(&query("static.cdninstagram.com", QTYPE_A)));
        // An unrelated direct host stays collateral.
        assert!(!l.companion_is_pending(&query("habr.com", QTYPE_A)));
    }

    #[test]
    fn collateral_fake_rewrites_a_fully_pinned_reply() {
        let fake = Ipv4Addr::new(198, 18, 0, 9);
        let claiming = Arc::new(ClaimingFake {
            fake,
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let l = listener(
            &["aistudio.google.com"],
            Ok(resolved(&[Ipv4Addr::new(1, 2, 3, 4)])),
        )
        .with_collateral_fake_ip(Arc::clone(&claiming) as Arc<dyn DirectFakeIpAnswerer>);
        let q = query("workspace.google.com", QTYPE_A);
        let pinned = Ipv4Addr::new(64, 233, 163, 100);
        let reply = reply_for("workspace.google.com", &[pinned]);
        let out = l.fake_collateral_response(&q, &reply).expect("claimed");
        match crate::dns_wire::parse_a_response(0x1234, "workspace.google.com", &out) {
            crate::dns_wire::AResponseOutcome::Answers { addresses, .. } => {
                assert_eq!(addresses, vec![fake], "client gets the virtual address");
            }
            other => panic!("expected Answers, got {other:?}"),
        }
        // The rescue recorded the pinned real set — what the relay must dial
        // (out the primary; the route selector maps a non-rule host there).
        let seen = claiming.seen.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(
            seen.as_slice(),
            &[("workspace.google.com".to_string(), vec![pinned])]
        );
    }

    #[test]
    fn collateral_fake_defaults_to_noop_and_skips_error_replies() {
        // Default (Noop) → never claims → the old fail-open path stands.
        let l = listener(&["chatgpt.com"], Ok(resolved(&[Ipv4Addr::new(1, 2, 3, 4)])));
        let q = query("workspace.google.com", QTYPE_A);
        let reply = reply_for("workspace.google.com", &[Ipv4Addr::new(64, 233, 163, 100)]);
        assert_eq!(l.fake_collateral_response(&q, &reply), None);
        // A claiming answerer must not rewrite an NXDOMAIN / error reply.
        let claiming = Arc::new(ClaimingFake {
            fake: Ipv4Addr::new(198, 18, 0, 9),
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let l = listener(&["chatgpt.com"], Ok(resolved(&[Ipv4Addr::new(1, 2, 3, 4)])))
            .with_collateral_fake_ip(claiming as Arc<dyn DirectFakeIpAnswerer>);
        let nx = crate::dns_wire::build_error_response(&q, RCODE_NXDOMAIN).expect("nx");
        assert_eq!(l.fake_collateral_response(&q, &nx), None);
    }
    // ── Per-datagram budget ──────────────────────────────────────────────────

    #[test]
    fn the_budget_cuts_a_forward_short_of_its_own_timeout() {
        // The stage timeout is the ceiling, the budget is the floor of the two:
        // spending two seconds on a client that re-asked a second ago is spent
        // for nobody.
        let l = DnsInterceptListener::new(
            Arc::new(Oracle(Vec::new())),
            Arc::new(Upstream(Ok(resolved(&[])))),
            Arc::new(NoopSink),
            Arc::new(OkReconciler),
            "192.0.2.1:53".parse().expect("test-net address"),
            Duration::from_millis(150),
            Duration::from_secs(2),
        );
        let started = Instant::now();
        assert_eq!(
            l.forward_within(&query("example.com", QTYPE_A), Duration::from_millis(200)),
            None
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the 2 s forward timeout must not outlive a 200 ms budget (took {:?})",
            started.elapsed()
        );
    }

    #[test]
    fn an_exhausted_budget_forwards_nothing_at_all() {
        let l = listener(&[], Ok(resolved(&[])));
        let started = Instant::now();
        assert_eq!(
            l.forward_within(&query("example.com", QTYPE_A), Duration::ZERO),
            None
        );
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn a_failed_forward_answers_servfail_instead_of_saying_nothing() {
        // Silence makes the client wait out its own timeout on top of ours; the
        // answer it is waiting for is not coming either way.
        let l = listener(&[], Ok(resolved(&[])));
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("server socket");
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client socket");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("client timeout");
        let q = query("example.com", QTYPE_A);
        l.handle_datagram(&server, &q, client.local_addr().expect("client addr"));
        let mut buf = [0u8; 512];
        let n = client.recv(&mut buf).expect("a reply, not silence");
        assert!(n >= 12);
        assert_eq!(buf[0..2], q[0..2], "same transaction id");
        assert_eq!(buf[2] & 0x80, 0x80, "QR set");
        assert_eq!(buf[3] & 0x0F, RCODE_SERVFAIL);
    }
}
