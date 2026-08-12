//! local DNS resolver query-handler CORE.
//!
//! The pure, port-abstracted heart of the "resolver" enforcement mode
//! ([`nrr_domain::enforcement_mode::EnforcementMode::Resolver`]). It encodes the
//! ordering invariant that closes the reactive first-contact gap (see
//! `DNS_RESOLVER_DESIGN.md` §5.3):
//!
//! ```text
//! upstream A  →  cache upsert  →  reconcile (route+WFP installed)  →  answer returned  →  app connects
//! ```
//!
//! - For a **non-rule host** (the vast majority) the handler FAILS OPEN: it
//!   resolves upstream and returns the answer with zero policy work, so the
//!   resolver never becomes a single point of failure for general DNS.
//! - For a **rule host** it records the freshly-resolved IPs into the FQDN cache
//!   and drives a SYNCHRONOUS, bounded reconcile BEFORE returning the answer, so
//!   the app cannot send a packet before enforcement exists.
//! - If the reconcile misses its deadline the handler still returns the answer
//!   (**fail-open on latency**) and lets the async safety-net tick converge; a
//!   slow install beats a stalled browser.
//!
//! This module is deliberately mechanism-free. The listener (`hickory-server`),
//! the upstream engine (`hickory-resolver` / `DnsQuery_W`), the cache, and the
//! awaitable reconcile are injected as traits and wired in later increments
//! (1b–1d). Everything here is synchronous, neutral, and unit-tested with fakes.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpScope};

use crate::dns_address_sanity::{classify_answer, rejected_addresses, AnswerSanity};

/// Firefox's DoH "canary" domain. When
/// a network answers this name with NXDOMAIN, Firefox disables its own
/// application-level DNS-over-HTTPS and falls back to the system resolver (see
/// Mozilla's "canary domain" contract). Returning NXDOMAIN here — regardless of
/// what upstream says — de-blinds our DNS observer for Firefox users without
/// touching the WFP layer. Chromium honours a group-policy signal, not a canary,
/// so it is handled by the WFP DoH/DoT lockdown instead.
///
/// Case-insensitive match on the apex and any subdomain.
pub(crate) const DOH_CANARY_DOMAIN: &str = "use-application-dns.net";

/// `true` when `hostname` is the Firefox DoH canary apex or a subdomain of it.
pub(crate) fn is_doh_canary(hostname: &str) -> bool {
    let h = hostname.trim_end_matches('.').to_ascii_lowercase();
    h == DOH_CANARY_DOMAIN || h.ends_with(&format!(".{DOH_CANARY_DOMAIN}"))
}

/// Is a queried hostname a SECONDARY rule host for the active principal? The
/// production impl (increment 1b) reuses the existing policy match
/// (`dns_observation_consumer::rule_set_matches` + `match_zone`); a query that
/// matches no secondary rule takes the fail-open path.
pub trait RuleHostOracle: Send + Sync {
    fn is_rule_host(&self, hostname: &str) -> bool;
}

/// Block D (fake-IP, slice 4) — decides whether a rule host is answered with a
/// **virtual** (fake) address instead of its real ones.
///
/// When fake-IP is on and `hostname` is in scope (broadly on, minus the
/// peer-to-peer/crypto exclusions), the production impl allocates the host's
/// stable fake address(es) from the [`FakeIpAllocator`] and returns them here.
/// The resolver still resolves and caches the REAL addresses first (the relay
/// needs them to reach the upstream) — this only changes what the *application*
/// is handed, so it connects to the fake address, the TUN catches the flow, and
/// the relay steers it per-hostname without pinning the shared real IP.
///
/// `None` means "not in fake-IP scope" — the query takes the normal per-IP
/// enforcement path unchanged.
///
/// [`FakeIpAllocator`]: nrr_platform_api::fake_ip::FakeIpAllocator
pub trait FakeIpAnswerer: Send + Sync {
    fn fake_answer(&self, hostname: &str) -> Option<Vec<Ipv4Addr>>;
}

/// Fake-IP disabled / off-scope everywhere: every query takes the real per-IP
/// path. The default wired when the feature is off.
pub struct NoopFakeIpAnswerer;

impl FakeIpAnswerer for NoopFakeIpAnswerer {
    fn fake_answer(&self, _hostname: &str) -> Option<Vec<Ipv4Addr>> {
        None
    }
}

/// A [`FakeIpAnswerer`] gated by a LIVE predicate: it hands out a fake address
/// only while `gate()` is true, and takes the real path otherwise.
///
/// The production wiring (S4.4-rest) gates on "is the fake-IP TUN stack actually
/// running?" (`FakeIpController::is_running`), NOT merely on the persisted
/// toggle — so a host is answered with a virtual address only when the relay is
/// up to carry it. If the driver is missing, the stack is still coming up, or
/// the feature is off, the gate is false and every query transparently uses its
/// real address: fake-IP can never black-hole traffic by handing out an address
/// nothing is listening on. Fail-open by construction, and the reason the same
/// `answerer()` can be wired unconditionally without a resolver restart on every
/// toggle — the gate flips, the wiring does not.
pub struct GatedFakeIpAnswerer {
    inner: Arc<dyn FakeIpAnswerer>,
    gate: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl GatedFakeIpAnswerer {
    #[must_use]
    pub fn new(inner: Arc<dyn FakeIpAnswerer>, gate: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        Self { inner, gate }
    }
}

impl FakeIpAnswerer for GatedFakeIpAnswerer {
    fn fake_answer(&self, hostname: &str) -> Option<Vec<Ipv4Addr>> {
        if !(self.gate)() {
            return None;
        }
        self.inner.fake_answer(hostname)
    }
}

/// Production [`FakeIpAnswerer`]: a [`FakeIpScope`] decides *whether* a host is
/// in scope, a shared [`FakeIpAllocator`] hands out its *stable* fake address.
///
/// The allocator is shared (`Arc<Mutex<…>>`) with the userspace stack's relay:
/// the answerer allocates a hostname's fake address on the DNS query, and the
/// stack looks that same address back up to the hostname when a packet arrives
/// — so the two must see one map.
///
/// The scope decision is made with `app_group = None`: a plain DNS query has no
/// attributable process, so the peer-to-peer/crypto app-group exclusion cannot
/// fire here. That is acceptable — those clients talk to bare IPs and rarely
/// resolve by name at all — and the host/literal/non-routable exclusions still
/// apply. Pool exhaustion falls open to the real path rather than failing the
/// query.
pub struct ScopedFakeIpAnswerer {
    scope: FakeIpScope,
    allocator: Arc<Mutex<FakeIpAllocator>>,
    runtime_exclusions: Arc<crate::fake_ip::RuntimeHostExclusions>,
    health: Arc<crate::fake_ip::FakeIpHealth>,
}

impl ScopedFakeIpAnswerer {
    #[must_use]
    pub fn new(scope: FakeIpScope, allocator: Arc<Mutex<FakeIpAllocator>>) -> Self {
        Self {
            scope,
            allocator,
            runtime_exclusions: Arc::new(crate::fake_ip::RuntimeHostExclusions::new()),
            health: Arc::new(crate::fake_ip::FakeIpHealth::new()),
        }
    }

    /// Share a runtime exclusion set (VPN self-heal) — a host it names keeps its
    /// real address even though it is otherwise in scope. Builder-style; the
    /// default is an empty set that never excludes.
    #[must_use]
    pub fn with_runtime_exclusions(
        mut self,
        exclusions: Arc<crate::fake_ip::RuntimeHostExclusions>,
    ) -> Self {
        self.runtime_exclusions = exclusions;
        self
    }

    /// Share the datapath-health counters so every handed-out virtual address
    /// feeds the relay watchdog. Builder-style; the default is a private
    /// counter nobody reads.
    #[must_use]
    pub fn with_health(mut self, health: Arc<crate::fake_ip::FakeIpHealth>) -> Self {
        self.health = health;
        self
    }
}

impl FakeIpAnswerer for ScopedFakeIpAnswerer {
    fn fake_answer(&self, hostname: &str) -> Option<Vec<Ipv4Addr>> {
        if !self.scope.decide(hostname, None).is_fake_ip() {
            return None;
        }
        // A runtime exclusion (a host the VPN self-heal moved back to its real
        // address) wins over the scope: fall open to the real path.
        if self.runtime_exclusions.contains(hostname) {
            return None;
        }
        // Poison-tolerant: a panic mid-allocation must not wedge DNS. Allocation
        // is stable/idempotent — the same hostname always maps to one address.
        let mut allocator = self.allocator.lock().unwrap_or_else(|p| p.into_inner());
        match allocator.allocate(hostname) {
            Ok(binding) => {
                self.health.record_answer();
                Some(vec![binding.v4])
            }
            // Pool full and un-recyclable → fall open to the real address rather
            // than NXDOMAIN the host.
            Err(_) => None,
        }
    }
}

/// A successful upstream `A`-record resolution: the addresses plus the record
/// TTL. The TTL is honored when the fact is cached (see `DNS_RESOLVER_DESIGN.md`
/// §7), so a rotating host re-installs enforcement on re-query after expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedA {
    pub addresses: Vec<Ipv4Addr>,
    pub ttl_seconds: u32,
}

/// Resolve a hostname's IPv4 addresses upstream. The upstream MUST be the
/// system-configured servers captured *before* the DNS redirect (to preserve
/// split-horizon / corporate zones), not a hardcoded public resolver. The
/// production impl wraps `DnsResolverPort::resolve_a`.
pub trait UpstreamResolver: Send + Sync {
    fn resolve_a(&self, hostname: &str) -> Result<ResolvedA, ResolveError>;
}

/// Record a freshly-resolved `hostname → IPs` fact into the FQDN cache (union
/// semantics — re-seeing a pair extends its lifetime, never replaces). The
/// production impl wraps `CacheRepository::upsert_resolution` with
/// `StorageResolutionSource::Dns`, and drops non-routable answers via
/// `net_filter::is_non_routable_v4` before recording.
pub trait FactSink: Send + Sync {
    fn record(&self, hostname: &str, resolved: &ResolvedA);

    /// the IPs already cached for `hostname`.
    /// Feeds [`stable_answer_subset`]: the resolver prefers answering with
    /// addresses that are ALREADY pinned, so the enforced set converges to a
    /// small stable core instead of accumulating the CDN's whole rotating
    /// pool. Defaults to empty (no preference) for tests/mocks.
    fn cached_routable_ips(&self, _hostname: &str) -> Vec<Ipv4Addr> {
        Vec::new()
    }
}

/// the set of IPv4 addresses currently owned by
/// the active principal's SECONDARY rules (the pinned/committed set). The
/// listener steers DIRECT-host answers with it: an upstream answer for a
/// non-rule host is filtered so the client never gets an address the
/// kill-switch pins to the secondary — the DNS-level cure for the shared-CDN
/// collateral (0719: www.google.com handed the same front-end IPs as
/// gemini/youtube secondary rules). Production memoizes over the rule book ×
/// FQDN cache; the default empty set disables steering.
pub trait SecondaryOwnedIps: Send + Sync {
    fn secondary_owned_ips(&self) -> std::collections::HashSet<Ipv4Addr>;
}

/// No-op [`SecondaryOwnedIps`]: empty set → direct-answer steering disabled.
pub struct NoopSecondaryOwnedIps;

impl SecondaryOwnedIps for NoopSecondaryOwnedIps {
    fn secondary_owned_ips(&self) -> std::collections::HashSet<Ipv4Addr> {
        std::collections::HashSet::new()
    }
}

/// gate a DIRECT (non-rule) host's steered answer on the
/// kill-switch block-all. The production impl registers the answered
/// addresses as known-direct and drives a bounded reconcile so the exemption
/// is installed BEFORE the client receives the answer — otherwise the app's
/// first connect races the catch-all and is dropped with no retry (the ALE
/// deny is instant; the habr.com case). Must be a fast no-op while the
/// block-all is not armed: this sits on the hot path of every direct `A`
/// answer in Mode B.
pub trait DirectAnswerGate: Send + Sync {
    fn gate(&self, hostname: &str, addresses: &[Ipv4Addr]);
}

/// No-op [`DirectAnswerGate`]: direct answers are never gated (strict
/// block-all posture / tests).
pub struct NoopDirectAnswerGate;

impl DirectAnswerGate for NoopDirectAnswerGate {
    fn gate(&self, _hostname: &str, _addresses: &[Ipv4Addr]) {}
}

/// answer a DIRECT (non-rule) host with a virtual
/// address while the fail-closed block-all is armed and fake-IP is active.
///
/// The gate-based exemption path ([`DirectAnswerGate`]) has an unavoidable
/// race: the exemption is a WFP recompile, and when it misses its budget the
/// first connect dies against the catch-all (92% of gates in the 0722 boot
/// log). Handing the client a fake address removes the race by construction —
/// the static pool permit is already installed, the TUN catches the flow, and
/// the relay dials the real address out the primary while the client waits
/// inside its handshake. Slow beats severed.
///
/// The impl MUST register `real` (the final, already steered answer set)
/// where the relay's upstream resolver can find it BEFORE returning the fake
/// address — the client's first packet may reach the TUN immediately.
///
/// `None` means "not claimed": feature off, block-all not armed, host
/// excluded from scope, or pool exhausted. The caller then falls back to the
/// gate + real-answer path unchanged.
pub trait DirectFakeIpAnswerer: Send + Sync {
    fn fake_direct_answer(&self, hostname: &str, real: &[Ipv4Addr]) -> Option<Vec<Ipv4Addr>>;
}

/// No-op [`DirectFakeIpAnswerer`]: direct hosts always take the real-answer
/// (steer + gate) path. The default when fake-IP is off or unavailable.
pub struct NoopDirectFakeIp;

impl DirectFakeIpAnswerer for NoopDirectFakeIp {
    fn fake_direct_answer(&self, _hostname: &str, _real: &[Ipv4Addr]) -> Option<Vec<Ipv4Addr>> {
        None
    }
}

/// Answers "is this direct host already suspected of belonging to a site the
/// user routes over the additional link?".
///
/// The collateral rescue exists for a host that merely *shares an address* with
/// a rule — an unrelated site caught in the crossfire, which belongs on the
/// primary. A host the companion detector has already parked as a suggestion is
/// the opposite case: it keeps appearing as part of that routed site, so pushing
/// it onto the primary breaks the very page the suggestion is meant to fix, and
/// does so while the user has not been asked yet.
pub trait CompanionCandidateLookup: Send + Sync {
    fn is_pending_secondary_companion(&self, hostname: &str) -> bool;
}

/// No-op [`CompanionCandidateLookup`]: nothing is ever a pending companion, so
/// the collateral rescue behaves exactly as it did before the port existed.
pub struct NoopCompanionCandidates;

impl CompanionCandidateLookup for NoopCompanionCandidates {
    fn is_pending_secondary_companion(&self, _hostname: &str) -> bool {
        false
    }
}

/// Reports a shared-address host under its OWN name. Every other route to the
/// engine names it by reverse lookup and reports the anchor instead, which the
/// ledger drops — a site cannot be its own companion.
pub trait CompanionRescueObserver: Send + Sync {
    fn note_rescued_companion(&self, hostname: &str);
}

/// No-op [`CompanionRescueObserver`] — the rescue reports nothing.
pub struct NoopCompanionRescue;

impl CompanionRescueObserver for NoopCompanionRescue {
    fn note_rescued_companion(&self, _hostname: &str) {}
}

/// cap on the `A` records a RULE-host answer
/// carries. Small enough to keep the pinned set from absorbing a CDN's whole
/// pool, large enough for client-side connection resilience.
pub const MAX_RULE_ANSWER_IPS: usize = 4;

/// Choose the addresses a rule-host answer carries: prefer addresses already
/// cached/pinned (`cached`), fill the remainder from the fresh upstream
/// answer, cap at `cap`. Preserves upstream order within each group; returns
/// the full resolved set unchanged when it already fits the cap. Pure.
pub fn stable_answer_subset(
    resolved: &[Ipv4Addr],
    cached: &[Ipv4Addr],
    cap: usize,
) -> Vec<Ipv4Addr> {
    if resolved.len() <= cap {
        return resolved.to_vec();
    }
    let mut out: Vec<Ipv4Addr> = Vec::with_capacity(cap);
    for ip in resolved.iter().filter(|ip| cached.contains(ip)) {
        if out.len() == cap {
            return out;
        }
        out.push(*ip);
    }
    for ip in resolved.iter().filter(|ip| !cached.contains(ip)) {
        if out.len() == cap {
            return out;
        }
        out.push(*ip);
    }
    out
}

/// Trigger the enforcement reconcile and BLOCK until the routes/filters for the
/// active user are installed, bounded by `deadline`. The production impl is the
/// awaitable reconcile (increment 1d, the P0-B on-ramp). Returns whether install
/// was confirmed within the deadline.
pub trait SyncReconciler: Send + Sync {
    fn reconcile_now(&self, deadline: Duration) -> ReconcileOutcome;

    /// Kick the reconcile WITHOUT waiting for it (the fast-answers path:
    /// every answered address is already cached-routable, so the answer does
    /// not need to block on confirmation, but the facts just recorded should
    /// still converge promptly). Default: a zero-deadline `reconcile_now`,
    /// which registers the request and returns immediately.
    fn request_reconcile(&self) {
        let _ = self.reconcile_now(Duration::ZERO);
    }
}

/// Result of a bounded synchronous reconcile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// Enforcement confirmed installed within the deadline — the answer that
    /// follows is fully covered.
    Installed,
    /// Deadline elapsed before confirmation. The handler answers anyway
    /// (fail-open on latency); the async safety tick converges shortly after.
    DeadlineExceeded,
    /// Fast-answers path: the answer was returned immediately because every
    /// answered address was already cached-routable; the reconcile was
    /// requested but deliberately not awaited.
    Deferred,
}

/// Why an upstream resolution did not yield addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// Upstream returned NXDOMAIN / no `A` records.
    NoRecords,
    /// Upstream unreachable / timed out.
    Unavailable(String),
}

/// Outcome of handling one `A` query under [`EnforcementMode::Resolver`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryOutcome {
    /// Answer to return to the app. `enforced` is `true` only for a rule host
    /// whose reconcile confirmed install BEFORE this answer (the gap-closing
    /// guarantee); `false` for a fail-open non-rule host OR a rule host that hit
    /// the latency deadline.
    Answer { ips: Vec<Ipv4Addr>, enforced: bool },
    /// Upstream resolution failed — propagate as a DNS failure to the app.
    Upstream(ResolveError),
}

/// The last two labels of `host` (the whole name when it has fewer).
fn origin_suffix(host: &str) -> &str {
    match host.rmatch_indices('.').nth(1) {
        Some((idx, _)) => &host[idx + 1..],
        None => host,
    }
}

/// Do two hostnames plausibly belong to one origin? True when they are equal,
/// one is a subdomain of the other, or both end in the same two labels — enough
/// to keep an ordinary shared front end (`static.whatsapp.net` /
/// `crashlogs.whatsapp.net`) from being reported as a cross-host collision.
/// Pure.
pub(crate) fn hosts_share_origin(a: &str, b: &str) -> bool {
    let a = a.trim_end_matches('.').to_ascii_lowercase();
    let b = b.trim_end_matches('.').to_ascii_lowercase();
    if a == b {
        return true;
    }
    if a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}")) {
        return true;
    }
    origin_suffix(&a) == origin_suffix(&b)
}

/// Log-friendly, stable description of why an upstream resolve did not yield
/// addresses — used as the `reason` field of the per-query diagnostic line
/// ([`handle_a_query`]). Pure and side-effect-free so the mapping is unit-tested
/// without standing up a `tracing` subscriber. The `Unavailable` detail already
/// distinguishes timeout / refused / truncated / network error (see
/// `dns_resolver_ports::DirectUdpUpstreamResolver`), so it is surfaced verbatim.
fn describe_resolve_failure(err: &ResolveError) -> String {
    match err {
        ResolveError::NoRecords => "nxdomain/no-records".to_string(),
        ResolveError::Unavailable(detail) => format!("unavailable: {detail}"),
    }
}

/// How long a rule-host answer may be held for the enforcement reconcile, and
/// whether the fast-answers path may skip the hold entirely when every
/// answered address is already cached-routable.
#[derive(Clone, Copy, Debug)]
pub struct AnswerHold {
    /// Upper bound on the synchronous reconcile wait.
    pub deadline: Duration,
    /// When `true`, an answer whose addresses are all cached-routable is
    /// returned immediately (reconcile requested, not awaited).
    pub fast_answers: bool,
}

/// Handle a single `A` query.
///
/// Ordering (rule host): resolve upstream → `sink.record` → `reconciler.reconcile_now`
/// → return. The record + reconcile strictly precede the returned answer, so the
/// install happens-before the app can connect — the core invariant of Mode B.
///
/// Emits one per-query DEBUG line on target `nrr::dns-resolver` (gated by the
/// service verbose toggle / `NRR_LOG`; never at info level, so normal operation
/// stays quiet). Diagnostics logs may carry hostnames/IPs per the project's
/// redaction exception. The upstream server address is not visible here — it is
/// logged at the port layer (`dns_resolver_ports`).
pub fn handle_a_query(
    hostname: &str,
    hold: AnswerHold,
    oracle: &dyn RuleHostOracle,
    upstream: &dyn UpstreamResolver,
    sink: &dyn FactSink,
    reconciler: &dyn SyncReconciler,
    fake_ip: &dyn FakeIpAnswerer,
) -> QueryOutcome {
    // Upstream resolve is needed for BOTH paths — do it first.
    let resolved = match upstream.resolve_a(hostname) {
        Ok(r) => r,
        Err(e) => {
            let reason = describe_resolve_failure(&e);
            tracing::debug!(
                target: "nrr::dns-resolver",
                host = %hostname,
                reason = %reason,
                "Mode B: upstream A resolve failed — propagating DNS failure to the app",
            );
            return QueryOutcome::Upstream(e);
        }
    };

    // Fail-open: a non-rule host (the majority) returns immediately with no
    // policy work, so general DNS never depends on enforcement health.
    if !oracle.is_rule_host(hostname) {
        tracing::debug!(
            target: "nrr::dns-resolver",
            host = %hostname,
            rule_host = false,
            addresses = ?resolved.addresses,
            "Mode B: pass-through (non-rule host) — resolved upstream and answering, no policy work (fail-open)",
        );
        return QueryOutcome::Answer {
            ips: resolved.addresses,
            enforced: false,
        };
    }

    // A filtering provider answers a name it blocks with a placeholder instead
    // of refusing it. Whatever cannot be a destination must never become a
    // route or a packet filter, so screen the answer BEFORE any of it is
    // remembered — this is the last gate, and it needs no network.
    let upstream_count = resolved.addresses.len();
    let ttl_seconds = resolved.ttl_seconds;
    let sanity = classify_answer(&resolved.addresses);
    let usable = match sanity {
        AnswerSanity::Clean => resolved.addresses,
        AnswerSanity::Sanitized { keep } => {
            tracing::info!(
                target: "nrr::dns-resolver",
                host = %hostname,
                dropped = ?rejected_addresses(&resolved.addresses),
                kept = ?keep,
                "rule-host answer carried addresses that cannot be a destination — dropped from enforcement",
            );
            keep
        }
        // Nothing survived, and the second-source confirmation upstream of here
        // could not replace it. Answering the client costs nothing (the name is
        // blocked either way); pinning would build enforcement on a fiction.
        AnswerSanity::Unusable => {
            tracing::warn!(
                target: "nrr::dns-resolver",
                host = %hostname,
                rejected = ?rejected_addresses(&resolved.addresses),
                "rule-host answer holds no address that could be a destination — answering the client but NOT pinning it to enforcement",
            );
            return QueryOutcome::Answer {
                ips: resolved.addresses,
                enforced: false,
            };
        }
    };

    // Rule host: install enforcement BEFORE answering. П0-D — answer (and
    // record) a small STABLE subset of the fresh addresses, preferring ones
    // already cached: the client only ever connects to what we enforce, and
    // the pinned set converges to a few addresses instead of the CDN's whole
    // rotating pool (which is what dragged the Google front-end into the
    // kill-switch on 0719). Record the answered subset only, then drive the
    // synchronous bounded reconcile.
    // Remember the FULL answer, not just the subset we are about to hand out.
    // An app with its own address cache may connect to one of the addresses we
    // did not answer with; when that connection is dropped, this memory is what
    // ties the address back to its rule host so it can be enforced instead of
    // staying broken. See `recent_rule_addresses`.
    let displaced = crate::recent_rule_addresses::global_recent_rule_addresses()
        .record_displacing(hostname, &usable);
    // Two unrelated names answered with one identical address set is not a
    // resolution — it is an upstream handing out a stub. Enforcement still
    // proceeds (fail-open; the addresses may be a legitimately shared front
    // end we cannot prove otherwise), but the collision is surfaced.
    if let Some(other) = displaced.filter(|other| !hosts_share_origin(hostname, other)) {
        tracing::warn!(
            target: "nrr::dns-resolver",
            host = %hostname,
            also_answered_for = %other,
            addresses = ?usable,
            "upstream answered two unrelated hostnames with one identical address set — suspect a provider stub rather than a destination",
        );
    }
    let cached = sink.cached_routable_ips(hostname);
    let answered = stable_answer_subset(&usable, &cached, MAX_RULE_ANSWER_IPS);
    sink.record(
        hostname,
        &ResolvedA {
            addresses: answered.clone(),
            ttl_seconds,
        },
    );

    // Block D (fake-IP, slice 4) — if this host is in fake-IP scope, hand the
    // application its VIRTUAL address instead of the real ones. The real
    // addresses were just recorded, so the relay can reach the upstream; the app
    // connects to the fake address, the TUN catches the flow, and the relay
    // steers it per-hostname. No WFP reconcile here: fake-IP replaces per-IP
    // routing for scope hosts, and the kill-switch blocks the real addresses
    // separately so a cached / in-app-DoH real IP cannot leak past the fake.
    if let Some(fake) = fake_ip.fake_answer(hostname) {
        tracing::debug!(
            target: "nrr::dns-resolver",
            host = %hostname,
            rule_host = true,
            fake = ?fake,
            real = ?answered,
            "Mode B: fake-IP — answering with virtual address (real recorded for the relay), no per-IP reconcile",
        );
        return QueryOutcome::Answer {
            ips: fake,
            enforced: true,
        };
    }

    // Fast answers: hold the answer for the reconcile deadline
    // ONLY when it introduces an address the routable cache has never seen —
    // the one case where the app's first connect can race the route install.
    // When every answered address is already cached (the steady state:
    // `stable_answer_subset` prefers cached addresses by design), answer
    // immediately and let the reconcile converge in the background. Field
    // measurement: holding every answer blew the deadline on
    // 57% of queries and 1359 clients abandoned the query entirely — a
    // page-wide stall that bought nothing for already-routed addresses.
    let first_contact = answered.iter().any(|ip| !cached.contains(ip));
    let reconcile = if hold.fast_answers && !first_contact {
        reconciler.request_reconcile();
        ReconcileOutcome::Deferred
    } else {
        reconciler.reconcile_now(hold.deadline)
    };
    let enforced = matches!(reconcile, ReconcileOutcome::Installed);
    tracing::debug!(
        target: "nrr::dns-resolver",
        host = %hostname,
        rule_host = true,
        addresses = ?answered,
        upstream_count,
        first_contact,
        enforced,
        reconcile = ?reconcile,
        "Mode B: rule host resolved and reconciled before answering",
    );
    // Fail-open on latency: return the answer whether or not install confirmed.
    QueryOutcome::Answer {
        ips: answered,
        enforced,
    }
}

/// Process-wide fast-DNS-answers toggle.
///
/// Same singleton rationale as `dns_egress::global_dns_via_secondary`: the
/// settings writer that flips the value and the resolver that consults it per
/// query are built in different composition scopes, and a process singleton
/// keeps them on one value by construction. Defaults to `true` (answer
/// immediately when every answered address is already cached-routable); the
/// boot path overwrites it with the persisted setting before the resolver
/// serves its first query.
pub fn global_dns_fast_answers() -> Arc<std::sync::atomic::AtomicBool> {
    static FLAG: std::sync::OnceLock<Arc<std::sync::atomic::AtomicBool>> =
        std::sync::OnceLock::new();
    Arc::clone(FLAG.get_or_init(|| Arc::new(std::sync::atomic::AtomicBool::new(true))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records the order of side-effecting calls so tests can assert the
    /// enforce-before-answer ordering invariant.
    #[derive(Default)]
    struct CallLog(Mutex<Vec<&'static str>>);
    impl CallLog {
        fn push(&self, s: &'static str) {
            self.0.lock().unwrap_or_else(|p| p.into_inner()).push(s);
        }
        fn snapshot(&self) -> Vec<&'static str> {
            self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }
    }

    struct FakeOracle {
        rule_hosts: Vec<String>,
    }
    impl RuleHostOracle for FakeOracle {
        fn is_rule_host(&self, hostname: &str) -> bool {
            self.rule_hosts.iter().any(|h| h.as_str() == hostname)
        }
    }
    fn oracle(hosts: &[&str]) -> FakeOracle {
        FakeOracle {
            rule_hosts: hosts.iter().map(|s| s.to_string()).collect(),
        }
    }

    struct FakeUpstream {
        answer: Result<ResolvedA, ResolveError>,
    }
    impl UpstreamResolver for FakeUpstream {
        fn resolve_a(&self, _hostname: &str) -> Result<ResolvedA, ResolveError> {
            self.answer.clone()
        }
    }

    struct FakeSink<'a>(&'a CallLog);
    impl FactSink for FakeSink<'_> {
        fn record(&self, _hostname: &str, _resolved: &ResolvedA) {
            self.0.push("record");
        }
    }

    fn resolved(ips: &[Ipv4Addr]) -> ResolvedA {
        ResolvedA {
            addresses: ips.to_vec(),
            ttl_seconds: 300,
        }
    }

    struct FakeReconciler<'a> {
        log: &'a CallLog,
        outcome: ReconcileOutcome,
    }
    impl SyncReconciler for FakeReconciler<'_> {
        fn reconcile_now(&self, _deadline: Duration) -> ReconcileOutcome {
            self.log.push("reconcile");
            self.outcome
        }
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn shared_origin_covers_subdomains_and_a_common_registrable_tail() {
        assert!(hosts_share_origin("signal.me", "signal.me."));
        assert!(hosts_share_origin("web.whatsapp.com", "whatsapp.com"));
        assert!(hosts_share_origin(
            "static.whatsapp.net",
            "crashlogs.whatsapp.net"
        ));
        assert!(!hosts_share_origin("chatgpt.com", "signal.me"));
        assert!(!hosts_share_origin("a.example.com", "a.example.net"));
    }

    /// Answers a fixed set of hosts with a fixed fake address; everything else
    /// takes the real path.
    struct FakeFakeIp {
        scope: Vec<String>,
        fake: Ipv4Addr,
    }
    impl FakeIpAnswerer for FakeFakeIp {
        fn fake_answer(&self, hostname: &str) -> Option<Vec<Ipv4Addr>> {
            self.scope
                .iter()
                .any(|h| h == hostname)
                .then(|| vec![self.fake])
        }
    }

    #[test]
    fn describe_resolve_failure_labels_each_variant() {
        // Authoritative "no answer" gets a stable low-cardinality token.
        assert_eq!(
            describe_resolve_failure(&ResolveError::NoRecords),
            "nxdomain/no-records"
        );
        // Transient failures surface their detail (timeout / rcode / truncated)
        // verbatim so the diagnostic line pinpoints WHY the resolve failed.
        assert_eq!(
            describe_resolve_failure(&ResolveError::Unavailable("timeout".into())),
            "unavailable: timeout"
        );
        assert_eq!(
            describe_resolve_failure(&ResolveError::Unavailable("rcode 5".into())),
            "unavailable: rcode 5"
        );
    }

    #[test]
    fn non_rule_host_fails_open_without_touching_enforcement() {
        let log = CallLog::default();
        let out = handle_a_query(
            "example.com",
            AnswerHold {
                deadline: Duration::from_millis(150),
                fast_answers: false,
            },
            &oracle(&[]),
            &FakeUpstream {
                answer: Ok(resolved(&[ip(93, 184, 216, 34)])),
            },
            &FakeSink(&log),
            &FakeReconciler {
                log: &log,
                outcome: ReconcileOutcome::Installed,
            },
            &NoopFakeIpAnswerer,
        );
        assert_eq!(
            out,
            QueryOutcome::Answer {
                ips: vec![ip(93, 184, 216, 34)],
                enforced: false,
            }
        );
        // Fail-open path must NOT record facts or reconcile: general DNS never
        // depends on enforcement health.
        assert!(log.snapshot().is_empty());
    }

    /// The observed provider placeholder: one address pair, every octet ending
    /// in `.0`, handed out for any filtered name. Second-source confirmation
    /// upstream of the handler already failed, so nothing about it may reach
    /// enforcement — no cache fact, no reconcile, `enforced: false`. The client
    /// still gets the answer: the name is blocked either way.
    #[test]
    fn a_placeholder_only_answer_is_never_pinned() {
        let log = CallLog::default();
        let stub = [ip(8, 47, 69, 0), ip(8, 6, 112, 0)];
        let out = handle_a_query(
            "signal.me",
            AnswerHold {
                deadline: Duration::from_millis(150),
                fast_answers: false,
            },
            &oracle(&["signal.me"]),
            &FakeUpstream {
                answer: Ok(resolved(&stub)),
            },
            &FakeSink(&log),
            &FakeReconciler {
                log: &log,
                outcome: ReconcileOutcome::Installed,
            },
            &NoopFakeIpAnswerer,
        );
        assert_eq!(
            out,
            QueryOutcome::Answer {
                ips: stub.to_vec(),
                enforced: false,
            }
        );
        assert!(
            log.snapshot().is_empty(),
            "a placeholder must not be recorded or reconciled: {:?}",
            log.snapshot()
        );
        // ...and it must not become an enforceable memory for the drop-learner
        // either, or the next reconcile pins it anyway.
        assert!(crate::recent_rule_addresses::global_recent_rule_addresses()
            .lookup(stub[0])
            .is_none());
    }

    /// A reserved address next to a real one costs only itself: the host stays
    /// enforced on what is left.
    #[test]
    fn an_unusable_address_beside_a_real_one_is_dropped_and_the_host_stays_enforced() {
        let log = CallLog::default();
        let real = ip(142, 250, 74, 78);
        let out = handle_a_query(
            "rule.example",
            AnswerHold {
                deadline: Duration::from_millis(150),
                fast_answers: false,
            },
            &oracle(&["rule.example"]),
            &FakeUpstream {
                answer: Ok(resolved(&[ip(169, 254, 3, 4), real, ip(9, 9, 9, 0)])),
            },
            &FakeSink(&log),
            &FakeReconciler {
                log: &log,
                outcome: ReconcileOutcome::Installed,
            },
            &NoopFakeIpAnswerer,
        );
        assert_eq!(
            out,
            QueryOutcome::Answer {
                ips: vec![real],
                enforced: true,
            }
        );
        assert_eq!(log.snapshot(), vec!["record", "reconcile"]);
    }

    /// A [`FakeSink`] whose cache already knows a fixed set of addresses —
    /// drives the fast-answers "every answered address is cached" branch.
    struct CachedSink<'a> {
        log: &'a CallLog,
        cached: Vec<Ipv4Addr>,
    }
    impl FactSink for CachedSink<'_> {
        fn record(&self, _hostname: &str, _resolved: &ResolvedA) {
            self.log.push("record");
        }
        fn cached_routable_ips(&self, _hostname: &str) -> Vec<Ipv4Addr> {
            self.cached.clone()
        }
    }

    /// Reconciler that panics if awaited — proves the fast path never blocks
    /// on `reconcile_now`, only kicks `request_reconcile`.
    struct RequestOnlyReconciler<'a>(&'a CallLog);
    impl SyncReconciler for RequestOnlyReconciler<'_> {
        fn reconcile_now(&self, _deadline: Duration) -> ReconcileOutcome {
            panic!("fast path must not await reconcile_now");
        }
        fn request_reconcile(&self) {
            self.0.push("request_reconcile");
        }
    }

    #[test]
    fn fast_answers_skips_the_hold_when_every_answered_address_is_cached() {
        let log = CallLog::default();
        let addr = ip(172, 64, 155, 209);
        let out = handle_a_query(
            "chatgpt.com",
            AnswerHold {
                deadline: Duration::from_millis(150),
                fast_answers: true,
            },
            &oracle(&["chatgpt.com"]),
            &FakeUpstream {
                answer: Ok(resolved(&[addr])),
            },
            &CachedSink {
                log: &log,
                cached: vec![addr],
            },
            &RequestOnlyReconciler(&log),
            &NoopFakeIpAnswerer,
        );
        // Answered immediately; not `enforced` (install was not awaited), but
        // the reconcile was still requested so the facts converge.
        assert_eq!(
            out,
            QueryOutcome::Answer {
                ips: vec![addr],
                enforced: false,
            }
        );
        assert_eq!(log.snapshot(), ["record", "request_reconcile"]);
    }

    #[test]
    fn fast_answers_still_holds_on_first_contact_with_a_new_address() {
        let log = CallLog::default();
        let out = handle_a_query(
            "chatgpt.com",
            AnswerHold {
                deadline: Duration::from_millis(150),
                fast_answers: true,
            },
            &oracle(&["chatgpt.com"]),
            &FakeUpstream {
                answer: Ok(resolved(&[ip(172, 64, 155, 209)])),
            },
            // Cache is empty → the answer introduces a never-seen address and
            // the first connect could race the install: hold as before.
            &FakeSink(&log),
            &FakeReconciler {
                log: &log,
                outcome: ReconcileOutcome::Installed,
            },
            &NoopFakeIpAnswerer,
        );
        assert_eq!(
            out,
            QueryOutcome::Answer {
                ips: vec![ip(172, 64, 155, 209)],
                enforced: true,
            }
        );
        assert_eq!(log.snapshot(), ["record", "reconcile"]);
    }

    #[test]
    fn fast_answers_off_awaits_the_reconcile_even_for_cached_addresses() {
        let log = CallLog::default();
        let addr = ip(172, 64, 155, 209);
        let out = handle_a_query(
            "chatgpt.com",
            AnswerHold {
                deadline: Duration::from_millis(150),
                fast_answers: false,
            },
            &oracle(&["chatgpt.com"]),
            &FakeUpstream {
                answer: Ok(resolved(&[addr])),
            },
            &CachedSink {
                log: &log,
                cached: vec![addr],
            },
            &FakeReconciler {
                log: &log,
                outcome: ReconcileOutcome::Installed,
            },
            &NoopFakeIpAnswerer,
        );
        assert_eq!(
            out,
            QueryOutcome::Answer {
                ips: vec![addr],
                enforced: true,
            }
        );
        assert_eq!(log.snapshot(), ["record", "reconcile"]);
    }

    #[test]
    fn rule_host_records_then_reconciles_before_answering() {
        let log = CallLog::default();
        let out = handle_a_query(
            "chatgpt.com",
            AnswerHold {
                deadline: Duration::from_millis(150),
                fast_answers: false,
            },
            &oracle(&["chatgpt.com"]),
            &FakeUpstream {
                answer: Ok(resolved(&[ip(172, 64, 155, 209)])),
            },
            &FakeSink(&log),
            &FakeReconciler {
                log: &log,
                outcome: ReconcileOutcome::Installed,
            },
            &NoopFakeIpAnswerer,
        );
        assert_eq!(
            out,
            QueryOutcome::Answer {
                ips: vec![ip(172, 64, 155, 209)],
                enforced: true,
            }
        );
        // Ordering invariant: cache upsert happens-before reconcile, and the
        // function only returns after reconcile → install strictly precedes the
        // answer handed back to the app.
        assert_eq!(log.snapshot(), vec!["record", "reconcile"]);
    }

    #[test]
    fn rule_host_answers_but_unenforced_when_deadline_exceeded() {
        let log = CallLog::default();
        let out = handle_a_query(
            "chatgpt.com",
            AnswerHold {
                deadline: Duration::from_millis(150),
                fast_answers: false,
            },
            &oracle(&["chatgpt.com"]),
            &FakeUpstream {
                answer: Ok(resolved(&[ip(172, 64, 155, 209)])),
            },
            &FakeSink(&log),
            &FakeReconciler {
                log: &log,
                outcome: ReconcileOutcome::DeadlineExceeded,
            },
            &NoopFakeIpAnswerer,
        );
        // Fail-open on latency: still answer, but flagged unenforced. The fact
        // was recorded, so the async safety tick converges shortly after.
        assert_eq!(
            out,
            QueryOutcome::Answer {
                ips: vec![ip(172, 64, 155, 209)],
                enforced: false,
            }
        );
        assert_eq!(log.snapshot(), vec!["record", "reconcile"]);
    }

    #[test]
    fn stable_answer_subset_passes_small_sets_through() {
        let resolved = [ip(1, 1, 1, 1), ip(2, 2, 2, 2)];
        assert_eq!(
            stable_answer_subset(&resolved, &[], MAX_RULE_ANSWER_IPS),
            resolved.to_vec()
        );
    }

    #[test]
    fn stable_answer_subset_prefers_cached_then_fills_and_caps() {
        let resolved: Vec<Ipv4Addr> = (1..=6).map(|i| ip(10, 0, 0, i)).collect();
        // Two of the six are already cached — they must lead the answer.
        let cached = [ip(10, 0, 0, 5), ip(10, 0, 0, 3)];
        let out = stable_answer_subset(&resolved, &cached, 4);
        assert_eq!(
            out,
            vec![
                ip(10, 0, 0, 3),
                ip(10, 0, 0, 5),
                ip(10, 0, 0, 1),
                ip(10, 0, 0, 2)
            ],
            "cached first (upstream order), then fresh, capped at 4"
        );
    }

    #[test]
    fn stable_answer_subset_all_cached_caps_without_fresh() {
        let resolved: Vec<Ipv4Addr> = (1..=6).map(|i| ip(10, 0, 0, i)).collect();
        let out = stable_answer_subset(&resolved, &resolved, 4);
        assert_eq!(out.len(), 4);
        assert_eq!(out, resolved[..4].to_vec());
    }

    #[test]
    fn rule_host_answer_is_capped_to_stable_subset() {
        // Seven upstream addresses → the answer (and the recorded fact) must
        // carry only MAX_RULE_ANSWER_IPS of them.
        let log = CallLog::default();
        let many: Vec<Ipv4Addr> = (1..=7).map(|i| ip(172, 64, 155, i)).collect();
        let out = handle_a_query(
            "chatgpt.com",
            AnswerHold {
                deadline: Duration::from_millis(150),
                fast_answers: false,
            },
            &oracle(&["chatgpt.com"]),
            &FakeUpstream {
                answer: Ok(resolved(&many)),
            },
            &FakeSink(&log),
            &FakeReconciler {
                log: &log,
                outcome: ReconcileOutcome::Installed,
            },
            &NoopFakeIpAnswerer,
        );
        match out {
            QueryOutcome::Answer { ips, enforced } => {
                assert!(enforced);
                assert_eq!(ips.len(), MAX_RULE_ANSWER_IPS);
                assert_eq!(ips, many[..MAX_RULE_ANSWER_IPS].to_vec());
            }
            other => panic!("expected Answer, got {other:?}"),
        }
        assert_eq!(log.snapshot(), vec!["record", "reconcile"]);
    }

    #[test]
    fn fake_ip_scope_host_is_answered_with_the_virtual_address_and_skips_reconcile() {
        let log = CallLog::default();
        let out = handle_a_query(
            "chatgpt.com",
            AnswerHold {
                deadline: Duration::from_millis(150),
                fast_answers: false,
            },
            &oracle(&["chatgpt.com"]),
            &FakeUpstream {
                answer: Ok(resolved(&[ip(104, 18, 32, 47)])),
            },
            &FakeSink(&log),
            &FakeReconciler {
                log: &log,
                outcome: ReconcileOutcome::Installed,
            },
            &FakeFakeIp {
                scope: vec!["chatgpt.com".to_string()],
                fake: ip(198, 18, 0, 5),
            },
        );
        // The app gets the FAKE address, flagged enforced (the TUN + relay carry
        // the flow, no per-IP install needed).
        assert_eq!(
            out,
            QueryOutcome::Answer {
                ips: vec![ip(198, 18, 0, 5)],
                enforced: true,
            }
        );
        // The REAL address was still recorded (the relay needs it as upstream),
        // but there is NO reconcile — fake-IP replaces per-IP routing for scope.
        assert_eq!(log.snapshot(), vec!["record"]);
    }

    #[test]
    fn a_rule_host_outside_fake_ip_scope_keeps_the_real_per_ip_path() {
        let log = CallLog::default();
        let out = handle_a_query(
            "bank.example",
            AnswerHold {
                deadline: Duration::from_millis(150),
                fast_answers: false,
            },
            &oracle(&["bank.example"]),
            &FakeUpstream {
                answer: Ok(resolved(&[ip(93, 184, 216, 34)])),
            },
            &FakeSink(&log),
            &FakeReconciler {
                log: &log,
                outcome: ReconcileOutcome::Installed,
            },
            // Fake-IP is on, but this host is NOT in scope (e.g. a P2P/crypto
            // exclusion) → real address + normal reconcile.
            &FakeFakeIp {
                scope: vec!["chatgpt.com".to_string()],
                fake: ip(198, 18, 0, 5),
            },
        );
        assert_eq!(
            out,
            QueryOutcome::Answer {
                ips: vec![ip(93, 184, 216, 34)],
                enforced: true,
            }
        );
        assert_eq!(log.snapshot(), vec!["record", "reconcile"]);
    }

    #[test]
    fn scoped_answerer_gives_an_in_scope_host_a_stable_fake_address() {
        let allocator = Arc::new(Mutex::new(FakeIpAllocator::default()));
        let answerer =
            ScopedFakeIpAnswerer::new(FakeIpScope::enabled(Vec::<String>::new()), allocator);
        let first = answerer.fake_answer("chatgpt.com").expect("in scope");
        assert_eq!(first.len(), 1);
        assert!(first[0].to_string().starts_with("198.18."));
        // Idempotent: the same host always maps to the same fake address.
        assert_eq!(answerer.fake_answer("chatgpt.com"), Some(first.clone()));
        // A different host gets a different address.
        let other = answerer.fake_answer("claude.ai").expect("in scope");
        assert_ne!(other, first);
    }

    #[test]
    fn scoped_answerer_returns_none_when_disabled_or_excluded() {
        let allocator = Arc::new(Mutex::new(FakeIpAllocator::default()));
        // Feature off → real path.
        let off = ScopedFakeIpAnswerer::new(FakeIpScope::disabled(), Arc::clone(&allocator));
        assert_eq!(off.fake_answer("chatgpt.com"), None);
        // On, but the host is excluded / non-routable / a literal → real path.
        let on = ScopedFakeIpAnswerer::new(FakeIpScope::enabled(["bank.example"]), allocator);
        assert_eq!(on.fake_answer("api.bank.example"), None);
        assert_eq!(on.fake_answer("localhost"), None);
        assert_eq!(on.fake_answer("142.250.74.78"), None);
    }

    #[test]
    fn scoped_answerer_honours_a_runtime_exclusion() {
        let allocator = Arc::new(Mutex::new(FakeIpAllocator::default()));
        let exclusions = Arc::new(crate::fake_ip::RuntimeHostExclusions::new());
        let answerer =
            ScopedFakeIpAnswerer::new(FakeIpScope::enabled(Vec::<String>::new()), allocator)
                .with_runtime_exclusions(Arc::clone(&exclusions));
        // In scope before the exclusion.
        assert!(answerer.fake_answer("vpn.example.com").is_some());
        // The VPN self-heal excludes the server → the answerer falls open to the
        // real path (and covers subdomains).
        exclusions.insert("vpn.example.com");
        assert_eq!(answerer.fake_answer("vpn.example.com"), None);
        assert_eq!(answerer.fake_answer("gw1.vpn.example.com"), None);
        // An unrelated in-scope host is unaffected.
        assert!(answerer.fake_answer("chatgpt.com").is_some());
    }

    #[test]
    fn gated_answerer_defers_to_the_live_gate() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let up = Arc::new(AtomicBool::new(false));
        let gate_flag = Arc::clone(&up);
        let inner: Arc<dyn FakeIpAnswerer> = Arc::new(FakeFakeIp {
            scope: vec!["chatgpt.com".to_string()],
            fake: ip(198, 18, 0, 9),
        });
        let gated =
            GatedFakeIpAnswerer::new(inner, Arc::new(move || gate_flag.load(Ordering::SeqCst)));
        // Gate closed (stack down / feature off) → real path even for an
        // in-scope host: fake-IP never hands out an address nothing carries.
        assert_eq!(gated.fake_answer("chatgpt.com"), None);
        // Gate open (stack running) → the inner answerer decides.
        up.store(true, Ordering::SeqCst);
        assert_eq!(
            gated.fake_answer("chatgpt.com"),
            Some(vec![ip(198, 18, 0, 9)])
        );
        // Still nothing for an out-of-scope host — the gate only enables, the
        // inner answerer still scopes.
        assert_eq!(gated.fake_answer("example.com"), None);
    }

    #[test]
    fn upstream_failure_propagates_without_enforcement() {
        let log = CallLog::default();
        let out = handle_a_query(
            "chatgpt.com",
            AnswerHold {
                deadline: Duration::from_millis(150),
                fast_answers: false,
            },
            &oracle(&["chatgpt.com"]),
            &FakeUpstream {
                answer: Err(ResolveError::Unavailable("timeout".into())),
            },
            &FakeSink(&log),
            &FakeReconciler {
                log: &log,
                outcome: ReconcileOutcome::Installed,
            },
            &NoopFakeIpAnswerer,
        );
        assert_eq!(
            out,
            QueryOutcome::Upstream(ResolveError::Unavailable("timeout".into()))
        );
        // No fact recorded, no reconcile: nothing to enforce on a failed resolve.
        assert!(log.snapshot().is_empty());
    }
}
