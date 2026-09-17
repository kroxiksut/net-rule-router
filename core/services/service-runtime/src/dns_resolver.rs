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
//! awaitable reconcile are injected as traits and wired in separately.
//! Everything here is synchronous, neutral, and unit-tested with fakes.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpScope};

use crate::dns_address_sanity::{classify_answer, rejected_addresses, AnswerSanity};
use nrr_platform_api::dns::AddressFamily;

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
/// production impl reuses the existing policy match
/// (`dns_observation_consumer::rule_set_matches` + `match_zone`); a query that
/// matches no secondary rule takes the fail-open path.
pub trait RuleHostOracle: Send + Sync {
    fn is_rule_host(&self, hostname: &str) -> bool;
}

/// Is the leak guard currently BLOCKING because the additional link could not
/// be resolved? Read once per rule-host answer that missed its reconcile
/// deadline — a latch read, off the fast path.
///
/// The production impl mirrors
/// [`crate::app_enforcement_status::FailClosedPostureStatus`]; a caller wired
/// without one reports "not blocking" and keeps the historic fail-open.
pub trait LeakGuardPosture: Send + Sync {
    fn blocking(&self) -> bool;
}

/// Any `bool`-yielding closure is a posture — lets the composition root hand in
/// a latch read without declaring a type for it.
impl<F> LeakGuardPosture for F
where
    F: Fn() -> bool + Send + Sync,
{
    fn blocking(&self) -> bool {
        self()
    }
}

/// A posture that never blocks: the default for listeners wired without the
/// latch (tests, previews, the Linux daemon until it publishes one).
pub struct OpenLeakGuard;

impl LeakGuardPosture for OpenLeakGuard {
    fn blocking(&self) -> bool {
        false
    }
}

/// Fake-IP — decides whether a rule host is answered with a
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
    /// May a virtual address stand in for these real ones? `true` by default;
    /// see the production implementation for the one case that says no.
    fn may_substitute(&self, _real: &[Ipv4Addr]) -> bool {
        true
    }

    fn fake_answer(&self, hostname: &str) -> Option<Vec<Ipv4Addr>>;

    /// Would this hostname be answered with a virtual address — WITHOUT
    /// allocating one? [`fake_answer`](Self::fake_answer) takes a lease and
    /// records health, so it must never be used as a probe. The AAAA branch
    /// asks this to decide whether IPv4 can carry the name before suppressing
    /// its v6 answer. Default `false`: an implementation that does not know
    /// must not cause suppression.
    fn carries_on_v4(&self, _hostname: &str) -> bool {
        false
    }
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
/// The production wiring gates on "is the fake-IP TUN stack actually
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

    fn carries_on_v4(&self, hostname: &str) -> bool {
        (self.gate)() && self.inner.carries_on_v4(hostname)
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
    /// The additional route's own subnets, read live. See
    /// [`FakeIpAnswerer::may_substitute`].
    secondary_subnets: Option<SecondarySubnetsFn>,
}

/// Reads the subnets that belong to the additional route itself. A closure over
/// the route coordinator at the composition root, so this module never learns
/// what an adapter is.
pub type SecondarySubnetsFn =
    Arc<dyn Fn() -> Vec<nrr_domain::ipv4_network::Ipv4Network> + Send + Sync>;

impl ScopedFakeIpAnswerer {
    #[must_use]
    pub fn new(scope: FakeIpScope, allocator: Arc<Mutex<FakeIpAllocator>>) -> Self {
        Self {
            scope,
            allocator,
            runtime_exclusions: Arc::new(crate::fake_ip::RuntimeHostExclusions::new()),
            health: Arc::new(crate::fake_ip::FakeIpHealth::new()),
            secondary_subnets: None,
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

    /// Teach the answerer which subnets belong to the additional route itself,
    /// so it never substitutes an address inside them (see
    /// [`FakeIpAnswerer::may_substitute`]). Unwired means "substitute freely",
    /// which is the behaviour that existed before.
    #[must_use]
    pub fn with_secondary_subnets(mut self, read: SecondarySubnetsFn) -> Self {
        self.secondary_subnets = Some(read);
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
    /// Never substitute a virtual address for one that lives INSIDE the
    /// additional route's own subnet.
    ///
    /// Those addresses are the tunnel's own interior — the VPN client's
    /// authorization endpoint is a live example (`10.117.0.1` on a
    /// `10.88.0.0/10` tunnel). Handing out a virtual address for them points
    /// the caller at our TUN, where nothing serves the tunnel's own protocol,
    /// and the client concludes the connection failed. The relay cannot rescue
    /// it either: reaching the interior requires being inside the tunnel, which
    /// is what the caller was already doing.
    fn may_substitute(&self, real: &[Ipv4Addr]) -> bool {
        let Some(read) = self.secondary_subnets.as_ref() else {
            return true;
        };
        let subnets = read();
        !real
            .iter()
            .any(|ip| subnets.iter().any(|net| net.contains(*ip)))
    }

    fn carries_on_v4(&self, hostname: &str) -> bool {
        self.scope.decide(hostname, None).is_fake_ip()
            && !self.runtime_exclusions.contains(hostname)
    }

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

/// A successful upstream address resolution: the addresses plus the record
/// TTL. Every address belongs to the family that was asked for. The TTL is
/// honored when the fact is cached (see `DNS_RESOLVER_DESIGN.md` §7), so a
/// rotating host re-installs enforcement on re-query after expiry.
/// The v4 half of a [`ResolvedAddresses`], for the handlers that still act on
/// one family. Goes away with the address-rule work; until then it keeps the
/// narrowing in the type rather than at forty call sites.
struct ResolvedAddressesV4 {
    addresses: Vec<Ipv4Addr>,
    ttl_seconds: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedAddresses {
    pub addresses: Vec<IpAddr>,
    pub ttl_seconds: u32,
}

/// Resolve a hostname's addresses upstream. The upstream MUST be the
/// system-configured servers captured *before* the DNS redirect (to preserve
/// split-horizon / corporate zones), not a hardcoded public resolver. The
/// production impl wraps `DnsResolverPort::resolve`.
///
/// The family is an argument, not a second method: the intercept path asks for
/// the one the client asked about, so it never pays for a round trip it would
/// throw away.
pub trait UpstreamResolver: Send + Sync {
    fn resolve(
        &self,
        hostname: &str,
        _family: AddressFamily,
    ) -> Result<ResolvedAddresses, ResolveError>;
}

/// Record a freshly-resolved `hostname → IPs` fact into the FQDN cache (union
/// semantics — re-seeing a pair extends its lifetime, never replaces). The
/// production impl wraps `CacheRepository::upsert_resolution` with
/// `StorageResolutionSource::Dns`, and drops non-routable answers via
/// `net_filter::is_non_routable_v4` before recording.
pub trait FactSink: Send + Sync {
    fn record(&self, hostname: &str, resolved: &ResolvedAddresses);

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
/// collateral (e.g. a search front end handed the same front-end IPs as a
/// video-site secondary rule). Production memoizes over the rule book ×
/// FQDN cache; the default empty set disables steering.
pub trait SecondaryOwnedIps: Send + Sync {
    /// Handed out behind an `Arc`: the production impl memoizes one set and
    /// every DIRECT answer asks for it, so returning it by value copied the
    /// whole pinned set per DNS reply.
    fn secondary_owned_ips(&self) -> Arc<std::collections::HashSet<Ipv4Addr>>;
}

/// No-op [`SecondaryOwnedIps`]: empty set → direct-answer steering disabled.
pub struct NoopSecondaryOwnedIps;

impl SecondaryOwnedIps for NoopSecondaryOwnedIps {
    fn secondary_owned_ips(&self) -> Arc<std::collections::HashSet<Ipv4Addr>> {
        Arc::new(std::collections::HashSet::new())
    }
}

/// gate a DIRECT (non-rule) host's steered answer on the
/// kill-switch block-all. The production impl registers the answered
/// addresses as known-direct and drives a bounded reconcile so the exemption
/// is installed BEFORE the client receives the answer — otherwise the app's
/// first connect races the catch-all and is dropped with no retry (the ALE
/// deny is instant; the observed first-contact drop). Must be a fast no-op while the
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
/// first connect dies against the catch-all. Handing the client a fake
/// address removes the race by construction —
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
/// the collateral rescue never defers to it.
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
/// awaitable reconcile. Returns whether install was confirmed within the
/// deadline.
pub trait SyncReconciler: Send + Sync {
    fn reconcile_now(&self, deadline: Duration) -> ReconcileOutcome;

    /// Kick the reconcile WITHOUT waiting for it (the fast-answers path:
    /// every answered address is already enforced, so the answer does not need
    /// to block on confirmation, but the facts just recorded should still
    /// converge promptly). Default: a zero-deadline `reconcile_now`, which
    /// registers the request and returns immediately.
    fn request_reconcile(&self) {
        let _ = self.reconcile_now(Duration::ZERO);
    }

    /// How long a reconcile run has been taking lately, when the implementation
    /// measures it. `None` = unknown.
    ///
    /// The answer path uses it to tell a wait that can succeed from one that
    /// cannot. A reconcile that runs an order of magnitude past the answer
    /// deadline never installs anything inside it, so waiting buys nothing and
    /// spends the deadline on every query — measured on the reporting machine
    /// as 0 successful holds out of 215, at 900 ms each. Reporting the real
    /// duration lets the gate skip a futile wait and start waiting again by
    /// itself if the reconcile ever gets cheap.
    fn typical_run(&self) -> Option<Duration> {
        None
    }

    /// Installs what can go in right now for `addresses`, ahead of the full
    /// run — their routes — so a first connect leaves through the link its rule
    /// names. Returns how many of them it covered. Default: none.
    fn install_first_contact(&self, _addresses: &[Ipv4Addr]) -> usize {
        0
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
    /// answered address is already enforced; the reconcile was requested but
    /// deliberately not awaited.
    Deferred,
    /// The answer carried an address the policy does not carry yet, and the
    /// reconcile that would carry it runs far past the answer deadline — so no
    /// wait was attempted. The answer goes out ahead of its own enforcement and
    /// the client's first connect to that address can be dropped; the
    /// learn-from-drops path is what recovers it.
    ///
    /// Distinct from [`Self::DeadlineExceeded`] on purpose: that one waited and
    /// was disappointed, this one knew better than to wait. Collapsing them
    /// would hide which of the two the machine is actually doing.
    AheadOfEnforcement,
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
    /// Upstream answered, but the addresses were WITHHELD: the leak guard is
    /// blocking with the additional link unresolved and the reconcile did not
    /// confirm a filter for them in time. Handing them over would put the very
    /// destinations the guard exists to hold back on the main link, so the
    /// caller is failed rather than answered — and, unlike
    /// [`Self::Upstream`], must NOT be forwarded raw.
    Withheld,
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
/// to keep an ordinary shared front end (`static.chatapp.test` /
/// `crashlogs.chatapp.test`) from being reported as a cross-host collision.
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
/// answered address is already enforced.
#[derive(Clone, Copy, Debug)]
pub struct AnswerHold {
    /// Upper bound on the synchronous reconcile wait.
    pub deadline: Duration,
    /// When `true`, an answer whose addresses are all enforced is returned
    /// immediately (reconcile requested, not awaited).
    pub fast_answers: bool,
}

/// Which destination addresses the installed policy carries right now.
///
/// The question the answer path has to settle is "will a connection to this
/// address be carried, or dropped". The FQDN cache cannot answer it — it
/// records what a name resolved to, not what the machine enforces — and the two
/// diverge by a whole apply cycle. See [`crate::enforced_addresses`].
pub trait EnforcedAddressView: Send + Sync {
    fn is_enforced(&self, ip: Ipv4Addr) -> bool;
}

/// View for callers with no enforcement of their own (tests, platforms without
/// an apply path). Reports nothing as enforced, which is the truth for them.
pub struct NoEnforcement;

impl EnforcedAddressView for NoEnforcement {
    fn is_enforced(&self, _ip: Ipv4Addr) -> bool {
        false
    }
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
// Every argument is one injected port — the module is deliberately
// mechanism-free, and grouping them into a struct would only move the same
// list one level down.
#[allow(clippy::too_many_arguments)]
mod query;
pub use query::*;
#[cfg(test)]
mod tests;
