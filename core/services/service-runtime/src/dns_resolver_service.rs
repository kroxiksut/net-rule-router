//! Mode B (local DNS resolver) runtime lifecycle — binds the loopback DNS
//! listener, points the OS at it, serves until stop, and restores the OS DNS on
//! the way out. Off by default; wired only when `EnforcementMode::Resolver` is
//! active and the platform supports system-DNS redirect.
//!
//! Split out of the boot wiring so the redirect lifecycle — order, fail-safe
//! teardown, cache flush — is unit-testable with a fake redirect + an ephemeral
//! socket, independent of a live Windows DNS client or a privileged `:53` bind.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nrr_domain::enforcement_mode::EnforcementMode;
use nrr_platform_api::dns_redirect::{
    DnsNamespaceExemption, RedirectHandle, RedirectState, SystemDnsRedirectPort,
};

use crate::dns_listener::DnsInterceptListener;

/// How often the serve loop wakes to check the stop flag (the socket read
/// timeout). Small enough that stop is honoured promptly on shutdown.
const SOCKET_READ_TIMEOUT: Duration = Duration::from_millis(500);

/// watchdog backoff: after a re-arm attempt the watchdog waits
/// this many `tick`s before trying again, so a persistently failing start (e.g.
/// `:53` already taken → `BindFailed`) never busy-spins a resolver thread. At a
/// ~5 s reconcile-tick cadence this is roughly 50 s between retries.
const RESOLVER_RESTART_BACKOFF_TICKS: u32 = 10;

/// Outcome of one [`DnsResolverService::run`] — lets the caller/log/tests tell
/// a bind failure from a redirect failure from a clean served-then-restored run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsResolverRunOutcome {
    /// Could not bind the loopback listener (port already in use / no
    /// privilege). Nothing was redirected — system DNS is untouched.
    BindFailed,
    /// Bound, but pointing the OS at us failed. The socket is dropped and an
    /// explicit `restore` is run as a backstop for a multi-step redirect that
    /// applied part of itself before failing (fail-open — general DNS keeps
    /// working once that rollback lands).
    RedirectFailed,
    /// Redirected, served until stop, and the OS DNS was restored.
    ServedAndRestored,
    /// a disarm (mode set A, or shutdown) fired while this
    /// arm was still binding, i.e. BEFORE the NRPT redirect was installed. The
    /// redirect is skipped entirely, so a rapid B→A toggle no longer flaps
    /// system DNS onto the loopback listener for the redirect-install +
    /// restore round-trip. Nothing was redirected — system DNS is untouched.
    CancelledBeforeRedirect,
}

/// How often the guard re-checks that the redirect is still configured and
/// the table around it is sane. The check is a registry read; the failure it
/// catches (a rule vanishing, a half-written rule from another process) left
/// the machine resolving past us for minutes without a single log line.
const REDIRECT_GUARD_INTERVAL: Duration = Duration::from_secs(30);

/// How long the claims may go unread while a change feed is wired. The feed
/// carries every change it can see; this bounds what a missed one costs (a
/// domain policy rewriting the search list, a feed that stopped).
pub const CLAIMS_SAFETY_RECHECK_INTERVAL: Duration = Duration::from_secs(300);

/// A link coming up is a burst of events; the claims are read once it settles.
const RECHECK_SETTLE: Duration = Duration::from_millis(250);

/// Raised when something happened that can change which namespaces are claimed
/// or how short names are completed — a link or route change, a DNS settings
/// write, the user's own short-name domain.
///
/// A VPN that connects hands its own DNS suffix to the machine, and until we
/// step out of that namespace its names resolve through us and fail. Waiting
/// for the next guard tick costs up to [`REDIRECT_GUARD_INTERVAL`], and the
/// client then caches our answer for [`crate::dns_wire::NEGATIVE_TTL_SECS`] on
/// top — so a link that comes up between ticks can leave a corporate name
/// unresolvable for a minute and a half after it was ready.
pub type NamespaceRecheck = Arc<AtomicBool>;

/// Which namespaces the product should stay out of, asked afresh each time.
///
/// A closure rather than a stored list: connections come and go, and the
/// answer at arm time is stale by the first reconnect. The caller decides
/// what qualifies; this module only carries the answer to the port.
pub type DnsNamespaceExemptionsFn = Arc<dyn Fn() -> Vec<DnsNamespaceExemption> + Send + Sync>;

/// Suffixes the user named for completing short names, asked afresh each tick.
pub type ShortNameSuffixesFn = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// The claims as the arm or the last guard tick read them, for the query path:
/// on Windows a read enumerates the adapters and walks the registry, which
/// has no place inside a DNS answer's budget. Empty until the arm publishes,
/// which completes nothing, exactly as with no source wired.
#[derive(Clone, Default)]
pub(crate) struct ClaimsSnapshot(Arc<RwLock<Arc<[DnsNamespaceExemption]>>>);

impl ClaimsSnapshot {
    /// The lock is held only for the pointer copy, never across a lookup.
    pub(crate) fn current(&self) -> Arc<[DnsNamespaceExemption]> {
        Arc::clone(&self.0.read().unwrap_or_else(|p| p.into_inner()))
    }

    pub(crate) fn publish(&self, claims: Arc<[DnsNamespaceExemption]>) {
        *self.0.write().unwrap_or_else(|p| p.into_inner()) = claims;
    }
}

/// Where the claims come from, and where the query path reads them.
#[derive(Clone, Default)]
struct NamespaceClaims {
    /// `None` claims every name, which is what the product did before it
    /// learned to step aside.
    source: Option<DnsNamespaceExemptionsFn>,
    published: ClaimsSnapshot,
    /// `None` re-reads on every guard tick: with nothing to say what changed,
    /// only a look can tell.
    feed: Option<ChangeFeed>,
}

/// Says when the claims changed, so a quiet tick reads nothing: on Windows a
/// read enumerates the adapters and walks the registry, on Linux it can start
/// a child process.
#[derive(Clone)]
struct ChangeFeed {
    raised: NamespaceRecheck,
    safety_interval: Duration,
}

impl NamespaceClaims {
    /// Read once for every consumer, and published for the listener.
    fn refresh(&self) -> Arc<[DnsNamespaceExemption]> {
        let claims: Arc<[DnsNamespaceExemption]> =
            self.source.as_ref().map(|s| s().into()).unwrap_or_default();
        self.published.publish(Arc::clone(&claims));
        claims
    }

    /// Take the raised flag, if any.
    fn take_raised(&self) -> bool {
        self.feed
            .as_ref()
            .is_some_and(|f| f.raised.swap(false, Ordering::SeqCst))
    }

    /// Whether this tick must read: always without a feed, otherwise when it
    /// was raised or the safety interval ran out.
    fn due(&self, raised: bool, last_read: Instant) -> bool {
        self.feed
            .as_ref()
            .is_none_or(|f| raised || last_read.elapsed() >= f.safety_interval)
    }
}

/// The user's short-name suffixes, and how the last attempt to keep short
/// names went — carried from the arm into the guard, so a failure is logged
/// once and retried until it clears.
#[derive(Clone, Default)]
struct ShortNameUpkeep {
    user_suffixes: Option<ShortNameSuffixesFn>,
    last_error: Option<String>,
}

impl ShortNameUpkeep {
    /// Ask the port to keep short names resolvable with `claimed`: the
    /// machine's suffixes change with its connections, and the port writes
    /// only on change.
    fn keep(
        &mut self,
        redirect: &Arc<dyn SystemDnsRedirectPort>,
        claimed: &[DnsNamespaceExemption],
    ) {
        let source = self.user_suffixes.as_ref();
        let extra = || source.map(|s| s()).unwrap_or_default();
        match redirect.keep_short_names(claimed, &extra) {
            Ok(()) => self.last_error = None,
            Err(error) => {
                let text = error.to_string();
                if self.last_error.as_deref() != Some(text.as_str()) {
                    tracing::warn!(
                        target: "nrr::dns-resolver",
                        msg_key = "dns-resolver-short-names-failed",
                        error = %text,
                        "Mode B: could not keep short names resolvable; single-label names may not resolve",
                    );
                    self.last_error = Some(text);
                }
            }
        }
    }

    fn failing(&self) -> bool {
        self.last_error.is_some()
    }
}

/// Owns the Mode-B intercept listener plus the system-DNS redirect port and
/// drives their combined lifecycle in one blocking call.
pub struct DnsResolverService {
    listener: DnsInterceptListener,
    redirect: Arc<dyn SystemDnsRedirectPort>,
    listen_addr: SocketAddr,
    guard_interval: Duration,
    claims: NamespaceClaims,
    short_names: ShortNameUpkeep,
}

impl DnsResolverService {
    pub fn new(
        listener: DnsInterceptListener,
        redirect: Arc<dyn SystemDnsRedirectPort>,
        listen_addr: SocketAddr,
    ) -> Self {
        Self {
            listener,
            redirect,
            listen_addr,
            guard_interval: REDIRECT_GUARD_INTERVAL,
            claims: NamespaceClaims::default(),
            short_names: ShortNameUpkeep::default(),
        }
    }

    /// Wire the user's own short-name suffixes. The machine's suffixes are the
    /// port's to know; these are added to them.
    #[must_use]
    pub fn with_short_name_suffixes(mut self, source: ShortNameSuffixesFn) -> Self {
        self.short_names.user_suffixes = Some(source);
        self
    }

    /// Wire the source of namespaces to stay out of. Re-read by the guard (see
    /// [`Self::with_change_feed`]), so a VPN that connects later is honoured
    /// without a restart.
    ///
    /// The listener completes short names with what the last read found: a short
    /// name reaches us with no suffix, and a claimed namespace is what the OS
    /// would have completed it with.
    #[must_use]
    pub fn with_namespace_exemptions(mut self, source: DnsNamespaceExemptionsFn) -> Self {
        self.listener = self
            .listener
            .with_claimed_namespaces(self.claims.published.clone());
        self.claims.source = Some(source);
        self
    }

    /// Wire the flag the change feed raises. The claims are then read when it
    /// is raised — at once, see [`NamespaceRecheck`] — or after
    /// `safety_interval` without it, and never on a quiet tick. Wire it only
    /// when the feed is actually subscribed.
    #[must_use]
    pub fn with_change_feed(mut self, raised: NamespaceRecheck, safety_interval: Duration) -> Self {
        self.claims.feed = Some(ChangeFeed {
            raised,
            safety_interval,
        });
        self
    }

    /// Hand the current set to the port, and say so only when it changed.
    ///
    /// Runs on every read of the claims, so an unconditional line would write
    /// one entry per read for a machine that never changes. No source wired
    /// claims every name, and nothing is handed over.
    fn apply_exemptions(
        redirect: &Arc<dyn SystemDnsRedirectPort>,
        claims: &NamespaceClaims,
        current: &[DnsNamespaceExemption],
        last: &mut Vec<DnsNamespaceExemption>,
    ) {
        if claims.source.is_none() || current == last.as_slice() {
            return;
        }
        match redirect.exempt_namespaces(current) {
            Ok(_) => {
                let names: Vec<&str> = current.iter().map(|e| e.suffix.as_str()).collect();
                tracing::info!(
                    target: "nrr::dns-resolver",
                    msg_key = "dns-resolver-namespaces-exempted",
                    namespaces = %names.join(", "),
                    "Mode B: these namespaces are answered by the connections that claim them",
                );
                *last = current.to_vec();
            }
            // Keep the previous set as the last-known state so the next tick
            // retries instead of believing the failed write took effect.
            Err(error) => tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "dns-resolver-exempt-namespaces-failed",
                error = %error,
                "Mode B: could not step out of the claimed namespaces; names inside them keep resolving through us",
            ),
        }
    }

    /// Guard cadence override for tests.
    pub fn with_guard_interval(mut self, interval: Duration) -> Self {
        self.guard_interval = interval;
        self
    }

    /// Sleep `interval` in `slice` steps. `true` when the feed was raised,
    /// which cuts the wait short: the namespaces a new link may claim are the
    /// whole reason the guard exists.
    fn wait_tick(claims: &NamespaceClaims, interval: Duration, stop: &AtomicBool) -> bool {
        let slice = Duration::from_millis(50).min(interval);
        let mut waited = Duration::ZERO;
        while waited < interval && !stop.load(Ordering::SeqCst) {
            if claims.take_raised() {
                // One read for the whole burst a link change raises.
                let mut settled = Duration::ZERO;
                while settled < RECHECK_SETTLE && !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(slice);
                    settled += slice;
                }
                claims.take_raised();
                return true;
            }
            std::thread::sleep(slice);
            waited += slice;
        }
        false
    }

    /// Re-installs the redirect whenever `inspect` finds it missing or the
    /// table damaged, until `stop`. Runs beside the serve loop.
    fn guard(
        redirect: Arc<dyn SystemDnsRedirectPort>,
        handle: RedirectHandle,
        interval: Duration,
        stop: Arc<AtomicBool>,
        claims: NamespaceClaims,
        mut applied: Vec<DnsNamespaceExemption>,
        mut short_names: ShortNameUpkeep,
    ) {
        // The arm has just read the claims.
        let mut last_read = Instant::now();
        // Something that undoes the redirect on every check is said once, not
        // every tick; a check that finds it in place ends the streak.
        let mut missing_streak = false;
        let mut last_reinstall_error: Option<String> = None;
        loop {
            let raised = Self::wait_tick(&claims, interval, &stop);
            if stop.load(Ordering::SeqCst) {
                return;
            }
            // A connection that appeared may claim a namespace of its own, and
            // one that went away stops claiming it. Checked before the redirect
            // itself: re-installing the catch-all without the exemptions beside
            // it would capture those names for a whole interval.
            let due = claims.due(raised, last_read);
            let current = if due {
                last_read = Instant::now();
                claims.refresh()
            } else {
                claims.published.current()
            };
            // Unchanged claims cost a comparison; a write that failed is
            // retried with what was read, without reading again.
            Self::apply_exemptions(&redirect, &claims, &current, &mut applied);
            if due || short_names.failing() {
                short_names.keep(&redirect, &current);
            }
            match redirect.inspect(&handle) {
                Ok(RedirectState::Active) => {
                    missing_streak = false;
                    last_reinstall_error = None;
                }
                Ok(RedirectState::Inactive) => {
                    let repeat = std::mem::replace(&mut missing_streak, true);
                    if repeat {
                        tracing::debug!(
                            target: "nrr::dns-resolver",
                            "Mode B: the system-DNS redirect went missing again; re-installing it",
                        );
                    } else {
                        tracing::warn!(
                            target: "nrr::dns-resolver",
                            msg_key = "dns-resolver-redirect-missing",
                            "Mode B: the system-DNS redirect is no longer configured as written — \
                             re-installing it",
                        );
                    }
                    match redirect.redirect_to(handle.listener) {
                        Ok(_) => {
                            // The catch-all was just rewritten; the exemptions
                            // must be put back beside it, and the remembered set
                            // no longer describes the table.
                            applied.clear();
                            Self::apply_exemptions(&redirect, &claims, &current, &mut applied);
                            let _ = redirect.flush_cache();
                            last_reinstall_error = None;
                            if !repeat {
                                tracing::info!(
                                    target: "nrr::dns-resolver",
                                    msg_key = "dns-resolver-redirect-reinstalled",
                                    "Mode B: system-DNS redirect re-installed",
                                );
                            }
                        }
                        Err(error) => {
                            let text = error.to_string();
                            if last_reinstall_error.as_deref() != Some(text.as_str()) {
                                tracing::warn!(
                                    target: "nrr::dns-resolver",
                                    msg_key = "dns-resolver-reinstall-failed",
                                    error = %text,
                                    "Mode B: re-installing the system-DNS redirect failed; \
                                     names resolve past the resolver until the next check",
                                );
                                last_reinstall_error = Some(text);
                            }
                        }
                    }
                }
                Err(error) => tracing::debug!(
                    target: "nrr::dns-resolver",
                    "Mode B: redirect self-check unavailable ({error})",
                ),
            }
        }
    }

    /// Blocking lifecycle: bind → redirect → flush → serve (until `stop`) →
    /// restore → flush. Never panics; every failure degrades to leaving the OS
    /// DNS untouched (fail-open) — a broken resolver must never brick name
    /// resolution.
    ///
    /// Invariants:
    /// - The redirect is installed only AFTER the socket is bound, so the OS is
    ///   never pointed at a listener that does not exist.
    /// - Once installed, the redirect is ALWAYS restored before returning —
    ///   including when the serve loop errors — so a dead `:53` never outlives
    ///   this call.
    pub fn run(&self, stop: &AtomicBool) -> DnsResolverRunOutcome {
        let socket = match UdpSocket::bind(self.listen_addr) {
            Ok(socket) => socket,
            Err(error) => {
                tracing::warn!(
                    target: "nrr::dns-resolver",
                    msg_key = "dns-resolver-bind-failed",
                    addr = %self.listen_addr,
                    error = %error,
                    "Mode B: could not bind the DNS listener; resolver disabled, \
                     system DNS untouched",
                );
                return DnsResolverRunOutcome::BindFailed;
            }
        };
        // Read timeout so the serve loop polls `stop` even with no DNS traffic.
        let _ = socket.set_read_timeout(Some(SOCKET_READ_TIMEOUT));

        // cancel BEFORE touching system DNS if a disarm
        // already fired during the bind. Arming holds no lock across the
        // (slow) NRPT redirect, so a `set(Reactive)` racing a `set(Resolver)`
        // could otherwise complete the full install→restore cycle even though
        // the user already switched back to mode A — stranding DNS on the
        // loopback listener for the round-trip. Checking `stop` here makes an
        // arm that is already superseded a no-op that never redirects.
        if stop.load(Ordering::SeqCst) {
            tracing::info!(
                target: "nrr::dns-resolver",
                msg_key = "dns-resolver-arm-cancelled",
                "Mode B: arm cancelled during bind (mode switched back before redirect); \
                 system DNS untouched",
            );
            return DnsResolverRunOutcome::CancelledBeforeRedirect;
        }

        let handle = match self.redirect.redirect_to(self.listen_addr) {
            Ok(handle) => handle,
            Err(error) => {
                // Backstop for a redirect that applied part of itself. Every
                // `restore` is idempotent and ignores the handle's fields.
                let backstop = RedirectHandle {
                    marker: String::new(),
                    listener: self.listen_addr,
                };
                match self.redirect.restore(&backstop) {
                    Ok(()) => tracing::warn!(
                        target: "nrr::dns-resolver",
                        msg_key = "dns-resolver-redirect-failed",
                        addr = %self.listen_addr,
                        error = %error,
                        "Mode B: system-DNS redirect failed; resolver disabled, \
                         system DNS untouched",
                    ),
                    Err(restore_error) => tracing::error!(
                        target: "nrr::dns-resolver",
                        msg_key = "dns-resolver-restore-failed",
                        error = %restore_error,
                        redirect_error = %error,
                        "Mode B: system-DNS redirect failed and the rollback also \
                         failed; if name resolution is broken, remove the \
                         NetRuleRouter NRPT rule manually (Get-DnsClientNrptRule / \
                         Remove-DnsClientNrptRule)",
                    ),
                }
                return DnsResolverRunOutcome::RedirectFailed;
            }
        };
        // Before the flush, so a name inside a claimed namespace is never
        // answered by us even once: the flush is what sends every cached name
        // back through the table we just wrote. Also published for the
        // listener before it serves, so no query waits for the first tick.
        let mut applied: Vec<DnsNamespaceExemption> = Vec::new();
        // This read covers every change raised before it.
        self.claims.take_raised();
        let claims = self.claims.refresh();
        Self::apply_exemptions(&self.redirect, &self.claims, &claims, &mut applied);
        let mut short_names = self.short_names.clone();
        short_names.keep(&self.redirect, &claims);
        // A warm OS cache would otherwise bypass us on first contact.
        // Best-effort: a flush failure is logged, not fatal.
        if let Err(error) = self.redirect.flush_cache() {
            tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "dns-resolver-cache-flush-failed",
                error = %error,
                "Mode B: DNS cache flush on activation failed; warm entries may \
                 bypass the resolver until they expire",
            );
        }
        tracing::info!(
            target: "nrr::dns-resolver",
            msg_key = "dns-resolver-active",
            addr = %self.listen_addr,
            "Mode B: DNS resolver active — system DNS redirected to the loopback listener",
        );

        let guard_stop = Arc::new(AtomicBool::new(false));
        let guard = std::thread::Builder::new()
            .name("nrr-dns-redirect-guard".to_string())
            .spawn({
                let redirect = Arc::clone(&self.redirect);
                let handle = handle.clone();
                let interval = self.guard_interval;
                let stop = Arc::clone(&guard_stop);
                let claims = self.claims.clone();
                // The set arm time installed: the guard starts from it so an
                // unchanged machine writes nothing on its first tick.
                let applied = applied.clone();
                move || {
                    Self::guard(
                        redirect,
                        handle,
                        interval,
                        stop,
                        claims,
                        applied,
                        short_names,
                    )
                }
            })
            .ok();

        let serve_result = self.listener.serve_udp(&socket, stop);

        // The guard must be gone before the restore, or it re-installs what
        // the restore just removed.
        guard_stop.store(true, Ordering::SeqCst);
        if let Some(guard) = guard {
            let _ = guard.join();
        }

        // Fail-safe teardown: restore no matter how the serve loop ended.
        if let Err(error) = self.redirect.restore(&handle) {
            tracing::error!(
                target: "nrr::dns-resolver",
                msg_key = "dns-resolver-restore-failed",
                error = %error,
                "Mode B: FAILED to restore system DNS; if name resolution is \
                 broken, remove the NetRuleRouter NRPT rule manually \
                 (Get-DnsClientNrptRule / Remove-DnsClientNrptRule)",
            );
        } else {
            let _ = self.redirect.flush_cache();
            tracing::info!(
                target: "nrr::dns-resolver",
                msg_key = "dns-resolver-stopped-restored",
                "Mode B: DNS resolver stopped — system DNS restored",
            );
        }
        if let Err(error) = serve_result {
            tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "dns-resolver-serve-loop-error",
                error = %error,
                "Mode B: DNS serve loop ended with an error",
            );
        }
        DnsResolverRunOutcome::ServedAndRestored
    }
}

/// Why a factory declined to build a resolver. Either way the controller stays
/// reactive and the OS DNS is untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmRefusal {
    /// Nobody is signed in. The sign-in event arms it; retrying earlier only
    /// repeats the refusal.
    AwaitingSignIn,
    /// Something the arm needs is missing: no upstream answered, or the
    /// listener could not be prepared. Worth retrying with backoff.
    Unavailable,
}

/// Builds a fresh [`DnsResolverService`] on each start, re-capturing the
/// upstream so a start after a network change is correct. The OS construction
/// is injected by the platform service crate.
pub type DnsResolverFactory = Arc<dyn Fn() -> Result<DnsResolverService, ArmRefusal> + Send + Sync>;

/// Runtime start/stop controller for the Mode-B resolver, so switching
/// [`EnforcementMode`] takes effect WITHOUT a service restart. Owns the
/// resolver thread + its stop flag behind a `Mutex`; `apply` / `start` / `stop`
/// are idempotent, so a redundant Save (same mode) never flaps system DNS.
///
/// Shared via `Arc` between the boot path (initial arm + shutdown stop) and the
/// service-stability IPC writer (live apply on `enforcement_mode` change),
/// mirroring how `SecondaryLivenessTracker` is shared for the liveness window.
/// Both `start` and `stop` hold the lock for their full duration (including the
/// join), so a live `apply` sequence is fully serialised — a fresh resolver can
/// never bind `:53` before a prior one has released it and restored the OS DNS.
#[derive(Default)]
pub struct DnsResolverController {
    inner: Mutex<ControllerInner>,
}

#[derive(Default)]
struct ControllerInner {
    factory: Option<DnsResolverFactory>,
    running: Option<(Arc<AtomicBool>, JoinHandle<()>)>,
    /// Terminal latch set by [`DnsResolverController::shutdown`] on service
    /// teardown. Once set, `start` is a permanent no-op — so an IPC
    /// enforcement-mode `set` racing the shutdown can never re-arm a resolver
    /// whose `:53` bind + NRPT redirect would then outlive the process.
    disarmed: bool,
    /// the mode the user last asked for: `true` = Resolver
    /// (Mode B) should be serving. The [`DnsResolverController::tick`] watchdog
    /// re-arms the thread when this is `true` but the serve loop has exited
    /// unexpectedly (defense-in-depth beyond the per-datagram 10054 fix), so a
    /// resolver that dies on some other fatal error self-heals instead of
    /// silently staying down until the next mode toggle.
    desired: bool,
    /// Ticks remaining before the watchdog re-attempts a re-arm, so a persistently
    /// failing start backs off instead of busy-spinning (see
    /// [`RESOLVER_RESTART_BACKOFF_TICKS`]).
    restart_cooldown: u32,
    /// Whether an upstream was reachable the last time the caller reported it.
    /// Only the false→true edge clears the backoff — see
    /// [`DnsResolverController::note_upstream_present`].
    upstream_present: bool,
    /// The last arm was refused because nobody is signed in: the watchdog
    /// leaves it to the sign-in event, which comes through `start`.
    awaiting_sign_in: bool,
}

impl DnsResolverController {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ControllerInner> {
        // Poison recovery: the guarded state is a factory handle + a thread
        // handle; a panic elsewhere never leaves it logically corrupt, so
        // recovering the inner value is safe and avoids an unwrap (workspace
        // lint denies `unwrap_used`).
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Installs the platform factory used to (re)build a resolver on each start.
    /// Called once during boot wiring, before any live `apply`.
    pub fn set_factory(&self, factory: DnsResolverFactory) {
        self.lock().factory = Some(factory);
    }

    /// Idempotently reconcile the running resolver to `mode`: `Resolver` → ensure
    /// started; `Reactive` → ensure stopped (and system DNS restored).
    pub fn apply(&self, mode: EnforcementMode) {
        match mode {
            EnforcementMode::Resolver => self.start(),
            EnforcementMode::Reactive => self.stop(),
        }
    }

    /// asynchronous [`Self::apply`] for the IPC write path.
    /// `start` runs NRPT PowerShell (seconds) and `stop` JOINS the serve loop;
    /// doing either inline in the `settings.service-stability.set` handler
    /// would hold the reply past the GUI's 30 s RPC deadline («Превышено время
    /// ожидания»). Records the desired mode first, then
    /// reconciles on a detached thread; the thread re-reads the LATEST desired
    /// mode at execution time, so two racing writes converge on the final
    /// value regardless of thread scheduling order (each apply is itself
    /// idempotent and internally serialized).
    pub fn apply_async(self: &Arc<Self>, mode: EnforcementMode) {
        {
            let mut inner = self.lock();
            inner.desired = mode == EnforcementMode::Resolver;
        }
        let this = Arc::clone(self);
        std::thread::spawn(move || {
            let desired = this.lock().desired;
            this.apply(if desired {
                EnforcementMode::Resolver
            } else {
                EnforcementMode::Reactive
            });
        });
    }

    #[cfg(test)]
    pub(crate) fn desired_mode(&self) -> EnforcementMode {
        if self.lock().desired {
            EnforcementMode::Resolver
        } else {
            EnforcementMode::Reactive
        }
    }

    /// True while a resolver thread is live (and hasn't self-exited).
    pub fn is_running(&self) -> bool {
        let mut inner = self.lock();
        Self::reap_finished(&mut inner);
        inner.running.is_some()
    }

    /// Reap a thread that already exited on its own (e.g. `BindFailed` — `:53`
    /// already taken → `run` returns immediately) so a later `start` spawns a
    /// fresh one instead of seeing a stale "running" handle.
    fn reap_finished(inner: &mut ControllerInner) {
        if inner
            .running
            .as_ref()
            .is_some_and(|(_, join)| join.is_finished())
        {
            if let Some((_, join)) = inner.running.take() {
                let _ = join.join();
            }
        }
    }

    /// Start the resolver if not already running. Builds a fresh service via the
    /// factory (fail-open: a missing factory or a `None` build leaves the OS DNS
    /// untouched and the service reactive).
    pub fn start(&self) {
        let mut inner = self.lock();
        inner.desired = true;
        inner.restart_cooldown = 0;
        inner.awaiting_sign_in = false;
        Self::start_locked(&mut inner);
    }

    /// Report whether an upstream DNS server is reachable right now.
    ///
    /// A cold boot arms Mode B before the router has finished coming up, so the
    /// first attempts fail with "no upstream" and the watchdog then waits out
    /// its full backoff — on a power-cut restart that left name resolution down
    /// for over two minutes after the link was already back. The upstream
    /// appearing is the event that arm was waiting for, so clear the backoff on
    /// that edge and let the next tick retry at once. Only the edge counts: a
    /// steady "yes" must not defeat the backoff that protects against a
    /// genuinely failing start (`:53` already taken).
    pub fn note_upstream_present(&self, present: bool) {
        let mut inner = self.lock();
        let appeared = present && !inner.upstream_present;
        inner.upstream_present = present;
        if appeared {
            inner.restart_cooldown = 0;
        }
    }

    /// Watchdog tick — call periodically (e.g. from the reconcile safety tick).
    /// Re-arms the resolver when Mode B is the desired mode but the serve thread
    /// has exited unexpectedly (the per-datagram 10054 fix covers the common case;
    /// this catches anything else). No-op when disarmed, when Reactive is desired,
    /// or while backing off after a failed re-arm. Idempotent and cheap.
    pub fn tick(&self) {
        let mut inner = self.lock();
        if inner.disarmed || !inner.desired || inner.awaiting_sign_in {
            return;
        }
        Self::reap_finished(&mut inner);
        if inner.running.is_some() {
            inner.restart_cooldown = 0; // healthy — clear any backoff
            return;
        }
        if inner.restart_cooldown > 0 {
            inner.restart_cooldown -= 1;
            return;
        }
        tracing::warn!(
            target: "nrr::dns-resolver",
            msg_key = "dns-resolver-watchdog-rearm",
            "Mode B: resolver is enabled but its serve thread has exited — re-arming (watchdog)",
        );
        inner.restart_cooldown = RESOLVER_RESTART_BACKOFF_TICKS;
        Self::start_locked(&mut inner);
    }

    fn start_locked(inner: &mut ControllerInner) {
        if inner.disarmed {
            // Terminally shut down (service teardown). Never re-arm — an IPC
            // set racing the shutdown must not resurrect the resolver.
            return;
        }
        Self::reap_finished(inner);
        if inner.running.is_some() {
            return; // already serving — no flap
        }
        let Some(factory) = inner.factory.clone() else {
            tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "dns-resolver-no-factory",
                "Mode B: start requested but no resolver factory is wired; staying reactive",
            );
            return;
        };
        // Re-captures the current upstream DNS (the network may have changed
        // since boot). A failure to arm is fail-open — general DNS keeps working.
        let service = match factory() {
            Ok(service) => service,
            Err(ArmRefusal::AwaitingSignIn) => {
                inner.awaiting_sign_in = true;
                return;
            }
            Err(ArmRefusal::Unavailable) => {
                tracing::warn!(
                    target: "nrr::dns-resolver",
                    msg_key = "dns-resolver-arm-failed",
                    "Mode B: resolver could not be armed (no upstream / deps); staying reactive",
                );
                return;
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        match std::thread::Builder::new()
            .name("nrr-dns-resolver".to_string())
            .spawn(move || {
                service.run(&thread_stop);
            }) {
            Ok(join) => {
                tracing::info!(
                    target: "nrr::dns-resolver",
                    msg_key = "dns-resolver-thread-started",
                    "Mode B: DNS resolver thread started",
                );
                inner.running = Some((stop, join));
            }
            Err(e) => {
                tracing::error!(
                    target: "nrr::dns-resolver",
                    msg_key = "dns-resolver-spawn-failed",
                    error = %e,
                    "Mode B: failed to spawn DNS resolver thread; staying reactive",
                );
            }
        }
    }

    /// Stop the resolver if running: flip the stop flag and JOIN the thread so
    /// the NRPT redirect is restored and `:53` released before returning. Held
    /// under the lock for the full duration so a concurrent `start` cannot bind a
    /// fresh `:53` until this teardown has completed.
    pub fn stop(&self) {
        let mut inner = self.lock();
        inner.desired = false;
        Self::stop_locked(&mut inner);
    }

    /// Terminal shutdown for the service teardown path: stop the resolver AND
    /// latch the controller so any later `apply` / `start` — e.g. an IPC
    /// enforcement-mode `set` still in flight when the service stops (the writer
    /// calls `apply` after dropping the DB lock, and IPC workers are drained only
    /// later) — becomes a permanent no-op. The lock makes this correct in EITHER
    /// order: a racing `start` that ran just before this call is stopped+joined
    /// here; one that arrives just after sees `disarmed` and no-ops. Without the
    /// latch such a re-arm would spawn a resolver whose `:53` bind + NRPT redirect
    /// outlive the process, stranding system DNS at a dead listener until the next
    /// boot's `clear_orphan_redirect`.
    pub fn shutdown(&self) {
        let mut inner = self.lock();
        inner.disarmed = true;
        Self::stop_locked(&mut inner);
    }

    fn stop_locked(inner: &mut ControllerInner) {
        if let Some((stop, join)) = inner.running.take() {
            stop.store(true, Ordering::SeqCst);
            if join.join().is_err() {
                tracing::warn!(
                    target: "nrr::dns-resolver",
                    msg_key = "dns-resolver-thread-panicked",
                    "Mode B: DNS resolver thread panicked during stop",
                );
            } else {
                tracing::info!(
                    target: "nrr::dns-resolver",
                    msg_key = "dns-resolver-stopped-restored",
                    "Mode B: DNS resolver stopped (system DNS restored)",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_resolver::{
        FactSink, ReconcileOutcome, ResolveError, ResolvedAddresses, RuleHostOracle,
        SyncReconciler, UpstreamResolver,
    };
    use nrr_platform_api::dns::AddressFamily;
    use nrr_platform_api::dns_redirect::{RedirectHandle, RedirectState};
    use nrr_platform_api::PlatformError;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;

    // ── Trivial listener ports — never invoked when `stop` is preset, so they
    // only need to satisfy the trait bounds. ────────────────────────────────
    struct NoHost;
    impl RuleHostOracle for NoHost {
        fn is_rule_host(&self, _hostname: &str) -> bool {
            false
        }
    }
    struct DeadUpstream;
    impl UpstreamResolver for DeadUpstream {
        fn resolve_within(
            &self,
            _hostname: &str,
            _family: AddressFamily,
            _budget: Duration,
        ) -> Result<ResolvedAddresses, ResolveError> {
            Err(ResolveError::NoRecords)
        }
    }
    struct NoopSink;
    impl FactSink for NoopSink {
        fn record(&self, _hostname: &str, _resolved: &ResolvedAddresses) {}
    }
    struct OkReconciler;
    impl SyncReconciler for OkReconciler {
        fn reconcile_now(&self, _deadline: Duration) -> ReconcileOutcome {
            ReconcileOutcome::Installed
        }
    }

    /// Records the ordered redirect calls so the teardown ordering is asserted.
    /// `flip_stop`, when set, is flipped to `true` the moment `redirect_to`
    /// runs — simulating a disarm that arrives just AFTER the redirect installs,
    /// so the serve loop exits on its first poll and the ordering
    /// (redirect → restore) is observable without real timing.
    #[derive(Default)]
    struct RecordingRedirect {
        calls: Mutex<Vec<&'static str>>,
        flip_stop: Option<Arc<AtomicBool>>,
        /// How many self-checks answer "gone" before the redirect reads as
        /// intact again — the guard's re-install is what the count buys.
        damaged_checks: std::sync::atomic::AtomicUsize,
        /// Every exemption set handed to the port, in order — so a test can
        /// assert both what was claimed and that an unchanged machine is not
        /// re-written on every guard tick.
        exempted: Mutex<Vec<Vec<String>>>,
        /// Set once the guard has re-installed the redirect at least once, so
        /// a test can stop the serve loop at that moment.
        reinstalled: Option<Arc<AtomicBool>>,
        /// Every set of user suffixes the port asked for, as the Windows
        /// port does; `false` leaves them unasked, as the default does.
        asks_user_suffixes: bool,
        short_names: Mutex<Vec<Vec<String>>>,
        /// The claims each keep-short-names call was handed.
        short_name_claims: Mutex<Vec<Vec<String>>>,
        /// How many keep-short-names calls fail before one holds.
        short_names_fail: std::sync::atomic::AtomicUsize,
    }
    impl SystemDnsRedirectPort for RecordingRedirect {
        fn redirect_to(&self, listener: SocketAddr) -> Result<RedirectHandle, PlatformError> {
            let mut calls = self.calls.lock().unwrap();
            calls.push("redirect_to");
            if calls.iter().filter(|c| **c == "redirect_to").count() > 1 {
                if let Some(flag) = self.reinstalled.as_ref() {
                    flag.store(true, Ordering::SeqCst);
                }
            }
            drop(calls);
            if let Some(stop) = self.flip_stop.as_ref() {
                stop.store(true, Ordering::SeqCst);
            }
            Ok(RedirectHandle {
                marker: "test".to_string(),
                listener,
            })
        }
        fn inspect(&self, _handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
            self.calls.lock().unwrap().push("inspect");
            let left = self.damaged_checks.load(Ordering::SeqCst);
            if left > 0 {
                self.damaged_checks.store(left - 1, Ordering::SeqCst);
                return Ok(RedirectState::Inactive);
            }
            Ok(RedirectState::Active)
        }
        fn restore(&self, _handle: &RedirectHandle) -> Result<(), PlatformError> {
            self.calls.lock().unwrap().push("restore");
            Ok(())
        }
        fn verify(&self, _handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
            Ok(RedirectState::Inactive)
        }
        fn flush_cache(&self) -> Result<(), PlatformError> {
            self.calls.lock().unwrap().push("flush");
            Ok(())
        }
        fn exempt_namespaces(
            &self,
            exemptions: &[DnsNamespaceExemption],
        ) -> Result<usize, PlatformError> {
            self.calls.lock().unwrap().push("exempt");
            self.exempted
                .lock()
                .unwrap()
                .push(exemptions.iter().map(|e| e.suffix.clone()).collect());
            Ok(exemptions.len())
        }
        fn keep_short_names(
            &self,
            claimed: &[DnsNamespaceExemption],
            extra: &dyn Fn() -> Vec<String>,
        ) -> Result<(), PlatformError> {
            self.calls.lock().unwrap().push("short_names");
            self.short_name_claims
                .lock()
                .unwrap()
                .push(claimed.iter().map(|e| e.suffix.clone()).collect());
            if self.asks_user_suffixes {
                self.short_names.lock().unwrap().push(extra());
            }
            let left = self.short_names_fail.load(Ordering::SeqCst);
            if left > 0 {
                self.short_names_fail.store(left - 1, Ordering::SeqCst);
                return Err(PlatformError::Transient {
                    operation: "test",
                    detail: "search list refused".to_string(),
                });
            }
            Ok(())
        }
    }

    fn listener() -> DnsInterceptListener {
        DnsInterceptListener::new(
            Arc::new(NoHost),
            Arc::new(DeadUpstream),
            Arc::new(NoopSink),
            Arc::new(OkReconciler),
            "127.0.0.1:5353".parse().unwrap(),
            Duration::from_millis(150),
            Duration::from_millis(500),
        )
    }

    #[test]
    fn the_guard_reinstalls_a_redirect_that_went_missing() {
        // The first self-check finds the redirect gone; the re-install it
        // triggers is the moment the test stops the serve loop.
        let stop = Arc::new(AtomicBool::new(false));
        let redirect = Arc::new(RecordingRedirect {
            damaged_checks: std::sync::atomic::AtomicUsize::new(1),
            reinstalled: Some(Arc::clone(&stop)),
            ..Default::default()
        });
        let service =
            DnsResolverService::new(listener(), redirect.clone(), "127.0.0.1:0".parse().unwrap())
                .with_guard_interval(Duration::from_millis(20));
        assert_eq!(service.run(&stop), DnsResolverRunOutcome::ServedAndRestored);

        let calls = redirect.calls.lock().unwrap().clone();
        let installs: Vec<usize> = calls
            .iter()
            .enumerate()
            .filter(|(_, c)| **c == "redirect_to")
            .map(|(i, _)| i)
            .collect();
        assert_eq!(installs.len(), 2, "one arm, one re-install: {calls:?}");
        let restore = calls
            .iter()
            .position(|c| *c == "restore")
            .expect("restored");
        assert!(
            installs[1] < restore,
            "the re-install happens while serving, never after the restore: {calls:?}"
        );
    }

    fn exemption(suffix: &str) -> DnsNamespaceExemption {
        DnsNamespaceExemption {
            suffix: suffix.to_string(),
            servers: vec!["192.168.0.53".parse().expect("ip")],
        }
    }

    /// The field case: a corporate VPN claims its own namespace, and we step
    /// out of it BEFORE the cache flush. The flush is what sends every warm
    /// name back through the table, so an exemption written after it would
    /// let us answer those names once.
    #[test]
    fn claimed_namespaces_are_left_alone_before_the_cache_is_flushed() {
        let stop = Arc::new(AtomicBool::new(false));
        let redirect = Arc::new(RecordingRedirect {
            flip_stop: Some(Arc::clone(&stop)),
            ..Default::default()
        });
        let service =
            DnsResolverService::new(listener(), redirect.clone(), "127.0.0.1:0".parse().unwrap())
                .with_namespace_exemptions(Arc::new(|| vec![exemption("branch.corp.example")]));

        assert_eq!(service.run(&stop), DnsResolverRunOutcome::ServedAndRestored);

        let calls = redirect.calls.lock().unwrap().clone();
        let exempt_at = calls.iter().position(|c| *c == "exempt").expect("exempted");
        let flush_at = calls.iter().position(|c| *c == "flush").expect("flushed");
        let redirect_at = calls.iter().position(|c| *c == "redirect_to").unwrap();
        assert!(redirect_at < exempt_at, "{calls:?}");
        assert!(exempt_at < flush_at, "{calls:?}");
        assert_eq!(
            redirect.exempted.lock().unwrap().clone(),
            vec![vec!["branch.corp.example".to_string()]],
        );
    }

    /// The OS completes a short name before any resolver sees it, so the
    /// suffixes must be in place before the flush sends names back through.
    /// Asked even with no suffix of the user's: the machine's own are the
    /// port's to restore.
    #[test]
    fn short_names_are_kept_before_the_cache_is_flushed() {
        for (user, expected) in [
            (Some("lab.example"), vec!["lab.example".to_string()]),
            (None, Vec::new()),
        ] {
            let stop = Arc::new(AtomicBool::new(false));
            let redirect = Arc::new(RecordingRedirect {
                flip_stop: Some(Arc::clone(&stop)),
                asks_user_suffixes: true,
                ..Default::default()
            });
            let service = DnsResolverService::new(
                listener(),
                redirect.clone(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .with_short_name_suffixes(Arc::new(move || {
                user.map(str::to_string).into_iter().collect()
            }));
            assert_eq!(service.run(&stop), DnsResolverRunOutcome::ServedAndRestored);

            let calls = redirect.calls.lock().unwrap().clone();
            let kept_at = calls
                .iter()
                .position(|c| *c == "short_names")
                .expect("asked");
            let flush_at = calls.iter().position(|c| *c == "flush").expect("flushed");
            assert!(kept_at < flush_at, "{calls:?}");
            assert_eq!(redirect.short_names.lock().unwrap()[0], expected);
        }
    }

    /// The guard running alone, counting each read of the claims (with when
    /// it happened) and of the user's suffixes.
    struct GuardRun {
        redirect: Arc<RecordingRedirect>,
        claim_reads: Arc<Mutex<Vec<std::time::Instant>>>,
        users_read: Arc<std::sync::atomic::AtomicUsize>,
        raised: NamespaceRecheck,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl GuardRun {
        /// `safety`: the change feed's safety interval; `None` runs without a
        /// feed, re-reading on every tick.
        fn start(redirect: Arc<RecordingRedirect>, safety: Option<Duration>) -> Self {
            use std::sync::atomic::AtomicUsize;
            let claim_reads = Arc::new(Mutex::new(Vec::new()));
            let users_read = Arc::new(AtomicUsize::new(0));
            let raised: NamespaceRecheck = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let claims = NamespaceClaims {
                source: Some({
                    let reads = Arc::clone(&claim_reads);
                    Arc::new(move || {
                        reads.lock().expect("reads").push(std::time::Instant::now());
                        vec![exemption("branch.corp.example")]
                    })
                }),
                published: ClaimsSnapshot::default(),
                feed: safety.map(|safety_interval| ChangeFeed {
                    raised: Arc::clone(&raised),
                    safety_interval,
                }),
            };
            let short_names = ShortNameUpkeep {
                user_suffixes: Some({
                    let count = Arc::clone(&users_read);
                    Arc::new(move || {
                        count.fetch_add(1, Ordering::SeqCst);
                        vec!["lab.example".to_string()]
                    })
                }),
                last_error: None,
            };
            let thread = std::thread::spawn({
                let redirect: Arc<dyn SystemDnsRedirectPort> = redirect.clone();
                let stop = Arc::clone(&stop);
                move || {
                    DnsResolverService::guard(
                        redirect,
                        RedirectHandle {
                            marker: "test".to_string(),
                            listener: "127.0.0.1:0".parse().expect("addr"),
                        },
                        Duration::from_millis(5),
                        stop,
                        claims,
                        Vec::new(),
                        short_names,
                    );
                }
            });
            Self {
                redirect,
                claim_reads,
                users_read,
                raised,
                stop,
                thread: Some(thread),
            }
        }

        fn calls(&self, name: &str) -> usize {
            let calls = self.redirect.calls.lock().expect("calls");
            calls.iter().filter(|c| **c == name).count()
        }

        fn ticks(&self) -> usize {
            self.calls("inspect")
        }

        fn claim_reads(&self) -> Vec<std::time::Instant> {
            self.claim_reads.lock().expect("reads").clone()
        }

        fn users_read(&self) -> usize {
            self.users_read.load(Ordering::SeqCst)
        }

        fn wait_until(&self, done: impl Fn(&Self) -> bool) -> bool {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !done(self) && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(2));
            }
            done(self)
        }

        fn wait_ticks(&self, more: usize) {
            let target = self.ticks() + more;
            assert!(self.wait_until(|r| r.ticks() >= target), "the guard ticked");
        }

        /// Stop and join, so every count is final.
        fn stop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    impl Drop for GuardRun {
        fn drop(&mut self) {
            self.stop();
        }
    }

    /// Without a change feed only a look can tell what changed: the claims
    /// are read on every tick, once for both consumers.
    #[test]
    fn without_a_feed_a_tick_reads_the_claims_once_for_both_consumers() {
        let mut run = GuardRun::start(
            Arc::new(RecordingRedirect {
                asks_user_suffixes: true,
                ..Default::default()
            }),
            None,
        );
        run.wait_ticks(3);
        run.stop();
        let (reads, ticks) = (run.claim_reads().len(), run.ticks());
        // The stop can land between a read and its inspection.
        assert!(
            reads == ticks || reads == ticks + 1,
            "{reads} reads, {ticks} ticks"
        );
        assert_eq!(run.users_read(), reads, "asked once per read");
        assert!(run
            .redirect
            .short_name_claims
            .lock()
            .expect("lock")
            .iter()
            .all(|c| c == &["branch.corp.example".to_string()]));
    }

    /// A port that completes nothing never costs a settings read.
    #[test]
    fn a_port_without_short_name_upkeep_never_reads_the_users_suffixes() {
        let run = GuardRun::start(Arc::new(RecordingRedirect::default()), None);
        run.wait_ticks(3);
        assert!(!run.claim_reads().is_empty());
        assert_eq!(run.users_read(), 0);
    }

    fn fed_run(safety: Duration) -> GuardRun {
        GuardRun::start(
            Arc::new(RecordingRedirect {
                asks_user_suffixes: true,
                ..Default::default()
            }),
            Some(safety),
        )
    }

    /// The point of the feed: a machine where nothing changes costs the guard
    /// no adapter enumeration, no registry walk and no settings read.
    #[test]
    fn quiet_ticks_read_nothing() {
        let run = fed_run(Duration::from_secs(3600));
        run.wait_ticks(20);
        assert!(
            run.claim_reads().is_empty(),
            "no claims read on a quiet tick"
        );
        assert_eq!(run.users_read(), 0, "no settings read on a quiet tick");
        assert_eq!(run.calls("short_names"), 0);
        assert_eq!(run.calls("exempt"), 0, "nothing changed, nothing written");
    }

    #[test]
    fn a_raised_feed_costs_exactly_one_read() {
        let run = fed_run(Duration::from_secs(3600));
        run.wait_ticks(3);
        run.raised.store(true, Ordering::SeqCst);
        assert!(
            run.wait_until(|r| !r.claim_reads().is_empty()),
            "the event was read"
        );
        run.wait_ticks(10);
        assert_eq!(run.claim_reads().len(), 1);
        assert_eq!(run.users_read(), 1);
        assert_eq!(run.calls("short_names"), 1);
        assert_eq!(
            *run.redirect.exempted.lock().expect("exempted"),
            vec![vec!["branch.corp.example".to_string()]],
            "what the read found was applied"
        );
    }

    /// A link coming up raises the feed many times within a moment.
    #[test]
    fn a_burst_of_events_is_read_once() {
        let run = fed_run(Duration::from_secs(3600));
        run.wait_ticks(3);
        for _ in 0..5 {
            run.raised.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(run.wait_until(|r| !r.claim_reads().is_empty()));
        run.wait_ticks(10);
        assert_eq!(run.claim_reads().len(), 1);
    }

    /// With no event at all the claims are still read once per safety
    /// interval, never sooner.
    #[test]
    fn the_safety_interval_reads_once_per_interval() {
        let safety = Duration::from_millis(300);
        let started = std::time::Instant::now();
        let mut run = fed_run(safety);
        assert!(
            run.wait_until(|r| r.claim_reads().len() >= 2),
            "two intervals passed"
        );
        run.stop();
        let reads = run.claim_reads();
        assert!(
            reads[0] - started >= safety,
            "not before the first interval"
        );
        for pair in reads.windows(2) {
            // The interval runs from just before the previous read.
            assert!(pair[1] - pair[0] >= safety - Duration::from_millis(10));
        }
        assert_eq!(run.users_read(), reads.len());
    }

    /// A failed search-list write is retried on the next tick from what was
    /// read, without reading the claims again.
    #[test]
    fn a_failing_short_name_upkeep_is_retried_without_a_new_read() {
        let run = GuardRun::start(
            Arc::new(RecordingRedirect {
                short_names_fail: std::sync::atomic::AtomicUsize::new(2),
                ..Default::default()
            }),
            Some(Duration::from_secs(3600)),
        );
        run.raised.store(true, Ordering::SeqCst);
        assert!(
            run.wait_until(|r| r.calls("short_names") >= 3),
            "retried until it held"
        );
        run.wait_ticks(5);
        assert_eq!(run.calls("short_names"), 3, "no retry once it held");
        assert_eq!(run.claim_reads().len(), 1);
    }

    /// The trait's own default is what every Linux mechanism inherits.
    #[test]
    fn the_default_short_name_upkeep_asks_for_nothing() {
        struct Bare;
        impl SystemDnsRedirectPort for Bare {
            fn redirect_to(&self, listener: SocketAddr) -> Result<RedirectHandle, PlatformError> {
                Ok(RedirectHandle {
                    marker: String::new(),
                    listener,
                })
            }
            fn restore(&self, _handle: &RedirectHandle) -> Result<(), PlatformError> {
                Ok(())
            }
            fn verify(&self, _handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
                Ok(RedirectState::Active)
            }
        }
        let asked = AtomicBool::new(false);
        Bare.keep_short_names(&[exemption("branch.corp.example")], &|| {
            asked.store(true, Ordering::SeqCst);
            Vec::new()
        })
        .expect("default");
        assert!(!asked.load(Ordering::SeqCst));
    }

    /// One source feeds both: the namespaces we step out of are the ones a
    /// short name is completed with. Wired separately, the listener's half was
    /// never wired at all.
    #[test]
    fn the_listener_completes_short_names_with_the_claimed_namespaces() {
        let redirect = Arc::new(RecordingRedirect::default());
        let bare =
            DnsResolverService::new(listener(), redirect.clone(), "127.0.0.1:0".parse().unwrap());
        assert!(!bare.listener.completes_short_names());
        let wired =
            bare.with_namespace_exemptions(Arc::new(|| vec![exemption("branch.corp.example")]));
        assert!(wired.listener.completes_short_names());
    }

    /// The arm reads the claims before the listener serves its first query,
    /// so a short name never waits for the first guard tick.
    #[test]
    fn the_arm_publishes_the_claims_for_the_listener() {
        let stop = Arc::new(AtomicBool::new(false));
        let redirect = Arc::new(RecordingRedirect {
            flip_stop: Some(Arc::clone(&stop)),
            ..Default::default()
        });
        let service =
            DnsResolverService::new(listener(), redirect, "127.0.0.1:0".parse().expect("addr"))
                .with_namespace_exemptions(Arc::new(|| vec![exemption("branch.corp.example")]));
        assert!(service.claims.published.current().is_empty());
        assert_eq!(service.run(&stop), DnsResolverRunOutcome::ServedAndRestored);
        assert_eq!(
            &*service.claims.published.current(),
            &[exemption("branch.corp.example")]
        );
    }

    /// Knows `scanner` under two namespaces with a different address each, so
    /// an answer tells which claims completed it.
    fn two_namespace_resolver() -> u16 {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("resolver socket");
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let port = socket.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = socket.recv_from(&mut buf) {
                let q = &buf[..n];
                let Some(name) = crate::dns_wire::parse_question(q).map(|p| p.qname) else {
                    continue;
                };
                let host = match name.trim_end_matches('.') {
                    "scanner.old.corp.example" => 41,
                    "scanner.new.corp.example" => 42,
                    _ => continue,
                };
                let address = std::net::Ipv4Addr::new(192, 0, 2, host);
                if let Some(reply) = crate::dns_wire::build_a_response(q, &[address], 60) {
                    let _ = socket.send_to(&reply, from);
                }
            }
        });
        port
    }

    /// A single-label answer costs no enumeration: the listener reads what
    /// the guard tick published, and the next tick's claims are what the
    /// next query completes with.
    #[test]
    fn a_short_name_answer_reads_the_claims_the_guard_published() {
        use crate::dns_wire::{parse_address_response, AddressResponseOutcome, QTYPE_A};
        use std::sync::atomic::AtomicUsize;

        let reads = Arc::new(AtomicUsize::new(0));
        let namespace = Arc::new(Mutex::new("old.corp.example"));
        let recheck: NamespaceRecheck = Arc::new(AtomicBool::new(false));
        let claims = NamespaceClaims {
            source: Some({
                let reads = Arc::clone(&reads);
                let namespace = Arc::clone(&namespace);
                Arc::new(move || {
                    reads.fetch_add(1, Ordering::SeqCst);
                    vec![DnsNamespaceExemption {
                        suffix: namespace.lock().expect("lock").to_string(),
                        servers: vec![std::net::Ipv4Addr::LOCALHOST],
                    }]
                })
            }),
            published: ClaimsSnapshot::default(),
            feed: Some(ChangeFeed {
                raised: Arc::clone(&recheck),
                safety_interval: Duration::from_secs(3600),
            }),
        };
        let listener = listener()
            .with_claimed_namespaces(claims.published.clone())
            .with_resolver_port(two_namespace_resolver());
        let query = crate::dns_wire::build_address_query(0x2a2a, "scanner", QTYPE_A).expect("q");
        let answer = || {
            let reply =
                listener.complete_single_label(&query, "scanner", Duration::from_secs(2))?;
            match parse_address_response(0x2a2a, "scanner", QTYPE_A, &reply) {
                AddressResponseOutcome::Answers { addresses, .. } => addresses.first().copied(),
                _ => None,
            }
        };
        let published_under = |suffix: &str| {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                if claims
                    .published
                    .current()
                    .iter()
                    .any(|c| c.suffix == suffix)
                {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            false
        };

        // Nothing published yet: completes nothing, as with no source wired.
        for _ in 0..10 {
            assert_eq!(answer(), None);
        }
        assert_eq!(reads.load(Ordering::SeqCst), 0);

        let stop = Arc::new(AtomicBool::new(false));
        let guard = std::thread::spawn({
            let redirect: Arc<dyn SystemDnsRedirectPort> = Arc::new(RecordingRedirect::default());
            let stop = Arc::clone(&stop);
            let claims = claims.clone();
            move || {
                DnsResolverService::guard(
                    redirect,
                    RedirectHandle {
                        marker: "test".to_string(),
                        listener: "127.0.0.1:0".parse().expect("addr"),
                    },
                    Duration::from_secs(3600),
                    stop,
                    claims,
                    Vec::new(),
                    ShortNameUpkeep::default(),
                );
            }
        });

        recheck.store(true, Ordering::SeqCst);
        assert!(published_under("old.corp.example"));
        for _ in 0..10 {
            assert_eq!(answer(), Some("192.0.2.41".parse().expect("ip")));
        }
        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "one read per tick, none per query"
        );

        *namespace.lock().expect("lock") = "new.corp.example";
        recheck.store(true, Ordering::SeqCst);
        assert!(published_under("new.corp.example"));
        assert_eq!(answer(), Some("192.0.2.42".parse().expect("ip")));
        assert_eq!(reads.load(Ordering::SeqCst), 2);

        stop.store(true, Ordering::SeqCst);
        let _ = guard.join();
    }

    /// A link that appears between guard ticks claims its namespace at once.
    ///
    /// Without the wake the names inside it resolve through us for up to a
    /// guard interval, and the client then caches that answer for the negative
    /// TTL on top — a corporate host stays unreachable long after its VPN was
    /// ready.
    #[test]
    fn a_link_that_appears_between_ticks_is_honoured_at_once() {
        let stop = Arc::new(AtomicBool::new(false));
        let redirect = Arc::new(RecordingRedirect::default());
        let recheck: NamespaceRecheck = Arc::new(AtomicBool::new(false));
        let claimed = Arc::new(AtomicBool::new(false));

        let source: DnsNamespaceExemptionsFn = {
            let claimed = Arc::clone(&claimed);
            Arc::new(move || {
                if claimed.load(Ordering::SeqCst) {
                    vec![exemption("branch.corp.example")]
                } else {
                    Vec::new()
                }
            })
        };

        let mut applied = Vec::new();
        // A guard interval far longer than the test: only the wake can end it.
        let guard = std::thread::spawn({
            let redirect: Arc<dyn SystemDnsRedirectPort> = redirect.clone();
            let stop = Arc::clone(&stop);
            let raised = Arc::clone(&recheck);
            move || {
                DnsResolverService::guard(
                    redirect,
                    RedirectHandle {
                        marker: "test".to_string(),
                        listener: "127.0.0.1:0".parse().expect("addr"),
                    },
                    Duration::from_secs(3600),
                    stop,
                    NamespaceClaims {
                        source: Some(source),
                        published: ClaimsSnapshot::default(),
                        feed: Some(ChangeFeed {
                            raised,
                            safety_interval: Duration::from_secs(3600),
                        }),
                    },
                    std::mem::take(&mut applied),
                    ShortNameUpkeep::default(),
                );
            }
        });

        claimed.store(true, Ordering::SeqCst);
        recheck.store(true, Ordering::SeqCst);

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if !redirect.exempted.lock().expect("lock").is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        stop.store(true, Ordering::SeqCst);
        let _ = guard.join();

        assert_eq!(
            redirect.exempted.lock().expect("lock").clone(),
            vec![vec!["branch.corp.example".to_string()]],
            "the wake must not wait out the guard interval"
        );
    }

    /// Nothing claimed is the ordinary machine, and it must cost nothing: no
    /// call at all, so a table that needs no narrowing is never rewritten.
    #[test]
    fn a_machine_where_nothing_is_claimed_is_never_narrowed() {
        let stop = Arc::new(AtomicBool::new(false));
        let redirect = Arc::new(RecordingRedirect {
            flip_stop: Some(Arc::clone(&stop)),
            ..Default::default()
        });
        let service =
            DnsResolverService::new(listener(), redirect.clone(), "127.0.0.1:0".parse().unwrap())
                .with_namespace_exemptions(Arc::new(Vec::new));

        assert_eq!(service.run(&stop), DnsResolverRunOutcome::ServedAndRestored);
        let calls = redirect.calls.lock().unwrap().clone();
        assert!(!calls.contains(&"exempt"), "{calls:?}");
    }

    /// Without a source wired every name is claimed, unfiltered — the control
    /// that keeps the two tests above honest about what the source is doing.
    #[test]
    fn an_unwired_source_claims_every_name_as_before() {
        let stop = Arc::new(AtomicBool::new(false));
        let redirect = Arc::new(RecordingRedirect {
            flip_stop: Some(Arc::clone(&stop)),
            ..Default::default()
        });
        let service =
            DnsResolverService::new(listener(), redirect.clone(), "127.0.0.1:0".parse().unwrap());
        assert_eq!(service.run(&stop), DnsResolverRunOutcome::ServedAndRestored);
        assert!(redirect.exempted.lock().unwrap().is_empty());
    }

    #[test]
    fn binds_redirects_then_restores_in_order() {
        // `stop` starts false (a genuine arm), and the redirect fake flips it to
        // true the instant the redirect installs, so the serve loop exits on its
        // first poll — exercising the full install → serve → restore path.
        let stop = Arc::new(AtomicBool::new(false));
        let redirect = Arc::new(RecordingRedirect {
            flip_stop: Some(Arc::clone(&stop)),
            ..Default::default()
        });
        // Ephemeral loopback port — no privilege, no clash with a real :53.
        let service =
            DnsResolverService::new(listener(), redirect.clone(), "127.0.0.1:0".parse().unwrap());
        let outcome = service.run(&stop);
        assert_eq!(outcome, DnsResolverRunOutcome::ServedAndRestored);
        let calls = redirect.calls.lock().unwrap().clone();
        // redirect_to happens-before restore; the activation flush is between.
        let redirect_at = calls.iter().position(|c| *c == "redirect_to").unwrap();
        let restore_at = calls.iter().position(|c| *c == "restore").unwrap();
        assert!(
            redirect_at < restore_at,
            "redirect must precede restore: {calls:?}"
        );
        assert!(calls.contains(&"flush"), "cache must be flushed: {calls:?}");
    }

    #[test]
    fn cancel_during_bind_skips_redirect_entirely() {
        // `stop` already set before `run` reaches the redirect
        // (a mode set A racing a set B): the resolver must NOT touch system DNS.
        let redirect = Arc::new(RecordingRedirect::default());
        let service =
            DnsResolverService::new(listener(), redirect.clone(), "127.0.0.1:0".parse().unwrap());
        let stop = AtomicBool::new(true);
        let outcome = service.run(&stop);
        assert_eq!(outcome, DnsResolverRunOutcome::CancelledBeforeRedirect);
        let calls = redirect.calls.lock().unwrap().clone();
        assert!(
            calls.is_empty(),
            "a cancelled arm must never redirect, flush, or restore: {calls:?}"
        );
    }

    #[test]
    fn redirect_failure_calls_restore_as_a_backstop() {
        // `redirect_to` can fail after applying part of a multi-step change;
        // `run` must call `restore` as a backstop even though it holds no
        // handle from a successful `redirect_to`.
        struct FailRedirect {
            restore_calls: Mutex<u32>,
        }
        impl SystemDnsRedirectPort for FailRedirect {
            fn redirect_to(&self, _l: SocketAddr) -> Result<RedirectHandle, PlatformError> {
                Err(PlatformError::Transient {
                    operation: "test",
                    detail: "boom".to_string(),
                })
            }
            fn restore(&self, _h: &RedirectHandle) -> Result<(), PlatformError> {
                *self.restore_calls.lock().unwrap() += 1;
                Ok(())
            }
            fn verify(&self, _h: &RedirectHandle) -> Result<RedirectState, PlatformError> {
                Ok(RedirectState::Inactive)
            }
        }
        let redirect = Arc::new(FailRedirect {
            restore_calls: Mutex::new(0),
        });
        let service =
            DnsResolverService::new(listener(), redirect.clone(), "127.0.0.1:0".parse().unwrap());
        // `stop` false so `run` reaches the (failing) redirect; a preset stop
        // would instead short-circuit as CancelledBeforeRedirect and never
        // exercise the redirect-failure path this test covers.
        let stop = AtomicBool::new(false);
        assert_eq!(service.run(&stop), DnsResolverRunOutcome::RedirectFailed);
        assert_eq!(
            *redirect.restore_calls.lock().unwrap(),
            1,
            "restore must run as a backstop after a failed redirect_to"
        );
        assert!(!stop.load(Ordering::SeqCst));
    }

    #[test]
    fn redirect_failure_survives_a_failing_restore_without_panicking() {
        // The backstop `restore` itself can fail (the same broken mechanism
        // that made `redirect_to` fail); `run` must still return cleanly
        // rather than propagate or ignore the double failure.
        struct DoubleFailRedirect;
        impl SystemDnsRedirectPort for DoubleFailRedirect {
            fn redirect_to(&self, _l: SocketAddr) -> Result<RedirectHandle, PlatformError> {
                Err(PlatformError::Transient {
                    operation: "test",
                    detail: "boom".to_string(),
                })
            }
            fn restore(&self, _h: &RedirectHandle) -> Result<(), PlatformError> {
                Err(PlatformError::Transient {
                    operation: "test",
                    detail: "restore also boom".to_string(),
                })
            }
            fn verify(&self, _h: &RedirectHandle) -> Result<RedirectState, PlatformError> {
                Ok(RedirectState::Inactive)
            }
        }
        let service = DnsResolverService::new(
            listener(),
            Arc::new(DoubleFailRedirect),
            "127.0.0.1:0".parse().unwrap(),
        );
        let stop = AtomicBool::new(false);
        assert_eq!(service.run(&stop), DnsResolverRunOutcome::RedirectFailed);
    }

    // ── DnsResolverController (live re-arm) ───────────────────────────────────

    #[test]
    fn controller_apply_is_noop_without_factory() {
        // No factory wired (e.g. deps missing) → apply must fail-open, never
        // pretend to be running.
        let controller = DnsResolverController::new();
        controller.apply(EnforcementMode::Resolver);
        assert!(!controller.is_running());
        controller.apply(EnforcementMode::Reactive);
        assert!(!controller.is_running());
    }

    #[test]
    fn controller_start_is_fail_open_when_factory_returns_none() {
        // A factory that refuses to arm (no upstream) leaves the resolver off.
        let controller = DnsResolverController::new();
        controller.set_factory(Arc::new(|| Err(ArmRefusal::Unavailable)));
        controller.apply(EnforcementMode::Resolver);
        assert!(!controller.is_running());
    }

    #[test]
    fn controller_start_then_stop_restores_and_is_idempotent() {
        let redirect = Arc::new(RecordingRedirect::default());
        let redirect_for_factory = Arc::clone(&redirect);
        let controller = DnsResolverController::new();
        // Ephemeral loopback port — no privilege, no clash with a real :53.
        controller.set_factory(Arc::new(move || {
            Ok(DnsResolverService::new(
                listener(),
                Arc::clone(&redirect_for_factory) as Arc<dyn SystemDnsRedirectPort>,
                "127.0.0.1:0".parse().unwrap(),
            ))
        }));

        assert!(!controller.is_running());
        controller.apply(EnforcementMode::Resolver);
        assert!(
            controller.is_running(),
            "Resolver mode must start the thread"
        );
        // Redundant re-apply of the same mode must NOT flap (idempotent).
        controller.apply(EnforcementMode::Resolver);
        assert!(controller.is_running());

        // Wait until the arm has actually installed the redirect before
        // switching back. A real mode switch happens after the resolver is up,
        // not within microseconds of the spawn; a stop that beats the redirect
        // legitimately cancels the arm, so racing the stop here would flakily
        // skip the redirect this test asserts.
        for _ in 0..200 {
            if redirect.calls.lock().unwrap().contains(&"redirect_to") {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        // Reactive stops + JOINS the thread → the redirect is restored.
        controller.apply(EnforcementMode::Reactive);
        assert!(
            !controller.is_running(),
            "Reactive mode must stop the thread"
        );
        controller.apply(EnforcementMode::Reactive); // idempotent no-op

        let calls = redirect.calls.lock().unwrap().clone();
        assert!(
            calls.contains(&"redirect_to"),
            "resolver must have redirected: {calls:?}"
        );
        assert!(
            calls.contains(&"restore"),
            "stop must restore system DNS: {calls:?}"
        );
    }

    #[test]
    fn controller_shutdown_latches_against_rearm() {
        // Regression: an IPC set(Resolver) racing service teardown must NOT be
        // able to re-arm the resolver after the terminal shutdown, or the fresh
        // NRPT redirect + :53 bind would outlive the process.
        let redirect = Arc::new(RecordingRedirect::default());
        let redirect_for_factory = Arc::clone(&redirect);
        let controller = DnsResolverController::new();
        controller.set_factory(Arc::new(move || {
            Ok(DnsResolverService::new(
                listener(),
                Arc::clone(&redirect_for_factory) as Arc<dyn SystemDnsRedirectPort>,
                "127.0.0.1:0".parse().unwrap(),
            ))
        }));
        controller.apply(EnforcementMode::Resolver);
        assert!(controller.is_running());

        // Terminal shutdown stops (restores DNS) AND latches against re-arm.
        controller.shutdown();
        assert!(!controller.is_running());
        // A racing set(Resolver) / start() after shutdown must be a no-op.
        controller.apply(EnforcementMode::Resolver);
        controller.start();
        assert!(
            !controller.is_running(),
            "shutdown must permanently latch against re-arm"
        );
    }

    #[test]
    fn watchdog_tick_rearms_a_dead_resolver_but_respects_shutdown() {
        // the Mode-B serve loop can exit unexpectedly (the
        // per-datagram 10054 fix covers the common case; this watchdog covers
        // anything else). `tick()` must re-arm a resolver that is DESIRED but not
        // running — yet must NEVER re-arm after a terminal shutdown.
        let redirect = Arc::new(RecordingRedirect::default());
        let redirect_for_factory = Arc::clone(&redirect);
        let controller = DnsResolverController::new();

        // Desire Resolver mode while arming is impossible (factory yields None):
        // `desired == true`, but nothing is running.
        controller.set_factory(Arc::new(|| Err(ArmRefusal::Unavailable)));
        controller.apply(EnforcementMode::Resolver);
        assert!(!controller.is_running(), "a None factory cannot arm");

        // A real factory is now available; the watchdog tick must re-arm.
        controller.set_factory(Arc::new(move || {
            Ok(DnsResolverService::new(
                listener(),
                Arc::clone(&redirect_for_factory) as Arc<dyn SystemDnsRedirectPort>,
                "127.0.0.1:0".parse().unwrap(),
            ))
        }));
        controller.tick();
        assert!(
            controller.is_running(),
            "watchdog must re-arm a desired-but-dead resolver"
        );

        // After terminal shutdown the watchdog must NOT resurrect it.
        controller.shutdown();
        assert!(!controller.is_running());
        controller.tick();
        assert!(
            !controller.is_running(),
            "watchdog must respect the shutdown latch"
        );
    }

    #[test]
    fn watchdog_leaves_an_unsigned_machine_to_the_sign_in_event() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let controller = DnsResolverController::new();
        controller.set_factory(Arc::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            Err(ArmRefusal::AwaitingSignIn)
        }));
        controller.apply(EnforcementMode::Resolver);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        for _ in 0..(RESOLVER_RESTART_BACKOFF_TICKS * 3 + 3) {
            controller.tick();
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "before sign-in the watchdog must not retry"
        );

        controller.start();
        assert_eq!(calls.load(Ordering::SeqCst), 2, "sign-in arms again");
    }
}
