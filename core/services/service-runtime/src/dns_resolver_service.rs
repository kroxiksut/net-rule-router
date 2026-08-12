//! Mode B (local DNS resolver) runtime lifecycle — binds the loopback DNS
//! listener, points the OS at it, serves until stop, and restores the OS DNS on
//! the way out. Off by default; wired only when `EnforcementMode::Resolver` is
//! active and the platform supports system-DNS redirect (HW-0709, phase 1e).
//!
//! Split out of the boot wiring so the redirect lifecycle — order, fail-safe
//! teardown, cache flush — is unit-testable with a fake redirect + an ephemeral
//! socket, independent of a live Windows DNS client or a privileged `:53` bind.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use nrr_domain::enforcement_mode::EnforcementMode;
use nrr_platform_api::dns_redirect::SystemDnsRedirectPort;

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
    /// Bound, but pointing the OS at us failed. The socket is dropped and the
    /// OS DNS is left exactly as it was (fail-open — general DNS keeps working).
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

/// Owns the Mode-B intercept listener plus the system-DNS redirect port and
/// drives their combined lifecycle in one blocking call.
pub struct DnsResolverService {
    listener: DnsInterceptListener,
    redirect: Arc<dyn SystemDnsRedirectPort>,
    listen_addr: SocketAddr,
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
                    addr = %self.listen_addr,
                    "Mode B: could not bind the DNS listener ({error}); resolver disabled, \
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
        // used to complete the full install→restore cycle even though the user
        // had already switched back to mode A — stranding DNS on the loopback
        // listener for the round-trip. Checking `stop` here makes an arm that
        // is already superseded a no-op that never redirects.
        if stop.load(Ordering::SeqCst) {
            tracing::info!(
                target: "nrr::dns-resolver",
                "Mode B: arm cancelled during bind (mode switched back before redirect); \
                 system DNS untouched",
            );
            return DnsResolverRunOutcome::CancelledBeforeRedirect;
        }

        let handle = match self.redirect.redirect_to(self.listen_addr) {
            Ok(handle) => handle,
            Err(error) => {
                tracing::warn!(
                    target: "nrr::dns-resolver",
                    addr = %self.listen_addr,
                    "Mode B: system-DNS redirect failed ({error}); resolver disabled, \
                     system DNS untouched",
                );
                return DnsResolverRunOutcome::RedirectFailed;
            }
        };
        // A warm OS cache would otherwise bypass us on first contact (HW-0709
        // review). Best-effort: a flush failure is logged, not fatal.
        if let Err(error) = self.redirect.flush_cache() {
            tracing::warn!(
                target: "nrr::dns-resolver",
                "Mode B: DNS cache flush on activation failed ({error}); warm entries may \
                 bypass the resolver until they expire",
            );
        }
        tracing::info!(
            target: "nrr::dns-resolver",
            addr = %self.listen_addr,
            "Mode B: DNS resolver active — system DNS redirected to the loopback listener",
        );

        let serve_result = self.listener.serve_udp(&socket, stop);

        // Fail-safe teardown: restore no matter how the serve loop ended.
        if let Err(error) = self.redirect.restore(&handle) {
            tracing::error!(
                target: "nrr::dns-resolver",
                "Mode B: FAILED to restore system DNS ({error}); if name resolution is \
                 broken, remove the NetRuleRouter NRPT rule manually \
                 (Get-DnsClientNrptRule / Remove-DnsClientNrptRule)",
            );
        } else {
            let _ = self.redirect.flush_cache();
            tracing::info!(
                target: "nrr::dns-resolver",
                "Mode B: DNS resolver stopped — system DNS restored",
            );
        }
        if let Err(error) = serve_result {
            tracing::warn!(
                target: "nrr::dns-resolver",
                "Mode B: DNS serve loop ended with an error ({error})",
            );
        }
        DnsResolverRunOutcome::ServedAndRestored
    }
}

/// Builds a fresh [`DnsResolverService`] on demand. Each call re-captures the
/// current upstream DNS + rebuilds the listener, so a runtime start after a
/// network change is correct. Returns `None` when the resolver cannot be safely
/// armed (no upstream captured, missing deps) — the controller then stays
/// reactive (fail-open, general DNS untouched). Injected from the platform boot
/// wiring so the concrete OS construction (NRPT redirect, upstream capture) stays
/// in the windows-service crate, not in this generic control logic.
pub type DnsResolverFactory = Arc<dyn Fn() -> Option<DnsResolverService> + Send + Sync>;

/// Runtime start/stop controller for the Mode-B resolver, so switching
/// [`EnforcementMode`] takes effect WITHOUT a service restart (HW-0710). Owns the
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
    /// held the reply past the GUI's 30 s RPC deadline («Превышено время
    /// ожидания» on the 0717 run). Records the desired mode first, then
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
        Self::start_locked(&mut inner);
    }

    /// Watchdog tick — call periodically (e.g. from the reconcile safety tick).
    /// Re-arms the resolver when Mode B is the desired mode but the serve thread
    /// has exited unexpectedly (the per-datagram 10054 fix covers the common case;
    /// this catches anything else). No-op when disarmed, when Reactive is desired,
    /// or while backing off after a failed re-arm. Idempotent and cheap.
    pub fn tick(&self) {
        let mut inner = self.lock();
        if inner.disarmed || !inner.desired {
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
                "Mode B: start requested but no resolver factory is wired; staying reactive",
            );
            return;
        };
        // Re-captures the current upstream DNS (the network may have changed
        // since boot). A failure to arm is fail-open — general DNS keeps working.
        let Some(service) = factory() else {
            tracing::warn!(
                target: "nrr::dns-resolver",
                "Mode B: resolver could not be armed (no upstream / deps); staying reactive",
            );
            return;
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
                    "Mode B: DNS resolver thread started",
                );
                inner.running = Some((stop, join));
            }
            Err(e) => {
                tracing::error!(
                    target: "nrr::dns-resolver",
                    "Mode B: failed to spawn DNS resolver thread ({e}); staying reactive",
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
                    "Mode B: DNS resolver thread panicked during stop",
                );
            } else {
                tracing::info!(
                    target: "nrr::dns-resolver",
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
        FactSink, ReconcileOutcome, ResolveError, ResolvedA, RuleHostOracle, SyncReconciler,
        UpstreamResolver,
    };
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
        fn resolve_a(&self, _hostname: &str) -> Result<ResolvedA, ResolveError> {
            Err(ResolveError::NoRecords)
        }
    }
    struct NoopSink;
    impl FactSink for NoopSink {
        fn record(&self, _hostname: &str, _resolved: &ResolvedA) {}
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
    }
    impl SystemDnsRedirectPort for RecordingRedirect {
        fn redirect_to(&self, listener: SocketAddr) -> Result<RedirectHandle, PlatformError> {
            self.calls.lock().unwrap().push("redirect_to");
            if let Some(stop) = self.flip_stop.as_ref() {
                stop.store(true, Ordering::SeqCst);
            }
            Ok(RedirectHandle {
                marker: "test".to_string(),
                listener,
            })
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
    fn redirect_failure_leaves_dns_untouched() {
        struct FailRedirect;
        impl SystemDnsRedirectPort for FailRedirect {
            fn redirect_to(&self, _l: SocketAddr) -> Result<RedirectHandle, PlatformError> {
                Err(PlatformError::Transient {
                    operation: "test",
                    detail: "boom".to_string(),
                })
            }
            fn restore(&self, _h: &RedirectHandle) -> Result<(), PlatformError> {
                panic!("restore must not run when redirect never installed")
            }
            fn verify(&self, _h: &RedirectHandle) -> Result<RedirectState, PlatformError> {
                Ok(RedirectState::Inactive)
            }
        }
        let service = DnsResolverService::new(
            listener(),
            Arc::new(FailRedirect),
            "127.0.0.1:0".parse().unwrap(),
        );
        // `stop` false so `run` reaches the (failing) redirect; a preset stop
        // would now short-circuit as CancelledBeforeRedirect (HW-0720) and never
        // exercise the redirect-failure path this test covers.
        let stop = AtomicBool::new(false);
        assert_eq!(service.run(&stop), DnsResolverRunOutcome::RedirectFailed);
        // No panic from restore ⇒ we never touched (or restored) system DNS.
        assert!(!stop.load(Ordering::SeqCst));
    }

    // ── DnsResolverController (HW-0710 live re-arm) ───────────────────────────

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
        controller.set_factory(Arc::new(|| None));
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
            Some(DnsResolverService::new(
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
        // now legitimately cancels the arm (HW-0720), so racing the stop here
        // would flakily skip the redirect this test asserts.
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
            Some(DnsResolverService::new(
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
        controller.set_factory(Arc::new(|| None));
        controller.apply(EnforcementMode::Resolver);
        assert!(!controller.is_running(), "a None factory cannot arm");

        // A real factory is now available; the watchdog tick must re-arm.
        controller.set_factory(Arc::new(move || {
            Some(DnsResolverService::new(
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
}
