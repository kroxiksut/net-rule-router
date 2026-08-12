//! Assembling and running the fake-IP data path.
//!
//! Two pieces the service needs on top of the neutral relay/stack:
//!
//! - [`FakeIpAssembly`] — the shared state that makes the DNS side and the
//!   packet side agree. The resolver's [`ScopedFakeIpAnswerer`] allocates a
//!   hostname's fake address when it answers a query; the stack's relay looks
//!   that same address back up to the hostname when a packet arrives. They MUST
//!   share ONE allocator (and one scope), or a query would hand out an address
//!   the stack cannot resolve. The assembly owns that single allocator and
//!   builds both halves from it.
//! - [`FakeIpController`] — starts and stops the stack thread when the feature
//!   is toggled, without a service restart. Mirrors the Mode-B
//!   [`crate::dns_resolver_service::DnsResolverController`]: an injected factory
//!   builds the OS TUN + stack on start (so the Wintun/utun/dev-tun construction
//!   stays in the platform boot wiring, not in this neutral control logic), and
//!   stop signals the run loop AND unblocks its reader.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;

use nrr_platform_api::fake_ip::tun::{TunControl, TunDevice};
use nrr_platform_api::fake_ip::{
    FakeIpAllocator, FakeIpPoolConfig, FakeIpScope, NoopStaleFlowReset, StaleFlowReset,
};

use crate::dns_resolver::ScopedFakeIpAnswerer;

use super::dialer::RelayDialer;
use super::relay::{RelayCore, RouteSelector, UpstreamAddressResolver};
use super::stack::{FakeIpStack, StackWaker};

/// The shared allocator + scope + pool that tie the DNS answer to the packet
/// relay. Cheap to clone-share via the internal `Arc`.
pub struct FakeIpAssembly {
    allocator: Arc<Mutex<FakeIpAllocator>>,
    scope: FakeIpScope,
    pool: FakeIpPoolConfig,
    /// Session `hostname → real IPs` for DIRECT hosts answered with a
    /// fake address under the armed block-all. Shared between the direct
    /// answerer (writer) and the relay's upstream resolver (reader).
    direct_map: Arc<super::direct::DirectRealIpMap>,
    /// VPN self-heal — hostnames excluded from fake-IP at runtime because a VPN
    /// client was seen reaching them through the relay. Shared between both
    /// answerers (readers) and the self-heal observer (writer).
    runtime_exclusions: Arc<super::self_heal::RuntimeHostExclusions>,
    /// Datapath-health pulse (answers vs. ingress) shared between the answerers,
    /// the stack and the controller watchdog.
    health: Arc<super::health::FakeIpHealth>,
    /// Confirmed-VPN-client bypass handed to every stack this assembly builds —
    /// a relayed flow owned by the client that establishes the secondary link
    /// leaves over the primary instead. Inert until the boot wiring supplies an
    /// owner lookup.
    vpn_bypass: Arc<dyn super::vpn_client_bypass::VpnClientFlowBypass>,
    /// Tears down TCP connections a previous run left pointing at now-dead fake
    /// addresses, swept once as each stack comes up. Inert until the boot
    /// wiring supplies an OS mechanism.
    stale_flow_reset: Arc<dyn StaleFlowReset>,
}

impl FakeIpAssembly {
    /// Build over a fresh allocator for `pool`, applying `scope`.
    #[must_use]
    pub fn new(scope: FakeIpScope, pool: FakeIpPoolConfig) -> Self {
        Self {
            allocator: Arc::new(Mutex::new(FakeIpAllocator::new(pool))),
            scope,
            pool,
            direct_map: Arc::new(super::direct::DirectRealIpMap::new()),
            runtime_exclusions: Arc::new(super::self_heal::RuntimeHostExclusions::new()),
            health: Arc::new(super::health::FakeIpHealth::new()),
            vpn_bypass: Arc::new(super::vpn_client_bypass::NoVpnClientBypass),
            stale_flow_reset: Arc::new(NoopStaleFlowReset),
        }
    }

    /// Wire the confirmed-VPN-client bypass every later [`Self::build_stack`]
    /// hands to its relay. Builder-style, applied by the boot wiring (which owns
    /// the OS flow-owner lookup) before the assembly is shared; the default never
    /// bypasses, so every existing composition is unchanged.
    #[must_use]
    pub fn with_vpn_client_bypass(
        mut self,
        bypass: Arc<dyn super::vpn_client_bypass::VpnClientFlowBypass>,
    ) -> Self {
        self.vpn_bypass = bypass;
        self
    }

    /// Wire the stale-flow sweep every later [`Self::build_stack`] runs once as
    /// the stack comes up. Builder-style, applied by the boot wiring (which owns
    /// the OS connection-table mechanism) before the assembly is shared; the
    /// default tears nothing down, so every existing composition is unchanged.
    #[must_use]
    pub fn with_stale_flow_reset(mut self, reset: Arc<dyn StaleFlowReset>) -> Self {
        self.stale_flow_reset = reset;
        self
    }

    /// The shared datapath-health counters, so the boot wiring can hand the
    /// same pulse to the controller watchdog.
    #[must_use]
    pub fn health(&self) -> Arc<super::health::FakeIpHealth> {
        Arc::clone(&self.health)
    }

    /// The shared runtime exclusion set (VPN self-heal), so the boot wiring can
    /// hand the same set to the self-heal observer that both answerers read.
    #[must_use]
    pub fn runtime_exclusions(&self) -> Arc<super::self_heal::RuntimeHostExclusions> {
        Arc::clone(&self.runtime_exclusions)
    }

    #[must_use]
    pub fn pool(&self) -> &FakeIpPoolConfig {
        &self.pool
    }

    /// Mirror the allocator into a persistence layer: seed it from `persisted`
    /// (oldest-touched first, as loaded) and register `sink` for every later
    /// change. A hostname then keeps its fake address across service restarts
    /// — the address is its stable identity, not a per-run accident.
    pub fn attach_binding_persistence(
        &self,
        persisted: Vec<(String, u32)>,
        sink: nrr_platform_api::fake_ip::BindingChangeSink,
    ) {
        let mut allocator = self.allocator.lock().unwrap_or_else(|p| p.into_inner());
        allocator.restore(persisted);
        allocator.set_change_sink(sink);
    }

    /// The DNS-side answerer, sharing this assembly's allocator, scope and
    /// runtime exclusion set (so a VPN-self-healed host keeps its real address).
    #[must_use]
    pub fn answerer(&self) -> ScopedFakeIpAnswerer {
        ScopedFakeIpAnswerer::new(self.scope.clone(), Arc::clone(&self.allocator))
            .with_runtime_exclusions(Arc::clone(&self.runtime_exclusions))
            .with_health(Arc::clone(&self.health))
    }

    /// The DIRECT-host answerer for the armed block-all,
    /// sharing this assembly's allocator, scope and direct-host map. `armed`
    /// is the same latch the [`crate::dns_resolver_ports::ReconcilingDirectAnswerGate`]
    /// reads.
    #[must_use]
    pub fn direct_answerer(
        &self,
        armed: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> super::direct::ArmedDirectFakeIpAnswerer {
        super::direct::ArmedDirectFakeIpAnswerer::new(
            self.scope.clone(),
            Arc::clone(&self.allocator),
            Arc::clone(&self.direct_map),
            armed,
        )
        .with_runtime_exclusions(Arc::clone(&self.runtime_exclusions))
        .with_health(Arc::clone(&self.health))
    }

    /// Wrap `inner` (the FQDN-cache resolver) so the relay resolves
    /// DIRECT hosts from this assembly's map first. Boot wiring passes the
    /// result to [`Self::build_stack`].
    #[must_use]
    pub fn direct_aware_resolver(
        &self,
        inner: Arc<dyn UpstreamAddressResolver>,
    ) -> super::direct::DirectAwareUpstreamResolver {
        super::direct::DirectAwareUpstreamResolver::new(Arc::clone(&self.direct_map), inner)
    }

    /// Read-only diagnostics view over the SAME allocator, for the
    /// cache viewer / explain ("show the virtual address next to the real
    /// one"). Never allocates — a host outside the map reads as `None`.
    #[must_use]
    pub fn binding_view(&self) -> FakeIpBindingView {
        FakeIpBindingView {
            allocator: Arc::clone(&self.allocator),
        }
    }

    /// Build the packet-side stack over `device`, sharing this assembly's
    /// allocator and scope with the answerer. `resolver` and `routes` are the
    /// production port adapters ([`super::production_ports`]).
    #[must_use]
    pub fn build_stack(
        &self,
        device: Box<dyn TunDevice>,
        dialer: Arc<dyn RelayDialer>,
        resolver: Arc<dyn UpstreamAddressResolver>,
        routes: Arc<dyn RouteSelector>,
        waker: Arc<StackWaker>,
    ) -> FakeIpStack {
        self.sweep_stale_flows();
        let relay = RelayCore::new(
            Arc::clone(&self.allocator),
            self.scope.clone(),
            resolver,
            routes,
        )
        .with_vpn_client_bypass(Arc::clone(&self.vpn_bypass));
        FakeIpStack::new(device, &self.pool, relay, dialer, waker)
            .with_health(Arc::clone(&self.health))
    }

    /// Tear down TCP connections a previous run left pointing at now-dead fake
    /// addresses, once as this stack comes up. The common case — a clean start
    /// — finds nothing and stays quiet; a non-empty sweep means the last run
    /// left applications holding dead sockets, worth an info line for run
    /// triage.
    fn sweep_stale_flows(&self) {
        let sweep = self
            .stale_flow_reset
            .reset_flows_to(self.pool.v4_base, self.pool.v4_prefix_len);
        if sweep.is_empty() {
            tracing::debug!(
                target: "nrr::fake_ip",
                "stale-flow sweep found nothing in the fake-IP pool — clean start",
            );
        } else {
            tracing::info!(
                target: "nrr::fake_ip",
                found = sweep.found,
                torn_down = sweep.torn_down,
                "stale-flow sweep tore down sockets a previous run left pointing at dead fake addresses",
            );
        }
    }
}

/// Cheap clone-shared, read-only `hostname → fake address` lookup for
/// diagnostics surfaces (cache viewer / explain). Wraps the assembly's shared
/// allocator; lookups go through [`FakeIpAllocator::binding_for_domain`],
/// which never allocates and never touches LRU order — a diagnostics page can
/// never grow the pool.
#[derive(Clone)]
pub struct FakeIpBindingView {
    allocator: Arc<Mutex<FakeIpAllocator>>,
}

impl FakeIpBindingView {
    /// The IPv4 fake address currently bound to `hostname`, if any.
    #[must_use]
    pub fn fake_v4_for(&self, hostname: &str) -> Option<std::net::Ipv4Addr> {
        let guard = self.allocator.lock().unwrap_or_else(|p| p.into_inner());
        guard.binding_for_domain(hostname).map(|b| b.v4)
    }
}

/// Builds the OS TUN adapter + [`FakeIpStack`] on demand. `None` means the stack
/// could not be brought up (driver missing, adapter create failed) — the
/// controller then stays off, leaving routing untouched (fail-open on the
/// feature, exactly like the Mode-B resolver factory).
pub type FakeIpStackFactory = Arc<dyn Fn() -> Option<FakeIpStack> + Send + Sync>;

/// See [`FakeIpController::datapath_status`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeIpDatapathStatus {
    pub desired: bool,
    pub running: bool,
    pub zombies: usize,
}

/// Runtime start/stop for the fake-IP stack thread, so toggling the feature
/// takes effect without a service restart. `apply` / `start` / `stop` are
/// idempotent.
#[derive(Default)]
pub struct FakeIpController {
    inner: Mutex<ControllerInner>,
}

#[derive(Default)]
struct ControllerInner {
    factory: Option<FakeIpStackFactory>,
    running: Option<RunningStack>,
    /// What the user last asked for — surfaced for a watchdog / diagnostics.
    desired: bool,
    /// Terminal latch (service teardown): once set, `start` is a permanent no-op
    /// so a toggle racing shutdown cannot re-arm a TUN that outlives the process.
    disarmed: bool,
    /// Shared datapath pulse the watchdog reads (answers vs. ingress).
    health: Option<Arc<super::health::FakeIpHealth>>,
    watchdog: WatchdogState,
    /// Stack threads that ignored the stop grace and were detached — a wedged
    /// TUN datapath can hold `join()` (and with it this controller's mutex)
    /// for minutes. They still own the old adapter, so `start`
    /// defers until they finally exit and are reaped. Each keeps its
    /// `TunControl` so every reap pass can re-fire the (idempotent) shutdown
    /// wake-up — a reader that missed the first signal gets another chance
    /// every tick instead of sleeping out its own timeout (observed taking
    /// up to 215 s to exit on a single wake-up).
    zombies: Vec<ZombieStack>,
    /// A desired stack went down without a user toggle (detached stop or a
    /// self-exited thread) — the watchdog tick keeps retrying the start until
    /// it succeeds. Gated so a factory that cannot build (driver missing) is
    /// not hammered every tick for a stack that never lived.
    restart_pending: bool,
    /// The datapath went DOWN outside a clean user toggle (detached stop /
    /// self-exited thread). The next watchdog tick reports a bring-up-style
    /// `true` to its caller even when no fresh stack could start, so the
    /// caller re-runs the enforcement replan and flushes the OS DNS cache —
    /// otherwise applications keep dialling their CACHED virtual addresses
    /// into a dead TUN for the whole outage (observed hitting WFP walls on
    /// stale fake answers for several minutes).
    down_flush_pending: bool,
}

/// A detached stack thread plus the control handle needed to keep nudging it.
struct ZombieStack {
    join: JoinHandle<()>,
    control: Arc<dyn TunControl>,
}

/// Per-tick bookkeeping for the "answers without ingress" wedge detector, and
/// the relay dial-activity delta logger.
#[derive(Default)]
struct WatchdogState {
    last_answers: u64,
    last_ingress: u64,
    strikes: u32,
    last_rebuild: Option<std::time::Instant>,
    last_tcp_relay_flows_opened: u64,
    last_tcp_dial_ok: u64,
    last_tcp_dial_refused: u64,
    last_tcp_dial_failed: u64,
    last_udp_relay_flows_opened: u64,
    last_udp_dial_ok: u64,
    last_udp_dial_refused: u64,
    last_udp_dial_failed: u64,
    last_udp_unreachable_sent: u64,
    /// Rate limit for the "desired but not running" outage warning — the one
    /// periodic signal that survives a dead stack (every per-flow event source
    /// lives inside the stack and goes silent with it).
    last_outage_warn: Option<std::time::Instant>,
}

/// A tick counts as a strike when at least this many virtual addresses were
/// handed out while the stack read ZERO packets. Low on purpose: under an
/// armed block-all everything resolves through the answerers, so a wedged
/// datapath accumulates answers fast.
const WATCHDOG_MIN_ANSWERS_PER_TICK: u64 = 2;
/// Consecutive strikes before the stack is rebuilt. With the ~5 s runtime
/// tick this detects a wedge in ~15 s; without it, a wedge has run to 9
/// minutes of total blackout before a manual service restart.
const WATCHDOG_STRIKES_TO_REBUILD: u32 = 3;
/// Minimum spacing between watchdog rebuilds, so a genuinely dead driver
/// (rebuild does not help) cannot flap the adapter every few seconds.
const WATCHDOG_REBUILD_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(300);
/// How long a stop waits for the stack thread to exit before detaching it.
/// A healthy stop returns in milliseconds; a wedged datapath can hold the
/// thread for minutes, blocked inside the stop with the
/// controller mutex held — every toggle and watchdog tick jammed behind it.
/// The grace keeps a slow-but-alive stop intact while bounding the damage.
const STOP_JOIN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
/// Minimum spacing between "enabled but not running" outage warnings.
const OUTAGE_WARN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

struct RunningStack {
    stop: Arc<AtomicBool>,
    control: Arc<dyn TunControl>,
    join: JoinHandle<()>,
}

impl FakeIpController {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, ControllerInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Install the platform factory used to (re)build the stack on each start.
    pub fn set_factory(&self, factory: FakeIpStackFactory) {
        self.lock().factory = Some(factory);
    }

    /// Wire the shared datapath pulse so [`Self::watchdog_tick`] can compare
    /// answers handed out against packets actually read.
    pub fn set_health(&self, health: Arc<super::health::FakeIpHealth>) {
        self.lock().health = Some(health);
    }

    /// Reconcile to `enabled`: `true` → ensure running, `false` → ensure stopped.
    pub fn apply(&self, enabled: bool) {
        if enabled {
            self.start();
        } else {
            self.stop();
        }
    }

    /// Start the stack if not already running. Fail-open: a missing factory or a
    /// `None` build leaves the feature off.
    pub fn start(&self) {
        let mut inner = self.lock();
        inner.desired = true;
        Self::start_locked(&mut inner);
    }

    fn start_locked(inner: &mut ControllerInner) {
        if inner.disarmed {
            return;
        }
        Self::reap_finished(inner);
        if inner.running.is_some() {
            return;
        }
        if !inner.zombies.is_empty() {
            // The old thread still owns the TUN adapter; building a second
            // stack against the same adapter name would fail or fight it.
            // The watchdog tick retries the start once the zombie is reaped.
            tracing::info!(
                target: "nrr::fake-ip",
                zombies = inner.zombies.len(),
                "fake-IP start deferred — a detached stack thread has not exited yet",
            );
            return;
        }
        let Some(factory) = inner.factory.clone() else {
            tracing::warn!(
                target: "nrr::fake-ip",
                "fake-IP start requested but no stack factory is wired; feature stays off",
            );
            return;
        };
        let Some(mut stack) = factory() else {
            // The factory logs WHY it could not build (driver missing, adapter
            // open failed); this line records that a start was attempted.
            tracing::warn!(
                target: "nrr::fake-ip",
                "fake-IP start requested but the stack could not be built; feature stays off (fail-open)",
            );
            return;
        };
        let stop = Arc::new(AtomicBool::new(false));
        let control = stack.control();
        let thread_stop = Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            // A device error ends the loop — and under an armed block-all a
            // silently dead relay blacks out the whole machine, so the exit
            // itself must be loud.
            if let Err(e) = stack.run(&thread_stop) {
                tracing::warn!(
                    target: "nrr::fake-ip",
                    error = ?e,
                    "fake-IP stack run loop exited on a device error — relay is DOWN until restarted",
                );
            }
        });
        inner.running = Some(RunningStack {
            stop,
            control,
            join,
        });
        inner.restart_pending = false;
        tracing::info!(
            target: "nrr::fake-ip",
            "fake-IP stack started — virtual addresses are live",
        );
    }

    /// Stop the stack if running: set the flag, unblock the reader, join.
    pub fn stop(&self) {
        let mut inner = self.lock();
        inner.desired = false;
        Self::stop_locked(&mut inner);
    }

    fn stop_locked(inner: &mut ControllerInner) {
        let Some(running) = inner.running.take() else {
            return;
        };
        running.stop.store(true, Ordering::SeqCst);
        if let Err(e) = running.control.shutdown() {
            // Logged rather than swallowed: without the wake-up the reader
            // only notices the flag on its next poll — or never, when the
            // datapath below it is wedged, which is why a stop can then sit
            // in the join.
            tracing::warn!(
                target: "nrr::fake-ip",
                error = ?e,
                "fake-IP stack shutdown signal failed — the reader may not wake promptly",
            );
        }
        let deadline = std::time::Instant::now() + STOP_JOIN_GRACE;
        while !running.join.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if running.join.is_finished() {
            let _ = running.join.join();
            tracing::info!(
                target: "nrr::fake-ip",
                "fake-IP stack stopped — names resolve to real addresses again",
            );
        } else {
            tracing::warn!(
                target: "nrr::fake-ip",
                grace_ms = STOP_JOIN_GRACE.as_millis() as u64,
                "fake-IP stack thread ignored the stop grace — detached; the next start waits for it to exit (wedged datapath keeps the old adapter open until then)",
            );
            inner.zombies.push(ZombieStack {
                join: running.join,
                control: running.control,
            });
            inner.restart_pending = true;
            inner.down_flush_pending = true;
        }
    }

    /// True while a stack thread is live (and hasn't self-exited on error).
    pub fn is_running(&self) -> bool {
        let mut inner = self.lock();
        Self::reap_finished(&mut inner);
        inner.running.is_some()
    }

    /// Snapshot of the datapath for status surfaces: whether the user wants
    /// the feature on, whether a stack thread is actually live, and how many
    /// detached threads still block a rebuild. `desired && !running` is the
    /// "toggle says ON but nothing works" state a UI must surface.
    #[must_use]
    pub fn datapath_status(&self) -> FakeIpDatapathStatus {
        let mut inner = self.lock();
        Self::reap_finished(&mut inner);
        FakeIpDatapathStatus {
            desired: inner.desired && !inner.disarmed,
            running: inner.running.is_some(),
            zombies: inner.zombies.len(),
        }
    }

    /// True once [`Self::shutdown`] latched the controller off — lets a
    /// detached watchdog loop know it should end.
    #[must_use]
    pub fn is_shut_down(&self) -> bool {
        self.lock().disarmed
    }

    /// Stop and latch off — service teardown.
    pub fn shutdown(&self) {
        let mut inner = self.lock();
        inner.desired = false;
        inner.disarmed = true;
        Self::stop_locked(&mut inner);
    }

    /// Reap a thread that exited on its own (device error), so a later `start`
    /// spawns a fresh one instead of seeing a stale "running" handle. Also
    /// reaps detached zombies (see [`ControllerInner::zombies`]) so a deferred
    /// rebuild can proceed the moment the old thread is truly gone.
    fn reap_finished(inner: &mut ControllerInner) {
        if inner.running.as_ref().is_some_and(|r| r.join.is_finished()) {
            if let Some(r) = inner.running.take() {
                let _ = r.join.join();
                inner.restart_pending = true;
                inner.down_flush_pending = true;
                tracing::warn!(
                    target: "nrr::fake-ip",
                    "fake-IP stack thread had self-exited and was reaped — the relay was not running",
                );
            }
        }
        let mut i = 0;
        while i < inner.zombies.len() {
            if inner.zombies[i].join.is_finished() {
                let zombie = inner.zombies.swap_remove(i);
                let _ = zombie.join.join();
                tracing::info!(
                    target: "nrr::fake-ip",
                    "a detached fake-IP stack thread finally exited and was reaped — a rebuild can proceed",
                );
            } else {
                // Re-fire the (idempotent) shutdown wake-up: a reader that
                // missed the first signal sleeps out its own poll timeout
                // otherwise — repeated nudges shrink a multi-minute zombie
                // window to one poll interval.
                let _ = inner.zombies[i].control.shutdown();
                i += 1;
            }
        }
    }

    /// Periodic visibility for the relay dial/outcome mix, since
    /// per-connection events alone leave the UDP relay's behaviour to infer
    /// from their absence. Reuses the SAME tick as the wedge detector
    /// below — no new timer — and reads counters that are bumped once per
    /// FLOW, never once per packet (see [`super::health::FakeIpHealth`]), so
    /// this adds no per-packet cost. Only logs when something changed since
    /// the last tick, so an idle machine stays quiet.
    fn log_relay_activity_delta(inner: &mut ControllerInner) {
        let Some(health) = &inner.health else {
            return;
        };
        let tcp_flows = health.tcp_relay_flows_opened();
        let tcp_ok = health.tcp_dial_ok();
        let tcp_refused = health.tcp_dial_refused();
        let tcp_failed = health.tcp_dial_failed();
        let udp_flows = health.udp_relay_flows_opened();
        let udp_ok = health.udp_dial_ok();
        let udp_refused = health.udp_dial_refused();
        let udp_failed = health.udp_dial_failed();
        let udp_unreachable = health.udp_unreachable_sent();

        let w = &mut inner.watchdog;
        let tcp_flows_delta = tcp_flows.saturating_sub(w.last_tcp_relay_flows_opened);
        let tcp_ok_delta = tcp_ok.saturating_sub(w.last_tcp_dial_ok);
        let tcp_refused_delta = tcp_refused.saturating_sub(w.last_tcp_dial_refused);
        let tcp_failed_delta = tcp_failed.saturating_sub(w.last_tcp_dial_failed);
        let udp_flows_delta = udp_flows.saturating_sub(w.last_udp_relay_flows_opened);
        let udp_ok_delta = udp_ok.saturating_sub(w.last_udp_dial_ok);
        let udp_refused_delta = udp_refused.saturating_sub(w.last_udp_dial_refused);
        let udp_failed_delta = udp_failed.saturating_sub(w.last_udp_dial_failed);
        let udp_unreachable_delta = udp_unreachable.saturating_sub(w.last_udp_unreachable_sent);
        w.last_tcp_relay_flows_opened = tcp_flows;
        w.last_tcp_dial_ok = tcp_ok;
        w.last_tcp_dial_refused = tcp_refused;
        w.last_tcp_dial_failed = tcp_failed;
        w.last_udp_relay_flows_opened = udp_flows;
        w.last_udp_dial_ok = udp_ok;
        w.last_udp_dial_refused = udp_refused;
        w.last_udp_dial_failed = udp_failed;
        w.last_udp_unreachable_sent = udp_unreachable;

        if tcp_flows_delta > 0 || udp_flows_delta > 0 || udp_unreachable_delta > 0 {
            tracing::info!(
                target: "nrr::fake-ip",
                tcp_flows_opened = tcp_flows_delta,
                tcp_dial_ok = tcp_ok_delta,
                tcp_dial_refused = tcp_refused_delta,
                tcp_dial_failed = tcp_failed_delta,
                udp_flows_opened = udp_flows_delta,
                udp_dial_ok = udp_ok_delta,
                udp_dial_refused = udp_refused_delta,
                udp_dial_failed = udp_failed_delta,
                udp_unreachable_sent = udp_unreachable_delta,
                "fake-IP relay dial activity since last tick",
            );
        }
    }

    /// Periodic wedge detector: the stack thread can stay alive while the TUN
    /// datapath below it silently stops delivering packets (external filter
    /// interference, driver session stall — observed running to 9 minutes of
    /// virtual addresses answered with zero packets arriving, total blackout
    /// under block-all until a manual service restart). Compare the two pulses
    /// and rebuild the stack when answers keep flowing but ingress is flat for
    /// [`WATCHDOG_STRIKES_TO_REBUILD`] consecutive ticks.
    ///
    /// Returns `true` when the stack was torn down and rebuilt this tick —
    /// the caller then re-runs the enforcement replan + OS DNS cache flush,
    /// exactly like a boot bring-up.
    pub fn watchdog_tick(&self) -> bool {
        let mut inner = self.lock();
        Self::reap_finished(&mut inner);
        Self::log_relay_activity_delta(&mut inner);
        let (answers, ingress) = match (&inner.health, &inner.running) {
            (Some(health), Some(_)) => (health.answers(), health.ingress()),
            // Not running (or no pulse wired): re-baseline so a later start
            // never inherits a stale delta, and keep strikes clear. When the
            // stack is DESIRED but absent (a deferred rebuild after a detached
            // stop, or a self-exited thread), retry the start here — this tick
            // is the only periodic caller, so without the retry a deferred
            // rebuild would never happen.
            _ => {
                if let Some(health) = &inner.health {
                    let (answers, ingress) = (health.answers(), health.ingress());
                    inner.watchdog.last_answers = answers;
                    inner.watchdog.last_ingress = ingress;
                }
                inner.watchdog.strikes = 0;
                // A down-transition (detached stop / self-exited thread) owes
                // the caller ONE replan + OS DNS cache flush even when no
                // fresh stack can start yet: the replan drops the fake-IP
                // enforcement context (`is_running` is false) and the flush
                // evicts cached virtual answers, so applications fall back to
                // real addresses instead of dialling a dead TUN for the whole
                // outage.
                let down_flush = std::mem::take(&mut inner.down_flush_pending);
                if inner.desired && !inner.disarmed && inner.restart_pending {
                    Self::start_locked(&mut inner);
                    if inner.running.is_some() {
                        inner.restart_pending = false;
                        // Same contract as the rebuild below: the caller
                        // re-runs the enforcement replan + OS DNS cache flush.
                        return true;
                    }
                }
                // Still down with the feature ON: say so periodically. Without
                // this warning a dead datapath can run for tens of minutes
                // visible only as an absence of events — every toggle the
                // user flips silently applies to nothing.
                if inner.desired && !inner.disarmed && inner.running.is_none() {
                    let due = inner
                        .watchdog
                        .last_outage_warn
                        .is_none_or(|at| at.elapsed() >= OUTAGE_WARN_INTERVAL);
                    if due {
                        inner.watchdog.last_outage_warn = Some(std::time::Instant::now());
                        tracing::warn!(
                            target: "nrr::fake-ip",
                            zombies = inner.zombies.len(),
                            "fake-IP is enabled but the datapath is NOT running — relay, RST and telemetry are all inactive until it restarts",
                        );
                    }
                } else {
                    inner.watchdog.last_outage_warn = None;
                }
                return down_flush;
            }
        };
        let answers_delta = answers.saturating_sub(inner.watchdog.last_answers);
        let ingress_delta = ingress.saturating_sub(inner.watchdog.last_ingress);
        inner.watchdog.last_answers = answers;
        inner.watchdog.last_ingress = ingress;
        if answers_delta >= WATCHDOG_MIN_ANSWERS_PER_TICK && ingress_delta == 0 {
            inner.watchdog.strikes += 1;
        } else {
            inner.watchdog.strikes = 0;
        }
        if inner.watchdog.strikes < WATCHDOG_STRIKES_TO_REBUILD {
            return false;
        }
        inner.watchdog.strikes = 0;
        if inner
            .watchdog
            .last_rebuild
            .is_some_and(|t| t.elapsed() < WATCHDOG_REBUILD_COOLDOWN)
        {
            tracing::warn!(
                target: "nrr::fake-ip",
                "fake-IP datapath still wedged (answers without ingress) but a rebuild just ran — waiting out the cooldown",
            );
            return false;
        }
        tracing::warn!(
            target: "nrr::fake-ip",
            answers_delta,
            "fake-IP datapath wedged: virtual addresses are being answered but NO packets arrive — rebuilding the TUN stack",
        );
        inner.watchdog.last_rebuild = Some(std::time::Instant::now());
        Self::stop_locked(&mut inner);
        Self::start_locked(&mut inner);
        // Re-baseline after the rebuild so the fresh stack starts clean.
        if let Some(health) = &inner.health {
            let (answers, ingress) = (health.answers(), health.ingress());
            inner.watchdog.last_answers = answers;
            inner.watchdog.last_ingress = ingress;
        }
        // A detach during the rebuild's stop leaves the datapath down with no
        // fresh stack — that still owes the caller the replan + flush (see
        // `down_flush_pending`), or cached virtual answers keep hitting a
        // dead TUN until the zombie exits.
        let down_flush = std::mem::take(&mut inner.down_flush_pending);
        inner.running.is_some() || down_flush
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_resolver::FakeIpAnswerer;
    use crate::fake_ip::relay::{FixedRouteSelector, StaticUpstreamResolver};
    use crate::fake_ip::MockRelayDialer;
    use nrr_platform_api::fake_ip::tun::{MockTunAdapter, TunAdapterConfig, TunAdapterPort};
    use nrr_shared::RouteRole;

    #[test]
    fn binding_view_reads_answered_hosts_and_never_allocates() {
        // The diagnostics view sees exactly what the answerer handed
        // out, and a lookup of an un-answered host returns None WITHOUT
        // creating a binding (read-only by construction).
        let assembly = FakeIpAssembly::new(
            FakeIpScope::enabled(Vec::<String>::new()),
            FakeIpPoolConfig::default(),
        );
        let view = assembly.binding_view();
        assert_eq!(view.fake_v4_for("habr.com"), None, "nothing answered yet");
        let answered = assembly
            .answerer()
            .fake_answer("habr.com")
            .expect("in scope")[0];
        assert_eq!(
            view.fake_v4_for("habr.com"),
            Some(answered),
            "view mirrors the live allocator"
        );
        // The failed lookup above must not have burned an index: the next
        // distinct host still gets a fresh address (no phantom binding).
        assert_eq!(view.fake_v4_for("never-asked.example"), None);
    }

    #[test]
    fn the_answerer_and_relay_share_one_allocator() {
        // Distinct hostnames must land on DISTINCT fake addresses across the
        // answerer and any relay built from the same assembly — proof they share
        // one allocator (separate allocators would each hand "x" and "y" the
        // first index and collide).
        let assembly = FakeIpAssembly::new(
            FakeIpScope::enabled(Vec::<String>::new()),
            FakeIpPoolConfig::default(),
        );
        let fx = assembly
            .answerer()
            .fake_answer("x.example")
            .expect("x in scope");
        let fy = assembly
            .answerer()
            .fake_answer("y.example")
            .expect("y in scope");
        assert_ne!(
            fx, fy,
            "shared allocator gives distinct hosts distinct addresses"
        );
        // Re-asking is stable.
        assert_eq!(assembly.answerer().fake_answer("x.example"), Some(fx));
    }

    #[test]
    fn direct_answerer_bindings_resolve_through_the_direct_aware_resolver() {
        // The DIRECT-host path must close end-to-end inside one
        // assembly: the answerer hands out a fake address, and the relay-side
        // resolver immediately finds the REAL addresses it recorded.
        use crate::dns_resolver::DirectFakeIpAnswerer as _;
        use crate::fake_ip::relay::UpstreamAddressResolver as _;
        use std::net::{IpAddr, Ipv4Addr};

        let assembly = FakeIpAssembly::new(
            FakeIpScope::enabled(Vec::<String>::new()),
            FakeIpPoolConfig::default(),
        );
        let direct = assembly.direct_answerer(Arc::new(|| true));
        let real = Ipv4Addr::new(178, 248, 237, 68);
        let fake = direct
            .fake_direct_answer("habr.com", &[real])
            .expect("armed + in scope")[0];
        // Shared allocator: a rule-host binding from the same assembly cannot
        // collide with the direct-host binding.
        let rule_fake = assembly
            .answerer()
            .fake_answer("chatgpt.com")
            .expect("in scope")[0];
        assert_ne!(fake, rule_fake, "one allocator serves both answerers");
        // The relay's resolver sees the recorded real set without any cache.
        let resolver = assembly.direct_aware_resolver(Arc::new(StaticUpstreamResolver::new()));
        assert_eq!(resolver.addresses_for("habr.com"), vec![IpAddr::V4(real)]);
    }

    #[test]
    fn build_stack_sweeps_stale_flows_exactly_once_over_the_pool_range() {
        // A restart leaves the fake addresses in place but rebuilds the
        // userspace stack empty — proof the sweep runs once, over the SAME
        // range the pool hands out, as the fresh stack comes up.
        use nrr_platform_api::fake_ip::{MockStaleFlowReset, StaleFlowSweep};

        let mock = Arc::new(MockStaleFlowReset::new());
        mock.set_answer(StaleFlowSweep {
            found: 3,
            torn_down: 2,
        });
        let pool = FakeIpPoolConfig::default();
        let assembly = FakeIpAssembly::new(FakeIpScope::enabled(Vec::<String>::new()), pool)
            .with_stale_flow_reset(Arc::clone(&mock) as Arc<dyn StaleFlowReset>);

        let (adapter, _state) = MockTunAdapter::new();
        let device = adapter
            .open(&TunAdapterConfig::default())
            .expect("mock adapter opens");
        let _stack = assembly.build_stack(
            device,
            Arc::new(MockRelayDialer::new()),
            Arc::new(StaticUpstreamResolver::new()),
            Arc::new(FixedRouteSelector(RouteRole::Primary)),
            StackWaker::new(),
        );

        assert_eq!(
            mock.calls(),
            vec![(pool.v4_base, pool.v4_prefix_len)],
            "swept exactly once, over the pool's own range"
        );
    }

    fn stack_factory() -> FakeIpStackFactory {
        Arc::new(|| {
            let assembly = FakeIpAssembly::new(
                FakeIpScope::enabled(Vec::<String>::new()),
                FakeIpPoolConfig::default(),
            );
            let (adapter, _state) = MockTunAdapter::new();
            let device = adapter.open(&TunAdapterConfig::default()).ok()?;
            Some(assembly.build_stack(
                device,
                Arc::new(MockRelayDialer::new()),
                Arc::new(StaticUpstreamResolver::new()),
                Arc::new(FixedRouteSelector(RouteRole::Primary)),
                StackWaker::new(),
            ))
        })
    }

    #[test]
    fn controller_starts_and_stops_the_stack_thread() {
        let controller = FakeIpController::new();
        // No factory → start is a fail-open no-op.
        controller.apply(true);
        assert!(!controller.is_running());

        controller.set_factory(stack_factory());
        controller.apply(true);
        assert!(controller.is_running(), "the stack thread is live");
        // Idempotent: a redundant enable does not flap.
        controller.apply(true);
        assert!(controller.is_running());

        controller.apply(false);
        assert!(!controller.is_running(), "stopped and joined");
    }

    #[test]
    fn watchdog_rebuilds_a_wedged_stack_and_respects_the_cooldown() {
        use std::sync::atomic::AtomicUsize;
        let controller = FakeIpController::new();
        let health = Arc::new(crate::fake_ip::FakeIpHealth::new());
        controller.set_health(Arc::clone(&health));
        let builds = Arc::new(AtomicUsize::new(0));
        let factory: FakeIpStackFactory = {
            let builds = Arc::clone(&builds);
            let inner = stack_factory();
            Arc::new(move || {
                builds.fetch_add(1, Ordering::SeqCst);
                inner()
            })
        };
        controller.set_factory(factory);
        controller.apply(true);
        assert!(controller.is_running());
        assert_eq!(builds.load(Ordering::SeqCst), 1);

        // Healthy ticks (answers AND ingress) never strike.
        for _ in 0..5 {
            health.record_answer();
            health.record_answer();
            health.record_ingress();
            assert!(!controller.watchdog_tick());
        }
        assert_eq!(
            builds.load(Ordering::SeqCst),
            1,
            "healthy pulse: no rebuild"
        );

        // The wedge signature — answers keep flowing, ingress flat — rebuilds
        // on the configured consecutive strike.
        for tick in 0..WATCHDOG_STRIKES_TO_REBUILD {
            health.record_answer();
            health.record_answer();
            let rebuilt = controller.watchdog_tick();
            assert_eq!(rebuilt, tick + 1 == WATCHDOG_STRIKES_TO_REBUILD);
        }
        assert_eq!(
            builds.load(Ordering::SeqCst),
            2,
            "wedge triggered ONE rebuild"
        );
        assert!(
            controller.is_running(),
            "fresh stack is live after the rebuild"
        );

        // Still wedged right after: the cooldown suppresses an adapter flap.
        for _ in 0..WATCHDOG_STRIKES_TO_REBUILD {
            health.record_answer();
            health.record_answer();
            assert!(!controller.watchdog_tick());
        }
        assert_eq!(builds.load(Ordering::SeqCst), 2, "cooldown held");
    }

    #[test]
    fn watchdog_retries_a_pending_restart_only_while_desired() {
        // A stack that went down without a user toggle (detached
        // stop / self-exited thread) must be brought back by the periodic
        // tick; nothing else retries. The retry is gated on `restart_pending`
        // so a factory that cannot build is not hammered for a stack that
        // never lived.
        let controller = FakeIpController::new();
        let health = Arc::new(crate::fake_ip::FakeIpHealth::new());
        controller.set_health(Arc::clone(&health));
        controller.set_factory(stack_factory());
        controller.apply(true);
        assert!(controller.is_running());

        // Simulate the down-without-toggle state exactly as the detach/reap
        // paths leave it: thread gone, desire intact, restart pending.
        {
            let mut inner = controller.lock();
            if let Some(r) = inner.running.take() {
                r.stop.store(true, Ordering::SeqCst);
                let _ = r.control.shutdown();
                let _ = r.join.join();
            }
            inner.restart_pending = true;
        }
        assert!(!controller.is_running());

        // The tick restarts the stack and reports a bring-up (the caller then
        // replans + flushes, exactly like a boot).
        assert!(
            controller.watchdog_tick(),
            "tick must restart and report it"
        );
        assert!(controller.is_running());
        // The flag cleared — a healthy running stack ticks quietly again.
        assert!(!controller.watchdog_tick());

        // With the feature toggled OFF the same pending state stays down.
        controller.apply(false);
        {
            let mut inner = controller.lock();
            inner.restart_pending = true;
        }
        assert!(!controller.watchdog_tick());
        assert!(!controller.is_running(), "no retry against the user's OFF");
    }

    #[test]
    fn watchdog_is_inert_while_stopped_and_rebaselines_on_start() {
        let controller = FakeIpController::new();
        let health = Arc::new(crate::fake_ip::FakeIpHealth::new());
        controller.set_health(Arc::clone(&health));
        controller.set_factory(stack_factory());
        // Answers minted while the stack is off (fail-open races) must neither
        // strike now nor be inherited as a delta by the first running tick.
        health.record_answer();
        health.record_answer();
        assert!(!controller.watchdog_tick());
        controller.apply(true);
        assert!(
            !controller.watchdog_tick(),
            "pre-start answers were re-baselined"
        );
    }

    #[test]
    fn a_down_transition_reports_one_flush_tick_even_when_no_rebuild_is_possible() {
        // A detached stop / self-exited thread leaves the datapath down. The
        // next tick must report `true` ONCE — the caller's replan + OS DNS
        // flush is what stops applications dialling cached virtual addresses
        // into a dead TUN — even when the factory cannot build a fresh stack.
        let controller = FakeIpController::new();
        let health = Arc::new(crate::fake_ip::FakeIpHealth::new());
        controller.set_health(Arc::clone(&health));
        controller.set_factory(Arc::new(|| None));
        {
            let mut inner = controller.lock();
            inner.desired = true;
            inner.restart_pending = true;
            inner.down_flush_pending = true;
        }
        assert!(
            controller.watchdog_tick(),
            "the down-transition owes exactly one replan+flush tick"
        );
        assert!(!controller.is_running(), "factory cannot build");
        assert!(
            !controller.watchdog_tick(),
            "the flush debt was consumed by the previous tick"
        );
    }

    #[test]
    fn unfinished_zombies_are_renudged_with_shutdown_every_tick() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::mpsc;

        struct CountingControl {
            calls: Arc<AtomicUsize>,
        }
        impl TunControl for CountingControl {
            fn shutdown(&self) -> Result<(), nrr_platform_api::PlatformError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let controller = FakeIpController::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel::<()>();
        // A "wedged" detached thread: alive until the test releases it.
        let join = std::thread::spawn(move || {
            let _ = rx.recv();
        });
        {
            let mut inner = controller.lock();
            inner.zombies.push(ZombieStack {
                join,
                control: Arc::new(CountingControl {
                    calls: Arc::clone(&calls),
                }),
            });
        }
        // Each tick re-fires the idempotent shutdown wake-up at the zombie.
        let _ = controller.watchdog_tick();
        let _ = controller.watchdog_tick();
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "the zombie must be nudged on every reap pass, got {}",
            calls.load(Ordering::SeqCst)
        );
        // Release the thread; the next pass reaps it and stops nudging.
        tx.send(()).expect("release zombie");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            let _ = controller.watchdog_tick();
            if controller.lock().zombies.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            controller.lock().zombies.is_empty(),
            "a finished zombie must be reaped"
        );
    }

    #[test]
    fn a_none_build_leaves_the_feature_off() {
        let controller = FakeIpController::new();
        controller.set_factory(Arc::new(|| None));
        controller.apply(true);
        assert!(!controller.is_running());
    }

    #[test]
    fn shutdown_latches_off_and_ignores_later_starts() {
        let controller = FakeIpController::new();
        controller.set_factory(stack_factory());
        controller.apply(true);
        assert!(controller.is_running());
        controller.shutdown();
        assert!(!controller.is_running());
        // A toggle after teardown must not re-arm.
        controller.apply(true);
        assert!(!controller.is_running());
    }
}
