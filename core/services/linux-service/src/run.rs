//! The `run` daemon body — the Linux analog of `windows-service`'s SCM/console
//! runtime.
//!
//! It bootstraps the OS-neutral storage topology and NDJSON tracing, honours the
//! systemd `Type=notify` + `WatchdogSec` contract, and hands control to the same
//! supervised runtime the Windows service uses: supervisor, health aggregation,
//! IPC accept task, retention jobs.
//!
//! ## What is not here yet
//!
//! The daemon enforces rule-driven policy: logind names who is present, the
//! per-principal store supplies their rules, nftables applies them, and the
//! per-destination leak-guard arms when the secondary link goes away.
//!
//! What is still missing is the catch-all block-all of the always-on modes. It
//! needs exemptions this platform does not collect yet — the tunnel's own server
//! addresses and the local subnets — and arming it without them would cut the
//! reconnect that ends the outage. Users whose settings ask for it are named in
//! the log on every apply, not once at boot.
//!
//! Storage and log directories live under `/var/lib` and `/var/log` and are
//! root-owned, so this path is only meaningfully exercised on a real host — not
//! in unit tests.

#![cfg(target_os = "linux")]

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nrr_platform_linux::daemon_lock::DaemonLock;
use nrr_platform_linux::systemd::{notify, watchdog_interval, NotifyError, NotifyState};
use nrr_service_runtime::ipc_handlers::stub::DegradedPolicyManager;
use nrr_service_runtime::managers::HealthReporter;
use nrr_service_runtime::principal_enforcement::PrincipalEnforcementCycle;
use nrr_service_runtime::state::{ServiceHealthSeverity, ServiceRuntimeState};
use nrr_service_runtime::{
    install_ndjson_tracing_with_verbose, run_bootstrap, run_supervised_runtime, BootstrapConfig,
    ContractNegotiateHandler, EventBus, HealthAggregator, HealthComponent, IpcHandlerRegistry,
    ServiceController, ServiceHealthHandler, ServiceSnapshot, StatusUpdatesSubscribeHandler,
    StopToken,
};
use nrr_shared::ipc::IpcOperationName;
use nrr_storage::StorageProfile;

use crate::unix_socket_server::SOCKET_PATH;

/// Fallback watchdog ping cadence when `$WATCHDOG_USEC` is absent (i.e. the unit
/// declared no `WatchdogSec`, or we are not running under systemd).
const DEFAULT_WATCHDOG_PING: Duration = Duration::from_secs(30);

/// Run the daemon. Never returns until a stop signal arrives: `systemctl stop`
/// sends `SIGTERM`, which is caught so the runtime tears its policy back out of
/// the kernel. Left to its default disposition that signal would kill the
/// process outright, and the filters and routes would outlive the service.
pub fn run() -> ExitCode {
    // Claimed before anything is opened or changed: a second daemon would
    // migrate the same databases, take the live socket and rewrite the same
    // nft table. Refused on stderr, which the journal keeps; tracing is not up.
    let socket = std::path::Path::new(SOCKET_PATH);
    crate::unix_socket_server::prepare_socket_dir(socket);
    let instance = match DaemonLock::acquire(socket) {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("{}: not starting: {e}", crate::DAEMON_NAME);
            return ExitCode::FAILURE;
        }
    };

    // Bootstrap storage: resolves the Linux production topology (/var/lib for
    // state + audit, /var/log for operational logs) and opens the DBs + writers.
    // Needs root / the systemd StateDirectory + LogsDirectory; degrades to a
    // report without a log writer when storage is unavailable.
    let mut artifacts = run_bootstrap(&BootstrapConfig::new(StorageProfile::ProductionService));

    // Install the NDJSON tracing subscriber so operational events are persisted
    // (same subscriber the Windows service uses; OS-neutral). The handle goes to
    // the stability writer, which resumes a stored verbose window and ends it on
    // time — one owner, or a window the user changes would still end on the old
    // deadline.
    let verbosity = match artifacts.log_writer.as_ref() {
        Some(writer) => {
            let verbose = nrr_service_runtime::verbose_logging::verbose_at_boot(
                &artifacts.topology.state_db_path,
            );
            Some(install_ndjson_tracing_with_verbose(Arc::clone(writer), verbose).1)
        }
        None => {
            eprintln!(
                "warning: operational log writer unavailable; tracing events will not be persisted"
            );
            None
        }
    };

    // The activation marker the previous run left, if any: audited and cleared
    // before anything new is applied. A blocking outcome walks the runtime to
    // `RecoveryRequired`; a stale marker only warns.
    let recovery = nrr_service_runtime::run_crash_recovery_on_startup(
        &artifacts.topology.data_dir,
        artifacts.audit_writer.clone(),
        Arc::new(nrr_service_runtime::ProductionIdGenerator::new()),
    );
    tracing::info!(
        target: "nrr::recovery",
        msg_key = "svc-boot-crash-recovery-complete",
        outcome = ?recovery,
        "crash recovery probe complete",
    );
    recovery.record_in(&mut artifacts.report);

    // The IPC server is NOT bound here: the supervised runtime binds it as part
    // of its accept-task bundle, so a bind failure lands in health rather than
    // beside it.

    // Ask the enforcement mechanism whether it can work AT ALL, before anything
    // depends on it. A missing `nftables` package is a fact the operator can act
    // on; discovering it on the first rule the user expects to be applied is a
    // support ticket that reads as "the product silently does nothing".
    report_enforcement_readiness();

    // Before any probe, lookup or relay opens a socket: an unmarked one meets
    // the machine-scope filters like any service account's traffic.
    nrr_platform_api::own_traffic::install_own_traffic_marker(Box::new(
        nrr_platform_linux::own_traffic::SoMarkOwnTraffic,
    ));
    nrr_platform_api::source_link::install_source_link_pinner(Box::new(
        nrr_platform_linux::source_link::BindToSourceDevice,
    ));

    tracing::info!(
        target: "nrr::lifecycle",
        msg_key = "linux-svc-bootstrap-complete",
        "linux-service bootstrap complete; supervised runtime starting",
    );

    let interval = watchdog_interval(std::env::var("WATCHDOG_USEC").ok().as_deref())
        .unwrap_or(DEFAULT_WATCHDOG_PING);
    let stop = StopToken::new();

    // Catch the stop signals before anything is enforced — DNS capture below
    // already rewrites the machine — so no window exists in which policy is
    // installed and the only way out of it is a kill.
    let stop_on_signal = stop.clone();
    if let Err(e) = nrr_platform_linux::signals::install_stop_signals(move || {
        use nrr_platform_api::power::MachineShutdownProbe;
        use nrr_service_runtime::lifecycle_matrix::StopReason;
        // The same SIGTERM arrives for `systemctl stop` and for a power-off;
        // only systemd knows which, and the teardown plans differently.
        let reason = if nrr_platform_linux::systemd::SystemdShutdownProbe.machine_is_shutting_down()
        {
            StopReason::MachineShutdown
        } else {
            StopReason::ServiceStop
        };
        tracing::info!(
            target: "nrr::lifecycle",
            msg_key = "linux-svc-stop-signal-received",
            reason = ?reason,
            "stop signal received; shutting down"
        );
        stop_on_signal.request_stop_for(reason);
    }) {
        tracing::error!(
            target: "nrr::lifecycle",
            msg_key = "linux-svc-stop-signals-install-failed",
            error = %e,
            "stop signals could NOT be installed: a stop will kill the process and leave its filters and routes in the kernel",
        );
    }

    // The same supervised runtime the Windows service runs — supervisor, health
    // aggregation, IPC accept task, retention jobs.
    let health = Arc::new(HealthAggregator::new());
    // Before any rules read: every one judges protected programs by these.
    nrr_service_runtime::protected_rules::install(
        nrr_platform_api::protected_places::ProtectedPlacesSource::protected_places(
            &nrr_platform_linux::protected_places::LinuxProtectedPlaces,
        ),
    );
    // One bus, two ends: the runtime tasks publish into it, the socket server's
    // workers drain it for their subscription. Two instances would leave a
    // subscribed client silently on poll-only.
    let event_bus = Arc::new(EventBus::new());

    // The policy layer comes FIRST, because both of the things below act on the
    // same one: the runtime enforces on a timer, and the IPC surface enforces
    // the moment a user approves a change. Two stacks would mean two readers of
    // one table, each replacing what the other just wrote.
    let adapter_source = Arc::new(nrr_platform_linux::adapters::LinuxAdapterSource);
    // Decided before the policy stack: whether our listener answers DNS
    // settles whether browser DoH must stay blocked and which servers the
    // service's own lookups use.
    let dns_capture = crate::dns_stack::prepare_dns_capture(&artifacts.topology.data_dir);
    let policy_stack = crate::runtime_deps::build_policy_stack(
        &artifacts,
        Arc::clone(&adapter_source),
        Arc::clone(&event_bus),
        dns_capture,
    );
    let enforcement = policy_stack.as_ref().map(|stack| Arc::clone(&stack.cycle));

    let ipc = crate::runtime_deps::build_ipc_server(
        &artifacts,
        Arc::clone(&health),
        Arc::clone(&event_bus),
        policy_stack.as_ref(),
        instance,
        verbosity,
    );
    let accept_heartbeat = Arc::clone(&ipc.accept_heartbeat);
    // Observed resolutions: systemd-resolved tells us what it answered, so the
    // addresses behind a domain rule are learnt without touching the data path.
    // Absent where resolved does not serve the machine's lookups, and that is
    // reported rather than left as silence.
    let dns_observation = policy_stack.as_ref().and_then(build_dns_observation);

    let deps = crate::runtime_deps::build_runtime_deps(
        &artifacts,
        Arc::clone(&health),
        ipc,
        event_bus,
        policy_stack,
        dns_observation,
        adapter_source,
    );
    spawn_watchdog(
        interval,
        stop.clone(),
        Heartbeats {
            health: Arc::clone(&health),
            enforcement,
            accept: accept_heartbeat,
        },
    );
    // READY comes from here, once the runtime reports the socket bound.
    let controller = LogController::new(health, notify);
    run_supervised_runtime(&controller, &stop, artifacts, deps);

    tracing::info!(
        target: "nrr::lifecycle",
        msg_key = "linux-svc-runtime-stopped",
        "linux-service runtime stopped",
    );
    ExitCode::SUCCESS
}

/// What the watchdog vouches for: the adapter monitor's tick, the enforcement
/// pass and the accept loop — any one of them wedged is a wedged daemon.
struct Heartbeats {
    health: Arc<HealthAggregator>,
    enforcement: Option<Arc<PrincipalEnforcementCycle>>,
    /// Epoch seconds of the last finished accept; `0` = none yet.
    accept: Arc<AtomicU64>,
}

impl Heartbeats {
    /// `None` = no evidence either way (a component that is not wired, or an
    /// acceptor that has not accepted yet), never evidence of death.
    fn readings(&self) -> [(&'static str, Option<u64>); 3] {
        let adapters = self
            .health
            .snapshot()
            .components
            .iter()
            .find(|c| c.component == HealthComponent::Adapters)
            .map(|c| c.updated_at_epoch_secs);
        let accept = self.accept.load(Ordering::Relaxed);
        [
            ("adapter-monitor", adapters),
            (
                "enforcement",
                self.enforcement.as_ref().map(|c| c.last_pass_epoch_secs()),
            ),
            ("ipc-accept", (accept != 0).then_some(accept)),
        ]
    }
}

/// Ping systemd on its own thread at half the declared timeout, for as long as
/// the runtime is observably alive.
///
/// Separate from the runtime on purpose: a watchdog that shares a thread with
/// the work it is supposed to vouch for stops pinging exactly when the work
/// wedges — which is the one moment systemd needs to hear silence. And it
/// withholds the ping when any heartbeat goes stale, or the separation buys
/// nothing: an unconditional ping says only "the process is scheduled".
fn spawn_watchdog(interval: Duration, stop: StopToken, beats: Heartbeats) {
    let window = Duration::from_secs(liveness_window(interval));
    let spawned = std::thread::Builder::new()
        .name("nrr-sd-watchdog".to_owned())
        .spawn(move || {
            let started = Instant::now();
            let mut ages = BeatAges::default();
            while !stop.is_stop_requested() {
                // An idle acceptor sits in `accept`; the poke makes a live one
                // turn once, and refresh its beat, before the next look.
                let _ = std::os::unix::net::UnixStream::connect(SOCKET_PATH);
                std::thread::sleep(interval);
                let stale = ages.stale(started.elapsed(), window, &beats.readings());
                if !stale.is_empty() {
                    tracing::error!(
                        target: "nrr::lifecycle",
                        msg_key = "linux-svc-watchdog-heartbeat-stale",
                        stale = %stale.join(", "),
                        "runtime heartbeat is stale — withholding the systemd watchdog ping",
                    );
                    continue;
                }
                let _ = notify(&[NotifyState::Watchdog]);
            }
        });
    if let Err(e) = spawned {
        tracing::warn!(
            target: "nrr::lifecycle",
            msg_key = "linux-svc-watchdog-thread-start-failed",
            error = %e,
            "watchdog thread could not start; systemd may restart the unit on WatchdogSec",
        );
    }
}

/// How long a heartbeat may go unrefreshed before the watchdog stops vouching.
/// The adapter monitor beats every second and enforcement every ten, so a
/// minute fires on a wedge, never on a slow moment.
const RUNTIME_LIVENESS_WINDOW_SECS: u64 = 60;

/// The window, widened for a long ping interval: the acceptor is poked once
/// per interval, so its beat is up to one interval old by design.
fn liveness_window(interval: Duration) -> u64 {
    RUNTIME_LIVENESS_WINDOW_SECS.max(interval.as_secs().saturating_mul(2))
}

/// How long each heartbeat has gone unchanged, on the monotonic clock.
///
/// A beat is a wall-clock stamp, so its age read against the wall clock lies:
/// set back an hour, a wedged loop looks fresh for that hour; after a suspend
/// every beat looks as old as the nap. Judging "has it moved since" instead
/// needs no wall clock at all, and `CLOCK_MONOTONIC` stands still in suspend.
#[derive(Default)]
struct BeatAges {
    /// Last value seen per heartbeat, and the monotonic moment it changed.
    seen: Vec<(&'static str, u64, Duration)>,
}

impl BeatAges {
    /// Names of the heartbeats unchanged for longer than `window` at `now`
    /// (monotonic time since the watchdog started).
    fn stale(
        &mut self,
        now: Duration,
        window: Duration,
        readings: &[(&'static str, Option<u64>)],
    ) -> Vec<&'static str> {
        // A heartbeat with no evidence drops out: when it comes back, its
        // first value starts a fresh age rather than an inherited one.
        self.seen
            .retain(|(name, ..)| readings.iter().any(|(n, beat)| n == name && beat.is_some()));
        let mut stale = Vec::new();
        for &(name, beat) in readings {
            let Some(beat) = beat else { continue };
            match self.seen.iter_mut().find(|(n, ..)| *n == name) {
                Some(entry) if entry.1 != beat => {
                    entry.1 = beat;
                    entry.2 = now;
                }
                Some(entry) => {
                    if now.saturating_sub(entry.2) > window {
                        stale.push(name);
                    }
                }
                None => self.seen.push((name, beat, now)),
            }
        }
        stale
    }
}

/// Whether systemd may be told the unit is up.
#[derive(Debug, PartialEq, Eq)]
enum Readiness {
    NotYet,
    Ready,
    /// Running, but the socket could not be bound: a client would get ENOENT
    /// from a unit systemd calls active.
    Unservable(String),
}

fn readiness(state: ServiceRuntimeState, snapshot: &ServiceSnapshot) -> Readiness {
    match state {
        ServiceRuntimeState::Running | ServiceRuntimeState::Degraded => {
            match snapshot
                .components
                .iter()
                .find(|c| c.component == HealthComponent::Ipc)
            {
                Some(ipc) if ipc.severity == ServiceHealthSeverity::Blocking => {
                    Readiness::Unservable(ipc.message.clone())
                }
                _ => Readiness::Ready,
            }
        }
        // The listener stays down on purpose until the operator acts; not
        // reporting ready would only have systemd restart it in a loop.
        ServiceRuntimeState::RecoveryRequired => Readiness::Ready,
        _ => Readiness::NotYet,
    }
}

type Notifier = fn(&[NotifyState]) -> Result<bool, NotifyError>;

/// Reports runtime state to the log, and readiness and stopping to systemd —
/// `sd_notify` has no per-state channel the way the Windows SCM does.
struct LogController {
    health: Arc<HealthAggregator>,
    notify: Notifier,
    ready_sent: AtomicBool,
}

impl LogController {
    fn new(health: Arc<HealthAggregator>, notify: Notifier) -> Self {
        Self {
            health,
            notify,
            ready_sent: AtomicBool::new(false),
        }
    }

    fn signal_ready(&self) {
        if self.ready_sent.swap(true, Ordering::SeqCst) {
            return;
        }
        match (self.notify)(&[NotifyState::Ready]) {
            Ok(true) => tracing::info!(
                target: "nrr::lifecycle",
                msg_key = "linux-svc-sdnotify-ready-sent",
                "sd_notify READY sent"
            ),
            Ok(false) => tracing::info!(
                target: "nrr::lifecycle",
                msg_key = "linux-svc-sdnotify-not-under-systemd",
                "no NOTIFY_SOCKET; not under systemd notify"
            ),
            Err(e) => tracing::warn!(
                target: "nrr::lifecycle",
                msg_key = "linux-svc-sdnotify-ready-failed",
                error = %e,
                "sd_notify READY failed"
            ),
        }
    }
}

impl ServiceController for LogController {
    fn report(&self, state: ServiceRuntimeState) {
        tracing::info!(
            target: "nrr::lifecycle",
            msg_key = "linux-svc-runtime-state",
            state = ?state,
            "runtime state"
        );
        match readiness(state, &self.health.snapshot()) {
            Readiness::NotYet => {}
            Readiness::Ready => self.signal_ready(),
            Readiness::Unservable(reason) => tracing::error!(
                target: "nrr::lifecycle",
                msg_key = "linux-svc-sdnotify-ready-withheld",
                reason = %reason,
                "the service socket is not bound; READY withheld so systemd does not report a service nobody can reach",
            ),
        }
        if matches!(state, ServiceRuntimeState::Stopping) {
            let _ = (self.notify)(&[NotifyState::Stopping]);
        }
    }
}

/// Probe the nftables mechanism once at start and say plainly what was found.
///
/// Not fatal: the daemon still serves IPC, health and diagnostics, and telling
/// the operator that enforcement is unavailable is more useful than refusing to
/// start at all. What it must never do is stay quiet — an enforcement backend
/// that cannot run looks exactly like one with nothing to do.
fn report_enforcement_readiness() {
    use nrr_platform_linux::nft_backend::NftablesEnforcement;

    match NftablesEnforcement::default().probe() {
        Ok(()) => tracing::info!(
            target: "nrr::enforcement",
            msg_key = "linux-svc-enforcement-available",
            backend = "nftables",
            "enforcement mechanism is available",
        ),
        Err(e) => tracing::error!(
            target: "nrr::enforcement",
            msg_key = "linux-svc-enforcement-unavailable",
            backend = "nftables",
            error = %e,
            "enforcement mechanism is NOT available — routing rules cannot be applied \
             until this is fixed",
        ),
    }
}

/// The operations this daemon can answer before its runtime deps exist.
///
/// Deliberately the two that need nothing from enforcement: the handshake, and
/// "are you alive". Together they are what a client needs to connect at all —
/// without them every connection ends in "unhandled", which is
/// indistinguishable from a broken transport. Everything policy-shaped stays
/// absent rather than stubbed: an empty answer that looks like a real one is
/// worse than a refusal.
/// Built around the aggregator the SUPERVISOR fills — passed in, never created
/// here.
///
/// One instance, two readers: the supervisor records component health into it
/// and the IPC handler reports from it. Building a second aggregator inside is a
/// bug the Windows side already paid for — IPC answered `starting` with no
/// components forever, because the instance being filled was not the one being
/// read. Taking it as a parameter makes that mistake unspellable.
pub(crate) fn serving_registry_with(
    health: Arc<HealthAggregator>,
    event_bus: Arc<EventBus>,
) -> IpcHandlerRegistry {
    let mut registry = IpcHandlerRegistry::new();
    registry.register(
        IpcOperationName::ContractNegotiate,
        ContractNegotiateHandler::new(),
    );
    // The real handler, not a stand-in: it needs nothing but the bus, and
    // without it the socket server's push pump can never engage — a subscribed
    // client would be told "unhandled" and fall back to polling.
    registry.register(
        IpcOperationName::StatusUpdatesSubscribe,
        StatusUpdatesSubscribeHandler::new(event_bus),
    );
    // Fallback when there is no state database: policy state stays "recovery
    // required", which lets the GUI render something other than a spinner.
    registry.register(
        IpcOperationName::ServiceHealthGet,
        ServiceHealthHandler::new(
            health as Arc<dyn HealthReporter>,
            Arc::new(DegradedPolicyManager),
        ),
    );
    registry
}

// The hand-rolled `start_ipc_server` + `accept_loop` that stood in for the
// supervisor are gone: `run_supervised_runtime` owns binding and the accept
// tick now, with retries governed by the stability policy and failures recorded
// in health. Keeping them beside it would have meant two servers on one socket.

/// Wire the DNS-observation tick, or explain why this machine will not observe.
fn build_dns_observation(
    stack: &crate::runtime_deps::PolicyStack,
) -> Option<nrr_service_runtime::service_tasks::DnsObservationWiring> {
    use nrr_platform_linux::dns_observe::{probe_resolver_mode, ResolvedDnsObserver};

    let source = ResolvedDnsObserver::start()?;
    // Connected and permanently silent is a real configuration: programs that
    // read `/etc/resolv.conf` and talk to the server directly never reach the
    // resolver we are listening to. Saying so beats an empty stream that reads
    // as a quiet network.
    if probe_resolver_mode() == Some(false) {
        tracing::warn!(
            target: "nrr::dns-observe",
            msg_key = "linux-svc-dns-resolver-foreign",
            "systemd-resolved is not this machine's resolver (resolv.conf mode: foreign): resolutions bypass it, so domain rules learn addresses only from their own refresh",
        );
    }

    let consumer = Arc::clone(&stack.dns_consumer);
    let subject = Arc::clone(&stack.dns_consumer_subject);
    Some(nrr_service_runtime::service_tasks::DnsObservationWiring {
        source: Arc::new(source),
        consume_for: Arc::new(move |principal, observations| {
            *subject.lock().unwrap_or_else(|p| p.into_inner()) = Some(principal.to_owned());
            consumer.consume(observations, std::time::SystemTime::now());
        }),
        principals: Arc::new(nrr_platform_linux::logind::LogindActivePrincipals),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_service_runtime::state::ServicePolicyState;
    use nrr_service_runtime::HealthComponentSnapshot;
    use std::cell::RefCell;

    const NOW: u64 = 1_000_000;

    fn snapshot_with(ipc: Option<ServiceHealthSeverity>) -> ServiceSnapshot {
        let components = ipc
            .map(|severity| {
                vec![HealthComponentSnapshot {
                    component: HealthComponent::Ipc,
                    severity,
                    message: "ipc bind failed: address in use".to_owned(),
                    updated_at_epoch_secs: NOW,
                }]
            })
            .unwrap_or_default();
        ServiceSnapshot {
            state: ServiceRuntimeState::Running,
            worst_severity: ServiceHealthSeverity::Ok,
            components,
            current_revision: None,
            policy_state: ServicePolicyState::NoState,
            snapshot_refreshed_at_epoch_secs: NOW,
            stale: false,
        }
    }

    const WINDOW: Duration = Duration::from_secs(RUNTIME_LIVENESS_WINDOW_SECS);

    fn at(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    /// A wedged enforcement pass or accept loop used to go unnoticed while
    /// the adapter monitor kept ticking.
    #[test]
    fn any_stuck_heartbeat_withholds_the_ping() {
        let mut ages = BeatAges::default();
        let beats = |adapters, enforcement, accept| {
            [
                ("adapter-monitor", Some(adapters)),
                ("enforcement", Some(enforcement)),
                ("ipc-accept", Some(accept)),
            ]
        };
        assert!(ages.stale(at(0), WINDOW, &beats(NOW, NOW, NOW)).is_empty());
        // Everything moves except enforcement.
        assert!(ages
            .stale(at(30), WINDOW, &beats(NOW + 30, NOW, NOW + 30))
            .is_empty());
        assert!(
            ages.stale(at(60), WINDOW, &beats(NOW + 60, NOW, NOW + 60))
                .is_empty(),
            "exactly at the edge is still alive"
        );
        assert_eq!(
            ages.stale(at(61), WINDOW, &beats(NOW + 61, NOW, NOW + 61)),
            vec!["enforcement"]
        );
        // It moves again: vouched for again.
        assert!(ages
            .stale(at(62), WINDOW, &beats(NOW + 62, NOW + 62, NOW + 62))
            .is_empty());
    }

    /// Read against the wall clock, a step back of an hour makes a wedged
    /// loop's last stamp look fresh for that hour.
    #[test]
    fn a_clock_set_back_does_not_hide_a_stuck_loop() {
        let mut ages = BeatAges::default();
        let back = NOW - 3_600;
        let beats = |adapters, enforcement| {
            [
                ("adapter-monitor", Some(adapters)),
                ("enforcement", Some(enforcement)),
            ]
        };
        assert!(ages.stale(at(0), WINDOW, &beats(NOW, NOW)).is_empty());
        // The clock steps back; the monitor keeps beating, enforcement is stuck
        // on its pre-step stamp, which now reads as an hour in the future.
        assert!(ages.stale(at(15), WINDOW, &beats(back, NOW)).is_empty());
        assert_eq!(
            ages.stale(at(75), WINDOW, &beats(back + 60, NOW)),
            vec!["enforcement"]
        );
    }

    /// A live loop after the clock is set back stamps an older value; that
    /// is movement, not a wedge.
    #[test]
    fn a_beat_that_moves_backwards_is_alive() {
        let mut ages = BeatAges::default();
        let one = |beat| [("enforcement", Some(beat))];
        assert!(ages.stale(at(0), WINDOW, &one(NOW)).is_empty());
        assert!(ages.stale(at(50), WINDOW, &one(NOW - 3_600)).is_empty());
        assert!(ages.stale(at(100), WINDOW, &one(NOW - 3_550)).is_empty());
    }

    /// The monotonic clock stands still in suspend, so a long nap followed by
    /// a beat in the first round after it never reads as a wedge, however far
    /// the wall-clock stamps moved meanwhile.
    #[test]
    fn a_sleep_is_not_a_stale_heartbeat() {
        let mut ages = BeatAges::default();
        let one = |beat| [("adapter-monitor", Some(beat))];
        assert!(ages.stale(at(0), WINDOW, &one(NOW)).is_empty());
        assert!(ages.stale(at(15), WINDOW, &one(NOW + 2_400)).is_empty());
    }

    /// Missing evidence is not evidence of death: withholding here would have
    /// systemd restart a service that is running fine.
    #[test]
    fn a_missing_heartbeat_keeps_the_ping() {
        let mut ages = BeatAges::default();
        let none = [
            ("adapter-monitor", None),
            ("enforcement", None),
            ("ipc-accept", None),
        ];
        assert!(ages.stale(at(0), WINDOW, &none).is_empty());
        assert!(ages.stale(at(600), WINDOW, &none).is_empty());
        // Gone for a while, then back with the same stamp: its age restarts.
        assert!(ages
            .stale(at(700), WINDOW, &[("ipc-accept", Some(NOW))])
            .is_empty());
        assert!(ages.stale(at(710), WINDOW, &none).is_empty());
        assert!(ages
            .stale(at(800), WINDOW, &[("ipc-accept", Some(NOW))])
            .is_empty());
    }

    /// The acceptor is poked once per interval, so a long interval must not
    /// read its by-design age as a wedge.
    #[test]
    fn the_window_covers_two_ping_intervals() {
        assert_eq!(
            liveness_window(Duration::from_secs(15)),
            RUNTIME_LIVENESS_WINDOW_SECS
        );
        assert_eq!(liveness_window(Duration::from_secs(90)), 180);
    }

    thread_local! {
        static SENT: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    fn recording(states: &[NotifyState]) -> Result<bool, NotifyError> {
        SENT.with(|sent| {
            sent.borrow_mut()
                .extend(states.iter().map(|s| format!("{s:?}")))
        });
        Ok(true)
    }

    fn sent() -> Vec<String> {
        SENT.with(|sent| std::mem::take(&mut *sent.borrow_mut()))
    }

    /// READY went out before the socket existed; a client then got ENOENT
    /// from a unit systemd already called active.
    #[test]
    fn ready_waits_for_the_running_report_and_is_sent_once() {
        let _ = sent();
        let controller = LogController::new(Arc::new(HealthAggregator::new()), recording);
        controller.report(ServiceRuntimeState::Starting);
        assert!(sent().is_empty(), "nothing is ready while starting");
        controller.report(ServiceRuntimeState::Running);
        assert_eq!(sent(), vec!["Ready".to_owned()]);
        controller.report(ServiceRuntimeState::Running);
        assert!(sent().is_empty(), "READY is sent once");
        controller.report(ServiceRuntimeState::Stopping);
        assert_eq!(sent(), vec!["Stopping".to_owned()]);
    }

    #[test]
    fn an_unbound_socket_withholds_ready() {
        assert!(matches!(
            readiness(
                ServiceRuntimeState::Running,
                &snapshot_with(Some(ServiceHealthSeverity::Blocking))
            ),
            Readiness::Unservable(_)
        ));
        assert_eq!(
            readiness(
                ServiceRuntimeState::Running,
                &snapshot_with(Some(ServiceHealthSeverity::Ok))
            ),
            Readiness::Ready
        );
        assert_eq!(
            readiness(ServiceRuntimeState::Starting, &snapshot_with(None)),
            Readiness::NotYet
        );
        assert_eq!(
            readiness(ServiceRuntimeState::RecoveryRequired, &snapshot_with(None)),
            Readiness::Ready
        );
    }
}
