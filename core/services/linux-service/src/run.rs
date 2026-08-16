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
//! Policy enforcement reconciles nothing. The nftables mechanism is ready and
//! proven against a live kernel, but the `EnforcementPlan` it would apply comes
//! from the per-principal policy store and route coordinator, which are Windows-
//! only so far. The daemon says so in its log rather than implying it enforces.
//!
//! Storage and log directories live under `/var/lib` and `/var/log` and are
//! root-owned, so this path is only meaningfully exercised on a real host — not
//! in unit tests.

#![cfg(target_os = "linux")]

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use nrr_platform_linux::systemd::{notify, notify_ready, watchdog_interval, NotifyState};
use nrr_service_runtime::ipc_handlers::stub::DegradedPolicyManager;
use nrr_service_runtime::managers::HealthReporter;
use nrr_service_runtime::state::ServiceRuntimeState;
use nrr_service_runtime::{
    install_ndjson_tracing, run_bootstrap, run_supervised_runtime, BootstrapConfig,
    ContractNegotiateHandler, HealthAggregator, IpcHandlerRegistry, ServiceController,
    ServiceHealthHandler, StopToken,
};
use nrr_shared::ipc::IpcOperationName;
use nrr_storage::StorageProfile;

/// Fallback watchdog ping cadence when `$WATCHDOG_USEC` is absent (i.e. the unit
/// declared no `WatchdogSec`, or we are not running under systemd).
const DEFAULT_WATCHDOG_PING: Duration = Duration::from_secs(30);

/// Run the daemon. Never returns under normal operation (systemd stops it with
/// SIGTERM, whose default disposition terminates the process cleanly between
/// watchdog pings).
pub fn run() -> ExitCode {
    // Bootstrap storage: resolves the Linux production topology (/var/lib for
    // state + audit, /var/log for operational logs) and opens the DBs + writers.
    // Needs root / the systemd StateDirectory + LogsDirectory; degrades to a
    // report without a log writer when storage is unavailable.
    let artifacts = run_bootstrap(&BootstrapConfig::new(StorageProfile::ProductionService));

    // Install the NDJSON tracing subscriber so operational events are persisted
    // (same subscriber the Windows service uses; OS-neutral).
    if let Some(writer) = artifacts.log_writer.as_ref() {
        let _ = install_ndjson_tracing(Arc::clone(writer));
    } else {
        eprintln!(
            "warning: operational log writer unavailable; tracing events will not be persisted"
        );
    }

    // The IPC server is NOT bound here: the supervised runtime binds it as part
    // of its accept-task bundle, so a bind failure lands in health rather than
    // beside it. Binding once here and again there would put two servers on one
    // socket path — and the first would carry its own health aggregator,
    // reporting state nobody fills.

    // Ask the enforcement mechanism whether it can work AT ALL, before anything
    // depends on it. A missing `nftables` package is a fact the operator can act
    // on; discovering it on the first rule the user expects to be applied is a
    // support ticket that reads as "the product silently does nothing".
    report_enforcement_readiness();

    tracing::info!(
        target: "nrr::lifecycle",
        "linux-service bootstrap complete; supervised runtime starting. Policy enforcement \
         reconciles nothing yet: the nftables mechanism is ready, but the per-principal policy \
         store that would produce a plan is not ported",
    );

    // Signal readiness: Type=notify holds the unit "activating" until this,
    // matching the Windows "report Running only after bootstrap" contract.
    match notify_ready() {
        Ok(true) => tracing::info!(target: "nrr::lifecycle", "sd_notify READY sent"),
        Ok(false) => {
            tracing::info!(target: "nrr::lifecycle", "no NOTIFY_SOCKET; not under systemd notify")
        }
        Err(e) => {
            tracing::warn!(target: "nrr::lifecycle", error = %e, "sd_notify READY failed")
        }
    }

    // Watchdog pings run beside the runtime, not instead of it: systemd must
    // keep hearing from the process while the supervisor does the work.
    let interval = watchdog_interval(std::env::var("WATCHDOG_USEC").ok().as_deref())
        .unwrap_or(DEFAULT_WATCHDOG_PING);
    let stop = StopToken::new();
    spawn_watchdog(interval, stop.clone());

    // The same supervised runtime the Windows service runs — supervisor, health
    // aggregation, IPC accept task, retention jobs. Until this landed the daemon
    // idled in a sleep loop, so none of those existed on Linux.
    let health = Arc::new(HealthAggregator::new());
    let ipc_server = crate::runtime_deps::build_ipc_server(Arc::clone(&health));
    let deps = crate::runtime_deps::build_runtime_deps(&artifacts, Arc::clone(&health), ipc_server);
    let controller = LogController;
    let reason = run_supervised_runtime(&controller, &stop, artifacts, deps);

    tracing::info!(
        target: "nrr::lifecycle",
        reason = ?reason,
        "linux-service runtime stopped",
    );
    ExitCode::SUCCESS
}

/// Ping systemd on its own thread at half the declared timeout.
///
/// Separate from the runtime on purpose: a watchdog that shares a thread with
/// the work it is supposed to vouch for stops pinging exactly when the work
/// wedges — which is the one moment systemd needs to hear silence.
fn spawn_watchdog(interval: Duration, stop: StopToken) {
    let spawned = std::thread::Builder::new()
        .name("nrr-sd-watchdog".to_owned())
        .spawn(move || {
            while !stop.is_stop_requested() {
                std::thread::sleep(interval);
                let _ = notify(&[NotifyState::Watchdog]);
            }
        });
    if let Err(e) = spawned {
        tracing::warn!(
            target: "nrr::lifecycle",
            error = %e,
            "watchdog thread could not start; systemd may restart the unit on WatchdogSec",
        );
    }
}

/// Reports runtime state to the log, since systemd has no per-state channel the
/// way the Windows SCM does — `sd_notify` covers readiness and stopping only.
struct LogController;

impl ServiceController for LogController {
    fn report(&self, state: ServiceRuntimeState) {
        tracing::info!(target: "nrr::lifecycle", state = ?state, "runtime state");
        if matches!(state, ServiceRuntimeState::Stopping) {
            let _ = notify(&[NotifyState::Stopping]);
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
            backend = "nftables",
            "enforcement mechanism is available",
        ),
        Err(e) => tracing::error!(
            target: "nrr::enforcement",
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
pub(crate) fn serving_registry_with(health: Arc<HealthAggregator>) -> IpcHandlerRegistry {
    let mut registry = IpcHandlerRegistry::new();
    registry.register(
        IpcOperationName::ContractNegotiate,
        ContractNegotiateHandler::new(),
    );
    // Policy state stays "recovery required": no policy store is wired on this
    // platform yet, and that is the truth the GUI needs in order to render
    // something other than a spinner.
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
