//! The `run` daemon body — the Linux analog of `windows-service`'s SCM/console
//! runtime, minus the enforcement supervisor.
//!
//! ## Scope (honest skeleton)
//!
//! This is the make-before-break skeleton: it exercises the OS-neutral bootstrap
//! (storage topology + NDJSON tracing, block 19.2.log parts A/B) and the systemd
//! `Type=notify` + `WatchdogSec` contract (block 19.2 systemd mechanism) on a
//! real systemd/root host, while enforcement stays a no-op — `LinuxApi` is a
//! stub until the nftables/rtnetlink backend lands.
//!
//! TODO: replace the idle watchdog loop with the real
//! `ServiceSupervisor` + `AF_UNIX` IPC accept loop (`peer_cred`) once a
//! systemd/root host is available. `SupervisedRuntimeDeps` is Windows-only
//! today; the Linux equivalent (a `runtime_deps` sibling wiring `LinuxApi`) is
//! the next mechanism slice. Because it drives storage/DB creation under
//! `/var/lib` + `/var/log` (root-owned) and talks to the systemd manager, this
//! path is HW-gated: it is only meaningfully exercised under systemd, not in
//! unit tests.

#![cfg(target_os = "linux")]

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use nrr_platform_linux::systemd::{notify, notify_ready, watchdog_interval, NotifyState};
use nrr_service_runtime::{
    install_ndjson_tracing, run_bootstrap, AcceptOutcome, BootstrapConfig, IpcAcceptor,
    IpcAuditEmitter, IpcHandlerRegistry, IpcRouter, IpcServer, NoopIpcAuditEmitter,
};
use nrr_storage::StorageProfile;

use crate::unix_socket_server::UnixDomainSocketServer;

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

    // Start the AF_UNIX IPC server. The router is EMPTY for now — real handlers
    // are wired by the Linux `runtime_deps` (`SupervisedRuntimeDeps` is
    // Windows-only today), so every operation currently gets an "unhandled"
    // error. What this proves on a real host: the daemon binds
    // `/run/netrulerouter/service-v1.sock`, classifies callers via SO_PEERCRED,
    // and round-trips framed requests. Bind failure (e.g. no RuntimeDirectory
    // outside systemd) degrades to watchdog-only rather than aborting the daemon.
    let _ipc_acceptor = start_ipc_server();

    tracing::info!(
        target: "nrr::lifecycle",
        "linux-service bootstrap complete; enforcement pending, IPC serving with empty router (HW-gated, block 19.2)",
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

    // Watchdog loop. Pings at half the systemd-declared timeout (the derivation
    // systemd recommends). SIGTERM terminates the process by default, so systemd
    // stop is clean without an explicit handler in this skeleton.
    let interval = watchdog_interval(std::env::var("WATCHDOG_USEC").ok().as_deref())
        .unwrap_or(DEFAULT_WATCHDOG_PING);
    loop {
        std::thread::sleep(interval);
        let _ = notify(&[NotifyState::Watchdog]);
    }
}

/// Bind the AF_UNIX IPC server and spawn its accept loop on a background thread.
/// Returns the acceptor so the caller keeps it alive for the process lifetime;
/// `None` on bind/spawn failure (the daemon then runs watchdog-only).
fn start_ipc_server() -> Option<Arc<dyn IpcAcceptor>> {
    // Empty router: transport works end to end, but every operation is
    // unhandled until the Linux runtime_deps wires the real handler registry.
    let registry = IpcHandlerRegistry::new();
    let audit: Arc<dyn IpcAuditEmitter> = Arc::new(NoopIpcAuditEmitter);
    let router = Arc::new(IpcRouter::new(registry, audit, 1));

    let acceptor: Arc<dyn IpcAcceptor> = match UnixDomainSocketServer::new(router).bind() {
        Ok(a) => Arc::from(a),
        Err(e) => {
            tracing::warn!(
                target: "nrr::lifecycle",
                error = %e,
                "IPC bind failed; running watchdog-only",
            );
            return None;
        }
    };

    let accept = Arc::clone(&acceptor);
    if let Err(e) = std::thread::Builder::new()
        .name("nrr-ipc-accept".into())
        .spawn(move || accept_loop(accept))
    {
        tracing::warn!(target: "nrr::lifecycle", error = %e, "IPC accept thread spawn failed");
        return None;
    }
    tracing::info!(target: "nrr::lifecycle", "IPC server listening (empty router)");
    Some(acceptor)
}

/// The background accept loop — the tick model the supervisor will own once the
/// Linux `runtime_deps` lands. Until then this stands in as a plain loop.
fn accept_loop(acceptor: Arc<dyn IpcAcceptor>) {
    loop {
        match acceptor.accept_one() {
            AcceptOutcome::Connected | AcceptOutcome::Idle => continue,
            AcceptOutcome::ShutdownRequested => break,
            AcceptOutcome::Err(e) => {
                tracing::warn!(target: "nrr::lifecycle", error = %e, "IPC accept error; retrying");
                // Brief backoff so a persistent accept failure does not hot-spin.
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}
