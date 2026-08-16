//! Linux counterpart of `windows-service/runtime_deps.rs`: assembles the
//! [`SupervisedRuntimeDeps`] the shared supervised runtime consumes.
//!
//! The runtime body itself is OS-neutral and already used by Windows; what was
//! missing on Linux was this wiring, which is why the daemon sat in an idle
//! watchdog loop. With it, Linux gets the same supervisor, the same health
//! aggregation, the same IPC accept task and the same retention jobs.
//!
//! ## What is wired and what is honestly absent
//!
//! Wired: health, IPC, adapter monitoring, operation-status GC, log and audit
//! retention. Absent, with `None` rather than a stub: everything that needs the
//! per-principal policy store and route coordinator — DNS refresh, the
//! observation consumers, the route hooks. Those are Windows-only today, and a
//! plausible-looking stub in their place would make the daemon report that it
//! is enforcing policy when it is not.
//!
//! Enforcement therefore reconciles nothing yet: the mechanism
//! (`nrr_platform_linux::nft_backend`) is ready and proven against a live
//! kernel, but the plan it would apply is produced by machinery that has not
//! been ported. The daemon says so at startup instead of implying otherwise.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::sync::Arc;

use nrr_diagnostics::{AuditRetentionPolicy, LogRetentionPolicy, ManualCleanupScope};
use nrr_domain::enforcement_mode::EnforcementMode;
use nrr_platform_api::adapters::AdapterMonitor;
use nrr_platform_linux::adapters::LinuxAdapterSource;
use nrr_service_runtime::bootstrap::BootstrapArtifacts;
use nrr_service_runtime::service_stability::ServiceStabilityConfig;
use nrr_service_runtime::supervised_runtime::SupervisedRuntimeDeps;
use nrr_service_runtime::{HealthAggregator, IpcServer};

use crate::unix_socket_server::UnixDomainSocketServer;

/// Debounce for adapter state changes, in milliseconds. Matches the Windows
/// wiring: a link that flaps must not produce a burst of recomputes.
const ADAPTER_DEBOUNCE_MS: u64 = 500;

/// Build the dependency bundle for the Linux daemon.
///
/// `health` is passed in rather than created here so the IPC health handler and
/// the supervisor share ONE aggregator. Two instances is a bug the Windows side
/// already paid for: IPC reported `starting` with no components forever, because
/// the aggregator being filled was not the one being read.
pub(crate) fn build_runtime_deps(
    artifacts: &BootstrapArtifacts,
    health: Arc<HealthAggregator>,
    ipc_server: Arc<dyn IpcServer>,
) -> SupervisedRuntimeDeps {
    let adapter_monitor = Arc::new(AdapterMonitor::new(
        Arc::new(LinuxAdapterSource),
        ADAPTER_DEBOUNCE_MS,
    ));

    let logs_dir: PathBuf = artifacts.topology.logs_dir.clone();
    // On Linux the two diverge, unlike Windows where both sit under the data
    // root: logs follow FHS into /var/log, while the audit trail stays under
    // /var/lib with the state it attests to — deliberately out of reach of a
    // logrotate config scoped to /var/log.
    let audit_dir: PathBuf = artifacts.topology.data_dir.join("audit");

    SupervisedRuntimeDeps {
        health,
        ipc_server,
        adapter_monitor,
        operation_results: Arc::default(),
        stability: ServiceStabilityConfig::default(),
        logs_dir,
        log_retention: LogRetentionPolicy::default(),
        // Operational logs only: the cleanup job must never touch the audit
        // trail or exported archives, and saying so explicitly beats relying on
        // a default that could change.
        cleanup_scope: ManualCleanupScope {
            operational_logs: true,
            diagnostic_temp_data: false,
            exported_archives: false,
        },
        audit_dir,
        audit_retention: AuditRetentionPolicy::default(),
        state_db_conn: None,
        traffic_tick: None,
        activation_coordinator: None,
        dns_refresh_orchestrator: None,
        // Every hook below needs the route coordinator / per-principal
        // orchestrator, neither of which is ported. `None` skips the task; a
        // stub would have the daemon claim work it does not do.
        route_recompute_hook: None,
        route_teardown_hook: None,
        rule_hostname_seeder: None,
        active_routing_sid: None,
        dns_observation_source: None,
        dns_observation_consumer: None,
        conn_observation_source: None,
        conn_observation_consumer: None,
        auto_rules_engine: None,
        app_destination_memory: None,
        secondary_external_address: None,
        dns_resolver_controller: None,
        // Reactive: the local resolver is a Windows mechanism today, so booting
        // in `Resolver` mode would arm something that does not exist here.
        dns_resolver_boot_mode: EnforcementMode::default(),
        event_bus: None,
        // The network-change observer IS implemented for Linux, but it only
        // earns its keep once a recompute hook exists to be re-armed; wiring it
        // to nothing would just spend wakeups.
        network_change_observer: None,
        secondary_liveness_hook: None,
        power_event_observer: None,
        rebind_requests: None,
    }
}

/// Build the production IPC server for the daemon.
pub(crate) fn build_ipc_server(health: Arc<HealthAggregator>) -> Arc<dyn IpcServer> {
    Arc::new(UnixDomainSocketServer::new(Arc::new(
        nrr_service_runtime::IpcRouter::new(
            crate::run::serving_registry_with(health),
            Arc::new(nrr_service_runtime::NoopIpcAuditEmitter),
            1,
        ),
    )))
}
