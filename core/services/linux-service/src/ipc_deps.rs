//! The daemon's IPC surface: the real handler registry, not a handshake.
//!
//! Until this landed the socket answered three operations — negotiate,
//! subscribe, health — and everything else came back "unhandled", which a
//! client cannot tell apart from a broken transport. The registry itself is
//! neutral (`register_production_handlers`); what was missing on Linux was the
//! bundle of providers it reads through, and every one of those already existed
//! as OS-neutral code over the state database.
//!
//! ## Applying rules from the GUI
//!
//! The activation coordinator takes a `RulesApplyDispatcher` TRAIT, so nothing
//! about approving a revision is Windows-bound. The Linux dispatcher hands the
//! work to the enforcement cycle: the coordinator has already written the
//! revision, so one pass reads it back and reconciles it. Doing it inline rather
//! than waiting for the next tick is what lets the GUI report the truth instead
//! of "submitted, probably".

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nrr_service_runtime::activation_coordinator::{
    ActivationCoordinator, DispatchFailure, PreFlightWarning, RulesApplyDispatcher,
    SidActionPlanSummary,
};
use nrr_service_runtime::ipc_handlers::event_bus::EventBus;
use nrr_service_runtime::ipc_handlers::IpcHandlerDeps;
use nrr_service_runtime::principal_enforcement::{CycleOutcome, PrincipalEnforcementCycle};
use nrr_service_runtime::production_coordinator::{
    ProductionActivationAuditEmitter, ProductionApplyMarkerStore, ProductionIdGenerator,
};
use nrr_service_runtime::production_diagnostics::ProductionDiagnosticsFacade;
use nrr_service_runtime::production_handlers_misc::{
    MonitoredAdaptersSnapshotProvider, NoopMutationExecutor, ProductionMigrationCompletionWriter,
    ProductionMigrationStatusProvider, ProductionRoutePolicyProvider, ProductionRoutePolicyWriter,
    ProductionRulesSnapshotProvider,
};
use nrr_service_runtime::production_policy_manager::CoordinatorPolicyManager;
use nrr_service_runtime::production_security_alerts::ProductionSecurityAlertsRepository;
use nrr_service_runtime::production_settings::{
    ProductionApplyFailurePolicy, ProductionAutostart, ProductionLogRetentionConfig,
    ProductionRetentionSettings, ProductionRoutingPause, ProductionStorageUsage,
};
use nrr_service_runtime::routing_pause::{
    NoopRoutingPauseAudit, PauseDispatcher, RoutingPauseCoordinator,
};
use nrr_service_runtime::{
    ActiveSidRegistry, IpcAuditEmitter, MutationTokenStore, NoopIpcAuditEmitter,
};

/// Everything the daemon needs to answer the full IPC surface.
pub(crate) struct IpcSurface {
    pub deps: Arc<IpcHandlerDeps>,
    /// The dry-run token store the surface actually uses. Handed back so the
    /// housekeeping tick can collect expired tokens: a dry-run needs no
    /// elevation and skips the mutation queue, so its payload parks here until
    /// confirmed or expired, and nothing else would ever sweep it.
    pub mutation_tokens: Arc<MutationTokenStore>,
    /// The audit emitter the router must share with the handlers. The router
    /// refuses a privileged mutation whose record cannot be written; with a
    /// no-op emitter that safeguard can never fire.
    pub audit: Arc<dyn IpcAuditEmitter>,
}

/// Turns an approved revision into kernel state by running one enforcement pass.
///
/// The coordinator writes the revision before dispatching, so there is nothing
/// to pass along: the pass reads the same store the cycle always reads. What the
/// dispatcher adds is timing — the change takes effect now rather than at the
/// next tick, which is the difference between the GUI reporting a result and
/// reporting a hope.
struct CycleApplyDispatcher {
    cycle: Arc<PrincipalEnforcementCycle>,
}

impl RulesApplyDispatcher for CycleApplyDispatcher {
    fn dry_run_for_sid(
        &self,
        sid: &str,
        _rules_json: &str,
    ) -> Result<SidActionPlanSummary, DispatchFailure> {
        // Zeroes because this platform does not compute the id-level diff yet,
        // and inventing counts would be worse than admitting none: the GUI
        // renders them as "what will change".
        tracing::debug!(
            target: "nrr::enforcement",
            sid,
            "dry-run on this platform reports no counts: the per-rule diff is not computed here",
        );
        Ok(SidActionPlanSummary {
            sid: sid.to_string(),
            filter_additions: 0,
            filter_removals: 0,
            routing_actions: 0,
        })
    }

    fn pre_flight_for_sid(
        &self,
        _sid: &str,
        _rules_json: &str,
    ) -> Result<Vec<PreFlightWarning>, DispatchFailure> {
        Ok(Vec::new())
    }

    fn apply_for_sid(&self, sid: &str, _rules_json: &str) -> Result<(), DispatchFailure> {
        self.run_pass(sid)
    }

    fn revert_for_sid(&self, sid: &str, _previous_rules_json: &str) -> Result<(), DispatchFailure> {
        // Revert is the same primitive: the coordinator has restored the
        // previous revision in the store, and a pass makes the machine match it.
        self.run_pass(sid)
    }
}

impl CycleApplyDispatcher {
    fn run_pass(&self, sid: &str) -> Result<(), DispatchFailure> {
        match self.cycle.tick_logged("apply") {
            CycleOutcome::Applied { .. } => Ok(()),
            // Both remaining outcomes mean the machine does NOT match the
            // revision that was just approved. Reporting success here would
            // leave the user believing rules are in force that are not.
            CycleOutcome::EnforcementFailed { reason } => Err(DispatchFailure {
                sid: sid.to_string(),
                message: reason,
            }),
            CycleOutcome::AuthorityUnavailable { reason } => Err(DispatchFailure {
                sid: sid.to_string(),
                message: format!("could not determine who is logged in: {reason}"),
            }),
            CycleOutcome::Stopped => Err(DispatchFailure {
                sid: sid.to_string(),
                message: "the service is stopping; the rules were saved but not applied".to_owned(),
            }),
        }
    }
}

/// Routing pause on this platform is not wired to a mechanism yet.
///
/// It refuses instead of pretending: a pause that reports success while traffic
/// keeps following the rules is the exact failure a pause exists to prevent.
struct UnsupportedPauseDispatcher;

impl PauseDispatcher for UnsupportedPauseDispatcher {
    fn install_for_sid(&self, _sid: &str) -> Result<(), String> {
        Err("routing pause is not available on this platform yet".to_owned())
    }

    fn remove_for_sid(&self, _sid: &str) -> Result<(), String> {
        Err("routing pause is not available on this platform yet".to_owned())
    }
}

/// The IPC audit emitter this daemon serves with: the real one when there is a
/// writer to record into, the no-op when there is not.
///
/// The choice is load-bearing rather than cosmetic. The router REFUSES a
/// privileged mutation whose audit record cannot be written — an operation that
/// cannot be accounted for does not happen — so with the no-op that safeguard
/// can never fire, and the trail stays empty while everything looks healthy.
/// Bootstrap has already reported why a writer is missing, so this stays quiet.
fn ipc_audit_emitter(
    audit_writer: Option<&Arc<nrr_diagnostics::AuditWriter>>,
) -> Arc<dyn IpcAuditEmitter> {
    match audit_writer {
        Some(writer) => Arc::new(
            nrr_service_runtime::production_ipc_audit::ProductionIpcAuditEmitter::new(Arc::clone(
                writer,
            )),
        ),
        None => Arc::new(NoopIpcAuditEmitter),
    }
}

/// Assemble the full IPC surface over the open state database.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_ipc_surface(
    state_conn: Arc<Mutex<rusqlite::Connection>>,
    cache_conn: Option<Arc<Mutex<rusqlite::Connection>>>,
    data_dir: PathBuf,
    logs_dir: PathBuf,
    audit_dir: PathBuf,
    state_db_path: PathBuf,
    cache_db_path: PathBuf,
    audit_writer: Option<Arc<nrr_diagnostics::AuditWriter>>,
    route_table: Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
    cycle: Arc<PrincipalEnforcementCycle>,
    health: Arc<nrr_service_runtime::HealthAggregator>,
    event_bus: Arc<EventBus>,
    gui_binary: PathBuf,
    auto_rules: Option<Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>>,
) -> IpcSurface {
    // Cloned before the facade takes ownership: storage usage counts the same
    // log directory the diagnostics reader serves from, and on Linux that lives
    // outside the data root.
    let usage_logs_dir = logs_dir.clone();
    let ids = Arc::new(ProductionIdGenerator::new());
    // Bound here rather than inline at the call below, so the caller can hand it
    // to the housekeeping tick — the same wiring the Windows surface has.
    let mutation_tokens: Arc<MutationTokenStore> = Arc::default();
    let audit = ipc_audit_emitter(audit_writer.as_ref());
    let alerts_repo = Arc::new(ProductionSecurityAlertsRepository::new(Arc::clone(
        &state_conn,
    )));

    // Without an audit writer the coordinator still runs, but its trail is not
    // persisted. Bootstrap already reported why, so this stays silent about the
    // cause and only picks the emitter.
    let activation_audit: Arc<
        dyn nrr_service_runtime::activation_coordinator::ActivationAuditEmitter,
    > = match audit_writer {
        Some(writer) => Arc::new(
            ProductionActivationAuditEmitter::new(writer, Arc::clone(&ids))
                .with_event_bus(Arc::clone(&event_bus)),
        ),
        None => Arc::new(nrr_service_runtime::activation_coordinator::NoopActivationAudit),
    };

    let sid_registry = Arc::new(ActiveSidRegistry::new());
    let coordinator = Arc::new(ActivationCoordinator::new(
        Arc::clone(&state_conn),
        Arc::clone(&sid_registry),
        Arc::new(CycleApplyDispatcher {
            cycle: Arc::clone(&cycle),
        }),
        Arc::new(ProductionApplyMarkerStore::new(&data_dir)),
        activation_audit,
        Arc::new(nrr_service_runtime::production_settings::SystemClock),
        ids,
        nrr_service_runtime::activation_coordinator::ApplyFailurePolicy::AllOrNothing,
    ));

    let pause_coordinator = Arc::new(RoutingPauseCoordinator::new(
        Arc::clone(&state_conn),
        sid_registry,
        Arc::new(UnsupportedPauseDispatcher),
        Arc::new(NoopRoutingPauseAudit),
        Arc::new(nrr_service_runtime::production_settings::SystemClock),
    ));

    // Wired but shadowed: the launcher answers `autostart.*` before the socket
    // hop because autostart is per-user and this daemon runs as root, where
    // `$HOME` is `/root` — an entry written here is one no session ever reads.
    // A missing XDG autostart directory is not a reason to refuse service: the
    // registry falls back to the standard location, and the write itself is what
    // reports a real failure to the user.
    let registry =
        nrr_platform_linux::autostart::XdgAutostartRegistry::new().unwrap_or_else(|_| {
            nrr_platform_linux::autostart::XdgAutostartRegistry::with_autostart_dir(
                default_autostart_dir(),
            )
        });
    let autostart_helper = Arc::new(nrr_platform_api::autostart::AutostartHelper::new(registry));

    let deps = IpcHandlerDeps::new(
        Arc::clone(&audit),
        health,
        Arc::new(CoordinatorPolicyManager::new(
            Arc::clone(&coordinator),
            Arc::clone(&state_conn),
        )),
        Arc::new(MonitoredAdaptersSnapshotProvider::new(route_table)),
        Arc::new(ProductionRulesSnapshotProvider::new(Arc::clone(
            &state_conn,
        ))),
        Arc::new(ProductionDiagnosticsFacade::new(
            logs_dir,
            audit_dir,
            cache_conn,
            alerts_repo,
            Some(Arc::clone(&state_conn)),
        )),
        // Rule mutations travel the coordinator, which the policy manager owns;
        // the executor covers the other mutation kinds and none of them are
        // wired here yet, so it refuses rather than reports success.
        Arc::new(NoopMutationExecutor),
        Arc::clone(&mutation_tokens),
        Arc::default(),
        Arc::clone(&event_bus),
        Arc::new(ProductionRoutePolicyProvider::new(Arc::clone(&state_conn))),
        Arc::new(ProductionRoutePolicyWriter::new(Arc::clone(&state_conn))),
        Arc::new(ProductionMigrationStatusProvider::new(Arc::clone(
            &state_conn,
        ))),
        Arc::new(ProductionMigrationCompletionWriter::new(Arc::clone(
            &state_conn,
        ))),
        Arc::new(ProductionRetentionSettings::new(Arc::clone(&state_conn))),
        Arc::new(ProductionRetentionSettings::new(Arc::clone(&state_conn))),
        Arc::new(ProductionLogRetentionConfig::new(Arc::clone(&state_conn))),
        Arc::new(ProductionLogRetentionConfig::new(Arc::clone(&state_conn))),
        Arc::new(ProductionApplyFailurePolicy::new(Arc::clone(&state_conn))),
        Arc::new(ProductionApplyFailurePolicy::new(Arc::clone(&state_conn))),
        Arc::new(ProductionStorageUsage::new(
            state_db_path,
            cache_db_path,
            usage_logs_dir,
        )),
        Arc::new(ProductionRoutingPause::new(
            Arc::clone(&state_conn),
            Arc::clone(&pause_coordinator),
        )),
        Arc::new(
            ProductionRoutingPause::new(Arc::clone(&state_conn), pause_coordinator)
                .with_event_bus(Arc::clone(&event_bus)),
        ),
        Arc::new(ProductionAutostart::new(
            Arc::clone(&state_conn),
            Arc::clone(&autostart_helper),
            gui_binary.clone(),
        )),
        Arc::new(
            ProductionAutostart::new(state_conn, autostart_helper, gui_binary)
                .with_event_bus(event_bus),
        ),
    );
    // The SAME engine the observation consumer feeds. Without it the
    // `autorules.candidates.*` operations stay registered as unimplemented and
    // the GUI's suggestions page has nothing to read.
    let deps = match auto_rules {
        Some(engine) => deps.with_auto_rules(engine),
        None => deps,
    };

    IpcSurface {
        deps: Arc::new(deps),
        mutation_tokens,
        audit,
    }
}

/// Where XDG says per-user autostart entries live, when the environment does
/// not say otherwise.
fn default_autostart_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("/etc/xdg"))
        .join("autostart")
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_service_runtime::{IpcRequestContext, IpcRequestEnvelope};

    fn envelope() -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: nrr_service_runtime::IPC_PROTOCOL_VERSION,
            request_id: "r-1".into(),
            correlation_id: None,
            operation: nrr_shared::ipc::IpcOperationName::MutationSubmit,
            operation_class: nrr_service_runtime::ipc::IpcOperationClass::MutationRequest,
            confirmation_token: Some("tok".into()),
            payload: serde_json::json!({ "mutation-kind": "rules-update" }),
        }
    }

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: nrr_shared::ipc::IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: None,
            caller_pid: None,
        }
    }

    /// With a writer the daemon must record for real. The router refuses a
    /// privileged mutation whose record cannot be written, and that refusal is
    /// the only thing standing between "audited" and "silently unaudited" — so
    /// the wiring is checked by what reaches the disk, not by what was passed.
    #[test]
    fn a_writer_gives_an_emitter_that_actually_records() {
        let dir = std::env::temp_dir().join(format!("nrr-ipc-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp audit dir");

        let writer = Arc::new(nrr_diagnostics::AuditWriter::open(
            nrr_diagnostics::AuditWriterConfig::new(dir.clone()),
        ));
        ipc_audit_emitter(Some(&writer))
            .record_request(&envelope(), &ctx())
            .expect("the record is written");

        let wrote_something = std::fs::read_dir(&dir)
            .expect("read temp audit dir")
            .filter_map(Result::ok)
            .any(|e| e.metadata().map(|m| m.len() > 0).unwrap_or(false));
        assert!(wrote_something, "an audit record must reach the trail");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Without a writer the emitter must still SUCCEED, not fail: reporting an
    /// error here would make the router refuse every privileged mutation on a
    /// daemon whose audit storage is merely unavailable.
    #[test]
    fn no_writer_gives_a_silent_emitter_that_does_not_refuse() {
        ipc_audit_emitter(None)
            .record_request(&envelope(), &ctx())
            .expect("the no-op reports success");
    }
}
