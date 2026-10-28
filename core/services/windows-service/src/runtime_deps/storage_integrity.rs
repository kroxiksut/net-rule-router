//! Storage integrity: the row-MAC signing key and the coordinator that uses it.
//!
//! Carved out of [`super::build_supervised_runtime_deps`] because its
//! interface is narrow — ten values in, three out — worth naming explicitly.
//! Nothing here touches Windows: the DPAPI-backed key store is the
//! OS-specific part, and it lives behind a port.

use super::*;

/// What the integrity stack needs from the boot bundle.
pub(super) struct StorageIntegrityInputs<'a> {
    pub artifacts: &'a BootstrapArtifacts,
    pub settings_conn: Option<Arc<Mutex<Connection>>>,
    pub cache_store: Option<Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>>,
    pub event_bus: Arc<EventBus>,
    pub health_agg: Arc<HealthAggregator>,
    pub sid_registry: Arc<ActiveSidRegistry>,
    pub id_generator: Arc<ProductionIdGenerator>,
    pub per_sid_orchestrator: Option<Arc<PerSidApplyOrchestrator>>,
    pub route_coordinator:
        Option<Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>>,
    pub auto_rules_engine: Option<Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>>,
}

/// What it hands back.
///
/// All `Option`: a boot with no settings DB or no audit writer still has to
/// come up, it just cannot sign revisions or author auto-rules.
pub(super) struct StorageIntegrity {
    pub activation_coordinator: Option<Arc<ActivationCoordinator>>,
    pub revision_watch: Option<nrr_service_runtime::revision_watch::RevisionWatch>,
    pub block_notice_rule_author: Option<Arc<dyn nrr_service_runtime::auto_rules::AutoRuleAuthor>>,
}

pub(super) fn build(inputs: StorageIntegrityInputs<'_>) -> StorageIntegrity {
    // Destructured so the moved body reads exactly as it did inline.
    let StorageIntegrityInputs {
        artifacts,
        settings_conn,
        cache_store,
        event_bus,
        health_agg,
        sid_registry,
        id_generator,
        per_sid_orchestrator,
        route_coordinator,
        auto_rules_engine,
    } = inputs;

    // Row signing: key from the DPAPI store, boot verification, signed
    // coordinator, live recheck — the one sequence every service runs.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let revision_signing = settings_conn.as_ref().map(|conn| {
        nrr_service_runtime::revision_signing::RevisionSigning::bootstrap(
            conn,
            production_key_store(),
            Arc::new(ProductionSecurityAlertsRepository::new(Arc::clone(conn)))
                as Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository>,
            artifacts
                .audit_writer
                .clone()
                .map(|w| w as Arc<nrr_service_runtime::boot_integrity::AuditTrail>),
            Arc::clone(&health_agg),
            now_ms,
        )
    });
    if let Some(signing) = revision_signing.as_ref() {
        signing.check_enforced_books();
    }

    let activation_coordinator = match (settings_conn.as_ref(), artifacts.audit_writer.as_ref()) {
        (Some(conn), Some(audit_writer)) => {
            let marker_store = Arc::new(ProductionApplyMarkerStore::new(
                &artifacts.topology.data_dir,
            ));
            let audit_emitter = Arc::new(
                ProductionActivationAuditEmitter::new(
                    Arc::clone(audit_writer),
                    Arc::clone(&id_generator),
                )
                .with_event_bus(Arc::clone(&event_bus)),
            );
            // Swap `NoopRulesApplyDispatcher` for
            // `ProductionRulesApplyDispatcher` when the per-SID
            // orchestrator is available. The Noop path stays as a
            // fallback so a WFP-engine-open failure on a development
            // VM doesn't block the rest of the service.
            let dispatcher: Arc<
                dyn nrr_service_runtime::activation_coordinator::RulesApplyDispatcher,
            > = match per_sid_orchestrator.as_ref() {
                // The settings conn lets the
                // dispatched snapshot pick up the caller's
                // `include_subdomains` widening, matching the provider read.
                Some(orch) => Arc::new(
                    ProductionRulesApplyDispatcher::new(Arc::clone(orch))
                        .with_settings_conn(Arc::clone(conn)),
                ),
                None => Arc::new(NoopRulesApplyDispatcher),
            };
            // Load the admin's persisted apply-failure policy at startup so the
            // coordinator's SID-level revert/keep behaviour matches Settings
            // across restarts (the IPC setter keeps it in sync mid-session via
            // `set_failure_policy`). No row yet → storage default (best-effort).
            let startup_failure_policy = {
                let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                let slug =
                    nrr_storage::policy_settings::ApplyFailurePolicySettingsRepository::new(&guard)
                        .get_or_default()
                        .map(|r| r.policy)
                        .unwrap_or_else(|_| {
                            nrr_storage::policy_settings::DEFAULT_POLICY_SLUG.to_string()
                        });
                ApplyFailurePolicy::from_slug(&slug).unwrap_or(ApplyFailurePolicy::BestEffort)
            };
            let mut coordinator = ActivationCoordinator::new(
                Arc::clone(conn),
                Arc::clone(&sid_registry),
                dispatcher,
                marker_store,
                audit_emitter,
                Arc::new(SystemClock),
                Arc::clone(&id_generator)
                    as Arc<dyn nrr_service_runtime::activation_coordinator::IdGenerator>,
                startup_failure_policy,
            );
            // Without a key the coordinator runs unsigned (already reported).
            if let Some(signing) = revision_signing.as_ref() {
                coordinator = signing.sign(coordinator);
            }
            // An activation must reach every served user — a dead tray
            // subscription or no tray at all (service-driven scope) included.
            if let Some(rc) = route_coordinator.as_ref() {
                let rc = Arc::clone(rc);
                let registry = Arc::clone(&sid_registry);
                coordinator = coordinator
                    .with_served_sids(Arc::new(move || rc.served_sids(&registry.active_sids())));
            }
            Some(Arc::new(coordinator))
        }
        _ => None,
    };

    // Verified before any SID install can read the rules — none has started
    // this early (the IPC server isn't listening); then rechecked after every
    // outside write while the service runs. Without a coordinator the tamper
    // alerts are still raised.
    let revision_watch = revision_signing
        .as_ref()
        .and_then(|signing| signing.enforce_and_watch(activation_coordinator.as_ref()));

    // Confirmed overrides of the protection of system programs, honoured only
    // under the key their rows were signed with. Before any rules read.
    if let Some(conn) = settings_conn.as_ref() {
        let audit = artifacts
            .audit_writer
            .clone()
            .map(|w| w as Arc<nrr_service_runtime::boot_integrity::AuditTrail>);
        let grants = match revision_signing.as_ref() {
            Some(signing) => signing.open_override_grants(Arc::clone(conn), audit, now_ms),
            None => nrr_service_runtime::override_grants::OverrideGrants::open(
                Arc::clone(conn),
                None,
                audit,
                now_ms,
            ),
        };
        grants.attach_events(Arc::clone(&event_bus));
        // A service that keeps stopping unexpectedly loses every confirmation
        // before the first pass can honour one.
        nrr_service_runtime::crash_series::withdraw_on_crash_loop(
            &artifacts.topology.data_dir,
            &grants,
            now_ms,
        );
        nrr_service_runtime::override_grants::install(grants);
    }

    // The rule author behind companion-domain acceptance and the "route this
    // blocked host" notice action. It submits through the ordinary mutation
    // executor, so an authored rule meets the same rule cap, gates, revision
    // audit and push events a typed rule does. A dedicated executor instance:
    // the handler-registry one is built inside `IpcHandlerDeps::new`.
    let block_notice_rule_author: Option<Arc<dyn nrr_service_runtime::auto_rules::AutoRuleAuthor>> =
        match (activation_coordinator.as_ref(), settings_conn.as_ref()) {
            (Some(coord), Some(conn)) => {
                // No IPC handler stands in front of the author, so both gates
                // the executor enforces — the administrative rules lock and the
                // tamper gate — must be wired here or this path goes around them.
                let executor = ProductionMutationExecutor::new(Arc::clone(coord))
                    .with_state_conn(Arc::clone(conn))
                    .with_event_bus(Arc::clone(&event_bus))
                    .with_alerts_repo(Arc::new(ProductionSecurityAlertsRepository::new(Arc::clone(
                        conn,
                    )))
                        as Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository>)
                    .with_stability_provider(Arc::new(ProductionServiceStability::new(Arc::clone(
                        conn,
                    )))
                        as Arc<dyn ServiceStabilityConfigProvider>);
                let rules: Arc<dyn RulesProvider> =
                    Arc::new(ProductionRulesProvider::new(Arc::clone(conn)));
                let mut production_author =
                    nrr_service_runtime::auto_rules::ProductionAutoRuleAuthor::new(
                        rules,
                        Arc::new(executor)
                            as Arc<dyn nrr_service_runtime::ipc_handlers::MutationExecutor>,
                    );
                // A new rule only governs connections opened after it. Without
                // this the user adds the address, nothing visibly changes, and
                // they have to reload the page by hand.
                if let Some(cache_arc) = cache_store.as_ref() {
                    let fqdn: Arc<dyn FqdnCacheLookup> = Arc::new(SqliteFqdnCacheLookup::new(
                        Arc::clone(cache_arc),
                        FreshnessThresholds::default_production(),
                    ));
                    let mut refresh =
                        nrr_service_runtime::routed_host_flow_refresh::RoutedHostFlowRefresh::new(
                            fqdn,
                            Arc::new(
                                nrr_platform_windows::stale_flows::WindowsStaleFlowReset::new(),
                            ),
                        );
                    if let Some(rc) = route_coordinator.as_ref() {
                        let rc = Arc::clone(rc);
                        refresh = refresh.with_links(Arc::new(move |sid: &str| {
                            rc.flow_links(sid, &rc.read_machine())
                        }));
                    }
                    production_author = production_author.with_flow_refresh(Arc::new(refresh));
                }
                let author: Arc<dyn nrr_service_runtime::auto_rules::AutoRuleAuthor> =
                    Arc::new(production_author);
                if let Some(engine) = auto_rules_engine.as_ref() {
                    engine.attach_author(Arc::clone(&author));
                }
                Some(author)
            }
            _ => None,
        };

    // What the installer staged lands in the baseline before any pass reads it.
    if let (Some(coord), Some(conn)) = (activation_coordinator.as_ref(), settings_conn.as_ref()) {
        apply_provisioning(coord, conn, artifacts.audit_writer.as_deref());
    }

    StorageIntegrity {
        activation_coordinator,
        revision_watch,
        block_notice_rule_author,
    }
}

/// Through its own executor, as the rule author above: no IPC handler stands
/// in front of it, so the tamper gate is wired here.
fn apply_provisioning(
    coord: &Arc<ActivationCoordinator>,
    conn: &Arc<Mutex<Connection>>,
    audit: Option<&nrr_diagnostics::AuditWriter>,
) {
    use nrr_service_runtime::provisioning::{apply_staged, ProvisionApplier};
    let Some(dir) = nrr_platform_api::paths::production_provision_dir() else {
        return;
    };
    let alerts = ProductionSecurityAlertsRepository::new(Arc::clone(conn));
    let executor = ProductionMutationExecutor::new(Arc::clone(coord))
        .with_state_conn(Arc::clone(conn))
        .with_alerts_repo(
            Arc::new(ProductionSecurityAlertsRepository::new(Arc::clone(conn)))
                as Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository>,
        );
    let mut applier = ProvisionApplier::new(&executor, conn);
    applier.audit = audit;
    applier.alerts = Some(&alerts);
    let _ = apply_staged(&dir, &applier);
}
