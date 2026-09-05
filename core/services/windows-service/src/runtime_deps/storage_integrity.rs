//! Storage integrity: the row-MAC signing key and the coordinator that uses it.
//!
//! Carved out of [`super::build_supervised_runtime_deps`]. Nothing here touches
//! Windows: it is the DPAPI-backed key STORE that is OS-specific, and that lives
//! behind a port. The block moved because its interface turned out to be nine
//! values in and two out — worth naming, and invisible while it sat inline.
//!
//! Behaviour is unchanged: the same statements in the same order.

use super::*;

/// What the integrity stack needs from the boot bundle.
pub(super) struct StorageIntegrityInputs<'a> {
    pub artifacts: &'a BootstrapArtifacts,
    pub settings_conn: Option<Arc<Mutex<Connection>>>,
    pub cache_store: Option<Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>>,
    pub event_bus: Arc<EventBus>,
    pub sid_registry: Arc<ActiveSidRegistry>,
    pub id_generator: Arc<ProductionIdGenerator>,
    pub per_sid_orchestrator: Option<Arc<PerSidApplyOrchestrator>>,
    pub route_coordinator:
        Option<Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>>,
    pub auto_rules_engine: Option<Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>>,
}

/// What it hands back.
///
/// Both `Option`: a boot with no settings DB or no audit writer still has to
/// come up, it just cannot sign revisions or author auto-rules.
pub(super) struct StorageIntegrity {
    pub activation_coordinator: Option<Arc<ActivationCoordinator>>,
    pub block_notice_rule_author: Option<Arc<dyn nrr_service_runtime::auto_rules::AutoRuleAuthor>>,
}

pub(super) fn build(inputs: StorageIntegrityInputs<'_>) -> StorageIntegrity {
    // Destructured so the moved body reads exactly as it did inline.
    let StorageIntegrityInputs {
        artifacts,
        settings_conn,
        cache_store,
        event_bus,
        sid_registry,
        id_generator,
        per_sid_orchestrator,
        route_coordinator,
        auto_rules_engine,
    } = inputs;

    // ── DB-MAC tamper bootstrap ───────────────────────────────────────
    // Load (or generate) the row-MAC signing key from the DPAPI key
    // store, verify existing revisions, and raise tamper / key-reset
    // alerts. The returned key is threaded into the
    // ActivationCoordinator below so every revision write is signed.
    // Best effort: a bootstrap failure (or a non-Windows build with no
    // DPAPI) logs and degrades to unsigned operation — routing is
    // independent of this integrity scan.
    let tamper_signing_key: Option<Vec<u8>> =
        settings_conn.as_ref().and_then(run_db_mac_tamper_bootstrap);
    // Keyed follow-up to the keyless boot sweep: signed candidate rows
    // orphaned by a hard kill can only be rejected once the signing key
    // exists (re-signing keeps their row_hmac consistent). Runs after
    // verification so the scan saw the rows exactly as the previous run
    // signed them. No key (bootstrap failed) → they stay pending until
    // a healthy boot rather than being corrupted by a keyless flip.
    if let (Some(conn), Some(key)) = (settings_conn.as_ref(), tamper_signing_key.as_ref()) {
        nrr_service_runtime::bootstrap::sweep_signed_orphaned_candidates(conn, key);
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
            // Sign revision rows when the tamper bootstrap produced a key.
            // Without it the coordinator runs unsigned (back-compat /
            // non-Windows / bootstrap error).
            if let Some(key) = tamper_signing_key.clone() {
                coordinator = coordinator.with_signing_key(key);
            }
            // No-tray routing-user fallback: an
            // activation with a dead tray subscription must still dispatch to
            // the console-session user (service-driven scope), not to nobody.
            if let Some(rc) = route_coordinator.as_ref() {
                let rc = Arc::clone(rc);
                coordinator = coordinator
                    .with_fallback_routing_sid(Arc::new(move || rc.effective_routing_sid(&[])));
            }
            Some(Arc::new(coordinator))
        }
        _ => None,
    };

    // Verify every principal's active revision (HMAC + Free rule cap)
    // before any SID install can read it — none have started yet this
    // early in bootstrap (the IPC server isn't listening). A row that
    // reached `revisions` outside the app is rolled back to the last
    // trusted revision here instead of being enforced as-is.
    if let (Some(coord), Some(conn)) = (activation_coordinator.as_ref(), settings_conn.as_ref()) {
        run_active_integrity_enforcement(coord, conn);
    }

    // Build the rule author, now that the activation coordinator exists.
    // Shared by the companion-domain engine's `accept` path AND the
    // "route this blocked host" notice action: both go through the ORDINARY
    // mutation executor, so an authored rule passes the same Free rule cap,
    // tamper gate, revision audit and push events a rule the user typed does
    // — the reason on the rule is the only difference. A dedicated executor
    // instance rather than the handler-registry one below: that one is built
    // inline inside `IpcHandlerDeps::new`, and the extra wiring it carries
    // (`recovery_audit_sink` for safe-disable, `alerts_repo` for alert
    // ack/resolve) governs mutation kinds this path never submits.
    let block_notice_rule_author: Option<Arc<dyn nrr_service_runtime::auto_rules::AutoRuleAuthor>> =
        match (activation_coordinator.as_ref(), settings_conn.as_ref()) {
            (Some(coord), Some(conn)) => {
                let executor = ProductionMutationExecutor::new(Arc::clone(coord))
                    .with_state_conn(Arc::clone(conn))
                    .with_event_bus(Arc::clone(&event_bus))
                    // The author reaches the executor without passing any IPC
                    // handler, so the administrative rules lock has to be wired
                    // here too or this path would be the way around it.
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
                    production_author = production_author.with_flow_refresh(Arc::new(
                        nrr_service_runtime::routed_host_flow_refresh::RoutedHostFlowRefresh::new(
                            fqdn,
                            Arc::new(
                                nrr_platform_windows::stale_flows::WindowsStaleFlowReset::new(),
                            ),
                        ),
                    ));
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

    StorageIntegrity {
        activation_coordinator,
        block_notice_rule_author,
    }
}
