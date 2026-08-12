//! Read-only provider traits the production handlers depend on.
//!
//! These traits abstract over service-internal data sources (adapter
//! monitor, rules snapshot store) so the handlers in [`super`] can be
//! tested with lightweight fakes. Production wiring reads rules
//! snapshots from `nrr-storage` and adapters from
//! `nrr-platform-windows::AdapterMonitor`.
//!
//! The traits return wire-shaped responses directly to keep the
//! handler→provider path one-hop. Internal richer types live in the
//! crates that implement these traits, not here.

use crate::ipc_handlers::mutation_token_store::StoredMutation;
use crate::ipc_handlers::operation_status_store::OperationError;
use crate::ipc_handlers::payloads::{
    AdapterEntry, ApplyFailurePolicyDto, AutostartDto, LinkProviderAppDto, LogRetentionConfigDto,
    LogRetentionConfigSetRequest, MigrationStatusGetResponse, MutationKind,
    PrincipalDataPurgeResponse, RetentionSettingsDto, RetentionSettingsSetRequest, ReviewRiskLevel,
    ReviewSummaryResponse, RoutePolicyDto, RoutePolicyUpdateRequest, RoutingPauseDto,
    RulesListResponse, RulesRouteFilter, SecondaryRouteStateDto, SnapshotInterfacesResponse,
    StorageUsageDto, TrafficStatsGetRequest, TrafficStatsGetResponse, TrafficStatsSettingsDto,
};

/// Synchronous source of an `AdaptersSnapshot` for the IPC layer.
///
/// Production impl wraps `nrr_platform_api::adapters::AdapterMonitor`.
/// `force_refresh = true` asks the impl to drop any cached snapshot and
/// re-enumerate; the call may block until the refresh completes.
pub trait AdaptersSnapshotProvider: Send + Sync {
    fn adapters_snapshot(&self, force_refresh: bool) -> SnapshotInterfacesResponse;

    /// The same snapshot, plus the per-adapter external-address probe.
    ///
    /// Kept as its own entry point rather than as another flag on
    /// `adapters_snapshot` because the difference is not "fresher data" but
    /// "sends packets to a third party". Only a request the user explicitly
    /// made may call this; every routine, polled or background snapshot path
    /// calls `adapters_snapshot` and stays network-silent. Callers must be
    /// prepared for it to take the probe budget (a few seconds) to return.
    ///
    /// The default delegates without probing, so a provider only reaches the
    /// network once it deliberately overrides this.
    fn adapters_snapshot_probing_external_ip(&self) -> SnapshotInterfacesResponse {
        self.adapters_snapshot(true)
    }
}

/// Per-SID Fail-Closed state probe.
///
/// The adapter snapshot itself is service-global, but the Fail-Closed
/// banner depends on (a) which adapter the caller picked as secondary
/// (per-SID `route_bindings`), and (b) whether the caller enabled the
/// "block secondary traffic when unavailable" policy or chose the
/// `StrictSecondaryFailClosed` behavior mode. Computing this inside
/// `AdaptersSnapshotProvider` would require leaking caller identity
/// into the trait — instead the handler composes: it gets the global
/// adapter list, then asks this probe to compute the per-SID flag.
///
/// `None` means "no banner" — used when the caller has no secondary
/// bound, or when storage is unavailable, or when the trait isn't
/// wired (degraded boot). The GUI treats `None` and
/// `Some { fail_closed_active: false }` identically: hide banner.
pub trait FailClosedStateProbe: Send + Sync {
    fn probe(&self, caller_sid: &str, adapters: &[AdapterEntry]) -> Option<SecondaryRouteStateDto>;
}

/// Synchronous source of the rules table snapshot for the IPC layer.
///
/// Production impl reads the active revision from `PolicyManager` and
/// the persisted rules table from `nrr-storage`.
pub trait RulesSnapshotProvider: Send + Sync {
    fn rules_snapshot(&self, route_filter: RulesRouteFilter) -> RulesListResponse;

    /// The rules table for one `principal` (caller SID), with read-through
    /// to the shared baseline when the caller has not diverged. The
    /// default delegates to the baseline-only [`Self::rules_snapshot`] so
    /// preview/mock/test providers stay unchanged; the production provider
    /// overrides it to read the caller's own per-SID active revision.
    fn rules_snapshot_for(
        &self,
        route_filter: RulesRouteFilter,
        _principal: &str,
    ) -> RulesListResponse {
        self.rules_snapshot(route_filter)
    }
}

/// Outcome of a single mutation execution.
///
/// `Completed` carries a kind-specific JSON result that the wire
/// `OperationStatusGet` response surfaces verbatim. `Failed` carries a
/// wire-friendly error.
#[derive(Clone, Debug)]
pub enum MutationOutcome {
    Completed(serde_json::Value),
    Failed(OperationError),
}

/// Execute mutations on behalf of `MutationSubmitHandler` and
/// `RollbackHandler`. The production implementation orchestrates
/// `PolicyManager` writes, `ApplyController::apply_active`, and
/// revision pointer updates.
///
/// Implementations run synchronously — the handler holds the
/// router's mutation-queue slot for the duration of the call. Long-
/// running work is fine; the queue serialises mutations by design.
pub trait MutationExecutor: Send + Sync {
    /// Compute a `ReviewSummary` for `dry_run` requests. Pure: must
    /// not persist, must not call into the apply layer.
    ///
    /// `principal` is the per-principal partition the
    /// preview is diffed against (the caller's own SID, or
    /// [`nrr_storage::BASELINE_PRINCIPAL`] for the admin baseline). The
    /// `ProductionRulesProvider` read-through means an un-diverged user
    /// sees the baseline rules, so the diff is computed against the
    /// caller's *effective* active revision.
    fn preview(
        &self,
        kind: MutationKind,
        payload: &serde_json::Value,
        principal: &str,
    ) -> ReviewSummaryResponse;

    /// Execute a confirmed mutation against `principal`'s revision
    /// partition. The submit handler derives `principal`
    /// from the envelope class + `IpcRequestContext.caller_stored()`.
    fn execute(&self, payload: StoredMutation, principal: &str) -> MutationOutcome;

    /// Execute a rollback of `principal`'s active revision to
    /// `target_revision_id` (or LKG when `None`). Rollback is scoped
    /// per-principal.
    fn rollback(&self, principal: &str, target_revision_id: Option<&str>) -> MutationOutcome;

    /// Execute the safe-disable flow: remove all routes/filters owned
    /// by the service and mark the runtime as `ApplyLayerDisabled`. The
    /// `reason` is a free-form string captured in audit. Production
    /// wiring routes to `crate::crash_recovery::execute_safe_disable`.
    fn safe_disable(&self, reason: &str) -> MutationOutcome;
}

/// Convenience: classify a `ReviewSummary` by its risk level field.
/// Both `dry_run` response payload positions need the same value, so
/// the handler builds the summary once and reads the level off it.
pub fn review_risk_level(summary: &ReviewSummaryResponse) -> ReviewRiskLevel {
    summary.risk_level
}

// ── Per-SID route policy ──────────────────────────────────────────────────

/// Source of the caller's per-SID route policy. Production impl wraps
/// `nrr_storage::RouteBindingsRepository` and reads from
/// `nrr_service_state.db`. Returns `None` when the SID has no rows in
/// any of the three policy tables — the documented "no policy yet,
/// drive migration first" signal.
pub trait RoutePolicyProvider: Send + Sync {
    fn get_for_sid(&self, sid: &str) -> Option<RoutePolicyDto>;
}

/// Wire-format application of a per-SID `RoutePolicyUpdate`. Production
/// impl writes to all three tables (`route_bindings`, `behavior_mode`,
/// `secondary_block_policy`) atomically, validates `stable_id` against
/// the current `AdapterMonitor` snapshot, and emits the EventBus
/// `RoutePolicyChanged { sid }` event. Returns the full new policy
/// snapshot or a typed error.
pub trait RoutePolicyWriter: Send + Sync {
    fn update_for_sid(
        &self,
        sid: &str,
        request: &RoutePolicyUpdateRequest,
    ) -> Result<RoutePolicyDto, RoutePolicyWriteError>;
}

/// Wire-format application of a per-SID
/// `route.link-provider.set`: full replacement of the caller's link-provider
/// app set for one binding role. Production impl writes
/// `route_link_provider_apps` and returns the stored (deduplicated,
/// path-ordered) set. Deliberately narrow — the onboarding dialog must not
/// read-modify-write the whole route policy.
pub trait LinkProviderWriter: Send + Sync {
    fn set_for_sid(
        &self,
        sid: &str,
        role: &str,
        apps: &[LinkProviderAppDto],
    ) -> Result<Vec<LinkProviderAppDto>, RoutePolicyWriteError>;
}

/// Full-reset auxiliary-state purge for the CALLER's own principal — see
/// `nrr_storage::principal_purge` for the exact table scope/boundary.
pub trait PrincipalDataPurger: Send + Sync {
    fn purge_for_sid(&self, sid: &str)
        -> Result<PrincipalDataPurgeResponse, RoutePolicyWriteError>;
}

/// Post-write hook fired AFTER a successful `route.policy.update`, so a
/// routing-active caller's WFP filters recompile mid-session.
/// Without it the new policy persists but only takes effect on the next
/// tray reconnect (the `ActiveSidRegistry` reconcile path). The production
/// impl (`OrchestratorRoutePolicyApplyTrigger`) gates on routing-active and
/// calls `PerSidApplyOrchestrator::recompile_for_sid`; a `None` trigger (no
/// orchestrator — e.g. WFP unavailable in a degraded boot) makes the update
/// persist-only. Best-effort: a recompile error is logged, not surfaced to
/// the caller (the policy is already durably written).
pub trait RoutePolicyApplyTrigger: Send + Sync {
    fn on_policy_changed(&self, sid: &str);
}

/// Errors surfaced by `RoutePolicyWriter::update_for_sid`. The handler
/// maps each variant to a wire `IpcErrorCode`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoutePolicyWriteError {
    /// SID not provided by the transport (`caller_sid.is_empty()`).
    /// Handler maps to `IpcErrorCode::Internal`.
    EmptySid,
    /// `stable_id` does not match any adapter the live `AdapterMonitor`
    /// knows about. Handler maps to `IpcErrorCode::PreconditionFailed`.
    UnknownAdapter { stable_id: String },
    /// Primary and secondary point at the same `stable_id`. Handler
    /// maps to `IpcErrorCode::PreconditionFailed`.
    PrimaryEqualsSecondary,
    /// `mode = strict-secondary-fail-closed` but `secondary` is
    /// `None`. Handler maps to `IpcErrorCode::PreconditionFailed`.
    StrictModeRequiresSecondary,
    /// Storage layer reported an error. Handler maps to
    /// `IpcErrorCode::Internal`.
    Storage(String),
}

impl std::fmt::Display for RoutePolicyWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySid => write!(f, "caller SID is empty"),
            Self::UnknownAdapter { stable_id } => {
                write!(f, "unknown adapter id: {stable_id}")
            }
            Self::PrimaryEqualsSecondary => {
                write!(f, "primary and secondary cannot reference the same adapter")
            }
            Self::StrictModeRequiresSecondary => write!(
                f,
                "strict-secondary-fail-closed mode requires a bound secondary"
            ),
            Self::Storage(m) => write!(f, "storage write failed: {m}"),
        }
    }
}

impl std::error::Error for RoutePolicyWriteError {}

/// Source of GUI-driven migration status. Production
/// impl wraps `nrr_storage::RouteBindingsRepository::migration_status`.
pub trait MigrationStatusProvider: Send + Sync {
    fn migration_status(&self, sid: &str, migration_id: &str) -> MigrationStatusGetResponse;
}

/// Records GUI-driven migration completion. Production
/// impl wraps `nrr_storage::RouteBindingsRepository::mark_migration_complete`.
/// Returns the timestamp recorded; idempotent (repeated calls preserve
/// the original timestamp).
pub trait MigrationCompletionWriter: Send + Sync {
    fn mark_migration_complete(
        &self,
        sid: &str,
        migration_id: &str,
        detail_json: Option<&str>,
    ) -> Result<MigrationCompletionRecord, RoutePolicyWriteError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationCompletionRecord {
    /// `true` when this call performed the write; `false` when the row
    /// already existed (idempotent path).
    pub recorded: bool,
    /// Epoch seconds at the recorded `completed_at` (the original
    /// timestamp on the idempotent path).
    pub completed_at: u64,
}

// ── Settings providers + writers ────────────────────────────────────────────

/// Errors surfaced by the four settings writers (retention, apply failure
/// policy, routing pause, autostart). Handlers map each variant to a
/// wire `IpcErrorCode`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingsWriteError {
    /// Caller provided a value outside the storage CHECK constraint
    /// range, an unknown slug, or a malformed combination. Handler
    /// maps to `IpcErrorCode::PreconditionFailed`.
    Invalid(String),
    /// Storage layer reported an error. Handler maps to
    /// `IpcErrorCode::Internal`.
    Storage(String),
    /// Caller is missing required privilege (e.g. autostart toggle
    /// invoked with empty SID, retention set on a non-elevated client).
    /// Handler maps to `IpcErrorCode::AccessDenied`.
    AccessDenied(String),
}

impl std::fmt::Display for SettingsWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) => write!(f, "invalid settings value: {m}"),
            Self::Storage(m) => write!(f, "storage write failed: {m}"),
            Self::AccessDenied(m) => write!(f, "access denied: {m}"),
        }
    }
}

impl std::error::Error for SettingsWriteError {}

/// Source of the singleton `retention_settings` row. Production impl
/// wraps `nrr_storage::RetentionSettingsRepository`.
pub trait RetentionSettingsProvider: Send + Sync {
    fn get(&self) -> RetentionSettingsDto;
}

/// Writer for the singleton `retention_settings` row. Validates ranges
/// before persisting. Production impl wraps the same repository.
pub trait RetentionSettingsWriter: Send + Sync {
    fn set(
        &self,
        request: &RetentionSettingsSetRequest,
    ) -> Result<RetentionSettingsDto, SettingsWriteError>;
}

/// Source of the singleton `log_retention_config`
/// row (operational-log + audit NDJSON retention). Production impl wraps
/// `nrr_storage::LogRetentionConfigRepository`.
pub trait LogRetentionConfigProvider: Send + Sync {
    fn get(&self) -> LogRetentionConfigDto;
}

/// Writer for the singleton `log_retention_config` row. Validates ranges
/// before persisting.
pub trait LogRetentionConfigWriter: Send + Sync {
    fn set(
        &self,
        request: &LogRetentionConfigSetRequest,
    ) -> Result<LogRetentionConfigDto, SettingsWriteError>;
}

/// Source of the singleton `apply_failure_policy_settings` row.
pub trait ApplyFailurePolicyProvider: Send + Sync {
    fn get(&self) -> ApplyFailurePolicyDto;
}

/// Writer for the singleton `apply_failure_policy_settings` row.
/// `set_by_sid` is filled from `IpcRequestContext.caller_stored()`. Production
/// impl persists then forwards the new policy to
/// `ActivationCoordinator::set_failure_policy` so the next activation
/// uses it.
pub trait ApplyFailurePolicyWriter: Send + Sync {
    fn set(
        &self,
        policy_slug: &str,
        set_by_sid: Option<&str>,
    ) -> Result<ApplyFailurePolicyDto, SettingsWriteError>;
}

/// Source of `%ProgramData%\NetRuleRouter` storage usage. Production
/// impl walks the four known files and synthesises totals.
pub trait StorageUsageProvider: Send + Sync {
    fn measure(&self) -> StorageUsageDto;
}

/// Source of the traffic-stats read response
/// (today + session totals + current settings + optional CSV export).
/// Production impl reads the service-side `TrafficSampler`.
pub trait TrafficStatsProvider: Send + Sync {
    fn get(&self, request: &TrafficStatsGetRequest) -> TrafficStatsGetResponse;
}

/// Writer for the service-global traffic-stats
/// settings (master toggle + loopback/virtual toggles + retention). Validates
/// ranges before persisting.
pub trait TrafficStatsWriter: Send + Sync {
    fn set(
        &self,
        settings: &TrafficStatsSettingsDto,
    ) -> Result<TrafficStatsSettingsDto, SettingsWriteError>;

    /// Reset all traffic data (daily ledger + session totals + cursors); the
    /// settings are kept. Returns the (unchanged) current settings.
    fn clear(&self) -> Result<TrafficStatsSettingsDto, SettingsWriteError>;
}

/// Source of the caller's per-SID `routing_pause_state` row.
pub trait RoutingPauseProvider: Send + Sync {
    fn get(&self, sid: &str) -> RoutingPauseDto;
}

/// Writer for the caller's per-SID `routing_pause_state` row.
/// Production impl wraps `RoutingPauseCoordinator::pause` /
/// `RoutingPauseCoordinator::resume` so the apply layer receives the
/// install/remove dispatch in the same call.
pub trait RoutingPauseWriter: Send + Sync {
    fn toggle(
        &self,
        sid: &str,
        paused: bool,
        reason: Option<&str>,
    ) -> Result<RoutingPauseDto, SettingsWriteError>;
}

/// Source of the singleton `autostart_state` row combined with the most
/// recent registry observation. Production impl probes
/// `HKCU\…\Run` lazily and updates the row via
/// `AutostartStateRepository::record_observation`.
pub trait AutostartProvider: Send + Sync {
    fn get(&self) -> AutostartDto;
}

/// Writer for the autostart configuration. Production impl wraps
/// `nrr_platform_api::autostart::AutostartHelper::set_enabled` /
/// `clear` and persists the result via `AutostartStateRepository::set`.
pub trait AutostartWriter: Send + Sync {
    fn toggle(&self, enabled: bool) -> Result<AutostartDto, SettingsWriteError>;
}

// ── Service stability config ────────────────────────────────────────────────

/// Source of the singleton `service_stability_config` row. Production
/// impl wraps `nrr_storage::ServiceStabilityConfigRepository`.
pub trait ServiceStabilityConfigProvider: Send + Sync {
    fn get(&self) -> nrr_shared::ipc_payloads::ServiceStabilityConfigDto;
}

/// Machine-wide answer to "may this caller author routing rules?".
///
/// The flag rides the `service_stability_config` singleton rather than any
/// per-principal table for one reason: it restricts a user, so that user must
/// not be able to write it. That singleton's wire operation already demands
/// elevation, which makes the storage location and the authorization model the
/// same decision instead of two that can drift.
///
/// Elevated callers are never gated — an administrator who set the lock still
/// edits both the shared baseline and their own rules. Everything else is a
/// deliberate fail-OPEN: an unwired provider (degraded boot, early bring-up)
/// and a stored `None` (a client that never sent an opinion) both read as
/// allowed, because a settings read that could not happen must never become an
/// accidental lockout of the whole machine.
pub fn rule_edits_allowed_for(
    provider: Option<&std::sync::Arc<dyn ServiceStabilityConfigProvider>>,
    caller_is_elevated: bool,
) -> bool {
    if caller_is_elevated {
        return true;
    }
    match provider {
        Some(p) => p.get().allow_user_rule_edits.unwrap_or(true),
        None => true,
    }
}

/// Message returned with [`nrr_shared::ipc_transport::IpcErrorCode::RulesLocked`].
/// One wording, one place — the handler, the executor and the tests all quote
/// it, so a client matching on the code never sees the text drift between the
/// paths that produce it.
pub const RULES_LOCKED_MESSAGE: &str =
    "rule changes are disabled by the administrator on this computer";

/// Wire error code the [`MutationOutcome::Failed`] path uses for the lock.
/// Mirrors the transport-level `rules_locked` code so an operation-status
/// poll and a direct IPC refusal are recognisably the same event.
pub const RULES_LOCKED_ERROR_CODE: &str = "rules-locked";

/// Writer for the singleton `service_stability_config` row. The wire
/// DTO is validated against the Rust-side range guard
/// (`nrr_storage::validate_recoverable_params`) BEFORE hitting SQL so
/// the IPC error code is a clean `PreconditionFailed`/`MalformedRequest`
/// rather than an opaque storage error.
pub trait ServiceStabilityConfigWriter: Send + Sync {
    fn set(
        &self,
        dto: &nrr_shared::ipc_payloads::ServiceStabilityConfigDto,
        set_by_sid: Option<&str>,
    ) -> Result<nrr_shared::ipc_payloads::ServiceStabilityConfigDto, SettingsWriteError>;
}
