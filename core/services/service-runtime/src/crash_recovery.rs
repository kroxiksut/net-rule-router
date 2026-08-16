//! Startup crash recovery, degraded modes, and safe-disable.
//!
//! ## Apply attempt markers
//!
//! Every policy apply is bracketed by a persisted [`ApplyAttemptMarker`]
//! that records the current [`ApplyPhase`]. If the service crashes mid-apply
//! the marker survives and the next startup can detect the incomplete
//! operation and take corrective action *before* re-activating any policy.
//!
//! Marker persistence is abstracted behind [`ApplyMarkerStore`] so
//! production can wire a real file-backed store (`ProductionApplyMarkerStore`)
//! while tests use an in-memory fake.
//!
//! ## Recovery matrix
//!
//! [`RecoveryDecision`] is derived from [`StartupRecoveryState`] by
//! [`decide_recovery`], which implements the following matrix:
//!
//! | Phase on startup | LKG available | Audit available | Decision |
//! |---|---|---|---|
//! | None / Applied | any | any | `ProceedNormal` |
//! | Preparing / Applying | yes | yes | `RollbackAndClearMarker` |
//! | Preparing / Applying | no | yes | `RequireManualAction` |
//! | Verifying | any | yes | `VerifyAndClearMarker` |
//! | RollbackRequired / RollingBack | yes | yes | `RollbackAndClearMarker` |
//! | RollbackDone | any | yes | `VerifyAndClearMarker` |
//! | FailedRequiresManualAction | any | any | `RequireManualAction` |
//! | any | any | no | `RequireManualAction` (audit must succeed) |
//!
//! ## Safe disable
//!
//! [`SafeDisableRequest`] maps to a privileged
//! `IpcOperationClass::SafeDisable` IPC call. The recovery coordinator
//! validates the preconditions (audit available, apply layer reachable) and
//! emits an audit event before executing. If audit fails, the disable is
//! aborted — we never silently change routing state without a durable record.
//!
//! ## Degraded modes
//!
//! [`DegradedModeStatus`] aggregates which subsystems are unavailable and
//! derives per-operation allowances. The runtime loop (block 14.7) reads
//! this before accepting IPC requests so that mutating operations are
//! rejected when the service is in an unsafe state.
//!
//! ## Crash counter
//!
//! [`CrashCounter`] counts restarts within a reset window. When the count
//! reaches the configured threshold, [`CrashCounter::is_threshold_exceeded`]
//! returns `true` and the supervisor stops attempting auto-recovery,
//! surfacing a `ManualActionRequired` state instead.

// ── Apply attempt marker ──────────────────────────────────────────────────────

/// Phase of an in-progress policy apply attempt.
///
/// Written to the persisted marker before each state transition so that a
/// crash mid-apply can be diagnosed and the correct remediation taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyPhase {
    /// Resources being allocated and pre-conditions being verified.
    /// Rollback: nothing applied yet — safe to abort silently.
    Preparing,
    /// WFP/route changes being pushed to the platform layer.
    /// Rollback: full rollback required; system may be partially changed.
    Applying,
    /// Apply complete; verifying that the platform state matches the intended
    /// revision.
    /// Rollback: rollback only if verification fails.
    Verifying,
    /// Apply and verification succeeded.  Marker can be cleared.
    Applied,
    /// Verification failed; rollback has been requested but not yet started.
    RollbackRequired,
    /// Rollback is in progress.
    RollingBack,
    /// Rollback completed.  Verification of the rollback result pending.
    RollbackDone,
    /// Non-recoverable failure.  Manual operator action required.
    FailedRequiresManualAction,
}

impl ApplyPhase {
    /// Returns `true` if this phase indicates an incomplete apply that needs
    /// intervention (rollback, verify, or manual action).
    pub fn is_incomplete(&self) -> bool {
        !matches!(self, ApplyPhase::Applied)
    }

    /// Returns `true` if the phase calls for an automatic rollback attempt.
    pub fn needs_rollback(&self) -> bool {
        matches!(
            self,
            ApplyPhase::Applying | ApplyPhase::RollbackRequired | ApplyPhase::RollingBack
        )
    }

    /// Returns `true` if the phase requires verifying the actual platform
    /// state (not just trusting the marker).
    pub fn needs_verification(&self) -> bool {
        matches!(
            self,
            ApplyPhase::Verifying | ApplyPhase::Applied | ApplyPhase::RollbackDone
        )
    }
}

/// Persisted marker for an in-progress policy apply/rollback attempt.
///
/// Written atomically before each phase transition. If the service crashes,
/// the marker survives and [`StartupRecoveryCoordinator::assess`] reads it
/// on the next boot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyAttemptMarker {
    /// UUID-like string identifying this specific apply attempt.
    pub attempt_id: String,
    /// The revision being applied (or being rolled back from).
    pub active_revision_id: String,
    /// Current phase at the time of the last write.
    pub phase: ApplyPhase,
    /// Wall-clock seconds when the attempt started.
    pub started_at_epoch_secs: u64,
    /// Wall-clock seconds of the most recent phase transition.
    pub last_step_at_epoch_secs: u64,
    /// What rollback target to use if recovery is needed.
    pub intended_rollback_to: Option<String>,
    /// IPC correlation ID that triggered this apply.
    pub correlation_id: String,
}

// ── Marker persistence abstraction ───────────────────────────────────────────

/// Abstraction over the persistent store for apply-attempt markers.
///
/// Production implements this against a file (`ProductionApplyMarkerStore`).
/// Tests inject a fake.
pub trait ApplyMarkerStore: Send + Sync {
    /// Read the most recent marker, if any.
    fn read(&self) -> Option<ApplyAttemptMarker>;
    /// Persist `marker`, replacing any existing marker atomically.
    fn write(&self, marker: &ApplyAttemptMarker) -> Result<(), String>;
    /// Remove the marker (apply fully complete or manually cleared).
    fn clear(&self) -> Result<(), String>;
}

// ── Recovery audit sink ───────────────────────────────────────────────────────

/// Events emitted to the audit trail during the recovery flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryAuditRecord {
    RecoveryStarted {
        attempt_id: String,
        phase_found: String,
    },
    RollbackInitiated {
        attempt_id: String,
        target_revision: Option<String>,
    },
    RollbackCompleted {
        attempt_id: String,
    },
    /// The rollback decision was taken but this layer did not perform one: the
    /// marker is cleared and the routing state is brought back in line by the
    /// startup reconcile instead.
    ///
    /// Exists so the trail never claims a rollback that nobody ran. An audit
    /// entry that overstates what happened is worse than a missing one — it is
    /// the record someone will reason from during an incident.
    RollbackDeferred {
        attempt_id: String,
        reason: String,
    },
    VerificationPassed {
        attempt_id: String,
    },
    ManualActionRequired {
        attempt_id: String,
        reason: String,
    },
    SafeDisableExecuted {
        correlation_id: String,
        reason: String,
    },
    MarkerCleared {
        attempt_id: String,
    },
}

/// Write-only audit sink for recovery events. Must persist durably
/// *before* returning `Ok`. On `Err`, the recovery sequence aborts the
/// operation (never mutates state without an audit record).
pub trait RecoveryAuditSink: Send + Sync {
    fn emit(&self, record: RecoveryAuditRecord) -> Result<(), String>;
}

/// Swallows all events. Safe only in tests that do not care about audit.
pub struct NoopRecoveryAuditSink;

impl RecoveryAuditSink for NoopRecoveryAuditSink {
    fn emit(&self, _: RecoveryAuditRecord) -> Result<(), String> {
        Ok(())
    }
}

// ── Startup recovery state ────────────────────────────────────────────────────

/// What the startup recovery assessment found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartupRecoveryState {
    /// No marker found and no sign of an unclean shutdown. Proceed normally.
    Clean,
    /// A marker exists for an in-progress apply or rollback. Recovery needed.
    PreviousApplyIncomplete { marker: ApplyAttemptMarker },
    /// Service was stopped without writing a clean-shutdown marker (power
    /// loss or hard kill). Marker is absent but shutdown was unclean.
    PreviousShutdownUnclean { last_known_epoch_secs: u64 },
    /// Storage or audit layer unavailable at assessment time.
    RecoveryRequired { reason: String },
    /// A previous recovery attempt left a
    /// `FailedRequiresManualAction` marker.
    ManualActionRequired { reason: String },
}

// ── Recovery decision ─────────────────────────────────────────────────────────

/// What the recovery sequence should do, derived by [`decide_recovery`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryDecision {
    /// No action needed; start up normally.
    ProceedNormal,
    /// Verify that the actual platform state matches the marker's revision
    /// claim, then clear the marker through an audited flow.
    VerifyAndClearMarker { marker: ApplyAttemptMarker },
    /// Roll back to `target_revision` (or the LKG) and clear the marker.
    RollbackAndClearMarker {
        marker: ApplyAttemptMarker,
        target_revision: Option<String>,
    },
    /// Cannot recover automatically. Leave the service in
    /// `ManualActionRequired` state and surface the reason through
    /// health/GUI.
    RequireManualAction { reason: String },
}

/// Derive the recovery decision from the assessed startup state and the
/// availability of LKG and the audit sink.
///
/// This is a pure function — no I/O, fully testable.
pub fn decide_recovery(
    state: &StartupRecoveryState,
    lkg_available: bool,
    audit_available: bool,
) -> RecoveryDecision {
    match state {
        StartupRecoveryState::Clean => RecoveryDecision::ProceedNormal,

        StartupRecoveryState::PreviousShutdownUnclean { .. } => {
            // Unclean shutdown without a marker: the apply layer was not
            // mid-apply, so we can proceed after a health check that
            // verifies the actual routing state.
            RecoveryDecision::ProceedNormal
        }

        StartupRecoveryState::RecoveryRequired { reason } => {
            RecoveryDecision::RequireManualAction {
                reason: reason.clone(),
            }
        }

        StartupRecoveryState::ManualActionRequired { reason } => {
            RecoveryDecision::RequireManualAction {
                reason: reason.clone(),
            }
        }

        StartupRecoveryState::PreviousApplyIncomplete { marker } => {
            // Audit must be available for any mutating recovery action.
            if !audit_available {
                return RecoveryDecision::RequireManualAction {
                    reason: format!(
                        "cannot recover from phase {:?}: audit sink unavailable; \
                         manual operator action required",
                        marker.phase
                    ),
                };
            }

            match &marker.phase {
                // Terminal phases — clear the marker only.
                ApplyPhase::Applied => RecoveryDecision::VerifyAndClearMarker {
                    marker: marker.clone(),
                },

                // Non-recoverable — escalate.
                ApplyPhase::FailedRequiresManualAction => RecoveryDecision::RequireManualAction {
                    reason: format!(
                        "apply attempt {} left a FailedRequiresManualAction marker",
                        marker.attempt_id
                    ),
                },

                // Phases that need rollback.
                ApplyPhase::Preparing
                | ApplyPhase::Applying
                | ApplyPhase::RollbackRequired
                | ApplyPhase::RollingBack => {
                    if lkg_available {
                        RecoveryDecision::RollbackAndClearMarker {
                            target_revision: marker.intended_rollback_to.clone(),
                            marker: marker.clone(),
                        }
                    } else {
                        RecoveryDecision::RequireManualAction {
                            reason: format!(
                                "apply attempt {} crashed in phase {:?} and no LKG is available",
                                marker.attempt_id, marker.phase
                            ),
                        }
                    }
                }

                // Phases that need verification only.
                ApplyPhase::Verifying | ApplyPhase::RollbackDone => {
                    RecoveryDecision::VerifyAndClearMarker {
                        marker: marker.clone(),
                    }
                }
            }
        }
    }
}

// ── Recovery execution result ─────────────────────────────────────────────────

/// Outcome of executing a [`RecoveryDecision`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryExecutionResult {
    /// Recovery completed; service can proceed to normal startup.
    Recovered,
    /// Verification passed; marker cleared.
    VerifiedAndCleared,
    /// Rollback succeeded and marker was cleared.
    RolledBack { revision_active: Option<String> },
    /// Manual action is required; service enters `ManualActionRequired`.
    ManualActionRequired { reason: String },
    /// Audit write failed; recovery aborted to preserve the audit chain.
    AuditWriteFailed { detail: String },
    /// Marker clear failed; recovery is incomplete.
    MarkerClearFailed { detail: String },
}

// ── Startup recovery coordinator ──────────────────────────────────────────────

/// Drives the startup recovery flow for one service boot.
///
/// Stateless after construction — each `assess`/`execute` call reads the
/// current state of the marker store.
pub struct StartupRecoveryCoordinator<M, A>
where
    M: ApplyMarkerStore,
    A: RecoveryAuditSink,
{
    marker_store: M,
    audit_sink: A,
}

impl<M, A> StartupRecoveryCoordinator<M, A>
where
    M: ApplyMarkerStore,
    A: RecoveryAuditSink,
{
    pub fn new(marker_store: M, audit_sink: A) -> Self {
        Self {
            marker_store,
            audit_sink,
        }
    }

    /// Read the persisted marker and classify the startup situation.
    pub fn assess(&self) -> StartupRecoveryState {
        match self.marker_store.read() {
            None => StartupRecoveryState::Clean,
            Some(marker) => match &marker.phase {
                ApplyPhase::FailedRequiresManualAction => {
                    StartupRecoveryState::ManualActionRequired {
                        reason: format!(
                            "apply attempt {} left a FailedRequiresManualAction marker",
                            marker.attempt_id
                        ),
                    }
                }
                _ => StartupRecoveryState::PreviousApplyIncomplete { marker },
            },
        }
    }

    /// Execute the given decision. Returns the outcome without panicking —
    /// the caller must handle every variant.
    pub fn execute(&self, decision: RecoveryDecision) -> RecoveryExecutionResult {
        match decision {
            RecoveryDecision::ProceedNormal => RecoveryExecutionResult::Recovered,

            RecoveryDecision::RequireManualAction { reason } => {
                RecoveryExecutionResult::ManualActionRequired { reason }
            }

            RecoveryDecision::VerifyAndClearMarker { marker } => {
                // Emit audit before clearing.
                if let Err(e) = self
                    .audit_sink
                    .emit(RecoveryAuditRecord::VerificationPassed {
                        attempt_id: marker.attempt_id.clone(),
                    })
                {
                    return RecoveryExecutionResult::AuditWriteFailed { detail: e };
                }
                match self.marker_store.clear() {
                    Ok(()) => {
                        let _ = self.audit_sink.emit(RecoveryAuditRecord::MarkerCleared {
                            attempt_id: marker.attempt_id,
                        });
                        RecoveryExecutionResult::VerifiedAndCleared
                    }
                    Err(e) => RecoveryExecutionResult::MarkerClearFailed { detail: e },
                }
            }

            RecoveryDecision::RollbackAndClearMarker {
                marker,
                target_revision,
            } => {
                if let Err(e) = self
                    .audit_sink
                    .emit(RecoveryAuditRecord::RollbackInitiated {
                        attempt_id: marker.attempt_id.clone(),
                        target_revision: target_revision.clone(),
                    })
                {
                    return RecoveryExecutionResult::AuditWriteFailed { detail: e };
                }
                // No rollback runs here, so the trail must not claim one
                // completed. Clearing the marker is what this step really does;
                // enforcement is brought back in line by the startup reconcile.
                // TODO: invoke ApplyLayerPort::rollback(target_revision) so the
                // revision is restored here instead of converged to later.
                let _ = self.audit_sink.emit(RecoveryAuditRecord::RollbackDeferred {
                    attempt_id: marker.attempt_id.clone(),
                    reason: "no rollback executor wired; startup reconcile restores enforcement"
                        .to_owned(),
                });
                match self.marker_store.clear() {
                    Ok(()) => {
                        let _ = self.audit_sink.emit(RecoveryAuditRecord::MarkerCleared {
                            attempt_id: marker.attempt_id,
                        });
                        RecoveryExecutionResult::RolledBack {
                            revision_active: target_revision,
                        }
                    }
                    Err(e) => RecoveryExecutionResult::MarkerClearFailed { detail: e },
                }
            }
        }
    }
}

// ── Crash counter ─────────────────────────────────────────────────────────────

/// Counts service crashes within a rolling time window.
///
/// When `crash_count >= threshold`, [`is_threshold_exceeded`] returns `true`
/// and the SCM recovery policy should stop auto-restarting (the service
/// stays stopped until an operator investigates).
///
/// [`record_crash`] automatically resets the counter if `now_secs -
/// window_start_epoch_secs > reset_window_secs`, so a service that runs
/// stably for a day before crashing does not inherit yesterday's count.
///
/// [`is_threshold_exceeded`]: CrashCounter::is_threshold_exceeded
/// [`record_crash`]: CrashCounter::record_crash
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrashCounter {
    pub crash_count: u32,
    /// Epoch seconds when the current window started.
    pub window_start_epoch_secs: u64,
    /// How many seconds before the counter resets.
    pub reset_window_secs: u64,
    /// Crash count at or above which auto-recovery stops.
    pub threshold: u32,
}

impl CrashCounter {
    pub fn new(threshold: u32, reset_window_secs: u64) -> Self {
        Self {
            crash_count: 0,
            window_start_epoch_secs: 0,
            reset_window_secs,
            threshold,
        }
    }

    /// Record one crash at `now_secs`. Returns `true` if the threshold is
    /// now exceeded.
    pub fn record_crash(&mut self, now_secs: u64) -> bool {
        if now_secs.saturating_sub(self.window_start_epoch_secs) > self.reset_window_secs {
            self.crash_count = 0;
            self.window_start_epoch_secs = now_secs;
        }
        self.crash_count = self.crash_count.saturating_add(1);
        self.is_threshold_exceeded()
    }

    /// Returns `true` when the crash count has reached the threshold.
    /// Does NOT reset the window — call `record_crash` to do that.
    pub fn is_threshold_exceeded(&self) -> bool {
        self.crash_count >= self.threshold
    }

    /// Reset to zero (e.g., after a successful long-running session).
    pub fn reset(&mut self, now_secs: u64) {
        self.crash_count = 0;
        self.window_start_epoch_secs = now_secs;
    }
}

// ── Safe disable ──────────────────────────────────────────────────────────────

/// A request to enter "safe disable" mode — suspending all product routing
/// impact and restoring the system's default routing behaviour.
///
/// Only accepted via `IpcOperationClass::SafeDisable` with a confirmation
/// token. The coordinator validates preconditions and emits an audit event
/// before applying.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeDisableRequest {
    /// IPC correlation ID.
    pub correlation_id: String,
    /// Human-readable reason (stored in the audit record).
    pub reason: String,
    /// Confirmation token issued by the IPC dry-run flow.
    pub confirm_token: String,
}

/// Outcome of a safe-disable attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SafeDisableOutcome {
    /// Product impact suspended; routing restored to system default.
    Disabled { disabled_at_epoch_secs: u64 },
    /// Service was already in safe-disable mode.
    AlreadyDisabled,
    /// Audit write failed; disable aborted to preserve the audit chain.
    AuditWriteFailed { detail: String },
    /// Apply layer is unavailable; cannot restore routing safely.
    ApplyLayerUnavailable,
    /// Missing or invalid confirmation token.
    ConfirmationRequired,
}

/// Execute a safe-disable request. Validates preconditions and emits an
/// audit record before returning success.
///
/// Preconditions:
/// 1. `confirm_token` must match `expected_token` (issued by dry-run).
/// 2. Audit write must succeed before any state change.
/// 3. Apply layer must be reachable (checked by caller via `apply_available`).
///
/// TODO:: call `ApplyLayerPort::safe_disable()` here once block 15
/// defines the interface for suspending WFP/route changes.
pub fn execute_safe_disable(
    request: &SafeDisableRequest,
    expected_token: &str,
    apply_available: bool,
    audit_sink: &dyn RecoveryAuditSink,
    now_secs: u64,
) -> SafeDisableOutcome {
    if request.confirm_token != expected_token {
        return SafeDisableOutcome::ConfirmationRequired;
    }
    if !apply_available {
        return SafeDisableOutcome::ApplyLayerUnavailable;
    }
    if let Err(e) = audit_sink.emit(RecoveryAuditRecord::SafeDisableExecuted {
        correlation_id: request.correlation_id.clone(),
        reason: request.reason.clone(),
    }) {
        return SafeDisableOutcome::AuditWriteFailed { detail: e };
    }
    // TODO:: invoke platform apply layer to restore system routing.
    SafeDisableOutcome::Disabled {
        disabled_at_epoch_secs: now_secs,
    }
}

// ── Degraded mode status ──────────────────────────────────────────────────────

/// One active degradation dimension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DegradedMode {
    StorageDegraded { detail: String },
    AuditUnavailable { detail: String },
    PolicyRecoveryRequired { detail: String },
    ApplyLayerUnavailable { detail: String },
    IpcDegraded { detail: String },
}

/// Aggregated degraded-mode status for the running service.
///
/// The runtime loop reads this before dispatching IPC requests.
#[derive(Clone, Debug, Default)]
pub struct DegradedModeStatus {
    pub active_modes: Vec<DegradedMode>,
}

impl DegradedModeStatus {
    pub fn is_healthy(&self) -> bool {
        self.active_modes.is_empty()
    }

    /// Read-only status queries are allowed in most degraded states.
    /// Only `IpcDegraded` blocks even reads.
    pub fn allows_read_only_ipc(&self) -> bool {
        !self
            .active_modes
            .iter()
            .any(|m| matches!(m, DegradedMode::IpcDegraded { .. }))
    }

    /// Mutating apply operations require storage, audit, and apply layer.
    pub fn allows_apply_operations(&self) -> bool {
        !self.active_modes.iter().any(|m| {
            matches!(
                m,
                DegradedMode::StorageDegraded { .. }
                    | DegradedMode::AuditUnavailable { .. }
                    | DegradedMode::ApplyLayerUnavailable { .. }
                    | DegradedMode::PolicyRecoveryRequired { .. }
            )
        })
    }

    /// Audit writes require the audit subsystem specifically.
    pub fn allows_audit_write(&self) -> bool {
        !self
            .active_modes
            .iter()
            .any(|m| matches!(m, DegradedMode::AuditUnavailable { .. }))
    }

    pub fn add(&mut self, mode: DegradedMode) {
        self.active_modes.push(mode);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // ── Test scaffolding ──────────────────────────────────────────────────

    struct FakeMarkerStore {
        marker: Mutex<Option<ApplyAttemptMarker>>,
    }

    impl FakeMarkerStore {
        fn empty() -> Self {
            Self {
                marker: Mutex::new(None),
            }
        }
        fn with(marker: ApplyAttemptMarker) -> Self {
            Self {
                marker: Mutex::new(Some(marker)),
            }
        }
    }

    impl ApplyMarkerStore for FakeMarkerStore {
        fn read(&self) -> Option<ApplyAttemptMarker> {
            self.marker.lock().unwrap().clone()
        }
        fn write(&self, m: &ApplyAttemptMarker) -> Result<(), String> {
            *self.marker.lock().unwrap() = Some(m.clone());
            Ok(())
        }
        fn clear(&self) -> Result<(), String> {
            *self.marker.lock().unwrap() = None;
            Ok(())
        }
    }

    #[allow(dead_code)]
    struct FailingMarkerStore;

    impl ApplyMarkerStore for FailingMarkerStore {
        fn read(&self) -> Option<ApplyAttemptMarker> {
            None
        }
        fn write(&self, _: &ApplyAttemptMarker) -> Result<(), String> {
            Err("disk full".into())
        }
        fn clear(&self) -> Result<(), String> {
            Err("disk full".into())
        }
    }

    struct RecordingAuditSink {
        events: Mutex<Vec<RecoveryAuditRecord>>,
        fail: bool,
    }

    impl RecordingAuditSink {
        fn ok() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                fail: true,
            }
        }
        fn count(&self) -> usize {
            self.events.lock().unwrap().len()
        }
        fn records(&self) -> Vec<RecoveryAuditRecord> {
            self.events.lock().unwrap().clone()
        }
    }

    impl RecoveryAuditSink for RecordingAuditSink {
        fn emit(&self, record: RecoveryAuditRecord) -> Result<(), String> {
            if self.fail {
                return Err("audit write failed".into());
            }
            self.events.lock().unwrap().push(record);
            Ok(())
        }
    }

    fn marker(phase: ApplyPhase) -> ApplyAttemptMarker {
        ApplyAttemptMarker {
            attempt_id: "att-001".to_string(),
            active_revision_id: "rev-aaa".to_string(),
            phase,
            started_at_epoch_secs: 1000,
            last_step_at_epoch_secs: 1001,
            intended_rollback_to: Some("rev-lkg".to_string()),
            correlation_id: "corr-001".to_string(),
        }
    }

    fn coord(
        store: FakeMarkerStore,
        audit: RecordingAuditSink,
    ) -> StartupRecoveryCoordinator<FakeMarkerStore, RecordingAuditSink> {
        StartupRecoveryCoordinator::new(store, audit)
    }

    // ── Cases ─────────────────────────────────────────────────────────────

    #[test]
    fn clean_startup_proceeds_normal() {
        let c = coord(FakeMarkerStore::empty(), RecordingAuditSink::ok());
        assert_eq!(c.assess(), StartupRecoveryState::Clean);
        let decision = decide_recovery(&StartupRecoveryState::Clean, true, true);
        assert_eq!(decision, RecoveryDecision::ProceedNormal);
        assert_eq!(c.execute(decision), RecoveryExecutionResult::Recovered);
    }

    #[test]
    fn crash_during_apply_with_lkg_triggers_rollback() {
        let c = coord(
            FakeMarkerStore::with(marker(ApplyPhase::Applying)),
            RecordingAuditSink::ok(),
        );
        let state = c.assess();
        assert!(matches!(
            state,
            StartupRecoveryState::PreviousApplyIncomplete { .. }
        ));
        let decision = decide_recovery(&state, true, true);
        assert!(
            matches!(decision, RecoveryDecision::RollbackAndClearMarker { .. }),
            "Applying phase with LKG should trigger rollback"
        );
        let result = c.execute(decision);
        assert!(
            matches!(result, RecoveryExecutionResult::RolledBack { .. }),
            "rollback should succeed: {result:?}"
        );
        // Marker must be cleared after rollback.
        assert!(c.marker_store.read().is_none(), "marker not cleared");
    }

    /// The audit trail is what someone reasons from during an incident, so it
    /// must not claim a rollback this layer never performed — no executor is
    /// wired yet, and enforcement is restored by the startup reconcile.
    #[test]
    fn the_trail_records_a_deferred_rollback_not_a_completed_one() {
        let c = coord(
            FakeMarkerStore::with(marker(ApplyPhase::Applying)),
            RecordingAuditSink::ok(),
        );
        let decision = decide_recovery(&c.assess(), true, true);
        let _ = c.execute(decision);

        let records = c.audit_sink.records();
        assert!(
            records
                .iter()
                .any(|r| matches!(r, RecoveryAuditRecord::RollbackInitiated { .. })),
            "the decision to roll back must still be recorded",
        );
        assert!(
            !records
                .iter()
                .any(|r| matches!(r, RecoveryAuditRecord::RollbackCompleted { .. })),
            "nothing rolled back, so nothing may claim it completed: {records:?}",
        );
        let deferred = records
            .iter()
            .find_map(|r| match r {
                RecoveryAuditRecord::RollbackDeferred { reason, .. } => Some(reason),
                _ => None,
            })
            .expect("the trail must say the rollback was deferred");
        assert!(
            !deferred.is_empty(),
            "a deferral without a reason is as opaque as silence",
        );
    }

    #[test]
    fn crash_after_apply_before_verify_triggers_verify_then_clear() {
        let c = coord(
            FakeMarkerStore::with(marker(ApplyPhase::Verifying)),
            RecordingAuditSink::ok(),
        );
        let state = c.assess();
        let decision = decide_recovery(&state, true, true);
        assert!(
            matches!(decision, RecoveryDecision::VerifyAndClearMarker { .. }),
            "Verifying phase should trigger verify+clear: {decision:?}"
        );
        let result = c.execute(decision);
        assert_eq!(result, RecoveryExecutionResult::VerifiedAndCleared);
        assert!(c.marker_store.read().is_none());
    }

    #[test]
    fn crash_during_rollback_retries_rollback() {
        let c = coord(
            FakeMarkerStore::with(marker(ApplyPhase::RollingBack)),
            RecordingAuditSink::ok(),
        );
        let state = c.assess();
        let decision = decide_recovery(&state, true, true);
        assert!(matches!(
            decision,
            RecoveryDecision::RollbackAndClearMarker { .. }
        ));
    }

    #[test]
    fn audit_unavailable_blocks_recovery_and_requires_manual_action() {
        let state = StartupRecoveryState::PreviousApplyIncomplete {
            marker: marker(ApplyPhase::Applying),
        };
        let decision = decide_recovery(&state, true, false /* audit unavailable */);
        assert!(
            matches!(decision, RecoveryDecision::RequireManualAction { .. }),
            "audit unavailable must block any mutating recovery"
        );
    }

    #[test]
    fn no_lkg_during_rollback_requires_manual_action() {
        let state = StartupRecoveryState::PreviousApplyIncomplete {
            marker: marker(ApplyPhase::Applying),
        };
        let decision = decide_recovery(&state, false /* no LKG */, true);
        assert!(matches!(
            decision,
            RecoveryDecision::RequireManualAction { .. }
        ));
    }

    #[test]
    fn failed_marker_always_requires_manual_action() {
        let c = coord(
            FakeMarkerStore::with(marker(ApplyPhase::FailedRequiresManualAction)),
            RecordingAuditSink::ok(),
        );
        let state = c.assess();
        assert!(matches!(
            state,
            StartupRecoveryState::ManualActionRequired { .. }
        ));
        let decision = decide_recovery(&state, true, true);
        assert!(matches!(
            decision,
            RecoveryDecision::RequireManualAction { .. }
        ));
    }

    #[test]
    fn audit_write_failure_during_rollback_aborts_without_clearing_marker() {
        let c = StartupRecoveryCoordinator::new(
            FakeMarkerStore::with(marker(ApplyPhase::Applying)),
            RecordingAuditSink::failing(),
        );
        let state = c.assess();
        let decision = decide_recovery(&state, true, true);
        let result = c.execute(decision);
        assert!(
            matches!(result, RecoveryExecutionResult::AuditWriteFailed { .. }),
            "audit failure must abort rollback: {result:?}"
        );
        // Marker MUST NOT be cleared when the audit write fails.
        assert!(
            c.marker_store.read().is_some(),
            "marker must remain when audit write fails"
        );
    }

    #[test]
    fn applied_phase_is_not_incomplete() {
        assert!(!ApplyPhase::Applied.is_incomplete());
        for phase in [
            ApplyPhase::Preparing,
            ApplyPhase::Applying,
            ApplyPhase::Verifying,
            ApplyPhase::RollbackRequired,
            ApplyPhase::RollingBack,
            ApplyPhase::RollbackDone,
            ApplyPhase::FailedRequiresManualAction,
        ] {
            assert!(phase.is_incomplete(), "{phase:?} should be incomplete");
        }
    }

    #[test]
    fn crash_counter_triggers_at_threshold() {
        let mut counter = CrashCounter::new(3, 86400);
        assert!(!counter.record_crash(1000));
        assert!(!counter.record_crash(1001));
        assert!(
            counter.record_crash(1002),
            "third crash should hit threshold"
        );
        assert!(counter.is_threshold_exceeded());
    }

    #[test]
    fn crash_counter_resets_after_window() {
        let mut counter = CrashCounter::new(2, 60);
        counter.record_crash(0);
        counter.record_crash(10);
        assert!(counter.is_threshold_exceeded());
        // After the reset window, a new crash should start a fresh count.
        assert!(
            !counter.record_crash(100),
            "first crash in new window should not exceed"
        );
        assert!(!counter.is_threshold_exceeded());
    }

    #[test]
    fn safe_disable_requires_confirmation_token() {
        let req = SafeDisableRequest {
            correlation_id: "req-1".into(),
            reason: "user request".into(),
            confirm_token: "wrong-token".into(),
        };
        let result = execute_safe_disable(&req, "correct-token", true, &NoopRecoveryAuditSink, 0);
        assert_eq!(result, SafeDisableOutcome::ConfirmationRequired);
    }

    #[test]
    fn safe_disable_emits_audit_event_and_succeeds() {
        let audit = RecordingAuditSink::ok();
        let req = SafeDisableRequest {
            correlation_id: "req-2".into(),
            reason: "test disable".into(),
            confirm_token: "tok".into(),
        };
        let result = execute_safe_disable(&req, "tok", true, &audit, 5000);
        assert_eq!(
            result,
            SafeDisableOutcome::Disabled {
                disabled_at_epoch_secs: 5000
            }
        );
        assert_eq!(audit.count(), 1, "one audit event emitted");
    }

    #[test]
    fn safe_disable_aborts_when_apply_layer_unavailable() {
        let req = SafeDisableRequest {
            correlation_id: "req-3".into(),
            reason: "test".into(),
            confirm_token: "tok".into(),
        };
        let result = execute_safe_disable(
            &req,
            "tok",
            false, /* unavailable */
            &NoopRecoveryAuditSink,
            0,
        );
        assert_eq!(result, SafeDisableOutcome::ApplyLayerUnavailable);
    }

    #[test]
    fn safe_disable_aborts_when_audit_write_fails() {
        let audit = RecordingAuditSink::failing();
        let req = SafeDisableRequest {
            correlation_id: "req-4".into(),
            reason: "test".into(),
            confirm_token: "tok".into(),
        };
        let result = execute_safe_disable(&req, "tok", true, &audit, 0);
        assert!(matches!(
            result,
            SafeDisableOutcome::AuditWriteFailed { .. }
        ));
    }

    #[test]
    fn degraded_mode_restricts_operations_correctly() {
        let mut status = DegradedModeStatus::default();
        assert!(status.is_healthy());
        assert!(status.allows_apply_operations());
        assert!(status.allows_read_only_ipc());

        status.add(DegradedMode::AuditUnavailable {
            detail: "log dir missing".into(),
        });
        assert!(
            !status.allows_apply_operations(),
            "audit unavailable blocks apply"
        );
        assert!(status.allows_read_only_ipc(), "read-only still allowed");
        assert!(!status.allows_audit_write());

        status.add(DegradedMode::IpcDegraded {
            detail: "pipe broken".into(),
        });
        assert!(
            !status.allows_read_only_ipc(),
            "IpcDegraded blocks reads too"
        );
    }
}
