//! Manager traits — the narrow interfaces between the service runtime
//! loop and the underlying subsystems (storage, diagnostics, policy,
//! IPC, apply, health): `StorageManager`, `PolicyManager`, `IpcServer`,
//! `HealthReporter`, `ApplyController`.
//!
//! Every trait is `Send + Sync` so the runtime loop can move them across
//! threads (background tasks, IPC handlers, watchdog timers). No async
//! yet — the runtime loop picks the executor; until then the
//! traits are blocking and the loop wraps them in `spawn_blocking` where
//! needed (mirroring `nrr-storage`'s sync-only contract).

use crate::state::{
    ActiveRevisionState, ServiceHealthSeverity, ServicePolicyState, ServiceRuntimeState,
};

/// Result of a single bootstrap phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapPhaseStatus {
    /// Stable slug for the phase: `topology`, `storage-open`,
    /// `migrations`, `integrity`, `policy-load`, `diagnostics-init`,
    /// `ipc-start`, `runtime-loop-start`.
    pub phase: &'static str,
    pub severity: ServiceHealthSeverity,
    /// Operator-visible message — English-only by design, like the rest of the
    /// audit trail. No translation needed here.
    pub message: String,
}

/// Aggregate result of the bootstrap pipeline. The runtime turns this
/// into a `ServiceRuntimeState` (`Running` / `Degraded` /
/// `RecoveryRequired`) and emits the corresponding audit events.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BootstrapReport {
    pub phases: Vec<BootstrapPhaseStatus>,
    /// Worst severity observed across all phases.
    pub worst_severity: ServiceHealthSeverity,
    /// `true` when at least one phase was `Blocking` — runtime must NOT
    /// transition to `Running` and must NOT accept mutating IPC.
    pub blocking: bool,
}

/// Storage subsystem (`nrr-storage`). The trait wraps the
/// service-state DB and the FQDN/IP cache so the runtime never touches
/// `rusqlite::Connection` directly. The production
/// impl is provided elsewhere; tests use a fake.
pub trait StorageManager: Send + Sync {
    /// Open service-state and FQDN/IP cache stores under the
    /// service-owned `%ProgramData%` topology, run migrations, and
    /// report what happened. Idempotent — calling it twice on a healthy
    /// install must not corrupt state.
    fn bootstrap(&self) -> BootstrapPhaseStatus;
}

/// Diagnostics subsystem (`nrr-diagnostics`). Owns the audit
/// NDJSON writer and the operational log writer.
pub trait DiagnosticsManager: Send + Sync {
    /// Open audit + operational log writers and continue the audit hash
    /// chain from the last persisted event. Returns the bootstrap phase
    /// status for the diagnostics-init phase.
    fn bootstrap(&self) -> BootstrapPhaseStatus;
}

/// Policy subsystem — the active-revision state machine. The
/// service is the *only* writer of the active pointer; GUI/tray submit
/// candidate revisions through IPC and the service decides whether to
/// promote them.
///
/// **Note.** Mutation entry points (submit candidate, dry
/// run, issue token, activate, rollback) live on
/// [`crate::activation_coordinator::ActivationCoordinator`]. The
/// coordinator wraps the storage layer + dispatcher + audit, while this
/// trait stays narrow — it carries the read-only state queries that
/// every consumer of the runtime needs (health snapshot, IPC status
/// envelope, recovery audit). The production
/// `PolicyManager` impl forwards the read methods to the
/// coordinator's accessor functions.
pub trait PolicyManager: Send + Sync {
    /// Load the active revision (or fall back to LKG, or report
    /// `RecoveryRequired`). Pure read — no apply attempt yet.
    fn load_active(&self) -> ServicePolicyState;
    /// Snapshot of the currently-loaded revision, if any.
    fn current_revision(&self) -> Option<ActiveRevisionState>;

    /// Pending / superseded revision summaries surfaced
    /// in `SnapshotInitialResponse.pending_revisions`. The default impl
    /// returns an empty list so existing implementors (mocks, scaffolds)
    /// compile unchanged; the production impl in
    /// [`crate::policy_manager_production::CoordinatorPolicyManager`]
    /// returns the latest N candidates + recent superseded entries from
    /// `nrr-storage::RevisionsRepository`.
    fn pending_revisions(&self) -> Vec<RevisionSummary> {
        Vec::new()
    }

    /// Id of the last known-good revision (most recent
    /// `superseded` entry, optional). Default `None` for mocks; the
    /// production impl reads `RevisionsRepository::last_known_good()`.
    fn last_known_good_id(&self) -> Option<String> {
        None
    }

    /// Slug of the active `ApplyFailurePolicy`, matching
    /// `ApplyFailurePolicySettings::VALID_POLICY_SLUGS`. Default
    /// `"all-or-nothing"` is the safe baseline used by mocks.
    fn current_failure_policy_slug(&self) -> &'static str {
        "all-or-nothing"
    }
}

/// Slim summary of a revision row used by snapshot/IPC consumers.
/// Mirrors a subset of `RevisionRecord` shaped for the wire DTO; the
/// full record (with `rules_json`) stays inside the storage layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionSummary {
    pub revision_id: String,
    pub status_slug: &'static str,
    pub source_slug: &'static str,
    pub correlation_id: String,
    pub created_at: u64,
    /// Epoch seconds. `None` unless the revision has been activated.
    pub activated_at: Option<u64>,
    /// Epoch seconds. `None` unless the revision has been superseded or
    /// rolled back.
    pub superseded_at: Option<u64>,
    pub risk_level_slug: Option<&'static str>,
    pub content_hash: String,
}

/// IPC server. `bind()` returns an
/// `IpcAcceptor` whose `accept_one()` is the tick primitive consumed by
/// the `ServiceSupervisor`. This makes `IpcAcceptFailurePolicy::Recoverable`
/// observable — supervisor calls `bind()` again after categorised
/// `AcceptOutcome::Err`, subject to retry budget.
pub trait IpcServer: Send + Sync {
    /// Build the listener state (security descriptor, shutdown signal,
    /// worker registry). Cheap; the actual `CreateNamedPipeW` happens per
    /// tick inside `accept_one`. Idempotent in the sense that multiple
    /// `bind()` calls without overlapping accept loops do not collide;
    /// this is the contract Recoverable policy depends on.
    fn bind(&self) -> Result<Box<dyn IpcAcceptor>, IpcBindError>;
}

/// One-tick accept primitive. Each `accept_one()` call either hands a
/// connection off to a worker thread or reports why it could not. The
/// supervisor's tick loop is approximately:
/// ```text
/// loop {
///     match acceptor.accept_one() {
///         AcceptOutcome::Connected | AcceptOutcome::Idle => continue,
///         AcceptOutcome::ShutdownRequested => break,
///         AcceptOutcome::Err(e) => consult policy, possibly rebind,
///     }
/// }
/// acceptor.join_workers();
/// ```
pub trait IpcAcceptor: Send + Sync {
    /// Block until the next client connects, the shutdown signal fires,
    /// or accept fails. On `Connected` the connection has already been
    /// dispatched to a worker thread — the supervisor only sees the
    /// outcome. On hard failures the supervisor consults
    /// `IpcAcceptFailurePolicy`.
    fn accept_one(&self) -> AcceptOutcome;

    /// Signal to any in-flight `accept_one` to return
    /// `AcceptOutcome::ShutdownRequested` on its next observation, and
    /// to subsequent ticks to short-circuit. Idempotent — safe to call
    /// from any thread, multiple times.
    fn request_shutdown(&self);

    /// Best-effort join of all worker threads launched by previous
    /// `Connected` outcomes. Called by the supervisor after the
    /// accept-tick loop has exited. Workers must already be winding down
    /// because they observe the same shutdown flag flipped by
    /// `request_shutdown`.
    fn join_workers(&self);
}

/// Result of one `IpcAcceptor::accept_one` tick.
#[derive(Debug)]
pub enum AcceptOutcome {
    /// A client connected and was handed off to a worker thread.
    /// Supervisor: tick again.
    Connected,
    /// Transient hiccup that did not produce a connection (e.g. a
    /// concurrent shutdown signal arriving after `CreateNamedPipeW`
    /// succeeded but before the client connected, or a busy-rejected
    /// inbound at the concurrency cap). Supervisor: tick again without
    /// charging the policy retry budget.
    Idle,
    /// Shutdown event signaled before a client connected, or the
    /// shutdown flag was already set when the tick started. Supervisor:
    /// stop ticking.
    ShutdownRequested,
    /// Hard accept-loop failure. Supervisor: consult
    /// `IpcAcceptFailurePolicy` to decide whether to rebind.
    Err(AcceptError),
}

/// Categorised hard-failure information for accept-loop policy
/// consultation. The category drives Recoverable vs Critical bookkeeping
/// in the supervisor; the message is for audit/log only.
#[derive(Debug, Clone)]
pub struct AcceptError {
    pub category: AcceptErrorCategory,
    pub message: String,
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.category, self.message)
    }
}

impl std::error::Error for AcceptError {}

/// Failure taxonomy for `AcceptOutcome::Err`. Stable slugs land in audit
/// payloads; do not rename without coordinating the migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptErrorCategory {
    /// `CreateNamedPipeW` failed. Usually transient (e.g. handle table
    /// pressure) but may indicate persistent system state.
    PipeCreate,
    /// Wait on shutdown/connect events failed. Should be impossible in
    /// healthy state; suggests OS-level corruption.
    WaitFailed,
    /// `thread::spawn` for the per-connection worker failed. Memory
    /// pressure / thread-handle exhaustion.
    WorkerSpawn,
    /// Anything else. The message field carries detail for audit.
    Other,
}

/// Errors returned by `IpcServer::bind`. These are setup-time failures
/// (security descriptor build, event creation) — the supervisor treats
/// any `Err(IpcBindError)` as `IpcAcceptFailurePolicy::Critical` because
/// without a valid listener we cannot serve IPC at all.
#[derive(Debug, Clone)]
pub enum IpcBindError {
    /// SDDL → `SECURITY_DESCRIPTOR` conversion failed.
    SecurityDescriptor(String),
    /// `CreateEventW` for the shutdown notification event failed.
    EventCreate(String),
    /// Catch-all for unforeseen platform errors.
    Other(String),
}

impl std::fmt::Display for IpcBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SecurityDescriptor(m) => write!(f, "security descriptor build failed: {m}"),
            Self::EventCreate(m) => write!(f, "shutdown event creation failed: {m}"),
            Self::Other(m) => write!(f, "ipc bind failed: {m}"),
        }
    }
}

impl std::error::Error for IpcBindError {}

/// Privileged-mutation gateway. Every change to Windows routing /
/// firewall flows through this trait so the platform layer can swap in the real
/// adapter without the runtime knowing the details.
pub trait ApplyController: Send + Sync {
    /// Attempt to apply the currently-active policy revision. Returns
    /// the outcome; the runtime turns it into an audit event and a
    /// health-status update.
    fn apply_active(&self) -> ApplyOutcome;
}

/// Shape of an apply attempt result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Policy applied successfully.
    Applied,
    /// Apply attempted but skipped — for example because policy state
    /// is not `ActiveReady`. The string is an English audit-grade
    /// reason slug.
    Skipped(&'static str),
    /// Apply failed; the message describes the failure for audit. The
    /// runtime is expected to mark the service `Degraded` until the
    /// next successful attempt.
    Failed(String),
}

/// Health aggregator. Combines per-component statuses (storage,
/// diagnostics, policy, apply, IPC, adapters) into a single
/// `ServiceRuntimeState` snapshot.
pub trait HealthReporter: Send + Sync {
    fn current_state(&self) -> ServiceRuntimeState;
    fn worst_severity(&self) -> ServiceHealthSeverity;
}

/// Bundle that the runtime entry-point in `nrr-windows-service`
/// receives. Each field is a trait object so dev/console mode can swap
/// in fakes via a `console` cargo feature on the
/// binary that supplies in-memory implementations.
pub struct ServiceManagers {
    pub storage: Box<dyn StorageManager>,
    pub diagnostics: Box<dyn DiagnosticsManager>,
    pub policy: Box<dyn PolicyManager>,
    pub ipc: Box<dyn IpcServer>,
    pub apply: Box<dyn ApplyController>,
    pub health: Box<dyn HealthReporter>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check the `IpcAcceptor` shape: a stub
    /// implementation is observable via the trait, `request_shutdown`
    /// is idempotent, and `accept_one` can return the full outcome
    /// vocabulary without panicking.
    #[test]
    fn ipc_acceptor_stub_supports_full_outcome_vocabulary() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;

        struct StubAcceptor {
            ticks: AtomicUsize,
            shutdown: AtomicBool,
            joined: AtomicBool,
        }
        impl IpcAcceptor for StubAcceptor {
            fn accept_one(&self) -> AcceptOutcome {
                let n = self.ticks.fetch_add(1, Ordering::SeqCst);
                if self.shutdown.load(Ordering::SeqCst) {
                    return AcceptOutcome::ShutdownRequested;
                }
                match n {
                    0 => AcceptOutcome::Connected,
                    1 => AcceptOutcome::Idle,
                    _ => AcceptOutcome::Err(AcceptError {
                        category: AcceptErrorCategory::PipeCreate,
                        message: "stub failure".into(),
                    }),
                }
            }
            fn request_shutdown(&self) {
                self.shutdown.store(true, Ordering::SeqCst);
            }
            fn join_workers(&self) {
                self.joined.store(true, Ordering::SeqCst);
            }
        }

        let acc = Arc::new(StubAcceptor {
            ticks: AtomicUsize::new(0),
            shutdown: AtomicBool::new(false),
            joined: AtomicBool::new(false),
        });

        // First tick: Connected.
        assert!(matches!(acc.accept_one(), AcceptOutcome::Connected));
        // Second tick: Idle.
        assert!(matches!(acc.accept_one(), AcceptOutcome::Idle));
        // Third tick: Err with category.
        match acc.accept_one() {
            AcceptOutcome::Err(e) => {
                assert_eq!(e.category, AcceptErrorCategory::PipeCreate);
                assert!(e.message.contains("stub"));
            }
            other => panic!("expected Err, got {other:?}"),
        }

        // request_shutdown is idempotent.
        acc.request_shutdown();
        acc.request_shutdown();
        assert!(matches!(acc.accept_one(), AcceptOutcome::ShutdownRequested));

        acc.join_workers();
        assert!(acc.joined.load(Ordering::SeqCst));
    }

    /// Verify `IpcBindError` Display formatting — used in audit messages
    /// and supervisor health-component rollups.
    #[test]
    fn ipc_bind_error_display_includes_cause() {
        let e = IpcBindError::SecurityDescriptor("0xC000003F".into());
        let s = format!("{e}");
        assert!(s.contains("security descriptor"));
        assert!(s.contains("0xC000003F"));
    }

    #[test]
    fn severity_ordering_is_monotonic() {
        assert!(ServiceHealthSeverity::Ok < ServiceHealthSeverity::Warning);
        assert!(ServiceHealthSeverity::Warning < ServiceHealthSeverity::Degraded);
        assert!(ServiceHealthSeverity::Degraded < ServiceHealthSeverity::Blocking);
        // `Unknown` is the largest variant so an unset severity does not
        // accidentally mask a real Blocking elsewhere when the
        // aggregator does `severities.iter().max()` and treats Unknown
        // as "needs investigation".
        assert!(ServiceHealthSeverity::Blocking < ServiceHealthSeverity::Unknown);
    }
}
