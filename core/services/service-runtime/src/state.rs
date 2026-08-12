//! Service-runtime state model. Pure data — no I/O, no Windows API
//! calls, no async.

/// Top-level service runtime state, mirrored 1:1 to the SCM status
/// reporting. `Degraded` and `RecoveryRequired` do not have a native
/// SCM equivalent — they are reported via the health snapshot while SCM
/// continues to see `Running`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServiceRuntimeState {
    /// Bootstrap in progress — storage opening, migrations, integrity
    /// checks. No mutating IPC accepted.
    Starting,
    /// Bootstrap completed, IPC server listening, runtime loop spinning.
    Running,
    /// Running but at least one component reports `degraded` severity
    /// (e.g. operational logs unavailable). Read-only IPC still served.
    Degraded,
    /// Active revision could not be loaded and no valid LKG was found.
    /// All apply attempts are blocked until the user acts.
    RecoveryRequired,
    /// User explicitly disabled the product. Service stays alive (so the
    /// user can re-enable from the GUI) but performs no privileged work.
    Disabled,
    /// SCM stop received, draining background tasks and flushing audit.
    Stopping,
    /// Shutdown complete; process is about to exit.
    Stopped,
}

/// Reason the service stopped, so the `Stopped` state carries enough
/// context to write a single audit event on exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServiceShutdownReason {
    /// SCM "stop" control code.
    ScmStop,
    /// Windows session shutdown.
    SystemShutdown,
    /// Bootstrap encountered a blocking failure that cannot be recovered
    /// in-process. The service exits so SCM recovery actions can apply.
    BootstrapBlocking,
    /// Internal panic / unrecoverable error caught at the runtime
    /// boundary.
    UnhandledError,
}

/// Coarse health severity used by the aggregator (`HealthReporter`) and
/// by every individual component manager when reporting status. The
/// monotonic ordering — `Ok < Warning < Degraded < Blocking` — lets the
/// aggregator just take the worst severity across components.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ServiceHealthSeverity {
    /// Component is healthy.
    Ok,
    /// Non-blocking anomaly (e.g. cache rebuild expected on next start).
    Warning,
    /// Reduced functionality but service can still serve read-only IPC.
    Degraded,
    /// Service-critical failure; mutating operations must be blocked.
    Blocking,
    /// Severity not yet computed for this component (early bootstrap).
    #[default]
    Unknown,
}

/// The lifecycle of the loaded canonical policy: active revision load,
/// integrity verification, and recovery/LKG coordination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServicePolicyState {
    /// First run or fresh install — no active revision yet.
    NoState,
    /// Reading the active pointer / loading + verifying the canonical
    /// profile.
    LoadingActive,
    /// Active revision validated and ready for apply attempts.
    ActiveReady,
    /// Active revision failed integrity; LKG fallback in progress.
    ActiveInvalid,
    /// LKG loaded and ready as the effective active revision.
    LkgReady,
    /// Neither active nor LKG is usable. User intervention required.
    RecoveryRequired,
    /// Product disabled by user.
    Disabled,
}

/// Per-revision summary surfaced via `HealthReporter` and the IPC status
/// snapshot. Field shapes match the contract in `nrr-shared`; the struct
/// here is a transport-neutral mirror so the runtime never touches GUI
/// types directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveRevisionState {
    /// Stable revision identifier (UUID v4 in production).
    pub revision_id: String,
    /// Where the revision came from: `import`, `gui-edit`, `auto-load`,
    /// `recovery-fallback`. Free-form.
    pub provenance: String,
    /// Number of canonical rules in this revision.
    pub rule_count: usize,
    /// `route_behavior_mode` slug from `nrr-shared`.
    pub behavior_mode: String,
    /// SHA-256 of the canonical bytes used for integrity verification.
    pub content_hash_hex: String,
    /// Wall-clock time the revision became active. ISO-8601 UTC string
    /// to keep the runtime free of `chrono` while we're still in the
    /// scaffold.
    pub activated_at_iso: String,
}
