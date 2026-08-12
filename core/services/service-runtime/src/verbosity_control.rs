//! Live tracing-verbosity control seam — block 16.HW-0716 P3.
//!
//! # Problem
//!
//! The "Verbose service logging" toggle (`service_stability_config
//! .verbose_logging`) was already boot-correct: `nrr-windows-service` reads
//! the persisted flag before installing the global tracing subscriber, so a
//! fresh service start always begins at the right filter
//! (`DEFAULT_TRACING_FILTER` / `VERBOSE_TRACING_FILTER`, see
//! `nrr_diagnostics::logs::tracing_layer`). What was missing: a mid-session
//! `Set` (the GUI Save button) only persisted the new value to SQLite — the
//! *running* process kept its boot-time `EnvFilter` until the service was
//! restarted.
//!
//! # Design — policy/mechanism seam
//!
//! The actual reload primitive (`tracing_subscriber::reload::Handle`) is a
//! concrete `nrr-diagnostics` type (`TracingVerbosityHandle`) constructed
//! once, at boot, alongside `install_ndjson_tracing_with_verbose` in
//! `nrr-windows-service`. `nrr-service-runtime` (this crate) must not
//! depend on `tracing-subscriber`'s reload machinery directly — instead it
//! defines the narrow [`VerbosityControl`] trait so:
//!
//! - `ProductionServiceStability::set` (in `production_settings.rs`) can
//!   drive live verbosity through an `Option<Arc<dyn VerbosityControl>>`
//!   field, exactly mirroring the existing `liveness_tracker` /
//!   `resolver_controller` optional-live-apply fields on the same struct.
//! - Tests inject a fake recorder instead of a real subscriber.
//! - `None` (tests, non-Windows, degraded boot) is a safe default: the
//!   value still persists to SQLite and takes effect on the next restart,
//!   same as before this change.
//!
//! `nrr_diagnostics::TracingVerbosityHandle` implements this trait directly
//! below, so production wiring (`runtime_deps.rs`) can pass the boot-time
//! handle straight through `Arc::clone` without an extra adapter type.

/// Applies a live change to the process's tracing verbosity.
///
/// Implementations MUST be best-effort: a failure to reload the filter is
/// diagnostic-only and must never surface as a settings-write error (the
/// caller is a `ServiceStabilityConfigSet` IPC handler on the hot path of
/// an admin-gated but otherwise ordinary settings save).
pub trait VerbosityControl: Send + Sync {
    /// Switches the live tracing filter to the verbose directive
    /// (`verbose == true`) or the default directive (`verbose == false`).
    fn set_verbose(&self, verbose: bool);
}

impl VerbosityControl for nrr_diagnostics::TracingVerbosityHandle {
    fn set_verbose(&self, verbose: bool) {
        nrr_diagnostics::TracingVerbosityHandle::set_verbose(self, verbose);
    }
}

// A `FakeVerbosityControl` test double (recording calls for handler-level
// assertions) lives alongside `ProductionServiceStability`'s existing test
// module in `production_settings.rs`, which is the only consumer that needs
// it — see `service_stability_tests::verbose_logging_set_drives_live_reload`.
