//! Live tracing-verbosity control seam.
//!
//! The reload primitive is a concrete `nrr-diagnostics` type
//! (`TracingVerbosityHandle`) built at boot beside the tracing installer; this
//! crate reaches it only through [`VerbosityControl`], so tests inject a
//! recorder and a boot without a log writer simply has none. The window that
//! decides WHEN to be verbose is `crate::verbose_logging`.

/// Applies a live change to the process's tracing verbosity.
///
/// Implementations MUST be best-effort: a failure to reload the filter is
/// diagnostic-only and must never fail the settings write that caused it.
pub trait VerbosityControl: Send + Sync {
    /// Switches the live filter to the verbose directive (`true`) or the
    /// default one (`false`).
    fn set_verbose(&self, verbose: bool);
}

impl VerbosityControl for nrr_diagnostics::TracingVerbosityHandle {
    fn set_verbose(&self, verbose: bool) {
        nrr_diagnostics::TracingVerbosityHandle::set_verbose(self, verbose);
    }
}
