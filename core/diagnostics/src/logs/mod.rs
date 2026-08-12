//! Operational NDJSON log writer, filter, and reader.
//!
//! # Storage
//!
//! Operational logs are written as NDJSON files in a `logs/` directory under
//! the service-owned data path.  Files are named `nrr_service_YYYYMMDD-N.ndjson`
//! (UTC date, rotation index starting at 1).
//!
//! # Separation from audit trail
//!
//! Operational logs use a completely separate directory and file prefix from
//! audit files (`nrr_audit_*`).  They must never be mixed.  Operational logs
//! can be cleared by the user; audit NDJSON files cannot.
//!
//! # Filtering and modes
//!
//! [`LogFilter`] controls what is written based on the current [`LoggingMode`]:
//! - `Default`: service lifecycle, errors, security events only
//! - `Diagnostic`: adds decision summaries, cache details
//! - `DeveloperTrace`: everything including Trace level

pub mod filter;
pub mod reader;
pub mod session_window;
pub mod tracing_layer;
pub mod writer;

pub use filter::{
    LogFilter, LoggingMode, RATE_LIMITED_CATEGORIES, RATE_LIMIT_MAX_DEFAULT,
    RATE_LIMIT_MAX_DIAGNOSTIC, RATE_LIMIT_WINDOW_SECS,
};
pub use reader::{LogQueryFilter, LogReader};
pub use tracing_layer::{
    install_ndjson_tracing, install_ndjson_tracing_with_console,
    install_ndjson_tracing_with_console_and_verbose, install_ndjson_tracing_with_verbose,
    NdjsonTracingLayer, TracingInstallOutcome, TracingVerbosityHandle, DEFAULT_TRACING_FILTER,
    VERBOSE_TRACING_FILTER,
};
pub use writer::{LogWriter, LogWriterConfig, DEFAULT_LOG_MAX_FILE_SIZE_BYTES};
