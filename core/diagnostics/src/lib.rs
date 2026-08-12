#![forbid(unsafe_code)]
// Enum/state types use inherent `from_str`/`as_str` pairs for the exact string
// forms persisted in NDJSON/DB — intentionally not `std::str::FromStr` (they
// return `Option`), so silence the trait-confusion lint crate-wide.
#![allow(clippy::should_implement_trait)]
//! Diagnostics, logging, and audit trail for NetRuleRouter.
//!
//! # Crate ownership
//!
//! `nrr-diagnostics` is the single authoritative location for:
//! - Operational NDJSON log writing and rotation
//! - Security audit NDJSON trail
//! - Privacy redaction layer
//! - Explain mode presentation
//! - Diagnostic archive export
//! - GUI/tray facade DTOs
//!
//! # Dependency graph
//!
//! ```text
//! nrr-diagnostics
//!   → nrr-domain   (DecisionExplain, ExplainDetailLevel, rule/decision types)
//!   → nrr-storage  (DiagnosticRedactionLevel, LookupExplainSummary, cache health)
//!   → nrr-shared   (IPC DTOs, route/adapter types)
//! ```
//!
//! This crate must **not** depend on Qt, QML, or any UI crate.
//! The service depends on this crate — not the other way around.
//!
//! # Logging facade
//!
//! All crates in this workspace use `tracing` spans and events.
//! The custom NDJSON `tracing-subscriber` layer that writes operational logs
//! is implemented within this crate.
//!
//! # Privacy policy
//!
//! Raw hostnames, IP addresses, process paths, and adapter identifiers must
//! never appear in output unless the caller explicitly requests `Diagnostics`
//! redaction level via an explicit user action.  The redaction layer
//! enforces this — callers must route all output through it.

pub mod archive;
pub mod audit;
pub mod error;
pub mod event;
pub mod explain;
pub mod facade;
pub mod local_offset;
pub mod logs;
pub mod privacy;
pub mod query;
pub mod reason;
pub mod redaction;
pub mod retention;
pub mod sink;
pub mod startup;
pub mod taxonomy;

pub use archive::{
    ArchiveBuilder, ArchiveInput, ArchiveSection, BuildResult, DiagnosticArchiveManifest,
    DiagnosticArchiveRequest, RedactionReport,
};
pub use audit::{
    compute_chain_hash, local_date_string, utc_date_string, ActorKind, AuditChainVerification,
    AuditEventInput, AuditEventKind, AuditEventResult, AuditQueryFilter, AuditReader, AuditWriter,
    AuditWriterConfig, InMemorySecurityAlertsRepository, SecurityAlert, SecurityAlertState,
    SecurityAlertsRepository, AUDIT_CHAIN_GENESIS, DEFAULT_MAX_FILE_SIZE_BYTES,
};
pub use error::{DiagnosticsError, DiagnosticsResult};
pub use event::{AuditEvent, LogEvent, AUDIT_EVENT_SCHEMA_VERSION, LOG_EVENT_SCHEMA_VERSION};
pub use explain::{
    map_explain, ExplainDataAvailability, ExplainQuery, ExplainQueryKind, ExplainResponse,
    RuntimeInputSample,
};
pub use facade::{
    AcknowledgeAlertRequest, AuditEntryDto, AuditEntryFilter, ClearLogsRequest, ClearLogsResult,
    DiagnosticModeStateDto, DiagnosticsFacade, DiagnosticsStatusDto, LogEntryDto, LogEntryFilter,
    MockDiagnosticsFacade, MockScenario, PageCursor, PageResult, PaginationParams,
    SecurityAlertDto, SetDiagnosticModeRequest,
};
pub use logs::{
    install_ndjson_tracing, install_ndjson_tracing_with_console,
    install_ndjson_tracing_with_console_and_verbose, install_ndjson_tracing_with_verbose,
    LogFilter, LogQueryFilter, LogReader, LogWriter, LogWriterConfig, LoggingMode,
    NdjsonTracingLayer, TracingInstallOutcome, TracingVerbosityHandle, DEFAULT_TRACING_FILTER,
    VERBOSE_TRACING_FILTER,
};
pub use privacy::{
    redact_adapter_id, redact_hostname, redact_ipv4, redact_ipv4_str, redact_process_path,
    redact_resolver_source, DiagnosticSession, DiagnosticSessionScope, Redacted, RedactionMode,
    SecretNeverLog, MARKER_DIAGNOSTIC_REQUIRED, MARKER_MASKED_IPV4, MARKER_MASKED_PATH,
    MARKER_PRIVATE_IPV4, MARKER_PUBLIC_IPV4, MARKER_REDACTED,
};
pub use query::{DiagnosticsQueryService, NoopQueryService};
pub use reason::{reason_code_meta, ReasonCode, ReasonCodeMeta, ALL_REASON_CODES};
pub use redaction::{
    explain_to_redaction, redaction_to_explain, DiagnosticRedactionLevel, ExplainDetailLevel,
};
pub use retention::{
    AuditRetentionPolicy, AuditWriteStatus, CleanupJob, CleanupResult, LogRetentionPolicy,
    ManualCleanupScope, StorageHealthCollector, StorageHealthSnapshot,
};
pub use sink::{AuditSink, CapturingSink, DiagnosticsSink, FailingAuditSink, NoopSink};
pub use startup::{DiagnosticsAvailability, DiagnosticsStartupHealth};
pub use taxonomy::{EventCategory, EventCorrelation, EventLevel, PrivacyClass};
