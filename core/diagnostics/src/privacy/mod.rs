//! Privacy filtering and redaction.
//!
//! # Two components
//!
//! | Module   | Responsibility                                               |
//! |----------|--------------------------------------------------------------|
//! | `mode`   | `RedactionMode` and its conversions                          |
//! | `redact` | `Redacted<T>`, redaction markers, per-field helper functions |
//!
//! # Unified policy
//!
//! All three output paths (operational logs, explain responses, archive export)
//! use `RedactionMode` as the single source of truth for what to reveal.
//! The mode converts to `DiagnosticRedactionLevel` (storage) and `LoggingMode`
//! (log writer) automatically via `From` impls.

pub mod mode;
pub mod redact;

pub use mode::RedactionMode;
pub use redact::{
    redact_adapter_id, redact_hostname, redact_ipv4, redact_ipv4_str, redact_process_path,
    redact_resolver_source, Redacted, MARKER_MASKED_IPV4, MARKER_MASKED_PATH, MARKER_PRIVATE_IPV4,
    MARKER_PUBLIC_IPV4, MARKER_REDACTED,
};
