//! Privacy filtering, redaction, and diagnostic session.
//!
//! # Three components
//!
//! | Module   | Responsibility                                               |
//! |----------|--------------------------------------------------------------|
//! | `mode`   | `RedactionMode`, `DiagnosticSession`, mode conversions       |
//! | `redact` | `Redacted<T>`, redaction markers, per-field helper functions |
//! | `secret` | `SecretNeverLog<T>` — deny-by-construction                   |
//!
//! # Unified policy
//!
//! All three output paths (operational logs, explain responses, archive export)
//! use `RedactionMode` as the single source of truth for what to reveal.
//! The mode converts to `DiagnosticRedactionLevel` (storage) and `LoggingMode`
//! (log writer) automatically via `From` impls.

pub mod mode;
pub mod redact;
pub mod secret;

pub use mode::{DiagnosticSession, DiagnosticSessionScope, RedactionMode};
pub use redact::{
    redact_adapter_id, redact_hostname, redact_ipv4, redact_ipv4_str, redact_process_path,
    redact_resolver_source, Redacted, MARKER_DIAGNOSTIC_REQUIRED, MARKER_MASKED_IPV4,
    MARKER_MASKED_PATH, MARKER_PRIVATE_IPV4, MARKER_PUBLIC_IPV4, MARKER_REDACTED,
};
pub use secret::SecretNeverLog;
