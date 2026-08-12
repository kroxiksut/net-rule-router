//! Diagnostic archive export.
//!
//! Produces a `.zip` archive containing redacted diagnostic data for
//! troubleshooting support.  The archive is never a backup/restore
//! mechanism for routing policy.

pub mod builder;
pub mod manifest;
pub mod playbooks;
pub mod request;

pub use builder::{ArchiveBuilder, ArchiveInput, BuildResult};
pub use manifest::{DiagnosticArchiveManifest, RedactionReport, MANIFEST_SCHEMA_VERSION};
pub use playbooks::{all_playbooks, render_playbooks_markdown};
pub use request::{
    ArchiveSection, DiagnosticArchiveRequest, DEFAULT_MAX_AUDIT_ENTRIES, DEFAULT_MAX_LOG_ENTRIES,
    MAX_ARCHIVE_SIZE_BYTES,
};
