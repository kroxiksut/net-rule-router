//! Diagnostic archive export.
//!
//! Produces a `.zip` archive containing redacted diagnostic data for
//! troubleshooting support.  The archive is never a backup/restore
//! mechanism for routing policy.

pub mod builder;
mod correlation;
pub mod manifest;
pub mod playbooks;
pub mod request;

#[cfg(feature = "fuzzing")]
pub fn fuzz_archive_correlation(data: &[u8]) {
    if data.len() > 4 * 1024 * 1024 {
        return;
    }
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    let Some(capped) =
        crate::logs::privacy::cap_stored_line(line, crate::taxonomy::PrivacyClass::PublicSummary)
    else {
        return;
    };
    if let Ok(aliases) = correlation::ArchiveAliases::new() {
        let _ = aliases.log_line(line, &capped, crate::privacy::RedactionMode::Default);
    }
}

pub use builder::{ArchiveBuilder, ArchiveInput, AttachedLog, BuildResult};
pub use manifest::{DiagnosticArchiveManifest, RedactionReport, MANIFEST_SCHEMA_VERSION};
pub use playbooks::{all_playbooks, render_playbooks_markdown};
pub use request::{
    ArchiveSection, DiagnosticArchiveRequest, DEFAULT_MAX_AUDIT_ENTRIES, DEFAULT_MAX_LOG_ENTRIES,
    MAX_ARCHIVE_SIZE_BYTES,
};
