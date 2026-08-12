//! Archive export request types.

use crate::privacy::mode::RedactionMode;

// ── ArchiveSection ────────────────────────────────────────────────────────────

/// A section that can be included in a diagnostic archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArchiveSection {
    /// `health.json` — service and storage health snapshot.
    Health,
    /// `logs.ndjson` — recent operational log entries.
    Logs,
    /// `audit_summary.json` — recent audit trail entries (no raw payloads).
    AuditSummary,
    /// `audit_chain.ndjson` — raw audit NDJSON verbatim, INCLUDING the
    /// `prev_hash` / `event_hash` chain fields, so the trail stays
    /// tamper-verifiable. Diagnostics / DeveloperLocal tiers only (the raw lines
    /// carry `payload_summary_json`); never in a default-redaction export.
    AuditChain,
    /// `explain_samples.json` — explain responses for recent decisions.
    ExplainSamples,
    /// `cache_health.json` — FQDN/IP cache health detail.
    CacheHealth,
    /// `storage_health.json` — SQLite storage health detail.
    StorageHealth,
    /// `troubleshooting.md` — generated troubleshooting guide.
    Troubleshooting,
    /// `redaction_report.json` — what was hidden and why.
    RedactionReport,
    /// `system_info.json` — host OS/CPU/RAM + app version.
    SystemInfo,
}

impl ArchiveSection {
    /// Stable filename for this section inside the archive.
    #[must_use]
    pub fn filename(self) -> &'static str {
        match self {
            Self::Health => "health.json",
            Self::Logs => "logs.ndjson",
            Self::AuditSummary => "audit_summary.json",
            Self::AuditChain => "audit_chain.ndjson",
            Self::ExplainSamples => "explain_samples.json",
            Self::CacheHealth => "cache_health.json",
            Self::StorageHealth => "storage_health.json",
            Self::Troubleshooting => "troubleshooting.md",
            Self::RedactionReport => "redaction_report.json",
            Self::SystemInfo => "system_info.json",
        }
    }

    /// Whether this section is always included (mandatory).
    #[must_use]
    pub fn is_mandatory(self) -> bool {
        matches!(
            self,
            Self::Health
                | Self::Logs
                | Self::AuditSummary
                | Self::Troubleshooting
                | Self::SystemInfo
        )
    }

    /// Mandatory sections for every archive.
    pub const MANDATORY: &'static [Self] = &[
        Self::Health,
        Self::Logs,
        Self::AuditSummary,
        Self::Troubleshooting,
        Self::SystemInfo,
    ];
}

// ── DiagnosticArchiveRequest ──────────────────────────────────────────────────

/// Maximum log entries included in a default archive. A high ceiling — the
/// effective limit is the byte budget [`DEFAULT_MAX_LOG_BYTES`], since the
/// archive is compressed and log lines vary wildly in length.
pub const DEFAULT_MAX_LOG_ENTRIES: u32 = 100_000;
/// Byte budget for `logs.ndjson` (5 MiB uncompressed).
/// The archive is zip-compressed, so 5 MiB of text costs little on disk while
/// giving far more history than a fixed 1000-entry cap.
pub const DEFAULT_MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
/// Maximum audit entries included in an archive.
pub const DEFAULT_MAX_AUDIT_ENTRIES: u32 = 100;
/// Byte budget for the raw `audit_chain.ndjson` section (2 MiB uncompressed).
/// Like `logs.ndjson`, the archive is zip-compressed, so a byte budget carries
/// far more of the verifiable chain than a fixed entry count while staying
/// bounded. Only spent in Diagnostics / DeveloperLocal exports.
pub const DEFAULT_MAX_AUDIT_CHAIN_BYTES: u64 = 2 * 1024 * 1024;
/// Maximum archive size in bytes (50 MiB).
pub const MAX_ARCHIVE_SIZE_BYTES: u64 = 50 * 1024 * 1024;

/// Request to build a diagnostic archive.
///
/// The archive **never** includes raw DB files, private keys, full policy
/// content, or `SecretNeverLog` fields.
#[derive(Clone, Debug)]
pub struct DiagnosticArchiveRequest {
    /// Privacy redaction applied to all sections.
    pub redaction_mode: RedactionMode,
    /// Additional (non-mandatory) sections to include.
    pub optional_sections: Vec<ArchiveSection>,
    /// Only include log entries from this UTC ms onward.
    pub logs_from_ms: Option<i64>,
    /// Only include log entries up to this UTC ms.
    pub logs_to_ms: Option<i64>,
    /// Maximum number of log entries (a safety ceiling — see [`max_log_bytes`]).
    ///
    /// [`max_log_bytes`]: Self::max_log_bytes
    pub max_log_entries: u32,
    /// Byte budget for `logs.ndjson`. Newest entries are
    /// kept until this many bytes are written; the rest are dropped.
    pub max_log_bytes: u64,
    /// Maximum number of audit entries (for `audit_summary.json`).
    pub max_audit_entries: u32,
    /// Byte budget for the raw `audit_chain.ndjson` section. Only consumed when
    /// [`ArchiveSection::AuditChain`] is present (Diagnostics / DeveloperLocal).
    pub max_audit_chain_bytes: u64,
    /// Human-readable app version string (e.g., `"0.1.0-preview"`).
    pub app_version: String,
}

impl DiagnosticArchiveRequest {
    /// Builds a default request with `RedactionMode::Default`.
    pub fn default_export(app_version: impl Into<String>) -> Self {
        Self {
            redaction_mode: RedactionMode::Default,
            optional_sections: vec![ArchiveSection::RedactionReport],
            logs_from_ms: None,
            logs_to_ms: None,
            max_log_entries: DEFAULT_MAX_LOG_ENTRIES,
            max_log_bytes: DEFAULT_MAX_LOG_BYTES,
            max_audit_entries: DEFAULT_MAX_AUDIT_ENTRIES,
            max_audit_chain_bytes: DEFAULT_MAX_AUDIT_CHAIN_BYTES,
            app_version: app_version.into(),
        }
    }

    /// Builds a diagnostics-level request. Ships the raw, tamper-verifiable
    /// [`ArchiveSection::AuditChain`] in addition to the redacted summary — the
    /// Diagnostics tier is where raw `payload_summary_json` is permitted.
    pub fn diagnostics_export(app_version: impl Into<String>) -> Self {
        Self {
            redaction_mode: RedactionMode::Diagnostics,
            optional_sections: vec![
                ArchiveSection::CacheHealth,
                ArchiveSection::StorageHealth,
                ArchiveSection::ExplainSamples,
                ArchiveSection::AuditChain,
                ArchiveSection::RedactionReport,
            ],
            logs_from_ms: None,
            logs_to_ms: None,
            max_log_entries: DEFAULT_MAX_LOG_ENTRIES,
            max_log_bytes: DEFAULT_MAX_LOG_BYTES,
            max_audit_entries: DEFAULT_MAX_AUDIT_ENTRIES,
            max_audit_chain_bytes: DEFAULT_MAX_AUDIT_CHAIN_BYTES,
            app_version: app_version.into(),
        }
    }

    /// Returns all sections (mandatory + requested optional), deduplicated.
    pub fn all_sections(&self) -> Vec<ArchiveSection> {
        let mut sections: Vec<ArchiveSection> = ArchiveSection::MANDATORY.to_vec();
        for s in &self.optional_sections {
            if !sections.contains(s) {
                sections.push(*s);
            }
        }
        sections
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_filenames_are_stable() {
        assert_eq!(ArchiveSection::Health.filename(), "health.json");
        assert_eq!(ArchiveSection::Logs.filename(), "logs.ndjson");
        assert_eq!(
            ArchiveSection::AuditSummary.filename(),
            "audit_summary.json"
        );
        assert_eq!(
            ArchiveSection::Troubleshooting.filename(),
            "troubleshooting.md"
        );
        assert_eq!(
            ArchiveSection::RedactionReport.filename(),
            "redaction_report.json"
        );
    }

    #[test]
    fn mandatory_sections_are_mandatory() {
        for s in ArchiveSection::MANDATORY {
            assert!(s.is_mandatory(), "{s:?} must be mandatory");
        }
        assert!(!ArchiveSection::ExplainSamples.is_mandatory());
        assert!(!ArchiveSection::CacheHealth.is_mandatory());
    }

    #[test]
    fn default_export_includes_redaction_report() {
        let req = DiagnosticArchiveRequest::default_export("0.1.0");
        let sections = req.all_sections();
        assert!(sections.contains(&ArchiveSection::Health));
        assert!(sections.contains(&ArchiveSection::Logs));
        assert!(sections.contains(&ArchiveSection::RedactionReport));
    }

    #[test]
    fn all_sections_no_duplicates() {
        let req = DiagnosticArchiveRequest::diagnostics_export("0.1.0");
        let sections = req.all_sections();
        let mut seen = std::collections::HashSet::new();
        for s in &sections {
            assert!(seen.insert(*s as u32), "duplicate section: {s:?}");
        }
    }

    #[test]
    fn max_archive_size_is_50mib() {
        assert_eq!(MAX_ARCHIVE_SIZE_BYTES, 50 * 1024 * 1024);
    }
}
