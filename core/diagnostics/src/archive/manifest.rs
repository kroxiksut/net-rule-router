//! Archive manifest and redaction report.

use serde::{Deserialize, Serialize};

/// Current manifest schema version.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

// ── DiagnosticArchiveManifest ─────────────────────────────────────────────────

/// Describes the contents and provenance of a diagnostic archive.
///
/// Always the first file read from an archive (`manifest.json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiagnosticArchiveManifest {
    /// Schema version (always [`MANIFEST_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// UTC Unix milliseconds when the archive was created.
    pub created_at: i64,
    /// Human-readable app version string.
    pub app_version: String,
    /// Redaction mode applied: `"default"` or `"diagnostics"`.
    pub redaction_mode: String,
    /// Filenames of sections included in the archive.
    pub included_sections: Vec<String>,
    /// Number of operational log entries included.
    pub log_entry_count: u32,
    /// Number of audit summary entries included.
    pub audit_entry_count: u32,
    /// Approximate total archive size in bytes.
    pub total_size_bytes_approx: u64,
    /// Whether this archive contains any diagnostic-level detail.
    pub contains_diagnostic_detail: bool,
    /// No-backup guarantee statement (always present, informational).
    pub no_backup_guarantee: String,
    /// Build provenance, so a triager can map the archive to the EXACT
    /// binary. `build_commit` is a short git SHA
    /// (with a `-dirty` suffix for an uncommitted tree) or `"unknown"`;
    /// `build_profile` is `debug`/`release`; `build_target` is the target
    /// triple. Captured at compile time by this crate's `build.rs`. Optional
    /// on the wire (`#[serde(default)]`) so archives from older builds still
    /// deserialize.
    #[serde(default)]
    pub build_commit: String,
    #[serde(default)]
    pub build_profile: String,
    #[serde(default)]
    pub build_target: String,
}

impl DiagnosticArchiveManifest {
    /// Short git SHA of the build that produced this binary (captured by
    /// `build.rs`), or `"unknown"`. A `-dirty` suffix means the tree had
    /// uncommitted changes at build time.
    pub const BUILD_COMMIT: &'static str = env!("NRR_BUILD_COMMIT");
    /// Build profile (`debug`/`release`).
    pub const BUILD_PROFILE: &'static str = env!("NRR_BUILD_PROFILE");
    /// Build target triple.
    pub const BUILD_TARGET: &'static str = env!("NRR_BUILD_TARGET");

    pub const NO_BACKUP_GUARANTEE: &'static str =
        "This archive does not contain private keys, raw policy backups, \
         raw service database files, or credential-like secrets. \
         It is a diagnostic snapshot only and cannot be used to restore service state.";

    /// Validates that mandatory sections are included.
    pub fn validate(&self) -> Result<(), String> {
        for required in &[
            "health.json",
            "logs.ndjson",
            "audit_summary.json",
            "troubleshooting.md",
        ] {
            if !self.included_sections.contains(&required.to_string()) {
                return Err(format!(
                    "mandatory section '{required}' is missing from archive"
                ));
            }
        }
        if self.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(format!(
                "unsupported manifest schema version: {}",
                self.schema_version
            ));
        }
        Ok(())
    }
}

// ── RedactionReport ───────────────────────────────────────────────────────────

/// Documents what was hidden in the archive and why.
///
/// Allows users to understand the privacy posture of their export before
/// sharing it with support.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedactionReport {
    /// Redaction mode applied.
    pub redaction_mode: String,
    /// Whether an active diagnostic session was in effect at export time.
    pub diagnostic_mode_active: bool,
    /// Number of hostname fields that were redacted to eTLD+1.
    pub hostnames_redacted: u32,
    /// Number of IP addresses hidden behind markers.
    pub ips_redacted: u32,
    /// Number of process paths reduced to filename only.
    pub paths_redacted: u32,
    /// Sections excluded from this archive.
    pub excluded_sections: Vec<String>,
    /// Fields that are always hidden regardless of mode.
    pub always_hidden_fields: Vec<String>,
}

impl RedactionReport {
    /// Returns the fields that are always hidden, regardless of redaction mode.
    pub fn always_hidden() -> Vec<String> {
        vec![
            "raw_db_files".into(),
            "private_keys".into(),
            "policy_backup".into(),
            "secret_never_log_fields".into(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> DiagnosticArchiveManifest {
        DiagnosticArchiveManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            created_at: 1_745_000_000_000,
            app_version: "0.1.0-preview".into(),
            redaction_mode: "default".into(),
            included_sections: vec![
                "manifest.json".into(),
                "health.json".into(),
                "logs.ndjson".into(),
                "audit_summary.json".into(),
                "troubleshooting.md".into(),
                "redaction_report.json".into(),
            ],
            log_entry_count: 42,
            audit_entry_count: 5,
            total_size_bytes_approx: 8192,
            contains_diagnostic_detail: false,
            no_backup_guarantee: DiagnosticArchiveManifest::NO_BACKUP_GUARANTEE.into(),
            build_commit: "abc1234".into(),
            build_profile: "debug".into(),
            build_target: "x86_64-pc-windows-msvc".into(),
        }
    }

    #[test]
    fn manifest_validates_ok_with_all_required_sections() {
        let m = sample_manifest();
        assert!(m.validate().is_ok());
    }

    #[test]
    fn manifest_validation_fails_when_mandatory_section_missing() {
        let mut m = sample_manifest();
        m.included_sections.retain(|s| s != "health.json");
        let err = m.validate().unwrap_err();
        assert!(err.contains("health.json"));
    }

    #[test]
    fn manifest_validation_fails_on_wrong_schema_version() {
        let mut m = sample_manifest();
        m.schema_version = 99;
        assert!(m.validate().is_err());
    }

    #[test]
    fn manifest_serializes_to_json() {
        let m = sample_manifest();
        let json = serde_json::to_string_pretty(&m).expect("serialize");
        let back: DiagnosticArchiveManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.log_entry_count, 42);
        assert_eq!(back.schema_version, MANIFEST_SCHEMA_VERSION);
    }

    #[test]
    fn no_backup_guarantee_is_non_empty() {
        assert!(!DiagnosticArchiveManifest::NO_BACKUP_GUARANTEE.is_empty());
        assert!(DiagnosticArchiveManifest::NO_BACKUP_GUARANTEE.contains("diagnostic"));
    }

    #[test]
    fn build_provenance_is_captured_and_round_trips() {
        // The build.rs-captured provenance is present (non-empty) and
        // survives a manifest serialise round-trip.
        assert!(!DiagnosticArchiveManifest::BUILD_PROFILE.is_empty());
        assert!(!DiagnosticArchiveManifest::BUILD_TARGET.is_empty());
        let m = sample_manifest();
        let json = serde_json::to_string(&m).expect("serialize");
        let back: DiagnosticArchiveManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.build_commit, "abc1234");
        assert_eq!(back.build_profile, "debug");
        // An older archive lacking the fields still deserializes (serde default).
        let legacy = r#"{"schema_version":1,"created_at":0,"app_version":"x",
            "redaction_mode":"default","included_sections":["health.json","logs.ndjson",
            "audit_summary.json","troubleshooting.md"],"log_entry_count":0,
            "audit_entry_count":0,"total_size_bytes_approx":0,
            "contains_diagnostic_detail":false,"no_backup_guarantee":"x"}"#;
        let m2: DiagnosticArchiveManifest =
            serde_json::from_str(legacy).expect("legacy manifest without build fields");
        assert_eq!(m2.build_commit, "");
    }

    #[test]
    fn redaction_report_always_hidden_fields() {
        let hidden = RedactionReport::always_hidden();
        assert!(hidden.contains(&"raw_db_files".to_string()));
        assert!(hidden.contains(&"private_keys".to_string()));
        assert!(hidden.contains(&"secret_never_log_fields".to_string()));
    }

    #[test]
    fn redaction_report_serializes() {
        let r = RedactionReport {
            redaction_mode: "default".into(),
            diagnostic_mode_active: false,
            hostnames_redacted: 10,
            ips_redacted: 5,
            paths_redacted: 3,
            excluded_sections: vec!["explain_samples.json".into()],
            always_hidden_fields: RedactionReport::always_hidden(),
        };
        let json = serde_json::to_string(&r).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(v["hostnames_redacted"], 10);
    }
}
