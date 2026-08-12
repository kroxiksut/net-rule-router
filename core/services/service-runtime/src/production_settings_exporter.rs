//! production [`SettingsExportSource`] for the
//! `SettingsExportFull` read-only IPC op.
//!
//! Emits YAML conforming to docs/en/rules-file-format.md Settings Export Format. Hand-rolled emitter (no
//! `serde_yaml` dependency) keeps the wire-format SSOT explicit and
//! avoids an extra crate with an unmaintained advisory.
//!
//! ## Service-owned vs client-supplied data
//!
//! Service owns: adapter bindings (per-SID via `RouteBindingsRepository`),
//! route behavior mode.
//!
//! Client supplies in the request: rules-file paths on disk
//! (`UiPreferences::last_saved_path_<role>`).
//!
//! ## Future YAML enhancements
//!
//! `file_change_behavior` and `include_child_processes` from docs/en/rules-file-format.md Settings Export Format are GUI preferences that may migrate to per-SID service storage.
//! Currently emitted YAML does not include those keys. Forward-compat:
//! readers MUST tolerate missing keys.

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use nrr_storage::route_bindings::{BehaviorMode, RouteBindingsRepository, RoutePolicyRecord};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// Schema version of the `nrr_settings_export` YAML document.
/// Mirrors docs/en/rules-file-format.md Settings Export Format (`version: 1`).
pub const SETTINGS_EXPORT_YAML_VERSION: u32 = 1;

/// Returns a UTF-8 YAML blob and its SHA-256 hex for the caller's
/// settings snapshot.
pub trait SettingsExportSource: Send + Sync {
    fn export_settings(
        &self,
        sid: &str,
        rules_file_path_primary: Option<&str>,
        rules_file_path_secondary: Option<&str>,
        exported_at_iso: &str,
    ) -> Result<SettingsExportOutput, SettingsExportError>;
}

/// Output of [`SettingsExportSource::export_settings`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsExportOutput {
    /// Raw UTF-8 YAML bytes. Caller base64-wraps for wire.
    pub yaml_bytes_utf8: String,
    /// SHA-256 hex (64 chars) of `yaml_bytes_utf8`.
    pub content_hash_hex: String,
}

/// Why an export could not be produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingsExportError {
    /// Caller SID is empty (transport layer didn't extract it).
    EmptySid,
    /// State DB mutex is poisoned.
    LockPoisoned,
    /// Storage layer returned an error reading bindings.
    StorageError(String),
}

impl std::fmt::Display for SettingsExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySid => f.write_str("caller SID is empty"),
            Self::LockPoisoned => f.write_str("state DB mutex poisoned"),
            Self::StorageError(e) => write!(f, "storage error: {e}"),
        }
    }
}

impl std::error::Error for SettingsExportError {}

/// Production [`SettingsExportSource`] backed by `nrr_service_state.db`.
pub struct ProductionSettingsExporter {
    conn: Arc<Mutex<Connection>>,
}

impl ProductionSettingsExporter {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

impl SettingsExportSource for ProductionSettingsExporter {
    fn export_settings(
        &self,
        sid: &str,
        rules_file_path_primary: Option<&str>,
        rules_file_path_secondary: Option<&str>,
        exported_at_iso: &str,
    ) -> Result<SettingsExportOutput, SettingsExportError> {
        if sid.is_empty() {
            return Err(SettingsExportError::EmptySid);
        }
        let guard = self
            .conn
            .lock()
            .map_err(|_| SettingsExportError::LockPoisoned)?;
        let repo = RouteBindingsRepository::new(&guard);
        let record = repo
            .load_for_sid(sid)
            .map_err(|e| SettingsExportError::StorageError(e.to_string()))?;
        drop(guard);

        let yaml_bytes_utf8 = emit_settings_yaml(
            &record,
            rules_file_path_primary,
            rules_file_path_secondary,
            exported_at_iso,
        );
        let mut hasher = Sha256::new();
        hasher.update(yaml_bytes_utf8.as_bytes());
        let content_hash_hex = format!("{:x}", hasher.finalize());
        Ok(SettingsExportOutput {
            yaml_bytes_utf8,
            content_hash_hex,
        })
    }
}

/// Base64-wraps the YAML bytes with the standard alphabet (RFC 4648,
/// padded). Mirrors the preset exporter's helper for symmetry.
pub fn encode_yaml_bytes_b64(yaml_bytes_utf8: &str) -> String {
    BASE64_STANDARD.encode(yaml_bytes_utf8.as_bytes())
}

/// Formats epoch-seconds as `YYYY-MM-DDTHH:MM:SSZ` (ISO 8601 UTC).
///
/// Implementation mirrors the Howard Hinnant civil-calendar arithmetic
/// used in `diagnostics_handlers::format_timestamp_for_filename` — kept
/// inline here so the exporter doesn't pull in `chrono` for one
/// formatter (workspace policy on optional deps).
pub fn format_iso_utc(now_secs: i64) -> String {
    let days_since_epoch = now_secs.div_euclid(86_400);
    let secs_of_day = now_secs.rem_euclid(86_400);
    let hour = (secs_of_day / 3600) as u32;
    let minute = ((secs_of_day % 3600) / 60) as u32;
    let second = (secs_of_day % 60) as u32;
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe as i64 - (365 * yoe as i64 + yoe as i64 / 4 - yoe as i64 / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, m, d, hour, minute, second
    )
}

// ── YAML emitter ─────────────────────────────────────────────────────────────

fn emit_settings_yaml(
    record: &RoutePolicyRecord,
    rules_file_path_primary: Option<&str>,
    rules_file_path_secondary: Option<&str>,
    exported_at_iso: &str,
) -> String {
    let mut out = String::new();
    out.push_str("nrr_settings_export:\n");
    out.push_str("  version: ");
    out.push_str(&SETTINGS_EXPORT_YAML_VERSION.to_string());
    out.push('\n');
    out.push_str("  exported_at: ");
    out.push_str(&yaml_quote(exported_at_iso));
    out.push('\n');
    out.push('\n');

    // adapters: block — service-owned per-SID bindings.
    out.push_str("  adapters:\n");
    emit_adapter(&mut out, "primary", record.primary.as_ref());
    emit_adapter(&mut out, "secondary", record.secondary.as_ref());
    out.push('\n');

    // rules_files: block — client-supplied paths.
    out.push_str("  rules_files:\n");
    out.push_str("    primary: ");
    out.push_str(&yaml_quote(rules_file_path_primary.unwrap_or("")));
    out.push('\n');
    out.push_str("    secondary: ");
    out.push_str(&yaml_quote(rules_file_path_secondary.unwrap_or("")));
    out.push('\n');
    out.push('\n');

    // behavior: block — service-owned route mode.
    // will add file_change_behavior + include_child_processes.
    out.push_str("  behavior:\n");
    out.push_str("    route_mode: ");
    out.push_str(&yaml_quote(behavior_slug(record.mode)));
    out.push('\n');

    out
}

fn emit_adapter(
    out: &mut String,
    role: &str,
    binding: Option<&nrr_storage::route_bindings::RouteBindingRecord>,
) {
    out.push_str("    ");
    out.push_str(role);
    out.push_str(":\n");
    match binding {
        Some(b) => {
            out.push_str("      system_id: ");
            out.push_str(&yaml_quote(&b.stable_id));
            out.push('\n');
            out.push_str("      user_label: ");
            out.push_str(&yaml_quote(&b.display_name));
            out.push('\n');
            out.push_str("      user_confirmed: ");
            out.push_str(if b.user_confirmed { "true" } else { "false" });
            out.push('\n');
        }
        None => {
            // Absent binding — emit explicit null/false placeholders so
            // readers can distinguish "no binding for this role" from
            // "field missing because key not yet defined".
            out.push_str("      system_id: \"\"\n");
            out.push_str("      user_label: \"\"\n");
            out.push_str("      user_confirmed: false\n");
        }
    }
}

const fn behavior_slug(mode: BehaviorMode) -> &'static str {
    match mode {
        BehaviorMode::PreferPrimary => "prefer-primary",
        BehaviorMode::PreferSecondaryWhenAvailable => "prefer-secondary-when-available",
        BehaviorMode::StrictSecondaryFailClosed => "strict-secondary-fail-closed",
    }
}

/// Emits a double-quoted YAML scalar with `\` and `"` escaped per the
/// YAML 1.2 spec, plus the control characters required for safety.
fn yaml_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\x{:02X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use nrr_storage::repository::MigrationRunner;
    use nrr_storage::route_bindings::{BindingSource, RouteBindingRecord};
    use nrr_storage::SqliteMigrationRunner;

    fn open_state_db_in_memory() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().expect("in-memory state DB");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("state migrations");
        Arc::new(Mutex::new(runner.into_connection()))
    }

    fn seed_bindings(conn: &Arc<Mutex<Connection>>, sid: &str, record: &RoutePolicyRecord) {
        let guard = conn.lock().unwrap();
        let repo = RouteBindingsRepository::new(&guard);
        repo.update_for_sid(sid, record, 1).expect("seed bindings");
    }

    #[test]
    fn yaml_quote_escapes_backslashes_and_quotes() {
        assert_eq!(
            yaml_quote(r#"C:\path\with"quote"#),
            r#""C:\\path\\with\"quote""#
        );
    }

    #[test]
    fn yaml_quote_escapes_newlines_and_tabs() {
        assert_eq!(yaml_quote("a\nb\tc\r"), r#""a\nb\tc\r""#);
    }

    #[test]
    fn yaml_quote_passes_unicode_through_verbatim() {
        // Unicode is allowed in YAML double-quoted scalars; only ASCII
        // control characters need escaping.
        assert_eq!(yaml_quote("Корп. сеть"), r#""Корп. сеть""#);
    }

    #[test]
    fn export_with_empty_db_emits_skeleton_with_empty_bindings() {
        let conn = open_state_db_in_memory();
        let exporter = ProductionSettingsExporter::new(Arc::clone(&conn));
        let out = exporter
            .export_settings("S-1-5-21-test", None, None, "2026-05-20T12:00:00Z")
            .expect("export");
        let yaml = &out.yaml_bytes_utf8;
        assert!(yaml.starts_with("nrr_settings_export:\n"));
        assert!(yaml.contains("version: 1\n"));
        assert!(yaml.contains("exported_at: \"2026-05-20T12:00:00Z\"\n"));
        assert!(yaml.contains("primary:\n      system_id: \"\"\n"));
        assert!(yaml.contains("route_mode: \"prefer-primary\"\n"));
        assert_eq!(out.content_hash_hex.len(), 64);
    }

    #[test]
    fn export_emits_adapter_bindings_for_each_role() {
        let conn = open_state_db_in_memory();
        let record = RoutePolicyRecord {
            primary: Some(RouteBindingRecord {
                stable_id: "mac=AA:BB:CC:DD:EE:FF;ifindex=3".to_string(),
                display_name: "Main network".to_string(),
                user_confirmed: true,
                known_stable_ids: vec![],
            }),
            secondary: Some(RouteBindingRecord {
                stable_id: "mac=11:22:33:44:55:66;ifindex=7".to_string(),
                display_name: "VPN".to_string(),
                user_confirmed: false,
                known_stable_ids: vec![],
            }),
            mode: BehaviorMode::PreferSecondaryWhenAvailable,
            block_secondary_when_unavailable: false,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            kill_switch_enabled: false,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
            mode_a_coverage_strategy: nrr_domain::mode_a_coverage::ModeACoverageStrategy::default(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: false,
            auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
            auto_rules_eager_delivery_names: false,
            binding_source: BindingSource::UserAssigned,
        };
        seed_bindings(&conn, "S-1-5-21-test", &record);

        let exporter = ProductionSettingsExporter::new(Arc::clone(&conn));
        let out = exporter
            .export_settings(
                "S-1-5-21-test",
                Some(r"C:\Users\u\rules_primary.txt"),
                Some(r"C:\Users\u\rules_secondary.txt"),
                "2026-05-20T12:00:00Z",
            )
            .expect("export");
        let yaml = &out.yaml_bytes_utf8;
        assert!(
            yaml.contains("system_id: \"mac=AA:BB:CC:DD:EE:FF;ifindex=3\""),
            "primary system_id missing; got:\n{yaml}"
        );
        assert!(yaml.contains("user_label: \"Main network\""));
        assert!(yaml.contains("primary:\n      system_id: \"mac=AA:BB:CC:DD:EE:FF"),);
        assert!(yaml.contains("user_confirmed: true\n"));
        assert!(
            yaml.contains("system_id: \"mac=11:22:33:44:55:66;ifindex=7\""),
            "secondary system_id missing; got:\n{yaml}"
        );
        assert!(yaml.contains("user_label: \"VPN\""));
        assert!(yaml.contains("user_confirmed: false\n"));
        assert!(
            yaml.contains("rules_files:\n    primary: \"C:\\\\Users\\\\u\\\\rules_primary.txt\""),
            "primary path missing; got:\n{yaml}"
        );
        assert!(
            yaml.contains("route_mode: \"prefer-secondary-when-available\""),
            "wrong route_mode; got:\n{yaml}"
        );
    }

    #[test]
    fn export_rejects_empty_sid() {
        let conn = open_state_db_in_memory();
        let exporter = ProductionSettingsExporter::new(Arc::clone(&conn));
        let err = exporter
            .export_settings("", None, None, "2026-05-20T12:00:00Z")
            .expect_err("empty SID must be rejected");
        assert_eq!(err, SettingsExportError::EmptySid);
    }

    #[test]
    fn export_omits_file_change_behavior_per_16_8_2_landmine() {
        // Forward-compat assertion: the YAML must NOT contain placeholder
        // keys (so future readers
        // unambiguously detect "field absent" rather than seeing a
        // wrong default).
        let conn = open_state_db_in_memory();
        let exporter = ProductionSettingsExporter::new(Arc::clone(&conn));
        let out = exporter
            .export_settings("S-1-5-21-test", None, None, "2026-05-20T12:00:00Z")
            .expect("export");
        assert!(!out.yaml_bytes_utf8.contains("file_change_behavior"));
        assert!(!out.yaml_bytes_utf8.contains("include_child_processes"));
    }

    #[test]
    fn export_hash_is_deterministic() {
        let conn = open_state_db_in_memory();
        let exporter = ProductionSettingsExporter::new(Arc::clone(&conn));
        let a = exporter
            .export_settings("S-1-5-21-test", None, None, "2026-05-20T12:00:00Z")
            .expect("a");
        let b = exporter
            .export_settings("S-1-5-21-test", None, None, "2026-05-20T12:00:00Z")
            .expect("b");
        assert_eq!(a, b);
    }

    #[test]
    fn encode_yaml_bytes_b64_round_trips() {
        let original = "nrr_settings_export:\n  version: 1\n";
        let encoded = encode_yaml_bytes_b64(original);
        let decoded = BASE64_STANDARD.decode(encoded.as_bytes()).expect("decode");
        assert_eq!(String::from_utf8(decoded).unwrap(), original);
    }

    // ── format_iso_utc ───────────────────────────────────────────────────────

    #[test]
    fn format_iso_utc_renders_epoch() {
        assert_eq!(format_iso_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_iso_utc_renders_known_moment() {
        // 1_700_000_000 seconds since epoch = 2023-11-14T22:13:20Z.
        assert_eq!(format_iso_utc(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn format_iso_utc_handles_leap_year() {
        // 2024-02-29T12:00:00Z is exactly 1_709_208_000 seconds.
        assert_eq!(format_iso_utc(1_709_208_000), "2024-02-29T12:00:00Z");
    }
}
