//! Production [`SettingsExportSource`] for the read-only `SettingsExportFull`
//! op: YAML per docs/en/rules-file-format.md §2, hand-rolled so the format
//! stays explicit and no YAML crate is pulled in.
//!
//! The service supplies the caller's bindings, route mode, leak protection
//! and the rules in force for them, written by the rules-file writer as
//! block scalars; the client supplies the bound rules-file paths and the
//! sections of those files this build does not apply (the service keeps
//! neither). `provisioning::bundle` reads this shape back. Nothing here writes.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use nrr_domain::rules_file::{HostPlatform, PassthroughSection, RulesFileSection};
use nrr_shared::ipc_payloads::SettingsExportFullRequest;
use nrr_shared::RouteRole;
use nrr_storage::route_bindings::{RouteBindingsRepository, RoutePolicyRecord};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::production_preset_exporter::{
    default_host_app_section, rules_file_text, rules_in_force, PresetExportError,
};

/// Schema version of the `nrr_settings_export` YAML document. Version 2 added
/// the `rules:` section; the provisioning reader takes 1 and 2.
pub const SETTINGS_EXPORT_YAML_VERSION: u32 = 2;

/// Returns a UTF-8 YAML blob and its SHA-256 hex for the caller's
/// settings snapshot.
pub trait SettingsExportSource: Send + Sync {
    /// `client` carries what only the caller knows: the bound rules-file
    /// paths and the sections of those files this build does not apply.
    fn export_settings(
        &self,
        sid: &str,
        client: &SettingsExportFullRequest,
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
    /// Storage layer returned an error reading bindings or rules.
    StorageError(String),
    /// The stored rules could not be decoded.
    DecodeError(String),
}

impl std::fmt::Display for SettingsExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySid => f.write_str("caller SID is empty"),
            Self::LockPoisoned => f.write_str("state DB mutex poisoned"),
            Self::StorageError(e) => write!(f, "storage error: {e}"),
            Self::DecodeError(e) => write!(f, "decode error: {e}"),
        }
    }
}

impl From<PresetExportError> for SettingsExportError {
    fn from(e: PresetExportError) -> Self {
        match e {
            PresetExportError::LockPoisoned => Self::LockPoisoned,
            PresetExportError::StorageError(e) => Self::StorageError(e),
            PresetExportError::DecodeError(e) => Self::DecodeError(e),
            PresetExportError::NoActiveRevision => {
                Self::StorageError("no active revision".to_owned())
            }
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
        client: &SettingsExportFullRequest,
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
        let section = default_host_app_section();
        let rules = rules_in_force(&guard, sid, section)?;
        drop(guard);
        let platform = section.app_platform().unwrap_or(HostPlatform::compiled());
        let [primary, secondary] = [
            (RouteRole::Primary, &client.passthrough_sections_primary),
            (RouteRole::Secondary, &client.passthrough_sections_secondary),
        ]
        .map(|(route, sections)| {
            let carried = not_applied_here(sections, platform);
            if rules.is_none() && carried.is_empty() {
                return String::new();
            }
            rules_file_text(rules.as_ref(), route, section, &carried, None)
        });

        let yaml_bytes_utf8 = emit_settings_yaml(
            &record,
            client.rules_file_path_primary.as_deref(),
            client.rules_file_path_secondary.as_deref(),
            [&primary, &secondary],
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

/// The caller's sections this build does not apply here. A section it does
/// apply is written from the rules in force; the caller's copy, or a header
/// smuggled inside a body, would come back as applied rules on install.
fn not_applied_here(
    sections: &BTreeMap<String, String>,
    platform: HostPlatform,
) -> Vec<PassthroughSection> {
    sections
        .iter()
        .filter(|(name, body)| {
            !RulesFileSection::from_name(name).is_some_and(|known| known.is_active_on(platform))
                && !body
                    .lines()
                    .any(|line| line.trim_start().starts_with("---"))
        })
        .map(|(name, body)| PassthroughSection {
            name: name.clone(),
            body: body.clone(),
        })
        .collect()
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
    [rules_primary, rules_secondary]: [&str; 2],
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

    out.push_str("  rules:\n");
    emit_rules_text(&mut out, "primary", rules_primary);
    emit_rules_text(&mut out, "secondary", rules_secondary);
    out.push('\n');

    // behavior: block — service-owned route mode and leak protection.
    out.push_str("  behavior:\n");
    out.push_str("    route_mode: ");
    out.push_str(&yaml_quote(record.mode.slug()));
    out.push('\n');
    out.push_str("    leak_protection: ");
    out.push_str(&yaml_quote(record.leak_protection.as_slug()));
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

/// A rules file as a literal block scalar, so the text stays the one rules
/// format; no rules is `""`. The writer never starts a file with a space,
/// so the indentation needs no indicator.
fn emit_rules_text(out: &mut String, role: &str, text: &str) {
    out.push_str("    ");
    out.push_str(role);
    if text.is_empty() {
        out.push_str(": \"\"\n");
        return;
    }
    out.push_str(": |\n");
    for line in text.lines() {
        if !line.is_empty() {
            out.push_str("      ");
            out.push_str(line);
        }
        out.push('\n');
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
    use nrr_storage::route_bindings::{BehaviorMode, BindingSource, RouteBindingRecord};
    use nrr_storage::SqliteMigrationRunner;

    fn open_state_db_in_memory() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().expect("in-memory state DB");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("state migrations");
        Arc::new(Mutex::new(runner.into_connection()))
    }

    fn no_client() -> SettingsExportFullRequest {
        SettingsExportFullRequest::default()
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
            .export_settings("S-1-5-21-test", &no_client(), "2026-05-20T12:00:00Z")
            .expect("export");
        let yaml = &out.yaml_bytes_utf8;
        assert!(yaml.starts_with("nrr_settings_export:\n"));
        assert!(yaml.contains("version: 2\n"));
        assert!(yaml.contains("exported_at: \"2026-05-20T12:00:00Z\"\n"));
        assert!(yaml.contains("primary:\n      system_id: \"\"\n"));
        assert!(yaml.contains("route_mode: \"prefer-primary\"\n"));
        // A user who never chose has the default level, and the export says so.
        assert!(yaml.contains("leak_protection: \"sites\"\n"));
        // The hash crosses IPC: fixed-width lowercase hex of the YAML bytes.
        let expected: String = Sha256::digest(yaml.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(out.content_hash_hex, expected);
    }

    /// The hash crosses IPC and is compared by the importer: a hash-crate
    /// upgrade that changed its spelling must fail here, not in the field.
    #[test]
    fn the_empty_export_hash_is_pinned() {
        let conn = open_state_db_in_memory();
        let exporter = ProductionSettingsExporter::new(Arc::clone(&conn));
        let out = exporter
            .export_settings("S-1-5-21-test", &no_client(), "2026-05-20T12:00:00Z")
            .expect("export");
        assert_eq!(
            out.content_hash_hex,
            "b48634613099682bcf434ac4a5ee830964eb357d25cc980aa836aa84daa62c5f"
        );
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
            leak_protection: nrr_domain::LeakProtection::Everything,
            kill_switch_protocols: 0x7F,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
            doh_lockdown_auto: true,
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: true,
            auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
            auto_rules_eager_delivery_names: false,
            primary_probe_auto: false,
            primary_probe_timeout_ms: 1500,
            primary_probe_max_targets: 8,
            primary_probe_repeat_secs: 300,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
            short_name_completion: false,
            short_name_suffix: String::new(),
            app_rules_take_all_addresses: false,
            forwarded_outage: String::new(),
            external_address_auto_check: false,
            binding_source: BindingSource::UserAssigned,
        };
        seed_bindings(&conn, "S-1-5-21-test", &record);

        let exporter = ProductionSettingsExporter::new(Arc::clone(&conn));
        let out = exporter
            .export_settings(
                "S-1-5-21-test",
                &SettingsExportFullRequest {
                    rules_file_path_primary: Some(r"C:\Users\u\rules_primary.txt".to_owned()),
                    rules_file_path_secondary: Some(r"C:\Users\u\rules_secondary.txt".to_owned()),
                    ..SettingsExportFullRequest::default()
                },
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
        assert!(
            yaml.contains("leak_protection: \"everything\""),
            "wrong leak_protection; got:\n{yaml}"
        );
    }

    #[test]
    fn export_rejects_empty_sid() {
        let conn = open_state_db_in_memory();
        let exporter = ProductionSettingsExporter::new(Arc::clone(&conn));
        let err = exporter
            .export_settings("", &no_client(), "2026-05-20T12:00:00Z")
            .expect_err("empty SID must be rejected");
        assert_eq!(err, SettingsExportError::EmptySid);
    }

    #[test]
    fn export_omits_file_change_behavior() {
        // No placeholder keys: a reader must see "absent", not a wrong default.
        let conn = open_state_db_in_memory();
        let exporter = ProductionSettingsExporter::new(Arc::clone(&conn));
        let out = exporter
            .export_settings("S-1-5-21-test", &no_client(), "2026-05-20T12:00:00Z")
            .expect("export");
        assert!(!out.yaml_bytes_utf8.contains("file_change_behavior"));
        assert!(!out.yaml_bytes_utf8.contains("include_child_processes"));
    }

    #[test]
    fn export_hash_is_deterministic() {
        let conn = open_state_db_in_memory();
        let exporter = ProductionSettingsExporter::new(Arc::clone(&conn));
        let a = exporter
            .export_settings("S-1-5-21-test", &no_client(), "2026-05-20T12:00:00Z")
            .expect("a");
        let b = exporter
            .export_settings("S-1-5-21-test", &no_client(), "2026-05-20T12:00:00Z")
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
