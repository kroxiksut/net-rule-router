use super::*;

// ── Migration status ──────────────────────────────────────────────────────

/// Stable migration ids known to the service. Each id has independent
/// per-SID lifecycle in `migration_state`.
pub const MIGRATION_ID_LEGACY_PREFERENCES_V1: &str = "legacy_preferences_v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MigrationStatusGetRequest {
    pub migration_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MigrationStatusGetResponse {
    pub completed: bool,
    /// Epoch seconds at completion. `None` when `completed = false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<u64>,
    /// Free-form JSON detail recorded at mark time (e.g. count of
    /// migrated fields). `None` when `completed = false` or no detail
    /// was supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_json: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MigrationMarkCompleteRequest {
    pub migration_id: String,
    /// Free-form JSON the GUI may attach (e.g.
    /// `{"migrated_fields_count": 7}`). Audit will quote it verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail_json: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MigrationMarkCompleteResponse {
    /// `true` when this call performed the write; `false` when the row
    /// already existed (idempotent path). The GUI treats both as success.
    pub recorded: bool,
    pub completed_at: u64,
}

// ── Retention settings ────────────────────────────────────────────────────

/// Singleton record describing how long superseded / rejected /
/// rolled-back revisions are retained before pruning. Field shape is
/// 1:1 with `nrr-storage::retention_settings::RetentionSettings`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RetentionSettingsDto {
    pub superseded_days: u32,
    pub superseded_count_cap: u32,
    pub rejected_days: u32,
    pub rolledback_days: u32,
    pub rolledback_count_cap: u32,
    pub pin_lkg: bool,
    /// Epoch seconds. `None` until the first cleanup pass writes a row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_cleanup_at: Option<u64>,
    pub updated_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RetentionSettingsGetRequest {}

pub type RetentionSettingsGetResponse = RetentionSettingsDto;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RetentionSettingsSetRequest {
    pub superseded_days: u32,
    pub superseded_count_cap: u32,
    pub rejected_days: u32,
    pub rolledback_days: u32,
    pub rolledback_count_cap: u32,
    pub pin_lkg: bool,
}

pub type RetentionSettingsSetResponse = RetentionSettingsDto;

// ── Log/audit retention config ───────────────────────────────────────────────

/// Singleton record for operational-log + audit NDJSON retention. Field shape
/// is 1:1 with `nrr-storage::log_retention_config::LogRetentionConfig`. Sizes
/// are BYTES on the wire; `0` = age-only (no size cap).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LogRetentionConfigDto {
    pub log_max_age_days: u32,
    pub log_max_size_bytes: u64,
    pub audit_max_age_days: u32,
    pub audit_max_size_bytes: u64,
    pub updated_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct LogRetentionConfigGetRequest {}

pub type LogRetentionConfigGetResponse = LogRetentionConfigDto;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LogRetentionConfigSetRequest {
    pub log_max_age_days: u32,
    pub log_max_size_bytes: u64,
    pub audit_max_age_days: u32,
    pub audit_max_size_bytes: u64,
}

pub type LogRetentionConfigSetResponse = LogRetentionConfigDto;

// ── Apply failure policy ──────────────────────────────────────────────────

/// Slug values recognised by the service: `"all-or-nothing"`,
/// `"best-effort"`, `"pre-flight-then-all-or-nothing"`. The GUI MUST
/// echo back one of these — the service rejects unknown slugs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ApplyFailurePolicyDto {
    pub policy: String,
    /// Epoch seconds of the last write.
    pub updated_at: u64,
    /// SID of the principal who last set the policy. `None` for the
    /// default row materialised on first read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_by_sid: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ApplyFailurePolicyGetRequest {}

pub type ApplyFailurePolicyGetResponse = ApplyFailurePolicyDto;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ApplyFailurePolicySetRequest {
    pub policy: String,
}

pub type ApplyFailurePolicySetResponse = ApplyFailurePolicyDto;

// ── Storage usage ─────────────────────────────────────────────────────────

/// On-disk byte counts for service-owned storage, sampled at request
/// time. Counts include only files currently present; no rolling
/// average. `None` means the file is absent or unreadable — the GUI
/// renders that as "Unavailable".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct StorageUsageDto {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_db_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_db_bytes: Option<u64>,
    pub operational_logs_bytes: u64,
    pub audit_logs_bytes: u64,
    pub total_bytes: u64,
    /// Epoch seconds when the scan was performed.
    pub scanned_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct StorageUsageGetRequest {}

pub type StorageUsageGetResponse = StorageUsageDto;

// ── Routing pause ─────────────────────────────────────────────────────────

/// Per-SID routing-pause record. `paused = false` is returned for SIDs
/// that have never been paused (no row in `routing_pause_state`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RoutingPauseDto {
    pub sid: String,
    pub paused: bool,
    /// Epoch seconds of the most recent pause transition. `None` when
    /// `paused = false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_reason: Option<String>,
    pub updated_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RoutingPauseGetRequest {}

pub type RoutingPauseGetResponse = RoutingPauseDto;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RoutingPauseToggleRequest {
    pub paused: bool,
    /// Free-form annotation persisted alongside the pause row. Audit
    /// quotes it verbatim. `None` clears the previous reason on resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub type RoutingPauseToggleResponse = RoutingPauseDto;

// ── Autostart ─────────────────────────────────────────────────────────────

/// Autostart status combining the user's stored intent (`enabled`)
/// with the most recent observation of `HKCU\…\Run`
/// (`last_known_state`). Slug values for `last_known_state`:
/// `"enabled" | "disabled" | "overridden-externally" | "absent"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutostartDto {
    pub enabled: bool,
    pub last_known_state: String,
    /// When `last_known_state == "overridden-externally"` carries the
    /// foreign registry value so the GUI can surface it for the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden_value: Option<String>,
    pub updated_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct AutostartGetRequest {}

pub type AutostartGetResponse = AutostartDto;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutostartToggleRequest {
    pub enabled: bool,
}

pub type AutostartToggleResponse = AutostartDto;
