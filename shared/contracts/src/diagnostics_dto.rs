//! GUI/tray facade DTOs.
//!
//! Lives in `nrr-shared` so the IPC client and other cross-crate consumers
//! can reference the wire shapes without depending on `nrr-diagnostics`.
//! The original module path (`nrr_diagnostics::facade::dto`) survives as a
//! thin `pub use` re-export of this module; the converter
//! `audit_write_status_to_str` stays inside `nrr-diagnostics` because it
//! references the engine-internal `AuditWriteStatus`.
//!
//! All DTOs are serialisable so they can be sent over the IPC channel
//! between the service and GUI/tray.
//!
//! # Privacy guarantee
//!
//! DTOs never contain raw storage paths, SQLite file handles, or direct
//! access to service-owned files. All sensitive fields are pre-redacted
//! by the service before being placed into a DTO.

use serde::{Deserialize, Serialize};

use crate::ipc_payloads::SnapshotInterfacesResponse;

// ── DiagnosticsStatusDto ──────────────────────────────────────────────────────

/// Top-level health and status overview for the Diagnostics screen.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiagnosticsStatusDto {
    /// Whether service, logs, and audit are all operational.
    pub overall_healthy: bool,
    /// Service health card.
    pub service_health: ServiceHealthCard,
    /// Security status card (active alerts, audit trail health).
    pub security_status: SecurityStatusCard,
    /// Active security alerts (unresolved).
    pub active_alerts: Vec<SecurityAlertDto>,
    /// Cache health card.
    pub cache_health: CacheHealthCard,
    /// Log storage health card.
    pub log_health: LogHealthCard,
    /// Current diagnostic mode state.
    pub diagnostic_mode: DiagnosticModeStateDto,
    /// Whether this snapshot may be stale (service unreachable).
    pub stale: bool,
}

/// Health of the Windows background service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceHealthCard {
    /// `"running"`, `"degraded"`, `"unavailable"`
    pub state: String,
    /// Active policy revision id, if known.
    pub active_revision_id: Option<String>,
    /// Number of pending changes awaiting review.
    pub pending_changes: u32,
}

/// Security-relevant status card.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityStatusCard {
    /// Whether the audit chain integrity is verified.
    pub audit_chain_ok: bool,
    /// Number of active security alerts.
    pub active_alert_count: u32,
    /// Whether the audit NDJSON writer is healthy.
    pub audit_write_healthy: bool,
}

/// Cache health card.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheHealthCard {
    /// Approximate number of cached hostname→IP entries.
    pub entry_count: u64,
    /// Whether the cache is healthy (not corrupt, not in rebuild).
    pub healthy: bool,
    /// Whether a cache rebuild is in progress.
    pub rebuilding: bool,
}

/// Log storage health card.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogHealthCard {
    /// Whether the logs directory is writable.
    pub dir_writable: bool,
    /// Total size of operational log files in bytes.
    pub total_size_bytes: u64,
    /// Number of log files on disk.
    pub file_count: u32,
    /// Events dropped due to write failures since service start.
    pub dropped_count: u64,
    /// UTC ms of the last retention cleanup run.
    pub last_cleanup_at: Option<i64>,
}

/// Current diagnostic mode state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiagnosticModeStateDto {
    /// Whether diagnostic mode is currently active.
    pub active: bool,
    /// UTC ms when the session expires (if active).
    pub expires_at: Option<i64>,
    /// Remaining milliseconds until session expiry.
    pub remaining_ms: Option<i64>,
    /// Scope label of the active session.
    pub scope_key: Option<String>,
}

impl DiagnosticModeStateDto {
    pub fn inactive() -> Self {
        Self {
            active: false,
            expires_at: None,
            remaining_ms: None,
            scope_key: None,
        }
    }
}

// ── SecurityAlertDto ──────────────────────────────────────────────────────────

/// A security alert entry for the GUI alert list.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityAlertDto {
    pub alert_id: String,
    /// Stable kind string (e.g., `"tamper_alert_raised"`).
    pub kind: String,
    /// Lifecycle state: `"active"`, `"acknowledged"`, `"resolved"`, `"superseded"`.
    pub state: String,
    pub created_at: i64,
    pub updated_at: i64,
    /// Namespaced reason code (e.g., `"integrity.audit_chain_mismatch"`).
    pub reason_code: String,
    /// Name of the audit NDJSON file that raised the alert.
    pub raised_file: String,
    /// Whether this alert requires immediate user action.
    pub requires_action: bool,
}

// ── LogEntryDto ───────────────────────────────────────────────────────────────

/// A single operational log entry for the Logs screen.
///
/// All fields are pre-redacted per the active `RedactionMode`.
///
/// **Note:** there is a separate `LogEntryDto` in
/// [`crate::ipc_dto`](crate::ipc_dto) used by an older contract surface.
/// Both names coexist intentionally — they describe different
/// shapes (this one is the runtime log entry; the other is the
/// contract-level summary placeholder). Disambiguate via the module
/// path when both are in scope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEntryDto {
    pub event_id: String,
    pub created_at: i64,
    /// Level string: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`.
    pub level: String,
    /// Category string: `"service"`, `"decision"`, `"cache"`, etc.
    pub category: String,
    /// Reason code kind string (e.g., `"service.started"`).
    pub kind: String,
    /// Localization key for user-facing display.
    pub message_key: String,
    /// Whether additional payload detail is available (requires diagnostic mode).
    pub has_payload: bool,
    /// Brief correlation summary (decision id, revision id).
    pub correlation_summary: Vec<String>,
}

// ── AuditEntryDto ─────────────────────────────────────────────────────────────

/// A single audit trail entry for the Audit screen.
///
/// Payload detail is always omitted unless diagnostic permission is active.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntryDto {
    pub event_id: String,
    pub seq: u64,
    /// Audit event kind (e.g., `"revision_activated"`).
    pub kind: String,
    pub created_at: i64,
    /// Outcome: `"success"`, `"failure"`, `"blocked"`.
    pub result: String,
    pub reason_code: String,
    pub revision_id: Option<String>,
    /// Whether payload summary is available (audit always has this unless redacted).
    pub has_payload_summary: bool,
}

// ── Filter types ──────────────────────────────────────────────────────────────

/// Filter for `ListLogEntries` queries.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LogEntryFilter {
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    /// Minimum level (inclusive): `"info"`, `"warn"`, `"error"`.
    pub level_min: Option<String>,
    /// Category filter: `"service"`, `"decision"`, etc.
    pub category: Option<String>,
    /// Exact kind match.
    pub kind: Option<String>,
    /// Decision id to correlate by.
    pub decision_id: Option<String>,
    /// Revision id to correlate by.
    pub revision_id: Option<String>,
}

/// Filter for `ListAuditEntries` queries.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditEntryFilter {
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    /// Audit event kind (e.g., `"revision_activated"`).
    pub kind: Option<String>,
    /// Alert state filter: `"active"`, `"acknowledged"`, etc.
    pub alert_state: Option<String>,
    pub revision_id: Option<String>,
}

// ── Command request / response types ─────────────────────────────────────────

/// Request to acknowledge a security alert.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcknowledgeAlertRequest {
    pub alert_id: String,
    pub reason: Option<String>,
}

/// Request to set or clear diagnostic mode.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetDiagnosticModeRequest {
    pub enabled: bool,
    /// Duration in milliseconds (clamped to the engine-side
    /// `DiagnosticSession::MAX_DURATION_MS`). Ignored when `enabled = false`
    /// or when `until_restart = true`.
    pub duration_ms: Option<i64>,
    /// Scope label: `"all"`, `"decision_and_cache"`, `"process_and_adapter"`.
    pub scope: Option<String>,
    /// When `true`, the session has no expiry and stays active until the
    /// service restarts (the "until restart" TTL radio). Overrides
    /// `duration_ms`. Ignored when `enabled = false`.
    #[serde(default)]
    pub until_restart: bool,
}

/// Request to clear operational logs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClearLogsRequest {
    /// Whether to include exported archives in the cleanup.
    pub include_archives: bool,
    /// If `true`, report what would be deleted without deleting.
    pub dry_run: bool,
}

/// Summary result of a log clear operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClearLogsResult {
    pub files_deleted: u32,
    pub bytes_freed: u64,
    pub dry_run: bool,
}

// ── DiagnosticArchiveHealthEnrichmentDto ───────────────────────────────────────

/// Fields added to the diagnostic
/// archive's `health.json` beyond the live [`DiagnosticsStatusDto`] snapshot:
/// the caller's per-SID route behavior mode, the service-state SQLite schema
/// version, and the adapters snapshot at export time.
///
/// All fields are `Option` with `#[serde(default)]` so a pre-enrichment
/// archive — or any other caller that builds the archive input without
/// populating this DTO — still round-trips cleanly. A field that is
/// genuinely unavailable at the call site is left `None` rather than
/// fabricated; see `DiagnosticsExportArchiveHandler::handle` in
/// `nrr-service-runtime` for how each field is sourced.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DiagnosticArchiveHealthEnrichmentDto {
    /// Kebab-case slug of the caller's per-SID `BehaviorModeDto`
    /// (`"prefer-primary"`, `"prefer-secondary-when-available"`,
    /// `"strict-secondary-fail-closed"`). `None` when no per-SID route
    /// policy row exists yet for the caller, or the caller SID could not be
    /// resolved (e.g. a service-internal / test caller).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior_mode: Option<String>,
    /// `nrr_service_state.db` schema version (`MAX(schema_migrations.version)`)
    /// at export time. `None` when the state DB connection was unavailable at
    /// the archive call site (degraded boot).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_schema_version: Option<u32>,
    /// Adapters snapshot (primary/secondary candidates) at export time — the
    /// same wire shape `SnapshotInterfacesGet` returns. `None` when the
    /// adapters provider was unavailable at the archive call site.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapters_snapshot: Option<SnapshotInterfacesResponse>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_status_dto_serializes() {
        let dto = DiagnosticsStatusDto {
            overall_healthy: true,
            service_health: ServiceHealthCard {
                state: "running".into(),
                active_revision_id: Some("rev-001".into()),
                pending_changes: 0,
            },
            security_status: SecurityStatusCard {
                audit_chain_ok: true,
                active_alert_count: 0,
                audit_write_healthy: true,
            },
            active_alerts: Vec::new(),
            cache_health: CacheHealthCard {
                entry_count: 42,
                healthy: true,
                rebuilding: false,
            },
            log_health: LogHealthCard {
                dir_writable: true,
                total_size_bytes: 1024,
                file_count: 1,
                dropped_count: 0,
                last_cleanup_at: None,
            },
            diagnostic_mode: DiagnosticModeStateDto::inactive(),
            stale: false,
        };
        let json = serde_json::to_string(&dto).expect("serialize");
        let back: DiagnosticsStatusDto = serde_json::from_str(&json).expect("deserialize");
        assert!(back.overall_healthy);
        assert!(!back.stale);
    }

    #[test]
    fn log_entry_dto_serializes() {
        let dto = LogEntryDto {
            event_id: "evt-001".into(),
            created_at: 1_745_000_000_000,
            level: "info".into(),
            category: "service".into(),
            kind: "service.started".into(),
            message_key: "diag.service.started.summary".into(),
            has_payload: false,
            correlation_summary: Vec::new(),
        };
        let json = serde_json::to_string(&dto).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(v["level"], "info");
        assert_eq!(v["kind"], "service.started");
    }

    #[test]
    fn audit_entry_dto_serializes() {
        let dto = AuditEntryDto {
            event_id: "adt-001".into(),
            seq: 1,
            kind: "revision_activated".into(),
            created_at: 1_745_000_000_000,
            result: "success".into(),
            reason_code: "review.approved".into(),
            revision_id: Some("rev-001".into()),
            has_payload_summary: false,
        };
        let json = serde_json::to_string(&dto).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(v["kind"], "revision_activated");
        assert_eq!(v["seq"], 1);
    }

    #[test]
    fn security_alert_dto_serializes() {
        let dto = SecurityAlertDto {
            alert_id: "alt-001".into(),
            kind: "tamper_alert_raised".into(),
            state: "active".into(),
            created_at: 1_745_000_000_000,
            updated_at: 1_745_000_000_000,
            reason_code: "integrity.audit_chain_mismatch".into(),
            raised_file: "nrr_audit_20260423-1.ndjson".into(),
            requires_action: true,
        };
        let json = serde_json::to_string(&dto).expect("serialize");
        let back: SecurityAlertDto = serde_json::from_str(&json).expect("deserialize");
        assert!(back.requires_action);
    }
}
