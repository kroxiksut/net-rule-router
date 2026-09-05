//! Diagnostics facade trait.
//!
//! [`DiagnosticsFacade`] is the narrow read/write interface through which
//! GUI and tray interact with the diagnostics subsystem.
//!
//! # Ownership rules
//!
//! - GUI/tray **never** read service-owned storage paths directly.
//! - GUI/tray **never** delete files directly — all cleanup goes through
//!   `clear_logs`.
//! - Audit trail is **never** clearable by the GUI (the command is absent).
//! - `security_alerts` state is modified only via `acknowledge_alert`.
//!
//! # Permission matrix
//!
//! | Operation              | GUI | Tray | Service-internal | Dev/test |
//! |------------------------|-----|------|-----------------|----------|
//! | `get_status`           | ✓   | ✓    | ✓               | ✓        |
//! | `list_log_entries`     | ✓   | –    | ✓               | ✓        |
//! | `list_audit_entries`   | ✓   | –    | ✓               | ✓        |
//! | `acknowledge_alert`    | ✓   | ✓    | –               | ✓        |
//! | `set_diagnostic_mode`  | ✓   | ✓    | –               | ✓        |
//! | `clear_logs`           | ✓   | –    | –               | ✓        |

use crate::error::DiagnosticsResult;
use crate::explain::{ExplainQuery, ExplainResponse};
use crate::facade::dto::{
    AcknowledgeAlertRequest, AuditEntryDto, AuditEntryFilter, ClearLogsRequest, ClearLogsResult,
    DiagnosticsAudience, DiagnosticsStatusDto, LogEntryDto, LogEntryFilter, SecurityAlertDto,
    SetDiagnosticModeRequest,
};
use crate::facade::pagination::{PageCursor, PageResult, PaginationParams, MAX_PAGE_SIZE};
use crate::redaction::ExplainDetailLevel;

/// Read/write diagnostics facade for GUI and tray.
///
/// Implemented by `RealDiagnosticsFacade` (wired to the
/// service) and by [`super::mock::MockDiagnosticsFacade`] for scaffold.
pub trait DiagnosticsFacade: Send + Sync {
    /// Returns the top-level health and status overview.
    fn get_status(&self) -> DiagnosticsStatusDto;

    /// Returns a paginated list of operational log entries.
    /// `audience` decides whose lines come back — see
    /// [`Self::list_audit_entries`]. A principal-scoped read returns the
    /// caller's own lines plus the machine-level ones that belong to nobody
    /// (boot, adapters, service lifecycle).
    fn list_log_entries(
        &self,
        filter: &LogEntryFilter,
        pagination: &PaginationParams,
        audience: &DiagnosticsAudience,
    ) -> DiagnosticsResult<PageResult<LogEntryDto>>;

    /// Returns up to `max_entries` of the MOST RECENT operational log
    /// entries, newest-first. This is an internal bulk accessor for the
    /// diagnostic archive: unlike [`list_log_entries`] it is NOT bound by the
    /// wire [`MAX_PAGE_SIZE`] cap and deliberately selects the freshest
    /// entries (the archive builder then trims them to its byte budget).
    /// Selecting newest-first matters: a single oldest-first page would ship
    /// the STALEST lines and waste the byte budget.
    ///
    /// The default implementation pages through the oldest-first listing and
    /// keeps the newest `max_entries`; storage-backed impls should override it
    /// with a single scan for efficiency.
    ///
    /// [`list_log_entries`]: Self::list_log_entries
    /// [`MAX_PAGE_SIZE`]: crate::facade::pagination::MAX_PAGE_SIZE
    fn recent_log_entries(
        &self,
        filter: &LogEntryFilter,
        max_entries: usize,
        audience: &DiagnosticsAudience,
    ) -> DiagnosticsResult<Vec<LogEntryDto>> {
        if max_entries == 0 {
            return Ok(Vec::new());
        }
        // Page through the ascending (oldest-first) listing to the END, keeping
        // only the newest `max_entries` seen. Capping the page count bounded the
        // walk by how many entries were ASKED FOR, so a store holding more than
        // that returned its oldest window — the exact opposite of what this
        // method promises. The spin guard is a cursor that stops advancing,
        // which is the only way a well-behaved store can fail to terminate.
        let mut acc: Vec<LogEntryDto> = Vec::new();
        let mut cursor: Option<PageCursor> = None;
        loop {
            let page = self.list_log_entries(
                filter,
                &PaginationParams {
                    cursor: cursor.clone(),
                    page_size: MAX_PAGE_SIZE,
                },
                audience,
            )?;
            let next = page.next_cursor;
            acc.extend(page.items);
            if acc.len() > max_entries {
                let overflow = acc.len() - max_entries;
                acc.drain(0..overflow);
            }
            match next {
                Some(c) if Some(&c) != cursor.as_ref() => cursor = Some(c),
                _ => break,
            }
        }
        acc.reverse();
        Ok(acc)
    }

    /// Returns a paginated list of audit trail entries.
    /// `audience` decides WHOSE events come back and is set by the service from
    /// the connection, never from the request: the audit directory is closed to
    /// ordinary users on disk (`SYSTEM` + `Administrators` on Windows, `0700` on
    /// Linux), so an unscoped read here would hand out precisely what those
    /// permissions withhold. A principal-scoped read returns that principal's
    /// own events plus the ones the service performed on its own behalf.
    fn list_audit_entries(
        &self,
        filter: &AuditEntryFilter,
        pagination: &PaginationParams,
        audience: &DiagnosticsAudience,
    ) -> DiagnosticsResult<PageResult<AuditEntryDto>>;

    /// Raw operational-log NDJSON lines VERBATIM (payloads intact), newest
    /// first, within `max_bytes` and scoped to `audience`.
    ///
    /// The archive's `logs.ndjson` is a payload-stripped listing; a support
    /// bundle needs the real lines too. They used to be attached by the
    /// LAUNCHER reading the service's log directory off disk, which required
    /// that directory to be readable by every local account — and put every
    /// user's lines into one user's bundle. The service reads its own files and
    /// answers with what the requester may see.
    ///
    /// `from_ms` trims to a session window; `None` means the whole history.
    /// The default returns nothing, which is right for a facade with no log
    /// store behind it (preview/mock).
    fn recent_log_lines_raw(
        &self,
        _max_bytes: usize,
        _from_ms: Option<i64>,
        _audience: &DiagnosticsAudience,
    ) -> DiagnosticsResult<Vec<String>> {
        Ok(Vec::new())
    }

    /// Returns raw audit NDJSON lines VERBATIM — including the `prev_hash` /
    /// `event_hash` chain fields — for the newest events, up to `max_bytes`
    /// (a contiguous suffix of the chain so it stays independently verifiable).
    ///
    /// This backs the diagnostic archive's `audit_chain.ndjson`. Unlike
    /// [`list_audit_entries`], whose [`AuditEntryDto`] drops the chain, this
    /// preserves the exact bytes so a recipient can re-verify tamper-evidence.
    /// The raw lines carry `payload_summary_json`, so the CALLER gates this to
    /// the Diagnostics / DeveloperLocal redaction tiers; the default
    /// implementation returns an empty vec, so only the storage-backed
    /// production facade actually ships the chain.
    ///
    /// [`list_audit_entries`]: Self::list_audit_entries
    fn recent_audit_chain_lines(&self, max_bytes: usize) -> DiagnosticsResult<Vec<String>> {
        let _ = max_bytes;
        Ok(Vec::new())
    }

    /// Returns all currently active (unresolved) security alerts.
    fn list_active_alerts(&self) -> DiagnosticsResult<Vec<SecurityAlertDto>>;

    /// Acknowledges a security alert.  Creates a new audit event.
    fn acknowledge_alert(&self, req: &AcknowledgeAlertRequest) -> DiagnosticsResult<()>;

    /// Enables or disables explicit diagnostic mode.
    fn set_diagnostic_mode(&self, req: &SetDiagnosticModeRequest) -> DiagnosticsResult<()>;

    /// Clears operational logs (never audit trail).
    /// If `dry_run = true`, returns what would be deleted without deleting.
    fn clear_logs(&self, req: &ClearLogsRequest) -> DiagnosticsResult<ClearLogsResult>;

    /// Returns an explain response for the given query.
    ///
    /// `caller_sid` is the OS SID of the requesting user; the synthetic
    /// probe uses it to load that user's per-SID `behavior_mode` so the
    /// default route an unmatched sample reports matches what the service
    /// would actually enforce. Empty string
    /// ⇒ fall back to `PreferPrimary`. Implementations with no per-SID
    /// policy (mocks/historical) may ignore it.
    fn get_explain(
        &self,
        query: &ExplainQuery,
        level: ExplainDetailLevel,
        caller_sid: &str,
    ) -> DiagnosticsResult<ExplainResponse>;
}
