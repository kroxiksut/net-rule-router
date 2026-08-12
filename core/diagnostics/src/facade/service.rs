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
    DiagnosticsStatusDto, LogEntryDto, LogEntryFilter, SecurityAlertDto, SetDiagnosticModeRequest,
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
    fn list_log_entries(
        &self,
        filter: &LogEntryFilter,
        pagination: &PaginationParams,
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
    ) -> DiagnosticsResult<Vec<LogEntryDto>> {
        if max_entries == 0 {
            return Ok(Vec::new());
        }
        // Page through the ascending (oldest-first) listing, retaining only the
        // newest `max_entries` seen so far. Page count is bounded so a
        // pathological store cannot spin (production overrides this anyway).
        let max_pages = max_entries / MAX_PAGE_SIZE as usize + 2;
        let mut acc: Vec<LogEntryDto> = Vec::new();
        let mut cursor: Option<PageCursor> = None;
        for _ in 0..max_pages {
            let page = self.list_log_entries(
                filter,
                &PaginationParams {
                    cursor,
                    page_size: MAX_PAGE_SIZE,
                },
            )?;
            let next = page.next_cursor;
            acc.extend(page.items);
            if acc.len() > max_entries {
                let overflow = acc.len() - max_entries;
                acc.drain(0..overflow);
            }
            match next {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        acc.reverse();
        Ok(acc)
    }

    /// Returns a paginated list of audit trail entries.
    fn list_audit_entries(
        &self,
        filter: &AuditEntryFilter,
        pagination: &PaginationParams,
    ) -> DiagnosticsResult<PageResult<AuditEntryDto>>;

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
