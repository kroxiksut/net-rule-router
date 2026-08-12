//! Logs mock backend.
//!
//! Re-exports log- and audit-related DTOs plus synchronous preview wrappers
//! so the GUI/tray shell can fetch a first page without holding a long-lived
//! `MockDiagnosticsFacade` handle.
//!
//! These will be wired to the real log reader via the service facade.

pub use nrr_diagnostics::facade::{
    AuditEntryDto, AuditEntryFilter, LogEntryDto, LogEntryFilter, MockDiagnosticsFacade,
    MockScenario, PageResult, PaginationParams,
};

/// Returns a page of mock log entries for preview mode.
///
/// Kept for backward compatibility; new callers should use
/// [`preview_operational_logs_first_page`].
pub fn preview_log_entries() -> PageResult<LogEntryDto> {
    preview_operational_logs_first_page()
}

/// Returns the first page (default page size 50) of operational log entries
/// from the `Healthy` scenario, sorted newest-first.
///
/// The facade returns entries in natural append order (oldest-first, matching
/// the NDJSON storage layout).  GUI consumers want newest-first, so the
/// preview wrapper reverses the page items here.
pub fn preview_operational_logs_first_page() -> PageResult<LogEntryDto> {
    use nrr_diagnostics::DiagnosticsFacade;
    let mut page = MockDiagnosticsFacade::healthy()
        .list_log_entries(&LogEntryFilter::default(), &PaginationParams::default())
        .unwrap_or_else(|_| PageResult::empty());
    page.items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    page
}

/// Returns the first page (default page size 50) of audit trail entries
/// from the `Healthy` scenario, sorted newest-first.
///
/// Same GUI-facing reversal rationale as [`preview_operational_logs_first_page`].
pub fn preview_audit_entries_first_page() -> PageResult<AuditEntryDto> {
    use nrr_diagnostics::DiagnosticsFacade;
    let mut page = MockDiagnosticsFacade::healthy()
        .list_audit_entries(&AuditEntryFilter::default(), &PaginationParams::default())
        .unwrap_or_else(|_| PageResult::empty());
    page.items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    page
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_diagnostics::facade::pagination::DEFAULT_PAGE_SIZE;

    fn is_sorted_desc_by_created_at_logs(items: &[LogEntryDto]) -> bool {
        items.windows(2).all(|w| w[0].created_at >= w[1].created_at)
    }

    fn is_sorted_desc_by_created_at_audit(items: &[AuditEntryDto]) -> bool {
        items.windows(2).all(|w| w[0].created_at >= w[1].created_at)
    }

    #[test]
    fn operational_logs_first_page_within_default_size() {
        let page = preview_operational_logs_first_page();
        assert!(
            (page.items.len() as u32) <= DEFAULT_PAGE_SIZE,
            "page size must not exceed default of {DEFAULT_PAGE_SIZE}"
        );
    }

    #[test]
    fn operational_logs_sorted_desc_by_created_at() {
        let page = preview_operational_logs_first_page();
        assert!(
            is_sorted_desc_by_created_at_logs(&page.items),
            "log entries must be ordered newest-first"
        );
    }

    #[test]
    fn audit_entries_first_page_within_default_size() {
        let page = preview_audit_entries_first_page();
        assert!(
            (page.items.len() as u32) <= DEFAULT_PAGE_SIZE,
            "page size must not exceed default of {DEFAULT_PAGE_SIZE}"
        );
    }

    #[test]
    fn audit_entries_sorted_desc_by_created_at() {
        let page = preview_audit_entries_first_page();
        assert!(
            is_sorted_desc_by_created_at_audit(&page.items),
            "audit entries must be ordered newest-first"
        );
    }

    #[test]
    fn preview_log_entries_aliases_first_page() {
        let via_alias = preview_log_entries();
        let direct = preview_operational_logs_first_page();
        assert_eq!(via_alias.items.len(), direct.items.len());
    }
}
