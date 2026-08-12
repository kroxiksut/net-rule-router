#![allow(clippy::unwrap_used, clippy::expect_used, clippy::unimplemented)]
//! Integration tests for the diagnostics IPC surfaces:
//!
//! - explain probe round-trip (currently `Unavailable` until the
//!   `ExplainSnapshotRepository` lands; the wire surface is still
//!   well-formed);
//! - logs.list cursor pagination across multiple pages with no
//!   duplicates;
//! - archive export produces a real zip file on disk.
//!
//! These tests exercise the handler layer end-to-end against either the
//! crate-published `MockDiagnosticsFacade` (where its fixture data
//! shape matches) or a tiny test-local paginating fake (when the mock
//! shortcuts pagination to a single page).

use std::path::PathBuf;
use std::sync::Arc;

use nrr_diagnostics::{
    AcknowledgeAlertRequest, AuditEntryDto, AuditEntryFilter, ClearLogsRequest, ClearLogsResult,
    DiagnosticsFacade, DiagnosticsResult, DiagnosticsStatusDto, ExplainQuery, ExplainResponse,
    LogEntryDto, LogEntryFilter, MockDiagnosticsFacade, PageCursor, PageResult, PaginationParams,
    SecurityAlertDto, SetDiagnosticModeRequest,
};
use nrr_domain::decision_explain::ExplainDetailLevel;
use nrr_service_runtime::ipc::{
    IpcHandler, IpcOperationClass, IpcRequestContext, IpcRequestEnvelope, IPC_PROTOCOL_VERSION,
};
use nrr_service_runtime::ipc_handlers::{
    DiagnosticsExportArchiveHandler, ExplainGetHandler, LogsListHandler,
};
use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn ctx() -> IpcRequestContext {
    IpcRequestContext {
        client_profile: IpcClientProfile::GuiInteractive,
        caller_is_elevated: false,
        caller_principal: None,
    }
}

fn req(op: IpcOperationName, payload: serde_json::Value) -> IpcRequestEnvelope {
    IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "r-test".into(),
        correlation_id: None,
        operation: op,
        operation_class: IpcOperationClass::ReadSnapshot,
        confirmation_token: None,
        payload,
    }
}

/// A minimal `AdaptersSnapshotProvider`
/// for `DiagnosticsExportArchiveHandler` in this external integration-test
/// crate (the crate's own `test_fakes` module is `pub(crate)`, unreachable
/// from here).
struct NoopAdapters;

impl nrr_service_runtime::ipc_handlers::providers::AdaptersSnapshotProvider for NoopAdapters {
    fn adapters_snapshot(
        &self,
        _force_refresh: bool,
    ) -> nrr_shared::ipc_payloads::SnapshotInterfacesResponse {
        nrr_shared::ipc_payloads::SnapshotInterfacesResponse {
            data_source: "test".into(),
            adapters: Vec::new(),
            secondary: None,
            rows: Vec::new(),
        }
    }
}

/// A minimal `RoutePolicyProvider`
/// counterpart to [`NoopAdapters`]; no per-SID policy stored in this test.
struct NoopRoutePolicy;

impl nrr_service_runtime::ipc_handlers::providers::RoutePolicyProvider for NoopRoutePolicy {
    fn get_for_sid(&self, _sid: &str) -> Option<nrr_shared::ipc_payloads::RoutePolicyDto> {
        None
    }
}

// ── Test 1: explain probe historical decision → Unavailable wire payload ────

#[test]
fn explain_probe_historical_decision_returns_compact_unavailable_view() {
    // `get_explain` returns
    // `Unavailable::DecisionNotFound` for any decision_id until the
    // ExplainSnapshotRepository lands. The wire surface MUST
    // still respond with a well-formed `ExplainGetResponse` carrying
    // a compact view whose `reason_key` flags the unavailable state
    // — that's what the GUI's DiagnosticsSection.qml probe renders.
    let facade: Arc<dyn DiagnosticsFacade> = Arc::new(MockDiagnosticsFacade::healthy());
    let handler = ExplainGetHandler::new(facade);

    let envelope = req(
        IpcOperationName::ExplainGet,
        serde_json::json!({
            "decision-id": "decision-that-does-not-exist",
            "detail-level": "compact-ui",
        }),
    );
    let response = handler
        .handle(&envelope, &ctx())
        .expect("explain.get must respond OK even when decision is unknown");

    // The handler's compact view uses `rename_all = "kebab-case"` on
    // its DTO — both kebab and snake are accepted as resilience hedge.
    let compact = response
        .get("compact")
        .expect("response must carry compact view");
    let reason_key = compact
        .get("reason-key")
        .or_else(|| compact.get("reason_key"))
        .and_then(|v| v.as_str())
        .expect("compact.reason_key must be a string");
    // The wire MUST carry SOME reason key — exact value depends on
    // which Unavailable variant the facade picked. Once the snapshot
    // store is real, this assertion can tighten to a specific success
    // key for known decision-ids.
    assert!(
        !reason_key.is_empty(),
        "reason_key must not be empty; explain handler must surface SOME state",
    );
}

// ── Test 2: logs.list cursor pagination across 3+ pages ─────────────────────

/// Test-local paginating fake — `MockDiagnosticsFacade` shortcuts to
/// `PageResult::single_page`, which doesn't exercise the cursor path
/// the handler claims to support. This fake walks the stored vec by
/// `(cursor, page_size)`, matching the contract the production facade
/// implements via the `paginate<T>` helper.
struct PaginatingFakeDiagnostics {
    entries: Vec<LogEntryDto>,
}

impl DiagnosticsFacade for PaginatingFakeDiagnostics {
    fn get_status(&self) -> DiagnosticsStatusDto {
        MockDiagnosticsFacade::healthy().get_status()
    }
    fn list_log_entries(
        &self,
        _filter: &LogEntryFilter,
        pagination: &PaginationParams,
    ) -> DiagnosticsResult<PageResult<LogEntryDto>> {
        // Cursor encodes the position of the last item on the previous
        // page. Decode by matching the cursor's event_id against the
        // event_id of each entry — matching the production facade's
        // "last item id" convention.
        let start = if let Some(cur) = pagination.cursor.as_ref() {
            let cursor_str = cur.as_str();
            self.entries
                .iter()
                .position(|e| {
                    PageCursor::from_position(e.created_at, &e.event_id).as_str() == cursor_str
                })
                .map(|i| i + 1)
                .unwrap_or(0)
        } else {
            0
        };
        let end = (start + pagination.page_size as usize).min(self.entries.len());
        let items = self.entries[start..end].to_vec();
        let next_cursor = if end < self.entries.len() {
            items
                .last()
                .map(|e| PageCursor::from_position(e.created_at, &e.event_id))
        } else {
            None
        };
        Ok(PageResult {
            items,
            next_cursor,
            total_count: Some(self.entries.len() as u64),
            stale: false,
        })
    }
    fn list_audit_entries(
        &self,
        _f: &AuditEntryFilter,
        _p: &PaginationParams,
    ) -> DiagnosticsResult<PageResult<AuditEntryDto>> {
        Ok(PageResult::empty())
    }
    fn list_active_alerts(&self) -> DiagnosticsResult<Vec<SecurityAlertDto>> {
        Ok(Vec::new())
    }
    fn acknowledge_alert(&self, _r: &AcknowledgeAlertRequest) -> DiagnosticsResult<()> {
        Ok(())
    }
    fn set_diagnostic_mode(&self, _r: &SetDiagnosticModeRequest) -> DiagnosticsResult<()> {
        Ok(())
    }
    fn clear_logs(&self, _r: &ClearLogsRequest) -> DiagnosticsResult<ClearLogsResult> {
        Ok(ClearLogsResult {
            files_deleted: 0,
            bytes_freed: 0,
            dry_run: true,
        })
    }
    fn get_explain(
        &self,
        _q: &ExplainQuery,
        _l: ExplainDetailLevel,
        _caller_sid: &str,
    ) -> DiagnosticsResult<ExplainResponse> {
        unimplemented!("not used in pagination test")
    }
}

fn make_log_entry(id: u32) -> LogEntryDto {
    LogEntryDto {
        event_id: format!("e-{id:04}"),
        created_at: i64::from(id) * 1000,
        level: "info".into(),
        category: "service".into(),
        kind: "diagnostics.test".into(),
        message_key: "diag.test.entry".into(),
        has_payload: false,
        correlation_summary: Vec::new(),
    }
}

#[test]
fn logs_list_cursor_pagination_walks_all_pages_without_duplicates() {
    let entries: Vec<LogEntryDto> = (1..=10).map(make_log_entry).collect();
    let facade: Arc<dyn DiagnosticsFacade> = Arc::new(PaginatingFakeDiagnostics {
        entries: entries.clone(),
    });
    let handler = LogsListHandler::new(facade);

    let mut collected: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;

    loop {
        pages += 1;
        assert!(pages <= 10, "infinite-loop guard");

        let payload = if let Some(cur) = cursor.as_ref() {
            serde_json::json!({
                "filter": {},
                "pagination": { "cursor": cur, "page_size": 3 },
            })
        } else {
            serde_json::json!({
                "filter": {},
                "pagination": { "page_size": 3 },
            })
        };
        let response = handler
            .handle(&req(IpcOperationName::LogsList, payload), &ctx())
            .expect("logs.list must respond OK");

        let items = response
            .get("items")
            .and_then(|v| v.as_array())
            .expect("items must be an array");
        for item in items {
            let id = item
                .get("event_id")
                .and_then(|v| v.as_str())
                .expect("entry must carry event_id");
            collected.push(id.to_string());
        }
        cursor = response
            .get("next_cursor")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        if cursor.is_none() {
            break;
        }
    }

    assert_eq!(pages, 4, "page count: 3+3+3+1 = 4 pages over 10 entries");
    assert_eq!(collected.len(), 10, "all 10 entries reached");
    let mut sorted = collected.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 10, "no duplicates across pages");
}

// ── Test 3: archive export produces a real zip file ─────────────────────────

#[test]
fn diagnostics_export_archive_creates_real_zip_file() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let archives_dir: PathBuf = tmp.path().join("archives");
    let facade: Arc<dyn DiagnosticsFacade> = Arc::new(MockDiagnosticsFacade::healthy());
    let handler = DiagnosticsExportArchiveHandler::new(
        facade,
        archives_dir.clone(),
        env!("CARGO_PKG_VERSION").to_string(),
        Some(nrr_shared::system_info::SystemInfo::from_std()),
        Arc::new(NoopAdapters),
        Arc::new(NoopRoutePolicy),
        None,
    );

    let envelope = req(
        IpcOperationName::DiagnosticsExportArchive,
        serde_json::json!({
            "include-logs": true,
            "include-audit-summary": true,
            "include-troubleshooting-playbooks": true,
        }),
    );
    let response = handler
        .handle(&envelope, &ctx())
        .expect("export-archive must succeed against mock facade");

    let archive_path = response
        .get("archive-path")
        .or_else(|| response.get("archive_path"))
        .and_then(|v| v.as_str())
        .expect("response must carry archive-path");
    let size_bytes = response
        .get("size-bytes")
        .or_else(|| response.get("size_bytes"))
        .and_then(|v| v.as_u64())
        .expect("response must carry size-bytes");

    assert!(
        std::path::Path::new(archive_path).exists(),
        "zip file must exist on disk at {archive_path}",
    );
    assert!(size_bytes > 0, "archive must be non-empty");
    assert!(
        archives_dir.exists(),
        "handler must create the destination directory",
    );

    // Verify the zip magic header (`PK\x03\x04`) — proves the file
    // is a real zip rather than an empty stub or a different format.
    // Avoids pulling the full `zip` crate as a dev-dep just for this
    // single check; the manifest layout is exercised by
    // `nrr-diagnostics::archive`'s own unit tests.
    let head = std::fs::read(archive_path).expect("read zip header");
    assert!(head.len() >= 4, "zip must be at least 4 bytes");
    assert_eq!(
        &head[..4],
        b"PK\x03\x04",
        "file must start with the local-file-header zip magic",
    );
}
