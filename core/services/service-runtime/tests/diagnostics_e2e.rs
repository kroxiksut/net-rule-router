#![allow(clippy::unwrap_used, clippy::expect_used, clippy::unimplemented)]
//! Integration tests for the diagnostics IPC surfaces, handler to facade:
//!
//! - a historical explain probe answers "decision not found" on the wire;
//! - logs.list cursor pagination walks every page with no duplicates;
//! - an archive export carries the manifest and the service's own log files.
//!
//! Explain and archive run against the production facade over a temporary
//! data tree; pagination uses a test-local paginating fake.

use std::path::PathBuf;
use std::sync::Arc;

use nrr_diagnostics::audit::alert::{InMemorySecurityAlertsRepository, SecurityAlertsRepository};
use nrr_diagnostics::{
    AcknowledgeAlertRequest, AuditEntryDto, AuditEntryFilter, ClearLogsRequest, ClearLogsResult,
    DiagnosticsFacade, DiagnosticsResult, DiagnosticsStatusDto, ExplainDataAvailability,
    ExplainQuery, ExplainResponse, LogEntryDto, LogEntryFilter, MockDiagnosticsFacade, PageCursor,
    PageResult, PaginationParams, SecurityAlertDto,
};
use nrr_domain::decision_explain::ExplainDetailLevel;
use nrr_service_runtime::ipc::{
    IpcHandler, IpcOperationClass, IpcRequestContext, IpcRequestEnvelope, IPC_PROTOCOL_VERSION,
};
use nrr_service_runtime::ipc_handlers::{
    DiagnosticsExportArchiveHandler, ExplainGetHandler, LogsListHandler,
};
use nrr_service_runtime::ProductionDiagnosticsFacade;
use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn ctx() -> IpcRequestContext {
    IpcRequestContext {
        client_profile: IpcClientProfile::GuiInteractive,
        caller_is_elevated: false,
        caller_principal: None,
        caller_pid: None,
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

/// The production facade over `<root>/logs` and `<root>/audit`, the layout the
/// archive handler assumes when it looks for `logs/` beside `archives/`.
fn production_facade(root: &std::path::Path) -> Arc<dyn DiagnosticsFacade> {
    let logs_dir = root.join("logs");
    let audit_dir = root.join("audit");
    std::fs::create_dir_all(&logs_dir).expect("logs dir");
    std::fs::create_dir_all(&audit_dir).expect("audit dir");
    let alerts: Arc<dyn SecurityAlertsRepository> =
        Arc::new(InMemorySecurityAlertsRepository::new());
    Arc::new(ProductionDiagnosticsFacade::new(
        logs_dir, audit_dir, None, alerts, None,
    ))
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

// ── Test 1: explain probe for an unknown decision → DecisionNotFound ─────────

#[test]
fn explain_probe_for_an_unknown_decision_answers_decision_not_found() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let handler = ExplainGetHandler::new(production_facade(tmp.path()));

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

    let expected = ExplainDataAvailability::DecisionNotFound.ui_key();
    assert_eq!(
        response["compact"]["reason-key"], expected,
        "the probe must say the decision is unknown: {response}"
    );
    assert_eq!(response["full"]["availability_key"], expected);
    assert_eq!(
        response["compact"]["route"], "none",
        "no verdict is invented"
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
    fn get_status(
        &self,
        _audience: &nrr_shared::diagnostics_dto::DiagnosticsAudience,
    ) -> DiagnosticsStatusDto {
        MockDiagnosticsFacade::healthy()
            .get_status(&nrr_shared::diagnostics_dto::DiagnosticsAudience::Machine)
    }
    fn list_log_entries(
        &self,
        _filter: &LogEntryFilter,
        pagination: &PaginationParams,
        _audience: &nrr_shared::diagnostics_dto::DiagnosticsAudience,
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
        _audience: &nrr_shared::diagnostics_dto::DiagnosticsAudience,
    ) -> DiagnosticsResult<PageResult<AuditEntryDto>> {
        Ok(PageResult::empty())
    }
    fn list_alerts(
        &self,
        _filter: nrr_diagnostics::facade::service::AlertListFilter,
        _audience: &nrr_shared::diagnostics_dto::DiagnosticsAudience,
    ) -> DiagnosticsResult<Vec<SecurityAlertDto>> {
        Ok(Vec::new())
    }
    fn acknowledge_alert(&self, _r: &AcknowledgeAlertRequest) -> DiagnosticsResult<()> {
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
        message: String::new(),
        has_payload: false,
        correlation_summary: Vec::new(),
        args: Default::default(),
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

// ── Test 3: archive export carries the manifest and the service logs ────────

/// One machine-level operational log file, named like the service's own.
fn write_service_log(logs_dir: &std::path::Path, event_id: &str) -> String {
    use std::io::Write;
    let date = nrr_diagnostics::audit::writer::local_date_string(std::time::SystemTime::now());
    let name = format!("nrr_service_{date}-1.ndjson");
    let event = nrr_diagnostics::LogEvent::new(
        event_id.to_string(),
        1_745_000_000_000,
        nrr_diagnostics::EventLevel::Info,
        nrr_diagnostics::reason::service::STARTED,
    );
    let mut file = std::fs::File::create(logs_dir.join(&name)).expect("create log file");
    writeln!(file, "{}", event.to_ndjson().expect("serialize")).expect("write log line");
    name
}

#[test]
fn diagnostics_export_archive_carries_manifest_and_service_logs() {
    use std::io::Read;

    let tmp = tempfile::tempdir().expect("temp dir");
    let facade = production_facade(tmp.path());
    let log_name = write_service_log(&tmp.path().join("logs"), "evt-e2e-archive");
    let archives_dir: PathBuf = tmp.path().join("archives");
    let handler = DiagnosticsExportArchiveHandler::new(
        facade,
        archives_dir.clone(),
        env!("CARGO_PKG_VERSION").to_string(),
        Some(nrr_shared::system_info::SystemInfo::from_std()),
        Arc::new(NoopAdapters),
        Arc::new(NoopRoutePolicy),
        None,
        Arc::new(nrr_platform_api::file_handoff::NoopFileHandoff),
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
        .expect("export-archive must succeed against the production facade");

    let archive_path = response["archive-path"]
        .as_str()
        .expect("response must carry archive-path");
    assert!(
        std::path::Path::new(archive_path).starts_with(&archives_dir),
        "the archive lands in the service's archives dir: {archive_path}"
    );

    let mut zip = zip::ZipArchive::new(std::fs::File::open(archive_path).expect("open archive"))
        .expect("the export must be a readable zip");
    let names: Vec<String> = zip.file_names().map(str::to_string).collect();
    assert!(
        names.iter().any(|n| n == "manifest.json"),
        "manifest.json missing: {names:?}"
    );
    let log_entry = format!("service-logs/{log_name}");
    assert!(
        names.contains(&log_entry),
        "the service's log file must ship under service-logs/: {names:?}"
    );

    let mut body = String::new();
    zip.by_name(&log_entry)
        .expect("service log entry")
        .read_to_string(&mut body)
        .expect("read service log entry");
    assert!(
        body.contains("evt-e2e-archive"),
        "the shipped file must be the one the service wrote: {body}"
    );
}
