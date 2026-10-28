//! «Diagnostics and logs»: the service's state, security alerts and their
//! acknowledgement, the explain probe, the diagnostic archive, the
//! operational log and the audit trail. The same operations as the GUI's two
//! sections: `service.health.get`, `snapshot.diagnostics.get`,
//! `mutation.submit` (`security-alert-ack`), `operation.status.get`,
//! `diagnostics.explain.get`, `diagnostics.export-archive`, `logs.list` and
//! `audit.list`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crossterm::event::{KeyCode, KeyEvent};
use nrr_client_logic::diagnostics::{
    alert_ack_outcome, security_alert_items, security_alerts_unreadable, AlertItem,
};
use nrr_client_logic::placeholders::format_log_line;
use nrr_client_logic::review::{operation_outcome, Outcome};
use nrr_client_logic::units::format_storage_bytes;
use nrr_ipc_client::IpcClient;
use nrr_shared::diagnostics_dto::{
    AuditEntryDto, DiagnosticsDataOrigin, DiagnosticsStatusDto, LogEntryDto, LogEntryFilter,
    OTHER_PRINCIPAL_ALERT_ID,
};
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    AuditListRequest, AuditListResponse, DiagnosticsExportArchiveRequest,
    DiagnosticsExportArchiveResponse, ExplainGetRequest, ExplainGetResponse, ExplainInputSampleDto,
    IntegrityRowKind, LogsListRequest, LogsListResponse, MutationConfirmResponse,
    MutationDryRunResponse, MutationKind, MutationSubmitRequest, OperationStatusRequest,
    OperationStatusResponse, ServiceHealthResponse, UnverifiedRowDto,
};
use nrr_shared::pagination::{PageCursor, PaginationParams};
use serde_json::{json, Value};

use super::{
    answer_key, answer_line, bad_response, call, call_within, command, edit, error_text,
    fill_numbered, keys, page_lines, queue, typing_lines, unencodable, wall_clock,
    wall_clock_seconds, Answer, Edit, Pager,
};
use crate::backend::Reply;
use crate::i18n::{Key, Texts};
use crate::screens::{Screen, ScreenId};
use crate::state::AppState;
use crate::view::{Panel, ScreenView, Segment, StateTone, ViewLine};

/// The service walks logs, audit and storage to build an archive; a support
/// archive is worth the wait (the console allows the same).
const EXPORT_TIMEOUT: Duration = Duration::from_secs(120);
const LOG_PAGE_SIZE: u32 = 50;
/// The GUI's level choices; empty is every level.
const LEVELS: [&str; 4] = ["", "info", "warn", "error"];
/// The window's caps on the raw service log in an archive; 0 is no cap.
const ARCHIVE_LOG_BUDGETS_MIB: [u64; 4] = [0, 24, 64, 128];
const MIB: u64 = 1024 * 1024;

/// The columns the window's log table sorts by.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum LogColumn {
    #[default]
    Time,
    Level,
    Category,
    Kind,
}

impl LogColumn {
    fn next(self) -> Self {
        match self {
            Self::Time => Self::Level,
            Self::Level => Self::Category,
            Self::Category => Self::Kind,
            Self::Kind => Self::Time,
        }
    }

    fn label(self) -> Key {
        match self {
            Self::Time => keys::COLUMN_TIME,
            Self::Level => keys::COLUMN_LEVEL,
            Self::Category => keys::COLUMN_CATEGORY,
            Self::Kind => keys::COLUMN_KIND,
        }
    }
}

/// The columns the window's audit table sorts by.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum AuditColumn {
    #[default]
    Seq,
    Time,
    Kind,
    Result,
    Reason,
    Revision,
}

impl AuditColumn {
    fn next(self) -> Self {
        match self {
            Self::Seq => Self::Time,
            Self::Time => Self::Kind,
            Self::Kind => Self::Result,
            Self::Result => Self::Reason,
            Self::Reason => Self::Revision,
            Self::Revision => Self::Seq,
        }
    }

    fn label(self) -> Key {
        match self {
            Self::Seq => keys::COLUMN_SEQ,
            Self::Time => keys::COLUMN_TIME,
            Self::Kind => keys::COLUMN_AUDIT_KIND,
            Self::Result => keys::COLUMN_RESULT,
            Self::Reason => keys::COLUMN_REASON,
            Self::Revision => keys::COLUMN_REVISION,
        }
    }
}

/// A table's order, newest first until the user picks another; a new column
/// starts in its natural direction, as a header click in the window does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sort<C> {
    column: C,
    descending: bool,
}

impl Sort<LogColumn> {
    fn next_column(self) -> Self {
        let column = self.column.next();
        Self {
            column,
            descending: column == LogColumn::Time,
        }
    }
}

impl Sort<AuditColumn> {
    fn next_column(self) -> Self {
        let column = self.column.next();
        Self {
            column,
            descending: matches!(column, AuditColumn::Seq | AuditColumn::Time),
        }
    }
}

impl<C: Default> Default for Sort<C> {
    fn default() -> Self {
        Self {
            column: C::default(),
            descending: true,
        }
    }
}

impl<C> Sort<C> {
    fn reversed(self) -> Self {
        Self {
            descending: !self.descending,
            ..self
        }
    }

    fn apply(self, order: std::cmp::Ordering) -> std::cmp::Ordering {
        if self.descending {
            order.reverse()
        } else {
            order
        }
    }
}

/// Text columns compare without regard to case, as the window's
/// `localeCompare` does for these ASCII slugs.
fn text_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.to_lowercase()
        .cmp(&b.to_lowercase())
        .then_with(|| a.cmp(b))
}

/// The loaded rows in display order; equal rows keep the order they came in.
fn log_order(entries: &[LogEntryDto], sort: Sort<LogColumn>) -> Vec<usize> {
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by(|&a, &b| {
        let (a, b) = (&entries[a], &entries[b]);
        sort.apply(match sort.column {
            LogColumn::Time => a.created_at.cmp(&b.created_at),
            LogColumn::Level => text_order(&a.level, &b.level),
            LogColumn::Category => text_order(&a.category, &b.category),
            LogColumn::Kind => text_order(&a.kind, &b.kind),
        })
    });
    order
}

fn audit_order(entries: &[AuditEntryDto], sort: Sort<AuditColumn>) -> Vec<usize> {
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by(|&a, &b| {
        let (a, b) = (&entries[a], &entries[b]);
        sort.apply(match sort.column {
            AuditColumn::Seq => a.seq.cmp(&b.seq),
            AuditColumn::Time => a.created_at.cmp(&b.created_at),
            AuditColumn::Kind => text_order(&a.kind, &b.kind),
            AuditColumn::Result => text_order(&a.result, &b.result),
            AuditColumn::Reason => text_order(&a.reason_code, &b.reason_code),
            AuditColumn::Revision => text_order(
                a.revision_id.as_deref().unwrap_or(""),
                b.revision_id.as_deref().unwrap_or(""),
            ),
        })
    });
    order
}

fn sort_words<C: Copy>(texts: &Texts, sort: Sort<C>, label: fn(C) -> Key) -> String {
    texts.fill(
        keys::SORT,
        &[
            ("column", texts.get(label(sort.column))),
            (
                "direction",
                texts.get(if sort.descending {
                    keys::SORT_DESCENDING
                } else {
                    keys::SORT_ASCENDING
                }),
            ),
        ],
    )
}

/// What the next archive carries, as the window's export options choose it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ArchiveOptions {
    full_detail: bool,
    session_only: bool,
    /// Index into [`ARCHIVE_LOG_BUDGETS_MIB`].
    budget: usize,
}

impl Default for ArchiveOptions {
    fn default() -> Self {
        Self {
            full_detail: false,
            session_only: true,
            budget: 0,
        }
    }
}

impl ArchiveOptions {
    fn budget_mib(self) -> u64 {
        ARCHIVE_LOG_BUDGETS_MIB
            .get(self.budget)
            .copied()
            .unwrap_or_default()
    }

    /// "This session" reaches back to the local midnight the session began
    /// on, so a restart during the day does not cut the day's history.
    fn request(self, session_start_ms: i64) -> DiagnosticsExportArchiveRequest {
        let budget = self.budget_mib().saturating_mul(MIB);
        DiagnosticsExportArchiveRequest {
            include_logs: true,
            include_audit_summary: true,
            include_troubleshooting_playbooks: true,
            redaction_level: Some(
                if self.full_detail {
                    "diagnostics"
                } else {
                    "standard"
                }
                .to_owned(),
            ),
            logs_from_ms: self
                .session_only
                .then(|| local_midnight(session_start_ms))
                .flatten(),
            raw_log_budget_bytes: (budget > 0).then_some(budget),
        }
    }
}

fn local_midnight(ms: i64) -> Option<i64> {
    use chrono::TimeZone;
    let at = chrono::DateTime::from_timestamp_millis(ms).filter(|_| ms > 0)?;
    let day = at.with_timezone(&chrono::Local).date_naive();
    let midnight = day.and_hms_opt(0, 0, 0)?;
    chrono::Local
        .from_local_datetime(&midnight)
        .earliest()
        .map(|local| local.timestamp_millis())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Part {
    #[default]
    Overview,
    Log,
    Audit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    Explain,
    LogKind,
    LogCategory,
    Site,
}

#[derive(Debug, Default)]
enum Ack {
    #[default]
    Idle,
    Working,
    /// Acknowledging trusts these rule sets: shown before the user agrees.
    Review {
        alert_id: String,
        kind: String,
        rows: Vec<UnverifiedRowDto>,
    },
    Done(Result<(), String>),
    /// Line mode: the alert printed under that number has left the list.
    Gone(usize),
}

#[derive(Debug)]
struct Probe {
    input: String,
    route: String,
    reason_key: String,
    enforcement: String,
    shared: u32,
    total: u32,
    blocking_ip: String,
}

#[derive(Debug, Default)]
struct Explain {
    input: String,
    probing: bool,
    generation: u64,
    result: Option<Result<Probe, String>>,
}

#[derive(Debug, Default)]
enum Archive {
    #[default]
    Ready,
    Busy,
    Saved {
        path: String,
        size: u64,
        readable: bool,
    },
    Failed(String),
}

#[derive(Debug, Default)]
struct Log {
    asked: bool,
    /// Read before the service came back: read again when shown.
    reread: bool,
    loading: bool,
    entries: Vec<LogEntryDto>,
    cursor: Option<PageCursor>,
    error: Option<String>,
    level: usize,
    kind: String,
    category: String,
    all_history: bool,
    sort: Sort<LogColumn>,
    pager: Pager,
    generation: u64,
    advance: bool,
}

#[derive(Debug, Default)]
struct AuditTrail {
    asked: bool,
    reread: bool,
    loading: bool,
    entries: Vec<AuditEntryDto>,
    cursor: Option<PageCursor>,
    error: Option<String>,
    sort: Sort<AuditColumn>,
    pager: Pager,
    generation: u64,
    advance: bool,
}

#[derive(Debug)]
pub struct DiagState {
    part: Part,
    asked: bool,
    /// The overview was read before the service came back.
    reread: bool,
    loading: bool,
    health: Option<Result<ServiceHealthResponse, String>>,
    status: Option<DiagnosticsStatusDto>,
    status_error: Option<String>,
    alerts: Vec<AlertItem>,
    alerts_known: bool,
    alerts_unreadable: bool,
    alert_pager: Pager,
    /// Line mode: the alerts as last printed, by id.
    printed_alerts: Vec<String>,
    ack: Ack,
    explain: Explain,
    typing: Option<(Field, String)>,
    archive: Archive,
    archive_options: ArchiveOptions,
    log: Log,
    audit: AuditTrail,
    pub(super) restart: super::audit_restart::Restart,
    /// "Current session" in the log starts when this program did.
    pub(super) session_start_ms: i64,
}

impl Default for DiagState {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        Self {
            part: Part::default(),
            asked: false,
            reread: false,
            loading: false,
            health: None,
            status: None,
            status_error: None,
            alerts: Vec::new(),
            alerts_known: false,
            alerts_unreadable: false,
            alert_pager: Pager::default(),
            printed_alerts: Vec::new(),
            ack: Ack::default(),
            explain: Explain::default(),
            typing: None,
            archive: Archive::default(),
            archive_options: ArchiveOptions::default(),
            log: Log::default(),
            audit: AuditTrail::default(),
            restart: Default::default(),
            session_start_ms: now,
        }
    }
}

// ── Service state and alerts ─────────────────────────────────────────────────

/// Both reads the overview stands on; the raw status, because the alert list
/// is judged on the service's own answer.
struct StatusRead {
    health: Result<ServiceHealthResponse, String>,
    status: Result<Value, String>,
}

fn read_status(client: &dyn IpcClient) -> StatusRead {
    let health = call(client, IpcOperationName::ServiceHealthGet, json!({}))
        .and_then(|v| serde_json::from_value(v).map_err(bad_response));
    let status = call(client, IpcOperationName::SnapshotDiagnosticsGet, json!({}))
        .map(|mut v| v.get_mut("status").map(Value::take).unwrap_or(Value::Null));
    StatusRead { health, status }
}

fn apply_status(state: &mut DiagState, read: StatusRead) {
    state.loading = false;
    state.health = Some(read.health);
    match read.status {
        Ok(status) => {
            state.status_error = None;
            state.status = serde_json::from_value(status.clone()).ok();
            if let Some(items) = security_alert_items(&status) {
                // The cursor stays on its alert, wherever the new list puts it.
                let chosen = state.alerts.get(state.alert_pager.selected);
                if let Some(at) =
                    chosen.and_then(|old| items.iter().position(|a| a.alert_id == old.alert_id))
                {
                    state.alert_pager.selected = at;
                }
                state.alerts = items;
                state.alerts_known = true;
                state.alerts_unreadable = false;
            } else if security_alerts_unreadable(&status) {
                // The alerts shown stay; they are only no longer known current.
                state.alerts_unreadable = true;
            }
            state.alert_pager.clamp(state.alerts.len());
        }
        Err(slug) => state.status_error = Some(slug),
    }
}

fn load_status(app: &mut AppState) {
    let state = &mut app.inspect.diag;
    state.asked = true;
    state.reread = false;
    state.loading = true;
    queue(app, |client| {
        let read = read_status(client);
        Reply::new(move |app| apply_status(&mut app.inspect.diag, read))
    });
}

/// The service came back: what was read before (a broken chain, alerts, its
/// health) may be gone, so each part is read again when shown.
pub fn on_reconnected(app: &mut AppState) {
    let state = &mut app.inspect.diag;
    state.reread = state.asked;
    state.log.reread = state.log.asked;
    state.audit.reread = state.audit.asked;
}

/// An alert was raised or acknowledged elsewhere: the list on screen is
/// re-read, so it does not keep an answered alert as open.
pub fn reload_alerts(app: &mut AppState) {
    if app.screen != ScreenId::Diagnostics || !app.link.is_connected() || app.inspect.diag.loading {
        return;
    }
    load_status(app);
}

/// Tamper and key-reset alerts trust rule sets when acknowledged, so the rows
/// the service's dry-run lists are shown first and sent back.
fn adopts_rows(kind: &str) -> bool {
    kind == "db_tamper_detected" || kind == "key_reset_with_existing_data"
}

fn submit(
    client: &dyn IpcClient,
    payload: Value,
    dry_run: bool,
    token: Option<&str>,
) -> Result<Value, String> {
    submit_kind(
        client,
        MutationKind::SecurityAlertAck,
        payload,
        dry_run,
        token,
    )
}

pub(super) fn submit_kind(
    client: &dyn IpcClient,
    kind: MutationKind,
    payload: Value,
    dry_run: bool,
    token: Option<&str>,
) -> Result<Value, String> {
    let request = MutationSubmitRequest {
        mutation_kind: kind,
        payload,
        dry_run,
    };
    let mut value = serde_json::to_value(&request).map_err(unencodable)?;
    // The client moves this key into the envelope, where the service reads it.
    if let (Some(token), Some(map)) = (token, value.as_object_mut()) {
        map.insert("_envelope_confirmation_token".into(), json!(token));
    }
    call(client, IpcOperationName::MutationSubmit, value)
}

fn dry_run(client: &dyn IpcClient, payload: &Value) -> Result<MutationDryRunResponse, String> {
    let answer = submit(client, payload.clone(), true, None)?;
    serde_json::from_value(answer).map_err(bad_response)
}

/// Confirm with the dry-run's token, then judge it: by the operation record,
/// else by whether the alert is still listed active. The overview is re-read
/// either way, so a refusal is shown against a list that is current.
fn confirm(
    client: &dyn IpcClient,
    payload: Value,
    token: &str,
    alert_id: &str,
) -> (Result<(), String>, StatusRead) {
    let recorded = submit(client, payload, false, Some(token))
        .and_then(|answer| {
            serde_json::from_value::<MutationConfirmResponse>(answer).map_err(bad_response)
        })
        .map(|confirmed| {
            let request = OperationStatusRequest {
                operation_id: confirmed.operation_id,
            };
            let record = serde_json::to_value(&request)
                .ok()
                .and_then(|p| call(client, IpcOperationName::OperationStatusGet, p).ok())
                .and_then(|v| serde_json::from_value::<OperationStatusResponse>(v).ok());
            operation_outcome(record.as_ref())
        });
    let read = read_status(client);
    let result = match recorded {
        Err(slug) => Err(slug),
        Ok(Some(Outcome::Applied)) => Ok(()),
        Ok(Some(Outcome::Failed(code))) => Err(code),
        Ok(None) => {
            let (status, code) = match &read.status {
                Ok(status) => (status.clone(), ""),
                Err(slug) => (Value::Null, slug.as_str()),
            };
            match alert_ack_outcome(&status, alert_id, code) {
                verdict if verdict.is_empty() => Ok(()),
                verdict => Err(verdict),
            }
        }
    };
    (result, read)
}

fn finish_ack(app: &mut AppState, result: Result<(), String>, read: StatusRead) {
    let state = &mut app.inspect.diag;
    state.ack = Ack::Done(result);
    apply_status(state, read);
}

fn acknowledge(app: &mut AppState, alert: &AlertItem) {
    if alert.state != "active" || matches!(app.inspect.diag.ack, Ack::Working) {
        return;
    }
    // Alerts about another user's rules: only an administrator, who sees the
    // alerts themselves, can clear them.
    if alert.alert_id == OTHER_PRINCIPAL_ALERT_ID {
        app.inspect.diag.ack = Ack::Done(Err("forbidden".to_owned()));
        return;
    }
    app.inspect.diag.ack = Ack::Working;
    let alert_id = alert.alert_id.clone();
    let kind = alert.kind.clone();
    queue(app, move |client| {
        let payload = json!({ "alert-id": alert_id });
        let preview = match dry_run(client, &payload) {
            Ok(preview) => preview,
            Err(slug) => {
                let read = read_status(client);
                return Reply::new(move |app| finish_ack(app, Err(slug), read));
            }
        };
        if adopts_rows(&kind) {
            let rows = preview.unverified_rows;
            return Reply::new(move |app| {
                app.inspect.diag.ack = Ack::Review {
                    alert_id,
                    kind,
                    rows,
                };
            });
        }
        let (result, read) = confirm(client, payload, &preview.confirmation_token, &alert_id);
        Reply::new(move |app| finish_ack(app, result, read))
    });
}

/// The listed rows go back unchanged; the service trusts only those whose
/// content still matches, and the token is minted for this exact payload.
fn acknowledge_reviewed(app: &mut AppState) {
    let Ack::Review { alert_id, rows, .. } = std::mem::take(&mut app.inspect.diag.ack) else {
        return;
    };
    app.inspect.diag.ack = Ack::Working;
    queue(app, move |client| {
        let refs: Vec<Value> = rows
            .iter()
            .filter_map(|r| serde_json::to_value(&r.row).ok())
            .collect();
        let payload = json!({ "alert-id": alert_id, "adopt-rows": refs });
        let (result, read) = match dry_run(client, &payload) {
            Ok(preview) => confirm(client, payload, &preview.confirmation_token, &alert_id),
            Err(slug) => (Err(slug), read_status(client)),
        };
        Reply::new(move |app| finish_ack(app, result, read))
    });
}

fn acknowledge_selected(app: &mut AppState) {
    let state = &app.inspect.diag;
    if let Some(alert) = state.alerts.get(state.alert_pager.selected).cloned() {
        acknowledge(app, &alert);
    }
}

// ── Explain ──────────────────────────────────────────────────────────────────

fn is_ip(s: &str) -> bool {
    let v4 = s.split('.').count() == 4
        && s.split('.')
            .all(|p| (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()));
    let v6 = s.contains(':') && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
    v4 || v6
}

/// Which rule would win for a destination, and whether the flow would be let
/// through right now. A trace row hands its address and program along so the
/// probe answers for that connection.
pub fn probe(app: &mut AppState, input: &str, sample_ip: &str, sample_process: &str) {
    let state = &mut app.inspect.diag;
    state.part = Part::Overview;
    state.typing = None;
    state.explain.input = input.trim().to_owned();
    state.explain.generation += 1;
    if state.explain.input.is_empty() {
        state.explain.probing = false;
        state.explain.result = Some(Err("input-required".to_owned()));
        return;
    }
    state.explain.probing = true;
    state.explain.result = None;
    let generation = state.explain.generation;
    let raw = state.explain.input.clone();
    let (hostname, ip) = if is_ip(&raw) {
        (None, raw)
    } else {
        (Some(raw), sample_ip.to_owned())
    };
    let request = ExplainGetRequest {
        decision_id: None,
        input_sample: Some(ExplainInputSampleDto {
            hostname,
            observed_ip: Some(ip).filter(|s| !s.is_empty()),
            process_name: Some(sample_process.to_owned()).filter(|s| !s.is_empty()),
        }),
        detail_level: Some("compact-ui".to_owned()),
    };
    queue(app, move |client| {
        let result = serde_json::to_value(&request)
            .map_err(unencodable)
            .and_then(|payload| call(client, IpcOperationName::ExplainGet, payload))
            .and_then(|answer| {
                serde_json::from_value::<ExplainGetResponse>(answer).map_err(bad_response)
            })
            .map(probe_from);
        Reply::new(move |app| {
            let explain = &mut app.inspect.diag.explain;
            if explain.generation == generation {
                explain.probing = false;
                explain.result = Some(result);
            }
        })
    });
}

fn probe_from(answer: ExplainGetResponse) -> Probe {
    let compact = answer.compact;
    // Blocked by an address rule: name the address when the answer has it.
    let blocking_ip = if compact.reason_key == "diag.explain.reason.blocked-by-ip-rule" {
        answer
            .full
            .pointer("/lookup_section/selected_ip")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    } else {
        String::new()
    };
    Probe {
        input: if compact.input.is_empty() {
            "-".to_owned()
        } else {
            compact.input
        },
        route: if compact.route.is_empty() {
            "none".to_owned()
        } else {
            compact.route
        },
        reason_key: compact.reason_key,
        enforcement: compact.enforcement,
        shared: compact.enforcement_shared_ips,
        total: compact.enforcement_total_ips,
        blocking_ip,
    }
}

fn route_label(texts: &Texts, route: &str) -> String {
    match route {
        "" | "none" => texts.get(keys::ROUTE_NONE),
        "blocked" => texts.get(keys::ROUTE_BLOCKED),
        "primary" => texts.get(keys::ROUTE_PRIMARY),
        "secondary" => texts.get(keys::ROUTE_SECONDARY),
        other => other.to_owned(),
    }
}

/// "Primary — Allowed": the route, and whether an enforcement caveat blocks
/// the flow right now. Caveats on an allowed flow do not flip it.
fn verdict_label(texts: &Texts, probe: &Probe) -> String {
    let route = match probe.route.as_str() {
        "primary" => texts.get(keys::PRIMARY),
        "secondary" => texts.get(keys::SECONDARY),
        other => return route_label(texts, other),
    };
    let blocking = matches!(
        probe.enforcement.as_str(),
        "everything-waits-when-secondary-down"
            | "fail-closed-when-secondary-down"
            | "collateral-blocked-strict"
    );
    let status = texts.get(if blocking {
        keys::VERDICT_BLOCK
    } else {
        keys::VERDICT_PERMIT
    });
    format!("{route} — {status}")
}

/// "Is it us or the site?" for `host`, from another screen: the overview
/// shows the check and its answer.
pub fn check_site(app: &mut AppState, host: &str) {
    let state = &mut app.inspect.diag;
    state.part = Part::Overview;
    state.typing = None;
    super::site_check::start(app, host);
}

// ── Archive ──────────────────────────────────────────────────────────────────

fn export(app: &mut AppState) {
    if matches!(app.inspect.diag.archive, Archive::Busy) {
        return;
    }
    app.inspect.diag.archive = Archive::Busy;
    let state = &app.inspect.diag;
    let request = state.archive_options.request(state.session_start_ms);
    queue(app, move |client| {
        let outcome = serde_json::to_value(&request)
            .map_err(unencodable)
            .and_then(|payload| {
                call_within(
                    client,
                    IpcOperationName::DiagnosticsExportArchive,
                    payload,
                    EXPORT_TIMEOUT,
                )
            })
            .and_then(|answer| {
                serde_json::from_value::<DiagnosticsExportArchiveResponse>(answer)
                    .map_err(bad_response)
            })
            .and_then(|done| {
                if done.archive_path.is_empty() {
                    return Err("bad-response".to_owned());
                }
                // The file reaches this account through the service's grant;
                // "saved" is said only together with whether it opens.
                let readable = std::fs::File::open(&done.archive_path).is_ok();
                Ok(Archive::Saved {
                    path: done.archive_path,
                    size: done.size_bytes,
                    readable,
                })
            });
        Reply::new(move |app| {
            app.inspect.diag.archive = outcome.unwrap_or_else(Archive::Failed);
        })
    });
}

// ── Log ──────────────────────────────────────────────────────────────────────

fn log_filter(state: &DiagState) -> LogEntryFilter {
    let log = &state.log;
    LogEntryFilter {
        from_ms: (!log.all_history && state.session_start_ms > 0).then_some(state.session_start_ms),
        level_min: Some(LEVELS[log.level].to_owned()).filter(|l| !l.is_empty()),
        category: Some(log.category.trim().to_owned()).filter(|c| !c.is_empty()),
        kind: Some(log.kind.trim().to_owned()).filter(|k| !k.is_empty()),
        ..LogEntryFilter::default()
    }
}

fn load_log(app: &mut AppState, reset: bool) {
    let filter = log_filter(&app.inspect.diag);
    let log = &mut app.inspect.diag.log;
    if reset {
        log.generation += 1;
        log.entries.clear();
        log.cursor = None;
        log.pager = Pager::default();
        log.advance = false;
    }
    log.asked = true;
    log.reread = false;
    log.loading = true;
    log.error = None;
    let generation = log.generation;
    let request = LogsListRequest {
        filter,
        pagination: PaginationParams {
            cursor: log.cursor.clone(),
            page_size: LOG_PAGE_SIZE,
        },
    };
    queue(app, move |client| {
        let result = serde_json::to_value(&request)
            .map_err(unencodable)
            .and_then(|payload| call(client, IpcOperationName::LogsList, payload))
            .and_then(|answer| {
                serde_json::from_value::<LogsListResponse>(answer).map_err(bad_response)
            });
        Reply::new(move |app| {
            let log = &mut app.inspect.diag.log;
            // Rows of an older filter must not stand under the new one.
            if log.generation != generation {
                return;
            }
            log.loading = false;
            match result {
                Ok(page) => {
                    log.entries.extend(page.items);
                    log.cursor = page.next_cursor;
                    if std::mem::take(&mut log.advance) {
                        log.pager.next_page(log.entries.len());
                    }
                }
                Err(slug) => {
                    log.advance = false;
                    log.error = Some(slug);
                }
            }
        })
    });
}

fn more_log(app: &mut AppState) {
    let log = &mut app.inspect.diag.log;
    let len = log.entries.len();
    if log.pager.next_page(len) || log.cursor.is_none() || log.loading {
        return;
    }
    log.advance = true;
    load_log(app, false);
}

fn level_label(texts: &Texts, level: &str) -> String {
    if level.is_empty() {
        texts.get(keys::LOGS_ALL_LEVELS)
    } else {
        texts.dynamic(&format!("diag.logs.level-{level}"), level)
    }
}

/// A tagged event in its translation with `{field}` filled from its own
/// fields; the English text where it has none, then the area it came from.
fn log_message(texts: &Texts, e: &LogEntryDto) -> String {
    let fallback = if e.message.is_empty() {
        e.kind.clone()
    } else {
        e.message.clone()
    };
    let translated = if e.message_key.is_empty() {
        fallback.clone()
    } else {
        texts.dynamic(&e.message_key, &fallback)
    };
    format_log_line(&translated, &fallback, &e.args, &e.correlation_summary)
}

fn log_row(texts: &Texts, e: &LogEntryDto) -> String {
    format!(
        "{} · {} · {}: {}",
        wall_clock_seconds(e.created_at),
        level_label(texts, &e.level),
        e.category,
        log_message(texts, e)
    )
}

// ── Audit trail ──────────────────────────────────────────────────────────────

fn load_audit(app: &mut AppState, reset: bool) {
    let audit = &mut app.inspect.diag.audit;
    if reset {
        audit.generation += 1;
        audit.entries.clear();
        audit.cursor = None;
        audit.pager = Pager::default();
        audit.advance = false;
    }
    audit.asked = true;
    audit.reread = false;
    audit.loading = true;
    audit.error = None;
    let generation = audit.generation;
    let request = AuditListRequest {
        pagination: PaginationParams {
            cursor: audit.cursor.clone(),
            page_size: LOG_PAGE_SIZE,
        },
        ..AuditListRequest::default()
    };
    queue(app, move |client| {
        let result = serde_json::to_value(&request)
            .map_err(unencodable)
            .and_then(|payload| call(client, IpcOperationName::AuditList, payload))
            .and_then(|answer| {
                serde_json::from_value::<AuditListResponse>(answer).map_err(bad_response)
            });
        Reply::new(move |app| {
            let audit = &mut app.inspect.diag.audit;
            if audit.generation != generation {
                return;
            }
            audit.loading = false;
            match result {
                Ok(page) => {
                    audit.entries.extend(page.items);
                    audit.cursor = page.next_cursor;
                    if std::mem::take(&mut audit.advance) {
                        audit.pager.next_page(audit.entries.len());
                    }
                }
                Err(slug) => {
                    audit.advance = false;
                    audit.error = Some(slug);
                }
            }
        })
    });
}

fn more_audit(app: &mut AppState) {
    let audit = &mut app.inspect.diag.audit;
    let len = audit.entries.len();
    if audit.pager.next_page(len) || audit.cursor.is_none() || audit.loading {
        return;
    }
    audit.advance = true;
    load_audit(app, false);
}

/// A cause is a service slug: it is shown only through its translation.
fn audit_cause(texts: &Texts, slug: &str) -> String {
    texts.dynamic(&format!("audit.cause.{slug}"), slug)
}

fn audit_row(texts: &Texts, e: &AuditEntryDto) -> String {
    let mut row = format!(
        "#{} · {} · {} · {} · {}",
        e.seq,
        wall_clock_seconds(e.created_at),
        e.kind,
        e.result,
        e.reason_code
    );
    if let Some(cause) = e.cause.as_deref().filter(|c| !c.is_empty()) {
        row.push_str(" · ");
        row.push_str(&audit_cause(texts, cause));
    }
    if let Some(revision) = e.revision_id.as_deref().filter(|r| !r.is_empty()) {
        row.push_str(" · ");
        row.push_str(revision);
    }
    row
}

fn switch_part(app: &mut AppState) {
    let state = &mut app.inspect.diag;
    state.typing = None;
    state.part = match state.part {
        Part::Overview => Part::Log,
        Part::Log => Part::Audit,
        Part::Audit => Part::Overview,
    };
    let connected = app.link.is_connected();
    let state = &app.inspect.diag;
    if state.part == Part::Log && (!state.log.asked || state.log.reread) && connected {
        load_log(app, true);
    } else if state.part == Part::Audit && (!state.audit.asked || state.audit.reread) && connected {
        load_audit(app, true);
    }
}

// ── Screen ───────────────────────────────────────────────────────────────────

pub struct DiagnosticsScreen;

impl Screen for DiagnosticsScreen {
    fn view(&self, app: &AppState, texts: &Texts) -> ScreenView {
        let state = &app.inspect.diag;
        let panels = match state.part {
            Part::Overview => vec![
                Panel {
                    title: texts.get(keys::SERVICE),
                    lines: service_lines(app, texts),
                    feed: false,
                },
                Panel {
                    title: texts.get(keys::AUDIT),
                    lines: alert_lines(state, texts),
                    feed: false,
                },
                Panel {
                    title: texts.get(keys::EXPLAIN),
                    lines: explain_lines(state, texts),
                    feed: false,
                },
                Panel {
                    title: texts.get(keys::SITE_CHECK),
                    lines: super::site_check::lines(
                        app,
                        texts,
                        match &state.typing {
                            Some((Field::Site, buffer)) => Some(buffer.as_str()),
                            _ => None,
                        },
                    ),
                    feed: false,
                },
                Panel {
                    title: texts.get(keys::ARCHIVE),
                    lines: archive_lines(state, texts),
                    feed: false,
                },
            ],
            Part::Log => vec![Panel {
                title: texts.get(keys::LOGS),
                lines: log_lines(app, texts),
                feed: false,
            }],
            Part::Audit => vec![Panel {
                title: texts.get(keys::AUDIT),
                lines: audit_lines(app, texts),
                feed: false,
            }],
        };
        ScreenView {
            title: texts.get(crate::keys::SCREEN_DIAGNOSTICS),
            panels,
        }
    }

    fn help(&self) -> &'static [Key] {
        &[
            keys::DIAG_HELP_SWITCH,
            keys::DIAG_HELP_ACK,
            keys::DIAG_HELP_EXPLAIN,
            keys::DIAG_HELP_SITE,
            keys::DIAG_HELP_EXPORT,
            keys::ARCHIVE_OPTIONS_HELP,
            keys::DIAG_HELP_LOG_FILTERS,
            keys::DIAG_HELP_LOG_SORT,
            keys::HELP_PAGES,
            keys::HELP_REFRESH,
            keys::EXPLAIN_SUBTITLE,
        ]
    }

    fn plain_help(&self) -> &'static [Key] {
        &[
            keys::DIAG_HELP_SWITCH,
            keys::DIAG_PLAIN_ACK,
            keys::DIAG_PLAIN_EXPLAIN,
            keys::DIAG_PLAIN_SITE,
            keys::DIAG_PLAIN_EXPORT,
            keys::ARCHIVE_OPTIONS_HELP,
            keys::DIAG_PLAIN_LOG_FILTERS,
            keys::DIAG_PLAIN_LOG_SORT,
            keys::PLAIN_PAGES,
            keys::HELP_REFRESH,
        ]
    }

    fn on_show(&self, app: &mut AppState) {
        if !app.link.is_connected() {
            return;
        }
        let state = &app.inspect.diag;
        if !state.loading && (!state.asked || state.reread || state.status_error.is_some()) {
            load_status(app);
        }
        let log = &app.inspect.diag.log;
        if app.inspect.diag.part == Part::Log
            && !log.loading
            && (!log.asked || log.reread || log.error.is_some())
        {
            load_log(app, true);
        }
        let audit = &app.inspect.diag.audit;
        if app.inspect.diag.part == Part::Audit
            && !audit.loading
            && (!audit.asked || audit.reread || audit.error.is_some())
        {
            load_audit(app, true);
        }
    }

    fn takes_focus(&self) -> bool {
        true
    }

    fn captures_keys(&self, app: &AppState) -> bool {
        let state = &app.inspect.diag;
        state.typing.is_some() || matches!(state.ack, Ack::Review { .. })
    }

    fn text_target(&self, app: &AppState) -> crate::paste::TextTarget {
        let state = &app.inspect.diag;
        if state.typing.is_some() && !matches!(state.ack, Ack::Review { .. }) {
            crate::paste::TextTarget::Line
        } else {
            crate::paste::TextTarget::None
        }
    }

    fn on_key(&self, app: &mut AppState, key: KeyEvent) -> bool {
        if app.inspect.diag.restart.reviewing() {
            match answer_key(key) {
                Some(Answer::Yes) => super::audit_restart::answer(app, true),
                Some(Answer::No) => super::audit_restart::answer(app, false),
                None => {}
            }
            return true;
        }
        if matches!(app.inspect.diag.ack, Ack::Review { .. }) {
            match answer_key(key) {
                Some(Answer::Yes) => acknowledge_reviewed(app),
                Some(Answer::No) => app.inspect.diag.ack = Ack::Idle,
                None => {}
            }
            return true;
        }
        if let Some((field, buffer)) = app.inspect.diag.typing.as_mut() {
            let field = *field;
            match edit(buffer, key) {
                Edit::Typing => {}
                Edit::Done(text) => {
                    app.inspect.diag.typing = None;
                    match field {
                        Field::Explain => probe(app, &text, "", ""),
                        Field::Site => super::site_check::start(app, &text),
                        Field::LogKind => {
                            app.inspect.diag.log.kind = text.trim().to_owned();
                            load_log(app, true);
                        }
                        Field::LogCategory => {
                            app.inspect.diag.log.category = text.trim().to_owned();
                            load_log(app, true);
                        }
                    }
                }
                Edit::Cancelled => app.inspect.diag.typing = None,
            }
            return true;
        }
        if key.code == KeyCode::Char('l') {
            switch_part(app);
            return true;
        }
        match app.inspect.diag.part {
            Part::Overview => overview_key(app, key),
            Part::Log => log_key(app, key),
            Part::Audit => audit_key(app, key),
        }
    }

    fn on_line(&self, app: &mut AppState, line: &str) -> bool {
        if app.inspect.diag.restart.reviewing() {
            match answer_line(line) {
                Some(Answer::Yes) => super::audit_restart::answer(app, true),
                Some(Answer::No) => super::audit_restart::answer(app, false),
                None => return false,
            }
            return true;
        }
        if matches!(app.inspect.diag.ack, Ack::Review { .. }) {
            match answer_line(line) {
                Some(Answer::Yes) => acknowledge_reviewed(app),
                Some(Answer::No) => app.inspect.diag.ack = Ack::Idle,
                None => return false,
            }
            return true;
        }
        if command(line) == ("l", "") {
            switch_part(app);
            return true;
        }
        match app.inspect.diag.part {
            Part::Overview => overview_line(app, line),
            Part::Log => log_line(app, line),
            Part::Audit => audit_line(app, line),
        }
    }

    fn on_printed(&self, app: &mut AppState) {
        let state = &mut app.inspect.diag;
        state.printed_alerts = state.alerts.iter().map(|a| a.alert_id.clone()).collect();
    }
}

fn overview_key(app: &mut AppState, key: KeyEvent) -> bool {
    let offered = restart_offered(&app.inspect.diag);
    if key.code == KeyCode::Char('a') && crate::screens::focus_list_first(app) {
        return true;
    }
    let state = &mut app.inspect.diag;
    match key.code {
        KeyCode::Char('a') => acknowledge_selected(app),
        KeyCode::Char('e') => state.typing = Some((Field::Explain, state.explain.input.clone())),
        KeyCode::Char('c') => {
            let host = app.inspect.site.host().to_owned();
            app.inspect.diag.typing = Some((Field::Site, host));
        }
        KeyCode::Char('m') => return super::site_check::move_sign_in(app),
        KeyCode::Char('t') => return super::site_check::open_trace(app),
        KeyCode::Char('x') => export(app),
        KeyCode::Char('d') => archive_option(app, ArchiveChange::Detail),
        KeyCode::Char('o') => archive_option(app, ArchiveChange::SessionOnly),
        KeyCode::Char('b') => archive_option(app, ArchiveChange::Budget),
        KeyCode::Char('k') if offered => super::audit_restart::start(app),
        KeyCode::Char('r') => load_status(app),
        code => {
            let len = state.alerts.len();
            return state.alert_pager.on_key(code, len);
        }
    }
    true
}

fn overview_line(app: &mut AppState, line: &str) -> bool {
    let offered = restart_offered(&app.inspect.diag);
    let state = &mut app.inspect.diag;
    match command(line) {
        ("a", number) => {
            let Some(n) = number.trim().parse::<usize>().ok() else {
                return false;
            };
            let now: Vec<String> = state.alerts.iter().map(|a| a.alert_id.clone()).collect();
            match crate::screens::numbered_now(&state.printed_alerts, &now, n) {
                crate::screens::Numbered::At(at) => {
                    state.alert_pager.selected = at;
                    acknowledge_selected(app);
                }
                crate::screens::Numbered::Gone => state.ack = Ack::Gone(n),
                crate::screens::Numbered::NoSuch => return false,
            }
        }
        ("e", host) => probe(app, host, "", ""),
        ("c", host) => super::site_check::start(app, host),
        ("m", "") => return super::site_check::move_sign_in(app),
        ("t", "") => return super::site_check::open_trace(app),
        ("k", "") if offered => super::audit_restart::start(app),
        ("x", "") => export(app),
        ("d", "") => archive_option(app, ArchiveChange::Detail),
        ("o", "") => archive_option(app, ArchiveChange::SessionOnly),
        ("b", "") => archive_option(app, ArchiveChange::Budget),
        ("r", "") => load_status(app),
        _ => return false,
    }
    true
}

#[derive(Clone, Copy)]
enum ArchiveChange {
    Detail,
    SessionOnly,
    Budget,
}

/// The next archive's options; one being written keeps what it was asked with.
/// Which logs and how much are kept for the next run; the detail level is not.
fn archive_option(app: &mut AppState, change: ArchiveChange) {
    let options = &mut app.inspect.diag.archive_options;
    match change {
        ArchiveChange::Detail => {
            options.full_detail = !options.full_detail;
            return;
        }
        ArchiveChange::SessionOnly => options.session_only = !options.session_only,
        ArchiveChange::Budget => {
            options.budget = (options.budget + 1) % ARCHIVE_LOG_BUDGETS_MIB.len();
        }
    }
    let (all_logs, budget) = (!options.session_only, options.budget_mib());
    let prefs = &mut app.settings.prefs;
    prefs.archive_all_logs = all_logs;
    prefs.archive_log_budget_mib = budget;
    // Unsaved, the choice still holds for this run.
    let _ = app.settings.save_prefs();
}

/// The archive options the user kept from an earlier run. A size the list
/// does not offer (an edited file) reads as no cap.
pub fn restore_archive_options(app: &mut AppState) {
    let prefs = app.settings.prefs;
    let options = &mut app.inspect.diag.archive_options;
    options.session_only = !prefs.archive_all_logs;
    options.budget = ARCHIVE_LOG_BUDGETS_MIB
        .iter()
        .position(|mib| *mib == prefs.archive_log_budget_mib)
        .unwrap_or(0);
}

fn log_key(app: &mut AppState, key: KeyEvent) -> bool {
    let state = &mut app.inspect.diag;
    let len = state.log.entries.len();
    match key.code {
        KeyCode::Char('v') => {
            state.log.level = (state.log.level + 1) % LEVELS.len();
            load_log(app, true);
        }
        KeyCode::Char('/') => state.typing = Some((Field::LogKind, state.log.kind.clone())),
        KeyCode::Char('c') => {
            state.typing = Some((Field::LogCategory, state.log.category.clone()));
        }
        KeyCode::Char('o') => state.log.sort = state.log.sort.next_column(),
        KeyCode::Char('d') => state.log.sort = state.log.sort.reversed(),
        KeyCode::Char('s') => {
            state.log.all_history = !state.log.all_history;
            load_log(app, true);
        }
        KeyCode::Char('r') => load_log(app, true),
        KeyCode::PageDown if state.log.pager.page_start() + super::PAGE_ROWS >= len => {
            more_log(app);
        }
        KeyCode::Down if state.log.pager.selected + 1 >= len => more_log(app),
        code => return state.log.pager.on_key(code, len),
    }
    true
}

fn log_line(app: &mut AppState, line: &str) -> bool {
    let state = &mut app.inspect.diag;
    match command(line) {
        ("n", "") => more_log(app),
        ("p", "") => state.log.pager.previous_page(),
        ("v", "") => {
            state.log.level = (state.log.level + 1) % LEVELS.len();
            load_log(app, true);
        }
        ("/", kind) => {
            state.log.kind = kind.to_owned();
            load_log(app, true);
        }
        ("c", category) => {
            state.log.category = category.to_owned();
            load_log(app, true);
        }
        ("o", "") => state.log.sort = state.log.sort.next_column(),
        ("d", "") => state.log.sort = state.log.sort.reversed(),
        ("s", "") => {
            state.log.all_history = !state.log.all_history;
            load_log(app, true);
        }
        ("r", "") => load_log(app, true),
        _ => return false,
    }
    true
}

fn audit_key(app: &mut AppState, key: KeyEvent) -> bool {
    let audit = &mut app.inspect.diag.audit;
    let len = audit.entries.len();
    match key.code {
        KeyCode::Char('r') => load_audit(app, true),
        KeyCode::Char('o') => audit.sort = audit.sort.next_column(),
        KeyCode::Char('d') => audit.sort = audit.sort.reversed(),
        KeyCode::PageDown if audit.pager.page_start() + super::PAGE_ROWS >= len => {
            more_audit(app);
        }
        KeyCode::Down if audit.pager.selected + 1 >= len => more_audit(app),
        code => return audit.pager.on_key(code, len),
    }
    true
}

fn audit_line(app: &mut AppState, line: &str) -> bool {
    match command(line) {
        ("n", "") => more_audit(app),
        ("p", "") => app.inspect.diag.audit.pager.previous_page(),
        ("r", "") => load_audit(app, true),
        ("o", "") => {
            let audit = &mut app.inspect.diag.audit;
            audit.sort = audit.sort.next_column();
        }
        ("d", "") => {
            let audit = &mut app.inspect.diag.audit;
            audit.sort = audit.sort.reversed();
        }
        _ => return false,
    }
    true
}

// ── Pictures ─────────────────────────────────────────────────────────────────

/// What the service says is wrong with a part of itself (a start after an
/// unasked stop, say), as it words it; the DNS case has its own line above.
pub(super) fn health_warning_lines(health: &ServiceHealthResponse) -> Vec<ViewLine> {
    const SHOWN: usize = 5;
    health
        .components
        .iter()
        .filter(|c| !matches!(c.severity.as_str(), "ok" | "healthy" | "info"))
        .filter_map(|c| {
            let message = c.message.as_deref().filter(|m| !m.is_empty())?;
            // Said by their own translated lines.
            if message.contains(nrr_shared::ipc_payloads::SYSTEM_DNS_NOT_RESTORED)
                || message.starts_with(nrr_shared::ipc_payloads::RULES_BOOK_UNREADABLE)
            {
                return None;
            }
            Some(ViewLine::new(vec![Segment::state(
                format!("{}: {}", display_text(&c.component), display_text(message)),
                StateTone::Caution,
            )]))
        })
        .take(SHOWN)
        .collect()
}

fn service_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let state = &app.inspect.diag;
    let mut lines = Vec::new();
    let health = state.health.as_ref().and_then(|h| h.as_ref().ok());
    // No answer is "unavailable", never a remembered "running".
    let service_state = health
        .filter(|_| app.link.is_connected())
        .map_or("unavailable", |h| h.service_state.as_str());
    let (word, tone) = match service_state {
        "running" => (keys::SERVICE_RUNNING, StateTone::Good),
        "degraded" => (keys::SERVICE_DEGRADED, StateTone::Caution),
        "starting" => (keys::SERVICE_STARTING, StateTone::Caution),
        "recovery-required" => (keys::SERVICE_RECOVERY, StateTone::Bad),
        _ => (keys::SERVICE_UNAVAILABLE, StateTone::Bad),
    };
    lines.push(ViewLine::new(vec![Segment::state(texts.get(word), tone)]));
    if let Some(h) = health {
        if let Some(revision) = h.active_revision_id.as_deref().filter(|r| !r.is_empty()) {
            lines.push(ViewLine::text(format!(
                "{}: {revision}",
                texts.get(keys::REVISION)
            )));
        }
        // Revisions the service holds unapplied, from its diagnostics answer.
        if let Some(pending) = state
            .status
            .as_ref()
            .map(|s| s.service_health.pending_changes)
            .filter(|n| *n > 0)
        {
            lines.push(ViewLine::text(format!(
                "{}: {pending}",
                texts.get(keys::PENDING)
            )));
        }
        let health_json = serde_json::to_value(h).unwrap_or_default();
        if nrr_client_logic::system_dns::not_restored(&health_json) {
            lines.push(ViewLine::new(vec![Segment::state(
                texts.get(keys::DNS_NOT_RESTORED),
                StateTone::Bad,
            )]));
        }
        if nrr_client_logic::diagnostics::rules_book_unreadable(&health_json) {
            lines.push(ViewLine::new(vec![Segment::state(
                texts.get(keys::RULES_BOOK_UNREADABLE),
                StateTone::Caution,
            )]));
        }
        lines.extend(health_warning_lines(h));
    }
    if state.loading && state.status.is_none() {
        lines.push(ViewLine::text(texts.get(keys::LOADING)));
    }
    let live = state
        .status
        .as_ref()
        .filter(|s| s.origin != DiagnosticsDataOrigin::Unavailable);
    match live {
        None if state.asked && !state.loading => {
            lines.push(ViewLine::text(texts.get(keys::NO_DATA)));
            if let Some(slug) = &state.status_error {
                lines.push(ViewLine::text(error_text(texts, slug)));
            }
        }
        None => {}
        Some(status) => {
            if status.stale || !app.link.is_connected() {
                lines.push(ViewLine::text(texts.get(keys::STALE)));
            }
            if let Some(boot) = boot_timing(texts, status) {
                lines.push(ViewLine::text(boot));
            }
            let cache = if status.cache_health.healthy {
                keys::CACHE_HEALTHY
            } else {
                keys::CACHE_STALE
            };
            lines.push(ViewLine::text(format!(
                "{} · {}: {}",
                texts.get(cache),
                texts.get(keys::CACHE_ENTRIES),
                status.cache_health.entry_count
            )));
            let log = &status.log_health;
            let mut storage = texts.fill(keys::LOG_FILES, &[("count", log.file_count.to_string())]);
            if log.dropped_count > 0 {
                storage.push_str(" · ");
                storage.push_str(&texts.fill(
                    keys::LOG_DROPPED,
                    &[("count", log.dropped_count.to_string())],
                ));
            }
            if !log.dir_writable {
                storage.push_str(" · ");
                storage.push_str(&texts.get(keys::LOG_DIR_NOT_WRITABLE));
            }
            lines.push(ViewLine::text(storage));
            lines.extend(missing_capability_lines(
                texts,
                &status.missing_capabilities,
            ));
            lines.extend(dns_tamper_lines(texts, status));
        }
    }
    lines.push(ViewLine::text(texts.get(keys::DIAG_HELP_SWITCH)));
    lines
}

/// What this machine cannot do and what that costs: silent while nothing is
/// missing.
fn missing_capability_lines(texts: &Texts, missing: &[String]) -> Vec<ViewLine> {
    if missing.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![ViewLine::text(texts.get(keys::MISSING_HEADING))];
    for slug in missing {
        let title = texts.dynamic(&format!("platform.missing.{slug}.title"), slug);
        let effect = texts.dynamic(&format!("platform.missing.{slug}.effect"), "");
        lines.push(ViewLine::text(format!("  {title}")));
        if !effect.is_empty() {
            lines.push(ViewLine::text(format!("    {effect}")));
        }
    }
    lines
}

/// The provider-tampering card: silent while no site was affected. The example
/// names come from other hosts, so they pass the display cleaner.
fn dns_tamper_lines(texts: &Texts, status: &DiagnosticsStatusDto) -> Vec<ViewLine> {
    let card = &status.dns_tamper;
    if card.affected_hosts == 0 {
        return Vec::new();
    }
    let mut lines = vec![
        ViewLine::text(texts.get(keys::DNS_TAMPER_HEADING)),
        ViewLine::text(texts.fill(
            keys::DNS_TAMPER_BODY,
            &[("count", card.affected_hosts.to_string())],
        )),
    ];
    if !card.examples.is_empty() {
        let names: Vec<_> = card.examples.iter().map(|n| display_text(n)).collect();
        lines.push(ViewLine::text(
            texts.fill(keys::DNS_TAMPER_EXAMPLES, &[("names", names.join(", "))]),
        ));
    }
    lines
}

/// Where the service's start sat against the boot's sign-in, in seconds; none
/// when the host cannot tell, so silence is never read as an all-clear.
fn boot_timing(texts: &Texts, status: &DiagnosticsStatusDto) -> Option<String> {
    let health = &status.service_health;
    let key = match health.start_relative_to_sign_in.as_str() {
        "after" => keys::STARTED_AFTER,
        "before" => keys::STARTED_BEFORE,
        _ => return None,
    };
    let gap = health.start_sign_in_gap_ms? as f64 / 1000.0;
    Some(fill_numbered(&texts.get(key), &[&format!("{gap:.1}")]))
}

fn alert_lines(state: &DiagState, texts: &Texts) -> Vec<ViewLine> {
    let mut lines = Vec::new();
    let live = state
        .status
        .as_ref()
        .filter(|s| s.origin != DiagnosticsDataOrigin::Unavailable);
    lines.push(ViewLine::new(vec![match live {
        Some(s) if !s.security_status.audit_chain_ok => {
            Segment::state(texts.get(keys::AUDIT_BROKEN), StateTone::Bad)
        }
        Some(_) => Segment::state(texts.get(keys::AUDIT_OK), StateTone::Good),
        None => Segment::plain(texts.get(keys::NO_DATA)),
    }]));
    lines.extend(super::audit_restart::lines(
        &state.restart,
        restart_offered(state),
        texts,
    ));
    let unread = state.alerts.iter().filter(|a| a.state == "active").count();
    if unread > 0 {
        lines.push(ViewLine::new(vec![Segment::state(
            format!("{} {unread}", texts.get(keys::ALERTS_UNREAD)),
            StateTone::Bad,
        )]));
    }
    if state.alerts_unreadable {
        lines.push(ViewLine::text(texts.get(keys::ALERTS_UNREADABLE)));
    }
    if state.alerts.is_empty() && !state.alerts_unreadable {
        let none = if state.alerts_known {
            keys::ALERTS_NONE
        } else {
            keys::NO_DATA
        };
        lines.push(ViewLine::text(texts.get(none)));
    }
    let mut pager = state.alert_pager;
    pager.clamp(state.alerts.len());
    lines.extend(page_lines(texts, pager, state.alerts.len(), false, |i| {
        alert_row(texts, &state.alerts[i])
    }));
    if let Some(alert) = state.alerts.get(pager.selected) {
        let slug = alert.kind.replace('_', "-");
        let detail = texts.dynamic(&format!("diag.alert.kind-detail.{slug}"), "");
        if !detail.is_empty() {
            lines.push(ViewLine::text(detail));
        }
        if !alert.raised_file.is_empty() {
            lines.push(ViewLine::text(alert.raised_file.clone()));
        }
        if alert.state == "active" && alert.alert_id != OTHER_PRINCIPAL_ALERT_ID {
            lines.push(ViewLine::text(format!("a: {}", texts.get(keys::ALERT_ACK))));
        }
    }
    lines.extend(ack_lines(state, texts));
    lines
}

/// The window offers the restart only for a broken chain the service can
/// restart on this platform.
fn restart_offered(state: &DiagState) -> bool {
    nrr_shared::platform_profile::PlatformProfile::current()
        .supports
        .audit_chain_restart
        && state
            .status
            .as_ref()
            .filter(|s| s.origin != DiagnosticsDataOrigin::Unavailable)
            .is_some_and(|s| !s.security_status.audit_chain_ok)
}

fn alert_row(texts: &Texts, alert: &AlertItem) -> String {
    let title = if alert.state == "active" {
        keys::ALERT_ACTIVE
    } else {
        keys::ALERT_ACKNOWLEDGED
    };
    let slug = alert.kind.replace('_', "-");
    let kind = texts.dynamic(&format!("diag.alert.kind.{slug}"), &alert.kind);
    format!("{}: {kind} · {}", texts.get(title), alert.reason_code)
}

fn ack_lines(state: &DiagState, texts: &Texts) -> Vec<ViewLine> {
    match &state.ack {
        Ack::Idle => Vec::new(),
        Ack::Working => vec![ViewLine::text(texts.get(keys::ALERT_ACKING))],
        Ack::Gone(n) => vec![ViewLine::text(
            texts.fill(crate::keys::PLAIN_NUMBER_GONE, &[("n", n.to_string())]),
        )],
        Ack::Done(Ok(())) => vec![ViewLine::text(texts.get(keys::ALERT_ACK_DONE))],
        Ack::Done(Err(slug)) => vec![ViewLine::text(format!(
            "{}{}",
            texts.get(keys::ALERT_ACK_FAILED),
            error_text(texts, slug)
        ))],
        Ack::Review { kind, rows, .. } => {
            let body = if rows.is_empty() {
                keys::REVIEW_EMPTY
            } else if kind == "key_reset_with_existing_data" {
                keys::REVIEW_KEY_RESET
            } else {
                keys::REVIEW_TAMPER
            };
            let mut lines = vec![
                ViewLine::new(vec![Segment::strong(texts.get(keys::REVIEW_TITLE))]),
                ViewLine::text(texts.get(body)),
            ];
            lines.extend(
                rows.iter()
                    .map(|row| ViewLine::text(format!("- {}", review_row(texts, row)))),
            );
            lines.push(ViewLine::text(texts.get(keys::YES_NO)));
            lines
        }
    }
}

/// One rule set the acknowledgement would trust, in the GUI dialog's words.
fn review_row(texts: &Texts, row: &UnverifiedRowDto) -> String {
    let scope = texts.get(if row.baseline {
        keys::REVIEW_BASELINE
    } else {
        keys::REVIEW_USER
    });
    let when = wall_clock(row.created_at.saturating_mul(1000));
    if row.row.row_kind == IntegrityRowKind::ActivePointer {
        return texts.fill(keys::REVIEW_POINTER, &[("scope", &scope), ("when", &when)]);
    }
    let source = row.source.clone().unwrap_or_default();
    let mut parts = vec![
        when,
        texts.dynamic(&format!("diag.alert.review.source.{source}"), &source),
        scope,
    ];
    if let Some(count) = row.rule_count {
        parts.push(texts.fill(keys::REVIEW_RULES, &[("count", count.to_string())]));
    }
    if row.status.as_deref() == Some("active") {
        parts.push(texts.get(keys::REVIEW_IN_USE));
    }
    parts.join(" · ")
}

fn explain_lines(state: &DiagState, texts: &Texts) -> Vec<ViewLine> {
    let explain = &state.explain;
    let mut lines = Vec::new();
    match &state.typing {
        Some((Field::Explain, buffer)) => {
            lines.extend(typing_lines(texts, &texts.get(keys::EXPLAIN_INPUT), buffer));
        }
        _ if !explain.input.is_empty() => lines.push(ViewLine::text(format!(
            "{}: {}",
            texts.get(keys::EXPLAIN_INPUT),
            explain.input
        ))),
        _ => {}
    }
    if explain.probing {
        lines.push(ViewLine::text(texts.get(keys::EXPLAIN_PROBING)));
    }
    match &explain.result {
        None if !explain.probing => lines.push(ViewLine::text(texts.get(keys::EXPLAIN_EMPTY))),
        None => {}
        Some(Err(slug)) if slug == "input-required" => {
            lines.push(ViewLine::text(texts.get(keys::EXPLAIN_REQUIRED)));
        }
        Some(Err(slug)) => lines.push(ViewLine::text(error_text(texts, slug))),
        Some(Ok(probe)) => {
            lines.push(ViewLine::new(vec![Segment::strong(format!(
                "{}  →  {}",
                probe.input,
                verdict_label(texts, probe)
            ))]));
            if !probe.reason_key.is_empty() {
                let mut reason = texts.dynamic(&probe.reason_key, &probe.reason_key);
                if !probe.blocking_ip.is_empty() {
                    reason.push_str(&format!(" ({})", probe.blocking_ip));
                }
                lines.push(ViewLine::text(reason));
            }
            if !probe.enforcement.is_empty() {
                let id = format!("diag.explain.enforcement.{}", probe.enforcement);
                let mut caveat = texts.dynamic(&id, &probe.enforcement);
                if probe.shared > 0 {
                    caveat.push_str(&format!(" ({}/{})", probe.shared, probe.total));
                }
                lines.push(ViewLine::text(caveat));
            }
        }
    }
    lines.push(ViewLine::text(format!(
        "e: {}",
        texts.get(keys::EXPLAIN_SUBTITLE)
    )));
    lines
}

fn archive_lines(state: &DiagState, texts: &Texts) -> Vec<ViewLine> {
    let options = state.archive_options;
    let budget = match options.budget_mib() {
        0 => texts.get(keys::ARCHIVE_BUDGET_UNLIMITED),
        mib => format!("{mib} MiB"),
    };
    let mut lines = vec![ViewLine::text(texts.get(keys::ARCHIVE_NOTE))];
    match &state.archive {
        Archive::Ready => lines.push(ViewLine::text(texts.get(keys::ARCHIVE_READY))),
        Archive::Busy => lines.push(ViewLine::text(texts.get(keys::ARCHIVE_BUSY))),
        Archive::Saved {
            path,
            size,
            readable,
        } => {
            lines.push(ViewLine::text(texts.fill(
                keys::ARCHIVE_SAVED,
                &[
                    ("path", path.clone()),
                    ("size", format_storage_bytes(*size)),
                ],
            )));
            if !readable {
                lines.push(ViewLine::text(texts.get(keys::ARCHIVE_UNREADABLE)));
            }
        }
        Archive::Failed(slug) => lines.push(ViewLine::text(format!(
            "{}: {}",
            texts.get(keys::ARCHIVE_FAILED),
            error_text(texts, slug)
        ))),
    }
    lines.push(ViewLine::text(format!("x: {}", texts.get(keys::ARCHIVE))));
    lines.push(ViewLine::text(format!(
        "{}: {} · {}: {} · {}: {budget}",
        texts.get(keys::ARCHIVE_LEVEL),
        texts.get(if options.full_detail {
            keys::ARCHIVE_LEVEL_FULL
        } else {
            keys::ARCHIVE_LEVEL_STANDARD
        }),
        texts.get(keys::ARCHIVE_SESSION_ONLY),
        texts.get(if options.session_only {
            keys::YES
        } else {
            keys::NO
        }),
        texts.get(keys::ARCHIVE_BUDGET),
    )));
    // The warning only where it applies: the panel shares a screen.
    if options.full_detail {
        lines.push(ViewLine::text(texts.get(keys::ARCHIVE_LEVEL_CAPTION)));
    }
    lines
}

fn log_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let state = &app.inspect.diag;
    let log = &state.log;
    let kind = if log.kind.is_empty() {
        texts.get(keys::LOGS_KIND_ANY)
    } else {
        log.kind.clone()
    };
    let range = texts.get(if log.all_history {
        keys::LOGS_ALL
    } else {
        keys::LOGS_SESSION
    });
    let category = if log.category.is_empty() {
        texts.get(keys::LOGS_KIND_ANY)
    } else {
        display_text(&log.category).into_owned()
    };
    let kind = display_text(&kind).into_owned();
    let mut lines = vec![
        ViewLine::text(format!(
            "{}: {} · {}: {category} · {}: {kind} · {}: {range}",
            texts.get(keys::LOGS_LEVEL),
            level_label(texts, LEVELS[log.level]),
            texts.get(keys::LOGS_CATEGORY),
            texts.get(keys::LOGS_KIND),
            texts.get(keys::LOGS_RANGE),
        )),
        ViewLine::text(sort_words(texts, log.sort, LogColumn::label)),
    ];
    match &state.typing {
        Some((Field::LogKind, buffer)) => {
            lines.extend(typing_lines(texts, &texts.get(keys::LOGS_KIND), buffer));
        }
        Some((Field::LogCategory, buffer)) => {
            lines.extend(typing_lines(texts, &texts.get(keys::LOGS_CATEGORY), buffer));
        }
        _ => {}
    }
    if !app.link.is_connected() && log.asked {
        lines.push(ViewLine::text(texts.get(keys::STALE)));
    }
    if let Some(slug) = &log.error {
        lines.push(ViewLine::text(format!(
            "{}: {}",
            texts.get(keys::LOGS_FAILED),
            error_text(texts, slug)
        )));
    }
    if log.loading && log.entries.is_empty() {
        lines.push(ViewLine::text(texts.get(keys::LOADING)));
    } else if log.asked && !log.loading && log.error.is_none() && log.entries.is_empty() {
        lines.push(ViewLine::text(texts.get(keys::LOGS_EMPTY)));
    }
    let mut pager = log.pager;
    pager.clamp(log.entries.len());
    let order = log_order(&log.entries, log.sort);
    lines.extend(page_lines(
        texts,
        pager,
        log.entries.len(),
        log.cursor.is_some(),
        |i| log_row(texts, &log.entries[order[i]]),
    ));
    lines.push(ViewLine::text(texts.get(keys::DIAG_HELP_SWITCH)));
    lines
}

fn audit_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let audit = &app.inspect.diag.audit;
    let mut lines = vec![ViewLine::text(sort_words(
        texts,
        audit.sort,
        AuditColumn::label,
    ))];
    if !app.link.is_connected() && audit.asked {
        lines.push(ViewLine::text(texts.get(keys::STALE)));
    }
    if let Some(slug) = &audit.error {
        lines.push(ViewLine::text(format!(
            "{}: {}",
            texts.get(keys::LOGS_FAILED),
            error_text(texts, slug)
        )));
    }
    if audit.loading && audit.entries.is_empty() {
        lines.push(ViewLine::text(texts.get(keys::LOADING)));
    } else if audit.asked && !audit.loading && audit.error.is_none() && audit.entries.is_empty() {
        lines.push(ViewLine::text(texts.get(keys::AUDIT_EMPTY)));
    }
    let mut pager = audit.pager;
    pager.clamp(audit.entries.len());
    let order = audit_order(&audit.entries, audit.sort);
    lines.extend(page_lines(
        texts,
        pager,
        audit.entries.len(),
        audit.cursor.is_some(),
        |i| audit_row(texts, &audit.entries[order[i]]),
    ));
    lines.push(ViewLine::text(texts.get(keys::DIAG_HELP_SWITCH)));
    lines
}

#[cfg(test)]
mod verdict_tests {
    use super::*;
    use crate::testing::texts_en;

    fn probe(route: &str, enforcement: &str) -> Probe {
        Probe {
            input: "a.example".into(),
            route: route.into(),
            reason_key: String::new(),
            enforcement: enforcement.into(),
            shared: 0,
            total: 0,
            blocking_ip: String::new(),
        }
    }

    /// A host no rule names waits under "Everything" while the additional
    /// connection is down, on either route: shown as blocked, like the rest.
    #[test]
    fn a_waiting_host_is_shown_as_blocked() {
        let texts = texts_en();
        let blocked = texts.get(keys::VERDICT_BLOCK);
        for route in ["primary", "secondary"] {
            let shown = verdict_label(
                &texts,
                &probe(route, "everything-waits-when-secondary-down"),
            );
            assert!(shown.ends_with(&blocked), "{shown}");
        }
        let allowed = verdict_label(&texts, &probe("primary", ""));
        assert!(
            allowed.ends_with(&texts.get(keys::VERDICT_PERMIT)),
            "{allowed}"
        );
    }

    /// Each missing capability is named with what it costs, under one heading;
    /// a machine that lacks nothing shows no card at all.
    #[test]
    fn missing_capabilities_are_named_with_their_effect() {
        let texts = texts_en();
        assert!(missing_capability_lines(&texts, &[]).is_empty());

        let shown: Vec<String> = missing_capability_lines(
            &texts,
            &["user-routes".to_owned(), "block-reports".to_owned()],
        )
        .iter()
        .map(ViewLine::plain_text)
        .collect();
        assert_eq!(shown[0], texts.get(keys::MISSING_HEADING));
        for slug in ["user-routes", "block-reports"] {
            for part in ["title", "effect"] {
                let text = texts.dynamic(&format!("platform.missing.{slug}.{part}"), "");
                assert!(!text.is_empty(), "{slug}.{part} has no text");
                assert!(
                    shown.iter().any(|line| line.trim() == text),
                    "{slug}.{part} not shown: {shown:?}"
                );
            }
        }
        assert!(
            !shown.iter().any(|line| line.contains("user-routes")),
            "a slug is never shown raw: {shown:?}"
        );
    }
}
