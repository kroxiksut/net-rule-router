//! `conn-history.{list,clear,settings.set}` — each user's connection history.
//!
//! Every operation acts on the caller's own history, elevated or not: a week
//! of where a person went is theirs, not machine diagnostics, so the
//! diagnostics audience does not widen it. None needs elevation. The history
//! rides the trace ring, so a ring without one answers "unavailable", never
//! "empty".

use super::*;

use nrr_shared::ipc_payloads::{
    ConnHistoryClearRequest, ConnHistoryClearResponse, ConnHistoryEntryDto, ConnHistoryListRequest,
    ConnHistoryListResponse, ConnHistoryPageKey, ConnHistorySettingsSetRequest,
    ConnHistorySettingsSetResponse, CONN_HISTORY_MAX_PROGRAM_FILTER, CONN_HISTORY_VERDICTS,
};
use nrr_storage::conn_history::MAX_RETENTION_DAYS;

use super::conn_trace::exe_name;
use crate::conn_history::{ConnHistory, ConnHistoryCursor, HistoryError, HistoryRead};
use crate::conn_observation_consumer::now_unix_ms;

const OP_LIST: &str = "conn-history.list";
const OP_CLEAR: &str = "conn-history.clear";
const OP_SETTINGS: &str = "conn-history.settings.set";

/// Writes act for a person; an unattributed connection owns no history.
fn caller(op: &'static str, ctx: &IpcRequestContext) -> Result<String, IpcError> {
    let sid = ctx.caller_stored();
    if sid.is_empty() {
        return Err(IpcError {
            code: IpcErrorCode::Unauthorized,
            message: format!("{op}: this request carries no user identity"),
            diagnostics_id: None,
        });
    }
    Ok(sid.to_owned())
}

fn history_of(op: &'static str, ring: &ConnectionTraceRing) -> Result<Arc<ConnHistory>, IpcError> {
    ring.history().cloned().ok_or_else(|| unavailable(op))
}

fn unavailable(op: &'static str) -> IpcError {
    IpcError {
        code: IpcErrorCode::ServiceDegraded,
        message: format!("{op}: the connection history is unavailable"),
        diagnostics_id: None,
    }
}

fn history_error(op: &'static str, e: HistoryError) -> IpcError {
    match e {
        HistoryError::Unavailable => unavailable(op),
        HistoryError::InvalidDays(_) => malformed_msg(op, e.to_string()),
        HistoryError::Storage(_) => internal(op, e.to_string()),
    }
}

fn decode<T: serde::de::DeserializeOwned + Default>(
    op: &'static str,
    request: &IpcRequestEnvelope,
) -> Result<T, IpcError> {
    if request.payload.is_null() {
        return Ok(T::default());
    }
    serde_json::from_value(request.payload.clone()).map_err(|e| malformed(op, e))
}

// ── list ─────────────────────────────────────────────────────────────────────

pub struct ConnHistoryListHandler {
    ring: Arc<ConnectionTraceRing>,
}

impl ConnHistoryListHandler {
    pub fn new(ring: Arc<ConnectionTraceRing>) -> Self {
        Self { ring }
    }
}

impl IpcHandler for ConnHistoryListHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: ConnHistoryListRequest = decode(OP_LIST, request)?;
        let program = req
            .program
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty());
        if program.is_some_and(|p| p.len() > CONN_HISTORY_MAX_PROGRAM_FILTER) {
            return Err(malformed_msg(OP_LIST, "program filter too long"));
        }
        let verdict = req.verdict.as_deref().filter(|v| !v.is_empty());
        if verdict.is_some_and(|v| !CONN_HISTORY_VERDICTS.contains(&v)) {
            return Err(malformed_msg(OP_LIST, "unknown verdict"));
        }
        let page_key = req
            .pagination
            .cursor
            .as_ref()
            .map(|c| {
                ConnHistoryPageKey::decode(c)
                    .ok_or_else(|| malformed_msg(OP_LIST, "cursor was not issued by this list"))
            })
            .transpose()?;
        let now_ms = now_unix_ms();
        let from_ms = u64::try_from(req.from_unix_ms).unwrap_or(0);
        // A continuing page keeps the end its first page was read to, so the
        // order the cursor points into cannot move under it.
        let to_ms = match &page_key {
            Some(k) => u64::try_from(k.to_ms).unwrap_or(0),
            None => req
                .to_unix_ms
                .map_or(now_ms, |t| u64::try_from(t).unwrap_or(0)),
        };
        if to_ms < from_ms {
            return Err(malformed_msg(OP_LIST, "the period ends before it starts"));
        }

        let caller_sid = ctx.caller_stored().to_owned();
        let empty =
            |available: bool, prefs: nrr_storage::ConnHistoryPrefs| ConnHistoryListResponse {
                page: PageResult::single_page(Vec::new()),
                enabled: prefs.enabled,
                retention_days: prefs.retention_days,
                max_retention_days: MAX_RETENTION_DAYS,
                available,
                removed: 0,
                skipped: 0,
            };
        let Some(history) = self.ring.history().cloned() else {
            return serialise(OP_LIST, empty(false, Default::default()));
        };
        let prefs = history.prefs_for(&caller_sid);
        // The caller comes from the connection, never from the request; an
        // unattributed one owns no history.
        if caller_sid.is_empty() {
            return serialise(OP_LIST, empty(history.is_available(), prefs));
        }

        let limit = req.pagination.effective_page_size();
        let after = page_key.as_ref().map(|k| ConnHistoryCursor {
            last_ms: k.last_ms,
            program: k.program.clone(),
            host: k.host.clone(),
            remote_ip: k.remote_ip.clone(),
            route: k.route.clone(),
            verdict: k.verdict.clone(),
            blocked_by: k.blocked_by.clone(),
        });
        let read = HistoryRead {
            principal: Some(caller_sid.as_str()),
            from_ms,
            to_ms,
            program,
            verdict,
            after: after.as_ref(),
            limit: limit.saturating_add(1),
        };
        let (rows, removed, skipped) = match history.read(&read, now_ms) {
            Ok(answer) => answer,
            Err(HistoryError::Unavailable) => {
                return serialise(OP_LIST, empty(false, prefs));
            }
            Err(e) => return Err(history_error(OP_LIST, e)),
        };
        let has_more = rows.len() as u32 > limit;
        let next_cursor = rows
            .get(limit as usize - 1)
            .filter(|_| has_more)
            .map(|last| {
                let key = ConnHistoryCursor::after(last);
                ConnHistoryPageKey {
                    to_ms: i64::try_from(to_ms).unwrap_or(i64::MAX),
                    last_ms: key.last_ms,
                    program: key.program,
                    host: key.host,
                    remote_ip: key.remote_ip,
                    route: key.route,
                    verdict: key.verdict,
                    blocked_by: key.blocked_by,
                }
                .encode()
            });
        let items = rows
            .into_iter()
            .take(limit as usize)
            .map(|e| ConnHistoryEntryDto {
                process: if e.program.is_empty() {
                    "?".to_string()
                } else {
                    exe_name(Some(e.program.as_str()))
                },
                process_path: e.program,
                host: e.host,
                remote_ip: e.remote_ip,
                route: e.route,
                verdict: e.verdict,
                blocked_by: e.blocked_by,
                block_reason: e.block_reason,
                first_seen_ms: e.first_ms,
                last_seen_ms: e.last_ms,
                attempts: e.attempts,
            })
            .collect();
        serialise(
            OP_LIST,
            ConnHistoryListResponse {
                page: PageResult {
                    items,
                    next_cursor,
                    total_count: None,
                    stale: false,
                },
                enabled: prefs.enabled,
                retention_days: prefs.retention_days,
                max_retention_days: MAX_RETENTION_DAYS,
                available: true,
                removed,
                skipped,
            },
        )
    }
}

// ── clear ────────────────────────────────────────────────────────────────────

pub struct ConnHistoryClearHandler {
    ring: Arc<ConnectionTraceRing>,
}

impl ConnHistoryClearHandler {
    pub fn new(ring: Arc<ConnectionTraceRing>) -> Self {
        Self { ring }
    }
}

impl CheckedIpcHandler for ConnHistoryClearHandler {
    type Checked = String;

    fn precheck(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<String, IpcError> {
        let _: ConnHistoryClearRequest = decode(OP_CLEAR, request)?;
        history_of(OP_CLEAR, &self.ring)?;
        caller(OP_CLEAR, ctx)
    }

    fn execute(
        &self,
        checked: Prechecked<String>,
        _request: &IpcRequestEnvelope,
        _ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        let history = history_of(OP_CLEAR, &self.ring)?;
        let erased = history
            .clear(&checked)
            .map_err(|e| history_error(OP_CLEAR, e))?;
        serialise(OP_CLEAR, ConnHistoryClearResponse { erased })
    }
}

// ── settings ─────────────────────────────────────────────────────────────────

pub struct ConnHistorySettingsSetHandler {
    ring: Arc<ConnectionTraceRing>,
}

impl ConnHistorySettingsSetHandler {
    pub fn new(ring: Arc<ConnectionTraceRing>) -> Self {
        Self { ring }
    }
}

/// The caller and what they asked to change, validated.
pub struct CheckedHistorySettings {
    principal: String,
    enabled: Option<bool>,
    retention_days: Option<u32>,
}

impl CheckedIpcHandler for ConnHistorySettingsSetHandler {
    type Checked = CheckedHistorySettings;

    fn precheck(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<CheckedHistorySettings, IpcError> {
        let req: ConnHistorySettingsSetRequest = decode(OP_SETTINGS, request)?;
        if let Some(days) = req.retention_days {
            if !(1..=MAX_RETENTION_DAYS).contains(&days) {
                return Err(malformed_msg(
                    OP_SETTINGS,
                    format!("retention-days must be 1..={MAX_RETENTION_DAYS}"),
                ));
            }
        }
        history_of(OP_SETTINGS, &self.ring)?;
        Ok(CheckedHistorySettings {
            principal: caller(OP_SETTINGS, ctx)?,
            enabled: req.enabled,
            retention_days: req.retention_days,
        })
    }

    fn execute(
        &self,
        checked: Prechecked<CheckedHistorySettings>,
        _request: &IpcRequestEnvelope,
        _ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        let history = history_of(OP_SETTINGS, &self.ring)?;
        let prefs = history
            .set_prefs(&checked.principal, checked.enabled, checked.retention_days)
            .map_err(|e| history_error(OP_SETTINGS, e))?;
        serialise(
            OP_SETTINGS,
            ConnHistorySettingsSetResponse {
                enabled: prefs.enabled,
                retention_days: prefs.retention_days,
            },
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::conn_observation_consumer::ConnectionTraceRecord;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use nrr_platform_api::conn_observe::egress::{EgressInterface, EgressRole};
    use nrr_platform_api::conn_observe::{ConnectionVerdict, TransportProtocol};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const ALICE: &str = "S-1-5-21-1-2-3-1001";
    const BOB: &str = "S-1-5-21-1-2-3-1002";

    fn ctx(sid: Option<&str>, elevated: bool) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: elevated,
            caller_principal: sid
                .and_then(|s| nrr_domain::user_principal::UserPrincipal::from_windows_sid(s).ok()),
            caller_pid: None,
        }
    }

    fn req(op: IpcOperationName, payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-ch".into(),
            correlation_id: None,
            operation: op,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    fn row(owner: &str, program: &str, last: u8) -> ConnectionTraceRecord {
        ConnectionTraceRecord {
            process_path: Some(program.to_owned()),
            user_sid: Some(owner.to_owned()),
            protocol: TransportProtocol::Tcp,
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 5)), 50_000),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), 443),
            egress: EgressInterface {
                ifindex: 2,
                role: EgressRole::Secondary,
            },
            verdict: ConnectionVerdict::Permit,
            blocked_by_nrr: None,
            nrr_drop_spec_id: None,
            nrr_block_reason: None,
            observed_unix_ms: Some(now_unix_ms()),
            remote_names: None,
        }
    }

    fn wired() -> (tempfile::TempDir, Arc<ConnectionTraceRing>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let ring = Arc::new(ConnectionTraceRing::new(16));
        let history = ConnHistory::open(dir.path().join("nrr_conn_history.db"));
        assert!(ring.attach_history(Arc::new(history)));
        ring.push(row(ALICE, r"C:\Apps\alice.exe", 1));
        ring.push(row(BOB, r"C:\Apps\bob.exe", 2));
        (dir, ring)
    }

    fn list(ring: &Arc<ConnectionTraceRing>, ctx: &IpcRequestContext) -> ConnHistoryListResponse {
        let value = ConnHistoryListHandler::new(Arc::clone(ring))
            .handle(
                &req(IpcOperationName::ConnHistoryList, serde_json::Value::Null),
                ctx,
            )
            .expect("list");
        serde_json::from_value(value).expect("decode")
    }

    #[test]
    fn every_caller_reads_only_their_own_history_elevated_or_not() {
        let (_dir, ring) = wired();
        let alice = list(&ring, &ctx(Some(ALICE), false));
        let programs: Vec<&str> = alice
            .page
            .items
            .iter()
            .map(|e| e.process.as_str())
            .collect();
        assert_eq!(
            programs,
            ["alice.exe"],
            "another user's history is not visible"
        );
        assert!(alice.available && alice.enabled);
        assert_eq!(alice.retention_days, 7);
        assert_eq!(alice.page.items[0].route, "secondary");
        let elevated = list(&ring, &ctx(Some(ALICE), true));
        let programs: Vec<&str> = elevated
            .page
            .items
            .iter()
            .map(|e| e.process.as_str())
            .collect();
        assert_eq!(
            programs,
            ["alice.exe"],
            "an administrator's rights do not open another person's history"
        );
        assert!(
            list(&ring, &ctx(None, false)).page.items.is_empty(),
            "an unattributed caller owns nothing"
        );
    }

    fn page(
        handler: &ConnHistoryListHandler,
        cursor: Option<nrr_shared::pagination::PageCursor>,
    ) -> ConnHistoryListResponse {
        let payload = serde_json::to_value(ConnHistoryListRequest {
            pagination: nrr_shared::pagination::PaginationParams {
                cursor,
                page_size: 1,
            },
            ..ConnHistoryListRequest::default()
        })
        .expect("encode");
        let value = handler
            .handle(
                &req(IpcOperationName::ConnHistoryList, payload),
                &ctx(Some(ALICE), false),
            )
            .expect("page");
        serde_json::from_value(value).expect("decode")
    }

    #[test]
    fn a_walk_over_pages_sees_each_destination_once_while_rows_arrive() {
        let (_dir, ring) = wired();
        ring.push(row(ALICE, r"C:\Apps\alice.exe", 3));
        ring.push(row(ALICE, r"C:\Apps\alice.exe", 4));
        let handler = ConnHistoryListHandler::new(Arc::clone(&ring));
        let mut seen = Vec::new();
        let mut cursor = None;
        loop {
            let answer = page(&handler, cursor);
            seen.extend(answer.page.items.into_iter().map(|e| e.remote_ip));
            // A destination that turns newest mid-walk must not jump back
            // to the start nor repeat the last row of the page before.
            ring.push(row(ALICE, r"C:\Apps\alice.exe", 1));
            cursor = answer.page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert_eq!(unique.len(), 3, "{seen:?}");
    }

    #[test]
    fn a_cursor_the_list_did_not_issue_is_refused() {
        let (_dir, ring) = wired();
        let handler = ConnHistoryListHandler::new(ring);
        let err = handler
            .handle(
                &req(
                    IpcOperationName::ConnHistoryList,
                    serde_json::json!({ "pagination": { "cursor": "200|conn-history", "page_size": 1 } }),
                ),
                &ctx(Some(ALICE), false),
            )
            .expect_err("refused");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn a_ring_without_a_history_says_unavailable_not_empty() {
        let ring = Arc::new(ConnectionTraceRing::new(4));
        let answer = list(&ring, &ctx(Some(ALICE), false));
        assert!(!answer.available);
        let refused = ConnHistoryClearHandler::new(ring)
            .handle(
                &req(IpcOperationName::ConnHistoryClear, serde_json::json!({})),
                &ctx(Some(ALICE), false),
            )
            .expect_err("nothing to clear");
        assert_eq!(refused.code, IpcErrorCode::ServiceDegraded);
    }

    #[test]
    fn hostile_list_requests_are_refused_before_any_read() {
        let (_dir, ring) = wired();
        let handler = ConnHistoryListHandler::new(ring);
        let too_long = "x".repeat(CONN_HISTORY_MAX_PROGRAM_FILTER + 1);
        for payload in [
            serde_json::json!({ "program": too_long }),
            serde_json::json!({ "verdict": "drop table" }),
            serde_json::json!({ "from-unix-ms": 10, "to-unix-ms": 5 }),
            serde_json::json!({ "from-unix-ms": "soon" }),
        ] {
            let err = handler
                .handle(
                    &req(IpcOperationName::ConnHistoryList, payload),
                    &ctx(Some(ALICE), false),
                )
                .expect_err("refused");
            assert_eq!(err.code, IpcErrorCode::MalformedRequest);
        }
    }

    #[test]
    fn clearing_erases_the_callers_history_only() {
        let (_dir, ring) = wired();
        let value = ConnHistoryClearHandler::new(Arc::clone(&ring))
            .handle(
                &req(IpcOperationName::ConnHistoryClear, serde_json::Value::Null),
                &ctx(Some(ALICE), false),
            )
            .expect("clear");
        let cleared: ConnHistoryClearResponse = serde_json::from_value(value).expect("decode");
        assert_eq!(cleared.erased, 1);
        assert!(list(&ring, &ctx(Some(ALICE), false)).page.items.is_empty());
        assert_eq!(list(&ring, &ctx(Some(BOB), false)).page.items.len(), 1);
    }

    #[test]
    fn settings_precheck_refuses_bad_days_and_anonymous_callers() {
        let (_dir, ring) = wired();
        let handler = ConnHistorySettingsSetHandler::new(Arc::clone(&ring));
        for days in [0, MAX_RETENTION_DAYS + 1] {
            let err = handler
                .precheck(
                    &req(
                        IpcOperationName::ConnHistorySettingsSet,
                        serde_json::json!({ "retention-days": days }),
                    ),
                    &ctx(Some(ALICE), false),
                )
                .err()
                .expect("refused");
            assert_eq!(err.code, IpcErrorCode::MalformedRequest);
        }
        let err = handler
            .precheck(
                &req(
                    IpcOperationName::ConnHistorySettingsSet,
                    serde_json::json!({ "enabled": false }),
                ),
                &ctx(None, false),
            )
            .err()
            .expect("refused");
        assert_eq!(err.code, IpcErrorCode::Unauthorized);
    }

    #[test]
    fn switching_off_is_the_callers_own_and_stops_their_recording() {
        let (_dir, ring) = wired();
        let value = ConnHistorySettingsSetHandler::new(Arc::clone(&ring))
            .handle(
                &req(
                    IpcOperationName::ConnHistorySettingsSet,
                    serde_json::json!({ "enabled": false, "retention-days": 3 }),
                ),
                &ctx(Some(ALICE), false),
            )
            .expect("set");
        let set: ConnHistorySettingsSetResponse = serde_json::from_value(value).expect("decode");
        assert_eq!((set.enabled, set.retention_days), (false, 3));
        ring.push(row(ALICE, r"C:\Apps\later.exe", 3));
        let alice = list(&ring, &ctx(Some(ALICE), false));
        assert!(!alice.enabled);
        assert!(alice.page.items.iter().all(|e| e.process != "later.exe"));
        assert!(
            list(&ring, &ctx(Some(BOB), false)).enabled,
            "Bob's choice is his"
        );
    }
}
