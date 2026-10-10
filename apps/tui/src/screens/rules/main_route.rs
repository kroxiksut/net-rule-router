//! "Check the main route": the service tries the additional route's rule
//! hosts over the main link, and the list shows what each one answered. The
//! verdicts arrive with later `rules.list` reads, polled while the service
//! still has hosts to try; only the verdicts are taken from them, so edits on
//! screen survive.

use std::collections::HashSet;
use std::time::Duration;

use nrr_client_logic::rules_table::{RuleType, TargetRoute};
use nrr_ipc_client::{ipc_operation_timeout, IpcClient};
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    AutoRuleCandidatesProbeRequest, AutoRuleCandidatesProbeResponse, RulesListResponse,
};
use serde_json::json;

use super::apply::Failure;
use super::table::Row;
use super::{text, Note};
use crate::backend::{Job, Reply};
use crate::i18n::{Key, Texts};
use crate::state::AppState;

/// How long the service gets between two reads of its progress.
pub const POLL: Duration = Duration::from_secs(2);

/// A check in progress.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Check {
    /// The hosts asked about; the summary counts their verdicts.
    pub hosts: Vec<String>,
    /// How many the service took; `None` until it answered.
    pub accepted: Option<u32>,
    /// Hosts it has yet to try, as the last read said.
    pub pending: Option<u32>,
}

#[derive(Debug, Default)]
pub struct MainRoute {
    pub check: Option<Check>,
    /// A check was started this session: the column stays from then on.
    pub asked: bool,
}

/// Whether the list shows the main-route column: once any rule has a verdict
/// or a check was started.
pub fn column_shown(app: &AppState) -> bool {
    app.rules.main_route.asked || app.rules.table.rows.iter().any(|r| r.main_route.is_some())
}

/// The column's word for a row and its explanation; `None` leaves it empty.
pub fn cell(row: &Row) -> Option<(Key, Key)> {
    match row.main_route.as_deref() {
        Some("answered") => Some((text::MAIN_ROUTE_ANSWERED, text::MAIN_ROUTE_ANSWERED_HINT)),
        Some("silent") => Some((text::MAIN_ROUTE_SILENT, text::MAIN_ROUTE_SILENT_HINT)),
        Some("no-address") => Some((
            text::MAIN_ROUTE_NO_ADDRESS,
            text::MAIN_ROUTE_NO_ADDRESS_HINT,
        )),
        Some("unclear") => Some((text::MAIN_ROUTE_UNCLEAR, text::MAIN_ROUTE_UNCLEAR_HINT)),
        _ if row.rule.rule_type == RuleType::Zone
            && row.rule.target_route == TargetRoute::Secondary =>
        {
            Some((text::MAIN_ROUTE_ZONE, text::MAIN_ROUTE_ZONE_HINT))
        }
        _ => None,
    }
}

/// The line saying how far a running check is.
pub fn progress_text(check: &Check, texts: &Texts) -> String {
    match (check.accepted, check.pending) {
        (None, _) => texts.get(text::CHECK_BUSY),
        (Some(total), None) => texts.fill(text::CHECK_STARTED, &[("count", total.to_string())]),
        (Some(total), Some(pending)) => texts.fill(
            text::CHECK_PROGRESS,
            &[
                ("done", total.saturating_sub(pending).to_string()),
                ("total", total.to_string()),
            ],
        ),
    }
}

/// `c`: ask about every additional-route host on screen. A running check is
/// not started twice.
pub fn start(app: &mut AppState) -> bool {
    if app.rules.main_route.check.is_some() {
        return true;
    }
    if !app.link.is_connected() {
        app.rules.note = Some(Note::new(crate::keys::ROUTING_DISCONNECTED));
        return true;
    }
    let hosts = app.rules.table.check_hosts();
    if hosts.is_empty() {
        app.rules.note = Some(Note::new(text::NOTHING_TO_CHECK));
        return true;
    }
    let rules = &mut app.rules;
    rules.note = None;
    rules.main_route.asked = true;
    rules.main_route.check = Some(Check {
        hosts: hosts.clone(),
        ..Check::default()
    });
    app.outbox.push(probe_job(hosts));
    true
}

fn probe_job(hosts: Vec<String>) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let op = IpcOperationName::AutoRuleCandidatesProbe;
        let request = AutoRuleCandidatesProbeRequest {
            rule_hostnames: hosts,
            ..AutoRuleCandidatesProbeRequest::default()
        };
        let answer = serde_json::to_value(&request)
            .map_err(|_| Failure::code("serialization-failed"))
            .and_then(|payload| {
                client
                    .call(op, payload, ipc_operation_timeout(op))
                    .map_err(|e| Failure::of(&e))
            })
            .and_then(|v| {
                serde_json::from_value::<AutoRuleCandidatesProbeResponse>(v)
                    .map_err(|_| Failure::code("bad-response"))
            });
        Reply::new(move |app| probed(app, answer))
    })
}

fn probed(app: &mut AppState, answer: Result<AutoRuleCandidatesProbeResponse, Failure>) {
    let rules = &mut app.rules;
    let Some(check) = rules.main_route.check.as_mut() else {
        return;
    };
    match answer {
        Ok(answer) if answer.accepted > 0 => {
            check.accepted = Some(answer.accepted);
            app.outbox.push_after(POLL, poll_job());
        }
        Ok(_) => {
            rules.main_route.check = None;
            rules.note = Some(Note::new(text::CHECK_NOTHING));
        }
        Err(failure) => {
            rules.main_route.check = None;
            rules.note = Some(Note::failed(text::CHECK_FAILED, failure));
        }
    }
}

fn poll_job() -> Job {
    Box::new(|client: &dyn IpcClient| {
        let op = IpcOperationName::RulesList;
        let result = client
            .call(op, json!({}), ipc_operation_timeout(op))
            .map_err(|e| Failure::of(&e))
            .and_then(|v| {
                serde_json::from_value::<RulesListResponse>(v)
                    .map_err(|_| Failure::code("bad-response"))
            });
        Reply::new(move |app| polled(app, result))
    })
}

fn polled(app: &mut AppState, result: Result<RulesListResponse, Failure>) {
    let rules = &mut app.rules;
    if rules.main_route.check.is_none() {
        return;
    }
    let list = match result {
        Ok(list) => list,
        Err(failure) => {
            rules.main_route.check = None;
            rules.note = Some(Note::failed(text::CHECK_FAILED, failure));
            return;
        }
    };
    rules.table.merge_main_route(&list.rows);
    if list.main_route_pending > 0 {
        if let Some(check) = rules.main_route.check.as_mut() {
            check.pending = Some(list.main_route_pending);
        }
        app.outbox.push_after(POLL, poll_job());
        return;
    }
    let Some(check) = rules.main_route.check.take() else {
        return;
    };
    let (answered, silent) = tally(&rules.table.rows, &check.hosts);
    let other = check.hosts.len().saturating_sub(answered + silent);
    rules.note = Some(Note::with(
        text::CHECK_DONE,
        vec![
            ("answered", answered.to_string()),
            ("silent", silent.to_string()),
            ("other", other.to_string()),
        ],
    ));
}

/// Hosts among `asked` the main route reached and did not, each counted once.
fn tally(rows: &[Row], asked: &[String]) -> (usize, usize) {
    let asked: HashSet<&str> = asked.iter().map(String::as_str).collect();
    let mut counted = HashSet::new();
    let (mut answered, mut silent) = (0, 0);
    for row in rows {
        let Some(host) = row.check_host() else {
            continue;
        };
        if !asked.contains(host.as_str()) || !counted.insert(host) {
            continue;
        }
        match row.main_route.as_deref() {
            Some("answered") => answered += 1,
            Some("silent") => silent += 1,
            _ => {}
        }
    }
    (answered, silent)
}
