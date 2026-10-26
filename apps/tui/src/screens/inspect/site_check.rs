//! "Is it us or the site?" — the GUI's site check in Diagnostics.
//! `diagnostics.site-check.run` starts it on the service and
//! `diagnostics.site-check.result` is read until it is done; the verdict's own
//! step follows: the cookie how-to, the sign-in names moved through the
//! Rules screen's "several rules", which the user confirms, or the trace.

use std::time::{Duration, Instant};

use nrr_client_logic::rules_table::TargetRoute;
use nrr_ipc_client::IpcClient;
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    SiteCheckNameDto, SiteCheckReport, SiteCheckRequest, SiteCheckStatus, SITE_CHECK_STATE_DONE,
    SITE_CHECK_VERDICT_FINE, SITE_CHECK_VERDICT_NOT_ANSWERING, SITE_CHECK_VERDICT_ROUTE_DOWN,
    SITE_CHECK_VERDICT_SIGN_IN_SPLIT,
};
use serde_json::json;

use super::{bad_response, call, error_text, keys, queue, unencodable};
use crate::backend::{Job, Reply};
use crate::i18n::Texts;
use crate::screens::ScreenId;
use crate::state::AppState;
use crate::view::{Segment, StateTone, ViewLine};

/// Between two reads of a running check.
const POLL: Duration = Duration::from_millis(700);
/// How long one check is followed before it is reported as too slow.
const FOLLOW_FOR: Duration = Duration::from_secs(30);

#[derive(Debug, Default)]
pub struct SiteCheckState {
    host: String,
    running: bool,
    generation: u64,
    started: Option<Instant>,
    result: Option<Result<SiteCheckReport, String>>,
}

impl SiteCheckState {
    pub fn host(&self) -> &str {
        &self.host
    }
}

/// Start checking `host`; the answer is followed until it is done.
pub fn start(app: &mut AppState, host: &str) {
    let state = &mut app.inspect.site;
    state.host = host.trim().to_owned();
    state.generation += 1;
    state.result = None;
    if state.host.is_empty() {
        state.running = false;
        state.result = Some(Err("input-required".to_owned()));
        return;
    }
    state.running = true;
    state.started = Some(Instant::now());
    let generation = state.generation;
    let request = SiteCheckRequest {
        host: state.host.clone(),
    };
    queue(app, move |client| {
        let answer = serde_json::to_value(&request)
            .map_err(unencodable)
            .and_then(|payload| call(client, IpcOperationName::SiteCheckRun, payload))
            .and_then(|v| serde_json::from_value::<SiteCheckStatus>(v).map_err(bad_response));
        Reply::new(move |app| followed(app, generation, answer))
    });
}

fn poll_job(generation: u64) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let answer = call(client, IpcOperationName::SiteCheckResultGet, json!({}))
            .and_then(|v| serde_json::from_value::<SiteCheckStatus>(v).map_err(bad_response));
        Reply::new(move |app| followed(app, generation, answer))
    })
}

fn followed(app: &mut AppState, generation: u64, answer: Result<SiteCheckStatus, String>) {
    let state = &mut app.inspect.site;
    if state.generation != generation || !state.running {
        return;
    }
    let status = match answer {
        Ok(status) => status,
        Err(slug) => {
            state.running = false;
            state.result = Some(Err(slug));
            return;
        }
    };
    if status.state == SITE_CHECK_STATE_DONE {
        if let Some(report) = status.report {
            state.running = false;
            state.result = Some(Ok(report));
            return;
        }
    }
    if !status.host.is_empty() {
        state.host = status.host;
    }
    if state.started.is_some_and(|at| at.elapsed() > FOLLOW_FOR) {
        state.running = false;
        state.result = Some(Err("timeout".to_owned()));
        return;
    }
    app.outbox.push_after(POLL, poll_job(generation));
}

/// The verdict's move: the sign-in names to the site's route, through the
/// Rules screen. `false` when the last check offered none.
pub fn move_sign_in(app: &mut AppState) -> bool {
    let Some(Ok(report)) = app.inspect.site.result.as_ref() else {
        return false;
    };
    if report.verdict != SITE_CHECK_VERDICT_SIGN_IN_SPLIT || report.move_names.is_empty() {
        return false;
    }
    let route = TargetRoute::from_slug(&report.site_route);
    let names = report.move_names.clone();
    crate::screens::rules::start_moving(app, route, &names)
}

fn route_text(texts: &Texts, route: &str) -> String {
    texts.get(match route {
        "secondary" => keys::SECONDARY,
        "blocked" => keys::ROUTE_DENIED,
        _ => keys::PRIMARY,
    })
}

fn name_line(texts: &Texts, n: &SiteCheckNameDto) -> String {
    let mut parts = vec![
        format!(
            "{} ({})",
            display_text(&n.name),
            texts.dynamic(&format!("diag.site-check.role.{}", n.role), &n.role)
        ),
        if n.address.is_empty() {
            texts.get(keys::SITE_NO_ADDRESS)
        } else {
            n.address.clone()
        },
        route_text(texts, &n.route),
        texts.dynamic(&format!("diag.site-check.answer.{}", n.answer), &n.answer),
    ];
    if let Some(code) = n.status {
        parts.push(texts.fill(keys::SITE_STATUS, &[("code", code.to_string())]));
    }
    if !n.redirects.is_empty() {
        let hosts: Vec<String> = n
            .redirects
            .iter()
            .map(|h| display_text(h).into_owned())
            .collect();
        parts.push(texts.fill(keys::SITE_REDIRECTS, &[("hosts", hosts.join(" → "))]));
    }
    parts.join(" · ")
}

/// The panel: what is being typed, the check under way, or its report.
pub fn lines(app: &AppState, texts: &Texts, typing: Option<&str>) -> Vec<ViewLine> {
    let state = &app.inspect.site;
    if let Some(buffer) = typing {
        return super::typing_lines(texts, &texts.get(keys::SITE_INPUT), buffer);
    }
    if state.running {
        return vec![ViewLine::text(
            texts.fill(keys::SITE_RUNNING, &[("host", display_text(&state.host))]),
        )];
    }
    let report = match &state.result {
        None => return vec![ViewLine::text(texts.get(keys::SITE_SUBTITLE))],
        Some(Err(slug)) if slug == "input-required" => {
            return vec![ViewLine::text(texts.get(keys::SITE_REQUIRED))];
        }
        Some(Err(slug)) => {
            return vec![ViewLine::text(format!(
                "{}{}",
                texts.get(keys::SITE_FAILED),
                error_text(texts, slug)
            ))];
        }
        Some(Ok(report)) => report,
    };
    let fine = report.verdict == SITE_CHECK_VERDICT_FINE;
    let mut lines = vec![
        ViewLine::new(vec![Segment::state(
            texts.dynamic(
                &format!("diag.site-check.verdict.{}.title", report.verdict),
                &report.verdict,
            ),
            if fine {
                StateTone::Good
            } else {
                StateTone::Caution
            },
        )]),
        ViewLine::text(texts.dynamic(
            &format!("diag.site-check.verdict.{}.body", report.verdict),
            "",
        )),
    ];
    lines.extend(
        report
            .names
            .iter()
            .map(|n| ViewLine::text(format!("  {}", name_line(texts, n)))),
    );
    if fine {
        lines.push(ViewLine::text(texts.get(keys::SITE_COOKIES)));
        for key in [
            keys::SITE_COOKIES_CHROME,
            keys::SITE_COOKIES_EDGE,
            keys::SITE_COOKIES_FIREFOX,
        ] {
            lines.push(ViewLine::text(format!("  {}", texts.get(key))));
        }
        lines.push(ViewLine::text(texts.get(keys::SITE_COOKIES_NOTE)));
    }
    if report.verdict == SITE_CHECK_VERDICT_SIGN_IN_SPLIT && !report.move_names.is_empty() {
        lines.push(ViewLine::text(texts.get(keys::SITE_MOVE)));
    }
    if leads_to_trace(report) {
        lines.push(ViewLine::text(texts.get(keys::SITE_TRACE)));
    }
    lines
}

/// The site does not answer where it is routed: what its connections did is
/// in the trace.
fn leads_to_trace(report: &SiteCheckReport) -> bool {
    report.verdict == SITE_CHECK_VERDICT_NOT_ANSWERING
        || report.verdict == SITE_CHECK_VERDICT_ROUTE_DOWN
}

/// The verdict's step to the connection trace. `false` when the last check
/// did not lead there.
pub fn open_trace(app: &mut AppState) -> bool {
    if !matches!(app.inspect.site.result.as_ref(), Some(Ok(r)) if leads_to_trace(r)) {
        return false;
    }
    app.open(ScreenId::Trace);
    true
}
