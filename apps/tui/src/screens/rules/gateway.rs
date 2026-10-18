//! `v`: a rule for a VPN's gateway, so that VPN connects through the channel
//! the user picks (the window's "Other VPNs (corporate)"). Asks for the
//! program and the channel, reads where the program connected lately
//! (`vpn.gateway-candidates.list`), and adds the chosen or typed address to
//! the list on screen; `s` applies it like any other edit.

use crossterm::event::{KeyCode, KeyEvent};
use nrr_client_logic::rules_table::RuleRow;
use nrr_client_logic::vpn_gateway::{gateway_rule_draft, program_file_name};
use nrr_client_logic::Route;
use nrr_ipc_client::{ipc_operation_timeout, IpcClient};
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    VpnGatewayCandidateDto, VpnGatewayCandidatesRequest, VpnGatewayCandidatesResponse,
};
use nrr_shared::rules_json::FREE_MAX_RULES;

use super::apply::Failure;
use super::table::{Row, VerdictStatus};
use super::{edit_text, text, Mode, Note};
use crate::backend::{Job, Reply};
use crate::i18n::{Key, Texts};
use crate::state::AppState;
use crate::view::{Segment, ViewLine};

/// The channels offered, in the order the window lists them.
const CHANNELS: [Route; 2] = [Route::Primary, Route::Secondary];

#[derive(Debug)]
pub enum Stage {
    Program { text: String },
    Channel { program: String, cursor: usize },
    Loading { program: String, route: Route },
    Pick(Pick),
}

#[derive(Debug)]
pub struct Pick {
    pub program: String,
    pub route: Route,
    pub candidates: Vec<VpnGatewayCandidateDto>,
    pub omitted: u32,
    pub observer_active: bool,
    pub failure: Option<Failure>,
    pub cursor: usize,
    pub text: String,
    /// The last value tried was neither an address nor a host name.
    pub invalid: bool,
}

/// `v` on the list.
pub fn start(app: &mut AppState) -> bool {
    if super::locked(app) {
        return true;
    }
    if !app.link.is_connected() {
        app.rules.note = Some(Note::new(crate::keys::ROUTING_DISCONNECTED));
        return true;
    }
    app.rules.mode = Mode::Gateway(Box::new(Stage::Program {
        text: String::new(),
    }));
    true
}

fn channel_label(route: Route) -> Key {
    match route {
        Route::Primary => text::ROUTE_PRIMARY,
        Route::Secondary => text::ROUTE_SECONDARY,
    }
}

fn lookup_job(program: String) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let op = IpcOperationName::VpnGatewayCandidatesList;
        let request = VpnGatewayCandidatesRequest {
            program: program.clone(),
        };
        let answer = serde_json::to_value(&request)
            .map_err(|_| Failure::code("serialization-failed"))
            .and_then(|payload| {
                client
                    .call(op, payload, ipc_operation_timeout(op))
                    .map_err(|e| Failure::of(&e))
            })
            .and_then(|v| {
                serde_json::from_value::<VpnGatewayCandidatesResponse>(v)
                    .map_err(|_| Failure::code("bad-response"))
            });
        Reply::new(move |app| found(app, &program, answer))
    })
}

/// The answer arrives; a lookup the user left meanwhile is dropped.
fn found(app: &mut AppState, asked: &str, answer: Result<VpnGatewayCandidatesResponse, Failure>) {
    let Mode::Gateway(stage) = &app.rules.mode else {
        return;
    };
    let Stage::Loading { program, route } = stage.as_ref() else {
        return;
    };
    if program != asked {
        return;
    }
    let mut pick = Pick {
        program: program.clone(),
        route: *route,
        candidates: Vec::new(),
        omitted: 0,
        observer_active: true,
        failure: None,
        cursor: 0,
        text: String::new(),
        invalid: false,
    };
    match answer {
        Ok(answer) => {
            pick.candidates = answer.candidates;
            pick.omitted = answer.omitted;
            pick.observer_active = answer.observer_active;
        }
        Err(failure) => pick.failure = Some(failure),
    }
    app.rules.mode = Mode::Gateway(Box::new(Stage::Pick(pick)));
}

fn channel_chosen(app: &mut AppState, program: String, cursor: usize) {
    let route = CHANNELS.get(cursor).copied().unwrap_or(Route::Secondary);
    app.rules.mode = Mode::Gateway(Box::new(Stage::Loading {
        program: program.clone(),
        route,
    }));
    app.outbox.push(lookup_job(program));
}

/// What `typed` names: a candidate's address for its number, else itself.
fn value_for(pick: &Pick, typed: &str) -> Option<String> {
    let typed = typed.trim();
    if typed.is_empty() {
        return pick.candidates.get(pick.cursor).map(|c| c.address.clone());
    }
    match typed.parse::<usize>() {
        Ok(n) if (1..=pick.candidates.len()).contains(&n) => {
            Some(pick.candidates[n - 1].address.clone())
        }
        _ => Some(typed.to_owned()),
    }
}

/// Adds the rule for `typed` and goes back to the list; a value that is no
/// address or host keeps the question open.
fn add(app: &mut AppState, mut pick: Pick, typed: &str) {
    let Some(value) = value_for(&pick, typed) else {
        app.rules.mode = Mode::Gateway(Box::new(Stage::Pick(pick)));
        return;
    };
    let template = if app.rules.gateway_comment.is_empty() {
        text::GATEWAY_COMMENT.en.to_owned()
    } else {
        app.rules.gateway_comment.clone()
    };
    let draft = gateway_rule_draft(&value, &pick.program, pick.route, &template).filter(|d| {
        super::table::Verdict::of(&d.rule_type, &d.value).status != VerdictStatus::Error
    });
    let Some(draft) = draft else {
        pick.invalid = true;
        pick.text = typed.to_owned();
        app.rules.mode = Mode::Gateway(Box::new(Stage::Pick(pick)));
        return;
    };
    let table = &mut app.rules.table;
    let rule = RuleRow {
        id: table.next_free_id(),
        enabled: true,
        rule_type: draft.rule_type,
        match_value: draft.value,
        target_route: draft.route.into(),
        verify: false,
        comment: draft.comment,
        origin: None,
    };
    if let Some(existing) = table.duplicate_of(&rule, None) {
        table.select(existing);
        app.rules.note = Some(Note::with(
            text::GATEWAY_ALREADY,
            vec![("count", "1".to_owned())],
        ));
        return;
    }
    if table.user_rule_count() >= FREE_MAX_RULES {
        app.rules.note = Some(Note::with(
            text::LIMIT_REACHED,
            vec![("max", FREE_MAX_RULES.to_string())],
        ));
        return;
    }
    table.rows.push(Row::new(rule));
    table.select(table.rows.len() - 1);
    app.rules.note = Some(Note::new(text::RULE_ADDED).then(Note::new(text::GATEWAY_APPLY_HINT)));
}

// ── Keys ─────────────────────────────────────────────────────────────────────

pub fn on_key(app: &mut AppState, stage: Stage, key: KeyEvent) -> bool {
    if key.code == KeyCode::Esc {
        return true;
    }
    match stage {
        Stage::Program { mut text } => match key.code {
            KeyCode::Enter => {
                let program = program_file_name(&text).to_owned();
                if program.is_empty() {
                    app.rules.mode = Mode::Gateway(Box::new(Stage::Program { text }));
                } else {
                    app.rules.mode = Mode::Gateway(Box::new(Stage::Channel { program, cursor: 1 }));
                }
            }
            _ => {
                let used = edit_text(&mut text, key);
                app.rules.mode = Mode::Gateway(Box::new(Stage::Program { text }));
                return used.unwrap_or(true);
            }
        },
        Stage::Channel {
            program,
            mut cursor,
        } => match key.code {
            KeyCode::Enter => channel_chosen(app, program, cursor),
            KeyCode::Char(c) if c.to_digit(10).is_some_and(|n| (1..=2).contains(&n)) => {
                let n = c.to_digit(10).unwrap_or(2) as usize;
                channel_chosen(app, program, n - 1);
            }
            KeyCode::F(1) => {
                app.rules.mode = Mode::Gateway(Box::new(Stage::Channel { program, cursor }));
                return false;
            }
            code => {
                match code {
                    KeyCode::Up => cursor = cursor.saturating_sub(1),
                    KeyCode::Down => cursor = (cursor + 1).min(CHANNELS.len() - 1),
                    _ => {}
                }
                app.rules.mode = Mode::Gateway(Box::new(Stage::Channel { program, cursor }));
            }
        },
        stage @ Stage::Loading { .. } => {
            app.rules.mode = Mode::Gateway(Box::new(stage));
            return key.code != KeyCode::F(1);
        }
        Stage::Pick(mut pick) => match key.code {
            KeyCode::Enter => {
                let typed = std::mem::take(&mut pick.text);
                add(app, pick, &typed);
            }
            KeyCode::Up if pick.text.is_empty() => {
                pick.cursor = pick.cursor.saturating_sub(1);
                app.rules.mode = Mode::Gateway(Box::new(Stage::Pick(pick)));
            }
            KeyCode::Down if pick.text.is_empty() => {
                pick.cursor = (pick.cursor + 1).min(pick.candidates.len().saturating_sub(1));
                app.rules.mode = Mode::Gateway(Box::new(Stage::Pick(pick)));
            }
            _ => {
                let used = edit_text(&mut pick.text, key);
                if used == Some(true) {
                    pick.invalid = false;
                }
                app.rules.mode = Mode::Gateway(Box::new(Stage::Pick(pick)));
                return used.unwrap_or(true);
            }
        },
    }
    true
}

/// Line mode: `!` cancels at any point; Enter alone keeps what is shown.
pub fn on_line(app: &mut AppState, stage: Stage, line: &str) {
    if line == "!" {
        return;
    }
    match stage {
        Stage::Program { text } => {
            let typed = if line.is_empty() {
                text
            } else {
                line.to_owned()
            };
            let program = program_file_name(&typed).to_owned();
            app.rules.mode = Mode::Gateway(Box::new(if program.is_empty() {
                Stage::Program { text: typed }
            } else {
                Stage::Channel { program, cursor: 1 }
            }));
        }
        Stage::Channel { program, cursor } => match line.trim() {
            "" => channel_chosen(app, program, cursor),
            "1" => channel_chosen(app, program, 0),
            "2" => channel_chosen(app, program, 1),
            _ => app.rules.mode = Mode::Gateway(Box::new(Stage::Channel { program, cursor })),
        },
        stage @ Stage::Loading { .. } => app.rules.mode = Mode::Gateway(Box::new(stage)),
        Stage::Pick(pick) => add(app, pick, line),
    }
}

pub fn plain_prompt(stage: &Stage) -> Option<Key> {
    match stage {
        Stage::Channel { .. } => Some(text::PLAIN_CHOICE_PROMPT),
        _ => Some(text::PLAIN_PROMPT),
    }
}

// ── View ─────────────────────────────────────────────────────────────────────

/// `YYYY-MM-DD HH:MM`, local time; UTC under test so views do not depend on
/// the zone of the machine running them.
fn stamp(ms: i64) -> String {
    let Some(at) = chrono::DateTime::from_timestamp_millis(ms).filter(|_| ms > 0) else {
        return "—".to_owned();
    };
    #[cfg(test)]
    let at = at.fixed_offset();
    #[cfg(not(test))]
    let at = at.with_timezone(&chrono::Local).fixed_offset();
    at.format("%Y-%m-%d %H:%M").to_string()
}

fn marker(on: bool) -> &'static str {
    if on {
        "> "
    } else {
        "  "
    }
}

fn candidate_text(c: &VpnGatewayCandidateDto, texts: &Texts) -> String {
    let ports = c
        .ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let mut line = texts.fill(
        text::GATEWAY_CANDIDATE,
        &[
            ("address", c.address.clone()),
            ("ports", ports),
            ("time", stamp(c.last_seen_ms)),
        ],
    );
    if !c.hostname.is_empty() {
        line.push_str(" · ");
        let host = display_text(&c.hostname);
        line.push_str(&texts.fill(text::GATEWAY_BY_NAME, &[("host", &host)]));
    }
    line
}

pub fn lines(stage: &Stage, texts: &Texts) -> Vec<ViewLine> {
    let mut lines = vec![ViewLine::text(texts.get(text::GATEWAY_NOTE))];
    match stage {
        Stage::Program { text: typed } => {
            lines.push(ViewLine::new(vec![Segment::strong(
                texts.get(text::GATEWAY_PROGRAM_QUESTION),
            )]));
            lines.push(ViewLine::text(format!("> {typed}")));
            lines.push(ViewLine::text(texts.get(text::INPUT_HINT)));
        }
        Stage::Channel { program, cursor } => {
            lines.push(ViewLine::text(program.clone()));
            lines.push(ViewLine::new(vec![Segment::strong(
                texts.get(text::GATEWAY_CHANNEL_QUESTION),
            )]));
            lines.extend(CHANNELS.iter().enumerate().map(|(i, route)| {
                ViewLine::text(format!(
                    "{}{}. {}",
                    marker(i == *cursor),
                    i + 1,
                    texts.get(channel_label(*route))
                ))
            }));
            lines.push(ViewLine::text(texts.get(text::CHOICE_HINT)));
        }
        Stage::Loading { program, .. } => {
            lines.push(ViewLine::text(program.clone()));
            lines.push(ViewLine::text(texts.get(text::GATEWAY_FINDING)));
        }
        Stage::Pick(pick) => pick_lines(pick, texts, &mut lines),
    }
    lines
}

fn pick_lines(pick: &Pick, texts: &Texts, lines: &mut Vec<ViewLine>) {
    lines.push(ViewLine::text(format!(
        "{} → {}",
        pick.program,
        texts.get(channel_label(pick.route))
    )));
    if let Some(failure) = &pick.failure {
        lines.push(ViewLine::text(
            texts.get(text::GATEWAY_FAILED) + &failure.text(texts),
        ));
    } else if pick.candidates.is_empty() {
        lines.push(ViewLine::text(if pick.observer_active {
            texts.fill(text::GATEWAY_EMPTY, &[("program", pick.program.as_str())])
        } else {
            texts.get(text::GATEWAY_OBSERVER_OFF)
        }));
    }
    lines.extend(pick.candidates.iter().enumerate().map(|(i, c)| {
        ViewLine::text(format!(
            "{}{}. {}",
            marker(i == pick.cursor && pick.text.is_empty()),
            i + 1,
            candidate_text(c, texts)
        ))
    }));
    if pick.omitted > 0 {
        lines.push(ViewLine::text(texts.fill(
            text::GATEWAY_OMITTED,
            &[("count", pick.omitted.to_string())],
        )));
    }
    lines.push(ViewLine::new(vec![Segment::strong(texts.get(
        if pick.candidates.is_empty() {
            text::GATEWAY_NONE_FOUND
        } else {
            text::GATEWAY_PICK
        },
    ))]));
    lines.push(ViewLine::text(format!("> {}", pick.text)));
    if pick.invalid {
        lines.push(ViewLine::text(texts.get(text::GATEWAY_INVALID)));
    }
    lines.push(ViewLine::text(texts.get(text::GATEWAY_PICK_KEYS)));
}
