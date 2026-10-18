//! `R`: «Recent», the window's filter of the same name — the rules the user
//! added or changed lately, newest first, and the ones they deleted, each
//! with its moment, as the service tells them from the user's own revisions
//! (`rules.recent-changes.list`). Asked for only while it is on. `U` puts a
//! deleted rule back into the list; `s` applies it like any edit.

use std::collections::HashMap;

use chrono::TimeZone;
use nrr_client_logic::recent_changes::{
    recent_change_stamp, recent_change_time, recent_period_since, RecentPeriod,
};
use nrr_client_logic::rules_table::{file_row_from_service_wire, RuleRow, TargetRoute};
use nrr_ipc_client::{ipc_operation_timeout, IpcClient};
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    RecentRuleChangeKind, RecentRulePreviousDto, RulesRecentChangesRequest,
    RulesRecentChangesResponse,
};
use nrr_shared::rules_json::FREE_MAX_RULES;

use super::apply::Failure;
use super::table::{route_label, Row};
use super::{ace, text, Choice, ChoicePurpose, Mode, Note};
use crate::backend::{Job, Reply};
use crate::i18n::Texts;
use crate::state::AppState;
use crate::view::{Segment, ViewLine};

/// Members of a replaced set the list spells out before it counts the rest.
const REPLACED_SHOWN: usize = 5;

/// What «Recent» found for one period.
#[derive(Debug)]
pub struct Recent {
    pub period: RecentPeriod,
    pub loading: bool,
    pub failure: Option<Failure>,
    /// By [`RuleRow::value_key`]: the rules added or changed.
    pub marks: HashMap<String, Mark>,
    /// Newest first.
    pub replaced: Vec<Replaced>,
    /// Newest first.
    pub deleted: Vec<Deleted>,
    pub history_starts_at: Option<i64>,
    pub truncated: bool,
}

impl Recent {
    fn asked(period: RecentPeriod) -> Self {
        Self {
            period,
            loading: true,
            failure: None,
            marks: HashMap::new(),
            replaced: Vec::new(),
            deleted: Vec::new(),
            history_starts_at: None,
            truncated: false,
        }
    }

    /// When the rule was added or changed, if it was.
    pub fn at_of(&self, rule: &RuleRow) -> Option<i64> {
        self.marks.get(&rule.value_key()).map(|m| m.at)
    }
}

#[derive(Debug)]
pub struct Mark {
    pub changed: bool,
    pub at: i64,
    pub previous: Option<RecentRulePreviousDto>,
}

#[derive(Debug)]
pub struct Replaced {
    pub at: i64,
    pub count: u32,
    pub members: Vec<RuleRow>,
}

#[derive(Debug)]
pub struct Deleted {
    pub at: i64,
    /// As it was just before it went.
    pub rule: RuleRow,
}

/// The reader's offset from UTC at `at`, in minutes east.
fn offset_at(at: i64) -> i64 {
    // Snapshots must not depend on the zone of the machine running them.
    if cfg!(test) {
        return 0;
    }
    chrono::Local
        .timestamp_opt(at, 0)
        .single()
        .map_or(0, |moment| {
            i64::from(moment.offset().local_minus_utc()) / 60
        })
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// `14:32`, `yesterday 14:32` or `14.10 14:32`.
pub fn time_text(at: i64, texts: &Texts) -> String {
    let now = now();
    recent_change_time(
        at,
        offset_at(at),
        now,
        offset_at(now),
        &texts.get(text::RECENT_YESTERDAY),
    )
}

/// The periods offered after "off", in the window's order.
fn choice_period(at: usize) -> Option<RecentPeriod> {
    at.checked_sub(1)
        .and_then(|i| RecentPeriod::ALL.get(i).copied())
}

pub fn period_label(period: RecentPeriod) -> crate::i18n::Key {
    match period {
        RecentPeriod::Hour => text::RECENT_HOUR,
        RecentPeriod::Today => text::RECENT_TODAY,
        RecentPeriod::Week => text::RECENT_WEEK,
    }
}

/// The question's options: off, then each period.
pub fn choice_labels(texts: &Texts) -> Vec<String> {
    let mut labels = vec![texts.get(text::RECENT_OFF)];
    labels.extend(RecentPeriod::ALL.map(|p| texts.get(period_label(p))));
    labels
}

/// `R` on the list.
pub fn ask(app: &mut AppState) -> bool {
    let cursor = match &app.rules.table.recent {
        None => 2,
        Some(recent) => RecentPeriod::ALL
            .iter()
            .position(|p| *p == recent.period)
            .map_or(2, |i| i + 1),
    };
    app.rules.mode = Mode::Choice(Choice {
        purpose: ChoicePurpose::Recent,
        cursor,
    });
    true
}

/// The option `at` of the question was chosen.
pub fn picked(app: &mut AppState, at: usize) {
    let table = &mut app.rules.table;
    table.set_cursor(0);
    match choice_period(at) {
        None => table.recent = None,
        Some(period) => {
            table.recent = Some(Recent::asked(period));
            ask_service(app);
        }
    }
}

/// Ask again for the period on screen, after the rules were read again.
pub fn refresh(app: &mut AppState) {
    let Some(recent) = app.rules.table.recent.as_mut() else {
        return;
    };
    recent.loading = true;
    ask_service(app);
}

fn ask_service(app: &mut AppState) {
    let Some(recent) = app.rules.table.recent.as_ref() else {
        return;
    };
    if !app.link.is_connected() {
        let period = recent.period;
        answered(app, period, Err(Failure::code("transport-disconnected")));
        return;
    }
    let period = recent.period;
    let now = now();
    let since = recent_period_since(period, now, offset_at(now));
    app.outbox.push(job(period, since));
}

fn job(period: RecentPeriod, since: i64) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let op = IpcOperationName::RulesRecentChangesList;
        let answer = serde_json::to_value(RulesRecentChangesRequest { since })
            .map_err(|_| Failure::code("serialization-failed"))
            .and_then(|payload| {
                client
                    .call(op, payload, ipc_operation_timeout(op))
                    .map_err(|e| Failure::of(&e))
            })
            .and_then(|v| {
                serde_json::from_value::<RulesRecentChangesResponse>(v)
                    .map_err(|_| Failure::code("bad-response"))
            });
        Reply::new(move |app| answered(app, period, answer))
    })
}

/// The answer arrives; one for a period the user left meanwhile is dropped.
fn answered(
    app: &mut AppState,
    period: RecentPeriod,
    answer: Result<RulesRecentChangesResponse, Failure>,
) {
    let Some(recent) = app.rules.table.recent.as_mut() else {
        return;
    };
    if recent.period != period {
        return;
    }
    let mut fresh = Recent::asked(period);
    fresh.loading = false;
    match answer {
        Err(failure) => fresh.failure = Some(failure),
        Ok(answer) => {
            fresh.history_starts_at = answer.history_starts_at;
            fresh.truncated = answer.truncated;
            for change in answer.changes {
                let rule = change
                    .rule
                    .as_ref()
                    .map(|entry| file_row_from_service_wire(entry, ace::decode));
                match (change.kind, rule) {
                    (RecentRuleChangeKind::Replaced, _) => fresh.replaced.push(Replaced {
                        at: change.at,
                        count: change.count,
                        members: change
                            .members
                            .iter()
                            .map(|entry| file_row_from_service_wire(entry, ace::decode))
                            .collect(),
                    }),
                    (RecentRuleChangeKind::Deleted, Some(rule)) => fresh.deleted.push(Deleted {
                        at: change.at,
                        rule,
                    }),
                    (kind, Some(rule)) => {
                        fresh.marks.entry(rule.value_key()).or_insert(Mark {
                            changed: kind == RecentRuleChangeKind::Changed,
                            at: change.at,
                            previous: change.previous,
                        });
                    }
                    (_, None) => {}
                }
            }
        }
    }
    *recent = fresh;
    app.rules.table.clamp_cursor();
}

/// Whether a rule with this type and value is in the list now.
fn in_list(app: &AppState, rule: &RuleRow) -> bool {
    let key = rule.value_key();
    app.rules
        .table
        .rows
        .iter()
        .any(|row| row.rule.value_key() == key)
}

/// `U` on the list: which deleted rule to put back.
pub fn ask_restore(app: &mut AppState) -> bool {
    let any = app
        .rules
        .table
        .recent
        .as_ref()
        .is_some_and(|r| !r.deleted.is_empty());
    if !any {
        app.rules.note = Some(Note::new(text::RECENT_NOTHING_DELETED));
        return true;
    }
    if super::locked(app) {
        return true;
    }
    app.rules.mode = Mode::Choice(Choice {
        purpose: ChoicePurpose::Restore(restore_len(app)),
        cursor: 0,
    });
    true
}

pub fn restore_len(app: &AppState) -> usize {
    app.rules
        .table
        .recent
        .as_ref()
        .map_or(0, |r| r.deleted.len())
}

/// The deleted rules as the question lists them.
pub fn restore_labels(app: &AppState, texts: &Texts) -> Vec<String> {
    let Some(recent) = app.rules.table.recent.as_ref() else {
        return Vec::new();
    };
    recent
        .deleted
        .iter()
        .map(|d| {
            let mut label = deleted_text(d, texts);
            if in_list(app, &d.rule) {
                label.push_str(&format!(" ({})", texts.get(text::RECENT_PRESENT)));
            }
            label
        })
        .collect()
}

/// The deleted rule `at` goes back as it was: route, switch, `?` and note.
pub fn restore(app: &mut AppState, at: usize) {
    let Some(rule) = app
        .rules
        .table
        .recent
        .as_ref()
        .and_then(|r| r.deleted.get(at))
        .map(|d| d.rule.clone())
    else {
        return;
    };
    if in_list(app, &rule) {
        app.rules.note = Some(Note::new(text::RECENT_PRESENT_NOTE));
        return;
    }
    let table = &mut app.rules.table;
    if table.user_rule_count() >= FREE_MAX_RULES {
        app.rules.note = Some(Note::with(
            text::LIMIT_REACHED,
            vec![("max", FREE_MAX_RULES.to_string())],
        ));
        return;
    }
    let value = display_text(&rule.match_value).into_owned();
    let id = table.next_free_id();
    table.rows.push(Row::new(RuleRow { id, ..rule }));
    app.rules.note = Some(Note::with(text::RECENT_RESTORED, vec![("value", value)]));
}

fn route_text(route: &TargetRoute, texts: &Texts) -> String {
    route_label(route).map_or_else(|| route.as_str().to_owned(), |k| texts.get(k))
}

fn deleted_text(deleted: &Deleted, texts: &Texts) -> String {
    let rule = &deleted.rule;
    let slug = rule.rule_type.canonical_slug();
    let mut route = route_text(&rule.target_route, texts);
    if !rule.enabled {
        route = format!("{route}, {}", texts.get(text::RECENT_WAS_OFF));
    }
    format!(
        "{}  {} \u{2014} {}, {}",
        texts.dynamic(&format!("rules.type.{slug}"), &slug),
        display_text(&rule.match_value),
        route,
        texts.fill(
            text::RECENT_DELETED_AT,
            &[("time", time_text(deleted.at, texts))]
        )
    )
}

/// The mark a row of the list carries: `added 14:32`.
pub fn mark_text(app: &AppState, rule: &RuleRow, texts: &Texts) -> Option<String> {
    let mark = app
        .rules
        .table
        .recent
        .as_ref()?
        .marks
        .get(&rule.value_key())?;
    let word = texts.get(if mark.changed {
        text::RECENT_CHANGED
    } else {
        text::RECENT_ADDED
    });
    Some(format!("{word} {}", time_text(mark.at, texts)))
}

/// What a changed rule was before, line by line.
pub fn previous_lines(app: &AppState, rule: &RuleRow, texts: &Texts) -> Vec<String> {
    let Some(previous) = app
        .rules
        .table
        .recent
        .as_ref()
        .and_then(|r| r.marks.get(&rule.value_key()))
        .and_then(|m| m.previous.as_ref())
    else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    let was = TargetRoute::from_slug(&previous.target_route);
    if was != rule.target_route {
        lines.push(texts.fill(
            text::RECENT_PREVIOUS_ROUTE,
            &[
                ("from", route_text(&was, texts)),
                ("to", route_text(&rule.target_route, texts)),
            ],
        ));
    }
    if previous.enabled != rule.enabled {
        lines.push(texts.get(if rule.enabled {
            text::RECENT_PREVIOUS_OFF
        } else {
            text::RECENT_PREVIOUS_ON
        }));
    }
    if previous.verify != rule.verify {
        lines.push(texts.get(if rule.verify {
            text::RECENT_PREVIOUS_SURE
        } else {
            text::RECENT_PREVIOUS_UNSURE
        }));
    }
    lines
}

/// What the list shows besides the rows while «Recent» is on.
pub fn extra_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let Some(recent) = app.rules.table.recent.as_ref() else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    if recent.loading {
        lines.push(ViewLine::text(texts.get(text::RECENT_LOADING)));
    }
    if let Some(failure) = &recent.failure {
        lines.push(ViewLine::text(
            texts.fill(text::RECENT_FAILED, &[("reason", failure.text(texts))]),
        ));
    }
    if !recent.loading
        && recent.failure.is_none()
        && recent.marks.is_empty()
        && recent.replaced.is_empty()
        && recent.deleted.is_empty()
    {
        lines.push(ViewLine::text(texts.get(text::RECENT_NONE)));
    }
    for replaced in &recent.replaced {
        lines.push(ViewLine::text(texts.fill(
            text::RECENT_REPLACED,
            &[
                ("time", time_text(replaced.at, texts)),
                ("count", replaced.count.to_string()),
            ],
        )));
        for member in replaced.members.iter().take(REPLACED_SHOWN) {
            let slug = member.rule_type.canonical_slug();
            lines.push(ViewLine::text(format!(
                "     {}  {} \u{2192} {}",
                texts.dynamic(&format!("rules.type.{slug}"), &slug),
                display_text(&member.match_value),
                route_text(&member.target_route, texts)
            )));
        }
        let shown = replaced.members.len().min(REPLACED_SHOWN);
        let rest = usize::try_from(replaced.count)
            .unwrap_or(usize::MAX)
            .saturating_sub(shown);
        if rest > 0 {
            lines.push(ViewLine::text(format!(
                "     {}",
                texts.fill(text::RECENT_REPLACED_MORE, &[("count", rest.to_string())])
            )));
        }
    }
    if !recent.deleted.is_empty() {
        lines.push(ViewLine::new(vec![Segment::strong(
            texts.get(text::RECENT_DELETED_TITLE),
        )]));
        for (i, deleted) in recent.deleted.iter().enumerate() {
            let mut line = format!("  U{}. {}", i + 1, deleted_text(deleted, texts));
            if in_list(app, &deleted.rule) {
                line.push_str(&format!(" ({})", texts.get(text::RECENT_PRESENT)));
            }
            lines.push(ViewLine::text(line));
        }
        lines.push(ViewLine::text(texts.get(text::RECENT_RESTORE_HINT)));
    }
    if let Some(at) = recent.history_starts_at {
        lines.push(ViewLine::text(texts.fill(
            text::RECENT_HISTORY_START,
            &[("time", recent_change_stamp(at, offset_at(at)))],
        )));
    }
    if recent.truncated {
        lines.push(ViewLine::text(texts.get(text::RECENT_TRUNCATED)));
    }
    lines
}
