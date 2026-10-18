//! "Several rules": lines of a rules file typed or pasted at once (the GUI's
//! "Several rules" in `RuleEditDialog`). `nrr_client_logic::bulk_rules` reads
//! them, the GUI's `planBulkRules` twin; each row is judged by the validator
//! the list uses. Adding puts every new rule and every move into the list on
//! screen in one step, so one apply sends them as one revision; lines that
//! were not taken stay in the form.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_client_logic::bulk_rules::{
    plan_bulk_rules, Bound, BulkInput, BulkPlan, BulkRow, ExistingRule, LineChoice, LineVerdict,
    RowAction, RowStatus, VerdictLevel,
};
use nrr_client_logic::placeholders::fill_placeholders;
use nrr_client_logic::rules_table::{RowOrigin, RuleRow, RuleType, TargetRoute};
use nrr_shared::display_text::display_text;
use nrr_shared::platform_profile::PlatformProfile;
use nrr_shared::rules_json::FREE_MAX_RULES;

use super::form::{offered_types, route_options, Form};
use super::table::{route_label, rule_id, Row, Table, Verdict, VerdictStatus};
use super::{ace, text, Mode, Note};
use crate::i18n::Texts;
use crate::state::AppState;
use crate::view::{Segment, StateTone, ViewLine};

/// Preview rows one page shows.
const ROWS_SHOWN: usize = 8;
/// Lines of the typed text the form shows, the last ones.
const TEXT_SHOWN: usize = 5;
/// Verdicts kept between keystrokes before the cache starts over.
const VERDICT_CACHE: usize = 5000;
/// What the field takes; typing or pasting past it is ignored. The planner
/// reads far less, and keeps the rest in the field.
const TEXT_MAX: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BulkField {
    Route,
    Text,
    Rows,
}

#[derive(Debug)]
pub struct BulkForm {
    pub route: TargetRoute,
    pub text: String,
    pub field: BulkField,
    /// By line: what the line read when the choice was made, and the choice.
    choices: HashMap<usize, (String, LineChoice)>,
    verdicts: HashMap<String, LineVerdict>,
    /// The list when the form opened, as `(type, value, route)`; it cannot
    /// change while the form is up.
    existing: Vec<(String, String, String)>,
    room: usize,
    pub plan: BulkPlan,
    /// The chosen preview row.
    pub cursor: usize,
}

impl BulkForm {
    /// `ask_route`: start on the route, as line mode asks it first; else on
    /// the text, the route already chosen in the one-rule form.
    pub fn open(table: &Table, route: TargetRoute, text: String, ask_route: bool) -> Self {
        let mut form = Self {
            route,
            text,
            field: if ask_route {
                BulkField::Route
            } else {
                BulkField::Text
            },
            choices: HashMap::new(),
            verdicts: HashMap::new(),
            existing: Vec::new(),
            room: 0,
            plan: BulkPlan {
                rows: Vec::new(),
                lines: 0,
                excess: 0,
                bound: None,
                remaining: String::new(),
            },
            cursor: 0,
        };
        form.take_list(table);
        form.replan();
        form
    }

    fn take_list(&mut self, table: &Table) {
        self.existing = table
            .rules()
            .map(|r| {
                (
                    r.rule_type.as_str().to_owned(),
                    r.match_value.clone(),
                    r.target_route.as_str().to_owned(),
                )
            })
            .collect();
        self.room = FREE_MAX_RULES.saturating_sub(table.user_rule_count());
    }

    /// Reads the text again; every row that needs a verdict gets one here.
    pub fn replan(&mut self) {
        if self.verdicts.len() > VERDICT_CACHE {
            self.verdicts.clear();
        }
        let existing: Vec<ExistingRule<'_>> = self
            .existing
            .iter()
            .map(|(rule_type, value, route)| ExistingRule {
                rule_type,
                value,
                route,
            })
            .collect();
        let lines: Vec<&str> = self.text.split('\n').collect();
        let choices: HashMap<usize, LineChoice> = self
            .choices
            .iter()
            .filter(|(line, (written, _))| line_text(&lines, **line) == written.as_str())
            .map(|(line, (_, choice))| (*line, choice.clone()))
            .collect();
        let route = self.route.as_str().to_owned();
        let os = PlatformProfile::current().os;
        let apps = offered_types().contains(&RuleType::Application);
        let mut plan = None;
        // The second pass has every verdict the first one asked for.
        for _ in 0..2 {
            let planned = plan_bulk_rules(&BulkInput {
                text: &self.text,
                route: &route,
                os,
                apps,
                existing: &existing,
                choices: &choices,
                verdicts: &self.verdicts,
                room: Some(self.room),
            });
            let pending: Vec<(String, &'static str, String)> = planned
                .rows
                .iter()
                .filter(|r| r.status == RowStatus::Pending)
                .map(|r| (r.verdict_key.clone(), r.rule_type, r.value.clone()))
                .collect();
            plan = Some(planned);
            if pending.is_empty() {
                break;
            }
            for (key, rule_type, value) in pending {
                self.verdicts.insert(key, verdict_of(rule_type, &value));
            }
        }
        if let Some(plan) = plan {
            self.plan = plan;
        }
        self.cursor = self.cursor.min(self.plan.rows.len().saturating_sub(1));
    }

    fn chosen_row(&self) -> Option<BulkRow> {
        self.plan.rows.get(self.cursor).cloned()
    }

    fn choice_for(&mut self, row: &BulkRow) -> &mut LineChoice {
        let entry = self
            .choices
            .entry(row.line)
            .or_insert_with(|| (row.text.clone(), LineChoice::default()));
        if entry.0 != row.text {
            *entry = (row.text.clone(), LineChoice::default());
        }
        &mut entry.1
    }

    /// The next type offered on `row`; past the last, none again.
    fn cycle_type(&mut self, row: &BulkRow) {
        if row.options.is_empty() {
            return;
        }
        let next = match row.options.iter().position(|o| *o == row.rule_type) {
            None => row.options.first().copied(),
            Some(at) => row.options.get(at + 1).copied(),
        };
        self.choice_for(row).rule_type = next.map(str::to_owned);
        self.replan();
    }

    /// The `n`-th type offered on `row` (1-based).
    fn pick_type(&mut self, row: &BulkRow, n: usize) {
        if let Some(t) = n.checked_sub(1).and_then(|i| row.options.get(i)) {
            self.choice_for(row).rule_type = Some((*t).to_owned());
            self.replan();
        }
    }

    fn toggle_move(&mut self, row: &BulkRow) {
        if row.status != RowStatus::Elsewhere {
            return;
        }
        let choice = self.choice_for(row);
        choice.move_elsewhere = !choice.move_elsewhere;
        self.replan();
    }

    fn row_at_line(&self, line: usize) -> Option<BulkRow> {
        self.plan.rows.iter().find(|r| r.line == line).cloned()
    }

    fn set_route(&mut self, by: isize) {
        let routes = route_options();
        let at = routes.iter().position(|r| *r == self.route).unwrap_or(0) as isize;
        let next = (at + by).rem_euclid(routes.len() as isize) as usize;
        if let Some(route) = routes.get(next) {
            self.route = route.clone();
            self.replan();
        }
    }

    fn push_text(&mut self, c: char) {
        if self.text.len() < TEXT_MAX {
            self.text.push(c);
        }
    }
}

/// Line `n` (1-based) as the planner compares it: without its `\r`, trimmed.
fn line_text<'a>(lines: &[&'a str], n: usize) -> &'a str {
    n.checked_sub(1)
        .and_then(|i| lines.get(i).copied())
        .map_or("", |l| l.strip_suffix('\r').unwrap_or(l).trim())
}

fn verdict_of(rule_type: &str, value: &str) -> LineVerdict {
    let verdict = Verdict::of(&RuleType::from_slug(rule_type), value);
    LineVerdict {
        level: match verdict.status {
            VerdictStatus::Valid => VerdictLevel::Valid,
            VerdictStatus::Warning => VerdictLevel::Warning,
            VerdictStatus::Error => VerdictLevel::Error,
        },
        message_key: verdict.message_key,
        args: verdict.args,
    }
}

/// `A` on the list, or "several rules" in the add form, which brings its route
/// and value along.
pub fn start(app: &mut AppState, route: TargetRoute, text: String, from_form: bool) -> bool {
    if super::locked(app) {
        return true;
    }
    let form = BulkForm::open(&app.rules.table, route, text, !from_form);
    app.rules.mode = Mode::Bulk(Box::new(form));
    true
}

/// Every new rule and every move the plan settles, into the list on screen at
/// once. The form stays up with whatever was not taken.
pub fn add(app: &mut AppState, mut form: Box<BulkForm>) {
    form.replan();
    let table = &mut app.rules.table;
    let first: usize = table
        .next_free_id()
        .get(2..)
        .and_then(|n| n.parse().ok())
        .unwrap_or(1);
    let mut added = 0usize;
    let mut moved = 0usize;
    for row in &form.plan.rows {
        match row.action {
            RowAction::Add => {
                let rule_type = RuleType::from_slug(row.rule_type);
                let mut comment = row.comment.clone();
                if comment.is_empty() && rule_type.is_hostlike() && !row.value.is_ascii() {
                    let encoded = ace::encode(&row.value);
                    if encoded != row.value {
                        comment = format!("Punycode: {encoded}");
                    }
                }
                let rule = RuleRow {
                    id: rule_id((first + added).min(FREE_MAX_RULES)),
                    enabled: row.enabled,
                    rule_type,
                    match_value: row.value.clone(),
                    target_route: TargetRoute::from_slug(&row.route),
                    verify: row.verify,
                    comment,
                    // A line of an `--- Auto` section stays app-authored, as an
                    // import keeps it.
                    origin: (!row.origin_reason.is_empty()).then(|| RowOrigin {
                        reason: row.origin_reason.clone(),
                        anchor: row.origin_anchor.clone(),
                        added: row.origin_added.clone(),
                    }),
                };
                table.rows.push(Row::new(rule));
                added += 1;
            }
            RowAction::Move => {
                let to = TargetRoute::from_slug(&row.route);
                let found = row.existing.and_then(|at| table.rows.get_mut(at));
                if let Some(existing) = found {
                    let rule = &mut existing.rule;
                    if rule.target_route != to
                        && rule.match_value.to_lowercase() == row.value.to_lowercase()
                    {
                        // A deny takes no `?`; it must not come back later.
                        if to == TargetRoute::Block {
                            rule.verify = false;
                        }
                        rule.target_route = to;
                        moved += 1;
                        existing.verdict = Verdict::for_route(
                            &existing.rule.rule_type,
                            &existing.rule.match_value,
                            &existing.rule.target_route,
                        );
                    }
                }
            }
            RowAction::Keep | RowAction::Drop => {}
        }
    }
    let kept = form.plan.count(RowAction::Keep);
    let mut note = Note::with(text::LIST_ADDED, vec![("count", added.to_string())]);
    let left = (kept > 0).then(|| Note::with(text::LIST_LEFT, vec![("count", kept.to_string())]));
    if moved > 0 {
        let mut then = Note::with(text::LIST_MOVED, vec![("count", moved.to_string())]);
        if let Some(left) = left {
            then = then.then(left);
        }
        note = note.then(then);
    } else if let Some(left) = left {
        note = note.then(left);
    }
    app.rules.note = Some(note);
    if form.plan.remaining.is_empty() {
        app.rules.mode = Mode::List;
        return;
    }
    form.text = std::mem::take(&mut form.plan.remaining);
    form.choices.clear();
    form.field = BulkField::Text;
    form.cursor = 0;
    form.take_list(&app.rules.table);
    form.replan();
    app.rules.mode = Mode::Bulk(form);
}

pub fn on_key(app: &mut AppState, mut form: Box<BulkForm>, key: KeyEvent) -> bool {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Esc => return true,
        KeyCode::Char('s') if ctrl => {
            add(app, form);
            return true;
        }
        KeyCode::F(1) => {
            app.rules.mode = Mode::Bulk(form);
            return false;
        }
        KeyCode::F(2) => {
            back_to_one_rule(app, &form);
            return true;
        }
        KeyCode::Tab => {
            form.field = match form.field {
                BulkField::Route => BulkField::Text,
                BulkField::Text => BulkField::Rows,
                BulkField::Rows => BulkField::Route,
            };
            form.replan();
        }
        KeyCode::BackTab => {
            form.field = match form.field {
                BulkField::Route => BulkField::Rows,
                BulkField::Text => BulkField::Route,
                BulkField::Rows => BulkField::Text,
            };
            form.replan();
        }
        _ => match form.field {
            BulkField::Route => match key.code {
                KeyCode::Left => form.set_route(-1),
                KeyCode::Right | KeyCode::Char(' ') => form.set_route(1),
                KeyCode::Enter => {
                    add(app, form);
                    return true;
                }
                _ => {}
            },
            // The preview follows each finished line, not each keystroke: a
            // paste arrives as keystrokes.
            BulkField::Text => match key.code {
                KeyCode::Enter => {
                    form.push_text('\n');
                    form.replan();
                }
                KeyCode::Backspace => {
                    if form.text.pop() == Some('\n') {
                        form.replan();
                    }
                }
                KeyCode::Char(c) if !ctrl => form.push_text(c),
                _ => {}
            },
            BulkField::Rows => {
                let row = form.chosen_row();
                match key.code {
                    KeyCode::Up => form.cursor = form.cursor.saturating_sub(1),
                    KeyCode::Down => {
                        form.cursor = (form.cursor + 1).min(form.plan.rows.len().saturating_sub(1));
                    }
                    KeyCode::PageUp => form.cursor = form.cursor.saturating_sub(ROWS_SHOWN),
                    KeyCode::PageDown => {
                        form.cursor =
                            (form.cursor + ROWS_SHOWN).min(form.plan.rows.len().saturating_sub(1));
                    }
                    KeyCode::Char('t' | ' ') => {
                        if let Some(row) = row {
                            form.cycle_type(&row);
                        }
                    }
                    KeyCode::Char('m') => {
                        if let Some(row) = row {
                            form.toggle_move(&row);
                        }
                    }
                    KeyCode::Enter => {
                        add(app, form);
                        return true;
                    }
                    _ => {}
                }
            }
        },
    }
    app.rules.mode = Mode::Bulk(form);
    true
}

/// F2: the one-rule form, with the route and the first line taken along.
fn back_to_one_rule(app: &mut AppState, form: &BulkForm) {
    let mut one = Form::add();
    one.set_route(form.route.clone());
    one.value = form
        .text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or_default()
        .chars()
        .take(260)
        .collect();
    super::open_form(app, one);
}

/// One line-mode answer: the route, then the text line by line until an empty
/// line, then commands on the preview.
pub fn on_line(app: &mut AppState, mut form: Box<BulkForm>, line: &str) {
    match form.field {
        BulkField::Route => {
            let routes = route_options();
            let picked = line
                .parse::<usize>()
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|i| routes.get(i));
            if let Some(route) = picked {
                form.route = route.clone();
            }
            form.field = BulkField::Text;
        }
        BulkField::Text if line.is_empty() => {
            form.field = BulkField::Rows;
            form.replan();
        }
        BulkField::Text => {
            for c in line.chars() {
                form.push_text(c);
            }
            form.push_text('\n');
        }
        BulkField::Rows => {
            let mut words = line.split_whitespace();
            let number = |w: Option<&str>| w.and_then(|w| w.parse::<usize>().ok());
            match words.next() {
                Some("y" | "Y") => {
                    add(app, form);
                    return;
                }
                Some("+") => form.field = BulkField::Text,
                Some("c") => {
                    form.text.clear();
                    form.choices.clear();
                    form.field = BulkField::Text;
                    form.replan();
                }
                Some("t") => {
                    let row = number(words.next()).and_then(|l| form.row_at_line(l));
                    if let (Some(row), Some(n)) = (row, number(words.next())) {
                        form.pick_type(&row, n);
                    }
                }
                Some("m") => {
                    if let Some(row) = number(words.next()).and_then(|l| form.row_at_line(l)) {
                        form.toggle_move(&row);
                    }
                }
                Some(">") => {
                    form.cursor =
                        (form.cursor + ROWS_SHOWN).min(form.plan.rows.len().saturating_sub(1));
                }
                Some("<") => form.cursor = form.cursor.saturating_sub(ROWS_SHOWN),
                _ => {}
            }
        }
    }
    app.rules.mode = Mode::Bulk(form);
}

pub fn plain_prompt(form: &BulkForm) -> crate::i18n::Key {
    match form.field {
        BulkField::Route => text::PLAIN_PROMPT,
        BulkField::Text => text::PLAIN_BULK_TEXT,
        BulkField::Rows => text::PLAIN_BULK_ROWS,
    }
}

// ── What the form shows ─────────────────────────────────────────────────────

fn type_label(slug: &str, texts: &Texts) -> String {
    texts.dynamic(&format!("rules.type.{slug}"), slug)
}

fn route_text(route: &str, texts: &Texts) -> String {
    route_label(&TargetRoute::from_slug(route)).map_or_else(|| route.to_owned(), |k| texts.get(k))
}

fn marker(on: bool) -> &'static str {
    if on {
        "> "
    } else {
        "  "
    }
}

/// What a row will do, in the GUI's words: type, route, marks, then its state.
pub fn row_text(row: &BulkRow, texts: &Texts) -> String {
    let mut parts = vec![if row.rule_type.is_empty() {
        texts.get(text::BULK_TYPE_UNKNOWN)
    } else {
        type_label(row.rule_type, texts)
    }];
    parts.push(route_text(&row.route, texts));
    if !row.enabled {
        parts.push(texts.get(text::DISABLED));
    }
    if row.verify {
        parts.push(texts.get(text::ROUTE_UNSURE));
    }
    let state = if row.status == RowStatus::Ok && row.action == RowAction::Add {
        texts.get(text::BULK_WILL_ADD)
    } else {
        let fallback = match row.status {
            RowStatus::Error => texts.get(text::VALIDATION_ERROR),
            _ => texts.get(text::VALIDATION_WARNING),
        };
        let mut args = row.args.clone();
        if let Some(route) = args.get_mut("route") {
            *route = route_text(route, texts);
        }
        if row.message_key.is_empty() {
            fallback
        } else {
            fill_placeholders(&texts.dynamic(&row.message_key, &fallback), &args)
        }
    };
    format!("{} \u{2014} {state}", parts.join(", "))
}

/// The word that says a row will not go in as it is, coloured as the list
/// colours a verdict.
fn state_word(row: &BulkRow) -> Option<(crate::i18n::Key, StateTone)> {
    match row.status {
        RowStatus::Error => Some((text::BULK_NOT_ADDED, StateTone::Bad)),
        RowStatus::Warning => Some((text::VALIDATION_WARNING, StateTone::Caution)),
        RowStatus::NeedsType | RowStatus::Elsewhere => {
            Some((text::BULK_CHOOSE, StateTone::Caution))
        }
        RowStatus::Ok | RowStatus::Pending | RowStatus::Duplicate => None,
    }
}

fn summary(plan: &BulkPlan, texts: &Texts) -> String {
    let mut out = texts.fill(
        text::BULK_SUMMARY,
        &[
            ("add", plan.count(RowAction::Add).to_string()),
            ("move", plan.count(RowAction::Move).to_string()),
            ("keep", plan.count(RowAction::Keep).to_string()),
            ("drop", plan.count(RowAction::Drop).to_string()),
        ],
    );
    let bound = match plan.bound {
        Some(Bound::Lines) => Some(texts.fill(
            text::BULK_BOUND_LINES,
            &[
                ("max", plan.lines.to_string()),
                ("count", plan.excess.to_string()),
            ],
        )),
        Some(Bound::Size) => Some(texts.fill(
            text::BULK_BOUND_SIZE,
            &[
                ("lines", plan.lines.to_string()),
                ("count", plan.excess.to_string()),
            ],
        )),
        None => None,
    };
    if let Some(bound) = bound {
        out.push(' ');
        out.push_str(&bound);
    }
    out
}

/// The offers on the chosen row: the type to pick, the move to make.
fn offer_lines(row: &BulkRow, texts: &Texts) -> Vec<ViewLine> {
    let mut lines = Vec::new();
    if !row.options.is_empty() {
        let offers: Vec<String> = row
            .options
            .iter()
            .enumerate()
            .map(|(i, option)| {
                let label = type_label(option, texts);
                let label = if row.section.is_empty() {
                    label
                } else {
                    texts.fill(text::MOVE_TO_TYPE_ACTION, &[("type", label)])
                };
                let tick = texts.get(if row.rule_type == *option {
                    text::TICKED
                } else {
                    text::UNTICKED
                });
                format!("{}. {tick} {label}", i + 1)
            })
            .collect();
        lines.push(ViewLine::text(format!(
            "     {}",
            texts.fill(text::BULK_TYPE_KEY, &[("choices", offers.join("  "))])
        )));
    }
    if row.status == RowStatus::Elsewhere {
        let what = if row.route == "block" {
            text::DENY_INSTEAD
        } else if row.other_route == "block" {
            text::LIFT_DENY
        } else {
            text::MOVE_HERE
        };
        let tick = texts.get(if row.move_elsewhere {
            text::TICKED
        } else {
            text::UNTICKED
        });
        lines.push(ViewLine::text(format!(
            "     {}",
            texts.fill(
                text::BULK_MOVE_KEY,
                &[("tick", tick), ("move", texts.get(what))]
            )
        )));
    }
    lines
}

pub fn lines(form: &BulkForm, texts: &Texts) -> Vec<ViewLine> {
    let mut lines = Vec::new();
    lines.push(ViewLine::new(vec![
        Segment::plain(marker(form.field == BulkField::Route)),
        Segment::strong(format!("{}: ", texts.get(text::FIELD_ROUTE))),
        Segment::plain(match form.route {
            TargetRoute::Block => texts.get(text::ROUTE_DENY),
            ref other => route_text(other.as_str(), texts),
        }),
    ]));
    if form.field == BulkField::Route {
        for (i, route) in route_options().iter().enumerate() {
            let tick = texts.get(if *route == form.route {
                text::TICKED
            } else {
                text::UNTICKED
            });
            let label = match route {
                TargetRoute::Block => texts.get(text::ROUTE_DENY_DESCRIPTION),
                other => route_text(other.as_str(), texts),
            };
            lines.push(ViewLine::text(format!("     {}. {tick} {label}", i + 1)));
        }
    }
    let typed: Vec<&str> = form.text.lines().collect();
    lines.push(ViewLine::new(vec![
        Segment::plain(marker(form.field == BulkField::Text)),
        Segment::strong(texts.fill(text::BULK_TEXT, &[("count", typed.len().to_string())])),
    ]));
    if form.field == BulkField::Text {
        lines.push(ViewLine::text(format!(
            "     {}",
            texts.get(text::BULK_LABEL)
        )));
    }
    let hidden = typed.len().saturating_sub(TEXT_SHOWN);
    if hidden > 0 {
        lines.push(ViewLine::text(format!(
            "     {}",
            texts.fill(text::BULK_MORE_ABOVE, &[("count", hidden.to_string())])
        )));
    }
    for line in typed.iter().skip(hidden) {
        lines.push(ViewLine::text(format!("     | {}", display_text(line))));
    }
    lines.push(ViewLine::text(summary(&form.plan, texts)));
    let rows = &form.plan.rows;
    if !rows.is_empty() {
        let first = form.cursor / ROWS_SHOWN * ROWS_SHOWN;
        for (at, row) in rows.iter().enumerate().skip(first).take(ROWS_SHOWN) {
            let chosen = form.field == BulkField::Rows && at == form.cursor;
            let head = format!(
                "{}{}. {}",
                marker(chosen),
                row.line,
                display_text(&row.text)
            );
            let mut segments = vec![if chosen {
                Segment::selected(head)
            } else {
                Segment::plain(head)
            }];
            segments.push(Segment::plain(" \u{2014} "));
            if let Some((word, tone)) = state_word(row) {
                segments.push(Segment::state(texts.get(word), tone));
                segments.push(Segment::plain(": "));
            }
            segments.push(Segment::plain(row_text(row, texts)));
            lines.push(ViewLine::new(segments));
            if chosen || (form.field != BulkField::Rows && !row.options.is_empty()) {
                lines.extend(offer_lines(row, texts));
            }
        }
    }
    lines.push(ViewLine::text(texts.get(text::BULK_HINT)));
    lines
}
