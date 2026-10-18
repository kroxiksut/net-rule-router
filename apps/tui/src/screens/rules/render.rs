//! The Rules screen as panels of lines, for both renderers.

use nrr_client_logic::placeholders::{fill_placeholders, list_summary};
use nrr_client_logic::rule_value_class::misplaced_target_type;
use nrr_client_logic::rules_table::{RuleType, TargetRoute};
use nrr_shared::display_text::display_text;
use nrr_shared::ipc_payloads::{ReviewRiskLevel, ReviewSummaryResponse, RuleSummaryEntryDto};
use nrr_shared::platform_profile::PlatformProfile;
use serde_json::Value;

use super::apply::Review;
use super::form::{offered_types, route_options, Field, Form};
use super::table::{route_label, RouteFilter, Row, SortMode, Verdict, VerdictStatus, PAGE};

/// Lines of the changes view's entry list one window shows.
pub const REVIEW_PAGE: usize = 12;
/// Overlaps the form spells out before it counts the rest.
const FORM_OVERLAPS: usize = 3;
use super::{
    bulk, gateway, main_route, recent, text, verdicts, Busy, Choice, ChoicePurpose, Input,
    InputPurpose, Mode, Phase, SetList,
};
use crate::i18n::Texts;
use crate::keys;
use crate::screens::overlaps::explain;
use crate::state::AppState;
use crate::view::{Panel, ScreenView, Segment, StateTone, ViewLine};

pub fn view(app: &AppState, texts: &Texts) -> ScreenView {
    let rules = &app.rules;
    let state = Panel {
        title: texts.get(text::STATE_TITLE),
        lines: state_lines(app, texts),
        feed: false,
    };
    let body = match &rules.mode {
        Mode::List => Panel {
            title: texts.get(text::LIST_TITLE),
            lines: list_lines(app, texts),
            feed: false,
        },
        Mode::Input(input) => Panel {
            title: texts.get(text::LIST_TITLE),
            lines: input_lines(input, texts),
            feed: false,
        },
        Mode::Form(form) => Panel {
            title: texts.get(if form.editing.is_some() {
                text::FORM_EDIT
            } else {
                text::FORM_ADD
            }),
            lines: form_lines(app, form, texts),
            feed: false,
        },
        Mode::Choice(choice) => Panel {
            title: texts.get(text::LIST_TITLE),
            lines: choice_lines(app, choice, texts),
            feed: false,
        },
        Mode::Review(review) => Panel {
            title: texts.get(text::REVIEW_TITLE),
            lines: review_lines(review, texts),
            feed: false,
        },
        Mode::Gateway(stage) => Panel {
            title: texts.get(text::GATEWAY_TITLE),
            lines: gateway::lines(stage, texts),
            feed: false,
        },
        Mode::Bulk(form) => Panel {
            title: texts.get(text::MODE_SEVERAL),
            lines: bulk::lines(form, texts),
            feed: false,
        },
    };
    ScreenView {
        title: texts.get(if rules.baseline {
            text::TITLE_BASELINE
        } else {
            keys::SCREEN_RULES
        }),
        panels: vec![state, body],
    }
}

fn state_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let rules = &app.rules;
    let table = &rules.table;
    let mut lines = Vec::new();
    if rules.baseline {
        lines.push(ViewLine::new(vec![Segment::state(
            texts.get(text::BASELINE_NOTE),
            StateTone::Caution,
        )]));
    }
    if rules.unrecognized > 0 {
        lines.push(ViewLine::new(vec![Segment::state(
            texts.fill(text::UNRECOGNIZED, &[("n", rules.unrecognized.to_string())]),
            StateTone::Caution,
        )]));
    }
    if table.is_loaded() || !table.rows.is_empty() {
        let word = if table.is_dirty() {
            Segment::state(texts.get(text::PENDING), StateTone::Caution)
        } else {
            Segment::state(texts.get(text::IN_FORCE), StateTone::Good)
        };
        lines.push(ViewLine::new(vec![
            Segment::strong(format!("{}: ", texts.get(text::CHANGES))),
            word,
        ]));
    } else if rules.busy.is_none() {
        let key = if app.link.is_connected() {
            text::NO_DATA
        } else {
            text::NOT_LOADED
        };
        lines.push(ViewLine::text(texts.get(key)));
    }
    match &rules.busy {
        None => {}
        Some(Busy::Loading) => lines.push(ViewLine::text(texts.get(text::LOADING))),
        Some(Busy::Previewing) => lines.push(ViewLine::text(texts.get(text::PREVIEWING))),
        Some(Busy::Applying { phase, .. }) => {
            lines.push(ViewLine::text(texts.get(text::APPLYING)));
            match phase {
                None => {}
                Some(Phase::Started) => {
                    lines.push(ViewLine::text(texts.get(text::PHASE_STARTED)));
                }
                Some(Phase::Completed) => {
                    lines.push(ViewLine::text(texts.get(text::PHASE_COMPLETED)));
                }
                Some(Phase::Failed(failure)) => lines.push(ViewLine::text(
                    texts.fill(text::PHASE_FAILED, &[("error", failure.text(texts))]),
                )),
            }
        }
    }
    if let Some(failure) = &rules.load_error {
        lines.push(ViewLine::text(
            texts.fill(text::LOAD_FAILED, &[("error", failure.text(texts))]),
        ));
    }
    let mut filter = vec![
        Segment::strong(format!("{}: ", texts.get(text::ROUTE_FILTER))),
        Segment::plain(texts.get(table.filter.label())),
    ];
    if !table.search.is_empty() {
        filter.push(Segment::strong(format!(" · {}: ", texts.get(text::SEARCH))));
        filter.push(Segment::plain(table.search.clone()));
    }
    if let Some(shown) = &table.recent {
        filter.push(Segment::strong(format!(" · {}: ", texts.get(text::RECENT))));
        filter.push(Segment::plain(
            texts.get(recent::period_label(shown.period)),
        ));
    } else if table.sort != SortMode::Display {
        filter.push(Segment::strong(format!(" · {}: ", texts.get(text::SORT))));
        filter.push(Segment::plain(texts.get(table.sort.label())));
    }
    lines.push(ViewLine::new(filter));
    if let Some(check) = &rules.main_route.check {
        lines.push(ViewLine::text(main_route::progress_text(check, texts)));
    }
    lines.extend(verdict_lines(app, texts));
    if let Some(note) = &rules.note {
        lines.push(ViewLine::text(note.text(texts)));
    }
    lines
}

/// The one question for every `?` rule that works only on the other route.
fn verdict_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let Some(waiting) = verdicts::notice(app) else {
        return Vec::new();
    };
    let mut lines = vec![
        ViewLine::new(vec![Segment::state(
            verdicts::title(&waiting, texts),
            StateTone::Caution,
        )]),
        ViewLine::text(texts.get(text::VERDICTS_BODY)),
    ];
    for (value, to) in &waiting.shown {
        let route = route_text(&TargetRoute::from_slug(to), texts);
        let value = display_text(value).into_owned();
        let item = texts.fill(text::VERDICTS_ITEM, &[("value", value), ("route", route)]);
        lines.push(ViewLine::text(format!("     {item}")));
    }
    if waiting.more > 0 {
        let rest = texts.fill(text::OVERLAPS_MORE, &[("count", waiting.more.to_string())]);
        lines.push(ViewLine::text(format!("     {rest}")));
    }
    lines.push(ViewLine::text(texts.get(text::VERDICTS_KEYS)));
    lines
}

fn type_label(rule_type: &RuleType, texts: &Texts) -> String {
    let slug = rule_type.canonical_slug();
    texts.dynamic(&format!("rules.type.{slug}"), &slug)
}

fn route_text(route: &TargetRoute, texts: &Texts) -> String {
    route_label(route).map_or_else(|| route.as_str().to_owned(), |k| texts.get(k))
}

/// A route as the form offers it: a deny names the action, not the row mark.
fn form_route_text(route: &TargetRoute, texts: &Texts) -> String {
    match route {
        TargetRoute::Block => texts.get(text::ROUTE_DENY),
        other => route_text(other, texts),
    }
}

/// A route as the open choice list spells it out.
fn route_option_text(route: &TargetRoute, texts: &Texts) -> String {
    match route {
        TargetRoute::Block => texts.get(text::ROUTE_DENY_DESCRIPTION),
        other => route_text(other, texts),
    }
}

fn verdict_message(verdict: &Verdict, texts: &Texts) -> String {
    let fallback = match verdict.status {
        VerdictStatus::Error => texts.get(text::VALIDATION_ERROR),
        _ => texts.get(text::VALIDATION_WARNING),
    };
    if verdict.message_key.is_empty() {
        return fallback;
    }
    fill_placeholders(
        &texts.dynamic(&verdict.message_key, &fallback),
        &verdict.args,
    )
}

fn verdict_word(verdict: &Verdict, texts: &Texts) -> Option<Segment> {
    match verdict.status {
        VerdictStatus::Valid => None,
        VerdictStatus::Warning => Some(Segment::state(
            texts.get(text::VALIDATION_WARNING),
            StateTone::Caution,
        )),
        VerdictStatus::Error => Some(Segment::state(
            texts.get(text::VALIDATION_ERROR),
            StateTone::Bad,
        )),
    }
}

/// One rule; `with_main_route` when the list shows the main-route column.
fn row_lines(
    app: &AppState,
    n: usize,
    row: &Row,
    chosen: bool,
    with_main_route: bool,
    texts: &Texts,
) -> Vec<ViewLine> {
    let rule = &row.rule;
    let switch = texts.get(if rule.enabled { text::ON } else { text::OFF });
    let lead = format!(
        "{}{n}. [{switch}] {}  {}  {} — ",
        if chosen { "> " } else { "  " },
        rule.id,
        type_label(&rule.rule_type, texts),
        display_text(&rule.match_value),
    );
    let route = route_text(&rule.target_route, texts);
    // The route's `?` mark, then the rest of the row.
    let mut tail = if rule.is_verify() {
        " ?".to_owned()
    } else {
        String::new()
    };
    let cell = if with_main_route {
        main_route::cell(row)
    } else {
        None
    };
    if let Some((word, _)) = cell {
        tail.push_str(&format!(
            " · {}: {}",
            texts.get(text::MAIN_ROUTE_COLUMN),
            texts.get(word)
        ));
    }
    if let Some(mark) = recent::mark_text(app, rule, texts) {
        tail.push_str(&format!(" · {mark}"));
    }
    let mut first = if chosen {
        vec![Segment::selected(format!("{lead}{route}{tail}"))]
    } else {
        let mut segments = vec![
            Segment::plain(lead),
            Segment::route_slug(route, rule.target_route.as_str()),
        ];
        if !tail.is_empty() {
            segments.push(Segment::plain(tail));
        }
        segments
    };
    if let Some(word) = verdict_word(&row.verdict, texts) {
        first.push(Segment::plain(" — "));
        first.push(word);
    }
    let mut lines = vec![ViewLine::new(first)];
    // The chosen row says the rest: what the validator found, what the main
    // route answered, who wrote it, and its note.
    if chosen {
        let mut details = Vec::new();
        if row.verdict.status != VerdictStatus::Valid {
            details.push(verdict_message(&row.verdict, texts));
        }
        if let Some(target) = misplaced_target_type(&row.verdict.message_key) {
            let label = type_label(&RuleType::from_slug(target), texts);
            details.push(texts.fill(text::MOVE_TO_TYPE, &[("type", label)]));
        }
        if rule.is_verify() {
            details.push(texts.get(text::VERIFY_HINT));
        }
        if let Some((_, hint)) = cell {
            details.push(texts.get(hint));
        }
        if rule.auto_origin().is_some() {
            details.push(texts.get(text::AUTO_ORIGIN));
        }
        details.extend(recent::previous_lines(app, rule, texts));
        if !rule.comment.is_empty() {
            details.push(format!("# {}", display_text(&rule.comment)));
        }
        for detail in details {
            lines.push(ViewLine::text(format!("     {detail}")));
        }
    }
    lines
}

fn list_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let table = &app.rules.table;
    if table.rows.is_empty() {
        if !table.is_loaded() {
            return Vec::new();
        }
        let mut lines = vec![
            ViewLine::new(vec![Segment::strong(texts.get(text::EMPTY_TITLE))]),
            ViewLine::text(texts.get(text::EMPTY_BODY)),
        ];
        lines.extend(recent::extra_lines(app, texts));
        return lines;
    }
    let visible = table.visible();
    let total = table.rows.len().to_string();
    if visible.is_empty() {
        let mut lines = Vec::new();
        if table.recent.as_ref().is_none_or(|r| !r.marks.is_empty()) {
            lines.push(ViewLine::text(
                texts.fill(text::NONE_SHOWN, &[("total", total)]),
            ));
        }
        lines.extend(recent::extra_lines(app, texts));
        return lines;
    }
    let cursor = table.cursor_in(&visible);
    let first = cursor / PAGE * PAGE;
    let last = (first + PAGE).min(visible.len());
    let mut lines = vec![ViewLine::text(texts.fill(
        text::SHOWN,
        &[
            ("first", (first + 1).to_string()),
            ("last", last.to_string()),
            ("shown", visible.len().to_string()),
            ("total", total),
        ],
    ))];
    let misplaced: Vec<String> = table
        .rows
        .iter()
        .filter_map(|row| {
            let target = misplaced_target_type(&row.verdict.message_key)?;
            Some(format!(
                "{}: {} \u{2192} {}",
                display_text(&row.rule.match_value),
                type_label(&row.rule.rule_type, texts),
                type_label(&RuleType::from_slug(target), texts)
            ))
        })
        .collect();
    if !misplaced.is_empty() {
        let more = texts.get(keys::APP_UNRESOLVED_MORE);
        lines.push(ViewLine::text(texts.fill(
            text::MISPLACED_COUNT,
            &[
                ("n", misplaced.len().to_string()),
                ("rules", list_summary(&misplaced, &more)),
            ],
        )));
        lines.push(ViewLine::text(texts.get(text::MOVE_ALL_TO_TYPE)));
    }
    let column = main_route::column_shown(app);
    for (at, &master) in visible.iter().enumerate().take(last).skip(first) {
        let chosen = at == cursor && app.focus == crate::state::Focus::Feed;
        lines.extend(row_lines(
            app,
            at + 1,
            &table.rows[master],
            chosen,
            column,
            texts,
        ));
    }
    lines.extend(recent::extra_lines(app, texts));
    lines
}

fn input_lines(input: &Input, texts: &Texts) -> Vec<ViewLine> {
    let question = match input.purpose {
        InputPurpose::Search => text::SEARCH_QUESTION,
        InputPurpose::Import => text::IMPORT_QUESTION,
        InputPurpose::Export => text::EXPORT_QUESTION,
        InputPurpose::RulesFolder => text::FOLDER_QUESTION,
        InputPurpose::VerdictFolder => text::VERDICTS_FOLDER_QUESTION,
    };
    vec![
        ViewLine::new(vec![Segment::strong(texts.get(question))]),
        ViewLine::text(format!("> {}", input.text)),
        ViewLine::text(texts.get(text::INPUT_HINT)),
    ]
}

fn marker(on: bool) -> &'static str {
    if on {
        "> "
    } else {
        "  "
    }
}

/// Numbered options with the one in force ticked.
fn options(labels: &[String], chosen: Option<usize>, texts: &Texts) -> Vec<ViewLine> {
    labels
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let tick = texts.get(if Some(i) == chosen {
                text::TICKED
            } else {
                text::UNTICKED
            });
            ViewLine::text(format!("     {}. {tick} {label}", i + 1))
        })
        .collect()
}

fn hint_suffix(rule_type: &RuleType) -> String {
    match rule_type {
        RuleType::Application => match PlatformProfile::current().os {
            "linux" => "application-linux".to_owned(),
            "macos" => "application-macos".to_owned(),
            _ => "application-windows".to_owned(),
        },
        other => other.canonical_slug().into_owned(),
    }
}

fn form_lines(app: &AppState, form: &Form, texts: &Texts) -> Vec<ViewLine> {
    let mut lines = Vec::new();
    for field in Field::ALL {
        let current = form.field == field;
        let (label, value) = match field {
            Field::Type => (text::FIELD_TYPE, type_label(&form.rule_type, texts)),
            Field::Value => (text::FIELD_VALUE, form.value.clone()),
            Field::Route => (text::FIELD_ROUTE, form_route_text(&form.route, texts)),
            Field::Comment => (text::FIELD_COMMENT, form.comment.clone()),
            Field::Verify => {
                if form.any_zone() {
                    lines.push(ViewLine::text(format!(
                        "     {}",
                        texts.get(text::VERIFY_ANY_ZONE)
                    )));
                    continue;
                }
                if form.verify_refused_by_deny() {
                    lines.push(ViewLine::text(format!(
                        "     {}",
                        texts.get(text::VERIFY_DENY)
                    )));
                    continue;
                }
                if !form.verify_offered() {
                    continue;
                }
                let tick = texts.get(if form.verify {
                    text::TICKED
                } else {
                    text::UNTICKED
                });
                lines.push(ViewLine::new(vec![
                    Segment::plain(marker(current)),
                    Segment::plain(format!("{tick} {}", texts.get(text::VERIFY))),
                ]));
                if form.verify {
                    lines.push(ViewLine::text(format!(
                        "     {}",
                        texts.get(text::VERIFY_HINT)
                    )));
                }
                if current {
                    let labels = [texts.get(text::ON), texts.get(text::OFF)];
                    lines.extend(options(&labels, Some(usize::from(!form.verify)), texts));
                }
                continue;
            }
            Field::Enabled => {
                let state = if form.enabled {
                    text::ENABLED_ON
                } else {
                    text::ENABLED_OFF
                };
                lines.push(ViewLine::new(vec![
                    Segment::plain(marker(current)),
                    Segment::plain(texts.get(state)),
                ]));
                if current {
                    let labels = [texts.get(text::ENABLED_ON), texts.get(text::ENABLED_OFF)];
                    lines.extend(options(&labels, Some(usize::from(!form.enabled)), texts));
                }
                continue;
            }
        };
        lines.push(ViewLine::new(vec![
            Segment::plain(marker(current)),
            Segment::strong(format!("{}: ", texts.get(label))),
            Segment::plain(value),
        ]));
        match field {
            Field::Type => {
                if current {
                    let types = offered_types();
                    let labels: Vec<String> = types.iter().map(|t| type_label(t, texts)).collect();
                    let chosen = types.iter().position(|t| *t == form.rule_type);
                    lines.extend(options(&labels, chosen, texts));
                    if form.editing.is_none() {
                        lines.push(ViewLine::text(format!(
                            "     {}. {} {}",
                            types.len() + 1,
                            texts.get(text::UNTICKED),
                            texts.get(text::SEVERAL_OPTION)
                        )));
                    }
                }
                if form.rule_type == RuleType::Application {
                    let note = if PlatformProfile::current().os == "linux" {
                        text::APP_ROUTING_NOTE_LINUX
                    } else {
                        text::APP_ROUTING_NOTE
                    };
                    lines.push(ViewLine::text(format!("     {}", texts.get(note))));
                }
                // An application deny is no guarantee where the platform cannot
                // hold the app's first connections.
                if form.rule_type == RuleType::Application
                    && !PlatformProfile::current().supports.per_app_block_leakproof
                {
                    lines.push(ViewLine::text(format!(
                        "     {}",
                        texts.get(text::APP_NOT_LEAKPROOF)
                    )));
                }
            }
            Field::Value => {
                match form.verdict() {
                    None => lines.push(ViewLine::text(format!(
                        "     {}",
                        texts.get(text::VERDICT_PENDING)
                    ))),
                    Some(verdict) => {
                        if let Some(word) = verdict_word(&verdict, texts) {
                            lines.push(ViewLine::new(vec![
                                Segment::plain("     "),
                                word,
                                Segment::plain(format!(": {}", verdict_message(&verdict, texts))),
                            ]));
                        }
                    }
                }
                if let Some(target) = form.switch_target() {
                    let label = type_label(&target, texts);
                    lines.push(ViewLine::text(format!(
                        "     {}",
                        texts.fill(text::FORM_SWITCH_TYPE, &[("type", label)])
                    )));
                }
                let hint =
                    texts.dynamic(&format!("rules.hint.{}", hint_suffix(&form.rule_type)), "");
                if current && !hint.is_empty() {
                    lines.push(ViewLine::text(format!("     {hint}")));
                }
            }
            Field::Route => {
                if current {
                    let routes = route_options();
                    let labels: Vec<String> =
                        routes.iter().map(|r| route_option_text(r, texts)).collect();
                    let chosen = routes.iter().position(|r| *r == form.route);
                    lines.extend(options(&labels, chosen, texts));
                }
            }
            _ => {}
        }
    }
    lines.extend(overlap_lines(form, texts));
    if let Some(existing) = form.duplicate {
        let id = app
            .rules
            .table
            .rows
            .get(existing)
            .map(|r| r.rule.id.clone())
            .unwrap_or_default();
        lines.push(ViewLine::text(texts.fill(text::DUPLICATE, &[("id", id)])));
        lines.push(ViewLine::text(format!(
            "Enter: {}",
            texts.get(text::OPEN_EXISTING)
        )));
    }
    lines.push(ViewLine::text(texts.get(text::FORM_HINT)));
    lines
}

/// Which rules of the other route the rule in the form meets, and which one
/// wins, before it is saved.
fn overlap_lines(form: &Form, texts: &Texts) -> Vec<ViewLine> {
    if form.overlaps.is_empty() {
        return Vec::new();
    }
    let heading = format!("{}:", texts.get(text::OVERLAPS_HEADING));
    let mut lines = vec![ViewLine::new(vec![Segment::strong(heading)])];
    for found in form.overlaps.iter().take(FORM_OVERLAPS) {
        let sentence = explain(&found.pair, &found.winner_route, &found.loser_route, texts);
        lines.push(ViewLine::text(format!("     {sentence}")));
    }
    let more = form.overlaps.len().saturating_sub(FORM_OVERLAPS);
    if more > 0 {
        let rest = texts.fill(text::OVERLAPS_MORE, &[("count", more.to_string())]);
        lines.push(ViewLine::text(format!("     {rest}")));
    }
    lines
}

/// How many options a question offers; line mode checks a typed number by it.
pub fn choice_len(purpose: &ChoicePurpose) -> usize {
    match purpose {
        ChoicePurpose::Filter => RouteFilter::ALL.len(),
        ChoicePurpose::Quit | ChoicePurpose::ImportMode { .. } => 3,
        ChoicePurpose::Preset(list) => list.sets.len(),
        ChoicePurpose::Recent => 4,
        ChoicePurpose::Restore(count) => *count,
        ChoicePurpose::Delete(_) | ChoicePurpose::Reload | ChoicePurpose::Overwrite(_) => 2,
        ChoicePurpose::HandEdited(_) => 3,
        ChoicePurpose::ChangedElsewhere => 2,
    }
}

fn choice_lines(app: &AppState, choice: &Choice, texts: &Texts) -> Vec<ViewLine> {
    let get = |k| texts.get(k);
    let (question, details, labels): (String, Vec<String>, Vec<String>) = match &choice.purpose {
        ChoicePurpose::Filter => (
            get(text::FILTER_QUESTION),
            Vec::new(),
            RouteFilter::ALL.iter().map(|f| get(f.label())).collect(),
        ),
        ChoicePurpose::Delete(i) => {
            let what = app
                .rules
                .table
                .rows
                .get(*i)
                .map(|r| format!("{} {}", r.rule.id, display_text(&r.rule.match_value)))
                .unwrap_or_default();
            (
                get(text::DELETE_TITLE),
                vec![what],
                vec![get(text::DELETE_CONFIRM), get(text::CANCEL)],
            )
        }
        ChoicePurpose::Reload => (
            get(text::RELOAD_QUESTION),
            vec![get(text::RELOAD_HINT)],
            vec![get(text::RELOAD), get(text::CANCEL)],
        ),
        ChoicePurpose::Quit => (
            get(text::QUIT_TITLE),
            vec![get(text::QUIT_BODY), get(text::QUIT_DETAIL)],
            vec![
                get(text::QUIT_APPLY),
                get(text::QUIT_DISCARD),
                get(text::QUIT_STAY),
            ],
        ),
        ChoicePurpose::ImportMode { path, .. } => (
            get(text::MODE_QUESTION),
            vec![path.clone()],
            vec![
                get(text::MODE_REPLACE),
                get(text::MODE_ADD),
                get(text::CANCEL),
            ],
        ),
        ChoicePurpose::Preset(list) => (
            get(text::PRESET_QUESTION),
            set_list_details(list, texts),
            list.sets.iter().map(|p| p.label.clone()).collect(),
        ),
        ChoicePurpose::Overwrite(path) => (
            get(text::OVERWRITE_QUESTION),
            vec![path.display().to_string()],
            vec![get(text::OVERWRITE), get(text::CANCEL)],
        ),
        ChoicePurpose::ChangedElsewhere => (
            get(text::CHANGED_ELSEWHERE_QUESTION),
            vec![get(text::CHANGED_ELSEWHERE_DETAIL)],
            vec![get(text::REBASE), get(text::KEEP_LIST)],
        ),
        ChoicePurpose::HandEdited(held) => (
            get(text::HAND_EDITED_TITLE),
            std::iter::once(get(text::HAND_EDITED_BODY))
                .chain(held.iter().map(|(_, path)| path.display().to_string()))
                .collect(),
            vec![
                get(text::HAND_EDITED_TAKE),
                get(text::HAND_EDITED_REPLACE),
                get(text::HAND_EDITED_LATER),
            ],
        ),
        ChoicePurpose::Recent => (
            get(text::RECENT_QUESTION),
            Vec::new(),
            recent::choice_labels(texts),
        ),
        ChoicePurpose::Restore(_) => (
            get(text::RESTORE_QUESTION),
            Vec::new(),
            recent::restore_labels(app, texts),
        ),
    };
    let mut lines = vec![ViewLine::new(vec![Segment::strong(question)])];
    lines.extend(details.into_iter().map(ViewLine::text));
    lines.extend(labels.iter().enumerate().map(|(i, label)| {
        ViewLine::text(format!("{}{}. {label}", marker(i == choice.cursor), i + 1))
    }));
    lines.push(ViewLine::text(get(text::CHOICE_HINT)));
    lines
}

/// Where the offered sets come from, and why not from the user's folder.
fn set_list_details(list: &SetList, texts: &Texts) -> Vec<String> {
    let mut details = Vec::new();
    if let Some(error) = &list.settings_error {
        details.push(texts.fill(text::SETTINGS_UNREADABLE, &[("error", error)]));
    }
    if let Some(own) = &list.empty_own_folder {
        let path = own.display().to_string();
        details.push(texts.fill(text::SETS_FOLDER_EMPTY, &[("path", path)]));
    }
    if let Some(folder) = &list.folder {
        let path = folder.display().to_string();
        details.push(texts.fill(text::SETS_FOLDER, &[("path", path)]));
    }
    details
}

// ── The changes view ─────────────────────────────────────────────────────────

/// `N SID(s); …` is the service's own plan counter; the user reviews rules.
fn is_plan_counter(raw: &str) -> bool {
    let digits = raw.len() - raw.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    let rest = &raw[digits..];
    let spaced = rest.trim_start();
    digits > 0 && spaced.len() < rest.len() && spaced.starts_with("SID(s);")
}

/// The summary line (`diffSummaryText`).
fn summary_text(summary: &ReviewSummaryResponse, texts: &Texts) -> String {
    let raw = &summary.diff_summary;
    if raw.is_empty() {
        return texts.get(text::REVIEW_EMPTY);
    }
    if !is_plan_counter(raw) {
        return raw.clone();
    }
    let added = summary.rules_added.len();
    let removed = summary.rules_removed.len();
    let changed = summary.rules_modified.len() + summary.rules_retargeted.len();
    if added + removed + changed == 0 {
        return texts.get(text::REVIEW_UNCHANGED);
    }
    texts.fill(
        text::REVIEW_COUNTS,
        &[
            ("added", added.to_string()),
            ("removed", removed.to_string()),
            ("changed", changed.to_string()),
        ],
    )
}

/// A signal in words: every payload field fills its `{placeholder}`.
fn signal_text(signal: &nrr_shared::ipc_payloads::RiskSignalDto, texts: &Texts) -> String {
    let Ok(Value::Object(fields)) = serde_json::to_value(signal) else {
        return String::new();
    };
    let kind = fields
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let template = texts.dynamic(&format!("risk.signal.{kind}"), kind);
    let values: Vec<(String, String)> = fields
        .iter()
        .filter(|(name, _)| name.as_str() != "kind")
        .map(|(name, value)| {
            let text = match value {
                Value::String(s) => s.clone(),
                Value::Array(items) => items
                    .iter()
                    .map(|i| i.as_str().map_or_else(|| i.to_string(), str::to_owned))
                    .collect::<Vec<_>>()
                    .join(", "),
                other => other.to_string(),
            };
            (name.clone(), text)
        })
        .collect();
    fill_placeholders(&template, values)
}

fn entry_lines(sign: &str, entries: &[&RuleSummaryEntryDto], texts: &Texts) -> Vec<ViewLine> {
    if entries.is_empty() {
        return vec![ViewLine::text(format!(
            "  {}",
            texts.get(text::REVIEW_NONE)
        ))];
    }
    entries
        .iter()
        .map(|entry| {
            let mut line = format!("  {sign} {}", entry.display);
            if !entry.route.is_empty() {
                let route = route_text(&TargetRoute::from_slug(&entry.route), texts);
                let mark = if entry.verify { " ?" } else { "" };
                line.push_str(&format!("  [{route}{mark}]"));
            }
            if !entry.enabled {
                line.push_str(&format!("  · {}", texts.get(text::DISABLED)));
            }
            ViewLine::text(line)
        })
        .collect()
}

fn review_lines(review: &Review, texts: &Texts) -> Vec<ViewLine> {
    let summary = &review.summary;
    let mut lines = Vec::new();
    match summary.provenance.as_str() {
        "gui-rules-edit" => lines.push(ViewLine::text(texts.get(text::PROVENANCE_EDIT))),
        "preset-import" => lines.push(ViewLine::text(texts.get(text::PROVENANCE_IMPORT))),
        _ => {}
    }
    lines.push(ViewLine::new(vec![Segment::strong(summary_text(
        summary, texts,
    ))]));

    let level = serde_json::to_value(summary.risk_level)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let word = texts.dynamic(&format!("risk.level.{level}"), &level);
    let word = match summary.risk_level {
        ReviewRiskLevel::Critical => Segment::state(word, StateTone::Bad),
        ReviewRiskLevel::High => Segment::state(word, StateTone::Caution),
        ReviewRiskLevel::Low | ReviewRiskLevel::Medium => Segment::plain(word),
    };
    lines.push(ViewLine::new(vec![
        Segment::strong(format!("{}: ", texts.get(text::RISK_HEADING))),
        word,
    ]));
    if !summary.risk_signals.is_empty() {
        lines.push(ViewLine::new(vec![Segment::strong(
            texts.get(text::SIGNALS_HEADING),
        )]));
        lines.extend(
            summary
                .risk_signals
                .iter()
                .map(|s| ViewLine::text(format!("  {}", signal_text(s, texts)))),
        );
    }
    if !summary.cross_set_duplicates.is_empty() {
        lines.push(ViewLine::new(vec![Segment::strong(
            texts.get(text::DUPLICATES_HEADING),
        )]));
        lines.extend(
            summary
                .cross_set_duplicates
                .iter()
                .map(|d| ViewLine::text(format!("  {}", d.match_summary))),
        );
    }

    let changed: Vec<&RuleSummaryEntryDto> = summary
        .rules_modified
        .iter()
        .chain(&summary.rules_retargeted)
        .collect();
    let groups: [(_, &str, Vec<&RuleSummaryEntryDto>); 3] = [
        (
            text::REVIEW_ADDED,
            "+",
            summary.rules_added.iter().collect(),
        ),
        (
            text::REVIEW_REMOVED,
            "-",
            summary.rules_removed.iter().collect(),
        ),
        (text::REVIEW_CHANGED, "~", changed),
    ];
    let mut entries = Vec::new();
    for (title, sign, group) in groups {
        entries.push(ViewLine::new(vec![Segment::strong(format!(
            "{}: {}",
            texts.get(title),
            group.len()
        ))]));
        entries.extend(entry_lines(sign, &group, texts));
    }
    // A window over the entries, so a long change fits a small terminal.
    let first = review.scroll.min(entries.len().saturating_sub(1));
    let last = (first + REVIEW_PAGE).min(entries.len());
    if entries.len() > REVIEW_PAGE {
        lines.push(ViewLine::text(texts.fill(
            text::REVIEW_WINDOW,
            &[
                ("first", (first + 1).to_string()),
                ("last", last.to_string()),
                ("total", entries.len().to_string()),
            ],
        )));
    }
    lines.extend(entries.drain(first..last));

    if review.is_critical() {
        let tick = texts.get(if review.understood {
            text::TICKED
        } else {
            text::UNTICKED
        });
        lines.push(ViewLine::text(format!(
            "{tick} {}",
            texts.get(text::UNDERSTAND)
        )));
        lines.push(ViewLine::text(texts.get(text::REVIEW_HINT_CRITICAL)));
    } else {
        lines.push(ViewLine::text(texts.get(text::REVIEW_HINT)));
    }
    lines.push(ViewLine::text(format!(
        "Enter: {}",
        texts.get(text::REVIEW_APPLY)
    )));
    lines
}
