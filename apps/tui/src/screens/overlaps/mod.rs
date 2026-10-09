//! Screen 5, overlaps: pairs of rules on the two routes that cover the same
//! sites, which route the sites actually take, and the conflicts the service
//! found in the applied rules. The pairs come from
//! `nrr_shared::rules_overlap::find_route_overlaps`, the function the GUI's
//! launcher runs, over the Rules screen's working copy, so an edit shows here
//! before it is applied; nothing here decides a winner.
//!
//! "Send over the other route" is an ordinary edit of that working copy:
//! nothing reaches the service until the list is reviewed and applied.

mod keys;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use crossterm::event::{KeyCode, KeyEvent};
use nrr_client_logic::rules_overlaps::confirmed_by_own_edit;
use nrr_client_logic::rules_table::TargetRoute;
use nrr_client_logic::Route;
use nrr_shared::ipc_payloads::{RuleConflictDto, RuleConflictKind};
use nrr_shared::rules_overlap::{OverlapRule, RouteOverlap, RouteOverlapKind};

use super::{rules, Screen, ScreenId};
use crate::i18n::{Key, Texts};
use crate::keys as common;
use crate::state::{AppState, Focus};
use crate::view::{Panel, ScreenView, Segment, ViewLine};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Note {
    NoItem(usize),
    CannotSend(usize),
    Gone(usize),
    /// The rules list is being applied and cannot change meanwhile.
    Locked,
}

#[derive(Debug, Default)]
pub struct Overlaps {
    /// Pairs over the Rules screen's working copy as of its last change seen
    /// here.
    pairs: Vec<RouteOverlap>,
    /// Pair keys the user confirmed this session; a key names both rules and
    /// their routes, so editing either asks again.
    confirmed: BTreeSet<String>,
    show_resolved: bool,
    /// Index into the shown pairs.
    selected: usize,
    note: Option<Note>,
}

impl Overlaps {
    fn is_confirmed(&self, pair: &RouteOverlap) -> bool {
        self.confirmed.contains(&pair.key)
    }

    /// Unconfirmed first, then the confirmed ones when asked for, each in the
    /// detector's order.
    fn shown(&self) -> Vec<&RouteOverlap> {
        let pending = self.pairs.iter().filter(|p| !self.is_confirmed(p));
        if !self.show_resolved {
            return pending.collect();
        }
        pending
            .chain(self.pairs.iter().filter(|p| self.is_confirmed(p)))
            .collect()
    }

    fn pending_count(&self) -> usize {
        self.pairs.iter().filter(|p| !self.is_confirmed(p)).count()
    }

    /// Only keys of pairs that exist now are kept, as the GUI stores them, so
    /// the set cannot outgrow the rules it describes. A pair that is gone for
    /// a moment keeps its key until the next confirmation.
    fn confirm(&mut self, keys: impl IntoIterator<Item = String>) {
        self.confirmed.extend(keys);
        let live: BTreeSet<&str> = self.pairs.iter().map(|p| p.key.as_str()).collect();
        self.confirmed.retain(|k| live.contains(k.as_str()));
        self.clamp();
    }

    fn clamp(&mut self) {
        let count = self.shown().len();
        self.selected = self.selected.min(count.saturating_sub(1));
    }
}

/// Find the pairs again; the working copy may have changed.
pub fn refresh(app: &mut AppState) {
    app.overlaps.pairs = rules::route_overlaps(app);
    app.overlaps.clamp();
}

/// A rule saved from the rule form: an exception it makes inside a wider rule
/// of the other route is what the user meant, so it is not asked about.
pub fn confirm_own_edit(app: &mut AppState, rule_id: &str) {
    refresh(app);
    let settled = confirmed_by_own_edit(&app.overlaps.pairs, &[rule_id]);
    if !settled.is_empty() {
        app.overlaps.confirm(settled);
    }
}

/// The route the working copy gives one side of a pair: a block rule rides in
/// the secondary bucket but is not a route.
fn route_of<'a>(app: &'a AppState, side: &'a OverlapRule) -> &'a str {
    let table = &app.rules.table;
    Route::from_slug(&side.route)
        .and_then(|bucket| table.find(bucket, &side.rule_id))
        .map_or(side.route.as_str(), |at| {
            table.rows[at].rule.target_route.as_str()
        })
}

/// Only two routing rules can trade places (a `?` rule is one); a block is
/// changed in the rules list.
fn can_reroute(app: &AppState, pair: &RouteOverlap) -> bool {
    is_plain_route(route_of(app, &pair.winner)) && is_plain_route(route_of(app, &pair.loser))
}

fn is_plain_route(route: &str) -> bool {
    route == Route::Primary.as_str() || route == Route::Secondary.as_str()
}

/// Whether there are rules to look at, read or written here.
fn has_rules(app: &AppState) -> bool {
    app.rules.table.is_loaded() || !app.rules.table.rows.is_empty()
}

pub struct OverlapsScreen;

impl Screen for OverlapsScreen {
    fn view(&self, app: &AppState, texts: &Texts) -> ScreenView {
        let mut panels = vec![
            Panel {
                title: texts.get(keys::TITLE),
                lines: head_lines(app, texts),
                feed: false,
            },
            Panel {
                title: texts.get(keys::PAIRS_TITLE),
                lines: pair_lines(app, texts),
                feed: true,
            },
        ];
        let conflicts = conflicts(app);
        if !conflicts.is_empty() {
            let mut lines = vec![ViewLine::text(texts.get(keys::CONFLICTS_HINT))];
            lines.extend(
                conflicts
                    .iter()
                    .map(|c| ViewLine::text(conflict_text(c, texts))),
            );
            panels.push(Panel {
                title: texts.get(keys::CONFLICTS_TITLE),
                lines,
                feed: false,
            });
        }
        ScreenView {
            title: texts.get(ScreenId::Overlaps.title()),
            panels,
        }
    }

    fn help(&self) -> &'static [Key] {
        keys::HELP_KEYS
    }

    fn plain_help(&self) -> &'static [Key] {
        keys::PLAIN_KEYS
    }

    /// The working copy may have changed on the Rules screen meanwhile.
    fn on_show(&self, app: &mut AppState) {
        rules::load_if_needed(app);
        refresh(app);
    }

    fn takes_focus(&self) -> bool {
        true
    }

    fn on_key(&self, app: &mut AppState, key: KeyEvent) -> bool {
        let count = app.overlaps.shown().len();
        let selected = app.overlaps.selected;
        match key.code {
            KeyCode::Up => move_to(app, selected.saturating_sub(1), count),
            KeyCode::Down => move_to(app, selected + 1, count),
            KeyCode::Home => move_to(app, 0, count),
            KeyCode::End => move_to(app, count.saturating_sub(1), count),
            KeyCode::Char('C') => confirm_all(app),
            KeyCode::Char(c) => return command(app, c, selected),
            _ => return false,
        }
        true
    }

    fn on_line(&self, app: &mut AppState, line: &str) -> bool {
        let mut chars = line.trim().chars();
        let Some(letter) = chars.next() else {
            return false;
        };
        let rest = chars.as_str().trim();
        match (letter, rest) {
            ('s', "") => command(app, 's', 0),
            ('c', "all") => {
                confirm_all(app);
                true
            }
            ('c' | 'u' | 'o', number) => {
                let Ok(number) = number.parse::<usize>() else {
                    return false;
                };
                let count = app.overlaps.shown().len();
                if number == 0 || number > count {
                    app.overlaps.note = Some(Note::NoItem(number));
                    return true;
                }
                app.overlaps.selected = number - 1;
                command(app, letter, number - 1)
            }
            _ => false,
        }
    }
}

fn move_to(app: &mut AppState, index: usize, count: usize) {
    app.overlaps.selected = index.min(count.saturating_sub(1));
    let seen: &AppState = app;
    let rows: usize = seen
        .overlaps
        .shown()
        .iter()
        .take(seen.overlaps.selected)
        .map(|p| pair_line_count(seen, p))
        .sum();
    app.scroll = u16::try_from(rows).unwrap_or(u16::MAX);
}

fn command(app: &mut AppState, letter: char, index: usize) -> bool {
    let chosen = app.overlaps.shown().get(index).map(|p| (*p).clone());
    match letter {
        's' => {
            app.overlaps.show_resolved = !app.overlaps.show_resolved;
            app.overlaps.selected = 0;
            app.scroll = 0;
        }
        'c' | 'u' | 'o' => {
            let Some(pair) = chosen else {
                app.overlaps.note = Some(Note::NoItem(index + 1));
                return true;
            };
            app.overlaps.note = None;
            match letter {
                'c' => app.overlaps.confirm([pair.key]),
                'u' => {
                    app.overlaps.confirmed.remove(&pair.key);
                    app.overlaps.clamp();
                }
                _ => send_over(app, &pair, index),
            }
        }
        _ => return false,
    }
    true
}

fn confirm_all(app: &mut AppState) {
    let state = &mut app.overlaps;
    let keys: Vec<String> = state.pairs.iter().map(|p| p.key.clone()).collect();
    state.confirm(keys);
    state.selected = 0;
    state.note = None;
    app.scroll = 0;
}

/// The shared sites take the loser's route: a nested winner moves there; of a
/// duplicate the winning copy is switched off, as the GUI's review does.
fn send_over(app: &mut AppState, pair: &RouteOverlap, index: usize) {
    if !can_reroute(app, pair) {
        app.overlaps.note = Some(Note::CannotSend(index + 1));
        return;
    }
    if rules::edits_locked(app) {
        app.overlaps.note = Some(Note::Locked);
        return;
    }
    let winner = &pair.winner;
    let table = &mut app.rules.table;
    let sent = Route::from_slug(&winner.route).is_some_and(|bucket| {
        if pair.kind == RouteOverlapKind::Duplicate {
            table.set_enabled(bucket, &winner.rule_id, false)
        } else {
            let to = TargetRoute::from_slug(&pair.loser.route);
            table.set_route(bucket, &winner.rule_id, to)
        }
    });
    if !sent {
        app.overlaps.note = Some(Note::Gone(index + 1));
        return;
    }
    refresh(app);
}

fn conflicts(app: &AppState) -> &[RuleConflictDto] {
    app.snapshot
        .as_ref()
        .map(|s| s.rule_conflicts.as_slice())
        .unwrap_or_default()
}

// ── Picture ──────────────────────────────────────────────────────────────────

fn head_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let state = &app.overlaps;
    let mut lines = vec![ViewLine::text(texts.get(keys::INTRO))];
    if has_rules(app) {
        lines.push(ViewLine::new(vec![Segment::strong(texts.fill(
            keys::PENDING_COUNT,
            &[("n", state.pending_count().to_string())],
        ))]));
    }
    lines.push(ViewLine::new(vec![
        Segment::plain(format!("{}: ", texts.get(keys::SHOW_RESOLVED))),
        Segment::strong(texts.get(if state.show_resolved {
            keys::YES
        } else {
            keys::NO
        })),
    ]));
    if !app.link.is_connected() {
        lines.push(ViewLine::text(texts.get(if has_rules(app) {
            common::STALE
        } else {
            common::NO_DATA
        })));
    } else if !has_rules(app) {
        if rules::is_loading(app) {
            lines.push(ViewLine::text(texts.get(keys::LOADING)));
        } else if let Some(error) = rules::load_failure(app, texts) {
            let failed = texts.fill(keys::FAILED, &[("error", error)]);
            lines.push(ViewLine::new(vec![Segment::strong(failed)]));
        }
    }
    if app.rules.table.is_dirty() {
        let screen = ScreenId::Rules;
        lines.push(ViewLine::new(vec![Segment::strong(
            texts.get(keys::PREVIEW_NOTICE),
        )]));
        lines.push(ViewLine::text(texts.fill(
            keys::APPLY_ON_RULES,
            &[
                ("key", screen.hotkey().map(String::from).unwrap_or_default()),
                ("screen", texts.get(screen.title())),
            ],
        )));
    }
    if let Some(note) = &state.note {
        let item = |key: Key, n: usize| texts.fill(key, &[("n", n.to_string())]);
        let text = match note {
            Note::NoItem(n) => item(keys::NO_ITEM, *n),
            Note::CannotSend(n) => item(keys::CANNOT_SEND, *n),
            Note::Gone(n) => item(keys::GONE, *n),
            Note::Locked => texts.get(keys::LOCKED),
        };
        lines.push(ViewLine::new(vec![Segment::strong(text)]));
    }
    lines
}

fn pair_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    if !has_rules(app) {
        return Vec::new();
    }
    let state = &app.overlaps;
    let shown = state.shown();
    if shown.is_empty() {
        let empty = if state.pairs.is_empty() {
            keys::EMPTY
        } else {
            keys::ALL_RESOLVED
        };
        return vec![ViewLine::text(texts.get(empty))];
    }
    let focused = app.focus == Focus::Feed;
    shown
        .iter()
        .enumerate()
        .flat_map(|(i, pair)| pair_item_lines(app, pair, i, focused && i == state.selected, texts))
        .collect()
}

/// Rows one pair takes; [`pair_item_lines`] must agree (a test holds them).
fn pair_line_count(app: &AppState, pair: &RouteOverlap) -> usize {
    let note = !can_reroute(app, pair) || pair.kind == RouteOverlapKind::Intersecting;
    3 + usize::from(pair.block_wins_tie) + usize::from(note)
}

fn pair_item_lines(
    app: &AppState,
    pair: &RouteOverlap,
    index: usize,
    selected: bool,
    texts: &Texts,
) -> Vec<ViewLine> {
    let marker = if selected { "> " } else { "" };
    let sentence = explain(
        pair,
        route_of(app, &pair.winner),
        route_of(app, &pair.loser),
        texts,
    );
    let mut lines = vec![ViewLine::new(vec![
        Segment::plain(format!("{marker}{}. ", index + 1)),
        Segment::strong(sentence),
    ])];
    lines.push(ViewLine::text(format!(
        "   {}: {}",
        texts.get(keys::REASON_LABEL),
        texts.get(reason(pair))
    )));
    let decision = if app.overlaps.is_confirmed(pair) {
        keys::CONFIRMED
    } else {
        keys::NOT_CONFIRMED
    };
    lines.push(ViewLine::new(vec![
        Segment::plain(format!("   {}: ", texts.get(keys::DECISION_LABEL))),
        Segment::strong(texts.get(decision)),
    ]));
    if pair.block_wins_tie {
        lines.push(ViewLine::text(format!(
            "   {}",
            texts.get(keys::BLOCK_TIE_WARNING)
        )));
    }
    if !can_reroute(app, pair) {
        lines.push(ViewLine::text(format!(
            "   {}",
            texts.get(keys::BLOCK_NOTE)
        )));
    } else if pair.kind == RouteOverlapKind::Intersecting {
        let send = texts.fill(
            keys::SEND_OVER,
            &[("route", route_label(&pair.loser.route, texts))],
        );
        lines.push(ViewLine::text(format!(
            "   {send}: {}",
            texts.get(keys::SEND_OVER_WHOLE)
        )));
    }
    lines
}

fn reason(pair: &RouteOverlap) -> Key {
    if pair.block_wins_tie {
        return keys::REASON_BLOCK_TIE;
    }
    match pair.kind {
        RouteOverlapKind::Duplicate => keys::REASON_DUPLICATE,
        RouteOverlapKind::Intersecting => keys::REASON_INTERSECTING,
        RouteOverlapKind::Nested => keys::REASON_NESTED,
    }
}

/// One pair as a sentence: the list reads it to a screen reader, the rule form
/// shows it before the rule is saved. Each route is that side's as the rules
/// list names it: `primary`, `secondary` or `block`.
pub fn explain(
    pair: &RouteOverlap,
    winner_route: &str,
    loser_route: &str,
    texts: &Texts,
) -> String {
    let template = if pair.block_wins_tie {
        keys::BLOCK_TIE
    } else {
        match pair.kind {
            RouteOverlapKind::Duplicate => keys::DUPLICATE,
            RouteOverlapKind::Intersecting => keys::INTERSECTING,
            RouteOverlapKind::Nested => keys::NESTED,
        }
    };
    let sentence = texts.fill(
        template,
        &[
            ("winner", describe(&pair.winner, texts)),
            ("loser", describe(&pair.loser, texts)),
            ("winner-route", route_label(winner_route, texts)),
            ("loser-route", route_label(loser_route, texts)),
        ],
    );
    if pair.main_stays_when_additional_down {
        format!("{sentence} {}", texts.get(keys::MAIN_STAYS))
    } else {
        sentence
    }
}

/// `{value} ({type})`; both name kinds are a "Domain" rule in the rules list.
fn describe(side: &OverlapRule, texts: &Texts) -> String {
    let type_label = match side.rule_type.as_str() {
        "exact-fqdn" | "suffix-domain" => texts.get(keys::TYPE_DOMAIN),
        "zone" => texts.get(keys::TYPE_ZONE),
        "exact-ip" => texts.get(keys::TYPE_EXACT_IP),
        "subnet" => texts.get(keys::TYPE_SUBNET),
        "ip-range" => texts.get(keys::TYPE_IP_RANGE),
        other => texts.dynamic(&format!("rules.type.{other}"), other),
    };
    let value = if side.rule_type == "suffix-domain" {
        format!("*.{}", side.value)
    } else {
        side.value.clone()
    };
    texts.fill(keys::RULE, &[("value", value), ("type", type_label)])
}

fn route_label(route: &str, texts: &Texts) -> String {
    texts.get(match route {
        "primary" => keys::ROUTE_PRIMARY,
        "block" => keys::ROUTE_BLOCK,
        _ => keys::ROUTE_SECONDARY,
    })
}

/// One service-reported conflict as a sentence.
fn conflict_text(conflict: &RuleConflictDto, texts: &Texts) -> String {
    let template = match conflict.kind {
        RuleConflictKind::LiteralBlockOverridesRoute => keys::CONFLICT_LITERAL_BLOCK,
        RuleConflictKind::UnsupportedRuleShape => keys::CONFLICT_UNSUPPORTED,
        RuleConflictKind::BlockLeaksSharedAddress => keys::CONFLICT_LEAK,
        RuleConflictKind::NetworkCarvingOverCap => keys::CONFLICT_CARVING_OVER_CAP,
    };
    let rule = if conflict.rule_value.is_empty() {
        &conflict.rule_id
    } else {
        &conflict.rule_value
    };
    let host = if conflict.host.is_empty() {
        &conflict.rule_value
    } else {
        &conflict.host
    };
    let mut text = texts.fill(
        template,
        &[
            ("rule", rule.as_str()),
            ("app", conflict.app.as_str()),
            ("host", host.as_str()),
            ("via", conflict.via_host.as_str()),
            ("ip", conflict.ip.as_str()),
        ],
    );
    let more = conflict.count.saturating_sub(1);
    if more > 0 {
        text.push(' ');
        text.push_str(&texts.fill(keys::CONFLICT_MORE, &[("count", more.to_string())]));
    }
    text
}
