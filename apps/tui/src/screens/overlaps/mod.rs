//! Screen 5, overlaps: pairs of rules on the two routes that cover the same
//! sites, which route the sites actually take, and the conflicts the service
//! found in the applied rules. The pairs and winners come from
//! `nrr_shared::rules_overlap::find_route_overlaps`, the function the GUI's
//! launcher runs; nothing here decides a winner.
//!
//! "Send over the other route" is an ordinary edit of the rules list: nothing
//! reaches the service until the list is reviewed and applied.

mod keys;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use crossterm::event::{KeyCode, KeyEvent};
use nrr_client_logic::rules_table::{
    file_row_from_service_wire, rule_row_to_wire_dto, RuleRow, TargetRoute, WireDtoOptions,
};
use nrr_client_logic::Route;
use nrr_ipc_client::IpcClient;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    RuleConflictDto, RuleConflictKind, RulesListRequest, RulesListResponse,
};
use nrr_shared::rules_json::{CanonicalRulesJsonV1, RULES_JSON_SCHEMA_VERSION};
use nrr_shared::rules_overlap::{find_route_overlaps, OverlapRule, RouteOverlap, RouteOverlapKind};

use super::suggestions::{call, CallError};
use super::{Screen, ScreenId};
use crate::backend::Reply;
use crate::i18n::{Key, Texts};
use crate::keys as common;
use crate::state::{AppState, Focus};
use crate::view::{Panel, ScreenView, Segment, ViewLine};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Note {
    Failed(CallError),
    NoItem(usize),
    CannotSend(usize),
    Gone(usize),
}

#[derive(Debug, Default)]
pub struct Overlaps {
    /// The rules the pairs are found in, with the service's ids, and where
    /// "send over" writes.
    rows: Vec<RuleRow>,
    /// Pairs over `rows`, recomputed whenever they change.
    pairs: Vec<RouteOverlap>,
    loaded: bool,
    loading: bool,
    /// `rows` hold an edit the service has not applied.
    edited: bool,
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

    /// The row one side of a pair names; `None` when the list moved on.
    fn row_of(&self, side: &OverlapRule) -> Option<usize> {
        self.rows
            .iter()
            .position(|row| bucket_slug(&row.target_route) == side.route && row.id == side.rule_id)
    }

    /// The route as the rules list names it: a block rule rides in the
    /// secondary bucket but is not a route.
    fn route_of<'a>(&'a self, side: &'a OverlapRule) -> &'a str {
        self.row_of(side).map_or(side.route.as_str(), |at| {
            self.rows[at].target_route.as_str()
        })
    }

    /// Only two routing rules can trade places; a block or "primary first"
    /// rule is changed in the rules list.
    fn can_reroute(&self, pair: &RouteOverlap) -> bool {
        is_plain_route(self.route_of(&pair.winner)) && is_plain_route(self.route_of(&pair.loser))
    }

    fn has_block_side(&self, pair: &RouteOverlap) -> bool {
        self.route_of(&pair.winner) == "block" || self.route_of(&pair.loser) == "block"
    }

    fn recompute(&mut self, include_subdomains: bool) {
        self.pairs = find_route_overlaps(&rules_json(&self.rows), include_subdomains);
        // A key of a pair that no longer exists can never be shown again.
        let live: BTreeSet<&str> = self.pairs.iter().map(|p| p.key.as_str()).collect();
        self.confirmed.retain(|k| live.contains(k.as_str()));
        let count = self.shown().len();
        self.selected = self.selected.min(count.saturating_sub(1));
    }
}

fn is_plain_route(route: &str) -> bool {
    route == Route::Primary.as_str() || route == Route::Secondary.as_str()
}

/// The bucket a row rides in, as the wire names it; an unknown target rides
/// with the primary rules, as the GUI's serializer puts it.
fn bucket_slug(target: &TargetRoute) -> &'static str {
    target.bucket().unwrap_or(Route::Primary).as_str()
}

/// The rules in the wire form the overlap finder reads.
fn rules_json(rows: &[RuleRow]) -> CanonicalRulesJsonV1 {
    let mut json = CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary: Vec::new(),
        secondary: Vec::new(),
    };
    for row in rows {
        let dto = rule_row_to_wire_dto(row, None, WireDtoOptions::FULL);
        match row.target_route.bucket() {
            Some(Route::Secondary) => json.secondary.push(dto),
            _ => json.primary.push(dto),
        }
    }
    json
}

/// The reader's subdomain setting; absent means on, the product default.
fn include_subdomains(app: &AppState) -> bool {
    app.snapshot
        .as_ref()
        .and_then(|s| s.route_policy.as_ref())
        .is_none_or(|p| p.include_subdomains)
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

    /// Re-read on every visit, unless an edit made here is still waiting to
    /// be applied: a re-read would throw it away.
    fn on_show(&self, app: &mut AppState) {
        if app.overlaps.edited {
            let subdomains = include_subdomains(app);
            app.overlaps.recompute(subdomains);
        } else if app.link.is_connected() {
            load(app);
        }
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
    let state = &app.overlaps;
    let rows: usize = state
        .shown()
        .iter()
        .take(state.selected)
        .map(|p| pair_line_count(state, p))
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
                'c' => {
                    app.overlaps.confirmed.insert(pair.key);
                }
                'u' => {
                    app.overlaps.confirmed.remove(&pair.key);
                }
                _ => send_over(app, &pair, index),
            }
            let count = app.overlaps.shown().len();
            app.overlaps.selected = app.overlaps.selected.min(count.saturating_sub(1));
        }
        _ => return false,
    }
    true
}

fn confirm_all(app: &mut AppState) {
    let state = &mut app.overlaps;
    let keys: Vec<String> = state.pairs.iter().map(|p| p.key.clone()).collect();
    state.confirmed.extend(keys);
    state.selected = 0;
    state.note = None;
    app.scroll = 0;
}

/// The shared sites take the loser's route: a nested winner moves there; of a
/// duplicate the winning copy is switched off, as the GUI's review does.
fn send_over(app: &mut AppState, pair: &RouteOverlap, index: usize) {
    let state = &mut app.overlaps;
    if !state.can_reroute(pair) {
        state.note = Some(Note::CannotSend(index + 1));
        return;
    }
    let Some(at) = state.row_of(&pair.winner) else {
        state.note = Some(Note::Gone(index + 1));
        return;
    };
    let row = &mut state.rows[at];
    if pair.kind == RouteOverlapKind::Duplicate {
        row.enabled = false;
    } else {
        row.target_route = TargetRoute::from_slug(&pair.loser.route);
    }
    state.edited = true;
    let subdomains = include_subdomains(app);
    app.overlaps.recompute(subdomains);
}

fn load(app: &mut AppState) {
    if app.overlaps.loading {
        return;
    }
    app.overlaps.loading = true;
    app.outbox.push(Box::new(|client: &dyn IpcClient| {
        let answer: Result<RulesListResponse, _> = call(
            client,
            IpcOperationName::RulesList,
            &RulesListRequest::default(),
        );
        Reply::new(move |app| loaded(app, answer))
    }));
}

fn loaded(app: &mut AppState, answer: Result<RulesListResponse, CallError>) {
    app.overlaps.loading = false;
    // An edit made while the read was in flight is newer than the read.
    if app.overlaps.edited {
        return;
    }
    match answer {
        Ok(list) => {
            app.overlaps.rows = list
                .rows
                .iter()
                .map(|entry| RuleRow {
                    id: entry.id.clone(),
                    ..file_row_from_service_wire(entry, str::to_owned)
                })
                .collect();
            app.overlaps.loaded = true;
            app.overlaps.note = None;
            let subdomains = include_subdomains(app);
            app.overlaps.recompute(subdomains);
        }
        Err(error) => app.overlaps.note = Some(Note::Failed(error)),
    }
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
    if state.loaded {
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
        lines.push(ViewLine::text(texts.get(if state.loaded {
            common::STALE
        } else {
            common::NO_DATA
        })));
    } else if state.loading && !state.loaded {
        lines.push(ViewLine::text(texts.get(keys::LOADING)));
    }
    if state.edited {
        let screen = ScreenId::Rules;
        lines.push(ViewLine::new(vec![Segment::strong(
            texts.get(keys::PREVIEW_NOTICE),
        )]));
        lines.push(ViewLine::text(texts.fill(
            keys::APPLY_ON_RULES,
            &[
                ("key", screen.hotkey().to_string()),
                ("screen", texts.get(screen.title())),
            ],
        )));
    }
    if let Some(note) = &state.note {
        let item = |key: Key, n: usize| texts.fill(key, &[("n", n.to_string())]);
        let text = match note {
            Note::Failed(error) => texts.fill(keys::FAILED, &[("error", error.text(texts))]),
            Note::NoItem(n) => item(keys::NO_ITEM, *n),
            Note::CannotSend(n) => item(keys::CANNOT_SEND, *n),
            Note::Gone(n) => item(keys::GONE, *n),
        };
        lines.push(ViewLine::new(vec![Segment::strong(text)]));
    }
    lines
}

fn pair_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let state = &app.overlaps;
    if !state.loaded {
        return Vec::new();
    }
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
        .flat_map(|(i, pair)| {
            pair_item_lines(state, pair, i, focused && i == state.selected, texts)
        })
        .collect()
}

/// Rows one pair takes; [`pair_item_lines`] must agree (a test holds them).
fn pair_line_count(state: &Overlaps, pair: &RouteOverlap) -> usize {
    let note = !state.can_reroute(pair) || pair.kind == RouteOverlapKind::Intersecting;
    3 + usize::from(pair.block_wins_tie) + usize::from(note)
}

fn pair_item_lines(
    state: &Overlaps,
    pair: &RouteOverlap,
    index: usize,
    selected: bool,
    texts: &Texts,
) -> Vec<ViewLine> {
    let marker = if selected { "> " } else { "" };
    let mut lines = vec![ViewLine::new(vec![
        Segment::plain(format!("{marker}{}. ", index + 1)),
        Segment::strong(explain(state, pair, texts)),
    ])];
    lines.push(ViewLine::text(format!(
        "   {}: {}",
        texts.get(keys::REASON_LABEL),
        texts.get(reason(pair))
    )));
    let decision = if state.is_confirmed(pair) {
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
    if !state.can_reroute(pair) {
        let note = if state.has_block_side(pair) {
            keys::BLOCK_NOTE
        } else {
            keys::VERIFY_NOTE
        };
        lines.push(ViewLine::text(format!("   {}", texts.get(note))));
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

/// The whole pair as one sentence, as the GUI reads it to a screen reader.
fn explain(state: &Overlaps, pair: &RouteOverlap, texts: &Texts) -> String {
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
            (
                "winner-route",
                route_label(state.route_of(&pair.winner), texts),
            ),
            (
                "loser-route",
                route_label(state.route_of(&pair.loser), texts),
            ),
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
        "verify" => keys::ROUTE_VERIFY,
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
