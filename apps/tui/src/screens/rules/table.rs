//! The rules on screen: rows, what the service holds, the route filter, the
//! search and the chosen row.

use std::collections::{BTreeMap, HashMap};

use nrr_client_logic::rules_table::{
    file_row_from_service_wire, row_matches_search, RowOrigin, RuleRow, RuleType, TargetRoute,
};
use nrr_client_logic::Route;
use nrr_domain::rule_value_validation::validate_rule_value;
use nrr_shared::ipc_payloads::RuleRowEntry;
use nrr_shared::rules_json::FREE_MAX_RULES;

use super::ace;
use super::text;
use crate::i18n::Key;

/// Rows one page of the list shows.
pub const PAGE: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerdictStatus {
    Valid,
    Warning,
    Error,
}

/// The validator's word on a value: the one the GUI's table and dialog show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub status: VerdictStatus,
    pub message_key: String,
    pub args: BTreeMap<String, String>,
}

impl Verdict {
    pub fn of(rule_type: &RuleType, value: &str) -> Self {
        let judged = validate_rule_value(&rule_type.canonical_slug(), value);
        let status = if judged.is_error() {
            VerdictStatus::Error
        } else if judged.is_warning() {
            VerdictStatus::Warning
        } else {
            VerdictStatus::Valid
        };
        Self {
            status,
            message_key: judged.message_key().to_owned(),
            args: judged.args().clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// `rule.id` is the list's own `R-NNNN`, unique across both routes.
    pub rule: RuleRow,
    /// The id `rules.list` gave the rule; `None` for a row added here. The
    /// service numbers each route on its own, so it repeats across the two.
    pub service_id: Option<String>,
    /// Lower-case ACE value, so a search finds either spelling.
    pub ace_lower: String,
    pub verdict: Verdict,
}

impl Row {
    pub fn new(rule: RuleRow) -> Self {
        let ace_lower = if rule.rule_type.is_hostlike() {
            ace::encode(&rule.match_value).to_lowercase()
        } else {
            rule.match_value.to_lowercase()
        };
        let verdict = Verdict::of(&rule.rule_type, &rule.match_value);
        Self {
            rule,
            service_id: None,
            ace_lower,
            verdict,
        }
    }
}

/// The table's route filter, in the GUI's order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RouteFilter {
    #[default]
    All,
    Primary,
    Secondary,
    Block,
    /// The `?` rules, on either route.
    Unsure,
}

impl RouteFilter {
    pub const ALL: [Self; 5] = [
        Self::All,
        Self::Primary,
        Self::Secondary,
        Self::Block,
        Self::Unsure,
    ];

    pub fn label(self) -> Key {
        match self {
            Self::All => text::ROUTE_ALL,
            Self::Primary => text::ROUTE_PRIMARY,
            Self::Secondary => text::ROUTE_SECONDARY,
            Self::Block => text::ROUTE_BLOCK,
            Self::Unsure => text::ROUTE_UNSURE,
        }
    }

    fn passes(self, rule: &RuleRow) -> bool {
        let route = &rule.target_route;
        match self {
            Self::All => true,
            Self::Primary => *route == TargetRoute::Primary,
            Self::Secondary => *route == TargetRoute::Secondary,
            Self::Block => *route == TargetRoute::Block,
            Self::Unsure => rule.is_verify(),
        }
    }
}

/// The words for a route, as the table and the review show it.
pub fn route_label(route: &TargetRoute) -> Option<Key> {
    match route {
        TargetRoute::Primary => Some(text::ROUTE_PRIMARY),
        TargetRoute::Secondary => Some(text::ROUTE_SECONDARY),
        TargetRoute::Block => Some(text::ROUTE_BLOCK),
        TargetRoute::Other(_) => None,
    }
}

/// The routing part of a row, and its note: what "unchanged" compares.
fn content(rule: &RuleRow) -> RuleRow {
    RuleRow {
        id: String::new(),
        ..rule.clone()
    }
}

#[derive(Debug, Default)]
pub struct Table {
    pub rows: Vec<Row>,
    /// What the service applies, as last read; `None` before the first read.
    baseline: Option<Vec<RuleRow>>,
    pub filter: RouteFilter,
    pub search: String,
    /// Position of the chosen row among the visible ones.
    pub cursor: usize,
    /// Sections of the last imported files this build does not apply, per
    /// route file, written back on export.
    pub passthrough: [BTreeMap<String, String>; 2],
}

impl Table {
    /// Master indices of the rows the filter and the search let through.
    pub fn visible(&self) -> Vec<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                self.filter.passes(&row.rule)
                    && row_matches_search(&row.rule, &row.ace_lower, &self.search)
            })
            .map(|(i, _)| i)
            .collect()
    }

    pub fn selected(&self) -> Option<usize> {
        self.visible().get(self.cursor).copied()
    }

    pub fn clamp_cursor(&mut self) {
        let shown = self.visible().len();
        self.cursor = self.cursor.min(shown.saturating_sub(1));
    }

    pub fn move_cursor(&mut self, by: isize) {
        let shown = self.visible().len();
        if shown == 0 {
            self.cursor = 0;
            return;
        }
        let target = self.cursor.saturating_add_signed(by);
        self.cursor = target.min(shown - 1);
    }

    /// Put the cursor on the row at `master`, clearing the filter and the
    /// search when they hide it.
    pub fn select(&mut self, master: usize) {
        if !self.visible().contains(&master) {
            self.filter = RouteFilter::All;
            self.search.clear();
        }
        if let Some(at) = self.visible().iter().position(|&i| i == master) {
            self.cursor = at;
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.baseline.is_some()
    }

    /// Whether the rows differ from what the service applies. Without a read
    /// any row on screen is a change.
    pub fn is_dirty(&self) -> bool {
        match &self.baseline {
            Some(base) => {
                base.len() != self.rows.len()
                    || base
                        .iter()
                        .zip(&self.rows)
                        .any(|(b, r)| *b != content(&r.rule))
            }
            None => !self.rows.is_empty(),
        }
    }

    /// The service's rules, numbered from `R-0001` in its order: it numbers
    /// each route on its own, so its ids repeat across the two.
    pub fn load(&mut self, entries: &[RuleRowEntry]) {
        self.rows = entries
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let mut rule = file_row_from_service_wire(entry, ace::decode);
                rule.id = rule_id(i + 1);
                let mut row = Row::new(rule);
                row.service_id = Some(entry.id.clone());
                row
            })
            .collect();
        self.mark_applied();
        self.clamp_cursor();
    }

    /// The rows on screen are what the service now applies.
    pub fn mark_applied(&mut self) {
        self.baseline = Some(self.rows.iter().map(|r| content(&r.rule)).collect());
    }

    /// `R-NNNN` past the highest in use (`nextFreeRuleId`).
    pub fn next_free_id(&self) -> String {
        let highest = self
            .rows
            .iter()
            .filter_map(|r| r.rule.id.strip_prefix("R-")?.parse::<usize>().ok())
            .max()
            .unwrap_or(0);
        rule_id((highest + 1).min(FREE_MAX_RULES))
    }

    /// Rules the user wrote; the cap is their allowance (`userRuleCount`).
    pub fn user_rule_count(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| r.rule.auto_origin().is_none())
            .count()
    }

    /// Another row with the same type, value and route (`mergeKey`).
    pub fn duplicate_of(&self, rule: &RuleRow, except: Option<usize>) -> Option<usize> {
        let wanted = rule.merge_key();
        self.rows
            .iter()
            .enumerate()
            .find(|(i, r)| Some(*i) != except && r.rule.merge_key() == wanted)
            .map(|(i, _)| i)
    }

    /// Rows read from files: `replace` drops every row first; otherwise only
    /// rows not already present are added. `?x` and `x` on one route are one
    /// rule, and the plain one wins. Returns how many were added.
    pub fn import(&mut self, parsed: Vec<RuleRow>, replace: bool) -> usize {
        if replace {
            self.rows.clear();
        }
        let mut seen: HashMap<String, usize> = self
            .rows
            .iter()
            .enumerate()
            .map(|(i, r)| (r.rule.merge_key(), i))
            .collect();
        let mut added = 0;
        for mut rule in parsed {
            if let Some(&at) = seen.get(&rule.merge_key()) {
                if !rule.is_verify() {
                    self.rows[at].rule.verify = false;
                }
                continue;
            }
            rule.id = self.next_free_id();
            seen.insert(rule.merge_key(), self.rows.len());
            self.rows.push(Row::new(rule));
            added += 1;
        }
        self.clamp_cursor();
        added
    }
}

/// The working copy as other screens read and edit it.
impl Table {
    /// The rules in list order, ids unique across both routes.
    pub fn rules(&self) -> impl Iterator<Item = &RuleRow> {
        self.rows.iter().map(|r| &r.rule)
    }

    /// The row with list id `id` riding in `bucket`.
    pub fn find(&self, bucket: Route, id: &str) -> Option<usize> {
        self.rows.iter().position(|r| {
            r.rule.id == id && r.rule.target_route.bucket().unwrap_or(Route::Primary) == bucket
        })
    }

    /// Move the rule to another route; `false` when it is not in the list.
    pub fn set_route(&mut self, bucket: Route, id: &str, to: TargetRoute) -> bool {
        let Some(at) = self.find(bucket, id) else {
            return false;
        };
        let rule = &mut self.rows[at].rule;
        // A block takes no `?`; it must not come back on a later move.
        if to == TargetRoute::Block {
            rule.verify = false;
        }
        rule.target_route = to;
        true
    }

    /// Switch the rule on or off; `false` when it is not in the list.
    pub fn set_enabled(&mut self, bucket: Route, id: &str, enabled: bool) -> bool {
        let Some(at) = self.find(bucket, id) else {
            return false;
        };
        self.rows[at].rule.enabled = enabled;
        true
    }
}

pub fn rule_id(n: usize) -> String {
    format!("R-{n:04}")
}

/// A row from a parsed rules file, as the GUI's import builds it.
pub fn row_from_parsed(rule: &nrr_shared::preset_parser::ParsedRule, file: Route) -> RuleRow {
    let rule_type = RuleType::from_slug(rule.rule_type.slug());
    let match_value = if rule_type.is_hostlike() {
        ace::decode(&rule.match_value)
    } else {
        rule.match_value.clone()
    };
    RuleRow {
        id: String::new(),
        enabled: rule.enabled,
        target_route: nrr_client_logic::rules_table::parsed_rule_target_route(rule, file),
        verify: nrr_client_logic::rules_table::parsed_rule_verify(rule),
        rule_type,
        match_value,
        comment: rule.comment.clone(),
        origin: rule.origin.as_ref().map(|origin| RowOrigin {
            reason: origin.reason().as_slug().to_owned(),
            anchor: origin.anchor().to_owned(),
            added: origin.added().to_owned(),
        }),
    }
}
