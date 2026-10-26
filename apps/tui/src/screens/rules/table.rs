//! The rules on screen: rows, what the service holds, the route filter, the
//! search and the chosen row.

use std::collections::{BTreeMap, HashMap};

use nrr_client_logic::rebase::{merge_view, rebase_edits, MergeView};
use nrr_client_logic::rules_table::{
    self as logic, compare_rule_rows, file_row_from_service_wire, main_route_check_hosts,
    rule_passes_filters, RowOrigin, RuleRow, RuleRowView, RuleType, RulesFilters, SortDir,
    TargetRoute,
};
use nrr_client_logic::Route;
use nrr_domain::rule_value_validation::{
    validate_rule_value, validate_rule_value_for, RuleEffect, RuleValueValidation,
};
use nrr_shared::ipc_payloads::RuleRowEntry;
use nrr_shared::preset_parser::{app_section_os_label, other_os_app_rules};
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
        Self::from_judged(&validate_rule_value(&rule_type.canonical_slug(), value))
    }

    /// The verdict for a rule on `route`: a deny or the additional route may
    /// not name a program the system needs, as the GUI's dialog and table say.
    pub fn for_route(rule_type: &RuleType, value: &str, route: &TargetRoute) -> Self {
        let effect = match route {
            TargetRoute::Primary => Some(RuleEffect::PrimaryRoute),
            TargetRoute::Secondary => Some(RuleEffect::SecondaryRoute),
            TargetRoute::Block => Some(RuleEffect::Deny),
            TargetRoute::Other(_) => None,
        };
        match effect {
            Some(effect) => Self::from_judged(&validate_rule_value_for(
                &rule_type.canonical_slug(),
                value,
                effect,
            )),
            None => Self::of(rule_type, value),
        }
    }

    fn from_judged(judged: &RuleValueValidation) -> Self {
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
    /// What the last main-route check found (`answered`, `silent`,
    /// `no-address`, `unclear`); `None` when it never asked about this rule.
    pub main_route: Option<String>,
    /// What an application rule holds on the additional link, machine-wide:
    /// a sample as `rules.list` carries it and the service's true count.
    pub pinned: Vec<String>,
    pub pinned_total: usize,
    /// The OS hosts file answers this hostname before the service sees it.
    pub hosts_override: Option<nrr_shared::ipc_payloads::HostsOverrideDto>,
    /// Picked for an action on several rules at once.
    pub marked: bool,
}

impl Row {
    pub fn new(rule: RuleRow) -> Self {
        let ace_lower = if rule.rule_type.is_hostlike() {
            ace::encode(&rule.match_value).to_lowercase()
        } else {
            rule.match_value.to_lowercase()
        };
        let verdict = Verdict::for_route(&rule.rule_type, &rule.match_value, &rule.target_route);
        Self {
            rule,
            service_id: None,
            ace_lower,
            verdict,
            main_route: None,
            pinned: Vec::new(),
            pinned_total: 0,
            hosts_override: None,
            marked: false,
        }
    }

    /// Move to another route; the route decides whether a program the rule
    /// names is protected, and a deny takes no `?`.
    pub fn move_to(&mut self, to: TargetRoute) {
        if to == TargetRoute::Block {
            self.rule.verify = false;
        }
        self.rule.target_route = to;
        self.verdict = Verdict::for_route(
            &self.rule.rule_type,
            &self.rule.match_value,
            &self.rule.target_route,
        );
    }

    /// What the shared filters and order read of this row.
    fn view(&self) -> RuleRowView<'_> {
        RuleRowView {
            rule: &self.rule,
            ace_lower: &self.ace_lower,
            validation_status: match self.verdict.status {
                VerdictStatus::Valid => "valid",
                VerdictStatus::Warning => "warning",
                VerdictStatus::Error => "error",
            },
            main_route: self.main_route.as_deref().unwrap_or_default(),
        }
    }

    /// The host a main-route check asks about for this rule, if any.
    pub fn check_host(&self) -> Option<String> {
        main_route_check_hosts([(&self.rule, Some(self.ace_lower.as_str()))])
            .into_iter()
            .next()
    }

    /// An edit that leaves the host as it was keeps the host's verdict.
    pub fn inherit_main_route(&mut self, old: &Row) {
        if self.mark_key() == old.mark_key() {
            self.main_route.clone_from(&old.main_route);
        }
    }

    /// Whose verdict a `rules.list` entry carries: the type as one spelling,
    /// the value as the service holds it.
    fn mark_key(&self) -> (String, String) {
        (
            self.rule.rule_type.canonical_slug().into_owned(),
            self.ace_lower.clone(),
        )
    }
}

fn entry_mark_key(entry: &RuleRowEntry) -> (String, String) {
    (
        RuleType::from_slug(&entry.rule_type)
            .canonical_slug()
            .into_owned(),
        entry.match_value.trim().to_lowercase(),
    )
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
    /// The rules applied despite the protection of system programs.
    Overridden,
}

impl RouteFilter {
    pub const ALL: [Self; 6] = [
        Self::All,
        Self::Primary,
        Self::Secondary,
        Self::Block,
        Self::Unsure,
        Self::Overridden,
    ];

    pub fn label(self) -> Key {
        match self {
            Self::All => text::ROUTE_ALL,
            Self::Primary => text::ROUTE_PRIMARY,
            Self::Secondary => text::ROUTE_SECONDARY,
            Self::Block => text::FILTER_DENIED,
            Self::Unsure => text::ROUTE_UNSURE,
            Self::Overridden => text::FILTER_OVERRIDDEN,
        }
    }

    /// The shared route filter; «overridden» is the shared status filter,
    /// offered here so that it combines with a status.
    fn shared(self) -> logic::RouteFilter {
        match self {
            Self::All | Self::Overridden => logic::RouteFilter::All,
            Self::Primary => logic::RouteFilter::Primary,
            Self::Secondary => logic::RouteFilter::Secondary,
            Self::Block => logic::RouteFilter::Block,
            Self::Unsure => logic::RouteFilter::Unsure,
        }
    }
}

/// Which rules by their state, as the window's «Status» filter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StatusFilter {
    #[default]
    All,
    EnabledOnly,
    DisabledOnly,
    /// Rules whose value the validator refuses: they are not applied.
    WithErrors,
}

impl StatusFilter {
    pub const ALL: [Self; 4] = [
        Self::All,
        Self::EnabledOnly,
        Self::DisabledOnly,
        Self::WithErrors,
    ];

    pub fn label(self) -> Key {
        match self {
            Self::All => text::STATUS_ALL,
            Self::EnabledOnly => text::STATUS_ENABLED,
            Self::DisabledOnly => text::STATUS_DISABLED,
            Self::WithErrors => text::STATUS_ERRORS,
        }
    }

    fn shared(self) -> logic::StatusFilter {
        match self {
            Self::All => logic::StatusFilter::All,
            Self::EnabledOnly => logic::StatusFilter::EnabledOnly,
            Self::DisabledOnly => logic::StatusFilter::DisabledOnly,
            Self::WithErrors => logic::StatusFilter::WithErrors,
        }
    }
}

pub use logic::TYPE_FILTERS;

pub fn type_filter_label(slug: &str) -> Key {
    match slug {
        "zone" => text::TYPE_FILTER_ZONE,
        "domain" => text::TYPE_FILTER_DOMAIN,
        "exact-ip" => text::TYPE_FILTER_EXACT_IP,
        "ip-range" => text::TYPE_FILTER_IP_RANGE,
        "subnet" => text::TYPE_FILTER_SUBNET,
        "application" => text::TYPE_FILTER_APPLICATION,
        _ => text::TYPE_FILTER_ALL,
    }
}

/// The list's order, the window's sort choices in their order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SortMode {
    /// As the rules are kept.
    #[default]
    Display,
    MatchValue,
    Type,
    Route,
    /// What the main route does not reach first, unchecked rules last.
    MainRoute,
}

impl SortMode {
    /// The shared column; `None` keeps the rules as they are kept.
    fn shared(self) -> Option<logic::SortBy> {
        match self {
            Self::Display => None,
            Self::MatchValue => Some(logic::SortBy::MatchValue),
            Self::Type => Some(logic::SortBy::Type),
            Self::Route => Some(logic::SortBy::Route),
            Self::MainRoute => Some(logic::SortBy::MainRoute),
        }
    }

    pub fn next(self) -> Self {
        match self {
            Self::Display => Self::MatchValue,
            Self::MatchValue => Self::Type,
            Self::Type => Self::Route,
            Self::Route => Self::MainRoute,
            Self::MainRoute => Self::Display,
        }
    }

    pub fn label(self) -> Key {
        match self {
            Self::Display => text::SORT_DISPLAY,
            Self::MatchValue => text::SORT_MATCH_VALUE,
            Self::Type => text::SORT_TYPE,
            Self::Route => text::SORT_ROUTE,
            Self::MainRoute => text::SORT_MAIN_ROUTE,
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

/// The rows on screen and the rules they were made against: laid over
/// rules read since, they say what the user changed (`rebase_edits`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Edits {
    /// The rules last read.
    base: Vec<RuleRow>,
    /// The rows on screen.
    edited: Vec<RuleRow>,
}

impl Edits {
    /// What these edits would add, change and delete over `entries`, the rules
    /// the service lists now, and where they would clash.
    pub fn preview(&self, entries: &[RuleRowEntry]) -> MergeView {
        let fresh: Vec<RuleRow> = entries
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let mut rule = file_row_from_service_wire(entry, ace::decode);
                rule.id = rule_id(i + 1);
                rule
            })
            .collect();
        merge_view(&rebase_edits(&self.base, &self.edited, &fresh, &[]))
    }
}

/// The routing part of a row, and its note: what "unchanged" compares.
fn content(rule: &RuleRow) -> RuleRow {
    RuleRow {
        id: String::new(),
        ..rule.clone()
    }
}

/// A program rule of another OS's section in a rules file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtherOsRow {
    /// The OS, as the user reads it.
    pub os: &'static str,
    pub row: Row,
}

#[derive(Debug, Default)]
pub struct Table {
    pub rows: Vec<Row>,
    /// What the service applies, as last read; `None` before the first read.
    baseline: Option<Vec<RuleRow>>,
    pub filter: RouteFilter,
    pub status: StatusFilter,
    /// One of [`TYPE_FILTERS`].
    pub type_filter: &'static str,
    /// Only the rules the app added itself.
    pub auto_only: bool,
    /// The rules that do not work are left out of the list.
    pub hide_not_working: bool,
    pub search: String,
    pub sort: SortMode,
    /// Position of the chosen row among the visible ones, as last put; read
    /// through [`Table::cursor`].
    cursor: usize,
    /// The chosen rule (`merge_key`). The list re-sorts while a main-route
    /// check runs and is re-read on every revision, so a position alone would
    /// soon name another rule.
    anchor: Option<String>,
    /// Sections of the last imported files this build does not apply, per
    /// route file, written back on export.
    pub passthrough: [BTreeMap<String, String>; 2],
    /// «Recent» while it is on: only the rules changed lately are shown,
    /// newest first.
    pub recent: Option<super::recent::Recent>,
    /// Keys ([`super::overrides::key_of`]) of the rules applied despite the
    /// protection, for the filter by them.
    pub overridden: std::collections::HashSet<String>,
}

impl Table {
    /// Master indices of the rows the filter and the search let through, in
    /// the chosen order.
    pub fn visible(&self) -> Vec<usize> {
        let filters = self.filters();
        let is_overridden =
            |rule: &RuleRow| self.overridden.contains(&super::overrides::key_of(rule));
        let mut shown: Vec<usize> = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                (self.filter != RouteFilter::Overridden || is_overridden(&row.rule))
                    && rule_passes_filters(
                        &row.view(),
                        &filters,
                        || is_overridden(&row.rule),
                        || {
                            self.recent
                                .as_ref()
                                .is_some_and(|recent| recent.at_of(&row.rule).is_some())
                        },
                    )
            })
            .map(|(i, _)| i)
            .collect();
        if let Some(recent) = &self.recent {
            // Newest first, whatever the order chosen.
            shown.sort_by_key(|&i| std::cmp::Reverse(recent.at_of(&self.rows[i].rule)));
            return shown;
        }
        if let Some(sort) = self.sort.shared() {
            // Stable, so rows the order calls equal keep theirs.
            shown.sort_by(|&a, &b| {
                compare_rule_rows(
                    &self.rows[a].view(),
                    &self.rows[b].view(),
                    sort,
                    SortDir::Asc,
                )
            });
        }
        shown
    }

    fn filters(&self) -> RulesFilters<'_> {
        RulesFilters {
            status: self.status.shared(),
            rule_type: self.type_filter,
            route: self.filter.shared(),
            auto_only: self.auto_only,
            recent_only: self.recent.is_some(),
            hide_not_working: self.hide_not_working,
            search: &self.search,
        }
    }

    /// Another OS's programs in the files, as the filters let them through.
    /// Read only: the file carries them as written, the service never sees
    /// them, so they are not rows of the list.
    pub fn other_os_rows(&self) -> Vec<OtherOsRow> {
        if self.filter == RouteFilter::Overridden {
            return Vec::new();
        }
        let filters = self.filters();
        let mut shown = Vec::new();
        for (route, sections) in Route::ALL.into_iter().zip(&self.passthrough) {
            for (name, raw_text) in sections {
                let Some(os) = app_section_os_label(name) else {
                    continue;
                };
                for parsed in other_os_app_rules(name, raw_text) {
                    let mut row = Row::new(row_from_parsed(&parsed, route));
                    row.verdict = Verdict {
                        status: VerdictStatus::Error,
                        message_key: text::OTHER_OS_NOT_APPLIED.id.to_owned(),
                        args: BTreeMap::from([("os".to_owned(), os.to_owned())]),
                    };
                    if rule_passes_filters(&row.view(), &filters, || false, || false) {
                        shown.push(OtherOsRow { os, row });
                    }
                }
            }
        }
        shown
    }

    /// Rules whose value is refused, so they are not applied.
    pub fn invalid_count(&self) -> usize {
        self.rows
            .iter()
            .filter(|row| row.verdict.status == VerdictStatus::Error)
            .count()
    }

    /// Back to every rule, as after an import.
    pub fn clear_filters(&mut self) {
        self.filter = RouteFilter::All;
        self.status = StatusFilter::All;
        self.type_filter = TYPE_FILTERS[0];
        self.auto_only = false;
        self.search.clear();
    }

    pub fn selected(&self) -> Option<usize> {
        let shown = self.visible();
        shown.get(self.cursor_in(&shown)).copied()
    }

    /// Where the chosen rule stands among the visible rows.
    pub fn cursor(&self) -> usize {
        self.cursor_in(&self.visible())
    }

    /// [`Table::cursor`] over `shown`, as [`Table::visible`] gave it. A rule
    /// that has left the list leaves the cursor where it was.
    pub fn cursor_in(&self, shown: &[usize]) -> usize {
        if let Some(key) = &self.anchor {
            if let Some(at) = shown
                .iter()
                .position(|&i| self.rows[i].rule.merge_key() == *key)
            {
                return at;
            }
        }
        self.cursor.min(shown.len().saturating_sub(1))
    }

    /// Put the cursor at visible position `at`, on the rule that stands there.
    pub fn set_cursor(&mut self, at: usize) {
        let shown = self.visible();
        self.cursor = at.min(shown.len().saturating_sub(1));
        self.anchor = shown
            .get(self.cursor)
            .map(|&i| self.rows[i].rule.merge_key());
    }

    /// The rule at `master` is the chosen one again after an edit changed its
    /// type, value or route.
    pub fn keep_chosen(&mut self, master: usize) {
        if let Some(row) = self.rows.get(master) {
            self.anchor = Some(row.rule.merge_key());
            self.cursor = self.cursor();
        }
    }

    pub fn clamp_cursor(&mut self) {
        let at = self.cursor();
        self.set_cursor(at);
    }

    pub fn move_cursor(&mut self, by: isize) {
        let from = self.cursor();
        self.set_cursor(from.saturating_add_signed(by));
    }

    /// Put the cursor on the row at `master`, clearing the filter and the
    /// search when they hide it.
    pub fn select(&mut self, master: usize) {
        if !self.visible().contains(&master) {
            self.filter = RouteFilter::All;
            self.search.clear();
            self.recent = None;
        }
        if let Some(at) = self.visible().iter().position(|&i| i == master) {
            self.set_cursor(at);
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
                row.main_route = entry.main_route.clone();
                row.pinned = entry.pinned_destinations.clone().unwrap_or_default();
                row.pinned_total = entry.pinned_destinations_total.unwrap_or(row.pinned.len());
                row.hosts_override = entry.hosts_override.clone();
                row
            })
            .collect();
        self.mark_applied();
        self.clamp_cursor();
    }

    /// Takes in the main-route verdicts of a fresh read and nothing else, so
    /// edits on screen survive.
    pub fn merge_main_route(&mut self, entries: &[RuleRowEntry]) {
        // The service may hold an IDN value in either spelling: key each
        // entry by both, and look a row up by its ACE form, then as typed.
        let mut marks: HashMap<(String, String), Option<String>> = HashMap::new();
        for entry in entries {
            let key = entry_mark_key(entry);
            let ace_key = (key.0.clone(), ace::encode(&key.1).to_lowercase());
            marks.insert(ace_key, entry.main_route.clone());
            marks.insert(key, entry.main_route.clone());
        }
        for row in &mut self.rows {
            let typed = (
                row.rule.rule_type.canonical_slug().into_owned(),
                row.rule.match_value.trim().to_lowercase(),
            );
            if let Some(mark) = marks.get(&row.mark_key()).or_else(|| marks.get(&typed)) {
                row.main_route.clone_from(mark);
            }
        }
    }

    /// The hosts a main-route check asks about.
    pub fn check_hosts(&self) -> Vec<String> {
        main_route_check_hosts(
            self.rows
                .iter()
                .map(|r| (&r.rule, Some(r.ace_lower.as_str()))),
        )
    }

    /// What the rows on screen changed against the rules last read.
    pub fn edits(&self) -> Edits {
        Edits {
            base: self.baseline.clone().unwrap_or_default(),
            edited: self.rows.iter().map(|r| r.rule.clone()).collect(),
        }
    }

    /// `edits` laid over the rows just read: a rule removed goes, a row of
    /// the same rule is replaced, a new one is added.
    /// A rule in `keep_theirs` (by `merge_key`) stays as the rules in force
    /// have it.
    pub fn apply_edits(&mut self, edits: Edits, keep_theirs: &[String]) {
        let fresh: Vec<RuleRow> = self.rows.iter().map(|r| r.rule.clone()).collect();
        let rebased = rebase_edits(&edits.base, &edits.edited, &fresh, keep_theirs);
        let mut old: HashMap<String, Row> = HashMap::new();
        for row in std::mem::take(&mut self.rows) {
            old.entry(row.rule.merge_key()).or_insert(row);
        }
        let mut next = rebased
            .rows
            .iter()
            .filter_map(|r| r.id.strip_prefix("R-")?.parse::<usize>().ok())
            .max()
            .unwrap_or(0);
        for rule in rebased.rows {
            let kept = old.remove(&rule.merge_key());
            let row = match kept {
                Some(old) if old.rule == rule => old,
                Some(old) => {
                    let mut row = Row {
                        service_id: old.service_id.clone(),
                        ..Row::new(rule)
                    };
                    row.inherit_main_route(&old);
                    row
                }
                None => {
                    next += 1;
                    Row::new(RuleRow {
                        id: rule_id(next.min(FREE_MAX_RULES)),
                        ..rule
                    })
                }
            };
            self.rows.push(row);
        }
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
        self.rows[at].move_to(to);
        true
    }

    /// The rows picked for an action on several, in list order.
    pub fn marked(&self) -> Vec<usize> {
        (0..self.rows.len())
            .filter(|&i| self.rows[i].marked)
            .collect()
    }

    pub fn clear_marks(&mut self) {
        for row in &mut self.rows {
            row.marked = false;
        }
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
        rule.stored_value()
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
