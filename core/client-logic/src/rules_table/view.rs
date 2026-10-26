//! The rules table's filters and its order (`rulePassesFilters` and
//! `compareRuleRows` in `rules.js`): which rows the window's four filter
//! boxes, the «auto-added» and «Recent» switches and the search let through,
//! and how the chosen column orders them.

use std::cmp::Ordering;

use super::{main_route_rank, row_matches_search, RuleRow, TargetRoute};

/// The «Status» filter, in the window's order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum StatusFilter {
    #[default]
    All,
    EnabledOnly,
    DisabledOnly,
    /// Rules whose value the validator refuses: they are not applied.
    WithErrors,
    /// Rules applied despite the protection of system programs.
    Overridden,
}

impl StatusFilter {
    pub const ALL: [Self; 5] = [
        Self::All,
        Self::EnabledOnly,
        Self::DisabledOnly,
        Self::WithErrors,
        Self::Overridden,
    ];

    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::EnabledOnly => "enabled-only",
            Self::DisabledOnly => "disabled-only",
            Self::WithErrors => "with-errors",
            Self::Overridden => "overridden",
        }
    }

    /// `None` for a slug this build does not know.
    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.slug() == slug)
    }
}

/// The «Route» filter, in the window's order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
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

    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Primary => "primary",
            Self::Secondary => "secondary",
            Self::Block => "block",
            Self::Unsure => "unsure",
        }
    }

    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.slug() == slug)
    }
}

/// The «Type» filter: `all`, or a canonical rule type slug.
pub const TYPE_FILTERS: [&str; 7] = [
    "all",
    "zone",
    "domain",
    "exact-ip",
    "ip-range",
    "subnet",
    "application",
];

/// The column the list is ordered by, in the window's order of choices.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SortBy {
    /// By rule id, which encodes insertion order.
    #[default]
    DisplayOrder,
    MatchValue,
    Type,
    Route,
    /// What the main route does not reach first, unchecked rules last.
    MainRoute,
}

impl SortBy {
    pub const ALL: [Self; 5] = [
        Self::DisplayOrder,
        Self::MatchValue,
        Self::Type,
        Self::Route,
        Self::MainRoute,
    ];

    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::DisplayOrder => "by-display-order",
            Self::MatchValue => "by-match-value",
            Self::Type => "by-type",
            Self::Route => "by-route",
            Self::MainRoute => "by-main-route",
        }
    }

    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.slug() == slug)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SortDir {
    #[default]
    Asc,
    Desc,
}

/// What the filters and the order read of one row, beyond the rule itself.
#[derive(Clone, Copy, Debug)]
pub struct RuleRowView<'a> {
    pub rule: &'a RuleRow,
    /// The lower-case ACE value, so a search finds either spelling.
    pub ace_lower: &'a str,
    /// The validator's word: `valid`, `warning` or `error`.
    pub validation_status: &'a str,
    /// The last main-route verdict, empty when never checked.
    pub main_route: &'a str,
}

/// The table's filters as set.
#[derive(Clone, Copy, Debug, Default)]
pub struct RulesFilters<'a> {
    pub status: StatusFilter,
    /// One of [`TYPE_FILTERS`]; empty reads as `all`.
    pub rule_type: &'a str,
    pub route: RouteFilter,
    /// Only the rules the application added itself.
    pub auto_only: bool,
    /// Only the rules changed lately («Recent»).
    pub recent_only: bool,
    /// Leave out the rules that do not work (a refused value): the table's
    /// «Show rules that do not work» switched off. Asking for the errors
    /// shows them anyway.
    pub hide_not_working: bool,
    pub search: &'a str,
}

/// Whether `row` passes `filters`. The table, not the row, knows which rules
/// were applied over the protection and which changed lately, so it answers
/// those two on demand.
#[must_use]
pub fn rule_passes_filters(
    row: &RuleRowView<'_>,
    filters: &RulesFilters<'_>,
    is_overridden: impl FnOnce() -> bool,
    is_recent: impl FnOnce() -> bool,
) -> bool {
    let rule = row.rule;
    let status_ok = match filters.status {
        StatusFilter::All => true,
        StatusFilter::EnabledOnly => rule.enabled,
        StatusFilter::DisabledOnly => !rule.enabled,
        // A warning does not disable the rule, so it is not an error here.
        StatusFilter::WithErrors => row.validation_status == "error",
        StatusFilter::Overridden => is_overridden(),
    };
    if !status_ok {
        return false;
    }
    if filters.hide_not_working
        && filters.status != StatusFilter::WithErrors
        && row.validation_status == "error"
    {
        return false;
    }
    if !matches!(filters.rule_type, "" | "all")
        && rule.rule_type.canonical_slug() != filters.rule_type
    {
        return false;
    }
    let route_ok = match filters.route {
        RouteFilter::All => true,
        RouteFilter::Primary => rule.target_route == TargetRoute::Primary,
        RouteFilter::Secondary => rule.target_route == TargetRoute::Secondary,
        RouteFilter::Block => rule.target_route == TargetRoute::Block,
        RouteFilter::Unsure => rule.is_verify(),
    };
    if !route_ok {
        return false;
    }
    if filters.auto_only && rule.auto_origin().is_none() {
        return false;
    }
    if filters.recent_only && !is_recent() {
        return false;
    }
    row_matches_search(rule, row.ace_lower, filters.search)
}

/// JS `<` on strings: by UTF-16 code unit.
fn code_units(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Text order shared with `rules.js`: case folded first, then as written, so
/// the two clients agree without a locale-aware collator.
fn compare_text(a: &str, b: &str) -> Ordering {
    code_units(&a.to_lowercase(), &b.to_lowercase()).then_with(|| code_units(a, b))
}

/// The order of two rows under `sort`; ties on a column fall back to the
/// value. The callers' sorts are stable, so rows equal here keep their order.
#[must_use]
pub fn compare_rule_rows(
    a: &RuleRowView<'_>,
    b: &RuleRowView<'_>,
    sort: SortBy,
    dir: SortDir,
) -> Ordering {
    let by_value = || compare_text(&a.rule.match_value, &b.rule.match_value);
    let ordering = match sort {
        SortBy::DisplayOrder => compare_text(&a.rule.id, &b.rule.id),
        SortBy::MatchValue => by_value(),
        // The spelling the row arrived with, as the window's column sorts.
        SortBy::Type => {
            compare_text(a.rule.rule_type.as_str(), b.rule.rule_type.as_str()).then_with(by_value)
        }
        SortBy::Route => compare_text(a.rule.target_route.as_str(), b.rule.target_route.as_str())
            .then_with(by_value),
        SortBy::MainRoute => main_route_rank(a.main_route)
            .cmp(&main_route_rank(b.main_route))
            .then_with(by_value),
    };
    match dir {
        SortDir::Asc => ordering,
        SortDir::Desc => ordering.reverse(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::RuleType;
    use super::*;

    fn rule(id: &str, value: &str, route: TargetRoute) -> RuleRow {
        RuleRow {
            id: id.into(),
            enabled: true,
            rule_type: RuleType::Domain,
            match_value: value.into(),
            target_route: route,
            verify: false,
            comment: String::new(),
            origin: None,
        }
    }

    fn view(rule: &RuleRow) -> RuleRowView<'_> {
        RuleRowView {
            rule,
            ace_lower: "",
            validation_status: "valid",
            main_route: "",
        }
    }

    #[test]
    fn overridden_is_a_status_the_table_answers() {
        let r = rule("R-0001", "a.example", TargetRoute::Primary);
        let filters = RulesFilters {
            status: StatusFilter::Overridden,
            ..RulesFilters::default()
        };
        assert!(rule_passes_filters(&view(&r), &filters, || true, || false));
        assert!(!rule_passes_filters(
            &view(&r),
            &filters,
            || false,
            || false
        ));
    }

    #[test]
    fn a_block_passes_only_its_own_route_filter() {
        let r = rule("R-0001", "a.example", TargetRoute::Block);
        let block = RulesFilters {
            route: RouteFilter::Block,
            ..RulesFilters::default()
        };
        let secondary = RulesFilters {
            route: RouteFilter::Secondary,
            ..RulesFilters::default()
        };
        assert!(rule_passes_filters(&view(&r), &block, || false, || false));
        assert!(!rule_passes_filters(
            &view(&r),
            &secondary,
            || false,
            || false
        ));
    }

    #[test]
    fn value_order_folds_case_and_descends_on_request() {
        let a = rule("R-0002", "B.example", TargetRoute::Primary);
        let b = rule("R-0001", "a.example", TargetRoute::Primary);
        assert_eq!(
            compare_rule_rows(&view(&a), &view(&b), SortBy::MatchValue, SortDir::Asc),
            Ordering::Greater
        );
        assert_eq!(
            compare_rule_rows(&view(&a), &view(&b), SortBy::MatchValue, SortDir::Desc),
            Ordering::Less
        );
        assert_eq!(
            compare_rule_rows(&view(&a), &view(&b), SortBy::DisplayOrder, SortDir::Asc),
            Ordering::Greater
        );
    }
}
