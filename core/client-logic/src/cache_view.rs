//! The cache list's three filters over the loaded rows
//! (`cacheEntryPassesFilters` in `pure.js`): by where a row came from, by
//! whether it is still fresh, and by the route the rules would give it. The
//! search box is not here: the window matches it against localized labels,
//! and the terminal asks the service.

/// The source filter's choices, in the window's order; `all` is off.
pub const CACHE_SOURCE_FILTERS: [&str; 9] = [
    "all",
    "dns",
    "observed-from-traffic",
    "manual-refresh",
    "imported-seed",
    "cache-rebuild",
    "os-cache-seed",
    "reverse-confirmed",
    "browser-history-seed",
];

/// The freshness filter's choices: `fresh` is the one `fresh` slug, `stale`
/// every other one.
pub const CACHE_FRESHNESS_FILTERS: [&str; 3] = ["all", "fresh", "stale"];

/// The route filter's choices; `none` is the rows no rule names.
pub const CACHE_ROUTE_FILTERS: [&str; 4] = ["all", "primary", "secondary", "none"];

/// The three filters by slug, as the window's combo boxes hold them. An empty
/// slug reads as `all`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheFilters<'a> {
    pub source: &'a str,
    pub freshness: &'a str,
    pub route: &'a str,
}

fn or_all(slug: &str) -> &str {
    if slug.is_empty() {
        "all"
    } else {
        slug
    }
}

/// Whether a cache row with these wire fields passes `filters`. Backend slugs
/// are snake_case and the filter slugs kebab-case, so the row's are folded.
#[must_use]
pub fn cache_entry_passes(
    source: &str,
    freshness: &str,
    expected_route: &str,
    filters: &CacheFilters<'_>,
) -> bool {
    let wanted_source = or_all(filters.source);
    if wanted_source != "all" && source.replace('_', "-") != wanted_source {
        return false;
    }
    let fresh = freshness.replace('_', "-") == "fresh";
    match or_all(filters.freshness) {
        "fresh" if !fresh => return false,
        "stale" if fresh => return false,
        _ => {}
    }
    match or_all(filters.route) {
        "all" => true,
        // No rule can cover an IPv6 row: it sits with the rows no rule names.
        "none" => expected_route.is_empty() || expected_route == "ipv6",
        other => expected_route == other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_filters_read_as_all() {
        let none = CacheFilters::default();
        assert!(cache_entry_passes("dns", "stale_usable", "", &none));
    }

    #[test]
    fn the_row_without_a_rule_includes_ipv6() {
        let none = CacheFilters {
            route: "none",
            ..CacheFilters::default()
        };
        assert!(cache_entry_passes("dns", "fresh", "ipv6", &none));
        assert!(cache_entry_passes("dns", "fresh", "", &none));
        assert!(!cache_entry_passes("dns", "fresh", "primary", &none));
    }

    #[test]
    fn stale_is_everything_but_fresh() {
        let stale = CacheFilters {
            freshness: "stale",
            ..CacheFilters::default()
        };
        assert!(cache_entry_passes("dns", "negative_cached", "", &stale));
        assert!(!cache_entry_passes("dns", "fresh", "", &stale));
    }
}
