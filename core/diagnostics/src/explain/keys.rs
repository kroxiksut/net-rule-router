//! Localization key constants for explain mode.
//!
//! All user-visible text in explain responses uses these keys.
//! The GUI resolves them to display strings via the locale system.
//!
//! Convention: `explain.<section>.<element>[.<state>]`

// ── Summary action keys ───────────────────────────────────────────────────────

pub const SUMMARY_ROUTE_PRIMARY: &str = "explain.summary.route_primary";
pub const SUMMARY_ROUTE_SECONDARY: &str = "explain.summary.route_secondary";
pub const SUMMARY_BLOCKED_FAIL_CLOSED: &str = "explain.summary.blocked_fail_closed";
pub const SUMMARY_BROWSER_STUB_ATTEMPT: &str = "explain.summary.browser_stub_attempt";
pub const SUMMARY_DEFERRED: &str = "explain.summary.deferred";
pub const SUMMARY_SIMULATION: &str = "explain.summary.simulation";

// ── Match section keys ────────────────────────────────────────────────────────

pub const MATCH_RULE_MATCHED: &str = "explain.match.rule_matched";
pub const MATCH_DEFAULT_ROUTE: &str = "explain.match.default_route";
pub const MATCH_CONFLICT_RESOLVED: &str = "explain.match.conflict_resolved";

// ── Lookup/cache section keys ─────────────────────────────────────────────────

pub const LOOKUP_CACHE_HIT: &str = "explain.lookup.cache_hit";
pub const LOOKUP_CACHE_MISS: &str = "explain.lookup.cache_miss";
pub const LOOKUP_STALE_USABLE: &str = "explain.lookup.stale_usable";
pub const LOOKUP_STALE_NOT_USABLE: &str = "explain.lookup.stale_not_usable";
pub const LOOKUP_NEGATIVE_CACHED: &str = "explain.lookup.negative_cached";
pub const LOOKUP_ERRORS_PRESENT: &str = "explain.lookup.errors_present";
pub const LOOKUP_NO_DATA: &str = "explain.lookup.no_data";

// ── Availability section keys ─────────────────────────────────────────────────

pub const AVAIL_SECONDARY_AVAILABLE: &str = "explain.availability_check.secondary_available";
pub const AVAIL_SECONDARY_NOT_CONFIGURED: &str =
    "explain.availability_check.secondary_not_configured";
pub const AVAIL_SECONDARY_NOT_REACHABLE: &str =
    "explain.availability_check.secondary_not_reachable";
pub const AVAIL_SECONDARY_UNKNOWN: &str = "explain.availability_check.secondary_unknown";
pub const AVAIL_SNAPSHOT_STALE: &str = "explain.availability_check.snapshot_stale";

// ── Final action keys ─────────────────────────────────────────────────────────

pub const ACTION_ROUTE_PRIMARY: &str = "explain.final_action.route_primary";
pub const ACTION_ROUTE_SECONDARY: &str = "explain.final_action.route_secondary";
pub const ACTION_BLOCK: &str = "explain.final_action.block";
pub const ACTION_BROWSER_STUB: &str = "explain.final_action.browser_stub";
pub const ACTION_DEFER: &str = "explain.final_action.defer";

// ── Warning keys ──────────────────────────────────────────────────────────────

pub const WARN_STALE_CACHE_USED: &str = "explain.warning.stale_cache_used";
pub const WARN_LOOKUP_TIMEOUT: &str = "explain.warning.lookup_timeout";
pub const WARN_MULTI_IP: &str = "explain.warning.multi_ip_resolved";
pub const WARN_CONFLICT_RESOLVED: &str = "explain.warning.match_conflict_resolved";
pub const WARN_PRIMARY_DEGRADED: &str = "explain.warning.primary_adapter_degraded";
pub const WARN_AVAIL_SNAPSHOT_STALE: &str = "explain.warning.availability_snapshot_stale";
pub const WARN_IPV4_MAPPED_NORMALISED: &str = "explain.warning.ipv4_mapped_normalised";
pub const WARN_WEAK_PROCESS_IDENTITY: &str = "explain.warning.weak_process_identity";
pub const WARN_APP_EXE_SUFFIX_ADDED: &str = "explain.warning.app_exe_suffix_added";
pub const WARN_DOMAIN_TRAILING_DOT: &str = "explain.warning.domain_trailing_dot_removed";

// ── Uncertainty marker keys ───────────────────────────────────────────────────

pub const UNCERTAINTY_HOSTNAME_UNAVAILABLE: &str = "explain.uncertainty.hostname_unavailable";
pub const UNCERTAINTY_APP_CONTEXT_UNAVAILABLE: &str = "explain.uncertainty.app_context_unavailable";
pub const UNCERTAINTY_STALE_CACHE: &str = "explain.uncertainty.stale_cache_used";
pub const UNCERTAINTY_AMBIGUOUS_LOOKUP: &str = "explain.uncertainty.ambiguous_lookup";
pub const UNCERTAINTY_STALE_AVAILABILITY: &str = "explain.uncertainty.stale_availability";
pub const UNCERTAINTY_UNKNOWN_SECONDARY: &str = "explain.uncertainty.unknown_secondary_state";
pub const UNCERTAINTY_IPV6_PRO_ONLY: &str = "explain.uncertainty.ipv6_destination_pro_only";

// ── Fail-Closed reason keys ───────────────────────────────────────────────────

pub const REASON_FAIL_CLOSED_NO_SECONDARY: &str = "explain.reason.fail_closed_no_secondary";
pub const REASON_FAIL_CLOSED_SECONDARY_DOWN: &str = "explain.reason.fail_closed_secondary_down";
pub const REASON_FAIL_OPEN_SECONDARY_DOWN: &str = "explain.reason.fail_open_secondary_down";
pub const REASON_FAIL_OPEN_NOT_CONFIGURED: &str = "explain.reason.fail_open_not_configured";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_keys_have_explain_prefix() {
        for key in [
            SUMMARY_ROUTE_PRIMARY,
            SUMMARY_ROUTE_SECONDARY,
            SUMMARY_BLOCKED_FAIL_CLOSED,
            MATCH_RULE_MATCHED,
            LOOKUP_CACHE_HIT,
            AVAIL_SECONDARY_AVAILABLE,
            ACTION_ROUTE_PRIMARY,
            WARN_STALE_CACHE_USED,
            UNCERTAINTY_HOSTNAME_UNAVAILABLE,
            REASON_FAIL_CLOSED_NO_SECONDARY,
        ] {
            assert!(
                key.starts_with("explain."),
                "key must start with 'explain.': {key}"
            );
        }
    }

    #[test]
    fn all_keys_are_snake_case() {
        for key in [
            SUMMARY_ROUTE_PRIMARY,
            SUMMARY_BLOCKED_FAIL_CLOSED,
            LOOKUP_STALE_USABLE,
            AVAIL_SECONDARY_NOT_CONFIGURED,
            WARN_MULTI_IP,
        ] {
            assert!(
                key.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
                "key must be snake_case with dots: {key}"
            );
        }
    }
}
