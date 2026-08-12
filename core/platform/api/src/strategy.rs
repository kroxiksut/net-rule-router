//! Per-rule-type implementation strategy and risk matrix.
//!
//! ## Decision: Route table vs WFP
//!
//! Two Win32 mechanisms are available for traffic control:
//!
//! | | Route table | WFP (ALE layer) |
//! |---|---|---|
//! | Granularity | Per destination prefix or host | Per flow (src/dst/port/process) |
//! | Mechanism | Redirect packets via different gateway | Permit or block at flow creation |
//! | Privilege needed | Admin / LocalSystem | Admin / LocalSystem |
//! | Latency | ~2 ms per route add | ~5 ms per filter add (in transaction) |
//! | Persistence | Route table entries survive service restart | Dynamic WFP session objects vanish on close |
//! | Idempotency | Manual (check-before-add) | Native (duplicate key = conflict) |
//! | Max objects | ~1000 routes practical | ~10000 filters practical |
//! | IPv6 | Not in scope | Not in scope |
//!
//! **Conclusion:** Route table for routing (directing traffic to secondary
//! adapter); WFP ALE for blocking (Fail-Closed enforcement when secondary
//! is unavailable) and for application-specific rules.
//!
//! ## Per-rule-type strategy
//!
//! See [`RuleImplementationStrategy`] for the enum and
//! [`rule_strategy`] for the mapping function.
//!
//! ## WFP callout driver (kernel-mode)
//!
//! A kernel-mode WFP callout driver would allow per-process traffic
//! redirection (route secondary traffic from a specific process without
//! touching the system route table). This is required for full Application
//! rule support (routing mode, not just blocking).
//!
//! **Decision: callout driver is out of scope for MVP.** Reasons:
//! - Requires a kernel-mode driver signed with an EV certificate.
//! - Driver development, testing, and signing adds significant scope.
//! - Application rules in Free tier support **block mode only** (WFP ALE
//!   `FWP_ACTION_BLOCK` when secondary is unavailable). Traffic routing
//!   via secondary must use an explicit IP-based rule alongside the app rule.
//! - Full per-process routing (routing mode) is a Pro-tier feature via callout.
//!
//! ## Risk matrix
//!
//! | Risk | Trigger | Consequence | Mitigation |
//! |------|---------|-------------|------------|
//! | Wrong default gateway | Delete system default route | User loses all internet connectivity | Only manipulate routes with `is_ours = true`; never delete system routes |
//! | DNS blockage | WFP block filter covers 53/udp | User cannot resolve domain names | Loopback (127.0.0.0/8) + link-local (169.254.0.0/16) always exempt from blocks |
//! | WFP filter orphan | Service crash / hard-kill (non-dynamic session — filters survive) | Stale block filters could lock the user out | Graceful stop strips all filters by id + enumerate (`cleanup_wfp`); service startup strips orphaned block filters (`cleanup_blocks_only`) so a kill-switch never persists unmanaged |
//! | Route table pollution | Service crash after add, before cleanup | Extra routes linger in routing table | `is_ours` flag + cleanup-on-start scans for our routes |
//! | Primary internet loss | Block filter on primary dest | Primary route traffic blocked | Our filters only block secondary-rule destinations; primary traffic exempt |
//! | AV/firewall conflict | 3rd-party AV blocks our WFP calls | Apply fails silently or with access error | `PlatformError::AccessDenied` → health warning in GUI; user prompted to allowlist service |
//! | Metric conflict with VPN | VPN adds lower-metric route for same dest | VPN route takes priority over ours | Document expected behavior; VPN users may need to adjust VPN settings |

// ── Rule implementation strategy ─────────────────────────────────────────────

/// The Win32 mechanism used to enforce one rule type.
///
/// The service layer selects the correct strategy for each
/// rule in the canonical rule book before constructing the `ApplyActionPlan`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleImplementationStrategy {
    /// Add an IPv4 route entry directing traffic to the secondary gateway.
    /// Used when secondary adapter is **available**.
    /// `CreateIpForwardEntry2` + `DeleteIpForwardEntry2`.
    RouteTableEntry,

    /// Add a WFP block filter for Fail-Closed enforcement.
    /// Used when secondary adapter is **unavailable** and rule requires secondary.
    /// `FwpmFilterAdd0` on `FWPM_LAYER_ALE_AUTH_CONNECT_V4`.
    WfpBlockFilter,

    /// Add both a route table entry (for when secondary is available) AND
    /// a WFP block filter (for when secondary is unavailable).
    /// The WFP filter is activated/deactivated by the apply layer based on
    /// `AdapterAvailability`.
    RouteWithFailClosedBlock,

    /// WFP ALE filter with application-path condition (`FWPM_CONDITION_ALE_APP_ID`).
    /// Supports **block mode only** in Free tier (no per-process routing without
    /// kernel callout driver — see module doc).
    WfpApplicationFilter,

    /// IPv6 destination — **skip silently**. No route or filter added.
    /// IPv6 is explicitly out of scope (see `strategy.rs` module doc).
    SkipIpv6,
}

impl RuleImplementationStrategy {
    /// Returns `true` if this strategy adds a route table entry.
    pub fn uses_route_table(self) -> bool {
        matches!(self, Self::RouteTableEntry | Self::RouteWithFailClosedBlock)
    }

    /// Returns `true` if this strategy adds a WFP filter.
    pub fn uses_wfp(self) -> bool {
        matches!(
            self,
            Self::WfpBlockFilter | Self::RouteWithFailClosedBlock | Self::WfpApplicationFilter
        )
    }
}

/// Map a rule type slug (from `nrr-domain::CanonicalRuleBook`) to the
/// implementation strategy.
///
/// Slugs come from `nrr-domain`'s rule matching taxonomy.
pub fn rule_strategy(rule_type_slug: &str) -> RuleImplementationStrategy {
    match rule_type_slug {
        // Destination-based rules → route table + Fail-Closed WFP block.
        "exact-fqdn" => RuleImplementationStrategy::RouteWithFailClosedBlock,
        "suffix-domain" => RuleImplementationStrategy::RouteWithFailClosedBlock,
        "zone" => RuleImplementationStrategy::RouteWithFailClosedBlock,
        "exact-ip" => RuleImplementationStrategy::RouteWithFailClosedBlock,

        // Application rules → WFP ALE with app-path condition (block mode only in Free).
        "application" => RuleImplementationStrategy::WfpApplicationFilter,

        // Unknown slug — treat as skip to avoid breaking unknown future rule types.
        _ => RuleImplementationStrategy::SkipIpv6,
    }
}

// ── IPv6 detection ────────────────────────────────────────────────────────────

/// Returns `true` if `addr_str` is an IPv6 address.
///
/// Used to gracefully skip IPv6 addresses that appear in rule files or
/// FQDN cache results, without returning an error.
///
/// Detection heuristic: presence of `:` in the string (IPv6 uses colons as
/// separators; IPv4 does not) or a `[` prefix (bracketed IPv6 notation).
pub fn is_ipv6_address(addr_str: &str) -> bool {
    let trimmed = addr_str.trim();
    // Bracketed form: [::1], [::ffff:192.0.2.1]
    if trimmed.starts_with('[') {
        return true;
    }
    // Bare IPv6: contains colon separator
    trimmed.contains(':')
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_strategies_cover_all_known_slugs() {
        let known_slugs = [
            "exact-fqdn",
            "suffix-domain",
            "zone",
            "exact-ip",
            "application",
        ];
        for slug in &known_slugs {
            let strat = rule_strategy(slug);
            assert_ne!(
                strat,
                RuleImplementationStrategy::SkipIpv6,
                "rule type '{slug}' must have a concrete strategy"
            );
        }
    }

    #[test]
    fn unknown_slug_returns_skip() {
        assert_eq!(
            rule_strategy("unknown-future-type"),
            RuleImplementationStrategy::SkipIpv6
        );
    }

    #[test]
    fn destination_rules_use_route_table() {
        for slug in &["exact-fqdn", "suffix-domain", "zone", "exact-ip"] {
            assert!(
                rule_strategy(slug).uses_route_table(),
                "'{slug}' should use route table"
            );
        }
    }

    #[test]
    fn destination_rules_use_wfp_for_fail_closed() {
        for slug in &["exact-fqdn", "suffix-domain", "zone", "exact-ip"] {
            assert!(
                rule_strategy(slug).uses_wfp(),
                "'{slug}' should use WFP for Fail-Closed blocking"
            );
        }
    }

    #[test]
    fn application_rules_use_wfp_not_route_table() {
        let strat = rule_strategy("application");
        assert!(strat.uses_wfp());
        assert!(
            !strat.uses_route_table(),
            "application rules must not add route table entries in Free tier"
        );
    }

    #[test]
    fn ipv6_detection_covers_all_forms() {
        let ipv6_cases = [
            "::1",
            "::ffff:192.0.2.1",
            "[::1]",
            "2001:db8::1",
            "fe80::1%eth0",
        ];
        for addr in &ipv6_cases {
            assert!(is_ipv6_address(addr), "'{addr}' should be detected as IPv6");
        }
    }

    #[test]
    fn ipv4_is_not_detected_as_ipv6() {
        let ipv4_cases = [
            "192.168.1.1",
            "10.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "example.com",
            "*.example.com",
        ];
        for addr in &ipv4_cases {
            assert!(
                !is_ipv6_address(addr),
                "'{addr}' must not be detected as IPv6"
            );
        }
    }

    #[test]
    fn route_with_fail_closed_uses_both_mechanisms() {
        let strat = RuleImplementationStrategy::RouteWithFailClosedBlock;
        assert!(strat.uses_route_table());
        assert!(strat.uses_wfp());
    }
}
