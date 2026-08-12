//! Fail-Closed local block enforcement.
//!
//! ## Invariant
//!
//! Traffic destined for a secondary-route destination **must never silently
//! fall back to primary** when the secondary adapter is unavailable. Instead,
//! the connection must be blocked locally via a WFP filter on
//! `FWPM_LAYER_ALE_AUTH_CONNECT_V4`.
//!
//! This invariant holds for three secondary states:
//! - `PresentNoIp`: secondary adapter is configured but has no IPv4 address
//!   (DHCP pending, lease expired). **Especially critical** — traffic would
//!   otherwise route via primary, violating the user's policy intent.
//! - `PresentDown`: secondary adapter exists but interface is down.
//! - `Absent`: secondary adapter not found in the system.
//!
//! ## How it works
//!
//! `compute_block_filters` is a **pure function**:
//!
//! ```text
//! destination IPs + rule_id + secondary_availability → Vec<WfpFilterSpec>
//! ```
//!
//! The resulting specs go into `DesiredPlatformState.wfp_filters`.
//! `compute_action_plan` diffs against current state; `execute_plan`
//! applies the change via `WfpSession::execute_wfp_plan`.
//!
//! ## Filter IDs
//!
//! Each `(rule_id, destination_ip)` pair maps to a deterministic `WfpFilterId`
//! via SHA-256. This enables idempotent apply and targeted revoke without
//! enumerating the WFP filter table.
//!
//! ## Exemptions
//!
//! Loopback (`127.0.0.0/8`) and link-local (`169.254.0.0/16`) addresses are
//! **never blocked** — they serve system services (mDNS, APIPA) that must not
//! be disrupted regardless of routing policy.
//!
//! ## IPv6
//!
//! IPv6 destinations are out-of-scope. If any IPv6 address leaks
//! through (parser bug or future extension), `compute_block_filters` silently
//! skips it — the caller must pre-filter using `strategy::is_ipv6_address`.
//!
//! ## FQDN rules and cache misses
//!
//! WFP operates at the IP layer; it cannot match by hostname. FQDN-rule
//! blocking requires the FQDN cache to supply resolved IPs. If the
//! cache has no entry for an FQDN, no filter is added — traffic may route via
//! primary until the cache is populated. This is a known Free-tier limitation
//! (Pro: callout driver intercepts at DNS/SNI level).
//!
//! ## Audit and rate-limiting
//!
//! Block events are emitted via `BlockNotificationEmitter`, which
//! applies rate-limiting. The `compute_block_filters` function itself is pure;
//! audit emission is the caller's responsibility.
//!
//! ## Existing connections
//!
//! WFP-block filters apply to **new** connection attempts (`ALE_AUTH_CONNECT`).
//! Already-established flows are not terminated (minimizes disruption). A
//! future `force_disconnect_on_block` setting (default off) would call
//! `FwpmFlowDelete0` after filter add.

use std::net::Ipv4Addr;

use sha2::{Digest, Sha256};

use crate::{
    adapters::AdapterAvailability,
    types::{WfpAction, WfpFilterId, WfpFilterSpec, WfpLayerKey, FILTER_WEIGHT_BASE},
};

// ── BlockReason ───────────────────────────────────────────────────────────────

/// Why Fail-Closed blocking is being applied. Surfaced in audit events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockReason {
    /// Secondary adapter is present and up but has no IPv4 address.
    SecondaryPresentNoIp,
    /// Secondary adapter interface is down or disconnected.
    SecondaryDown,
    /// Secondary adapter not found in the system.
    SecondaryAbsent,
}

impl BlockReason {
    /// Classify based on adapter availability.
    pub fn from_availability(avail: AdapterAvailability) -> Option<Self> {
        match avail {
            AdapterAvailability::Available => None,
            AdapterAvailability::PresentNoIp => Some(Self::SecondaryPresentNoIp),
            AdapterAvailability::PresentDown => Some(Self::SecondaryDown),
            AdapterAvailability::Absent => Some(Self::SecondaryAbsent),
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::SecondaryPresentNoIp => "secondary adapter has no IPv4 address",
            Self::SecondaryDown => "secondary adapter is down",
            Self::SecondaryAbsent => "secondary adapter not found",
        }
    }
}

// ── Exemption checks ──────────────────────────────────────────────────────────

/// Returns `true` if this IP must never be blocked (loopback or link-local).
///
/// - `127.0.0.0/8` — loopback; system services, IPC, mDNS stub resolvers
/// - `169.254.0.0/16` — APIPA / link-local; mDNS, LLMNR
pub fn is_exempt_from_blocking(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 127 || (o[0] == 169 && o[1] == 254)
}

// ── Deterministic filter ID ───────────────────────────────────────────────────

/// Compute a deterministic `WfpFilterId` for a `(rule_id, destination_ip)` pair.
///
/// Uses SHA-256 so the same pair always produces the same ID.
/// This enables idempotent apply and targeted revoke without enumerating filters.
pub fn fail_closed_filter_id(rule_id: &str, ip: Ipv4Addr) -> WfpFilterId {
    let mut hasher = Sha256::new();
    hasher.update(b"nrr-fail-closed-v1-");
    hasher.update(rule_id.as_bytes());
    hasher.update(b"-");
    hasher.update(u32::from(ip).to_be_bytes());
    let hash = hasher.finalize();
    // sha256 output is 32 bytes, so slicing the first 8 is infallible.
    #[allow(clippy::expect_used)]
    let raw = u64::from_be_bytes(
        hash[..8]
            .try_into()
            .expect("sha256 output is at least 8 bytes"),
    );
    WfpFilterId { raw }
}

// ── Core computation ──────────────────────────────────────────────────────────

/// Compute the WFP block filter specs needed for one rule when secondary
/// is unavailable.
///
/// ## Parameters
///
/// - `destination_ips`: IPv4 addresses that should be blocked. For
///   `ExactIp` rules, this is the single configured IP. For FQDN rules,
///   this is the resolved IP set from the FQDN cache. Empty vec → no filters.
/// - `rule_id`: Stable identifier for the rule (from `CanonicalRuleBook`).
/// - `secondary_availability`: Current state of the secondary adapter.
/// - `position_index`: Position of this rule in the canonical rule book.
///   Used for deterministic weight assignment.
///
/// ## Return value
///
/// Empty vec when `secondary_availability == Available` (no blocking needed).
/// One `WfpFilterSpec` per non-exempt destination IP when blocking.
pub fn compute_block_filters(
    destination_ips: &[Ipv4Addr],
    rule_id: &str,
    secondary_availability: AdapterAvailability,
    position_index: u64,
) -> Vec<WfpFilterSpec> {
    if secondary_availability.is_usable() {
        return Vec::new();
    }

    let mut specs = Vec::new();
    let base_weight = FILTER_WEIGHT_BASE + position_index * 1000;

    for (i, &ip) in destination_ips.iter().enumerate() {
        if is_exempt_from_blocking(ip) {
            continue;
        }
        specs.push(WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Block,
            remote_ip: Some(ip),
            remote_port: None,
            weight: base_weight + i as u64,
            id: fail_closed_filter_id(rule_id, ip),
            user_sid: None,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
        });
    }

    specs
}

/// Compute the WFP filter IDs to **remove** when secondary becomes available.
///
/// Mirrors `compute_block_filters` but returns IDs (for `WfpFilterAction::DeleteFilter`).
pub fn compute_unblock_filter_ids(destination_ips: &[Ipv4Addr], rule_id: &str) -> Vec<WfpFilterId> {
    destination_ips
        .iter()
        .filter(|&&ip| !is_exempt_from_blocking(ip))
        .map(|&ip| fail_closed_filter_id(rule_id, ip))
        .collect()
}

// ── FailClosedPlan ────────────────────────────────────────────────────────────

/// The complete Fail-Closed plan for all secondary-bound rules in a profile.
///
/// Call `for_secondary_unavailable` or `for_secondary_available` depending
/// on the current secondary adapter state. The result plugs directly into
/// `DesiredPlatformState.wfp_filters`.
#[derive(Clone, Debug, Default)]
pub struct FailClosedPlan {
    pub block_filters: Vec<WfpFilterSpec>,
    pub reason: Option<BlockReason>,
}

impl FailClosedPlan {
    /// Build the filter specs for all secondary-bound rules when secondary is
    /// **unavailable**. Returns an empty plan when secondary is usable.
    pub fn compute(
        rules: &[FailClosedRuleSpec],
        secondary_availability: AdapterAvailability,
    ) -> Self {
        let reason = BlockReason::from_availability(secondary_availability);
        if reason.is_none() {
            return Self::default();
        }
        let block_filters: Vec<WfpFilterSpec> = rules
            .iter()
            .flat_map(|r| {
                compute_block_filters(
                    &r.destination_ips,
                    &r.rule_id,
                    secondary_availability,
                    r.canonical_position,
                )
            })
            .collect();
        Self {
            block_filters,
            reason,
        }
    }
}

/// One secondary-bound rule entry passed to `FailClosedPlan::compute`.
#[derive(Clone, Debug)]
pub struct FailClosedRuleSpec {
    /// Stable rule identifier.
    pub rule_id: String,
    /// Resolved destination IPs (empty for FQDN cache-miss rules).
    pub destination_ips: Vec<Ipv4Addr>,
    /// Position in canonical rule book (for weight ordering).
    pub canonical_position: u64,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    // ── Exemptions ────────────────────────────────────────────────────────

    #[test]
    fn loopback_127_is_always_exempt() {
        assert!(is_exempt_from_blocking(ip(127, 0, 0, 1)));
        assert!(is_exempt_from_blocking(ip(127, 255, 255, 255)));
    }

    #[test]
    fn link_local_169_254_is_always_exempt() {
        assert!(is_exempt_from_blocking(ip(169, 254, 0, 1)));
        assert!(is_exempt_from_blocking(ip(169, 254, 99, 99)));
    }

    #[test]
    fn regular_ips_are_not_exempt() {
        assert!(!is_exempt_from_blocking(ip(10, 0, 0, 1)));
        assert!(!is_exempt_from_blocking(ip(192, 168, 1, 1)));
        assert!(!is_exempt_from_blocking(ip(8, 8, 8, 8)));
    }

    // ── Filter ID determinism ─────────────────────────────────────────────

    #[test]
    fn filter_id_is_deterministic_for_same_inputs() {
        let id1 = fail_closed_filter_id("rule-001", ip(10, 0, 0, 1));
        let id2 = fail_closed_filter_id("rule-001", ip(10, 0, 0, 1));
        assert_eq!(id1, id2);
    }

    #[test]
    fn filter_id_differs_for_different_ips() {
        let id1 = fail_closed_filter_id("rule-001", ip(10, 0, 0, 1));
        let id2 = fail_closed_filter_id("rule-001", ip(10, 0, 0, 2));
        assert_ne!(id1.raw, id2.raw);
    }

    #[test]
    fn filter_id_differs_for_different_rule_ids() {
        let id1 = fail_closed_filter_id("rule-001", ip(10, 0, 0, 1));
        let id2 = fail_closed_filter_id("rule-002", ip(10, 0, 0, 1));
        assert_ne!(id1.raw, id2.raw);
    }

    // ── compute_block_filters ─────────────────────────────────────────────

    #[test]
    fn secondary_available_returns_no_filters() {
        let filters = compute_block_filters(
            &[ip(10, 0, 0, 1)],
            "rule-x",
            AdapterAvailability::Available,
            0,
        );
        assert!(filters.is_empty());
    }

    #[test]
    fn secondary_absent_produces_block_filters() {
        let filters =
            compute_block_filters(&[ip(10, 0, 0, 1)], "rule-x", AdapterAvailability::Absent, 0);
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].action, WfpAction::Block);
        assert_eq!(filters[0].remote_ip, Some(ip(10, 0, 0, 1)));
    }

    #[test]
    fn secondary_present_no_ip_produces_block_filters() {
        // Critical invariant: secondary has adapter but no IP → must block
        let filters = compute_block_filters(
            &[ip(10, 0, 0, 1)],
            "rule-x",
            AdapterAvailability::PresentNoIp,
            0,
        );
        assert_eq!(
            filters.len(),
            1,
            "PresentNoIp must trigger Fail-Closed blocking"
        );
        assert_eq!(filters[0].action, WfpAction::Block);
    }

    #[test]
    fn secondary_present_down_produces_block_filters() {
        let filters = compute_block_filters(
            &[ip(10, 0, 0, 1)],
            "rule-x",
            AdapterAvailability::PresentDown,
            0,
        );
        assert_eq!(filters.len(), 1);
    }

    #[test]
    fn loopback_destination_is_skipped() {
        let filters = compute_block_filters(
            &[ip(127, 0, 0, 1)],
            "rule-x",
            AdapterAvailability::Absent,
            0,
        );
        assert!(filters.is_empty(), "loopback must be exempt from blocking");
    }

    #[test]
    fn link_local_destination_is_skipped() {
        let filters = compute_block_filters(
            &[ip(169, 254, 0, 1)],
            "rule-x",
            AdapterAvailability::Absent,
            0,
        );
        assert!(
            filters.is_empty(),
            "link-local must be exempt from blocking"
        );
    }

    #[test]
    fn exempt_ips_filtered_out_while_non_exempt_included() {
        let ips = vec![
            ip(127, 0, 0, 1),   // loopback — exempt
            ip(10, 0, 0, 1),    // regular — block
            ip(169, 254, 1, 1), // link-local — exempt
            ip(8, 8, 8, 8),     // regular — block
        ];
        let filters = compute_block_filters(&ips, "rule-x", AdapterAvailability::Absent, 0);
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0].remote_ip, Some(ip(10, 0, 0, 1)));
        assert_eq!(filters[1].remote_ip, Some(ip(8, 8, 8, 8)));
    }

    #[test]
    fn all_filters_use_ale_auth_connect_v4_layer() {
        let filters = compute_block_filters(
            &[ip(10, 0, 0, 1), ip(10, 0, 0, 2)],
            "rule-x",
            AdapterAvailability::Absent,
            0,
        );
        for f in &filters {
            assert_eq!(f.layer, WfpLayerKey::AleAuthConnectV4);
        }
    }

    #[test]
    fn weights_are_ascending_within_one_rule() {
        let ips: Vec<Ipv4Addr> = (1..=5).map(|i| ip(10, 0, 0, i)).collect();
        let filters = compute_block_filters(&ips, "rule-x", AdapterAvailability::Absent, 0);
        let weights: Vec<u64> = filters.iter().map(|f| f.weight).collect();
        let is_ascending = weights.windows(2).all(|w| w[0] < w[1]);
        assert!(is_ascending, "filter weights must be strictly ascending");
    }

    #[test]
    fn different_rules_at_different_positions_have_non_overlapping_weights() {
        let rule_a =
            compute_block_filters(&[ip(10, 0, 0, 1)], "rule-a", AdapterAvailability::Absent, 0);
        let rule_b =
            compute_block_filters(&[ip(10, 0, 0, 1)], "rule-b", AdapterAvailability::Absent, 1);
        // position 0 → base + 0*1000 = BASE; position 1 → base + 1000
        assert!(rule_b[0].weight > rule_a[0].weight);
    }

    #[test]
    fn empty_destinations_produces_no_filters() {
        let filters = compute_block_filters(&[], "rule-x", AdapterAvailability::Absent, 0);
        assert!(
            filters.is_empty(),
            "no IPs → no filters (FQDN cache-miss case)"
        );
    }

    #[test]
    fn filter_ids_are_stable_across_multiple_calls() {
        let f1 = compute_block_filters(
            &[ip(10, 0, 0, 1)],
            "rule-stable",
            AdapterAvailability::Absent,
            0,
        );
        let f2 = compute_block_filters(
            &[ip(10, 0, 0, 1)],
            "rule-stable",
            AdapterAvailability::Absent,
            0,
        );
        assert_eq!(
            f1[0].id, f2[0].id,
            "same inputs must always produce same filter ID"
        );
    }

    // ── compute_unblock_filter_ids ────────────────────────────────────────

    #[test]
    fn unblock_ids_match_block_ids_for_same_inputs() {
        let ips = vec![ip(10, 0, 0, 1), ip(10, 0, 0, 2)];
        let block = compute_block_filters(&ips, "rule-x", AdapterAvailability::Absent, 0);
        let unblock = compute_unblock_filter_ids(&ips, "rule-x");
        let block_ids: Vec<u64> = block.iter().map(|f| f.id.raw).collect();
        let unblock_ids: Vec<u64> = unblock.iter().map(|id| id.raw).collect();
        assert_eq!(block_ids, unblock_ids, "unblock IDs must match block IDs");
    }

    #[test]
    fn unblock_skips_exempt_ips() {
        let ips = vec![ip(127, 0, 0, 1), ip(10, 0, 0, 1)];
        let unblock = compute_unblock_filter_ids(&ips, "rule-x");
        assert_eq!(unblock.len(), 1, "loopback must not appear in unblock IDs");
    }

    // ── FailClosedPlan ────────────────────────────────────────────────────

    #[test]
    fn plan_is_empty_when_secondary_available() {
        let rules = vec![FailClosedRuleSpec {
            rule_id: "rule-a".into(),
            destination_ips: vec![ip(10, 0, 0, 1)],
            canonical_position: 0,
        }];
        let plan = FailClosedPlan::compute(&rules, AdapterAvailability::Available);
        assert!(plan.block_filters.is_empty());
        assert!(plan.reason.is_none());
    }

    #[test]
    fn plan_has_filters_for_multiple_rules_when_secondary_down() {
        let rules = vec![
            FailClosedRuleSpec {
                rule_id: "rule-a".into(),
                destination_ips: vec![ip(10, 0, 0, 1)],
                canonical_position: 0,
            },
            FailClosedRuleSpec {
                rule_id: "rule-b".into(),
                destination_ips: vec![ip(10, 0, 1, 1), ip(10, 0, 1, 2)],
                canonical_position: 1,
            },
        ];
        let plan = FailClosedPlan::compute(&rules, AdapterAvailability::PresentNoIp);
        assert_eq!(
            plan.block_filters.len(),
            3,
            "3 non-exempt IPs across 2 rules"
        );
        assert_eq!(plan.reason, Some(BlockReason::SecondaryPresentNoIp));
    }

    #[test]
    fn block_reason_from_availability_covers_all_variants() {
        assert!(BlockReason::from_availability(AdapterAvailability::Available).is_none());
        assert_eq!(
            BlockReason::from_availability(AdapterAvailability::PresentNoIp),
            Some(BlockReason::SecondaryPresentNoIp)
        );
        assert_eq!(
            BlockReason::from_availability(AdapterAvailability::PresentDown),
            Some(BlockReason::SecondaryDown)
        );
        assert_eq!(
            BlockReason::from_availability(AdapterAvailability::Absent),
            Some(BlockReason::SecondaryAbsent)
        );
    }
}
