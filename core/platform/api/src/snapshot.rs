//! Platform state snapshot, desired state, and action plan diff.
//!
//! ## Overview
//!
//! Before every apply the service layer captures a `PlatformStateSnapshot`
//! of the current routing table and WFP filter state. The snapshot:
//! - provides the "before" baseline for rollback
//! - enables idempotency: if `current_hash == desired_hash` → skip apply
//! - is persisted in `nrr_service_state.db` tied to the `ApplyAttemptMarker`
//!
//! `compute_action_plan` is a **pure function** (no I/O) that diffs
//! `current` vs `desired` and returns the minimal set of mutations needed.
//!
//! ## `DesiredPlatformState`
//!
//! Already-resolved platform-level description of the intended state.
//! The service layer populates this from `CanonicalProfile`
//! and FQDN cache results before calling `compute_action_plan`. No FQDNs
//! appear here — only concrete IPv4 addresses and filter specs.
//!
//! ## Canonicalization
//!
//! Routes are sorted by `(destination, prefix_length, interface_index)`.
//! WFP filters are sorted by `filter_id.raw`.
//! Canonical order ensures the SHA-256 hash is deterministic across
//! applies with identical logical state.
//!
//! ## Snapshot scope
//!
//! The snapshot captures only **our** routes (`is_ours = true`) plus the
//! current default route (for context). External routes (DHCP, VPN clients,
//! system) are not included — they are irrelevant for diff and rollback.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::{
    ApplyActionPlan, RouteEntry, RoutingAction, WfpFilterAction, WfpFilterId, WfpFilterRecord,
    WfpFilterSpec, WFP_PROVIDER_GUID, WFP_SUBLAYER_GUID,
};

// ── RoutingStateSnapshot ──────────────────────────────────────────────────────

/// Snapshot of relevant IPv4 route table entries at a point in time.
///
/// Scope: only `is_ours` routes plus the default route for context.
/// External routes (DHCP/VPN/system) are excluded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoutingStateSnapshot {
    /// Our route entries, canonically sorted.
    pub entries: Vec<RouteEntry>,
    /// Wall-clock seconds at capture time.
    pub taken_at_epoch_secs: u64,
}

impl RoutingStateSnapshot {
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
            taken_at_epoch_secs: 0,
        }
    }

    /// Canonical form for hashing: sorted by (destination, prefix_length, ifindex).
    pub fn canonical_entries(&self) -> Vec<&RouteEntry> {
        let mut entries: Vec<&RouteEntry> = self.entries.iter().collect();
        entries.sort_by_key(|e| (u32::from(e.destination), e.prefix_length, e.interface_index));
        entries
    }
}

// ── WfpFilterSnapshot ─────────────────────────────────────────────────────────

/// Snapshot of WFP filters registered under our provider GUID.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WfpFilterSnapshot {
    /// Our provider GUID (for verification that this snapshot matches the
    /// current provider configuration).
    pub provider_guid: [u8; 16],
    /// Our sub-layer GUID.
    pub sublayer_guid: [u8; 16],
    /// Filters registered under our provider, canonically sorted.
    pub filters: Vec<WfpFilterRecord>,
    /// Wall-clock seconds at capture time.
    pub taken_at_epoch_secs: u64,
}

impl WfpFilterSnapshot {
    pub fn empty() -> Self {
        Self {
            provider_guid: WFP_PROVIDER_GUID,
            sublayer_guid: WFP_SUBLAYER_GUID,
            filters: Vec::new(),
            taken_at_epoch_secs: 0,
        }
    }

    /// Canonical form for hashing: sorted by filter_id.raw.
    pub fn canonical_filters(&self) -> Vec<&WfpFilterRecord> {
        let mut filters: Vec<&WfpFilterRecord> = self.filters.iter().collect();
        filters.sort_by_key(|f| f.id.raw);
        filters
    }
}

// ── PlatformStateSnapshot ─────────────────────────────────────────────────────

/// Combined platform snapshot: routing table + WFP filter state.
///
/// Serialized to JSON and stored in `apply_snapshots` tied to the
/// `ApplyAttemptMarker.attempt_id`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlatformStateSnapshot {
    pub routing: RoutingStateSnapshot,
    pub wfp: WfpFilterSnapshot,
    /// SHA-256 of the canonical serialization of routing + wfp entries.
    /// Used for idempotency: if this hash matches the desired state hash,
    /// the apply is skipped.
    pub content_hash_hex: String,
    /// Schema version for forward-compatibility on startup.
    pub schema_version: u32,
}

/// Current schema version for `PlatformStateSnapshot` serialization.
pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;

impl PlatformStateSnapshot {
    /// Build a snapshot from its parts, computing the content hash.
    pub fn new(routing: RoutingStateSnapshot, wfp: WfpFilterSnapshot) -> Self {
        let hash = compute_snapshot_hash(&routing, &wfp);
        Self {
            routing,
            wfp,
            content_hash_hex: hash,
            schema_version: SNAPSHOT_SCHEMA_VERSION,
        }
    }

    /// Returns an empty snapshot (no routes, no filters).
    /// Used as baseline for first-ever apply (no prior state).
    pub fn empty() -> Self {
        Self::new(RoutingStateSnapshot::empty(), WfpFilterSnapshot::empty())
    }

    /// Recompute the hash from current contents. Used to verify an
    /// untrusted snapshot loaded from the database.
    pub fn verify_hash(&self) -> bool {
        let expected = compute_snapshot_hash(&self.routing, &self.wfp);
        self.content_hash_hex == expected
    }
}

/// Compute the SHA-256 content hash of a routing + WFP snapshot pair.
///
/// The hash is over the canonical serialization: routing entries sorted by
/// (destination, prefix_length, interface_index), then WFP filter ids sorted
/// by filter_id.raw. Both serialized as compact JSON.
pub fn compute_snapshot_hash(routing: &RoutingStateSnapshot, wfp: &WfpFilterSnapshot) -> String {
    let mut hasher = Sha256::new();

    // Hash routing entries in canonical order.
    for entry in routing.canonical_entries() {
        // Stable byte representation: destination IP as u32 BE, prefix_length,
        // next_hop as u32 BE, interface_index BE, metric BE.
        hasher.update(u32::from(entry.destination).to_be_bytes());
        hasher.update([entry.prefix_length]);
        hasher.update(u32::from(entry.next_hop).to_be_bytes());
        hasher.update(entry.interface_index.to_be_bytes());
        hasher.update(entry.metric.to_be_bytes());
        hasher.update([entry.is_ours as u8]);
    }

    // Separator between routing and WFP sections.
    hasher.update(b"---wfp---");

    // Hash WFP filters in canonical order (by filter_id.raw).
    for filter in wfp.canonical_filters() {
        hasher.update(filter.id.raw.to_be_bytes());
        hasher.update([filter.action as u8]);
        hasher.update(filter.weight.to_be_bytes());
        // Optional remote IP: prefix with 0 (absent) or 1 (present).
        match filter.remote_ip {
            None => hasher.update([0u8]),
            Some(ip) => {
                hasher.update([1u8]);
                hasher.update(u32::from(ip).to_be_bytes());
            }
        }
    }

    format!("{:x}", hasher.finalize())
}

// ── DesiredPlatformState ──────────────────────────────────────────────────────

/// The platform-level desired state after a successful apply.
///
/// Populated from `CanonicalProfile` + FQDN cache results.
/// All FQDNs have been resolved to IPs; no domain names appear here.
///
/// IPv6 destinations are excluded before this type is populated
/// (graceful-skip policy).
#[derive(Clone, Debug, Default)]
pub struct DesiredPlatformState {
    /// Routes to maintain in the routing table.
    pub routes: Vec<RouteEntry>,
    /// WFP filters to maintain in our sub-layer.
    pub wfp_filters: Vec<WfpFilterSpec>,
}

impl DesiredPlatformState {
    /// Compute the content hash of this desired state, using the same
    /// algorithm as `PlatformStateSnapshot::compute_snapshot_hash`.
    /// Used for idempotency: compare with current snapshot hash.
    pub fn content_hash(&self) -> String {
        // Build temporary snapshot-like structures for hashing.
        let mut route_entries = self.routes.clone();
        route_entries
            .sort_by_key(|e| (u32::from(e.destination), e.prefix_length, e.interface_index));

        let mut filter_records: Vec<WfpFilterRecord> = self
            .wfp_filters
            .iter()
            .map(|s| WfpFilterRecord {
                id: s.id,
                layer: s.layer,
                action: s.action,
                remote_ip: s.remote_ip,
                remote_port: s.remote_port,
                weight: s.weight,
                user_sid: s.user_sid.clone(),
                app_pattern: s.app_pattern.clone(),
                local_interface_luid: s.local_interface_luid,
                remote_subnet: s.remote_subnet,
                remote_subnet_v6: s.remote_subnet_v6,
                ip_protocol: s.ip_protocol,
            })
            .collect();
        filter_records.sort_by_key(|f| f.id.raw);

        let routing = RoutingStateSnapshot {
            entries: route_entries,
            taken_at_epoch_secs: 0,
        };
        let wfp = WfpFilterSnapshot {
            provider_guid: WFP_PROVIDER_GUID,
            sublayer_guid: WFP_SUBLAYER_GUID,
            filters: filter_records,
            taken_at_epoch_secs: 0,
        };
        compute_snapshot_hash(&routing, &wfp)
    }
}

// ── compute_action_plan ───────────────────────────────────────────────────────

/// Diff `current` vs `desired` and return the minimal set of mutations.
///
/// **Pure function — no I/O, no side effects.**
///
/// ## Routing diff
/// - Route key: `(destination, prefix_length, interface_index)`
/// - In desired but not current → `AddRoute`
/// - In current (`is_ours`) but not desired → `DeleteRoute`
/// - Same key but different `next_hop` or `metric` → `UpdateRoute`
///
/// ## WFP diff
/// - Filter key: `WfpFilterId` (stable UUIDv5 per rule)
/// - In desired but not current → `AddFilter`
/// - In current but not desired → `DeleteFilter`
/// - (No update: delete + re-add if spec changes)
///
/// ## Output order
/// Route deletions before additions (avoid metric conflicts).
/// WFP deletions before additions (avoid duplicate key conflicts).
pub fn compute_action_plan(
    current: &PlatformStateSnapshot,
    desired: &DesiredPlatformState,
) -> ApplyActionPlan {
    // Early exit: hashes match — desired == current, no-op.
    if current.content_hash_hex == desired.content_hash() {
        return ApplyActionPlan::default();
    }

    let mut plan = ApplyActionPlan::default();

    // ── Routing diff ──────────────────────────────────────────────────────
    route_diff(&current.routing, desired, &mut plan);

    // ── WFP diff ──────────────────────────────────────────────────────────
    wfp_diff(&current.wfp, desired, &mut plan);

    plan
}

fn route_diff(
    current: &RoutingStateSnapshot,
    desired: &DesiredPlatformState,
    plan: &mut ApplyActionPlan,
) {
    use std::collections::HashMap;

    type RouteKey = (u32, u8, u32); // (destination_u32, prefix_length, interface_index)

    fn key(e: &RouteEntry) -> RouteKey {
        (u32::from(e.destination), e.prefix_length, e.interface_index)
    }

    // Build lookup maps.
    let current_ours: HashMap<RouteKey, &RouteEntry> = current
        .entries
        .iter()
        .filter(|e| e.is_ours)
        .map(|e| (key(e), e))
        .collect();

    let desired_map: HashMap<RouteKey, &RouteEntry> =
        desired.routes.iter().map(|e| (key(e), e)).collect();

    // Deletions first (current is_ours routes not in desired).
    let mut to_delete: Vec<RouteEntry> = current_ours
        .iter()
        .filter(|(k, _)| !desired_map.contains_key(k))
        .map(|(_, &e)| e.clone())
        .collect();
    to_delete.sort_by_key(|e| (u32::from(e.destination), e.prefix_length, e.interface_index));
    plan.routing_actions
        .extend(to_delete.into_iter().map(RoutingAction::DeleteRoute));

    // Additions and updates.
    let mut to_add_or_update: Vec<&RouteEntry> = desired_map
        .iter()
        .filter_map(|(k, &desired_entry)| {
            match current_ours.get(k) {
                None => Some(desired_entry), // not present → add
                Some(&current_entry) => {
                    // Same key: check if update needed.
                    if current_entry.next_hop != desired_entry.next_hop
                        || current_entry.metric != desired_entry.metric
                    {
                        Some(desired_entry)
                    } else {
                        None // identical → no-op
                    }
                }
            }
        })
        .collect();
    to_add_or_update
        .sort_by_key(|e| (u32::from(e.destination), e.prefix_length, e.interface_index));

    for desired_entry in to_add_or_update {
        let k = key(desired_entry);
        if let Some(&current_entry) = current_ours.get(&k) {
            plan.routing_actions.push(RoutingAction::UpdateRoute {
                old: current_entry.clone(),
                new: desired_entry.clone(),
            });
        } else {
            plan.routing_actions
                .push(RoutingAction::AddRoute(desired_entry.clone()));
        }
    }
}

fn wfp_diff(
    current: &WfpFilterSnapshot,
    desired: &DesiredPlatformState,
    plan: &mut ApplyActionPlan,
) {
    use std::collections::HashSet;

    let current_ids: HashSet<u64> = current.filters.iter().map(|f| f.id.raw).collect();
    let desired_ids: HashSet<u64> = desired.wfp_filters.iter().map(|s| s.id.raw).collect();

    // Deletions first.
    let mut to_delete: Vec<WfpFilterId> = current
        .filters
        .iter()
        .filter(|f| !desired_ids.contains(&f.id.raw))
        .map(|f| f.id)
        .collect();
    to_delete.sort_by_key(|id| id.raw);
    plan.wfp_actions
        .extend(to_delete.into_iter().map(WfpFilterAction::DeleteFilter));

    // Additions.
    let mut to_add: Vec<&WfpFilterSpec> = desired
        .wfp_filters
        .iter()
        .filter(|s| !current_ids.contains(&s.id.raw))
        .collect();
    to_add.sort_by_key(|s| s.id.raw);
    plan.wfp_actions.extend(
        to_add
            .into_iter()
            .map(|s| WfpFilterAction::AddFilter(s.clone())),
    );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{WfpAction, WfpLayerKey};
    use std::net::Ipv4Addr;

    fn route(
        dest: [u8; 4],
        prefix: u8,
        next_hop: [u8; 4],
        ifindex: u32,
        metric: u32,
        ours: bool,
    ) -> RouteEntry {
        RouteEntry {
            destination: Ipv4Addr::from(dest),
            prefix_length: prefix,
            next_hop: Ipv4Addr::from(next_hop),
            interface_index: ifindex,
            metric,
            is_ours: ours,
            table: crate::RouteTableRef::Main,
        }
    }

    fn filter_spec(id_raw: u64, ip: [u8; 4], action: WfpAction) -> WfpFilterSpec {
        WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action,
            remote_ip: Some(Ipv4Addr::from(ip)),
            remote_port: None,
            weight: 0x100000 + id_raw,
            id: WfpFilterId { raw: id_raw },
            user_sid: None,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
        }
    }

    fn filter_record(id_raw: u64, ip: [u8; 4], action: WfpAction) -> WfpFilterRecord {
        WfpFilterRecord {
            id: WfpFilterId { raw: id_raw },
            layer: WfpLayerKey::AleAuthConnectV4,
            action,
            remote_ip: Some(Ipv4Addr::from(ip)),
            remote_port: None,
            weight: 0x100000 + id_raw,
            user_sid: None,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
        }
    }

    fn empty_snapshot() -> PlatformStateSnapshot {
        PlatformStateSnapshot::empty()
    }

    fn snapshot_with_route(r: RouteEntry) -> PlatformStateSnapshot {
        let routing = RoutingStateSnapshot {
            entries: vec![r],
            taken_at_epoch_secs: 1000,
        };
        PlatformStateSnapshot::new(routing, WfpFilterSnapshot::empty())
    }

    fn snapshot_with_filter(f: WfpFilterRecord) -> PlatformStateSnapshot {
        let wfp = WfpFilterSnapshot {
            filters: vec![f],
            ..WfpFilterSnapshot::empty()
        };
        PlatformStateSnapshot::new(RoutingStateSnapshot::empty(), wfp)
    }

    // ── hash tests ────────────────────────────────────────────────────────

    #[test]
    fn empty_snapshot_has_stable_hash() {
        let s1 = empty_snapshot();
        let s2 = empty_snapshot();
        assert_eq!(s1.content_hash_hex, s2.content_hash_hex);
        assert!(!s1.content_hash_hex.is_empty());
    }

    #[test]
    fn different_routes_produce_different_hashes() {
        let s1 = snapshot_with_route(route([10, 0, 0, 0], 24, [192, 168, 1, 1], 5, 10, true));
        let s2 = snapshot_with_route(route([10, 0, 1, 0], 24, [192, 168, 1, 1], 5, 10, true));
        assert_ne!(s1.content_hash_hex, s2.content_hash_hex);
    }

    #[test]
    fn hash_is_deterministic_regardless_of_insertion_order() {
        let r1 = route([10, 0, 0, 0], 24, [192, 168, 1, 1], 5, 10, true);
        let r2 = route([10, 0, 1, 0], 24, [192, 168, 1, 2], 5, 20, true);
        let routing_ab = RoutingStateSnapshot {
            entries: vec![r1.clone(), r2.clone()],
            taken_at_epoch_secs: 0,
        };
        let routing_ba = RoutingStateSnapshot {
            entries: vec![r2.clone(), r1.clone()],
            taken_at_epoch_secs: 0,
        };
        let h_ab = compute_snapshot_hash(&routing_ab, &WfpFilterSnapshot::empty());
        let h_ba = compute_snapshot_hash(&routing_ba, &WfpFilterSnapshot::empty());
        assert_eq!(
            h_ab, h_ba,
            "hash must be order-independent (canonical sort)"
        );
    }

    #[test]
    fn snapshot_hash_verification_succeeds_on_valid_snapshot() {
        let s = snapshot_with_route(route([10, 0, 0, 0], 24, [192, 168, 1, 1], 5, 10, true));
        assert!(s.verify_hash());
    }

    #[test]
    fn snapshot_hash_verification_fails_on_tampered_snapshot() {
        let mut s = snapshot_with_route(route([10, 0, 0, 0], 24, [192, 168, 1, 1], 5, 10, true));
        s.content_hash_hex = "deadbeef".to_string();
        assert!(!s.verify_hash());
    }

    // ── compute_action_plan tests ─────────────────────────────────────────

    #[test]
    fn empty_current_and_desired_produces_empty_plan() {
        let plan = compute_action_plan(&empty_snapshot(), &DesiredPlatformState::default());
        assert!(plan.is_empty());
    }

    #[test]
    fn identical_state_produces_empty_plan() {
        let r = route([10, 0, 0, 0], 24, [192, 168, 1, 1], 5, 10, true);
        let current = snapshot_with_route(r.clone());
        let desired = DesiredPlatformState {
            routes: vec![r],
            wfp_filters: vec![],
        };
        let plan = compute_action_plan(&current, &desired);
        assert!(plan.is_empty(), "identical state must produce no-op plan");
    }

    #[test]
    fn new_desired_route_produces_add_action() {
        let r = route([10, 0, 0, 0], 24, [192, 168, 1, 1], 5, 10, true);
        let current = empty_snapshot();
        let desired = DesiredPlatformState {
            routes: vec![r.clone()],
            wfp_filters: vec![],
        };
        let plan = compute_action_plan(&current, &desired);
        assert_eq!(plan.routing_actions.len(), 1);
        assert!(
            matches!(&plan.routing_actions[0], RoutingAction::AddRoute(added) if added.destination == r.destination)
        );
    }

    #[test]
    fn removed_desired_route_produces_delete_action() {
        let r = route([10, 0, 0, 0], 24, [192, 168, 1, 1], 5, 10, true);
        let current = snapshot_with_route(r.clone());
        let desired = DesiredPlatformState::default();
        let plan = compute_action_plan(&current, &desired);
        assert_eq!(plan.routing_actions.len(), 1);
        assert!(matches!(
            &plan.routing_actions[0],
            RoutingAction::DeleteRoute(_)
        ));
    }

    #[test]
    fn external_route_not_ours_is_not_deleted() {
        // Route with is_ours = false must not appear in the delete list.
        let r = route([10, 0, 0, 0], 24, [192, 168, 1, 1], 5, 10, false);
        let current = snapshot_with_route(r);
        let desired = DesiredPlatformState::default();
        let plan = compute_action_plan(&current, &desired);
        assert!(
            plan.routing_actions.is_empty(),
            "external routes must never be deleted"
        );
    }

    #[test]
    fn changed_metric_produces_update_action() {
        let old = route([10, 0, 0, 0], 24, [192, 168, 1, 1], 5, 10, true);
        let new = route([10, 0, 0, 0], 24, [192, 168, 1, 1], 5, 20, true);
        let current = snapshot_with_route(old);
        let desired = DesiredPlatformState {
            routes: vec![new],
            wfp_filters: vec![],
        };
        let plan = compute_action_plan(&current, &desired);
        assert_eq!(plan.routing_actions.len(), 1);
        assert!(matches!(
            &plan.routing_actions[0],
            RoutingAction::UpdateRoute { .. }
        ));
    }

    #[test]
    fn new_wfp_filter_produces_add_action() {
        let spec = filter_spec(42, [1, 2, 3, 4], WfpAction::Block);
        let current = empty_snapshot();
        let desired = DesiredPlatformState {
            routes: vec![],
            wfp_filters: vec![spec.clone()],
        };
        let plan = compute_action_plan(&current, &desired);
        assert_eq!(plan.wfp_actions.len(), 1);
        assert!(matches!(
            &plan.wfp_actions[0],
            WfpFilterAction::AddFilter(_)
        ));
    }

    #[test]
    fn removed_wfp_filter_produces_delete_action() {
        let f = filter_record(42, [1, 2, 3, 4], WfpAction::Block);
        let current = snapshot_with_filter(f);
        let desired = DesiredPlatformState::default();
        let plan = compute_action_plan(&current, &desired);
        assert_eq!(plan.wfp_actions.len(), 1);
        assert!(matches!(
            &plan.wfp_actions[0],
            WfpFilterAction::DeleteFilter(_)
        ));
    }

    #[test]
    fn deletions_come_before_additions_in_plan() {
        // Current has filter 1; desired has filter 2. Delete 1 before add 2.
        let old_filter = filter_record(1, [1, 1, 1, 1], WfpAction::Block);
        let new_spec = filter_spec(2, [2, 2, 2, 2], WfpAction::Block);
        let current = snapshot_with_filter(old_filter);
        let desired = DesiredPlatformState {
            routes: vec![],
            wfp_filters: vec![new_spec],
        };
        let plan = compute_action_plan(&current, &desired);
        assert_eq!(plan.wfp_actions.len(), 2);
        assert!(matches!(
            &plan.wfp_actions[0],
            WfpFilterAction::DeleteFilter(_)
        ));
        assert!(matches!(
            &plan.wfp_actions[1],
            WfpFilterAction::AddFilter(_)
        ));
    }

    #[test]
    fn snapshot_serialises_and_deserialises() {
        let r = route([10, 0, 0, 0], 24, [192, 168, 1, 1], 5, 10, true);
        let s = snapshot_with_route(r);
        let json = serde_json::to_string(&s).expect("serialize");
        let s2: PlatformStateSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(s.content_hash_hex, s2.content_hash_hex);
        assert!(s2.verify_hash());
    }
}
