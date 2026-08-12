//! Post-apply verification and drift detection.
//!
//! ## Overview
//!
//! After a policy apply commits, `VerifyEngine::verify_apply` re-captures the
//! live platform state and compares it against the `DesiredPlatformState` that
//! was just applied. Any mismatch is classified by severity and returned as a
//! `VerifyResult`.
//!
//! ## Two-level strategy
//!
//! 1. **Hash fast-path**: recompute the SHA-256 content hash of the actual
//!    state (our routes + our WFP filters). If it matches `intended.content_hash()`
//!    the state is clean and entry-by-entry work is skipped.
//! 2. **Entry-by-entry slow-path**: triggered only on hash mismatch. Produces
//!    a `Vec<DriftItem>` with per-entry severity and diagnostic detail.
//!
//! ## Drift triage matrix
//!
//! | Situation | Severity |
//! |-----------|----------|
//! | Our route/filter missing from actual state | `Critical` |
//! | Our route/filter modified by external software | `Critical` |
//! | Extra "our" route that should have been deleted | `Critical` |
//! | External route added, same dest prefix AND lower metric (would shadow ours) | `Warning` |
//! | Extra filter in our sub-layer not in intended | `Minor` |
//! | External route added, non-conflicting (or loopback/link-local exempt) | `Minor` |
//!
//! ## Tolerable drift
//!
//! Routes to loopback (127.0.0.0/8) and link-local (169.254.0.0/16) are
//! always `Minor` regardless of metric. VPN/tunnel adapters may add routes
//! that appear during the verify window; as long as they don't conflict,
//! they are classified `Minor`.
//!
//! ## Timeout
//!
//! A hard cap of `VERIFY_TIMEOUT_SECS` (default 10 s) guards against hangs
//! from slow Win32 enumeration. Timeout returns `VerifyResult::TimedOut`.
//!
//! ## Periodic drift monitor
//!
//! This module implements the **one-shot post-apply verify** only. The
//! periodic drift monitor (60 s poll comparing current vs `last_known_intended`)
//! is a separate task in the runtime loop, not part of this module.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{
    constants::VERIFY_TIMEOUT_SECS,
    snapshot::{
        DesiredPlatformState, PlatformStateSnapshot, RoutingStateSnapshot, WfpFilterSnapshot,
    },
    types::{RouteEntry, WfpFilterId, WfpFilterRecord, WfpFilterSpec},
    wfp::WfpSession,
    windows_api::WindowsApiPort,
};

// ── DriftSeverity ─────────────────────────────────────────────────────────────

/// Classification of a detected drift item. Higher = more severe.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DriftSeverity {
    /// Non-conflicting external addition. Audit as informational.
    Minor,
    /// Conflicting external addition. Audit as warning; do not auto-rollback.
    Warning,
    /// One of our entries is missing or was modified. Trigger rollback.
    Critical,
}

// ── DriftKind ─────────────────────────────────────────────────────────────────

/// The specific nature of one drift item.
#[derive(Clone, Debug)]
pub enum DriftKind {
    /// An intended route is absent from the actual routing table.
    OurRouteMissing { entry: RouteEntry },
    /// An intended route exists but has different `next_hop` or `metric`.
    OurRouteModified {
        intended: RouteEntry,
        actual: RouteEntry,
    },
    /// An is_ours route exists in actual but was not in intended (stale, failed delete).
    OurRouteStale { entry: RouteEntry },
    /// External (not is_ours) route added — non-conflicting or exempt.
    ExternalRouteAdded { entry: RouteEntry },
    /// External route added with same (dest, prefix_len) AND lower metric than ours.
    ExternalRouteConflict {
        entry: RouteEntry,
        shadowed_route: RouteEntry,
    },
    /// An intended WFP filter is absent from the actual sub-layer.
    OurFilterMissing { id: WfpFilterId },
    /// An intended WFP filter has different fields (weight/action/conditions).
    OurFilterModified { id: WfpFilterId, detail: String },
    /// A WFP filter in our sub-layer was not in intended.
    ExternalFilterAdded { id: WfpFilterId },
}

// ── DriftItem ─────────────────────────────────────────────────────────────────

/// One detected discrepancy between intended and actual platform state.
#[derive(Clone, Debug)]
pub struct DriftItem {
    pub severity: DriftSeverity,
    pub kind: DriftKind,
}

// ── VerifyResult ──────────────────────────────────────────────────────────────

/// Outcome of one `VerifyEngine::verify_apply` call.
#[derive(Clone, Debug)]
pub enum VerifyResult {
    /// Actual state matches intended state exactly (hash + entry-by-entry confirm).
    Clean { verified_at_epoch_secs: u64 },
    /// Differences detected. `max_severity` determines whether to rollback.
    Drift {
        max_severity: DriftSeverity,
        items: Vec<DriftItem>,
        verified_at_epoch_secs: u64,
    },
    /// Platform state capture failed (Win32 error).
    CaptureFailed { reason: String },
    /// Verify did not complete within the timeout budget.
    TimedOut { items_checked: usize },
}

impl VerifyResult {
    /// Returns the worst drift severity, or `None` for clean/error results.
    pub fn max_severity(&self) -> Option<&DriftSeverity> {
        match self {
            Self::Drift { max_severity, .. } => Some(max_severity),
            _ => None,
        }
    }

    /// Returns `true` when any `Critical` drift was detected — rollback required.
    pub fn requires_rollback(&self) -> bool {
        matches!(self.max_severity(), Some(DriftSeverity::Critical))
    }

    /// Returns `true` when state is confirmed clean.
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::Clean { .. })
    }
}

// ── VerifyEngine ──────────────────────────────────────────────────────────────

/// Performs post-apply verification by re-capturing the platform state and
/// comparing it against the intended `DesiredPlatformState`.
pub struct VerifyEngine {
    api: Arc<dyn WindowsApiPort>,
    /// Hard time limit for the entire verify operation.
    pub verify_timeout_secs: u64,
}

impl VerifyEngine {
    pub fn new(api: Arc<dyn WindowsApiPort>) -> Self {
        Self {
            api,
            verify_timeout_secs: VERIFY_TIMEOUT_SECS,
        }
    }

    /// Verify that the platform state matches `intended` after an apply.
    ///
    /// `now_secs` is the current wall-clock epoch (injected for tests).
    pub fn verify_apply(
        &self,
        intended: &DesiredPlatformState,
        session: &WfpSession,
        now_secs: u64,
    ) -> VerifyResult {
        let deadline = Instant::now() + Duration::from_secs(self.verify_timeout_secs);

        // ── Step 1: capture actual routing table ──────────────────────────
        let actual_routes = match self.api.get_ip_forward_table() {
            Ok(r) => r,
            Err(e) => {
                return VerifyResult::CaptureFailed {
                    reason: format!("routing table read failed: {e}"),
                }
            }
        };
        if Instant::now() > deadline {
            return VerifyResult::TimedOut { items_checked: 0 };
        }

        // ── Step 2: capture actual WFP filters ────────────────────────────
        let actual_filters = match session.enumerate_our_filters() {
            Ok(f) => f,
            Err(e) => {
                return VerifyResult::CaptureFailed {
                    reason: format!("WFP filter enumeration failed: {e}"),
                }
            }
        };
        if Instant::now() > deadline {
            return VerifyResult::TimedOut {
                items_checked: actual_routes.len(),
            };
        }

        // ── Step 3: hash fast-path for our entries ────────────────────────
        // The hash covers is_ours routes + our WFP filters only.
        // External (is_ours=false) routes are NOT in the hash, so they must
        // always be scanned separately.
        let actual_our_routes: Vec<RouteEntry> = actual_routes
            .iter()
            .filter(|r| r.is_ours)
            .cloned()
            .collect();
        let actual_snap = build_snapshot(&actual_our_routes, &actual_filters);
        let our_state_clean = actual_snap.content_hash_hex == intended.content_hash();

        let mut items = Vec::new();

        // ── Step 4: our-entry analysis (skipped when hash matches) ────────
        if !our_state_clean {
            analyze_our_route_drift(intended, &actual_routes, &mut items);
            analyze_filter_drift(intended, &actual_filters, &mut items);
        }

        if Instant::now() > deadline {
            return VerifyResult::TimedOut {
                items_checked: items.len(),
            };
        }

        // ── Step 5: external route scan (always — not in hash) ────────────
        analyze_external_routes(intended, &actual_routes, &mut items);

        if items.is_empty() {
            return VerifyResult::Clean {
                verified_at_epoch_secs: now_secs,
            };
        }

        let max_severity = items
            .iter()
            .map(|i| &i.severity)
            .max()
            .cloned()
            .unwrap_or(DriftSeverity::Minor);

        VerifyResult::Drift {
            max_severity,
            items,
            verified_at_epoch_secs: now_secs,
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn build_snapshot(
    our_routes: &[RouteEntry],
    our_filters: &[WfpFilterRecord],
) -> PlatformStateSnapshot {
    let routing = RoutingStateSnapshot {
        entries: our_routes.to_vec(),
        taken_at_epoch_secs: 0,
    };
    let wfp = WfpFilterSnapshot {
        filters: our_filters.to_vec(),
        ..WfpFilterSnapshot::empty()
    };
    PlatformStateSnapshot::new(routing, wfp)
}

/// Route tuple key: (destination_u32, prefix_length, interface_index).
type RouteKey = (u32, u8, u32);

fn route_key(e: &RouteEntry) -> RouteKey {
    (u32::from(e.destination), e.prefix_length, e.interface_index)
}

/// Returns `true` for destinations that are always tolerable as external routes
/// (loopback 127.0.0.0/8 and link-local 169.254.0.0/16).
fn is_always_tolerable(dest: Ipv4Addr) -> bool {
    let o = dest.octets();
    o[0] == 127 || (o[0] == 169 && o[1] == 254)
}

/// Full entry-by-entry analysis of OUR (is_ours=true) routes against intended.
/// Produces Critical items for missing, modified, or stale entries.
fn analyze_our_route_drift(
    intended: &DesiredPlatformState,
    actual_routes: &[RouteEntry],
    items: &mut Vec<DriftItem>,
) {
    let intended_map: HashMap<RouteKey, &RouteEntry> =
        intended.routes.iter().map(|e| (route_key(e), e)).collect();

    let actual_ours: HashMap<RouteKey, &RouteEntry> = actual_routes
        .iter()
        .filter(|r| r.is_ours)
        .map(|r| (route_key(r), r))
        .collect();

    // Intended routes missing from or modified in actual.
    for (&k, &intended_entry) in &intended_map {
        match actual_ours.get(&k) {
            None => {
                items.push(DriftItem {
                    severity: DriftSeverity::Critical,
                    kind: DriftKind::OurRouteMissing {
                        entry: intended_entry.clone(),
                    },
                });
            }
            Some(&actual_entry) => {
                if actual_entry.next_hop != intended_entry.next_hop
                    || actual_entry.metric != intended_entry.metric
                {
                    items.push(DriftItem {
                        severity: DriftSeverity::Critical,
                        kind: DriftKind::OurRouteModified {
                            intended: intended_entry.clone(),
                            actual: actual_entry.clone(),
                        },
                    });
                }
            }
        }
    }

    // Actual is_ours routes not in intended (stale / failed delete).
    for (&k, &actual_entry) in &actual_ours {
        if !intended_map.contains_key(&k) {
            items.push(DriftItem {
                severity: DriftSeverity::Critical,
                kind: DriftKind::OurRouteStale {
                    entry: actual_entry.clone(),
                },
            });
        }
    }
}

/// Scan external (is_ours=false) routes for Warning/Minor items.
/// Always called regardless of the hash fast-path result because external
/// routes are not included in the content hash.
fn analyze_external_routes(
    intended: &DesiredPlatformState,
    actual_routes: &[RouteEntry],
    items: &mut Vec<DriftItem>,
) {
    for external in actual_routes.iter().filter(|r| !r.is_ours) {
        if is_always_tolerable(external.destination) {
            items.push(DriftItem {
                severity: DriftSeverity::Minor,
                kind: DriftKind::ExternalRouteAdded {
                    entry: external.clone(),
                },
            });
            continue;
        }

        let dest_u32 = u32::from(external.destination);
        let conflicting_intended = intended.routes.iter().find(|i| {
            u32::from(i.destination) == dest_u32
                && i.prefix_length == external.prefix_length
                && external.metric < i.metric
        });

        match conflicting_intended {
            Some(shadowed) => items.push(DriftItem {
                severity: DriftSeverity::Warning,
                kind: DriftKind::ExternalRouteConflict {
                    entry: external.clone(),
                    shadowed_route: shadowed.clone(),
                },
            }),
            None => items.push(DriftItem {
                severity: DriftSeverity::Minor,
                kind: DriftKind::ExternalRouteAdded {
                    entry: external.clone(),
                },
            }),
        }
    }
}

fn analyze_filter_drift(
    intended: &DesiredPlatformState,
    actual_filters: &[WfpFilterRecord],
    items: &mut Vec<DriftItem>,
) {
    let intended_map: HashMap<u64, &WfpFilterSpec> =
        intended.wfp_filters.iter().map(|s| (s.id.raw, s)).collect();

    let actual_map: HashMap<u64, &WfpFilterRecord> =
        actual_filters.iter().map(|r| (r.id.raw, r)).collect();

    // ── Check intended filters against actual ─────────────────────────────
    for (&id_raw, &spec) in &intended_map {
        match actual_map.get(&id_raw) {
            None => {
                items.push(DriftItem {
                    severity: DriftSeverity::Critical,
                    kind: DriftKind::OurFilterMissing { id: spec.id },
                });
            }
            Some(&record) => {
                // Check if fields match the spec.
                let mismatch = record.action != spec.action
                    || record.layer != spec.layer
                    || record.weight != spec.weight
                    || record.remote_ip != spec.remote_ip
                    || record.remote_port != spec.remote_port;
                if mismatch {
                    let detail = format!(
                        "filter {:?}: action={:?} (expected {:?}), \
                         weight={} (expected {})",
                        spec.id, record.action, spec.action, record.weight, spec.weight
                    );
                    items.push(DriftItem {
                        severity: DriftSeverity::Critical,
                        kind: DriftKind::OurFilterModified {
                            id: spec.id,
                            detail,
                        },
                    });
                }
                // else: exact match — OK.
            }
        }
    }

    // ── Check actual filters not in intended ──────────────────────────────
    for (&id_raw, &record) in &actual_map {
        if !intended_map.contains_key(&id_raw) {
            // Extra filter in our sub-layer that we did not intend — minor.
            items.push(DriftItem {
                severity: DriftSeverity::Minor,
                kind: DriftKind::ExternalFilterAdded { id: record.id },
            });
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        types::{WfpAction, WfpFilterId, WfpFilterSpec, WfpLayerKey},
        windows_api::MockWindowsApi,
    };
    use std::net::Ipv4Addr;

    fn api() -> Arc<MockWindowsApi> {
        Arc::new(MockWindowsApi::new())
    }

    fn session(api: &Arc<MockWindowsApi>) -> WfpSession {
        WfpSession::open(Arc::clone(api) as Arc<dyn WindowsApiPort>).unwrap()
    }

    fn engine(api: &Arc<MockWindowsApi>) -> VerifyEngine {
        VerifyEngine::new(Arc::clone(api) as Arc<dyn WindowsApiPort>)
    }

    fn route(
        dest: [u8; 4],
        next_hop: [u8; 4],
        ifindex: u32,
        metric: u32,
        ours: bool,
    ) -> RouteEntry {
        RouteEntry {
            destination: Ipv4Addr::from(dest),
            prefix_length: 24,
            next_hop: Ipv4Addr::from(next_hop),
            interface_index: ifindex,
            metric,
            is_ours: ours,
            table: nrr_platform_api::RouteTableRef::Main,
        }
    }

    fn filter_spec(id_raw: u64) -> WfpFilterSpec {
        WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Block,
            remote_ip: Some(Ipv4Addr::new(1, 2, 3, id_raw as u8)),
            remote_port: None,
            weight: 0x100_000 + id_raw,
            id: WfpFilterId { raw: id_raw },
            user_sid: None,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
        }
    }

    fn add_filter(session: &WfpSession, spec: &WfpFilterSpec) {
        use crate::types::WfpFilterAction;
        session
            .execute_wfp_plan(&[WfpFilterAction::AddFilter(spec.clone())])
            .unwrap();
    }

    // ── Clean state ───────────────────────────────────────────────────────

    #[test]
    fn empty_intended_empty_actual_is_clean() {
        let api = api();
        let session = session(&api);
        let eng = engine(&api);
        let intended = DesiredPlatformState::default();
        let result = eng.verify_apply(&intended, &session, 1000);
        assert!(
            result.is_clean(),
            "empty vs empty must be clean: {result:?}"
        );
    }

    #[test]
    fn matching_route_and_filter_is_clean() {
        let api = api();
        let r = route([10, 0, 0, 0], [192, 168, 1, 1], 5, 10, true);
        api.create_ip_forward_entry(&r).unwrap();
        let spec = filter_spec(1);
        let session = session(&api);
        add_filter(&session, &spec);
        let eng = engine(&api);
        let intended = DesiredPlatformState {
            routes: vec![r],
            wfp_filters: vec![spec],
        };
        let result = eng.verify_apply(&intended, &session, 1000);
        assert!(
            result.is_clean(),
            "matching state must be clean: {result:?}"
        );
    }

    // ── Critical: missing ─────────────────────────────────────────────────

    #[test]
    fn missing_intended_route_is_critical() {
        let api = api();
        // Intended has route, but actual is empty.
        let session = session(&api);
        let eng = engine(&api);
        let r = route([10, 0, 0, 0], [192, 168, 1, 1], 5, 10, true);
        let intended = DesiredPlatformState {
            routes: vec![r],
            wfp_filters: vec![],
        };
        let result = eng.verify_apply(&intended, &session, 1000);
        assert!(
            result.requires_rollback(),
            "missing route must be critical: {result:?}"
        );
        assert!(matches!(
            result.max_severity(),
            Some(DriftSeverity::Critical)
        ));
    }

    #[test]
    fn missing_intended_filter_is_critical() {
        let api = api();
        let session = session(&api);
        // Filter not added to session.
        let eng = engine(&api);
        let spec = filter_spec(1);
        let intended = DesiredPlatformState {
            routes: vec![],
            wfp_filters: vec![spec],
        };
        let result = eng.verify_apply(&intended, &session, 1000);
        assert!(
            result.requires_rollback(),
            "missing filter must be critical: {result:?}"
        );
    }

    // ── Critical: modified ────────────────────────────────────────────────

    #[test]
    fn modified_route_metric_is_critical() {
        let api = api();
        let intended_r = route([10, 0, 0, 0], [192, 168, 1, 1], 5, 10, true);
        let actual_r = RouteEntry {
            metric: 99,
            ..intended_r.clone()
        };
        api.create_ip_forward_entry(&actual_r).unwrap();
        let session = session(&api);
        let eng = engine(&api);
        let intended = DesiredPlatformState {
            routes: vec![intended_r],
            wfp_filters: vec![],
        };
        let result = eng.verify_apply(&intended, &session, 1000);
        assert!(
            result.requires_rollback(),
            "modified route metric must be critical: {result:?}"
        );
    }

    #[test]
    fn modified_route_next_hop_is_critical() {
        let api = api();
        let intended_r = route([10, 0, 0, 0], [192, 168, 1, 1], 5, 10, true);
        let actual_r = RouteEntry {
            next_hop: Ipv4Addr::new(192, 168, 2, 1),
            ..intended_r.clone()
        };
        api.create_ip_forward_entry(&actual_r).unwrap();
        let session = session(&api);
        let eng = engine(&api);
        let intended = DesiredPlatformState {
            routes: vec![intended_r],
            wfp_filters: vec![],
        };
        let result = eng.verify_apply(&intended, &session, 1000);
        assert!(
            result.requires_rollback(),
            "modified next_hop must be critical: {result:?}"
        );
    }

    #[test]
    fn stale_our_route_not_in_intended_is_critical() {
        let api = api();
        // Actual has a is_ours route that wasn't in intended (failed delete).
        let stale = route([10, 0, 0, 0], [192, 168, 1, 1], 5, 10, true);
        api.create_ip_forward_entry(&stale).unwrap();
        let session = session(&api);
        let eng = engine(&api);
        let intended = DesiredPlatformState::default(); // no routes expected
        let result = eng.verify_apply(&intended, &session, 1000);
        assert!(
            result.requires_rollback(),
            "stale our route must be critical: {result:?}"
        );
    }

    // ── Warning: conflicting external route ───────────────────────────────

    #[test]
    fn external_route_same_prefix_lower_metric_is_warning() {
        let api = api();
        let our = route([10, 0, 0, 0], [192, 168, 1, 1], 5, 10, true);
        // External route to same subnet with lower metric (higher priority).
        let ext = RouteEntry {
            metric: 5,
            is_ours: false,
            table: nrr_platform_api::RouteTableRef::Main,
            ..our.clone()
        };
        api.create_ip_forward_entry(&our).unwrap();
        api.create_ip_forward_entry(&ext).unwrap();
        let session = session(&api);
        let eng = engine(&api);
        let intended = DesiredPlatformState {
            routes: vec![our],
            wfp_filters: vec![],
        };
        let result = eng.verify_apply(&intended, &session, 1000);
        assert!(
            !result.requires_rollback(),
            "external conflict must not trigger rollback"
        );
        assert_eq!(result.max_severity(), Some(&DriftSeverity::Warning));
    }

    #[test]
    fn external_route_same_prefix_higher_metric_is_minor() {
        let api = api();
        let our = route([10, 0, 0, 0], [192, 168, 1, 1], 5, 10, true);
        // External route to same subnet with HIGHER metric (lower priority).
        let ext = RouteEntry {
            metric: 20,
            is_ours: false,
            table: nrr_platform_api::RouteTableRef::Main,
            ..our.clone()
        };
        api.create_ip_forward_entry(&our).unwrap();
        api.create_ip_forward_entry(&ext).unwrap();
        let session = session(&api);
        let eng = engine(&api);
        let intended = DesiredPlatformState {
            routes: vec![our],
            wfp_filters: vec![],
        };
        let result = eng.verify_apply(&intended, &session, 1000);
        // Not critical (our route is correct) and not warning (no conflict).
        assert!(!result.requires_rollback());
        // Max severity should be Minor (external non-conflicting add) or Clean.
        assert!(
            matches!(result.max_severity(), None | Some(DriftSeverity::Minor)),
            "higher-metric external must be minor: {result:?}"
        );
    }

    // ── Minor: tolerable external additions ───────────────────────────────

    #[test]
    fn loopback_external_route_is_always_minor() {
        let api = api();
        // Our intended state is empty. An external loopback route exists.
        let loopback = route([127, 0, 0, 1], [127, 0, 0, 1], 1, 0, false);
        api.create_ip_forward_entry(&loopback).unwrap();
        let session = session(&api);
        let eng = engine(&api);
        let intended = DesiredPlatformState::default();
        let result = eng.verify_apply(&intended, &session, 1000);
        // Loopback is tolerable — should be clean or minor, never warning/critical.
        assert!(
            !result.requires_rollback(),
            "loopback route must not trigger rollback"
        );
        assert!(
            matches!(result.max_severity(), None | Some(DriftSeverity::Minor)),
            "loopback must be minor: {result:?}"
        );
    }

    #[test]
    fn link_local_external_route_is_minor() {
        let api = api();
        let link_local = route([169, 254, 0, 1], [169, 254, 0, 1], 1, 0, false);
        api.create_ip_forward_entry(&link_local).unwrap();
        let session = session(&api);
        let eng = engine(&api);
        let result = eng.verify_apply(&DesiredPlatformState::default(), &session, 1000);
        assert!(!result.requires_rollback());
        assert!(matches!(
            result.max_severity(),
            None | Some(DriftSeverity::Minor)
        ));
    }

    #[test]
    fn extra_filter_in_sub_layer_is_minor() {
        let api = api();
        let session = session(&api);
        // Add a filter that is NOT in the intended state.
        add_filter(&session, &filter_spec(99));
        let eng = engine(&api);
        let intended = DesiredPlatformState::default(); // no filters expected
        let result = eng.verify_apply(&intended, &session, 1000);
        assert!(
            !result.requires_rollback(),
            "extra filter must not trigger rollback"
        );
        assert_eq!(
            result.max_severity(),
            Some(&DriftSeverity::Minor),
            "extra filter must be minor: {result:?}"
        );
    }

    // ── Severity ordering ─────────────────────────────────────────────────

    #[test]
    fn drift_severity_ordering_is_correct() {
        assert!(DriftSeverity::Critical > DriftSeverity::Warning);
        assert!(DriftSeverity::Warning > DriftSeverity::Minor);
    }

    // ── Multiple items ────────────────────────────────────────────────────

    #[test]
    fn max_severity_picks_highest_across_items() {
        let api = api();
        // Intended: route r1.  Actual: r1 with modified metric (critical) +
        // external loopback (minor).
        let r1 = route([10, 0, 0, 0], [192, 168, 1, 1], 5, 10, true);
        let r1_modified = RouteEntry {
            metric: 50,
            ..r1.clone()
        };
        api.create_ip_forward_entry(&r1_modified).unwrap();
        let loopback = route([127, 0, 0, 1], [127, 0, 0, 1], 1, 0, false);
        api.create_ip_forward_entry(&loopback).unwrap();
        let session = session(&api);
        let eng = engine(&api);
        let intended = DesiredPlatformState {
            routes: vec![r1],
            wfp_filters: vec![],
        };
        let result = eng.verify_apply(&intended, &session, 1000);
        assert_eq!(result.max_severity(), Some(&DriftSeverity::Critical));
    }

    // ── Timeout constant ──────────────────────────────────────────────────

    #[test]
    fn verify_engine_default_timeout_matches_constant() {
        let api = api();
        let eng = engine(&api);
        assert_eq!(eng.verify_timeout_secs, VERIFY_TIMEOUT_SECS);
    }

    // ── VerifyResult helpers ──────────────────────────────────────────────

    #[test]
    fn requires_rollback_only_on_critical() {
        let clean = VerifyResult::Clean {
            verified_at_epoch_secs: 0,
        };
        assert!(!clean.requires_rollback());
        assert!(clean.is_clean());

        let minor = VerifyResult::Drift {
            max_severity: DriftSeverity::Minor,
            items: vec![],
            verified_at_epoch_secs: 0,
        };
        assert!(!minor.requires_rollback());

        let warning = VerifyResult::Drift {
            max_severity: DriftSeverity::Warning,
            items: vec![],
            verified_at_epoch_secs: 0,
        };
        assert!(!warning.requires_rollback());

        let critical = VerifyResult::Drift {
            max_severity: DriftSeverity::Critical,
            items: vec![],
            verified_at_epoch_secs: 0,
        };
        assert!(critical.requires_rollback());

        let failed = VerifyResult::CaptureFailed { reason: "x".into() };
        assert!(!failed.requires_rollback());
        assert!(!failed.is_clean());
    }
}
