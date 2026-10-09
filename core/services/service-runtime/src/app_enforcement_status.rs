//! Shared "application rules not enforced" status.
//!
//! When an `Application` rule's exe name/glob cannot be resolved to any
//! on-disk path (app not installed / not running / not in App Paths), the
//! WFP codegen skips its per-process `ALE_APP_ID` filter and records a
//! [`crate::wfp_codegen::CodegenDiagnostic::AppUnresolved`]. Such a rule is
//! silently unenforced from the user's point of view, so the GUI wants to
//! surface a banner listing the offending app patterns.
//!
//! This type is the tiny hand-off between the two sides:
//! [`crate::per_sid_orchestrator::PerSidApplyOrchestrator`] WRITES the latest
//! set on every filter compute, and the `SnapshotInitial` IPC handler READS
//! it when composing the GUI's first-render snapshot. The Free model has a
//! single active user, so one global list (not a per-SID map) is sufficient.
//!
//! `Clone` shares the inner `Mutex` (it wraps an `Arc`), so the writer and
//! reader observe the same state.
//!
//! The same hand-off carries the rule conflicts the compute found (a literal-IP
//! Block over a route, a Block leaking a shared address): they are the other
//! half of "what the last compute enforced differently from the rules", and
//! riding the existing channel keeps one writer and one reader for both.

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use nrr_shared::ipc_payloads::{EnforcementStatusDto, RuleConflictDto};

/// Ceiling on the conflicts kept per principal, so one pathological rule book
/// cannot grow the snapshot past a frame.
const MAX_RULE_CONFLICTS: usize = 128;

/// Latest set of application rules whose exe could not be resolved to a path
/// (so their per-process `ALE_APP_ID` filter was not built), plus each
/// principal's rule conflicts. Written by the orchestrator on every applying
/// compute, read by the `SnapshotInitial` handler. App entries are the rule's
/// pattern (e.g. `"ab.exe"`, `"disko*.exe"`), stored sorted + deduped.
#[derive(Clone, Default)]
pub struct AppEnforcementStatus(Arc<Mutex<EnforcementState>>);

#[derive(Default)]
struct EnforcementState {
    unresolved: Vec<String>,
    /// Per principal: a conflict names that user's own rules and addresses.
    conflicts: HashMap<String, Vec<RuleConflictDto>>,
}

impl AppEnforcementStatus {
    /// Construct an empty status (no unresolved app rules).
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the stored set with `apps`, sorted + deduplicated. A poisoned
    /// lock is skipped (best-effort diagnostics must never panic the apply
    /// path); the previous value is left intact in that case.
    pub fn set_unresolved(&self, mut apps: Vec<String>) {
        apps.sort();
        apps.dedup();
        if let Ok(mut guard) = self.0.lock() {
            guard.unresolved = apps;
        }
    }

    /// Snapshot the current set (already sorted + deduped). A poisoned lock
    /// recovers the inner value rather than panicking.
    pub fn unresolved(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .unresolved
            .clone()
    }

    /// Replace `principal`'s rule conflicts; an empty list forgets them.
    /// Returns whether the stored set changed, so a caller that re-plans on a
    /// timer reports a change once rather than on every pass.
    pub fn set_rule_conflicts(&self, principal: &str, mut conflicts: Vec<RuleConflictDto>) -> bool {
        conflicts.truncate(MAX_RULE_CONFLICTS);
        let Ok(mut guard) = self.0.lock() else {
            return false;
        };
        if conflicts.is_empty() {
            return guard.conflicts.remove(principal).is_some();
        }
        if guard.conflicts.get(principal) == Some(&conflicts) {
            return false;
        }
        guard.conflicts.insert(principal.to_string(), conflicts);
        true
    }

    /// `principal`'s rule conflicts from its last applying compute.
    pub fn rule_conflicts(&self, principal: &str) -> Vec<RuleConflictDto> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .conflicts
            .get(principal)
            .cloned()
            .unwrap_or_default()
    }
}

/// Upper bound on how many excluded addresses are retained for the GUI
/// "show details" list. The exclusion COUNT (`SharedIpExemptionStatus::count`)
/// is never truncated — only the address list surfaced for display is, so a
/// large shared-IP census cannot bloat the snapshot IPC payload.
const MAX_DISPLAYED_ADDRESSES: usize = 32;

/// Which secondary-destined IPs the "smart"
/// kill-switch EXCLUDED from its per-IP pin/block set this compute because the
/// shared-IP census saw them on direct (non-rule) hostnames too. Empty under
/// the "strict" policy, when the leak-guard is disarmed, or when nothing is
/// shared. Same hand-off shape as [`AppEnforcementStatus`]: the orchestrator
/// WRITES on every filter compute, the `SnapshotInitial` handler READS both
/// the count (for the "strictness reduced for N shared IPs" warning) and the
/// addresses themselves (for the "show details" list).
#[derive(Clone, Default)]
pub struct SharedIpExemptionStatus(Arc<Mutex<SharedIpExemptionState>>);

#[derive(Default)]
struct SharedIpExemptionState {
    count: u32,
    addresses: Vec<Ipv4Addr>,
}

impl SharedIpExemptionStatus {
    /// Construct with a zero count (nothing excluded).
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the stored excluded-address set. A poisoned lock is skipped
    /// (best-effort diagnostics must never panic the apply path). The count
    /// reflects the full `excluded` set; the retained address list is capped
    /// at [`MAX_DISPLAYED_ADDRESSES`].
    pub fn set(&self, excluded: &[Ipv4Addr]) {
        if let Ok(mut guard) = self.0.lock() {
            guard.count = excluded.len() as u32;
            guard.addresses = excluded
                .iter()
                .copied()
                .take(MAX_DISPLAYED_ADDRESSES)
                .collect();
        }
    }

    /// The last stored count. A poisoned lock recovers the inner value.
    pub fn count(&self) -> u32 {
        self.0
            .lock()
            .map_or_else(|p| p.into_inner().count, |g| g.count)
    }

    /// The last stored addresses (dotted-quad strings), capped at
    /// [`MAX_DISPLAYED_ADDRESSES`]. A poisoned lock recovers the inner value.
    pub fn addresses(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .addresses
            .iter()
            .map(Ipv4Addr::to_string)
            .collect()
    }
}

/// Whether ANY tracked SID currently has the fail-closed
/// catch-all block-all armed (secondary unresolved + kill-switch fail-closed).
/// Same hand-off shape as [`SharedIpExemptionStatus`]: the orchestrator WRITES
/// on every block-all state transition, the `SnapshotInitial` handler READS
/// for the GUI's "leak protection is blocking unknown traffic — secondary
/// adapter unavailable" banner (dismissible via a preference — deliberately
/// running the service with the VPN down is a legitimate setup).
#[derive(Clone, Default)]
pub struct BlockAllPostureStatus(Arc<Mutex<bool>>);

impl BlockAllPostureStatus {
    /// Construct disarmed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the stored armed flag. A poisoned lock is skipped (best-effort
    /// diagnostics must never panic the apply path).
    pub fn set(&self, armed: bool) {
        if let Ok(mut guard) = self.0.lock() {
            *guard = armed;
        }
    }

    /// The last stored armed flag. A poisoned lock recovers the inner value.
    pub fn armed(&self) -> bool {
        *self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// Whether ANY tracked SID currently has the leak guard BLOCKING because the
/// additional link could not be resolved — the `secondary interface unresolved
/// — kill-switch FAIL-CLOSED` posture, in either of its shapes (the enumerated
/// per-IP block set or the catch-all).
///
/// Deliberately WIDER than [`BlockAllPostureStatus`], which arms only for the
/// catch-all: with the default per-IP posture that one stays disarmed while
/// the guard is very much blocking. Readers that must not hand an application a
/// destination the guard has no filter for yet — the DNS handler and the rule
/// hostname seeder — key on THIS one.
///
/// Not armed when the pair is merely empty on a healthy tunnel: there the
/// additional link is up and the per-IP guard is a no-op, so withholding an
/// answer or hammering the resolver would cost the user connectivity it never
/// protects.
#[derive(Clone, Default)]
pub struct FailClosedPostureStatus(Arc<Mutex<bool>>);

impl FailClosedPostureStatus {
    /// Construct disarmed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the stored armed flag. A poisoned lock is skipped (best-effort
    /// diagnostics must never panic the apply path).
    pub fn set(&self, armed: bool) {
        if let Ok(mut guard) = self.0.lock() {
            *guard = armed;
        }
    }

    /// The last stored armed flag. A poisoned lock recovers the inner value.
    pub fn armed(&self) -> bool {
        *self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// The last enforcement report per principal and role: the route coordinator
/// writes it as it decides whether to push, the `SnapshotInitial` handler reads
/// the caller's own. The push fires on change only, so without this a client
/// that connects later never learns a standing state.
#[derive(Clone, Default)]
pub struct RouteEnforcementStatus {
    reports: Arc<Mutex<ReportsByPrincipal>>,
    /// Told when a principal's additional route goes down or comes back, so
    /// the outage list opens and closes at the instant the status shows.
    outages: Arc<std::sync::OnceLock<Arc<crate::outage_blocks::OutageBlocks>>>,
}

/// Principal → role → report.
type ReportsByPrincipal = HashMap<String, BTreeMap<String, EnforcementStatusDto>>;

impl RouteEnforcementStatus {
    /// Construct with nothing reported.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open and close `outages` episodes from the additional route's status.
    /// The first store stays; `false` says one was already attached.
    pub fn watch_outages(&self, outages: Arc<crate::outage_blocks::OutageBlocks>) -> bool {
        self.outages.set(outages).is_ok()
    }

    /// Store `report` for `principal`, stamped with when its status began.
    /// Returns the stored report when it differs from the previous one, which
    /// is what decides the push.
    pub fn record(
        &self,
        principal: &str,
        report: &EnforcementStatusDto,
    ) -> Option<EnforcementStatusDto> {
        let now_ms = crate::conn_observation_consumer::now_unix_ms();
        self.record_at(principal, report, i64::try_from(now_ms).unwrap_or(i64::MAX))
    }

    /// [`Self::record`] at `now_ms`. The start time moves only when the status
    /// does: new candidates for the same status are the same outage.
    pub fn record_at(
        &self,
        principal: &str,
        report: &EnforcementStatusDto,
        now_ms: i64,
    ) -> Option<EnforcementStatusDto> {
        let stored = {
            let mut guard = self.reports.lock().unwrap_or_else(|p| p.into_inner());
            let roles = guard.entry(principal.to_string()).or_default();
            let previous = roles.get(&report.role);
            let since_unix_ms = match previous {
                Some(previous) if previous.status == report.status => previous.since_unix_ms,
                _ => Some(now_ms),
            };
            let stored = EnforcementStatusDto {
                since_unix_ms,
                ..report.clone()
            };
            if previous == Some(&stored) {
                return None;
            }
            roles.insert(report.role.clone(), stored.clone());
            stored
        };
        if stored.role == "secondary" {
            if let Some(outages) = self.outages.get() {
                let at_ms = u64::try_from(now_ms).unwrap_or(0);
                if stored.status == "ok" {
                    outages.outage_ended(principal, at_ms);
                } else {
                    outages.outage_began(principal, at_ms);
                }
            }
        }
        Some(stored)
    }

    /// `principal`'s last status for `role`, when one was reported.
    pub fn status_of(&self, principal: &str, role: &str) -> Option<String> {
        self.reports
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal)
            .and_then(|roles| roles.get(role))
            .map(|r| r.status.clone())
    }

    /// `principal`'s reports, ordered by role. Never another principal's: the
    /// candidates name that user's adapters.
    pub fn for_principal(&self, principal: &str) -> Vec<EnforcementStatusDto> {
        self.reports
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(principal)
            .map(|roles| roles.values().cloned().collect())
            .unwrap_or_default()
    }
}

/// The rule conflicts in one codegen pass, projected for the GUI.
///
/// Read off the codegen's own diagnostics rather than re-derived, so what the
/// user is told is exactly what was enforced.
#[must_use]
pub fn rule_conflicts_from(
    diagnostics: &[crate::wfp_codegen::CodegenDiagnostic],
    rule_book: &nrr_domain::canonical::CanonicalRuleBook,
) -> Vec<RuleConflictDto> {
    let conflicts: Vec<_> = diagnostics
        .iter()
        .filter_map(crate::wfp_codegen::CodegenDiagnostic::rule_conflict)
        .collect();
    crate::rule_conflicts::rule_conflict_dtos(&conflicts, rule_book)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_conflicts_are_kept_per_principal_and_cleared_by_an_empty_set() {
        use nrr_shared::ipc_payloads::RuleConflictKind;
        let status = AppEnforcementStatus::new();
        let conflict = RuleConflictDto {
            kind: RuleConflictKind::BlockLeaksSharedAddress,
            rule_id: "b1".into(),
            rule_value: "example".into(),
            ip: "192.0.2.10".into(),
            count: 1,
            other_rule_id: String::new(),
            host: "b.example".into(),
            via_host: "a.example".into(),
            app: String::new(),
        };
        assert!(status.set_rule_conflicts("S-1", vec![conflict.clone()]));
        assert_eq!(status.rule_conflicts("S-1"), vec![conflict.clone()]);
        assert!(
            status.rule_conflicts("S-2").is_empty(),
            "another user sees none"
        );
        assert!(
            !status.set_rule_conflicts("S-1", vec![conflict]),
            "the same set again is not a change"
        );
        assert!(status.set_rule_conflicts("S-1", Vec::new()));
        assert!(status.rule_conflicts("S-1").is_empty());
        assert!(
            !status.set_rule_conflicts("S-1", Vec::new()),
            "clearing an empty set is not a change"
        );
    }

    fn status_report(status: &str, role: &str) -> EnforcementStatusDto {
        EnforcementStatusDto {
            status: status.into(),
            role: role.into(),
            candidates: Vec::new(),
            since_unix_ms: None,
        }
    }

    fn stamped(status: &str, role: &str, since: i64) -> EnforcementStatusDto {
        EnforcementStatusDto {
            since_unix_ms: Some(since),
            ..status_report(status, role)
        }
    }

    #[test]
    fn route_enforcement_keeps_the_last_report_per_role_and_principal() {
        let report = status_report;
        let writer = RouteEnforcementStatus::new();
        let reader = writer.clone();
        assert!(writer
            .record_at("S-1", &report("secondary-down", "secondary"), 10)
            .is_some());
        assert!(
            writer
                .record_at("S-1", &report("secondary-down", "secondary"), 20)
                .is_none(),
            "the same report again is not a change"
        );
        assert!(writer
            .record_at("S-1", &report("ok", "primary"), 30)
            .is_some());
        assert!(writer
            .record_at("S-2", &report("adapter-gone", "secondary"), 40)
            .is_some());
        assert_eq!(
            reader.for_principal("S-1"),
            vec![
                stamped("ok", "primary", 30),
                stamped("secondary-down", "secondary", 10)
            ]
        );
        assert!(writer
            .record_at("S-1", &report("ok", "secondary"), 50)
            .is_some());
        assert_eq!(reader.status_of("S-1", "secondary").as_deref(), Some("ok"));
        assert_eq!(
            reader.for_principal("S-2"),
            vec![stamped("adapter-gone", "secondary", 40)]
        );
        assert!(reader.for_principal("S-3").is_empty());
    }

    #[test]
    fn since_moves_only_when_the_status_does() {
        let board = RouteEnforcementStatus::new();
        let gone = |candidates: &[&str]| EnforcementStatusDto {
            candidates: candidates.iter().map(|c| (*c).to_string()).collect(),
            ..status_report("adapter-gone", "secondary")
        };
        assert_eq!(
            board
                .record_at("S-1", &gone(&["Tunnel A"]), 100)
                .and_then(|r| r.since_unix_ms),
            Some(100)
        );
        let pushed = board.record_at("S-1", &gone(&["Tunnel A", "Tunnel B"]), 200);
        assert_eq!(
            pushed.and_then(|r| r.since_unix_ms),
            Some(100),
            "new candidates are still the same outage"
        );
        assert_eq!(
            board
                .record_at("S-1", &status_report("secondary-down", "secondary"), 300)
                .and_then(|r| r.since_unix_ms),
            Some(300)
        );
        assert_eq!(
            board
                .record_at("S-1", &status_report("ok", "secondary"), 400)
                .and_then(|r| r.since_unix_ms),
            Some(400)
        );
    }

    #[test]
    fn the_secondary_status_opens_and_closes_the_outage_list() {
        use crate::outage_blocks::OutageBlocks;
        let board = RouteEnforcementStatus::new();
        let outages = Arc::new(OutageBlocks::new());
        assert!(board.clone().watch_outages(Arc::clone(&outages)));
        assert!(!board.watch_outages(Arc::new(OutageBlocks::new())));

        board.record_at("S-1", &status_report("ok", "primary"), 50);
        assert_eq!(
            outages.snapshot("S-1").episode,
            None,
            "the main link is not the outage"
        );
        board.record_at("S-1", &status_report("secondary-down", "secondary"), 100);
        board.record_at("S-1", &status_report("adapter-gone", "secondary"), 150);
        let open = outages.snapshot("S-1").episode;
        assert_eq!(open.map(|e| (e.since_ms, e.until_ms)), Some((100, None)));
        board.record_at("S-1", &status_report("ok", "secondary"), 300);
        let closed = outages.snapshot("S-1").episode;
        assert_eq!(
            closed.map(|e| (e.since_ms, e.until_ms)),
            Some((100, Some(300)))
        );
        assert_eq!(outages.snapshot("S-2").episode, None);
    }

    #[test]
    fn fail_closed_posture_round_trips_and_shares_state() {
        let writer = FailClosedPostureStatus::new();
        let reader = writer.clone();
        assert!(!reader.armed(), "disarmed by default");
        writer.set(true);
        assert!(reader.armed());
        writer.set(false);
        assert!(!reader.armed());
    }

    #[test]
    fn block_all_posture_round_trips_and_shares_state() {
        let writer = BlockAllPostureStatus::new();
        let reader = writer.clone();
        assert!(!reader.armed(), "disarmed by default");
        writer.set(true);
        assert!(reader.armed());
        writer.set(false);
        assert!(!reader.armed());
    }

    #[test]
    fn empty_by_default() {
        let status = AppEnforcementStatus::new();
        assert!(status.unresolved().is_empty());
    }

    #[test]
    fn set_then_get_round_trips() {
        let status = AppEnforcementStatus::new();
        status.set_unresolved(vec!["ab.exe".to_string(), "disko*.exe".to_string()]);
        assert_eq!(status.unresolved(), vec!["ab.exe", "disko*.exe"]);
    }

    #[test]
    fn stores_sorted_and_deduped() {
        let status = AppEnforcementStatus::new();
        status.set_unresolved(vec![
            "b.exe".to_string(),
            "a.exe".to_string(),
            "b.exe".to_string(),
            "a.exe".to_string(),
        ]);
        assert_eq!(status.unresolved(), vec!["a.exe", "b.exe"]);
    }

    #[test]
    fn clone_shares_inner_state() {
        let writer = AppEnforcementStatus::new();
        let reader = writer.clone();
        writer.set_unresolved(vec!["chrome.exe".to_string()]);
        assert_eq!(reader.unresolved(), vec!["chrome.exe"]);
    }

    #[test]
    fn set_overwrites_previous() {
        let status = AppEnforcementStatus::new();
        status.set_unresolved(vec!["old.exe".to_string()]);
        status.set_unresolved(vec!["new.exe".to_string()]);
        assert_eq!(status.unresolved(), vec!["new.exe"]);
    }

    #[test]
    fn shared_ip_exemption_status_round_trips_count_and_addresses() {
        let writer = SharedIpExemptionStatus::new();
        let reader = writer.clone();
        assert_eq!(reader.count(), 0, "no exclusions by default");
        assert!(reader.addresses().is_empty());
        writer.set(&[Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)]);
        assert_eq!(reader.count(), 2);
        assert_eq!(reader.addresses(), vec!["192.0.2.1", "192.0.2.2"]);
        writer.set(&[]);
        assert_eq!(reader.count(), 0);
        assert!(reader.addresses().is_empty());
    }

    #[test]
    fn shared_ip_exemption_status_caps_displayed_addresses_but_not_count() {
        let status = SharedIpExemptionStatus::new();
        let many: Vec<Ipv4Addr> = (0..40u8).map(|n| Ipv4Addr::new(10, 0, 0, n)).collect();
        status.set(&many);
        assert_eq!(status.count(), 40, "count reflects the full exclusion set");
        assert_eq!(
            status.addresses().len(),
            MAX_DISPLAYED_ADDRESSES,
            "display list is capped to protect the IPC payload size"
        );
    }
}
