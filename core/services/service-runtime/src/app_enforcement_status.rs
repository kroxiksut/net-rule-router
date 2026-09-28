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

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use nrr_shared::ipc_payloads::RuleConflictDto;

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
    pub fn set_rule_conflicts(&self, principal: &str, mut conflicts: Vec<RuleConflictDto>) {
        conflicts.truncate(MAX_RULE_CONFLICTS);
        if let Ok(mut guard) = self.0.lock() {
            if conflicts.is_empty() {
                guard.conflicts.remove(principal);
            } else {
                guard.conflicts.insert(principal.to_string(), conflicts);
            }
        }
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

/// The rule conflicts in one codegen pass, projected for the GUI.
///
/// Read off the codegen's own diagnostics rather than re-derived, so what the
/// user is told is exactly what was enforced.
#[must_use]
pub fn rule_conflicts_from(
    diagnostics: &[crate::wfp_codegen::CodegenDiagnostic],
    rule_book: &nrr_domain::canonical::CanonicalRuleBook,
) -> Vec<RuleConflictDto> {
    use crate::wfp_codegen::CodegenDiagnostic;
    use nrr_shared::ipc_payloads::RuleConflictKind;

    let rule_of = |rule_id: &str| {
        rule_book
            .primary
            .rules()
            .iter()
            .chain(rule_book.secondary.rules())
            .find(|r| r.id.as_str() == rule_id)
    };
    let value_of = |rule_id: &str| -> String {
        rule_of(rule_id)
            .and_then(|r| r.address_match.as_ref())
            .map(display_value)
            .unwrap_or_default()
    };
    diagnostics
        .iter()
        .filter_map(|d| match d {
            CodegenDiagnostic::RouteOverriddenByLiteralBlock {
                rule_id,
                block_rule_id,
                ip,
                host,
                count,
            } => Some(RuleConflictDto {
                kind: RuleConflictKind::LiteralBlockOverridesRoute,
                rule_id: rule_id.clone(),
                rule_value: value_of(rule_id),
                ip: ip.to_string(),
                count: u32::try_from(*count).unwrap_or(u32::MAX),
                other_rule_id: block_rule_id.clone(),
                host: host.clone(),
                via_host: String::new(),
                app: String::new(),
            }),
            CodegenDiagnostic::BlockLeaksSharedAddress {
                rule_id,
                ip,
                host,
                via_host,
                count,
            } => Some(RuleConflictDto {
                kind: RuleConflictKind::BlockLeaksSharedAddress,
                rule_id: rule_id.clone(),
                rule_value: value_of(rule_id),
                ip: ip.to_string(),
                count: u32::try_from(*count).unwrap_or(u32::MAX),
                other_rule_id: String::new(),
                host: host.clone(),
                via_host: via_host.clone(),
                app: String::new(),
            }),
            CodegenDiagnostic::UnsupportedRuleShape { rule_id, .. } => Some(RuleConflictDto {
                kind: RuleConflictKind::UnsupportedRuleShape,
                rule_id: rule_id.clone(),
                rule_value: value_of(rule_id),
                ip: String::new(),
                count: 0,
                other_rule_id: String::new(),
                host: String::new(),
                via_host: String::new(),
                app: rule_of(rule_id)
                    .and_then(|r| r.app_match.as_ref())
                    .map(|a| a.pattern.as_str().to_string())
                    .unwrap_or_default(),
            }),
            _ => None,
        })
        .collect()
}

/// A rule's address as the rules table spells it.
fn display_value(m: &nrr_domain::canonical::CanonicalAddressMatch) -> String {
    use nrr_domain::canonical::CanonicalAddressMatch;
    match m {
        CanonicalAddressMatch::ExactFqdn(host) => host.clone(),
        CanonicalAddressMatch::SuffixDomain(suffix) => format!("*.{suffix}"),
        CanonicalAddressMatch::Zone(zone) => zone.clone(),
        CanonicalAddressMatch::ExactIp(ip) => ip.to_string(),
    }
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
        status.set_rule_conflicts("S-1", vec![conflict.clone()]);
        assert_eq!(status.rule_conflicts("S-1"), vec![conflict]);
        assert!(
            status.rule_conflicts("S-2").is_empty(),
            "another user sees none"
        );
        status.set_rule_conflicts("S-1", Vec::new());
        assert!(status.rule_conflicts("S-1").is_empty());
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
