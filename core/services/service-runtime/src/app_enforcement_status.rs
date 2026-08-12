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

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

/// Latest set of application rules whose exe could not be resolved to a path
/// (so their per-process `ALE_APP_ID` filter was not built). Written by the
/// orchestrator on every filter compute, read by the `SnapshotInitial`
/// handler for the GUI banner. Entries are the rule's app pattern (e.g.
/// `"vk.exe"`, `"disko*.exe"`), stored sorted + deduped.
#[derive(Clone, Default)]
pub struct AppEnforcementStatus(Arc<Mutex<Vec<String>>>);

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
            *guard = apps;
        }
    }

    /// Snapshot the current set (already sorted + deduped). A poisoned lock
    /// recovers the inner value rather than panicking.
    pub fn unresolved(&self) -> Vec<String> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
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

#[cfg(test)]
mod tests {
    use super::*;

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
        status.set_unresolved(vec!["vk.exe".to_string(), "disko*.exe".to_string()]);
        assert_eq!(status.unresolved(), vec!["disko*.exe", "vk.exe"]);
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
        writer.set(&[Ipv4Addr::new(8, 6, 112, 1), Ipv4Addr::new(8, 6, 112, 2)]);
        assert_eq!(reader.count(), 2);
        assert_eq!(reader.addresses(), vec!["8.6.112.1", "8.6.112.2"]);
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
