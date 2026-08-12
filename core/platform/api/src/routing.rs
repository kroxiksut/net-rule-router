//! Routing table transaction with compensating-action journal.
//!
//! Windows route table has no true atomic batch API. We simulate atomicity
//! with a **compensating-action journal**: every successful mutation is
//! immediately pushed onto a rollback stack. On failure, `rollback()` walks
//! the stack in reverse and undoes each mutation.
//!
//! ## Error handling
//!
//! - `Idempotent` (e.g. ERROR_NOT_FOUND on delete) → treat as success,
//!   push no compensating action (nothing to undo).
//! - `Conflict` (e.g. route already exists on add) → treat as success for
//!   AddRoute; for UpdateRoute a conflict means the current state may be
//!   stale — surface as `Fatal` so the orchestrator re-snapshots.
//! - `Retryable` → propagated; caller may retry the whole plan.
//! - `Fatal` / `PrivilegeRequired` → propagated; caller triggers rollback.
//!
//! ## Rollback semantics
//!
//! Best-effort: if a compensating action itself fails, we collect the error
//! and continue with the remaining undo steps. The caller decides whether
//! partial rollback is acceptable.
//!
//! ## IPv6
//!
//! IPv6 destinations never reach this module — they are skipped by the
//! `compute_action_plan` caller.

use std::sync::Arc;

use crate::{
    error::{ErrorClass, PlatformError},
    types::{RouteEntry, RoutingAction},
    windows_api::WindowsApiPort,
};

// ── CompensatingAction ────────────────────────────────────────────────────────

/// A single undo step stored in the compensating-action journal.
// Variants intentionally share the `Route` suffix — each names the route
// operation it compensates (DeleteRoute undoes AddRoute, etc.).
#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
enum CompensatingAction {
    /// Undo an AddRoute: delete the route that was added.
    DeleteRoute(RouteEntry),
    /// Undo a DeleteRoute: re-add the route that was removed.
    AddRoute(RouteEntry),
    /// Undo an UpdateRoute: delete the new entry and restore the old one.
    SwapRoute {
        delete_new: RouteEntry,
        restore_old: RouteEntry,
    },
}

// ── RoutingTransaction ────────────────────────────────────────────────────────

/// Executes a batch of routing-table mutations with compensating actions.
///
/// Call `execute()` to apply a slice of `RoutingAction`s. On success call
/// `finalize()` to clear the journal. On failure (or before finalize) call
/// `rollback()` to undo every applied mutation in reverse order.
pub struct RoutingTransaction {
    api: Arc<dyn WindowsApiPort>,
    /// Undo steps in *forward* order; `rollback()` iterates in reverse.
    compensating: Vec<CompensatingAction>,
}

impl RoutingTransaction {
    pub fn new(api: Arc<dyn WindowsApiPort>) -> Self {
        Self {
            api,
            compensating: Vec::new(),
        }
    }

    /// Apply `actions` in order, building the compensating journal.
    ///
    /// Returns `Err` on the first non-idempotent failure.  The journal is
    /// populated up to (but not including) the failed action, so `rollback()`
    /// can undo exactly the mutations that succeeded.
    pub fn execute(&mut self, actions: &[RoutingAction]) -> Result<(), PlatformError> {
        for action in actions {
            self.execute_one(action)?;
        }
        Ok(())
    }

    /// Apply a single routing action.
    fn execute_one(&mut self, action: &RoutingAction) -> Result<(), PlatformError> {
        match action {
            RoutingAction::AddRoute(entry) => {
                match self.api.create_ip_forward_entry(entry) {
                    Ok(()) => {
                        self.compensating
                            .push(CompensatingAction::DeleteRoute(entry.clone()));
                    }
                    Err(e) if e.classify() == ErrorClass::Idempotent => {
                        // Route already exists in the exact desired state —
                        // no-op, no undo needed.
                    }
                    Err(e) if e.classify() == ErrorClass::Conflict => {
                        // A route with this key already exists with a different
                        // config — e.g. a redirect-gateway VPN's own `/1`
                        // overlay (its metric ≠ ours). Per the module doc,
                        // AddRoute treats a conflict as success: we neither own
                        // nor undo the pre-existing entry, and a more-specific
                        // `/32` still wins by longest-prefix match. This keeps
                        // the mode-B overlay idempotent against the VPN's own
                        // redirect pair and stops one collision from failing
                        // the whole reconcile.
                    }
                    Err(e) => return Err(e),
                }
            }

            RoutingAction::DeleteRoute(entry) => {
                match self.api.delete_ip_forward_entry(entry) {
                    Ok(()) => {
                        self.compensating
                            .push(CompensatingAction::AddRoute(entry.clone()));
                    }
                    Err(e) if e.classify() == ErrorClass::Idempotent => {
                        // Already gone — idempotent success, no undo needed.
                    }
                    Err(e) => return Err(e),
                }
            }

            RoutingAction::UpdateRoute { old, new } => {
                // Step 1: delete the old entry.
                self.api.delete_ip_forward_entry(old)?;
                // Step 2: add the new entry.
                match self.api.create_ip_forward_entry(new) {
                    Ok(()) => {
                        self.compensating.push(CompensatingAction::SwapRoute {
                            delete_new: new.clone(),
                            restore_old: old.clone(),
                        });
                    }
                    Err(e) => {
                        // New add failed. Best-effort: try to restore the old entry
                        // so the system is not left without any route for this dest.
                        let _ = self.api.create_ip_forward_entry(old);
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }

    /// Undo all applied mutations in reverse order (last-in, first-out).
    ///
    /// Best-effort: errors from compensating actions are collected and
    /// returned rather than aborting the rollback loop.
    pub fn rollback(&mut self) -> Vec<PlatformError> {
        let mut errors = Vec::new();
        // Drain in reverse — last action undone first.
        while let Some(undo) = self.compensating.pop() {
            let result = match &undo {
                CompensatingAction::DeleteRoute(entry) => {
                    // Undo AddRoute: delete what we added.
                    match self.api.delete_ip_forward_entry(entry) {
                        Err(e) if e.classify() == ErrorClass::Idempotent => Ok(()),
                        other => other,
                    }
                }
                CompensatingAction::AddRoute(entry) => {
                    // Undo DeleteRoute: re-add what we deleted.
                    match self.api.create_ip_forward_entry(entry) {
                        Err(e) if e.classify() == ErrorClass::Idempotent => Ok(()),
                        other => other,
                    }
                }
                CompensatingAction::SwapRoute {
                    delete_new,
                    restore_old,
                } => {
                    // Undo UpdateRoute: delete new entry, restore old.
                    let _ = match self.api.delete_ip_forward_entry(delete_new) {
                        Err(e) if e.classify() == ErrorClass::Idempotent => Ok(()),
                        other => other,
                    };
                    match self.api.create_ip_forward_entry(restore_old) {
                        Err(e) if e.classify() == ErrorClass::Idempotent => Ok(()),
                        other => other,
                    }
                }
            };
            if let Err(e) = result {
                errors.push(e);
            }
        }
        errors
    }

    /// Discard the journal after a successful apply + verify.
    /// After this call `rollback()` is a no-op.
    pub fn finalize(&mut self) {
        self.compensating.clear();
    }

    /// Number of pending compensating actions. Mainly for tests.
    pub fn pending_undo_count(&self) -> usize {
        self.compensating.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::PlatformError, types::RoutingAction, windows_api::MockWindowsApi};
    use std::net::Ipv4Addr;

    fn api() -> Arc<MockWindowsApi> {
        Arc::new(MockWindowsApi::new())
    }

    fn route(dest: [u8; 4], next_hop: [u8; 4], ifindex: u32, ours: bool) -> RouteEntry {
        RouteEntry {
            destination: Ipv4Addr::from(dest),
            prefix_length: 24,
            next_hop: Ipv4Addr::from(next_hop),
            interface_index: ifindex,
            metric: 10,
            is_ours: ours,
            table: crate::RouteTableRef::Main,
        }
    }

    #[test]
    fn add_route_inserts_into_table() {
        let api = api();
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        let r = route([10, 0, 0, 0], [192, 168, 1, 1], 5, true);
        tx.execute(&[RoutingAction::AddRoute(r.clone())]).unwrap();
        let table = api.get_ip_forward_table().unwrap();
        assert_eq!(table.len(), 1);
        assert_eq!(table[0].destination, r.destination);
        assert_eq!(tx.pending_undo_count(), 1);
    }

    #[test]
    fn add_route_treats_conflict_as_success_with_no_undo() {
        // A route whose key already exists with a different config (e.g. a
        // redirect-gateway VPN's own /1 overlay) makes CreateIpForwardEntry2
        // return ERROR_OBJECT_ALREADY_EXISTS → Conflict. AddRoute treats it as
        // success and records NO undo (we don't own the pre-existing entry), so
        // one collision can't fail or roll back the whole reconcile.
        let api = api();
        api.set_force_error(Some(PlatformError::Win32 {
            operation: "CreateIpForwardEntry2",
            code: 0x1392,
            message: "route already exists".to_string(),
        }));
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        let r = route([0, 0, 0, 0], [10, 91, 192, 1], 78, true);
        tx.execute(&[RoutingAction::AddRoute(r)])
            .expect("conflict on add is treated as success");
        assert_eq!(
            tx.pending_undo_count(),
            0,
            "a conflicting add owns nothing, so records no compensating undo"
        );
    }

    #[test]
    fn delete_route_removes_from_table() {
        let api = api();
        let r = route([10, 0, 0, 0], [192, 168, 1, 1], 5, true);
        api.create_ip_forward_entry(&r).unwrap();

        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        tx.execute(&[RoutingAction::DeleteRoute(r.clone())])
            .unwrap();
        assert!(api.get_ip_forward_table().unwrap().is_empty());
        assert_eq!(tx.pending_undo_count(), 1);
    }

    #[test]
    fn update_route_replaces_in_table() {
        let api = api();
        let old = route([10, 0, 0, 0], [192, 168, 1, 1], 5, true);
        api.create_ip_forward_entry(&old).unwrap();
        let new = RouteEntry {
            metric: 20,
            ..old.clone()
        };

        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        tx.execute(&[RoutingAction::UpdateRoute {
            old: old.clone(),
            new: new.clone(),
        }])
        .unwrap();

        let table = api.get_ip_forward_table().unwrap();
        assert_eq!(table.len(), 1);
        assert_eq!(table[0].metric, 20, "table must contain updated route");
        assert_eq!(tx.pending_undo_count(), 1);
    }

    #[test]
    fn rollback_undoes_add_route() {
        let api = api();
        let r = route([10, 0, 0, 0], [192, 168, 1, 1], 5, true);
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        tx.execute(&[RoutingAction::AddRoute(r.clone())]).unwrap();
        assert_eq!(api.get_ip_forward_table().unwrap().len(), 1);

        let errors = tx.rollback();
        assert!(errors.is_empty(), "rollback must succeed: {errors:?}");
        assert!(
            api.get_ip_forward_table().unwrap().is_empty(),
            "route must be removed"
        );
        assert_eq!(tx.pending_undo_count(), 0);
    }

    #[test]
    fn rollback_undoes_delete_route() {
        let api = api();
        let r = route([10, 0, 0, 0], [192, 168, 1, 1], 5, true);
        api.create_ip_forward_entry(&r).unwrap();

        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        tx.execute(&[RoutingAction::DeleteRoute(r.clone())])
            .unwrap();
        assert!(api.get_ip_forward_table().unwrap().is_empty());

        let errors = tx.rollback();
        assert!(errors.is_empty());
        assert_eq!(
            api.get_ip_forward_table().unwrap().len(),
            1,
            "route must be restored"
        );
    }

    #[test]
    fn partial_failure_limits_rollback_scope() {
        // Add r1 succeeds, add r2 fails. Rollback must only undo r1.
        let api = api();
        api.set_force_error(None); // start clean

        let r1 = route([10, 0, 0, 0], [192, 168, 1, 1], 5, true);
        let r2 = route([10, 0, 1, 0], [192, 168, 1, 2], 5, true);

        // Pre-add r2 to the mock to simulate duplicate conflict for r2 only.
        // We'll instead use force_error after r1.
        // Trick: add r1 first ourselves, then make subsequent calls fail.
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        tx.execute(&[RoutingAction::AddRoute(r1.clone())]).unwrap();

        api.set_force_error(Some(PlatformError::Win32 {
            operation: "create_ip_forward_entry",
            code: 0x5, // ERROR_ACCESS_DENIED → Fatal
            message: "simulated fatal".into(),
        }));

        let result = tx.execute(&[RoutingAction::AddRoute(r2.clone())]);
        assert!(result.is_err(), "second add must fail");

        // Now rollback: only r1's add should be undone.
        api.set_force_error(None);
        let errors = tx.rollback();
        assert!(errors.is_empty());
        let table = api.get_ip_forward_table().unwrap();
        assert!(table.is_empty(), "r1 must have been rolled back");
    }

    #[test]
    fn idempotent_delete_of_missing_route_succeeds() {
        let api = api(); // empty table
        let r = route([10, 0, 0, 0], [192, 168, 1, 1], 5, true);
        api.set_force_error(Some(PlatformError::Win32 {
            operation: "delete_ip_forward_entry",
            code: 0x490, // ERROR_NOT_FOUND → Idempotent
            message: "not found".into(),
        }));

        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        let result = tx.execute(&[RoutingAction::DeleteRoute(r)]);
        // Idempotent → treated as success
        assert!(
            result.is_ok(),
            "delete of absent route must succeed: {result:?}"
        );
        // No compensating action pushed (nothing was changed).
        assert_eq!(tx.pending_undo_count(), 0);
    }

    #[test]
    fn finalize_clears_compensating_log() {
        let api = api();
        let r = route([10, 0, 0, 0], [192, 168, 1, 1], 5, true);
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        tx.execute(&[RoutingAction::AddRoute(r)]).unwrap();
        assert_eq!(tx.pending_undo_count(), 1);
        tx.finalize();
        assert_eq!(tx.pending_undo_count(), 0);
        // Rollback after finalize is a no-op.
        let errors = tx.rollback();
        assert!(errors.is_empty());
        // The route must still be in the table (not deleted by rollback).
        assert_eq!(api.get_ip_forward_table().unwrap().len(), 1);
    }

    #[test]
    fn multiple_actions_applied_in_order() {
        let api = api();
        let r1 = route([10, 0, 0, 0], [192, 168, 1, 1], 5, true);
        let r2 = route([10, 0, 1, 0], [192, 168, 1, 2], 5, true);
        api.create_ip_forward_entry(&r1).unwrap();

        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        tx.execute(&[
            RoutingAction::DeleteRoute(r1.clone()),
            RoutingAction::AddRoute(r2.clone()),
        ])
        .unwrap();

        let table = api.get_ip_forward_table().unwrap();
        assert_eq!(table.len(), 1);
        assert_eq!(table[0].destination, r2.destination);
        assert_eq!(tx.pending_undo_count(), 2);
    }
}
