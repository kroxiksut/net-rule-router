//! Routing table transaction with compensating-action journal.
//!
//! Neutral: it drives [`RouteTablePort`], so the same journal works on any OS
//! whose backend can add and delete a route.
//!
//! Windows route table has no true atomic batch API. We simulate atomicity
//! with a **compensating-action journal**: every successful mutation is
//! immediately pushed onto a rollback stack. On failure, `rollback()` walks
//! the stack in reverse and undoes each mutation.
//!
//! ## Error handling
//!
//! - `Idempotent` (e.g. ERROR_NOT_FOUND on delete) → treat as success,
//!   push no compensating action (nothing to undo). On an ADD the same code
//!   is the interface having gone (`MutationIntent::Add` → `Fatal`).
//! - `Conflict` on add → keep the existing entry without claiming ownership.
//! - `Retryable` → propagated; caller may retry the whole plan.
//! - `Fatal` / `PrivilegeRequired` → propagated; caller triggers rollback.
//!
//! ## Rollback semantics
//!
//! Best-effort: if a compensating action itself fails, we collect the error
//! and continue with the remaining undo steps. The caller decides whether
//! partial rollback is acceptable.

use std::sync::Arc;

use crate::{
    error::{ErrorClass, MutationIntent, PlatformError},
    route_table::RouteTablePort,
    types::{RouteEntry, RoutingAction},
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

/// What a rollback left in place because its undo step failed.
#[derive(Debug, Default)]
pub struct RollbackResidue {
    pub errors: Vec<PlatformError>,
    /// Added by the transaction and still in the table.
    pub still_added: Vec<RouteEntry>,
    /// Removed by the transaction and still missing from the table.
    pub still_removed: Vec<RouteEntry>,
}

// ── RoutingTransaction ────────────────────────────────────────────────────────

/// Executes a batch of routing-table mutations with compensating actions.
///
/// Call `execute()` to apply a slice of `RoutingAction`s. On success call
/// `finalize()` to clear the journal. On failure (or before finalize) call
/// `rollback()` to undo every applied mutation in reverse order.
pub struct RoutingTransaction {
    api: Arc<dyn RouteTablePort>,
    /// Undo steps in *forward* order; `rollback()` iterates in reverse.
    compensating: Vec<CompensatingAction>,
}

impl RoutingTransaction {
    pub fn new(api: Arc<dyn RouteTablePort>) -> Self {
        Self {
            api,
            compensating: Vec::new(),
        }
    }

    /// Apply `actions` in order, building the compensating journal.
    ///
    /// Stops at the first failure; the journal includes successful mutations
    /// within an update that failed halfway through.
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
                // Classified as an ADD: "not found" here is the interface having
                // gone, so the route was never installed and the add fails.
                match self.api.create_ip_forward_entry(entry) {
                    Ok(()) => {
                        self.compensating
                            .push(CompensatingAction::DeleteRoute(entry.clone()));
                    }
                    Err(e) if e.classify_for(MutationIntent::Add) == ErrorClass::Conflict => {
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
                let removed_old = match self.api.delete_ip_forward_entry(old) {
                    Ok(()) => true,
                    Err(e) if e.classify() == ErrorClass::Idempotent => false,
                    Err(e) => return Err(e),
                };
                // Preserve the successful deletion even if the add fails.
                if removed_old {
                    self.compensating
                        .push(CompensatingAction::AddRoute(old.clone()));
                }
                match self.api.create_ip_forward_entry(new) {
                    Ok(()) => {
                        if removed_old {
                            let _ = self.compensating.pop();
                            self.compensating.push(CompensatingAction::SwapRoute {
                                delete_new: new.clone(),
                                restore_old: old.clone(),
                            });
                        } else {
                            self.compensating
                                .push(CompensatingAction::DeleteRoute(new.clone()));
                        }
                    }
                    // A conflict confirms no mutation of the existing route.
                    Err(e) if e.classify_for(MutationIntent::Add) == ErrorClass::Conflict => {}
                    Err(e) => return Err(e),
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
        self.rollback_with_residue().errors
    }

    /// [`Self::rollback`], also naming the mutations it could not undo, so a
    /// caller tracking what it owns in the table can stay accurate.
    pub fn rollback_with_residue(&mut self) -> RollbackResidue {
        let mut residue = RollbackResidue::default();
        // Drain in reverse — last action undone first.
        while let Some(undo) = self.compensating.pop() {
            match undo {
                CompensatingAction::DeleteRoute(entry) => {
                    if let Err(e) = self.delete_tolerant(&entry) {
                        residue.errors.push(e);
                        residue.still_added.push(entry);
                    }
                }
                CompensatingAction::AddRoute(entry) => {
                    if let Err(e) = self.create_tolerant(&entry) {
                        residue.errors.push(e);
                        residue.still_removed.push(entry);
                    }
                }
                CompensatingAction::SwapRoute {
                    delete_new,
                    restore_old,
                } => {
                    if let Err(e) = self.delete_tolerant(&delete_new) {
                        residue.errors.push(e);
                        residue.still_added.push(delete_new);
                    }
                    if let Err(e) = self.create_tolerant(&restore_old) {
                        residue.errors.push(e);
                        residue.still_removed.push(restore_old);
                    }
                }
            }
        }
        residue
    }

    fn delete_tolerant(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        match self.api.delete_ip_forward_entry(entry) {
            Err(e) if e.classify() == ErrorClass::Idempotent => Ok(()),
            other => other,
        }
    }

    /// A restore that finds the route already back is done; one whose
    /// interface has gone is not, and is reported so the caller's ownership
    /// stays honest.
    fn create_tolerant(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        match self.api.create_ip_forward_entry(entry) {
            Err(e) if e.classify_for(MutationIntent::Add) == ErrorClass::Conflict => Ok(()),
            other => other,
        }
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

    /// The routes this transaction actually ADDED — the ones the caller may
    /// claim as its own.
    ///
    /// A conflicting add is reported as success (a route with that key already
    /// exists, put there by somebody else — a redirect VPN's own overlay is the
    /// usual case), and it leaves no compensating entry precisely because it is
    /// not ours to undo. A caller that assumes "the whole desired set is mine
    /// now" adopts that foreign route and deletes it on a later pass.
    #[must_use]
    pub fn added_routes(&self) -> Vec<RouteEntry> {
        self.compensating
            .iter()
            .filter_map(|c| match c {
                CompensatingAction::DeleteRoute(entry) => Some(entry.clone()),
                _ => None,
            })
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_table::RouteTablePort;
    use crate::{error::PlatformError, types::RoutingAction, windows_api::MockWindowsApi};
    use std::net::{IpAddr, Ipv4Addr};

    fn api() -> Arc<MockWindowsApi> {
        Arc::new(MockWindowsApi::new())
    }

    fn route(dest: [u8; 4], next_hop: [u8; 4], ifindex: u32, ours: bool) -> RouteEntry {
        RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::from(dest)),
            prefix_length: 24,
            next_hop: IpAddr::V4(Ipv4Addr::from(next_hop)),
            interface_index: ifindex,
            metric: 10,
            is_ours: ours,
            table: crate::RouteTableRef::Main,
        }
    }

    #[test]
    fn add_route_inserts_into_table() {
        let api = api();
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
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
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
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

        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
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

        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
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
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
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

        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
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
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
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

    fn fatal() -> PlatformError {
        PlatformError::Win32 {
            operation: "simulated",
            code: 0x5, // ERROR_ACCESS_DENIED → Fatal
            message: "simulated fatal".into(),
        }
    }

    /// A caller that tracks what it owns needs to know which undo steps did
    /// not land; a clean rollback leaves nothing behind.
    #[test]
    fn rollback_residue_names_what_could_not_be_undone() {
        let api = api();
        let kept = route([10, 0, 0, 0], [192, 168, 1, 1], 5, true);
        let dropped = route([10, 0, 1, 0], [192, 168, 1, 1], 5, true);
        api.create_ip_forward_entry(&dropped).unwrap();
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        tx.execute(&[
            RoutingAction::DeleteRoute(dropped.clone()),
            RoutingAction::AddRoute(kept.clone()),
        ])
        .unwrap();

        // Every undo fails: the add stays, the delete stays undone.
        api.set_force_error(Some(fatal()));
        let residue = tx.rollback_with_residue();
        assert_eq!(residue.errors.len(), 2);
        assert_eq!(residue.still_added, vec![kept.clone()]);
        assert_eq!(residue.still_removed, vec![dropped.clone()]);

        // Positive control: the same transaction shape rolls back cleanly.
        api.set_force_error(None);
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        tx.execute(&[RoutingAction::AddRoute(dropped)]).unwrap();
        let residue = tx.rollback_with_residue();
        assert!(residue.errors.is_empty());
        assert!(residue.still_added.is_empty() && residue.still_removed.is_empty());
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

        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        let result = tx.execute(&[RoutingAction::DeleteRoute(r)]);
        // Idempotent → treated as success
        assert!(
            result.is_ok(),
            "delete of absent route must succeed: {result:?}"
        );
        // No compensating action pushed (nothing was changed).
        assert_eq!(tx.pending_undo_count(), 0);
    }

    /// An add answered "not found" is a route onto an interface that vanished:
    /// the apply fails, nothing is journalled as added, and the rollback has
    /// nothing to undo — instead of a phantom route the reconciler owns.
    #[test]
    fn an_add_onto_a_vanished_interface_fails_instead_of_counting_as_done() {
        let api = api();
        let first = route([10, 0, 0, 0], [192, 168, 1, 1], 5, true);
        let vanished = route([10, 0, 1, 0], [192, 168, 1, 1], 99, true);
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        tx.execute(&[RoutingAction::AddRoute(first)]).unwrap();

        api.set_route_create_error(Some(PlatformError::Win32 {
            operation: "CreateIpForwardEntry2",
            code: 0x490, // ERROR_NOT_FOUND
            message: "interface gone".into(),
        }));
        assert!(
            tx.execute(&[RoutingAction::AddRoute(vanished)]).is_err(),
            "not found on an add is the interface being gone, not success"
        );
        assert_eq!(
            tx.pending_undo_count(),
            1,
            "only the first add is journalled"
        );
        assert!(tx.added_routes().iter().all(|r| r.interface_index == 5));

        api.set_route_create_error(None);
        let residue = tx.rollback_with_residue();
        assert!(residue.errors.is_empty());
        assert!(api.get_ip_forward_table().unwrap().is_empty());
    }

    /// The same answer on the way back: a restore whose interface is gone is
    /// reported as still missing, and one that finds the route already there
    /// is done.
    #[test]
    fn a_rollback_restore_onto_a_vanished_interface_is_reported_not_swallowed() {
        let api = api();
        let dropped = route([10, 0, 1, 0], [192, 168, 1, 1], 5, true);
        api.create_ip_forward_entry(&dropped).unwrap();
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        tx.execute(&[RoutingAction::DeleteRoute(dropped.clone())])
            .unwrap();

        api.set_route_create_error(Some(PlatformError::Win32 {
            operation: "CreateIpForwardEntry2",
            code: 0x490,
            message: "interface gone".into(),
        }));
        let residue = tx.rollback_with_residue();
        assert_eq!(residue.still_removed, vec![dropped.clone()]);
        assert_eq!(residue.errors.len(), 1);

        // Already back (somebody re-added it) is the state the restore wanted.
        api.set_route_create_error(None);
        api.create_ip_forward_entry(&dropped).unwrap();
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        tx.execute(&[RoutingAction::DeleteRoute(dropped.clone())])
            .unwrap();
        api.set_route_create_error(Some(PlatformError::Win32 {
            operation: "CreateIpForwardEntry2",
            code: 0x1392,
            message: "already exists".into(),
        }));
        let residue = tx.rollback_with_residue();
        assert!(residue.errors.is_empty(), "{:?}", residue.errors);
        assert!(residue.still_removed.is_empty());
    }

    #[test]
    fn finalize_clears_compensating_log() {
        let api = api();
        let r = route([10, 0, 0, 0], [192, 168, 1, 1], 5, true);
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
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

        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
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
    /// An update whose add fails leaves the old route RECOVERABLE.
    ///
    /// The delete has already happened by then, so the only thing between the
    /// user and a destination with no route at all is the undo journal.
    /// Recording the undo only on SUCCESS meant `rollback()` had nothing for
    /// this case: the single inline retry was the whole recovery, and if that
    /// failed too the route was gone for good.
    #[test]
    fn a_failed_update_leaves_the_old_route_in_the_undo_journal() {
        let api = api();
        let old = route([10, 0, 0, 0], [192, 168, 1, 1], 5, true);
        let new_route = route([10, 0, 0, 0], [192, 168, 1, 2], 5, true);
        // The add fails; the delete before it does not.
        api.set_route_create_error(Some(PlatformError::Win32 {
            operation: "CreateIpForwardEntry2",
            code: 0x5,
            message: "denied".to_string(),
        }));
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        assert!(tx
            .execute(&[RoutingAction::UpdateRoute {
                old: old.clone(),
                new: new_route,
            }])
            .is_err());
        assert_eq!(
            tx.pending_undo_count(),
            1,
            "the old route must be restorable from the journal, not only inline",
        );
    }

    #[test]
    fn update_conflict_rollback_keeps_the_preexisting_foreign_route() {
        let api = api();
        let old = route([10, 0, 1, 0], [192, 0, 2, 1], 5, true);
        let foreign = route([10, 0, 2, 0], [192, 0, 2, 2], 6, false);
        api.set_route_table(vec![old.clone(), foreign.clone()]);
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        api.set_route_create_error(Some(PlatformError::Win32 {
            operation: "CreateIpForwardEntry2",
            code: 0x1392,
            message: "foreign route exists".into(),
        }));
        tx.execute(&[RoutingAction::UpdateRoute {
            old: old.clone(),
            new: foreign.clone(),
        }])
        .unwrap();
        assert!(
            tx.added_routes().is_empty(),
            "a conflict does not establish ownership"
        );
        api.set_route_create_error(None);
        assert!(tx.rollback().is_empty());
        let table = api.get_ip_forward_table().unwrap();
        assert!(table.contains(&old), "our removal must be undone");
        assert!(
            table.contains(&foreign),
            "the foreign route must survive rollback"
        );
    }

    struct MissingOldRoute {
        api: Arc<MockWindowsApi>,
        old: RouteEntry,
    }

    impl RouteTablePort for MissingOldRoute {
        fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError> {
            self.api.get_ip_forward_table()
        }
        fn create_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
            self.api.create_ip_forward_entry(entry)
        }
        fn delete_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
            if entry == &self.old {
                return Err(PlatformError::Win32 {
                    operation: "DeleteIpForwardEntry2",
                    code: 0x490,
                    message: "already removed".into(),
                });
            }
            self.api.delete_ip_forward_entry(entry)
        }
        fn get_adapter_infos(&self) -> Result<Vec<crate::adapters::AdapterInfo>, PlatformError> {
            self.api.get_adapter_infos()
        }
        fn interface_luid_for_index(&self, ifindex: u32) -> Result<u64, PlatformError> {
            self.api.interface_luid_for_index(ifindex)
        }
    }

    #[test]
    fn update_rollback_does_not_resurrect_an_old_route_that_was_already_missing() {
        let api = api();
        let old = route([10, 0, 1, 0], [192, 0, 2, 1], 5, true);
        let new = route([10, 0, 2, 0], [192, 0, 2, 2], 6, true);
        let port = Arc::new(MissingOldRoute {
            api: Arc::clone(&api),
            old: old.clone(),
        });
        let mut tx = RoutingTransaction::new(port);
        tx.execute(&[RoutingAction::UpdateRoute { old, new }])
            .unwrap();
        assert!(tx.rollback().is_empty());
        assert!(
            api.get_ip_forward_table().unwrap().is_empty(),
            "rollback must preserve the original absence"
        );
    }

    #[test]
    fn update_rollback_reports_both_failed_compensations() {
        let api = api();
        let old = route([10, 0, 1, 0], [192, 0, 2, 1], 5, true);
        let new = route([10, 0, 2, 0], [192, 0, 2, 2], 6, true);
        api.set_route_table(vec![old.clone()]);
        let mut tx = RoutingTransaction::new(Arc::clone(&api) as Arc<dyn RouteTablePort>);
        tx.execute(&[RoutingAction::UpdateRoute {
            old: old.clone(),
            new: new.clone(),
        }])
        .unwrap();
        api.set_force_error(Some(PlatformError::Win32 {
            operation: "route rollback",
            code: 5,
            message: "access denied".into(),
        }));
        let residue = tx.rollback_with_residue();
        assert_eq!(
            residue.errors.len(),
            2,
            "neither rollback failure may be hidden"
        );
        assert_eq!(residue.still_added, vec![new]);
        assert_eq!(residue.still_removed, vec![old]);
    }
}
