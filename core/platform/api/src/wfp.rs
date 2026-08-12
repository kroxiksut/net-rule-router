//! WFP session RAII handles and plan execution.
//!
//! ## Session lifecycle (per-service-instance)
//!
//! The WFP engine session is opened **once at service start** and kept alive
//! until graceful stop. The session is **non-dynamic**: filters registered
//! within it are NOT auto-removed when the session closes — they persist until
//! an explicit delete or a reboot (a non-dynamic session's block filters even
//! survive `taskkill /F`, see `cleanup_blocks_only`). Cleanup is therefore
//! explicit: graceful stop strips every filter (`cleanup_all`), and service
//! startup strips orphaned block filters left by a hard-killed prior instance.
//!
//! The `WindowsApplyEngine` owns the session. Each policy apply uses a
//! **per-apply WFP transaction** (begin → add/delete filters → commit/abort)
//! within the long-lived session.
//!
//! ## Batching
//!
//! If a plan has more than `MAX_FILTERS_PER_TRANSACTION` filter actions
//! (default 500), they are split into multiple transactions. Each batch is
//! committed independently. A failure in a non-first batch leaves earlier
//! batches committed; the rollback logic in `apply/mod.rs` enumerates and
//! deletes all our filters by provider GUID to restore the previous state.
//!
//! ## Idempotency (error classification)
//!
//! - `FWP_E_DUPLICATE_OBJECT` on AddFilter → already added → treat as success.
//! - `ERROR_NOT_FOUND` on DeleteFilter → already gone → treat as success.
//! - All other errors → propagated to caller.
//!
//! ## RAII invariants
//!
//! - `WfpSession::drop` always calls `FwpmEngineClose0` exactly once.
//! - `WfpTransactionGuard::drop` calls `FwpmTransactionAbort0` unless
//!   `commit()` was called first.
//! - No raw `HANDLE`/`HFWPENGINE` escapes into business logic.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::{
    error::{ErrorClass, PlatformError},
    types::{
        WfpAction, WfpEngineToken, WfpFilterAction, WfpFilterId, WfpFilterRecord, WfpFilterSpec,
    },
    windows_api::WindowsApiPort,
};

/// Maximum number of WFP filters per transaction. Prevents
/// `FwpmTransactionCommit0` from timing out on very large rule sets.
/// Apply plans larger than this are split into multiple transactions.
///
/// Neutral batching cap (its former home was the Windows `constants` module);
/// it travels with the WFP session logic into `nrr-platform-api` and is
/// re-exported from the Windows crate for source compatibility.
pub const MAX_FILTERS_PER_TRANSACTION: usize = 500;

// ── Apply resilience ──────────────────────────────────────────────────────────

/// How a single un-materializable filter is handled during an apply.
///
/// Maps 1:1 from `nrr_service_runtime::ApplyFailurePolicy` at the per-SID
/// orchestrator boundary (`AllOrNothing → Strict`, `BestEffort →
/// BestEffort`, `PreFlightThenAllOrNothing → Strict` at this level — its
/// pre-flight is a separate phase). Lives in the platform crate so the
/// WFP layer needs no dependency on service-runtime.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FilterFailureMode {
    /// Any filter that cannot be materialized aborts the whole apply —
    /// the transaction is rolled back. The revision is applied exactly
    /// or not at all.
    Strict,
    /// Un-materializable filters (absent app executable, degenerate
    /// app-id blob, rejected filter condition) are skipped with a
    /// recorded diagnostic; the rest of the revision still applies. One
    /// bad rule in a shared preset never nukes the whole policy. Default.
    #[default]
    BestEffort,
}

/// One filter the apply layer skipped because it could not be
/// materialized (only ever populated under [`FilterFailureMode::BestEffort`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedFilter {
    pub id: WfpFilterId,
    /// Human-readable reason (the underlying `PlatformError` rendering).
    pub reason: String,
}

/// Result of an apply that may have skipped individual filters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WfpApplyOutcome {
    pub skipped: Vec<SkippedFilter>,
}

// ── WfpSession ────────────────────────────────────────────────────────────────

/// RAII guard for a per-service-instance WFP engine session.
///
/// Opened once at service start; closed on graceful stop or drop.
/// All filter mutations go through `execute_wfp_plan()`.
pub struct WfpSession {
    token: Option<WfpEngineToken>,
    api: Arc<dyn WindowsApiPort>,
    /// Serializes every filter-mutation transaction on this session. A WFP
    /// transaction is session-wide (one per engine handle); concurrent
    /// `FwpmTransactionBegin0` calls on the same handle return
    /// `FWP_E_TXN_IN_PROGRESS` (0x8032000E). The `PerSidApplyOrchestrator`
    /// shares ONE `Arc<WfpSession>` across the periodic reconcile tick, the
    /// event-driven network-change / Mode-B re-arm threads, and IPC apply
    /// handlers; without this lock they collide and a fail-closed batch is
    /// silently dropped for that tick. Held for the whole
    /// begin→mutate→commit critical section of `execute_wfp_plan_resilient`.
    apply_lock: Mutex<()>,
    /// Filter ids (`WfpFilterId::raw`) that have already
    /// logged a `warn!` for a best-effort skip during this session's
    /// lifetime. A persistently un-materializable filter (e.g. a
    /// missing-exe app-block) is re-proposed by codegen on every apply /
    /// reconcile tick (every few seconds); without this de-dup the same
    /// skip reason floods the log at `warn!` forever, leaving no
    /// observability into which filter never installed. The first
    /// occurrence of an id warns once; subsequent occurrences of the SAME id
    /// stay at `debug!`.
    warned_skips: Mutex<HashSet<u64>>,
}

impl WfpSession {
    /// Open a new WFP engine session. **Non-dynamic**: filters persist until an
    /// explicit delete or a reboot — closing the handle does NOT remove them
    /// (cleanup is explicit; see `cleanup_all` / `cleanup_blocks_only`).
    pub fn open(api: Arc<dyn WindowsApiPort>) -> Result<Self, PlatformError> {
        let token = api.wfp_engine_open()?;
        Ok(Self {
            token: Some(token),
            api,
            apply_lock: Mutex::new(()),
            warned_skips: Mutex::new(HashSet::new()),
        })
    }

    /// Execute a slice of WFP filter actions in batches of at most
    /// `MAX_FILTERS_PER_TRANSACTION`. Each batch is committed atomically.
    ///
    /// On failure in any batch the failed transaction is aborted (via
    /// `WfpTransactionGuard::drop`); committed earlier batches remain. The
    /// caller is responsible for rolling back via `cleanup_all()` if needed.
    pub fn execute_wfp_plan(&self, actions: &[WfpFilterAction]) -> Result<(), PlatformError> {
        let outcome = self.execute_wfp_plan_resilient(actions, FilterFailureMode::Strict)?;
        debug_assert!(
            outcome.skipped.is_empty(),
            "Strict mode must never skip filters"
        );
        Ok(())
    }

    /// Like [`execute_wfp_plan`](Self::execute_wfp_plan) but honours
    /// `mode`: under [`FilterFailureMode::BestEffort`] an un-materializable
    /// filter ([`PlatformError::is_unmaterializable_filter`]) is skipped
    /// and recorded in the returned [`WfpApplyOutcome`] instead of
    /// aborting the batch. Catastrophic errors (access denied,
    /// transaction failures) always abort regardless of mode.
    pub fn execute_wfp_plan_resilient(
        &self,
        actions: &[WfpFilterAction],
        mode: FilterFailureMode,
    ) -> Result<WfpApplyOutcome, PlatformError> {
        let mut outcome = WfpApplyOutcome::default();
        if actions.is_empty() {
            return Ok(outcome);
        }
        // Serialize the whole multi-batch apply against every other caller
        // sharing this session: a WFP transaction is session-wide, so
        // two threads opening one concurrently collide with FWP_E_TXN_IN_PROGRESS
        // and one side's filters (e.g. a fail-closed block) are dropped for that
        // tick. Poison-tolerant: a prior panic mid-apply must not wedge routing
        // enforcement. `begin_transaction` is a low-level primitive NOT guarded by
        // this lock — production mutations funnel through here / `execute_wfp_plan`.
        let _apply = self.apply_lock.lock().unwrap_or_else(|p| p.into_inner());
        for batch in actions.chunks(MAX_FILTERS_PER_TRANSACTION) {
            self.execute_batch(batch, mode, &mut outcome)?;
        }
        Ok(outcome)
    }

    /// Execute one batch of filter actions within a single WFP transaction.
    fn execute_batch(
        &self,
        actions: &[WfpFilterAction],
        mode: FilterFailureMode,
        outcome: &mut WfpApplyOutcome,
    ) -> Result<(), PlatformError> {
        let guard = self.begin_transaction()?;
        for action in actions {
            match action {
                WfpFilterAction::AddFilter(spec) => {
                    match self.add_filter(spec) {
                        Ok(_) => {}
                        // A failed SUB-LAYER registration must abort,
                        // and this arm must stay ABOVE the idempotent/conflict
                        // one: `FWP_E_ALREADY_EXISTS` from the sub-layer stage
                        // classifies as `Conflict` exactly like a duplicate
                        // FILTER add, but here NOTHING was installed. Folding
                        // it into "already present — success" is the phantom-
                        // filter bug: installed counters grow, WFP stays empty,
                        // enforcement silently never happens.
                        Err(e) if e.is_sublayer_registration_failure() => {
                            tracing::error!(
                                target: "nrr::wfp",
                                filter_id = format_args!("{:016x}", spec.id.raw),
                                error = %e,
                                "sub-layer registration failed — aborting batch (no filter in it can install)"
                            );
                            return Err(e);
                        }
                        Err(e)
                            if e.classify() == ErrorClass::Idempotent
                                || e.classify() == ErrorClass::Conflict =>
                        {
                            // Already present — idempotent success. Safe ONLY
                            // because the sub-layer stage was ruled out above:
                            // this error is now provably about the filter itself.
                        }
                        Err(e) if e.is_unmaterializable_filter() => match mode {
                            // A single filter that can't be materialized
                            // (absent app, degenerate app-id blob, rejected
                            // condition). Under best-effort skip just this
                            // filter so a shared preset listing one bad rule
                            // (e.g. an uninstalled `2gis.exe`, or a malformed
                            // condition → FWP_E_CONDITION_NOT_FOUND) does NOT
                            // roll back the user's ENTIRE policy. The engine
                            // and transaction stay healthy, so we continue.
                            FilterFailureMode::BestEffort => {
                                // Expected, handled outcome (e.g. an uninstalled
                                // app in a shared preset) — debug, not warn, so a
                                // preset with dozens of app rules does not look
                                // like "a pile of errors". The count is surfaced
                                // once in the apply summary ("ok (N skipped)") and
                                // each skip is recorded in `outcome.skipped`. Run
                                // with NRR_LOG=nrr=debug to see them individually.
                                //
                                // The FIRST time this filter id is
                                // skipped in the session's lifetime is promoted to
                                // `warn!` so a persistently-unmaterializable filter
                                // is visible without needing `NRR_LOG=debug`. Every
                                // later skip of the SAME id (e.g. the ~2s
                                // reconcile tick re-proposing the same rule) stays
                                // at `debug!` so it does not spam the log.
                                let first_time_this_session = {
                                    let mut warned =
                                        self.warned_skips.lock().unwrap_or_else(|p| p.into_inner());
                                    warned.insert(spec.id.raw)
                                };
                                if first_time_this_session {
                                    tracing::warn!(
                                        target: "nrr::wfp",
                                        filter_id = format_args!("{:016x}", spec.id.raw),
                                        action = ?spec.action,
                                        remote_ip = ?spec.remote_ip,
                                        has_app = spec.app_pattern.is_some(),
                                        user_sid = ?spec.user_sid,
                                        weight = spec.weight,
                                        error = %e,
                                        "skipping un-materializable filter (best-effort apply policy) — first occurrence this session, will not repeat at warn level for this filter id"
                                    );
                                } else {
                                    tracing::debug!(
                                        target: "nrr::wfp",
                                        filter_id = format_args!("{:016x}", spec.id.raw),
                                        action = ?spec.action,
                                        remote_ip = ?spec.remote_ip,
                                        has_app = spec.app_pattern.is_some(),
                                        user_sid = ?spec.user_sid,
                                        weight = spec.weight,
                                        error = %e,
                                        "skipping un-materializable filter (best-effort apply policy)"
                                    );
                                }
                                outcome.skipped.push(SkippedFilter {
                                    id: spec.id,
                                    reason: e.to_string(),
                                });
                            }
                            // Strict (all-or-nothing): even one un-materializable
                            // filter aborts — the revision applies exactly or
                            // not at all. Log which filter so the codegen root
                            // cause is identifiable.
                            FilterFailureMode::Strict => {
                                tracing::error!(
                                    target: "nrr::wfp",
                                    filter_id = format_args!("{:016x}", spec.id.raw),
                                    action = ?spec.action,
                                    remote_ip = ?spec.remote_ip,
                                    has_app = spec.app_pattern.is_some(),
                                    user_sid = ?spec.user_sid,
                                    weight = spec.weight,
                                    error = %e,
                                    "un-materializable filter aborts apply (strict / all-or-nothing policy)"
                                );
                                return Err(e);
                            }
                        },
                        Err(e) => {
                            // Catastrophic (access denied, transaction/engine
                            // failure, unknown fatal). Always abort; log the
                            // filter identity for diagnosis.
                            tracing::error!(
                                target: "nrr::wfp",
                                filter_id = format_args!("{:016x}", spec.id.raw),
                                error = %e,
                                "filter add failed with a non-recoverable error — aborting batch"
                            );
                            return Err(e);
                        } // guard drops here → FwpmTransactionAbort0
                    }
                }
                WfpFilterAction::DeleteFilter(id) => {
                    match self.delete_filter(*id) {
                        Ok(()) => {}
                        Err(e) if e.classify() == ErrorClass::Idempotent => {
                            // Already gone — idempotent success.
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        guard.commit()
    }

    /// Delete all filters registered under our provider GUID.
    ///
    /// Called on graceful stop and as an orphan-cleanup step on startup.
    /// Returns the number of filters deleted.
    pub fn cleanup_all(&self) -> Result<usize, PlatformError> {
        let filters = self.enumerate_our_filters()?;
        let count = filters.len();
        if count == 0 {
            return Ok(0);
        }
        // Delete all in one transaction (or in batches if > cap).
        let delete_actions: Vec<WfpFilterAction> = filters
            .into_iter()
            .map(|f| WfpFilterAction::DeleteFilter(f.id))
            .collect();
        self.execute_wfp_plan(&delete_actions)?;
        Ok(count)
    }

    /// Delete only **block** filters registered under our provider GUID,
    /// leaving permit filters untouched. Returns the number deleted.
    ///
    /// Used on `persist`-mode graceful stop (keep the /32 routes + permit
    /// filters, but never leave a kill-switch / fail-closed block armed with
    /// no service to lift it) and — unconditionally — at service startup to
    /// strip any orphaned block/fail-closed filter a dead prior instance left
    /// behind (a non-dynamic WFP session's block filters survive `taskkill /F`
    /// until reboot, which would otherwise lock the user out). Mirrors
    /// [`cleanup_all`](Self::cleanup_all) but filters on
    /// `action == WfpAction::Block`.
    pub fn cleanup_blocks_only(&self) -> Result<usize, PlatformError> {
        let delete_actions: Vec<WfpFilterAction> = self
            .enumerate_our_filters()?
            .into_iter()
            .filter(|f| f.action == WfpAction::Block)
            .map(|f| WfpFilterAction::DeleteFilter(f.id))
            .collect();
        let count = delete_actions.len();
        if count == 0 {
            return Ok(0);
        }
        // Delete all matched blocks in one transaction (or in batches if > cap).
        self.execute_wfp_plan(&delete_actions)?;
        Ok(count)
    }

    // ── Low-level accessors ───────────────────────────────────────────────────

    pub fn begin_transaction(&self) -> Result<WfpTransactionGuard<'_>, PlatformError> {
        let token = self.token();
        self.api.wfp_transaction_begin(token)?;
        Ok(WfpTransactionGuard {
            session: self,
            committed: false,
        })
    }

    pub fn add_filter(&self, spec: &WfpFilterSpec) -> Result<WfpFilterId, PlatformError> {
        self.api.wfp_filter_add(self.token(), spec)
    }

    pub fn delete_filter(&self, id: WfpFilterId) -> Result<(), PlatformError> {
        self.api.wfp_filter_delete(self.token(), id)
    }

    pub fn enumerate_our_filters(&self) -> Result<Vec<WfpFilterRecord>, PlatformError> {
        self.api.wfp_enumerate_our_filters(self.token())
    }

    // The token is present for the whole session lifetime (cleared only on
    // close, after which the session is not used), so this is an invariant.
    #[allow(clippy::expect_used)]
    fn token(&self) -> &WfpEngineToken {
        self.token
            .as_ref()
            .expect("WfpSession token already closed")
    }
}

impl Drop for WfpSession {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            let _ = self.api.wfp_engine_close(token);
        }
    }
}

// ── WfpTransactionGuard ───────────────────────────────────────────────────────

/// RAII guard for one WFP transaction within a session.
///
/// Aborts the transaction on drop unless `commit()` was called first.
pub struct WfpTransactionGuard<'a> {
    session: &'a WfpSession,
    committed: bool,
}

impl<'a> WfpTransactionGuard<'a> {
    pub fn commit(mut self) -> Result<(), PlatformError> {
        let result = self
            .session
            .api
            .wfp_transaction_commit(self.session.token());
        if result.is_ok() {
            self.committed = true;
        }
        result
    }
}

impl<'a> Drop for WfpTransactionGuard<'a> {
    fn drop(&mut self) {
        if !self.committed {
            if let Some(token) = &self.session.token {
                self.session.api.wfp_transaction_abort(token);
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::PlatformError,
        types::{WfpAction, WfpFilterId, WfpFilterSpec, WfpLayerKey},
        windows_api::MockWindowsApi,
    };
    use std::net::Ipv4Addr;

    fn mock_api() -> Arc<MockWindowsApi> {
        Arc::new(MockWindowsApi::new())
    }

    fn spec(id_raw: u64) -> WfpFilterSpec {
        WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Block,
            remote_ip: Some(Ipv4Addr::new(1, 2, 3, id_raw as u8)),
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

    fn session(api: &Arc<MockWindowsApi>) -> WfpSession {
        WfpSession::open(Arc::clone(api) as Arc<dyn WindowsApiPort>).unwrap()
    }

    // ── RAII ─────────────────────────────────────────────────────────────────

    #[test]
    fn session_opens_and_closes_on_drop() {
        let api = mock_api();
        {
            let _s = session(&api);
        }
        // no panic
    }

    #[test]
    fn transaction_guard_aborts_on_drop_without_commit() {
        let api = mock_api();
        let s = session(&api);
        {
            let _g = s.begin_transaction().unwrap();
        }
        // no panic — abort path executed
    }

    #[test]
    fn transaction_guard_commits_without_abort() {
        let api = mock_api();
        let s = session(&api);
        s.begin_transaction().unwrap().commit().unwrap();
    }

    #[test]
    fn open_fails_on_api_error() {
        let api = mock_api();
        api.set_force_error(Some(PlatformError::AccessDenied {
            operation: "wfp_engine_open",
        }));
        assert!(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).is_err());
    }

    // ── execute_wfp_plan ──────────────────────────────────────────────────────

    #[test]
    fn execute_empty_plan_is_noop() {
        let api = mock_api();
        let s = session(&api);
        s.execute_wfp_plan(&[]).unwrap();
        assert!(api.wfp_filters.lock().unwrap().is_empty());
    }

    #[test]
    fn execute_add_filter_inserts_into_session() {
        let api = mock_api();
        let s = session(&api);
        s.execute_wfp_plan(&[WfpFilterAction::AddFilter(spec(1))])
            .unwrap();
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 1);
    }

    #[test]
    fn execute_delete_filter_removes_from_session() {
        let api = mock_api();
        let s = session(&api);
        s.execute_wfp_plan(&[WfpFilterAction::AddFilter(spec(1))])
            .unwrap();
        s.execute_wfp_plan(&[WfpFilterAction::DeleteFilter(WfpFilterId { raw: 1 })])
            .unwrap();
        assert!(api.wfp_filters.lock().unwrap().is_empty());
    }

    #[test]
    fn duplicate_add_treated_as_idempotent() {
        let api = mock_api();
        let s = session(&api);
        s.execute_wfp_plan(&[WfpFilterAction::AddFilter(spec(1))])
            .unwrap();
        // Mock doesn't return Conflict on re-add, so this just adds again.
        // The real test is that ErrorClass::Conflict → success (covered in integration).
        // For now verify the plan executes without panic.
        s.execute_wfp_plan(&[WfpFilterAction::AddFilter(spec(2))])
            .unwrap();
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 2);
    }

    #[test]
    fn delete_missing_filter_treated_as_idempotent() {
        let api = mock_api();
        let s = session(&api);
        // Filter 99 doesn't exist. Mock delete succeeds (no error for missing).
        s.execute_wfp_plan(&[WfpFilterAction::DeleteFilter(WfpFilterId { raw: 99 })])
            .unwrap();
    }

    #[test]
    fn failure_aborts_transaction_leaving_no_filters() {
        let api = mock_api();
        let s = session(&api);

        api.set_force_error(Some(PlatformError::Win32 {
            operation: "wfp_filter_add",
            code: 0x5,
            message: "access denied".into(),
        }));
        let result = s.execute_wfp_plan(&[WfpFilterAction::AddFilter(spec(1))]);
        assert!(result.is_err());
        // No filters should have been committed.
        assert!(api.wfp_filters.lock().unwrap().is_empty());
    }

    // ── Per-filter resilience (FilterFailureMode) ─────────────────────────────

    #[test]
    fn best_effort_skips_unmaterializable_filter_and_keeps_the_rest() {
        let api = mock_api();
        // Filter id 2 will fail to add with FWP_E_CONDITION_NOT_FOUND.
        api.set_fail_add_unmaterializable(&[2]);
        let s = session(&api);
        let outcome = s
            .execute_wfp_plan_resilient(
                &[
                    WfpFilterAction::AddFilter(spec(1)),
                    WfpFilterAction::AddFilter(spec(2)),
                    WfpFilterAction::AddFilter(spec(3)),
                ],
                FilterFailureMode::BestEffort,
            )
            .expect("best-effort must not abort");
        // 1 and 3 installed; 2 skipped and recorded.
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 2);
        assert_eq!(outcome.skipped.len(), 1);
        assert_eq!(outcome.skipped[0].id, WfpFilterId { raw: 2 });
    }

    /// The warn-once-per-id de-dup set records the filter id after
    /// its first best-effort skip, and does NOT grow on a repeat skip of the
    /// same id (the ~2s reconcile tick re-proposing the same unmaterializable
    /// filter must not re-warn every tick).
    #[test]
    fn warn_once_set_records_id_on_first_skip_and_does_not_grow_on_repeat() {
        let api = mock_api();
        api.set_fail_add_unmaterializable(&[2]);
        let s = session(&api);

        let first = s
            .execute_wfp_plan_resilient(
                &[WfpFilterAction::AddFilter(spec(2))],
                FilterFailureMode::BestEffort,
            )
            .expect("best-effort must not abort");
        assert_eq!(first.skipped.len(), 1);
        assert_eq!(s.warned_skips.lock().unwrap().len(), 1);
        assert!(s.warned_skips.lock().unwrap().contains(&2));

        let second = s
            .execute_wfp_plan_resilient(
                &[WfpFilterAction::AddFilter(spec(2))],
                FilterFailureMode::BestEffort,
            )
            .expect("best-effort must not abort");
        assert_eq!(second.skipped.len(), 1, "still recorded in the outcome");
        // Same id skipped again — the warn-once set must not grow.
        assert_eq!(s.warned_skips.lock().unwrap().len(), 1);

        // A DIFFERENT unmaterializable id is a fresh first-time warn.
        api.set_fail_add_unmaterializable(&[2, 3]);
        let third = s
            .execute_wfp_plan_resilient(
                &[WfpFilterAction::AddFilter(spec(3))],
                FilterFailureMode::BestEffort,
            )
            .expect("best-effort must not abort");
        assert_eq!(third.skipped.len(), 1);
        assert_eq!(s.warned_skips.lock().unwrap().len(), 2);
        assert!(s.warned_skips.lock().unwrap().contains(&3));
    }

    #[test]
    fn strict_aborts_on_unmaterializable_filter() {
        let api = mock_api();
        api.set_fail_add_unmaterializable(&[2]);
        let s = session(&api);
        let result = s.execute_wfp_plan_resilient(
            &[
                WfpFilterAction::AddFilter(spec(1)),
                WfpFilterAction::AddFilter(spec(2)),
                WfpFilterAction::AddFilter(spec(3)),
            ],
            FilterFailureMode::Strict,
        );
        // Strict surfaces the error (real WFP rolls the transaction back; the
        // mock has no rollback semantics, so we assert on the contract — the
        // call fails and the caller treats the whole apply as failed).
        assert!(
            result.is_err(),
            "strict must abort on un-materializable filter"
        );
        match result {
            Err(PlatformError::Win32 { code, .. }) => assert_eq!(code, 0x8032_0002),
            other => panic!("expected FWP_E_CONDITION_NOT_FOUND, got {other:?}"),
        }
    }

    #[test]
    fn strict_wrapper_execute_wfp_plan_aborts_on_unmaterializable() {
        let api = mock_api();
        api.set_fail_add_unmaterializable(&[1]);
        let s = session(&api);
        assert!(s
            .execute_wfp_plan(&[WfpFilterAction::AddFilter(spec(1))])
            .is_err());
    }

    /// Anti-phantom regression: a sub-layer registration failure —
    /// even one whose Win32 code classifies as `Conflict` (the real
    /// `FWP_E_ALREADY_EXISTS`) — must ABORT the batch, not be swallowed as
    /// "filter already present". Swallowing it is exactly how every apply
    /// became a phantom success with zero filters in WFP.
    #[test]
    fn sublayer_stage_failure_aborts_batch_instead_of_phantom_success() {
        use crate::error::win32_codes::FWP_E_ALREADY_EXISTS;
        let api = mock_api();
        api.set_fail_add_win32(&[1], "FwpmSubLayerAdd0", FWP_E_ALREADY_EXISTS);
        let s = session(&api);
        let result = s.execute_wfp_plan_resilient(
            &[
                WfpFilterAction::AddFilter(spec(1)),
                WfpFilterAction::AddFilter(spec(2)),
            ],
            FilterFailureMode::BestEffort,
        );
        match result {
            Err(e) => assert!(
                e.is_sublayer_registration_failure(),
                "the sub-layer error itself must surface, got {e:?}"
            ),
            Ok(outcome) => panic!(
                "sub-layer failure must abort, got phantom success (skipped={:?})",
                outcome.skipped
            ),
        }
        // Nothing may be counted as installed.
        assert!(api.wfp_filters.lock().unwrap().is_empty());
    }

    /// The counterpart: the SAME Win32 code from the filter-add itself is a
    /// genuine duplicate → idempotent success, not an abort and not a skip.
    #[test]
    fn duplicate_filter_add_is_still_idempotent_success() {
        use crate::error::win32_codes::FWP_E_ALREADY_EXISTS;
        let api = mock_api();
        api.set_fail_add_win32(&[2], "FwpmFilterAdd0", FWP_E_ALREADY_EXISTS);
        let s = session(&api);
        let outcome = s
            .execute_wfp_plan_resilient(
                &[
                    WfpFilterAction::AddFilter(spec(1)),
                    WfpFilterAction::AddFilter(spec(2)),
                    WfpFilterAction::AddFilter(spec(3)),
                ],
                FilterFailureMode::BestEffort,
            )
            .expect("duplicate filter add must not abort");
        // 1 and 3 really added; 2 "already present" — success, NOT a skip.
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 2);
        assert!(outcome.skipped.is_empty());
    }

    #[test]
    fn batch_splitting_for_large_plan() {
        let api = mock_api();
        let s = session(&api);
        let n = MAX_FILTERS_PER_TRANSACTION + 10;
        let actions: Vec<WfpFilterAction> = (0..n as u64)
            .map(|i| WfpFilterAction::AddFilter(spec(i)))
            .collect();
        s.execute_wfp_plan(&actions).unwrap();
        assert_eq!(api.wfp_filters.lock().unwrap().len(), n);
    }

    // ── cleanup_all ───────────────────────────────────────────────────────────

    #[test]
    fn cleanup_all_removes_all_our_filters() {
        let api = mock_api();
        let s = session(&api);
        for i in 0..5u64 {
            s.execute_wfp_plan(&[WfpFilterAction::AddFilter(spec(i))])
                .unwrap();
        }
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 5);

        let deleted = s.cleanup_all().unwrap();
        assert_eq!(deleted, 5);
        assert!(api.wfp_filters.lock().unwrap().is_empty());
    }

    #[test]
    fn cleanup_all_on_empty_session_returns_zero() {
        let api = mock_api();
        let s = session(&api);
        assert_eq!(s.cleanup_all().unwrap(), 0);
    }

    // ── cleanup_blocks_only ───────────────────────────────────────────────────

    fn permit_spec(id_raw: u64) -> WfpFilterSpec {
        WfpFilterSpec {
            action: WfpAction::Permit,
            ..spec(id_raw)
        }
    }

    #[test]
    fn cleanup_blocks_only_removes_blocks_and_keeps_permits() {
        let api = mock_api();
        let s = session(&api);
        // Two block filters (kill-switch / fail-closed) + one permit filter.
        s.execute_wfp_plan(&[
            WfpFilterAction::AddFilter(spec(1)),
            WfpFilterAction::AddFilter(permit_spec(2)),
            WfpFilterAction::AddFilter(spec(3)),
        ])
        .unwrap();
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 3);

        let removed = s.cleanup_blocks_only().unwrap();
        assert_eq!(removed, 2, "only the two block filters must be deleted");

        let remaining = api.wfp_filters.lock().unwrap().clone();
        assert_eq!(remaining.len(), 1, "the permit filter must survive");
        assert_eq!(remaining[0].action, WfpAction::Permit);
        assert_eq!(remaining[0].id, WfpFilterId { raw: 2 });
    }

    #[test]
    fn cleanup_blocks_only_with_no_blocks_returns_zero_and_keeps_permits() {
        let api = mock_api();
        let s = session(&api);
        s.execute_wfp_plan(&[WfpFilterAction::AddFilter(permit_spec(7))])
            .unwrap();
        assert_eq!(s.cleanup_blocks_only().unwrap(), 0);
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 1);
    }

    // ── Per-user (FWPM_CONDITION_ALE_USER_ID) ─────────────────────────

    #[test]
    fn execute_plan_preserves_user_sid_in_added_filter_records() {
        let api = mock_api();
        let s = session(&api);
        let mut spec_a = spec(1);
        spec_a.user_sid = Some("S-1-5-21-A".into());
        let mut spec_b = spec(2);
        spec_b.user_sid = Some("S-1-5-21-B".into());
        let spec_global = spec(3);
        s.execute_wfp_plan(&[
            WfpFilterAction::AddFilter(spec_a),
            WfpFilterAction::AddFilter(spec_b),
            WfpFilterAction::AddFilter(spec_global),
        ])
        .unwrap();
        let filters = api.wfp_filters.lock().unwrap().clone();
        assert_eq!(filters.len(), 3);
        let sids: Vec<Option<&str>> = filters.iter().map(|f| f.user_sid.as_deref()).collect();
        assert_eq!(sids, vec![Some("S-1-5-21-A"), Some("S-1-5-21-B"), None]);
    }

    #[test]
    fn cleanup_all_removes_per_sid_and_global_filters_alike() {
        // The provider-GUID enumeration treats per-user and system-wide
        // filters uniformly — both are "ours" and both should be
        // removed by cleanup_all on graceful stop, so a service restart
        // leaves no orphan per-user filters.
        let api = mock_api();
        let s = session(&api);
        let mut spec_a = spec(10);
        spec_a.user_sid = Some("S-1-5-21-A".into());
        let mut spec_b = spec(11);
        spec_b.user_sid = Some("S-1-5-21-B".into());
        let spec_global = spec(12);
        s.execute_wfp_plan(&[
            WfpFilterAction::AddFilter(spec_a),
            WfpFilterAction::AddFilter(spec_b),
            WfpFilterAction::AddFilter(spec_global),
        ])
        .unwrap();
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 3);
        let removed = s.cleanup_all().unwrap();
        assert_eq!(removed, 3);
        assert!(api.wfp_filters.lock().unwrap().is_empty());
    }
}
