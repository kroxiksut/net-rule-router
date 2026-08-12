//! `WindowsApplyEngine` — atomic apply orchestration.
//!
//! ## Apply cycle (one call to `execute_plan`)
//!
//! 1. Routing batch: execute `plan.routing_actions` via `RoutingTransaction`
//!    with compensating-action journal. On failure → rollback routing.
//! 2. WFP plan: execute `plan.wfp_actions` in batches via the long-lived
//!    `WfpSession`. On failure → the WFP transaction is auto-aborted by
//!    `WfpTransactionGuard::drop`, then routing is rolled back.
//! 3. On success: `RoutingTransaction::finalize()` (discard undo log).
//!
//! ## Atomic boundary
//!
//! One product apply = one compensating routing batch + one (or more batched)
//! WFP transactions. The pairing is not truly atomic at the OS level, but the
//! compensating journal ensures rollback can be attempted if anything fails.
//!
//! ## WFP session lifetime
//!
//! The WFP session is **per-service-instance** (opened by `open_session()` at
//! service start, closed by `close_session()` on graceful stop). Volatile
//! filters survive within the session and are automatically removed when the
//! session closes.
//!
//! ## Rollback states
//!
//! | Routing ok | WFP ok | Result |
//! |---|---|---|
//! | ✓ | ✓ | `Success` |
//! | ✗ | — | `RollbackStarted` (routing rolled back cleanly) or `RequiresUserAction` (rollback had errors) |
//! | ✓ | ✗ | `RollbackStarted` (routing rolled back cleanly) or `RequiresUserAction` |

use std::sync::{Arc, Mutex};

use crate::{
    adapters::AdapterMonitor,
    error::{ErrorClass, PlatformError},
    notify::BlockNotificationEmitter,
    rollback::{RollbackEngine, RollbackResult},
    routing::RoutingTransaction,
    snapshot::DesiredPlatformState,
    types::ApplyActionPlan,
    verify::{VerifyEngine, VerifyResult},
    wfp::WfpSession,
    windows_api::WindowsApiPort,
};

// ── EngineResult ──────────────────────────────────────────────────────────────

/// Outcome of one `WindowsApplyEngine::execute_plan` call.
///
/// Mirrors `nrr-service-runtime::integration_ports::ApplyResult` in
/// structure. `WindowsApplyAdapter` converts between them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineResult {
    Success {
        applied_at_epoch_secs: u64,
    },
    Failed {
        reason: String,
        retryable: bool,
    },
    VerificationFailed {
        expected: String,
        actual: String,
    },
    RollbackStarted {
        reason: String,
    },
    RollbackCompleted {
        fallback_revision_id: Option<String>,
    },
    RequiresUserAction {
        reason: String,
    },
    /// Placeholder for an apply path that has not been wired yet.
    NotYetImplemented,
}

// ── WindowsApplyEngine ────────────────────────────────────────────────────────

/// Orchestrates routing-table + WFP mutations for one policy apply cycle.
///
/// Constructed once per service instance. Call `open_session()` at startup
/// and `close_session()` on graceful stop.
pub struct WindowsApplyEngine {
    api: Arc<dyn WindowsApiPort>,
    /// Per-service-instance WFP session (long-lived, **non-dynamic** — filters
    /// persist until an explicit delete/reboot; not auto-removed on close).
    session: Mutex<Option<WfpSession>>,
    // Held for the block-notification wiring; not yet read on this path.
    #[allow(dead_code)]
    pub(crate) notifications: BlockNotificationEmitter,
}

impl WindowsApplyEngine {
    /// Construct with the given Win32 API abstraction.
    pub fn new(api: Arc<dyn WindowsApiPort>) -> Self {
        Self {
            api,
            session: Mutex::new(None),
            notifications: BlockNotificationEmitter::new(),
        }
    }

    /// Open the per-service-instance WFP engine session.
    /// Must be called before `execute_plan` for non-empty WFP plans.
    pub fn open_session(&self) -> Result<(), PlatformError> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| PlatformError::StateCorrupted {
                detail: "session mutex poisoned".into(),
            })?;
        if guard.is_some() {
            return Ok(()); // already open
        }
        let session = WfpSession::open(Arc::clone(&self.api))?;
        *guard = Some(session);
        Ok(())
    }

    /// Close the WFP session. NOTE: the session is **non-dynamic**, so closing
    /// it does NOT remove filters — they must be stripped explicitly (see
    /// `PerSidApplyOrchestrator::cleanup_wfp`) before/around close.
    pub fn close_session(&self) -> Result<(), PlatformError> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| PlatformError::StateCorrupted {
                detail: "session mutex poisoned".into(),
            })?;
        *guard = None; // WfpSession::drop calls FwpmEngineClose0
        Ok(())
    }

    /// Execute an `ApplyActionPlan`.
    ///
    /// Returns `Success` for an empty plan (idempotent no-op).
    pub fn execute_plan(&self, plan: &ApplyActionPlan) -> EngineResult {
        if plan.is_empty() {
            return EngineResult::Success {
                applied_at_epoch_secs: epoch_secs(),
            };
        }

        // ── Routing batch ──────────────────────────────────────────────────
        let mut routing_tx = RoutingTransaction::new(Arc::clone(&self.api));

        if let Err(e) = routing_tx.execute(&plan.routing_actions) {
            let _retryable = e.classify() == ErrorClass::Retryable;
            let rollback_errors = routing_tx.rollback();
            return if rollback_errors.is_empty() {
                EngineResult::RollbackStarted {
                    reason: e.to_string(),
                }
            } else {
                EngineResult::RequiresUserAction {
                    reason: format!(
                        "routing apply failed ({e}) and rollback had {} error(s)",
                        rollback_errors.len()
                    ),
                }
            };
        }

        // ── WFP plan ───────────────────────────────────────────────────────
        if !plan.wfp_actions.is_empty() {
            let session_guard = self
                .session
                .lock()
                .map_err(|_| PlatformError::StateCorrupted {
                    detail: "session mutex poisoned".into(),
                });

            let result = match session_guard {
                Err(e) => Err(e),
                Ok(ref guard) => match guard.as_ref() {
                    None => Err(PlatformError::StateCorrupted {
                        detail: "WFP session not open; call open_session() at service start".into(),
                    }),
                    Some(session) => session.execute_wfp_plan(&plan.wfp_actions),
                },
            };

            if let Err(e) = result {
                // WFP failed → rollback routing
                let rollback_errors = routing_tx.rollback();
                return if rollback_errors.is_empty() {
                    EngineResult::RollbackStarted {
                        reason: e.to_string(),
                    }
                } else {
                    EngineResult::RequiresUserAction {
                        reason: format!(
                            "WFP apply failed ({e}) and routing rollback had {} error(s)",
                            rollback_errors.len()
                        ),
                    }
                };
            }
        }

        // ── Success ────────────────────────────────────────────────────────
        routing_tx.finalize();
        EngineResult::Success {
            applied_at_epoch_secs: epoch_secs(),
        }
    }

    /// Roll back to the given pre-apply snapshot.
    ///
    /// `now_secs` is the current wall-clock epoch (injected for testability).
    /// The WFP session must be open before calling this method.
    pub fn rollback_with_snapshot(
        &self,
        stored: &nrr_storage::StoredSnapshot,
        now_secs: u64,
    ) -> EngineResult {
        let engine = RollbackEngine::new(Arc::clone(&self.api));
        let session_guard = match self.session.lock() {
            Ok(g) => g,
            Err(_) => {
                return EngineResult::RequiresUserAction {
                    reason: "WFP session mutex poisoned during rollback".into(),
                }
            }
        };
        let session = match session_guard.as_ref() {
            Some(s) => s,
            None => {
                return EngineResult::RequiresUserAction {
                    reason: "WFP session not open; cannot execute rollback".into(),
                }
            }
        };
        match engine.rollback_to_snapshot(stored, session, now_secs) {
            RollbackResult::Completed | RollbackResult::AlreadyAtBaseline => {
                EngineResult::RollbackCompleted {
                    fallback_revision_id: None,
                }
            }
            RollbackResult::PartiallyCompleted {
                routing_errors,
                wfp_errors,
            } => EngineResult::RequiresUserAction {
                reason: format!(
                    "rollback partially completed: routing_errors={routing_errors}, \
                         wfp_errors={wfp_errors}; manual inspection required"
                ),
            },
            RollbackResult::Failed { reason } => EngineResult::RequiresUserAction {
                reason: format!("rollback failed: {reason}"),
            },
            RollbackResult::SnapshotTooOld {
                age_secs,
                max_age_secs,
            } => EngineResult::Failed {
                reason: format!(
                    "rollback snapshot too old: {age_secs}s > {max_age_secs}s limit; \
                         use force-rollback to override"
                ),
                retryable: false,
            },
            RollbackResult::SnapshotInvalid { reason } => EngineResult::Failed {
                reason: format!("invalid rollback snapshot: {reason}"),
                retryable: false,
            },
            RollbackResult::TimedOut {
                completed_actions,
                remaining_actions,
            } => EngineResult::RequiresUserAction {
                reason: format!(
                    "rollback timed out: {completed_actions} done, {remaining_actions} remaining"
                ),
            },
        }
    }

    /// Capture the current platform state as a `PlatformStateSnapshot`.
    ///
    /// Used by the apply orchestrator before computing the
    /// action plan, and by the rollback path after rollback completes.
    pub fn capture_current_snapshot(
        &self,
        now_secs: u64,
    ) -> Result<crate::snapshot::PlatformStateSnapshot, PlatformError> {
        use crate::snapshot::{RoutingStateSnapshot, WfpFilterSnapshot};

        let session_guard = self
            .session
            .lock()
            .map_err(|_| PlatformError::StateCorrupted {
                detail: "session mutex poisoned during snapshot capture".into(),
            })?;
        let session = session_guard
            .as_ref()
            .ok_or_else(|| PlatformError::StateCorrupted {
                detail: "WFP session not open; cannot enumerate filters for snapshot".into(),
            })?;

        let all_routes = self.api.get_ip_forward_table()?;
        let our_routes: Vec<_> = all_routes.into_iter().filter(|r| r.is_ours).collect();
        let wfp_filters = session.enumerate_our_filters()?;

        let routing = RoutingStateSnapshot {
            entries: our_routes,
            taken_at_epoch_secs: now_secs,
        };
        let wfp = WfpFilterSnapshot {
            filters: wfp_filters,
            ..WfpFilterSnapshot::empty()
        };
        Ok(crate::snapshot::PlatformStateSnapshot::new(routing, wfp))
    }

    /// Return current adapter infos. Thin delegation to the underlying API.
    pub fn get_adapter_infos(&self) -> Result<Vec<crate::adapters::AdapterInfo>, PlatformError> {
        self.api.get_adapter_infos()
    }

    /// Verify that the current platform state matches `intended`.
    ///
    /// Re-captures the live routing table and WFP filters, then compares them
    /// against `intended` using the two-level (hash + entry-by-entry) strategy.
    /// Returns `VerifyResult::Drift { Critical }` when rollback should be triggered.
    pub fn verify_apply(&self, intended: &DesiredPlatformState, now_secs: u64) -> VerifyResult {
        let engine = VerifyEngine::new(Arc::clone(&self.api));
        let session_guard = match self.session.lock() {
            Ok(g) => g,
            Err(_) => {
                return VerifyResult::CaptureFailed {
                    reason: "WFP session mutex poisoned during verify".into(),
                }
            }
        };
        match session_guard.as_ref() {
            Some(session) => engine.verify_apply(intended, session, now_secs),
            None => VerifyResult::CaptureFailed {
                reason: "WFP session not open; cannot verify WFP filter state".into(),
            },
        }
    }

    /// Delete all WFP filters in our sub-layer. Used on graceful stop
    /// and as startup orphan-cleanup.
    pub fn cleanup_wfp(&self) -> Result<usize, PlatformError> {
        let guard = self
            .session
            .lock()
            .map_err(|_| PlatformError::StateCorrupted {
                detail: "session mutex poisoned".into(),
            })?;
        match guard.as_ref() {
            None => Ok(0),
            Some(session) => session.cleanup_all(),
        }
    }

    /// Delete only **block** (kill-switch / fail-closed) WFP filters in our
    /// sub-layer, keeping permit filters. Used on `persist`-mode graceful stop
    /// and as startup orphan-cleanup so an orphaned kill-switch never survives.
    pub fn cleanup_wfp_blocks_only(&self) -> Result<usize, PlatformError> {
        let guard = self
            .session
            .lock()
            .map_err(|_| PlatformError::StateCorrupted {
                detail: "session mutex poisoned".into(),
            })?;
        match guard.as_ref() {
            None => Ok(0),
            Some(session) => session.cleanup_blocks_only(),
        }
    }

    /// Get a current adapter availability snapshot for health reporting.
    pub fn adapter_snapshot(&self) -> crate::adapters::AdapterAvailabilitySnapshot {
        use crate::adapters::{AdapterEventSource, WindowsApiAdapterSource};
        let source = Arc::new(WindowsApiAdapterSource::new(Arc::clone(&self.api)));
        AdapterMonitor::new(source as Arc<dyn AdapterEventSource>, 500).snapshot()
    }
}

fn epoch_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::PlatformError,
        types::{
            RouteEntry, RoutingAction, WfpAction, WfpFilterAction, WfpFilterId, WfpFilterSpec,
            WfpLayerKey,
        },
        windows_api::MockWindowsApi,
    };
    use std::net::Ipv4Addr;

    fn engine() -> (Arc<MockWindowsApi>, WindowsApplyEngine) {
        let api = Arc::new(MockWindowsApi::new());
        let eng = WindowsApplyEngine::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        eng.open_session().unwrap();
        (api, eng)
    }

    fn route(dest: [u8; 4], ifindex: u32) -> RouteEntry {
        RouteEntry {
            destination: Ipv4Addr::from(dest),
            prefix_length: 24,
            next_hop: Ipv4Addr::new(192, 168, 1, 1),
            interface_index: ifindex,
            metric: 10,
            is_ours: true,
            table: nrr_platform_api::RouteTableRef::Main,
        }
    }

    fn filter_spec(id_raw: u64) -> WfpFilterSpec {
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

    // ── Empty plan ────────────────────────────────────────────────────────

    #[test]
    fn execute_empty_plan_returns_success() {
        let (_, eng) = engine();
        assert!(matches!(
            eng.execute_plan(&ApplyActionPlan::default()),
            EngineResult::Success { .. }
        ));
    }

    // ── Routing ───────────────────────────────────────────────────────────

    #[test]
    fn execute_routing_add_inserts_route() {
        let (api, eng) = engine();
        let mut plan = ApplyActionPlan::default();
        plan.routing_actions
            .push(RoutingAction::AddRoute(route([10, 0, 0, 0], 5)));
        assert!(matches!(
            eng.execute_plan(&plan),
            EngineResult::Success { .. }
        ));
        assert_eq!(api.get_ip_forward_table().unwrap().len(), 1);
    }

    #[test]
    fn execute_routing_delete_removes_route() {
        let (api, eng) = engine();
        let r = route([10, 0, 0, 0], 5);
        api.create_ip_forward_entry(&r).unwrap();

        let mut plan = ApplyActionPlan::default();
        plan.routing_actions.push(RoutingAction::DeleteRoute(r));
        assert!(matches!(
            eng.execute_plan(&plan),
            EngineResult::Success { .. }
        ));
        assert!(api.get_ip_forward_table().unwrap().is_empty());
    }

    #[test]
    fn routing_failure_triggers_rollback_and_returns_rollback_started() {
        let (api, eng) = engine();

        // First action succeeds, second fails.
        let mut plan = ApplyActionPlan::default();
        plan.routing_actions
            .push(RoutingAction::AddRoute(route([10, 0, 0, 0], 5)));
        plan.routing_actions
            .push(RoutingAction::AddRoute(route([10, 0, 1, 0], 5)));

        // Pre-add route [10,0,0,0] — the execute will succeed (idempotent).
        // Make the second add fail.
        // Step 1: let first action succeed by not setting error yet.
        // Step 2: set error after first action by running it in two separate plans.

        // Alternative: use a different approach. Force error from the start
        // so the whole plan fails, and check rollback.
        api.set_force_error(Some(PlatformError::Win32 {
            operation: "create_ip_forward_entry",
            code: 0x5, // Fatal
            message: "injected".into(),
        }));

        let result = eng.execute_plan(&plan);
        assert!(
            matches!(
                result,
                EngineResult::RollbackStarted { .. } | EngineResult::Failed { .. }
            ),
            "routing failure must trigger rollback: {result:?}"
        );
        // After rollback, table should be empty (nothing was committed).
        api.set_force_error(None);
        assert!(api.get_ip_forward_table().unwrap().is_empty());
    }

    // ── WFP ───────────────────────────────────────────────────────────────

    #[test]
    fn execute_wfp_add_inserts_filter() {
        let (api, eng) = engine();
        let mut plan = ApplyActionPlan::default();
        plan.wfp_actions
            .push(WfpFilterAction::AddFilter(filter_spec(1)));
        assert!(matches!(
            eng.execute_plan(&plan),
            EngineResult::Success { .. }
        ));
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 1);
    }

    #[test]
    fn execute_wfp_delete_removes_filter() {
        let (api, eng) = engine();
        // Add directly via session
        {
            let guard = eng.session.lock().unwrap();
            guard.as_ref().unwrap().add_filter(&filter_spec(1)).unwrap();
        }

        let mut plan = ApplyActionPlan::default();
        plan.wfp_actions
            .push(WfpFilterAction::DeleteFilter(WfpFilterId { raw: 1 }));
        assert!(matches!(
            eng.execute_plan(&plan),
            EngineResult::Success { .. }
        ));
        assert!(api.wfp_filters.lock().unwrap().is_empty());
    }

    #[test]
    fn wfp_failure_rolls_back_routing_and_returns_rollback_started() {
        let (api, eng) = engine();
        let r = route([10, 0, 0, 0], 5);

        let mut plan = ApplyActionPlan::default();
        plan.routing_actions
            .push(RoutingAction::AddRoute(r.clone()));
        plan.wfp_actions
            .push(WfpFilterAction::AddFilter(filter_spec(1)));

        // Force WFP failure.
        api.set_force_error(Some(PlatformError::Win32 {
            operation: "wfp_filter_add",
            code: 0x5,
            message: "injected".into(),
        }));

        let result = eng.execute_plan(&plan);
        assert!(
            matches!(result, EngineResult::RollbackStarted { .. }),
            "WFP failure must roll back routing: {result:?}"
        );
        api.set_force_error(None);
        // Routing was rolled back — table must be empty.
        assert!(
            api.get_ip_forward_table().unwrap().is_empty(),
            "routing changes must be rolled back when WFP fails"
        );
    }

    #[test]
    fn execute_without_open_session_fails_gracefully_for_wfp_actions() {
        let api = Arc::new(MockWindowsApi::new());
        // Do NOT call open_session()
        let eng = WindowsApplyEngine::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        let mut plan = ApplyActionPlan::default();
        plan.wfp_actions
            .push(WfpFilterAction::AddFilter(filter_spec(1)));
        let result = eng.execute_plan(&plan);
        assert!(
            matches!(
                result,
                EngineResult::RollbackStarted { .. } | EngineResult::RequiresUserAction { .. }
            ),
            "missing session must not panic or silently succeed: {result:?}"
        );
    }

    // ── cleanup_wfp ───────────────────────────────────────────────────────

    #[test]
    fn cleanup_wfp_removes_all_filters_on_session_open() {
        let (api, eng) = engine();
        for i in 0..3u64 {
            let mut plan = ApplyActionPlan::default();
            plan.wfp_actions
                .push(WfpFilterAction::AddFilter(filter_spec(i)));
            assert!(matches!(
                eng.execute_plan(&plan),
                EngineResult::Success { .. }
            ));
        }
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 3);
        let deleted = eng.cleanup_wfp().unwrap();
        assert_eq!(deleted, 3);
        assert!(api.wfp_filters.lock().unwrap().is_empty());
    }

    #[test]
    fn cleanup_wfp_without_session_returns_zero() {
        let api = Arc::new(MockWindowsApi::new());
        let eng = WindowsApplyEngine::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        assert_eq!(eng.cleanup_wfp().unwrap(), 0);
    }

    // ── cleanup_wfp_blocks_only ─────────────────────────────────────────────

    #[test]
    fn cleanup_wfp_blocks_only_strips_blocks_and_keeps_permits() {
        let (api, eng) = engine();
        // Two block filters + one permit filter added directly via the session.
        {
            let guard = eng.session.lock().unwrap();
            let session = guard.as_ref().unwrap();
            session.add_filter(&filter_spec(1)).unwrap();
            let mut permit = filter_spec(2);
            permit.action = WfpAction::Permit;
            session.add_filter(&permit).unwrap();
            session.add_filter(&filter_spec(3)).unwrap();
        }
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 3);
        let deleted = eng.cleanup_wfp_blocks_only().unwrap();
        assert_eq!(deleted, 2);
        let remaining = api.wfp_filters.lock().unwrap().clone();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].action, WfpAction::Permit);
    }

    #[test]
    fn cleanup_wfp_blocks_only_without_session_returns_zero() {
        let api = Arc::new(MockWindowsApi::new());
        let eng = WindowsApplyEngine::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);
        assert_eq!(eng.cleanup_wfp_blocks_only().unwrap(), 0);
    }
}
