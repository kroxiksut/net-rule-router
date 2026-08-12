//! `RoutingPauseCoordinator` ties together the persistent pause state
//! (`RoutingPauseStateRepository`) with the per-SID apply layer
//! (`PerSidApplyOrchestrator`).
//!
//! ## Why a coordinator
//!
//! Pause has two effects:
//! 1. **Storage** — set/clear `routing_pause_state.paused`.
//! 2. **Platform** — install or remove the SID's WFP filters so the
//!    pause is observable on the next packet.
//!
//! These two effects must move together but the orchestrator and the
//! storage layer have no other reason to know about each other. This
//! module is the join.
//!
//! ## Concurrency
//!
//! - Storage writes hold the connection mutex briefly.
//! - The platform call is synchronous; on `pause` the dispatcher's
//!   `remove_for_sid` runs OUTSIDE the connection mutex (we drop the
//!   guard before calling the dispatcher).
//! - Concurrent `pause` and `resume` for the same SID serialise via the
//!   IPC `MutationQueue` (block 14) — this coordinator does not add a
//!   second lock.
//!
//! ## M-1 awareness
//!
//! `resume` only triggers the dispatcher's `install_for_sid` if the SID
//! is currently routing-active in [`ActiveSidRegistry`] (i.e. has a
//! tray connection). Otherwise the pause flag is cleared in storage and
//! the next tray connect will install via the standard listener flow.

use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use nrr_storage::pause_state::RoutingPauseStateRepository;

use crate::activation_coordinator::Clock;
use crate::active_sid_registry::{ActiveSidRegistry, ActiveSidsListener};

// ── Errors ────────────────────────────────────────────────────────────────────

/// Things that can go wrong inside the pause coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PauseError {
    Storage {
        operation: &'static str,
        message: String,
    },
    Dispatch {
        operation: &'static str,
        sid: String,
        message: String,
    },
    EmptySid,
}

// ── Audit ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoutingPauseAuditEvent {
    /// User explicitly paused routing for `sid`.
    Paused {
        sid: String,
        reason: Option<String>,
        at_secs: i64,
    },
    /// User explicitly resumed routing for `sid`.
    Resumed { sid: String, at_secs: i64 },
    /// Tray for `sid` connected but the persistent pause flag was set,
    /// so the orchestrator was NOT invoked. Audit only — no state
    /// change.
    PausedOnTrayConnect {
        sid: String,
        paused_at_secs: Option<i64>,
        observed_at_secs: i64,
    },
}

pub trait RoutingPauseAudit: Send + Sync {
    fn emit(&self, event: RoutingPauseAuditEvent);
}

/// Drops every event. Test default.
pub struct NoopRoutingPauseAudit;

impl RoutingPauseAudit for NoopRoutingPauseAudit {
    fn emit(&self, _event: RoutingPauseAuditEvent) {}
}

// ── Dispatcher trait ──────────────────────────────────────────────────────────

/// Bridge from the pause coordinator to the per-SID apply layer.
/// Production impl wraps `PerSidApplyOrchestrator`; tests use a
/// scriptable mock.
pub trait PauseDispatcher: Send + Sync {
    /// Apply the SID's current per-user policy to the platform layer
    /// (install WFP filters). Idempotent — calling install on an
    /// already-installed SID succeeds.
    fn install_for_sid(&self, sid: &str) -> Result<(), String>;

    /// Withdraw the SID's WFP filters. Idempotent — calling remove on
    /// an already-removed SID succeeds.
    fn remove_for_sid(&self, sid: &str) -> Result<(), String>;
}

// ── Coordinator ───────────────────────────────────────────────────────────────

pub struct RoutingPauseCoordinator {
    conn: Arc<Mutex<Connection>>,
    registry: Arc<ActiveSidRegistry>,
    dispatcher: Arc<dyn PauseDispatcher>,
    audit: Arc<dyn RoutingPauseAudit>,
    clock: Arc<dyn Clock>,
    /// Safe-disable (ROUTE-half) — optional handle to the secondary-route
    /// coordinator. When present, pausing the effective routing user also tears
    /// down the single-owner route table (not just its WFP filters), and
    /// resuming recomputes it. `None` (the default / most tests) keeps the
    /// pre-ROUTE-half behaviour: WFP-only. Held one-directionally — the route
    /// coordinator reads the pause flag from storage, so there is no Arc cycle.
    route_coord: Option<Arc<crate::route_coordinator::SecondaryRouteCoordinator>>,
}

// State is `Mutex`-guarded; `lock().expect(...)` propagates poisoning (a prior
// panic) as a panic — deliberate, not a recoverable error path.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl RoutingPauseCoordinator {
    pub fn new(
        conn: Arc<Mutex<Connection>>,
        registry: Arc<ActiveSidRegistry>,
        dispatcher: Arc<dyn PauseDispatcher>,
        audit: Arc<dyn RoutingPauseAudit>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            conn,
            registry,
            dispatcher,
            audit,
            clock,
            route_coord: None,
        }
    }

    /// Attaches the secondary-route coordinator (safe-disable ROUTE-half).
    /// Without it, `pause` / `resume` / `pause_all_active` only move WFP filters;
    /// with it, pausing the effective routing user also tears the route table
    /// down and resume restores it. Wired in `runtime_deps` after the route
    /// coordinator is built (one-directional — no Arc cycle).
    pub fn with_route_coordinator(
        mut self,
        coord: Arc<crate::route_coordinator::SecondaryRouteCoordinator>,
    ) -> Self {
        self.route_coord = Some(coord);
        self
    }

    /// `true` when `sid` is the user the route table is actually built for — the
    /// coordinator's effective routing SID (the first connected-tray SID, or the
    /// console user under service-driven scope with no tray). Always `false`
    /// without a route coordinator. This — not `registry.is_active` alone — is
    /// what makes a no-tray console safe-disable tear down the console user's
    /// routes and filters.
    fn is_effective(&self, sid: &str) -> bool {
        self.route_coord
            .as_ref()
            .and_then(|c| c.effective_routing_sid(&self.registry.active_sids()))
            .as_deref()
            == Some(sid)
    }

    /// Tear down the single-owner route table for a pause (best-effort). The
    /// teardown *flavor* is read FRESH from `routing_stop_policy`:
    /// [`nrr_storage::service_stability_config::RoutingStopPolicy::Persist`]
    /// keeps the `/32` secondary rule-routes (matched hosts keep egressing the
    /// secondary) and removes only NRR's overlays; any other value does a full
    /// clear. A teardown error is logged, not propagated — mirrors the
    /// graceful-stop hook (routing is route-table based; a failure here can never
    /// lock the user out).
    fn teardown_routes(&self) {
        let Some(coord) = self.route_coord.as_ref() else {
            return;
        };
        let persist = {
            use nrr_storage::service_stability_config::{
                RoutingStopPolicy, ServiceStabilityConfigRepository,
            };
            let guard = self
                .conn
                .lock()
                .expect("teardown_routes connection mutex poisoned");
            matches!(
                ServiceStabilityConfigRepository::new(&guard)
                    .get_or_default()
                    .map(|r| r.routing_stop_policy),
                Ok(RoutingStopPolicy::Persist)
            )
        };
        let result = if persist {
            coord.teardown_keep_secondary_hosts()
        } else {
            coord.teardown()
        };
        match result {
            Ok(delta) => tracing::info!(
                target: "nrr::routing-pause",
                persist,
                removed = delta.removed,
                "routing paused — tore down secondary route table",
            ),
            Err(e) => tracing::warn!(
                target: "nrr::routing-pause",
                "routing-pause route teardown failed (best-effort): {e:?}",
            ),
        }
    }

    /// Pauses routing for `sid`. Persists the flag and (synchronously)
    /// removes the SID's filters via the dispatcher. Idempotent — a
    /// pause-while-paused succeeds and updates `pause_reason`.
    pub fn pause(&self, sid: &str, reason: Option<&str>) -> Result<(), PauseError> {
        if sid.is_empty() {
            return Err(PauseError::EmptySid);
        }
        let now = self.clock.now_secs();
        // Storage write first (durable record before platform mutation).
        {
            let conn = self.conn.lock().expect("pause connection mutex poisoned");
            RoutingPauseStateRepository::new(&conn)
                .set_paused(sid, true, reason, now)
                .map_err(|e| PauseError::Storage {
                    operation: "set_paused(true)",
                    message: e.to_string(),
                })?;
        }
        // Platform mutation outside the connection lock. Widened from
        // `is_active` alone to ALSO cover the effective routing SID: a no-tray
        // console user is not in the active registry, yet its filters and routes
        // are live and must come down. `remove_for_sid` is idempotent, so the
        // widened guard is safe even when no filters are installed.
        let effective = self.is_effective(sid);
        if self.registry.is_active(sid) || effective {
            self.dispatcher
                .remove_for_sid(sid)
                .map_err(|e| PauseError::Dispatch {
                    operation: "remove_for_sid",
                    sid: sid.to_string(),
                    message: e,
                })?;
        }
        // ROUTE-half — tear the single-owner route table for the effective
        // routing user. The WFP-only removal above left the `/32` host routes and
        // `/2` counter-overlays installed, so matched traffic kept egressing the
        // secondary until now.
        if effective {
            self.teardown_routes();
        }
        self.audit.emit(RoutingPauseAuditEvent::Paused {
            sid: sid.to_string(),
            reason: reason.map(String::from),
            at_secs: now,
        });
        Ok(())
    }

    /// Resumes routing for `sid`. Clears the persistent flag and, if
    /// the SID currently has a tray connection (M-1 routing-active),
    /// reinstalls filters immediately. If no tray is connected, the
    /// next `on_connect` will install via the registry's listener.
    pub fn resume(&self, sid: &str) -> Result<(), PauseError> {
        if sid.is_empty() {
            return Err(PauseError::EmptySid);
        }
        let now = self.clock.now_secs();
        {
            let conn = self.conn.lock().expect("resume connection mutex poisoned");
            RoutingPauseStateRepository::new(&conn)
                .set_paused(sid, false, None, now)
                .map_err(|e| PauseError::Storage {
                    operation: "set_paused(false)",
                    message: e.to_string(),
                })?;
        }
        let effective = self.is_effective(sid);
        if self.registry.is_active(sid) || effective {
            self.dispatcher
                .install_for_sid(sid)
                .map_err(|e| PauseError::Dispatch {
                    operation: "install_for_sid",
                    sid: sid.to_string(),
                    message: e,
                })?;
        }
        // ROUTE-half — the pause flag is already cleared in storage above, so a
        // recompute now RE-ADDS the effective user's routes (the recompute gate
        // sees "not paused"). Restores routing immediately instead of waiting for
        // the next background tick. Best-effort: a recompute error is logged by
        // the coordinator and must not fail the resume.
        if effective {
            if let Some(coord) = self.route_coord.as_ref() {
                let _ = coord.recompute_active(&self.registry.active_sids());
            }
        }
        self.audit.emit(RoutingPauseAuditEvent::Resumed {
            sid: sid.to_string(),
            at_secs: now,
        });
        Ok(())
    }

    /// pause routing for EVERY currently
    /// routing-active SID. Used by safe-disable ("suspend all product impact"):
    /// each active SID's WFP filters are removed and its pause flag persisted,
    /// so the routing-pause toggle's `resume` reinstalls them. Returns the SIDs
    /// that were paused. Every SID is attempted even if one errs (all impact
    /// should come down); the FIRST error is surfaced so the caller reports the
    /// teardown as incomplete rather than claiming success.
    pub fn pause_all_active(&self, reason: Option<&str>) -> Result<Vec<String>, PauseError> {
        // The SID set is every routing-active (tray-connected) SID PLUS the
        // effective routing SID (the console user under service-driven scope with
        // NO tray), deduped. Without the effective SID a no-tray safe-disable
        // would iterate an EMPTY active set, pause nothing, and falsely report "0
        // suspended" while the console user's routes and filters stayed live.
        let mut sids = self.registry.active_sids();
        if let Some(coord) = self.route_coord.as_ref() {
            if let Some(eff) = coord.effective_routing_sid(&sids) {
                if !sids.iter().any(|s| s == &eff) {
                    sids.push(eff);
                }
            }
        }
        let mut paused = Vec::new();
        let mut first_err: Option<PauseError> = None;
        for sid in sids {
            match self.pause(&sid, reason) {
                Ok(()) => paused.push(sid),
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(paused),
        }
    }

    /// Reads the persistent pause flag. Defaults to `false` for unknown
    /// SIDs (M-1 default state).
    pub fn is_paused(&self, sid: &str) -> Result<bool, PauseError> {
        if sid.is_empty() {
            return Err(PauseError::EmptySid);
        }
        let conn = self
            .conn
            .lock()
            .expect("is_paused connection mutex poisoned");
        RoutingPauseStateRepository::new(&conn)
            .is_paused(sid)
            .map_err(|e| PauseError::Storage {
                operation: "is_paused",
                message: e.to_string(),
            })
    }

    /// Snapshot of every SID currently flagged paused. Startup logic uses
    /// this to skip recompile on tray reconnect for paused users.
    pub fn paused_sids(&self) -> Result<Vec<String>, PauseError> {
        let conn = self
            .conn
            .lock()
            .expect("paused_sids connection mutex poisoned");
        RoutingPauseStateRepository::new(&conn)
            .list_paused()
            .map_err(|e| PauseError::Storage {
                operation: "list_paused",
                message: e.to_string(),
            })
    }

    /// Builds a registry listener that subtracts the persistent paused
    /// set from the routing-active snapshot before invoking the
    /// dispatcher. The orchestrator wired through this listener
    /// receives only "tray-connected AND not paused" SIDs.
    ///
    /// Audit `PausedOnTrayConnect` is emitted for each SID that the
    /// tray connect would otherwise have installed.
    pub fn make_pause_aware_listener(self: Arc<Self>) -> ActiveSidsListener {
        Arc::new(move |snapshot: &[String]| {
            let paused = match self.paused_sids() {
                Ok(p) => p,
                Err(_) => return, // storage failure: fail-closed (don't touch platform)
            };
            for sid in snapshot {
                if paused.iter().any(|p| p == sid) {
                    let now = self.clock.now_secs();
                    let paused_at = match RoutingPauseStateRepository::new(
                        &self.conn.lock().expect("listener mutex"),
                    )
                    .get(sid)
                    {
                        Ok(Some(rec)) => rec.paused_at,
                        _ => None,
                    };
                    self.audit
                        .emit(RoutingPauseAuditEvent::PausedOnTrayConnect {
                            sid: sid.clone(),
                            paused_at_secs: paused_at,
                            observed_at_secs: now,
                        });
                    continue;
                }
                if let Err(e) = self.dispatcher.install_for_sid(sid) {
                    // Fail-loud only via audit; we do not want a single
                    // failed install to block other SIDs.
                    let _ = e; // production wiring will route this to operational logs
                }
            }
        })
    }
}

// ── Test fixtures ─────────────────────────────────────────────────────────────

/// Records every event for assertions.
pub struct RecordingPauseAudit {
    events: Mutex<Vec<RoutingPauseAuditEvent>>,
}

impl Default for RecordingPauseAudit {
    fn default() -> Self {
        Self::new()
    }
}

// Test double: lock-poisoning `expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl RecordingPauseAudit {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn snapshot(&self) -> Vec<RoutingPauseAuditEvent> {
        self.events.lock().expect("audit mutex poisoned").clone()
    }
}

// Test double: lock-poisoning `expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl RoutingPauseAudit for RecordingPauseAudit {
    fn emit(&self, event: RoutingPauseAuditEvent) {
        self.events
            .lock()
            .expect("audit mutex poisoned")
            .push(event);
    }
}

/// Scriptable dispatcher: queues per-call outcomes and records every
/// install/remove call.
pub struct ScriptedPauseDispatcher {
    install_log: Mutex<Vec<String>>,
    remove_log: Mutex<Vec<String>>,
    install_outcomes: Mutex<std::collections::BTreeMap<String, Vec<Result<(), String>>>>,
    remove_outcomes: Mutex<std::collections::BTreeMap<String, Vec<Result<(), String>>>>,
}

impl Default for ScriptedPauseDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

// Test double: lock-poisoning `expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl ScriptedPauseDispatcher {
    pub fn new() -> Self {
        Self {
            install_log: Mutex::new(Vec::new()),
            remove_log: Mutex::new(Vec::new()),
            install_outcomes: Mutex::new(std::collections::BTreeMap::new()),
            remove_outcomes: Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    pub fn install_log(&self) -> Vec<String> {
        self.install_log.lock().expect("dispatcher mutex").clone()
    }

    pub fn remove_log(&self) -> Vec<String> {
        self.remove_log.lock().expect("dispatcher mutex").clone()
    }

    pub fn queue_install(&self, sid: &str, outcome: Result<(), String>) {
        self.install_outcomes
            .lock()
            .expect("dispatcher mutex")
            .entry(sid.to_string())
            .or_default()
            .push(outcome);
    }
}

// Test double: lock-poisoning `expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl PauseDispatcher for ScriptedPauseDispatcher {
    fn install_for_sid(&self, sid: &str) -> Result<(), String> {
        self.install_log
            .lock()
            .expect("dispatcher mutex")
            .push(sid.to_string());
        let mut map = self.install_outcomes.lock().expect("dispatcher mutex");
        let queue = map.entry(sid.to_string()).or_default();
        if queue.is_empty() {
            Ok(())
        } else {
            queue.remove(0)
        }
    }

    fn remove_for_sid(&self, sid: &str) -> Result<(), String> {
        self.remove_log
            .lock()
            .expect("dispatcher mutex")
            .push(sid.to_string());
        let mut map = self.remove_outcomes.lock().expect("dispatcher mutex");
        let queue = map.entry(sid.to_string()).or_default();
        if queue.is_empty() {
            Ok(())
        } else {
            queue.remove(0)
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activation_coordinator::FixedClock;
    use crate::fqdn_cache_lookup::{FqdnCacheLookup, MockFqdnCacheLookup};
    use crate::per_sid_orchestrator::{
        ActiveRulesSnapshot, PerSidPolicySnapshot, RoutePolicySource, RulesProvider,
    };
    use crate::route_coordinator::{RuleScopeProvider, SecondaryRouteCoordinator};
    use nrr_platform_api::{MockWindowsApi, RouteEntry, WindowsApiPort};
    use nrr_shared::ipc::IpcClientProfile;
    use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
    use nrr_storage::repository::MigrationRunner;
    use std::net::Ipv4Addr;

    struct Fx {
        coord: Arc<RoutingPauseCoordinator>,
        registry: Arc<ActiveSidRegistry>,
        dispatcher: Arc<ScriptedPauseDispatcher>,
        audit: Arc<RecordingPauseAudit>,
        _dir: tempfile::TempDir,
    }

    fn build_fx() -> Fx {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("state.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let conn = Arc::new(Mutex::new(runner.into_connection()));

        let registry = Arc::new(ActiveSidRegistry::new());
        let dispatcher = Arc::new(ScriptedPauseDispatcher::new());
        let audit = Arc::new(RecordingPauseAudit::new());
        let clock = FixedClock::new(1_700_000_000);

        let coord = Arc::new(RoutingPauseCoordinator::new(
            conn,
            registry.clone(),
            dispatcher.clone() as Arc<dyn PauseDispatcher>,
            audit.clone() as Arc<dyn RoutingPauseAudit>,
            clock as Arc<dyn Clock>,
        ));
        Fx {
            coord,
            registry,
            dispatcher,
            audit,
            _dir: dir,
        }
    }

    #[test]
    fn pause_all_active_pauses_and_tears_down_every_active_sid() {
        // safe-disable path: every routing-active
        // SID is paused (persisted) and its filters removed via the dispatcher.
        let fx = build_fx();
        fx.registry
            .on_connect("S-A", IpcClientProfile::TrayLightweight);
        fx.registry
            .on_connect("S-B", IpcClientProfile::TrayLightweight);
        let paused = fx
            .coord
            .pause_all_active(Some("safe-disable"))
            .expect("pause_all_active");
        assert!(fx.coord.is_paused("S-A").expect("is_paused A"));
        assert!(fx.coord.is_paused("S-B").expect("is_paused B"));
        let mut removed = fx.dispatcher.remove_log();
        removed.sort();
        assert_eq!(removed, vec!["S-A".to_string(), "S-B".to_string()]);
        assert_eq!(paused.len(), 2);
    }

    #[test]
    fn pause_with_active_sid_persists_and_calls_remove() {
        let fx = build_fx();
        fx.registry
            .on_connect("S-A", IpcClientProfile::TrayLightweight);
        fx.coord.pause("S-A", Some("travel")).expect("pause");
        assert!(fx.coord.is_paused("S-A").expect("is_paused"));
        assert_eq!(fx.dispatcher.remove_log(), vec!["S-A".to_string()]);
        let events = fx.audit.snapshot();
        assert!(matches!(events[0], RoutingPauseAuditEvent::Paused { .. }));
    }

    #[test]
    fn pause_without_active_tray_persists_only() {
        let fx = build_fx();
        // No tray connection registered.
        fx.coord.pause("S-A", None).expect("pause");
        assert!(fx.coord.is_paused("S-A").expect("is_paused"));
        // Dispatcher was NOT called — SID is not routing-active.
        assert!(fx.dispatcher.remove_log().is_empty());
    }

    #[test]
    fn resume_with_active_sid_persists_and_calls_install() {
        let fx = build_fx();
        fx.registry
            .on_connect("S-A", IpcClientProfile::TrayLightweight);
        fx.coord.pause("S-A", None).expect("pause");
        fx.dispatcher.remove_log(); // drain to focus on resume

        fx.coord.resume("S-A").expect("resume");
        assert!(!fx.coord.is_paused("S-A").expect("is_paused"));
        assert_eq!(fx.dispatcher.install_log(), vec!["S-A".to_string()]);
    }

    #[test]
    fn resume_without_active_tray_persists_only() {
        let fx = build_fx();
        // Pause first via direct repo (no tray needed).
        fx.coord.pause("S-A", None).expect("pause");
        // Now resume without a tray connection.
        fx.coord.resume("S-A").expect("resume");
        assert!(!fx.coord.is_paused("S-A").expect("is_paused"));
        // Install was NOT called — next tray connect handles it.
        assert!(fx.dispatcher.install_log().is_empty());
    }

    #[test]
    fn pause_is_idempotent_under_repeated_calls() {
        let fx = build_fx();
        fx.registry
            .on_connect("S-A", IpcClientProfile::TrayLightweight);
        fx.coord.pause("S-A", None).expect("first");
        fx.coord
            .pause("S-A", Some("now-with-reason"))
            .expect("second");
        assert!(fx.coord.is_paused("S-A").expect("paused"));
        // Both calls reach the dispatcher (idempotent at platform layer).
        assert_eq!(fx.dispatcher.remove_log().len(), 2);
    }

    #[test]
    fn paused_sids_lists_only_paused_users() {
        let fx = build_fx();
        fx.coord.pause("S-A", None).expect("pause a");
        fx.coord.pause("S-B", None).expect("pause b");
        fx.coord.pause("S-C", None).expect("pause c");
        fx.coord.resume("S-B").expect("resume b");
        let mut paused = fx.coord.paused_sids().expect("list");
        paused.sort();
        assert_eq!(paused, vec!["S-A".to_string(), "S-C".to_string()]);
    }

    #[test]
    fn empty_sid_rejected_consistently() {
        let fx = build_fx();
        assert!(matches!(
            fx.coord.pause("", None),
            Err(PauseError::EmptySid)
        ));
        assert!(matches!(fx.coord.resume(""), Err(PauseError::EmptySid)));
        assert!(matches!(fx.coord.is_paused(""), Err(PauseError::EmptySid)));
    }

    // ── Pause-aware listener ──────────────────────────────────────────────────

    #[test]
    fn pause_aware_listener_skips_paused_and_emits_audit() {
        let fx = build_fx();
        // Pre-flag B as paused.
        fx.coord.pause("S-B", Some("offline")).expect("pause b");
        fx.dispatcher.install_log(); // drain (pause shouldn't have called install)

        // Build the listener and register it.
        let listener = Arc::clone(&fx.coord).make_pause_aware_listener();
        // Drive the listener with a snapshot containing both A and B.
        listener(&["S-A".to_string(), "S-B".to_string()]);

        let installs = fx.dispatcher.install_log();
        assert_eq!(installs, vec!["S-A".to_string()]);
        let events = fx.audit.snapshot();
        let saw_skip = events
            .iter()
            .any(|e| matches!(e, RoutingPauseAuditEvent::PausedOnTrayConnect { sid, .. } if sid == "S-B"));
        assert!(saw_skip, "must emit PausedOnTrayConnect for skipped SIDs");
    }

    #[test]
    fn pause_aware_listener_installs_all_when_none_paused() {
        let fx = build_fx();
        let listener = Arc::clone(&fx.coord).make_pause_aware_listener();
        listener(&["S-A".to_string(), "S-B".to_string()]);
        let installs = fx.dispatcher.install_log();
        assert_eq!(installs, vec!["S-A".to_string(), "S-B".to_string()]);
    }

    // (Cross-restart persistence is verified in
    // `nrr-storage::pause_state::tests::pause_state_persists_across_reopen`.)

    // ── ROUTE-half fixtures (safe-disable route teardown) ─────────────────────

    /// Route policy that binds nothing — every SID resolves to "no secondary"
    /// so a recompute clears the table. Enough to observe that a recompute ran.
    struct NoPolicy;
    impl RoutePolicySource for NoPolicy {
        fn load_for_sid(&self, _sid: &str) -> Option<PerSidPolicySnapshot> {
            None
        }
    }

    /// Rules provider that yields nothing (routing decisions are driven by the
    /// route policy above; this satisfies the coordinator's constructor).
    struct NoRules;
    impl RulesProvider for NoRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            None
        }
        fn active_rules_for(&self, _principal: &str) -> Option<ActiveRulesSnapshot> {
            None
        }
    }

    fn route_entry(dest: [u8; 4], prefix: u8, next_hop: [u8; 4], ifindex: u32) -> RouteEntry {
        RouteEntry {
            destination: Ipv4Addr::from(dest),
            prefix_length: prefix,
            next_hop: Ipv4Addr::from(next_hop),
            interface_index: ifindex,
            metric: 5,
            is_ours: true,
            table: nrr_platform_api::RouteTableRef::Main,
        }
    }

    /// Build a real `SecondaryRouteCoordinator` under service-driven scope over
    /// `api` (so `effective_routing_sid([])` resolves the console user).
    fn route_coord_service_driven(api: Arc<MockWindowsApi>) -> Arc<SecondaryRouteCoordinator> {
        Arc::new(SecondaryRouteCoordinator::new(
            api as Arc<dyn WindowsApiPort>,
            Arc::new(NoRules) as Arc<dyn RulesProvider>,
            Arc::new(NoPolicy) as Arc<dyn RoutePolicySource>,
            Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
            Arc::new(|| true) as RuleScopeProvider,
        ))
    }

    struct RouteFx {
        coord: Arc<RoutingPauseCoordinator>,
        route_coord: Arc<SecondaryRouteCoordinator>,
        dispatcher: Arc<ScriptedPauseDispatcher>,
        api: Arc<MockWindowsApi>,
        conn: Arc<Mutex<Connection>>,
        _dir: tempfile::TempDir,
    }

    /// Pause coordinator wired WITH a route coordinator, an empty registry (no
    /// tray) and a fake active console session (`console_sid`).
    fn build_route_fx(console_sid: Option<&str>) -> RouteFx {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("state.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let conn = Arc::new(Mutex::new(runner.into_connection()));

        let registry = Arc::new(ActiveSidRegistry::new());
        let dispatcher = Arc::new(ScriptedPauseDispatcher::new());
        let audit = Arc::new(RecordingPauseAudit::new());
        let clock = FixedClock::new(1_700_000_000);

        let api = Arc::new(MockWindowsApi::new());
        api.set_console_user_sid(console_sid);
        let route_coord = route_coord_service_driven(Arc::clone(&api));

        let coord = Arc::new(
            RoutingPauseCoordinator::new(
                Arc::clone(&conn),
                registry,
                dispatcher.clone() as Arc<dyn PauseDispatcher>,
                audit as Arc<dyn RoutingPauseAudit>,
                clock as Arc<dyn Clock>,
            )
            .with_route_coordinator(Arc::clone(&route_coord)),
        );
        RouteFx {
            coord,
            route_coord,
            dispatcher,
            api,
            conn,
            _dir: dir,
        }
    }

    #[test]
    fn pause_all_active_includes_effective_console_sid_without_tray() {
        // No tray connections (empty registry) but a console session under
        // service-driven scope → safe-disable must still pause the console user,
        // remove its filters, and return a truthful non-empty list (the old
        // `registry.active_sids()`-only path returned an empty "0 suspended").
        let fx = build_route_fx(Some("S-CONSOLE"));
        let paused = fx
            .coord
            .pause_all_active(Some("safe-disable"))
            .expect("pause_all_active");
        assert_eq!(paused, vec!["S-CONSOLE".to_string()]);
        assert!(fx.coord.is_paused("S-CONSOLE").expect("is_paused"));
        assert_eq!(fx.dispatcher.remove_log(), vec!["S-CONSOLE".to_string()]);
    }

    #[test]
    fn pause_effective_sid_persist_keeps_slash32_drops_overlay() {
        // routing_stop_policy = Persist (opt-in; the default is teardown, HW-0709)
        // → keep the /32 rule-route on the additional adapter, remove only NRR's
        // /2 counter-overlay.
        let fx = build_route_fx(Some("S-CONSOLE"));
        {
            use nrr_domain::enforcement_mode::EnforcementMode;
            use nrr_storage::service_stability_config::{
                IpcAcceptPolicyWrite, RoutingStopPolicy, ServiceStabilityConfigRepository,
            };
            let guard = fx.conn.lock().expect("conn");
            ServiceStabilityConfigRepository::new(&guard)
                .set(
                    &IpcAcceptPolicyWrite::Critical,
                    false,
                    false,
                    false,
                    true,
                    RoutingStopPolicy::Persist,
                    300,
                    EnforcementMode::Reactive,
                    0,
                    false,
                    false,
                    true,
                    false,
                    true,
                    true,
                    false,
                    None,
                    0,
                )
                .expect("set persist policy");
        }
        let host = route_entry([1, 1, 1, 1], 32, [10, 0, 0, 1], 7);
        let overlay = route_entry([64, 0, 0, 0], 2, [192, 168, 0, 1], 9);
        fx.api.set_route_table(vec![host.clone(), overlay.clone()]);
        fx.route_coord.adopt_owned(vec![host, overlay]);
        assert_eq!(fx.route_coord.owned_count(), 2);

        fx.coord
            .pause("S-CONSOLE", Some("safe-disable"))
            .expect("pause");

        assert_eq!(
            fx.route_coord.owned_count(),
            1,
            "persist keeps the /32 rule-route, removes the /2 overlay"
        );
        // The effective (no-tray) console user's filters came down too.
        assert_eq!(fx.dispatcher.remove_log(), vec!["S-CONSOLE".to_string()]);
        assert!(fx.coord.is_paused("S-CONSOLE").expect("is_paused"));
    }

    #[test]
    fn pause_effective_sid_full_teardown_when_policy_teardown() {
        // routing_stop_policy = teardown → full clear of every NRR route.
        let fx = build_route_fx(Some("S-CONSOLE"));
        {
            use nrr_domain::enforcement_mode::EnforcementMode;
            use nrr_storage::service_stability_config::{
                IpcAcceptPolicyWrite, RoutingStopPolicy, ServiceStabilityConfigRepository,
            };
            let guard = fx.conn.lock().expect("conn");
            ServiceStabilityConfigRepository::new(&guard)
                .set(
                    &IpcAcceptPolicyWrite::Critical,
                    false,
                    false,
                    false,
                    true,
                    RoutingStopPolicy::Teardown,
                    300,
                    EnforcementMode::Reactive,
                    0,
                    false,
                    false,
                    true,
                    false,
                    true,
                    true,
                    false,
                    None,
                    0,
                )
                .expect("set stop policy");
        }
        let host = route_entry([1, 1, 1, 1], 32, [10, 0, 0, 1], 7);
        let overlay = route_entry([64, 0, 0, 0], 2, [192, 168, 0, 1], 9);
        fx.api.set_route_table(vec![host.clone(), overlay.clone()]);
        fx.route_coord.adopt_owned(vec![host, overlay]);
        assert_eq!(fx.route_coord.owned_count(), 2);

        fx.coord
            .pause("S-CONSOLE", Some("safe-disable"))
            .expect("pause");
        assert_eq!(
            fx.route_coord.owned_count(),
            0,
            "teardown removes every NRR route"
        );
    }

    #[test]
    fn resume_effective_sid_reinstalls_and_recomputes() {
        let fx = build_route_fx(Some("S-CONSOLE"));
        fx.coord
            .pause("S-CONSOLE", Some("safe-disable"))
            .expect("pause");
        assert!(fx.coord.is_paused("S-CONSOLE").expect("paused"));

        // Simulate routes present when resume runs; resume clears the flag then
        // recomputes → with no bound secondary the recompute resolves to "no
        // target" and clears them, proving the recompute ran.
        let host = route_entry([1, 1, 1, 1], 32, [10, 0, 0, 1], 7);
        fx.api.set_route_table(vec![host.clone()]);
        fx.route_coord.adopt_owned(vec![host]);
        assert_eq!(fx.route_coord.owned_count(), 1);

        fx.coord.resume("S-CONSOLE").expect("resume");
        assert!(!fx.coord.is_paused("S-CONSOLE").expect("resumed"));
        // The effective (no-tray) console user's filters were reinstalled.
        assert_eq!(fx.dispatcher.install_log(), vec!["S-CONSOLE".to_string()]);
        // And the route table was recomputed (cleared here, since NoPolicy has no
        // secondary target) — demonstrating resume drives a recompute.
        assert_eq!(fx.route_coord.owned_count(), 0);
    }

    #[test]
    fn pause_without_route_coordinator_is_wfp_only() {
        // Regression guard for the `route_coord = None` fallback (all pre-existing
        // fixtures): `is_effective` is false, so a non-active SID neither touches
        // the dispatcher nor tears down routes — WFP-only, exactly as before.
        let fx = build_fx();
        fx.coord.pause("S-A", None).expect("pause");
        assert!(fx.coord.is_paused("S-A").expect("is_paused"));
        assert!(fx.dispatcher.remove_log().is_empty());
    }
}
