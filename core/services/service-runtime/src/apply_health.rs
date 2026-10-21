//! The apply pass's verdict on `HealthComponent::Apply`.
//!
//! A pass the platform refused used to be a log line and nothing else: the
//! service stayed `Running`, the GUI showed the rules as applied. Both apply
//! paths now speak through one voice on the aggregator — the neutral cycle on
//! Linux, the per-user orchestrator on Windows — and the next pass that
//! succeeds clears it. A verdict another writer holds on the same component
//! (no filtering session at boot, say) stays.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::health::{HealthAggregator, HealthComponent};
use crate::per_sid_orchestrator::{PerSidApplyAudit, PerSidApplyAuditKind, PerSidApplyAuditRecord};
use crate::principal_enforcement::CycleOutcome;
use crate::state::ServiceHealthSeverity;

/// The aggregator voice both apply paths record under.
pub const APPLY_PASS_SOURCE: &str = "apply-pass";

/// Fold one pass of the neutral cycle into health.
pub fn report_cycle_outcome(health: &HealthAggregator, outcome: &CycleOutcome) {
    let degraded = match outcome {
        CycleOutcome::Applied { routes, .. } => routes
            .as_ref()
            .and_then(|r| r.failure.as_deref())
            .map(|why| format!("filters applied but routes were not: {why}")),
        CycleOutcome::Unchanged => None,
        CycleOutcome::AuthorityUnavailable { reason } => {
            Some(format!("who is signed in could not be read: {reason}"))
        }
        CycleOutcome::EnforcementFailed { reason, .. } => Some(refused(reason)),
        CycleOutcome::RefusalStands { reason } => Some(refused(reason)),
        // Teardown says nothing: the service is leaving.
        CycleOutcome::Stopped => return,
    };
    match degraded {
        Some(message) => health.record_as(
            APPLY_PASS_SOURCE,
            HealthComponent::Apply,
            ServiceHealthSeverity::Degraded,
            message,
        ),
        None => health.clear_as(APPLY_PASS_SOURCE, HealthComponent::Apply),
    }
}

fn refused(reason: &str) -> String {
    format!("the platform refused the rules: {reason}")
}

/// The voice of the route-before-block hook, apart from the pass verdicts: a
/// later good pass must not wipe a route failure it never retried.
const ROUTE_SYNC_SOURCE: &str = "route-sync";

/// The route-before-block hook over `recompute`. A failure marks `Apply`
/// degraded and asks for a full pass, so the retry comes from the next tick
/// instead of waiting for an input to move; a success clears the mark.
pub fn route_sync_hook(
    recompute: impl Fn() -> Result<(), String> + Send + Sync + 'static,
    health: Arc<HealthAggregator>,
    retry: crate::pass_inputs::FullPassRequest,
) -> crate::per_sid_orchestrator::RouteSyncHook {
    Arc::new(move || match recompute() {
        Ok(()) => {
            health.clear_as(ROUTE_SYNC_SOURCE, HealthComponent::Apply);
            Ok(())
        }
        Err(error) => {
            health.record_as(
                ROUTE_SYNC_SOURCE,
                HealthComponent::Apply,
                ServiceHealthSeverity::Degraded,
                format!("routes were not updated before new rules took effect: {error}"),
            );
            retry.request();
            Err(error)
        }
    })
}

/// [`PerSidApplyAudit`] that also keeps `Apply` honest: a user whose filters
/// the platform refused holds it at `Degraded` until a later install, update
/// or withdrawal for that user succeeds. Users are counted, never named — the
/// message reaches every client.
pub struct ApplyHealthAudit {
    inner: Arc<dyn PerSidApplyAudit>,
    health: Arc<HealthAggregator>,
    /// Users whose last transition failed → the platform's reason.
    failed: Mutex<BTreeMap<String, String>>,
}

impl ApplyHealthAudit {
    pub fn new(inner: Arc<dyn PerSidApplyAudit>, health: Arc<HealthAggregator>) -> Self {
        Self {
            inner,
            health,
            failed: Mutex::new(BTreeMap::new()),
        }
    }

    fn publish(&self, failed: &BTreeMap<String, String>) {
        let Some(last) = failed.values().next_back() else {
            self.health
                .clear_as(APPLY_PASS_SOURCE, HealthComponent::Apply);
            return;
        };
        let users = failed.len();
        self.health.record_as(
            APPLY_PASS_SOURCE,
            HealthComponent::Apply,
            ServiceHealthSeverity::Degraded,
            format!("rules of {users} user(s) are not in force: {last}"),
        );
    }
}

impl PerSidApplyAudit for ApplyHealthAudit {
    fn emit(&self, record: PerSidApplyAuditRecord) {
        let mut failed = self.failed.lock().unwrap_or_else(|p| p.into_inner());
        let changed = match record.kind {
            PerSidApplyAuditKind::Failed => {
                failed.insert(record.sid.clone(), record.message.clone());
                true
            }
            PerSidApplyAuditKind::Applied
            | PerSidApplyAuditKind::Updated
            | PerSidApplyAuditKind::Withdrawn => failed.remove(&record.sid).is_some(),
        };
        if changed {
            self.publish(&failed);
        }
        drop(failed);
        self.inner.emit(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::per_sid_orchestrator::NoopPerSidApplyAudit;
    use crate::route_apply::RouteApplyReport;
    use crate::state::ServiceRuntimeState;

    fn health() -> Arc<HealthAggregator> {
        let health = Arc::new(HealthAggregator::new());
        health.clear_lifecycle_override();
        // A running service has other components reporting; without one the
        // table is empty once Apply clears and derives `Starting`.
        health.record_initial(HealthComponent::Storage, ServiceHealthSeverity::Ok, "ok");
        health
    }

    fn apply(health: &HealthAggregator) -> Option<(ServiceHealthSeverity, String)> {
        health
            .snapshot()
            .components
            .into_iter()
            .find(|c| c.component == HealthComponent::Apply)
            .map(|c| (c.severity, c.message))
    }

    fn applied(routes: Option<RouteApplyReport>) -> CycleOutcome {
        CycleOutcome::Applied {
            principals: Vec::new(),
            report: nrr_platform_api::enforcement::ApplyReport::default(),
            changed: true,
            delta: None,
            unprotected: Vec::new(),
            guarded: 0,
            routes,
        }
    }

    #[test]
    fn a_failed_route_sync_degrades_apply_and_asks_for_a_retry_until_one_works() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let health = health();
        let retry = crate::pass_inputs::FullPassRequest::default();
        let failing = Arc::new(AtomicBool::new(true));
        let hook = {
            let failing = Arc::clone(&failing);
            route_sync_hook(
                move || {
                    if failing.load(Ordering::SeqCst) {
                        Err("table busy".to_owned())
                    } else {
                        Ok(())
                    }
                },
                Arc::clone(&health),
                retry.clone(),
            )
        };
        assert_eq!(hook(), Err("table busy".to_owned()));
        let (severity, message) = apply(&health).expect("apply degraded");
        assert_eq!(severity, ServiceHealthSeverity::Degraded);
        assert!(message.contains("table busy"), "{message}");
        assert!(retry.take(), "a retry was requested");
        failing.store(false, Ordering::SeqCst);
        assert_eq!(hook(), Ok(()));
        assert_eq!(apply(&health), None);
        assert!(!retry.take(), "a success asks for nothing");
    }

    #[test]
    fn a_refused_pass_degrades_apply_and_the_next_good_pass_clears_it() {
        let health = health();
        report_cycle_outcome(
            &health,
            &CycleOutcome::EnforcementFailed {
                reason: "nft refused".into(),
                persistent: false,
            },
        );
        let (severity, message) = apply(&health).expect("apply");
        assert_eq!(severity, ServiceHealthSeverity::Degraded);
        assert!(message.contains("nft refused"), "{message}");
        assert_eq!(health.snapshot().state, ServiceRuntimeState::Degraded);

        report_cycle_outcome(&health, &applied(None));
        assert_eq!(apply(&health), None);
        assert_eq!(health.snapshot().state, ServiceRuntimeState::Running);
    }

    #[test]
    fn a_standing_refusal_and_an_unreadable_authority_degrade_but_a_stop_says_nothing() {
        let health = health();
        report_cycle_outcome(
            &health,
            &CycleOutcome::RefusalStands {
                reason: "bad plan".into(),
            },
        );
        assert_eq!(
            apply(&health).map(|a| a.0),
            Some(ServiceHealthSeverity::Degraded)
        );
        report_cycle_outcome(&health, &CycleOutcome::Unchanged);
        assert_eq!(apply(&health), None);
        report_cycle_outcome(
            &health,
            &CycleOutcome::AuthorityUnavailable {
                reason: "logind down".into(),
            },
        );
        assert_eq!(
            apply(&health).map(|a| a.0),
            Some(ServiceHealthSeverity::Degraded)
        );
        report_cycle_outcome(&health, &CycleOutcome::Stopped);
        assert_eq!(
            apply(&health).map(|a| a.0),
            Some(ServiceHealthSeverity::Degraded)
        );
    }

    #[test]
    fn filters_applied_with_routes_failed_still_degrades() {
        let health = health();
        let routes = RouteApplyReport {
            failure: Some("no gateway".into()),
            ..RouteApplyReport::default()
        };
        report_cycle_outcome(&health, &applied(Some(routes)));
        let (severity, message) = apply(&health).expect("apply");
        assert_eq!(severity, ServiceHealthSeverity::Degraded);
        assert!(message.contains("no gateway"), "{message}");
    }

    #[test]
    fn a_pass_verdict_never_clears_what_another_writer_said() {
        let health = health();
        health.record(
            HealthComponent::Apply,
            ServiceHealthSeverity::Degraded,
            "no filtering session",
        );
        report_cycle_outcome(&health, &applied(None));
        assert_eq!(
            apply(&health),
            Some((
                ServiceHealthSeverity::Degraded,
                "no filtering session".to_owned()
            ))
        );
    }

    fn record(sid: &str, kind: PerSidApplyAuditKind, message: &str) -> PerSidApplyAuditRecord {
        PerSidApplyAuditRecord {
            sid: sid.to_owned(),
            kind,
            filter_count: 0,
            message: message.to_owned(),
        }
    }

    #[test]
    fn a_failed_user_install_degrades_apply_until_that_user_succeeds() {
        let health = health();
        let audit = ApplyHealthAudit::new(Arc::new(NoopPerSidApplyAudit), Arc::clone(&health));
        audit.emit(record(
            "S-1-5-21-1",
            PerSidApplyAuditKind::Failed,
            "engine busy",
        ));
        let (severity, message) = apply(&health).expect("apply");
        assert_eq!(severity, ServiceHealthSeverity::Degraded);
        assert!(message.contains("engine busy"), "{message}");
        assert!(!message.contains("S-1-5-21"), "no user named: {message}");

        // Another user's success does not speak for the failed one.
        audit.emit(record("S-1-5-21-2", PerSidApplyAuditKind::Applied, "ok"));
        assert_eq!(
            apply(&health).map(|a| a.0),
            Some(ServiceHealthSeverity::Degraded)
        );

        audit.emit(record("S-1-5-21-1", PerSidApplyAuditKind::Updated, "ok"));
        assert_eq!(apply(&health), None);
    }
}
