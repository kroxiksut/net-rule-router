//! Every long-lived task of the service, and where its loss shows in health.
//!
//! A task the GUI cannot see die is a feature that silently stops. Adding a
//! task means adding a variant here, which forces the decision; the source
//! scan in `tests/background_tasks_in_health.rs` refuses a task built from an
//! id this enum does not know, and a thread outside the supervisor that holds
//! no lease on its kind.

use super::*;

/// One long-lived task, by its stable id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ServiceTaskKind {
    HealthAggregator,
    AdapterMonitor,
    RouteReconcileSafety,
    SecondaryLiveness,
    ResumeWatchdog,
    AppObservation,
    LiveConnectionRefresh,
    DnsObservation,
    IpcAcceptLoop,
    IpcShutdownWatcher,
    OperationResultsGc,
    DiagnosticsCleanup,
    DiagnosticsAuditCleanup,
    RevisionsRetention,
    StorageCheckpoint,
    RevisionWatch,
    PrincipalEnforcement,
    TrafficSample,
    DnsRefresh,
    RuleHostnameSeed,
    DnsObserve,
    ConnObserve,
    AutoRules,
    AppDestinationFlush,
    SecondaryExternalAddress,
    // Threads outside the supervisor; each holds a `TaskLiveness` lease.
    DnsResolver,
    DnsRedirectGuard,
    DnsReconcileWorker,
    FakeIpStack,
    FakeIpFlowObserver,
    FakeIpSelfHeal,
    FakeIpWatchdog,
    NetChangeDebounce,
    FcrdnsLearner,
}

/// Who runs the task: the supervisor's own loop, or a thread the task's owner
/// spawns and reports on through a [`crate::task_liveness::ThreadLease`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskRunner {
    Supervisor,
    OwnThread,
}

/// Where a task that is gone for good — retired after its restarts, or ended
/// while the service keeps running — shows up. A failure with a restart still
/// pending is reported by class instead: an `Optional` task holds
/// `BackgroundTasks` at `Degraded` until it ticks again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskHealth {
    Reports {
        component: HealthComponent,
        severity: ServiceHealthSeverity,
    },
    /// Deliberately absent from the roll-up; the reason says why that is safe.
    Invisible(&'static str),
}

const BACKGROUND: TaskHealth = TaskHealth::Reports {
    component: HealthComponent::BackgroundTasks,
    severity: ServiceHealthSeverity::Degraded,
};

impl ServiceTaskKind {
    pub const ALL: [Self; 34] = [
        Self::HealthAggregator,
        Self::AdapterMonitor,
        Self::RouteReconcileSafety,
        Self::SecondaryLiveness,
        Self::ResumeWatchdog,
        Self::AppObservation,
        Self::LiveConnectionRefresh,
        Self::DnsObservation,
        Self::IpcAcceptLoop,
        Self::IpcShutdownWatcher,
        Self::OperationResultsGc,
        Self::DiagnosticsCleanup,
        Self::DiagnosticsAuditCleanup,
        Self::RevisionsRetention,
        Self::StorageCheckpoint,
        Self::RevisionWatch,
        Self::PrincipalEnforcement,
        Self::TrafficSample,
        Self::DnsRefresh,
        Self::RuleHostnameSeed,
        Self::DnsObserve,
        Self::ConnObserve,
        Self::AutoRules,
        Self::AppDestinationFlush,
        Self::SecondaryExternalAddress,
        Self::DnsResolver,
        Self::DnsRedirectGuard,
        Self::DnsReconcileWorker,
        Self::FakeIpStack,
        Self::FakeIpFlowObserver,
        Self::FakeIpSelfHeal,
        Self::FakeIpWatchdog,
        Self::NetChangeDebounce,
        Self::FcrdnsLearner,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            Self::HealthAggregator => TASK_ID_HEALTH_AGGREGATOR,
            Self::AdapterMonitor => TASK_ID_ADAPTER_MONITOR,
            Self::RouteReconcileSafety => TASK_ID_ROUTE_RECONCILE_SAFETY,
            Self::SecondaryLiveness => TASK_ID_SECONDARY_LIVENESS,
            Self::ResumeWatchdog => crate::power_resume::TASK_ID_RESUME_WATCHDOG,
            Self::AppObservation => TASK_ID_APP_OBSERVATION,
            Self::LiveConnectionRefresh => TASK_ID_LIVE_CONNECTION_REFRESH,
            Self::DnsObservation => TASK_ID_DNS_OBSERVATION,
            Self::IpcAcceptLoop => TASK_ID_IPC_ACCEPT_LOOP,
            Self::IpcShutdownWatcher => TASK_ID_IPC_SHUTDOWN_WATCHER,
            Self::OperationResultsGc => TASK_ID_OPERATION_RESULTS_GC,
            Self::DiagnosticsCleanup => TASK_ID_DIAGNOSTICS_CLEANUP,
            Self::DiagnosticsAuditCleanup => TASK_ID_DIAGNOSTICS_AUDIT_CLEANUP,
            Self::RevisionsRetention => TASK_ID_REVISIONS_RETENTION,
            Self::StorageCheckpoint => TASK_ID_STORAGE_CHECKPOINT,
            Self::RevisionWatch => TASK_ID_REVISION_WATCH,
            Self::PrincipalEnforcement => TASK_ID_PRINCIPAL_ENFORCEMENT,
            Self::TrafficSample => TASK_ID_TRAFFIC_SAMPLE,
            Self::DnsRefresh => TASK_ID_DNS_REFRESH,
            Self::RuleHostnameSeed => TASK_ID_RULE_HOSTNAME_SEED,
            Self::DnsObserve => TASK_ID_DNS_OBSERVE,
            Self::ConnObserve => TASK_ID_CONN_OBSERVE,
            Self::AutoRules => TASK_ID_AUTO_RULES,
            Self::AppDestinationFlush => TASK_ID_APP_DESTINATION_FLUSH,
            Self::SecondaryExternalAddress => TASK_ID_SECONDARY_EXTERNAL_ADDRESS,
            Self::DnsResolver => "dns-resolver",
            Self::DnsRedirectGuard => "dns-redirect-guard",
            Self::DnsReconcileWorker => "dns-reconcile-worker",
            Self::FakeIpStack => "fake-ip-stack",
            Self::FakeIpFlowObserver => "fake-ip-flow-observer",
            Self::FakeIpSelfHeal => "fake-ip-self-heal",
            Self::FakeIpWatchdog => "fake-ip-watchdog",
            Self::NetChangeDebounce => "net-change-debounce",
            Self::FcrdnsLearner => "fcrdns-learner",
        }
    }

    pub const fn runner(self) -> TaskRunner {
        match self {
            Self::DnsResolver
            | Self::DnsRedirectGuard
            | Self::DnsReconcileWorker
            | Self::FakeIpStack
            | Self::FakeIpFlowObserver
            | Self::FakeIpSelfHeal
            | Self::FakeIpWatchdog
            | Self::NetChangeDebounce
            | Self::FcrdnsLearner => TaskRunner::OwnThread,
            _ => TaskRunner::Supervisor,
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.id() == id)
    }

    pub const fn health(self) -> TaskHealth {
        match self {
            // `Blocking` for the two whose loss the IPC gate must act on: no
            // listener means no GUI, no adapter view means no correct binding.
            Self::IpcAcceptLoop => TaskHealth::Reports {
                component: HealthComponent::Ipc,
                severity: ServiceHealthSeverity::Blocking,
            },
            Self::AdapterMonitor => TaskHealth::Reports {
                component: HealthComponent::Adapters,
                severity: ServiceHealthSeverity::Blocking,
            },
            // Without it a stop cannot wake the accept loop; IPC itself still works.
            Self::IpcShutdownWatcher => TaskHealth::Reports {
                component: HealthComponent::Ipc,
                severity: ServiceHealthSeverity::Degraded,
            },
            // Rules are no longer enforced, but editing them still works: the
            // same verdict as a filtering engine that never handed out a session.
            Self::PrincipalEnforcement => TaskHealth::Reports {
                component: HealthComponent::Apply,
                severity: ServiceHealthSeverity::Degraded,
            },
            Self::RevisionWatch => TaskHealth::Reports {
                component: HealthComponent::Integrity,
                severity: ServiceHealthSeverity::Degraded,
            },
            // The local resolver is how domain rules are enforced in resolver
            // mode: with it gone, names resolve past the rules. Its serve loop
            // restores the system DNS on every exit, and reports `Blocking` on
            // its own when that restore fails.
            Self::DnsResolver => TaskHealth::Reports {
                component: HealthComponent::Apply,
                severity: ServiceHealthSeverity::Degraded,
            },
            // Without the guard a redirect the OS undoes stays undone; without
            // the worker every rule-host answer waits out its deadline unenforced.
            Self::DnsRedirectGuard | Self::DnsReconcileWorker => TaskHealth::Reports {
                component: HealthComponent::Apply,
                severity: ServiceHealthSeverity::Degraded,
            },
            // The relay is what carries the shared-address hosts: dead, their
            // traffic has no path while names still resolve to its addresses.
            Self::FakeIpStack => TaskHealth::Reports {
                component: HealthComponent::Apply,
                severity: ServiceHealthSeverity::Degraded,
            },
            Self::HealthAggregator => TaskHealth::Invisible(
                "only re-reads the aggregator; every reader computes its own snapshot, so \
                 nothing depends on this tick",
            ),
            Self::RouteReconcileSafety
            | Self::SecondaryLiveness
            | Self::ResumeWatchdog
            | Self::AppObservation
            | Self::LiveConnectionRefresh
            | Self::DnsObservation
            | Self::OperationResultsGc
            | Self::DiagnosticsCleanup
            | Self::DiagnosticsAuditCleanup
            | Self::RevisionsRetention
            | Self::StorageCheckpoint
            | Self::TrafficSample
            | Self::DnsRefresh
            | Self::RuleHostnameSeed
            | Self::DnsObserve
            | Self::ConnObserve
            | Self::AutoRules
            | Self::AppDestinationFlush
            | Self::SecondaryExternalAddress
            | Self::FakeIpFlowObserver
            | Self::FakeIpSelfHeal
            | Self::FakeIpWatchdog
            | Self::NetChangeDebounce
            | Self::FcrdnsLearner => BACKGROUND,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_task_id_is_unique_and_resolves_back_to_its_kind() {
        let mut seen = HashSet::new();
        for kind in ServiceTaskKind::ALL {
            assert!(seen.insert(kind.id()), "duplicate task id {}", kind.id());
            assert_eq!(ServiceTaskKind::from_id(kind.id()), Some(kind));
        }
        assert_eq!(ServiceTaskKind::from_id("no-such-task"), None);
    }

    #[test]
    fn own_thread_kinds_are_the_ones_without_a_task_id_constant() {
        let own: Vec<&str> = ServiceTaskKind::ALL
            .into_iter()
            .filter(|k| k.runner() == TaskRunner::OwnThread)
            .map(ServiceTaskKind::id)
            .collect();
        assert_eq!(own.len(), 9, "{own:?}");
        assert!(own.contains(&"dns-resolver"));
    }

    #[test]
    fn the_mapping_is_total_and_every_invisible_task_says_why() {
        for kind in ServiceTaskKind::ALL {
            match kind.health() {
                TaskHealth::Reports { severity, .. } => assert!(
                    severity >= ServiceHealthSeverity::Degraded,
                    "{}: a task gone for good must move the roll-up off Running",
                    kind.id()
                ),
                TaskHealth::Invisible(reason) => assert!(
                    reason.trim().len() > 20,
                    "{}: an invisible task needs a real reason",
                    kind.id()
                ),
            }
        }
    }
}
