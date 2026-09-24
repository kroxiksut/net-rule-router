//! Task constructors for the production `ServiceSupervisor`.
//!
//! Five long-lived `ServiceTask` shapes consumed by the runtime entry-point.
//! Each builder returns a freshly-constructed `ServiceTask` that the
//! supervisor can `spawn()` — no global state, no implicit ordering.
//! Cross-task dependencies (`ipc-accept-loop` ↔ `ipc-shutdown-watcher`) are
//! threaded through `Arc` so each task sees the same listener state.
//!
//! | Task id                  | Class       | Interval | Failure semantics                                 |
//! |--------------------------|-------------|----------|----------------------------------------------------|
//! | `health-aggregator-tick` | Recoverable | 5s       | Restarted up to 20× with supervisor backoff        |
//! | `adapter-monitor-tick`   | Recoverable | 1s       | Restarted up to 20×; degraded mode on retire       |
//! | `diagnostics-cleanup`    | Optional    | 1h       | Dropped quietly on failure                         |
//! | `operation-results-gc`   | Optional    | 5min     | Dropped quietly on failure                         |
//! | `ipc-accept-loop`        | per policy  | event    | Recoverable / Critical from `ServiceStabilityConfig` |
//!
//! The IPC bundle is special:
//!
//! - `bind()` happens **once** during the bundle build, before any
//!   `spawn()` — bind errors surface to the caller synchronously so they
//!   can be folded into the bootstrap report.
//! - The accept-task tick calls `acceptor.accept_one()`, which blocks until
//!   a client connects, the shutdown event fires, or accept fails.
//! - Because `accept_one` blocks, the supervisor's `StopToken` cannot
//!   reach it directly. A second task — `ipc-shutdown-watcher` — polls
//!   the stop token every 100 ms and calls `acceptor.request_shutdown()`
//!   when set, which wakes the blocking `ConnectNamedPipe`.
//! - On `AcceptOutcome::Err` the accept-task drops the current acceptor,
//!   asks the `IpcServer` for a fresh `bind()`, and returns
//!   `TaskOutcome::Failed`. The supervisor's policy then decides whether
//!   to retry (Recoverable) or terminate fatally (Critical), in line
//!   with `IpcAcceptFailurePolicy`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nrr_diagnostics::{AuditRetentionPolicy, CleanupJob, LogRetentionPolicy, ManualCleanupScope};
use nrr_platform_api::AdapterMonitor;

use crate::health::{HealthAggregator, HealthComponent};
use crate::ipc_handlers::event_bus::EventBus;
use crate::ipc_handlers::operation_status_store::OperationStatusStore;
use crate::lifecycle::StopToken;
use crate::managers::{AcceptOutcome, IpcAcceptor, IpcBindError, IpcServer};
use crate::runtime_loop::{BackoffSchedule, ServiceTask, TaskClass, TaskId, TaskOutcome};
use crate::service_stability::{IpcAcceptFailurePolicy, ServiceStabilityConfig};
use crate::state::ServiceHealthSeverity;
use nrr_shared::ipc_payloads::StatusUpdateEvent;

mod auto_rules;
mod dns;
mod ipc;
mod maintenance;
mod observation;
mod routing;

pub use auto_rules::*;
pub use dns::*;
pub use ipc::*;
pub use maintenance::*;
pub use observation::*;
pub use routing::*;

// ── Constants ────────────────────────────────────────────────────────────────

/// Cadence the health aggregator recomputes its rolled-up snapshot at.
pub const HEALTH_AGGREGATOR_INTERVAL: Duration = Duration::from_secs(5);
/// Cadence the adapter monitor polls its underlying source at. Tight
/// (1 s) so adapter availability transitions land in the GUI within
/// the debounce window without burning CPU on enumeration.
pub const ADAPTER_MONITOR_INTERVAL: Duration = Duration::from_secs(1);
/// Cadence of the periodic route-reconcile safety net. The adapter
/// monitor only reacts to availability
/// *transitions* (`Absent`/`PresentDown`/`PresentNoIp` ↔ `Available`); it
/// is blind to a secondary that changes its internal IP / gateway while
/// staying continuously `Available` — e.g. a secondary adapter renewing its tunnel
/// address without dropping the interface. This slow tick re-drives the
/// active user's route table so such a silent re-IP (and, under
/// service-driven rule-scope with no tray, a baseline change) converges
/// within one interval. `recompute_active` re-derives the secondary
/// next-hop FRESH and reconciles to a no-op when nothing changed, so the
/// steady-state cost is one route-table enumeration plus a diff.
pub const ROUTE_RECONCILE_SAFETY_INTERVAL: Duration = Duration::from_secs(30);
/// Cadence the operational-log cleanup job runs at. 1 hour is the
/// retention spec — fast enough that disk pressure from a verbose
/// session resolves within an hour, slow enough to keep file IO load
/// negligible.
pub const DIAGNOSTICS_CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);
/// Cadence operation-result GC runs at. Operation results carry a 5-min
/// TTL; GC matches so expired records leave memory promptly after the
/// GUI has had a chance to poll.
pub const OPERATION_RESULTS_GC_INTERVAL: Duration = Duration::from_secs(300);
/// Cadence the IPC shutdown watcher polls `StopToken` at. 100 ms is
/// short enough that GUI/SCM-driven shutdown latency stays under one
/// poll round, long enough that the watcher contributes negligible CPU.
pub const IPC_SHUTDOWN_WATCHER_INTERVAL: Duration = Duration::from_millis(100);

/// `max_restarts` for Recoverable tasks whose failure policy is implicit
/// (everything except `ipc-accept-loop`, which derives its budget from
/// `IpcAcceptFailurePolicy`).
pub const RECOVERABLE_DEFAULT_MAX_RESTARTS: u8 = 20;

// ── Task-id slugs ────────────────────────────────────────────────────────────

/// Stable task ids. Surface in audit / health snapshots — do not rename
/// without coordinating with the GUI side.
pub const TASK_ID_HEALTH_AGGREGATOR: &str = "health-aggregator-tick";
pub const TASK_ID_ADAPTER_MONITOR: &str = "adapter-monitor-tick";
pub const TASK_ID_ROUTE_RECONCILE_SAFETY: &str = "route-reconcile-safety-tick";
pub const TASK_ID_DIAGNOSTICS_CLEANUP: &str = "diagnostics-cleanup";
/// Scheduled audit NDJSON retention pruner. Distinct task from
/// `diagnostics-cleanup` because it targets `nrr_audit_*` files under
/// the same dir via `CleanupJob::run_audit` (never user-triggered).
pub const TASK_ID_DIAGNOSTICS_AUDIT_CLEANUP: &str = "diagnostics-audit-cleanup";
pub const TASK_ID_OPERATION_RESULTS_GC: &str = "operation-results-gc";
/// Periodic revisions retention pruner. Runs the same 1-hour cadence
/// as `diagnostics-cleanup`. Optional class.
pub const TASK_ID_REVISIONS_RETENTION: &str = "revisions-retention-prune";
/// Periodic WAL checkpoint over every database the service holds open. Same
/// 1-hour cadence as the retention pruners. Optional class.
pub const TASK_ID_STORAGE_CHECKPOINT: &str = "storage-wal-checkpoint";
pub const TASK_ID_IPC_ACCEPT_LOOP: &str = "ipc-accept-loop";
pub const TASK_ID_IPC_SHUTDOWN_WATCHER: &str = "ipc-shutdown-watcher";
/// Periodic DNS refresh tick. Optional class — DNS failures degrade
/// rule matching (SuffixDomain/ExactFqdn lose stale IPs over time) but
/// never block routing policy enforcement.
pub const TASK_ID_DNS_REFRESH: &str = "dns-refresh-tick";

/// Cadence the DNS refresh task runs at. 60 s is a compromise: short
/// enough that a TTL=30 s record becomes fresh again within ~1.5
/// minutes of expiry, long enough that the resolver cost is amortised
/// (DnsQuery_W typically returns in <50 ms for cached entries; cold
/// queries can take 200–1000 ms but are batched at `DNS_REFRESH_BATCH`).
pub const DNS_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum hostnames the DNS refresh task processes in a single tick.
/// Bounded so a backlog after a long offline period (e.g. laptop wake
/// from suspend) does not stall the supervisor tick thread.
pub const DNS_REFRESH_BATCH: usize = 50;

/// Rule-hostname seed task id.
pub const TASK_ID_RULE_HOSTNAME_SEED: &str = "rule-hostname-seed-tick";

/// DNS-observation pump task id.
pub const TASK_ID_DNS_OBSERVE: &str = "dns-observe-tick";

/// Cadence the DNS-observation pump drains the observation buffer. Tight
/// (1 s) so a freshly-observed subdomain under a suffix/zone rule becomes a
/// route quickly: under an armed block-all, the first SYN to a
/// freshly-observed rule host is dropped until its permit compiles, so a
/// short observe cadence shrinks that window to about one TCP SYN
/// retransmit — the browser's own retry usually lands after the permit
/// exists. The drain itself stays a cheap ETW buffer read, not a network
/// call, so a 1 s cadence costs nothing at idle.
pub const DNS_OBSERVE_INTERVAL: Duration = Duration::from_secs(1);

/// Connection-observation pump task id.
pub const TASK_ID_CONN_OBSERVE: &str = "conn-observe-tick";

/// Cadence the connection-observation pump drains its buffer. Matches the
/// DNS-observe cadence (5 s) — frequent enough for a live trace, while
/// debouncing high-volume connection bursts into one drain per tick.
pub const CONN_OBSERVE_INTERVAL: Duration = Duration::from_secs(5);

/// Companion-domain proposal tick — task id.
pub const TASK_ID_AUTO_RULES: &str = "auto-rules-tick";

/// Cadence the companion-domain proposal tick runs at.
///
/// The feature is judged on one behaviour: the prompt has to arrive while the
/// user is still on the page that was half-broken. A brand-related companion
/// qualifies from its FIRST window, so waiting out a slow tick is dead time,
/// not evidence-gathering — and the recompute is a walk over a
/// browsing-session-sized table, cheap enough to repeat.
pub const AUTO_RULES_INTERVAL: Duration = Duration::from_secs(10);

/// External-address notice — task id.
pub const TASK_ID_SECONDARY_EXTERNAL_ADDRESS: &str = "secondary-external-address-tick";

/// Cadence the external-address notice tick runs at.
///
/// Two ticks make up
/// [`crate::secondary_external_address::LINK_SETTLE`], so the notice lands
/// within roughly half a minute of the additional link coming up — prompt
/// enough to read as "it just connected". The steady-state cost is one route
/// resolution plus an adapter enumeration; the network probe happens once per
/// connection, on its own thread, never on this one.
pub const SECONDARY_EXTERNAL_ADDRESS_INTERVAL: Duration = Duration::from_secs(2);

/// Cadence the rule-hostname seed task runs at. Matches the DNS refresh
/// cadence: the seeder only resolves NOT-yet-cached `ExactFqdn` rule
/// hostnames (each pass skips already-cached ones), so steady-state cost
/// is near zero — work happens once after a new domain rule lands, then
/// the DNS refresh task keeps it warm.
pub const RULE_HOSTNAME_SEED_INTERVAL: Duration = Duration::from_secs(60);

/// Application-destination write-back — task id.
pub const TASK_ID_APP_DESTINATION_FLUSH: &str = "app-destination-flush-tick";

/// Cadence the application-destination write-back runs at. The same 60 s as the
/// rule-hostname seed, and for the same reason: both read one rule snapshot and
/// then do work proportional to what the rule book actually names, so a rule book
/// with no application routed over the additional link costs a snapshot read and
/// nothing else. Fast enough that a crash loses at most a minute of freshly
/// learned destinations, slow enough to be invisible.
pub const APP_DESTINATION_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

// ── Health aggregator ────────────────────────────────────────────────────────

/// Periodic snapshot recompute. Cheap — `HealthAggregator::snapshot()`
/// is O(N) over component count. The task body throws the snapshot away
/// because the GUI polls on demand; the only purpose of the periodic
/// run is to keep `snapshot_refreshed_at` fresh and to detect aggregator
/// poisoning (a poisoned mutex makes `snapshot()` return a synthesised
/// `RecoveryRequired` snapshot, which is observable even from a tick
/// that doesn't read the result).
pub fn build_health_aggregator_task(health: Arc<HealthAggregator>) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_HEALTH_AGGREGATOR,
        TaskClass::Recoverable,
        HEALTH_AGGREGATOR_INTERVAL,
        RECOVERABLE_DEFAULT_MAX_RESTARTS,
        move |_stop| {
            // Touch the aggregator so a poisoned mutex is detected.
            // Discarding the snapshot is intentional — the GUI reads
            // through `service.health.get` on its own cadence.
            let _ = health.snapshot();
            TaskOutcome::Continue
        },
    )
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
