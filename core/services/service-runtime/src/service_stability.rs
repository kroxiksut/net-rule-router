//! Service-stability configuration.
//!
//! Today this only covers the **IPC accept loop** failure policy. The shape
//! is open for future tasks (apply controller, adapter monitor, …) without a
//! breaking change.
//!
//! The defaults are chosen for end-user installations. The `Critical` mode
//! exists for compliance scenarios where any control-channel disturbance
//! must put the service into recovery rather than silently restart.
//!
//! # Persistence
//!
//! Defaults are hardcoded and live in this struct. GUI-driven persistence
//! (read/write through IPC, `nrr_service_state.db` row) is deferred to the
//! GUI BackendFacade.

use std::time::Duration;

// ── Defaults ──────────────────────────────────────────────────────────────────

/// Default upper bound on consecutive accept-thread restart attempts before
/// the supervisor retires the task. Tuned on the high side because a healthy
/// service can be hit by transient `ERROR_BROKEN_PIPE` / `ERROR_NO_DATA` from
/// flaky GUI/Tray clients without that meaning the service itself is broken.
pub const DEFAULT_IPC_MAX_RESTARTS: u32 = 20;

/// Default base for the exponential-backoff sleep between accept-thread
/// restarts. Mirrors the supervisor's hardcoded behaviour
/// (`100ms × attempt, capped at 1s`); kept here as a documented constant so
/// the GUI surface can render it without introspecting the supervisor.
pub const DEFAULT_IPC_BACKOFF_BASE: Duration = Duration::from_millis(100);

/// Default ceiling on the exponential-backoff sleep between accept-thread
/// restarts.
pub const DEFAULT_IPC_BACKOFF_CAP: Duration = Duration::from_secs(5);

// ── IpcAcceptFailurePolicy ────────────────────────────────────────────────────

/// What the supervisor should do when the IPC accept thread fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpcAcceptFailurePolicy {
    /// Default. Supervisor restarts the accept thread on failure with
    /// exponential backoff. After `max_restarts` consecutive failures the
    /// task is retired and the supervisor calls `HealthReporter::record(
    /// HealthComponent::Ipc, Critical, …)` so the GUI sees the channel as
    /// dead — but the service keeps enforcing routing policy.
    Recoverable {
        /// Maximum *additional* restart attempts before retirement (i.e.
        /// the task may run `1 + max_restarts` times total).
        max_restarts: u32,
        /// Base delay for the exponential backoff between restarts.
        ///
        /// **Currently informational** — the supervisor uses a hardcoded
        /// `100ms × attempt, capped at 1s` schedule (`runtime_loop.rs`).
        /// Surfaced here so the GUI render is consistent with what would
        /// be persisted once the supervisor accepts a per-task backoff.
        backoff_base: Duration,
        /// Ceiling on the exponential backoff (informational; see
        /// `backoff_base`).
        backoff_cap: Duration,
    },
    /// Strict fail-fast. Any accept-thread failure flips the service to
    /// `RecoveryRequired` immediately — no restart, no degraded mode.
    /// Intended for compliance scenarios where the operator must
    /// intervene.
    Critical,
}

impl Default for IpcAcceptFailurePolicy {
    fn default() -> Self {
        Self::Recoverable {
            max_restarts: DEFAULT_IPC_MAX_RESTARTS,
            backoff_base: DEFAULT_IPC_BACKOFF_BASE,
            backoff_cap: DEFAULT_IPC_BACKOFF_CAP,
        }
    }
}

impl IpcAcceptFailurePolicy {
    /// Stable string slug for telemetry / IPC payloads. Pinned because the
    /// GUI renders human strings from locale keys, not from this slug.
    pub const fn slug(&self) -> &'static str {
        match self {
            Self::Recoverable { .. } => "recoverable",
            Self::Critical => "critical",
        }
    }
}

// ── ServiceStabilityConfig ────────────────────────────────────────────────────

/// Aggregated stability settings the service runtime consults at startup.
///
/// Currently only carries the IPC accept policy; future blocks may extend
/// it (apply-layer restart policy, adapter-monitor jitter, …).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ServiceStabilityConfig {
    pub ipc_accept_policy: IpcAcceptFailurePolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_recoverable_with_canonical_constants() {
        match ServiceStabilityConfig::default().ipc_accept_policy {
            IpcAcceptFailurePolicy::Recoverable {
                max_restarts,
                backoff_base,
                backoff_cap,
            } => {
                assert_eq!(max_restarts, DEFAULT_IPC_MAX_RESTARTS);
                assert_eq!(backoff_base, DEFAULT_IPC_BACKOFF_BASE);
                assert_eq!(backoff_cap, DEFAULT_IPC_BACKOFF_CAP);
            }
            other => panic!("expected Recoverable, got {other:?}"),
        }
    }

    #[test]
    fn slugs_are_stable_strings() {
        assert_eq!(IpcAcceptFailurePolicy::default().slug(), "recoverable");
        assert_eq!(IpcAcceptFailurePolicy::Critical.slug(), "critical");
    }

    #[test]
    fn critical_variant_is_distinct() {
        let r = IpcAcceptFailurePolicy::default();
        let c = IpcAcceptFailurePolicy::Critical;
        assert_ne!(r, c);
    }
}
