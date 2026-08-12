//! Route availability check contracts for the routing decision pipeline.
//!
//! This module formalises the **availability check stage**: the fourth step of
//! the routing decision pipeline that verifies whether the route requested by
//! the match stage is actually reachable at the moment of the decision.
//!
//! # What the availability check does
//!
//! 1. Reads the pre-computed [`RouteAvailabilitySnapshot`] from `RuntimeInput`.
//! 2. Checks the availability of the **requested** route
//!    (`RouteRole::Primary` or `RouteRole::Secondary`).
//! 3. Applies staleness policy — marks the outcome as uncertain when the
//!    snapshot is too old.
//! 4. Produces an [`AvailabilityCheckOutcome`] that is passed to the
//!    Fail-Closed / Fail-Open arbitration stage.
//!
//! # All checks are synchronous reads of a pre-computed snapshot
//!
//! Availability checks must **never** perform I/O, network probes, or blocking
//! calls on the WFP callout path.  The snapshot is maintained asynchronously
//! by the service layer and injected into every `RuntimeInput`.  The pipeline
//! reads it once and discards it.
//!
//! # Interface lifecycle → route availability mapping
//!
//! ```text
//! InterfaceLifecycleState      RouteAvailabilityState
//! ───────────────────────      ──────────────────────
//! PresentActive                Available
//! PresentNoIp                  Degraded  (known problem: no IP)
//! TemporarilyMissing           Unknown   (no recent data; treat cautiously)
//! Disabled                     Unavailable
//! Disconnected                 Unavailable
//! ```
//!
//! # `secondary = None` vs `secondary = Some(Unavailable)`
//!
//! These are **different conditions** with different explain reason codes,
//! even though both cause the pipeline to fall back or block:
//!
//! | Condition                             | Explain reason code             |
//! |---------------------------------------|---------------------------------|
//! | `secondary` field is `None`           | `secondary_not_configured`      |
//! | `secondary` is `Some` but unreachable | `secondary_unavailable`         |
//!
//! # Behavior matrix when secondary is requested
//!
//! ```text
//! Secondary state          PreferSecondaryWhenAvailable   StrictSecondaryFailClosed
//! ─────────────────────    ────────────────────────────   ─────────────────────────
//! Available                route_secondary                route_secondary
//! Degraded                 fallback → primary             block (Fail-Closed)
//! Unavailable              fallback → primary             block (Fail-Closed)
//! Unknown (stale)          fallback → primary (+warn)     block (+uncertainty warn)
//! NotConfigured            fallback → primary             block (Fail-Closed)
//! ```
//!
//! The actual Fail-Closed / fallback arbitration is performed downstream.
//! `AvailabilityCheckOutcome` carries all the data that stage needs.
//!
//! # Snapshot staleness policy
//!
//! | Snapshot age                       | Classification    | Decision behaviour          |
//! |------------------------------------|-------------------|-----------------------------|
//! | ≤ `fresh_max_age_ms`               | `Fresh`           | Use as-is                   |
//! | `fresh_max_age_ms`…`stale_max_ms`  | `StaleUsable`     | Use + uncertainty warning   |
//! | > `stale_max_ms`                   | `StaleNotUsable`  | Treat all states as Unknown |

use std::time::SystemTime;

use nrr_shared::{RouteBehaviorMode, RouteRole};

// ── InterfaceLifecycleState ───────────────────────────────────────────────────

/// Runtime lifecycle state of a network interface, as observed by the Windows
/// adapter monitor.
///
/// This enum is the authoritative input to the
/// [`interface_lifecycle_to_availability`] mapping function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceLifecycleState {
    /// Interface is up and has at least one assigned IP address.
    PresentActive,
    /// Interface is up but has no IP address assigned (e.g. DHCP pending,
    /// cable connected but unconfigured).
    PresentNoIp,
    /// Interface was present recently but is temporarily absent from the OS
    /// adapter list (e.g. driver reinitialisation, brief disconnect).
    TemporarilyMissing,
    /// Interface is administratively disabled.
    Disabled,
    /// Interface is physically disconnected (cable unplugged, Wi-Fi off).
    Disconnected,
}

// ── RouteAvailabilityState ────────────────────────────────────────────────────

/// Availability state of a single route adapter, as assessed by the
/// availability check stage.
///
/// # Degraded vs Unknown
///
/// - **`Degraded`** — the adapter has a *known, specific* problem.  The service
///   has recent data and the problem is identified (e.g. no IP address).
/// - **`Unknown`** — the service has *insufficient fresh data*.  The adapter
///   may be fine or may not — we cannot tell.  Treated conservatively:
///   `PreferSecondaryWhenAvailable` falls back to primary; `StrictFail-Closed`
///   blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteAvailabilityState {
    /// Adapter is up, has an IP, and passes health checks.
    Available,
    /// Adapter is present but has a known problem (e.g. `PresentNoIp`).
    Degraded,
    /// Adapter is disabled, disconnected, or confirmed unreachable.
    Unavailable,
    /// No fresh availability data — the snapshot is too old or the adapter
    /// was temporarily missing when the snapshot was taken.
    Unknown,
}

impl RouteAvailabilityState {
    /// Returns `true` only when the state is unambiguously `Available`.
    pub fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }

    /// Returns `true` when routing via this adapter should be refused
    /// (for Fail-Closed policies).
    pub fn blocks_routing(self) -> bool {
        !matches!(self, Self::Available)
    }
}

/// Maps an [`InterfaceLifecycleState`] to a [`RouteAvailabilityState`].
///
/// This is the canonical mapping from raw interface state to the
/// routing-decision vocabulary.
pub fn interface_lifecycle_to_availability(
    state: InterfaceLifecycleState,
) -> RouteAvailabilityState {
    match state {
        InterfaceLifecycleState::PresentActive => RouteAvailabilityState::Available,
        InterfaceLifecycleState::PresentNoIp => RouteAvailabilityState::Degraded,
        InterfaceLifecycleState::TemporarilyMissing => RouteAvailabilityState::Unknown,
        InterfaceLifecycleState::Disabled => RouteAvailabilityState::Unavailable,
        InterfaceLifecycleState::Disconnected => RouteAvailabilityState::Unavailable,
    }
}

// ── AvailabilityReason ────────────────────────────────────────────────────────

/// Specific reason attached to a non-`Available` route state.
///
/// Carried in [`RouteAdapterAvailability`] and surfaced in explain output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvailabilityReason {
    /// Adapter is present but has no IP address assigned.
    NoIpAddress,
    /// Adapter is administratively disabled.
    InterfaceDisabled,
    /// Physical link is down (cable unplugged, Wi-Fi disconnected).
    PhysicalLinkDown,
    /// Adapter was briefly absent from the OS adapter list.
    TemporarilyMissing,
    /// The availability snapshot is too old to trust.
    SnapshotStale,
    /// Secondary adapter has not been configured by the user.
    NotConfigured,
}

// ── RouteAdapterAvailability ──────────────────────────────────────────────────

/// Full availability assessment for a single route adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteAdapterAvailability {
    /// Assessed availability state.
    pub state: RouteAvailabilityState,
    /// Observed interface lifecycle state that produced this assessment.
    pub lifecycle: InterfaceLifecycleState,
    /// Optional specific reason for a non-`Available` state.
    pub reason: Option<AvailabilityReason>,
}

impl RouteAdapterAvailability {
    /// Constructs availability from an interface lifecycle state, deriving
    /// the reason automatically.
    pub fn from_lifecycle(lifecycle: InterfaceLifecycleState) -> Self {
        let state = interface_lifecycle_to_availability(lifecycle);
        let reason = match lifecycle {
            InterfaceLifecycleState::PresentNoIp => Some(AvailabilityReason::NoIpAddress),
            InterfaceLifecycleState::TemporarilyMissing => {
                Some(AvailabilityReason::TemporarilyMissing)
            }
            InterfaceLifecycleState::Disabled => Some(AvailabilityReason::InterfaceDisabled),
            InterfaceLifecycleState::Disconnected => Some(AvailabilityReason::PhysicalLinkDown),
            InterfaceLifecycleState::PresentActive => None,
        };
        Self {
            state,
            lifecycle,
            reason,
        }
    }
}

// ── SecondaryAvailabilityStatus ───────────────────────────────────────────────

/// Availability status of the secondary route adapter, distinguishing between
/// "not configured" and "configured but unavailable".
///
/// This distinction must be preserved all the way to the explain output —
/// the two cases have different reason codes and different UI messaging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecondaryAvailabilityStatus {
    /// No secondary adapter has been configured by the user.
    /// Explain reason: `secondary_not_configured`.
    NotConfigured,
    /// Secondary adapter is configured; the inner value describes its state.
    Configured(RouteAdapterAvailability),
}

impl SecondaryAvailabilityStatus {
    /// Returns the availability state, or `Unavailable` if not configured.
    pub fn state(&self) -> RouteAvailabilityState {
        match self {
            Self::NotConfigured => RouteAvailabilityState::Unavailable,
            Self::Configured(a) => a.state,
        }
    }

    /// Returns `true` only when secondary is configured **and** available.
    pub fn is_routable(&self) -> bool {
        matches!(
            self,
            Self::Configured(RouteAdapterAvailability {
                state: RouteAvailabilityState::Available,
                ..
            })
        )
    }
}

// ── SnapshotStaleness ─────────────────────────────────────────────────────────

/// Staleness classification of a [`RouteAvailabilitySnapshot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotStaleness {
    /// Within the fresh window — use as-is.
    Fresh,
    /// Expired but within the stale-usable window — use with uncertainty warning.
    StaleUsable,
    /// Too old to trust — treat all contained states as `Unknown`.
    StaleNotUsable,
}

impl SnapshotStaleness {
    /// Returns `true` if the snapshot is usable for routing decisions.
    pub fn is_usable(self) -> bool {
        matches!(self, Self::Fresh | Self::StaleUsable)
    }
}

// ── SnapshotFreshnessThresholds ───────────────────────────────────────────────

/// Age thresholds for classifying availability snapshot staleness.
///
/// This is a **named contract** — the service layer must refresh the
/// availability snapshot more frequently than `fresh_max_age_ms`.
///
/// Default values:
///
/// | Threshold            | Default   | Rationale                            |
/// |----------------------|-----------|--------------------------------------|
/// | `fresh_max_age_ms`   | 5 000 ms  | Service checks adapters every ~2 s   |
/// | `stale_max_age_ms`   | 30 000 ms | 30 s is the absolute trust ceiling   |
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotFreshnessThresholds {
    /// Maximum snapshot age (ms) to be classified as `Fresh`.
    pub fresh_max_age_ms: u32,
    /// Maximum snapshot age (ms) to be classified as `StaleUsable`.
    /// Snapshots older than this are `StaleNotUsable`.
    pub stale_max_age_ms: u32,
}

impl SnapshotFreshnessThresholds {
    /// Default production thresholds.
    pub fn default_production() -> Self {
        Self {
            fresh_max_age_ms: 5_000,
            stale_max_age_ms: 30_000,
        }
    }

    /// Classifies the snapshot age in milliseconds.
    pub fn classify(&self, age_ms: u32) -> SnapshotStaleness {
        if age_ms <= self.fresh_max_age_ms {
            SnapshotStaleness::Fresh
        } else if age_ms <= self.stale_max_age_ms {
            SnapshotStaleness::StaleUsable
        } else {
            SnapshotStaleness::StaleNotUsable
        }
    }
}

// ── AvailabilityCheckSource ───────────────────────────────────────────────────

/// How the availability snapshot was produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvailabilityCheckSource {
    /// Live snapshot pre-computed by the service adapter monitor.
    ServicePrecomputed,
    /// Synthetic snapshot injected by a test harness.
    TestHarness,
}

// ── RouteAvailabilitySnapshot ─────────────────────────────────────────────────

/// Pre-computed availability snapshot for both route adapters, as of
/// `taken_at`.
///
/// Constructed by the service layer and injected into `RuntimeInput`.
/// The pipeline reads it once during the availability check stage and must
/// not refresh it mid-decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteAvailabilitySnapshot {
    /// Availability of the primary route adapter.
    pub primary: RouteAdapterAvailability,
    /// Availability status of the secondary route adapter.
    pub secondary: SecondaryAvailabilityStatus,
    /// Wall-clock time when this snapshot was taken.
    pub taken_at: SystemTime,
    /// Age of the snapshot at decision time (ms).
    /// Computed by the service layer before injecting into `RuntimeInput`.
    pub age_ms: u32,
    /// Staleness classification derived from `age_ms`.
    pub staleness: SnapshotStaleness,
    /// Source of this snapshot.
    pub check_source: AvailabilityCheckSource,
}

impl RouteAvailabilitySnapshot {
    /// Returns the effective availability state of `role`, accounting for
    /// staleness — if the snapshot is `StaleNotUsable`, all states are
    /// downgraded to `Unknown`.
    pub fn effective_state(&self, role: RouteRole) -> RouteAvailabilityState {
        if self.staleness == SnapshotStaleness::StaleNotUsable {
            return RouteAvailabilityState::Unknown;
        }
        match role {
            RouteRole::Primary => self.primary.state,
            RouteRole::Secondary => self.secondary.state(),
        }
    }
}

// ── AvailabilityExplainData ───────────────────────────────────────────────────

/// Explain fields produced by the availability check stage.
///
/// All fields are propagated into the final explain output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailabilityExplainData {
    /// Route role that was requested by the match stage.
    pub requested_route: RouteRole,
    /// Effective availability state of the requested route at decision time.
    pub observed_state: RouteAvailabilityState,
    /// Whether the availability data carried uncertainty (stale snapshot).
    pub stale_marker: Option<SnapshotStaleness>,
    /// Reason for the observed non-`Available` state, if applicable.
    pub unavailability_reason: Option<AvailabilityReason>,
    /// Whether secondary was not configured (as opposed to configured but down).
    pub secondary_not_configured: bool,
}

// ── AvailabilityCheckOutcome ──────────────────────────────────────────────────

/// Output of the availability check stage — input to the Fail-Closed / Fail-Open
/// arbitration stage.
///
/// # Variants
///
/// - [`Available`] — the requested route is up; proceed to arbitration as-is.
/// - [`SecondaryNotConfigured`] — secondary was requested but never configured.
/// - [`SecondaryNotReachable`] — secondary configured but degraded/unavailable.
/// - [`SecondaryUnknown`] — secondary state unclear (stale snapshot).
/// - [`PrimaryDegraded`] — primary has a known problem; note in explain but
///   do not block (no Fail-Closed semantics for primary in Free edition).
///
/// The `behavior_mode` field is forwarded to the arbitration stage so it can
/// apply the correct Fail-Closed or Fail-Open policy without needing to
/// re-read `RuntimeInput`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AvailabilityCheckOutcome {
    /// Requested route is available — proceed normally.
    Available {
        route: RouteRole,
        explain: AvailabilityExplainData,
    },
    /// Secondary was requested but has not been configured.
    /// Explain reason: `secondary_not_configured`.
    SecondaryNotConfigured {
        behavior_mode: RouteBehaviorMode,
        explain: AvailabilityExplainData,
    },
    /// Secondary is configured but currently degraded or unavailable.
    /// Explain reason: `secondary_unavailable`.
    SecondaryNotReachable {
        state: RouteAvailabilityState,
        reason: Option<AvailabilityReason>,
        behavior_mode: RouteBehaviorMode,
        explain: AvailabilityExplainData,
    },
    /// Secondary availability is unknown due to a stale snapshot.
    /// Treated as unavailable by conservative policies.
    SecondaryUnknown {
        staleness: SnapshotStaleness,
        behavior_mode: RouteBehaviorMode,
        explain: AvailabilityExplainData,
    },
    /// Primary is degraded — note in explain, but do not block in Free edition.
    PrimaryDegraded {
        state: RouteAvailabilityState,
        reason: Option<AvailabilityReason>,
        explain: AvailabilityExplainData,
    },
}

impl AvailabilityCheckOutcome {
    /// Returns `true` when the outcome allows routing to proceed without a
    /// Fail-Closed block (i.e. the requested route is available).
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    /// Returns `true` when secondary routing was attempted but is not possible,
    /// requiring the arbitration stage to apply its Fail-Closed or fallback
    /// policy.
    pub fn requires_fail_policy(&self) -> bool {
        matches!(
            self,
            Self::SecondaryNotConfigured { .. }
                | Self::SecondaryNotReachable { .. }
                | Self::SecondaryUnknown { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    // ── interface_lifecycle_to_availability ───────────────────────────────────

    #[test]
    fn present_active_maps_to_available() {
        assert_eq!(
            interface_lifecycle_to_availability(InterfaceLifecycleState::PresentActive),
            RouteAvailabilityState::Available
        );
    }

    #[test]
    fn present_no_ip_maps_to_degraded() {
        assert_eq!(
            interface_lifecycle_to_availability(InterfaceLifecycleState::PresentNoIp),
            RouteAvailabilityState::Degraded
        );
    }

    #[test]
    fn temporarily_missing_maps_to_unknown() {
        assert_eq!(
            interface_lifecycle_to_availability(InterfaceLifecycleState::TemporarilyMissing),
            RouteAvailabilityState::Unknown
        );
    }

    #[test]
    fn disabled_maps_to_unavailable() {
        assert_eq!(
            interface_lifecycle_to_availability(InterfaceLifecycleState::Disabled),
            RouteAvailabilityState::Unavailable
        );
    }

    #[test]
    fn disconnected_maps_to_unavailable() {
        assert_eq!(
            interface_lifecycle_to_availability(InterfaceLifecycleState::Disconnected),
            RouteAvailabilityState::Unavailable
        );
    }

    // ── RouteAvailabilityState helpers ────────────────────────────────────────

    #[test]
    fn available_state_is_available() {
        assert!(RouteAvailabilityState::Available.is_available());
        assert!(!RouteAvailabilityState::Degraded.is_available());
        assert!(!RouteAvailabilityState::Unavailable.is_available());
        assert!(!RouteAvailabilityState::Unknown.is_available());
    }

    #[test]
    fn non_available_states_block_routing() {
        assert!(!RouteAvailabilityState::Available.blocks_routing());
        assert!(RouteAvailabilityState::Degraded.blocks_routing());
        assert!(RouteAvailabilityState::Unavailable.blocks_routing());
        assert!(RouteAvailabilityState::Unknown.blocks_routing());
    }

    // ── RouteAdapterAvailability::from_lifecycle ──────────────────────────────

    #[test]
    fn from_lifecycle_present_active_no_reason() {
        let a = RouteAdapterAvailability::from_lifecycle(InterfaceLifecycleState::PresentActive);
        assert_eq!(a.state, RouteAvailabilityState::Available);
        assert!(a.reason.is_none());
    }

    #[test]
    fn from_lifecycle_present_no_ip_has_reason() {
        let a = RouteAdapterAvailability::from_lifecycle(InterfaceLifecycleState::PresentNoIp);
        assert_eq!(a.state, RouteAvailabilityState::Degraded);
        assert_eq!(a.reason, Some(AvailabilityReason::NoIpAddress));
    }

    #[test]
    fn from_lifecycle_disconnected_has_physical_link_down_reason() {
        let a = RouteAdapterAvailability::from_lifecycle(InterfaceLifecycleState::Disconnected);
        assert_eq!(a.state, RouteAvailabilityState::Unavailable);
        assert_eq!(a.reason, Some(AvailabilityReason::PhysicalLinkDown));
    }

    #[test]
    fn from_lifecycle_disabled_has_disabled_reason() {
        let a = RouteAdapterAvailability::from_lifecycle(InterfaceLifecycleState::Disabled);
        assert_eq!(a.state, RouteAvailabilityState::Unavailable);
        assert_eq!(a.reason, Some(AvailabilityReason::InterfaceDisabled));
    }

    // ── SecondaryAvailabilityStatus ───────────────────────────────────────────

    #[test]
    fn secondary_not_configured_state_is_unavailable() {
        assert_eq!(
            SecondaryAvailabilityStatus::NotConfigured.state(),
            RouteAvailabilityState::Unavailable
        );
    }

    #[test]
    fn secondary_not_configured_is_not_routable() {
        assert!(!SecondaryAvailabilityStatus::NotConfigured.is_routable());
    }

    #[test]
    fn secondary_configured_available_is_routable() {
        let avail = SecondaryAvailabilityStatus::Configured(
            RouteAdapterAvailability::from_lifecycle(InterfaceLifecycleState::PresentActive),
        );
        assert!(avail.is_routable());
    }

    #[test]
    fn secondary_configured_degraded_is_not_routable() {
        let avail = SecondaryAvailabilityStatus::Configured(
            RouteAdapterAvailability::from_lifecycle(InterfaceLifecycleState::PresentNoIp),
        );
        assert!(!avail.is_routable());
    }

    #[test]
    fn secondary_not_configured_vs_unavailable_are_distinct_variants() {
        let not_cfg = SecondaryAvailabilityStatus::NotConfigured;
        let unavail = SecondaryAvailabilityStatus::Configured(
            RouteAdapterAvailability::from_lifecycle(InterfaceLifecycleState::Disconnected),
        );
        // Both block routing but are structurally different (different explain reason)
        assert!(!not_cfg.is_routable());
        assert!(!unavail.is_routable());
        assert_ne!(not_cfg, unavail);
    }

    // ── SnapshotFreshnessThresholds ───────────────────────────────────────────

    #[test]
    fn freshness_thresholds_classify_fresh() {
        let t = SnapshotFreshnessThresholds::default_production();
        assert_eq!(t.classify(0), SnapshotStaleness::Fresh);
        assert_eq!(t.classify(5_000), SnapshotStaleness::Fresh);
    }

    #[test]
    fn freshness_thresholds_classify_stale_usable() {
        let t = SnapshotFreshnessThresholds::default_production();
        assert_eq!(t.classify(5_001), SnapshotStaleness::StaleUsable);
        assert_eq!(t.classify(30_000), SnapshotStaleness::StaleUsable);
    }

    #[test]
    fn freshness_thresholds_classify_stale_not_usable() {
        let t = SnapshotFreshnessThresholds::default_production();
        assert_eq!(t.classify(30_001), SnapshotStaleness::StaleNotUsable);
        assert_eq!(t.classify(u32::MAX), SnapshotStaleness::StaleNotUsable);
    }

    #[test]
    fn freshness_thresholds_default_fresh_lt_stale() {
        let t = SnapshotFreshnessThresholds::default_production();
        assert!(t.fresh_max_age_ms < t.stale_max_age_ms);
    }

    // ── SnapshotStaleness ─────────────────────────────────────────────────────

    #[test]
    fn staleness_fresh_and_stale_usable_are_usable() {
        assert!(SnapshotStaleness::Fresh.is_usable());
        assert!(SnapshotStaleness::StaleUsable.is_usable());
        assert!(!SnapshotStaleness::StaleNotUsable.is_usable());
    }

    // ── RouteAvailabilitySnapshot::effective_state ────────────────────────────

    fn make_snapshot(
        primary_lc: InterfaceLifecycleState,
        secondary: SecondaryAvailabilityStatus,
        staleness: SnapshotStaleness,
    ) -> RouteAvailabilitySnapshot {
        RouteAvailabilitySnapshot {
            primary: RouteAdapterAvailability::from_lifecycle(primary_lc),
            secondary,
            taken_at: UNIX_EPOCH,
            age_ms: 0,
            staleness,
            check_source: AvailabilityCheckSource::ServicePrecomputed,
        }
    }

    #[test]
    fn effective_state_returns_primary_when_fresh() {
        let snap = make_snapshot(
            InterfaceLifecycleState::PresentActive,
            SecondaryAvailabilityStatus::NotConfigured,
            SnapshotStaleness::Fresh,
        );
        assert_eq!(
            snap.effective_state(RouteRole::Primary),
            RouteAvailabilityState::Available
        );
    }

    #[test]
    fn effective_state_returns_secondary_when_configured_and_fresh() {
        let snap = make_snapshot(
            InterfaceLifecycleState::PresentActive,
            SecondaryAvailabilityStatus::Configured(RouteAdapterAvailability::from_lifecycle(
                InterfaceLifecycleState::PresentActive,
            )),
            SnapshotStaleness::Fresh,
        );
        assert_eq!(
            snap.effective_state(RouteRole::Secondary),
            RouteAvailabilityState::Available
        );
    }

    #[test]
    fn effective_state_downgrades_to_unknown_when_stale_not_usable() {
        let snap = make_snapshot(
            InterfaceLifecycleState::PresentActive,
            SecondaryAvailabilityStatus::Configured(RouteAdapterAvailability::from_lifecycle(
                InterfaceLifecycleState::PresentActive,
            )),
            SnapshotStaleness::StaleNotUsable,
        );
        // Even though both adapters appear "available" in snapshot, too stale → Unknown
        assert_eq!(
            snap.effective_state(RouteRole::Primary),
            RouteAvailabilityState::Unknown
        );
        assert_eq!(
            snap.effective_state(RouteRole::Secondary),
            RouteAvailabilityState::Unknown
        );
    }

    // ── AvailabilityCheckOutcome ───────────────────────────────────────────────

    fn explain(route: RouteRole, state: RouteAvailabilityState) -> AvailabilityExplainData {
        AvailabilityExplainData {
            requested_route: route,
            observed_state: state,
            stale_marker: None,
            unavailability_reason: None,
            secondary_not_configured: false,
        }
    }

    #[test]
    fn outcome_available_is_available() {
        let o = AvailabilityCheckOutcome::Available {
            route: RouteRole::Secondary,
            explain: explain(RouteRole::Secondary, RouteAvailabilityState::Available),
        };
        assert!(o.is_available());
        assert!(!o.requires_fail_policy());
    }

    #[test]
    fn outcome_secondary_not_configured_requires_fail_policy() {
        let o = AvailabilityCheckOutcome::SecondaryNotConfigured {
            behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
            explain: {
                let mut e = explain(RouteRole::Secondary, RouteAvailabilityState::Unavailable);
                e.secondary_not_configured = true;
                e
            },
        };
        assert!(!o.is_available());
        assert!(o.requires_fail_policy());
    }

    #[test]
    fn outcome_secondary_not_reachable_requires_fail_policy() {
        let o = AvailabilityCheckOutcome::SecondaryNotReachable {
            state: RouteAvailabilityState::Degraded,
            reason: Some(AvailabilityReason::NoIpAddress),
            behavior_mode: RouteBehaviorMode::PreferSecondaryWhenAvailable,
            explain: explain(RouteRole::Secondary, RouteAvailabilityState::Degraded),
        };
        assert!(!o.is_available());
        assert!(o.requires_fail_policy());
    }

    #[test]
    fn outcome_secondary_unknown_requires_fail_policy() {
        let o = AvailabilityCheckOutcome::SecondaryUnknown {
            staleness: SnapshotStaleness::StaleUsable,
            behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
            explain: {
                let mut e = explain(RouteRole::Secondary, RouteAvailabilityState::Unknown);
                e.stale_marker = Some(SnapshotStaleness::StaleUsable);
                e
            },
        };
        assert!(!o.is_available());
        assert!(o.requires_fail_policy());
    }

    #[test]
    fn outcome_primary_degraded_does_not_require_fail_policy() {
        // In Free edition, primary degraded is noted but not blocked
        let o = AvailabilityCheckOutcome::PrimaryDegraded {
            state: RouteAvailabilityState::Degraded,
            reason: Some(AvailabilityReason::NoIpAddress),
            explain: explain(RouteRole::Primary, RouteAvailabilityState::Degraded),
        };
        assert!(!o.is_available());
        assert!(!o.requires_fail_policy());
    }
}
