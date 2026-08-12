//! Routing decision pipeline — design contracts.
//!
//! This module formalises the **algorithm and runtime input boundary** for the
//! routing decision pipeline.  Concrete rule-engine logic and unit tests live
//! in a separate module; this module defines what the pipeline *receives* and
//! what the stages *are*, so that the rule engine has an unambiguous contract
//! to implement against.
//!
//! # Pipeline stages
//!
//! ```text
//! RuntimeInput
//!     │
//!     ▼  1. Normalization
//! NormalizedDecisionInput
//!     │
//!     ▼  2. FQDN / IP lookup
//! ResolvedDestination
//!     │
//!     ▼  3. Rule matching
//! MatchedRule | NoMatch
//!     │
//!     ▼  4. Route availability check
//! AvailabilityResult
//!     │
//!     ▼  5. Fail-Closed / Fail-Open arbitration
//! RouteDecision
//!     │
//!     ▼  6. Explain assembly
//! DecisionExplain
//! ```
//!
//! # Ownership boundary
//!
//! The pipeline **reads only the active service-owned revision**.  It must not:
//! - read UI preferences directly,
//! - read imported preset files from disk,
//! - read preview or scaffold state stored in `UiPreferences`.
//!
//! Route behaviour mode (Fail-Closed vs Fail-Open) and interface availability
//! are injected into `RuntimeInput` by the service layer, which is the
//! authoritative source of truth for active policy.

use std::net::IpAddr;
use std::time::SystemTime;

use crate::revision::RevisionId;
use nrr_shared::RouteBehaviorMode;

// ── ObservationSource ─────────────────────────────────────────────────────────

/// Origin of a routing observation fed into the pipeline.
///
/// The source affects how the pipeline treats missing or ambiguous context:
/// - `WfpCallback` inputs arrive from the Windows Filtering Platform and must
///   be processed with production latency constraints.
/// - `TestHarness` inputs are synthetic; the pipeline may apply relaxed
///   timeouts and emit richer diagnostic output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservationSource {
    /// Live observation from the Windows Filtering Platform callout driver.
    WfpCallback,
    /// Synthetic input from a test or diagnostic harness.
    TestHarness,
}

// ── ProcessContext ─────────────────────────────────────────────────────────────

/// Identity and context of the process initiating the network connection.
///
/// All string fields are optional because WFP does not guarantee that process
/// metadata is available at callback time (e.g. the process may have already
/// exited).  A pipeline stage that relies on process identity must handle the
/// `None` case by falling back to application-rule-less matching or default.
///
/// `browser_hint` is set when the process is a known browser executable. It
/// enables the experimental browser-stub feature (`DecisionFeatureFlags
/// ::browser_stub_experimental`) without requiring a full application rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessContext {
    /// OS process identifier.
    pub pid: u32,
    /// Basename of the executable (e.g. `"firefox.exe"`).  Normalised to
    /// lowercase.  `None` if the process metadata could not be resolved.
    pub process_name: Option<String>,
    /// Full filesystem path of the executable.  `None` when unavailable.
    pub process_path: Option<String>,
    /// PID of the parent process, if available.
    pub parent_pid: Option<u32>,
    /// True when the process has been identified as a known browser.  Used by
    /// the experimental browser-stub feature.  Default: `false`.
    pub browser_hint: bool,
}

// ── ProtocolHints ─────────────────────────────────────────────────────────────

/// Lightweight protocol and port context for the observed connection.
///
/// These fields are *hints* — they inform rule selection and explain output but
/// are not independently sufficient for routing decisions in Free edition.
/// This struct may be extended when port/protocol rules are introduced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolHints {
    /// IP protocol number (e.g. `6` = TCP, `17` = UDP).  `None` if unknown.
    pub ip_protocol: Option<u8>,
    /// Destination port.  `None` if the protocol does not use ports or the
    /// value was not available at observation time.
    pub destination_port: Option<u16>,
}

// ── DecisionFeatureFlags ──────────────────────────────────────────────────────

/// Feature gate flags that modify pipeline behaviour for a single decision.
///
/// Populated from `UiPreferences` by the service layer before the pipeline is
/// invoked.  The pipeline itself must not read `UiPreferences` directly.
///
/// All flags default to `false` (conservative, production-safe behaviour).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DecisionFeatureFlags {
    /// Enable the experimental browser-stub routing path.
    ///
    /// When `true` and `ProcessContext::browser_hint` is also `true`, the
    /// pipeline may select a stub route for browser traffic before consulting
    /// the normal rule table.  Disabled by default; marked experimental in UI.
    pub browser_stub_experimental: bool,
}

// ── RuntimeInput ─────────────────────────────────────────────────────────────

/// Complete, unprocessed input to the routing decision pipeline.
///
/// This is the authoritative contract between the WFP callout (or test
/// harness) and the pipeline.  No routing decision is made without a
/// `RuntimeInput`.  The pipeline must not mutate or cache this value — it
/// is consumed once and discarded after explain output is emitted.
///
/// # Field semantics
///
/// - `process_context` — who is making the connection.
/// - `destination_hostname` — the DNS name being resolved, if available.
///   `None` for direct-IP connections or when the DNS layer is bypassed.
/// - `destination_ip` — the IPv4 address of the destination, if already
///   resolved.  At least one of `destination_hostname` / `destination_ip`
///   must be `Some`; the pipeline returns an error if both are `None`.
/// - `protocol_hints` — lightweight protocol context.
/// - `active_revision_id` — the revision snapshot the pipeline must evaluate
///   against.  The service injects the currently active revision ID; the
///   pipeline verifies it matches the loaded snapshot.
/// - `route_behavior_mode` — Fail-Closed or Fail-Open policy for this
///   decision, as set by the active service-owned config.
/// - `interface_availability` — snapshot of primary/secondary adapter
///   availability at the moment of observation, provided by the service.
/// - `observed_at` — wall-clock time of the WFP observation.
/// - `observation_source` — `WfpCallback` or `TestHarness`.
/// - `feature_flags` — optional per-decision feature overrides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeInput {
    /// Identity and context of the originating process.
    pub process_context: ProcessContext,
    /// DNS name of the destination, if available.
    pub destination_hostname: Option<String>,
    /// Observed IP address of the destination, if available.
    ///
    /// The raw WFP observation — may be IPv4, IPv6, or IPv4-mapped IPv6.
    /// The normalization stage converts this to [`NormalizedIp`], rejecting
    /// native IPv6 as Pro-only in Free edition and normalising IPv4-mapped
    /// IPv6 to IPv4 with a warning.
    pub destination_ip: Option<IpAddr>,
    /// Protocol and port hints.
    pub protocol_hints: ProtocolHints,
    /// ID of the active policy revision this decision is evaluated against.
    pub active_revision_id: RevisionId,
    /// Active route behaviour mode (Fail-Closed / Fail-Open).
    pub route_behavior_mode: RouteBehaviorMode,
    /// Per-adapter availability snapshot injected by the service layer.
    pub interface_availability: InterfaceAvailabilitySnapshot,
    /// Wall-clock time when the WFP observation was captured.
    pub observed_at: SystemTime,
    /// Source of this observation.
    pub observation_source: ObservationSource,
    /// Per-decision feature flags populated from `UiPreferences`.
    pub feature_flags: DecisionFeatureFlags,
}

// ── InterfaceAvailabilitySnapshot ─────────────────────────────────────────────

/// Runtime availability of the primary and secondary route adapters at the
/// moment a routing decision is being made.
///
/// The service layer constructs this snapshot from its most recent adapter
/// health check and injects it into every `RuntimeInput`.  The pipeline must
/// not probe adapter state directly.
///
/// `secondary` is `None` when no secondary adapter has been configured by the
/// user.  This is distinct from `secondary = Some(status)` where the adapter
/// is configured but currently unavailable — the pipeline must treat these as
/// different conditions and emit different `reason` codes in explain output:
/// - `secondary = None` → explain reason `secondary_not_configured`
/// - `secondary = Some(AdapterAvailability::Unavailable)` → explain reason
///   `secondary_unavailable`
///
/// Both conditions result in routing to the default/primary route (or
/// Fail-Closed block, depending on `route_behavior_mode`), but they are
/// surfaced differently in logs and the explain panel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceAvailabilitySnapshot {
    /// Availability status of the primary route adapter.
    pub primary: AdapterAvailability,
    /// Availability status of the secondary route adapter.
    /// `None` if no secondary adapter has been configured.
    pub secondary: Option<AdapterAvailability>,
}

/// Runtime availability status of a single network adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterAvailability {
    /// Adapter is up and passes health checks.
    Available,
    /// Adapter is configured but currently unreachable or degraded.
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_feature_flags_default_is_conservative() {
        let flags = DecisionFeatureFlags::default();
        assert!(!flags.browser_stub_experimental);
    }

    #[test]
    fn protocol_hints_none_fields_allowed() {
        let hints = ProtocolHints {
            ip_protocol: None,
            destination_port: None,
        };
        assert!(hints.ip_protocol.is_none());
        assert!(hints.destination_port.is_none());
    }

    #[test]
    fn process_context_browser_hint_defaults_to_false_by_convention() {
        let ctx = ProcessContext {
            pid: 1234,
            process_name: Some("firefox.exe".to_owned()),
            process_path: None,
            parent_pid: None,
            browser_hint: false,
        };
        assert!(!ctx.browser_hint);
    }

    #[test]
    fn interface_availability_secondary_none_is_not_configured() {
        let snap = InterfaceAvailabilitySnapshot {
            primary: AdapterAvailability::Available,
            secondary: None,
        };
        // secondary = None means "not configured" — distinct from Unavailable.
        assert!(snap.secondary.is_none());
    }

    #[test]
    fn interface_availability_secondary_unavailable_is_distinct_from_not_configured() {
        let snap = InterfaceAvailabilitySnapshot {
            primary: AdapterAvailability::Available,
            secondary: Some(AdapterAvailability::Unavailable),
        };
        assert_eq!(snap.secondary, Some(AdapterAvailability::Unavailable));
    }
}
