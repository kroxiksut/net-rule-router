//! Input adapter and fixture support for the routing decision engine.
//!
//! # Responsibilities
//!
//! - [`normalize_runtime_input`] — converts a raw [`RuntimeInput`] to a
//!   [`NormalizedDecisionInput`] ready for the rule matching stage.
//! - [`collect_input_warnings`] — derives [`DecisionWarning`] entries from
//!   the normalised input, the lookup result, and the availability snapshot.
//! - [`test_support`] — fixture helpers for unit tests (always compiled so
//!   integration tests in `tests/` can use them too).
//!
//! # Ownership boundary
//!
//! - The adapter reads only [`RuntimeInput`] for normalization.
//! - [`LookupResult`] and [`RouteAvailabilitySnapshot`] are injected by the
//!   service/cache layer; the engine never resolves DNS or polls adapters.
//! - All functions are pure and deterministic — no I/O, no side effects.

use std::net::IpAddr;

use crate::decision_availability::{RouteAvailabilitySnapshot, SnapshotStaleness};
use crate::decision_engine::DecisionWarning;
use crate::decision_lookup::{CacheEntryState, LookupResult};
use crate::decision_normalization::{
    InputAvailabilitySignal, MatchClassAvailability, NormalizationError, NormalizationWarning,
    NormalizedAppIdentity, NormalizedDecisionInput, NormalizedHostname, NormalizedIp,
};
use crate::decision_pipeline::{ProcessContext, RuntimeInput};

// ── normalize_runtime_input ───────────────────────────────────────────────────

/// Converts a raw [`RuntimeInput`] into a [`NormalizedDecisionInput`].
///
/// Normalization rules:
/// - **hostname**: lowercase, trailing-dot removal, IDNA2008 (Unicode → ASCII).
/// - **IP**: IPv4 passes through; IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is
///   converted to IPv4 with a warning; native IPv6 becomes
///   [`NormalizedIp::ProOnlyNativeIpv6`] and blocks `ExactIp` matching.
/// - **process identity**: lowercase, path stripped to basename, `.exe`
///   suffix ensured.
///
/// Normalization errors are scoped to their match class — the pipeline
/// continues with the remaining classes rather than failing entirely.
pub fn normalize_runtime_input(input: &RuntimeInput) -> NormalizedDecisionInput {
    let mut top_warnings: Vec<NormalizationWarning> = Vec::new();
    let mut availability_signals: Vec<InputAvailabilitySignal> = Vec::new();

    let (hostname, hn_warnings) = normalize_hostname_value(input.destination_hostname.as_deref());
    top_warnings.extend(hn_warnings);
    if matches!(hostname, NormalizedHostname::Unavailable) {
        availability_signals.push(InputAvailabilitySignal::HostnameUnavailable);
    }

    let (ip, ip_warnings) = normalize_ip_value(input.destination_ip);
    top_warnings.extend(ip_warnings);
    if matches!(ip, NormalizedIp::Unavailable) {
        availability_signals.push(InputAvailabilitySignal::IpUnavailable);
    }

    let (app_identity, app_signals) = normalize_app_identity_value(&input.process_context);
    availability_signals.extend(app_signals);

    let match_class_availability = derive_match_class_availability(&hostname, &ip, &app_identity);

    NormalizedDecisionInput {
        hostname,
        ip,
        app_identity,
        match_class_availability,
        availability_signals,
        warnings: top_warnings,
    }
}

// ── collect_input_warnings ────────────────────────────────────────────────────

/// Derives [`DecisionWarning`] entries from the normalised input, lookup
/// result, and availability snapshot.
///
/// Called once per decision, before the matching stage.  The returned list is
/// stored in [`DecisionOutcome::warnings`].
pub fn collect_input_warnings(
    input: &NormalizedDecisionInput,
    lookup: &LookupResult,
    availability: &RouteAvailabilitySnapshot,
) -> Vec<DecisionWarning> {
    let mut warnings = Vec::new();

    for signal in &input.availability_signals {
        match signal {
            InputAvailabilitySignal::HostnameUnavailable => {
                warnings.push(DecisionWarning::HostnameUnavailable);
            }
            InputAvailabilitySignal::IpUnavailable => {
                warnings.push(DecisionWarning::IpUnavailable);
            }
            InputAvailabilitySignal::AppContextUnavailable => {
                warnings.push(DecisionWarning::AppContextUnavailable);
            }
        }
    }

    if let Some(identity) = &input.app_identity {
        let is_weak = identity.warnings.iter().any(|w| {
            matches!(
                w,
                NormalizationWarning::ApplicationBareProcessNameWeakIdentity { .. }
            )
        });
        if is_weak {
            warnings.push(DecisionWarning::WeakAppIdentityMatch);
        }
    }

    if let Some(freshness) = &lookup.explain_data.standard.freshness {
        if matches!(
            freshness,
            CacheEntryState::StaleUsable | CacheEntryState::StaleNotUsable
        ) {
            warnings.push(DecisionWarning::LookupStale);
        }
    }

    match availability.staleness {
        SnapshotStaleness::StaleUsable | SnapshotStaleness::StaleNotUsable => {
            warnings.push(DecisionWarning::AvailabilityStale);
        }
        SnapshotStaleness::Fresh => {}
    }
    if availability.staleness == SnapshotStaleness::StaleNotUsable {
        warnings.push(DecisionWarning::AvailabilityUnknown);
    }

    warnings
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn normalize_hostname_value(raw: Option<&str>) -> (NormalizedHostname, Vec<NormalizationWarning>) {
    let Some(h) = raw else {
        return (NormalizedHostname::Unavailable, vec![]);
    };
    let trimmed = h.trim();
    if trimmed.is_empty() {
        return (
            NormalizedHostname::Invalid {
                raw: h.to_owned(),
                error: NormalizationError::DomainEmpty,
            },
            vec![],
        );
    }
    let mut warnings = Vec::new();
    let without_dot = if let Some(stripped) = trimmed.strip_suffix('.') {
        warnings.push(NormalizationWarning::DomainTrailingDotRemoved);
        stripped
    } else {
        trimmed
    };
    let lowercased = without_dot.to_lowercase();
    if lowercased.is_ascii() {
        if lowercased
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            (NormalizedHostname::Valid(lowercased), warnings)
        } else {
            (
                NormalizedHostname::Invalid {
                    raw: h.to_owned(),
                    error: NormalizationError::DomainInvalidCharacters { raw: h.to_owned() },
                },
                warnings,
            )
        }
    } else {
        match idna::domain_to_ascii(&lowercased) {
            Ok(ascii) => {
                if ascii != lowercased {
                    warnings.push(NormalizationWarning::DomainPunycodeEncoded {
                        original: lowercased,
                        punycode: ascii.clone(),
                    });
                }
                (NormalizedHostname::Valid(ascii), warnings)
            }
            Err(_) => (
                NormalizedHostname::Invalid {
                    raw: h.to_owned(),
                    error: NormalizationError::DomainIdnaFailed { raw: h.to_owned() },
                },
                warnings,
            ),
        }
    }
}

fn normalize_ip_value(raw: Option<IpAddr>) -> (NormalizedIp, Vec<NormalizationWarning>) {
    match raw {
        None => (NormalizedIp::Unavailable, vec![]),
        Some(IpAddr::V4(v4)) => (NormalizedIp::ValidIpv4(v4), vec![]),
        Some(IpAddr::V6(v6)) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                (
                    NormalizedIp::ValidIpv4(v4),
                    vec![NormalizationWarning::Ipv4MappedIpv6NormalizedToIpv4 {
                        original: v6,
                        normalized: v4,
                    }],
                )
            } else {
                (NormalizedIp::ProOnlyNativeIpv6 { addr: v6 }, vec![])
            }
        }
    }
}

fn normalize_app_identity_value(
    ctx: &ProcessContext,
) -> (Option<NormalizedAppIdentity>, Vec<InputAvailabilitySignal>) {
    let Some(raw_name) = ctx.process_name.as_deref() else {
        return (None, vec![InputAvailabilitySignal::AppContextUnavailable]);
    };
    let trimmed = raw_name.trim();
    if trimmed.is_empty() {
        return (None, vec![InputAvailabilitySignal::AppContextUnavailable]);
    }
    let mut norm_warnings: Vec<NormalizationWarning> = Vec::new();
    let original_path = ctx.process_path.clone();
    let contains_sep = trimmed.contains('/') || trimmed.contains('\\');

    let filename = if contains_sep {
        let stripped = trimmed
            .split(['/', '\\'])
            .rev()
            .find(|s| !s.is_empty())
            .unwrap_or(trimmed)
            .to_owned();
        norm_warnings.push(NormalizationWarning::ApplicationPathStripped {
            original_path: trimmed.to_owned(),
            normalized_name: stripped.clone(),
        });
        stripped
    } else {
        trimmed.to_owned()
    };

    let lowercased = filename.to_lowercase();
    let process_name = if lowercased.ends_with(".exe") {
        lowercased
    } else {
        let with_exe = format!("{lowercased}.exe");
        norm_warnings.push(NormalizationWarning::ApplicationExeSuffixAdded {
            original: lowercased,
        });
        with_exe
    };

    if process_name.trim_end_matches(".exe").is_empty() {
        return (None, vec![InputAvailabilitySignal::AppContextUnavailable]);
    }

    // Bare process name (no original path and no path separator in input) = weak identity.
    if original_path.is_none() && !contains_sep {
        norm_warnings.push(
            NormalizationWarning::ApplicationBareProcessNameWeakIdentity {
                process_name: process_name.clone(),
            },
        );
    }

    (
        Some(NormalizedAppIdentity {
            process_name,
            original_path,
            warnings: norm_warnings,
        }),
        vec![],
    )
}

fn derive_match_class_availability(
    hostname: &NormalizedHostname,
    ip: &NormalizedIp,
    app_identity: &Option<NormalizedAppIdentity>,
) -> MatchClassAvailability {
    let hostname_block = match hostname {
        NormalizedHostname::Valid(_) => None,
        NormalizedHostname::Unavailable => Some(NormalizationError::DomainEmpty),
        NormalizedHostname::Invalid { error, .. } => Some(error.clone()),
    };
    let ip_block = match ip {
        NormalizedIp::ValidIpv4(_) | NormalizedIp::Unavailable => None,
        NormalizedIp::ProOnlyNativeIpv6 { addr } => {
            Some(NormalizationError::IpNativeIpv6ProOnly { addr: *addr })
        }
    };
    let app_block = if app_identity.is_none() {
        Some(NormalizationError::ApplicationNameEmpty)
    } else {
        None
    };
    MatchClassAvailability {
        exact_fqdn: hostname_block.clone(),
        suffix_domain: hostname_block.clone(),
        zone: hostname_block,
        exact_ip: ip_block,
        application: app_block,
    }
}

// ── Synthetic / probe matching ────────────────────────────────────────────────

/// Evaluates a synthetic explain/probe *sample* (destination hostname, observed
/// IP, and optional originating process) against a rule book using the **real**
/// matching engine ([`crate::decision_rules_matching::match_rules`]).
///
/// This is the single blessed entry point for "which rule would the engine pick
/// for this destination?" tooling. The diagnostics explain probe — and any
/// future route simulator — MUST go through here instead of re-implementing
/// matching, so they cannot drift from production semantics: the `enabled` flag,
/// tier ordering, the Zone↔ExactIp priority policy, and the app-filter
/// AND-semantics are all honoured exactly as in routing.
///
/// Pure, deterministic, and I/O-free — no clock, DNS, or storage access. Adapter
/// availability and DNS lookup are modelled as "primary available / nothing
/// resolved": correct for a rule-matching question, which asks *which rule
/// matches*, not *what the live final action is* (the latter depends on adapter
/// availability and fail-policy and is intentionally out of scope here).
pub fn match_sample(
    rule_book: &crate::canonical::CanonicalRuleBook,
    hostname: Option<&str>,
    observed_ip: Option<std::net::IpAddr>,
    process_name: Option<&str>,
    zone_policy: crate::decision_matching::ZonePriorityPolicy,
    behavior_mode: crate::RouteBehaviorMode,
) -> crate::decision_matching::RequestedRouteDecision {
    use crate::decision_lookup::{
        LookupExplainData, LookupExtendedMetadata, LookupResult, LookupStandardSignals,
    };
    use crate::decision_pipeline::{
        AdapterAvailability, DecisionFeatureFlags, InterfaceAvailabilitySnapshot,
        ObservationSource, ProcessContext, ProtocolHints, RuntimeInput,
    };
    use crate::decision_rules_matching::match_rules;
    use crate::revision::RevisionId;

    use std::time::SystemTime;

    let runtime = RuntimeInput {
        process_context: ProcessContext {
            pid: 0,
            process_name: process_name.map(str::to_owned),
            process_path: None,
            parent_pid: None,
            browser_hint: false,
        },
        destination_hostname: hostname.map(str::to_owned),
        destination_ip: observed_ip,
        protocol_hints: ProtocolHints {
            ip_protocol: None,
            destination_port: None,
        },
        // Pure filler: `match_rules` never reads the revision id, clock,
        // adapter availability, or observation source. A static, well-formed
        // value keeps the helper deterministic. `TestHarness` is the honest
        // provenance — this is not a live WFP observation.
        active_revision_id: RevisionId::from_prefixed_string("rev-probe".to_owned())
            .unwrap_or_else(|_| panic!("static probe revision id must be well-formed")),
        // `behavior_mode` is NOT filler: it decides the default route for an
        // unmatched sample, so the explain probe must reflect the caller's
        // real per-SID mode (passed in).
        route_behavior_mode: behavior_mode,
        interface_availability: InterfaceAvailabilitySnapshot {
            primary: AdapterAvailability::Available,
            secondary: None,
        },
        observed_at: SystemTime::UNIX_EPOCH,
        observation_source: ObservationSource::TestHarness,
        feature_flags: DecisionFeatureFlags::default(),
    };
    let input = normalize_runtime_input(&runtime);
    let lookup = LookupResult {
        selected_ip: None,
        is_multi_ip: false,
        has_conflict: false,
        explain_data: LookupExplainData {
            standard: LookupStandardSignals {
                cache_hit: false,
                freshness: None,
                source: None,
                errors: Vec::new(),
            },
            extended: LookupExtendedMetadata {
                all_resolved_ips: Vec::new(),
                reverse_hostnames: Vec::new(),
                selected_entry_ttl_secs: None,
                selected_entry_resolved_at: None,
            },
        },
    };
    match_rules(&input, &lookup, rule_book, zone_policy, behavior_mode)
}

#[cfg(test)]
mod match_sample_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::match_sample;
    use crate::canonical::{
        CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
    };
    use crate::decision_matching::{MatchClass, RequestedRouteDecision, ZonePriorityPolicy};
    use crate::RuleId;

    fn rule(id: &str, enabled: bool, am: CanonicalAddressMatch) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_owned()),
            enabled,
            address_match: Some(am),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn book_primary(rules: Vec<CanonicalRule>) -> CanonicalRuleBook {
        CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(rules),
            secondary: CanonicalRuleSet::from_rules(Vec::new()),
        }
    }

    fn matched_class(d: &RequestedRouteDecision) -> Option<MatchClass> {
        match d {
            RequestedRouteDecision::MatchedRoute { candidate } => Some(candidate.match_class),
            RequestedRouteDecision::DefaultRoute { .. } => None,
        }
    }

    #[test]
    fn enabled_zone_rule_matches_host_in_zone() {
        let book = book_primary(vec![rule(
            "R-0001",
            true,
            CanonicalAddressMatch::Zone("ru".to_owned()),
        )]);
        let d = match_sample(
            &book,
            Some("example.ru"),
            None,
            None,
            ZonePriorityPolicy::default(),
            crate::RouteBehaviorMode::PreferPrimary,
        );
        assert_eq!(matched_class(&d), Some(MatchClass::Zone));
    }

    #[test]
    fn disabled_zone_rule_does_not_match() {
        // Regression: the diagnostics explain probe used to report disabled
        // rules as matching because it bypassed `match_rules`. `match_sample`
        // must honour `enabled` exactly like production routing.
        let book = book_primary(vec![rule(
            "R-0001",
            false,
            CanonicalAddressMatch::Zone("ru".to_owned()),
        )]);
        let d = match_sample(
            &book,
            Some("example.ru"),
            None,
            None,
            ZonePriorityPolicy::default(),
            crate::RouteBehaviorMode::PreferPrimary,
        );
        assert!(matches!(d, RequestedRouteDecision::DefaultRoute { .. }));
    }

    #[test]
    fn exact_ip_rule_matches_observed_ip() {
        let book = book_primary(vec![rule(
            "R-0001",
            true,
            CanonicalAddressMatch::ExactIp(Ipv4Addr::new(203, 0, 113, 7)),
        )]);
        let ip = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        let d = match_sample(
            &book,
            None,
            ip,
            None,
            ZonePriorityPolicy::default(),
            crate::RouteBehaviorMode::PreferPrimary,
        );
        assert_eq!(matched_class(&d), Some(MatchClass::ExactIp));
    }

    #[test]
    fn no_rule_yields_default_route_carrying_behavior_mode() {
        let book = book_primary(Vec::new());
        let d = match_sample(
            &book,
            Some("example.com"),
            None,
            None,
            ZonePriorityPolicy::default(),
            crate::RouteBehaviorMode::StrictSecondaryFailClosed,
        );
        // The passed behavior_mode must be carried into the DefaultRoute so
        // the explain probe reflects the caller's real per-SID mode (not a
        // hardcoded PreferPrimary).
        match d {
            RequestedRouteDecision::DefaultRoute { behavior_mode, .. } => {
                assert_eq!(
                    behavior_mode,
                    crate::RouteBehaviorMode::StrictSecondaryFailClosed
                );
            }
            other => panic!("expected DefaultRoute, got {other:?}"),
        }
    }
}

// ── Test support fixtures ─────────────────────────────────────────────────────

/// Ready-made fixture data for unit tests.
///
/// All functions in this module are deterministic and produce the same output
/// every time they are called — suitable for snapshot tests and table-driven
/// tests.
pub mod test_support {
    use std::time::SystemTime;

    use crate::canonical::{CanonicalProfile, CanonicalRuleBook};
    use crate::decision_availability::{
        AvailabilityCheckSource, InterfaceLifecycleState, RouteAdapterAvailability,
        RouteAvailabilitySnapshot, RouteAvailabilityState, SecondaryAvailabilityStatus,
        SnapshotStaleness,
    };
    use crate::decision_engine::{DecisionRequest, DecisionWarning};
    use crate::decision_lookup::{
        LookupExplainData, LookupExtendedMetadata, LookupResult, LookupStandardSignals,
    };
    use crate::decision_matching::ZonePriorityPolicy;
    use crate::decision_pipeline::{DecisionFeatureFlags, RuntimeInput};
    use crate::revision::RevisionId;
    use crate::{AdapterIdentity, BindingSource, RouteBehaviorMode, RouteBinding, RouteRole};

    use super::normalize_runtime_input;

    // ── LookupResult fixtures ─────────────────────────────────────────────────

    /// A [`LookupResult`] with no cached data — no IP resolved, no cache hit.
    ///
    /// Use this when the test does not depend on lookup behaviour.
    pub fn empty_lookup() -> LookupResult {
        LookupResult {
            selected_ip: None,
            is_multi_ip: false,
            has_conflict: false,
            explain_data: LookupExplainData {
                standard: LookupStandardSignals {
                    cache_hit: false,
                    freshness: None,
                    source: None,
                    errors: vec![],
                },
                extended: LookupExtendedMetadata {
                    all_resolved_ips: vec![],
                    reverse_hostnames: vec![],
                    selected_entry_ttl_secs: None,
                    selected_entry_resolved_at: None,
                },
            },
        }
    }

    // ── RouteAvailabilitySnapshot fixtures ────────────────────────────────────

    /// A fresh snapshot with primary available and no secondary configured.
    pub fn primary_available_snapshot() -> RouteAvailabilitySnapshot {
        RouteAvailabilitySnapshot {
            primary: RouteAdapterAvailability {
                state: RouteAvailabilityState::Available,
                lifecycle: InterfaceLifecycleState::PresentActive,
                reason: None,
            },
            secondary: SecondaryAvailabilityStatus::NotConfigured,
            taken_at: SystemTime::UNIX_EPOCH,
            age_ms: 0,
            staleness: SnapshotStaleness::Fresh,
            check_source: AvailabilityCheckSource::TestHarness,
        }
    }

    /// A fresh snapshot with both primary and secondary available.
    pub fn both_available_snapshot() -> RouteAvailabilitySnapshot {
        RouteAvailabilitySnapshot {
            primary: RouteAdapterAvailability {
                state: RouteAvailabilityState::Available,
                lifecycle: InterfaceLifecycleState::PresentActive,
                reason: None,
            },
            secondary: SecondaryAvailabilityStatus::Configured(RouteAdapterAvailability {
                state: RouteAvailabilityState::Available,
                lifecycle: InterfaceLifecycleState::PresentActive,
                reason: None,
            }),
            taken_at: SystemTime::UNIX_EPOCH,
            age_ms: 0,
            staleness: SnapshotStaleness::Fresh,
            check_source: AvailabilityCheckSource::TestHarness,
        }
    }

    /// A snapshot with secondary configured but unavailable (no IP).
    pub fn secondary_no_ip_snapshot() -> RouteAvailabilitySnapshot {
        use crate::decision_availability::AvailabilityReason;
        RouteAvailabilitySnapshot {
            primary: RouteAdapterAvailability {
                state: RouteAvailabilityState::Available,
                lifecycle: InterfaceLifecycleState::PresentActive,
                reason: None,
            },
            secondary: SecondaryAvailabilityStatus::Configured(RouteAdapterAvailability {
                state: RouteAvailabilityState::Degraded,
                lifecycle: InterfaceLifecycleState::PresentNoIp,
                reason: Some(AvailabilityReason::NoIpAddress),
            }),
            taken_at: SystemTime::UNIX_EPOCH,
            age_ms: 0,
            staleness: SnapshotStaleness::Fresh,
            check_source: AvailabilityCheckSource::TestHarness,
        }
    }

    /// A stale-not-usable snapshot (> 30 s old) — all states downgraded to Unknown.
    pub fn stale_snapshot() -> RouteAvailabilitySnapshot {
        RouteAvailabilitySnapshot {
            primary: RouteAdapterAvailability {
                state: RouteAvailabilityState::Available,
                lifecycle: InterfaceLifecycleState::PresentActive,
                reason: None,
            },
            secondary: SecondaryAvailabilityStatus::NotConfigured,
            taken_at: SystemTime::UNIX_EPOCH,
            age_ms: 60_000,
            staleness: SnapshotStaleness::StaleNotUsable,
            check_source: AvailabilityCheckSource::TestHarness,
        }
    }

    // ── CanonicalProfile fixture ──────────────────────────────────────────────

    /// A minimal [`CanonicalProfile`] with a primary binding and an empty rule book.
    ///
    /// Use when the test does not depend on rule content.
    pub fn minimal_profile() -> CanonicalProfile {
        CanonicalProfile {
            primary: RouteBinding {
                role: RouteRole::Primary,
                adapter: AdapterIdentity {
                    stable_id: "eth0-test".to_owned(),
                    display_name: "Test Ethernet".to_owned(),
                },
                source: BindingSource::UserAssigned,
            },
            secondary: None,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            rule_book: CanonicalRuleBook::default(),
        }
    }

    /// A [`CanonicalProfile`] with both primary and secondary bound and empty rules.
    pub fn dual_route_profile() -> CanonicalProfile {
        CanonicalProfile {
            primary: RouteBinding {
                role: RouteRole::Primary,
                adapter: AdapterIdentity {
                    stable_id: "eth0-test".to_owned(),
                    display_name: "Test Ethernet".to_owned(),
                },
                source: BindingSource::UserAssigned,
            },
            secondary: Some(RouteBinding {
                role: RouteRole::Secondary,
                adapter: AdapterIdentity {
                    stable_id: "vpn0-test".to_owned(),
                    display_name: "Test VPN".to_owned(),
                },
                source: BindingSource::UserAssigned,
            }),
            behavior_mode: RouteBehaviorMode::PreferSecondaryWhenAvailable,
            rule_book: CanonicalRuleBook::default(),
        }
    }

    // ── DecisionRequest builder ───────────────────────────────────────────────

    /// Builder for constructing a [`DecisionRequest`] in unit tests.
    ///
    /// All fields have defaults that produce a clean, no-warnings decision:
    /// - hostname: `"example.com"`, IP: `None`, process: `"chrome.exe"`
    /// - empty lookup, primary available snapshot
    /// - default zone policy (prefer IP), no experimental flags
    pub struct DecisionRequestBuilder {
        revision_id: RevisionId,
        profile: CanonicalProfile,
        runtime_input: RuntimeInput,
        lookup: LookupResult,
        availability: RouteAvailabilitySnapshot,
        zone_policy: ZonePriorityPolicy,
        feature_flags: DecisionFeatureFlags,
    }

    impl DecisionRequestBuilder {
        /// Creates a builder with sensible defaults for happy-path tests.
        pub fn new() -> Self {
            Self {
                revision_id: RevisionId::from_prefixed_string("rev-test-001".to_owned())
                    .unwrap_or_else(|e| panic!("fixture revision id invalid: {e}")),
                profile: minimal_profile(),
                runtime_input: default_runtime_input(),
                lookup: empty_lookup(),
                availability: primary_available_snapshot(),
                zone_policy: ZonePriorityPolicy::default(),
                feature_flags: DecisionFeatureFlags::default(),
            }
        }

        /// Overrides the revision ID.
        pub fn revision(mut self, id: &str) -> Self {
            self.revision_id = RevisionId::from_prefixed_string(id.to_owned())
                .unwrap_or_else(|e| panic!("invalid revision id '{id}': {e}"));
            self
        }

        /// Overrides the canonical profile (rule book + bindings).
        pub fn profile(mut self, profile: CanonicalProfile) -> Self {
            self.profile = profile;
            self
        }

        /// Overrides the raw runtime input (before normalization).
        pub fn runtime_input(mut self, input: RuntimeInput) -> Self {
            self.runtime_input = input;
            self
        }

        /// Overrides the lookup result.
        pub fn lookup(mut self, lookup: LookupResult) -> Self {
            self.lookup = lookup;
            self
        }

        /// Overrides the route availability snapshot.
        pub fn availability(mut self, availability: RouteAvailabilitySnapshot) -> Self {
            self.availability = availability;
            self
        }

        /// Overrides the zone priority policy.
        pub fn zone_policy(mut self, policy: ZonePriorityPolicy) -> Self {
            self.zone_policy = policy;
            self
        }

        /// Overrides the feature flags.
        pub fn feature_flags(mut self, flags: DecisionFeatureFlags) -> Self {
            self.feature_flags = flags;
            self
        }

        /// Enables the browser stub experimental flag.
        pub fn browser_stub_experimental(mut self) -> Self {
            self.feature_flags.browser_stub_experimental = true;
            self
        }

        /// Consumes the builder and returns a [`DecisionRequest`].
        pub fn build(self) -> DecisionRequest {
            use crate::decision_explain::DecisionId;
            let process_context = self.runtime_input.process_context.clone();
            let observation_source = self.runtime_input.observation_source.clone();
            let input = normalize_runtime_input(&self.runtime_input);
            DecisionRequest {
                decision_id: DecisionId("d-00000000-0000-0000-0000-000000000001".to_owned()),
                revision_id: self.revision_id,
                profile: self.profile,
                input,
                lookup: self.lookup,
                availability: self.availability,
                zone_policy: self.zone_policy,
                feature_flags: self.feature_flags,
                process_context,
                observation_source,
            }
        }
    }

    impl Default for DecisionRequestBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    // ── RuntimeInput helpers ──────────────────────────────────────────────────

    /// A default [`RuntimeInput`] with `"example.com"` hostname, no IP, and
    /// `"chrome.exe"` as process name.
    pub fn default_runtime_input() -> RuntimeInput {
        runtime_input_for("example.com", None, Some("chrome.exe"))
    }

    /// Constructs a [`RuntimeInput`] with the given hostname, IP, and process name.
    ///
    /// All other fields use test-harness defaults.
    pub fn runtime_input_for(
        hostname: &str,
        ip: Option<std::net::IpAddr>,
        process_name: Option<&str>,
    ) -> RuntimeInput {
        use crate::decision_pipeline::{
            AdapterAvailability, InterfaceAvailabilitySnapshot, ObservationSource, ProtocolHints,
        };
        RuntimeInput {
            process_context: crate::decision_pipeline::ProcessContext {
                pid: 1,
                process_name: process_name.map(str::to_owned),
                process_path: None,
                parent_pid: None,
                browser_hint: false,
            },
            destination_hostname: Some(hostname.to_owned()),
            destination_ip: ip,
            protocol_hints: ProtocolHints {
                ip_protocol: None,
                destination_port: None,
            },
            active_revision_id: RevisionId::from_prefixed_string("rev-test-001".to_owned())
                .unwrap_or_else(|e| panic!("fixture revision id: {e}")),
            route_behavior_mode: RouteBehaviorMode::PreferPrimary,
            interface_availability: InterfaceAvailabilitySnapshot {
                primary: AdapterAvailability::Available,
                secondary: None,
            },
            observed_at: SystemTime::UNIX_EPOCH,
            observation_source: ObservationSource::TestHarness,
            feature_flags: DecisionFeatureFlags::default(),
        }
    }

    /// Produces sample [`DecisionWarning`] entries for snapshot tests.
    pub fn all_warnings() -> Vec<DecisionWarning> {
        vec![
            DecisionWarning::HostnameUnavailable,
            DecisionWarning::IpUnavailable,
            DecisionWarning::AppContextUnavailable,
            DecisionWarning::LookupStale,
            DecisionWarning::AvailabilityStale,
            DecisionWarning::ConflictDetected,
            DecisionWarning::UnsupportedRuleSkipped,
            DecisionWarning::WeakAppIdentityMatch,
            DecisionWarning::AvailabilityUnknown,
        ]
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::SystemTime;

    use super::*;
    use crate::decision_availability::{
        AvailabilityCheckSource, InterfaceLifecycleState, RouteAdapterAvailability,
        RouteAvailabilityState, SecondaryAvailabilityStatus, SnapshotStaleness,
    };
    use crate::decision_lookup::{
        CacheEntryState, LookupExplainData, LookupExtendedMetadata, LookupResult,
        LookupStandardSignals,
    };
    use crate::decision_normalization::InputAvailabilitySignal;
    use crate::decision_pipeline::{
        AdapterAvailability, InterfaceAvailabilitySnapshot, ObservationSource, ProtocolHints,
    };
    use crate::revision::RevisionId;
    use nrr_shared::RouteBehaviorMode;

    // ── Test helpers ──────────────────────────────────────────────────────────

    fn make_runtime_input(
        hostname: Option<&str>,
        ip: Option<IpAddr>,
        process_name: Option<&str>,
    ) -> RuntimeInput {
        RuntimeInput {
            process_context: ProcessContext {
                pid: 1,
                process_name: process_name.map(str::to_owned),
                process_path: None,
                parent_pid: None,
                browser_hint: false,
            },
            destination_hostname: hostname.map(str::to_owned),
            destination_ip: ip,
            protocol_hints: ProtocolHints {
                ip_protocol: None,
                destination_port: None,
            },
            active_revision_id: RevisionId::from_prefixed_string("rev-t".to_owned())
                .unwrap_or_else(|e| panic!("revision: {e}")),
            route_behavior_mode: RouteBehaviorMode::PreferPrimary,
            interface_availability: InterfaceAvailabilitySnapshot {
                primary: AdapterAvailability::Available,
                secondary: None,
            },
            observed_at: SystemTime::UNIX_EPOCH,
            observation_source: ObservationSource::TestHarness,
            feature_flags: Default::default(),
        }
    }

    fn fresh_snapshot() -> RouteAvailabilitySnapshot {
        RouteAvailabilitySnapshot {
            primary: RouteAdapterAvailability {
                state: RouteAvailabilityState::Available,
                lifecycle: InterfaceLifecycleState::PresentActive,
                reason: None,
            },
            secondary: SecondaryAvailabilityStatus::NotConfigured,
            taken_at: SystemTime::UNIX_EPOCH,
            age_ms: 0,
            staleness: SnapshotStaleness::Fresh,
            check_source: AvailabilityCheckSource::TestHarness,
        }
    }

    fn no_lookup() -> LookupResult {
        LookupResult {
            selected_ip: None,
            is_multi_ip: false,
            has_conflict: false,
            explain_data: LookupExplainData {
                standard: LookupStandardSignals {
                    cache_hit: false,
                    freshness: None,
                    source: None,
                    errors: vec![],
                },
                extended: LookupExtendedMetadata {
                    all_resolved_ips: vec![],
                    reverse_hostnames: vec![],
                    selected_entry_ttl_secs: None,
                    selected_entry_resolved_at: None,
                },
            },
        }
    }

    // ── normalize_hostname_value ──────────────────────────────────────────────

    #[test]
    fn hostname_none_is_unavailable() {
        let (h, w) = normalize_hostname_value(None);
        assert_eq!(h, NormalizedHostname::Unavailable);
        assert!(w.is_empty());
    }

    #[test]
    fn hostname_whitespace_only_is_invalid_empty() {
        let (h, _) = normalize_hostname_value(Some("   "));
        assert!(matches!(
            h,
            NormalizedHostname::Invalid {
                error: NormalizationError::DomainEmpty,
                ..
            }
        ));
    }

    #[test]
    fn hostname_ascii_is_lowercased() {
        let (h, w) = normalize_hostname_value(Some("Example.COM"));
        assert_eq!(h, NormalizedHostname::Valid("example.com".to_owned()));
        assert!(w.is_empty());
    }

    #[test]
    fn hostname_trailing_dot_removed_with_warning() {
        let (h, w) = normalize_hostname_value(Some("example.com."));
        assert_eq!(h, NormalizedHostname::Valid("example.com".to_owned()));
        assert!(w
            .iter()
            .any(|x| matches!(x, NormalizationWarning::DomainTrailingDotRemoved)));
    }

    #[test]
    fn hostname_invalid_chars_produces_invalid_variant() {
        let (h, _) = normalize_hostname_value(Some("bad!host.com"));
        assert!(matches!(
            h,
            NormalizedHostname::Invalid {
                error: NormalizationError::DomainInvalidCharacters { .. },
                ..
            }
        ));
    }

    #[test]
    fn hostname_subdomain_multiple_labels_preserved() {
        let (h, _) = normalize_hostname_value(Some("a.b.example.com"));
        assert_eq!(h, NormalizedHostname::Valid("a.b.example.com".to_owned()));
    }

    #[test]
    fn hostname_hyphens_allowed() {
        let (h, _) = normalize_hostname_value(Some("my-host.example.com"));
        assert_eq!(
            h,
            NormalizedHostname::Valid("my-host.example.com".to_owned())
        );
    }

    // ── normalize_ip_value ────────────────────────────────────────────────────

    #[test]
    fn ip_none_is_unavailable() {
        let (ip, w) = normalize_ip_value(None);
        assert_eq!(ip, NormalizedIp::Unavailable);
        assert!(w.is_empty());
    }

    #[test]
    fn ip_v4_passes_through() {
        let addr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let (ip, w) = normalize_ip_value(Some(addr));
        assert_eq!(ip, NormalizedIp::ValidIpv4(Ipv4Addr::new(93, 184, 216, 34)));
        assert!(w.is_empty());
    }

    #[test]
    fn ip_ipv4_mapped_ipv6_converted_with_warning() {
        let v6: Ipv6Addr = "::ffff:203.0.113.7"
            .parse()
            .unwrap_or_else(|e| panic!("fixture addr: {e}"));
        let (ip, w) = normalize_ip_value(Some(IpAddr::V6(v6)));
        assert_eq!(ip, NormalizedIp::ValidIpv4(Ipv4Addr::new(203, 0, 113, 7)));
        assert!(w.iter().any(|x| matches!(
            x,
            NormalizationWarning::Ipv4MappedIpv6NormalizedToIpv4 { .. }
        )));
    }

    #[test]
    fn ip_native_ipv6_becomes_pro_only() {
        let v6: Ipv6Addr = "2001:db8::1"
            .parse()
            .unwrap_or_else(|e| panic!("fixture addr: {e}"));
        let (ip, w) = normalize_ip_value(Some(IpAddr::V6(v6)));
        assert!(matches!(ip, NormalizedIp::ProOnlyNativeIpv6 { .. }));
        assert!(w.is_empty());
    }

    // ── normalize_app_identity_value ─────────────────────────────────────────

    fn pctx(name: Option<&str>, path: Option<&str>) -> ProcessContext {
        ProcessContext {
            pid: 1234,
            process_name: name.map(str::to_owned),
            process_path: path.map(str::to_owned),
            parent_pid: None,
            browser_hint: false,
        }
    }

    #[test]
    fn app_none_name_signals_unavailable() {
        let (id, signals) = normalize_app_identity_value(&pctx(None, None));
        assert!(id.is_none());
        assert!(signals.contains(&InputAvailabilitySignal::AppContextUnavailable));
    }

    #[test]
    fn app_bare_name_lowercased_exe_added() {
        let (id, signals) = normalize_app_identity_value(&pctx(Some("Firefox"), None));
        let id = id.unwrap_or_else(|| panic!("identity must be present"));
        assert_eq!(id.process_name, "firefox.exe");
        assert!(signals.is_empty());
        assert!(id
            .warnings
            .iter()
            .any(|w| matches!(w, NormalizationWarning::ApplicationExeSuffixAdded { .. })));
    }

    #[test]
    fn app_bare_name_emits_weak_identity_warning() {
        let (id, _) = normalize_app_identity_value(&pctx(Some("chrome.exe"), None));
        let id = id.unwrap_or_else(|| panic!("identity must be present"));
        assert!(id.warnings.iter().any(|w| {
            matches!(
                w,
                NormalizationWarning::ApplicationBareProcessNameWeakIdentity { .. }
            )
        }));
    }

    #[test]
    fn app_full_path_strips_to_basename() {
        let path = r"C:\Program Files\Mozilla Firefox\firefox.exe";
        let (id, signals) = normalize_app_identity_value(&pctx(Some(path), Some(path)));
        let id = id.unwrap_or_else(|| panic!("identity must be present"));
        assert_eq!(id.process_name, "firefox.exe");
        assert!(signals.is_empty());
        assert!(id
            .warnings
            .iter()
            .any(|w| matches!(w, NormalizationWarning::ApplicationPathStripped { .. })));
    }

    #[test]
    fn app_with_path_no_weak_identity_warning() {
        let path = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
        let (id, _) = normalize_app_identity_value(&pctx(Some("chrome.exe"), Some(path)));
        let id = id.unwrap_or_else(|| panic!("identity must be present"));
        assert!(!id.warnings.iter().any(|w| {
            matches!(
                w,
                NormalizationWarning::ApplicationBareProcessNameWeakIdentity { .. }
            )
        }));
    }

    // ── normalize_runtime_input ───────────────────────────────────────────────

    #[test]
    fn full_connection_all_classes_available() {
        let input = make_runtime_input(
            Some("example.com"),
            Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            Some("firefox.exe"),
        );
        let n = normalize_runtime_input(&input);
        assert!(n.hostname.is_usable());
        assert!(n.ip.is_usable());
        assert!(n.app_identity.is_some());
        assert!(n.match_class_availability.all_available());
        assert!(n.availability_signals.is_empty());
    }

    #[test]
    fn ip_only_blocks_hostname_match_classes() {
        let input = make_runtime_input(None, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), None);
        let n = normalize_runtime_input(&input);
        assert!(n.match_class_availability.exact_fqdn.is_some());
        assert!(n.match_class_availability.suffix_domain.is_some());
        assert!(n.match_class_availability.zone.is_some());
        assert!(n.match_class_availability.exact_ip.is_none());
        assert!(n
            .availability_signals
            .contains(&InputAvailabilitySignal::HostnameUnavailable));
    }

    #[test]
    fn native_ipv6_blocks_only_exact_ip() {
        let v6: Ipv6Addr = "2001:db8::1"
            .parse()
            .unwrap_or_else(|e| panic!("fixture: {e}"));
        let input = make_runtime_input(Some("ipv6host.example.com"), Some(IpAddr::V6(v6)), None);
        let n = normalize_runtime_input(&input);
        assert!(n.match_class_availability.exact_ip.is_some());
        assert!(n.match_class_availability.exact_fqdn.is_none());
        assert!(n.match_class_availability.suffix_domain.is_none());
        assert!(n.match_class_availability.zone.is_none());
    }

    #[test]
    fn no_inputs_blocks_hostname_and_app_but_not_exact_ip() {
        // ip=None keeps exact_ip unblocked — lookup stage may still provide an IP.
        let input = make_runtime_input(None, None, None);
        let n = normalize_runtime_input(&input);
        assert!(n.match_class_availability.exact_fqdn.is_some());
        assert!(n.match_class_availability.suffix_domain.is_some());
        assert!(n.match_class_availability.zone.is_some());
        assert!(n.match_class_availability.exact_ip.is_none());
        assert!(n.match_class_availability.application.is_some());
        assert!(!n.match_class_availability.nothing_available());
        assert_eq!(n.availability_signals.len(), 3);
    }

    // ── collect_input_warnings ────────────────────────────────────────────────

    #[test]
    fn collect_warns_ip_unavailable_when_no_ip() {
        let input = make_runtime_input(Some("example.com"), None, Some("chrome.exe"));
        let n = normalize_runtime_input(&input);
        let w = collect_input_warnings(&n, &no_lookup(), &fresh_snapshot());
        assert!(w.contains(&DecisionWarning::IpUnavailable));
        assert!(!w.contains(&DecisionWarning::LookupStale));
        assert!(!w.contains(&DecisionWarning::AvailabilityStale));
    }

    #[test]
    fn collect_warns_stale_lookup() {
        let input = make_runtime_input(Some("example.com"), None, None);
        let n = normalize_runtime_input(&input);
        let stale_lookup = LookupResult {
            selected_ip: None,
            is_multi_ip: false,
            has_conflict: false,
            explain_data: LookupExplainData {
                standard: LookupStandardSignals {
                    cache_hit: true,
                    freshness: Some(CacheEntryState::StaleUsable),
                    source: None,
                    errors: vec![],
                },
                extended: LookupExtendedMetadata {
                    all_resolved_ips: vec![],
                    reverse_hostnames: vec![],
                    selected_entry_ttl_secs: None,
                    selected_entry_resolved_at: None,
                },
            },
        };
        let w = collect_input_warnings(&n, &stale_lookup, &fresh_snapshot());
        assert!(w.contains(&DecisionWarning::LookupStale));
    }

    #[test]
    fn collect_warns_stale_and_unknown_when_snapshot_stale_not_usable() {
        let input = make_runtime_input(Some("example.com"), None, None);
        let n = normalize_runtime_input(&input);
        let stale_snap = RouteAvailabilitySnapshot {
            primary: RouteAdapterAvailability {
                state: RouteAvailabilityState::Available,
                lifecycle: InterfaceLifecycleState::PresentActive,
                reason: None,
            },
            secondary: SecondaryAvailabilityStatus::NotConfigured,
            taken_at: SystemTime::UNIX_EPOCH,
            age_ms: 60_000,
            staleness: SnapshotStaleness::StaleNotUsable,
            check_source: AvailabilityCheckSource::TestHarness,
        };
        let w = collect_input_warnings(&n, &no_lookup(), &stale_snap);
        assert!(w.contains(&DecisionWarning::AvailabilityStale));
        assert!(w.contains(&DecisionWarning::AvailabilityUnknown));
    }

    #[test]
    fn collect_warns_weak_identity_from_app() {
        let input = make_runtime_input(Some("example.com"), None, Some("myapp"));
        let n = normalize_runtime_input(&input);
        let w = collect_input_warnings(&n, &no_lookup(), &fresh_snapshot());
        assert!(w.contains(&DecisionWarning::WeakAppIdentityMatch));
    }

    // ── test_support fixtures ─────────────────────────────────────────────────

    #[test]
    fn decision_request_builder_produces_valid_request() {
        use crate::decision_engine_input::test_support::DecisionRequestBuilder;
        let req = DecisionRequestBuilder::new().build();
        assert!(req.input.hostname.is_usable());
    }

    #[test]
    fn decision_request_builder_respects_overrides() {
        use crate::decision_engine_input::test_support::{
            both_available_snapshot, DecisionRequestBuilder,
        };
        let req = DecisionRequestBuilder::new()
            .availability(both_available_snapshot())
            .browser_stub_experimental()
            .build();
        assert!(req.feature_flags.browser_stub_experimental);
        assert!(req.availability.secondary.is_routable());
    }

    #[test]
    fn all_warnings_fixture_has_all_variants() {
        use crate::decision_engine_input::test_support::all_warnings;
        let w = all_warnings();
        assert!(w.contains(&DecisionWarning::HostnameUnavailable));
        assert!(w.contains(&DecisionWarning::AvailabilityUnknown));
        assert_eq!(w.len(), 9);
    }
}
