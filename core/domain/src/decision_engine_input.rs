//! Input adapter and fixture support for the routing decision engine.
//!
//! # Responsibilities
//!
//! - [`normalize_runtime_input`] — converts a raw [`RuntimeInput`] to a
//!   [`NormalizedDecisionInput`] ready for the rule matching stage.
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
///   [`NormalizedIp::UnsupportedNativeIpv6`] and blocks `ExactIp` matching.
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
        // `_` too: the rule validator accepts it (internal corp zones use it),
        // and rejecting it here made a valid rule's host `Invalid`, which
        // silently disables three match classes for that request.
        if lowercased
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            if !dns_labels_are_well_formed(&lowercased) {
                return (
                    NormalizedHostname::Invalid {
                        raw: h.to_owned(),
                        error: NormalizationError::DomainMalformedLabels { raw: h.to_owned() },
                    },
                    warnings,
                );
            }
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
                if !dns_labels_are_well_formed(&ascii) {
                    return (
                        NormalizedHostname::Invalid {
                            raw: h.to_owned(),
                            error: NormalizationError::DomainMalformedLabels { raw: h.to_owned() },
                        },
                        warnings,
                    );
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
                (NormalizedIp::UnsupportedNativeIpv6 { addr: v6 }, vec![])
            }
        }
    }
}

/// Does `host` have a label structure a resolver could answer?
///
/// The character check above says every octet is legal; it says nothing about
/// where the dots are. `example.com..` survives the single trailing-dot strip
/// with an empty label still on the end, `a..b` never had one, and a 400-octet
/// label is legal by character and impossible by DNS — all three used to reach
/// the matcher as `Valid`, so a rule could be compared against a name that
/// cannot exist.
///
/// Limits are RFC 1035: 63 octets per label, 253 for the name. Checked on the
/// ASCII form, which is what punycode leaves behind and what the wire carries.
fn dns_labels_are_well_formed(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.')
        .all(|label| !label.is_empty() && label.len() <= 63)
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
        NormalizedIp::UnsupportedNativeIpv6 { addr } => {
            Some(NormalizationError::IpNativeIpv6Unsupported { addr: *addr })
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

    use crate::decision_lookup::{
        LookupExplainData, LookupExtendedMetadata, LookupResult, LookupStandardSignals,
    };
    use crate::decision_pipeline::{DecisionFeatureFlags, RuntimeInput};
    use crate::revision::RevisionId;
    use crate::RouteBehaviorMode;

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

    // ── RuntimeInput helpers ──────────────────────────────────────────────────

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
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::SystemTime;

    use super::*;
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

    /// Every octet legal, the structure impossible. All three used to reach the
    /// matcher as `Valid`, so a rule was compared against a name no resolver
    /// could ever answer.
    #[test]
    fn hostname_with_a_legal_but_impossible_label_structure_is_invalid() {
        let long_label = "a".repeat(64);
        for raw in [
            "example.com..".to_owned(),  // one dot stripped, an empty label left
            "a..b".to_owned(),           // an empty label in the middle
            format!("{long_label}.com"), // 64 octets in one label
            format!("{}.com", "b".repeat(250)), // over 253 for the whole name
        ] {
            let (h, _) = normalize_hostname_value(Some(&raw));
            assert!(
                matches!(
                    h,
                    NormalizedHostname::Invalid {
                        error: NormalizationError::DomainMalformedLabels { .. },
                        ..
                    }
                ),
                "{raw} must not normalize to a valid hostname, got {h:?}"
            );
        }

        // Negative control: the exact-63 boundary and a plain name still pass.
        let boundary = format!("{}.com", "a".repeat(63));
        assert!(matches!(
            normalize_hostname_value(Some(&boundary)).0,
            NormalizedHostname::Valid(_)
        ));
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

    /// The rule validator accepts `_`; the runtime path must not disagree, or
    /// a live `*.corp.intra` rule answers "default route" for `db_srv.corp.intra`.
    #[test]
    fn hostname_underscore_is_valid_like_the_rule_validator_says() {
        let (h, _) = normalize_hostname_value(Some("db_srv.corp.intra"));
        assert_eq!(h, NormalizedHostname::Valid("db_srv.corp.intra".to_owned()));
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
    fn ip_native_ipv6_becomes_unsupported() {
        let v6: Ipv6Addr = "2001:db8::1"
            .parse()
            .unwrap_or_else(|e| panic!("fixture addr: {e}"));
        let (ip, w) = normalize_ip_value(Some(IpAddr::V6(v6)));
        assert!(matches!(ip, NormalizedIp::UnsupportedNativeIpv6 { .. }));
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
}
