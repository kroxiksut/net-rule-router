//! Mapper from `DecisionExplain` → `ExplainResponse`.
//!
//! # Privacy contract
//!
//! - `CompactUi`: hostname and process name shown; IP omitted; no warnings.
//! - `Diagnostics`: adds IP, cache detail, TTL, warnings, uncertainty markers.
//! - `DeveloperTrace`: adds conflict markers, full path, all signals.
//!
//! No raw IP addresses or process paths appear at `CompactUi` level.

use nrr_domain::decision_explain::{
    DecisionExplain, ExplainDetailLevel, ExplainWarning, MatchTraceSummary, UncertaintyMarker,
};
use nrr_domain::decision_fail_policy::FinalAction;
use nrr_storage::LookupExplainSummary;

use crate::explain::keys::*;
use crate::explain::query::{ExplainDataAvailability, ExplainQueryKind};
use crate::explain::response::{
    detail_level_to_str, query_kind_to_str, ExplainAvailabilitySection, ExplainCorrelationSection,
    ExplainFinalActionSection, ExplainInputSection, ExplainLookupSection, ExplainMatchSection,
    ExplainResponse, ExplainSummarySection, ExplainWarningEntry,
};
use crate::taxonomy::EventCorrelation;

/// Converts a `DecisionExplain` into an `ExplainResponse` DTO.
///
/// `lookup` is optional — when `None`, the lookup section is omitted.
/// `query_kind` determines whether the result is marked as a simulation.
pub fn map_explain(
    explain: &DecisionExplain,
    lookup: Option<&LookupExplainSummary>,
    level: ExplainDetailLevel,
    query_kind: ExplainQueryKind,
) -> ExplainResponse {
    let summary = build_summary(explain, query_kind);
    let input = build_input(explain, level);
    let match_section = build_match(explain, level);
    let lookup_section = lookup.map(|l| build_lookup(l, level));
    let availability_section = build_availability(explain);
    let final_action_section = build_final_action(explain);
    let warnings = if level >= ExplainDetailLevel::Diagnostics {
        build_warnings(explain)
    } else {
        Vec::new()
    };
    let correlation = build_correlation(explain, query_kind);

    ExplainResponse {
        query_kind: query_kind_to_str(query_kind),
        detail_level: detail_level_to_str(level),
        availability_key: ExplainDataAvailability::Available.ui_key().to_string(),
        summary,
        input: Some(input),
        match_section: Some(match_section),
        lookup_section,
        availability_section: Some(availability_section),
        final_action_section: Some(final_action_section),
        warnings,
        correlation,
    }
}

// ── Section builders ──────────────────────────────────────────────────────────

fn build_summary(explain: &DecisionExplain, query_kind: ExplainQueryKind) -> ExplainSummarySection {
    let summary_key = match explain.final_action_summary.action {
        FinalAction::RoutePrimary => SUMMARY_ROUTE_PRIMARY,
        FinalAction::RouteSecondary => SUMMARY_ROUTE_SECONDARY,
        FinalAction::Block => SUMMARY_BLOCKED_FAIL_CLOSED,
        FinalAction::BrowserStubAttempt => SUMMARY_BROWSER_STUB_ATTEMPT,
        FinalAction::Defer => SUMMARY_DEFERRED,
    };
    ExplainSummarySection {
        summary_key: summary_key.to_string(),
        is_simulation: query_kind.is_simulation(),
    }
}

fn build_input(explain: &DecisionExplain, level: ExplainDetailLevel) -> ExplainInputSection {
    let input = &explain.input_summary;
    let destination_ip = if level >= ExplainDetailLevel::Diagnostics {
        // At Diagnostics+ we could show the IP, but we don't have a raw IP
        // in InputSummary at CompactUi — just the presence flag.
        // Extended path is available at Diagnostics+.
        input.process_path_extended.clone()
    } else {
        None
    };
    ExplainInputSection {
        destination_hostname: input.destination_hostname.clone(),
        destination_ip_present: input.destination_ip_present,
        destination_ip: destination_ip.and(None), // IP field: reserved for future
        process_name: input.process_name.clone(),
        process_path: if level >= ExplainDetailLevel::Diagnostics {
            input.process_path_extended.clone()
        } else {
            None
        },
    }
}

fn build_match(explain: &DecisionExplain, _level: ExplainDetailLevel) -> ExplainMatchSection {
    match &explain.match_trace {
        Some(MatchTraceSummary::RuleMatched {
            rule_id,
            match_class_label,
            route_role,
            conflict_resolved,
        }) => ExplainMatchSection {
            outcome_key: MATCH_RULE_MATCHED.to_string(),
            matched_rule_id: Some(rule_id.0.clone()),
            match_class_label: Some(match_class_label.clone()),
            route_role: Some(format!("{route_role:?}").to_lowercase()),
            conflict_resolved: *conflict_resolved,
            default_reason_key: None,
        },
        Some(MatchTraceSummary::DefaultRoute {
            reason_label,
            behavior_mode_label: _,
        }) => ExplainMatchSection {
            outcome_key: MATCH_DEFAULT_ROUTE.to_string(),
            matched_rule_id: None,
            match_class_label: None,
            route_role: None,
            conflict_resolved: false,
            default_reason_key: Some(reason_label.clone()),
        },
        None => ExplainMatchSection {
            outcome_key: MATCH_DEFAULT_ROUTE.to_string(),
            matched_rule_id: None,
            match_class_label: None,
            route_role: None,
            conflict_resolved: false,
            default_reason_key: None,
        },
    }
}

fn build_lookup(lookup: &LookupExplainSummary, level: ExplainDetailLevel) -> ExplainLookupSection {
    let cache_state_key = if !lookup.cache_hit {
        if lookup.has_errors {
            LOOKUP_ERRORS_PRESENT
        } else {
            LOOKUP_CACHE_MISS
        }
    } else {
        match lookup.freshness_label {
            Some(l) if l.contains("stale") => LOOKUP_STALE_USABLE,
            Some(_) => LOOKUP_CACHE_HIT,
            None => LOOKUP_CACHE_MISS,
        }
    };

    let selected_ip = if level >= ExplainDetailLevel::Diagnostics {
        lookup.selected_ip.map(|ip| ip.to_string())
    } else {
        None
    };

    ExplainLookupSection {
        cache_state_key: cache_state_key.to_string(),
        cache_hit: lookup.cache_hit,
        has_errors: lookup.has_errors,
        selected_ip,
        is_multi_ip: lookup.is_multi_ip,
        ttl_seconds: if level >= ExplainDetailLevel::Diagnostics {
            lookup.ttl_seconds
        } else {
            None
        },
    }
}

fn build_availability(explain: &DecisionExplain) -> ExplainAvailabilitySection {
    let avail = &explain.availability_trace;
    let secondary_state_key = if avail.secondary_not_configured {
        AVAIL_SECONDARY_NOT_CONFIGURED
    } else if avail.snapshot_stale {
        AVAIL_SNAPSHOT_STALE
    } else {
        AVAIL_SECONDARY_AVAILABLE
    };

    ExplainAvailabilitySection {
        secondary_state_key: secondary_state_key.to_string(),
        requested_route: format!("{:?}", avail.requested_route).to_lowercase(),
        secondary_configured: !avail.secondary_not_configured,
        snapshot_stale: avail.snapshot_stale,
    }
}

fn build_final_action(explain: &DecisionExplain) -> ExplainFinalActionSection {
    let action = &explain.final_action_summary;
    let action_key = match action.action {
        FinalAction::RoutePrimary => ACTION_ROUTE_PRIMARY,
        FinalAction::RouteSecondary => ACTION_ROUTE_SECONDARY,
        FinalAction::Block => ACTION_BLOCK,
        FinalAction::BrowserStubAttempt => ACTION_BROWSER_STUB,
        FinalAction::Defer => ACTION_DEFER,
    };
    let route_role = action.route_role.map(|r| format!("{r:?}").to_lowercase());

    ExplainFinalActionSection {
        action_key: action_key.to_string(),
        route_role,
        reason_key: action.reason_label.clone(),
    }
}

fn build_warnings(explain: &DecisionExplain) -> Vec<ExplainWarningEntry> {
    let mut warnings: Vec<ExplainWarningEntry> = explain
        .warnings
        .iter()
        .map(|w| ExplainWarningEntry {
            warning_key: warning_to_key(w).to_string(),
        })
        .collect();

    // Add uncertainty markers as warnings.
    for marker in &explain.uncertainty_markers {
        warnings.push(ExplainWarningEntry {
            warning_key: uncertainty_to_key(marker).to_string(),
        });
    }

    warnings
}

fn build_correlation(
    explain: &DecisionExplain,
    query_kind: ExplainQueryKind,
) -> ExplainCorrelationSection {
    let decision_id = if query_kind == ExplainQueryKind::Historical {
        Some(explain.decision_id.as_str().to_string())
    } else {
        None
    };

    ExplainCorrelationSection {
        decision_id,
        revision_id: Some(explain.active_revision_id.clone()),
        log_correlation: EventCorrelation::default()
            .with_decision(explain.decision_id.as_str())
            .with_revision(&explain.active_revision_id),
    }
}

// ── Key mapping helpers ───────────────────────────────────────────────────────

fn warning_to_key(warning: &ExplainWarning) -> &'static str {
    match warning {
        ExplainWarning::Ipv4MappedNormalised => WARN_IPV4_MAPPED_NORMALISED,
        ExplainWarning::WeakProcessIdentity => WARN_WEAK_PROCESS_IDENTITY,
        ExplainWarning::AppExeSuffixAdded => WARN_APP_EXE_SUFFIX_ADDED,
        ExplainWarning::DomainTrailingDotRemoved => WARN_DOMAIN_TRAILING_DOT,
        ExplainWarning::LookupStaleCacheUsed => WARN_STALE_CACHE_USED,
        ExplainWarning::LookupTimeout => WARN_LOOKUP_TIMEOUT,
        ExplainWarning::LookupMultipleIpsResolved => WARN_MULTI_IP,
        ExplainWarning::MatchConflictResolved => WARN_CONFLICT_RESOLVED,
        ExplainWarning::PrimaryAdapterDegraded => WARN_PRIMARY_DEGRADED,
        ExplainWarning::AvailabilitySnapshotStale => WARN_AVAIL_SNAPSHOT_STALE,
    }
}

fn uncertainty_to_key(marker: &UncertaintyMarker) -> &'static str {
    match marker {
        UncertaintyMarker::HostnameUnavailable => UNCERTAINTY_HOSTNAME_UNAVAILABLE,
        UncertaintyMarker::AppContextUnavailable => UNCERTAINTY_APP_CONTEXT_UNAVAILABLE,
        UncertaintyMarker::StaleCacheUsed => UNCERTAINTY_STALE_CACHE,
        UncertaintyMarker::AmbiguousLookup => UNCERTAINTY_AMBIGUOUS_LOOKUP,
        UncertaintyMarker::StaleAvailabilitySnapshot => UNCERTAINTY_STALE_AVAILABILITY,
        UncertaintyMarker::UnknownSecondaryState => UNCERTAINTY_UNKNOWN_SECONDARY,
        UncertaintyMarker::Ipv6DestinationProOnly => UNCERTAINTY_IPV6_PRO_ONLY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_domain::decision_explain::{
        AvailabilityTraceSummary, DecisionId, FinalActionSummary, InputSummary,
        ObservationSourceLabel,
    };
    use nrr_domain::decision_fail_policy::FinalAction;
    use nrr_shared::RouteRole;

    fn sample_explain(action: FinalAction) -> DecisionExplain {
        DecisionExplain {
            decision_id: DecisionId("d-test-001".into()),
            active_revision_id: "rev-001".into(),
            decided_at: None,
            input_summary: InputSummary {
                destination_hostname: Some("updates.example.com".into()),
                destination_ip_present: true,
                process_name: Some("chrome.exe".into()),
                process_path_extended: Some("C:\\Program Files\\Chrome\\chrome.exe".into()),
                observation_source: ObservationSourceLabel::WfpCallback,
            },
            match_trace: Some(MatchTraceSummary::RuleMatched {
                rule_id: nrr_domain::RuleId("r-001".into()),
                match_class_label: "ExactFqdn".into(),
                route_role: RouteRole::Secondary,
                conflict_resolved: false,
            }),
            availability_trace: AvailabilityTraceSummary {
                requested_route: RouteRole::Secondary,
                observed_state_label: "available".into(),
                secondary_not_configured: false,
                snapshot_stale: false,
            },
            final_action_summary: FinalActionSummary {
                action,
                route_role: match action {
                    FinalAction::RoutePrimary => Some(RouteRole::Primary),
                    FinalAction::RouteSecondary => Some(RouteRole::Secondary),
                    _ => None,
                },
                reason_label: "explain.reason.rule_matched".into(),
                stub_considered_but_rejected: false,
            },
            uncertainty_markers: Vec::new(),
            conflict_markers: Vec::new(),
            warnings: Vec::new(),
            used_signals: vec!["fqdn".into()],
            correlation_id: None,
        }
    }

    #[test]
    fn map_route_secondary_compact() {
        let explain = sample_explain(FinalAction::RouteSecondary);
        let r = map_explain(
            &explain,
            None,
            ExplainDetailLevel::CompactUi,
            ExplainQueryKind::Historical,
        );

        assert!(r.is_available());
        assert!(!r.is_simulation());
        assert_eq!(r.summary.summary_key, SUMMARY_ROUTE_SECONDARY);
        assert!(r.warnings.is_empty(), "no warnings at CompactUi");
        assert!(r.input.is_some());
        assert!(r.final_action_section.is_some());
    }

    #[test]
    fn map_route_primary_compact() {
        let explain = sample_explain(FinalAction::RoutePrimary);
        let r = map_explain(
            &explain,
            None,
            ExplainDetailLevel::CompactUi,
            ExplainQueryKind::Historical,
        );
        assert_eq!(r.summary.summary_key, SUMMARY_ROUTE_PRIMARY);
    }

    #[test]
    fn map_blocked_fail_closed_compact() {
        let explain = sample_explain(FinalAction::Block);
        let r = map_explain(
            &explain,
            None,
            ExplainDetailLevel::CompactUi,
            ExplainQueryKind::Historical,
        );
        assert_eq!(r.summary.summary_key, SUMMARY_BLOCKED_FAIL_CLOSED);
        let action = r.final_action_section.unwrap();
        assert_eq!(action.action_key, ACTION_BLOCK);
    }

    #[test]
    fn synthetic_explain_is_marked_as_simulation() {
        let explain = sample_explain(FinalAction::RoutePrimary);
        let r = map_explain(
            &explain,
            None,
            ExplainDetailLevel::CompactUi,
            ExplainQueryKind::Synthetic,
        );
        assert!(r.is_simulation());
        assert!(r.summary.is_simulation);
    }

    #[test]
    fn diagnostics_level_includes_warnings_for_explain_with_warnings() {
        let mut explain = sample_explain(FinalAction::RoutePrimary);
        explain.warnings.push(ExplainWarning::LookupStaleCacheUsed);
        explain.warnings.push(ExplainWarning::WeakProcessIdentity);

        let r = map_explain(
            &explain,
            None,
            ExplainDetailLevel::Diagnostics,
            ExplainQueryKind::Historical,
        );
        assert_eq!(r.warnings.len(), 2);
        assert!(r
            .warnings
            .iter()
            .any(|w| w.warning_key == WARN_STALE_CACHE_USED));
    }

    #[test]
    fn compact_level_excludes_warnings() {
        let mut explain = sample_explain(FinalAction::RoutePrimary);
        explain.warnings.push(ExplainWarning::LookupStaleCacheUsed);

        let r = map_explain(
            &explain,
            None,
            ExplainDetailLevel::CompactUi,
            ExplainQueryKind::Historical,
        );
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn compact_level_hides_process_path() {
        let explain = sample_explain(FinalAction::RoutePrimary);
        let r = map_explain(
            &explain,
            None,
            ExplainDetailLevel::CompactUi,
            ExplainQueryKind::Historical,
        );
        let input = r.input.unwrap();
        assert!(
            input.process_path.is_none(),
            "process path hidden at CompactUi"
        );
        assert!(
            input.process_name.is_some(),
            "process name shown at all levels"
        );
    }

    #[test]
    fn diagnostics_level_shows_process_path() {
        let explain = sample_explain(FinalAction::RoutePrimary);
        let r = map_explain(
            &explain,
            None,
            ExplainDetailLevel::Diagnostics,
            ExplainQueryKind::Historical,
        );
        let input = r.input.unwrap();
        assert!(input.process_path.is_some());
    }

    #[test]
    fn correlation_section_contains_decision_id_for_historical() {
        let explain = sample_explain(FinalAction::RoutePrimary);
        let r = map_explain(
            &explain,
            None,
            ExplainDetailLevel::CompactUi,
            ExplainQueryKind::Historical,
        );
        assert_eq!(r.correlation.decision_id.as_deref(), Some("d-test-001"));
        assert_eq!(r.correlation.revision_id.as_deref(), Some("rev-001"));
    }

    #[test]
    fn correlation_section_no_decision_id_for_synthetic() {
        let explain = sample_explain(FinalAction::RoutePrimary);
        let r = map_explain(
            &explain,
            None,
            ExplainDetailLevel::CompactUi,
            ExplainQueryKind::Synthetic,
        );
        assert!(
            r.correlation.decision_id.is_none(),
            "no decision id for synthetic"
        );
    }

    #[test]
    fn uncertainty_markers_become_warnings_at_diagnostics() {
        let mut explain = sample_explain(FinalAction::RoutePrimary);
        explain
            .uncertainty_markers
            .push(UncertaintyMarker::HostnameUnavailable);
        explain
            .uncertainty_markers
            .push(UncertaintyMarker::StaleCacheUsed);

        let r = map_explain(
            &explain,
            None,
            ExplainDetailLevel::Diagnostics,
            ExplainQueryKind::Historical,
        );
        let keys: Vec<_> = r.warnings.iter().map(|w| w.warning_key.as_str()).collect();
        assert!(keys.contains(&UNCERTAINTY_HOSTNAME_UNAVAILABLE));
        assert!(keys.contains(&UNCERTAINTY_STALE_CACHE));
    }

    #[test]
    fn explain_response_serializes_deterministically() {
        let explain = sample_explain(FinalAction::RouteSecondary);
        let r1 = map_explain(
            &explain,
            None,
            ExplainDetailLevel::CompactUi,
            ExplainQueryKind::Historical,
        );
        let r2 = map_explain(
            &explain,
            None,
            ExplainDetailLevel::CompactUi,
            ExplainQueryKind::Historical,
        );
        let j1 = serde_json::to_string(&r1).unwrap();
        let j2 = serde_json::to_string(&r2).unwrap();
        assert_eq!(j1, j2, "explain mapping must be deterministic");
    }

    #[test]
    fn default_route_match_section() {
        let mut explain = sample_explain(FinalAction::RoutePrimary);
        explain.match_trace = Some(MatchTraceSummary::DefaultRoute {
            reason_label: "no rule matched".into(),
            behavior_mode_label: "prefer_primary".into(),
        });
        let r = map_explain(
            &explain,
            None,
            ExplainDetailLevel::CompactUi,
            ExplainQueryKind::Historical,
        );
        let m = r.match_section.unwrap();
        assert_eq!(m.outcome_key, MATCH_DEFAULT_ROUTE);
        assert!(m.matched_rule_id.is_none());
    }
}
