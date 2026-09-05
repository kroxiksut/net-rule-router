//! Interfaces & routes *preview* layer.
//!
//! The adapter rich-row enrichment SSOT (the [`InterfaceRouteRow`] type,
//! its sub-structs/enums, and the `build_*`/`collect_*`/`fallback_rows`
//! builders) lives in [`nrr_platform_api::interface_rows`] so the Windows
//! service can build identical rows without depending on this preview
//! crate. It is re-exported below so every existing call site
//! (`ui_surface.rs`, the `nrr-application` backend facade, this module's
//! own preview logic, and the tests) keeps compiling unchanged.
//!
//! What stays here is the *preview-only* layer: route-role selection,
//! the advisory recommendation scoring engine, and the per-adapter
//! diagnostics checks — all driven by a [`RouteSelectionRequest`] and
//! never run by the service path.

pub use nrr_platform_api::interface_rows::*;

use nrr_shared::{
    AdapterCheckActionId, AdapterCheckResultStatus, ConnectivityState, DerivedLikelihood,
    ExternalIpStatus, RecommendationClass, RecommendationConfidence, RouteBehaviorMode, RouteRole,
    RouteSelectionState,
};

pub const INTERFACES_ROLE_EXPLANATION: &str =
    "Primary route is the default preferred interface; secondary route is the fallback route.";

const SUPPORTED_ROUTE_BEHAVIOR_MODES: [RouteBehaviorMode; 3] = [
    RouteBehaviorMode::PreferPrimary,
    RouteBehaviorMode::PreferSecondaryWhenAvailable,
    RouteBehaviorMode::StrictSecondaryFailClosed,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSelectionRequest {
    pub primary_candidate_id: Option<String>,
    pub primary_candidate_name: Option<String>,
    pub primary_candidate_confirmed: bool,
    pub secondary_candidate_id: Option<String>,
    pub secondary_candidate_name: Option<String>,
    pub secondary_candidate_confirmed: bool,
    pub include_bluetooth_adapters: bool,
    pub behavior_mode: RouteBehaviorMode,
}

impl Default for RouteSelectionRequest {
    fn default() -> Self {
        Self {
            primary_candidate_id: None,
            primary_candidate_name: None,
            primary_candidate_confirmed: false,
            secondary_candidate_id: None,
            secondary_candidate_name: None,
            secondary_candidate_confirmed: false,
            include_bluetooth_adapters: false,
            behavior_mode: RouteBehaviorMode::default_when_secondary_unbound(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfacesRoutesPreviewSnapshot {
    pub data_source: InterfacesDataSource,
    pub role_explanation: &'static str,
    pub supported_behavior_modes: &'static [RouteBehaviorMode],
    pub selected_behavior_mode: RouteBehaviorMode,
    pub role_assignment_advisory: RoleAssignmentAdvisory,
    pub rows: Vec<InterfaceRouteRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterCheckResult {
    pub action: AdapterCheckActionId,
    pub status: AdapterCheckResultStatus,
    pub explanation: String,
    pub read_only: bool,
    pub requires_service_mediation: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceDiagnosticsChecksRow {
    pub persistent_id: String,
    pub windows_name: String,
    pub checks: Vec<AdapterCheckResult>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceDiagnosticsChecksSnapshot {
    pub data_source: InterfacesDataSource,
    pub rows: Vec<InterfaceDiagnosticsChecksRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleAssignmentAdvisory {
    pub manual_confirmation_required: bool,
    pub user_choice_priority_note: String,
    pub conflict_warning: Option<String>,
    pub warnings: Vec<String>,
}

pub fn interfaces_routes_preview_snapshot(
    request: RouteSelectionRequest,
) -> InterfacesRoutesPreviewSnapshot {
    // Preview path never runs an external-IP probe. The live enumeration is
    // Windows-only (`nrr-platform-windows`); off Windows the preview uses the
    // neutral deterministic fallback dataset.
    #[cfg(windows)]
    let (data_source, rows) = nrr_platform_windows::collect_interfaces_rows(false);
    #[cfg(not(windows))]
    let (data_source, rows) = (InterfacesDataSource::FallbackMock, fallback_rows());
    build_preview_snapshot(data_source, rows, &request)
}

/// Decorate externally-supplied rows (e.g. a snapshot pulled from the
/// service over IPC) with the preview engine's advisory recommendations and
/// the request's explicit role assignment, exactly as
/// [`interfaces_routes_preview_snapshot`] does for locally-enumerated rows.
/// This lets the IPC facade treat the service as the single source of truth
/// for the adapter list while still rendering a fully-decorated snapshot.
///
/// `data_source` is the provenance the SUPPLIER reported. It is a parameter
/// and not a constant because the service answers with a deterministic
/// placeholder dataset whenever its own live enumeration came back empty;
/// stamping every incoming row `WindowsLive` turned that placeholder into
/// four invented adapters the user could bind a route to.
pub fn decorate_interface_rows(
    rows: Vec<InterfaceRouteRow>,
    request: &RouteSelectionRequest,
    data_source: InterfacesDataSource,
) -> InterfacesRoutesPreviewSnapshot {
    build_preview_snapshot(data_source, rows, request)
}

fn build_preview_snapshot(
    data_source: InterfacesDataSource,
    mut rows: Vec<InterfaceRouteRow>,
    request: &RouteSelectionRequest,
) -> InterfacesRoutesPreviewSnapshot {
    if !request.include_bluetooth_adapters {
        // A row the user CONFIRMED for a role survives the filter whatever the
        // toggle says. `is_bluetooth_like` is a substring guess ("pan" matches
        // more than Bluetooth PAN), and dropping the confirmed adapter on a
        // false positive made it vanish from the screen under "Confirmed
        // primary adapter is currently unavailable in this snapshot" — a
        // message about an adapter that is present and working. It also made
        // the "confirmed primary uses Bluetooth" warning unreachable: the row
        // it warns about had already been removed.
        rows.retain(|row| !row.is_bluetooth_like || is_confirmed_for_a_role(row, request));
    }
    assign_recommendations(&mut rows, request);
    let role_assignment_advisory = assign_preview_roles(&mut rows, request);

    InterfacesRoutesPreviewSnapshot {
        data_source,
        role_explanation: INTERFACES_ROLE_EXPLANATION,
        supported_behavior_modes: &SUPPORTED_ROUTE_BEHAVIOR_MODES,
        selected_behavior_mode: request.behavior_mode,
        role_assignment_advisory,
        rows,
    }
}

pub fn interface_diagnostics_checks_snapshot(
    request: RouteSelectionRequest,
) -> InterfaceDiagnosticsChecksSnapshot {
    interface_diagnostics_checks_from(&interfaces_routes_preview_snapshot(request))
}

/// Derives the per-adapter checks from an ALREADY-TAKEN interfaces snapshot.
///
/// Every check reads only the row it is given, so a caller that already holds a
/// snapshot must not enumerate the adapters again: on Windows one snapshot is
/// two `GetAdaptersAddresses` plus `GetIpForwardTable` plus `GetAdaptersInfo`,
/// and taking a second one also means the rows and the checks describe two
/// DIFFERENT moments — a tunnel that came up in between showed as present in
/// one list and absent in the other.
pub fn interface_diagnostics_checks_from(
    snapshot: &InterfacesRoutesPreviewSnapshot,
) -> InterfaceDiagnosticsChecksSnapshot {
    interface_diagnostics_checks_from_rows(snapshot.data_source, &snapshot.rows)
}

/// Same derivation over an explicit row set, for a caller that has to narrow
/// the rows first (the desktop hides Bluetooth-like adapters unless asked).
pub fn interface_diagnostics_checks_from_rows(
    data_source: InterfacesDataSource,
    rows: &[InterfaceRouteRow],
) -> InterfaceDiagnosticsChecksSnapshot {
    let rows = rows
        .iter()
        .map(|row| InterfaceDiagnosticsChecksRow {
            persistent_id: row.persistent_id.clone(),
            windows_name: row.windows_name.clone(),
            checks: evaluate_adapter_checks(row),
        })
        .collect::<Vec<_>>();

    InterfaceDiagnosticsChecksSnapshot { data_source, rows }
}

/// Did the user confirm this row for either role?
///
/// Matched the way the resolvers match — id first, then name — so "the user
/// picked this one" means the same thing here as where the role is assigned.
fn is_confirmed_for_a_role(row: &InterfaceRouteRow, request: &RouteSelectionRequest) -> bool {
    let named = |confirmed: bool, id: Option<&str>, name: Option<&str>| {
        confirmed
            && (id.map(str::trim).is_some_and(|value| {
                !value.is_empty() && row.persistent_id.eq_ignore_ascii_case(value)
            }) || name.map(str::trim).is_some_and(|value| {
                !value.is_empty() && row.windows_name.eq_ignore_ascii_case(value)
            }))
    };
    named(
        request.primary_candidate_confirmed,
        request.primary_candidate_id.as_deref(),
        request.primary_candidate_name.as_deref(),
    ) || named(
        request.secondary_candidate_confirmed,
        request.secondary_candidate_id.as_deref(),
        request.secondary_candidate_name.as_deref(),
    )
}

/// Would the router actually route through this adapter?
///
/// `has_forwarding_path` is the platform layer's own answer, computed for
/// exactly the case a visible default route misses: OpenVPN / WireGuard TUN
/// links install split-defaults pointing at the tunnel PEER and report no
/// gateway at all, so judging them by `has_default_route` alone called a
/// perfectly healthy tunnel degraded — the one thing
/// `nrr_platform_api::interface_rows` promises the GUI will never do. `None`
/// means the layer could not tell, and then the visible default route is the
/// best evidence there is.
fn carries_traffic(row: &InterfaceRouteRow) -> bool {
    row.has_forwarding_path.unwrap_or(row.has_default_route)
}

/// A link that routes without advertising a gateway — the shape that made the
/// old check wrong, kept separate so the reason reaches the user.
fn routes_without_a_gateway(row: &InterfaceRouteRow) -> bool {
    carries_traffic(row) && !(row.has_default_route && row.gateway != "-")
}

fn assign_preview_roles(
    rows: &mut [InterfaceRouteRow],
    request: &RouteSelectionRequest,
) -> RoleAssignmentAdvisory {
    for row in rows.iter_mut() {
        row.selected_role = None;
        row.route_state = baseline_route_state(row);
    }

    let primary_index = resolve_explicit_primary_index(rows, request);
    if let Some(index) = primary_index {
        rows[index].selected_role = Some(RouteRole::Primary);
        if matches!(rows[index].route_state, RouteSelectionState::NotSelected) {
            rows[index].route_state = RouteSelectionState::Selected;
        }
    }

    let secondary_index = resolve_explicit_secondary_index(rows, request, primary_index);
    if let Some(index) = secondary_index {
        rows[index].selected_role = Some(RouteRole::Secondary);
        rows[index].route_state = secondary_state_for_row(&rows[index], request.behavior_mode);
    }

    // Heuristics remain advisory-only; no implicit assignment here.
    build_role_assignment_advisory(rows, request, primary_index, secondary_index)
}

fn baseline_route_state(row: &InterfaceRouteRow) -> RouteSelectionState {
    match row.availability_status {
        BasicAvailabilityStatus::Unavailable => RouteSelectionState::Unavailable,
        BasicAvailabilityStatus::RequiresCheck => RouteSelectionState::RequiresVerification,
        BasicAvailabilityStatus::Available => {
            if row.local_ip == "-" {
                RouteSelectionState::RequiresVerification
            } else {
                RouteSelectionState::NotSelected
            }
        }
    }
}

fn secondary_state_for_row(
    row: &InterfaceRouteRow,
    behavior_mode: RouteBehaviorMode,
) -> RouteSelectionState {
    match row.availability_status {
        BasicAvailabilityStatus::Unavailable => {
            if matches!(behavior_mode, RouteBehaviorMode::StrictSecondaryFailClosed) {
                RouteSelectionState::FailClosedConflict
            } else {
                RouteSelectionState::Unavailable
            }
        }
        BasicAvailabilityStatus::RequiresCheck => RouteSelectionState::RequiresVerification,
        BasicAvailabilityStatus::Available => {
            if row.local_ip == "-" {
                RouteSelectionState::RequiresVerification
            } else {
                RouteSelectionState::Selected
            }
        }
    }
}

fn resolve_explicit_primary_index(
    rows: &[InterfaceRouteRow],
    request: &RouteSelectionRequest,
) -> Option<usize> {
    if !request.primary_candidate_confirmed {
        return None;
    }

    if let Some(index) = resolve_id_index(rows, request.primary_candidate_id.as_deref(), None) {
        return Some(index);
    }

    resolve_named_index(rows, request.primary_candidate_name.as_deref(), None)
}

fn resolve_explicit_secondary_index(
    rows: &[InterfaceRouteRow],
    request: &RouteSelectionRequest,
    primary_index: Option<usize>,
) -> Option<usize> {
    if !request.secondary_candidate_confirmed {
        return None;
    }

    if let Some(index) = resolve_id_index(
        rows,
        request.secondary_candidate_id.as_deref(),
        primary_index,
    ) {
        return Some(index);
    }

    if let Some(index) = resolve_named_index(
        rows,
        request.secondary_candidate_name.as_deref(),
        primary_index,
    ) {
        return Some(index);
    }

    None
}

fn resolve_id_index(
    rows: &[InterfaceRouteRow],
    persistent_id: Option<&str>,
    excluded_index: Option<usize>,
) -> Option<usize> {
    let target = persistent_id?.trim();
    if target.is_empty() {
        return None;
    }

    rows.iter().enumerate().find_map(|(index, row)| {
        if Some(index) == excluded_index {
            return None;
        }
        if row.persistent_id.eq_ignore_ascii_case(target) {
            Some(index)
        } else {
            None
        }
    })
}

fn resolve_named_index(
    rows: &[InterfaceRouteRow],
    name: Option<&str>,
    excluded_index: Option<usize>,
) -> Option<usize> {
    let target = name?.trim();
    if target.is_empty() {
        return None;
    }

    rows.iter().enumerate().find_map(|(index, row)| {
        if Some(index) == excluded_index {
            return None;
        }
        if row.windows_name.eq_ignore_ascii_case(target) {
            Some(index)
        } else {
            None
        }
    })
}

fn build_role_assignment_advisory(
    rows: &[InterfaceRouteRow],
    request: &RouteSelectionRequest,
    primary_index: Option<usize>,
    secondary_index: Option<usize>,
) -> RoleAssignmentAdvisory {
    let conflict_warning = if requested_same_adapter_for_both_roles(request) {
        Some(
            "Primary and secondary cannot be confirmed as the same adapter in default mode."
                .to_string(),
        )
    } else {
        None
    };

    let mut warnings = Vec::new();
    if request.primary_candidate_confirmed && primary_index.is_none() {
        warnings.push(
            "Confirmed primary adapter is currently unavailable in this snapshot; selection is preserved until user changes it."
                .to_string(),
        );
    }
    if request.secondary_candidate_confirmed && secondary_index.is_none() {
        warnings.push(
            "Confirmed secondary adapter is currently unavailable (or conflicts with confirmed primary); selection is preserved until user changes it."
                .to_string(),
        );
    }

    if !request.secondary_candidate_confirmed
        && !rows.iter().any(|row| {
            row.recommendation.class == RecommendationClass::PreferredSecondary
                && row.recommendation.confidence != RecommendationConfidence::Unknown
        })
    {
        warnings.push(
            "No suitable secondary candidate was found; manual confirmation is needed.".to_string(),
        );
    }

    if let Some(index) = secondary_index {
        let secondary = &rows[index];
        if secondary.local_ip == "-" {
            warnings.push(
                "Confirmed secondary currently has no IP address; selection is preserved and marked for verification."
                    .to_string(),
            );
        }
        if secondary.recommendation.class == RecommendationClass::NotRecommended
            || matches!(
                secondary.observed_facts.connectivity_state,
                ConnectivityState::Unavailable
                    | ConnectivityState::Unknown
                    | ConnectivityState::Timeout
            )
        {
            warnings.push(
                "Confirmed secondary looks unstable or not recommended; selection is preserved, keep fallback expectations conservative."
                    .to_string(),
            );
        }
        if secondary.is_bluetooth_like {
            warnings.push(
                "Confirmed secondary uses Bluetooth; this profile is allowed but not recommended for stable fallback routing."
                    .to_string(),
            );
        }
    }

    if let Some(index) = primary_index {
        if rows[index].is_bluetooth_like {
            warnings.push(
                "Confirmed primary uses Bluetooth; this profile is allowed but not recommended for default routing."
                    .to_string(),
            );
        }
    }

    RoleAssignmentAdvisory {
        manual_confirmation_required: true,
        user_choice_priority_note:
            "User-confirmed role assignment has priority; recommendation is advisory-only."
                .to_string(),
        conflict_warning,
        warnings,
    }
}

/// Re-derivations of what the row already says — no packet is sent from here.
///
/// The wording matters because these strings reach the user verbatim: they used
/// to claim a check had been performed ("connectivity check indicates…",
/// `Timeout` for a timeout that never happened), so an adapter plugged into a
/// switch with a dead uplink collected a green tick. Each explanation now says
/// what it is actually based on — the interface's reported state — and the
/// statuses no longer invent an outcome the code did not observe.
fn evaluate_adapter_checks(row: &InterfaceRouteRow) -> Vec<AdapterCheckResult> {
    vec![
        evaluate_check_route(row),
        evaluate_show_external_ip(row),
        evaluate_check_internet_availability(row),
    ]
}

fn evaluate_check_route(row: &InterfaceRouteRow) -> AdapterCheckResult {
    let (status, explanation) = if row.availability_status == BasicAvailabilityStatus::Unavailable {
        (
            AdapterCheckResultStatus::Unavailable,
            "Adapter is unavailable; route check cannot be completed.",
        )
    } else if matches!(
        row.observed_facts.connectivity_state,
        ConnectivityState::Timeout
    ) {
        (
            AdapterCheckResultStatus::Timeout,
            "The adapter reports a connectivity timeout, so its route cannot be judged.",
        )
    } else if row.has_default_route && row.gateway != "-" {
        (
            AdapterCheckResultStatus::Success,
            "The adapter reports a default route and a gateway.",
        )
    } else if routes_without_a_gateway(row) {
        (
            AdapterCheckResultStatus::Success,
            "The adapter advertises no gateway, but a usable forwarding path was found for it \
             — the shape a VPN tunnel normally has.",
        )
    } else {
        (
            AdapterCheckResultStatus::Degraded,
            "The adapter reports no default route, no gateway, and no usable forwarding path.",
        )
    };

    AdapterCheckResult {
        action: AdapterCheckActionId::CheckRoute,
        status,
        explanation: explanation.to_string(),
        read_only: true,
        requires_service_mediation: false,
    }
}

fn evaluate_show_external_ip(row: &InterfaceRouteRow) -> AdapterCheckResult {
    let (status, explanation) = match row.observed_facts.external_ip_status {
        // `Resolved` with no address is not a success — it is a row that says
        // one thing and carries another. It used to print "resolved: unknown".
        ExternalIpStatus::Resolved => match row.observed_facts.external_ip.as_deref() {
            Some(ip) => (
                AdapterCheckResultStatus::Success,
                format!("The adapter reports an external address: {ip}."),
            ),
            None => (
                AdapterCheckResultStatus::Degraded,
                "The adapter reports a resolved external address but carries none.".to_string(),
            ),
        },
        ExternalIpStatus::NotChecked => (
            AdapterCheckResultStatus::Degraded,
            "No external address has been looked up for this adapter.".to_string(),
        ),
        ExternalIpStatus::CheckFailed | ExternalIpStatus::RateLimited => (
            AdapterCheckResultStatus::Degraded,
            "The last external-address lookup did not finish.".to_string(),
        ),
        ExternalIpStatus::Blocked => (
            AdapterCheckResultStatus::Unavailable,
            "External-address lookups are blocked in this environment.".to_string(),
        ),
    };

    AdapterCheckResult {
        action: AdapterCheckActionId::ShowExternalIp,
        status,
        explanation,
        read_only: true,
        requires_service_mediation: false,
    }
}

fn evaluate_check_internet_availability(row: &InterfaceRouteRow) -> AdapterCheckResult {
    let (status, explanation) = match row.observed_facts.connectivity_state {
        ConnectivityState::Available => (
            AdapterCheckResultStatus::Success,
            "The adapter reports a usable connection.".to_string(),
        ),
        ConnectivityState::Degraded | ConnectivityState::Unknown => (
            AdapterCheckResultStatus::Degraded,
            "The adapter reports an uncertain connection; confirm it yourself.".to_string(),
        ),
        ConnectivityState::Unavailable => (
            AdapterCheckResultStatus::Unavailable,
            "The adapter reports no usable connection.".to_string(),
        ),
        ConnectivityState::Timeout => (
            AdapterCheckResultStatus::Timeout,
            "The adapter reports a connectivity timeout.".to_string(),
        ),
    };

    AdapterCheckResult {
        action: AdapterCheckActionId::CheckInternetAvailability,
        status,
        explanation,
        read_only: true,
        requires_service_mediation: false,
    }
}

fn requested_same_adapter_for_both_roles(request: &RouteSelectionRequest) -> bool {
    if request.primary_candidate_confirmed && request.secondary_candidate_confirmed {
        if let (Some(primary_id), Some(secondary_id)) = (
            request.primary_candidate_id.as_deref(),
            request.secondary_candidate_id.as_deref(),
        ) {
            let primary_id = primary_id.trim();
            let secondary_id = secondary_id.trim();
            if !primary_id.is_empty() && primary_id.eq_ignore_ascii_case(secondary_id) {
                return true;
            }
        }
        if let (Some(primary_name), Some(secondary_name)) = (
            request.primary_candidate_name.as_deref(),
            request.secondary_candidate_name.as_deref(),
        ) {
            let primary_name = primary_name.trim();
            let secondary_name = secondary_name.trim();
            if !primary_name.is_empty() && primary_name.eq_ignore_ascii_case(secondary_name) {
                return true;
            }
        }
    }
    false
}

#[derive(Clone, Debug)]
struct RecommendationScore {
    primary_score: i32,
    secondary_score: i32,
    blocked: bool,
    confidence: RecommendationConfidence,
    key_signals: Vec<String>,
}

fn assign_recommendations(rows: &mut [InterfaceRouteRow], request: &RouteSelectionRequest) {
    // The SAME resolution the role assignment uses, so the pin that scores and
    // the pin that gets the role can never be two different adapters. Matching
    // "id or name" here instead let a stale name out of a renamed adapter hand
    // the +5 and the tie-break to a row that holds no role.
    let explicit = ExplicitChoices::resolve(rows, request);

    let scores = rows
        .iter()
        .enumerate()
        .map(|(index, row)| (index, evaluate_recommendation_score(row, index, explicit)))
        .collect::<Vec<_>>();

    let best_primary_index = scores
        .iter()
        .filter(|(_, score)| !score.blocked)
        .max_by_key(|(index, score)| {
            (
                score.primary_score,
                primary_tie_break_weight(&rows[*index], *index, explicit),
            )
        })
        .map(|(index, _)| *index);

    let best_secondary_index = scores
        .iter()
        .filter(|(index, score)| !score.blocked && Some(*index) != best_primary_index)
        .max_by_key(|(index, score)| {
            (
                score.secondary_score,
                secondary_tie_break_weight(&rows[*index], *index, explicit),
            )
        })
        .map(|(index, _)| *index);

    for (index, score) in scores {
        let class = if score.blocked {
            RecommendationClass::NotRecommended
        } else if rows[index].is_bluetooth_like {
            RecommendationClass::AllowedButNotRecommended
        } else if Some(index) == best_primary_index && score.primary_score >= 6 {
            RecommendationClass::PreferredPrimary
        } else if Some(index) == best_secondary_index && score.secondary_score >= 5 {
            RecommendationClass::PreferredSecondary
        } else {
            RecommendationClass::AllowedButNotRecommended
        };

        let mut excluded_alternatives = Vec::new();
        if class != RecommendationClass::PreferredPrimary {
            if let Some(best_index) = best_primary_index {
                if best_index != index {
                    excluded_alternatives.push(format!(
                        "better-primary-candidate={}",
                        rows[best_index].windows_name
                    ));
                }
            }
        }
        if class != RecommendationClass::PreferredSecondary {
            if let Some(best_index) = best_secondary_index {
                if best_index != index {
                    excluded_alternatives.push(format!(
                        "better-secondary-candidate={}",
                        rows[best_index].windows_name
                    ));
                }
            }
        }

        rows[index].recommendation = RouteRoleRecommendation {
            class,
            confidence: score.confidence,
            advisory_only: true,
            summary: recommendation_summary_for_class(class),
            key_signals: score.key_signals,
            excluded_alternatives,
        };
    }
}

fn evaluate_recommendation_score(
    row: &InterfaceRouteRow,
    index: usize,
    explicit: ExplicitChoices,
) -> RecommendationScore {
    let mut primary_score = 0;
    let mut secondary_score = 0;
    let mut key_signals = Vec::new();

    let mut blocked = false;
    if row.availability_status == BasicAvailabilityStatus::Unavailable {
        blocked = true;
        key_signals.push("blocked-unavailable-interface".to_string());
    }
    if row.runtime_data_unavailable {
        // Every row reads "-" because the query failed. Blocking here would
        // report "no usable adapter" for a machine whose link is fine.
        key_signals.push("adapter-data-unreadable".to_string());
    } else if row.local_ip == "-" {
        blocked = true;
        key_signals.push("blocked-missing-local-ip".to_string());
    }
    // Two of the three signals behind the service-interface verdict are "no
    // gateway, no IP" and "connectivity unknown" — exactly what an unreadable
    // query looks like — so it cannot block when the data never arrived.
    if row.derived_assessment.service_interface_likelihood == DerivedLikelihood::Likely
        && !row.runtime_data_unavailable
    {
        blocked = true;
        key_signals.push("blocked-service-interface-likely".to_string());
    }

    match row.observed_facts.connectivity_state {
        ConnectivityState::Available => {
            primary_score += 4;
            secondary_score += 2;
            key_signals.push("connectivity-available".to_string());
        }
        ConnectivityState::Degraded => {
            primary_score += 2;
            secondary_score += 2;
            key_signals.push("connectivity-degraded".to_string());
        }
        ConnectivityState::Timeout => {
            primary_score -= 1;
            secondary_score -= 1;
            key_signals.push("connectivity-timeout".to_string());
        }
        ConnectivityState::Unknown => {
            primary_score -= 1;
            secondary_score -= 1;
            key_signals.push("connectivity-unknown".to_string());
        }
        ConnectivityState::Unavailable => {
            primary_score -= 4;
            secondary_score -= 3;
            key_signals.push("connectivity-unavailable".to_string());
        }
    }

    if row.has_default_route {
        primary_score += 3;
        key_signals.push("has-default-route".to_string());
    } else if carries_traffic(row) {
        // A gateway-less tunnel routes as well as anything; it just says so
        // differently. Scoring it as "no default route" pushed a healthy
        // WireGuard link down by 2 and handed the +1 to whatever else was
        // around.
        primary_score += 3;
        key_signals.push("forwarding-path-without-gateway".to_string());
    } else if row.has_forwarding_path == Some(false)
        && row.derived_assessment.vpn_tunnel_likelihood != DerivedLikelihood::Likely
    {
        // The platform layer looked and found no way out through this adapter,
        // and it does not look like a tunnel either — a host-only virtual
        // switch, an adapter with no usable next hop. Preferring THAT as the
        // secondary is the worst outcome available: rules would be routed into
        // a link that reaches nothing.
        //
        // A VPN-shaped adapter is deliberately exempt: at the moment the user
        // is choosing their secondary the tunnel is usually still down, which
        // is the same `Some(false)`. Penalising it there would stop the app
        // recommending the very adapter the user came to bind.
        primary_score -= 2;
        secondary_score -= 3;
        key_signals.push("no-forwarding-path".to_string());
    } else {
        primary_score -= 2;
        secondary_score += 1;
        key_signals.push("no-default-route".to_string());
    }

    match row.observed_facts.external_ip_status {
        ExternalIpStatus::Resolved => {
            primary_score += 2;
            secondary_score += 1;
            key_signals.push("external-ip-resolved".to_string());
        }
        ExternalIpStatus::NotChecked => {
            key_signals.push("external-ip-not-checked".to_string());
        }
        ExternalIpStatus::CheckFailed
        | ExternalIpStatus::RateLimited
        | ExternalIpStatus::Blocked => {
            primary_score -= 1;
            key_signals.push("external-ip-check-not-successful".to_string());
        }
    }

    match row.derived_assessment.vpn_tunnel_likelihood {
        DerivedLikelihood::Likely => {
            primary_score -= 4;
            secondary_score += 4;
            key_signals.push("vpn-tunnel-likely".to_string());
        }
        DerivedLikelihood::Possible => {
            primary_score -= 1;
            secondary_score += 2;
            key_signals.push("vpn-tunnel-possible".to_string());
        }
        DerivedLikelihood::Unlikely => {
            primary_score += 1;
        }
        DerivedLikelihood::Unknown => {}
    }

    if row.derived_assessment.virtual_interface_likelihood == DerivedLikelihood::Likely {
        primary_score -= 3;
        secondary_score -= 2;
        key_signals.push("virtual-interface-likely".to_string());
    }
    if row.is_bluetooth_like {
        primary_score -= 4;
        secondary_score -= 2;
        key_signals.push("bluetooth-adapter-nondefault-routing-profile".to_string());
    }

    if explicit.is_primary(index) {
        primary_score += 5;
        key_signals.push("manual-primary-pin".to_string());
    }
    if explicit.is_secondary(index) {
        secondary_score += 5;
        key_signals.push("manual-secondary-pin".to_string());
    }

    if !row.persistent_id.trim().is_empty() {
        primary_score += 1;
        secondary_score += 1;
        key_signals.push("stable-identity-present".to_string());
    }

    let confidence = if blocked {
        RecommendationConfidence::High
    } else {
        let top_score = primary_score.max(secondary_score);
        if top_score >= 9 {
            RecommendationConfidence::High
        } else if top_score >= 6 {
            RecommendationConfidence::Medium
        } else if top_score >= 3 {
            RecommendationConfidence::Low
        } else {
            RecommendationConfidence::Unknown
        }
    };

    RecommendationScore {
        primary_score,
        secondary_score,
        blocked,
        confidence,
        key_signals,
    }
}

fn primary_tie_break_weight(
    row: &InterfaceRouteRow,
    index: usize,
    explicit: ExplicitChoices,
) -> i32 {
    let mut weight = 0;
    if explicit.is_primary(index) {
        weight += 100;
    }
    if !row.persistent_id.trim().is_empty() {
        weight += 10;
    }
    if carries_traffic(row) {
        weight += 5;
    }
    weight
}

fn secondary_tie_break_weight(
    row: &InterfaceRouteRow,
    index: usize,
    explicit: ExplicitChoices,
) -> i32 {
    let mut weight = 0;
    if explicit.is_secondary(index) {
        weight += 100;
    }
    if !row.persistent_id.trim().is_empty() {
        weight += 10;
    }
    if row.derived_assessment.vpn_tunnel_likelihood == DerivedLikelihood::Likely {
        weight += 8;
    }
    weight
}

/// The rows the user's confirmed pins resolve to, resolved once per pass.
#[derive(Clone, Copy, Debug, Default)]
struct ExplicitChoices {
    primary: Option<usize>,
    secondary: Option<usize>,
}

impl ExplicitChoices {
    fn resolve(rows: &[InterfaceRouteRow], request: &RouteSelectionRequest) -> Self {
        let primary = resolve_explicit_primary_index(rows, request);
        Self {
            primary,
            secondary: resolve_explicit_secondary_index(rows, request, primary),
        }
    }

    fn is_primary(self, index: usize) -> bool {
        self.primary == Some(index)
    }

    fn is_secondary(self, index: usize) -> bool {
        self.secondary == Some(index)
    }
}

fn recommendation_summary_for_class(class: RecommendationClass) -> String {
    match class {
        RecommendationClass::PreferredPrimary => {
            "Looks like primary internet interface".to_string()
        }
        RecommendationClass::PreferredSecondary => {
            "Looks like fallback/VPN secondary interface".to_string()
        }
        RecommendationClass::AllowedButNotRecommended => {
            "Usable, but not a top recommendation".to_string()
        }
        RecommendationClass::NotRecommended => {
            "Not recommended for routing role assignment".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        assign_preview_roles, assign_recommendations, decorate_interface_rows, fallback_rows,
        interface_diagnostics_checks_from, interface_diagnostics_checks_snapshot,
        interfaces_routes_preview_snapshot, InterfaceRouteRow, InterfacesDataSource,
        RouteSelectionRequest,
    };
    use nrr_shared::{ConnectivityState, RouteBehaviorMode, RouteRole, RouteSelectionState};

    #[test]
    fn named_candidates_are_respected_in_preview_assignment() {
        let mut rows = fallback_rows();
        let request = RouteSelectionRequest {
            primary_candidate_id: None,
            primary_candidate_name: Some("Wi-Fi".to_string()),
            primary_candidate_confirmed: true,
            secondary_candidate_id: None,
            secondary_candidate_name: Some("Ethernet".to_string()),
            secondary_candidate_confirmed: true,
            include_bluetooth_adapters: false,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        };
        assign_preview_roles(&mut rows, &request);

        let wifi = find_row(&rows, "Wi-Fi");
        let ethernet = find_row(&rows, "Ethernet");
        assert_eq!(wifi.selected_role, Some(RouteRole::Primary));
        assert_eq!(wifi.route_state, RouteSelectionState::Selected);
        assert_eq!(ethernet.selected_role, Some(RouteRole::Secondary));
        assert_eq!(ethernet.route_state, RouteSelectionState::Selected);
    }

    #[test]
    fn strict_secondary_mode_marks_unavailable_secondary_as_conflict() {
        let mut rows = vec![
            InterfaceRouteRow {
                persistent_id: "win-adapter:primary".to_string(),
                adapter_name: "{PRIMARY-ADAPTER}".to_string(),
                windows_name: "Primary".to_string(),
                interface_description: "Primary adapter".to_string(),
                interface_type: "Ethernet".to_string(),
                is_bluetooth_like: false,
                local_ip: "192.168.0.2".to_string(),
                gateway: "192.168.0.1".to_string(),
                dns_servers: "1.1.1.1".to_string(),
                has_default_route: true,
                has_forwarding_path: Some(true),
                runtime_data_unavailable: false,
                availability_status: super::BasicAvailabilityStatus::Available,
                observed_facts: super::build_observed_facts(
                    super::BasicAvailabilityStatus::Available,
                    "192.168.0.2",
                    "192.168.0.1",
                ),
                derived_assessment: super::build_derived_assessment(
                    "Primary",
                    "Ethernet",
                    "Primary adapter",
                    "{PRIMARY-ADAPTER}",
                    "192.168.0.1",
                    "192.168.0.2",
                    true,
                    ConnectivityState::Available,
                ),
                recommendation: super::unknown_recommendation(),
                selected_role: None,
                route_state: RouteSelectionState::NotSelected,
            },
            InterfaceRouteRow {
                persistent_id: "win-adapter:backup".to_string(),
                adapter_name: "{BACKUP-ADAPTER}".to_string(),
                windows_name: "Backup".to_string(),
                interface_description: "Backup adapter".to_string(),
                interface_type: "Wireless".to_string(),
                is_bluetooth_like: false,
                local_ip: "-".to_string(),
                gateway: "-".to_string(),
                dns_servers: "-".to_string(),
                has_forwarding_path: Some(false),
                runtime_data_unavailable: false,
                has_default_route: false,
                availability_status: super::BasicAvailabilityStatus::Unavailable,
                observed_facts: super::build_observed_facts(
                    super::BasicAvailabilityStatus::Unavailable,
                    "-",
                    "-",
                ),
                derived_assessment: super::build_derived_assessment(
                    "Backup",
                    "Wireless",
                    "Backup adapter",
                    "{BACKUP-ADAPTER}",
                    "-",
                    "-",
                    false,
                    ConnectivityState::Unavailable,
                ),
                recommendation: super::unknown_recommendation(),
                selected_role: None,
                route_state: RouteSelectionState::Unavailable,
            },
        ];

        let request = RouteSelectionRequest {
            primary_candidate_id: None,
            primary_candidate_name: Some("Primary".to_string()),
            primary_candidate_confirmed: true,
            secondary_candidate_id: None,
            secondary_candidate_name: Some("Backup".to_string()),
            secondary_candidate_confirmed: true,
            include_bluetooth_adapters: false,
            behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
        };
        assign_preview_roles(&mut rows, &request);

        let backup = find_row(&rows, "Backup");
        assert_eq!(backup.selected_role, Some(RouteRole::Secondary));
        assert_eq!(backup.route_state, RouteSelectionState::FailClosedConflict);
    }

    #[test]
    fn snapshot_exposes_preview_contract_markers() {
        let snapshot = interfaces_routes_preview_snapshot(RouteSelectionRequest::default());
        assert!(!snapshot.rows.is_empty());
        assert!(snapshot
            .supported_behavior_modes
            .contains(&RouteBehaviorMode::StrictSecondaryFailClosed));
    }

    #[test]
    fn stable_identity_candidates_are_respected_before_names() {
        let mut rows = fallback_rows();
        let request = RouteSelectionRequest {
            primary_candidate_id: Some("win-adapter:ethernet-fallback".to_string()),
            primary_candidate_name: Some("Wi-Fi".to_string()),
            primary_candidate_confirmed: true,
            secondary_candidate_id: Some("win-adapter:wifi-fallback".to_string()),
            secondary_candidate_name: Some("Ethernet".to_string()),
            secondary_candidate_confirmed: true,
            include_bluetooth_adapters: false,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        };
        assign_preview_roles(&mut rows, &request);

        let ethernet = find_row(&rows, "Ethernet");
        let wifi = find_row(&rows, "Wi-Fi");
        assert_eq!(ethernet.selected_role, Some(RouteRole::Primary));
        assert_eq!(wifi.selected_role, Some(RouteRole::Secondary));
    }

    #[test]
    fn fallback_rows_include_enriched_connectivity_and_external_ip_status() {
        let rows = fallback_rows();
        let ethernet = find_row(&rows, "Ethernet");
        let vpn = find_row(&rows, "VPN");

        assert_eq!(
            ethernet.observed_facts.connectivity_state,
            ConnectivityState::Available
        );
        // No probe runs in a placeholder dataset, so neither row may claim a
        // resolved external address.
        assert_eq!(
            ethernet.observed_facts.external_ip_status,
            nrr_shared::ExternalIpStatus::NotChecked
        );
        assert_eq!(
            vpn.observed_facts.connectivity_state,
            ConnectivityState::Unknown
        );
        assert_eq!(
            vpn.observed_facts.external_ip_status,
            nrr_shared::ExternalIpStatus::NotChecked
        );
    }

    #[test]
    fn derived_assessment_marks_tunnel_as_vpn_likely_and_heuristic_only() {
        let rows = fallback_rows();
        let vpn = find_row(&rows, "VPN");
        assert_eq!(
            vpn.derived_assessment.vpn_tunnel_likelihood,
            nrr_shared::DerivedLikelihood::Likely
        );
        assert!(vpn.derived_assessment.heuristic_only);
        assert!(!vpn.derived_assessment.signals.is_empty());
    }

    #[test]
    fn heuristics_do_not_auto_assign_roles_without_user_choice() {
        let snapshot = interfaces_routes_preview_snapshot(RouteSelectionRequest::default());
        assert!(snapshot.rows.iter().all(|row| row.selected_role.is_none()));
    }

    /// A failed IP Helper query leaves EVERY row at `"-"`. Read as "this
    /// adapter has no address" it blocks all of them, and a machine with a
    /// working link is told it has no usable adapter.
    #[test]
    fn a_failed_data_query_does_not_block_every_adapter() {
        let mut row = InterfaceRouteRow {
            persistent_id: "win-adapter:primary".to_string(),
            adapter_name: "{PRIMARY-ADAPTER}".to_string(),
            windows_name: "Primary".to_string(),
            interface_description: "Primary adapter".to_string(),
            interface_type: "Ethernet".to_string(),
            is_bluetooth_like: false,
            local_ip: "-".to_string(),
            gateway: "-".to_string(),
            dns_servers: "-".to_string(),
            has_default_route: false,
            has_forwarding_path: None,
            runtime_data_unavailable: true,
            availability_status: super::BasicAvailabilityStatus::Available,
            observed_facts: super::build_observed_facts(
                super::BasicAvailabilityStatus::Available,
                "-",
                "-",
            ),
            derived_assessment: super::build_derived_assessment(
                "Primary",
                "Ethernet",
                "Primary adapter",
                "{PRIMARY-ADAPTER}",
                "-",
                "-",
                false,
                ConnectivityState::Unknown,
            ),
            recommendation: super::unknown_recommendation(),
            selected_role: None,
            route_state: RouteSelectionState::NotSelected,
        };

        let explicit = super::ExplicitChoices {
            primary: None,
            secondary: None,
        };
        let unreadable = super::evaluate_recommendation_score(&row, 0, explicit);
        assert!(
            !unreadable.blocked,
            "a query that failed is not evidence the adapter is unusable"
        );
        assert!(unreadable
            .key_signals
            .iter()
            .any(|s| s == "adapter-data-unreadable"));

        // The same row without the flag IS a genuine "no address" reading.
        row.runtime_data_unavailable = false;
        let genuine = super::evaluate_recommendation_score(&row, 0, explicit);
        assert!(genuine.blocked);
        assert!(genuine
            .key_signals
            .iter()
            .any(|s| s == "blocked-missing-local-ip"));
    }

    #[test]
    fn recommendation_engine_marks_primary_and_secondary_candidates() {
        // Fixed two-adapter fixture (strong wired link + VPN-shaped tunnel) run
        // through the same decoration path production uses for service-supplied
        // rows, so the assertion doesn't depend on what the host machine enumerates.
        let wired = InterfaceRouteRow {
            persistent_id: "win-adapter:primary".to_string(),
            adapter_name: "{PRIMARY-ADAPTER}".to_string(),
            windows_name: "Primary".to_string(),
            interface_description: "Primary adapter".to_string(),
            interface_type: "Ethernet".to_string(),
            is_bluetooth_like: false,
            local_ip: "192.168.0.2".to_string(),
            gateway: "192.168.0.1".to_string(),
            dns_servers: "1.1.1.1".to_string(),
            has_default_route: true,
            has_forwarding_path: Some(true),
            runtime_data_unavailable: false,
            availability_status: super::BasicAvailabilityStatus::Available,
            observed_facts: super::build_observed_facts(
                super::BasicAvailabilityStatus::Available,
                "192.168.0.2",
                "192.168.0.1",
            ),
            derived_assessment: super::build_derived_assessment(
                "Primary",
                "Ethernet",
                "Primary adapter",
                "{PRIMARY-ADAPTER}",
                "192.168.0.1",
                "192.168.0.2",
                true,
                ConnectivityState::Available,
            ),
            recommendation: super::unknown_recommendation(),
            selected_role: None,
            route_state: RouteSelectionState::NotSelected,
        };
        let vpn_tunnel = InterfaceRouteRow {
            persistent_id: "win-adapter:vpn-tunnel".to_string(),
            adapter_name: "{VPN-ADAPTER}".to_string(),
            windows_name: "VPN Tunnel".to_string(),
            interface_description: "VPN tunnel adapter".to_string(),
            interface_type: "Tunnel".to_string(),
            is_bluetooth_like: false,
            local_ip: "10.8.0.5".to_string(),
            gateway: "-".to_string(),
            dns_servers: "-".to_string(),
            has_default_route: false,
            has_forwarding_path: Some(false),
            runtime_data_unavailable: false,
            availability_status: super::BasicAvailabilityStatus::Available,
            observed_facts: super::build_observed_facts(
                super::BasicAvailabilityStatus::Available,
                "10.8.0.5",
                "-",
            ),
            derived_assessment: super::build_derived_assessment(
                "VPN Tunnel",
                "Tunnel",
                "VPN tunnel adapter",
                "{VPN-ADAPTER}",
                "-",
                "10.8.0.5",
                false,
                ConnectivityState::Degraded,
            ),
            recommendation: super::unknown_recommendation(),
            selected_role: None,
            route_state: RouteSelectionState::NotSelected,
        };

        let snapshot = decorate_interface_rows(
            vec![wired, vpn_tunnel],
            &RouteSelectionRequest::default(),
            InterfacesDataSource::WindowsLive,
        );
        assert!(snapshot.rows.iter().any(|row| {
            row.recommendation.class == nrr_shared::RecommendationClass::PreferredPrimary
        }));
        assert!(snapshot.rows.iter().any(|row| {
            row.recommendation.class == nrr_shared::RecommendationClass::PreferredSecondary
        }));
        assert!(snapshot
            .rows
            .iter()
            .all(|row| row.recommendation.advisory_only));
    }

    /// The platform layer computes `has_forwarding_path` for exactly the link a
    /// visible default route misses: a TUN tunnel that points its split-default
    /// at the PEER and advertises no gateway at all. Judging it by
    /// `has_default_route` called a healthy tunnel degraded — the one thing
    /// `nrr_platform_api::interface_rows` promises the GUI will never do.
    #[test]
    fn a_gatewayless_link_with_a_forwarding_path_is_not_called_degraded() {
        let mut rows = fallback_rows();
        let vpn = rows
            .iter_mut()
            .find(|row| row.windows_name == "VPN")
            .expect("fallback set has a VPN row");
        vpn.has_default_route = false;
        vpn.gateway = "-".to_string();
        vpn.has_forwarding_path = Some(true);
        vpn.availability_status = super::BasicAvailabilityStatus::Available;
        vpn.observed_facts.connectivity_state = ConnectivityState::Available;

        let checks = super::evaluate_adapter_checks(find_row(&rows, "VPN"));
        let route_check = checks
            .iter()
            .find(|c| c.action == nrr_shared::AdapterCheckActionId::CheckRoute)
            .expect("route check present");
        assert_eq!(
            route_check.status,
            nrr_shared::AdapterCheckResultStatus::Success,
            "a usable forwarding path is a route, gateway or not: {}",
            route_check.explanation
        );

        // Positive control: with the platform layer reporting no way out, the
        // same row is still degraded.
        let mut cold = rows.clone();
        cold.iter_mut()
            .find(|row| row.windows_name == "VPN")
            .expect("row")
            .has_forwarding_path = Some(false);
        let checks = super::evaluate_adapter_checks(find_row(&cold, "VPN"));
        let route_check = checks
            .iter()
            .find(|c| c.action == nrr_shared::AdapterCheckActionId::CheckRoute)
            .expect("route check present");
        assert_eq!(
            route_check.status,
            nrr_shared::AdapterCheckResultStatus::Degraded
        );
    }

    /// An adapter the platform layer says reaches nothing must not be the
    /// PREFERRED secondary — rules would be routed into a link that goes
    /// nowhere. The exemption that keeps the setup flow working is tested with
    /// it: a VPN-shaped adapter is normally down at the moment the user binds
    /// it, and that is the same `Some(false)`.
    #[test]
    fn an_adapter_with_no_way_out_is_not_recommended_unless_it_looks_like_a_tunnel() {
        let mut rows = fallback_rows();
        for row in rows.iter_mut() {
            if row.windows_name == "Wi-Fi" {
                row.has_default_route = false;
                row.gateway = "-".to_string();
                row.has_forwarding_path = Some(false);
            }
        }
        assign_recommendations(&mut rows, &RouteSelectionRequest::default());
        assert!(find_row(&rows, "Wi-Fi")
            .recommendation
            .key_signals
            .iter()
            .any(|s| s == "no-forwarding-path"));
        assert_ne!(
            find_row(&rows, "Wi-Fi").recommendation.class,
            nrr_shared::RecommendationClass::PreferredSecondary
        );

        // The VPN row of the same fixture already carries
        // `has_forwarding_path: Some(false)` and a tunnel likelihood — it keeps
        // its old score, because a tunnel that is not up yet is the normal
        // state at binding time.
        assert!(!find_row(&rows, "VPN")
            .recommendation
            .key_signals
            .iter()
            .any(|s| s == "no-forwarding-path"));
    }

    #[test]
    fn a_stale_name_does_not_pin_a_second_adapter() {
        // Rename an adapter and the saved name still matches the row that took
        // it over, while the saved id keeps pointing at the original. The role
        // goes to the id (id-first resolution), so the scoring bonus must go
        // there too — otherwise the GUI recommends one adapter while another
        // holds the role.
        let mut rows = fallback_rows();
        let request = RouteSelectionRequest {
            primary_candidate_id: Some("win-adapter:ethernet-fallback".to_string()),
            primary_candidate_name: Some("Wi-Fi".to_string()),
            primary_candidate_confirmed: true,
            secondary_candidate_id: None,
            secondary_candidate_name: None,
            secondary_candidate_confirmed: false,
            include_bluetooth_adapters: false,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        };
        assign_preview_roles(&mut rows, &request);
        assign_recommendations(&mut rows, &request);

        assert_eq!(
            find_row(&rows, "Ethernet").selected_role,
            Some(RouteRole::Primary)
        );
        assert!(find_row(&rows, "Ethernet")
            .recommendation
            .key_signals
            .iter()
            .any(|s| s == "manual-primary-pin"));
        assert!(!find_row(&rows, "Wi-Fi")
            .recommendation
            .key_signals
            .iter()
            .any(|s| s == "manual-primary-pin"));
    }

    #[test]
    fn an_empty_id_is_not_an_explicit_choice() {
        let mut rows = fallback_rows();
        let request = RouteSelectionRequest {
            primary_candidate_id: Some(String::new()),
            primary_candidate_name: None,
            primary_candidate_confirmed: true,
            secondary_candidate_id: None,
            secondary_candidate_name: None,
            secondary_candidate_confirmed: false,
            include_bluetooth_adapters: false,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        };
        assign_recommendations(&mut rows, &request);

        assert!(rows.iter().all(|row| !row
            .recommendation
            .key_signals
            .iter()
            .any(|s| s == "manual-primary-pin")));
    }

    #[test]
    fn bluetooth_rows_are_hidden_by_default() {
        let mut rows = fallback_rows();
        assert!(rows
            .iter()
            .any(|row| row.windows_name == "Bluetooth PAN" && row.is_bluetooth_like));
        rows.retain(|row| !row.is_bluetooth_like);
        assert!(!rows.iter().any(|row| row.windows_name == "Bluetooth PAN"));
    }

    /// The row the user confirmed is never filtered away by a substring guess.
    /// Before this, a false "pan" match made the confirmed adapter disappear
    /// under "Confirmed primary adapter is currently unavailable in this
    /// snapshot" — about an adapter that is present and working — and the
    /// Bluetooth warning that exists for exactly this case could never fire.
    #[test]
    fn a_confirmed_adapter_survives_the_bluetooth_filter() {
        let request = RouteSelectionRequest {
            primary_candidate_id: None,
            primary_candidate_name: Some("Bluetooth PAN".to_string()),
            primary_candidate_confirmed: true,
            secondary_candidate_id: None,
            secondary_candidate_name: None,
            secondary_candidate_confirmed: false,
            include_bluetooth_adapters: false,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        };
        let snapshot = decorate_interface_rows(
            fallback_rows(),
            &request,
            InterfacesDataSource::FallbackMock,
        );

        let kept = find_row(&snapshot.rows, "Bluetooth PAN");
        assert_eq!(kept.selected_role, Some(RouteRole::Primary));
        assert!(
            snapshot
                .role_assignment_advisory
                .warnings
                .iter()
                .any(|w| w.contains("Bluetooth")),
            "the warning about the confirmed choice must be reachable"
        );

        // Negative control: an UNCONFIRMED Bluetooth row is still filtered out.
        let snapshot = decorate_interface_rows(
            fallback_rows(),
            &RouteSelectionRequest::default(),
            InterfacesDataSource::FallbackMock,
        );
        assert!(!snapshot
            .rows
            .iter()
            .any(|row| row.windows_name == "Bluetooth PAN"));
    }

    #[test]
    fn bluetooth_rows_can_be_included_explicitly() {
        let mut rows = fallback_rows();
        let request = RouteSelectionRequest {
            include_bluetooth_adapters: true,
            ..RouteSelectionRequest::default()
        };
        assign_recommendations(&mut rows, &request);
        assert!(rows.iter().any(|row| row.windows_name == "Bluetooth PAN"));
    }

    #[test]
    fn bluetooth_row_is_never_preferred_when_included() {
        let mut rows = fallback_rows();
        let request = RouteSelectionRequest {
            include_bluetooth_adapters: true,
            ..RouteSelectionRequest::default()
        };
        assign_recommendations(&mut rows, &request);
        let bluetooth = find_row(&rows, "Bluetooth PAN");
        assert_eq!(
            bluetooth.recommendation.class,
            nrr_shared::RecommendationClass::AllowedButNotRecommended
        );
        assert!(bluetooth
            .recommendation
            .key_signals
            .iter()
            .any(|signal| { signal == "bluetooth-adapter-nondefault-routing-profile" }));
    }

    #[test]
    fn same_adapter_cannot_be_confirmed_for_primary_and_secondary() {
        // Deterministic fixture: live enumeration on a host without an
        // "Ethernet"-named adapter would leave both roles unresolved and the
        // assertions below vacuously true, so exercise the fallback dataset instead.
        let snapshot = decorate_interface_rows(
            fallback_rows(),
            &RouteSelectionRequest {
                primary_candidate_id: Some("win-adapter:ethernet-fallback".to_string()),
                primary_candidate_name: Some("Ethernet".to_string()),
                primary_candidate_confirmed: true,
                secondary_candidate_id: Some("win-adapter:ethernet-fallback".to_string()),
                secondary_candidate_name: Some("Ethernet".to_string()),
                secondary_candidate_confirmed: true,
                include_bluetooth_adapters: false,
                behavior_mode: RouteBehaviorMode::PreferPrimary,
            },
            InterfacesDataSource::FallbackMock,
        );

        assert!(snapshot.role_assignment_advisory.conflict_warning.is_some());
        let primary_count = snapshot
            .rows
            .iter()
            .filter(|row| row.selected_role == Some(RouteRole::Primary))
            .count();
        let secondary_count = snapshot
            .rows
            .iter()
            .filter(|row| row.selected_role == Some(RouteRole::Secondary))
            .count();
        assert_eq!(primary_count, 1);
        assert_eq!(secondary_count, 0);
    }

    #[test]
    fn unconfirmed_candidate_names_do_not_assign_roles() {
        let snapshot = interfaces_routes_preview_snapshot(RouteSelectionRequest {
            primary_candidate_id: None,
            primary_candidate_name: Some("Ethernet".to_string()),
            primary_candidate_confirmed: false,
            secondary_candidate_id: None,
            secondary_candidate_name: Some("VPN".to_string()),
            secondary_candidate_confirmed: false,
            include_bluetooth_adapters: false,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        });
        assert!(snapshot.rows.iter().all(|row| row.selected_role.is_none()));
    }

    #[test]
    fn confirmed_selection_has_priority_over_heuristic_recommendation() {
        let mut rows = fallback_rows();
        let request = RouteSelectionRequest {
            primary_candidate_id: None,
            primary_candidate_name: Some("VPN".to_string()),
            primary_candidate_confirmed: true,
            secondary_candidate_id: None,
            secondary_candidate_name: Some("Ethernet".to_string()),
            secondary_candidate_confirmed: true,
            include_bluetooth_adapters: false,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        };
        let advisory = assign_preview_roles(&mut rows, &request);

        let vpn = find_row(&rows, "VPN");
        let ethernet = find_row(&rows, "Ethernet");
        assert_eq!(vpn.selected_role, Some(RouteRole::Primary));
        assert_eq!(ethernet.selected_role, Some(RouteRole::Secondary));
        assert!(advisory.user_choice_priority_note.contains("priority"));
    }

    #[test]
    fn confirmed_secondary_without_ip_is_preserved_and_warned() {
        let mut rows = fallback_rows();
        let request = RouteSelectionRequest {
            primary_candidate_id: Some("win-adapter:ethernet-fallback".to_string()),
            primary_candidate_name: Some("Ethernet".to_string()),
            primary_candidate_confirmed: true,
            secondary_candidate_id: Some("win-adapter:vpn-fallback".to_string()),
            secondary_candidate_name: Some("VPN".to_string()),
            secondary_candidate_confirmed: true,
            include_bluetooth_adapters: false,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        };
        assign_recommendations(&mut rows, &request);
        let advisory = assign_preview_roles(&mut rows, &request);
        let secondary = find_row(&rows, "VPN");
        assert_eq!(secondary.selected_role, Some(RouteRole::Secondary));
        assert_eq!(
            secondary.route_state,
            RouteSelectionState::RequiresVerification
        );
        assert!(advisory
            .warnings
            .iter()
            .any(|warning| warning.contains("has no IP address")));
    }

    #[test]
    fn missing_confirmed_secondary_keeps_selection_contract() {
        let snapshot = interfaces_routes_preview_snapshot(RouteSelectionRequest {
            primary_candidate_id: Some("win-adapter:ethernet-fallback".to_string()),
            primary_candidate_name: Some("Ethernet".to_string()),
            primary_candidate_confirmed: true,
            secondary_candidate_id: Some("win-adapter:missing-secondary".to_string()),
            secondary_candidate_name: Some("Missing secondary".to_string()),
            secondary_candidate_confirmed: true,
            include_bluetooth_adapters: false,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        });
        assert!(snapshot
            .role_assignment_advisory
            .warnings
            .iter()
            .any(|warning| warning.contains("selection is preserved")));
    }

    #[test]
    fn diagnostics_checks_snapshot_uses_required_status_set() {
        let snapshot = interface_diagnostics_checks_snapshot(RouteSelectionRequest::default());
        assert!(!snapshot.rows.is_empty());
        let statuses = snapshot
            .rows
            .iter()
            .flat_map(|row| row.checks.iter().map(|check| check.status))
            .collect::<Vec<_>>();
        assert!(statuses.iter().all(|status| matches!(
            status,
            nrr_shared::AdapterCheckResultStatus::Success
                | nrr_shared::AdapterCheckResultStatus::Degraded
                | nrr_shared::AdapterCheckResultStatus::Unavailable
                | nrr_shared::AdapterCheckResultStatus::Timeout
        )));
    }

    #[test]
    fn diagnostics_checks_are_read_only_for_block_5_6() {
        let snapshot = interface_diagnostics_checks_snapshot(RouteSelectionRequest::default());
        assert!(snapshot
            .rows
            .iter()
            .flat_map(|row| row.checks.iter())
            .all(|check| check.read_only && !check.requires_service_mediation));
    }

    fn find_row<'a>(rows: &'a [InterfaceRouteRow], name: &str) -> &'a InterfaceRouteRow {
        rows.iter()
            .find(|row| row.windows_name == name)
            .unwrap_or_else(|| panic!("row '{name}' not found"))
    }

    #[test]
    fn the_checks_describe_the_rows_they_were_given() {
        // The regression this guards: the checks used to come from a SECOND
        // enumeration, so a tunnel appearing between the two calls showed in
        // one list and not the other.
        let snapshot = interfaces_routes_preview_snapshot(RouteSelectionRequest::default());
        let derived = interface_diagnostics_checks_from(&snapshot);

        assert_eq!(derived.rows.len(), snapshot.rows.len());
        for (checks, row) in derived.rows.iter().zip(snapshot.rows.iter()) {
            assert_eq!(checks.persistent_id, row.persistent_id);
            assert_eq!(checks.windows_name, row.windows_name);
        }
        assert_eq!(derived.data_source, snapshot.data_source);
    }
}
