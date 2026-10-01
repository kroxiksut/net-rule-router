//! Interfaces & routes snapshot for the desktop.
//!
//! The row type, its enrichment, the recommendation and the binding resolver
//! live in [`nrr_platform_api::interface_rows`] (re-exported here), shared
//! with the service so a row reads alike whichever side produced it. What
//! stays here is the desktop's half: applying the user's role bindings.

pub use nrr_platform_api::interface_rows::*;

use nrr_shared::{RouteBehaviorMode, RouteRole, RouteSelectionState};

const SUPPORTED_ROUTE_BEHAVIOR_MODES: [RouteBehaviorMode; 3] = [
    RouteBehaviorMode::PreferPrimary,
    RouteBehaviorMode::PreferSecondaryWhenAvailable,
    RouteBehaviorMode::StrictSecondaryFailClosed,
];

/// The user's saved role bindings. A binding counts only once confirmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSelectionRequest {
    pub primary_candidate_id: Option<String>,
    pub primary_candidate_name: Option<String>,
    pub primary_candidate_confirmed: bool,
    pub secondary_candidate_id: Option<String>,
    pub secondary_candidate_name: Option<String>,
    pub secondary_candidate_confirmed: bool,
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
            behavior_mode: RouteBehaviorMode::default_when_secondary_unbound(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfacesRoutesPreviewSnapshot {
    pub data_source: InterfacesDataSource,
    pub supported_behavior_modes: &'static [RouteBehaviorMode],
    pub selected_behavior_mode: RouteBehaviorMode,
    pub rows: Vec<InterfaceRouteRow>,
}

/// This host's adapter enumeration: the one place the desktop side picks it.
pub fn local_interface_rows() -> &'static dyn InterfaceRowsPort {
    #[cfg(windows)]
    {
        &nrr_platform_windows::WindowsInterfaceRows
    }
    #[cfg(target_os = "linux")]
    {
        &nrr_platform_linux::interface_rows::LinuxInterfaceRows
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        &PlaceholderInterfaceRows
    }
}

/// This host's adapters, scored and bound. Never probes the external address.
pub fn interfaces_routes_preview_snapshot(
    request: RouteSelectionRequest,
) -> InterfacesRoutesPreviewSnapshot {
    interfaces_snapshot_from(local_interface_rows(), &request)
}

/// [`interfaces_routes_preview_snapshot`] over any enumeration.
pub fn interfaces_snapshot_from(
    port: &dyn InterfaceRowsPort,
    request: &RouteSelectionRequest,
) -> InterfacesRoutesPreviewSnapshot {
    let (data_source, rows) = port.collect_rows(false);
    decorate_interface_rows(rows, request, data_source)
}

/// Score `rows` and apply the request's bindings, exactly as for a local
/// enumeration. `data_source` is the provenance the supplier reported: a
/// service whose enumeration came back empty answers with the placeholder
/// set, and only it knows which happened.
pub fn decorate_interface_rows(
    mut rows: Vec<InterfaceRouteRow>,
    request: &RouteSelectionRequest,
    data_source: InterfacesDataSource,
) -> InterfacesRoutesPreviewSnapshot {
    assign_recommendations(&mut rows);
    apply_role_bindings(&mut rows, request);
    InterfacesRoutesPreviewSnapshot {
        data_source,
        supported_behavior_modes: &SUPPORTED_ROUTE_BEHAVIOR_MODES,
        selected_behavior_mode: request.behavior_mode,
        rows,
    }
}

/// Mark the rows the user's confirmed bindings resolve to. Heuristics never
/// assign a role.
fn apply_role_bindings(rows: &mut [InterfaceRouteRow], request: &RouteSelectionRequest) {
    for row in rows.iter_mut() {
        row.selected_role = None;
        row.route_state = baseline_route_state(row);
    }

    let primary_index = request
        .primary_candidate_confirmed
        .then(|| {
            find_adapter_index(
                rows,
                request.primary_candidate_id.as_deref(),
                request.primary_candidate_name.as_deref(),
                None,
            )
        })
        .flatten();
    if let Some(index) = primary_index {
        rows[index].selected_role = Some(RouteRole::Primary);
        if rows[index].route_state == RouteSelectionState::NotSelected {
            rows[index].route_state = RouteSelectionState::Selected;
        }
    }

    let secondary_index = request
        .secondary_candidate_confirmed
        .then(|| {
            find_adapter_index(
                rows,
                request.secondary_candidate_id.as_deref(),
                request.secondary_candidate_name.as_deref(),
                primary_index,
            )
        })
        .flatten();
    if let Some(index) = secondary_index {
        rows[index].selected_role = Some(RouteRole::Secondary);
        rows[index].route_state = secondary_state_for_row(&rows[index], request.behavior_mode);
    }
}

fn baseline_route_state(row: &InterfaceRouteRow) -> RouteSelectionState {
    match row.availability_status {
        BasicAvailabilityStatus::Unavailable => RouteSelectionState::Unavailable,
        BasicAvailabilityStatus::RequiresCheck => RouteSelectionState::RequiresVerification,
        BasicAvailabilityStatus::Available if row.local_ip == "-" => {
            RouteSelectionState::RequiresVerification
        }
        BasicAvailabilityStatus::Available => RouteSelectionState::NotSelected,
    }
}

fn secondary_state_for_row(
    row: &InterfaceRouteRow,
    behavior_mode: RouteBehaviorMode,
) -> RouteSelectionState {
    match row.availability_status {
        BasicAvailabilityStatus::Unavailable
            if behavior_mode == RouteBehaviorMode::StrictSecondaryFailClosed =>
        {
            RouteSelectionState::FailClosedConflict
        }
        BasicAvailabilityStatus::Unavailable => RouteSelectionState::Unavailable,
        BasicAvailabilityStatus::RequiresCheck => RouteSelectionState::RequiresVerification,
        BasicAvailabilityStatus::Available if row.local_ip == "-" => {
            RouteSelectionState::RequiresVerification
        }
        BasicAvailabilityStatus::Available => RouteSelectionState::Selected,
    }
}

#[cfg(test)]
mod tests;
