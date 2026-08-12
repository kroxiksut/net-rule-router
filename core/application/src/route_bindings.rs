use nrr_shared::RouteBehaviorMode;
use nrr_ui_support::ui_preferences::UiPreferences;

pub const ROUTE_BINDING_REVISION_LINK_POLICY: &str =
    "Route bindings are persisted in UI/config storage and linked to the currently visible active revision marker.";
pub const ROUTE_BINDING_CHANGE_CLASSIFICATION_POLICY: &str =
    "In block 2 changes are UI/config-only; service-owned pending/active revision flow will be enabled in later blocks.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteBindingResolutionState {
    Unset,
    StableIdentityBound,
    NameOnlyFallback,
}

impl RouteBindingResolutionState {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Unset => "unset",
            Self::StableIdentityBound => "stable-identity-bound",
            Self::NameOnlyFallback => "name-only-fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteBindingChangeClass {
    UiConfigOnly,
    RequiresPendingRevision,
}

impl RouteBindingChangeClass {
    pub const fn title(self) -> &'static str {
        match self {
            Self::UiConfigOnly => "ui-config-only",
            Self::RequiresPendingRevision => "requires-pending-revision",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRoleBindingExport {
    pub persistent_id: String,
    pub adapter_name: String,
    pub user_confirmed: bool,
    pub resolution_state: RouteBindingResolutionState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteBindingsExportSnapshot {
    // `active_revision` is a free-form `String` for now; it predates the
    // per-SID storage rework and the active-revision pointer in
    // `nrr_service_state.db`. It will be retyped to
    // `nrr-domain::revision::RevisionId` once the export pipeline reads
    // directly from `route_bindings` and `active_revision_pointer` rows
    // (see comment on `route_bindings_export_snapshot` below). Until then
    // callers pass a string slice and the value is preserved verbatim.
    pub active_revision: String,
    pub behavior_mode: RouteBehaviorMode,
    pub change_class: RouteBindingChangeClass,
    pub revision_link_policy: &'static str,
    pub change_classification_policy: &'static str,
    pub primary: RouteRoleBindingExport,
    pub secondary: RouteRoleBindingExport,
}

// `route_bindings_export_snapshot` reads the legacy `UiPreferences`
// policy fields for the export-snapshot path. The fields are deprecated
// in favor of per-SID service-owned storage; after the launcher
// migration runs they are zeroed and this function emits the empty
// snapshot. Real route bindings now live in
// `nrr_service_state.db::route_bindings`; the canonical export path
// will eventually be reworked to read from there.
#[allow(deprecated)]
pub fn route_bindings_export_snapshot(
    preferences: &UiPreferences,
    active_revision: &str,
) -> RouteBindingsExportSnapshot {
    RouteBindingsExportSnapshot {
        active_revision: active_revision.trim().to_string(),
        behavior_mode: preferences.route_behavior_mode,
        change_class: RouteBindingChangeClass::UiConfigOnly,
        revision_link_policy: ROUTE_BINDING_REVISION_LINK_POLICY,
        change_classification_policy: ROUTE_BINDING_CHANGE_CLASSIFICATION_POLICY,
        primary: build_binding_export(
            &preferences.selected_primary_interface_id,
            &preferences.selected_primary_interface_name,
            preferences.primary_role_user_confirmed,
        ),
        secondary: build_binding_export(
            &preferences.selected_secondary_interface_id,
            &preferences.selected_secondary_interface_name,
            preferences.secondary_role_user_confirmed,
        ),
    }
}

pub fn format_route_bindings_export(snapshot: &RouteBindingsExportSnapshot) -> String {
    format!(
        "active_revision={}\nbehavior_mode={}\nchange_class={}\nprimary.persistent_id={}\nprimary.adapter_name={}\nprimary.user_confirmed={}\nprimary.resolution_state={}\nsecondary.persistent_id={}\nsecondary.adapter_name={}\nsecondary.user_confirmed={}\nsecondary.resolution_state={}\n",
        snapshot.active_revision,
        snapshot.behavior_mode.slug(),
        snapshot.change_class.title(),
        snapshot.primary.persistent_id,
        snapshot.primary.adapter_name,
        snapshot.primary.user_confirmed,
        snapshot.primary.resolution_state.title(),
        snapshot.secondary.persistent_id,
        snapshot.secondary.adapter_name,
        snapshot.secondary.user_confirmed,
        snapshot.secondary.resolution_state.title(),
    )
}

fn build_binding_export(
    persistent_id: &str,
    adapter_name: &str,
    user_confirmed: bool,
) -> RouteRoleBindingExport {
    let persistent_id = persistent_id.trim().to_string();
    let adapter_name = adapter_name.trim().to_string();
    let resolution_state = if !user_confirmed {
        RouteBindingResolutionState::Unset
    } else if !persistent_id.is_empty() {
        RouteBindingResolutionState::StableIdentityBound
    } else if !adapter_name.is_empty() {
        RouteBindingResolutionState::NameOnlyFallback
    } else {
        RouteBindingResolutionState::Unset
    };

    RouteRoleBindingExport {
        persistent_id,
        adapter_name,
        user_confirmed,
        resolution_state,
    }
}

#[cfg(test)]
mod tests {
    // These tests deliberately populate the deprecated per-UiPreferences route
    // fields to verify the export/migration path.
    #![allow(deprecated)]
    use super::{
        format_route_bindings_export, route_bindings_export_snapshot, RouteBindingChangeClass,
        RouteBindingResolutionState,
    };
    use nrr_shared::RouteBehaviorMode;
    use nrr_ui_support::ui_preferences::UiPreferences;

    #[test]
    fn export_snapshot_keeps_stable_identity_bindings() {
        let preferences = UiPreferences {
            selected_primary_interface_id: "win-adapter:ethernet-1".to_string(),
            selected_primary_interface_name: "Ethernet".to_string(),
            primary_role_user_confirmed: true,
            selected_secondary_interface_id: "win-adapter:vpn-1".to_string(),
            selected_secondary_interface_name: "VPN".to_string(),
            secondary_role_user_confirmed: true,
            route_behavior_mode: RouteBehaviorMode::PreferSecondaryWhenAvailable,
            ..UiPreferences::default()
        };

        let snapshot = route_bindings_export_snapshot(&preferences, "rev-preview-001");
        assert_eq!(snapshot.active_revision, "rev-preview-001");
        assert_eq!(
            snapshot.behavior_mode,
            RouteBehaviorMode::PreferSecondaryWhenAvailable
        );
        assert_eq!(snapshot.change_class, RouteBindingChangeClass::UiConfigOnly);
        assert_eq!(
            snapshot.primary.resolution_state,
            RouteBindingResolutionState::StableIdentityBound
        );
        assert_eq!(
            snapshot.secondary.resolution_state,
            RouteBindingResolutionState::StableIdentityBound
        );
    }

    #[test]
    fn export_snapshot_marks_name_only_fallback_when_id_is_missing() {
        let preferences = UiPreferences {
            selected_secondary_interface_id: String::new(),
            selected_secondary_interface_name: "VPN".to_string(),
            secondary_role_user_confirmed: true,
            ..UiPreferences::default()
        };

        let snapshot = route_bindings_export_snapshot(&preferences, "rev-preview-001");
        assert_eq!(
            snapshot.secondary.resolution_state,
            RouteBindingResolutionState::NameOnlyFallback
        );
    }

    #[test]
    fn formatted_export_contains_contract_fields() {
        let snapshot = route_bindings_export_snapshot(&UiPreferences::default(), "rev-preview-001");
        let formatted = format_route_bindings_export(&snapshot);
        assert!(formatted.contains("active_revision=rev-preview-001"));
        assert!(formatted.contains("primary.persistent_id="));
        assert!(formatted.contains("secondary.persistent_id="));
        assert!(formatted.contains("change_class=ui-config-only"));
    }
}
