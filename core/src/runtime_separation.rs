#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeLayer {
    PureDomainApplication,
    ServiceRuntime,
    UiRuntime,
    SharedContracts,
}

impl RuntimeLayer {
    pub const fn title(self) -> &'static str {
        match self {
            Self::PureDomainApplication => "pure-domain-application",
            Self::ServiceRuntime => "service-runtime",
            Self::UiRuntime => "ui-runtime",
            Self::SharedContracts => "shared-contracts",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnershipClass {
    PureDomain,
    ServiceOnly,
    UiOnly,
    TemporaryPreview,
}

impl OwnershipClass {
    pub const fn title(self) -> &'static str {
        match self {
            Self::PureDomain => "pure-domain",
            Self::ServiceOnly => "service-only",
            Self::UiOnly => "ui-only",
            Self::TemporaryPreview => "temporary-preview",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleOwnershipEntry {
    pub module_path: &'static str,
    pub ownership: OwnershipClass,
    pub target_layer: RuntimeLayer,
    pub note: &'static str,
}

pub const ALLOWED_DEPENDENCY_DIRECTION: [&str; 2] = [
    "gui/tray/service -> facade/application/domain -> shared-contracts",
    "service runtime must not depend on ui runtime modules",
];

pub const WORKSPACE_ALLOWED_DEPENDENCY_GRAPH_6_1B: [&str; 4] = [
    "apps -> application/ui-support/mock-backend/contracts",
    "service -> application/platform/domain/contracts",
    "platform -> domain/contracts",
    "domain -> contracts",
];

pub const WORKSPACE_FORBIDDEN_DEPENDENCIES_6_1B: [&str; 3] = [
    "service runtime must not import ui-support",
    "platform/windows must not depend on gui/tray",
    "domain must not depend on windows api, qml, tray, or local ui storage",
];

const MODULE_OWNERSHIP_MAP: [ModuleOwnershipEntry; 11] = [
    ModuleOwnershipEntry {
        module_path: "diagnostics",
        ownership: OwnershipClass::TemporaryPreview,
        target_layer: RuntimeLayer::UiRuntime,
        note: "Placeholder diagnostics snapshot for preview screens.",
    },
    ModuleOwnershipEntry {
        module_path: "first_run",
        ownership: OwnershipClass::UiOnly,
        target_layer: RuntimeLayer::UiRuntime,
        note: "Wizard flow and UI-only startup guidance.",
    },
    ModuleOwnershipEntry {
        module_path: "interface_manager",
        ownership: OwnershipClass::TemporaryPreview,
        target_layer: RuntimeLayer::PureDomainApplication,
        note: "Collector plus fallback preview data; split live collector from preview glue.",
    },
    ModuleOwnershipEntry {
        module_path: "logs",
        ownership: OwnershipClass::TemporaryPreview,
        target_layer: RuntimeLayer::UiRuntime,
        note: "Preview log snapshot until service-backed log source is introduced.",
    },
    ModuleOwnershipEntry {
        module_path: "network_interfaces",
        ownership: OwnershipClass::TemporaryPreview,
        target_layer: RuntimeLayer::PureDomainApplication,
        note: "Mixed collectors/validators/preview snapshots; planned split is required.",
    },
    ModuleOwnershipEntry {
        module_path: "route_bindings",
        ownership: OwnershipClass::TemporaryPreview,
        target_layer: RuntimeLayer::PureDomainApplication,
        note: "Policy-affecting export is UI-managed in preview and must migrate to service store.",
    },
    ModuleOwnershipEntry {
        module_path: "rules",
        ownership: OwnershipClass::TemporaryPreview,
        target_layer: RuntimeLayer::PureDomainApplication,
        note: "Rules are preview-seed now and move to service-owned list revision flow.",
    },
    ModuleOwnershipEntry {
        module_path: "security_status",
        ownership: OwnershipClass::TemporaryPreview,
        target_layer: RuntimeLayer::ServiceRuntime,
        note: "Service/runtime health and integrity view should be service-driven.",
    },
    ModuleOwnershipEntry {
        module_path: "theme",
        ownership: OwnershipClass::UiOnly,
        target_layer: RuntimeLayer::UiRuntime,
        note: "Theme and accessibility rendering policy are UI-runtime concerns.",
    },
    ModuleOwnershipEntry {
        module_path: "tray",
        ownership: OwnershipClass::UiOnly,
        target_layer: RuntimeLayer::UiRuntime,
        note: "Tray runtime/menu flow is UI-runtime and not a service dependency.",
    },
    ModuleOwnershipEntry {
        module_path: "ui_preferences",
        ownership: OwnershipClass::UiOnly,
        target_layer: RuntimeLayer::UiRuntime,
        note: "Managed local UI preferences; policy-affecting fields are temporary.",
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceOwnedStateField {
    pub field: &'static str,
    pub note: &'static str,
}

const SERVICE_OWNED_STATE_FIELDS: [ServiceOwnedStateField; 7] = [
    ServiceOwnedStateField {
        field: "active_revision",
        note: "Single authoritative active policy revision identifier.",
    },
    ServiceOwnedStateField {
        field: "pending_revision",
        note: "Staged policy candidate awaiting explicit apply/switch.",
    },
    ServiceOwnedStateField {
        field: "last_known_good_revision",
        note: "Rollback anchor for safe recovery.",
    },
    ServiceOwnedStateField {
        field: "applied_policy_state",
        note: "Observed state after apply operation and verification gates.",
    },
    ServiceOwnedStateField {
        field: "integrity_metadata",
        note: "Hash/signature/timestamp metadata for policy and config integrity.",
    },
    ServiceOwnedStateField {
        field: "audit_trail",
        note: "Privileged mutation history with actor/source tags.",
    },
    ServiceOwnedStateField {
        field: "privileged_mutations",
        note: "Service-mediated mutation operations with authorization checks.",
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreviewPolicyMigrationItem {
    pub ui_preferences_field: &'static str,
    pub service_target: &'static str,
    pub migration_stage: &'static str,
    pub note: &'static str,
}

const PREVIEW_POLICY_MIGRATION_MAP: [PreviewPolicyMigrationItem; 7] = [
    PreviewPolicyMigrationItem {
        ui_preferences_field: "selected_primary_interface_id",
        service_target: "pending_revision.route_bindings.primary.persistent_id",
        migration_stage: "before-block-16",
        note: "Primary route binding must be part of service-owned revision payload.",
    },
    PreviewPolicyMigrationItem {
        ui_preferences_field: "selected_primary_interface_name",
        service_target: "pending_revision.route_bindings.primary.display_name",
        migration_stage: "before-block-16",
        note: "Display name is non-authoritative metadata linked to stable identity.",
    },
    PreviewPolicyMigrationItem {
        ui_preferences_field: "primary_role_user_confirmed",
        service_target: "pending_revision.route_bindings.primary.user_confirmed",
        migration_stage: "before-block-16",
        note: "Confirmation flag controls explicit candidate acceptance.",
    },
    PreviewPolicyMigrationItem {
        ui_preferences_field: "selected_secondary_interface_id",
        service_target: "pending_revision.route_bindings.secondary.persistent_id",
        migration_stage: "before-block-16",
        note: "Secondary binding ownership follows the same revision rules as primary.",
    },
    PreviewPolicyMigrationItem {
        ui_preferences_field: "selected_secondary_interface_name",
        service_target: "pending_revision.route_bindings.secondary.display_name",
        migration_stage: "before-block-16",
        note: "UI label is migrated with binding identity as revision metadata.",
    },
    PreviewPolicyMigrationItem {
        ui_preferences_field: "secondary_role_user_confirmed",
        service_target: "pending_revision.route_bindings.secondary.user_confirmed",
        migration_stage: "before-block-16",
        note: "Confirmed secondary choice must be tracked in service-owned candidate set.",
    },
    PreviewPolicyMigrationItem {
        ui_preferences_field: "route_behavior_mode",
        service_target: "pending_revision.default_behavior.mode",
        migration_stage: "before-block-16",
        note: "Default behavior mode is policy-affecting and cannot remain UI-owned.",
    },
];

pub const SUBBLOCK_6_1A_DONE_CRITERION: &str = "Runtime layers and ownership map are fixed in code so crate refactoring can proceed without GUI/tray behavior changes and without moving policy ownership back to UI.";

pub const NRR_CORE_SPLIT_DIRECTION_NOTE: &str = "Split nrr-core into reusable domain/application logic, ui-specific helpers, and service runtime orchestration without changing external behavior.";
pub const SERVICE_RUNTIME_ORCHESTRATION_BOUNDARY_NOTE: &str = "Service runtime orchestration boundary is defined in windows-service/src/service_runtime.rs (SCM lifecycle, health/readiness, recovery, privileged operations, install/update hooks).";
pub const TRANSPORT_AGNOSTIC_APPLICATION_LAYER_NOTE: &str = "core/application is the transport-agnostic backend/application layer shared between mock backend integration and future service-backed runtime.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreSplitAction {
    MoveAsIs,
    Split,
    TemporaryReExport,
    LeaveInPlaceUntilNextStep,
}

impl CoreSplitAction {
    pub const fn title(self) -> &'static str {
        match self {
            Self::MoveAsIs => "move as-is",
            Self::Split => "split",
            Self::TemporaryReExport => "temporary re-export",
            Self::LeaveInPlaceUntilNextStep => "leave in place until next step",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoreFileSplitMapEntry {
    pub source_file: &'static str,
    pub target_location: &'static str,
    pub action: CoreSplitAction,
    pub note: &'static str,
}

const CORE_FILE_SPLIT_MAP_6_1B: [CoreFileSplitMapEntry; 13] = [
    CoreFileSplitMapEntry {
        source_file: "core/src/theme.rs",
        target_location: "core/ui-support/src/theme.rs",
        action: CoreSplitAction::MoveAsIs,
        note: "UI theme resolution stays UI-runtime-owned.",
    },
    CoreFileSplitMapEntry {
        source_file: "core/src/first_run.rs",
        target_location: "core/ui-support/src/first_run.rs",
        action: CoreSplitAction::MoveAsIs,
        note: "First-run workflow remains UI support logic.",
    },
    CoreFileSplitMapEntry {
        source_file: "core/src/tray.rs",
        target_location: "core/ui-support/src/tray.rs",
        action: CoreSplitAction::MoveAsIs,
        note: "Tray runtime/menu state remains UI-runtime-owned.",
    },
    CoreFileSplitMapEntry {
        source_file: "core/src/ui_preferences.rs",
        target_location: "core/ui-support/src/ui_preferences.rs",
        action: CoreSplitAction::MoveAsIs,
        note: "UI-managed storage semantics preserved in ui-support.",
    },
    CoreFileSplitMapEntry {
        source_file: "core/src/diagnostics.rs",
        target_location: "core/mock-backend/src/diagnostics.rs",
        action: CoreSplitAction::MoveAsIs,
        note: "Preview diagnostics snapshot moved to mock backend.",
    },
    CoreFileSplitMapEntry {
        source_file: "core/src/logs.rs",
        target_location: "core/mock-backend/src/logs.rs",
        action: CoreSplitAction::MoveAsIs,
        note: "Preview logs snapshot moved to mock backend.",
    },
    CoreFileSplitMapEntry {
        source_file: "core/src/rules.rs",
        target_location: "core/mock-backend/src/rules.rs",
        action: CoreSplitAction::MoveAsIs,
        note: "Preview rules seed moved to mock backend.",
    },
    CoreFileSplitMapEntry {
        source_file: "core/src/security_status.rs",
        target_location: "core/mock-backend/src/security_status.rs",
        action: CoreSplitAction::MoveAsIs,
        note: "Preview security snapshot moved to mock backend.",
    },
    CoreFileSplitMapEntry {
        source_file: "core/src/network_interfaces.rs",
        target_location: "core/mock-backend/src/network_interfaces.rs + core/platform/windows/src/interface_manager.rs",
        action: CoreSplitAction::Split,
        note: "Windows collector split from preview snapshot glue.",
    },
    CoreFileSplitMapEntry {
        source_file: "core/src/interface_manager.rs",
        target_location: "core/platform/windows/src/interface_manager.rs",
        action: CoreSplitAction::MoveAsIs,
        note: "Windows adapter collector extracted to platform crate.",
    },
    CoreFileSplitMapEntry {
        source_file: "core/src/route_bindings.rs",
        target_location: "core/application/src/route_bindings.rs",
        action: CoreSplitAction::TemporaryReExport,
        note: "Application owns route binding export; core keeps compatibility re-export.",
    },
    CoreFileSplitMapEntry {
        source_file: "core/src/lib.rs",
        target_location: "core facade",
        action: CoreSplitAction::TemporaryReExport,
        note: "Compatibility facade keeps legacy import paths stable.",
    },
    CoreFileSplitMapEntry {
        source_file: "core/src/runtime_separation.rs",
        target_location: "core/src/runtime_separation.rs",
        action: CoreSplitAction::LeaveInPlaceUntilNextStep,
        note: "Planning/ownership policy remains in core during staged refactor.",
    },
];

pub fn module_ownership_map() -> &'static [ModuleOwnershipEntry] {
    &MODULE_OWNERSHIP_MAP
}

pub fn service_owned_state_fields() -> &'static [ServiceOwnedStateField] {
    &SERVICE_OWNED_STATE_FIELDS
}

pub fn preview_policy_migration_map() -> &'static [PreviewPolicyMigrationItem] {
    &PREVIEW_POLICY_MIGRATION_MAP
}

pub fn core_file_split_map_6_1b() -> &'static [CoreFileSplitMapEntry] {
    &CORE_FILE_SPLIT_MAP_6_1B
}

#[cfg(test)]
mod tests {
    use super::{
        core_file_split_map_6_1b, module_ownership_map, preview_policy_migration_map,
        service_owned_state_fields, CoreSplitAction, OwnershipClass, RuntimeLayer,
        ALLOWED_DEPENDENCY_DIRECTION, WORKSPACE_ALLOWED_DEPENDENCY_GRAPH_6_1B,
        WORKSPACE_FORBIDDEN_DEPENDENCIES_6_1B,
    };

    #[test]
    fn dependency_direction_explicitly_blocks_service_to_ui_imports() {
        assert_eq!(ALLOWED_DEPENDENCY_DIRECTION.len(), 2);
        assert!(ALLOWED_DEPENDENCY_DIRECTION[0].contains("shared-contracts"));
        assert!(ALLOWED_DEPENDENCY_DIRECTION[1].contains("must not depend on ui runtime"));
    }

    #[test]
    fn ownership_map_covers_existing_core_modules() {
        let map = module_ownership_map();
        assert_eq!(map.len(), 11);
        assert!(map.iter().any(|entry| {
            entry.module_path == "theme"
                && entry.ownership == OwnershipClass::UiOnly
                && entry.target_layer == RuntimeLayer::UiRuntime
        }));
        assert!(map.iter().any(|entry| {
            entry.module_path == "tray"
                && entry.ownership == OwnershipClass::UiOnly
                && entry.target_layer == RuntimeLayer::UiRuntime
        }));
        assert!(map.iter().any(|entry| {
            entry.module_path == "network_interfaces"
                && entry.ownership == OwnershipClass::TemporaryPreview
                && entry.target_layer == RuntimeLayer::PureDomainApplication
        }));
    }

    #[test]
    fn service_owned_state_is_revision_centric() {
        let fields = service_owned_state_fields();
        assert!(fields.iter().any(|item| item.field == "active_revision"));
        assert!(fields.iter().any(|item| item.field == "pending_revision"));
        assert!(fields
            .iter()
            .any(|item| item.field == "last_known_good_revision"));
        assert!(fields.iter().any(|item| item.field == "audit_trail"));
    }

    #[test]
    fn migration_map_tracks_policy_affecting_preview_fields() {
        let map = preview_policy_migration_map();
        assert!(map
            .iter()
            .any(|item| item.ui_preferences_field == "selected_primary_interface_id"));
        assert!(map
            .iter()
            .any(|item| item.ui_preferences_field == "selected_secondary_interface_id"));
        assert!(map
            .iter()
            .any(|item| item.ui_preferences_field == "route_behavior_mode"));
        assert!(map
            .iter()
            .all(|item| item.migration_stage == "before-block-16"));
    }

    #[test]
    fn workspace_dependency_graph_is_fixed_for_subblock_6_1b() {
        assert_eq!(WORKSPACE_ALLOWED_DEPENDENCY_GRAPH_6_1B.len(), 4);
        assert!(WORKSPACE_ALLOWED_DEPENDENCY_GRAPH_6_1B[0].contains("apps ->"));
        assert!(WORKSPACE_ALLOWED_DEPENDENCY_GRAPH_6_1B[1].contains("service ->"));
        assert_eq!(WORKSPACE_FORBIDDEN_DEPENDENCIES_6_1B.len(), 3);
        assert!(WORKSPACE_FORBIDDEN_DEPENDENCIES_6_1B[0].contains("ui-support"));
    }

    #[test]
    fn split_map_covers_move_split_and_compatibility_actions() {
        let map = core_file_split_map_6_1b();
        assert!(map.iter().any(|item| {
            item.source_file == "core/src/network_interfaces.rs"
                && item.action == CoreSplitAction::Split
        }));
        assert!(map.iter().any(|item| {
            item.source_file == "core/src/lib.rs"
                && item.action == CoreSplitAction::TemporaryReExport
        }));
        assert!(map.iter().any(|item| {
            item.source_file == "core/src/runtime_separation.rs"
                && item.action == CoreSplitAction::LeaveInPlaceUntilNextStep
        }));
    }
}
