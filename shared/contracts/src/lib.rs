use core::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

pub mod auto_rule;
pub mod diagnostics_dto;
pub mod eula;
pub mod ipc;
pub mod ipc_dto;
pub mod ipc_flow;
pub mod ipc_payloads;
pub mod ipc_readiness;
pub mod ipc_transport;
pub mod launcher_rpc;
pub mod localization;
pub mod merge_dto;
pub mod pagination;
pub mod platform_profile;
pub mod preset_parser;
pub mod product_identity;
pub mod rules_json;
pub mod settings_export;
pub mod summary;
pub mod system_info;
// Descriptors + integrity status of the binaries we ship from third parties
// (today: WireGuard LLC's Wintun, Windows only). The GUI renders these, so
// the shapes belong to the wire contract; the port that fills them lives in
// `nrr-platform-api`.
pub mod third_party;
pub use auto_rule::{AutoRuleReason, RuleOrigin};
pub use ipc::{
    ipc_lifecycle_stages, ipc_operation_catalog, CompatibilityClientBehavior, IpcClientProfile,
    IpcContractVersionPolicy, IpcCorrelationModel, IpcCorrelationSource, IpcDataDeliveryKind,
    IpcEnvelopeField, IpcEnvelopePayloadBoundary, IpcExecutionModel, IpcIdempotencyClass,
    IpcInteractionClass, IpcLifecycleStage, IpcOperationName, IpcOperationSpec, IpcRetryPolicy,
    IpcStateUpdateModel, IpcUpdateModel, IpcVersionCompatibilityMatrix,
    IpcVersionCompatibilityRule, VersionCompatibilityCase, IPC_CONTRACT_VERSION_POLICY,
    IPC_CORRELATION_MODEL, IPC_ENVELOPE_PAYLOAD_BOUNDARY, IPC_RETRY_POLICY, IPC_STATE_UPDATE_MODEL,
    IPC_VERSION_COMPATIBILITY_MATRIX,
};
pub use ipc_dto::{
    AdapterIdentityDto, AvailabilityState, DiagnosticsSnapshotDto, DtoEnvelopePolicy,
    DtoFieldStability, DtoGroup, DtoToUiViewModelMapping, EnvelopeMetaDto, EnvelopePayloadDto,
    ErrorCategory, ErrorDto, ExplainSampleDto, InterfaceDerivedAssessmentDto, InterfaceDisplayDto,
    InterfaceObservedFactsDto, InterfaceRecommendationDto, InterfaceSnapshotDto, LogEntryDto,
    LogsSnapshotDto, LogsWindowingPolicyDto, OperationOutcome, OperationResultDto,
    ResponseEnvelopeDto, ReviewRiskLevel, ReviewSummaryDto, RouteAssignmentStateDto,
    RouteRoleAssignmentDto, ServiceAvailability, ServiceHealthDto, StringFieldStateDto,
    CANONICAL_INTEGRATION_PAYLOAD_EXAMPLE_6_5, CANONICAL_MOCK_PAYLOAD_EXAMPLE_6_5,
    DTO_ENVELOPE_POLICY_6_5, DTO_GROUPS_6_5, DTO_TO_UI_VIEW_MODEL_MAPPING_6_5,
};
pub use ipc_flow::{
    mutation_command_contracts, AmbiguousTimeoutHandlingPolicy, CommandSideEffect,
    ConflictDetectionReason, ConsistencyExpectation, MutationCommandContract, MutationCommandId,
    MutationEffectClass, MutationFlowStage, MutationPostcondition, MutationPrecondition,
    MutationResponseMode, OperationFlowClass, OperationResultStatus, ReadQueryId,
    ReadStateReference, RevisionFlowState, RevisionStateTransition,
    AMBIGUOUS_TIMEOUT_HANDLING_POLICY, COMMAND_SIDE_EFFECTS, CONFLICT_REASON_SET,
    MUTATION_COMMAND_SET_BASELINE, OPERATION_RESULT_STATUS_SET, READ_QUERY_SET_BASELINE,
    READ_STATE_REFERENCE_SET, REVISION_MUTATION_STAGES, REVISION_STATE_MACHINE,
};
pub use ipc_readiness::{
    block6_downstream_input_blocks, Block16BoundaryScope, Block6CrossBlockAlignment,
    Block6ReadinessChecklist, BLOCK_6_8_BLOCK16_BOUNDARY, BLOCK_6_8_CROSS_BLOCK_ALIGNMENT,
    BLOCK_6_8_READINESS_CHECKLIST,
};
pub use ipc_transport::{
    ipc_endpoint_security_specs, CallerIdentityCheck, IpcAclPolicy, IpcAclPrincipal,
    IpcCallerIdentityPolicy, IpcDegradationBehavior, IpcEndpointAccessClass, IpcEndpointName,
    IpcEndpointSecuritySpec, IpcFailureAndDegradationPolicy, IpcFailureMode, IpcFailurePolicyRule,
    IpcTransportKind, IPC_ACL_POLICY, IPC_CALLER_IDENTITY_POLICY,
    IPC_FAILURE_AND_DEGRADATION_POLICY, IPC_TRANSPORT_KIND, SERVICE_ENDPOINT_ADDRESS,
};
pub use localization::{
    load_locale_catalog, load_locale_descriptors, load_locale_map, load_locale_reports,
    resolve_catalog_text, translate_or, LocaleDescriptor, LocaleLoadReport, LocaleLoadStatus,
    LocaleSource, LOCALE_SCHEMA_PATH, LOCALE_SCHEMA_VERSION,
};
pub use settings_export::SettingsExportV1;
pub use summary::{
    format_about_summary, format_accessibility_baseline_summary, format_first_run_summary,
    format_interfaces_routes_summary, format_main_window_shell_summary, format_rules_summary,
    format_security_visibility_summary, format_settings_summary, format_shell_summary,
    format_tooltip_policy_summary, format_ui_surface_contract_summary,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AppSection {
    InterfacesAndRoutes,
    Rules,
    Diagnostics,
    Logs,
    Settings,
}

impl AppSection {
    pub const ALL: [Self; 5] = [
        Self::InterfacesAndRoutes,
        Self::Rules,
        Self::Diagnostics,
        Self::Logs,
        Self::Settings,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::InterfacesAndRoutes => "interfaces-routes",
            Self::Rules => "rules",
            Self::Diagnostics => "diagnostics",
            Self::Logs => "logs",
            Self::Settings => "settings",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::InterfacesAndRoutes => "Interfaces and routes",
            Self::Rules => "Rules",
            Self::Diagnostics => "Diagnostics",
            Self::Logs => "Logs",
            Self::Settings => "Settings",
        }
    }
}

impl fmt::Display for AppSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for AppSection {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "interfaces-routes" | "routes" | "interfaces" => Ok(Self::InterfacesAndRoutes),
            "rules" => Ok(Self::Rules),
            "diagnostics" => Ok(Self::Diagnostics),
            "logs" => Ok(Self::Logs),
            "settings" => Ok(Self::Settings),
            _ => Err("unknown section id"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AppAction {
    OpenMainWindow,
    OpenSection(AppSection),
    LoadRuleList,
    UpdateRulesFromFile,
    ImportPreset,
    ExportCurrentRuleList,
    RefreshInterfaces,
    CheckServiceStatus,
    SafeRollback,
    TemporarilyDisableProductImpact,
    OpenAboutWindow,
    OpenLicenseWindow,
    OpenLogsFolder,
    CheckForUpdates,
    ExitApplication,
}

impl AppAction {
    pub const fn id(self) -> &'static str {
        match self {
            Self::OpenMainWindow => "open-main-window",
            Self::OpenSection(section) => section.slug(),
            Self::LoadRuleList => "load-rule-list",
            Self::UpdateRulesFromFile => "update-rules-from-file",
            Self::ImportPreset => "import-preset",
            Self::ExportCurrentRuleList => "export-current-rule-list",
            Self::RefreshInterfaces => "refresh-interfaces",
            Self::CheckServiceStatus => "check-service-status",
            Self::SafeRollback => "safe-rollback",
            Self::TemporarilyDisableProductImpact => "temporary-disable-product-impact",
            Self::OpenAboutWindow => "open-about-window",
            Self::OpenLicenseWindow => "open-license-window",
            Self::OpenLogsFolder => "open-logs-folder",
            Self::CheckForUpdates => "check-for-updates",
            Self::ExitApplication => "exit-application",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::OpenMainWindow => "Open NetRuleRouter",
            Self::OpenSection(AppSection::InterfacesAndRoutes) => "Interfaces and routes",
            Self::OpenSection(AppSection::Rules) => "Rules",
            Self::OpenSection(AppSection::Diagnostics) => "Diagnostics",
            Self::OpenSection(AppSection::Logs) => "Logs",
            Self::OpenSection(AppSection::Settings) => "Settings",
            Self::LoadRuleList => "Load rule list...",
            Self::UpdateRulesFromFile => "Update rules from file",
            Self::ImportPreset => "Import preset...",
            Self::ExportCurrentRuleList => "Export current list...",
            Self::RefreshInterfaces => "Refresh interfaces",
            Self::CheckServiceStatus => "Check service status",
            Self::SafeRollback => "Safe rollback",
            Self::TemporarilyDisableProductImpact => "Temporarily disable product impact",
            Self::OpenAboutWindow => "About",
            Self::OpenLicenseWindow => "License",
            Self::OpenLogsFolder => "Open logs folder",
            Self::CheckForUpdates => "Check for updates",
            Self::ExitApplication => "Exit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MenuAvailability {
    Enabled,
    Preview,
}

impl MenuAvailability {
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MenuItem {
    pub action: AppAction,
    pub availability: MenuAvailability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MenuGroupId {
    File,
    View,
    Tools,
    Help,
}

impl MenuGroupId {
    pub const fn title(self) -> &'static str {
        match self {
            Self::File => "File",
            Self::View => "View",
            Self::Tools => "Tools",
            Self::Help => "Help",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MenuGroup {
    pub id: MenuGroupId,
    pub items: &'static [MenuItem],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NavigationStyle {
    SidebarWithStackedViews,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NavigationModel {
    pub style: NavigationStyle,
    pub back_cancel_apply_supported: bool,
    pub tray_opening_reuses_main_window: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MainWindowLayoutZone {
    TitleBar,
    MenuBar,
    Sidebar,
    Workspace,
    StatusBar,
    ActionBar,
}

impl MainWindowLayoutZone {
    pub const fn title(self) -> &'static str {
        match self {
            Self::TitleBar => "Title bar",
            Self::MenuBar => "Menu bar",
            Self::Sidebar => "Sidebar",
            Self::Workspace => "Workspace",
            Self::StatusBar => "Status bar",
            Self::ActionBar => "Action bar",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MainWindowShellContract {
    pub window_title: &'static str,
    pub layout_zones: &'static [MainWindowLayoutZone],
    pub sidebar_sections: &'static [AppSection],
    pub shared_shell_sections: &'static [AppSection],
    pub shared_shell_review_dialogs: &'static [GuiDialog],
    pub workspace_note: &'static str,
    pub apply_cancel_actions_visible: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GuiWindow {
    MainWindow,
    FirstRunWizard,
    RuleListLoadWindow,
    RuleListEditWindow,
    AboutWindow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GuiDialog {
    ConfirmReplaceCurrentList,
    ReviewReplaceCurrentList,
    ConfirmDiscardUnsavedChanges,
    ConfirmClearLogs,
    ConfirmRollback,
    ConfirmDisableProductImpact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ActivationSource {
    Tray,
    Menu,
}

impl ActivationSource {
    pub const ALL: [Self; 2] = [Self::Tray, Self::Menu];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::Tray => "tray",
            Self::Menu => "menu",
        }
    }
}

impl fmt::Display for ActivationSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for ActivationSource {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "tray" => Ok(Self::Tray),
            "menu" => Ok(Self::Menu),
            _ => Err("unknown activation source"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InformationArchitecture {
    pub main_window_sections: &'static [AppSection],
    pub tray_only_actions: &'static [AppAction],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SecondaryLaunchBehavior {
    FocusExistingInstanceAndOpenRequestedSection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SingleInstancePolicy {
    pub instance_key: &'static str,
    pub behavior: SecondaryLaunchBehavior,
    pub accepted_sources: &'static [ActivationSource],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TrayMenuModel {
    pub status_line: &'static str,
    pub primary_actions: &'static [MenuItem],
    pub quick_actions: &'static [MenuItem],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AppShellModel {
    pub information_architecture: InformationArchitecture,
    pub navigation: NavigationModel,
    pub main_window_shell: MainWindowShellContract,
    pub first_run: FirstRunContract,
    pub windows: &'static [GuiWindow],
    pub dialogs: &'static [GuiDialog],
    pub menu_bar: &'static [MenuGroup],
    pub tray_menu: TrayMenuModel,
    pub single_instance: SingleInstancePolicy,
    pub settings: SettingsContract,
    pub about: AboutContract,
    pub security_visibility: SecurityVisibilityContract,
    pub tooltip_policy: TooltipPolicyContract,
    pub accessibility_baseline: AccessibilityBaselineContract,
    pub ui_surface_contract: UiSurfaceContract,
    pub interfaces_routes: InterfacesRoutesContract,
    pub rules: RulesContract,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ThemeMode {
    Light,
    Dark,
    System,
    HighContrast,
}

impl ThemeMode {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
            Self::System => "system",
            Self::HighContrast => "high-contrast",
        }
    }
}

impl fmt::Display for ThemeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for ThemeMode {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "light" => Ok(Self::Light),
            "dark" => Ok(Self::Dark),
            "system" => Ok(Self::System),
            "high-contrast" | "high_contrast" | "highcontrast" | "accessibility" => {
                Ok(Self::HighContrast)
            }
            _ => Err("unknown theme mode"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UiLanguage {
    Ru,
    En,
}

impl UiLanguage {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Ru => "ru",
            Self::En => "en",
        }
    }
}

impl fmt::Display for UiLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for UiLanguage {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ru" => Ok(Self::Ru),
            "en" => Ok(Self::En),
            _ => Err("unknown ui language"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SettingAvailability {
    Enabled,
    Preview,
    Disabled,
}

impl SettingAvailability {
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SettingOwnership {
    UiPreference,
    PolicyAffectingPreview,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SettingsSectionId {
    General,
    Appearance,
    Accessibility,
    Language,
    LogsAndDiagnostics,
    RoutingBehavior,
    ExperimentalFeatures,
    FreeUpdates,
}

impl SettingsSectionId {
    pub const fn title(self) -> &'static str {
        match self {
            Self::General => "General",
            Self::Appearance => "Appearance",
            Self::Accessibility => "Accessibility",
            Self::Language => "Language",
            Self::LogsAndDiagnostics => "Logs and diagnostics",
            Self::RoutingBehavior => "Routing behavior",
            Self::ExperimentalFeatures => "Experimental features",
            Self::FreeUpdates => "Updates",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SettingFieldId {
    LaunchWindowOnStartup,
    MinimizeToTrayInsteadOfClose,
    ShowNotifications,
    ReopenLastSectionOnStartup,
    ThemeMode,
    InterfaceDensity,
    UiFontSize,
    AccessibilityHighContrast,
    AccessibilityUiFontSize,
    AccessibilitySystemFont,
    AccessibilityEnhancedFocusIndicator,
    AccessibilitySimplifiedLabels,
    InterfaceLanguage,
    TranslationSource,
    UserLogVerbosity,
    OpenLogsFolder,
    ClearLogs,
    EnableExtendedDiagnostics,
    DefaultRoutingMode,
    FailClosedBehavior,
    WarnWhenSecondaryUnavailable,
    RulesFileChangeMode,
    /// Apply routing rules to direct child processes of a matched application.
    RuleIncludeChildProcesses,
    /// Show rules written for operating systems other than the running platform.
    ShowOtherOsRules,
    /// When a Zone rule and an Exact IP rule both match the same destination,
    /// determines which takes priority. Default: ExactIp wins.
    ZonePriorityOverIp,
    BrowserStubExperimental,
    CheckForUpdates,
    UpdateChannel,
    CurrentVersion,
}

impl SettingFieldId {
    pub const fn label(self) -> &'static str {
        match self {
            Self::LaunchWindowOnStartup => "Launch window on startup",
            Self::MinimizeToTrayInsteadOfClose => "Minimize to tray instead of close",
            Self::ShowNotifications => "Show notifications",
            Self::ReopenLastSectionOnStartup => "Open last section on startup",
            Self::ThemeMode => "Theme",
            Self::InterfaceDensity => "Interface density",
            Self::UiFontSize => "UI font size",
            Self::AccessibilityHighContrast => "High-contrast mode",
            Self::AccessibilityUiFontSize => "UI font size",
            Self::AccessibilitySystemFont => "System font",
            Self::AccessibilityEnhancedFocusIndicator => "Enhanced focus indicator",
            Self::AccessibilitySimplifiedLabels => "Simplified labels and descriptions",
            Self::InterfaceLanguage => "Interface language",
            Self::TranslationSource => "Translation source",
            Self::UserLogVerbosity => "User log verbosity",
            Self::OpenLogsFolder => "Open logs folder",
            Self::ClearLogs => "Clear logs",
            Self::EnableExtendedDiagnostics => "Enable extended diagnostics",
            Self::DefaultRoutingMode => "Default routing mode",
            Self::FailClosedBehavior => "Fail-Closed behavior",
            Self::WarnWhenSecondaryUnavailable => "Warn when secondary route is unavailable",
            Self::RulesFileChangeMode => "When rules file changes on disk",
            Self::RuleIncludeChildProcesses => "Apply rules to child processes",
            Self::ShowOtherOsRules => "Show rules for other operating systems",
            Self::ZonePriorityOverIp => "Zone vs. IP priority",
            Self::BrowserStubExperimental => "Local browser stub",
            Self::CheckForUpdates => "Check for updates",
            Self::UpdateChannel => "Update channel",
            Self::CurrentVersion => "Current version",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SettingField {
    pub id: SettingFieldId,
    pub availability: SettingAvailability,
    pub ownership: SettingOwnership,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SettingsSection {
    pub id: SettingsSectionId,
    pub fields: &'static [SettingField],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SettingsContract {
    pub sections: &'static [SettingsSection],
    pub storage_backend_hint: &'static str,
    pub policy_source_of_truth: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AboutContract {
    pub product_name: &'static str,
    pub edition: &'static str,
    pub license: &'static str,
    pub project_url: &'static str,
    pub build_channel: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TooltipPolicyContract {
    pub enabled_by_default: bool,
    pub supplemental_only: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccessibilityRequirementId {
    AccessibleMetadata,
    KeyboardFirstNavigation,
    VisibleFocusIndicator,
    ScalableText,
    SystemFontSelection,
    DedicatedHighContrastTheme,
    TooltipsAreSupplementalOnly,
}

impl AccessibilityRequirementId {
    pub const fn title(self) -> &'static str {
        match self {
            Self::AccessibleMetadata => "Accessible names, roles, states, descriptions",
            Self::KeyboardFirstNavigation => "Keyboard-first navigation",
            Self::VisibleFocusIndicator => "Visible focus indicator",
            Self::ScalableText => "Scalable UI text",
            Self::SystemFontSelection => "System font selection",
            Self::DedicatedHighContrastTheme => "Dedicated accessibility/high-contrast theme",
            Self::TooltipsAreSupplementalOnly => "Tooltips are supplemental only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AccessibilityRequirement {
    pub id: AccessibilityRequirementId,
    pub mandatory: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AccessibilityBaselineContract {
    pub requirements: &'static [AccessibilityRequirement],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UiSurfaceId {
    MainWindow,
    FirstRunWizard,
    InterfacesAndRoutesScreen,
    RulesScreen,
    LoadListDialog,
    EditListDialog,
    EditRuleDialog,
    RuleReplaceReviewDialog,
    DiagnosticsScreen,
    LogsScreen,
    AboutWindow,
    ConfirmationDialogs,
}

impl UiSurfaceId {
    pub const fn title(self) -> &'static str {
        match self {
            Self::MainWindow => "Main window",
            Self::FirstRunWizard => "First-run wizard",
            Self::InterfacesAndRoutesScreen => "Interfaces and routes",
            Self::RulesScreen => "Rules",
            Self::LoadListDialog => "Load list dialog",
            Self::EditListDialog => "Edit list dialog",
            Self::EditRuleDialog => "Edit rule dialog",
            Self::RuleReplaceReviewDialog => "Rule replace review dialog",
            Self::DiagnosticsScreen => "Diagnostics",
            Self::LogsScreen => "Logs",
            Self::AboutWindow => "About window",
            Self::ConfirmationDialogs => "Confirmation dialogs",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UiSurfaceSpec {
    pub id: UiSurfaceId,
    pub fields: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UiSurfaceContract {
    pub surfaces: &'static [UiSurfaceSpec],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InterfaceFieldId {
    WindowsName,
    InterfaceType,
    LocalIp,
    Gateway,
    DnsServers,
    HasDefaultRoute,
    BasicAvailabilityStatus,
}

impl InterfaceFieldId {
    pub const fn title(self) -> &'static str {
        match self {
            Self::WindowsName => "Windows name",
            Self::InterfaceType => "Interface type",
            Self::LocalIp => "Local IP",
            Self::Gateway => "Gateway",
            Self::DnsServers => "DNS servers",
            Self::HasDefaultRoute => "Has default route",
            Self::BasicAvailabilityStatus => "Basic availability status",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DataReadiness {
    RealInBlock2,
    PlaceholderUntilBlock5,
}

impl DataReadiness {
    pub const fn title(self) -> &'static str {
        match self {
            Self::RealInBlock2 => "real-in-block-2",
            Self::PlaceholderUntilBlock5 => "placeholder-until-block-5",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InterfaceFieldReadiness {
    pub field: InterfaceFieldId,
    pub readiness: DataReadiness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SnapshotValueAvailability {
    AlwaysPresentFromSnapshot,
    MayBeUnknownFromSnapshot,
}

impl SnapshotValueAvailability {
    pub const fn title(self) -> &'static str {
        match self {
            Self::AlwaysPresentFromSnapshot => "always-present-from-snapshot",
            Self::MayBeUnknownFromSnapshot => "may-be-unknown-from-snapshot",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InterfaceFieldSnapshotStatus {
    pub field: InterfaceFieldId,
    pub availability: SnapshotValueAvailability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InterfaceFieldUsageScope {
    UiOnly,
    DiagnosticsContract,
    DecisionInput,
}

impl InterfaceFieldUsageScope {
    pub const fn title(self) -> &'static str {
        match self {
            Self::UiOnly => "ui-only",
            Self::DiagnosticsContract => "diagnostics-contract",
            Self::DecisionInput => "decision-input",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InterfaceFieldUsage {
    pub field: InterfaceFieldId,
    pub scope: InterfaceFieldUsageScope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InterfacesDisplayFormat {
    pub ordered_fields: &'static [InterfaceFieldId],
    pub unknown_value_marker: &'static str,
    pub dns_separator: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConnectivityState {
    Available,
    Degraded,
    Unavailable,
    Unknown,
    Timeout,
}

impl ConnectivityState {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
            Self::Unknown => "unknown",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExternalIpStatus {
    Resolved,
    NotChecked,
    CheckFailed,
    RateLimited,
    Blocked,
}

impl ExternalIpStatus {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::NotChecked => "not-checked",
            Self::CheckFailed => "check-failed",
            Self::RateLimited => "rate-limited",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DerivedLikelihood {
    Likely,
    Possible,
    Unlikely,
    Unknown,
}

impl DerivedLikelihood {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Likely => "likely",
            Self::Possible => "possible",
            Self::Unlikely => "unlikely",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnectivityChecksPolicy {
    pub local_checks_without_network_probe: bool,
    pub external_probe_allowed: bool,
    pub probe_timeout_ms: u64,
    pub max_probe_retries: u8,
    pub min_refresh_interval_seconds: u64,
    pub offline_mode_behavior: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecommendationClass {
    PreferredPrimary,
    PreferredSecondary,
    AllowedButNotRecommended,
    NotRecommended,
}

impl RecommendationClass {
    pub const fn title(self) -> &'static str {
        match self {
            Self::PreferredPrimary => "preferred-primary",
            Self::PreferredSecondary => "preferred-secondary",
            Self::AllowedButNotRecommended => "allowed-but-not-recommended",
            Self::NotRecommended => "not-recommended",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecommendationConfidence {
    High,
    Medium,
    Low,
    Unknown,
}

impl RecommendationConfidence {
    pub const fn title(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdapterCheckActionId {
    CheckRoute,
    ShowExternalIp,
    CheckInternetAvailability,
}

impl AdapterCheckActionId {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::CheckRoute => "check-route",
            Self::ShowExternalIp => "show-external-ip",
            Self::CheckInternetAvailability => "check-internet-availability",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::CheckRoute => "Check route",
            Self::ShowExternalIp => "Show external IP",
            Self::CheckInternetAvailability => "Internet available via adapter",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdapterCheckExecutionScope {
    ReadOnlyDiagnostics,
    RequiresServiceMediation,
}

impl AdapterCheckExecutionScope {
    pub const fn title(self) -> &'static str {
        match self {
            Self::ReadOnlyDiagnostics => "read-only-diagnostics",
            Self::RequiresServiceMediation => "requires-service-mediation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AdapterCheckActionContract {
    pub id: AdapterCheckActionId,
    pub scope: AdapterCheckExecutionScope,
    pub description: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdapterCheckResultStatus {
    Success,
    Degraded,
    Unavailable,
    Timeout,
}

impl AdapterCheckResultStatus {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdapterIdentityField {
    AdapterName,
    Ipv6IfIndex,
    PhysicalAddress,
}

impl AdapterIdentityField {
    pub const fn title(self) -> &'static str {
        match self {
            Self::AdapterName => "AdapterName",
            Self::Ipv6IfIndex => "IPv6IfIndex",
            Self::PhysicalAddress => "PhysicalAddress",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterIdentityContract {
    pub stable_fields: &'static [AdapterIdentityField],
    pub display_only_fields: &'static [&'static str],
    pub persistent_id_policy: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AdapterSnapshotDataSource {
    WindowsLive,
    FallbackMock,
}

impl AdapterSnapshotDataSource {
    pub const fn title(self) -> &'static str {
        match self {
            Self::WindowsLive => "windows-live",
            Self::FallbackMock => "fallback-mock",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterIdentity {
    pub persistent_id: String,
    pub adapter_name: String,
    pub ipv6_if_index: u32,
    pub physical_address: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterSnapshotEntry {
    pub identity: AdapterIdentity,
    pub windows_name: String,
    pub interface_description: String,
    pub interface_type: String,
    pub oper_status: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdaptersSnapshot {
    pub data_source: AdapterSnapshotDataSource,
    pub identity_contract: AdapterIdentityContract,
    pub adapters: Vec<AdapterSnapshotEntry>,
}

/// The two supported route roles in the Free edition.
///
/// This is the canonical shared type for route roles used across domain,
/// IPC contracts, and DTO layers.
///
/// The Pro edition will introduce additional named routes beyond `Primary`
/// and `Secondary`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteRole {
    Primary,
    Secondary,
}

impl RouteRole {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
        }
    }

    pub const fn user_label(self) -> &'static str {
        match self {
            Self::Primary => "Primary route",
            Self::Secondary => "Secondary route",
        }
    }
}

impl fmt::Display for RouteRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// Describes how a route role was bound to an adapter.
///
/// A richer typed source than a plain `user_confirmed: bool` — it carries
/// provenance for the binding.
///
/// # Confirmation semantics
///
/// `is_user_confirmed()` returns `true` for sources that carry the same
/// authority as an explicit user decision:
/// - `UserAssigned`: user made an explicit choice and confirmed it
/// - `RestoredFromConfig`: previously confirmed by the user and persisted
///
/// `HeuristicSuggestion` is **not** confirmed — unconfirmed bindings must
/// not be treated as authoritative policy assignments.
///
/// Enforcement logic (refusing to apply routing without a `UserAssigned`
/// or `RestoredFromConfig` source, surfacing `HeuristicSuggestion` as a
/// pending confirmation UI state) lives in the real service apply flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BindingSource {
    /// User explicitly selected and confirmed this adapter for the role.
    UserAssigned,
    /// System heuristic suggestion — not yet acknowledged by the user.
    /// Must not be treated as a confirmed policy assignment.
    HeuristicSuggestion,
    /// Restored from a previously persisted configuration on startup.
    /// Treated as confirmed (the user confirmed it in a prior session).
    RestoredFromConfig,
}

impl BindingSource {
    /// Returns `true` when the binding carries the authority of an explicit
    /// user decision — either directly assigned or restored from a prior
    /// confirmed session.
    pub const fn is_user_confirmed(self) -> bool {
        matches!(self, Self::UserAssigned | Self::RestoredFromConfig)
    }

    pub const fn slug(self) -> &'static str {
        match self {
            Self::UserAssigned => "user-assigned",
            Self::HeuristicSuggestion => "heuristic-suggestion",
            Self::RestoredFromConfig => "restored-from-config",
        }
    }
}

/// Default routing behavior when no rule matches a given connection.
///
/// # Free edition modes
///
/// Three modes are available. They differ in how unmatched traffic is
/// handled and what happens when the secondary adapter is unavailable.
///
/// | Mode | Unmatched traffic | Secondary unavailable |
/// |------|-------------------|-----------------------|
/// | `PreferPrimary` | → primary | primary continues normally |
/// | `PreferSecondaryWhenAvailable` | → secondary if up, else primary | falls back to primary |
/// | `StrictSecondaryFailClosed` | → secondary | **blocks all traffic** |
///
/// # Default mode selection (Variant B)
///
/// - When no secondary adapter is bound: `PreferPrimary` is the default.
///   Use `default_when_secondary_unbound()`.
/// - When the user first binds a secondary adapter: `StrictSecondaryFailClosed`
///   is the recommended default (prevents accidental leak via primary).
///   Use `recommended_when_secondary_bound()`.
///
/// Actual enforcement — monitoring secondary availability, blocking traffic
/// in `StrictSecondaryFailClosed`, and falling back in
/// `PreferSecondaryWhenAvailable` — is implemented via real Windows routing
/// table manipulation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteBehaviorMode {
    /// All unmatched traffic uses the primary adapter. Rules redirect
    /// specific destinations to secondary. Default when secondary is
    /// not yet configured.
    PreferPrimary,
    /// Unmatched traffic uses secondary when available, falls back to
    /// primary if secondary is down. Suitable when secondary is preferred
    /// but not strictly required.
    PreferSecondaryWhenAvailable,
    /// All unmatched traffic must use secondary. If secondary becomes
    /// unavailable, **all traffic is blocked** — nothing falls back to
    /// primary. Recommended default when secondary (VPN) is configured.
    StrictSecondaryFailClosed,
}

impl RouteBehaviorMode {
    /// Returns the mode to use when no secondary adapter is bound yet.
    ///
    /// `PreferPrimary` is safe here: without a secondary, routing is
    /// effectively pass-through via the OS routing table.
    pub const fn default_when_secondary_unbound() -> Self {
        Self::PreferPrimary
    }

    /// Returns the recommended mode when the user first binds a secondary.
    ///
    /// `StrictSecondaryFailClosed` prevents accidental traffic leak via
    /// primary when secondary (typically VPN) is configured but unavailable.
    pub const fn recommended_when_secondary_bound() -> Self {
        Self::StrictSecondaryFailClosed
    }

    pub const fn slug(self) -> &'static str {
        match self {
            Self::PreferPrimary => "prefer-primary",
            Self::PreferSecondaryWhenAvailable => "prefer-secondary-when-available",
            Self::StrictSecondaryFailClosed => "strict-secondary-fail-closed",
        }
    }

    pub const fn user_label(self) -> &'static str {
        match self {
            Self::PreferPrimary => "Primary (direct)",
            Self::PreferSecondaryWhenAvailable => "Prefer secondary when available",
            Self::StrictSecondaryFailClosed => "Strict secondary (Fail-Closed)",
        }
    }

    /// Where traffic goes when no rule matches it.
    ///
    /// The availability check reads it to know which link a default-routed
    /// request depends on; companion discovery reads it to know which
    /// suggestions would change nothing (a rule naming this role only restates
    /// what already happens).
    pub const fn default_route_role(self) -> RouteRole {
        match self {
            Self::PreferPrimary => RouteRole::Primary,
            Self::PreferSecondaryWhenAvailable | Self::StrictSecondaryFailClosed => {
                RouteRole::Secondary
            }
        }
    }
}

impl fmt::Display for RouteBehaviorMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for RouteBehaviorMode {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "prefer-primary" | "primary" => Ok(Self::PreferPrimary),
            "prefer-secondary-when-available" | "prefer-secondary" | "secondary" => {
                Ok(Self::PreferSecondaryWhenAvailable)
            }
            "strict-secondary-fail-closed" | "strict-secondary" | "fail-closed" => {
                Ok(Self::StrictSecondaryFailClosed)
            }
            _ => Err("unknown route behavior mode"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteSelectionState {
    Selected,
    NotSelected,
    Unavailable,
    RequiresVerification,
    FailClosedConflict,
}

impl RouteSelectionState {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Selected => "selected",
            Self::NotSelected => "not-selected",
            Self::Unavailable => "unavailable",
            Self::RequiresVerification => "requires-verification",
            Self::FailClosedConflict => "fail-closed-conflict",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InterfacesRoutesContract {
    pub field_readiness: &'static [InterfaceFieldReadiness],
    pub field_snapshot_status: &'static [InterfaceFieldSnapshotStatus],
    pub field_usage_scopes: &'static [InterfaceFieldUsage],
    pub display_format: InterfacesDisplayFormat,
    pub enriched_fields: &'static [&'static str],
    pub connectivity_states: &'static [ConnectivityState],
    pub external_ip_statuses: &'static [ExternalIpStatus],
    pub derived_likelihood_scale: &'static [DerivedLikelihood],
    pub recommendation_classes: &'static [RecommendationClass],
    pub recommendation_confidence_levels: &'static [RecommendationConfidence],
    pub connectivity_checks_policy: ConnectivityChecksPolicy,
    pub observed_vs_derived_boundary: &'static str,
    pub vpn_tunnel_signals: &'static [&'static str],
    pub virtual_interface_signals: &'static [&'static str],
    pub service_interface_signals: &'static [&'static str],
    pub derived_cache_policy: &'static str,
    pub recommendation_tie_break_priority: &'static [&'static str],
    pub recommendation_advisory_policy: &'static str,
    pub recommendation_hints_catalog: &'static [&'static str],
    pub manual_role_confirmation_required: bool,
    pub role_conflict_policy: &'static str,
    pub confirmed_choice_priority_policy: &'static str,
    pub secondary_role_ux_warnings: &'static [&'static str],
    pub show_bluetooth_adapters_default: bool,
    pub bluetooth_detection_signals: &'static [&'static str],
    pub bluetooth_recommendation_policy: &'static str,
    pub adapter_check_actions: &'static [AdapterCheckActionContract],
    pub adapter_check_result_statuses: &'static [AdapterCheckResultStatus],
    pub diagnostics_explain_integration_note: &'static str,
    pub supported_behavior_modes: &'static [RouteBehaviorMode],
    pub route_state_placeholders: &'static [RouteSelectionState],
    pub preview_only_selection: bool,
    pub preview_notice: &'static str,
    pub role_explanation: &'static str,
    pub diagnostics_alignment_note: &'static str,
}

/// Free edition rule type — determines how the match value is interpreted.
///
/// # Domain vs exact-FQDN vs suffix/subdomain (legacy)
///
/// In the Free edition, domain-based rules always match the label itself **and
/// all subdomains at any depth**. The former `ExactFqdn` and `SuffixOrSubdomain`
/// distinctions are collapsed into a single `Domain` variant. Legacy preset files
/// using the old slugs are automatically mapped to `Domain` by `FromStr`.
///
/// # Evaluation order
///
/// See [`evaluation_priority`](Self::evaluation_priority) for the relative
/// priority of each type within the evaluation pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FreeRuleType {
    /// Matches traffic by Windows process name (e.g. `"browser.exe"`).
    /// Evaluated in Pass 2, after all address-based rules.
    Application,
    /// Matches a domain label and all its subdomains at any depth.
    /// `"example.com"` matches `example.com`, `www.example.com`, etc.
    Domain,
    /// Matches a TLD or internal domain suffix (e.g. `".ru"`,
    /// `".intra"`). Free tier supports domain-suffix zones only;
    /// IP-subnet zones remain Pro-only. The rule engine evaluates
    /// zone matches at tier 3 (after Exact FQDN and Subdomain/Suffix).
    Zone,
    /// Matches one exact IP address. No CIDR prefix or range matching.
    ExactIp,
}

impl FreeRuleType {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Domain => "domain",
            Self::Zone => "zone",
            Self::ExactIp => "exact-ip",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::Application => "Application",
            Self::Domain => "Domain",
            Self::Zone => "Zone",
            Self::ExactIp => "Exact IP",
        }
    }

    /// Evaluation priority for this rule type.
    ///
    /// Lower values are evaluated first (more-specific first).
    /// `Application` rules have the highest number — they are evaluated in
    /// a separate pass after all address-based rules.
    ///
    /// | Type          | Priority | Pass   |
    /// |---------------|----------|--------|
    /// | `Domain`      | 1        | Pass 1 |
    /// | `Zone`        | 2        | Pass 1 |
    /// | `ExactIp`     | 3        | Pass 1 |
    /// | `Application` | 4        | Pass 2 |
    pub const fn evaluation_priority(self) -> u8 {
        match self {
            Self::Domain => 1,
            Self::Zone => 2,
            Self::ExactIp => 3,
            Self::Application => 4,
        }
    }
}

impl fmt::Display for FreeRuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for FreeRuleType {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "application" | "app" => Ok(Self::Application),
            // "domain" is canonical; legacy preset aliases are accepted for migration
            "domain" | "exact-fqdn" | "fqdn" | "suffix-or-subdomain" | "suffix" | "subdomain" => {
                Ok(Self::Domain)
            }
            "zone" => Ok(Self::Zone),
            "exact-ip" | "ip" => Ok(Self::ExactIp),
            _ => Err("unknown free rule type"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RuleScenario {
    Create,
    Edit,
    Delete,
    Reorder,
    Search,
}

impl RuleScenario {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Edit => "edit",
            Self::Delete => "delete",
            Self::Reorder => "reorder",
            Self::Search => "search",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::Create => "Create",
            Self::Edit => "Edit",
            Self::Delete => "Delete",
            Self::Reorder => "Reorder",
            Self::Search => "Search",
        }
    }
}

impl fmt::Display for RuleScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for RuleScenario {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "create" | "add" => Ok(Self::Create),
            "edit" => Ok(Self::Edit),
            "delete" | "remove" => Ok(Self::Delete),
            "reorder" | "order" => Ok(Self::Reorder),
            "search" | "find" => Ok(Self::Search),
            _ => Err("unknown rule scenario"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RuleFormFieldId {
    RuleType,
    MatchValue,
    TargetRoute,
    Enabled,
    Comment,
}

impl RuleFormFieldId {
    pub const fn title(self) -> &'static str {
        match self {
            Self::RuleType => "Rule type",
            Self::MatchValue => "Match value",
            Self::TargetRoute => "Target route",
            Self::Enabled => "Enabled",
            Self::Comment => "Comment",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RuleFormFieldSpec {
    pub id: RuleFormFieldId,
    pub required: bool,
    pub constraint_hint: &'static str,
    pub visible_in_gui_v1: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FreeRuleListType {
    SingleActiveManagedList,
    ImportedPresetReplacingActiveList,
}

impl FreeRuleListType {
    pub const fn title(self) -> &'static str {
        match self {
            Self::SingleActiveManagedList => "Single active managed list",
            Self::ImportedPresetReplacingActiveList => "Imported preset replacing active list",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RuleListLoadFieldId {
    FilePath,
    Format,
    SchemaVersion,
    ParsedSummary,
    ReplaceCurrentList,
    LoadAction,
    CancelAction,
}

impl RuleListLoadFieldId {
    pub const fn title(self) -> &'static str {
        match self {
            Self::FilePath => "File path",
            Self::Format => "Format",
            Self::SchemaVersion => "Schema version",
            Self::ParsedSummary => "Parsed summary",
            Self::ReplaceCurrentList => "Replace current list",
            Self::LoadAction => "Load",
            Self::CancelAction => "Cancel",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RuleListEditFieldId {
    ListName,
    Description,
    RulesSet,
    RulesOrder,
    DefaultMode,
    SaveAction,
    CancelAction,
}

impl RuleListEditFieldId {
    pub const fn title(self) -> &'static str {
        match self {
            Self::ListName => "List name",
            Self::Description => "Description",
            Self::RulesSet => "Rules set",
            Self::RulesOrder => "Rules order",
            Self::DefaultMode => "Default mode",
            Self::SaveAction => "Save",
            Self::CancelAction => "Cancel",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RuleReplaceReviewFieldId {
    IncomingListName,
    IncomingRulesCount,
    CurrentRulesCount,
    DefaultModeDiff,
    NewTypesSummary,
    ReplaceAction,
    CancelAction,
}

impl RuleReplaceReviewFieldId {
    pub const fn title(self) -> &'static str {
        match self {
            Self::IncomingListName => "Incoming list name",
            Self::IncomingRulesCount => "Incoming rules count",
            Self::CurrentRulesCount => "Current rules count",
            Self::DefaultModeDiff => "Default mode difference",
            Self::NewTypesSummary => "New rule types summary",
            Self::ReplaceAction => "Replace",
            Self::CancelAction => "Cancel",
        }
    }
}

/// Sort order for the rules table view.
///
/// `ByDisplayOrder` is the default and preserves the user-defined file order.
/// Other modes re-order the visible rows without modifying the underlying rule
/// file — the file always stores rules in user display order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RulesViewSort {
    /// User-defined display order (default). Preserves the order from the rule file.
    #[default]
    ByDisplayOrder,
    /// Alphabetical by match value (domain label, IP address, or process name).
    ByMatchValue,
    /// Grouped by rule type: Domain → ExactIp → Application.
    ByType,
    /// Grouped by target route: Primary first, then Secondary.
    ByRoute,
}

impl RulesViewSort {
    pub const ALL: [Self; 4] = [
        Self::ByDisplayOrder,
        Self::ByMatchValue,
        Self::ByType,
        Self::ByRoute,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::ByDisplayOrder => "by-display-order",
            Self::ByMatchValue => "by-match-value",
            Self::ByType => "by-type",
            Self::ByRoute => "by-route",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::ByDisplayOrder => "Display order",
            Self::ByMatchValue => "Match value",
            Self::ByType => "Rule type",
            Self::ByRoute => "Target route",
        }
    }
}

impl fmt::Display for RulesViewSort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for RulesViewSort {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "by-display-order" | "display-order" | "default" => Ok(Self::ByDisplayOrder),
            "by-match-value" | "match-value" | "alphabetical" => Ok(Self::ByMatchValue),
            "by-type" | "type" => Ok(Self::ByType),
            "by-route" | "route" => Ok(Self::ByRoute),
            _ => Err("unknown rules view sort"),
        }
    }
}

/// Enabled/disabled filter for the rules table view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RulesEnabledFilter {
    /// Show all rules regardless of enabled state (default).
    #[default]
    All,
    /// Show only rules that are currently enabled.
    EnabledOnly,
    /// Show only rules that are currently disabled.
    DisabledOnly,
}

impl RulesEnabledFilter {
    pub const ALL: [Self; 3] = [Self::All, Self::EnabledOnly, Self::DisabledOnly];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::EnabledOnly => "enabled-only",
            Self::DisabledOnly => "disabled-only",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::EnabledOnly => "Enabled only",
            Self::DisabledOnly => "Disabled only",
        }
    }
}

impl fmt::Display for RulesEnabledFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for RulesEnabledFilter {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "all" => Ok(Self::All),
            "enabled-only" | "enabled" => Ok(Self::EnabledOnly),
            "disabled-only" | "disabled" => Ok(Self::DisabledOnly),
            _ => Err("unknown rules enabled filter"),
        }
    }
}

/// Rule-type filter for the rules table view.
///
/// `All` is the default and shows every rule regardless of type. Section-based
/// variants (`Zones`, `Domain`, `ExactIp`, `Application`, `Windows`, `Linux`,
/// `MacOS`) narrow the visible set to the corresponding rules-file section.
///
/// `Application` is an alias for the current-platform application section
/// (equivalent to `Windows` on Windows). `Windows`, `Linux`, and `MacOS` are
/// the explicit cross-platform section names; the latter two are "other OS"
/// filters hidden in the GUI unless the user enables "Show rules for other OS".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RulesTypeFilter {
    /// Show all rule types (default).
    #[default]
    All,
    /// Show only rules in the `--- Zones` section.
    Zones,
    /// Show only rules in the `--- Domains` section.
    Domain,
    /// Show only rules in the `--- IP` section.
    ExactIp,
    /// Show only application rules for the current platform
    /// (on Windows, equivalent to `Windows`).
    Application,
    /// Show only rules in the `--- Windows` section.
    Windows,
    /// Show only rules in the `--- Linux` section (other-OS filter).
    Linux,
    /// Show only rules in the `--- MacOS` section (other-OS filter).
    MacOS,
}

impl RulesTypeFilter {
    pub const ALL: [Self; 8] = [
        Self::All,
        Self::Zones,
        Self::Domain,
        Self::ExactIp,
        Self::Application,
        Self::Windows,
        Self::Linux,
        Self::MacOS,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Zones => "zones",
            Self::Domain => "domain",
            Self::ExactIp => "exact-ip",
            Self::Application => "application",
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::MacOS => "macos",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All types",
            Self::Zones => "Zones",
            Self::Domain => "Domain",
            Self::ExactIp => "Exact IP",
            Self::Application => "Application",
            Self::Windows => "Windows",
            Self::Linux => "Linux",
            Self::MacOS => "macOS",
        }
    }

    /// `true` for filters that represent another OS's application-rule section.
    ///
    /// These are hidden in the GUI by default and only shown when the user
    /// enables "Show rules for other OS" in settings.
    pub const fn is_other_os_on_windows(self) -> bool {
        matches!(self, Self::Linux | Self::MacOS)
    }
}

impl fmt::Display for RulesTypeFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for RulesTypeFilter {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "all" => Ok(Self::All),
            "zones" => Ok(Self::Zones),
            "domain" => Ok(Self::Domain),
            "exact-ip" | "ip" => Ok(Self::ExactIp),
            "application" | "app" => Ok(Self::Application),
            "windows" => Ok(Self::Windows),
            "linux" => Ok(Self::Linux),
            "macos" => Ok(Self::MacOS),
            _ => Err("unknown rules type filter"),
        }
    }
}

/// Resolution choice for the "duplicate rule across primary and secondary lists" dialog.
///
/// Shown when the same rule (`DuplicateRuleAcrossSets` warning from validation) appears
/// in both lists simultaneously. The user decides which list retains the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RulesDuplicateResolution {
    /// Remove the rule from the secondary list, keep only in primary.
    KeepInPrimary,
    /// Remove the rule from the primary list, keep only in secondary.
    KeepInSecondary,
    /// Keep the rule in both lists (dismiss the warning without removing either copy).
    KeepInBoth,
}

impl RulesDuplicateResolution {
    pub const ALL: [Self; 3] = [Self::KeepInPrimary, Self::KeepInSecondary, Self::KeepInBoth];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::KeepInPrimary => "keep-in-primary",
            Self::KeepInSecondary => "keep-in-secondary",
            Self::KeepInBoth => "keep-in-both",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::KeepInPrimary => "Keep in primary",
            Self::KeepInSecondary => "Keep in secondary",
            Self::KeepInBoth => "Keep in both",
        }
    }
}

impl fmt::Display for RulesDuplicateResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for RulesDuplicateResolution {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "keep-in-primary" | "primary" => Ok(Self::KeepInPrimary),
            "keep-in-secondary" | "secondary" => Ok(Self::KeepInSecondary),
            "keep-in-both" | "both" => Ok(Self::KeepInBoth),
            _ => Err("unknown duplicate resolution"),
        }
    }
}

/// How the application responds when the external rules file changes on disk.
///
/// Stored in `UiPreferences`. Determines the default behavior of the
/// "Update rules from file" flow. The user can change this in Settings.
///
/// Default is [`Notify`](RulesFileChangeBehavior::Notify) — the safer option
/// that always surfaces a diff for the user to review before applying.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RulesFileChangeBehavior {
    /// Show a notification and wait for the user to press "Update rules from
    /// file" before applying the change. The diff is shown for review.
    #[default]
    Notify,
    /// The service reads the changed file and applies the update immediately
    /// without waiting for user confirmation. A diff is recorded in the audit
    /// log but no interactive review step is shown.
    AutoApply,
}

impl RulesFileChangeBehavior {
    pub const ALL: [Self; 2] = [Self::Notify, Self::AutoApply];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::Notify => "notify",
            Self::AutoApply => "auto-apply",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Notify => "Notify me",
            Self::AutoApply => "Apply automatically",
        }
    }
}

impl fmt::Display for RulesFileChangeBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for RulesFileChangeBehavior {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "notify" => Ok(Self::Notify),
            "auto-apply" | "auto" => Ok(Self::AutoApply),
            _ => Err("unknown rules file change behavior"),
        }
    }
}

/// Verbosity level for the diagnostic log output.
///
/// Controls how much detail the service writes to its log store and presents
/// on the Logs screen. Stored in `UiPreferences` and applied by the service
/// when it initialises its log sink.
///
/// Default: [`Info`](LogLevel::Info) — useful in everyday operation without
/// overwhelming the log view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum LogLevel {
    /// Informational messages about normal service operation.
    #[default]
    Info,
    /// Warnings about recoverable conditions (e.g. stale cache, interface
    /// briefly unavailable).
    Warning,
    /// Detailed trace output for troubleshooting (includes rule matching
    /// decisions and availability snapshots).
    Debug,
    /// Critical errors only — the smallest possible log volume. Suitable
    /// for users who want minimal log noise in production.
    Critical,
}

impl LogLevel {
    pub const ALL: [Self; 4] = [Self::Info, Self::Warning, Self::Debug, Self::Critical];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Debug => "debug",
            Self::Critical => "critical",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Warning => "Warning",
            Self::Debug => "Debug",
            Self::Critical => "Critical",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for LogLevel {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "info" => Ok(Self::Info),
            "warning" | "warn" => Ok(Self::Warning),
            "debug" => Ok(Self::Debug),
            "critical" | "crit" => Ok(Self::Critical),
            _ => Err("unknown log level"),
        }
    }
}

/// Validation outcome for a single rule as exposed in the rules screen.
///
/// Lets the GUI highlight individual rows without needing access to the full
/// `ValidationOutcome` type from `nrr-domain`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RuleValidationStatus {
    /// Rule passed validation without issues.
    Valid,
    /// Rule was accepted with one or more normalization warnings (e.g. IDN
    /// domain punycode-encoded, process path stripped, `.exe` suffix added).
    Warning,
    /// Rule contains a blocking validation error and will not participate in
    /// route evaluation until the error is resolved.
    Error,
}

impl RuleValidationStatus {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Valid => "Valid",
            Self::Warning => "Warning",
            Self::Error => "Error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RulesContract {
    pub supported_free_rule_types: &'static [FreeRuleType],
    pub placeholder_scenarios: &'static [RuleScenario],
    pub form_fields: &'static [RuleFormFieldSpec],
    pub supported_free_list_types: &'static [FreeRuleListType],
    pub load_list_dialog_fields: &'static [RuleListLoadFieldId],
    pub edit_list_dialog_fields: &'static [RuleListEditFieldId],
    pub replace_review_dialog_fields: &'static [RuleReplaceReviewFieldId],
    pub load_list_requires_review_before_replace: bool,
    pub preview_notice: &'static str,
    /// Sort modes available in the rules table view.
    pub supported_sort_modes: &'static [RulesViewSort],
    /// Enabled/disabled filter options available in the rules table view.
    pub supported_enabled_filters: &'static [RulesEnabledFilter],
    /// Rule-type filter options available in the rules table view (all variants).
    pub supported_type_filters: &'static [RulesTypeFilter],
    /// Subset of `supported_type_filters` that represent other-OS sections.
    ///
    /// The GUI hides these filters by default and reveals them only when the
    /// user enables "Show rules for other OS" in settings.
    pub other_os_type_filters: &'static [RulesTypeFilter],
    /// Resolution choices for the duplicate-rule-across-sets dialog.
    pub supported_duplicate_resolutions: &'static [RulesDuplicateResolution],
    /// Default value for the "block secondary-targeted connections when secondary
    /// is unavailable" setting. `false` = fail-open (reroute to primary).
    pub block_secondary_when_unavailable_default: bool,
    /// Supported behaviors when the external rules file changes on disk.
    pub supported_file_change_behaviors: &'static [RulesFileChangeBehavior],
    /// Default file-change behavior. `Notify` is the safe default — the user
    /// reviews the diff before the service applies it.
    pub default_file_change_behavior: RulesFileChangeBehavior,
    /// `true` when the GUI shows a per-rule enable/disable toggle.
    ///
    /// Toggling a rule off in the GUI comments out its line in the rules file
    /// (`# value`). Toggling it on removes the leading `#`.
    pub supports_rule_enable_toggle: bool,
    /// `true` when the GUI shows and allows editing of the per-rule inline
    /// comment (the text after `#` on an active rule line).
    pub supports_rule_comments: bool,
    /// Enabled state a rule gets when the user adds it and never touches the
    /// enable toggle. Must stay `true`: a rule the user typed in is a rule the
    /// user wants applied, and a rule that silently lands disabled enforces
    /// nothing while looking like it was accepted.
    ///
    /// The Add/Edit dialog (`apps/desktop/qml/components/RuleEditDialog.qml`)
    /// realises this by resetting its local enabled state — and the widget
    /// bound to it — on every open, so a toggle cleared in one dialog session
    /// cannot survive into the next.
    pub new_rule_enabled_default: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FirstRunStepId {
    Welcome,
    BasicScenarioSelection,
    RoutesSetup,
    RulesSetup,
    DiagnosticsPreview,
    Finish,
}

impl FirstRunStepId {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Welcome => "Welcome",
            Self::BasicScenarioSelection => "Basic scenario selection",
            Self::RoutesSetup => "Routes setup",
            Self::RulesSetup => "Rules setup",
            Self::DiagnosticsPreview => "Diagnostics preview",
            Self::Finish => "Finish",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FirstRunScenarioId {
    QuickStart,
    GuidedDefault,
}

impl FirstRunScenarioId {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::QuickStart => "quick-start",
            Self::GuidedDefault => "guided-default",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::QuickStart => "Quick start",
            Self::GuidedDefault => "Guided default setup",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FirstRunStepSpec {
    pub id: FirstRunStepId,
    pub required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StartupDataState {
    Empty,
    SemiEmpty,
    TestDataPreview,
}

impl StartupDataState {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::SemiEmpty => "semi-empty",
            Self::TestDataPreview => "test-data-preview",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SectionStartupState {
    pub section: AppSection,
    pub state: StartupDataState,
    pub note: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SetupActionAvailability {
    Allowed,
    SoftGuided,
    BlockedUntilWizardCompletion,
}

impl SetupActionAvailability {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::SoftGuided => "soft-guided",
            Self::BlockedUntilWizardCompletion => "blocked-until-wizard-completion",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SetupActionGate {
    pub action: AppAction,
    pub before_completion: SetupActionAvailability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FirstRunContract {
    pub steps: &'static [FirstRunStepSpec],
    pub scenarios: &'static [FirstRunScenarioId],
    pub default_scenario: FirstRunScenarioId,
    pub quick_start_path_sections: &'static [AppSection],
    pub startup_states: &'static [SectionStartupState],
    pub action_gates_before_completion: &'static [SetupActionGate],
    pub list_editing_preview_notice: &'static str,
    pub completion_notice: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SecurityIndicatorId {
    ActiveRevision,
    PendingChanges,
    TamperAlerts,
    RollbackState,
    ServiceStatus,
    ExplainWarnings,
}

impl SecurityIndicatorId {
    pub const fn title(self) -> &'static str {
        match self {
            Self::ActiveRevision => "Active revision",
            Self::PendingChanges => "Pending changes",
            Self::TamperAlerts => "Tamper alerts",
            Self::RollbackState => "Rollback state",
            Self::ServiceStatus => "Service status",
            Self::ExplainWarnings => "Explain warnings",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VisibilityScope {
    AlwaysVisible,
    ScreenOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SecurityVisibilityRule {
    pub indicator: SecurityIndicatorId,
    pub scope: VisibilityScope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SecurityVisibilityContract {
    pub rules: &'static [SecurityVisibilityRule],
}

const MAIN_WINDOW_SECTIONS: [AppSection; 5] = AppSection::ALL;
const TRAY_ONLY_ACTIONS: [AppAction; 2] = [
    AppAction::SafeRollback,
    AppAction::TemporarilyDisableProductImpact,
];

const FILE_MENU_ITEMS: [MenuItem; 4] = [
    MenuItem {
        action: AppAction::LoadRuleList,
        availability: MenuAvailability::Preview,
    },
    MenuItem {
        action: AppAction::ImportPreset,
        availability: MenuAvailability::Preview,
    },
    MenuItem {
        action: AppAction::ExportCurrentRuleList,
        availability: MenuAvailability::Preview,
    },
    MenuItem {
        action: AppAction::ExitApplication,
        availability: MenuAvailability::Enabled,
    },
];

const VIEW_MENU_ITEMS: [MenuItem; 5] = [
    MenuItem {
        action: AppAction::OpenSection(AppSection::InterfacesAndRoutes),
        availability: MenuAvailability::Enabled,
    },
    MenuItem {
        action: AppAction::OpenSection(AppSection::Rules),
        availability: MenuAvailability::Enabled,
    },
    MenuItem {
        action: AppAction::OpenSection(AppSection::Diagnostics),
        availability: MenuAvailability::Enabled,
    },
    MenuItem {
        action: AppAction::OpenSection(AppSection::Logs),
        availability: MenuAvailability::Enabled,
    },
    MenuItem {
        action: AppAction::OpenSection(AppSection::Settings),
        availability: MenuAvailability::Enabled,
    },
];

const TOOLS_MENU_ITEMS: [MenuItem; 4] = [
    MenuItem {
        action: AppAction::RefreshInterfaces,
        availability: MenuAvailability::Preview,
    },
    MenuItem {
        action: AppAction::CheckServiceStatus,
        availability: MenuAvailability::Preview,
    },
    MenuItem {
        action: AppAction::SafeRollback,
        availability: MenuAvailability::Preview,
    },
    MenuItem {
        action: AppAction::TemporarilyDisableProductImpact,
        availability: MenuAvailability::Preview,
    },
];

const HELP_MENU_ITEMS: [MenuItem; 4] = [
    MenuItem {
        action: AppAction::OpenAboutWindow,
        availability: MenuAvailability::Enabled,
    },
    MenuItem {
        action: AppAction::OpenLicenseWindow,
        availability: MenuAvailability::Enabled,
    },
    MenuItem {
        action: AppAction::OpenLogsFolder,
        availability: MenuAvailability::Preview,
    },
    MenuItem {
        action: AppAction::CheckForUpdates,
        availability: MenuAvailability::Preview,
    },
];

const MENU_BAR: [MenuGroup; 4] = [
    MenuGroup {
        id: MenuGroupId::File,
        items: &FILE_MENU_ITEMS,
    },
    MenuGroup {
        id: MenuGroupId::View,
        items: &VIEW_MENU_ITEMS,
    },
    MenuGroup {
        id: MenuGroupId::Tools,
        items: &TOOLS_MENU_ITEMS,
    },
    MenuGroup {
        id: MenuGroupId::Help,
        items: &HELP_MENU_ITEMS,
    },
];

const TRAY_PRIMARY_ACTIONS: [MenuItem; 10] = [
    MenuItem {
        action: AppAction::OpenMainWindow,
        availability: MenuAvailability::Enabled,
    },
    MenuItem {
        action: AppAction::OpenSection(AppSection::InterfacesAndRoutes),
        availability: MenuAvailability::Enabled,
    },
    MenuItem {
        action: AppAction::OpenSection(AppSection::Rules),
        availability: MenuAvailability::Enabled,
    },
    MenuItem {
        action: AppAction::OpenSection(AppSection::Diagnostics),
        availability: MenuAvailability::Enabled,
    },
    MenuItem {
        action: AppAction::OpenSection(AppSection::Logs),
        availability: MenuAvailability::Enabled,
    },
    MenuItem {
        action: AppAction::OpenSection(AppSection::Settings),
        availability: MenuAvailability::Enabled,
    },
    MenuItem {
        action: AppAction::OpenAboutWindow,
        availability: MenuAvailability::Enabled,
    },
    MenuItem {
        action: AppAction::OpenLicenseWindow,
        availability: MenuAvailability::Enabled,
    },
    MenuItem {
        action: AppAction::OpenLogsFolder,
        availability: MenuAvailability::Enabled,
    },
    MenuItem {
        action: AppAction::ExitApplication,
        availability: MenuAvailability::Enabled,
    },
];

const TRAY_QUICK_ACTIONS: [MenuItem; 3] = [
    MenuItem {
        action: AppAction::RefreshInterfaces,
        availability: MenuAvailability::Preview,
    },
    MenuItem {
        action: AppAction::SafeRollback,
        availability: MenuAvailability::Preview,
    },
    MenuItem {
        action: AppAction::TemporarilyDisableProductImpact,
        availability: MenuAvailability::Preview,
    },
];

const WINDOWS: [GuiWindow; 5] = [
    GuiWindow::MainWindow,
    GuiWindow::FirstRunWizard,
    GuiWindow::RuleListLoadWindow,
    GuiWindow::RuleListEditWindow,
    GuiWindow::AboutWindow,
];

const DIALOGS: [GuiDialog; 6] = [
    GuiDialog::ConfirmReplaceCurrentList,
    GuiDialog::ReviewReplaceCurrentList,
    GuiDialog::ConfirmDiscardUnsavedChanges,
    GuiDialog::ConfirmClearLogs,
    GuiDialog::ConfirmRollback,
    GuiDialog::ConfirmDisableProductImpact,
];

const NAVIGATION_MODEL: NavigationModel = NavigationModel {
    style: NavigationStyle::SidebarWithStackedViews,
    back_cancel_apply_supported: true,
    tray_opening_reuses_main_window: true,
};

const MAIN_WINDOW_LAYOUT_ZONES: [MainWindowLayoutZone; 6] = [
    MainWindowLayoutZone::TitleBar,
    MainWindowLayoutZone::MenuBar,
    MainWindowLayoutZone::Sidebar,
    MainWindowLayoutZone::Workspace,
    MainWindowLayoutZone::StatusBar,
    MainWindowLayoutZone::ActionBar,
];

const SHARED_SHELL_SECTIONS: [AppSection; 2] = [AppSection::Settings, AppSection::Diagnostics];

const SHARED_SHELL_REVIEW_DIALOGS: [GuiDialog; 2] = [
    GuiDialog::ReviewReplaceCurrentList,
    GuiDialog::ConfirmReplaceCurrentList,
];

const MAIN_WINDOW_SHELL_CONTRACT: MainWindowShellContract = MainWindowShellContract {
    window_title: "NetRuleRouter",
    layout_zones: &MAIN_WINDOW_LAYOUT_ZONES,
    sidebar_sections: &MAIN_WINDOW_SECTIONS,
    shared_shell_sections: &SHARED_SHELL_SECTIONS,
    shared_shell_review_dialogs: &SHARED_SHELL_REVIEW_DIALOGS,
    workspace_note:
        "Main window uses one shell frame for sections and launches review flows as dialogs.",
    apply_cancel_actions_visible: true,
};

const INFORMATION_ARCHITECTURE: InformationArchitecture = InformationArchitecture {
    main_window_sections: &MAIN_WINDOW_SECTIONS,
    tray_only_actions: &TRAY_ONLY_ACTIONS,
};

const TRAY_MENU: TrayMenuModel = TrayMenuModel {
    status_line: "Preview mode: policy changes are not applied in block 2 shell.",
    primary_actions: &TRAY_PRIMARY_ACTIONS,
    quick_actions: &TRAY_QUICK_ACTIONS,
};

const SINGLE_INSTANCE_POLICY: SingleInstancePolicy = SingleInstancePolicy {
    instance_key: "nrr-gui-shell-v1",
    behavior: SecondaryLaunchBehavior::FocusExistingInstanceAndOpenRequestedSection,
    accepted_sources: &ActivationSource::ALL,
};

const SETTINGS_GENERAL_FIELDS: [SettingField; 4] = [
    SettingField {
        id: SettingFieldId::LaunchWindowOnStartup,
        availability: SettingAvailability::Enabled,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::MinimizeToTrayInsteadOfClose,
        availability: SettingAvailability::Enabled,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::ShowNotifications,
        availability: SettingAvailability::Enabled,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::ReopenLastSectionOnStartup,
        availability: SettingAvailability::Enabled,
        ownership: SettingOwnership::UiPreference,
    },
];

const SETTINGS_APPEARANCE_FIELDS: [SettingField; 3] = [
    SettingField {
        id: SettingFieldId::ThemeMode,
        availability: SettingAvailability::Enabled,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::InterfaceDensity,
        availability: SettingAvailability::Enabled,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::UiFontSize,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::UiPreference,
    },
];

const SETTINGS_ACCESSIBILITY_FIELDS: [SettingField; 5] = [
    SettingField {
        id: SettingFieldId::AccessibilityHighContrast,
        availability: SettingAvailability::Enabled,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::AccessibilityUiFontSize,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::AccessibilitySystemFont,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::AccessibilityEnhancedFocusIndicator,
        availability: SettingAvailability::Enabled,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::AccessibilitySimplifiedLabels,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::UiPreference,
    },
];

const SETTINGS_LANGUAGE_FIELDS: [SettingField; 2] = [
    SettingField {
        id: SettingFieldId::InterfaceLanguage,
        availability: SettingAvailability::Enabled,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::TranslationSource,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::UiPreference,
    },
];

const SETTINGS_LOGS_DIAGNOSTICS_FIELDS: [SettingField; 4] = [
    SettingField {
        id: SettingFieldId::UserLogVerbosity,
        availability: SettingAvailability::Enabled,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::OpenLogsFolder,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::ClearLogs,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::EnableExtendedDiagnostics,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::UiPreference,
    },
];

const SETTINGS_ROUTING_BEHAVIOR_FIELDS: [SettingField; 7] = [
    SettingField {
        id: SettingFieldId::DefaultRoutingMode,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::PolicyAffectingPreview,
    },
    SettingField {
        id: SettingFieldId::FailClosedBehavior,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::PolicyAffectingPreview,
    },
    SettingField {
        id: SettingFieldId::WarnWhenSecondaryUnavailable,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::PolicyAffectingPreview,
    },
    SettingField {
        id: SettingFieldId::RulesFileChangeMode,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::PolicyAffectingPreview,
    },
    SettingField {
        id: SettingFieldId::RuleIncludeChildProcesses,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::PolicyAffectingPreview,
    },
    SettingField {
        id: SettingFieldId::ShowOtherOsRules,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::ZonePriorityOverIp,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::UiPreference,
    },
];

const SETTINGS_EXPERIMENTAL_FIELDS: [SettingField; 1] = [SettingField {
    id: SettingFieldId::BrowserStubExperimental,
    availability: SettingAvailability::Preview,
    ownership: SettingOwnership::UiPreference,
}];

const SETTINGS_UPDATES_FIELDS: [SettingField; 3] = [
    SettingField {
        id: SettingFieldId::CheckForUpdates,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::UpdateChannel,
        availability: SettingAvailability::Preview,
        ownership: SettingOwnership::UiPreference,
    },
    SettingField {
        id: SettingFieldId::CurrentVersion,
        availability: SettingAvailability::Enabled,
        ownership: SettingOwnership::UiPreference,
    },
];

const SETTINGS_SECTIONS: [SettingsSection; 8] = [
    SettingsSection {
        id: SettingsSectionId::General,
        fields: &SETTINGS_GENERAL_FIELDS,
    },
    SettingsSection {
        id: SettingsSectionId::Appearance,
        fields: &SETTINGS_APPEARANCE_FIELDS,
    },
    SettingsSection {
        id: SettingsSectionId::Accessibility,
        fields: &SETTINGS_ACCESSIBILITY_FIELDS,
    },
    SettingsSection {
        id: SettingsSectionId::Language,
        fields: &SETTINGS_LANGUAGE_FIELDS,
    },
    SettingsSection {
        id: SettingsSectionId::LogsAndDiagnostics,
        fields: &SETTINGS_LOGS_DIAGNOSTICS_FIELDS,
    },
    SettingsSection {
        id: SettingsSectionId::RoutingBehavior,
        fields: &SETTINGS_ROUTING_BEHAVIOR_FIELDS,
    },
    SettingsSection {
        id: SettingsSectionId::ExperimentalFeatures,
        fields: &SETTINGS_EXPERIMENTAL_FIELDS,
    },
    SettingsSection {
        id: SettingsSectionId::FreeUpdates,
        fields: &SETTINGS_UPDATES_FIELDS,
    },
];

const SETTINGS_CONTRACT: SettingsContract = SettingsContract {
    sections: &SETTINGS_SECTIONS,
    storage_backend_hint:
        "Managed local storage (Qt QSettings / Windows Registry target: HKCU\\Software\\NetRuleRouter\\NetRuleRouter)",
    policy_source_of_truth:
        "Policy-affecting state belongs to service-owned storage and is not sourced from editable user config files.",
};

const ABOUT_CONTRACT: AboutContract = AboutContract {
    product_name: "NetRuleRouter",
    edition: "",
    license: "MPL-2.0",
    project_url: "https://github.com/kroxiksut/net-rule-router",
    build_channel: "development",
};

const SECURITY_VISIBILITY_RULES: [SecurityVisibilityRule; 6] = [
    SecurityVisibilityRule {
        indicator: SecurityIndicatorId::ActiveRevision,
        scope: VisibilityScope::AlwaysVisible,
    },
    SecurityVisibilityRule {
        indicator: SecurityIndicatorId::PendingChanges,
        scope: VisibilityScope::AlwaysVisible,
    },
    SecurityVisibilityRule {
        indicator: SecurityIndicatorId::TamperAlerts,
        scope: VisibilityScope::AlwaysVisible,
    },
    SecurityVisibilityRule {
        indicator: SecurityIndicatorId::RollbackState,
        scope: VisibilityScope::AlwaysVisible,
    },
    SecurityVisibilityRule {
        indicator: SecurityIndicatorId::ServiceStatus,
        scope: VisibilityScope::AlwaysVisible,
    },
    SecurityVisibilityRule {
        indicator: SecurityIndicatorId::ExplainWarnings,
        scope: VisibilityScope::ScreenOnly,
    },
];

const SECURITY_VISIBILITY_CONTRACT: SecurityVisibilityContract = SecurityVisibilityContract {
    rules: &SECURITY_VISIBILITY_RULES,
};

const TOOLTIP_POLICY_CONTRACT: TooltipPolicyContract = TooltipPolicyContract {
    enabled_by_default: true,
    supplemental_only: true,
};

const ACCESSIBILITY_REQUIREMENTS: [AccessibilityRequirement; 7] = [
    AccessibilityRequirement {
        id: AccessibilityRequirementId::AccessibleMetadata,
        mandatory: true,
    },
    AccessibilityRequirement {
        id: AccessibilityRequirementId::KeyboardFirstNavigation,
        mandatory: true,
    },
    AccessibilityRequirement {
        id: AccessibilityRequirementId::VisibleFocusIndicator,
        mandatory: true,
    },
    AccessibilityRequirement {
        id: AccessibilityRequirementId::ScalableText,
        mandatory: true,
    },
    AccessibilityRequirement {
        id: AccessibilityRequirementId::SystemFontSelection,
        mandatory: true,
    },
    AccessibilityRequirement {
        id: AccessibilityRequirementId::DedicatedHighContrastTheme,
        mandatory: true,
    },
    AccessibilityRequirement {
        id: AccessibilityRequirementId::TooltipsAreSupplementalOnly,
        mandatory: true,
    },
];

const ACCESSIBILITY_BASELINE_CONTRACT: AccessibilityBaselineContract =
    AccessibilityBaselineContract {
        requirements: &ACCESSIBILITY_REQUIREMENTS,
    };

const MAIN_WINDOW_FIELDS: [&str; 7] = [
    "Sidebar sections",
    "Active list title",
    "Status block",
    "Section workspace",
    "Apply action",
    "Cancel action",
    "Close action",
];

const FIRST_RUN_WIZARD_FIELDS: [&str; 8] = [
    "Welcome",
    "Interfaces selection",
    "Default mode selection",
    "Summary",
    "Back action",
    "Next action",
    "Finish action",
    "Keyboard step navigation",
];

const INTERFACES_AND_ROUTES_FIELDS: [&str; 15] = [
    "Interfaces table",
    "Name column",
    "Type column",
    "IP column",
    "Gateway column",
    "DNS column",
    "Default route column",
    "Status column",
    "Connectivity state column",
    "External IP status column",
    "External IP value column",
    "VPN/tunnel likelihood indicator",
    "Virtual interface likelihood indicator",
    "Service interface likelihood indicator",
    "Primary/secondary assignment controls",
];

const RULES_SCREEN_FIELDS: [&str; 10] = [
    "Rules list",
    "Search row",
    "Type filter",
    "Rule edit form",
    "Add action",
    "Edit action",
    "Delete action",
    "Reorder action",
    "Import action",
    "Export action",
];

const LOAD_LIST_DIALOG_FIELDS: [&str; 8] = [
    "File path",
    "Browse action",
    "Format",
    "Schema version",
    "Summary",
    "Replace current list flag",
    "Load action",
    "Cancel action",
];

const EDIT_LIST_DIALOG_FIELDS: [&str; 8] = [
    "List name",
    "Description",
    "Default mode",
    "Rules table",
    "Rules ordering controls",
    "Save action",
    "Cancel action",
    "Reset changes action",
];

const EDIT_RULE_DIALOG_FIELDS: [&str; 6] = [
    "Rule type",
    "Rule value",
    "Target route",
    "Comment",
    "Enabled toggle",
    "Save/cancel actions",
];

const RULE_REPLACE_REVIEW_DIALOG_FIELDS: [&str; 7] = [
    "Incoming list summary",
    "Current list summary",
    "Rules count delta",
    "Default mode comparison",
    "Rule types comparison",
    "Replace action",
    "Cancel action",
];

const DIAGNOSTICS_SCREEN_FIELDS: [&str; 6] = [
    "Selected interfaces",
    "Service status",
    "Explain sample output",
    "Test data zone",
    "Refresh action",
    "Screen-reader status narration",
];

const LOGS_SCREEN_FIELDS: [&str; 8] = [
    "Time column",
    "Level column",
    "Source column",
    "Message column",
    "Filters",
    "Refresh action",
    "Clear action",
    "Export action",
];

const ABOUT_WINDOW_FIELDS: [&str; 8] = [
    "Application icon",
    "Product name",
    "Version",
    "Edition",
    "License",
    "Build info",
    "Project and third-party links",
    "OK action",
];

const CONFIRMATION_DIALOG_FIELDS: [&str; 5] = [
    "Replace current list confirmation",
    "Discard unsaved changes confirmation",
    "Clear logs confirmation",
    "Rollback confirmation",
    "Disable product impact confirmation",
];

const UI_SURFACE_SPECS: [UiSurfaceSpec; 12] = [
    UiSurfaceSpec {
        id: UiSurfaceId::MainWindow,
        fields: &MAIN_WINDOW_FIELDS,
    },
    UiSurfaceSpec {
        id: UiSurfaceId::FirstRunWizard,
        fields: &FIRST_RUN_WIZARD_FIELDS,
    },
    UiSurfaceSpec {
        id: UiSurfaceId::InterfacesAndRoutesScreen,
        fields: &INTERFACES_AND_ROUTES_FIELDS,
    },
    UiSurfaceSpec {
        id: UiSurfaceId::RulesScreen,
        fields: &RULES_SCREEN_FIELDS,
    },
    UiSurfaceSpec {
        id: UiSurfaceId::LoadListDialog,
        fields: &LOAD_LIST_DIALOG_FIELDS,
    },
    UiSurfaceSpec {
        id: UiSurfaceId::EditListDialog,
        fields: &EDIT_LIST_DIALOG_FIELDS,
    },
    UiSurfaceSpec {
        id: UiSurfaceId::EditRuleDialog,
        fields: &EDIT_RULE_DIALOG_FIELDS,
    },
    UiSurfaceSpec {
        id: UiSurfaceId::RuleReplaceReviewDialog,
        fields: &RULE_REPLACE_REVIEW_DIALOG_FIELDS,
    },
    UiSurfaceSpec {
        id: UiSurfaceId::DiagnosticsScreen,
        fields: &DIAGNOSTICS_SCREEN_FIELDS,
    },
    UiSurfaceSpec {
        id: UiSurfaceId::LogsScreen,
        fields: &LOGS_SCREEN_FIELDS,
    },
    UiSurfaceSpec {
        id: UiSurfaceId::AboutWindow,
        fields: &ABOUT_WINDOW_FIELDS,
    },
    UiSurfaceSpec {
        id: UiSurfaceId::ConfirmationDialogs,
        fields: &CONFIRMATION_DIALOG_FIELDS,
    },
];

const UI_SURFACE_CONTRACT: UiSurfaceContract = UiSurfaceContract {
    surfaces: &UI_SURFACE_SPECS,
};

const INTERFACE_FIELD_READINESS: [InterfaceFieldReadiness; 7] = [
    InterfaceFieldReadiness {
        field: InterfaceFieldId::WindowsName,
        readiness: DataReadiness::RealInBlock2,
    },
    InterfaceFieldReadiness {
        field: InterfaceFieldId::InterfaceType,
        readiness: DataReadiness::RealInBlock2,
    },
    InterfaceFieldReadiness {
        field: InterfaceFieldId::LocalIp,
        readiness: DataReadiness::RealInBlock2,
    },
    InterfaceFieldReadiness {
        field: InterfaceFieldId::Gateway,
        readiness: DataReadiness::RealInBlock2,
    },
    InterfaceFieldReadiness {
        field: InterfaceFieldId::DnsServers,
        readiness: DataReadiness::RealInBlock2,
    },
    InterfaceFieldReadiness {
        field: InterfaceFieldId::HasDefaultRoute,
        readiness: DataReadiness::RealInBlock2,
    },
    InterfaceFieldReadiness {
        field: InterfaceFieldId::BasicAvailabilityStatus,
        readiness: DataReadiness::PlaceholderUntilBlock5,
    },
];

const INTERFACE_FIELD_SNAPSHOT_STATUS: [InterfaceFieldSnapshotStatus; 7] = [
    InterfaceFieldSnapshotStatus {
        field: InterfaceFieldId::WindowsName,
        availability: SnapshotValueAvailability::AlwaysPresentFromSnapshot,
    },
    InterfaceFieldSnapshotStatus {
        field: InterfaceFieldId::InterfaceType,
        availability: SnapshotValueAvailability::AlwaysPresentFromSnapshot,
    },
    InterfaceFieldSnapshotStatus {
        field: InterfaceFieldId::LocalIp,
        availability: SnapshotValueAvailability::MayBeUnknownFromSnapshot,
    },
    InterfaceFieldSnapshotStatus {
        field: InterfaceFieldId::Gateway,
        availability: SnapshotValueAvailability::MayBeUnknownFromSnapshot,
    },
    InterfaceFieldSnapshotStatus {
        field: InterfaceFieldId::DnsServers,
        availability: SnapshotValueAvailability::MayBeUnknownFromSnapshot,
    },
    InterfaceFieldSnapshotStatus {
        field: InterfaceFieldId::HasDefaultRoute,
        availability: SnapshotValueAvailability::AlwaysPresentFromSnapshot,
    },
    InterfaceFieldSnapshotStatus {
        field: InterfaceFieldId::BasicAvailabilityStatus,
        availability: SnapshotValueAvailability::AlwaysPresentFromSnapshot,
    },
];

const INTERFACE_FIELD_USAGE_SCOPES: [InterfaceFieldUsage; 7] = [
    InterfaceFieldUsage {
        field: InterfaceFieldId::WindowsName,
        scope: InterfaceFieldUsageScope::DiagnosticsContract,
    },
    InterfaceFieldUsage {
        field: InterfaceFieldId::InterfaceType,
        scope: InterfaceFieldUsageScope::DiagnosticsContract,
    },
    InterfaceFieldUsage {
        field: InterfaceFieldId::LocalIp,
        scope: InterfaceFieldUsageScope::DiagnosticsContract,
    },
    InterfaceFieldUsage {
        field: InterfaceFieldId::Gateway,
        scope: InterfaceFieldUsageScope::DecisionInput,
    },
    InterfaceFieldUsage {
        field: InterfaceFieldId::DnsServers,
        scope: InterfaceFieldUsageScope::UiOnly,
    },
    InterfaceFieldUsage {
        field: InterfaceFieldId::HasDefaultRoute,
        scope: InterfaceFieldUsageScope::DecisionInput,
    },
    InterfaceFieldUsage {
        field: InterfaceFieldId::BasicAvailabilityStatus,
        scope: InterfaceFieldUsageScope::DecisionInput,
    },
];

const INTERFACE_DISPLAY_ORDERED_FIELDS: [InterfaceFieldId; 7] = [
    InterfaceFieldId::WindowsName,
    InterfaceFieldId::InterfaceType,
    InterfaceFieldId::LocalIp,
    InterfaceFieldId::Gateway,
    InterfaceFieldId::DnsServers,
    InterfaceFieldId::HasDefaultRoute,
    InterfaceFieldId::BasicAvailabilityStatus,
];

const INTERFACES_DISPLAY_FORMAT: InterfacesDisplayFormat = InterfacesDisplayFormat {
    ordered_fields: &INTERFACE_DISPLAY_ORDERED_FIELDS,
    unknown_value_marker: "-",
    dns_separator: ", ",
};

const ENRICHED_INTERFACE_FIELDS: [&str; 5] = [
    "connectivity_state",
    "external_ip_status",
    "vpn_tunnel_likelihood",
    "virtual_interface_likelihood",
    "service_interface_likelihood",
];

const CONNECTIVITY_STATES: [ConnectivityState; 5] = [
    ConnectivityState::Available,
    ConnectivityState::Degraded,
    ConnectivityState::Unavailable,
    ConnectivityState::Unknown,
    ConnectivityState::Timeout,
];

const EXTERNAL_IP_STATUSES: [ExternalIpStatus; 5] = [
    ExternalIpStatus::Resolved,
    ExternalIpStatus::NotChecked,
    ExternalIpStatus::CheckFailed,
    ExternalIpStatus::RateLimited,
    ExternalIpStatus::Blocked,
];

const DERIVED_LIKELIHOOD_SCALE: [DerivedLikelihood; 4] = [
    DerivedLikelihood::Likely,
    DerivedLikelihood::Possible,
    DerivedLikelihood::Unlikely,
    DerivedLikelihood::Unknown,
];

const RECOMMENDATION_CLASSES: [RecommendationClass; 4] = [
    RecommendationClass::PreferredPrimary,
    RecommendationClass::PreferredSecondary,
    RecommendationClass::AllowedButNotRecommended,
    RecommendationClass::NotRecommended,
];

const RECOMMENDATION_CONFIDENCE_LEVELS: [RecommendationConfidence; 4] = [
    RecommendationConfidence::High,
    RecommendationConfidence::Medium,
    RecommendationConfidence::Low,
    RecommendationConfidence::Unknown,
];

const CONNECTIVITY_CHECKS_POLICY: ConnectivityChecksPolicy = ConnectivityChecksPolicy {
    local_checks_without_network_probe: true,
    external_probe_allowed: true,
    probe_timeout_ms: 3000,
    max_probe_retries: 1,
    min_refresh_interval_seconds: 30,
    offline_mode_behavior: "degrade-to-local-observations-without-infinite-retry",
};

const VPN_TUNNEL_SIGNALS: [&str; 6] = [
    "interface_type_contains_tunnel_or_ppp",
    "windows_name_contains_vpn_or_wireguard_or_tunnel",
    "description_contains_tunnel_or_virtual_private",
    "no_default_gateway_but_adapter_up",
    "private_or_linklocal_only_addressing",
    "adapter_name_contains_tap_tun_wg",
];

const VIRTUAL_INTERFACE_SIGNALS: [&str; 6] = [
    "interface_type_is_loopback_or_tunnel",
    "windows_name_contains_virtual_vmware_vbox_hyperv",
    "description_contains_virtual_or_host_only",
    "missing_physical_address",
    "host_only_or_internal_address_pattern",
    "no_external_connectivity_with_local_link_up",
];

const SERVICE_INTERFACE_SIGNALS: [&str; 6] = [
    "windows_name_contains_loopback",
    "description_contains_pseudo_or_isatap_or_teredo",
    "interface_type_is_loopback",
    "reserved_or_internal_adapter_name_pattern",
    "missing_gateway_and_no_dns",
    "high_likelihood_virtual_and_unavailable_connectivity",
];

const RECOMMENDATION_TIE_BREAK_PRIORITY: [&str; 5] = [
    "manual_pin_or_user_choice",
    "stable_identity_persistent_id",
    "last_confirmed_choice",
    "connectivity_score",
    "has_default_route",
];

const RECOMMENDATION_HINTS_CATALOG: [&str; 5] = [
    "home-wifi: usually preferred-primary when external connectivity is available and no strong tunnel markers are present.",
    "ethernet: often preferred-primary when default route and stable connectivity are present.",
    "wireguard-openvpn: usually preferred-secondary unless explicitly selected as primary by user.",
    "corporate-tunnel: can be preferred-secondary when connectivity is available and service-only markers are absent.",
    "virtual-host-only: usually not-recommended for routing roles.",
];

const SECONDARY_ROLE_UX_WARNINGS: [&str; 3] = [
    "no-suitable-secondary-found",
    "secondary-looks-unstable-or-not-recommended",
    "primary-and-secondary-cannot-point-to-same-adapter",
];

const BLUETOOTH_DETECTION_SIGNALS: [&str; 4] = [
    "windows_name_contains_bluetooth",
    "interface_description_contains_bluetooth",
    "adapter_name_contains_bluetooth",
    "pan_marker_in_name_or_description",
];

const ADAPTER_CHECK_ACTIONS: [AdapterCheckActionContract; 3] = [
    AdapterCheckActionContract {
        id: AdapterCheckActionId::CheckRoute,
        scope: AdapterCheckExecutionScope::ReadOnlyDiagnostics,
        description: "Validate whether route-related fields for this adapter look usable.",
    },
    AdapterCheckActionContract {
        id: AdapterCheckActionId::ShowExternalIp,
        scope: AdapterCheckExecutionScope::ReadOnlyDiagnostics,
        description: "Show external IP status/value from latest probe or local fallback.",
    },
    AdapterCheckActionContract {
        id: AdapterCheckActionId::CheckInternetAvailability,
        scope: AdapterCheckExecutionScope::ReadOnlyDiagnostics,
        description: "Estimate whether internet is reachable via this adapter.",
    },
];

const ADAPTER_CHECK_RESULT_STATUSES: [AdapterCheckResultStatus; 4] = [
    AdapterCheckResultStatus::Success,
    AdapterCheckResultStatus::Degraded,
    AdapterCheckResultStatus::Unavailable,
    AdapterCheckResultStatus::Timeout,
];

const SUPPORTED_ROUTE_BEHAVIOR_MODES: [RouteBehaviorMode; 3] = [
    RouteBehaviorMode::PreferPrimary,
    RouteBehaviorMode::PreferSecondaryWhenAvailable,
    RouteBehaviorMode::StrictSecondaryFailClosed,
];

const ROUTE_STATE_PLACEHOLDERS: [RouteSelectionState; 5] = [
    RouteSelectionState::Selected,
    RouteSelectionState::NotSelected,
    RouteSelectionState::Unavailable,
    RouteSelectionState::RequiresVerification,
    RouteSelectionState::FailClosedConflict,
];

const INTERFACES_ROUTES_CONTRACT: InterfacesRoutesContract = InterfacesRoutesContract {
    field_readiness: &INTERFACE_FIELD_READINESS,
    field_snapshot_status: &INTERFACE_FIELD_SNAPSHOT_STATUS,
    field_usage_scopes: &INTERFACE_FIELD_USAGE_SCOPES,
    display_format: INTERFACES_DISPLAY_FORMAT,
    enriched_fields: &ENRICHED_INTERFACE_FIELDS,
    connectivity_states: &CONNECTIVITY_STATES,
    external_ip_statuses: &EXTERNAL_IP_STATUSES,
    derived_likelihood_scale: &DERIVED_LIKELIHOOD_SCALE,
    recommendation_classes: &RECOMMENDATION_CLASSES,
    recommendation_confidence_levels: &RECOMMENDATION_CONFIDENCE_LEVELS,
    connectivity_checks_policy: CONNECTIVITY_CHECKS_POLICY,
    observed_vs_derived_boundary:
        "observed_facts store measured adapter/runtime values; derived_assessment stores heuristic classification and confidence.",
    vpn_tunnel_signals: &VPN_TUNNEL_SIGNALS,
    virtual_interface_signals: &VIRTUAL_INTERFACE_SIGNALS,
    service_interface_signals: &SERVICE_INTERFACE_SIGNALS,
    derived_cache_policy:
        "cache derived flags in snapshot for UI consistency; recompute on each manual/periodic refresh.",
    recommendation_tie_break_priority: &RECOMMENDATION_TIE_BREAK_PRIORITY,
    recommendation_advisory_policy:
        "recommendation engine is advisory-only: it never auto-assigns primary/secondary and never overrides explicit user choice.",
    recommendation_hints_catalog: &RECOMMENDATION_HINTS_CATALOG,
    manual_role_confirmation_required: true,
    role_conflict_policy:
        "One adapter cannot be confirmed as both primary and secondary in default product mode.",
    confirmed_choice_priority_policy:
        "User-confirmed role selection has priority over heuristic recommendation.",
    secondary_role_ux_warnings: &SECONDARY_ROLE_UX_WARNINGS,
    show_bluetooth_adapters_default: false,
    bluetooth_detection_signals: &BLUETOOTH_DETECTION_SIGNALS,
    bluetooth_recommendation_policy:
        "Bluetooth adapters are hidden by default and treated as allowed-but-not-recommended when shown.",
    adapter_check_actions: &ADAPTER_CHECK_ACTIONS,
    adapter_check_result_statuses: &ADAPTER_CHECK_RESULT_STATUSES,
    diagnostics_explain_integration_note:
        "Adapter check results are computed in core and reused by diagnostics/explain surfaces without GUI-side duplication.",
    supported_behavior_modes: &SUPPORTED_ROUTE_BEHAVIOR_MODES,
    route_state_placeholders: &ROUTE_STATE_PLACEHOLDERS,
    preview_only_selection: true,
    preview_notice:
        "In block 2 this screen is preview/setup only: selecting interfaces does not apply routing policy.",
    role_explanation:
        "Primary route is the default preferred interface; secondary route is the fallback interface.",
    diagnostics_alignment_note:
        "Adapter field labels and unknown-value marker are shared across GUI, diagnostics, and explain payloads.",
};

const SUPPORTED_FREE_RULE_TYPES: [FreeRuleType; 4] = [
    FreeRuleType::Application,
    FreeRuleType::Domain,
    FreeRuleType::Zone,
    FreeRuleType::ExactIp,
];

const RULE_PLACEHOLDER_SCENARIOS: [RuleScenario; 5] = [
    RuleScenario::Create,
    RuleScenario::Edit,
    RuleScenario::Delete,
    RuleScenario::Reorder,
    RuleScenario::Search,
];

const RULE_FORM_FIELDS: [RuleFormFieldSpec; 5] = [
    RuleFormFieldSpec {
        id: RuleFormFieldId::RuleType,
        required: true,
        constraint_hint:
            "Select one supported Free type: application, domain (includes all subdomains), exact IP.",
        visible_in_gui_v1: true,
    },
    RuleFormFieldSpec {
        id: RuleFormFieldId::MatchValue,
        required: true,
        constraint_hint:
            "1..255 chars; domain rules match the label and all subdomains automatically.",
        visible_in_gui_v1: true,
    },
    RuleFormFieldSpec {
        id: RuleFormFieldId::TargetRoute,
        required: true,
        constraint_hint:
            "Select the route set: Primary or Secondary. Determines which rule file the rule is written to.",
        visible_in_gui_v1: true,
    },
    RuleFormFieldSpec {
        id: RuleFormFieldId::Enabled,
        required: false,
        constraint_hint: "Boolean toggle, enabled by default for new rule.",
        visible_in_gui_v1: true,
    },
    RuleFormFieldSpec {
        id: RuleFormFieldId::Comment,
        required: false,
        constraint_hint: "Optional note up to 256 chars.",
        visible_in_gui_v1: true,
    },
];

const FREE_RULE_LIST_TYPES: [FreeRuleListType; 2] = [
    FreeRuleListType::SingleActiveManagedList,
    FreeRuleListType::ImportedPresetReplacingActiveList,
];

const RULE_LIST_LOAD_DIALOG_FIELDS: [RuleListLoadFieldId; 7] = [
    RuleListLoadFieldId::FilePath,
    RuleListLoadFieldId::Format,
    RuleListLoadFieldId::SchemaVersion,
    RuleListLoadFieldId::ParsedSummary,
    RuleListLoadFieldId::ReplaceCurrentList,
    RuleListLoadFieldId::LoadAction,
    RuleListLoadFieldId::CancelAction,
];

const RULE_LIST_EDIT_DIALOG_FIELDS: [RuleListEditFieldId; 7] = [
    RuleListEditFieldId::ListName,
    RuleListEditFieldId::Description,
    RuleListEditFieldId::RulesSet,
    RuleListEditFieldId::RulesOrder,
    RuleListEditFieldId::DefaultMode,
    RuleListEditFieldId::SaveAction,
    RuleListEditFieldId::CancelAction,
];

const RULE_REPLACE_REVIEW_FIELDS: [RuleReplaceReviewFieldId; 7] = [
    RuleReplaceReviewFieldId::IncomingListName,
    RuleReplaceReviewFieldId::IncomingRulesCount,
    RuleReplaceReviewFieldId::CurrentRulesCount,
    RuleReplaceReviewFieldId::DefaultModeDiff,
    RuleReplaceReviewFieldId::NewTypesSummary,
    RuleReplaceReviewFieldId::ReplaceAction,
    RuleReplaceReviewFieldId::CancelAction,
];

const RULES_VIEW_SORT_MODES: [RulesViewSort; 4] = [
    RulesViewSort::ByDisplayOrder,
    RulesViewSort::ByMatchValue,
    RulesViewSort::ByType,
    RulesViewSort::ByRoute,
];

const RULES_ENABLED_FILTERS: [RulesEnabledFilter; 3] = [
    RulesEnabledFilter::All,
    RulesEnabledFilter::EnabledOnly,
    RulesEnabledFilter::DisabledOnly,
];

const RULES_TYPE_FILTERS: [RulesTypeFilter; 8] = [
    RulesTypeFilter::All,
    RulesTypeFilter::Zones,
    RulesTypeFilter::Domain,
    RulesTypeFilter::ExactIp,
    RulesTypeFilter::Application,
    RulesTypeFilter::Windows,
    RulesTypeFilter::Linux,
    RulesTypeFilter::MacOS,
];

const RULES_OTHER_OS_TYPE_FILTERS: [RulesTypeFilter; 2] =
    [RulesTypeFilter::Linux, RulesTypeFilter::MacOS];

const RULES_DUPLICATE_RESOLUTIONS: [RulesDuplicateResolution; 3] = [
    RulesDuplicateResolution::KeepInPrimary,
    RulesDuplicateResolution::KeepInSecondary,
    RulesDuplicateResolution::KeepInBoth,
];

const RULES_FILE_CHANGE_BEHAVIORS: [RulesFileChangeBehavior; 2] = RulesFileChangeBehavior::ALL;

const RULES_CONTRACT: RulesContract = RulesContract {
    supported_free_rule_types: &SUPPORTED_FREE_RULE_TYPES,
    placeholder_scenarios: &RULE_PLACEHOLDER_SCENARIOS,
    form_fields: &RULE_FORM_FIELDS,
    supported_free_list_types: &FREE_RULE_LIST_TYPES,
    load_list_dialog_fields: &RULE_LIST_LOAD_DIALOG_FIELDS,
    edit_list_dialog_fields: &RULE_LIST_EDIT_DIALOG_FIELDS,
    replace_review_dialog_fields: &RULE_REPLACE_REVIEW_FIELDS,
    load_list_requires_review_before_replace: true,
    preview_notice:
        "In block 2 this screen is UI preview only: rule editing scenarios are placeholders until backend validation and policy apply are connected.",
    supported_sort_modes: &RULES_VIEW_SORT_MODES,
    supported_enabled_filters: &RULES_ENABLED_FILTERS,
    supported_type_filters: &RULES_TYPE_FILTERS,
    other_os_type_filters: &RULES_OTHER_OS_TYPE_FILTERS,
    supported_duplicate_resolutions: &RULES_DUPLICATE_RESOLUTIONS,
    block_secondary_when_unavailable_default: false,
    supported_file_change_behaviors: &RULES_FILE_CHANGE_BEHAVIORS,
    default_file_change_behavior: RulesFileChangeBehavior::Notify,
    supports_rule_enable_toggle: true,
    supports_rule_comments: true,
    new_rule_enabled_default: true,
};

const FIRST_RUN_STEPS: [FirstRunStepSpec; 6] = [
    FirstRunStepSpec {
        id: FirstRunStepId::Welcome,
        required: true,
    },
    FirstRunStepSpec {
        id: FirstRunStepId::BasicScenarioSelection,
        required: true,
    },
    FirstRunStepSpec {
        id: FirstRunStepId::RoutesSetup,
        required: true,
    },
    FirstRunStepSpec {
        id: FirstRunStepId::RulesSetup,
        required: true,
    },
    FirstRunStepSpec {
        id: FirstRunStepId::DiagnosticsPreview,
        required: true,
    },
    FirstRunStepSpec {
        id: FirstRunStepId::Finish,
        required: true,
    },
];

const FIRST_RUN_SCENARIOS: [FirstRunScenarioId; 2] = [
    FirstRunScenarioId::QuickStart,
    FirstRunScenarioId::GuidedDefault,
];

const QUICK_START_PATH: [AppSection; 3] = [
    AppSection::InterfacesAndRoutes,
    AppSection::Rules,
    AppSection::Diagnostics,
];

const STARTUP_STATES: [SectionStartupState; 4] = [
    SectionStartupState {
        section: AppSection::InterfacesAndRoutes,
        state: StartupDataState::SemiEmpty,
        note: "Interfaces are visible; primary/secondary candidates are not selected yet.",
    },
    SectionStartupState {
        section: AppSection::Rules,
        state: StartupDataState::Empty,
        note: "Rules list starts empty before first import or manual creation.",
    },
    SectionStartupState {
        section: AppSection::Diagnostics,
        state: StartupDataState::SemiEmpty,
        note: "Diagnostics starts with minimal placeholders until user runs checks.",
    },
    SectionStartupState {
        section: AppSection::Logs,
        state: StartupDataState::Empty,
        note: "Logs table can be empty on first launch before events are generated.",
    },
];

const FIRST_RUN_ACTION_GATES: [SetupActionGate; 9] = [
    SetupActionGate {
        action: AppAction::OpenSection(AppSection::InterfacesAndRoutes),
        before_completion: SetupActionAvailability::Allowed,
    },
    SetupActionGate {
        action: AppAction::OpenSection(AppSection::Rules),
        before_completion: SetupActionAvailability::SoftGuided,
    },
    SetupActionGate {
        action: AppAction::OpenSection(AppSection::Diagnostics),
        before_completion: SetupActionAvailability::SoftGuided,
    },
    SetupActionGate {
        action: AppAction::LoadRuleList,
        before_completion: SetupActionAvailability::SoftGuided,
    },
    SetupActionGate {
        action: AppAction::UpdateRulesFromFile,
        before_completion: SetupActionAvailability::SoftGuided,
    },
    SetupActionGate {
        action: AppAction::ImportPreset,
        before_completion: SetupActionAvailability::SoftGuided,
    },
    SetupActionGate {
        action: AppAction::ExportCurrentRuleList,
        before_completion: SetupActionAvailability::BlockedUntilWizardCompletion,
    },
    SetupActionGate {
        action: AppAction::SafeRollback,
        before_completion: SetupActionAvailability::BlockedUntilWizardCompletion,
    },
    SetupActionGate {
        action: AppAction::TemporarilyDisableProductImpact,
        before_completion: SetupActionAvailability::BlockedUntilWizardCompletion,
    },
];

const FIRST_RUN_CONTRACT: FirstRunContract = FirstRunContract {
    steps: &FIRST_RUN_STEPS,
    scenarios: &FIRST_RUN_SCENARIOS,
    default_scenario: FirstRunScenarioId::QuickStart,
    quick_start_path_sections: &QUICK_START_PATH,
    startup_states: &STARTUP_STATES,
    action_gates_before_completion: &FIRST_RUN_ACTION_GATES,
    list_editing_preview_notice:
        "Opening or editing a list in first-run is preview/setup only and does not mean service policy was applied.",
    completion_notice:
        "First-run completion opens interfaces/routes first; rule and diagnostics screens stay immediately available from sidebar.",
};

pub const fn gui_shell_v1() -> AppShellModel {
    AppShellModel {
        information_architecture: INFORMATION_ARCHITECTURE,
        navigation: NAVIGATION_MODEL,
        main_window_shell: MAIN_WINDOW_SHELL_CONTRACT,
        first_run: FIRST_RUN_CONTRACT,
        windows: &WINDOWS,
        dialogs: &DIALOGS,
        menu_bar: &MENU_BAR,
        tray_menu: TRAY_MENU,
        single_instance: SINGLE_INSTANCE_POLICY,
        settings: SETTINGS_CONTRACT,
        about: ABOUT_CONTRACT,
        security_visibility: SECURITY_VISIBILITY_CONTRACT,
        tooltip_policy: TOOLTIP_POLICY_CONTRACT,
        accessibility_baseline: ACCESSIBILITY_BASELINE_CONTRACT,
        ui_surface_contract: UI_SURFACE_CONTRACT,
        interfaces_routes: INTERFACES_ROUTES_CONTRACT,
        rules: RULES_CONTRACT,
    }
}
