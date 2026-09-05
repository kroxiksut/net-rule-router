use core::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The line a runtime prints when it comes up, and the one naming what that
/// runtime is responsible for.
///
/// They live here, in the contracts crate every runtime already depends on,
/// because the background service needed exactly these two strings and nothing
/// else from `nrr-application` — and that one unused-in-practice dependency was
/// enough to link 5423 lines of UI and preview code into a service running as
/// LocalSystem. A shared string does not justify a shared dependency edge.
pub fn runtime_boot_banner(component: &str) -> String {
    format!(
        "{} {component} starting",
        crate::product_identity::PRODUCT_NAME
    )
}

/// What this process does — printed under the banner. The service carries the
/// routing engine, enforcement and the kill switch, so the old wording
/// ("starts without routing business logic") was a statement about the code
/// that stopped being true long ago; a boot line that lies is worse than none.
pub fn runtime_boot_role_message(component: &str) -> String {
    match component {
        "service" => "Applies and enforces the routing policy.".to_string(),
        _ => "Presents the routing policy; the background service enforces it.".to_string(),
    }
}

/// A short string identifying the shape of the wire contracts this build
/// speaks: crate version plus the two schema numbers that gate decoding.
///
/// Anything that persists decoded payloads (the GUI's snapshot cache) stores it
/// alongside the data and refuses what does not match. A hand-maintained
/// "cache schema version" was the alternative, and it is the kind of number
/// that is only ever bumped after the bug: nothing forces it to move when a DTO
/// gains a field.
pub fn contract_fingerprint() -> String {
    format!(
        "{}/rules-{}",
        env!("CARGO_PKG_VERSION"),
        rules_json::RULES_JSON_SCHEMA_VERSION
    )
}

pub mod app_identity;
pub mod auto_rule;
pub mod diagnostics_dto;
pub mod eula;
pub mod ipc;
pub mod ipc_dto;
pub mod ipc_flow;
pub mod ipc_payloads;
pub mod ipc_readiness;
pub mod ipc_transport;
pub mod ipc_wire;
pub mod launcher_rpc;
pub mod localization;
pub mod merge_dto;
pub mod pagination;
pub mod platform_profile;
pub mod preset_parser;
pub mod product_identity;
pub mod rules_json;
pub mod rules_overlap;
pub mod settings_export;
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
    load_locale_state, resolve_catalog_text, translate_or, LocaleDescriptor, LocaleLoadReport,
    LocaleLoadState, LocaleLoadStatus, LocaleSource, LOCALE_SCHEMA_PATH, LOCALE_SCHEMA_VERSION,
};
pub use settings_export::SettingsExportV1;

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
pub struct MainWindowShellContract {
    pub window_title: &'static str,
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
    /// Rights holder named by the licence agreement, spelled as the English
    /// text spells it; the UI renders it through `label.author-name`, so each
    /// locale can carry its own spelling of the same person.
    pub author: &'static str,
    pub author_email: &'static str,
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
/// Named routes beyond `Primary` and `Secondary` may be added later.
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
    /// IP-subnet zones remain unsupported. The rule engine evaluates
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

/// How long work the service has not seen yet stays parked.
///
/// One window for both parks — the rules marker in the GUI's sidecar and the
/// routing-settings intents in preferences. They record the same fact, so a
/// month-old "block everything" must not land on the next connect while rules
/// parked in the same session have long since lapsed.
pub const PARKED_INTENT_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

/// Key carrying the parking timestamp inside a parked-intents blob.
pub const PARKED_AT_MS_KEY: &str = "parked-at-ms";

/// Whether a parked-intents blob is past [`PARKED_INTENT_TTL_SECONDS`].
///
/// A blob without the stamp counts as fresh: it was written before the stamp
/// existed, and discarding a user's work over a format detail is worse than
/// carrying it one session longer — the next write stamps it.
pub fn parked_intents_expired(raw: &str, now_ms: i64) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return false;
    };
    let Some(parked_at) = value
        .get(PARKED_AT_MS_KEY)
        .and_then(serde_json::Value::as_i64)
    else {
        return false;
    };
    now_ms.saturating_sub(parked_at) > PARKED_INTENT_TTL_SECONDS.saturating_mul(1000)
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

const MAIN_WINDOW_SHELL_CONTRACT: MainWindowShellContract = MainWindowShellContract {
    window_title: crate::product_identity::PRODUCT_NAME,
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
    product_name: crate::product_identity::PRODUCT_NAME,
    edition: "",
    license: "MPL-2.0",
    project_url: "https://github.com/kroxiksut/net-rule-router",
    build_channel: "development",
    author: "Fyodor Malkov (kroxiksut)",
    author_email: "fmalkov91@gmail.com",
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
    }
}
