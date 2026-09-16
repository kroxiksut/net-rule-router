//! The constant tables `gui_shell_v1()` assembles, and that function.
//!
//! Data, not types — the types are in [`crate::shell`]. Keeping the two apart
//! is what lets the vocabulary be read without the inventory, and the
//! inventory be edited without touching the vocabulary.

use super::*;

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
