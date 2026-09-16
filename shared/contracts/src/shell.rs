//! The shell vocabulary: sections, actions, menus, windows and dialogs, plus
//! the surface identifiers the GUI and the tray both name.
//!
//! Types only. The tables that assemble them into one model live in
//! [`crate::shell_model`], so a reader after "what is a section" is not made
//! to scroll through the section list itself.

use super::*;

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
