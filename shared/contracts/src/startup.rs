//! Log level, validation status, first-run steps and the gates that decide
//! what a not-yet-configured install may do.

use super::*;

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
