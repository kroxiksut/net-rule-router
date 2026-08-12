use crate::first_run::setup_action_availability;
use nrr_shared::{
    AppAction, AppShellModel, MenuAvailability, MenuItem, SetupActionAvailability, ThemeMode,
};
use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayStatusKind {
    PreviewMode,
    /// Nothing is known about enforcement yet — the tray has just started and
    /// has not heard from the service. Replaced by the tray's own live status
    /// within the first seconds; it exists so the first paint says "checking"
    /// instead of asserting something nobody has verified.
    CheckingStatus,
    NoActivePolicy,
    ServiceUnavailable,
}

impl TrayStatusKind {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::PreviewMode => "preview-mode",
            Self::CheckingStatus => "checking-status",
            Self::NoActivePolicy => "no-active-policy",
            Self::ServiceUnavailable => "service-unavailable",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::PreviewMode => "Preview mode",
            Self::CheckingStatus => "Checking status…",
            Self::NoActivePolicy => "Нет активного применения policy",
            Self::ServiceUnavailable => "Служба недоступна",
        }
    }

    pub const fn icon_asset_hint(self, high_contrast: bool) -> &'static str {
        match self {
            Self::PreviewMode => {
                if high_contrast {
                    "assets/icons/tray/tray-warning-hc.ico"
                } else {
                    "assets/icons/tray/tray-warning.ico"
                }
            }
            Self::CheckingStatus | Self::NoActivePolicy => {
                if high_contrast {
                    "assets/icons/tray/tray-default-hc.ico"
                } else {
                    "assets/icons/tray/tray-default.ico"
                }
            }
            Self::ServiceUnavailable => {
                if high_contrast {
                    "assets/icons/tray/tray-error-hc.ico"
                } else {
                    "assets/icons/tray/tray-error.ico"
                }
            }
        }
    }
}

/// What the caller knows about the link to the background service at the moment
/// the tray context is written.
///
/// The tray's status used to be derived from "has the first-run wizard been
/// completed", which says nothing about whether the service is reachable or
/// whether any rules are being enforced — so a healthy, enforcing setup was
/// announced as "no active policy application", and the user reasonably
/// concluded the app had lost the service.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TrayServiceLink {
    /// Caller has not probed the service (preview and demo paths).
    #[default]
    Unknown,
    /// Probe says the service cannot be talked to right now.
    Unavailable,
    /// Probe says the service answered.
    Reachable,
}

impl fmt::Display for TrayStatusKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for TrayStatusKind {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "preview-mode" | "preview" => Ok(Self::PreviewMode),
            "checking-status" | "checking" => Ok(Self::CheckingStatus),
            "no-active-policy" | "no-policy" => Ok(Self::NoActivePolicy),
            "service-unavailable" | "service-down" => Ok(Self::ServiceUnavailable),
            _ => Err("unknown tray status kind"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrayActionRuntime {
    pub action: AppAction,
    pub availability: MenuAvailability,
    pub setup_availability: SetupActionAvailability,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrayRuntimeSnapshot {
    pub status_kind: TrayStatusKind,
    pub status_line: &'static str,
    pub icon_asset_hint: &'static str,
    pub primary_actions: Vec<TrayActionRuntime>,
    pub quick_actions: Vec<TrayActionRuntime>,
    pub single_instance_note: &'static str,
}

/// Build the tray's launch snapshot.
///
/// `service_link` is what the caller has actually observed about the service.
/// The status it produces is the FIRST PAINT only: the tray re-derives its own
/// status line and tooltip from live data (service state, whether its event
/// stream is live, whether rules are being enforced) as soon as QML is up. What
/// this function must never do is assert enforcement state nobody measured.
pub fn tray_runtime_snapshot(
    shell: &AppShellModel,
    first_run_completed: bool,
    status_override: Option<TrayStatusKind>,
    effective_theme_mode: ThemeMode,
    service_link: TrayServiceLink,
) -> TrayRuntimeSnapshot {
    let status_kind = status_override.unwrap_or(match (first_run_completed, service_link) {
        // Setup is unfinished — nothing is being applied, and saying so is
        // accurate regardless of the service.
        (false, _) => TrayStatusKind::PreviewMode,
        (true, TrayServiceLink::Unavailable) => TrayStatusKind::ServiceUnavailable,
        (true, TrayServiceLink::Reachable) | (true, TrayServiceLink::Unknown) => {
            TrayStatusKind::CheckingStatus
        }
    });
    let high_contrast = effective_theme_mode == ThemeMode::HighContrast;

    TrayRuntimeSnapshot {
        status_kind,
        status_line: status_kind.title(),
        icon_asset_hint: status_kind.icon_asset_hint(high_contrast),
        primary_actions: shell
            .tray_menu
            .primary_actions
            .iter()
            .map(|item| map_action_runtime(shell, *item, first_run_completed))
            .collect(),
        quick_actions: shell
            .tray_menu
            .quick_actions
            .iter()
            .map(|item| map_action_runtime(shell, *item, first_run_completed))
            .collect(),
        single_instance_note:
            "Tray commands are routed into the existing GUI instance (single-instance policy).",
    }
}

fn map_action_runtime(
    shell: &AppShellModel,
    item: MenuItem,
    first_run_completed: bool,
) -> TrayActionRuntime {
    let setup_availability = setup_action_availability(shell, item.action, first_run_completed);
    let availability = if matches!(
        setup_availability,
        SetupActionAvailability::BlockedUntilWizardCompletion
    ) {
        MenuAvailability::Preview
    } else {
        item.availability
    };

    TrayActionRuntime {
        action: item.action,
        availability,
        setup_availability,
    }
}

#[cfg(test)]
mod tests {
    use super::{tray_runtime_snapshot, TrayServiceLink, TrayStatusKind};
    use nrr_shared::{
        gui_shell_v1, AppAction, AppSection, MenuAvailability, SetupActionAvailability, ThemeMode,
    };

    #[test]
    fn default_status_is_preview_before_first_run_completion() {
        let shell = gui_shell_v1();
        let snapshot = tray_runtime_snapshot(
            &shell,
            false,
            None,
            ThemeMode::Light,
            TrayServiceLink::Reachable,
        );
        assert_eq!(snapshot.status_kind, TrayStatusKind::PreviewMode);
        assert_eq!(snapshot.status_line, "Preview mode");
        assert_eq!(
            snapshot.icon_asset_hint,
            "assets/icons/tray/tray-warning.ico"
        );
    }

    #[test]
    fn a_reachable_service_is_not_reported_as_having_no_active_policy() {
        // The regression this pins: the tray announced "no active policy
        // application" purely because first-run was complete, while the service
        // was reachable and enforcing. Nothing here has measured enforcement, so
        // the only honest first paint is "checking".
        let shell = gui_shell_v1();
        let snapshot = tray_runtime_snapshot(
            &shell,
            true,
            None,
            ThemeMode::Light,
            TrayServiceLink::Reachable,
        );
        assert_eq!(snapshot.status_kind, TrayStatusKind::CheckingStatus);
        assert_eq!(
            snapshot.icon_asset_hint,
            "assets/icons/tray/tray-default.ico"
        );
    }

    #[test]
    fn an_unreachable_service_is_reported_as_such() {
        let shell = gui_shell_v1();
        let snapshot = tray_runtime_snapshot(
            &shell,
            true,
            None,
            ThemeMode::Light,
            TrayServiceLink::Unavailable,
        );
        assert_eq!(snapshot.status_kind, TrayStatusKind::ServiceUnavailable);
    }

    #[test]
    fn status_override_supports_service_unavailable() {
        let shell = gui_shell_v1();
        let snapshot = tray_runtime_snapshot(
            &shell,
            true,
            Some(TrayStatusKind::ServiceUnavailable),
            ThemeMode::Light,
            TrayServiceLink::Reachable,
        );
        assert_eq!(snapshot.status_kind, TrayStatusKind::ServiceUnavailable);
        assert_eq!(snapshot.status_line, "Служба недоступна");
        assert_eq!(snapshot.icon_asset_hint, "assets/icons/tray/tray-error.ico");
    }

    #[test]
    fn quick_actions_respect_first_run_gates() {
        let shell = gui_shell_v1();
        let snapshot = tray_runtime_snapshot(
            &shell,
            false,
            None,
            ThemeMode::Light,
            TrayServiceLink::Unknown,
        );

        let rollback = snapshot
            .quick_actions
            .iter()
            .find(|item| item.action == AppAction::SafeRollback)
            .unwrap_or_else(|| panic!("safe rollback action must exist"));
        assert_eq!(
            rollback.setup_availability,
            SetupActionAvailability::BlockedUntilWizardCompletion
        );
        assert_eq!(rollback.availability, MenuAvailability::Preview);

        let refresh = snapshot
            .quick_actions
            .iter()
            .find(|item| item.action == AppAction::RefreshInterfaces)
            .unwrap_or_else(|| panic!("refresh interfaces action must exist"));
        assert_eq!(refresh.setup_availability, SetupActionAvailability::Allowed);
    }

    #[test]
    fn tray_primary_menu_contains_required_actions() {
        let shell = gui_shell_v1();
        let snapshot = tray_runtime_snapshot(
            &shell,
            false,
            None,
            ThemeMode::Light,
            TrayServiceLink::Unknown,
        );
        let actions = snapshot
            .primary_actions
            .iter()
            .map(|item| item.action)
            .collect::<Vec<_>>();
        assert_eq!(
            actions,
            vec![
                AppAction::OpenMainWindow,
                AppAction::OpenSection(AppSection::InterfacesAndRoutes),
                AppAction::OpenSection(AppSection::Rules),
                AppAction::OpenSection(AppSection::Diagnostics),
                AppAction::OpenSection(AppSection::Logs),
                AppAction::OpenSection(AppSection::Settings),
                AppAction::OpenAboutWindow,
                AppAction::OpenLicenseWindow,
                AppAction::OpenLogsFolder,
                AppAction::ExitApplication,
            ]
        );
    }

    #[test]
    fn high_contrast_mode_uses_dedicated_tray_icon_set() {
        let shell = gui_shell_v1();
        let snapshot = tray_runtime_snapshot(
            &shell,
            false,
            None,
            ThemeMode::HighContrast,
            TrayServiceLink::Unknown,
        );
        assert_eq!(
            snapshot.icon_asset_hint,
            "assets/icons/tray/tray-warning-hc.ico"
        );
    }
}
