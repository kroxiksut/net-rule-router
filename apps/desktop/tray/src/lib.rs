//! Tray context emitter.
//!
//! What is left of the crate after the tray runtime moved to `nrr-launcher`
//! plus the C++ Qt host: `write_qt_tray_context_file` and the types it needs.
//! The old orchestrator (menu dispatch, helper self-spawn, Qt-host discovery,
//! log-folder opening) lived on here with no callers — and carried an
//! unguarded `explorer.exe` and three hard-coded product names, which read as
//! supported code.

use nrr_shared::{load_locale_catalog, resolve_catalog_text, AppAction, SetupActionAvailability};
use nrr_ui_support::theme::resolve_theme;
use nrr_ui_support::tray::{TrayActionRuntime, TrayRuntimeSnapshot, TrayStatusKind};
use nrr_ui_support::ui_preferences::UiPreferences;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrayLaunchOptions {
    first_run_completed_override: Option<bool>,
    status_override: Option<TrayStatusKind>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelperCommand {
    EmitTrayContext {
        output_path: PathBuf,
        options: TrayLaunchOptions,
    },
}

pub fn parse_launch_options_arguments<I>(arguments: I) -> TrayLaunchOptions
where
    I: IntoIterator<Item = String>,
{
    let mut options = TrayLaunchOptions {
        first_run_completed_override: None,
        status_override: None,
    };

    for argument in arguments {
        if let Some(value) = argument.strip_prefix("--first-run=") {
            options.first_run_completed_override = match value {
                "required" | "pending" => Some(false),
                "completed" | "done" => Some(true),
                _ => {
                    eprintln!(
                        "Unknown --first-run value '{}'. Use required|completed.",
                        value
                    );
                    None
                }
            };
            continue;
        }

        if let Some(value) = argument.strip_prefix("--status=") {
            match value.parse::<TrayStatusKind>() {
                Ok(status) => options.status_override = Some(status),
                Err(_) => eprintln!(
                    "Unknown --status value '{}'. Use preview-mode|no-active-policy|service-unavailable.",
                    value
                ),
            }
            continue;
        }

        eprintln!("Unknown tray launch argument '{}'.", argument);
    }

    options
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrayActionContext {
    id: String,
    label: String,
    enabled: bool,
    accessible_description: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrayContextPayload {
    language: String,
    locale_catalog: BTreeMap<String, BTreeMap<String, String>>,
    status_key: String,
    status_accessibility_key: String,
    status_line: String,
    status_accessibility_text: String,
    route_primary_label: String,
    route_secondary_label: String,
    icon_file_url: Option<String>,
    /// Mirrors the user's "show notifications" preference. The tray is the only
    /// surface that raises unsolicited windows, so it has to honour the toggle;
    /// it is a launch-time snapshot like `language` and `theme`, so a change
    /// takes effect the next time the tray starts.
    show_notifications: bool,
    /// Per-kind mute for the suggestions-changed stripe, under the master
    /// toggle above. Same launch-time snapshot rule.
    notify_suggestion_changes: bool,
    /// Per-kind mute for the "connection blocked" notice — the tray is the
    /// surface that raises it, so it honours this like `show_notifications`.
    notify_block_notices: bool,
    /// Whether that notice may name the destination. Off-screen leaks are the
    /// point: a shared screen must not show what the user browses.
    hide_block_notice_addresses: bool,
    /// Opacity of the notice window in percent — it is our own window, so the
    /// preference reaches the tray the same way the mutes do.
    tray_notice_opacity_percent: u16,
    /// Mirrors the "Detailed routing mode" preference. The tray does not
    /// itself gate anything on it today; carried through for parity with the
    /// main GUI context.
    routing_detailed_mode: bool,
    theme: TrayThemeContext,
    primary_actions: Vec<TrayActionContext>,
    quick_actions: Vec<TrayActionContext>,
    /// OS capability descriptor, mirrored from the main GUI context so the
    /// tray can degrade capability-driven if it ever needs to.
    platform_profile: nrr_shared::platform_profile::PlatformProfile,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrayThemeContext {
    selected_mode: String,
    effective_mode: String,
    system_mode: String,
    system_mode_detected: bool,
}

pub fn write_qt_tray_context_file(
    runtime: &TrayRuntimeSnapshot,
    language: &str,
    preferences: &UiPreferences,
    icon_file_url: Option<String>,
) -> Result<PathBuf, String> {
    let locale_catalog = load_locale_catalog();
    let status_slug = runtime.status_kind.slug();
    let theme = resolve_theme(preferences.theme_mode);
    let context = TrayContextPayload {
        language: language.to_string(),
        locale_catalog: locale_catalog.clone(),
        status_key: format!("tray.status.{status_slug}"),
        status_accessibility_key: status_accessibility_key(runtime.status_kind),
        status_line: resolve_catalog_text(
            &locale_catalog,
            language,
            &format!("tray.status.{status_slug}"),
            runtime.status_line,
        ),
        status_accessibility_text: resolve_tray_status_accessibility_text(
            &locale_catalog,
            language,
            runtime.status_kind,
            runtime.status_line,
        ),
        route_primary_label: preferences.route_primary_label.clone(),
        route_secondary_label: preferences.route_secondary_label.clone(),
        icon_file_url,
        show_notifications: preferences.show_notifications,
        notify_suggestion_changes: preferences.notify_suggestion_changes,
        notify_block_notices: preferences.notify_block_notices,
        hide_block_notice_addresses: preferences.hide_block_notice_addresses,
        tray_notice_opacity_percent: preferences.tray_notice_opacity_percent,
        routing_detailed_mode: preferences.routing_detailed_mode,
        theme: TrayThemeContext {
            selected_mode: theme.selected_mode.slug().to_string(),
            effective_mode: theme.effective_mode.slug().to_string(),
            system_mode: theme.system_mode.slug().to_string(),
            system_mode_detected: theme.system_mode_detected,
        },
        primary_actions: to_action_context(&runtime.primary_actions, &locale_catalog, language),
        quick_actions: to_action_context(&runtime.quick_actions, &locale_catalog, language),
        platform_profile: nrr_shared::platform_profile::PlatformProfile::current(),
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    // The coordination directory, not the shared temp root: on Unix `/tmp` is
    // every local user's, and this file is this user's settings.
    let dir = nrr_platform_api::paths::ensure_user_runtime_dir()
        .map_err(|error| format!("Failed to prepare the runtime directory: {error}"))?;
    let file_path = dir.join(format!(
        "nrr-tray-context-{}-{timestamp}.json",
        std::process::id()
    ));

    let payload = serde_json::to_string(&context)
        .map_err(|error| format!("Failed to serialize Qt tray context: {error}"))?;
    let mut file = nrr_platform_api::paths::create_private_file(&file_path)
        .map_err(|error| format!("Failed to create Qt tray context file: {error}"))?;
    std::io::Write::write_all(&mut file, payload.as_bytes())
        .map_err(|error| format!("Failed to write Qt tray context file: {error}"))?;
    Ok(file_path)
}

fn to_action_context(
    actions: &[TrayActionRuntime],
    locale_catalog: &BTreeMap<String, BTreeMap<String, String>>,
    language: &str,
) -> Vec<TrayActionContext> {
    actions
        .iter()
        .map(|item| TrayActionContext {
            id: item.action.id().to_string(),
            label: resolve_action_label(locale_catalog, language, item.action),
            enabled: item.availability.is_enabled(),
            accessible_description: resolve_action_accessibility_description(
                locale_catalog,
                language,
                item,
            ),
        })
        .collect()
}

fn action_label_key(action: AppAction) -> String {
    match action {
        AppAction::OpenSection(section) => format!("section.{}", section.slug()),
        _ => format!("action.{}", action.id()),
    }
}

fn action_accessibility_label_key(action: AppAction) -> String {
    format!("a11y.tray.action-label.{}", action.id())
}

fn action_accessibility_description_key(action: AppAction) -> String {
    format!("a11y.tray.action-description.{}", action.id())
}

fn setup_state_accessibility_note_key(setup: SetupActionAvailability) -> &'static str {
    match setup {
        SetupActionAvailability::Allowed => "a11y.tray.setup-state.allowed",
        SetupActionAvailability::SoftGuided => "a11y.tray.setup-state.soft-guided",
        SetupActionAvailability::BlockedUntilWizardCompletion => {
            "a11y.tray.setup-state.blocked-until-wizard-completion"
        }
    }
}

fn resolve_action_label(
    locale_catalog: &BTreeMap<String, BTreeMap<String, String>>,
    language: &str,
    action: AppAction,
) -> String {
    let default_label = resolve_catalog_text(
        locale_catalog,
        language,
        &action_label_key(action),
        action.label(),
    );
    resolve_catalog_text(
        locale_catalog,
        language,
        &action_accessibility_label_key(action),
        &default_label,
    )
}

fn resolve_action_accessibility_description(
    locale_catalog: &BTreeMap<String, BTreeMap<String, String>>,
    language: &str,
    action: &TrayActionRuntime,
) -> String {
    let localized_label = resolve_action_label(locale_catalog, language, action.action);
    let base = resolve_catalog_text(
        locale_catalog,
        language,
        &action_accessibility_description_key(action.action),
        &localized_label,
    );
    let setup_note = resolve_catalog_text(
        locale_catalog,
        language,
        setup_state_accessibility_note_key(action.setup_availability),
        "",
    );
    let preview_note = if action.availability.is_enabled() {
        String::new()
    } else {
        resolve_catalog_text(locale_catalog, language, "a11y.tray.preview-only-note", "")
    };
    [base, setup_note, preview_note]
        .into_iter()
        .filter(|chunk| !chunk.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn status_accessibility_key(status_kind: TrayStatusKind) -> String {
    format!("a11y.tray.status-text.{}", status_kind.slug())
}

fn resolve_tray_status_accessibility_text(
    locale_catalog: &BTreeMap<String, BTreeMap<String, String>>,
    language: &str,
    status_kind: TrayStatusKind,
    fallback: &str,
) -> String {
    resolve_catalog_text(
        locale_catalog,
        language,
        &status_accessibility_key(status_kind),
        fallback,
    )
}

#[cfg(test)]
mod tests {
    use super::parse_launch_options_arguments;
    use nrr_ui_support::tray::TrayStatusKind;

    #[test]
    fn tray_parser_reads_first_run_and_status_flags() {
        let parsed = parse_launch_options_arguments([
            "--first-run=completed".to_string(),
            "--status=service-unavailable".to_string(),
        ]);

        assert_eq!(parsed.first_run_completed_override, Some(true));
        assert_eq!(
            parsed.status_override,
            Some(TrayStatusKind::ServiceUnavailable)
        );
    }

    /// The tray is the only surface that raises unsolicited windows, and its
    /// QML gate reads exactly this field. If the preference stopped reaching the
    /// context, "show notifications = off" would silently stop being honoured —
    /// so the plumbing is pinned here rather than left to the QML side.
    #[test]
    fn tray_context_carries_the_show_notifications_preference() {
        use nrr_ui_support::theme::resolve_theme;
        use nrr_ui_support::tray::tray_runtime_snapshot;
        use nrr_ui_support::ui_preferences::UiPreferences;

        let shell = nrr_shared::gui_shell_v1();
        for wanted in [true, false] {
            let preferences = UiPreferences {
                show_notifications: wanted,
                ..UiPreferences::default()
            };
            let theme = resolve_theme(preferences.theme_mode);
            let runtime = tray_runtime_snapshot(
                &shell,
                true,
                None,
                theme.effective_mode,
                nrr_ui_support::tray::TrayServiceLink::Unknown,
            );
            let path = super::write_qt_tray_context_file(
                &runtime,
                &preferences.language,
                &preferences,
                None,
            )
            .expect("context file is written to the temp dir");
            let raw = std::fs::read_to_string(&path).expect("context file is readable");
            let _ = std::fs::remove_file(&path);
            let parsed: serde_json::Value =
                serde_json::from_str(&raw).expect("context file is JSON");
            assert_eq!(
                parsed.get("showNotifications").and_then(|v| v.as_bool()),
                Some(wanted),
            );
        }
    }
}
