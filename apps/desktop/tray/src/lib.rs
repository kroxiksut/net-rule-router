//! Tray context emitter.
//!
//! What is left of the crate after the tray runtime moved to `nrr-launcher`
//! plus the C++ Qt host: `write_qt_tray_context_file` and the types it needs.
//! The old orchestrator (menu dispatch, helper self-spawn, Qt-host discovery,
//! log-folder opening) lived on here with no callers — and carried an
//! unguarded `explorer.exe` and three hard-coded product names, which read as
//! supported code.

use nrr_shared::launcher_rpc::HostAnswerDeadlines;
use nrr_shared::{
    load_tray_locale_catalog, resolve_catalog_text, AppAction, FreeRuleType,
    SetupActionAvailability,
};
use nrr_ui_support::theme::resolve_theme;
use nrr_ui_support::tray::{TrayActionRuntime, TrayRuntimeSnapshot, TrayStatusKind};
use nrr_ui_support::ui_preferences::UiPreferences;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrayLaunchOptions {
    first_run_completed_override: Option<bool>,
    status_override: Option<TrayStatusKind>,
}

impl TrayLaunchOptions {
    /// Status painted instead of the live one on the first frame (`--status=`).
    pub fn status_override(&self) -> Option<TrayStatusKind> {
        self.status_override
    }
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
                    "Unknown --status value '{}'. Use preview-mode|checking-status|no-active-policy|service-unavailable.",
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
    /// Root of every icon and image the tray QML draws (`ui_surface::assets_root_url`).
    assets_root_url: Option<String>,
    /// The service log folder (`ui_surface::logs_folder_url`). The C++ host
    /// opens this rather than resolving a path of its own.
    logs_folder_url: Option<String>,
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
    /// Per-kind mute for the "a rule is set on both routes" notice, which the
    /// tray raises while no window is on screen.
    notify_rule_duplicates: bool,
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
    /// The text size and font the user chose, so the tray's windows follow
    /// them as the main window does.
    font_scale_percent: u16,
    system_font: &'static str,
    theme: TrayThemeContext,
    primary_actions: Vec<TrayActionContext>,
    quick_actions: Vec<TrayActionContext>,
    /// OS capability descriptor, mirrored from the main GUI context so the
    /// tray can degrade capability-driven if it ever needs to.
    platform_profile: nrr_shared::platform_profile::PlatformProfile,
    /// How long `RpcTransport.qml` waits for each answer; the launcher owns the budgets.
    rpc_answer_deadlines: HostAnswerDeadlines,
    /// The rule types the window's add-rule form offers, so the tray's copy of
    /// that form offers the same ones.
    supported_rule_types: Vec<RuleTypeContext>,
}

#[derive(Debug, Serialize)]
struct RuleTypeContext {
    id: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrayThemeContext {
    selected_mode: String,
    effective_mode: String,
    system_mode: String,
    system_mode_detected: bool,
}

/// Locations the tray context carries as `file://` URLs, resolved by the caller.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrayContextUrls {
    pub icon_file_url: Option<String>,
    pub assets_root_url: Option<String>,
    pub logs_folder_url: Option<String>,
}

/// Words of the main locale files the tray shows: a key, or a family when it
/// ends in `.`. Words only the tray shows live in `locales/tray/<id>.json`.
/// `tests/tray_words_resolve.rs` fails on a tray key neither place holds.
pub const WINDOW_WORDS: &[&str] = &[
    "action.",
    "block-reason.",
    "dialog.leak-holds-now.",
    "dialog.nothing-to-apply.",
    "dialog.rule.",
    "dialog.safe-disable.term.",
    "dialog.unroutable-secondary.",
    "errors.",
    "label.",
    "mutations.",
    "notifications.",
    "risk.signal.invalid-rule-value",
    "routing.pause.",
    "rules.app-browse-filter-all",
    "rules.app-browse-filter-exe",
    "rules.app-browse-title",
    "rules.application-folder-scripts",
    "rules.application-folder-scripts-deny",
    "rules.application-not-leakproof",
    "rules.application-routing-note",
    "rules.application-routing-note-linux",
    "rules.comment.",
    "rules.filter.route.",
    "rules.hint.",
    "rules.move-to-type.",
    "rules.overlaps.",
    "rules.override.left.",
    "rules.paste.",
    "rules.placeholder.",
    "rules.preview-notice",
    "rules.route.",
    "rules.suggestions.accept.",
    "rules.suggestions.inbox.any-zone",
    "rules.suggestions.inbox.less-certain",
    "rules.suggestions.less-certain.",
    "rules.type.",
    // Whole: the add-rule form shows verdict keys the launcher and the
    // service name at run time, which no scan of the QML sees.
    "rules.validation.",
    "rules.value.",
    "section.",
    "settings.routing.doh-lockdown.label",
    "settings.routing.kill-switch.shared-strict-label",
    "settings.routing.kill-switch.title",
    "settings.routing.leak-protection.",
    "settings.service.recovery.",
    "status.activate-uac-declined",
    "status.auto-rules-failed",
    "status.bridge-unavailable",
    "status.kill-switch-enabled-failed",
    "status.protection.",
    "status.rules-activate-failed",
    "status.rules-apply-unexpected-diff",
    "status.rules-list-added",
    "status.rules-list-moved",
    "status.rules-serialize-failed",
    "status.settings-restore-adapter-missing",
    "status.settings-restore-nothing",
    "status.settings-restored",
    // What is left of the family in the main files: the window shows it too.
    "tray.",
];

/// The tray's words in `language` and English.
pub fn tray_locale_catalog(language: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    load_tray_locale_catalog(language, WINDOW_WORDS)
}

pub fn write_qt_tray_context_file(
    runtime: &TrayRuntimeSnapshot,
    language: &str,
    preferences: &UiPreferences,
    urls: TrayContextUrls,
    rpc_answer_deadlines: HostAnswerDeadlines,
    supported_rule_types: &[FreeRuleType],
) -> Result<PathBuf, String> {
    let locale_catalog = tray_locale_catalog(language);
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
        icon_file_url: urls.icon_file_url,
        assets_root_url: urls.assets_root_url,
        logs_folder_url: urls.logs_folder_url,
        show_notifications: preferences.show_notifications,
        notify_suggestion_changes: preferences.notify_suggestion_changes,
        notify_block_notices: preferences.notify_block_notices,
        notify_rule_duplicates: preferences.notify_rule_duplicates,
        hide_block_notice_addresses: preferences.hide_block_notice_addresses,
        tray_notice_opacity_percent: preferences.tray_notice_opacity_percent,
        routing_detailed_mode: preferences.routing_detailed_mode,
        font_scale_percent: preferences.accessibility_ui_font_scale_percent,
        system_font: preferences.accessibility_system_font.slug(),
        theme: TrayThemeContext {
            selected_mode: theme.selected_mode.slug().to_string(),
            effective_mode: theme.effective_mode.slug().to_string(),
            system_mode: theme.system_mode.slug().to_string(),
            system_mode_detected: theme.system_mode_detected,
        },
        primary_actions: to_action_context(&runtime.primary_actions, &locale_catalog, language),
        quick_actions: to_action_context(&runtime.quick_actions, &locale_catalog, language),
        platform_profile: nrr_shared::platform_profile::PlatformProfile::current(),
        rpc_answer_deadlines,
        supported_rule_types: supported_rule_types
            .iter()
            .map(|rule_type| RuleTypeContext {
                id: rule_type.slug(),
            })
            .collect(),
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    // The coordination directory, not the shared temp root: on Unix `/tmp` is
    // every local user's, and this file is this user's settings.
    let dir = nrr_platform_api::paths::ensure_user_runtime_dir()
        .map_err(|error| format!("Failed to prepare the runtime directory: {error}"))?;
    // Pid and millisecond alone collide for two writes in one millisecond.
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_path = dir.join(format!(
        "nrr-tray-context-{}-{timestamp}-{sequence}.json",
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
                super::TrayContextUrls::default(),
                super::HostAnswerDeadlines::default(),
                &[],
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

    /// Someone who enlarged the text reads the tray's notices and its add-rule
    /// window at that size too, not at the default.
    #[test]
    fn tray_context_carries_the_text_size_and_font() {
        use nrr_ui_support::theme::resolve_theme;
        use nrr_ui_support::tray::tray_runtime_snapshot;
        use nrr_ui_support::ui_preferences::{SystemFontFamily, UiPreferences};

        let shell = nrr_shared::gui_shell_v1();
        let preferences = UiPreferences {
            accessibility_ui_font_scale_percent: 200,
            accessibility_system_font: SystemFontFamily::Verdana,
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
            super::TrayContextUrls::default(),
            super::HostAnswerDeadlines::default(),
            &[],
        )
        .expect("context file is written to the temp dir");
        let raw = std::fs::read_to_string(&path).expect("context file is readable");
        let _ = std::fs::remove_file(&path);
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("context file is JSON");
        assert_eq!(parsed["fontScalePercent"], 200);
        assert_eq!(parsed["systemFont"], "verdana");
    }

    /// `RpcTransport.qml` reads its answer deadlines from here; without them
    /// every request falls back to the transport's own guess.
    #[test]
    fn tray_context_carries_the_answer_deadlines() {
        use nrr_shared::launcher_rpc::HOST_ANSWER_DEADLINES_CONTEXT_KEY;
        use nrr_ui_support::theme::resolve_theme;
        use nrr_ui_support::tray::tray_runtime_snapshot;
        use nrr_ui_support::ui_preferences::UiPreferences;

        let shell = nrr_shared::gui_shell_v1();
        let preferences = UiPreferences::default();
        let theme = resolve_theme(preferences.theme_mode);
        let runtime = tray_runtime_snapshot(
            &shell,
            true,
            None,
            theme.effective_mode,
            nrr_ui_support::tray::TrayServiceLink::Unknown,
        );
        let deadlines = super::HostAnswerDeadlines {
            default_ms: 1234,
            operations_ms: [("mutation.submit".to_string(), 5678)]
                .into_iter()
                .collect(),
        };
        let path = super::write_qt_tray_context_file(
            &runtime,
            &preferences.language,
            &preferences,
            super::TrayContextUrls::default(),
            deadlines,
            &[],
        )
        .expect("context file is written to the temp dir");
        let raw = std::fs::read_to_string(&path).expect("context file is readable");
        let _ = std::fs::remove_file(&path);
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("context file is JSON");
        let carried = &parsed[HOST_ANSWER_DEADLINES_CONTEXT_KEY];
        assert_eq!(carried["defaultMs"], 1234);
        assert_eq!(carried["operationsMs"]["mutation.submit"], 5678);
    }

    /// `Tray.qml` builds its icon from this root alone; under any other key the
    /// tray falls back to no icon at all.
    #[test]
    fn tray_context_carries_the_assets_root() {
        use nrr_ui_support::theme::resolve_theme;
        use nrr_ui_support::tray::tray_runtime_snapshot;
        use nrr_ui_support::ui_preferences::UiPreferences;

        let shell = nrr_shared::gui_shell_v1();
        let preferences = UiPreferences::default();
        let theme = resolve_theme(preferences.theme_mode);
        let runtime = tray_runtime_snapshot(
            &shell,
            true,
            None,
            theme.effective_mode,
            nrr_ui_support::tray::TrayServiceLink::Unknown,
        );
        let urls = super::TrayContextUrls {
            assets_root_url: Some("file:///C:/NetRuleRouter/assets".to_string()),
            ..super::TrayContextUrls::default()
        };
        let path = super::write_qt_tray_context_file(
            &runtime,
            &preferences.language,
            &preferences,
            urls,
            super::HostAnswerDeadlines::default(),
            &[],
        )
        .expect("context file is written to the temp dir");
        let raw = std::fs::read_to_string(&path).expect("context file is readable");
        let _ = std::fs::remove_file(&path);
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("context file is JSON");
        assert_eq!(parsed["assetsRootUrl"], "file:///C:/NetRuleRouter/assets");
    }

    /// The status line and the menu are worded here, from the tray's own
    /// catalogue: a word the window has and the tray lacks would show raw.
    #[test]
    fn the_tray_catalogue_holds_every_word_the_menu_and_status_are_built_from() {
        use super::*;
        use nrr_ui_support::tray::{tray_runtime_snapshot, TrayServiceLink};

        let window = nrr_shared::load_locale_state()
            .catalog
            .remove("en")
            .expect("English");
        let tray = tray_locale_catalog("en").remove("en").expect("English");
        let shell = nrr_shared::gui_shell_v1();
        let mut asked = vec![
            "a11y.tray.preview-only-note".to_string(),
            setup_state_accessibility_note_key(SetupActionAvailability::Allowed).to_string(),
            setup_state_accessibility_note_key(SetupActionAvailability::SoftGuided).to_string(),
            setup_state_accessibility_note_key(
                SetupActionAvailability::BlockedUntilWizardCompletion,
            )
            .to_string(),
        ];
        for status in [
            TrayStatusKind::PreviewMode,
            TrayStatusKind::CheckingStatus,
            TrayStatusKind::NoActivePolicy,
            TrayStatusKind::ServiceUnavailable,
        ] {
            asked.push(format!("tray.status.{}", status.slug()));
            asked.push(status_accessibility_key(status));
            for first_run_completed in [true, false] {
                let runtime = tray_runtime_snapshot(
                    &shell,
                    first_run_completed,
                    Some(status),
                    nrr_shared::ThemeMode::Light,
                    TrayServiceLink::Reachable,
                );
                for item in runtime.primary_actions.iter().chain(&runtime.quick_actions) {
                    asked.push(action_label_key(item.action));
                    asked.push(action_accessibility_label_key(item.action));
                    asked.push(action_accessibility_description_key(item.action));
                }
            }
        }
        let missing: Vec<&String> = asked
            .iter()
            .filter(|key| window.contains_key(*key) && !tray.contains_key(*key))
            .collect();
        assert!(missing.is_empty(), "{missing:?}");
    }

    /// The tray never switches language, so it carries its own language and
    /// English for the keys a translation lacks, never the other languages or
    /// the window's whole catalogue.
    #[test]
    fn tray_context_carries_only_its_language_and_english() {
        use nrr_ui_support::theme::resolve_theme;
        use nrr_ui_support::tray::tray_runtime_snapshot;
        use nrr_ui_support::ui_preferences::UiPreferences;

        let shell = nrr_shared::gui_shell_v1();
        for (language, expected) in [("ru", vec!["en", "ru"]), ("en", vec!["en"])] {
            let preferences = UiPreferences {
                language: language.to_string(),
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
                super::TrayContextUrls::default(),
                super::HostAnswerDeadlines::default(),
                &[],
            )
            .expect("context file is written to the temp dir");
            let raw = std::fs::read_to_string(&path).expect("context file is readable");
            let _ = std::fs::remove_file(&path);
            let parsed: serde_json::Value =
                serde_json::from_str(&raw).expect("context file is JSON");
            let catalog = parsed["localeCatalog"]
                .as_object()
                .expect("a catalogue object");
            let mut languages: Vec<&str> = catalog.keys().map(String::as_str).collect();
            languages.sort_unstable();
            assert_eq!(languages, expected, "for {language}");
            for words in catalog.values() {
                let words = words.as_object().expect("a language's words");
                let foreign: Vec<&String> = words
                    .keys()
                    .filter(|key| key.starts_with("tui.") || key.starts_with("diag."))
                    .take(5)
                    .collect();
                assert!(
                    foreign.is_empty(),
                    "words the tray never shows: {foreign:?}"
                );
                assert!(!words.is_empty());
            }
        }
    }

    /// The tray's add-rule window builds its type list from this field alone;
    /// without it the form would open with nothing to choose.
    #[test]
    fn tray_context_carries_the_offered_rule_types() {
        use nrr_shared::FreeRuleType;
        use nrr_ui_support::theme::resolve_theme;
        use nrr_ui_support::tray::tray_runtime_snapshot;
        use nrr_ui_support::ui_preferences::UiPreferences;

        let shell = nrr_shared::gui_shell_v1();
        let preferences = UiPreferences::default();
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
            super::TrayContextUrls::default(),
            super::HostAnswerDeadlines::default(),
            &[FreeRuleType::Domain, FreeRuleType::Subnet],
        )
        .expect("context file is written to the temp dir");
        let raw = std::fs::read_to_string(&path).expect("context file is readable");
        let _ = std::fs::remove_file(&path);
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("context file is JSON");
        assert_eq!(
            parsed["supportedRuleTypes"],
            serde_json::json!([{ "id": "domain" }, { "id": "subnet" }])
        );
    }
}
