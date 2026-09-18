// QML context emission for both surfaces, cold-start section resolution, and
// the temp-file lifecycle (path generation, stale-leftover sweep) it rides on.

use std::env;
use std::fs;
use std::path::PathBuf;

use nrr_application::backend_facade::{mock_scenario_from_env, tray_status_for_mock_scenario};
use nrr_desktop_gui::app_shell::LaunchRequest;
use nrr_desktop_gui::ui_surface::write_qt_context_file_at;
use nrr_desktop_tray::write_qt_tray_context_file;
use nrr_shared::{gui_shell_v1, AppSection};
use nrr_ui_support::first_run::{first_run_flow_snapshot, resolve_entry_section_for_first_run};
use nrr_ui_support::theme::resolve_theme;
use nrr_ui_support::tray::{tray_runtime_snapshot, TrayServiceLink};
use nrr_ui_support::ui_preferences::UiPreferences;

use super::resolve::resolve_native_icon_path;
use super::{path_to_file_url, LauncherSurface};

pub(super) fn emit_context(
    surface: LauncherSurface,
    preferences: &UiPreferences,
    backend_bundle: &crate::backend_factory::BackendBundle,
    request: &LaunchRequest,
) -> Result<PathBuf, String> {
    match surface {
        LauncherSurface::MainGui => emit_main_gui_context(preferences, backend_bundle, request),
        LauncherSurface::Tray => emit_tray_context(preferences, backend_bundle),
    }
}

fn emit_main_gui_context(
    preferences: &UiPreferences,
    backend_bundle: &crate::backend_factory::BackendBundle,
    request: &LaunchRequest,
) -> Result<PathBuf, String> {
    let shell = gui_shell_v1();

    let requested_section = cold_start_section(request, preferences);
    // The first-run gate applies to the section a cold start OPENS, not just to
    // actions taken later: opening Rules before the wizard is finished shows a
    // surface whose prerequisites (an adapter binding) do not exist yet. The
    // launcher used to skip the gate entirely — it was live only in the console
    // shell — so the redirect the model promises never happened in the shipped
    // application.
    let (section_to_open, _availability) = resolve_entry_section_for_first_run(
        &shell,
        requested_section,
        preferences.first_run_completed,
    );

    let first_run = first_run_flow_snapshot(&shell, preferences.first_run_completed, None);

    let context_path = generate_temp_path("nrr-qt-context");
    write_qt_context_file_at(
        &context_path,
        &shell,
        section_to_open,
        preferences.clone(),
        &first_run,
        request,
        backend_bundle.facade.as_ref(),
        &backend_bundle.status,
    )?;

    Ok(context_path)
}

fn emit_tray_context(
    preferences: &UiPreferences,
    backend_bundle: &crate::backend_factory::BackendBundle,
) -> Result<PathBuf, String> {
    let shell = gui_shell_v1();
    let resolved_theme = resolve_theme(preferences.theme_mode);
    let mock_status_override = mock_scenario_from_env().and_then(tray_status_for_mock_scenario);
    // The cold-start probe already answered "can the service be talked to";
    // passing it on keeps the tray's first paint from asserting an enforcement
    // state nobody has looked at.
    let service_link = if backend_bundle.status.is_connected() {
        TrayServiceLink::Reachable
    } else {
        TrayServiceLink::Unavailable
    };
    let runtime = tray_runtime_snapshot(
        &shell,
        preferences.first_run_completed,
        mock_status_override,
        resolved_theme.effective_mode,
        service_link,
    );
    let icon_file_url = resolve_native_icon_path().as_deref().map(path_to_file_url);

    write_qt_tray_context_file(&runtime, &preferences.language, preferences, icon_file_url)
}

/// Which section a cold start opens.
///
/// A launch that carries a section is the tray handing work over, so it wins:
/// dropping it opened whatever the preferences remembered, and "Open and
/// compare" on the tray's rules notice landed on an unrelated section.
pub fn cold_start_section(request: &LaunchRequest, preferences: &UiPreferences) -> AppSection {
    match request.section {
        Some(section) => section,
        None if preferences.reopen_last_section_on_startup => preferences.last_opened_section,
        None => AppSection::InterfacesAndRoutes,
    }
}

/// A path for one run's context file, inside the coordination directory.
///
/// Not the shared temp root: on Unix that is `/tmp`, writable by every local
/// user, and this file carries the user's settings into the Qt host. Falls back
/// to the temp root only when the guarded directory cannot be prepared, which
/// is also the case where the launcher is about to fail anyway.
fn generate_temp_path(prefix: &str) -> PathBuf {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let name = format!("{prefix}-{}-{timestamp}.json", std::process::id());
    match nrr_platform_api::paths::ensure_user_runtime_dir() {
        Ok(dir) => dir.join(name),
        Err(_) => env::temp_dir().join(name),
    }
}

/// Sweep `%TEMP%` for stale `nrr-*-context-*.json` files left behind when a
/// previous run was killed (kill-9, crash, fast machine shutdown). Graceful
/// exit already removes its own context file via `fs::remove_file(&context_file)`
/// in `run_primary`, but a force-killed process never gets there. Files older
/// than `LEFTOVER_MAX_AGE` are considered safely abandoned and deleted on
/// startup so `%TEMP%` does not grow unbounded over time.
pub(super) fn cleanup_temp_leftovers() {
    const LEFTOVER_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(60 * 60);
    let Ok(dir) = nrr_platform_api::paths::ensure_user_runtime_dir() else {
        return;
    };
    let now = std::time::SystemTime::now();
    let Ok(entries) = fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        let is_context_file = (file_name.starts_with("nrr-qt-context-")
            || file_name.starts_with("nrr-tray-context-"))
            && file_name.ends_with(".json");
        if !is_context_file {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let modified = metadata.modified().unwrap_or(now);
        if now.duration_since(modified).unwrap_or_default() < LEFTOVER_MAX_AGE {
            continue;
        }
        let _ = fs::remove_file(entry.path());
    }
}
