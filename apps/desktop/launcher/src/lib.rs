//! Rust launcher for `NetRuleRouter.exe` / `NetRuleRouterTray.exe`.
//!
//! Single-process orchestrator: emits the QML context JSON in-process and
//! spawns exactly one C++ Qt host child (`nrr_qt_native_host.exe`). All prior
//! `--nrr-helper=...` self-spawn hops and the legacy `nrr-qt-host.exe`
//! intermediate orchestrator are eliminated; preferences round-trip uses
//! the existing `NRR_PREFS_JSON:` stdout marker.

#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

pub mod archive_localize;
pub mod autostart_local;
pub mod backend_factory;
pub mod console_path;
pub mod console_path_local;
pub mod diag_stream;
pub mod launcher;
pub mod legacy_prefs_migration;
pub mod local_handlers;
pub(crate) mod prefs_persistence;
pub mod preset_handlers;
pub mod rpc_dispatcher;
pub mod sidecar_handlers;
pub mod update_check_fetch;

pub use launcher::{
    apply_qt_preferences_payload, default_activation_request_path, path_to_file_url,
    preferences_to_persist, resolve_native_host_executable, run, write_activation_request,
    write_activation_request_to_default_path, LauncherConfig, LauncherSurface, SingleInstanceGuard,
};

pub use legacy_prefs_migration::{
    run_legacy_preferences_migration, FailureStage, MigrationOutcome, SkipReason,
    MIGRATION_CALL_TIMEOUT,
};
