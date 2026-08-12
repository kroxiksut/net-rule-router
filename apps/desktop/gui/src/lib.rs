// The QML context emitter in `ui_surface.rs` uses one large
// `serde_json::json!` macro that grew past the default 128-deep macro
// recursion limit as tracking fields were added. Bumping the cap is
// the canonical fix per `json!`'s docs.
#![recursion_limit = "512"]

//! Library surface of the legacy GUI orchestrator crate.
//!
//! The crate continues to ship the binary `NetRuleRouter.exe` (its current
//! user-facing role) while in parallel exposing a stable subset of its
//! internals as a library so that the `nrr-launcher` crate can reuse
//! `write_qt_context_file_at`, `apply_qt_preferences_payload`,
//! `parse_preferences_from_qt_output`, and the `LaunchRequest` value type.

pub mod accessibility;
pub mod app_shell;
pub mod interfaces_routes;
pub mod rules;
pub mod security;
pub mod settings;
pub mod summary;
pub mod ui_surface;
pub mod update_check;
