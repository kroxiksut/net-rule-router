pub mod diagnostics;
pub mod first_run;
pub mod interface_manager;
pub mod logs;
pub mod network_interfaces;
pub mod route_bindings;
pub mod rules;
pub mod runtime_separation;
pub mod security_status;
pub mod theme;
pub mod tray;
pub mod ui_preferences;

pub use nrr_application::{
    about_window_info, runtime_boot_banner, runtime_boot_guard_message, AboutWindowInfo,
};
