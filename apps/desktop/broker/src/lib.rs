//! `nrr-broker` — session elevation broker ("one UAC per session").
//!
//! See the crate `Cargo.toml` header and the module docs for the full
//! rationale. Public surface:
//!
//! - [`new_handle`] / [`Broker`] / [`BrokerHandle`] / [`BrokerCallError`]
//!   — the launcher-side client. Call it on a service `Forbidden`.
//! - [`run_broker_server`] / [`BrokerServerArgs`] / [`BROKER_MODE_FLAG`]
//!   — the elevated-broker process side, dispatched from the launcher's
//!   `run()` when the binary is started with `--nrr-elevated-broker`.
//!
//! All Win32 / `unsafe` lives in `windows_sys` so the launcher stays
//! unsafe-free.

#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

pub mod client;
pub mod protocol;
pub mod spawn;

#[cfg(target_os = "windows")]
pub mod server;
#[cfg(target_os = "windows")]
pub mod service_control;
#[cfg(target_os = "windows")]
mod windows_sys;

pub use client::{new_handle, Broker, BrokerCallError, BrokerHandle};
pub use protocol::{BrokerServerArgs, BROKER_MODE_FLAG};

#[cfg(target_os = "windows")]
pub use server::run_broker_server;
#[cfg(target_os = "windows")]
pub use service_control::{try_start_demand_service, DemandStartOutcome};

/// Non-Windows fallbacks for the DemandStart auto-start helper so the
/// launcher compiles cross-platform. DemandStart only exists on Windows.
#[cfg(not(target_os = "windows"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemandStartOutcome {
    Started,
    AlreadyRunning,
    NotStartable,
}

#[cfg(not(target_os = "windows"))]
pub fn try_start_demand_service() -> DemandStartOutcome {
    DemandStartOutcome::NotStartable
}

/// Non-Windows fallback so the launcher crate still compiles on other
/// platforms. Broker mode is never entered off Windows in practice.
#[cfg(not(target_os = "windows"))]
pub fn run_broker_server(_args: BrokerServerArgs) -> std::process::ExitCode {
    eprintln!("nrr-broker: broker mode is only supported on Windows");
    std::process::ExitCode::FAILURE
}
