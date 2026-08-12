//! The platform state snapshot / desired state / action plan diff logic is
//! OS-neutral (pure functions over `nrr-platform-api` value types, zero
//! `windows::`), so it lives in `nrr_platform_api::snapshot`.
//!
//! This module is a compatibility shim: it re-exports the neutral definitions so
//! the crate-root re-export in `lib.rs` (`compute_action_plan`,
//! `DesiredPlatformState`, `PlatformStateSnapshot`, …) and every
//! `crate::snapshot::*` / `nrr_platform_windows::snapshot::*` path keeps
//! resolving unchanged.

pub use nrr_platform_api::snapshot::*;
