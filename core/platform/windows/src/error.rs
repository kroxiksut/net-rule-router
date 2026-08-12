//! Platform error type and error classification.
//!
//! The neutral `PlatformError` + `ErrorClass` taxonomy now lives in
//! `nrr-platform-api` (shared by every OS backend); re-exported here so existing
//! `nrr_platform_windows::error::*` / `nrr_platform_windows::PlatformError` paths
//! keep resolving unchanged. The Windows backend populates the `Win32` variant.

pub use nrr_platform_api::error::{win32_codes, ErrorClass, PlatformError};
