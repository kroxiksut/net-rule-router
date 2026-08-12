//! Neutral platform-level network value types.
//!
//! These DEFINITIONS (`RouteEntry`, `WfpEngineToken`, `WfpFilterId`,
//! `WfpLayerKey`, `WfpAction`, `WfpFilterSpec`, `WfpFilterRecord`,
//! `ApplyActionPlan`, `RoutingAction`, `WfpFilterAction`) moved to the neutral
//! `nrr-platform-api` (they are pure `std::net` + `serde`, no `windows::`); this
//! is a re-export shim so `nrr_platform_windows::types::*` paths (and the Windows
//! backend's `crate::types::…`) keep resolving byte-for-byte unchanged. The
//! Windows MECHANISM that turns a `WfpEngineToken`'s `raw: u64` back into an
//! `HFWPENGINE` lives in `win32_ffi::wfp_engine`.
pub use nrr_platform_api::types::*;
