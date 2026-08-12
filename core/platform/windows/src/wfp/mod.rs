//! WFP session RAII handles and plan execution.
//!
//! This module's logic is FULLY NEUTRAL (pure logic over the `WindowsApiPort`
//! trait + neutral value-types + `std::sync`), so per the
//! policy/mechanism seam the DEFINITIONS live in `nrr-platform-api`
//! (`nrr_platform_api::wfp`) — including the `MAX_FILTERS_PER_TRANSACTION`
//! batching cap. This is a re-export shim so `nrr_platform_windows::wfp::…`
//! paths (and the Windows backend's `crate::wfp::…`) keep resolving
//! byte-for-byte unchanged. The Windows-semantic constants (WFP provider /
//! sub-layer GUIDs, `\\.\pipe\NrrService`, sub-layer weight) stay in
//! `crate::constants`.
pub use nrr_platform_api::wfp::*;
