//! The fail-closed BLOCK PLANNING (which IPs to block, the filter specs,
//! exemptions, filter-id derivation) is neutral policy, so it lives in
//! `nrr_platform_api::fail_closed`. The Win32 WFP APPLY of those filters
//! stays in the backend. Shim for source compatibility.

pub use nrr_platform_api::fail_closed::*;
