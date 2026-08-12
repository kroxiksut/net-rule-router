//! Re-export shim — the pure egress-interface derivation now lives in
//! `nrr-platform-api`; kept here so `crate::conn_observe::egress::*` paths (the
//! Windows backends' `super::egress::…`) keep resolving unchanged.
pub use nrr_platform_api::conn_observe::egress::*;
