//! Windows connection-egress observation backends.
//!
//! The neutral port + value types + the pure [`egress`] derivation + the
//! `Mock`/`Merged` combinators live in `nrr-platform-api`; re-export them so
//! `nrr_platform_windows::conn_observe::*` paths keep resolving unchanged. The
//! two Windows MECHANISMs (both pure user-mode — no kernel driver) stay here:
//! - `wfp_events` — WFP `FwpmNetEventSubscribe1`, on the same WFP engine the
//!   apply pipeline already drives. Carries the process image path (NT app-id
//!   blob), the user SID, and an allow/block verdict natively.
//! - `etw_tcpip` — an ETW `Microsoft-Windows-TCPIP` consumer (a near-copy of the
//!   proven `dns_observe::etw` scaffold). Carries PID + 5-tuple for every
//!   connection but no verdict; the no-extra-filter fallback when WFP net-event
//!   collection cannot capture every flow on a given host.

pub use nrr_platform_api::conn_observe::{
    ConnectionObservation, ConnectionObservationSource, ConnectionProgress, ConnectionVerdict,
    MergedConnectionObservationSource, MockConnectionObservationSource, TransportProtocol,
};

// The pure egress derivation also lives in api; `egress.rs` is a re-export shim
// so `crate::conn_observe::egress::*` (used by the backends below via
// `super::egress::…`) keeps resolving unchanged.
pub mod egress;

#[cfg(target_os = "windows")]
pub mod etw_tcpip;
#[cfg(target_os = "windows")]
pub mod wfp_events;
