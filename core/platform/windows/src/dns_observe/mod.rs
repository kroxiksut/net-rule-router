//! Passive DNS-resolution observation.
//!
//! Neutral definitions (`DnsObservation`, `DnsObservationSource`,
//! `MockDnsObservationSource`) live in `nrr-platform-api` and are
//! re-exported here unchanged. The Windows mechanism ([`etw`]) stays in
//! this crate.

#[cfg(target_os = "windows")]
pub mod etw;

pub use nrr_platform_api::dns_observe::*;
