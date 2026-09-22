//! Neutral adapter rich-row types + deterministic enrichment.
//!
//! Owns the [`InterfaceRouteRow`] type and the pure enrichment that turns a
//! live adapter enumeration into the rows the GUI "Interfaces & routes" list
//! renders: observed connectivity facts, heuristic VPN/virtual/service
//! classification, a default (unknown) recommendation slot, the wire-DTO
//! projection, and the deterministic `fallback_rows` dataset. All of it is
//! OS-neutral (pure functions over `nrr-shared` value types). The live Windows
//! enumeration (`collect_interfaces_rows`, which reads the OS adapter table)
//! stays in `nrr-platform-windows` and re-exports these definitions.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nrr_shared::{
    ConnectivityState, DerivedLikelihood, ExternalIpStatus, RecommendationClass,
    RecommendationConfidence, RouteRole, RouteSelectionState,
};

use crate::external_ip::ExternalIpProbeOutcome;
use crate::types::RouteEntry;

mod assess;
mod dto;
mod preview;
mod probe;
mod routes;
mod types;

pub use assess::*;
pub use preview::*;
pub use probe::*;
pub use routes::*;
pub use types::*;

#[cfg(test)]
mod tests;
