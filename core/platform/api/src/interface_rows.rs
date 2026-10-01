//! Neutral adapter rich-row types + deterministic enrichment.
//!
//! Owns the [`InterfaceRouteRow`] type and the pure enrichment that turns a
//! live adapter enumeration into the rows the GUI "Interfaces & routes" list
//! renders: observed connectivity facts, heuristic VPN/virtual/service
//! classification, the advisory route-role recommendation, the resolver of a
//! saved binding, the wire-DTO projection, and the deterministic
//! `fallback_rows` dataset. All of it is
//! OS-neutral (pure functions over `nrr-shared` value types). The live
//! enumeration is the [`InterfaceRowsPort`], implemented per OS in the backend
//! crates.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nrr_shared::{
    ConnectivityState, DerivedLikelihood, ExternalIpStatus, RecommendationClass,
    RecommendationConfidence, RouteRole, RouteSelectionState,
};

use crate::external_ip::ExternalIpProbeOutcome;
use crate::types::RouteEntry;

mod assess;
mod dto;
mod port;
mod preview;
mod probe;
mod recommend;
mod routes;
mod types;

pub use assess::*;
pub use port::*;
pub use preview::*;
pub use probe::*;
pub use recommend::*;
pub use routes::*;
pub use types::*;

#[cfg(test)]
mod tests;
