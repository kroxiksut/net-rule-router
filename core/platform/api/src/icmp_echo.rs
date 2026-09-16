//! One ICMP echo with a chosen hop limit, sent from a chosen source address.
//!
//! The mechanism behind `ping` and `traceroute` for a host the product answers
//! with a virtual address: the probe the user aimed at that address is sent to
//! the real one, over the link the rules picked, and what came back is handed
//! to them. The hop limit is what makes routers along the path answer.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::error::PlatformError;

/// One probe to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EchoProbe {
    pub destination: Ipv4Addr,
    /// Local address to send from, which is what puts the probe on that
    /// address's adapter. `None` leaves the choice to the routing table.
    pub source: Option<Ipv4Addr>,
    pub ttl: u8,
    pub payload: Vec<u8>,
    pub timeout: Duration,
}

/// What came back for one probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EchoOutcome {
    /// The destination answered.
    Reply,
    /// A router discarded the probe when its hop limit ran out.
    TtlExpired { router: Ipv4Addr },
    /// `from` reported the destination unreachable; `code` is the ICMP
    /// destination-unreachable code (0 net, 1 host, 2 protocol, 3 port, ...).
    Unreachable { from: Ipv4Addr, code: u8 },
    /// Nothing came back in time.
    TimedOut,
}

pub trait IcmpEchoPort: Send + Sync {
    fn echo(&self, probe: &EchoProbe) -> Result<EchoOutcome, PlatformError>;
}

/// For a platform with no mechanism: every probe fails to run.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedIcmpEcho;

impl IcmpEchoPort for UnsupportedIcmpEcho {
    fn echo(&self, _probe: &EchoProbe) -> Result<EchoOutcome, PlatformError> {
        Err(PlatformError::NotSupported {
            reason: "ICMP echo is not implemented on this platform",
        })
    }
}
