//! Connection-egress observation port (Free diagnostic; the foundation for
//! per-process routing, whose strict *enforcement* is the Pro experiment).
//!
//! Where [`crate::dns_observe`] watches DNS *resolutions* (hostname → IP), this
//! port watches actual outbound *connections*: which process connected to which
//! remote endpoint, and — derived from the connection's local (source) address
//! via [`egress`] — which interface the packet egressed.
//!
//! ## Why a connection trace, in addition to DNS observation
//!
//! The DNS observer is blinded by DNS-over-HTTPS (a browser's in-process DoH
//! resolver bypasses the OS DNS client, so the `*.example.com` / `.ru` routing
//! feed never sees those names). A connection observer is **not**: it sees the
//! socket connect regardless of how the name was resolved, so it is a strictly
//! more complete picture of real egress — which is exactly what is needed to
//! answer "did this app's connection actually leave via the secondary adapter or
//! the provider?" across *every* process, not just the browser.
//!
//! ## Backends
//!
//! Per the policy/mechanism seam only the PORT, the neutral value types,
//! the pure [`egress`] derivation, and the [`MockConnectionObservationSource`] /
//! [`MergedConnectionObservationSource`] combinators live here; the real backends
//! live in each OS crate and `impl` [`ConnectionObservationSource`] (Windows: an
//! ETW `Microsoft-Windows-TCPIP` consumer plus a WFP `FwpmNetEventSubscribe1`
//! net-event source; Linux/macOS: their own conntrack / socket sources). The
//! egress interface index is **not** a native field of any backend event; it is
//! derived from the connection's local source address in [`egress`].

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

pub mod egress;

/// Transport protocol of an observed connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    /// Any other IP protocol number the backend reported.
    Other(u8),
}

/// The verdict a connection received, when the backend can report one.
///
/// A pure ETW/conntrack backend cannot and always yields [`Self::Unknown`]; a
/// WFP net-event backend maps `FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW` →
/// [`Self::Permit`] and `…_CLASSIFY_DROP` → [`Self::Block`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionVerdict {
    Permit,
    Block,
    Unknown,
}

/// What the stack was seen doing with a connection.
///
/// [`Self::Attempt`] is the connection itself — every backend reports it, and
/// only these become trace rows. The other two are evidence ABOUT a peer rather
/// than connections of their own: a stack resends because the peer is not
/// acknowledging, and tears down in order because the connection carried
/// traffic. Backends that cannot distinguish them report [`Self::Attempt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ConnectionProgress {
    #[default]
    Attempt,
    Retransmit,
    ClosedInOrder,
}

/// One observed outbound connection attempt.
///
/// Transport-level only — no interface, no hostname. The egress interface is
/// derived downstream from [`Self::local`] (see [`egress`]); the hostname (if
/// any) is joined downstream from the FQDN cache by [`Self::remote`]'s IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionObservation {
    /// Initiating process id, or `0` when the backend could not attribute it.
    pub pid: u32,
    /// Full image path of the initiating process, when the backend supplies it
    /// (WFP net-events carry the NT app-id blob; a pure ETW/conntrack source
    /// does not).
    pub process_path: Option<String>,
    /// SID (or uid) of the user the process ran as, when known.
    pub user_sid: Option<String>,
    pub protocol: TransportProtocol,
    /// Local (source) endpoint the OS bound for this connection. Its address
    /// identifies the egress interface (see [`egress`]). IPv4 or IPv6.
    pub local: SocketAddr,
    /// Remote (destination) endpoint.
    pub remote: SocketAddr,
    pub verdict: ConnectionVerdict,
    /// Backend runtime filter id that produced a DROP, when the backend knows it
    /// (WFP net-events only). Internal to attribution — `None` for allows, for a
    /// pure ETW/conntrack backend, and when the event did not carry one.
    pub drop_filter_id: Option<u64>,
    /// Attribution of a DROP verdict. `Some(true)` — an NetRuleRouter filter
    /// dropped it (its `providerKey` is NRR's); `Some(false)` — some OTHER
    /// filter did (an OS firewall, an antivirus, …); `None` — not a drop, or the
    /// owner could not be resolved. So the trace never
    /// blames NetRuleRouter for a foreign drop.
    pub blocked_by_nrr: Option<bool>,
    /// The NetRuleRouter codegen spec id ([`WfpFilterId::raw`](crate::types::WfpFilterId))
    /// decoded from the dropping WFP filter's `filterKey`, when the backend can
    /// resolve one (WFP net-events only). `None` when the drop is foreign, the
    /// filter key does not carry our namespace signature, or the lookup failed.
    /// Unlike [`Self::blocked_by_nrr`] (provider/sub-layer attribution — "is this
    /// OUR filter"), this identifies WHICH filter, letting a consumer check its
    /// ROLE (e.g. kill-switch/fail-closed Block vs. a user's own Block rule)
    /// against a registry before trusting the drop for anything security-
    /// sensitive.
    pub nrr_drop_spec_id: Option<u64>,
    /// Event time in Unix milliseconds when the backend stamped it; `None` lets
    /// the consumer stamp at drain time.
    pub observed_unix_ms: Option<u64>,
    /// Whether this is the connection itself or later evidence about the peer.
    /// See [`ConnectionProgress`].
    pub progress: ConnectionProgress,
}

/// A source of passively-observed outbound connections. The consumer polls
/// [`Self::drain`] periodically; the source buffers events between drains
/// (identical contract to [`crate::dns_observe::DnsObservationSource`]).
pub trait ConnectionObservationSource: Send + Sync {
    /// Remove and return all connections buffered since the last drain. Returns
    /// an empty vector when nothing was observed.
    fn drain(&self) -> Vec<ConnectionObservation>;
}

/// In-memory scripted source for tests (and for OSes without a live backend,
/// where it simply never produces anything). Push observations with
/// [`Self::push`]; the consumer drains them.
#[derive(Default)]
pub struct MockConnectionObservationSource {
    buffered: Mutex<Vec<ConnectionObservation>>,
}

// Test/dev double: `lock().unwrap()` poisoning is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl MockConnectionObservationSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Buffer one observation for the next drain.
    pub fn push(&self, observation: ConnectionObservation) {
        self.buffered.lock().unwrap().push(observation);
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
impl ConnectionObservationSource for MockConnectionObservationSource {
    fn drain(&self) -> Vec<ConnectionObservation> {
        std::mem::take(&mut *self.buffered.lock().unwrap())
    }
}

/// A [`ConnectionObservationSource`] that fans in several underlying sources:
/// `drain()` concatenates every child's drained observations. This lets two
/// backends run side by side — ETW (captures every TCP connect) merged with WFP
/// (adds the allow/block verdict, notably drops) — for a strictly more complete
/// trace than either alone, WITHOUT adding any observe-filter to the live filter
/// set (no lockout risk). The WFP backend alone rarely emits CLASSIFY_ALLOW
/// without a permit observe-filter it deliberately omits, which would leave an
/// almost-empty trace; folding ETW back in restores the full connection list
/// (codex, browsers, …).
pub struct MergedConnectionObservationSource {
    sources: Vec<Arc<dyn ConnectionObservationSource>>,
}

impl MergedConnectionObservationSource {
    /// Wrap the given sources. Order only affects the within-tick ordering of the
    /// concatenated drain; the consumer stamps arrival order into the ring.
    pub fn new(sources: Vec<Arc<dyn ConnectionObservationSource>>) -> Self {
        Self { sources }
    }
}

impl ConnectionObservationSource for MergedConnectionObservationSource {
    fn drain(&self) -> Vec<ConnectionObservation> {
        let mut out = Vec::new();
        for s in &self.sources {
            out.append(&mut s.drain());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn sample() -> ConnectionObservation {
        ConnectionObservation {
            pid: 4242,
            process_path: Some(r"C:\Program Files\Mozilla Firefox\firefox.exe".to_string()),
            user_sid: Some("S-1-5-21-1".to_string()),
            protocol: TransportProtocol::Tcp,
            local: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 8, 0, 6), 51514)),
            remote: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(188, 40, 167, 82), 443)),
            verdict: ConnectionVerdict::Permit,
            drop_filter_id: None,
            blocked_by_nrr: None,
            nrr_drop_spec_id: None,
            observed_unix_ms: Some(1_782_445_490_400),
            progress: ConnectionProgress::Attempt,
        }
    }

    #[test]
    fn mock_buffers_and_drains_once() {
        let src = MockConnectionObservationSource::new();
        src.push(sample());
        let mut second = sample();
        second.pid = 1;
        src.push(second);

        let first = src.drain();
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].pid, 4242);
        assert_eq!(first[0].remote.port(), 443);
        // Drained — a second drain is empty.
        assert!(src.drain().is_empty());
    }
}
