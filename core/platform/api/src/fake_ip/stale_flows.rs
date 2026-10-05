//! Fake-IP — the neutral "tear down flows the last run left behind" contract.
//!
//! Fake addresses outlive a service restart on purpose: a hostname keeps its
//! address as a stable identity. The userspace TCP stack behind those addresses
//! does not — it is rebuilt empty on every start. An application that still
//! holds a socket to a fake address is therefore talking to a peer that no
//! longer exists on the other side, and nothing tells it so: no reset arrives,
//! the socket stays "established", and a browser will sit on it instead of
//! re-resolving. The visible symptom is a page whose images never load while
//! the service looks perfectly healthy.
//!
//! Per the policy/mechanism seam this trait is the mechanism half: an
//! implementation asks the OS to tear down established TCP connections whose
//! remote address falls inside a given range. WHICH range (the fake-IP pool)
//! and WHEN to do it (once, as the stack comes up) stay neutral in
//! `service-runtime`.
//!
//! Tearing down is best-effort by construction: a socket may close on its own
//! between listing and teardown, the platform may expose no such control, or a
//! single row may be refused while the rest succeed. None of that is fatal —
//! the worst case is the old behaviour, an application waiting on a dead
//! socket, so callers log the outcome and carry on.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Mutex;

use nrr_shared::ip_block::IpBlock;

/// What one teardown pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StaleFlowSweep {
    /// Connections found inside the range.
    pub found: usize,
    /// Of those, the ones the OS agreed to tear down.
    pub torn_down: usize,
}

impl StaleFlowSweep {
    /// Nothing was in range — the common case on a clean start.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.found == 0
    }
}

/// One established TCP connection and the user it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishedFlow {
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    /// The owning user in the stored principal form (`S-1-5-21-…`,
    /// `unix:uid:<n>`). `None` when the owner could not be resolved — the
    /// process exited, or the OS refused to say.
    pub owner: Option<String>,
    /// The owning process, when the OS says so.
    pub pid: Option<u32>,
    /// File name of that process's image, resolved while it was still alive.
    pub image: Option<String>,
}

/// The remote addresses one listing asks about: single hosts and whole
/// networks, read from one pass over the connection table.
///
/// A network rule names every address inside it, so a flow to any of them sits
/// behind the rule. Only IPv4 networks can hold a listed flow; an IPv6 block
/// matches nothing here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowTargets {
    hosts: Vec<Ipv4Addr>,
    networks: Vec<IpBlock>,
}

impl FlowTargets {
    #[must_use]
    pub fn new(hosts: Vec<Ipv4Addr>, networks: Vec<IpBlock>) -> Self {
        Self { hosts, networks }
    }

    #[must_use]
    pub fn hosts(&self) -> &[Ipv4Addr] {
        &self.hosts
    }

    #[must_use]
    pub fn networks(&self) -> &[IpBlock] {
        &self.networks
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.networks.is_empty()
    }

    /// The membership test a platform runs per table row, built once.
    #[must_use]
    pub fn matcher(&self) -> FlowTargetMatcher<'_> {
        FlowTargetMatcher {
            hosts: self.hosts.iter().copied().collect(),
            networks: &self.networks,
        }
    }
}

/// [`FlowTargets`] prepared for a per-row membership test.
#[derive(Debug)]
pub struct FlowTargetMatcher<'a> {
    hosts: HashSet<Ipv4Addr>,
    networks: &'a [IpBlock],
}

impl FlowTargetMatcher<'_> {
    /// Is `remote` one of the hosts, or inside one of the networks?
    #[must_use]
    pub fn matches(&self, remote: Ipv4Addr) -> bool {
        self.hosts.contains(&remote)
            || self
                .networks
                .iter()
                .any(|net| net.contains(IpAddr::V4(remote)))
    }
}

/// Tear down established TCP connections aimed at a range of addresses.
pub trait StaleFlowReset: Send + Sync {
    /// Tear down every established TCP connection whose REMOTE address falls
    /// inside `base`/`prefix_len`, whoever owns it. Returns what the pass found
    /// and closed. Only for a range no user's traffic can legitimately reach,
    /// like the fake-IP pool; a real destination goes through
    /// [`Self::established_flows_to`] so the caller can decide per owner.
    ///
    /// Called once as the stack comes up, so it may read the whole connection
    /// table, but it must not block for long: a slow sweep delays the moment
    /// policy starts being enforced.
    fn reset_flows_to(&self, base: Ipv4Addr, prefix_len: u8) -> StaleFlowSweep;

    /// Established TCP connections to any of `targets`, each with its owner.
    /// [`Self::established_flows_matching`] over hosts only.
    fn established_flows_to(&self, targets: &[Ipv4Addr]) -> Vec<EstablishedFlow> {
        self.established_flows_matching(&FlowTargets::new(targets.to_vec(), Vec::new()))
    }

    /// Established TCP connections to any host or into any network of
    /// `targets`, each with its owner, from one read of the connection table.
    /// Lets a caller decide per connection instead of per address, when one
    /// address serves several users. The default lists nothing, so a platform
    /// without the mechanism tears nothing down.
    fn established_flows_matching(&self, _targets: &FlowTargets) -> Vec<EstablishedFlow> {
        Vec::new()
    }

    /// Tear down exactly `flows`, as listed by [`Self::established_flows_matching`].
    /// Returns how many the OS agreed to close.
    fn reset_established(&self, _flows: &[EstablishedFlow]) -> usize {
        0
    }
}

/// The default: tears nothing down. Used on platforms with no connection-table
/// control wired, and as the inert default so the stack comes up unchanged when
/// the sweep is not configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopStaleFlowReset;

impl StaleFlowReset for NoopStaleFlowReset {
    fn reset_flows_to(&self, _base: Ipv4Addr, _prefix_len: u8) -> StaleFlowSweep {
        StaleFlowSweep::default()
    }
}

/// Test double: reports a fixed sweep and records the ranges it was asked
/// about, so a test can prove the stack swept the pool exactly once.
#[derive(Debug, Default)]
pub struct MockStaleFlowReset {
    inner: Mutex<MockInner>,
}

#[derive(Debug, Default)]
struct MockInner {
    calls: Vec<(Ipv4Addr, u8)>,
    queried: Vec<Ipv4Addr>,
    queried_networks: Vec<IpBlock>,
    answer: StaleFlowSweep,
    flows: Vec<EstablishedFlow>,
    reset: Vec<EstablishedFlow>,
}

impl MockStaleFlowReset {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set what the next sweeps report.
    pub fn set_answer(&self, answer: StaleFlowSweep) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).answer = answer;
    }

    /// Ranges this double was asked to sweep, in call order.
    #[must_use]
    pub fn calls(&self) -> Vec<(Ipv4Addr, u8)> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .calls
            .clone()
    }

    /// Every address [`StaleFlowReset::established_flows_to`] was asked about,
    /// in call order.
    #[must_use]
    pub fn queried(&self) -> Vec<Ipv4Addr> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .queried
            .clone()
    }

    /// Every network a listing was asked about, in call order.
    #[must_use]
    pub fn queried_networks(&self) -> Vec<IpBlock> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .queried_networks
            .clone()
    }

    /// The connection table [`StaleFlowReset::established_flows_to`] reads.
    pub fn set_flows(&self, flows: Vec<EstablishedFlow>) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).flows = flows;
    }

    /// Every connection this double was asked to tear down, in call order.
    #[must_use]
    pub fn reset_flows(&self) -> Vec<EstablishedFlow> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .reset
            .clone()
    }
}

impl StaleFlowReset for MockStaleFlowReset {
    fn reset_flows_to(&self, base: Ipv4Addr, prefix_len: u8) -> StaleFlowSweep {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.calls.push((base, prefix_len));
        inner.answer
    }

    fn established_flows_matching(&self, targets: &FlowTargets) -> Vec<EstablishedFlow> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.queried.extend_from_slice(targets.hosts());
        inner.queried_networks.extend_from_slice(targets.networks());
        let matcher = targets.matcher();
        inner
            .flows
            .iter()
            .filter(|flow| matcher.matches(*flow.remote.ip()))
            .cloned()
            .collect()
    }

    fn reset_established(&self, flows: &[EstablishedFlow]) -> usize {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.reset.extend_from_slice(flows);
        flows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POOL: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0);

    #[test]
    fn noop_tears_nothing_down() {
        let sweep = NoopStaleFlowReset.reset_flows_to(POOL, 15);
        assert_eq!(sweep, StaleFlowSweep::default());
        assert!(sweep.is_empty());
    }

    #[test]
    fn mock_records_the_range_and_reports_its_answer() {
        let mock = MockStaleFlowReset::new();
        mock.set_answer(StaleFlowSweep {
            found: 8,
            torn_down: 7,
        });

        let sweep = mock.reset_flows_to(POOL, 15);

        assert_eq!(sweep.found, 8);
        assert_eq!(sweep.torn_down, 7);
        assert!(!sweep.is_empty());
        assert_eq!(mock.calls(), vec![(POOL, 15)]);
    }

    #[test]
    fn noop_lists_and_resets_nothing() {
        assert!(NoopStaleFlowReset.established_flows_to(&[POOL]).is_empty());
        let flow = EstablishedFlow {
            local: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 50_000),
            remote: SocketAddrV4::new(POOL, 443),
            owner: None,
            pid: None,
            image: None,
        };
        assert_eq!(NoopStaleFlowReset.reset_established(&[flow]), 0);
    }

    #[test]
    fn mock_lists_only_flows_to_the_asked_addresses() {
        let mock = MockStaleFlowReset::new();
        let to = |ip: Ipv4Addr| EstablishedFlow {
            local: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 50_000),
            remote: SocketAddrV4::new(ip, 443),
            owner: Some("S-1-5-21-1-2-3-1001".into()),
            pid: None,
            image: None,
        };
        let wanted = Ipv4Addr::new(203, 0, 113, 1);
        mock.set_flows(vec![to(wanted), to(Ipv4Addr::new(203, 0, 113, 2))]);

        let listed = mock.established_flows_to(&[wanted]);

        assert_eq!(listed, vec![to(wanted)]);
        assert_eq!(mock.queried(), vec![wanted]);
        assert_eq!(mock.reset_established(&listed), 1);
        assert_eq!(mock.reset_flows(), listed);
    }

    #[test]
    fn a_network_target_matches_every_address_inside_it_and_nothing_outside() {
        let net = IpBlock::parse("203.0.113.0/28").expect("test network");
        let targets = FlowTargets::new(vec![Ipv4Addr::new(198, 51, 100, 7)], vec![net]);
        let matcher = targets.matcher();
        assert!(matcher.matches(Ipv4Addr::new(203, 0, 113, 0)));
        assert!(matcher.matches(Ipv4Addr::new(203, 0, 113, 15)));
        assert!(!matcher.matches(Ipv4Addr::new(203, 0, 113, 16)));
        assert!(matcher.matches(Ipv4Addr::new(198, 51, 100, 7)));
        assert!(!matcher.matches(Ipv4Addr::new(198, 51, 100, 8)));
    }

    #[test]
    fn an_ipv6_network_matches_no_listed_flow() {
        let v6 = IpBlock::parse("::/0").expect("test network");
        let targets = FlowTargets::new(Vec::new(), vec![v6]);
        assert!(!targets.matcher().matches(Ipv4Addr::new(203, 0, 113, 1)));
    }

    #[test]
    fn mock_lists_flows_into_an_asked_network() {
        let mock = MockStaleFlowReset::new();
        let to = |ip: Ipv4Addr| EstablishedFlow {
            local: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 50_000),
            remote: SocketAddrV4::new(ip, 443),
            owner: None,
            pid: None,
            image: None,
        };
        let inside = Ipv4Addr::new(203, 0, 113, 9);
        mock.set_flows(vec![to(inside), to(Ipv4Addr::new(198, 51, 100, 1))]);
        let net = IpBlock::parse("203.0.113.0/24").expect("test network");

        let listed = mock.established_flows_matching(&FlowTargets::new(Vec::new(), vec![net]));

        assert_eq!(listed, vec![to(inside)]);
        assert_eq!(mock.queried_networks(), vec![net]);
    }

    #[test]
    fn the_noop_lists_nothing_for_a_network_either() {
        let net = IpBlock::parse("203.0.113.0/24").expect("test network");
        assert!(NoopStaleFlowReset
            .established_flows_matching(&FlowTargets::new(Vec::new(), vec![net]))
            .is_empty());
    }
}
