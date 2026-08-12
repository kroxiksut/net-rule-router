//! What the relay does with each packet, and what it remembers between them.
//!
//! This is the neutral heart of fake-IP: given a parsed packet, decide whether
//! it belongs to us, which hostname its fake destination stands for, where that
//! hostname really lives, and over which route the flow must leave. Every input
//! is injected — the address map, the address resolver, the route policy — so
//! the decision is a pure function over them and every branch below is a test,
//! not a guess about live traffic.
//!
//! The bytes themselves are not moved here; that is the dialer's and the
//! userspace stack's job. Separating "decide" from "move" is what keeps the
//! decision reviewable: a wrong verdict here would send a user's traffic to the
//! wrong place, and that must be provable without a network card.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpScope, FakeIpVerdict};
use nrr_shared::RouteRole;

use super::dialer::UpstreamTarget;
use super::flow::{FlowKey, FlowProtocol, ParsedPacket};

/// Real addresses known for a hostname. Fed by the FQDN cache in production —
/// the relay never performs a DNS lookup itself, because the answer it would
/// get is the one fake-IP exists to bypass.
pub trait UpstreamAddressResolver: Send + Sync {
    /// Known real addresses for `hostname`, best first. Empty when nothing is
    /// cached — the flow is then dropped rather than guessed at.
    fn addresses_for(&self, hostname: &str) -> Vec<IpAddr>;
}

/// Which route a hostname's traffic must leave over — the existing rule engine
/// verdict, injected so the relay never re-implements policy.
pub trait RouteSelector: Send + Sync {
    fn route_for(&self, hostname: &str) -> RouteRole;
}

/// What to do with a packet addressed to the fake range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayDecision {
    /// Open (or continue) a flow to this upstream.
    Relay {
        hostname: String,
        target: UpstreamTarget,
    },
    /// Not addressed to the fake range at all — none of our business. The
    /// packet reached the adapter by accident (or the pool was reconfigured).
    NotFakeAddress,
    /// Inside the pool but no hostname holds that address any more: a stale
    /// binding whose slot was recycled. Dropping is the safe answer — the
    /// alternative would be forwarding a user's bytes to whatever host happens
    /// to hold the slot now.
    UnmappedFakeAddress,
    /// The hostname is known but no real address for it is: nothing can be
    /// dialled, so the flow fails closed instead of leaking to a guess.
    NoUpstreamAddress { hostname: String },
    /// Fake-IP is off, or this hostname is excluded from it — the flow should
    /// never have reached the adapter, so treat it as a misroute and drop.
    OutOfScope {
        hostname: String,
        reason: &'static str,
    },
}

impl RelayDecision {
    /// Short slug for logs and the explain surface.
    #[must_use]
    pub fn slug(&self) -> &'static str {
        match self {
            Self::Relay { .. } => "relay",
            Self::NotFakeAddress => "not-fake-address",
            Self::UnmappedFakeAddress => "unmapped-fake-address",
            Self::NoUpstreamAddress { .. } => "no-upstream-address",
            Self::OutOfScope { .. } => "out-of-scope",
        }
    }
}

/// One live flow the relay is carrying.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelaySession {
    pub key: FlowKey,
    pub hostname: String,
    pub target: UpstreamTarget,
    /// Monotonic tick (milliseconds) of the packet that opened the flow.
    pub opened_at: u64,
    /// Monotonic tick of the most recent packet seen in either direction.
    pub last_seen_at: u64,
}

/// Live flows, bounded so a scan or a flood cannot grow it without limit.
///
/// Eviction is by idleness, not by age: a long download is a legitimate flow
/// that must not be cut, while a flow with no packets for the idle window is
/// finished as far as anyone can tell.
#[derive(Debug)]
pub struct SessionTable {
    sessions: HashMap<FlowKey, RelaySession>,
    capacity: usize,
    idle_timeout_ms: u64,
}

/// Default ceiling on concurrent relayed flows. Generous for a desktop (a busy
/// browser opens low hundreds), low enough that a runaway cannot exhaust memory.
pub const DEFAULT_SESSION_CAPACITY: usize = 4096;
/// Default idle window before a flow is considered finished (2 minutes).
pub const DEFAULT_SESSION_IDLE_MS: u64 = 120_000;

impl Default for SessionTable {
    fn default() -> Self {
        Self::new(DEFAULT_SESSION_CAPACITY, DEFAULT_SESSION_IDLE_MS)
    }
}

impl SessionTable {
    #[must_use]
    pub fn new(capacity: usize, idle_timeout_ms: u64) -> Self {
        Self {
            sessions: HashMap::new(),
            capacity: capacity.max(1),
            idle_timeout_ms,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    #[must_use]
    pub fn get(&self, key: &FlowKey) -> Option<&RelaySession> {
        self.sessions.get(key)
    }

    /// Record a packet for an existing flow. Returns false when the flow is
    /// unknown — the caller then decides whether it may be opened.
    pub fn touch(&mut self, key: &FlowKey, now_ms: u64) -> bool {
        match self.sessions.get_mut(key) {
            Some(session) => {
                session.last_seen_at = now_ms;
                true
            }
            None => false,
        }
    }

    /// Open a flow, first expiring idle ones and, if still full, evicting the
    /// least recently used. Returns the session that was displaced, if any, so
    /// the caller can tear its upstream down.
    pub fn open(&mut self, session: RelaySession, now_ms: u64) -> Option<RelaySession> {
        self.expire_idle(now_ms);
        let mut displaced = None;
        if self.sessions.len() >= self.capacity {
            if let Some(victim) = self
                .sessions
                .values()
                .min_by_key(|s| (s.last_seen_at, s.key))
                .map(|s| s.key)
            {
                displaced = self.sessions.remove(&victim);
            }
        }
        self.sessions.insert(session.key, session);
        displaced
    }

    pub fn close(&mut self, key: &FlowKey) -> Option<RelaySession> {
        self.sessions.remove(key)
    }

    /// Drop every flow with no packet within the idle window; returns them so
    /// their upstream sockets can be closed.
    pub fn expire_idle(&mut self, now_ms: u64) -> Vec<RelaySession> {
        // Strictly older than the cutoff: a flow whose last packet lands exactly
        // on the boundary is still within its window. With `<=`, a flow opened
        // at tick 0 was expired by its own `open()` call (cutoff saturates to 0)
        // and never survived to carry a byte.
        let cutoff = now_ms.saturating_sub(self.idle_timeout_ms);
        let expired: Vec<FlowKey> = self
            .sessions
            .values()
            .filter(|s| s.last_seen_at < cutoff)
            .map(|s| s.key)
            .collect();
        expired
            .into_iter()
            .filter_map(|key| self.sessions.remove(&key))
            .collect()
    }

    /// Drop everything (feature switched off, adapter torn down).
    pub fn clear(&mut self) -> Vec<RelaySession> {
        self.sessions.drain().map(|(_, session)| session).collect()
    }
}

/// The relay's decision layer: everything needed to turn a packet into a
/// verdict, and the table of flows already decided.
pub struct RelayCore {
    allocator: Arc<Mutex<FakeIpAllocator>>,
    scope: FakeIpScope,
    resolver: Arc<dyn UpstreamAddressResolver>,
    routes: Arc<dyn RouteSelector>,
    sessions: SessionTable,
    /// Asked only for flows the route policy sends over the secondary: a
    /// confirmed VPN client's own traffic is the tunnel's transport and must
    /// never ride the tunnel. Inert by default — see
    /// [`super::vpn_client_bypass`].
    vpn_bypass: Arc<dyn super::vpn_client_bypass::VpnClientFlowBypass>,
    /// Hand a hostname with no cached address to the dialer to resolve, instead
    /// of refusing the flow. Off unless the composition wired a resolver into
    /// the dialer — otherwise the flow would only fail later and less clearly.
    resolve_at_dial: bool,
}

// The allocator mutex is shared with the resolver thread; poisoning it would
// mean a panic mid-update, and the relay must fail closed rather than keep
// routing on a half-written map — hence `expect` on the lock.
#[allow(clippy::expect_used)]
impl RelayCore {
    pub fn new(
        allocator: Arc<Mutex<FakeIpAllocator>>,
        scope: FakeIpScope,
        resolver: Arc<dyn UpstreamAddressResolver>,
        routes: Arc<dyn RouteSelector>,
    ) -> Self {
        Self {
            allocator,
            scope,
            resolver,
            routes,
            sessions: SessionTable::default(),
            vpn_bypass: Arc::new(super::vpn_client_bypass::NoVpnClientBypass),
            resolve_at_dial: false,
        }
    }

    /// Let a flow whose hostname has no cached address proceed, with the dialer
    /// resolving it. Only meaningful when the dialer has a name resolver wired;
    /// the composition root sets both together.
    #[must_use]
    pub fn with_dial_time_resolution(mut self, enabled: bool) -> Self {
        self.set_dial_time_resolution(enabled);
        self
    }

    /// Same, for a core already owned by the stack.
    pub fn set_dial_time_resolution(&mut self, enabled: bool) {
        self.resolve_at_dial = enabled;
    }

    #[must_use]
    pub fn with_session_table(mut self, sessions: SessionTable) -> Self {
        self.sessions = sessions;
        self
    }

    /// Wire the confirmed-VPN-client bypass. Builder-style; the default never
    /// bypasses, so every existing composition is byte-for-byte unchanged.
    #[must_use]
    pub fn with_vpn_client_bypass(
        mut self,
        bypass: Arc<dyn super::vpn_client_bypass::VpnClientFlowBypass>,
    ) -> Self {
        self.vpn_bypass = bypass;
        self
    }

    #[must_use]
    pub fn sessions(&self) -> &SessionTable {
        &self.sessions
    }

    /// Decide what to do with a packet, WITHOUT touching the session table —
    /// used by tests and by the explain surface to answer "what would happen to
    /// this flow?".
    #[must_use]
    pub fn decide(&self, packet: &ParsedPacket) -> RelayDecision {
        let destination = packet.key.destination;
        let hostname = {
            let mut allocator = self.allocator.lock().expect("fake-ip allocator mutex");
            if !allocator.is_fake_address(destination.ip()) {
                // In-tunnel rescue: a VPN client that enumerates
                // TUN adapters can bind its in-tunnel control socket to OUR
                // adapter instead of its own (two wintun devices look alike),
                // so its API/status calls (private addresses like 10.117.0.1)
                // would otherwise land here and die with a reset — the client
                // then shows no external IP and no session stats. A private
                // destination can only mean "meant for the tunnel", so carry
                // it literally over the SECONDARY link: the dialer's source
                // policy already refuses when the secondary is unresolved,
                // and no route ever points private ranges into this adapter,
                // so the rescue cannot loop back into itself.
                if let std::net::IpAddr::V4(v4) = destination.ip() {
                    if is_private_or_cgnat_v4(v4) {
                        let literal = v4.to_string();
                        return RelayDecision::Relay {
                            target: UpstreamTarget::at(
                                literal.clone(),
                                destination,
                                RouteRole::Secondary,
                            ),
                            hostname: literal,
                        };
                    }
                }
                return RelayDecision::NotFakeAddress;
            }
            match allocator.domain_for_ip(destination.ip()) {
                Some(hostname) => hostname,
                None => return RelayDecision::UnmappedFakeAddress,
            }
        };

        // The scope check is a consistency guard, not the primary gate: a
        // hostname only holds a fake address because the resolver decided it
        // was in scope. If the two ever disagree — policy changed while a flow
        // was live — the newer answer wins and the flow is dropped rather than
        // silently carried under the old policy.
        if let FakeIpVerdict::RealIp(reason) = self.scope.decide(&hostname, None) {
            return RelayDecision::OutOfScope {
                hostname,
                reason: real_ip_reason_slug(reason),
            };
        }

        let cached = self
            .resolver
            .addresses_for(&hostname)
            .into_iter()
            .find(|ip| {
                // Keep the address family the application used: an app that opened
                // an IPv4 socket cannot be handed an IPv6 upstream.
                ip.is_ipv4() == destination.is_ipv4()
            });
        // Nothing cached is not the same as nowhere to go: the name is the
        // durable fact, the address is a lookup nobody has performed yet. With
        // dial-time resolution the flow proceeds and the dialer finds out; the
        // poll loop must not, which is why the lookup is not attempted here.
        if cached.is_none() && !self.resolve_at_dial {
            return RelayDecision::NoUpstreamAddress { hostname };
        }

        let mut route = self.routes.route_for(&hostname);
        // A confirmed VPN client's own flow leaves over the PRIMARY link. Its
        // traffic IS the tunnel's transport, so carrying it over the secondary
        // routes the tunnel through itself: while the adapter is coming up the
        // dialer refuses the dial (it would otherwise leak via the primary) and
        // the client's own probes fail on every reconnect. The lookup is skipped
        // entirely unless the secondary was selected — the override cannot
        // change a flow that already leaves over the primary — and unless the
        // user has actually confirmed a client (see `vpn_client_bypass`).
        if route == RouteRole::Secondary
            && self
                .vpn_bypass
                .owned_by_confirmed_client(packet.key.source, destination)
        {
            route = RouteRole::Primary;
        }
        RelayDecision::Relay {
            target: UpstreamTarget {
                hostname: hostname.clone(),
                address: cached.map(|ip| SocketAddr::new(ip, destination.port())),
                port: destination.port(),
                route,
            },
            hostname,
        }
    }

    /// Decide and update the flow table in one step — the packet-loop entry
    /// point. Returns the decision plus whether this packet opened a new flow.
    pub fn admit(&mut self, packet: &ParsedPacket, now_ms: u64) -> (RelayDecision, bool) {
        if self.sessions.touch(&packet.key, now_ms) {
            // Mid-flow packet: the decision was made when the flow opened and
            // must not be revisited per packet — re-deciding would let a policy
            // change mid-download silently redirect an open connection.
            let session = self
                .sessions
                .get(&packet.key)
                .expect("session was just touched");
            return (
                RelayDecision::Relay {
                    hostname: session.hostname.clone(),
                    target: session.target.clone(),
                },
                false,
            );
        }

        // An unknown TCP flow that is not a SYN is a stray segment of a
        // connection we do not carry (a retransmit after eviction, or a scan).
        if packet.key.protocol == FlowProtocol::Tcp && !packet.is_connection_open {
            return (RelayDecision::UnmappedFakeAddress, false);
        }

        let decision = self.decide(packet);
        if let RelayDecision::Relay { hostname, target } = &decision {
            self.sessions.open(
                RelaySession {
                    key: packet.key,
                    hostname: hostname.clone(),
                    target: target.clone(),
                    opened_at: now_ms,
                    last_seen_at: now_ms,
                },
                now_ms,
            );
            return (decision, true);
        }
        (decision, false)
    }

    pub fn close(&mut self, key: &FlowKey) -> Option<RelaySession> {
        self.sessions.close(key)
    }

    pub fn expire_idle(&mut self, now_ms: u64) -> Vec<RelaySession> {
        self.sessions.expire_idle(now_ms)
    }
}

/// Private (RFC 1918) or CGNAT (RFC 6598) IPv4 — the only destinations the
/// in-tunnel rescue carries. Consumer VPN control planes live in these ranges;
/// anything public that reaches the relay adapter without a fake binding stays
/// a misroute and is refused as before.
fn is_private_or_cgnat_v4(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private() || (o[0] == 100 && (64..128).contains(&o[1]))
}

fn real_ip_reason_slug(reason: nrr_platform_api::fake_ip::RealIpReason) -> &'static str {
    use nrr_platform_api::fake_ip::RealIpReason;
    match reason {
        RealIpReason::FeatureDisabled => "feature-disabled",
        RealIpReason::ExcludedAppGroup => "excluded-app-group",
        RealIpReason::ExcludedHost => "excluded-host",
        RealIpReason::LiteralAddress => "literal-address",
        RealIpReason::NonRoutableName => "non-routable-name",
    }
}

/// Test double: a fixed hostname → addresses map.
#[derive(Debug, Default, Clone)]
pub struct StaticUpstreamResolver {
    addresses: HashMap<String, Vec<IpAddr>>,
}

impl StaticUpstreamResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, hostname: &str, addresses: &[IpAddr]) -> Self {
        self.addresses
            .insert(hostname.to_ascii_lowercase(), addresses.to_vec());
        self
    }
}

impl UpstreamAddressResolver for StaticUpstreamResolver {
    fn addresses_for(&self, hostname: &str) -> Vec<IpAddr> {
        self.addresses
            .get(&hostname.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }
}

/// Test double / degraded default: every hostname takes one fixed route.
#[derive(Debug, Clone, Copy)]
pub struct FixedRouteSelector(pub RouteRole);

impl RouteSelector for FixedRouteSelector {
    fn route_for(&self, _hostname: &str) -> RouteRole {
        self.0
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::fake_ip::flow::FlowProtocol;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("address")
    }

    fn packet(destination: SocketAddr, opens: bool) -> ParsedPacket {
        ParsedPacket {
            key: FlowKey {
                protocol: FlowProtocol::Tcp,
                source: "10.0.0.2:51000".parse().expect("source"),
                destination,
            },
            is_connection_open: opens,
            payload_offset: 40,
        }
    }

    /// Allocator holding one binding, plus the fake address it handed out.
    fn allocator_with(hostname: &str) -> (Arc<Mutex<FakeIpAllocator>>, IpAddr) {
        let mut allocator = FakeIpAllocator::default();
        let binding = allocator.allocate(hostname).expect("allocate");
        (Arc::new(Mutex::new(allocator)), IpAddr::V4(binding.v4))
    }

    fn core(
        allocator: Arc<Mutex<FakeIpAllocator>>,
        resolver: StaticUpstreamResolver,
        route: RouteRole,
    ) -> RelayCore {
        RelayCore::new(
            allocator,
            FakeIpScope::enabled(Vec::<String>::new()),
            Arc::new(resolver),
            Arc::new(FixedRouteSelector(route)),
        )
    }

    #[test]
    fn a_mapped_fake_address_relays_to_the_real_host_on_its_route() {
        let (allocator, fake) = allocator_with("chatgpt.com");
        let resolver = StaticUpstreamResolver::new().with("chatgpt.com", &[ip("104.18.32.47")]);
        let relay = core(allocator, resolver, RouteRole::Secondary);

        let decision = relay.decide(&packet(SocketAddr::new(fake, 443), true));
        match decision {
            RelayDecision::Relay { hostname, target } => {
                assert_eq!(hostname, "chatgpt.com");
                assert_eq!(target.address, "104.18.32.47:443".parse().ok());
                assert_eq!(target.route, RouteRole::Secondary);
            }
            other => panic!("expected a relay decision, got {other:?}"),
        }
    }

    #[test]
    fn an_uncached_host_is_refused_by_default_and_carried_with_dial_time_resolution() {
        // Default: nothing known, nothing dialled � the historical behaviour.
        let (allocator, fake) = allocator_with("late.example");
        let relay = core(
            Arc::clone(&allocator),
            StaticUpstreamResolver::new(),
            RouteRole::Secondary,
        );
        assert_eq!(
            relay.decide(&packet(SocketAddr::new(fake, 443), true)),
            RelayDecision::NoUpstreamAddress {
                hostname: "late.example".to_string()
            }
        );

        // With dial-time resolution the flow is carried and the target says
        // "find out where this name lives" instead of naming an address.
        let relay = core(
            allocator,
            StaticUpstreamResolver::new(),
            RouteRole::Secondary,
        )
        .with_dial_time_resolution(true);
        match relay.decide(&packet(SocketAddr::new(fake, 8443), true)) {
            RelayDecision::Relay { hostname, target } => {
                assert_eq!(hostname, "late.example");
                assert_eq!(target.address, None);
                assert_eq!(target.port, 8443, "the port the client asked for");
                assert_eq!(target.route, RouteRole::Secondary);
            }
            other => panic!("expected the flow to be carried, got {other:?}"),
        }
    }

    #[test]
    fn traffic_to_a_real_address_is_not_ours() {
        let (allocator, _) = allocator_with("chatgpt.com");
        let relay = core(allocator, StaticUpstreamResolver::new(), RouteRole::Primary);
        let decision = relay.decide(&packet("142.250.74.78:443".parse().expect("addr"), true));
        assert_eq!(decision, RelayDecision::NotFakeAddress);
    }

    #[test]
    fn a_private_destination_is_rescued_over_the_secondary() {
        // A VPN client bound its in-tunnel API socket to our adapter by
        // mistake — the flow must be carried literally over the secondary
        // link, not reset.
        let (allocator, _) = allocator_with("chatgpt.com");
        let relay = core(allocator, StaticUpstreamResolver::new(), RouteRole::Primary);
        for destination in ["10.117.0.1:80", "192.168.77.1:443", "100.64.0.1:80"] {
            let decision = relay.decide(&packet(destination.parse().expect("addr"), true));
            match decision {
                RelayDecision::Relay { hostname, target } => {
                    let expected: SocketAddr = destination.parse().expect("addr");
                    assert_eq!(hostname, expected.ip().to_string());
                    assert_eq!(target.address, Some(expected), "carried literally");
                    assert_eq!(
                        target.route,
                        RouteRole::Secondary,
                        "in-tunnel traffic only ever leaves in-tunnel"
                    );
                }
                other => panic!("expected an in-tunnel rescue for {destination}, got {other:?}"),
            }
        }
        // Public non-pool addresses stay a refused misroute (previous test),
        // and CGNAT boundaries hold: 100.128.0.0 is NOT CGNAT space.
        assert_eq!(
            relay.decide(&packet("100.128.0.1:80".parse().expect("addr"), true)),
            RelayDecision::NotFakeAddress
        );
    }

    /// Bypass double: reports every flow as owned by a confirmed VPN client.
    struct AlwaysConfirmedClient;
    impl crate::fake_ip::vpn_client_bypass::VpnClientFlowBypass for AlwaysConfirmedClient {
        fn owned_by_confirmed_client(&self, _client: SocketAddr, _fake: SocketAddr) -> bool {
            true
        }
    }

    /// Bypass double that fails the test if it is ever consulted.
    struct NeverAsked;
    impl crate::fake_ip::vpn_client_bypass::VpnClientFlowBypass for NeverAsked {
        fn owned_by_confirmed_client(&self, _client: SocketAddr, _fake: SocketAddr) -> bool {
            panic!("the bypass must not be consulted for a primary-routed flow");
        }
    }

    #[test]
    fn a_confirmed_vpn_clients_flow_leaves_over_the_primary() {
        // The host is routed to the secondary, but this flow belongs to the
        // client that ESTABLISHES the secondary — sending it through the tunnel
        // it is bringing up is the loop that broke its external-address probe.
        let (allocator, fake) = allocator_with("check.example");
        let resolver = StaticUpstreamResolver::new().with("check.example", &[ip("203.0.113.9")]);
        let relay = core(allocator, resolver, RouteRole::Secondary)
            .with_vpn_client_bypass(Arc::new(AlwaysConfirmedClient));

        match relay.decide(&packet(SocketAddr::new(fake, 443), true)) {
            RelayDecision::Relay { target, .. } => {
                assert_eq!(target.route, RouteRole::Primary);
                assert_eq!(target.address, "203.0.113.9:443".parse().ok());
            }
            other => panic!("expected a relay decision, got {other:?}"),
        }
    }

    #[test]
    fn an_ordinary_flow_keeps_its_secondary_route() {
        let (allocator, fake) = allocator_with("check.example");
        let resolver = StaticUpstreamResolver::new().with("check.example", &[ip("203.0.113.9")]);
        // Default (inert) bypass — the same composition every other test uses.
        let relay = core(allocator, resolver, RouteRole::Secondary);
        match relay.decide(&packet(SocketAddr::new(fake, 443), true)) {
            RelayDecision::Relay { target, .. } => {
                assert_eq!(target.route, RouteRole::Secondary);
            }
            other => panic!("expected a relay decision, got {other:?}"),
        }
    }

    #[test]
    fn a_primary_routed_flow_never_pays_for_an_owner_lookup() {
        let (allocator, fake) = allocator_with("example.com");
        let resolver = StaticUpstreamResolver::new().with("example.com", &[ip("93.184.216.34")]);
        let relay = core(allocator, resolver, RouteRole::Primary)
            .with_vpn_client_bypass(Arc::new(NeverAsked));
        assert!(matches!(
            relay.decide(&packet(SocketAddr::new(fake, 443), true)),
            RelayDecision::Relay { .. }
        ));
    }

    #[test]
    fn a_recycled_fake_address_is_dropped_not_guessed() {
        let (allocator, _) = allocator_with("chatgpt.com");
        let relay = core(allocator, StaticUpstreamResolver::new(), RouteRole::Primary);
        // Inside the pool, but no hostname holds it.
        let stale = SocketAddr::new(ip("198.18.9.9"), 443);
        assert_eq!(
            relay.decide(&packet(stale, true)),
            RelayDecision::UnmappedFakeAddress
        );
    }

    #[test]
    fn a_hostname_with_no_known_address_fails_closed() {
        let (allocator, fake) = allocator_with("chatgpt.com");
        let relay = core(allocator, StaticUpstreamResolver::new(), RouteRole::Primary);
        assert_eq!(
            relay.decide(&packet(SocketAddr::new(fake, 443), true)),
            RelayDecision::NoUpstreamAddress {
                hostname: "chatgpt.com".to_string()
            }
        );
    }

    #[test]
    fn the_upstream_address_family_matches_what_the_application_opened() {
        let (allocator, fake) = allocator_with("example.com");
        // Only an IPv6 upstream is known, but the app dialled the v4 fake
        // address — there is nothing legitimate to connect to.
        let resolver = StaticUpstreamResolver::new().with("example.com", &[ip("2606:4700::1111")]);
        let relay = core(allocator, resolver, RouteRole::Primary);
        assert!(matches!(
            relay.decide(&packet(SocketAddr::new(fake, 443), true)),
            RelayDecision::NoUpstreamAddress { .. }
        ));
    }

    #[test]
    fn a_policy_change_that_excludes_the_host_stops_new_flows() {
        let (allocator, fake) = allocator_with("chatgpt.com");
        let resolver = StaticUpstreamResolver::new().with("chatgpt.com", &[ip("104.18.32.47")]);
        let relay = RelayCore::new(
            allocator,
            FakeIpScope::enabled(["chatgpt.com"]),
            Arc::new(resolver),
            Arc::new(FixedRouteSelector(RouteRole::Primary)),
        );
        match relay.decide(&packet(SocketAddr::new(fake, 443), true)) {
            RelayDecision::OutOfScope { hostname, reason } => {
                assert_eq!(hostname, "chatgpt.com");
                assert_eq!(reason, "excluded-host");
            }
            other => panic!("expected out-of-scope, got {other:?}"),
        }
    }

    #[test]
    fn an_open_flow_keeps_its_decision_when_policy_changes_mid_stream() {
        let (allocator, fake) = allocator_with("chatgpt.com");
        let resolver = StaticUpstreamResolver::new().with("chatgpt.com", &[ip("104.18.32.47")]);
        let mut relay = core(allocator, resolver, RouteRole::Secondary);
        let destination = SocketAddr::new(fake, 443);

        let (opened, is_new) = relay.admit(&packet(destination, true), 1_000);
        assert!(is_new);
        assert!(matches!(opened, RelayDecision::Relay { .. }));

        // Mid-flow data packet: same flow, no re-decision, not counted as new.
        let (continued, is_new) = relay.admit(&packet(destination, false), 1_500);
        assert!(!is_new);
        match continued {
            RelayDecision::Relay { target, .. } => {
                assert_eq!(target.route, RouteRole::Secondary)
            }
            other => panic!("expected the flow to continue, got {other:?}"),
        }
        assert_eq!(relay.sessions().len(), 1);
    }

    #[test]
    fn a_stray_segment_of_an_unknown_tcp_flow_is_dropped() {
        let (allocator, fake) = allocator_with("chatgpt.com");
        let resolver = StaticUpstreamResolver::new().with("chatgpt.com", &[ip("104.18.32.47")]);
        let mut relay = core(allocator, resolver, RouteRole::Primary);
        let (decision, is_new) = relay.admit(&packet(SocketAddr::new(fake, 443), false), 10);
        assert_eq!(decision, RelayDecision::UnmappedFakeAddress);
        assert!(!is_new);
        assert!(relay.sessions().is_empty());
    }

    #[test]
    fn idle_flows_expire_and_busy_ones_survive() {
        let mut table = SessionTable::new(16, 1_000);
        let make = |port: u16| RelaySession {
            key: FlowKey {
                protocol: FlowProtocol::Tcp,
                source: format!("10.0.0.2:{port}").parse().expect("source"),
                destination: "198.18.0.2:443".parse().expect("destination"),
            },
            hostname: "chatgpt.com".to_string(),
            target: UpstreamTarget::at(
                "chatgpt.com".to_string(),
                "104.18.32.47:443".parse().expect("addr"),
                RouteRole::Primary,
            ),
            opened_at: 0,
            last_seen_at: 0,
        };
        table.open(make(1), 0);
        table.open(make(2), 0);
        let busy = make(2).key;
        assert!(table.touch(&busy, 900));

        let expired = table.expire_idle(1_500);
        assert_eq!(expired.len(), 1, "only the untouched flow expires");
        assert!(table.get(&busy).is_some());
    }

    #[test]
    fn a_full_table_evicts_the_least_recently_used_flow() {
        let mut table = SessionTable::new(1, 60_000);
        let session = |port: u16| RelaySession {
            key: FlowKey {
                protocol: FlowProtocol::Tcp,
                source: format!("10.0.0.2:{port}").parse().expect("source"),
                destination: "198.18.0.2:443".parse().expect("destination"),
            },
            hostname: "chatgpt.com".to_string(),
            target: UpstreamTarget::at(
                "chatgpt.com".to_string(),
                "104.18.32.47:443".parse().expect("addr"),
                RouteRole::Primary,
            ),
            opened_at: 0,
            last_seen_at: 0,
        };
        assert!(table.open(session(1), 0).is_none());
        let displaced = table
            .open(session(2), 10)
            .expect("the first flow is displaced");
        assert_eq!(displaced.key.source.port(), 1);
        assert_eq!(table.len(), 1);
    }
}
