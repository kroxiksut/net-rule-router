//! What the relay does with each packet.
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

use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpScope, FakeIpVerdict, FlowTransport};
use nrr_shared::RouteRole;

/// One owner's book, read once and asked per hostname; `None` when blocked.
pub type BookRoute<'a> = Box<dyn Fn(&str) -> Option<RouteRole> + 'a>;

use super::dialer::UpstreamTarget;
use super::flow::ParsedPacket;

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
    /// The route the routing user's book gives `hostname`; `None` when that
    /// book blocks it. The relay's dial is the service's own traffic and
    /// passes the user's filters, so the block is honoured here or nowhere.
    fn route_for(&self, hostname: &str) -> Option<RouteRole>;

    /// The route `principal`'s own rule book gives `hostname`; `None` when
    /// that book blocks it.
    fn route_for_principal(&self, _principal: &str, hostname: &str) -> Option<RouteRole> {
        self.route_for(hostname)
    }

    /// Whether every rule of the routing user's book naming `hostname` is a
    /// public top-level zone (`nrr_domain::public_zone`).
    fn held_only_by_public_zone(&self, _hostname: &str) -> bool {
        false
    }

    /// [`Self::held_only_by_public_zone`] in `principal`'s own book.
    fn held_only_by_public_zone_for(&self, _principal: &str, hostname: &str) -> bool {
        self.held_only_by_public_zone(hostname)
    }

    /// A number that moves whenever a rule book may have changed. The stack
    /// re-decides every live flow when it moves, so a flow opened under the
    /// old book does not outlive it. Read once per poll step: cheap or never.
    fn policy_stamp(&self) -> u64 {
        0
    }

    /// [`Self::route_for`] (`owner` `None`) or [`Self::route_for_principal`]
    /// over a book read once, for asking about every live flow at a time.
    fn book_for(&self, owner: Option<&str>) -> BookRoute<'_> {
        let owner = owner.map(str::to_owned);
        Box::new(move |hostname| match owner.as_deref() {
            None => self.route_for(hostname),
            Some(principal) => self.route_for_principal(principal, hostname),
        })
    }
}

/// Whose flow this is, as far as carrying it goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlowOwner {
    /// The user the shared DNS answers were given for: the only one served,
    /// or a machine service account, which follows that user.
    RoutingUser,
    /// Another served user, whose own book and links the flow takes.
    Principal(String),
    /// Nobody the relay may carry it for.
    Refused(&'static str),
}

/// The routing principal captured alongside the flow-owner classification.
#[derive(Clone, Debug)]
pub struct FlowOwnerContext {
    pub owner: FlowOwner,
    pub routing_principal: Option<String>,
}

/// Who opened a relayed flow. The relay's dial is the service's own traffic
/// and passes every user's filters, so carrying another user's flow by the
/// routing user's rules would let one user's traffic leave by another's.
pub trait FlowOwners: Send + Sync {
    /// Classify against one routing-principal snapshot. Unknown means no VPN exemption.
    fn context_for(
        &self,
        client: SocketAddr,
        destination: SocketAddr,
        transport: Option<FlowTransport>,
    ) -> FlowOwnerContext {
        FlowOwnerContext {
            owner: self.owner_of(client, destination, transport),
            routing_principal: None,
        }
    }

    /// `transport` is `None` for traffic no socket table lists (an echo).
    fn owner_of(
        &self,
        client: SocketAddr,
        destination: SocketAddr,
        transport: Option<FlowTransport>,
    ) -> FlowOwner;

    /// Whether more than one user is served now, so the relay's flows are
    /// shared between them.
    fn several_served(&self) -> bool {
        false
    }
}

/// Why [`RelayCore::for_owner`] refused a flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerRefusal {
    pub hostname: String,
    pub reason: &'static str,
}

impl From<OwnerRefusal> for RelayDecision {
    fn from(refusal: OwnerRefusal) -> Self {
        Self::OwnerRefused {
            hostname: refusal.hostname,
            reason: refusal.reason,
        }
    }
}

/// One user's machine: every flow is the routing user's, at no cost.
#[derive(Debug, Default, Clone, Copy)]
pub struct RoutingUserOnly;

impl FlowOwners for RoutingUserOnly {
    fn owner_of(&self, _: SocketAddr, _: SocketAddr, _: Option<FlowTransport>) -> FlowOwner {
        FlowOwner::RoutingUser
    }
}

/// Could `ip` be a single host that owns a flow?
///
/// Excludes multicast, the limited broadcast and the unspecified address. The
/// pool's own network and broadcast addresses are excluded separately, by
/// [`FakeIpPoolConfig::holds_host`], because only the pool knows its prefix.
fn is_unicast_host(ip: IpAddr) -> bool {
    use nrr_domain::address_class::{classify, AddressClass};
    matches!(
        classify(ip),
        AddressClass::Routable | AddressClass::Loopback | AddressClass::LinkLocal
    )
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
    /// Not a flow at all: the destination is multicast, broadcast, or the
    /// pool's own network/broadcast address, so no endpoint owns it.
    ///
    /// Kept apart from every other refusal because it must NOT be answered.
    /// These are discovery datagrams — mDNS, LLMNR, NetBIOS, SSDP — and they
    /// are how the host resolves SHORT names when DNS does not. Refusing one
    /// does not fail a flow closed; it breaks name resolution on the link, and
    /// the symptom lands far away (a share or an RDP host that "does not
    /// exist"). The packet is simply not ours: ignore it.
    NotAFlow,
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
    /// The flow's owner could not be read, is not served, or blocks the host
    /// in their own book.
    OwnerRefused {
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
            Self::NotAFlow => "not-a-flow",
            Self::UnmappedFakeAddress => "unmapped-fake-address",
            Self::NoUpstreamAddress { .. } => "no-upstream-address",
            Self::OutOfScope { .. } => "out-of-scope",
            Self::OwnerRefused { .. } => "owner-refused",
        }
    }
}

/// Default idle window before a flow is considered finished (2 minutes).
/// Handed to smoltcp as the per-socket timeout by the stack, which is what
/// actually retires finished flows.
pub const DEFAULT_SESSION_IDLE_MS: u64 = 120_000;

/// The relay's decision layer: everything needed to turn a packet into a
/// verdict.
pub struct RelayCore {
    allocator: Arc<Mutex<FakeIpAllocator>>,
    scope: FakeIpScope,
    resolver: Arc<dyn UpstreamAddressResolver>,
    routes: Arc<dyn RouteSelector>,
    /// Asked only for flows the route policy sends over the secondary: a
    /// confirmed VPN client's own traffic is the tunnel's transport and must
    /// never ride the tunnel. Inert by default — see
    /// [`super::vpn_client_bypass`].
    vpn_bypass: Arc<dyn super::vpn_client_bypass::VpnClientFlowBypass>,
    owners: Arc<dyn FlowOwners>,
    /// Hand a hostname with no cached address to the dialer to resolve, instead
    /// of refusing the flow. Off unless the composition wired a resolver into
    /// the dialer — otherwise the flow would only fail later and less clearly.
    resolve_at_dial: bool,
}

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
            vpn_bypass: Arc::new(super::vpn_client_bypass::NoVpnClientBypass),
            owners: Arc::new(RoutingUserOnly),
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

    /// Read who owns each flow, for a machine serving several users.
    pub fn set_flow_owners(&mut self, owners: Arc<dyn FlowOwners>) {
        self.owners = owners;
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

    /// Decide what to do with a packet. Pure: the caller owns flow lifetime, so
    /// the explain surface can ask "what would happen to this flow?" without
    /// disturbing anything.
    #[must_use]
    pub fn decide(&self, packet: &ParsedPacket) -> RelayDecision {
        self.decide_endpoints(packet.key.source, packet.key.destination)
    }

    /// [`Self::decide`] for traffic with no ports — an ICMP echo is keyed on
    /// its addresses alone (pass port 0), and must leave the way a connection
    /// to the same name would.
    #[must_use]
    pub fn decide_endpoints(&self, _source: SocketAddr, destination: SocketAddr) -> RelayDecision {
        // Reject non-unicast before locking: these addresses name no relay endpoint.
        if !is_unicast_host(destination.ip()) {
            return RelayDecision::NotAFlow;
        }
        let hostname = {
            // Recover poison so one allocation failure cannot wedge every later flow.
            let mut allocator = self.allocator.lock().unwrap_or_else(|p| p.into_inner());
            // The pool's network and broadcast addresses are not endpoints either.
            if allocator.is_fake_address(destination.ip())
                && !allocator.holds_host(destination.ip())
            {
                return RelayDecision::NotAFlow;
            }
            if !allocator.is_fake_address(destination.ip()) {
                // Some clients bind private tunnel probes to our TUN by mistake.
                // Carry them only through Secondary; an unavailable tunnel still refuses.
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

        // A scope change invalidates outstanding fake answers; newer policy wins.
        if let FakeIpVerdict::RealIp(reason) = self.scope.decide(&hostname, None) {
            return RelayDecision::OutOfScope {
                hostname,
                reason: real_ip_reason_slug(reason),
            };
        }

        // The upstream must use the application's address family.
        let mut cached = self
            .resolver
            .addresses_for(&hostname)
            .into_iter()
            .filter(|ip| ip.is_ipv4() == destination.is_ipv4())
            .take(super::dialer::MAX_DIAL_ADDRESSES)
            .map(|ip| SocketAddr::new(ip, destination.port()));
        let address = cached.next();
        let fallbacks: Vec<SocketAddr> = cached.collect();
        // Uncached names resolve on dial workers, never the shared packet thread.
        if address.is_none() && !self.resolve_at_dial {
            return RelayDecision::NoUpstreamAddress { hostname };
        }

        // A host the routing user's book blocks is still decided: the flow may
        // be another served user's, whose own book `for_owner` asks.
        let book_route = self.routes.route_for(&hostname);
        let route = book_route.unwrap_or(RouteRole::Primary);
        RelayDecision::Relay {
            target: UpstreamTarget {
                hostname: hostname.clone(),
                address,
                fallbacks,
                port: destination.port(),
                route,
                book_route,
                owner: None,
                // Asked only of a tunnel flow: the one it constrains.
                held_only_by_public_zone: route == RouteRole::Secondary
                    && self.routes.held_only_by_public_zone(&hostname),
            },
            hostname,
        }
    }

    /// Authorize once, after the owner's book has chosen the route.
    fn unless_vpn_client(
        &self,
        route: RouteRole,
        source: SocketAddr,
        destination: SocketAddr,
        principal: &str,
        allow_service_owner: bool,
    ) -> RouteRole {
        if route == RouteRole::Secondary
            && self.vpn_bypass.owned_by_confirmed_client(
                source,
                destination,
                principal,
                allow_service_owner,
            )
        {
            RouteRole::Primary
        } else {
            route
        }
    }

    /// Bind authorization, book and egress to the same captured principal.
    pub fn for_owner(
        &self,
        mut target: UpstreamTarget,
        client: SocketAddr,
        destination: SocketAddr,
        transport: Option<FlowTransport>,
    ) -> Result<UpstreamTarget, OwnerRefusal> {
        let context = self.owners.context_for(client, destination, transport);
        let routing_user = matches!(context.owner, FlowOwner::RoutingUser);
        let principal = match context.owner {
            FlowOwner::RoutingUser => context.routing_principal,
            FlowOwner::Principal(principal) => Some(principal),
            FlowOwner::Refused(reason) => {
                return Err(OwnerRefusal {
                    hostname: target.hostname,
                    reason,
                })
            }
        };
        // Literal tunnel interiors stay on the tunnel, including for its own client.
        if target.hostname.parse::<IpAddr>().is_err() {
            let book_route = match principal.as_deref() {
                Some(principal) => self.routes.route_for_principal(principal, &target.hostname),
                None => target.book_route,
            };
            let Some(route) = book_route else {
                return Err(OwnerRefusal {
                    hostname: target.hostname,
                    reason: if routing_user {
                        "blocked-host"
                    } else {
                        "owner-blocks-host"
                    },
                });
            };
            target.route = route;
            target.book_route = Some(route);
            if transport == Some(FlowTransport::Tcp) {
                if let Some(principal) = principal.as_deref() {
                    target.route =
                        self.unless_vpn_client(route, client, destination, principal, routing_user);
                }
            }
            target.held_only_by_public_zone = target.route == RouteRole::Secondary
                && match principal.as_deref() {
                    Some(principal) => self
                        .routes
                        .held_only_by_public_zone_for(principal, &target.hostname),
                    None => self.routes.held_only_by_public_zone(&target.hostname),
                };
        }
        target.owner = principal;
        Ok(target)
    }

    /// See [`FlowOwners::several_served`].
    #[must_use]
    pub fn several_users_served(&self) -> bool {
        self.owners.several_served()
    }

    /// See [`RouteSelector::policy_stamp`].
    #[must_use]
    pub fn policy_stamp(&self) -> u64 {
        self.routes.policy_stamp()
    }
    /// The route the books give hostnames now — the routing user's (`owner`
    /// `None`) or that owner's, `None` when blocked — over one read of the
    /// book. Compared with a live flow's [`UpstreamTarget::book_route`]:
    /// before the VPN-client bypass, whose lookup is rate-limited and must
    /// not decide whether a flow is torn down.
    #[must_use]
    pub fn book_routes(&self, owner: Option<&str>) -> BookRoute<'_> {
        self.routes.book_for(owner)
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
    fn route_for(&self, _hostname: &str) -> Option<RouteRole> {
        Some(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_ip::flow::{FlowKey, FlowProtocol};

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

    /// The pool's own broadcast address is where the host sends NetBIOS name
    /// queries on this link. Treating it as a recycled binding answered a name
    /// lookup with a refusal, and the symptom surfaces far away — a host that
    /// «does not exist» when reached by short name.
    #[test]
    fn the_pools_broadcast_address_is_not_a_binding() {
        let (allocator, _) = allocator_with("assistant.example");
        let relay = core(
            allocator,
            StaticUpstreamResolver::new(),
            RouteRole::Secondary,
        );

        assert_eq!(
            relay.decide(&packet("198.19.255.255:137".parse().expect("addr"), false)),
            RelayDecision::NotAFlow,
            "the subnet broadcast is not a host in the pool"
        );
    }

    /// Discovery runs on multicast, and the answer to a multicast datagram is
    /// silence, not a refusal.
    #[test]
    fn multicast_and_broadcast_destinations_are_not_flows() {
        let (allocator, _) = allocator_with("assistant.example");
        let relay = core(
            allocator,
            StaticUpstreamResolver::new(),
            RouteRole::Secondary,
        );

        for dst in [
            "224.0.0.251:5353",
            "224.0.0.252:5355",
            "239.255.255.250:1900",
            "255.255.255.255:138",
            "[ff02::fb]:5353",
        ] {
            assert_eq!(
                relay.decide(&packet(dst.parse().expect("addr"), false)),
                RelayDecision::NotAFlow,
                "{dst} names no endpoint"
            );
        }
    }

    #[test]
    fn a_mapped_fake_address_relays_to_the_real_host_on_its_route() {
        let (allocator, fake) = allocator_with("assistant.example");
        let resolver =
            StaticUpstreamResolver::new().with("assistant.example", &[ip("203.0.113.140")]);
        let relay = core(allocator, resolver, RouteRole::Secondary);

        let decision = relay.decide(&packet(SocketAddr::new(fake, 443), true));
        match decision {
            RelayDecision::Relay { hostname, target } => {
                assert_eq!(hostname, "assistant.example");
                assert_eq!(target.address, "203.0.113.140:443".parse().ok());
                assert_eq!(target.route, RouteRole::Secondary);
            }
            other => panic!("expected a relay decision, got {other:?}"),
        }
    }

    /// The application holds one virtual address, so the host's other
    /// addresses reach the dial only through the target.
    #[test]
    fn the_hosts_other_addresses_of_the_same_family_ride_along_as_fallbacks() {
        let (allocator, fake) = allocator_with("assistant.example");
        let resolver = StaticUpstreamResolver::new().with(
            "assistant.example",
            &[
                ip("203.0.113.1"),
                ip("2001:db8::1"),
                ip("203.0.113.2"),
                ip("203.0.113.3"),
                ip("203.0.113.4"),
                ip("203.0.113.5"),
            ],
        );
        let relay = core(allocator, resolver, RouteRole::Primary);

        match relay.decide(&packet(SocketAddr::new(fake, 443), true)) {
            RelayDecision::Relay { target, .. } => {
                assert_eq!(target.address, "203.0.113.1:443".parse().ok());
                let fallbacks: Vec<SocketAddr> =
                    ["203.0.113.2:443", "203.0.113.3:443", "203.0.113.4:443"]
                        .iter()
                        .map(|a| a.parse().expect("address"))
                        .collect();
                assert_eq!(target.fallbacks, fallbacks, "same family, bounded");
            }
            other => panic!("expected a relay decision, got {other:?}"),
        }
    }

    #[test]
    fn an_uncached_host_is_refused_by_default_and_carried_with_dial_time_resolution() {
        // Default: nothing known, nothing dialled — the flow fails closed.
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
        let (allocator, _) = allocator_with("assistant.example");
        let relay = core(allocator, StaticUpstreamResolver::new(), RouteRole::Primary);
        let decision = relay.decide(&packet("203.0.113.78:443".parse().expect("addr"), true));
        assert_eq!(decision, RelayDecision::NotFakeAddress);
    }

    #[test]
    fn a_private_destination_is_rescued_over_the_secondary() {
        // A VPN client bound its in-tunnel API socket to our adapter by
        // mistake — the flow must be carried literally over the secondary
        // link, not reset.
        let (allocator, _) = allocator_with("assistant.example");
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
        fn owned_by_confirmed_client(
            &self,
            _client: SocketAddr,
            _fake: SocketAddr,
            _: &str,
            _: bool,
        ) -> bool {
            true
        }
    }

    /// Bypass double that fails the test if it is ever consulted.
    struct NeverAsked;
    impl crate::fake_ip::vpn_client_bypass::VpnClientFlowBypass for NeverAsked {
        fn owned_by_confirmed_client(
            &self,
            _client: SocketAddr,
            _fake: SocketAddr,
            _: &str,
            _: bool,
        ) -> bool {
            panic!("the bypass must not be consulted for a primary-routed flow");
        }
    }

    #[test]
    fn a_confirmed_vpn_clients_flow_leaves_over_the_primary() {
        // The tunnel's own transport must not depend on that tunnel being up.
        let (allocator, fake) = allocator_with("check.example");
        let resolver = StaticUpstreamResolver::new().with("check.example", &[ip("203.0.113.9")]);
        let mut relay = core(allocator, resolver, RouteRole::Secondary)
            .with_vpn_client_bypass(Arc::new(AlwaysConfirmedClient));
        relay.set_flow_owners(Arc::new(BootstrapFlowOwners(bootstrap_routing_context())));
        let request = packet(SocketAddr::new(fake, 443), true);
        match relay.decide(&request) {
            RelayDecision::Relay { target, .. } => {
                let target = relay
                    .for_owner(
                        target,
                        request.key.source,
                        request.key.destination,
                        Some(FlowTransport::Tcp),
                    )
                    .expect("carried");
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
        let resolver = StaticUpstreamResolver::new().with("example.com", &[ip("203.0.113.138")]);
        let mut relay = core(allocator, resolver, RouteRole::Primary)
            .with_vpn_client_bypass(Arc::new(NeverAsked));
        relay.set_flow_owners(Arc::new(BootstrapFlowOwners(bootstrap_routing_context())));
        let request = packet(SocketAddr::new(fake, 443), true);
        let RelayDecision::Relay { target, .. } = relay.decide(&request) else {
            panic!("the primary host is carried");
        };
        let target = relay
            .for_owner(
                target,
                request.key.source,
                request.key.destination,
                Some(FlowTransport::Tcp),
            )
            .expect("carried");
        assert_eq!(target.route, RouteRole::Primary);
    }

    #[test]
    fn a_recycled_fake_address_is_dropped_not_guessed() {
        let (allocator, _) = allocator_with("assistant.example");
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
        let (allocator, fake) = allocator_with("assistant.example");
        let relay = core(allocator, StaticUpstreamResolver::new(), RouteRole::Primary);
        assert_eq!(
            relay.decide(&packet(SocketAddr::new(fake, 443), true)),
            RelayDecision::NoUpstreamAddress {
                hostname: "assistant.example".to_string()
            }
        );
    }

    #[test]
    fn the_upstream_address_family_matches_what_the_application_opened() {
        let (allocator, fake) = allocator_with("example.com");
        // Only an IPv6 upstream is known, but the app dialled the v4 fake
        // address — there is nothing legitimate to connect to.
        let resolver = StaticUpstreamResolver::new().with("example.com", &[ip("2001:db8::1111")]);
        let relay = core(allocator, resolver, RouteRole::Primary);
        assert!(matches!(
            relay.decide(&packet(SocketAddr::new(fake, 443), true)),
            RelayDecision::NoUpstreamAddress { .. }
        ));
    }

    #[test]
    fn a_policy_change_that_excludes_the_host_stops_new_flows() {
        let (allocator, fake) = allocator_with("assistant.example");
        let resolver =
            StaticUpstreamResolver::new().with("assistant.example", &[ip("203.0.113.140")]);
        let relay = RelayCore::new(
            allocator,
            FakeIpScope::enabled(["assistant.example"]),
            Arc::new(resolver),
            Arc::new(FixedRouteSelector(RouteRole::Primary)),
        );
        match relay.decide(&packet(SocketAddr::new(fake, 443), true)) {
            RelayDecision::OutOfScope { hostname, reason } => {
                assert_eq!(hostname, "assistant.example");
                assert_eq!(reason, "excluded-host");
            }
            other => panic!("expected out-of-scope, got {other:?}"),
        }
    }

    /// Blocks every hostname in the routing user's book; "S-1-5-21-2" routes
    /// them over the secondary.
    struct RoutingUserBlocks;

    impl RouteSelector for RoutingUserBlocks {
        fn route_for(&self, _hostname: &str) -> Option<RouteRole> {
            None
        }

        fn route_for_principal(&self, principal: &str, _hostname: &str) -> Option<RouteRole> {
            (principal == "S-1-5-21-2").then_some(RouteRole::Secondary)
        }
    }

    /// A host the routing user's book blocks is refused even though its
    /// binding is still live: the relay's own dial passes their filters, so
    /// carrying it would reach the host the rule forbids. Another served
    /// user's flow is still carried by that user's own book.
    #[test]
    fn a_host_the_routing_users_book_blocks_is_refused_not_carried() {
        let (allocator, fake) = allocator_with("bank.example");
        let resolver = StaticUpstreamResolver::new().with("bank.example", &[ip("203.0.113.5")]);
        let mut relay = RelayCore::new(
            allocator,
            FakeIpScope::enabled(Vec::<String>::new()),
            Arc::new(resolver),
            Arc::new(RoutingUserBlocks),
        );
        let destination = SocketAddr::new(fake, 443);
        let decide = |relay: &RelayCore| match relay.decide(&packet(destination, true)) {
            RelayDecision::Relay { target, .. } => target,
            other => panic!("decided for the owner to judge, got {other:?}"),
        };
        let routing_user: SocketAddr = "10.0.0.2:51000".parse().expect("addr");

        let refusal = relay
            .for_owner(
                decide(&relay),
                routing_user,
                destination,
                Some(FlowTransport::Tcp),
            )
            .expect_err("the routing user's block holds");
        assert_eq!(refusal.reason, "blocked-host");
        assert_eq!(relay.book_routes(None)("bank.example"), None);

        relay.set_flow_owners(Arc::new(OwnersByPort));
        let other_user: SocketAddr = "10.0.0.2:50002".parse().expect("addr");
        let carried = relay
            .for_owner(
                decide(&relay),
                other_user,
                destination,
                Some(FlowTransport::Tcp),
            )
            .expect("another user's own book routes the host");
        assert_eq!(carried.route, RouteRole::Secondary);
        assert_eq!(carried.book_route, Some(RouteRole::Secondary));
    }

    /// The routing user's book holds every host by a public zone alone; the
    /// owner "S-1-5-21-2" names it narrowly.
    struct PublicZoneOnly;

    impl RouteSelector for PublicZoneOnly {
        fn route_for(&self, _hostname: &str) -> Option<RouteRole> {
            Some(RouteRole::Secondary)
        }

        fn held_only_by_public_zone(&self, _hostname: &str) -> bool {
            true
        }

        fn held_only_by_public_zone_for(&self, principal: &str, _hostname: &str) -> bool {
            principal != "S-1-5-21-2"
        }
    }

    /// The dialer keeps a public zone's private addresses out of the tunnel
    /// only if the flow tells it the host is held that way — by whichever
    /// user's book carries the flow.
    #[test]
    fn a_flow_to_a_public_zone_name_tells_the_dialer_so() {
        let (allocator, fake) = allocator_with("a1.attacker.ru");
        let mut relay = RelayCore::new(
            allocator,
            FakeIpScope::enabled(Vec::<String>::new()),
            Arc::new(StaticUpstreamResolver::new()),
            Arc::new(PublicZoneOnly),
        );
        relay.set_dial_time_resolution(true);
        let destination = SocketAddr::new(fake, 443);
        let decided = match relay.decide(&packet(destination, true)) {
            RelayDecision::Relay { target, .. } => target,
            other => panic!("expected a relay, got {other:?}"),
        };
        assert!(decided.held_only_by_public_zone);

        relay.set_flow_owners(Arc::new(OwnersByPort));
        let other_user: SocketAddr = "10.0.0.2:50002".parse().expect("addr");
        let carried = relay
            .for_owner(decided, other_user, destination, Some(FlowTransport::Tcp))
            .expect("carried");
        assert!(!carried.held_only_by_public_zone, "the owner named it");
    }

    /// Routes by whose book is asked: "S-1-5-21-2" sends the host over the
    /// secondary, "S-1-5-21-3" blocks it, the routing user takes the primary.
    struct PerUserRoutes;

    impl RouteSelector for PerUserRoutes {
        fn route_for(&self, _hostname: &str) -> Option<RouteRole> {
            Some(RouteRole::Primary)
        }

        fn route_for_principal(&self, principal: &str, _hostname: &str) -> Option<RouteRole> {
            match principal {
                "S-1-5-21-2" => Some(RouteRole::Secondary),
                _ => None,
            }
        }
    }

    struct OwnersByPort;

    struct VpnBootstrapOwner {
        identity: Option<(&'static str, &'static str)>,
        legacy_image: &'static str,
        legacy_principal: &'static str,
    }

    impl nrr_platform_api::FlowOwnerLookup for VpnBootstrapOwner {
        fn owner_identity(&self, _: SocketAddr, _: SocketAddr) -> Option<(String, String)> {
            self.identity.map(|(sid, path)| (sid.into(), path.into()))
        }

        fn owner_image_name(&self, _: SocketAddr, _: SocketAddr) -> Option<String> {
            Some(self.legacy_image.into())
        }

        fn owner_principal(
            &self,
            _: SocketAddr,
            _: SocketAddr,
            _: FlowTransport,
        ) -> Option<String> {
            Some(self.legacy_principal.into())
        }
    }

    const BOOTSTRAP_CLIENT: &str = r"C:\Program Files\ExampleVPN\client.exe";
    const BOOTSTRAP_PRINCIPAL: &str = "S-1-5-21-2";

    fn vpn_bootstrap_target(
        owner: VpnBootstrapOwner,
        confirmed_sid: Option<&str>,
        second_user: bool,
    ) -> UpstreamTarget {
        vpn_bootstrap_target_for_transport(owner, confirmed_sid, second_user, FlowTransport::Tcp)
    }

    fn vpn_bootstrap_target_for_transport(
        owner: VpnBootstrapOwner,
        confirmed_sid: Option<&str>,
        second_user: bool,
        transport: FlowTransport,
    ) -> UpstreamTarget {
        let context = FlowOwnerContext {
            owner: if second_user {
                FlowOwner::Principal(BOOTSTRAP_PRINCIPAL.into())
            } else {
                FlowOwner::RoutingUser
            },
            routing_principal: Some(
                if second_user {
                    "S-1-5-21-1"
                } else {
                    BOOTSTRAP_PRINCIPAL
                }
                .into(),
            ),
        };
        vpn_bootstrap_with_context(owner, confirmed_sid, transport, context, true, false)
    }

    struct BootstrapFlowOwners(FlowOwnerContext);

    impl FlowOwners for BootstrapFlowOwners {
        fn owner_of(&self, _: SocketAddr, _: SocketAddr, _: Option<FlowTransport>) -> FlowOwner {
            self.0.owner.clone()
        }

        fn context_for(
            &self,
            _: SocketAddr,
            _: SocketAddr,
            _: Option<FlowTransport>,
        ) -> FlowOwnerContext {
            self.0.clone()
        }
    }

    struct BootstrapChangedRoutingBook;

    impl RouteSelector for BootstrapChangedRoutingBook {
        fn route_for(&self, _: &str) -> Option<RouteRole> {
            Some(RouteRole::Primary)
        }

        fn route_for_principal(&self, _: &str, _: &str) -> Option<RouteRole> {
            Some(RouteRole::Secondary)
        }
    }

    fn vpn_bootstrap_with_context(
        owner: VpnBootstrapOwner,
        confirmed_sid: Option<&str>,
        transport: FlowTransport,
        context: FlowOwnerContext,
        protected_install: bool,
        changed_book: bool,
    ) -> UpstreamTarget {
        use crate::fake_ip::vpn_client_bypass::OwnerLookupVpnClientBypass;
        use crate::vpn_client_registry::ConfirmedVpnClients;

        let (allocator, fake) = allocator_with("check.example");
        let confirmed = Arc::new(ConfirmedVpnClients::new());
        if let Some(sid) = confirmed_sid {
            confirmed.publish(sid, &[BOOTSTRAP_CLIENT.into()]);
        }
        // A long interval makes duplicate probes fail deterministically, even on a busy host.
        let programs = nrr_platform_api::MockAppPathResolver::new();
        let programs = if protected_install {
            programs.with_protected_root(r"C:\Program Files")
        } else {
            programs
        };
        let bypass = OwnerLookupVpnClientBypass::new(Arc::new(owner), confirmed)
            .with_min_probe_interval(std::time::Duration::from_secs(3600))
            .with_service_programs(Arc::new(programs));
        let resolver = StaticUpstreamResolver::new().with("check.example", &[ip("203.0.113.9")]);
        let mut relay = core(allocator, resolver, RouteRole::Secondary)
            .with_vpn_client_bypass(Arc::new(bypass));
        relay.set_flow_owners(Arc::new(BootstrapFlowOwners(context)));
        if changed_book {
            relay.routes = Arc::new(BootstrapChangedRoutingBook);
        }
        let mut request = packet(SocketAddr::new(fake, 443), true);
        request.key.source.set_port(50002);
        if transport == FlowTransport::Udp {
            request.key.protocol = FlowProtocol::Udp;
        }
        let RelayDecision::Relay { target, .. } = relay.decide(&request) else {
            panic!("the known hostname must reach owner-specific routing");
        };
        relay
            .for_owner(
                target,
                request.key.source,
                request.key.destination,
                Some(transport),
            )
            .expect("a served user's permitted hostname")
    }

    fn bootstrap_owner(path: &'static str) -> VpnBootstrapOwner {
        VpnBootstrapOwner {
            identity: Some((BOOTSTRAP_PRINCIPAL, path)),
            legacy_image: "client.exe",
            legacy_principal: BOOTSTRAP_PRINCIPAL,
        }
    }

    #[test]
    fn vpn_bootstrap_second_users_confirmation_survives_owner_rerouting() {
        let target = vpn_bootstrap_target(
            bootstrap_owner(BOOTSTRAP_CLIENT),
            Some(BOOTSTRAP_PRINCIPAL),
            true,
        );
        assert_eq!(target.owner.as_deref(), Some(BOOTSTRAP_PRINCIPAL));
        assert_eq!(target.book_route, Some(RouteRole::Secondary));
        assert_eq!(
            target.route,
            RouteRole::Primary,
            "the second user's VPN must establish its tunnel over the main link"
        );
    }

    #[test]
    fn vpn_bootstrap_same_basename_in_another_folder_keeps_secondary() {
        let target = vpn_bootstrap_target(
            bootstrap_owner(r"C:\Users\test\Downloads\client.exe"),
            Some(BOOTSTRAP_PRINCIPAL),
            false,
        );
        assert_eq!(
            target.route,
            RouteRole::Secondary,
            "a file name is not authorization"
        );
    }

    #[test]
    fn vpn_bootstrap_another_users_confirmation_keeps_secondary() {
        let target =
            vpn_bootstrap_target(bootstrap_owner(BOOTSTRAP_CLIENT), Some("S-1-5-21-1"), false);
        assert_eq!(target.route, RouteRole::Secondary);
    }

    #[test]
    fn vpn_bootstrap_an_unconfirmed_client_keeps_secondary() {
        let target = vpn_bootstrap_target(bootstrap_owner(BOOTSTRAP_CLIENT), None, false);
        assert_eq!(target.route, RouteRole::Secondary);
    }

    #[test]
    fn vpn_bootstrap_unverified_identity_does_not_join_separate_process_reads() {
        let mut owner = bootstrap_owner(BOOTSTRAP_CLIENT);
        owner.identity = None;
        let target = vpn_bootstrap_target(owner, Some(BOOTSTRAP_PRINCIPAL), false);
        assert_eq!(
            target.route,
            RouteRole::Secondary,
            "independent image and SID reads do not authenticate one process"
        );
    }

    #[test]
    fn vpn_bootstrap_authenticated_identity_is_not_replaced_by_a_later_process() {
        let mut owner = bootstrap_owner(BOOTSTRAP_CLIENT);
        owner.legacy_image = "unrelated.exe";
        owner.legacy_principal = "S-1-5-21-1";
        let target = vpn_bootstrap_target(owner, Some(BOOTSTRAP_PRINCIPAL), false);
        assert_eq!(target.route, RouteRole::Primary);
    }

    #[test]
    fn vpn_bootstrap_udp_does_not_borrow_a_confirmed_tcp_sockets_identity() {
        let target = vpn_bootstrap_target_for_transport(
            bootstrap_owner(BOOTSTRAP_CLIENT),
            Some(BOOTSTRAP_PRINCIPAL),
            false,
            FlowTransport::Udp,
        );
        assert_eq!(
            target.route,
            RouteRole::Secondary,
            "a matching TCP tuple cannot authorize a datagram from another socket"
        );
    }

    fn bootstrap_service_owner(principal: &'static str) -> VpnBootstrapOwner {
        VpnBootstrapOwner {
            identity: Some((principal, BOOTSTRAP_CLIENT)),
            legacy_image: "client.exe",
            legacy_principal: principal,
        }
    }

    fn bootstrap_routing_context() -> FlowOwnerContext {
        FlowOwnerContext {
            owner: FlowOwner::RoutingUser,
            routing_principal: Some(BOOTSTRAP_PRINCIPAL.into()),
        }
    }

    #[test]
    fn vpn_bootstrap_protected_service_uses_only_its_routing_users_confirmation() {
        for service in ["S-1-5-18", "S-1-5-19", "S-1-5-20"] {
            let target = vpn_bootstrap_with_context(
                bootstrap_service_owner(service),
                Some(BOOTSTRAP_PRINCIPAL),
                FlowTransport::Tcp,
                bootstrap_routing_context(),
                true,
                false,
            );
            assert_eq!(
                target.route,
                RouteRole::Primary,
                "the user's confirmed system VPN must reconnect"
            );
            assert_eq!(target.owner.as_deref(), Some(BOOTSTRAP_PRINCIPAL));
            assert_eq!(target.book_route, Some(RouteRole::Secondary));
        }
    }

    #[test]
    fn vpn_bootstrap_service_does_not_use_another_users_confirmation() {
        let target = vpn_bootstrap_with_context(
            bootstrap_service_owner("S-1-5-18"),
            Some("S-1-5-21-1"),
            FlowTransport::Tcp,
            bootstrap_routing_context(),
            true,
            false,
        );
        assert_eq!(target.route, RouteRole::Secondary);
    }

    #[test]
    fn vpn_bootstrap_service_without_a_routing_principal_keeps_secondary() {
        let mut context = bootstrap_routing_context();
        context.routing_principal = None;
        let target = vpn_bootstrap_with_context(
            bootstrap_service_owner("S-1-5-18"),
            Some(BOOTSTRAP_PRINCIPAL),
            FlowTransport::Tcp,
            context,
            true,
            false,
        );
        assert_eq!(target.route, RouteRole::Secondary);
    }

    #[test]
    fn vpn_bootstrap_service_from_an_unprotected_install_keeps_secondary() {
        let target = vpn_bootstrap_with_context(
            bootstrap_service_owner("S-1-5-18"),
            Some(BOOTSTRAP_PRINCIPAL),
            FlowTransport::Tcp,
            bootstrap_routing_context(),
            false,
            false,
        );
        assert_eq!(target.route, RouteRole::Secondary);
    }

    #[test]
    fn vpn_bootstrap_service_cannot_borrow_a_nonrouting_principals_confirmation() {
        let context = FlowOwnerContext {
            owner: FlowOwner::Principal(BOOTSTRAP_PRINCIPAL.into()),
            routing_principal: Some("S-1-5-21-1".into()),
        };
        let target = vpn_bootstrap_with_context(
            bootstrap_service_owner("S-1-5-18"),
            Some(BOOTSTRAP_PRINCIPAL),
            FlowTransport::Tcp,
            context,
            true,
            false,
        );
        assert_eq!(target.route, RouteRole::Secondary);
    }

    #[test]
    fn vpn_bootstrap_service_with_another_image_path_keeps_secondary() {
        let mut owner = bootstrap_service_owner("S-1-5-18");
        owner.identity = Some(("S-1-5-18", r"C:\Program Files\Other\client.exe"));
        let target = vpn_bootstrap_with_context(
            owner,
            Some(BOOTSTRAP_PRINCIPAL),
            FlowTransport::Tcp,
            bootstrap_routing_context(),
            true,
            false,
        );
        assert_eq!(target.route, RouteRole::Secondary);
    }

    #[test]
    fn vpn_bootstrap_captured_routing_user_owns_the_book_and_the_service_grant() {
        let target = vpn_bootstrap_with_context(
            bootstrap_service_owner("S-1-5-18"),
            Some(BOOTSTRAP_PRINCIPAL),
            FlowTransport::Tcp,
            bootstrap_routing_context(),
            true,
            true,
        );
        assert_eq!(target.route, RouteRole::Primary);
        assert_eq!(
            target.book_route,
            Some(RouteRole::Secondary),
            "read the captured user's book"
        );
        assert_eq!(target.owner.as_deref(), Some(BOOTSTRAP_PRINCIPAL));
    }

    #[test]
    fn vpn_bootstrap_does_not_authorize_one_users_process_under_anothers_book() {
        let mut owner = bootstrap_owner(BOOTSTRAP_CLIENT);
        owner.identity = Some(("S-1-5-21-1", BOOTSTRAP_CLIENT));
        owner.legacy_principal = "S-1-5-21-1";
        let context = FlowOwnerContext {
            owner: FlowOwner::Principal(BOOTSTRAP_PRINCIPAL.into()),
            routing_principal: Some("S-1-5-21-1".into()),
        };
        let target = vpn_bootstrap_with_context(
            owner,
            Some("S-1-5-21-1"),
            FlowTransport::Tcp,
            context,
            true,
            false,
        );
        assert_eq!(target.route, RouteRole::Secondary);
    }

    impl FlowOwners for OwnersByPort {
        fn owner_of(
            &self,
            client: SocketAddr,
            _: SocketAddr,
            _: Option<FlowTransport>,
        ) -> FlowOwner {
            match client.port() {
                50001 => FlowOwner::RoutingUser,
                50002 => FlowOwner::Principal("S-1-5-21-2".into()),
                50003 => FlowOwner::Principal("S-1-5-21-3".into()),
                _ => FlowOwner::Refused("owner-unknown"),
            }
        }
    }

    /// Two users reach the same virtual address: each flow leaves by its own
    /// owner's book and links, one blocked in its owner's book is refused, and
    /// one nobody can be named for is refused, never carried by another's rules.
    #[test]
    fn each_users_flow_is_carried_by_that_users_own_book() {
        let (allocator, fake) = allocator_with("shared.example");
        let mut relay = RelayCore::new(
            allocator,
            FakeIpScope::enabled(Vec::<String>::new()),
            Arc::new(StaticUpstreamResolver::new().with("shared.example", &[ip("203.0.113.10")])),
            Arc::new(PerUserRoutes),
        );
        relay.set_flow_owners(Arc::new(OwnersByPort));
        let destination = SocketAddr::new(fake, 443);
        let RelayDecision::Relay { target, .. } = relay.decide(&packet(destination, true)) else {
            panic!("the routing user's decision relays the flow");
        };
        let client = |port: u16| SocketAddr::new(ip("10.0.0.2"), port);
        let carried = |port| {
            relay.for_owner(
                target.clone(),
                client(port),
                destination,
                Some(FlowTransport::Tcp),
            )
        };

        let routing = carried(50001).expect("the routing user's flow");
        assert_eq!((routing.route, routing.owner), (RouteRole::Primary, None));

        let other = carried(50002).expect("the second user's flow");
        assert_eq!(other.route, RouteRole::Secondary);
        assert_eq!(other.owner.as_deref(), Some("S-1-5-21-2"));

        assert!(matches!(carried(50003), Err(OwnerRefusal { .. })));
        assert!(matches!(carried(50009), Err(OwnerRefusal { .. })));
    }
}
