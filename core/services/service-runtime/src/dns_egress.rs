//! Where the service's own upstream DNS queries go out.
//!
//! By default they leave over the primary link and ask the address captured
//! from the primary connection's DHCP/adapter config — the provider's own
//! resolver. That is fine until the provider answers with a stub or a wrong
//! address for a name it dislikes: every downstream consumer (Mode-B resolver,
//! rule seeder, refresh) then caches a useless answer, and a browser that
//! resolves the name itself gets a different (real) address that no permit
//! covers.
//!
//! With the opt-in DNS-over-secondary setting the queries are instead sent to a
//! well-known public resolver, source-bound to the secondary (tunnel) adapter,
//! so the answers come back over the tunnel and the primary provider never sees
//! or shapes them.
//!
//! ## Availability over purity
//!
//! The policy falls back to the primary path whenever the secondary link has no
//! usable IPv4 source (tunnel down, still connecting, adapter unbound). Name
//! resolution failing outright would take the whole product down with it, so a
//! degraded-but-working answer wins; the caller can see which path was used in
//! the trace.
//!
//! The fallback is also PER QUERY: only the
//! first attempt of a query rides the tunnel; every retry goes to the caller's
//! own primary upstream. An adapter can hold its address while the tunnel
//! behind it is dead — the dead verdict has a whole hysteresis window of lag —
//! and during that lag a tunnel-only policy turns every resolution into a
//! guaranteed timeout. Worse, a VPN client needs working DNS to bring the
//! tunnel UP, so tunnel-only DNS deadlocks the very recovery it waits for.
//! One timed-out attempt is the price of purity; the retry must deliver.
//!
//! ## Source binding needs a route
//!
//! Binding a UDP socket to the tunnel's address is not by itself enough on
//! Windows: the route table still picks the outgoing interface by destination,
//! and a packet leaving the primary link with a tunnel source address is
//! spoofed traffic that the ISP drops. The route half of this feature —
//! `/32` routes for [`PUBLIC_DNS_SERVERS`] via the secondary — is emitted by
//! `route_codegen::dns_via_secondary_routes` and reconciled together with the
//! rule routes. This module owns only the socket-side decision.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Public resolvers used when DNS-over-secondary is on, in preference order.
///
/// Two independent operators, both anycast and reachable worldwide, so a single
/// operator outage does not take name resolution with it. They are queried over
/// plain UDP/53 through the tunnel — the tunnel is what provides confidentiality
/// here, so no DoH/DoT dependency is introduced.
pub const PUBLIC_DNS_SERVERS: &[Ipv4Addr] = &[
    Ipv4Addr::new(1, 1, 1, 1),
    Ipv4Addr::new(8, 8, 8, 8),
    Ipv4Addr::new(9, 9, 9, 9),
];

/// The DNS port every entry in [`PUBLIC_DNS_SERVERS`] is asked on.
pub const DNS_PORT: u16 = 53;

/// How many attempts of one query are sent through the secondary link before
/// the policy steps aside and lets the retry use the caller's own primary
/// upstream. Exactly one: the production resolvers run two attempts per
/// query, and the second attempt is the availability guarantee — it must
/// succeed even when the tunnel silently eats packets.
pub const SECONDARY_ATTEMPTS_PER_QUERY: u32 = 1;

/// One resolved decision: which upstream to ask and which local address to
/// leave from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsEgress {
    /// Upstream server to send the query to.
    pub server: SocketAddr,
    /// Local address to bind the socket to before sending, or `None` to let
    /// the routing table pick.
    pub bind: Option<IpAddr>,
    /// `true` when this decision routes over the secondary link. Purely
    /// informational — used for tracing and tests.
    pub via_secondary: bool,
}

impl DnsEgress {
    /// The unbound, primary-link decision for `server`.
    pub fn primary(server: SocketAddr) -> Self {
        Self {
            server,
            bind: None,
            via_secondary: false,
        }
    }
}

/// Live decision source, consulted per query so a tunnel that comes up or
/// drops mid-session is picked up on the next name — a snapshot taken at
/// resolver-build time would go stale exactly when it matters.
pub trait DnsEgressPolicy: Send + Sync {
    /// Where the next query should go, or `None` to keep the caller's own
    /// upstream unbound (feature off, the secondary is unusable right now, or
    /// this attempt is the reserved primary-fallback retry).
    ///
    /// Returning `None` rather than a primary decision is deliberate: the
    /// captured primary upstream belongs to whoever built the resolver — some
    /// callers re-capture it periodically — so a policy carrying its own copy
    /// would answer with a stale address after a network change.
    ///
    /// `attempt` is the zero-based retry counter of ONE query. Attempts past
    /// [`SECONDARY_ATTEMPTS_PER_QUERY`] must fall back to the caller's own
    /// upstream so a silently-dead tunnel costs one timeout, never the query.
    fn decide(&self, attempt: u32) -> Option<DnsEgress>;
}

/// Resolves the secondary link's current IPv4 source address, or `None` when
/// the link is down / unbound / has no usable address.
///
/// Kept as its own trait (rather than taking the route coordinator directly) so
/// the decision logic stays testable without a live adapter table, and so the
/// non-Windows composition roots can supply their own resolver.
pub trait SecondarySourceAddr: Send + Sync {
    fn current(&self) -> Option<Ipv4Addr>;
}

impl<F> SecondarySourceAddr for F
where
    F: Fn() -> Option<Ipv4Addr> + Send + Sync,
{
    fn current(&self) -> Option<Ipv4Addr> {
        self()
    }
}

/// The production policy: public resolver over the secondary link while the
/// toggle is on AND the link has a source address; the primary upstream
/// otherwise.
pub struct SecondaryPreferredEgress {
    /// Live toggle — flipped by the settings writer, read per query.
    enabled: Arc<AtomicBool>,
    source: Arc<dyn SecondarySourceAddr>,
    servers: &'static [Ipv4Addr],
    /// Cross-query operator rotation. With only the first attempt of each
    /// query riding the tunnel, in-query rotation can't spread load across
    /// operators any more — successive QUERIES do it instead, so one operator
    /// rate-limiting us degrades every other query, not every query.
    rotation: std::sync::atomic::AtomicU32,
}

impl SecondaryPreferredEgress {
    pub fn new(enabled: Arc<AtomicBool>, source: Arc<dyn SecondarySourceAddr>) -> Self {
        Self {
            enabled,
            source,
            servers: PUBLIC_DNS_SERVERS,
            rotation: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Override the public-resolver list (tests).
    pub fn with_servers(mut self, servers: &'static [Ipv4Addr]) -> Self {
        self.servers = servers;
        self
    }
}

impl DnsEgressPolicy for SecondaryPreferredEgress {
    fn decide(&self, attempt: u32) -> Option<DnsEgress> {
        if !self.enabled.load(Ordering::Relaxed) || self.servers.is_empty() {
            return None;
        }
        // Retries belong to the primary fallback — see the module doc. A
        // tunnel that silently swallows the first attempt costs one timeout,
        // not the whole resolution (and not a VPN client's bootstrap).
        if attempt >= SECONDARY_ATTEMPTS_PER_QUERY {
            return None;
        }
        // Tunnel down / no address — asking a public resolver would either
        // leave over the primary link anyway (defeating the point) or fail to
        // bind. Fall back to the caller's upstream rather than fail.
        let src = self.source.current()?;
        let slot = self.rotation.fetch_add(1, Ordering::Relaxed);
        let server = self.servers[(slot as usize) % self.servers.len()];
        Some(DnsEgress {
            server: SocketAddr::from((server, DNS_PORT)),
            bind: Some(IpAddr::V4(src)),
            via_secondary: true,
        })
    }
}

/// Process-wide DNS-over-secondary toggle.
///
/// Three independent parts of the composition root need the SAME flag — the
/// egress policy the query sockets consult, the route coordinator that installs
/// the resolver `/32` routes, and the settings writer that flips it — and they
/// are built in different scopes at different times. A process singleton (the
/// pattern the observed-app store already uses) keeps them on one value by
/// construction, instead of threading an argument through five layers where a
/// missed call site silently means "toggle does nothing".
pub fn global_dns_via_secondary() -> Arc<AtomicBool> {
    static FLAG: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();
    Arc::clone(FLAG.get_or_init(|| Arc::new(AtomicBool::new(false))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(enabled: bool, src: Option<Ipv4Addr>) -> SecondaryPreferredEgress {
        SecondaryPreferredEgress::new(Arc::new(AtomicBool::new(enabled)), Arc::new(move || src))
    }

    #[test]
    fn disabled_toggle_keeps_the_callers_own_upstream() {
        let p = policy(false, Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(p.decide(0), None);
    }

    #[test]
    fn enabled_without_secondary_source_falls_back_to_the_caller() {
        assert_eq!(policy(true, None).decide(0), None);
    }

    #[test]
    fn enabled_with_source_binds_and_targets_a_public_resolver() {
        let src = Ipv4Addr::new(10, 91, 193, 99);
        let d = policy(true, Some(src))
            .decide(0)
            .expect("a secondary decision");
        assert_eq!(d.bind, Some(IpAddr::V4(src)));
        assert!(d.via_secondary);
        assert!(PUBLIC_DNS_SERVERS.contains(&match d.server.ip() {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => panic!("v6 upstream is not expected"),
        }));
    }

    #[test]
    fn retries_fall_back_to_the_callers_primary_upstream() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let p = policy(true, Some(src));
        assert!(p.decide(0).is_some_and(|d| d.via_secondary));
        // Every attempt past the tunnel quota is the availability guarantee:
        // it must reach the caller's own upstream even while the adapter
        // still holds an address on a silently-dead tunnel.
        assert_eq!(p.decide(SECONDARY_ATTEMPTS_PER_QUERY), None);
        assert_eq!(p.decide(SECONDARY_ATTEMPTS_PER_QUERY + 5), None);
    }

    #[test]
    fn successive_queries_rotate_operators() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let p = policy(true, Some(src));
        let first = p.decide(0).expect("a secondary decision").server.ip();
        let second = p.decide(0).expect("a secondary decision").server.ip();
        assert_ne!(
            first, second,
            "consecutive queries must not all depend on one operator"
        );
        // Rotation wraps rather than running off the end of the list.
        for _ in 2..PUBLIC_DNS_SERVERS.len() {
            let _ = p.decide(0);
        }
        assert_eq!(
            p.decide(0).expect("a secondary decision").server.ip(),
            first
        );
    }

    #[test]
    fn live_toggle_is_observed_between_queries() {
        let flag = Arc::new(AtomicBool::new(false));
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let p = SecondaryPreferredEgress::new(Arc::clone(&flag), Arc::new(move || Some(src)));
        assert_eq!(p.decide(0), None);
        flag.store(true, Ordering::Relaxed);
        assert!(p.decide(0).is_some_and(|d| d.via_secondary));
    }
}
