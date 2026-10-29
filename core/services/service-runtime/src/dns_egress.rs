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
//! A retry stays in the tunnel, at the next operator: sent to the provider, it
//! let anyone who could delay one tunnel packet put the provider's answer back
//! (a stub address, pinned into the tunnel, ties the user's address to the
//! tunnel's exit). The tunnel is left only once it is judged dead: a run of
//! failed attempts opens the breaker below, and a tunnel with no address (down,
//! a VPN client still bringing it up) is never asked at all.
//!
//! ## The additional link's rule hosts, with the setting off
//!
//! The provider must not shape the answer for a name a rule sends through the
//! tunnel: a stub it hands back is pinned into the tunnel. So with the setting
//! off those names alone go through the tunnel, to [`RULE_HOST_RESOLVER`] — one
//! address ordinary programs almost never ask, so routing it into the tunnel
//! moves nobody else's lookups there. Every other name keeps the provider.
//! [`query_egress`] is the decision; the availability rules above apply to it.
//!
//! ## Source binding needs a route
//!
//! Binding a UDP socket to the tunnel's address is not by itself enough on
//! Windows: the route table still picks the outgoing interface by destination,
//! and a packet leaving the primary link with a tunnel source address is
//! spoofed traffic that the ISP drops. The route half — a `/32` via the
//! secondary for each of [`resolvers_via_tunnel`] — is emitted by
//! `route_codegen::dns_via_secondary_routes` and reconciled together with the
//! rule routes. This module owns only the socket-side decision.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// Asked about the additional link's rule hosts while "DNS through the tunnel"
/// is off: Quad9's second address, which programs configured for a public
/// resolver almost never use.
pub const RULE_HOST_RESOLVER: Ipv4Addr = Ipv4Addr::new(149, 112, 112, 112);

const RULE_HOST_RESOLVERS: &[Ipv4Addr] = &[RULE_HOST_RESOLVER];

/// Which way one of the service's own queries leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryEgress {
    /// The caller's own upstream on the main link.
    CallerUpstream,
    /// [`PUBLIC_DNS_SERVERS`] through the tunnel.
    PublicResolvers,
    /// [`RULE_HOST_RESOLVER`] through the tunnel.
    RuleHostResolver,
}

/// Where a query goes: `additional_link_rule_host` is whether an enabled rule
/// for the additional link names it, `tunnel_usable` whether the tunnel has an
/// address and is not judged dead.
#[must_use]
pub fn query_egress(
    additional_link_rule_host: bool,
    setting_on: bool,
    tunnel_usable: bool,
) -> QueryEgress {
    match (tunnel_usable, setting_on, additional_link_rule_host) {
        (false, _, _) => QueryEgress::CallerUpstream,
        (true, true, _) => QueryEgress::PublicResolvers,
        (true, false, true) => QueryEgress::RuleHostResolver,
        (true, false, false) => QueryEgress::CallerUpstream,
    }
}

/// The resolvers whose `/32` rides the tunnel: exactly those [`query_egress`]
/// can send a query to, and only while one can be sent there.
#[must_use]
pub fn resolvers_via_tunnel(
    setting_on: bool,
    additional_link_names_hosts: bool,
) -> &'static [Ipv4Addr] {
    if setting_on {
        PUBLIC_DNS_SERVERS
    } else if additional_link_names_hosts {
        RULE_HOST_RESOLVERS
    } else {
        &[]
    }
}

/// Consecutive tunnel failures before the secondary is skipped for a while.
///
/// Not one: a single timeout is ordinary (a packet lost, an operator rate
/// limiting us), and tripping on it would give up the setting's whole point
/// over noise.
pub const SECONDARY_FAILURE_THRESHOLD: u32 = 3;

/// How long the secondary is skipped once the threshold is reached, before one
/// query is allowed through to see whether the tunnel came back.
///
/// The cost of being wrong in either direction is small and symmetric: too
/// short and a dead tunnel costs one extra timeout per window; too long and a
/// recovered tunnel keeps queries on the primary a little longer.
pub const SECONDARY_COOLDOWN: Duration = Duration::from_secs(15);

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
    /// `attempt` is the zero-based retry counter of ONE query.
    fn decide(&self, attempt: u32) -> Option<DnsEgress>;

    /// [`Self::decide`] for a query about `hostname`, for a policy that tells
    /// names apart. The default does not.
    fn decide_for(&self, _hostname: &str, attempt: u32) -> Option<DnsEgress> {
        self.decide(attempt)
    }

    /// Report how an attempt this policy chose actually went.
    ///
    /// Without it the policy is blind: it keeps sending the first attempt of
    /// every query into a tunnel that stopped carrying traffic, and each one
    /// costs a full timeout before the caller falls back. The default does
    /// nothing, so a policy that has no state to keep is unaffected.
    fn note_outcome(&self, _via_secondary: bool, _ok: bool) {}
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

/// A [`SecondarySourceAddr`] read at most once per `ttl`: a reading walks the
/// links, and every query of a rule host asks.
pub struct MemoizedSecondarySource<F> {
    read: F,
    ttl: Duration,
    memo: Mutex<Option<(Instant, Option<Ipv4Addr>)>>,
}

impl<F> MemoizedSecondarySource<F>
where
    F: Fn() -> Option<Ipv4Addr> + Send + Sync,
{
    pub fn new(ttl: Duration, read: F) -> Self {
        Self {
            read,
            ttl,
            memo: Mutex::new(None),
        }
    }
}

impl<F> SecondarySourceAddr for MemoizedSecondarySource<F>
where
    F: Fn() -> Option<Ipv4Addr> + Send + Sync,
{
    fn current(&self) -> Option<Ipv4Addr> {
        // Held across the reading: a burst of queries costs one.
        let mut memo = self.memo.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((read_at, address)) = *memo {
            if read_at.elapsed() < self.ttl {
                return address;
            }
        }
        let address = (self.read)();
        *memo = Some((Instant::now(), address));
        address
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
    /// Consecutive failures of attempts this policy sent over the tunnel.
    consecutive_failures: AtomicU32,
    /// While set and unexpired, the tunnel is skipped: `decide` answers `None`
    /// and the caller uses its own upstream immediately. The one way out of
    /// the tunnel for an address-holding link: a dead tunnel must not make
    /// every name on the machine time out.
    open_until: Mutex<Option<Instant>>,
    cooldown: Duration,
    /// Which names an additional-link rule names: the remembered books the
    /// resolver already keeps, so a query costs no store read. `None` sends
    /// every name the caller's way while the setting is off.
    rule_hosts: Option<Arc<dyn crate::dns_resolver::RuleHostOracle>>,
    rule_host_server: SocketAddr,
}

impl SecondaryPreferredEgress {
    pub fn new(enabled: Arc<AtomicBool>, source: Arc<dyn SecondarySourceAddr>) -> Self {
        Self {
            enabled,
            source,
            servers: PUBLIC_DNS_SERVERS,
            rotation: std::sync::atomic::AtomicU32::new(0),
            consecutive_failures: AtomicU32::new(0),
            open_until: Mutex::new(None),
            cooldown: SECONDARY_COOLDOWN,
            rule_hosts: None,
            rule_host_server: SocketAddr::from((RULE_HOST_RESOLVER, DNS_PORT)),
        }
    }

    /// Ask the additional link's rule hosts through the tunnel with the
    /// setting off too.
    #[must_use]
    pub fn with_rule_hosts(mut self, oracle: Arc<dyn crate::dns_resolver::RuleHostOracle>) -> Self {
        self.rule_hosts = Some(oracle);
        self
    }

    /// Override where those rule hosts are asked (tests).
    #[must_use]
    pub fn with_rule_host_server(mut self, server: SocketAddr) -> Self {
        self.rule_host_server = server;
        self
    }

    /// Override how long the tunnel stays skipped (tests).
    #[must_use]
    pub fn with_cooldown(mut self, cooldown: Duration) -> Self {
        self.cooldown = cooldown;
        self
    }

    /// Override the public-resolver list (tests).
    pub fn with_servers(mut self, servers: &'static [Ipv4Addr]) -> Self {
        self.servers = servers;
        self
    }
}

impl SecondaryPreferredEgress {
    /// Is the tunnel currently being skipped? Clears the latch once the
    /// cooldown is up, which is what lets the next query act as the trial.
    fn skipping_tunnel(&self) -> bool {
        let mut open = self.open_until.lock().unwrap_or_else(|p| p.into_inner());
        match *open {
            Some(until) if Instant::now() < until => true,
            Some(_) => {
                *open = None;
                // Leave the counter one short of the threshold so a single
                // failure re-opens immediately: a tunnel that is still dead
                // must not cost another full round of failures to notice.
                self.consecutive_failures.store(
                    SECONDARY_FAILURE_THRESHOLD.saturating_sub(1),
                    Ordering::Relaxed,
                );
                false
            }
            None => false,
        }
    }

    /// [`query_egress`] for a query about `hostname` (`None`: about no name).
    fn route(&self, hostname: Option<&str>) -> Option<DnsEgress> {
        let setting_on = self.enabled.load(Ordering::Relaxed) && !self.servers.is_empty();
        // With the setting on every name rides the tunnel: the books are not
        // asked.
        let rule_host = !setting_on
            && hostname
                .zip(self.rule_hosts.as_deref())
                .is_some_and(|(name, oracle)| oracle.is_rule_host(name));
        // Nothing would ride the tunnel, so neither the latch nor the link is read.
        if !setting_on && !rule_host {
            return None;
        }
        // Tunnel down / no address — the query would leave over the primary
        // link anyway (defeating the point) or fail to bind.
        let src = if self.skipping_tunnel() {
            None
        } else {
            self.source.current()
        };
        let server = match query_egress(rule_host, setting_on, src.is_some()) {
            QueryEgress::CallerUpstream => return None,
            QueryEgress::PublicResolvers => {
                let slot = self.rotation.fetch_add(1, Ordering::Relaxed);
                SocketAddr::from((self.servers[(slot as usize) % self.servers.len()], DNS_PORT))
            }
            QueryEgress::RuleHostResolver => self.rule_host_server,
        };
        Some(DnsEgress {
            server,
            bind: src.map(IpAddr::V4),
            via_secondary: true,
        })
    }
}

impl DnsEgressPolicy for SecondaryPreferredEgress {
    fn decide(&self, _attempt: u32) -> Option<DnsEgress> {
        self.route(None)
    }

    fn decide_for(&self, hostname: &str, _attempt: u32) -> Option<DnsEgress> {
        self.route(Some(hostname))
    }

    fn note_outcome(&self, via_secondary: bool, ok: bool) {
        if !via_secondary {
            return;
        }
        if ok {
            self.consecutive_failures.store(0, Ordering::Relaxed);
            *self.open_until.lock().unwrap_or_else(|p| p.into_inner()) = None;
            return;
        }
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures < SECONDARY_FAILURE_THRESHOLD {
            return;
        }
        let mut open = self.open_until.lock().unwrap_or_else(|p| p.into_inner());
        if open.is_none() {
            tracing::info!(
                target: "nrr::dns-resolver",
                msg_key = "dnsegress-tunnel-cooldown",
                failures,
                cooldown_secs = self.cooldown.as_secs(),
                "DNS-over-secondary: the tunnel stopped answering — sending queries straight to the captured upstream for now. They already fell back there after a timeout; this only drops the wait",
            );
        }
        *open = Some(Instant::now() + self.cooldown);
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

    fn fail(p: &SecondaryPreferredEgress, times: u32) {
        for _ in 0..times {
            p.note_outcome(true, false);
        }
    }

    #[test]
    fn a_run_of_tunnel_failures_stops_queries_being_sent_into_it() {
        let p = policy(true, Some(Ipv4Addr::new(10, 0, 0, 2)));
        fail(&p, SECONDARY_FAILURE_THRESHOLD - 1);
        assert!(
            p.decide(0).is_some(),
            "one short of the threshold still tries"
        );
        fail(&p, 1);
        assert_eq!(p.decide(0), None, "at the threshold the tunnel is skipped");
    }

    #[test]
    fn an_answer_clears_the_run() {
        let p = policy(true, Some(Ipv4Addr::new(10, 0, 0, 2)));
        fail(&p, SECONDARY_FAILURE_THRESHOLD - 1);
        p.note_outcome(true, true);
        fail(&p, SECONDARY_FAILURE_THRESHOLD - 1);
        assert!(p.decide(0).is_some(), "the run restarted from zero");
    }

    #[test]
    fn after_the_cooldown_one_query_is_let_through_to_look() {
        let p =
            policy(true, Some(Ipv4Addr::new(10, 0, 0, 2))).with_cooldown(Duration::from_millis(5));
        fail(&p, SECONDARY_FAILURE_THRESHOLD);
        assert_eq!(p.decide(0), None);
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            p.decide(0).is_some(),
            "the cooldown expired — try the tunnel again"
        );
    }

    #[test]
    fn a_tunnel_that_is_still_dead_is_dropped_again_on_the_first_failure() {
        // The trial query must not cost another full run of failures.
        let p =
            policy(true, Some(Ipv4Addr::new(10, 0, 0, 2))).with_cooldown(Duration::from_millis(5));
        fail(&p, SECONDARY_FAILURE_THRESHOLD);
        std::thread::sleep(Duration::from_millis(20));
        assert!(p.decide(0).is_some());
        fail(&p, 1);
        assert_eq!(p.decide(0), None);
    }

    #[test]
    fn outcomes_of_attempts_that_did_not_use_the_tunnel_are_not_counted() {
        let p = policy(true, Some(Ipv4Addr::new(10, 0, 0, 2)));
        for _ in 0..(SECONDARY_FAILURE_THRESHOLD * 3) {
            p.note_outcome(false, false);
        }
        assert!(p.decide(0).is_some());
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

    /// A retry sent to the provider let anyone who delayed one tunnel packet
    /// put the provider's answer back. It stays in the tunnel, at another
    /// operator, until the tunnel is judged dead.
    #[test]
    fn a_retry_stays_in_the_tunnel_until_the_tunnel_is_judged_dead() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let p = policy(true, Some(src));
        let first = p.decide(0).expect("first attempt");
        let retry = p.decide(1).expect("the retry stays in the tunnel");
        assert!(first.via_secondary && retry.via_secondary);
        assert_ne!(
            first.server, retry.server,
            "the retry asks another operator"
        );
        fail(&p, SECONDARY_FAILURE_THRESHOLD);
        assert_eq!(
            p.decide(1),
            None,
            "a dead tunnel is left for the caller's upstream"
        );
        let unbound = policy(true, None);
        assert_eq!(
            unbound.decide(1),
            None,
            "a tunnel with no address is never asked"
        );
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

    /// The names an additional-link rule names, nothing else.
    struct RuleHosts(&'static [&'static str]);
    impl crate::dns_resolver::RuleHostOracle for RuleHosts {
        fn is_rule_host(&self, hostname: &str) -> bool {
            self.0.contains(&hostname)
        }
    }

    fn rule_host_policy(enabled: bool, src: Option<Ipv4Addr>) -> SecondaryPreferredEgress {
        policy(enabled, src).with_rule_hosts(Arc::new(RuleHosts(&["rule.example"])))
    }

    /// A provider answering a rule host with a stub pins the stub into the
    /// tunnel. With the setting off only those names leave through it, and
    /// only while it can carry them.
    #[test]
    fn with_the_setting_off_only_the_additional_links_rule_hosts_use_the_tunnel() {
        use QueryEgress::*;
        assert_eq!(query_egress(true, false, true), RuleHostResolver);
        assert_eq!(query_egress(false, false, true), CallerUpstream);
        assert_eq!(query_egress(true, false, false), CallerUpstream);
        assert_eq!(query_egress(true, true, true), PublicResolvers);
        assert_eq!(query_egress(false, true, true), PublicResolvers);
        assert_eq!(query_egress(false, true, false), CallerUpstream);
    }

    /// A `/32` into the tunnel for a resolver nobody asks there blackholes
    /// every program that uses it; one missing strands the query bound to
    /// the tunnel.
    #[test]
    fn the_tunnel_carries_exactly_the_resolvers_queries_are_sent_to() {
        assert_eq!(resolvers_via_tunnel(false, true), &[RULE_HOST_RESOLVER]);
        assert!(resolvers_via_tunnel(false, false).is_empty());
        assert_eq!(resolvers_via_tunnel(true, true), PUBLIC_DNS_SERVERS);
        assert_eq!(resolvers_via_tunnel(true, false), PUBLIC_DNS_SERVERS);
    }

    #[test]
    fn with_the_setting_off_a_rule_host_is_asked_of_its_resolver_through_the_tunnel() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let p = rule_host_policy(false, Some(src));
        let expected = Some(DnsEgress {
            server: SocketAddr::from((RULE_HOST_RESOLVER, DNS_PORT)),
            bind: Some(IpAddr::V4(src)),
            via_secondary: true,
        });
        assert_eq!(p.decide_for("rule.example", 0), expected);
        assert_eq!(
            p.decide_for("rule.example", 1),
            expected,
            "the retry stays in the tunnel"
        );
        assert_eq!(
            p.decide_for("other.example", 0),
            None,
            "a name no rule names keeps the provider"
        );
        assert_eq!(p.decide(0), None, "a query with no name keeps the provider");
    }

    #[test]
    fn a_rule_host_falls_back_to_the_caller_when_the_tunnel_cannot_carry_it() {
        assert_eq!(
            rule_host_policy(false, None).decide_for("rule.example", 0),
            None,
            "no tunnel address"
        );
        let p = rule_host_policy(false, Some(Ipv4Addr::new(10, 0, 0, 2)));
        fail(&p, SECONDARY_FAILURE_THRESHOLD);
        assert_eq!(
            p.decide_for("rule.example", 0),
            None,
            "a tunnel judged dead"
        );
    }

    /// A reading walks the links: per query it would sit on every rule host's
    /// answer. A tunnel that came back is still seen once the memo is old.
    #[test]
    fn a_burst_of_queries_reads_the_tunnel_address_once() {
        let reads = Arc::new(AtomicU32::new(0));
        let counted = Arc::clone(&reads);
        let source = MemoizedSecondarySource::new(Duration::from_millis(30), move || {
            counted.fetch_add(1, Ordering::Relaxed);
            Some(Ipv4Addr::new(10, 0, 0, 2))
        });
        for _ in 0..100 {
            assert_eq!(source.current(), Some(Ipv4Addr::new(10, 0, 0, 2)));
        }
        assert_eq!(reads.load(Ordering::Relaxed), 1);
        std::thread::sleep(Duration::from_millis(60));
        let _ = source.current();
        assert_eq!(
            reads.load(Ordering::Relaxed),
            2,
            "an old memo is read again"
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
