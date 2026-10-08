//! Tearing down the connections a freshly applied rule left on the old path.
//!
//! # The problem this solves
//!
//! A rule only decides where a connection goes while that connection is being
//! established. Sockets opened before the rule existed keep running over the
//! route they were opened on, and nothing tells the application otherwise: the
//! page is already loaded, its images already have their sockets, so the user
//! adds the rule and sees no change until they press refresh. Worse, the
//! browser holds a DNS answer of its own, so even a new socket can go to the
//! old address for another minute.
//!
//! Tearing those sockets down is what turns the rule into something the user
//! can see. The application reconnects on its next request and that connection
//! is established under the new rule.
//!
//! Two sets of addresses are worth tearing down, and they close different
//! halves of the problem:
//!
//! - the **hosts the new rule routes** — whatever is being fetched right now
//!   moves onto the new path;
//! - the **anchor**, the site the suggestion was made next to — a page that
//!   keeps a channel open re-opens it and asks for its resources again, which
//!   is what makes the images appear without a manual refresh.
//!
//! # Cost and blast radius
//!
//! Nothing here sits on the data path: one pass over the connection table per
//! accepted suggestion, never per packet or per observation. Only established
//! TCP connections to the exact addresses behind those hostnames are
//! candidates, and of those only the ones [`flows_to_reset`] keeps: the rule
//! belongs to one user, so another user's connection to the same address is
//! none of its business, and an address the shared-IP census has seen serving
//! a direct host is spared for the same reason the kill-switch spares it —
//! except the anchor's. Only the owner's own connections go, their browser
//! reconnects at once, and sparing a CDN-hosted anchor is what left the page
//! waiting for a manual reload.
//! Both the address count and the per-suffix expansion are capped so a broad
//! rule over a warm cache cannot turn into an unbounded sweep.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use nrr_platform_api::conn_observe::egress::EgressRole;
use nrr_platform_api::fake_ip::stale_flows::{
    EstablishedFlow, FlowLinks, FlowTargets, StaleFlowReset, StaleFlowSweep,
};
use nrr_shared::ip_block::IpBlock;

use crate::flow_reset_log::{log_reset_flows, ResetCause};
use crate::fqdn_cache_lookup::FqdnCacheLookup;

/// Addresses torn down in one pass. Reached only by a suffix rule over a warm
/// cache; past this point the user has bigger changes in flight than one page's
/// sockets, and a bounded pass is worth more than a complete one.
const MAX_ADDRESSES_PER_PASS: usize = 256;

/// Hostnames one suffix rule expands to. The cache can hold thousands under a
/// popular suffix, and the ones worth tearing down are the handful the browser
/// is actually talking to.
const MAX_HOSTS_PER_SUFFIX: usize = 64;

/// A hostname that a just-applied rule now routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutedHost {
    /// One name, matched exactly.
    Exact(String),
    /// A domain and everything under it.
    Suffix(String),
    /// The site a suggestion was offered next to, matched exactly: not routed
    /// by the rule, torn down so the page asks for its resources again.
    Anchor(String),
}

/// What one [`RoutedHostFlowRefresh::refresh`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FlowRefreshOutcome {
    pub sweep: StaleFlowSweep,
    /// An anchor was named but none of its connections went, so the page will
    /// not complete by itself — the user has to reload it.
    pub anchor_skipped: bool,
}

/// What [`flows_to_reset`] decided for one pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FlowRefreshDecision {
    pub reset: Vec<EstablishedFlow>,
    /// Of `reset`, the connections to an anchor address.
    pub anchor_reset: usize,
    /// Aimed at an address a direct host shares.
    pub kept_shared: usize,
    /// Owned by a user other than the one whose rules changed.
    pub kept_other_owner: usize,
    /// Owner unknown: tearing down a connection nobody can vouch for is how
    /// another user's session gets cut.
    pub kept_unknown_owner: usize,
    /// Riding a link that is neither of the owner's — a tunnel they run beside
    /// ours. No rule of ours moves it, so a reset only breaks it.
    pub kept_other_link: usize,
    /// Already on the link the plan assigns its destination.
    pub kept_on_course: usize,
}

/// The link the plan sends a destination over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Course {
    Primary,
    Secondary,
}

/// The [`Course`] of each destination whose course is certain. A destination
/// absent here — blocked, or steered both ways — has none, and its connections
/// are reset wherever they run.
#[derive(Debug, Clone, Default)]
pub struct Courses {
    hosts: HashMap<Ipv4Addr, Course>,
    networks: Vec<(IpBlock, Course)>,
}

impl Courses {
    pub fn insert_host(&mut self, host: Ipv4Addr, course: Course) {
        self.hosts.insert(host, course);
    }

    pub fn insert_network(&mut self, network: IpBlock, course: Course) {
        self.networks.push((network, course));
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.networks.is_empty()
    }

    /// The course of exactly `network`, as a rule names it.
    #[must_use]
    pub fn of_network(&self, network: IpBlock) -> Option<Course> {
        self.networks
            .iter()
            .find(|(net, _)| *net == network)
            .map(|(_, course)| *course)
    }

    /// A host's own course outranks a network's, and a longer prefix a shorter
    /// one — the narrower rule wins, as in enforcement.
    #[must_use]
    pub fn of(&self, remote: Ipv4Addr) -> Option<Course> {
        if let Some(course) = self.hosts.get(&remote) {
            return Some(*course);
        }
        self.networks
            .iter()
            .filter(|(net, _)| net.contains(std::net::IpAddr::V4(remote)))
            .max_by_key(|(net, _)| net.prefix_len())
            .map(|(_, course)| *course)
    }
}

/// Where the owner's connections run and where the plan wants them. The
/// default knows neither, which spares nothing.
#[derive(Debug, Clone, Default)]
pub struct FlowPaths {
    pub links: FlowLinks,
    pub courses: Courses,
}

/// Which `candidates` a rule change by `rule_owner` may tear down: the owner's
/// own connections, to addresses no direct host shares unless they are in
/// `anchors`, that are off course on one of the owner's links.
#[must_use]
pub fn flows_to_reset(
    candidates: Vec<EstablishedFlow>,
    rule_owner: &str,
    shared_direct: &HashSet<Ipv4Addr>,
    anchors: &HashSet<Ipv4Addr>,
    paths: &FlowPaths,
) -> FlowRefreshDecision {
    let mut decision = FlowRefreshDecision::default();
    for flow in candidates {
        let anchor = anchors.contains(flow.remote.ip());
        if !anchor && shared_direct.contains(flow.remote.ip()) {
            decision.kept_shared += 1;
            continue;
        }
        match flow.owner.as_deref() {
            None => decision.kept_unknown_owner += 1,
            // SID strings compare case-insensitively.
            Some(owner) if owner.eq_ignore_ascii_case(rule_owner) => {
                let on_course = match (
                    paths.links.role_of(*flow.local.ip()),
                    paths.courses.of(*flow.remote.ip()),
                ) {
                    (EgressRole::Other, _) => {
                        decision.kept_other_link += 1;
                        continue;
                    }
                    (EgressRole::Primary, Some(Course::Primary))
                    | (EgressRole::Secondary, Some(Course::Secondary)) => true,
                    _ => false,
                };
                // An anchor goes on course too: tearing it down is what makes
                // the page ask for its resources again.
                if on_course && !anchor {
                    decision.kept_on_course += 1;
                    continue;
                }
                decision.anchor_reset += usize::from(anchor);
                decision.reset.push(flow);
            }
            Some(_) => decision.kept_other_owner += 1,
        }
    }
    decision
}

/// What [`reset_owner_flows`] decided and how much of it the OS carried out.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OwnerFlowReset {
    pub decision: FlowRefreshDecision,
    pub torn_down: usize,
}

/// Tear down `owner`'s established connections to `targets` — hosts, or any
/// address inside a network a rule names — under [`flows_to_reset`]'s rules,
/// with no anchor. `None` when nothing was connected: the census and `paths`
/// are queries, read only when there is a connection to spare.
pub fn reset_owner_flows(
    reset: &dyn StaleFlowReset,
    cache: &dyn FqdnCacheLookup,
    owner: &str,
    targets: &FlowTargets,
    paths: impl FnOnce() -> FlowPaths,
) -> Option<OwnerFlowReset> {
    if targets.is_empty() {
        return None;
    }
    let candidates = reset.established_flows_matching(targets);
    if candidates.is_empty() {
        return None;
    }
    let decision = flows_to_reset(
        candidates,
        owner,
        &cache.shared_direct_ips(),
        &HashSet::new(),
        &paths(),
    );
    let torn_down = if decision.reset.is_empty() {
        0
    } else {
        reset.reset_established(&decision.reset)
    };
    Some(OwnerFlowReset {
        decision,
        torn_down,
    })
}

/// The addresses one pass looks at, and which of them are the anchors'.
struct RefreshTargets {
    addresses: Vec<Ipv4Addr>,
    anchors: HashSet<Ipv4Addr>,
    /// The hostname each address was reached through, for the per-connection log.
    hosts: HashMap<Ipv4Addr, String>,
}

/// A principal's links, read when a pass has connections to decide on.
pub type FlowLinksSource = Arc<dyn Fn(&str) -> FlowLinks + Send + Sync>;

/// Tears down established connections to hosts whose route just changed.
pub struct RoutedHostFlowRefresh {
    cache: Arc<dyn FqdnCacheLookup>,
    reset: Arc<dyn StaleFlowReset>,
    links: Option<FlowLinksSource>,
}

impl RoutedHostFlowRefresh {
    #[must_use]
    pub fn new(cache: Arc<dyn FqdnCacheLookup>, reset: Arc<dyn StaleFlowReset>) -> Self {
        Self {
            cache,
            reset,
            links: None,
        }
    }

    /// Spare the connections riding a link that is neither of the principal's.
    #[must_use]
    pub fn with_links(mut self, links: FlowLinksSource) -> Self {
        self.links = Some(links);
        self
    }

    /// Where the owner's connections run. Which link a routed host belongs on
    /// is the rule's, not known here, so no connection counts as on course.
    fn paths(&self, principal: &str) -> FlowPaths {
        FlowPaths {
            links: self
                .links
                .as_ref()
                .map(|links| links(principal))
                .unwrap_or_default(),
            courses: Courses::default(),
        }
    }

    /// Tear down `principal`'s established connections aimed at an address
    /// behind `hosts`. Best-effort by contract: the worst case is the old
    /// behaviour, an application sitting on a socket over the previous route.
    ///
    /// Call this only once the rule is applied. Tearing down first would have
    /// the application reconnect over the route that is still in force.
    pub fn refresh(&self, principal: &str, hosts: &[RoutedHost]) -> FlowRefreshOutcome {
        let has_anchor = hosts.iter().any(|h| matches!(h, RoutedHost::Anchor(_)));
        let RefreshTargets {
            addresses,
            anchors,
            hosts: host_of,
        } = self.addresses_behind(hosts);
        let candidates = self.reset.established_flows_to(&addresses);
        if candidates.is_empty() {
            tracing::debug!(
                target: "nrr::auto-rules",
                addresses = addresses.len(),
                "no connection was left on the previous route",
            );
            return FlowRefreshOutcome {
                sweep: StaleFlowSweep::default(),
                anchor_skipped: has_anchor,
            };
        }
        // Read only when something is connected: the census is a query.
        let decision = flows_to_reset(
            candidates,
            principal,
            &self.cache.shared_direct_ips(),
            &anchors,
            &self.paths(principal),
        );
        let anchor_skipped = has_anchor && decision.anchor_reset == 0;
        if decision.kept_unknown_owner > 0 {
            tracing::debug!(
                target: "nrr::auto-rules",
                sid = %principal,
                kept = decision.kept_unknown_owner,
                "left connections standing whose owner could not be resolved",
            );
        }
        let sweep = StaleFlowSweep {
            found: decision.reset.len(),
            torn_down: self.reset.reset_established(&decision.reset),
        };
        if sweep.found > 0 {
            log_reset_flows(Some(principal), &decision.reset, |ip| {
                let cause = if anchors.contains(&ip) {
                    ResetCause::Anchor
                } else {
                    ResetCause::RoutedHost
                };
                (host_of.get(&ip).map(String::as_str), cause)
            });
            tracing::info!(
                target: "nrr::auto-rules",
                msg_key = "flowrefresh-torn-down",
                sid = %principal,
                addresses = addresses.len(),
                found = sweep.found,
                torn_down = sweep.torn_down,
                anchor_reset = decision.anchor_reset,
                anchor_skipped,
                kept_shared = decision.kept_shared,
                kept_other_owner = decision.kept_other_owner,
                kept_other_link = decision.kept_other_link,
                "tore down connections still running over the previous route — \
                 the application reconnects under the new rule",
            );
        } else {
            tracing::debug!(
                target: "nrr::auto-rules",
                sid = %principal,
                addresses = addresses.len(),
                kept_shared = decision.kept_shared,
                kept_other_owner = decision.kept_other_owner,
                "every connection on the previous route belongs to someone else",
            );
        }
        FlowRefreshOutcome {
            sweep,
            anchor_skipped,
        }
    }

    /// Cached addresses behind `hosts`, deduplicated and capped, the anchors'
    /// first so the cap never drops them. Sorted because `BTreeMap` makes the
    /// pass order deterministic, which keeps a log line from one run
    /// comparable with the next.
    fn addresses_behind(&self, hosts: &[RoutedHost]) -> RefreshTargets {
        let mut anchors = BTreeMap::new();
        for host in hosts {
            if let RoutedHost::Anchor(name) = host {
                self.collect_into(&mut anchors, name);
            }
        }
        let mut addresses = BTreeMap::new();
        for host in hosts {
            match host {
                RoutedHost::Exact(name) => {
                    self.collect_into(&mut addresses, name);
                }
                RoutedHost::Anchor(_) => {}
                RoutedHost::Suffix(label) => {
                    // The expansion helper is the same one enforcement uses, so
                    // the set torn down cannot drift from the set routed.
                    for name in self
                        .cache
                        .hostnames_for_suffix_domain(label, MAX_HOSTS_PER_SUFFIX)
                    {
                        self.collect_into(&mut addresses, &name);
                    }
                }
            }
            if addresses.len() >= MAX_ADDRESSES_PER_PASS {
                break;
            }
        }
        let mut names: HashMap<Ipv4Addr, String> = addresses.clone().into_iter().collect();
        names.extend(anchors.clone());
        let anchors: Vec<Ipv4Addr> = anchors.into_keys().take(MAX_ADDRESSES_PER_PASS).collect();
        let rest = addresses.into_keys().filter(|a| !anchors.contains(a));
        RefreshTargets {
            addresses: anchors
                .iter()
                .copied()
                .chain(rest)
                .take(MAX_ADDRESSES_PER_PASS)
                .collect(),
            anchors: anchors.into_iter().collect(),
            hosts: names,
        }
    }

    fn collect_into(&self, addresses: &mut BTreeMap<Ipv4Addr, String>, hostname: &str) {
        // Routed-host flow refresh acts on the v4 flows the relay tracks.
        for address in crate::dns_wire::only_v4(&self.cache.ips_for_hostname(hostname)) {
            addresses
                .entry(address)
                .or_insert_with(|| hostname.to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, SocketAddrV4};

    use nrr_platform_api::fake_ip::MockStaleFlowReset;

    use super::*;

    const OWNER: &str = "S-1-5-21-1-2-3-1001";
    const OTHER_USER: &str = "S-1-5-21-1-2-3-1002";

    #[derive(Default)]
    struct FakeCache {
        addresses: HashMap<String, Vec<IpAddr>>,
        under_suffix: HashMap<String, Vec<String>>,
        shared_direct: HashSet<Ipv4Addr>,
    }

    impl FqdnCacheLookup for FakeCache {
        fn ips_for_hostname(&self, hostname: &str) -> Vec<IpAddr> {
            self.addresses.get(hostname).cloned().unwrap_or_default()
        }

        fn hostnames_under_suffix(&self, suffix: &str, limit: usize) -> Vec<String> {
            let mut hosts = self.under_suffix.get(suffix).cloned().unwrap_or_default();
            hosts.truncate(limit);
            hosts
        }

        fn shared_direct_ips(&self) -> HashSet<Ipv4Addr> {
            self.shared_direct.clone()
        }
    }

    fn cache_with(rows: &[(&str, &str)]) -> FakeCache {
        let mut cache = FakeCache::default();
        for (host, address) in rows {
            cache
                .addresses
                .entry((*host).to_string())
                .or_default()
                .push(address.parse().expect("test address"));
        }
        cache
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().expect("test address")
    }

    fn flow(remote: &str, local_port: u16, owner: Option<&str>) -> EstablishedFlow {
        EstablishedFlow {
            local: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), local_port),
            remote: SocketAddrV4::new(ip(remote), 443),
            owner: owner.map(str::to_string),
            pid: None,
            image: None,
        }
    }

    fn addresses_of(cache: FakeCache, hosts: &[RoutedHost]) -> Vec<Ipv4Addr> {
        RoutedHostFlowRefresh::new(Arc::new(cache), Arc::new(MockStaleFlowReset::new()))
            .addresses_behind(hosts)
            .addresses
    }

    // ── the decision ──────────────────────────────────────────────────────

    #[test]
    fn the_rule_owners_connection_to_a_routed_only_address_is_reset() {
        let mine = flow("203.0.113.10", 50_000, Some(OWNER));
        let decision = flows_to_reset(
            vec![mine.clone()],
            OWNER,
            &HashSet::new(),
            &HashSet::new(),
            &FlowPaths::default(),
        );
        assert_eq!(decision.reset, vec![mine]);
    }

    #[test]
    fn another_users_connection_to_the_same_address_is_kept() {
        let mine = flow("203.0.113.10", 50_000, Some(OWNER));
        let theirs = flow("203.0.113.10", 50_001, Some(OTHER_USER));
        let decision = flows_to_reset(
            vec![mine.clone(), theirs],
            OWNER,
            &HashSet::new(),
            &HashSet::new(),
            &FlowPaths::default(),
        );
        assert_eq!(decision.reset, vec![mine]);
        assert_eq!(decision.kept_other_owner, 1);
    }

    #[test]
    fn a_connection_to_an_address_a_direct_host_shares_is_kept() {
        let shared = HashSet::from([ip("203.0.113.10")]);
        let to_shared = flow("203.0.113.10", 50_000, Some(OWNER));
        let to_routed = flow("203.0.113.11", 50_001, Some(OWNER));
        let decision = flows_to_reset(
            vec![to_shared, to_routed.clone()],
            OWNER,
            &shared,
            &HashSet::new(),
            &FlowPaths::default(),
        );
        assert_eq!(decision.reset, vec![to_routed]);
        assert_eq!(decision.kept_shared, 1);
    }

    #[test]
    fn a_connection_whose_owner_is_unknown_is_kept() {
        let decision = flows_to_reset(
            vec![flow("203.0.113.10", 50_000, None)],
            OWNER,
            &HashSet::new(),
            &HashSet::new(),
            &FlowPaths::default(),
        );
        assert!(decision.reset.is_empty());
        assert_eq!(decision.kept_unknown_owner, 1);
    }

    #[test]
    fn the_owner_matches_regardless_of_sid_letter_case() {
        let mine = flow("203.0.113.10", 50_000, Some("s-1-5-21-1-2-3-1001"));
        assert_eq!(
            flows_to_reset(
                vec![mine],
                OWNER,
                &HashSet::new(),
                &HashSet::new(),
                &FlowPaths::default()
            )
            .reset
            .len(),
            1
        );
    }

    // ── the link a connection rides ───────────────────────────────────────

    const PRIMARY_IF: u32 = 23;
    const SECONDARY_IF: u32 = 28;
    const CORPORATE_IF: u32 = 20;

    fn on_primary() -> Ipv4Addr {
        ip("192.0.2.1")
    }
    fn on_secondary() -> Ipv4Addr {
        ip("198.51.100.41")
    }
    fn on_corporate() -> Ipv4Addr {
        ip("172.16.0.150")
    }

    fn links() -> FlowLinks {
        FlowLinks::new(
            vec![
                (IpAddr::V4(on_primary()), PRIMARY_IF),
                (IpAddr::V4(on_secondary()), SECONDARY_IF),
                (IpAddr::V4(on_corporate()), CORPORATE_IF),
            ],
            Some(PRIMARY_IF),
            Some(SECONDARY_IF),
        )
    }

    fn via(local: Ipv4Addr, remote: &str, local_port: u16) -> EstablishedFlow {
        EstablishedFlow {
            local: SocketAddrV4::new(local, local_port),
            ..flow(remote, local_port, Some(OWNER))
        }
    }

    fn paths(courses: &[(&str, Course)]) -> FlowPaths {
        let mut known = Courses::default();
        for (host, course) in courses {
            known.insert_host(ip(host), *course);
        }
        FlowPaths {
            links: links(),
            courses: known,
        }
    }

    fn decide(candidates: Vec<EstablishedFlow>, paths: &FlowPaths) -> FlowRefreshDecision {
        flows_to_reset(candidates, OWNER, &HashSet::new(), &HashSet::new(), paths)
    }

    /// A corporate tunnel the user runs beside ours carries its own routes:
    /// nothing we steer moves its connections, so a reset only cuts them.
    #[test]
    fn a_connection_riding_a_link_that_is_neither_of_the_owners_is_kept() {
        let corporate = via(on_corporate(), "203.0.113.10", 50_000);
        let decision = decide(
            vec![corporate],
            &paths(&[("203.0.113.10", Course::Primary)]),
        );
        assert!(decision.reset.is_empty());
        assert_eq!(decision.kept_other_link, 1);

        let unrouted = decide(
            vec![via(on_corporate(), "203.0.113.11", 50_001)],
            &paths(&[]),
        );
        assert_eq!(unrouted.kept_other_link, 1, "with no course known either");
    }

    #[test]
    fn a_connection_already_on_its_course_is_kept_and_one_off_it_is_reset() {
        let p = paths(&[
            ("203.0.113.10", Course::Primary),
            ("203.0.113.20", Course::Secondary),
        ]);
        let off_course = vec![
            via(on_secondary(), "203.0.113.10", 50_001),
            via(on_primary(), "203.0.113.20", 50_003),
        ];
        let mut candidates = vec![
            via(on_primary(), "203.0.113.10", 50_000),
            via(on_secondary(), "203.0.113.20", 50_002),
        ];
        candidates.extend(off_course.clone());

        let decision = decide(candidates, &p);

        assert_eq!(decision.reset, off_course);
        assert_eq!(decision.kept_on_course, 2);
    }

    /// A destination with no certain course — blocked, say — is reset on any
    /// of the owner's links, as is a connection whose link nobody could read.
    #[test]
    fn no_course_or_no_link_reading_leaves_the_reset_as_it_was() {
        let blocked = via(on_primary(), "203.0.113.30", 50_000);
        assert_eq!(
            decide(vec![blocked.clone()], &paths(&[])).reset,
            vec![blocked]
        );

        let unread = via(on_primary(), "203.0.113.10", 50_001);
        let mut no_links = paths(&[("203.0.113.10", Course::Primary)]);
        no_links.links = FlowLinks::default();
        assert_eq!(decide(vec![unread.clone()], &no_links).reset, vec![unread]);
    }

    #[test]
    fn an_anchor_on_course_is_still_reset() {
        let anchor = via(on_primary(), "203.0.113.10", 50_000);
        let decision = flows_to_reset(
            vec![anchor.clone()],
            OWNER,
            &HashSet::new(),
            &HashSet::from([ip("203.0.113.10")]),
            &paths(&[("203.0.113.10", Course::Primary)]),
        );
        assert_eq!(decision.reset, vec![anchor]);
    }

    #[test]
    fn a_hosts_own_course_outranks_its_networks_and_a_longer_prefix_a_shorter_one() {
        let mut courses = Courses::default();
        courses.insert_network(network("203.0.113.0/24"), Course::Secondary);
        courses.insert_network(network("203.0.113.0/28"), Course::Primary);
        courses.insert_host(ip("203.0.113.5"), Course::Secondary);
        assert_eq!(courses.of(ip("203.0.113.5")), Some(Course::Secondary));
        assert_eq!(courses.of(ip("203.0.113.6")), Some(Course::Primary));
        assert_eq!(courses.of(ip("203.0.113.200")), Some(Course::Secondary));
        assert_eq!(courses.of(ip("198.51.100.1")), None);
    }

    #[test]
    fn a_routed_host_pass_spares_a_connection_on_another_link() {
        let cache = cache_with(&[("cdn.example", "203.0.113.10")]);
        let reset = Arc::new(MockStaleFlowReset::new());
        let mine = via(on_primary(), "203.0.113.10", 50_000);
        reset.set_flows(vec![
            mine.clone(),
            via(on_corporate(), "203.0.113.10", 50_001),
        ]);
        let refresher = RoutedHostFlowRefresh::new(
            Arc::new(cache),
            Arc::clone(&reset) as Arc<dyn StaleFlowReset>,
        )
        .with_links(Arc::new(|_: &str| links()));

        refresher.refresh(OWNER, &[RoutedHost::Exact("cdn.example".into())]);

        assert_eq!(reset.reset_flows(), vec![mine]);
    }

    // ── the pass ──────────────────────────────────────────────────────────

    #[test]
    fn a_pass_resets_only_what_the_decision_keeps() {
        let mut cache = cache_with(&[
            ("cdn.example", "203.0.113.10"),
            ("cdn.example", "203.0.113.11"),
        ]);
        cache.shared_direct.insert(ip("203.0.113.11"));
        let reset = Arc::new(MockStaleFlowReset::new());
        let mine = flow("203.0.113.10", 50_000, Some(OWNER));
        reset.set_flows(vec![
            mine.clone(),
            flow("203.0.113.10", 50_001, Some(OTHER_USER)),
            flow("203.0.113.10", 50_002, None),
            flow("203.0.113.11", 50_003, Some(OWNER)),
            // Not behind the routed host at all.
            flow("203.0.113.99", 50_004, Some(OWNER)),
        ]);
        let refresher = RoutedHostFlowRefresh::new(
            Arc::new(cache),
            Arc::clone(&reset) as Arc<dyn StaleFlowReset>,
        );

        let outcome = refresher.refresh(OWNER, &[RoutedHost::Exact("cdn.example".into())]);

        assert_eq!(reset.reset_flows(), vec![mine]);
        assert_eq!(
            outcome,
            FlowRefreshOutcome {
                sweep: StaleFlowSweep {
                    found: 1,
                    torn_down: 1
                },
                anchor_skipped: false,
            }
        );
    }

    #[test]
    fn a_host_the_cache_never_saw_resets_nothing() {
        let reset = Arc::new(MockStaleFlowReset::new());
        reset.set_flows(vec![flow("203.0.113.10", 50_000, Some(OWNER))]);
        let refresher = RoutedHostFlowRefresh::new(
            Arc::new(FakeCache::default()),
            Arc::clone(&reset) as Arc<dyn StaleFlowReset>,
        );
        let outcome = refresher.refresh(OWNER, &[RoutedHost::Exact("unknown.example".into())]);
        assert!(reset.reset_flows().is_empty());
        assert_eq!(outcome, FlowRefreshOutcome::default());
    }

    // ── the anchor ────────────────────────────────────────────────────────

    #[test]
    fn the_owners_anchor_connection_on_a_shared_address_is_reset() {
        let shared = HashSet::from([ip("203.0.113.10")]);
        let anchor = flow("203.0.113.10", 50_000, Some(OWNER));
        let decision = flows_to_reset(
            vec![anchor.clone()],
            OWNER,
            &shared,
            &shared,
            &FlowPaths::default(),
        );
        assert_eq!(decision.reset, vec![anchor]);
        assert_eq!(decision.anchor_reset, 1);
        assert_eq!(decision.kept_shared, 0);
    }

    #[test]
    fn a_non_anchor_connection_on_a_shared_address_is_still_kept() {
        let shared = HashSet::from([ip("203.0.113.10"), ip("203.0.113.11")]);
        let anchors = HashSet::from([ip("203.0.113.11")]);
        let decision = flows_to_reset(
            vec![flow("203.0.113.10", 50_000, Some(OWNER))],
            OWNER,
            &shared,
            &anchors,
            &FlowPaths::default(),
        );
        assert!(decision.reset.is_empty());
        assert_eq!(decision.kept_shared, 1);
    }

    #[test]
    fn another_users_or_an_unattributed_anchor_connection_is_kept() {
        let anchors = HashSet::from([ip("203.0.113.10")]);
        let decision = flows_to_reset(
            vec![
                flow("203.0.113.10", 50_000, Some(OTHER_USER)),
                flow("203.0.113.10", 50_001, None),
            ],
            OWNER,
            &anchors,
            &anchors,
            &FlowPaths::default(),
        );
        assert!(decision.reset.is_empty());
        assert_eq!(decision.anchor_reset, 0);
        assert_eq!(decision.kept_other_owner, 1);
        assert_eq!(decision.kept_unknown_owner, 1);
    }

    #[test]
    fn an_anchor_on_a_shared_address_is_torn_down_and_reported_done() {
        let mut cache = cache_with(&[
            ("cdn.example", "203.0.113.11"),
            ("site.example", "203.0.113.10"),
        ]);
        cache.shared_direct.insert(ip("203.0.113.10"));
        cache.shared_direct.insert(ip("203.0.113.11"));
        let reset = Arc::new(MockStaleFlowReset::new());
        let anchor = flow("203.0.113.10", 50_000, Some(OWNER));
        reset.set_flows(vec![
            anchor.clone(),
            flow("203.0.113.11", 50_001, Some(OWNER)),
        ]);
        let refresher = RoutedHostFlowRefresh::new(
            Arc::new(cache),
            Arc::clone(&reset) as Arc<dyn StaleFlowReset>,
        );

        let outcome = refresher.refresh(
            OWNER,
            &[
                RoutedHost::Exact("cdn.example".into()),
                RoutedHost::Anchor("site.example".into()),
            ],
        );

        assert_eq!(reset.reset_flows(), vec![anchor]);
        assert!(!outcome.anchor_skipped);
    }

    #[test]
    fn an_anchor_nothing_could_tear_down_is_reported_skipped() {
        let cache = cache_with(&[("site.example", "203.0.113.10")]);
        let reset = Arc::new(MockStaleFlowReset::new());
        reset.set_flows(vec![flow("203.0.113.10", 50_000, None)]);
        let refresher = RoutedHostFlowRefresh::new(
            Arc::new(cache),
            Arc::clone(&reset) as Arc<dyn StaleFlowReset>,
        );
        let anchor = [RoutedHost::Anchor("site.example".into())];

        assert!(
            refresher.refresh(OWNER, &anchor).anchor_skipped,
            "unknown owner"
        );

        reset.set_flows(Vec::new());
        assert!(
            refresher.refresh(OWNER, &anchor).anchor_skipped,
            "no connection"
        );
        assert!(
            !refresher
                .refresh(OWNER, &[RoutedHost::Exact("site.example".into())])
                .anchor_skipped,
            "no anchor named, nothing to report"
        );
    }

    #[test]
    fn the_cap_never_drops_an_anchor_address() {
        let mut rows: Vec<(String, String)> = (0..=MAX_ADDRESSES_PER_PASS)
            .map(|i| {
                (
                    "cdn.example".to_string(),
                    format!("10.0.{}.{}", i / 250, i % 250),
                )
            })
            .collect();
        rows.push(("site.example".into(), "203.0.113.200".into()));
        let rows: Vec<(&str, &str)> = rows.iter().map(|(h, a)| (h.as_str(), a.as_str())).collect();
        let listed = addresses_of(
            cache_with(&rows),
            &[
                RoutedHost::Exact("cdn.example".into()),
                RoutedHost::Anchor("site.example".into()),
            ],
        );
        assert_eq!(listed.len(), MAX_ADDRESSES_PER_PASS);
        assert!(listed.contains(&ip("203.0.113.200")));
    }

    // ── a network target ──────────────────────────────────────────────────

    fn network(text: &str) -> nrr_shared::ip_block::IpBlock {
        nrr_shared::ip_block::IpBlock::parse(text).expect("test network")
    }

    #[test]
    fn a_network_tears_down_only_the_owners_flows_inside_it() {
        let reset = MockStaleFlowReset::new();
        let mine_inside = flow("198.51.100.20", 50_000, Some(OWNER));
        reset.set_flows(vec![
            mine_inside.clone(),
            flow("198.51.100.21", 50_001, Some(OTHER_USER)),
            flow("198.51.100.22", 50_002, None),
            flow("198.51.101.1", 50_003, Some(OWNER)),
        ]);
        let targets = FlowTargets::new(Vec::new(), vec![network("198.51.100.0/24")]);

        let outcome = reset_owner_flows(
            &reset,
            &FakeCache::default(),
            OWNER,
            &targets,
            FlowPaths::default,
        )
        .expect("something was connected");

        assert_eq!(reset.reset_flows(), vec![mine_inside]);
        assert_eq!(outcome.torn_down, 1);
        assert_eq!(outcome.decision.kept_other_owner, 1);
        assert_eq!(outcome.decision.kept_unknown_owner, 1);
    }

    #[test]
    fn an_address_the_census_saw_serving_a_direct_host_is_spared_inside_a_network() {
        let reset = MockStaleFlowReset::new();
        let routed = flow("198.51.100.20", 50_000, Some(OWNER));
        reset.set_flows(vec![
            routed.clone(),
            flow("198.51.100.30", 50_001, Some(OWNER)),
        ]);
        let mut cache = FakeCache::default();
        cache.shared_direct.insert(ip("198.51.100.30"));
        let targets = FlowTargets::new(Vec::new(), vec![network("198.51.100.0/24")]);

        let outcome = reset_owner_flows(&reset, &cache, OWNER, &targets, FlowPaths::default)
            .expect("connected");

        assert_eq!(reset.reset_flows(), vec![routed]);
        assert_eq!(outcome.decision.kept_shared, 1);
    }

    #[test]
    fn nothing_connected_or_nothing_asked_reads_nothing() {
        let reset = MockStaleFlowReset::new();
        assert!(reset_owner_flows(
            &reset,
            &FakeCache::default(),
            OWNER,
            &FlowTargets::default(),
            FlowPaths::default
        )
        .is_none());
        assert!(reset.queried_networks().is_empty());
        let targets = FlowTargets::new(Vec::new(), vec![network("198.51.100.0/24")]);
        assert!(reset_owner_flows(
            &reset,
            &FakeCache::default(),
            OWNER,
            &targets,
            FlowPaths::default
        )
        .is_none());
        assert!(reset.reset_flows().is_empty());
    }

    // ── the address set ───────────────────────────────────────────────────

    #[test]
    fn every_address_behind_the_named_hosts_is_listed_once() {
        let cache = cache_with(&[
            ("cdn.example", "203.0.113.10"),
            ("cdn.example", "203.0.113.11"),
            ("site.example", "203.0.113.20"),
            ("mirror.example", "203.0.113.10"),
        ]);
        let listed = addresses_of(
            cache,
            &[
                RoutedHost::Exact("cdn.example".into()),
                RoutedHost::Exact("site.example".into()),
                RoutedHost::Exact("mirror.example".into()),
            ],
        );
        assert_eq!(
            listed,
            vec![ip("203.0.113.10"), ip("203.0.113.11"), ip("203.0.113.20")]
        );
    }

    #[test]
    fn a_suffix_lists_the_hosts_it_covers() {
        let mut cache = cache_with(&[
            ("img.site.example", "203.0.113.30"),
            ("api.site.example", "203.0.113.31"),
            ("elsewhere.example", "203.0.113.99"),
        ]);
        cache.under_suffix.insert(
            "site.example".to_string(),
            vec!["api.site.example".into(), "img.site.example".into()],
        );
        let listed = addresses_of(cache, &[RoutedHost::Suffix("site.example".into())]);
        assert_eq!(listed.len(), 2);
        assert!(!listed.contains(&ip("203.0.113.99")));
    }
}
