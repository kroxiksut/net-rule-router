use super::*;
use crate::boot_clock::BootInstant;

/// A first contact routes only what the planner would, from the last
/// recompute's resolution, and the next recompute finds it in place.
#[test]
fn a_first_contact_routes_only_what_the_planner_would() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("a", 203, 0, 113, 1)]),
    );
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));
    let second = Ipv4Addr::new(203, 0, 113, 2);
    let unnamed = Ipv4Addr::new(198, 51, 100, 9);
    let second_v4 = IpAddr::V4(second);
    assert_eq!(
        coord.route_first_contact("S-IVANOV", &[second_v4]),
        0,
        "nothing recomputed yet, so no resolution to plan from"
    );
    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .expect("recompute");

    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![
            ip_rule("a", 203, 0, 113, 1),
            ip_rule("b", 203, 0, 113, 2),
        ]),
    );
    assert_eq!(
        coord.route_first_contact("S-IVANOV", &[second_v4, IpAddr::V4(unnamed)]),
        1
    );
    let dests = table_dests(&api);
    assert!(dests.contains(&second), "{dests:?}");
    assert!(!dests.contains(&unnamed), "no rule names it: {dests:?}");

    let delta = coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .expect("recompute");
    assert!(delta.is_noop(), "{delta:?}");

    coord
        .recompute_for("S-IVANOV", &res(None))
        .expect("teardown");
    assert_eq!(
        coord.route_first_contact("S-IVANOV", &[second_v4]),
        0,
        "no link, nothing to route"
    );
}

/// Counts whole-cache and per-address snapshot requests.
#[derive(Default)]
struct CountingSnapshots {
    live: MockFqdnCacheLookup,
    whole: std::sync::atomic::AtomicUsize,
    scoped: std::sync::atomic::AtomicUsize,
}

impl FqdnCacheLookup for CountingSnapshots {
    fn ips_for_hostname(&self, hostname: &str) -> Vec<IpAddr> {
        self.live.ips_for_hostname(hostname)
    }
    fn hostnames_under_suffix(&self, suffix: &str, limit: usize) -> Vec<String> {
        self.live.hostnames_under_suffix(suffix, limit)
    }
    fn snapshot_for_compute(&self) -> Option<crate::fqdn_cache_lookup::FqdnCacheSnapshot> {
        self.whole.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        None
    }
    fn snapshot_for_addresses(
        &self,
        _addresses: &[IpAddr],
    ) -> Option<crate::fqdn_cache_lookup::FqdnCacheSnapshot> {
        self.scoped
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        None
    }
}

/// A first contact answers a DNS reply: reading the whole cache there held
/// every resolver worker behind the cache lock for tens of milliseconds.
#[test]
fn a_first_contact_reads_only_the_rows_on_its_addresses() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![
            ip_rule("a", 203, 0, 113, 1),
            ip_rule("b", 203, 0, 113, 2),
        ]),
    );
    let cache = Arc::new(CountingSnapshots::default());
    let coord = SecondaryRouteCoordinator::new(
        Arc::clone(&api) as Arc<dyn RouteTablePort>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        Arc::new(FakePolicy::new()) as Arc<dyn RoutePolicySource>,
        Arc::clone(&cache) as Arc<dyn FqdnCacheLookup>,
        Arc::new(|| false) as RuleScopeProvider,
    );
    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .expect("recompute");
    cache.whole.store(0, std::sync::atomic::Ordering::SeqCst);

    let routed =
        coord.route_first_contact("S-IVANOV", &[IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2))]);

    assert_eq!(routed, 1, "the first contact still routes its address");
    assert_eq!(cache.whole.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(cache.scoped.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// A rule book whose next read hands out the book as it stood and then, before
/// returning, moves to `newer` and runs `hook` — a first contact landing after
/// the pass has read its plan's inputs.
struct BookMovesMidRead {
    book: Mutex<CanonicalRuleSet>,
    next: Mutex<Option<(CanonicalRuleSet, MidReadHook)>>,
}

type MidReadHook = Box<dyn FnOnce() + Send>;

impl BookMovesMidRead {
    fn set(&self, book: CanonicalRuleSet) {
        *self.book.lock().unwrap_or_else(|p| p.into_inner()) = book;
    }
}

impl RulesProvider for BookMovesMidRead {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        None
    }
    fn active_rules_for(&self, _principal: &str) -> Option<ActiveRulesSnapshot> {
        let secondary = self.book.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let armed = self.next.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some((newer, hook)) = armed {
            self.set(newer);
            hook();
        }
        Some(ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(vec![]),
                secondary,
            },
        })
    }
}

/// A first contact installed while a pass is already planning from the book
/// without its address must outlive that pass: the plan never saw the address.
/// The pin installed right after it (route before pin) would otherwise be left
/// with no route until the next pass. A pass planned later without the address
/// takes the route out as any of ours.
#[test]
fn a_first_contact_outlives_the_pass_planned_before_it() {
    let api = Arc::new(MockWindowsApi::new());
    let only_a = || CanonicalRuleSet::from_rules(vec![ip_rule("a", 203, 0, 113, 1)]);
    let rules = Arc::new(BookMovesMidRead {
        book: Mutex::new(only_a()),
        next: Mutex::new(None),
    });
    let coord = Arc::new(SecondaryRouteCoordinator::new(
        Arc::clone(&api) as Arc<dyn RouteTablePort>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        Arc::new(FakePolicy::new()) as Arc<dyn RoutePolicySource>,
        Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
        Arc::new(|| false) as RuleScopeProvider,
    ));
    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .expect("recompute");

    let fresh = Ipv4Addr::new(203, 0, 113, 2);
    let routed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hook = {
        let coord = Arc::downgrade(&coord);
        let routed = Arc::clone(&routed);
        Box::new(move || {
            if let Some(coord) = coord.upgrade() {
                let n = coord.route_first_contact("S-IVANOV", &[IpAddr::V4(fresh)]);
                routed.store(n, std::sync::atomic::Ordering::SeqCst);
            }
        }) as Box<dyn FnOnce() + Send>
    };
    let with_b = CanonicalRuleSet::from_rules(vec![
        ip_rule("a", 203, 0, 113, 1),
        ip_rule("b", 203, 0, 113, 2),
    ]);
    *rules.next.lock().unwrap_or_else(|p| p.into_inner()) = Some((with_b, hook));

    let delta = coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .expect("recompute");
    assert_eq!(routed.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(delta.removed, 0, "{delta:?}");
    assert!(table_dests(&api).contains(&fresh));

    let delta = coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .expect("recompute");
    assert!(
        delta.is_noop(),
        "the pass that plans it finds it: {delta:?}"
    );

    rules.set(only_a());
    let delta = coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .expect("recompute");
    assert_eq!(delta.removed, 1, "{delta:?}");
    assert!(!table_dests(&api).contains(&fresh));
}

/// An empty cache whose next snapshot request runs `hook` first: something
/// landing while a pass is between its resolve and its plan.
#[derive(Default)]
struct HookOnSnapshot {
    live: MockFqdnCacheLookup,
    hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl FqdnCacheLookup for HookOnSnapshot {
    fn ips_for_hostname(&self, hostname: &str) -> Vec<IpAddr> {
        self.live.ips_for_hostname(hostname)
    }
    fn hostnames_under_suffix(&self, suffix: &str, limit: usize) -> Vec<String> {
        self.live.hostnames_under_suffix(suffix, limit)
    }
    fn hostnames_for_any_zone(&self, base: &str, limit: usize) -> Vec<String> {
        self.live.hostnames_for_any_zone(base, limit)
    }
    fn snapshot_for_compute(&self) -> Option<crate::fqdn_cache_lookup::FqdnCacheSnapshot> {
        let hook = self.hook.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(hook) = hook {
            hook();
        }
        None
    }
}

/// The tunnel is recreated under a new interface and the pass that follows
/// has resolved it, but not yet planned: a first contact landing then goes
/// through the new interface, not the one the previous pass saw.
#[test]
fn a_first_contact_during_a_pass_takes_the_link_that_pass_resolved() {
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("vpn", 78, true, true, Some([10, 0, 0, 1]));
    let vpn_id = vpn.stable_id();
    api.set_adapter_infos(vec![vpn]);
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("a", 203, 0, 113, 1)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &vpn_id);
    let cache = Arc::new(HookOnSnapshot::default());
    let coord = Arc::new(SecondaryRouteCoordinator::new(
        Arc::clone(&api) as Arc<dyn RouteTablePort>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        policy as Arc<dyn RoutePolicySource>,
        Arc::clone(&cache) as Arc<dyn FqdnCacheLookup>,
        Arc::new(|| false) as RuleScopeProvider,
    ));
    let sids = ["S-IVANOV".to_string()];
    coord.recompute_active(&sids).expect("first pass");

    // Same adapter, recreated under a new index.
    let mut again = adapter("vpn", 79, true, true, Some([10, 0, 0, 1]));
    again.mac = Some([0, 1, 2, 3, 4, 78]);
    assert_eq!(again.stable_id(), vpn_id);
    api.set_adapter_infos(vec![again]);
    let fresh = Ipv4Addr::new(203, 0, 113, 2);
    *cache.hook.lock().unwrap_or_else(|p| p.into_inner()) = Some({
        let coord = Arc::downgrade(&coord);
        let rules = Arc::clone(&rules);
        Box::new(move || {
            rules.set_secondary(
                "S-IVANOV",
                CanonicalRuleSet::from_rules(vec![
                    ip_rule("a", 203, 0, 113, 1),
                    ip_rule("b", 203, 0, 113, 2),
                ]),
            );
            if let Some(coord) = coord.upgrade() {
                coord.route_first_contact("S-IVANOV", &[IpAddr::V4(fresh)]);
            }
        }) as Box<dyn FnOnce() + Send>
    });
    coord.recompute_active(&sids).expect("second pass");

    let links: Vec<u32> = api
        .get_ip_forward_table()
        .expect("table")
        .iter()
        .filter(|r| r.destination == IpAddr::V4(fresh))
        .map(|r| r.interface_index)
        .collect();
    assert_eq!(links, vec![79], "never through the interface that is gone");
}

/// A pass that could not read the table names no LAN and no foreign tunnel, so
/// a first contact after it would plan blind and could pull such an address
/// into the tunnel: it waits for a pass that read the machine.
#[test]
fn a_first_contact_waits_out_a_pass_that_could_not_read_the_machine() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![
            ip_rule("a", 203, 0, 113, 1),
            ip_rule("b", 203, 0, 113, 2),
        ]),
    );
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));
    let fresh = [IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2))];

    api.set_route_table_read_error(Some("busy"));
    // Its outcome does not matter here: only what it read.
    let _ = coord.recompute_for("S-IVANOV", &res(Some(target())));
    assert_eq!(coord.route_first_contact("S-IVANOV", &fresh), 0);

    api.set_route_table_read_error(None);
    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .expect("recompute");
    assert_eq!(coord.route_first_contact("S-IVANOV", &fresh), 1);
}

/// A rule host's IPv6 front is first contact like its IPv4 one: its `/128`
/// goes in ahead of the full run through the link's v6 next hop — and only
/// when the link has one, or the route would attract traffic into a black
/// hole and the user would read the hang as a broken site.
#[test]
fn a_v6_first_contact_gets_its_slash_128_only_through_a_v6_capable_link() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    let v6: std::net::Ipv6Addr = "2001:db8::7".parse().expect("literal");
    let rule = CanonicalRule {
        id: RuleId("a6".into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V6(v6))),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    };
    rules.set_secondary("S-IVANOV", CanonicalRuleSet::from_rules(vec![rule]));
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));

    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .expect("recompute over a v4-only link");
    assert_eq!(
        coord.route_first_contact("S-IVANOV", &[IpAddr::V6(v6)]),
        0,
        "a link with no v6 next hop gets no /128"
    );

    let v6_link = SecondaryRouteTarget {
        gateway_v6: Some("fe80::1".parse().expect("literal")),
        ..target()
    };
    coord
        .recompute_for("S-IVANOV", &res(Some(v6_link)))
        .expect("recompute over a v6-capable link");
    // The recompute already routed the rule's own address; a fresh one the
    // book does not carry yet is what a first contact brings.
    let fresh: std::net::Ipv6Addr = "2001:db8::8".parse().expect("literal");
    let fresh_rule = CanonicalRule {
        id: RuleId("b6".into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V6(fresh))),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    };
    rules.set_secondary("S-IVANOV", CanonicalRuleSet::from_rules(vec![fresh_rule]));
    assert_eq!(
        coord.route_first_contact("S-IVANOV", &[IpAddr::V6(fresh)]),
        1,
        "the v6 first contact is routed ahead of the full run"
    );
    let routed = api
        .get_ip_forward_table()
        .expect("table")
        .into_iter()
        .find(|r| r.destination == IpAddr::V6(fresh))
        .expect("the /128 is in the table");
    assert_eq!(routed.prefix_length, 128);
    assert_eq!(
        routed.next_hop,
        IpAddr::V6("fe80::1".parse().expect("literal"))
    );
}

/// A first contact plans over the cache cut down to its own addresses. The
/// cut must not change a single decision about them: whatever the plan over
/// the whole cache routes among those addresses is routed, a shared one it
/// declines stays out, and nothing else comes along.
#[test]
fn a_first_contact_over_its_own_addresses_routes_what_the_full_plan_would() {
    use crate::fqdn_cache_lookup::SqliteFqdnCacheLookup;
    use nrr_domain::decision_lookup::FreshnessThresholds;
    use nrr_storage::dto::ResolutionEntry;
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::{CacheRepository, MigrationRunner};
    use nrr_storage::resolution_source::StorageResolutionSource;
    use nrr_storage::store::SqliteCacheStore;

    let conn = rusqlite::Connection::open_in_memory().expect("open");
    let runner = SqliteMigrationRunner::for_cache_db(conn);
    runner.run_pending_migrations().expect("migrate");
    let thresholds = FreshnessThresholds::default_production();
    let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(
        SqliteCacheStore::new(runner.into_connection(), thresholds.clone()),
    ));
    let lookup = Arc::new(SqliteFqdnCacheLookup::new(Arc::clone(&cache), thresholds));

    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    let suffix = CanonicalRule {
        id: RuleId("cdn".into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::SuffixDomain("cdn.example".into())),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    };
    rules.set_secondary("S-IVANOV", CanonicalRuleSet::from_rules(vec![suffix]));
    let coord = SecondaryRouteCoordinator::new(
        Arc::clone(&api) as Arc<dyn RouteTablePort>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        Arc::new(FakePolicy::new()) as Arc<dyn RoutePolicySource>,
        Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
        Arc::new(|| false) as RuleScopeProvider,
    );
    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .expect("recompute over a cold cache");

    let fresh = Ipv4Addr::new(203, 0, 113, 1);
    let shared = Ipv4Addr::new(203, 0, 113, 2);
    let not_asked = Ipv4Addr::new(203, 0, 113, 3);
    let unnamed = Ipv4Addr::new(198, 51, 100, 9);
    {
        let guard = cache.lock().expect("cache");
        for (host, ips) in [
            ("a.cdn.example", vec![fresh, shared]),
            ("b.cdn.example", vec![not_asked]),
            ("direct.example", vec![shared]),
        ] {
            guard
                .upsert_resolution(ResolutionEntry {
                    canonical_hostname: host.into(),
                    raw_hostname_sample: None,
                    resolved_ips: ips.into_iter().map(IpAddr::V4).collect(),
                    ttl_seconds: Some(300),
                    source: StorageResolutionSource::Dns,
                    resolved_at: std::time::SystemTime::now(),
                    active_revision_id: None,
                })
                .expect("upsert");
        }
        guard
            .record_shared_ip_direct_host(shared, "direct.example", 1, false)
            .expect("census");
    }
    let asked = [IpAddr::V4(fresh), IpAddr::V4(shared), IpAddr::V4(unnamed)];
    let rule_book = rules.active_rules_for("S-IVANOV").expect("rules").rule_book;
    let full_plan: HashSet<Ipv4Addr> = coord
        .planned_routes(
            "S-IVANOV",
            &res(Some(target())),
            coord.route_source.load_for_sid("S-IVANOV").as_ref(),
            &target(),
            &rule_book,
            lookup.as_ref(),
            &[],
            &crate::route_codegen::network_routes::NetworkRouteFacts::default(),
        )
        .routes
        .into_iter()
        .filter(|r| r.prefix_length == 32 && asked.contains(&r.destination))
        .filter_map(|r| match r.destination {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .collect();
    assert!(
        full_plan.contains(&fresh),
        "the oracle routes the rule host: {full_plan:?}"
    );

    let before = table_dests(&api);
    let routed = coord.route_first_contact("S-IVANOV", &asked);
    let added: HashSet<Ipv4Addr> = table_dests(&api).difference(&before).copied().collect();

    assert_eq!(
        added, full_plan,
        "the cut plan is the full plan for these addresses"
    );
    assert_eq!(routed, full_plan.len());
    assert!(!added.contains(&not_asked), "only what the answer brought");
}

#[test]
fn fail_closed_exemptions_seed_persisted_server_ips_before_reconnect() {
    // after a restart the in-memory server_ip_cache is
    // empty (the VPN has not reconnected), but the persisted loader seeds the
    // fail-closed exemptions so the block-all can still arm with a server hole.
    let api = Arc::new(MockWindowsApi::new());
    let persisted = Ipv4Addr::new(203, 0, 113, 77);
    let coord = coordinator(Arc::clone(&api), Arc::new(FakeRules::new()))
        .with_bootstrap_server_persistence(
            Arc::new(|_ips: &[Ipv4Addr]| {}),
            Arc::new(move || vec![persisted]),
        );
    let ex = coord.fail_closed_exemptions("S-1-5-21-A", &coord.read_machine());
    assert!(
        ex.bootstrap_server_ips.contains(&persisted),
        "persisted server IP seeds the fail-closed exemption before any live observation",
    );
}

#[test]
fn fail_closed_exemptions_without_persistence_is_unchanged() {
    // No persistence wired → empty exemption server set.
    let api = Arc::new(MockWindowsApi::new());
    let coord = coordinator(api, Arc::new(FakeRules::new()));
    let ex = coord.fail_closed_exemptions("S-1-5-21-A", &coord.read_machine());
    assert!(ex.bootstrap_server_ips.is_empty());
    assert!(ex.probe_target_ips.is_empty());
}

#[test]
fn fail_closed_exemptions_carry_probe_target_even_when_liveness_dead() {
    // The block-all must keep a hole for the liveness
    // probe's ICMP target (the tunnel next-hop). A probe-DEAD verdict
    // empties the GATED resolution — which is exactly when the block-all
    // arms — so the exemption must come from the RAW binding resolution,
    // or the armed block eats the probe's echo and the DEAD verdict can
    // never flip back (the kill-switch would stay fail-closed through
    // every VPN reconnect until service restart).
    let sid = "S-1-5-21-A";
    let gw = Ipv4Addr::new(10, 0, 0, 1);
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("examplevpnvpn", 78, true, true, Some([10, 0, 0, 1]));
    let vpn_id = vpn.stable_id();
    api.set_adapter_infos(vec![vpn]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary(sid, &vpn_id);

    // Alive tunnel (liveness disabled) → the gated resolution carries the
    // target and so must the exemptions.
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    );
    assert_eq!(
        coord
            .fail_closed_exemptions(sid, &coord.read_machine())
            .probe_target_ips,
        vec![gw]
    );

    // Probe-DEAD tunnel: a failure run older than the whole window makes
    // `is_dead` true, the gated resolution loses the secondary, and the
    // exemptions must still carry the raw next-hop.
    let tracker = Arc::new(SecondaryLivenessTracker::new(1));
    let dead_since = BootInstant::now()
        .checked_sub(std::time::Duration::from_secs(10))
        .expect("the clock reads past its start");
    // Baseline first: a DEAD verdict requires the peer to have answered
    // at least once (silent-from-birth gateways are unprobeable, not
    // dead) — and the evidence must be FRESH (records within the
    // evidence gap of "now"), so the failing run is recorded up to the
    // present rather than left in the past.
    tracker.record(78, true, dead_since);
    tracker.record(78, false, dead_since);
    tracker.record(78, false, BootInstant::now());
    assert!(
        tracker.is_dead(78, BootInstant::now()),
        "fixture must be DEAD"
    );
    let coord_dead = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy)
        .with_liveness_probe(
            tracker,
            Arc::new(nrr_platform_api::reachability::AlwaysReachableProbe),
        );
    assert_eq!(
        coord_dead
            .fail_closed_exemptions(sid, &coord_dead.read_machine())
            .probe_target_ips,
        vec![gw],
        "DEAD verdict must not drop the probe-target exemption",
    );
}

#[test]
fn probe_tick_forgets_the_failing_run_when_the_binding_stops_resolving() {
    // While a VPN reconnects, its adapter enumerates Down
    // (no IPv4) and the probe cannot run. The failing run accumulated just
    // before the outage must be dropped the moment the binding stops
    // resolving, or the stale window declares the tunnel DEAD the instant
    // it comes back Up and the kill-switch fail-closes a freshly
    // reconnected, working tunnel.
    let sid = "S-1-5-21-A";
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("examplevpnvpn", 60, true, true, Some([10, 88, 0, 1]));
    let vpn_id = vpn.stable_id();
    api.set_adapter_infos(vec![vpn]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary(sid, &vpn_id);
    let tracker = Arc::new(SecondaryLivenessTracker::new(10));
    let probe = Arc::new(nrr_platform_api::reachability::MockReachabilityProbe::new(
        false,
    ));
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy)
        .with_liveness_probe(Arc::clone(&tracker), probe);
    let sids = vec![sid.to_string()];
    coord.probe_active_secondaries(&sids);
    assert!(
        tracker.in_failing_run(60),
        "a failed probe starts a failing run"
    );
    // The adapter drops (VPN mid-reconnect) → the binding stops resolving.
    api.set_adapter_infos(vec![adapter("examplevpnvpn", 60, false, false, None)]);
    coord.probe_active_secondaries(&sids);
    assert!(
        !tracker.in_failing_run(60),
        "an unprobeable binding must forget the stale failing run"
    );
}

#[test]
fn probe_tick_forgets_the_failing_run_when_the_adapter_comes_back_under_a_new_ifindex() {
    // A recreated tunnel adapter keeps its NAME and gets a NEW ifindex, and
    // the liveness window is keyed by index. Left alone the old index keeps
    // its failing run forever (nothing probes it again), and the new index
    // inherits whatever an unrelated adapter left there — which would
    // declare a healthy tunnel dead on its first probe.
    let sid = "S-1-5-21-A";
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("examplevpnvpn", 60, true, true, Some([10, 88, 0, 1]));
    let vpn_id = vpn.stable_id();
    api.set_adapter_infos(vec![vpn]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary(sid, &vpn_id);
    let tracker = Arc::new(SecondaryLivenessTracker::new(10));
    let probe = Arc::new(nrr_platform_api::reachability::MockReachabilityProbe::new(
        false,
    ));
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy)
        .with_liveness_probe(Arc::clone(&tracker), probe);
    let sids = vec![sid.to_string()];
    coord.probe_active_secondaries(&sids);
    assert!(tracker.in_failing_run(60), "a failed probe starts a run");

    // Same adapter name, new ifindex — and the new index already carries a
    // failing run from whoever held it before.
    tracker.record(61, false, BootInstant::now());
    assert!(tracker.in_failing_run(61));
    api.set_adapter_infos(vec![adapter(
        "examplevpnvpn",
        61,
        true,
        true,
        Some([10, 88, 0, 1]),
    )]);
    coord.probe_active_secondaries(&sids);
    assert!(
        !tracker.in_failing_run(60),
        "the abandoned index must not keep a run nobody will ever clear"
    );
}

#[test]
fn no_next_hop_warn_latch_dedups_until_cleared() {
    let api = Arc::new(MockWindowsApi::new());
    let coord = coordinator(api, Arc::new(FakeRules::new()));
    assert!(coord.note_no_next_hop_once("S", "secondary"));
    assert!(
        !coord.note_no_next_hop_once("S", "secondary"),
        "same spell stays deduped"
    );
    assert!(
        coord.note_no_next_hop_once("S", "primary"),
        "latch is per (sid, role)"
    );
    coord.clear_no_next_hop("S", "secondary");
    assert!(
        coord.note_no_next_hop_once("S", "secondary"),
        "a successful resolution re-arms the warn"
    );
}

/// The tunnel drops and comes back under another interface before the pass
/// that follows has run: a first contact in between must not install a route
/// through the interface that is gone. Losing one first connection is the
/// price; a route on the old link would outlive the reconnect.
#[test]
fn a_first_contact_after_the_link_is_gone_waits_for_the_next_pass() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("a", 203, 0, 113, 1)]),
    );
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));
    let fresh = Ipv4Addr::new(203, 0, 113, 2);
    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .expect("recompute");
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![
            ip_rule("a", 203, 0, 113, 1),
            ip_rule("b", 203, 0, 113, 2),
        ]),
    );

    coord.forget_links(&[target().interface_index]);
    assert_eq!(
        coord.route_first_contact("S-IVANOV", &[IpAddr::V4(fresh)]),
        0
    );
    assert!(!table_dests(&api).contains(&fresh));

    let back = SecondaryRouteTarget {
        interface_index: 9,
        ..target()
    };
    coord
        .recompute_for("S-IVANOV", &res(Some(back)))
        .expect("recompute");
    let links: Vec<u32> = api
        .get_ip_forward_table()
        .expect("table")
        .iter()
        .filter(|r| r.destination == IpAddr::V4(fresh))
        .map(|r| r.interface_index)
        .collect();
    assert_eq!(links, vec![9], "{links:?}");
}

/// An unrelated adapter going away must not cost this user a first contact.
#[test]
fn another_adapter_going_away_keeps_the_first_contact() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("a", 203, 0, 113, 1)]),
    );
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));
    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .expect("recompute");
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![
            ip_rule("a", 203, 0, 113, 1),
            ip_rule("b", 203, 0, 113, 2),
        ]),
    );
    coord.forget_links(&[target().interface_index + 1]);
    assert_eq!(
        coord.route_first_contact("S-IVANOV", &[IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2))]),
        1
    );
}
