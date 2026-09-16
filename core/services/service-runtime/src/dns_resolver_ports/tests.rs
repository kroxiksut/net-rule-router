/// The id is one of three barriers between a forged answer and the cache
/// that routes, pins and kill-switch exemptions are derived from. It used
/// to be a counter: one observed query gave away every id after it.
#[test]
fn query_ids_are_not_a_counter() {
    let ids: Vec<u16> = (0..32).map(|_| next_query_id()).collect();
    let consecutive = ids
        .windows(2)
        .filter(|w| w[1] == w[0].wrapping_add(1))
        .count();
    assert!(
        consecutive < 4,
        "{consecutive} of 31 pairs increment by one, which is what a counter does: {ids:?}",
    );
    let distinct: std::collections::HashSet<u16> = ids.iter().copied().collect();
    assert!(distinct.len() > 24, "too many repeats: {ids:?}");
}

/// The query socket must be CONNECTED to the upstream it asks. Unconnected,
/// it accepts an answer from anyone who guesses the ephemeral port, and what
/// that answer feeds is the host cache the routes, pins and kill-switch
/// exemptions are derived from.
#[test]
fn the_query_socket_only_accepts_the_server_it_asked() {
    let server: std::net::SocketAddr = "127.0.0.1:5353".parse().expect("addr");
    let egress = crate::dns_egress::DnsEgress::primary(server);
    let sock = DirectUdpUpstreamResolver::open_socket(&egress).expect("socket");
    assert_eq!(
        sock.peer_addr().expect("connected socket has a peer"),
        server,
    );
}
use super::*;
use nrr_domain::canonical::{
    CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
};
use nrr_domain::{RouteBehaviorMode, RuleId};
use nrr_platform_api::dns::DnsResolverError;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::per_sid_orchestrator::ActiveRulesSnapshot;

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

// ── PortUpstreamResolver ──────────────────────────────────────────────────

struct FakeResolver {
    answer: Result<ResolvedRecord, DnsResolverError>,
}
impl DnsResolverPort for FakeResolver {
    fn resolve(
        &self,
        _hostname: &str,
        _family: AddressFamily,
    ) -> Result<ResolvedRecord, DnsResolverError> {
        self.answer.clone()
    }
}

// ── PoisonFallbackUpstreamResolver ────────────────────────────────────────

struct FixedUpstream {
    answer: Result<ResolvedAddresses, ResolveError>,
    calls: AtomicUsize,
}
impl FixedUpstream {
    fn new(answer: Result<ResolvedAddresses, ResolveError>) -> Arc<Self> {
        Arc::new(Self {
            answer,
            calls: AtomicUsize::new(0),
        })
    }
    fn ok(addresses: Vec<Ipv4Addr>) -> Arc<Self> {
        Self::new(Ok(ResolvedAddresses {
            addresses: addresses.into_iter().map(IpAddr::V4).collect(),
            ttl_seconds: 60,
        }))
    }
}
impl UpstreamResolver for FixedUpstream {
    fn resolve(
        &self,
        _hostname: &str,
        _family: AddressFamily,
    ) -> Result<ResolvedAddresses, ResolveError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.answer.clone()
    }
}

#[test]
fn poison_fallback_leaves_clean_answers_alone() {
    let inner = FixedUpstream::ok(vec![ip(23, 10, 20, 78)]);
    let fallback = FixedUpstream::ok(vec![ip(1, 2, 3, 4)]);
    let r = PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
        .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>]);
    assert_eq!(
        r.resolve("video.example", AddressFamily::Ipv4)
            .expect("clean")
            .addresses,
        vec![ip(23, 10, 20, 78)]
    );
    assert_eq!(
        fallback.calls.load(Ordering::SeqCst),
        0,
        "no fallback fired"
    );
}

#[test]
fn the_port_adapter_refuses_to_hand_a_placeholder_to_the_cache() {
    // What the seeder and the DNS refresh write goes straight into the
    // cache the relay dials from, so an unconfirmed placeholder there is a
    // rule pointing at nowhere that nothing re-queries.
    let port =
        UpstreamResolverPort::new(
            FixedUpstream::ok(vec![ip(192, 0, 2, 1), ip(203, 0, 113, 7)])
                as Arc<dyn UpstreamResolver>,
        );
    assert_eq!(
        port.resolve("secure.example", AddressFamily::Ipv4),
        Err(DnsResolverError::Timeout {
            hostname: "secure.example".to_string()
        }),
        "transient, not NXDOMAIN — the name exists, we were not told where"
    );
}

#[test]
fn the_port_adapter_passes_a_real_answer_through() {
    let port = UpstreamResolverPort::new(
        FixedUpstream::ok(vec![ip(23, 10, 20, 157)]) as Arc<dyn UpstreamResolver>
    );
    let record = port
        .resolve("WWW.Social.Example", AddressFamily::Ipv4)
        .expect("resolved");
    assert_eq!(record.canonical_hostname, "www.social.example");
    assert_eq!(record.addresses, vec![ip(23, 10, 20, 157)]);
}

#[test]
fn the_confirming_query_follows_the_egress_policy() {
    // On the primary link the interception that produced the placeholder
    // answers the confirmation too, so the second source agrees with the
    // first and nothing is ever pinned. The policy is what moves the query
    // somewhere the provider is not.
    let tunnel_resolver = spawn_fake_dns(|query| {
        vec![build_a_response(query, &[ip(23, 10, 20, 157)], 60).expect("resp")]
    });
    struct ViaTunnel(std::net::SocketAddr);
    impl crate::dns_egress::DnsEgressPolicy for ViaTunnel {
        fn decide(&self, _attempt: u32) -> Option<crate::dns_egress::DnsEgress> {
            Some(crate::dns_egress::DnsEgress {
                server: self.0,
                bind: None,
                via_secondary: true,
            })
        }
    }

    // Documentation space standing in for the name.
    let inner = FixedUpstream::ok(vec![ip(192, 0, 2, 1), ip(203, 0, 113, 7)]);
    let r = PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
        .with_egress(Arc::new(ViaTunnel(tunnel_resolver)));

    assert_eq!(
        r.resolve("www.social.example", AddressFamily::Ipv4)
            .expect("confirmed")
            .addresses,
        vec![ip(23, 10, 20, 157)]
    );
}

#[test]
fn poison_fallback_rescues_loopback_stub_answers() {
    // A filtering upstream answers the rule host with 127.0.0.1 — the
    // fallback's clean answer must win.
    let inner = FixedUpstream::ok(vec![ip(127, 0, 0, 1)]);
    let fallback = FixedUpstream::ok(vec![ip(23, 10, 20, 78)]);
    let r = PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
        .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>]);
    assert_eq!(
        r.resolve("www.video.example", AddressFamily::Ipv4)
            .expect("rescued")
            .addresses,
        vec![ip(23, 10, 20, 78)]
    );
}

#[test]
fn poison_fallback_rescues_nxdomain() {
    // The provider NXDOMAINs a rotating googlevideo node; a public resolver
    // knows it.
    let inner = FixedUpstream::new(Err(ResolveError::NoRecords));
    let fallback = FixedUpstream::ok(vec![ip(172, 217, 132, 74)]);
    let r = PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
        .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>]);
    assert_eq!(
        r.resolve("rr5.example", AddressFamily::Ipv4)
            .expect("rescued")
            .addresses,
        vec![ip(172, 217, 132, 74)]
    );
}

/// "Nothing to pin" arrives two ways, and only one of them is an alarm.
///
/// An answer full of placeholders is somebody interfering. An EMPTY answer is
/// what a zone apex normally has — most rule hosts are suffixes, and
/// `example.com` itself often carries no A record at all. Both leave nothing to
/// enforce on, so the resolver treats them alike; what must NOT be alike is the
/// verdict when a second source says the same thing, because agreement is
/// confirmation of absence, not a failure to confirm.
#[test]
fn an_empty_answer_and_a_placeholder_answer_both_carry_nothing_to_pin() {
    let empty = ResolvedAddresses {
        addresses: Vec::new(),
        ttl_seconds: 60,
    };
    let placeholder = ResolvedAddresses {
        addresses: vec![IpAddr::V4(ip(127, 0, 0, 1))],
        ttl_seconds: 60,
    };
    let real = ResolvedAddresses {
        addresses: vec![IpAddr::V4(ip(23, 10, 20, 78))],
        ttl_seconds: 60,
    };
    assert!(carries_nothing_to_pin(&empty));
    assert!(carries_nothing_to_pin(&placeholder));
    assert!(!carries_nothing_to_pin(&real));
    // A real address travelling beside a placeholder still leaves something to
    // enforce on — the screen drops the placeholder, it does not drop the answer.
    let mixed = ResolvedAddresses {
        addresses: vec![IpAddr::V4(ip(127, 0, 0, 1)), IpAddr::V4(ip(23, 10, 20, 78))],
        ttl_seconds: 60,
    };
    assert!(!carries_nothing_to_pin(&mixed));
}

#[test]
fn poison_fallback_returns_the_original_when_fallbacks_fail_too() {
    let inner = FixedUpstream::ok(vec![ip(127, 0, 0, 1)]);
    let dead = FixedUpstream::new(Err(ResolveError::Unavailable("down".into())));
    let poisoned_too = FixedUpstream::ok(vec![ip(0, 0, 0, 0)]);
    let r = PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
        .with_fallbacks(vec![
            Arc::clone(&dead) as Arc<dyn UpstreamResolver>,
            Arc::clone(&poisoned_too) as Arc<dyn UpstreamResolver>,
        ]);
    // Original poisoned answer comes back unchanged (downstream
    // sanitization refuses to cache/route it — behaviour unchanged).
    assert_eq!(
        r.resolve("app.example", AddressFamily::Ipv4)
            .expect("original")
            .addresses,
        vec![ip(127, 0, 0, 1)]
    );
    assert_eq!(dead.calls.load(Ordering::SeqCst), 1);
    assert_eq!(poisoned_too.calls.load(Ordering::SeqCst), 1);
}

/// The observed provider placeholder — a pair of `.0` addresses. It is not
/// loopback, so only the address-sanity screen catches it.
#[test]
fn poison_fallback_rescues_a_documentation_space_placeholder() {
    let inner = FixedUpstream::ok(vec![ip(192, 0, 2, 1), ip(203, 0, 113, 7)]);
    let fallback = FixedUpstream::ok(vec![ip(23, 10, 20, 135)]);
    let r = PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
        .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>]);
    assert_eq!(
        r.resolve("secure.example", AddressFamily::Ipv4)
            .expect("rescued")
            .addresses,
        vec![ip(23, 10, 20, 135)]
    );
}

/// A synthetic address travelling with a real one leaves the answer
/// usable — no second source, no added latency.
#[test]
fn poison_fallback_ignores_a_single_suspicious_address() {
    let inner = FixedUpstream::ok(vec![ip(192, 0, 2, 1), ip(23, 10, 20, 78)]);
    let fallback = FixedUpstream::ok(vec![ip(1, 2, 3, 4)]);
    let r = PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
        .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>]);
    assert_eq!(
        r.resolve("x.example", AddressFamily::Ipv4)
            .expect("clean")
            .addresses
            .len(),
        2
    );
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn address_reuse_by_an_unrelated_host_asks_a_second_source() {
    let recent = Arc::new(RecentRuleAddressIndex::new());
    let shared = vec![ip(203, 0, 55, 7), ip(203, 0, 55, 8)];
    recent.record("secure.example", &shared);

    let inner = FixedUpstream::ok(shared.clone());
    let fallback = FixedUpstream::ok(vec![ip(23, 10, 20, 159)]);
    let r = PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
        .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>])
        .with_recent_addresses(Arc::clone(&recent));
    assert_eq!(
        r.resolve("assistant.example", AddressFamily::Ipv4)
            .expect("rescued")
            .addresses,
        vec![ip(23, 10, 20, 159)]
    );
}

/// Re-resolving a host, and a genuinely shared front end, must not drag the
/// public resolvers in — that is the common case.
#[test]
fn re_resolution_and_shared_front_ends_do_not_ask_a_second_source() {
    let recent = Arc::new(RecentRuleAddressIndex::new());
    let shared = vec![ip(203, 0, 55, 7), ip(203, 0, 55, 8)];
    recent.record("static.chatapp.test", &shared);

    let inner = FixedUpstream::ok(shared.clone());
    let fallback = FixedUpstream::ok(vec![ip(1, 2, 3, 4)]);
    let r = PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
        .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>])
        .with_recent_addresses(Arc::clone(&recent));
    // Same origin, two labels deep.
    assert_eq!(
        r.resolve("crashlogs.chatapp.test", AddressFamily::Ipv4)
            .expect("clean")
            .addresses,
        shared
    );
    // An address nobody remembers ends the scan on the first lookup.
    let fresh = FixedUpstream::ok(vec![ip(203, 0, 55, 7), ip(198, 41, 30, 9)]);
    let r2 = PoisonFallbackUpstreamResolver::new(fresh as Arc<dyn UpstreamResolver>)
        .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>])
        .with_recent_addresses(recent);
    assert_eq!(
        r2.resolve("other.example", AddressFamily::Ipv4)
            .expect("clean")
            .addresses
            .len(),
        2
    );
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
}

/// One operator, two registrable domains (`claude.ai` / `api.anthropic.com`,
/// `chatapp.example` / `chatapp.test`) legitimately share a front end, and the
/// origin check cannot see it. The honest second source then answers with
/// the very address set that raised the alarm — testing IT for the same
/// suspicion would make confirmation impossible and tax every such query
/// with the full budget. Agreement is the proof.
#[test]
fn a_second_source_that_agrees_settles_the_reuse_alarm() {
    let recent = Arc::new(RecentRuleAddressIndex::new());
    let shared = vec![ip(160, 79, 104, 10)];
    recent.record("claude.ai", &shared);

    let inner = FixedUpstream::ok(shared.clone());
    // Same set, listed the other way round: agreement is about the set.
    let agrees = FixedUpstream::ok(shared.clone());
    let never = FixedUpstream::ok(vec![ip(1, 2, 3, 4)]);
    let r = PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
        .with_fallbacks(vec![
            Arc::clone(&agrees) as Arc<dyn UpstreamResolver>,
            Arc::clone(&never) as Arc<dyn UpstreamResolver>,
        ])
        .with_recent_addresses(recent);

    assert_eq!(
        r.resolve("api.anthropic.com", AddressFamily::Ipv4)
            .expect("confirmed")
            .addresses,
        shared
    );
    // The first agreement ends it — no walking the whole fallback list.
    assert_eq!(agrees.calls.load(Ordering::SeqCst), 1);
    assert_eq!(never.calls.load(Ordering::SeqCst), 0);
}

/// Agreement only rescues a set that could carry traffic — a second source
/// repeating a loopback placeholder confirms nothing.
#[test]
fn agreement_on_an_unusable_set_confirms_nothing() {
    let recent = Arc::new(RecentRuleAddressIndex::new());
    let shared = vec![ip(127, 0, 0, 1)];
    recent.record("secure.example", &shared);

    let inner = FixedUpstream::ok(shared.clone());
    let agrees = FixedUpstream::ok(shared.clone());
    let r = PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
        .with_fallbacks(vec![Arc::clone(&agrees) as Arc<dyn UpstreamResolver>])
        .with_recent_addresses(recent);

    assert_eq!(
        r.resolve("app.example", AddressFamily::Ipv4)
            .expect("original")
            .addresses,
        shared
    );
    assert_eq!(agrees.calls.load(Ordering::SeqCst), 1);
}

/// Without the memory wired the reuse trigger is simply off — it must never
/// fire on a fresh index and never panic.
#[test]
fn the_reuse_trigger_is_inert_when_the_memory_is_not_wired() {
    let inner = FixedUpstream::ok(vec![ip(203, 0, 55, 7)]);
    let fallback = FixedUpstream::ok(vec![ip(1, 2, 3, 4)]);
    let r = PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
        .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>]);
    assert_eq!(
        r.resolve("anything.example", AddressFamily::Ipv4)
            .expect("clean")
            .addresses,
        vec![ip(203, 0, 55, 7)]
    );
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
}

/// A second source that repeats the placeholder confirms nothing — the
/// upstream answer comes back and the downstream gate refuses to pin it.
#[test]
fn a_second_source_repeating_the_placeholder_is_not_a_confirmation() {
    let stub = vec![ip(192, 0, 2, 1), ip(203, 0, 113, 7)];
    let inner = FixedUpstream::ok(stub.clone());
    let echo = FixedUpstream::ok(stub.clone());
    let r = PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
        .with_fallbacks(vec![Arc::clone(&echo) as Arc<dyn UpstreamResolver>]);
    assert_eq!(
        r.resolve("secure.example", AddressFamily::Ipv4)
            .expect("original")
            .addresses,
        stub
    );
    assert_eq!(echo.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn poison_fallback_does_not_fire_on_transport_failure() {
    // Unavailable = the attempt/egress machinery's job; the fallback must
    // not add three more timeouts on top.
    let inner = FixedUpstream::new(Err(ResolveError::Unavailable("timeout".into())));
    let fallback = FixedUpstream::ok(vec![ip(1, 2, 3, 4)]);
    let r = PoisonFallbackUpstreamResolver::new(Arc::clone(&inner) as Arc<dyn UpstreamResolver>)
        .with_fallbacks(vec![Arc::clone(&fallback) as Arc<dyn UpstreamResolver>]);
    assert!(r.resolve("x.example", AddressFamily::Ipv4).is_err());
    assert_eq!(fallback.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn upstream_maps_record_ttl_and_default() {
    // TTL present → carried through.
    let r = PortUpstreamResolver::new(Arc::new(FakeResolver {
        answer: Ok(ResolvedRecord {
            canonical_hostname: "assistant.example".into(),
            addresses: vec![IpAddr::V4(ip(23, 10, 20, 159))],
            ttl_seconds: Some(42),
        }),
    }));
    assert_eq!(
        r.resolve("assistant.example", AddressFamily::Ipv4),
        Ok(ResolvedAddresses {
            addresses: vec![IpAddr::V4(ip(23, 10, 20, 159))],
            ttl_seconds: 42,
        })
    );
    // TTL absent → default.
    let r = PortUpstreamResolver::new(Arc::new(FakeResolver {
        answer: Ok(ResolvedRecord {
            canonical_hostname: "x.com".into(),
            addresses: vec![IpAddr::V4(ip(1, 2, 3, 4))],
            ttl_seconds: None,
        }),
    }));
    assert_eq!(
        r.resolve("x.com", AddressFamily::Ipv4).unwrap().ttl_seconds,
        DEFAULT_TTL_SECS
    );
}

#[test]
fn upstream_maps_authoritative_vs_transient_errors() {
    // NXDOMAIN (authoritative) → NoRecords.
    let r = PortUpstreamResolver::new(Arc::new(FakeResolver {
        answer: Err(DnsResolverError::NxDomain {
            hostname: "nope.example".into(),
        }),
    }));
    assert_eq!(
        r.resolve("nope.example", AddressFamily::Ipv4),
        Err(ResolveError::NoRecords)
    );
    // Timeout (transient) → Unavailable.
    let r = PortUpstreamResolver::new(Arc::new(FakeResolver {
        answer: Err(DnsResolverError::Timeout {
            hostname: "slow.example".into(),
        }),
    }));
    assert!(matches!(
        r.resolve("slow.example", AddressFamily::Ipv4),
        Err(ResolveError::Unavailable(_))
    ));
}

// ── ActiveRuleHostOracle ──────────────────────────────────────────────────

struct FakeRules {
    primary: CanonicalRuleSet,
    secondary: CanonicalRuleSet,
}
impl RulesProvider for FakeRules {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        Some(ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook {
                primary: self.primary.clone(),
                secondary: self.secondary.clone(),
            },
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        })
    }
}

fn exact_rule(id: &str, host: &str) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactFqdn(host.into())),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

#[test]
fn oracle_matches_secondary_rule_only() {
    let rules = Arc::new(FakeRules {
        primary: CanonicalRuleSet::from_rules(vec![exact_rule("r-p", "example.com")]),
        secondary: CanonicalRuleSet::from_rules(vec![exact_rule("r-s", "assistant.example")]),
    });
    let oracle = ActiveRuleHostOracle::new(rules, Arc::new(|| Some("S-1-5-21-1".to_string())));
    assert!(
        oracle.is_rule_host("assistant.example"),
        "secondary rule host"
    );
    assert!(
        !oracle.is_rule_host("example.com"),
        "primary-only match is not a secondary rule host"
    );
    assert!(!oracle.is_rule_host("random.net"), "unmatched host");
}

#[test]
fn oracle_fails_open_when_no_active_user() {
    let rules = Arc::new(FakeRules {
        primary: CanonicalRuleSet::from_rules(vec![]),
        secondary: CanonicalRuleSet::from_rules(vec![exact_rule("r-s", "assistant.example")]),
    });
    // No routing-active SID → nothing is a rule host (fail-open).
    let oracle = ActiveRuleHostOracle::new(rules, Arc::new(|| None));
    assert!(!oracle.is_rule_host("assistant.example"));
}

// ── ActiveSecondaryOwnedIps — direct-answer steering set ─────────────────

/// The  case: `workspace.search.example` (direct) shares every
/// front-end address with `aistudio.search.example` (secondary rule). While the
/// secondary cannot carry traffic those addresses are BLOCKED by the
/// fail-closed posture, so the steering set must stay armed — an empty set
/// here is what handed the direct host a set of addresses that could only
/// be dropped.
#[test]
fn steering_set_stays_armed_so_a_shared_direct_host_is_not_strangled() {
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use std::time::Instant;
    let shared = ip(23, 10, 20, 164);
    let fqdn = Arc::new(MockFqdnCacheLookup::new());
    fqdn.set_ips("aistudio.search.example", vec![shared]);
    let rules = Arc::new(FakeRules {
        primary: CanonicalRuleSet::from_rules(vec![]),
        secondary: CanonicalRuleSet::from_rules(vec![exact_rule("r-s", "aistudio.search.example")]),
    });
    let owned =
        ActiveSecondaryOwnedIps::new(rules, Arc::new(|| Some("S-1-5-21-1".to_string())), fqdn);
    let t0 = Instant::now();
    assert!(owned.owned_ips_at(t0).contains(&shared));
    // The posture the  gate used to blank: still armed, so the
    // listener strips the shared address from the direct host's answer (and,
    // when every address is shared, flags the reply for the collateral
    // rescue) instead of relaying addresses that will be dropped.
    let t1 = t0 + OWNED_SET_MEMO_TTL + Duration::from_millis(1);
    assert!(
        owned.owned_ips_at(t1).contains(&shared),
        "steering must not stand down while the secondary is unusable"
    );
}

/// An address the cache holds but no live resolution has confirmed inside
/// the enforcement window is not enforced, so it must not be steered away
/// from either — the steering set and the pin/block set read the same port
/// and therefore narrow together.
#[test]
fn steering_set_follows_the_enforcement_confirmation_window() {
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use std::time::Instant;
    let fqdn = Arc::new(MockFqdnCacheLookup::new());
    // The mock models "the port answered nothing for this host", which is
    // what the SQLite adapter does once every row falls out of the window.
    fqdn.set_ips("aistudio.search.example", vec![]);
    let rules = Arc::new(FakeRules {
        primary: CanonicalRuleSet::from_rules(vec![]),
        secondary: CanonicalRuleSet::from_rules(vec![exact_rule("r-s", "aistudio.search.example")]),
    });
    let owned =
        ActiveSecondaryOwnedIps::new(rules, Arc::new(|| Some("S-1-5-21-1".to_string())), fqdn);
    assert!(owned.owned_ips_at(Instant::now()).is_empty());
}

// ── build_resolution_entry ────────────────────────────────────────────────

#[test]
fn entry_drops_non_routable_and_keeps_ttl_and_source() {
    let now = SystemTime::UNIX_EPOCH;
    let resolved = ResolvedAddresses {
        addresses: vec![
            IpAddr::V4(ip(127, 0, 0, 1)),
            IpAddr::V4(ip(203, 0, 113, 7)),
            IpAddr::V4(ip(0, 0, 0, 0)),
        ],
        ttl_seconds: 77,
    };
    let entry = build_resolution_entry("assistant.example", &resolved, now).expect("routable IP");
    assert_eq!(entry.canonical_hostname, "assistant.example");
    assert_eq!(entry.resolved_ips, vec![ip(203, 0, 113, 7)]); // loopback + unspecified dropped
    assert_eq!(entry.ttl_seconds, Some(77));
    assert_eq!(entry.source, StorageResolutionSource::Dns);
}

#[test]
fn entry_is_none_when_all_non_routable() {
    // An ad-block hosts pin to 127.0.0.1 must NOT become a /32 out the secondary adapter.
    let resolved = ResolvedAddresses {
        addresses: vec![IpAddr::V4(ip(127, 0, 0, 1))],
        ttl_seconds: 60,
    };
    assert!(build_resolution_entry("blocked.example", &resolved, SystemTime::UNIX_EPOCH).is_none());
}

// ── HookSyncReconciler ────────────────────────────────────────────────────

#[test]
fn reconciler_installs_when_hook_completes_within_deadline() {
    let ran = Arc::new(AtomicUsize::new(0));
    let r = Arc::clone(&ran);
    let hook: RouteRecomputeHook = Arc::new(move || {
        r.fetch_add(1, Ordering::SeqCst);
    });
    let out = HookSyncReconciler::new(hook).reconcile_now(Duration::from_secs(2));
    assert_eq!(out, ReconcileOutcome::Installed);
    // `Installed` is only returned after the completion signal, which the
    // worker sends AFTER running the hook — so the reconcile really ran.
    assert_eq!(ran.load(Ordering::SeqCst), 1);
}

#[test]
fn reconciler_reports_deadline_exceeded_for_a_slow_hook() {
    // Hook far slower than the deadline → fail open on latency.
    let hook: RouteRecomputeHook = Arc::new(|| {
        std::thread::sleep(Duration::from_millis(300));
    });
    let out = HookSyncReconciler::new(hook).reconcile_now(Duration::from_millis(30));
    assert_eq!(out, ReconcileOutcome::DeadlineExceeded);
}

#[test]
fn concurrent_reconciles_coalesce_onto_a_shared_run() {
    // under the armed block-all a burst of direct-host answers
    // used to spawn a full reconcile EACH, convoying on the orchestrator
    // lock. Now concurrent callers must share hook runs: with 8 callers and
    // a 40 ms hook, thread-per-call would take 8 runs; coalescing needs at
    // most a handful (a run in flight when a caller registers cannot vouch
    // for it, so up to ~2-3 runs may still start).
    let ran = Arc::new(AtomicUsize::new(0));
    let r = Arc::clone(&ran);
    let hook: RouteRecomputeHook = Arc::new(move || {
        r.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(40));
    });
    let reconciler = Arc::new(HookSyncReconciler::new(hook));
    let callers: Vec<_> = (0..8)
        .map(|_| {
            let rc = Arc::clone(&reconciler);
            std::thread::spawn(move || rc.reconcile_now(Duration::from_secs(5)))
        })
        .collect();
    for caller in callers {
        assert_eq!(
            caller.join().expect("caller thread"),
            ReconcileOutcome::Installed,
            "a generous deadline must always confirm install"
        );
    }
    let runs = ran.load(Ordering::SeqCst);
    assert!(
        (1..=4).contains(&runs),
        "8 concurrent callers coalesced into {runs} hook runs (expected ≤4)"
    );
}

#[test]
fn a_caller_is_only_satisfied_by_a_run_that_started_after_its_request() {
    // The first call's run is already in flight when the second call
    // registers — the second must NOT be credited by it (its facts landed
    // mid-run) and instead waits for the next run. Observable effect: both
    // calls Installed, and the hook ran twice.
    let ran = Arc::new(AtomicUsize::new(0));
    let r = Arc::clone(&ran);
    let hook: RouteRecomputeHook = Arc::new(move || {
        r.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(60));
    });
    let reconciler = Arc::new(HookSyncReconciler::new(hook));
    let rc = Arc::clone(&reconciler);
    let first = std::thread::spawn(move || rc.reconcile_now(Duration::from_secs(5)));
    // Let the first run actually start before registering the second.
    std::thread::sleep(Duration::from_millis(20));
    let second = reconciler.reconcile_now(Duration::from_secs(5));
    assert_eq!(
        first.join().expect("first caller"),
        ReconcileOutcome::Installed
    );
    assert_eq!(second, ReconcileOutcome::Installed);
    assert_eq!(
        ran.load(Ordering::SeqCst),
        2,
        "the in-flight run must not satisfy a request registered after it started"
    );
}

// ── DirectUdpUpstreamResolver (HW-0714) ───────────────────────────────────

use crate::dns_wire::{build_a_response, build_error_response, RCODE_NXDOMAIN};
use std::net::UdpSocket;

/// One-shot fake DNS server on 127.0.0.1: receives a single query and sends
/// back every frame `reply` produces for it.
fn spawn_fake_dns(reply: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static) -> std::net::SocketAddr {
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake dns");
    let addr = sock.local_addr().expect("fake dns addr");
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("cfg fake dns");
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        if let Ok((n, src)) = sock.recv_from(&mut buf) {
            for frame in reply(&buf[..n]) {
                let _ = sock.send_to(&frame, src);
            }
        }
    });
    addr
}

#[test]
fn direct_udp_resolves_answers_and_ttl_from_fake_server() {
    let addr = spawn_fake_dns(|query| {
        // The response builders echo the query's id + question, so the
        // client's id/question match passes without knowing the id here.
        vec![build_a_response(query, &[ip(1, 2, 3, 4), ip(5, 6, 7, 8)], 90).expect("resp")]
    });
    let r = DirectUdpUpstreamResolver::new(addr, Duration::from_secs(2), 1);
    let resolved = r
        .resolve("assistant.example", AddressFamily::Ipv4)
        .expect("resolved");
    assert_eq!(resolved.addresses, vec![ip(1, 2, 3, 4), ip(5, 6, 7, 8)]);
    assert_eq!(resolved.ttl_seconds, 90);
}

#[test]
fn direct_udp_resolves_ptr_names_from_fake_server() {
    // Fake server replies to the PTR query with one PTR RR (owner = pointer
    // to the question, RDATA = uncompressed target name).
    let addr = spawn_fake_dns(|query| {
        let q = crate::dns_wire::parse_question(query).expect("question");
        let mut resp = query[..q.question_end].to_vec();
        resp[2] = 0x80; // QR=1
        resp[3] = 0x80; // RA, RCODE 0
        resp[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
        resp.extend_from_slice(&[0xC0, 0x0C]); // owner → question
        resp.extend_from_slice(&crate::dns_wire::QTYPE_PTR.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        resp.extend_from_slice(&3600u32.to_be_bytes());
        let mut rdata = Vec::new();
        for label in ["feed", "example"] {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);
        vec![resp]
    });
    let r = DirectUdpUpstreamResolver::new(addr, Duration::from_secs(2), 1);
    let names = r.resolve_ptr(ip(203, 0, 113, 100)).expect("ptr names");
    assert_eq!(names, vec!["feed.example".to_string()]);
}

#[test]
fn direct_udp_nxdomain_is_authoritative_no_records() {
    let addr =
        spawn_fake_dns(|query| vec![build_error_response(query, RCODE_NXDOMAIN).expect("nx")]);
    let r = DirectUdpUpstreamResolver::new(addr, Duration::from_secs(2), 3);
    assert_eq!(
        r.resolve("gone.example", AddressFamily::Ipv4),
        Err(ResolveError::NoRecords),
        "NXDOMAIN must not be retried as transient"
    );
}

#[test]
fn direct_udp_ignores_mismatched_datagram_then_accepts_answer() {
    let addr = spawn_fake_dns(|query| {
        let good = build_a_response(query, &[ip(9, 9, 9, 9)], 60).expect("resp");
        let mut wrong_id = good.clone();
        wrong_id[0] ^= 0xFF; // late reply of some other query
        vec![wrong_id, good]
    });
    let r = DirectUdpUpstreamResolver::new(addr, Duration::from_secs(2), 1);
    let resolved = r
        .resolve("assistant.example", AddressFamily::Ipv4)
        .expect("resolved");
    assert_eq!(resolved.addresses, vec![ip(9, 9, 9, 9)]);
}

#[test]
fn direct_udp_reports_unavailable_when_nothing_answers() {
    // Bind-then-drop reserves a port that is closed by the time we query:
    // the ICMP port-unreachable surfaces as a transient recv error, the
    // window drains, and the resolver reports Unavailable (never hangs).
    let addr = {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        sock.local_addr().expect("addr")
    };
    let r = DirectUdpUpstreamResolver::new(addr, Duration::from_millis(120), 2);
    match r.resolve("assistant.example", AddressFamily::Ipv4) {
        Err(ResolveError::Unavailable(_)) => {}
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[test]
fn direct_udp_unencodable_name_is_no_records_without_network() {
    // Never resolvable → authoritative, and no socket traffic is attempted
    // (the server address is irrelevant/unroutable here).
    let r = DirectUdpUpstreamResolver::new(
        std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
        Duration::from_millis(50),
        1,
    );
    assert_eq!(
        r.resolve("a..b", AddressFamily::Ipv4),
        Err(ResolveError::NoRecords)
    );
}

// ── HostsBypassDnsResolver (HW-0714) ──────────────────────────────────────

use nrr_platform_api::dns::MockDnsResolver;

fn system_with(host: &str, ips: &[Ipv4Addr]) -> Arc<dyn DnsResolverPort> {
    let mock = MockDnsResolver::new();
    mock.set_response(
        host,
        ResolvedRecord {
            canonical_hostname: host.to_string(),
            addresses: ips.iter().copied().map(IpAddr::V4).collect(),
            ttl_seconds: Some(300),
        },
    );
    Arc::new(mock)
}

#[test]
fn hosts_bypass_off_uses_the_system_resolver() {
    let r = HostsBypassDnsResolver::new(
        system_with("pinned.example", &[ip(10, 0, 0, 1)]),
        Arc::new(|| false),
        Arc::new(|| panic!("upstream must not be consulted when bypass is off")),
        Duration::from_millis(200),
    );
    let rec = r
        .resolve("pinned.example", AddressFamily::Ipv4)
        .expect("system answer");
    assert_eq!(rec.addresses, vec![ip(10, 0, 0, 1)]);
}

#[test]
fn hosts_bypass_on_resolves_directly_past_the_system() {
    let addr = spawn_fake_dns(|query| {
        vec![build_a_response(query, &[ip(203, 0, 113, 7)], 120).expect("resp")]
    });
    let r = HostsBypassDnsResolver::new(
        // System would answer with the hosts-file pin — must NOT be used.
        system_with("pinned.example", &[ip(127, 0, 0, 1)]),
        Arc::new(|| true),
        Arc::new(move || Some(addr)),
        Duration::from_secs(2),
    );
    let rec = r
        .resolve("pinned.example", AddressFamily::Ipv4)
        .expect("direct answer");
    assert_eq!(
        rec.addresses,
        vec![ip(203, 0, 113, 7)],
        "hosts pin bypassed"
    );
    assert_eq!(rec.ttl_seconds, Some(120));
    assert_eq!(rec.canonical_hostname, "pinned.example");
}

#[test]
fn hosts_bypass_falls_back_to_system_when_no_upstream() {
    let r = HostsBypassDnsResolver::new(
        system_with("host.example", &[ip(198, 51, 100, 4)]),
        Arc::new(|| true),
        Arc::new(|| None),
        Duration::from_millis(200),
    );
    let rec = r
        .resolve("host.example", AddressFamily::Ipv4)
        .expect("fallback answer");
    assert_eq!(rec.addresses, vec![ip(198, 51, 100, 4)]);
}

#[test]
fn hosts_bypass_falls_back_to_system_on_direct_timeout() {
    // Upstream present but nothing answers there (bind-then-drop reserves
    // a closed port) → transient direct failure → system fallback.
    let dead = {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        sock.local_addr().expect("addr")
    };
    let r = HostsBypassDnsResolver::new(
        system_with("host.example", &[ip(198, 51, 100, 9)]),
        Arc::new(|| true),
        Arc::new(move || Some(dead)),
        Duration::from_millis(120),
    );
    let rec = r
        .resolve("host.example", AddressFamily::Ipv4)
        .expect("fallback answer");
    assert_eq!(rec.addresses, vec![ip(198, 51, 100, 9)]);
}
