use super::*;
use nrr_platform_api::dns::AddressFamily;

/// A name one server calls non-existent is not settled: the machine may
/// hold a resolver for a namespace nobody outside has heard of. The field
/// case is a corporate host and a machine on the LAN, both of which
/// stopped resolving once every name was pointed at us.
#[test]
fn a_non_existent_reply_is_recognised_and_a_real_answer_is_not() {
    use crate::dns_wire::{build_address_query, build_error_response, RCODE_SERVFAIL};
    let query = build_address_query(0x4242, "host.corp.example", QTYPE_A).expect("query");

    let nx = build_error_response(&query, RCODE_NXDOMAIN).expect("nx");
    assert!(reply_is_nxdomain(&nx));

    // Every other outcome leaves the answer alone: a server failure is
    // retried elsewhere, and a real answer is the end of the question.
    let servfail = build_error_response(&query, RCODE_SERVFAIL).expect("servfail");
    assert!(!reply_is_nxdomain(&servfail));
    let answer = build_a_response(&query, &[Ipv4Addr::new(10, 0, 0, 4)], 60).expect("a");
    assert!(!reply_is_nxdomain(&answer));

    // A truncated buffer is not an answer at all, so it is not a
    // non-existence either — treating it as one would send every
    // malformed reply on a second round of queries.
    assert!(!reply_is_nxdomain(&[]));
    assert!(!reply_is_nxdomain(&[0u8; 3]));
}

/// The forward path relays bytes straight to the client's stub resolver, so
/// what it accepts becomes the OS cache and, downstream, the rule host cache
/// the routes and kill-switch exemptions are built from.
#[test]
fn a_forwarded_reply_is_accepted_only_when_it_answers_our_query() {
    use crate::dns_wire::build_address_query;
    let query = build_address_query(0x1234, "example.com", QTYPE_A).expect("query");

    let mut good = query.clone();
    good[2] |= 0x80; // QR = response
    assert!(reply_answers_query(&query, &good));

    // Somebody else's transaction.
    let mut wrong_id = good.clone();
    wrong_id[0] = 0xFF;
    assert!(!reply_answers_query(&query, &wrong_id));

    // Right id, different question - the shape a blind forger produces
    // when it guesses the id but not what was asked.
    let mut other = build_address_query(0x1234, "evil.example", QTYPE_A).expect("query");
    other[2] |= 0x80;
    assert!(!reply_answers_query(&query, &other));

    // A query echoed back is not an answer.
    assert!(!reply_answers_query(&query, &query));

    // Case differences in the echoed name are legal (0x20 encoding).
    let mut mixed = build_address_query(0x1234, "ExAmPlE.CoM", QTYPE_A).expect("query");
    mixed[2] |= 0x80;
    assert!(reply_answers_query(&query, &mixed));
}
use crate::dns_resolver::{ReconcileOutcome, ResolvedAddresses};
use crate::dns_wire::{parse_question, QTYPE_HTTPS};
use std::net::{IpAddr, Ipv4Addr};

// ── Fake ports ────────────────────────────────────────────────────────────

struct Oracle(Vec<String>);
impl RuleHostOracle for Oracle {
    fn is_rule_host(&self, hostname: &str) -> bool {
        self.0.iter().any(|h| h.as_str() == hostname)
    }
}
struct Upstream(Result<ResolvedAddresses, ResolveError>);
impl UpstreamResolver for Upstream {
    fn resolve_within(
        &self,
        _h: &str,
        _family: AddressFamily,
        _budget: Duration,
    ) -> Result<ResolvedAddresses, ResolveError> {
        self.0.clone()
    }
}
struct NoopSink;
impl FactSink for NoopSink {
    fn record(&self, _h: &str, _r: &ResolvedAddresses) {}
}
struct OkReconciler;
impl SyncReconciler for OkReconciler {
    fn reconcile_now(&self, _d: Duration) -> ReconcileOutcome {
        ReconcileOutcome::Installed
    }
}

fn listener(
    rule_hosts: &[&str],
    upstream: Result<ResolvedAddresses, ResolveError>,
) -> DnsInterceptListener {
    DnsInterceptListener::new(
        Arc::new(Oracle(rule_hosts.iter().map(|s| s.to_string()).collect())),
        Arc::new(Upstream(upstream)),
        Arc::new(NoopSink),
        Arc::new(OkReconciler),
        // TEST-NET-1 (RFC 5737): a forwarder that can never answer. Pointing
        // at 127.0.0.1:53 made these tests consult whatever resolver the
        // machine runs — our own service, when it is up.
        "192.0.2.1:53".parse().unwrap(),
        Duration::from_millis(150),
        Duration::from_millis(150),
    )
}

/// Stands in for the fake-IP layer: says whether IPv4 can carry a name,
/// without allocating anything.
struct CarriesOnV4(bool);
impl crate::dns_resolver::FakeIpAnswerer for CarriesOnV4 {
    fn fake_answer(&self, _hostname: &str) -> Option<Vec<std::net::Ipv4Addr>> {
        panic!("the AAAA branch must never allocate a lease")
    }
    fn carries_on_v4(&self, _hostname: &str) -> bool {
        self.0
    }
}

/// A rule host IPv4 can carry: its AAAA is answered NODATA so the client
/// falls back to the family our rules route.
#[test]
fn aaaa_for_a_rule_host_is_answered_nodata_when_ipv4_can_carry_it() {
    let l = listener(
        &["assistant.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    )
    .with_fake_ip(std::sync::Arc::new(CarriesOnV4(true)));
    match l.answer_query(&query("assistant.example", QTYPE_AAAA)) {
        ListenerAction::Respond(bytes) => {
            assert_eq!(bytes[3] & 0x0f, RCODE_NOERROR, "NOERROR, not NXDOMAIN");
            assert_eq!(&bytes[6..8], &[0, 0], "no answer records — NODATA");
        }
        other => panic!("expected a NODATA response, got {other:?}"),
    }
}

/// The whole point of the condition: a name IPv4 cannot carry keeps its
/// AAAA. Suppressing it would make a v6-only destination unreachable, which
/// the user reads as a broken network rather than as protection.
#[test]
fn aaaa_is_forwarded_when_ipv4_cannot_carry_the_name() {
    let l = listener(
        &["assistant.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    )
    .with_fake_ip(std::sync::Arc::new(CarriesOnV4(false)));
    assert_eq!(
        l.answer_query(&query("assistant.example", QTYPE_AAAA)),
        ListenerAction::Forward
    );
}

/// The hole is reported ONCE per name, not on every lookup: a browser asks
/// for the same host many times a minute, and a warning that repeats that
/// often is a warning nobody reads.
#[test]
fn a_rule_host_leaving_over_ipv6_is_reported_once() {
    let l = listener(
        &["assistant.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    )
    .with_fake_ip(std::sync::Arc::new(CarriesOnV4(false)));
    for _ in 0..3 {
        assert_eq!(
            l.answer_query(&query("assistant.example", QTYPE_AAAA)),
            ListenerAction::Forward
        );
    }
    let seen = l
        .aaaa_outside_policy_reported
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    assert_eq!(
        seen.len(),
        1,
        "three lookups of one name must leave one report"
    );
}

fn resolved6(ips: &[std::net::Ipv6Addr]) -> ResolvedAddresses {
    ResolvedAddresses {
        addresses: ips.iter().copied().map(IpAddr::V6).collect(),
        ttl_seconds: 300,
    }
}

fn carried(guard: crate::enforcement_planner::Ipv6Guard) -> Ipv6DispositionFn {
    Arc::new(move || guard)
}

/// The tunnel carries IPv6: the rule host's v6 is answered, not suppressed.
#[test]
fn aaaa_for_a_rule_host_is_routed_when_the_tunnel_carries_ipv6() {
    let v6: std::net::Ipv6Addr = "fd00::1".parse().expect("v6");
    let l = listener(&["assistant.example"], Ok(resolved6(&[v6])))
        .with_fake_ip(std::sync::Arc::new(CarriesOnV4(false)))
        .with_ipv6_disposition(carried(
            crate::enforcement_planner::Ipv6Guard::FiltersAndRoutes,
        ));
    match l.answer_query(&query("assistant.example", QTYPE_AAAA)) {
        ListenerAction::Respond(bytes) => {
            assert_eq!(bytes[3] & 0x0f, RCODE_NOERROR);
            assert_eq!(&bytes[6..8], &[0, 1], "one AAAA record");
        }
        other => panic!("expected an AAAA answer, got {other:?}"),
    }
}

/// Only the main link carries IPv6: handing out a v6 address the tunnel
/// cannot take would leak it or stall on the block. NODATA, no upstream.
#[test]
fn aaaa_for_a_rule_host_is_nodata_when_only_the_main_link_carries_ipv6() {
    let l = listener(
        &["assistant.example"],
        Err(ResolveError::Unavailable("must not be asked".into())),
    )
    .with_fake_ip(std::sync::Arc::new(CarriesOnV4(false)))
    .with_ipv6_disposition(carried(crate::enforcement_planner::Ipv6Guard::FiltersOnly));
    match l.answer_query(&query("assistant.example", QTYPE_AAAA)) {
        ListenerAction::Respond(bytes) => {
            assert_eq!(bytes[3] & 0x0f, RCODE_NOERROR, "NOERROR, not NXDOMAIN");
            assert_eq!(&bytes[6..8], &[0, 0], "no answer records — NODATA");
        }
        other => panic!("expected a NODATA response, got {other:?}"),
    }
}

/// A fake-IP host is carried by the relay on IPv4 even when the tunnel
/// carries IPv6 — a real v6 answer would route around the relay.
#[test]
fn a_fake_ip_host_keeps_its_aaaa_suppressed_when_the_tunnel_carries_ipv6() {
    let v6: std::net::Ipv6Addr = "fd00::1".parse().expect("v6");
    let l = listener(&["assistant.example"], Ok(resolved6(&[v6])))
        .with_fake_ip(std::sync::Arc::new(CarriesOnV4(true)))
        .with_ipv6_disposition(carried(
            crate::enforcement_planner::Ipv6Guard::FiltersAndRoutes,
        ));
    match l.answer_query(&query("assistant.example", QTYPE_AAAA)) {
        ListenerAction::Respond(bytes) => assert_eq!(&bytes[6..8], &[0, 0], "NODATA"),
        other => panic!("expected a NODATA response, got {other:?}"),
    }
}

/// A host no rule covers is none of our business in either family.
#[test]
fn aaaa_for_a_non_rule_host_is_forwarded() {
    let l = listener(
        &["assistant.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    )
    .with_fake_ip(std::sync::Arc::new(CarriesOnV4(true)));
    assert_eq!(
        l.answer_query(&query("example.com", QTYPE_AAAA)),
        ListenerAction::Forward
    );
}

fn query(name: &str, qtype: u16) -> Vec<u8> {
    let mut p = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x01]);
    p
}

fn question(packet: &[u8]) -> crate::dns_wire::ParsedQuestion {
    parse_question(packet).expect("a well-formed question")
}

fn resolved(ips: &[Ipv4Addr]) -> ResolvedAddresses {
    ResolvedAddresses {
        addresses: ips.iter().copied().map(IpAddr::V4).collect(),
        ttl_seconds: 300,
    }
}

#[test]
fn intercepts_a_rule_host_and_builds_answer() {
    let l = listener(
        &["assistant.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 0, 159)])),
    );
    match l.answer_query(&query("assistant.example", QTYPE_A)) {
        ListenerAction::Respond(resp) => {
            let q = parse_question(&resp).expect("response parses");
            assert_eq!(q.qname, "assistant.example");
            assert_eq!(resp[2] & 0x80, 0x80, "QR set");
            assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "one answer");
            // RDATA is the resolved IP.
            assert_eq!(&resp[resp.len() - 4..], &[100, 64, 0, 159]);
        }
        other => panic!("expected Respond, got {other:?}"),
    }
}

#[test]
fn forwards_aaaa_and_steers_non_rule_a() {
    let l = listener(
        &["assistant.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    );
    // AAAA for a rule host with the default fake-IP port: `carries_on_v4`
    // is false, so IPv4 cannot carry the name and its AAAA is forwarded
    // untouched. Suppression is asserted separately, where v4 CAN carry it.
    assert_eq!(
        l.answer_query(&query("assistant.example", 28)),
        ListenerAction::Forward
    );
    // A for a non-rule host → forward WITH direct-answer steering.
    assert_eq!(
        l.answer_query(&query("example.com", QTYPE_A)),
        ListenerAction::ForwardFiltered
    );
}

#[test]
fn https_rr_is_forwarded_raw_for_rule_and_direct_hosts() {
    // Pins today's behaviour, which is a known hole rather than a decision:
    // an HTTPS answer's `ipv4hint` carries real addresses past both the
    // rule-host interception and the direct-answer steering. CDN-fronted
    // names populate that hint in practice.
    let l = listener(
        &["assistant.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    );
    assert_eq!(
        l.answer_query(&query("assistant.example", QTYPE_HTTPS)),
        ListenerAction::Forward,
        "rule host: not intercepted"
    );
    assert_eq!(
        l.answer_query(&query("example.com", QTYPE_HTTPS)),
        ListenerAction::Forward,
        "direct host: not even steered"
    );
}

// ── direct-answer steering ────────────────────────────────────────

struct OwnedSet(Arc<std::collections::HashSet<Ipv4Addr>>);
impl crate::dns_resolver::SecondaryOwnedIps for OwnedSet {
    fn secondary_owned_ips(&self) -> Arc<std::collections::HashSet<Ipv4Addr>> {
        Arc::clone(&self.0)
    }
}

fn steering_listener(owned: &[Ipv4Addr]) -> DnsInterceptListener {
    listener(
        &["assistant.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    )
    .with_direct_answer_steering(Arc::new(OwnedSet(Arc::new(
        owned.iter().copied().collect(),
    ))))
}

/// Build an upstream-style reply to `query(name, A)` carrying `ips`.
fn reply_for(name: &str, ips: &[Ipv4Addr]) -> Vec<u8> {
    crate::dns_wire::build_a_response(&query(name, QTYPE_A), ips, 300).expect("reply")
}

#[test]
fn steering_passes_clean_answers_through_untouched() {
    let l = steering_listener(&[Ipv4Addr::new(100, 64, 9, 9)]);
    let q = query("www.search.example", QTYPE_A);
    let reply = reply_for("www.search.example", &[Ipv4Addr::new(100, 64, 0, 147)]);
    assert_eq!(
        l.steer_direct_answer(&q, &question(&q), reply.clone(), QUERY_BUDGET),
        (reply, false)
    );
}

#[test]
fn steering_drops_secondary_pinned_addresses() {
    let pinned = Ipv4Addr::new(100, 64, 0, 151);
    let clean = Ipv4Addr::new(100, 64, 0, 134);
    let l = steering_listener(&[pinned]);
    let q = query("www.search.example", QTYPE_A);
    let reply = reply_for("www.search.example", &[pinned, clean]);
    let (steered, still_pinned) = l.steer_direct_answer(&q, &question(&q), reply, QUERY_BUDGET);
    assert!(!still_pinned, "a partially clean answer is not pinned");
    let out =
        crate::dns_wire::parse_address_response(0x1234, "www.search.example", QTYPE_A, &steered);
    match out {
        crate::dns_wire::AddressResponseOutcome::Answers { addresses, .. } => {
            assert_eq!(addresses, vec![clean], "pinned address filtered out");
        }
        other => panic!("expected Answers, got {other:?}"),
    }
}

#[test]
fn steering_with_empty_owned_set_is_a_no_op() {
    let l = steering_listener(&[]);
    let q = query("www.search.example", QTYPE_A);
    let pinned = Ipv4Addr::new(100, 64, 0, 151);
    let reply = reply_for("www.search.example", &[pinned]);
    assert_eq!(
        l.steer_direct_answer(&q, &question(&q), reply.clone(), QUERY_BUDGET),
        (reply, false)
    );
}

#[test]
fn steering_relays_error_replies_unchanged() {
    let l = steering_listener(&[Ipv4Addr::new(100, 64, 1, 1)]);
    let q = query("www.search.example", QTYPE_A);
    let nx = crate::dns_wire::build_error_response(&q, RCODE_NXDOMAIN).expect("nx");
    assert_eq!(
        l.steer_direct_answer(&q, &question(&q), nx.clone(), QUERY_BUDGET),
        (nx, false)
    );
}

#[test]
fn steering_reports_a_fully_pinned_reply() {
    // Every address is secondary-pinned, and the test forwarder (127.0.0.1
    // with a 150 ms budget) cannot produce a clean re-query → the terminal
    // fail-open path must hand the reply back flagged, so the caller can
    // offer it to the collateral fake-IP rescue.
    let pinned = Ipv4Addr::new(100, 64, 0, 133);
    let l = steering_listener(&[pinned]);
    let q = query("workspace.search.example", QTYPE_A);
    let reply = reply_for("workspace.search.example", &[pinned]);
    assert_eq!(
        l.steer_direct_answer(&q, &question(&q), reply.clone(), QUERY_BUDGET),
        (reply, true)
    );
}

#[test]
fn doh_canary_gets_nxdomain_before_rule_gate_for_any_qtype() {
    // the Firefox DoH canary is NOT a rule host, yet must
    // be answered NXDOMAIN (not forwarded) so Firefox disables DoH. Verify for
    // both A and HTTPS (type 65) qtypes and a subdomain.
    let l = listener(
        &["assistant.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    );
    for (name, qtype) in [
        ("use-application-dns.net", QTYPE_A),
        ("use-application-dns.net", QTYPE_HTTPS),
        ("x.use-application-dns.net", QTYPE_A),
    ] {
        match l.answer_query(&query(name, qtype)) {
            ListenerAction::Respond(resp) => {
                assert_eq!(resp[3] & 0x0F, RCODE_NXDOMAIN, "{name}/{qtype} → NXDOMAIN");
                assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "no answers");
            }
            other => panic!("expected NXDOMAIN Respond for {name}, got {other:?}"),
        }
    }
}

#[test]
fn rule_host_no_records_returns_nxdomain() {
    let l = listener(&["gone.example"], Err(ResolveError::NoRecords));
    match l.answer_query(&query("gone.example", QTYPE_A)) {
        ListenerAction::Respond(resp) => {
            assert_eq!(resp[3] & 0x0F, RCODE_NXDOMAIN);
            assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "no answers");
        }
        other => panic!("expected NXDOMAIN Respond, got {other:?}"),
    }
}

#[test]
fn rule_host_upstream_unavailable_fails_open_to_forward() {
    let l = listener(
        &["assistant.example"],
        Err(ResolveError::Unavailable("timeout".into())),
    );
    // Our resolver failed — forward raw so the OS server can still answer.
    assert_eq!(
        l.answer_query(&query("assistant.example", QTYPE_A)),
        ListenerAction::Forward
    );
}

#[test]
fn unparseable_datagram_is_forwarded() {
    let l = listener(
        &["assistant.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    );
    assert_eq!(l.answer_query(&[0u8; 3]), ListenerAction::Forward);
}

// ── S4.8 — direct-host fake-IP under block-all (variant A) ───────────────

/// Claims every host: returns one fixed fake address and records what the
/// listener offered (host + the steered real set).
struct ClaimingFake {
    fake: Ipv4Addr,
    seen: std::sync::Mutex<Vec<(String, Vec<Ipv4Addr>)>>,
}
impl DirectFakeIpAnswerer for ClaimingFake {
    fn fake_direct_answer(&self, hostname: &str, real: &[Ipv4Addr]) -> Option<Vec<Ipv4Addr>> {
        self.seen
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((hostname.to_string(), real.to_vec()));
        Some(vec![self.fake])
    }
}

#[test]
fn direct_fake_rewrites_the_reply_and_sees_the_steered_addresses() {
    let fake = Ipv4Addr::new(198, 18, 0, 7);
    let claiming = Arc::new(ClaimingFake {
        fake,
        seen: std::sync::Mutex::new(Vec::new()),
    });
    let l = listener(
        &["assistant.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    )
    .with_direct_fake_ip(Arc::clone(&claiming) as Arc<dyn DirectFakeIpAnswerer>);
    let q = query("blog.example", QTYPE_A);
    let real = Ipv4Addr::new(203, 0, 113, 68);
    let reply = reply_for("blog.example", &[real]);
    let out = l
        .fake_direct_response(&q, &question(&q), &reply)
        .expect("claimed");
    match crate::dns_wire::parse_address_response(0x1234, "blog.example", QTYPE_A, &out) {
        crate::dns_wire::AddressResponseOutcome::Answers { addresses, .. } => {
            assert_eq!(
                addresses,
                vec![fake],
                "client is handed the virtual address"
            );
        }
        other => panic!("expected Answers, got {other:?}"),
    }
    // The answerer saw the FINAL (steered) real set — what the relay dials.
    let seen = claiming.seen.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(seen.as_slice(), &[("blog.example".to_string(), vec![real])]);
}

#[test]
fn direct_fake_declines_leave_the_gate_path_in_charge() {
    // Default (Noop) answerer → never claims → caller falls back to the
    // gate + steered-reply path.
    let l = listener(
        &["assistant.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    );
    let q = query("blog.example", QTYPE_A);
    let reply = reply_for("blog.example", &[Ipv4Addr::new(203, 0, 113, 68)]);
    assert_eq!(l.fake_direct_response(&q, &question(&q), &reply), None);
    // Even a claiming answerer must not rewrite an NXDOMAIN / error reply.
    let claiming = Arc::new(ClaimingFake {
        fake: Ipv4Addr::new(198, 18, 0, 7),
        seen: std::sync::Mutex::new(Vec::new()),
    });
    let l = listener(
        &["assistant.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    )
    .with_direct_fake_ip(claiming as Arc<dyn DirectFakeIpAnswerer>);
    let nx = crate::dns_wire::build_error_response(&q, RCODE_NXDOMAIN).expect("nx");
    assert_eq!(l.fake_direct_response(&q, &question(&q), &nx), None);
}

// ── Collateral rescue — fully pinned direct host → virtual address ───────

struct StubCompanions(&'static str);
impl CompanionCandidateLookup for StubCompanions {
    fn is_pending_secondary_companion(&self, hostname: &str) -> bool {
        hostname == self.0
    }
}

#[test]
fn a_parked_companion_suggestion_vetoes_the_collateral_rescue() {
    let l = listener(
        &["insta.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    )
    .with_companion_candidates(Arc::new(StubCompanions("static.cdninsta.test")));
    // The CDN of a site routed over the additional link: it belongs there,
    // not on the primary, whatever addresses it shares.
    assert!(l.companion_is_pending(&question(&query("static.cdninsta.test", QTYPE_A))));
    // An unrelated direct host stays collateral.
    assert!(!l.companion_is_pending(&question(&query("blog.example", QTYPE_A))));
}

#[test]
fn collateral_fake_rewrites_a_fully_pinned_reply() {
    let fake = Ipv4Addr::new(198, 18, 0, 9);
    let claiming = Arc::new(ClaimingFake {
        fake,
        seen: std::sync::Mutex::new(Vec::new()),
    });
    let l = listener(
        &["aistudio.search.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    )
    .with_collateral_fake_ip(Arc::clone(&claiming) as Arc<dyn DirectFakeIpAnswerer>);
    let q = query("workspace.search.example", QTYPE_A);
    let pinned = Ipv4Addr::new(100, 64, 0, 133);
    let reply = reply_for("workspace.search.example", &[pinned]);
    let out = l
        .fake_collateral_response(&q, &question(&q), &reply)
        .expect("claimed");
    match crate::dns_wire::parse_address_response(0x1234, "workspace.search.example", QTYPE_A, &out)
    {
        crate::dns_wire::AddressResponseOutcome::Answers { addresses, .. } => {
            assert_eq!(addresses, vec![fake], "client gets the virtual address");
        }
        other => panic!("expected Answers, got {other:?}"),
    }
    // The rescue recorded the pinned real set — what the relay must dial
    // (out the primary; the route selector maps a non-rule host there).
    let seen = claiming.seen.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(
        seen.as_slice(),
        &[("workspace.search.example".to_string(), vec![pinned])]
    );
}

#[test]
fn collateral_fake_defaults_to_noop_and_skips_error_replies() {
    // Default (Noop) → never claims → the old fail-open path stands.
    let l = listener(
        &["assistant.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    );
    let q = query("workspace.search.example", QTYPE_A);
    let reply = reply_for(
        "workspace.search.example",
        &[Ipv4Addr::new(100, 64, 0, 133)],
    );
    assert_eq!(l.fake_collateral_response(&q, &question(&q), &reply), None);
    // A claiming answerer must not rewrite an NXDOMAIN / error reply.
    let claiming = Arc::new(ClaimingFake {
        fake: Ipv4Addr::new(198, 18, 0, 9),
        seen: std::sync::Mutex::new(Vec::new()),
    });
    let l = listener(
        &["assistant.example"],
        Ok(resolved(&[Ipv4Addr::new(100, 64, 1, 4)])),
    )
    .with_collateral_fake_ip(claiming as Arc<dyn DirectFakeIpAnswerer>);
    let nx = crate::dns_wire::build_error_response(&q, RCODE_NXDOMAIN).expect("nx");
    assert_eq!(l.fake_collateral_response(&q, &question(&q), &nx), None);
}
// ── Per-datagram budget ──────────────────────────────────────────────────

#[test]
fn the_budget_cuts_a_forward_short_of_its_own_timeout() {
    // The stage timeout is the ceiling, the budget is the floor of the two:
    // spending two seconds on a client that re-asked a second ago is spent
    // for nobody.
    let l = DnsInterceptListener::new(
        Arc::new(Oracle(Vec::new())),
        Arc::new(Upstream(Ok(resolved(&[])))),
        Arc::new(NoopSink),
        Arc::new(OkReconciler),
        "192.0.2.1:53".parse().expect("test-net address"),
        Duration::from_millis(150),
        Duration::from_secs(2),
    );
    let started = Instant::now();
    assert_eq!(
        l.forward_within(&query("example.com", QTYPE_A), Duration::from_millis(200)),
        None
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the 2 s forward timeout must not outlive a 200 ms budget (took {:?})",
        started.elapsed()
    );
}

#[test]
fn an_exhausted_budget_forwards_nothing_at_all() {
    let l = listener(&[], Ok(resolved(&[])));
    let started = Instant::now();
    assert_eq!(
        l.forward_within(&query("example.com", QTYPE_A), Duration::ZERO),
        None
    );
    assert!(started.elapsed() < Duration::from_millis(50));
}

#[test]
fn a_failed_forward_answers_servfail_instead_of_saying_nothing() {
    // Silence makes the client wait out its own timeout on top of ours; the
    // answer it is waiting for is not coming either way.
    let l = listener(&[], Ok(resolved(&[])));
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("server socket");
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client socket");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    let q = query("example.com", QTYPE_A);
    l.handle_datagram(
        &server,
        &q,
        client.local_addr().expect("client addr"),
        RULE_HOST_LANE_WAIT,
    );
    let mut buf = [0u8; 512];
    let n = client.recv(&mut buf).expect("a reply, not silence");
    assert!(n >= 12);
    assert_eq!(buf[0..2], q[0..2], "same transaction id");
    assert_eq!(buf[2] & 0x80, 0x80, "QR set");
    assert_eq!(buf[3] & 0x0F, RCODE_SERVFAIL);
}

// ── Direct path ───────────────────────────────────────────────────────────

const DIRECT_PINNED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DIRECT_CLEAN: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);

/// Pins what a direct (non-rule) host hears for each query type: an `A`
/// answer loses only the addresses the additional route owns, anything else
/// is relayed as the upstream gave it.
#[test]
fn the_direct_path_answers_each_query_type_as_before() {
    let l = steering_listener(&[DIRECT_PINNED]);

    let a = query("shared.example", QTYPE_A);
    assert_eq!(l.answer_query(&a), ListenerAction::ForwardFiltered);
    let heard = l.answer_direct(
        &a,
        &question(&a),
        reply_for("shared.example", &[DIRECT_PINNED, DIRECT_CLEAN]),
        QUERY_BUDGET,
    );
    match crate::dns_wire::parse_address_response(0x1234, "shared.example", QTYPE_A, &heard) {
        crate::dns_wire::AddressResponseOutcome::Answers { addresses, .. } => {
            assert_eq!(addresses, vec![IpAddr::V4(DIRECT_CLEAN)]);
        }
        other => panic!("expected the steered answer, got {other:?}"),
    }
    let clean = reply_for("shared.example", &[DIRECT_CLEAN]);
    assert_eq!(
        l.answer_direct(&a, &question(&a), clean.clone(), QUERY_BUDGET),
        clean,
        "a clean answer is relayed byte for byte"
    );

    for qtype in [QTYPE_AAAA, QTYPE_HTTPS] {
        assert_eq!(
            l.answer_query(&query("shared.example", qtype)),
            ListenerAction::Forward,
            "qtype {qtype} is relayed untouched"
        );
    }
}

#[test]
fn the_doh_canary_matches_without_regard_to_case_or_root_dot() {
    use crate::dns_resolver::is_doh_canary;
    for name in [
        "use-application-dns.net",
        "USE-Application-DNS.net.",
        "x.use-application-dns.net",
        ".use-application-dns.net",
    ] {
        assert!(is_doh_canary(name), "{name}");
    }
    for name in [
        "xuse-application-dns.net",
        "application-dns.net",
        "use-application-dns.net.example",
        "",
    ] {
        assert!(!is_doh_canary(name), "{name}");
    }
}

// ── Short-name completion ─────────────────────────────────────────────────

/// Answers every question from `answer`; stops after two quiet seconds.
fn fake_resolver(answer: fn(&[u8], &str) -> Option<Vec<u8>>) -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("resolver socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("resolver timeout");
    let addr = socket.local_addr().expect("resolver addr");
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            let q = &buf[..n];
            let Some(name) = parse_question(q).map(|p| p.qname) else {
                continue;
            };
            if let Some(reply) = answer(q, name.trim_end_matches('.')) {
                let _ = socket.send_to(&reply, from);
            }
        }
    });
    addr
}

/// Knows the printer's IPv4 only, and answers every question about it with it.
fn v4_only_printer(q: &[u8], name: &str) -> Option<Vec<u8>> {
    (name == "printer.branch.corp.example")
        .then(|| build_a_response(q, &[Ipv4Addr::new(192, 0, 2, 31)], 60))
        .flatten()
}

fn short_name_listener(namespaces: bool) -> DnsInterceptListener {
    short_name_listener_answering(namespaces, v4_only_printer)
}

fn short_name_listener_answering(
    namespaces: bool,
    answer: fn(&[u8], &str) -> Option<Vec<u8>>,
) -> DnsInterceptListener {
    let corporate = fake_resolver(answer);
    let l = DnsInterceptListener::new(
        Arc::new(Oracle(Vec::new())),
        Arc::new(Upstream(Ok(resolved(&[])))),
        Arc::new(NoopSink),
        Arc::new(OkReconciler),
        "192.0.2.1:53".parse().expect("test-net address"),
        Duration::from_millis(150),
        Duration::from_millis(500),
    )
    .with_resolver_port(corporate.port());
    if !namespaces {
        return l;
    }
    let claims = crate::dns_resolver_service::ClaimsSnapshot::default();
    claims.publish(Arc::new([
        nrr_platform_api::dns_redirect::DnsNamespaceExemption {
            suffix: "branch.corp.example".to_string(),
            servers: vec![Ipv4Addr::LOCALHOST],
        },
    ]));
    l.with_claimed_namespaces(claims)
}

/// The field case: a corporate host reached by its bare name, which the
/// public upstream has already called non-existent.
#[test]
fn a_short_name_is_completed_with_the_namespace_its_connection_claims() {
    let q = query("printer", QTYPE_A);
    let budget = Duration::from_secs(2);
    let reply = short_name_listener(true)
        .complete_single_label(&q, "printer", budget)
        .expect("the completed answer");
    let id = u16::from_be_bytes([q[0], q[1]]);
    match crate::dns_wire::parse_address_response(id, "printer", QTYPE_A, &reply) {
        crate::dns_wire::AddressResponseOutcome::Answers { addresses, .. } => {
            assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 31))]);
        }
        other => panic!("answered against the original question, got {other:?}"),
    }

    // Positive control: the same resolver with no claim completes nothing.
    assert_eq!(
        short_name_listener(false).complete_single_label(&q, "printer", budget),
        None
    );
    assert_eq!(
        crate::short_name_completions::global_short_name_completions()
            .qualify("printer")
            .as_deref(),
        Some("printer.branch.corp.example"),
        "an offer must be able to name the host the answer came from",
    );
}

/// A connection that announces no domain: the user named it, and the name is
/// asked of the machine's private resolvers and the upstream.
#[test]
fn a_short_name_is_completed_with_the_domain_the_user_named() {
    let q = query("printer", QTYPE_A);
    let budget = Duration::from_secs(2);
    let asks_this_machine =
        |l: DnsInterceptListener| l.with_private_resolvers(Arc::new(|_| vec![Ipv4Addr::LOCALHOST]));
    let named = asks_this_machine(short_name_listener(false))
        .with_short_name_suffix(Arc::new(|| Some("branch.corp.example".to_string())));
    assert!(named.complete_single_label(&q, "printer", budget).is_some());

    // Positive control: same resolvers, setting off.
    let unnamed =
        asks_this_machine(short_name_listener(false)).with_short_name_suffix(Arc::new(|| None));
    assert_eq!(unnamed.complete_single_label(&q, "printer", budget), None);
}

/// On a split-horizon domain the public upstream knows the name too, with
/// its outside address. The domain the user named is asked of the private
/// resolvers first, so the inside answer wins.
#[test]
fn a_short_name_under_the_named_domain_takes_the_private_answer_over_the_upstream() {
    fn outside_view(q: &[u8], name: &str) -> Option<Vec<u8>> {
        (name == "printer.branch.corp.example")
            .then(|| build_a_response(q, &[Ipv4Addr::new(100, 64, 0, 31)], 60))
            .flatten()
    }
    let public = fake_resolver(outside_view);
    let inside = fake_resolver(v4_only_printer);
    let listener = DnsInterceptListener::new(
        Arc::new(Oracle(Vec::new())),
        Arc::new(Upstream(Ok(resolved(&[])))),
        Arc::new(NoopSink),
        Arc::new(OkReconciler),
        public,
        Duration::from_millis(150),
        Duration::from_millis(500),
    )
    .with_resolver_port(inside.port())
    .with_private_resolvers(Arc::new(|_| vec![Ipv4Addr::LOCALHOST]))
    .with_short_name_suffix(Arc::new(|| Some("branch.corp.example".to_string())));

    let q = query("printer", QTYPE_A);
    let reply = listener
        .complete_single_label(&q, "printer", Duration::from_secs(2))
        .expect("the completed answer");
    assert_eq!(
        parse_address_response(0x1234, "printer", QTYPE_A, &reply),
        AddressResponseOutcome::Answers {
            addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 31))],
            min_ttl: 60,
        }
    );
}

/// A completed name is answered with records of the type the client asked
/// for: an A record under an AAAA question is a positive the client caches
/// for a question it never got an answer to.
#[test]
fn a_short_name_is_completed_only_with_records_of_the_type_asked() {
    const PRINTER_V6: std::net::Ipv6Addr =
        std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x31);
    fn dual_stack_printer(q: &[u8], name: &str) -> Option<Vec<u8>> {
        if name != "printer.branch.corp.example" {
            return None;
        }
        match parse_question(q)?.qtype {
            QTYPE_AAAA => crate::dns_wire::build_aaaa_response(q, &[PRINTER_V6], 60),
            _ => v4_only_printer(q, name),
        }
    }
    let budget = Duration::from_secs(2);
    let dual = short_name_listener_answering(true, dual_stack_printer);

    let a = query("printer", QTYPE_A);
    let reply = dual
        .complete_single_label(&a, "printer", budget)
        .expect("A completed");
    assert_eq!(
        parse_address_response(0x1234, "printer", QTYPE_A, &reply),
        AddressResponseOutcome::Answers {
            addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 31))],
            min_ttl: 60,
        }
    );

    let aaaa = query("printer", QTYPE_AAAA);
    let reply = dual
        .complete_single_label(&aaaa, "printer", budget)
        .expect("AAAA completed");
    assert_eq!(
        parse_address_response(0x1234, "printer", QTYPE_AAAA, &reply),
        AddressResponseOutcome::Answers {
            addresses: vec![IpAddr::V6(PRINTER_V6)],
            min_ttl: 60,
        }
    );
    // A name with no IPv6 is not completed for an AAAA question at all.
    assert_eq!(
        short_name_listener(true).complete_single_label(&aaaa, "printer", budget),
        None
    );

    const QTYPE_TXT: u16 = 16;
    for qtype in [QTYPE_TXT, crate::dns_wire::QTYPE_HTTPS] {
        assert_eq!(
            dual.complete_single_label(&query("printer", qtype), "printer", budget),
            None,
            "qtype {qtype} is not an address question"
        );
    }
}

// ── Private resolvers ─────────────────────────────────────────────────────

const FIRST_RESOLVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);
const SECOND_RESOLVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 54);

fn two_private_resolvers_listener(forward_timeout: Duration) -> DnsInterceptListener {
    DnsInterceptListener::new(
        Arc::new(Oracle(Vec::new())),
        Arc::new(Upstream(Ok(resolved(&[])))),
        Arc::new(NoopSink),
        Arc::new(OkReconciler),
        "192.0.2.1:53".parse().expect("test-net address"),
        Duration::from_millis(150),
        forward_timeout,
    )
    .with_private_resolvers(Arc::new(|_| vec![FIRST_RESOLVER, SECOND_RESOLVER]))
}

/// Asks on a clock only `script` moves: it gets each question's server,
/// window and bytes and returns the time the question took and the reply.
/// Returns the reply and every question as (server, window).
fn ask_on_a_manual_clock(
    listener: &DnsInterceptListener,
    budget: Duration,
    script: impl Fn(Ipv4Addr, Duration, &[u8]) -> (Duration, Option<Vec<u8>>),
) -> (Option<Vec<u8>>, Vec<(Ipv4Addr, Duration)>) {
    let q = query("host.corp.example", QTYPE_A);
    let start = Instant::now();
    let spent = std::cell::Cell::new(Duration::ZERO);
    let mut asked = Vec::new();
    let reply = listener.ask_private_resolvers_via(
        "192.0.2.1:53".parse().expect("addr"),
        budget,
        || start + spent.get(),
        |target, window| {
            assert_eq!(target.port(), 53);
            let std::net::IpAddr::V4(server) = target.ip() else {
                panic!("private resolvers are IPv4");
            };
            asked.push((server, window));
            let (took, reply) = script(server, window, &q);
            spent.set(spent.get() + took);
            reply
        },
    );
    (reply, asked)
}

/// Every private resolver shares one budget. Before, each retry got the whole
/// of it again, and the worker sat on an answer the client had given up on.
#[test]
fn asking_the_private_resolvers_spends_one_budget_between_them() {
    // Longer than the budget: only the budget can bound the windows.
    let listener = two_private_resolvers_listener(Duration::from_secs(2));
    let budget = Duration::from_millis(400);
    let first_answer_after = Duration::from_millis(250);
    // A slow "no such name" from the first, silence from the second.
    let (reply, asked) = ask_on_a_manual_clock(&listener, budget, |server, window, q| {
        if server == FIRST_RESOLVER {
            (first_answer_after, build_error_response(q, RCODE_NXDOMAIN))
        } else {
            (window, None)
        }
    });
    assert_eq!(reply, None);
    assert_eq!(
        asked,
        vec![
            (FIRST_RESOLVER, budget),
            (SECOND_RESOLVER, budget - first_answer_after),
        ]
    );
}

/// The first resolver is mute and spends its whole window; the second answers.
fn mute_then_answering(
    server: Ipv4Addr,
    window: Duration,
    q: &[u8],
) -> (Duration, Option<Vec<u8>>) {
    if server == FIRST_RESOLVER {
        (window, None)
    } else {
        (
            Duration::ZERO,
            build_a_response(q, &[Ipv4Addr::new(192, 0, 2, 44)], 60),
        )
    }
}

/// One mute resolver is not the verdict of all of them: the next one is still
/// asked while the budget lasts.
#[test]
fn a_mute_private_resolver_hands_the_question_to_the_next_one() {
    let window = Duration::from_millis(150);
    let listener = two_private_resolvers_listener(window);
    let (reply, asked) =
        ask_on_a_manual_clock(&listener, Duration::from_secs(2), mute_then_answering);
    let reply = reply.expect("the second resolver answered");
    assert!(!reply_is_nxdomain(&reply));
    assert_eq!(
        asked,
        vec![(FIRST_RESOLVER, window), (SECOND_RESOLVER, window)]
    );
}

/// Positive control for the one above: a budget the first mute resolver
/// spends whole leaves nothing to ask the second with.
#[test]
fn a_spent_budget_asks_no_further_private_resolver() {
    // Longer than the budget: only the budget can stop the second ask.
    let listener = two_private_resolvers_listener(Duration::from_secs(2));
    let budget = Duration::from_millis(200);
    let (reply, asked) = ask_on_a_manual_clock(&listener, budget, mute_then_answering);
    assert_eq!(reply, None);
    assert_eq!(asked, vec![(FIRST_RESOLVER, budget)]);
}

/// A resolver on loopback that answers every question after `delay`.
fn udp_resolver_answering_after(delay: Duration) -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("resolver socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("resolver timeout");
    let addr = socket.local_addr().expect("resolver addr");
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            std::thread::sleep(delay);
            if let Some(reply) = build_a_response(&buf[..n], &[Ipv4Addr::new(192, 0, 2, 44)], 60) {
                let _ = socket.send_to(&reply, from);
            }
        }
    });
    addr
}

/// The real socket path: an answer inside the window is relayed, and one that
/// comes after it is not waited for. Only lower bounds on time, which load
/// cannot break; a read the window failed to bound gets the late answer.
#[test]
fn a_forward_relays_an_answer_and_gives_up_at_the_window() {
    let listener = two_private_resolvers_listener(Duration::from_secs(2));
    let q = query("host.corp.example", QTYPE_A);

    let prompt = udp_resolver_answering_after(Duration::ZERO);
    let reply = listener
        .forward_to(&q, prompt, Duration::from_secs(30))
        .expect("an answer inside the window");
    assert!(reply_answers_query(&q, &reply));

    let late = udp_resolver_answering_after(Duration::from_secs(10));
    let window = Duration::from_millis(200);
    let started = Instant::now();
    let reply = listener.forward_to(&q, late, window);
    let took = started.elapsed();
    assert_eq!(reply, None);
    // Slack for a timer that fires a tick early.
    assert!(
        took + Duration::from_millis(50) >= window,
        "gave up after {took:?} of a {window:?} window"
    );
}

#[test]
fn a_server_list_keeps_the_first_occurrence_of_each_resolver() {
    let a: SocketAddr = "192.0.2.1:53".parse().expect("addr");
    let b: SocketAddr = "192.0.2.2:53".parse().expect("addr");
    let c: SocketAddr = "192.0.2.3:53".parse().expect("addr");
    assert_eq!(first_occurrences(vec![b, a, b, c, a]), vec![b, a, c]);
}

// ── Rule-host admission control ───────────────────────────────────────────

/// Stands in for the FQDN cache: the addresses enforcement was built from.
struct CachedSink(Vec<Ipv4Addr>);
impl FactSink for CachedSink {
    fn record(&self, _h: &str, _r: &ResolvedAddresses) {}
    fn cached_routable_ips(&self, _hostname: &str) -> Vec<Ipv4Addr> {
        self.0.clone()
    }
}

/// The upstream that made this necessary: one that never comes back.
struct NeverAnswers;
impl UpstreamResolver for NeverAnswers {
    fn resolve_within(
        &self,
        _h: &str,
        _f: AddressFamily,
        _budget: Duration,
    ) -> Result<ResolvedAddresses, ResolveError> {
        panic!("a saturated rule-host lane must not reach the upstream")
    }
}

/// An upstream that takes everything it is allowed to, as a resolver waiting
/// on a server that has stopped answering does.
struct SpendsTheBudget;
impl UpstreamResolver for SpendsTheBudget {
    fn resolve_within(
        &self,
        _h: &str,
        _f: AddressFamily,
        budget: Duration,
    ) -> Result<ResolvedAddresses, ResolveError> {
        std::thread::sleep(budget.min(Duration::from_secs(5)));
        Err(ResolveError::Unavailable("nothing answered".into()))
    }
}

/// The datagram's remaining budget reaches the enforce-before-answer branch.
/// It used to stop at the forward path: the branch ran on the sum of its own
/// stage timeouts (about five seconds) while the client's stub resolver gave up
/// after one and re-asked, which is what the `client port closed` storm counted.
#[test]
fn the_rule_host_branch_answers_inside_the_budget_it_was_given() {
    let l = DnsInterceptListener::new(
        Arc::new(Oracle(vec!["routed.example".to_string()])),
        Arc::new(SpendsTheBudget),
        Arc::new(CachedSink(Vec::new())),
        Arc::new(OkReconciler),
        "192.0.2.1:53".parse().unwrap(),
        Duration::from_millis(150),
        Duration::from_millis(150),
    );
    let started = Instant::now();
    let q = query("routed.example", QTYPE_A);
    let action = l.answer_query_within(
        &q,
        &question(&q),
        Duration::ZERO,
        Duration::from_millis(200),
    );
    let spent = started.elapsed();
    // Upstream unavailable is the fail-open forward; what is asserted is when.
    assert_eq!(action, ListenerAction::Forward);
    assert!(
        spent < Duration::from_millis(600),
        "the branch spent {spent:?} of a 200ms budget",
    );
}

fn saturated_listener(cached: &[Ipv4Addr]) -> DnsInterceptListener {
    DnsInterceptListener::new(
        Arc::new(Oracle(vec!["routed.example".to_string()])),
        Arc::new(NeverAnswers),
        Arc::new(CachedSink(cached.to_vec())),
        Arc::new(OkReconciler),
        "192.0.2.1:53".parse().unwrap(),
        Duration::from_millis(150),
        Duration::from_millis(150),
    )
}

/// Every slot taken: the name still resolves, from what enforcement already
/// holds, and the worker is free again immediately.
#[test]
fn a_saturated_rule_host_lane_answers_from_the_cache() {
    let cached = Ipv4Addr::new(203, 0, 113, 7);
    let l = saturated_listener(&[cached]);
    let _held: Vec<_> = (0..MAX_CONCURRENT_RULE_HOST_RESOLVES)
        .map(|_| l.rule_host_lane.enter(Duration::ZERO).expect("slot"))
        .collect();

    match l.answer_query(&query("routed.example", QTYPE_A)) {
        ListenerAction::Respond(bytes) => {
            match crate::dns_wire::parse_address_response(0x1234, "routed.example", QTYPE_A, &bytes)
            {
                crate::dns_wire::AddressResponseOutcome::Answers { addresses, .. } => {
                    assert_eq!(addresses, vec![cached]);
                }
                other => panic!("expected Answers, got {other:?}"),
            }
        }
        other => panic!("expected a response built from the cache, got {other:?}"),
    }
}

/// Nothing cached and no slot: SERVFAIL, so the client re-asks in a moment
/// instead of waiting out its own timeout on an answer that is not coming.
#[test]
fn a_saturated_rule_host_lane_without_a_cache_entry_fails_fast() {
    let l = saturated_listener(&[]);
    let _held: Vec<_> = (0..MAX_CONCURRENT_RULE_HOST_RESOLVES)
        .map(|_| l.rule_host_lane.enter(Duration::ZERO).expect("slot"))
        .collect();

    match l.answer_query(&query("routed.example", QTYPE_A)) {
        ListenerAction::Respond(bytes) => {
            assert_eq!(bytes[3] & 0x0F, RCODE_SERVFAIL, "SERVFAIL rcode");
        }
        other => panic!("expected SERVFAIL, got {other:?}"),
    }
}

/// The point of the cap: a name no rule claims is unaffected by rule hosts
/// queueing on a resolver that stopped answering.
#[test]
fn a_name_no_rule_claims_is_unaffected_by_a_saturated_lane() {
    let l = saturated_listener(&[]);
    let _held: Vec<_> = (0..MAX_CONCURRENT_RULE_HOST_RESOLVES)
        .map(|_| l.rule_host_lane.enter(Duration::ZERO).expect("slot"))
        .collect();

    let started = Instant::now();
    assert_eq!(
        l.answer_query(&query("vk.example", QTYPE_A)),
        ListenerAction::ForwardFiltered
    );
    assert!(
        started.elapsed() < RULE_HOST_LANE_WAIT,
        "a direct name must not wait for a rule-host slot"
    );
}

/// The slot is released when the answer is done, not held for the process.
#[test]
fn a_rule_host_slot_is_returned_after_the_query() {
    let l = saturated_listener(&[Ipv4Addr::new(203, 0, 113, 7)]);
    {
        let _held: Vec<_> = (0..MAX_CONCURRENT_RULE_HOST_RESOLVES)
            .map(|_| l.rule_host_lane.enter(Duration::ZERO).expect("slot"))
            .collect();
        assert!(l.rule_host_lane.enter(Duration::ZERO).is_none());
    }
    assert!(
        l.rule_host_lane.enter(Duration::ZERO).is_some(),
        "slots are free again once the permits drop"
    );
}

/// Any local process can send the listener a datagram that trips a receive
/// error. Counting those toward the fatal streak let sixteen of them switch
/// interception off for the whole machine.
#[test]
fn per_datagram_receive_errors_never_count_toward_the_fatal_streak() {
    use std::io::{Error, ErrorKind};
    for kind in [ErrorKind::WouldBlock, ErrorKind::TimedOut] {
        assert_eq!(
            classify_recv_error(&Error::from(kind)),
            RecvErrorClass::Idle
        );
    }
    for kind in [
        ErrorKind::ConnectionReset,
        ErrorKind::ConnectionRefused,
        ErrorKind::ConnectionAborted,
    ] {
        assert_eq!(
            classify_recv_error(&Error::from(kind)),
            RecvErrorClass::PerDatagram,
            "{kind:?}"
        );
    }
    // A socket that is genuinely broken still ends the loop.
    for kind in [
        ErrorKind::InvalidInput,
        ErrorKind::PermissionDenied,
        ErrorKind::Other,
    ] {
        assert_eq!(
            classify_recv_error(&Error::from(kind)),
            RecvErrorClass::Unrecognised,
            "{kind:?}"
        );
    }
}

#[cfg(windows)]
#[test]
fn an_oversized_datagram_is_skipped_on_windows() {
    // WSAEMSGSIZE, what a datagram past the buffer comes back as.
    let oversized = std::io::Error::from_raw_os_error(10040);
    assert_eq!(classify_recv_error(&oversized), RecvErrorClass::PerDatagram);
    // WSAENOTSOCK: the socket itself is gone.
    let not_a_socket = std::io::Error::from_raw_os_error(10038);
    assert_eq!(
        classify_recv_error(&not_a_socket),
        RecvErrorClass::Unrecognised
    );
}

/// End to end over a real loopback socket: a datagram larger than the
/// receive buffer is at worst one skipped read on every OS, and the next
/// query is still read.
#[test]
fn an_oversized_datagram_leaves_the_socket_serving() {
    let server = UdpSocket::bind("127.0.0.1:0").expect("bind server");
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    let target = server.local_addr().expect("server addr");
    client
        .send_to(&vec![0u8; DNS_DATAGRAM_BUFFER_BYTES + 512], target)
        .expect("send oversized");
    client.send_to(b"next", target).expect("send next");

    let mut buf = [0u8; DNS_DATAGRAM_BUFFER_BYTES];
    let mut next_seen = false;
    for _ in 0..2 {
        match server.recv_from(&mut buf) {
            // Linux and macOS: the oversized one arrives truncated.
            Ok((n, _)) if &buf[..n] == b"next" => {
                next_seen = true;
                break;
            }
            Ok((n, _)) => assert_eq!(n, DNS_DATAGRAM_BUFFER_BYTES),
            Err(e) => assert_eq!(
                classify_recv_error(&e),
                RecvErrorClass::PerDatagram,
                "an oversized datagram must be per-datagram noise, got {e:?}"
            ),
        }
    }
    assert!(next_seen, "the query after the oversized one is still read");
}

// ── AAAA through the production resolver chain ───────────────────────────

/// Answers each family from its own list and remembers what it was asked. The
/// listener tests above use a family-blind upstream, which is how decorators
/// that quietly asked for `A` kept every AAAA at NODATA.
struct FamilyUpstream {
    v4: Vec<Ipv4Addr>,
    v6: Vec<std::net::Ipv6Addr>,
    asked: std::sync::Mutex<Vec<AddressFamily>>,
}
impl UpstreamResolver for FamilyUpstream {
    fn resolve_within(
        &self,
        _h: &str,
        family: AddressFamily,
        _budget: Duration,
    ) -> Result<ResolvedAddresses, ResolveError> {
        self.asked.lock().unwrap().push(family);
        let addresses: Vec<IpAddr> = match family {
            AddressFamily::Ipv4 => self.v4.iter().copied().map(IpAddr::V4).collect(),
            AddressFamily::Ipv6 => self.v6.iter().copied().map(IpAddr::V6).collect(),
        };
        if addresses.is_empty() {
            return Err(ResolveError::NoRecords);
        }
        Ok(ResolvedAddresses {
            addresses,
            ttl_seconds: 300,
        })
    }
}

#[derive(Default)]
struct RecordingSink(std::sync::Mutex<Vec<IpAddr>>);
impl FactSink for RecordingSink {
    fn record(&self, _h: &str, r: &ResolvedAddresses) {
        self.0.lock().unwrap().extend(r.addresses.iter().copied());
    }
}

struct NoSystemServers;
impl nrr_platform_api::dns::SystemDnsServersPort for NoSystemServers {
    fn upstream_candidates_v4(&self) -> Vec<nrr_platform_api::dns::UpstreamDnsCandidate> {
        Vec::new()
    }
}

/// The listener over the decorators production stacks on the raw upstream.
fn chained_listener(
    upstream: Arc<FamilyUpstream>,
    sink: Arc<RecordingSink>,
    guard: crate::enforcement_planner::Ipv6Guard,
) -> DnsInterceptListener {
    let poison = crate::dns_resolver_ports::PoisonFallbackUpstreamResolver::new(
        upstream as Arc<dyn UpstreamResolver>,
    )
    .with_fallbacks(Vec::new());
    let chain = crate::local_namespace_fallback::LocalNamespaceFallbackResolver::new(
        Arc::new(poison),
        Arc::new(NoSystemServers),
        Duration::from_millis(1),
    );
    DnsInterceptListener::new(
        Arc::new(Oracle(vec!["assistant.example".to_string()])),
        Arc::new(chain),
        sink,
        Arc::new(OkReconciler),
        "192.0.2.1:53".parse().unwrap(),
        Duration::from_millis(150),
        Duration::from_millis(150),
    )
    .with_ipv6_disposition(carried(guard))
}

fn family_upstream() -> Arc<FamilyUpstream> {
    Arc::new(FamilyUpstream {
        v4: vec![Ipv4Addr::new(100, 64, 0, 78)],
        v6: vec!["2001:db8::7".parse().expect("v6")],
        asked: std::sync::Mutex::new(Vec::new()),
    })
}

/// The tunnel carries IPv6: the AAAA is asked upstream as an AAAA, answered,
/// and its address recorded so enforcement is built for it like for a v4 one.
#[test]
fn aaaa_through_the_resolver_chain_is_answered_and_recorded() {
    let upstream = family_upstream();
    let sink = Arc::new(RecordingSink::default());
    let l = chained_listener(
        Arc::clone(&upstream),
        Arc::clone(&sink),
        crate::enforcement_planner::Ipv6Guard::FiltersAndRoutes,
    );
    match l.answer_query(&query("assistant.example", QTYPE_AAAA)) {
        ListenerAction::Respond(bytes) => {
            assert_eq!(bytes[3] & 0x0f, RCODE_NOERROR);
            assert_eq!(&bytes[6..8], &[0, 1], "one AAAA record");
        }
        other => panic!("expected an AAAA answer, got {other:?}"),
    }
    let v6: std::net::Ipv6Addr = "2001:db8::7".parse().expect("v6");
    assert_eq!(*sink.0.lock().unwrap(), vec![IpAddr::V6(v6)]);
    assert_eq!(*upstream.asked.lock().unwrap(), vec![AddressFamily::Ipv6]);
}

/// Only the main link carries IPv6: the policy still says NODATA, and the
/// upstream is not asked at all.
#[test]
fn aaaa_through_the_resolver_chain_stays_nodata_when_the_tunnel_cannot_carry_it() {
    let upstream = family_upstream();
    let sink = Arc::new(RecordingSink::default());
    let l = chained_listener(
        Arc::clone(&upstream),
        Arc::clone(&sink),
        crate::enforcement_planner::Ipv6Guard::FiltersOnly,
    );
    match l.answer_query(&query("assistant.example", QTYPE_AAAA)) {
        ListenerAction::Respond(bytes) => assert_eq!(&bytes[6..8], &[0, 0], "NODATA"),
        other => panic!("expected a NODATA response, got {other:?}"),
    }
    assert!(upstream.asked.lock().unwrap().is_empty());
    assert!(sink.0.lock().unwrap().is_empty());
}

/// The A path through the same chain: one upstream question, of its family.
#[test]
fn a_through_the_resolver_chain_asks_once_for_a() {
    let upstream = family_upstream();
    let sink = Arc::new(RecordingSink::default());
    let l = chained_listener(
        Arc::clone(&upstream),
        Arc::clone(&sink),
        crate::enforcement_planner::Ipv6Guard::FiltersAndRoutes,
    );
    match l.answer_query(&query("assistant.example", QTYPE_A)) {
        ListenerAction::Respond(bytes) => assert_eq!(&bytes[6..8], &[0, 1], "one A record"),
        other => panic!("expected an A answer, got {other:?}"),
    }
    assert_eq!(*upstream.asked.lock().unwrap(), vec![AddressFamily::Ipv4]);
    assert_eq!(
        *sink.0.lock().unwrap(),
        vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 78))]
    );
}
