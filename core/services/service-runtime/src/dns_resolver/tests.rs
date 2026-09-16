use super::*;
use std::sync::Mutex;

/// Records the order of side-effecting calls so tests can assert the
/// enforce-before-answer ordering invariant.
#[derive(Default)]
struct CallLog(Mutex<Vec<&'static str>>);
impl CallLog {
    fn push(&self, s: &'static str) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).push(s);
    }
    fn snapshot(&self) -> Vec<&'static str> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

struct FakeOracle {
    rule_hosts: Vec<String>,
}
impl RuleHostOracle for FakeOracle {
    fn is_rule_host(&self, hostname: &str) -> bool {
        self.rule_hosts.iter().any(|h| h.as_str() == hostname)
    }
}
fn oracle(hosts: &[&str]) -> FakeOracle {
    FakeOracle {
        rule_hosts: hosts.iter().map(|s| s.to_string()).collect(),
    }
}

struct FakeUpstream {
    answer: Result<ResolvedAddresses, ResolveError>,
}
impl UpstreamResolver for FakeUpstream {
    fn resolve(
        &self,
        _hostname: &str,
        _family: AddressFamily,
    ) -> Result<ResolvedAddresses, ResolveError> {
        self.answer.clone()
    }
}

struct FakeSink<'a>(&'a CallLog);
impl FactSink for FakeSink<'_> {
    fn record(&self, _hostname: &str, _resolved: &ResolvedAddresses) {
        self.0.push("record");
    }
}

fn resolved(ips: &[Ipv4Addr]) -> ResolvedAddresses {
    ResolvedAddresses {
        addresses: ips.iter().copied().map(IpAddr::V4).collect(),
        ttl_seconds: 300,
    }
}

struct FakeReconciler<'a> {
    log: &'a CallLog,
    outcome: ReconcileOutcome,
}
impl SyncReconciler for FakeReconciler<'_> {
    fn reconcile_now(&self, _deadline: Duration) -> ReconcileOutcome {
        self.log.push("reconcile");
        self.outcome
    }
}

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

fn resolved6(ips: &[std::net::Ipv6Addr]) -> ResolvedAddresses {
    ResolvedAddresses {
        addresses: ips.iter().copied().map(IpAddr::V6).collect(),
        ttl_seconds: 300,
    }
}

fn aaaa_hold() -> AnswerHold {
    AnswerHold {
        deadline: Duration::from_millis(150),
        fast_answers: true,
    }
}

#[test]
fn a_routed_ipv6_answer_is_recorded_and_reconciled_before_it_is_given_out() {
    let log = CallLog::default();
    let v6: std::net::Ipv6Addr = "fd00::1".parse().expect("v6");
    let out = handle_aaaa_query(
        "assistant.example",
        aaaa_hold(),
        &FakeUpstream {
            answer: Ok(resolved6(&[v6])),
        },
        &FakeSink(&log),
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::Installed,
        },
        &OpenLeakGuard,
    );
    assert_eq!(out, AaaaOutcome::Answer(vec![v6]));
    assert_eq!(
        log.snapshot(),
        vec!["record", "reconcile"],
        "enforce, then answer"
    );
}

/// Positive control for the pin: an address nothing can route is handed
/// out as it came, and neither a route nor a filter is built on it.
#[test]
fn an_ipv6_answer_nothing_can_route_is_given_out_but_never_pinned() {
    let log = CallLog::default();
    let loopback = std::net::Ipv6Addr::LOCALHOST;
    let out = handle_aaaa_query(
        "assistant.example",
        aaaa_hold(),
        &FakeUpstream {
            answer: Ok(resolved6(&[loopback])),
        },
        &FakeSink(&log),
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::Installed,
        },
        &OpenLeakGuard,
    );
    assert_eq!(out, AaaaOutcome::Answer(vec![loopback]));
    assert!(log.snapshot().is_empty(), "{:?}", log.snapshot());
}

#[test]
fn a_late_ipv6_answer_is_withheld_while_the_leak_guard_blocks() {
    let log = CallLog::default();
    let v6: std::net::Ipv6Addr = "fd00::1".parse().expect("v6");
    let blocking = || true;
    let out = handle_aaaa_query(
        "assistant.example",
        aaaa_hold(),
        &FakeUpstream {
            answer: Ok(resolved6(&[v6])),
        },
        &FakeSink(&log),
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::DeadlineExceeded,
        },
        &blocking,
    );
    assert_eq!(out, AaaaOutcome::Withheld);
}

#[test]
fn shared_origin_covers_subdomains_and_a_common_registrable_tail() {
    assert!(hosts_share_origin("secure.example", "secure.example."));
    assert!(hosts_share_origin("web.chatapp.example", "chatapp.example"));
    assert!(hosts_share_origin(
        "static.chatapp.test",
        "crashlogs.chatapp.test"
    ));
    assert!(!hosts_share_origin("assistant.example", "secure.example"));
    assert!(!hosts_share_origin("a.example.com", "a.example.net"));
}

/// Answers a fixed set of hosts with a fixed fake address; everything else
/// takes the real path.
struct FakeFakeIp {
    scope: Vec<String>,
    fake: Ipv4Addr,
    /// Subnets this double treats as the tunnel's own interior.
    refuse: Vec<nrr_domain::ipv4_network::Ipv4Network>,
}
impl FakeFakeIp {
    fn refusing_subnets(mut self, subnets: Vec<nrr_domain::ipv4_network::Ipv4Network>) -> Self {
        self.refuse = subnets;
        self
    }
}
impl FakeIpAnswerer for FakeFakeIp {
    fn fake_answer(&self, hostname: &str) -> Option<Vec<Ipv4Addr>> {
        self.scope
            .iter()
            .any(|h| h == hostname)
            .then(|| vec![self.fake])
    }

    fn may_substitute(&self, real: &[Ipv4Addr]) -> bool {
        !real
            .iter()
            .any(|addr| self.refuse.iter().any(|net| net.contains(*addr)))
    }
}

#[test]
fn describe_resolve_failure_labels_each_variant() {
    // Authoritative "no answer" gets a stable low-cardinality token.
    assert_eq!(
        describe_resolve_failure(&ResolveError::NoRecords),
        "nxdomain/no-records"
    );
    // Transient failures surface their detail (timeout / rcode / truncated)
    // verbatim so the diagnostic line pinpoints WHY the resolve failed.
    assert_eq!(
        describe_resolve_failure(&ResolveError::Unavailable("timeout".into())),
        "unavailable: timeout"
    );
    assert_eq!(
        describe_resolve_failure(&ResolveError::Unavailable("rcode 5".into())),
        "unavailable: rcode 5"
    );
}

#[test]
fn non_rule_host_fails_open_without_touching_enforcement() {
    let log = CallLog::default();
    let out = handle_a_query(
        "example.com",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: false,
        },
        &oracle(&[]),
        &FakeUpstream {
            answer: Ok(resolved(&[ip(23, 10, 20, 138)])),
        },
        &FakeSink(&log),
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::Installed,
        },
        &NoopFakeIpAnswerer,
        &OpenLeakGuard,
        &NoEnforcement,
    );
    assert_eq!(
        out,
        QueryOutcome::Answer {
            ips: vec![ip(23, 10, 20, 138)],
            enforced: false,
        }
    );
    // Fail-open path must NOT record facts or reconcile: general DNS never
    // depends on enforcement health.
    assert!(log.snapshot().is_empty());
}

/// An address inside the tunnel's OWN subnet must keep its real value.
///
/// The live case: a VPN client authorizes against `10.117.0.1` on a
/// `10.88.0.0/10` link. A virtual address there sends it to our TUN, where
/// nothing speaks the tunnel's protocol — the client concludes the
/// connection failed and reconnects forever.
#[test]
fn a_host_inside_the_tunnels_own_subnet_is_never_given_a_virtual_address() {
    let log = CallLog::default();
    let interior = ip(10, 117, 0, 1);
    let answerer = FakeFakeIp {
        scope: vec!["auth.tunnel.internal".to_string()],
        refuse: Vec::new(),
        fake: ip(198, 18, 0, 7),
    }
    .refusing_subnets(vec![nrr_domain::ipv4_network::Ipv4Network::parse(
        "10.88.0.0/10",
    )
    .expect("parse")]);

    let out = handle_a_query(
        "auth.tunnel.internal",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: false,
        },
        &oracle(&["auth.tunnel.internal"]),
        &FakeUpstream {
            answer: Ok(resolved(&[interior])),
        },
        &FakeSink(&log),
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::Installed,
        },
        &answerer,
        &OpenLeakGuard,
        &NoEnforcement,
    );

    match out {
        QueryOutcome::Answer { ips, .. } => assert_eq!(
            ips,
            vec![interior],
            "the caller must be sent into the tunnel, not to our TUN"
        ),
        other => panic!("unexpected outcome: {other:?}"),
    }
}

/// A resolver standing documentation space in for a name it will not
/// carry. Second-source confirmation upstream of the handler already
/// failed, so nothing about it may reach enforcement — no cache fact, no
/// reconcile, `enforced: false`. The client still gets the answer: the name
/// is blocked either way.
#[test]
fn a_placeholder_only_answer_is_never_pinned() {
    let log = CallLog::default();
    let stub = [ip(192, 0, 2, 1), ip(203, 0, 113, 7)];
    let out = handle_a_query(
        "secure.example",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: false,
        },
        &oracle(&["secure.example"]),
        &FakeUpstream {
            answer: Ok(resolved(&stub)),
        },
        &FakeSink(&log),
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::Installed,
        },
        &NoopFakeIpAnswerer,
        &OpenLeakGuard,
        &NoEnforcement,
    );
    assert_eq!(
        out,
        QueryOutcome::Answer {
            ips: stub.to_vec(),
            enforced: false,
        }
    );
    assert!(
        log.snapshot().is_empty(),
        "a placeholder must not be recorded or reconciled: {:?}",
        log.snapshot()
    );
    // ...and it must not become an enforceable memory for the drop-learner
    // either, or the next reconcile pins it anyway.
    assert!(crate::recent_rule_addresses::global_recent_rule_addresses()
        .lookup(stub[0])
        .is_none());
}

/// A reserved address next to a real one costs only itself: the host stays
/// enforced on what is left.
#[test]
fn an_unusable_address_beside_a_real_one_is_dropped_and_the_host_stays_enforced() {
    let log = CallLog::default();
    let real = ip(23, 10, 20, 78);
    let out = handle_a_query(
        "rule.example",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: false,
        },
        &oracle(&["rule.example"]),
        &FakeUpstream {
            answer: Ok(resolved(&[ip(169, 254, 3, 4), real, ip(198, 51, 100, 9)])),
        },
        &FakeSink(&log),
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::Installed,
        },
        &NoopFakeIpAnswerer,
        &OpenLeakGuard,
        &NoEnforcement,
    );
    assert_eq!(
        out,
        QueryOutcome::Answer {
            ips: vec![real],
            enforced: true,
        }
    );
    assert_eq!(log.snapshot(), vec!["record", "reconcile"]);
}

/// A [`FakeSink`] whose cache already knows a fixed set of addresses —
/// drives the fast-answers "every answered address is cached" branch.
struct CachedSink<'a> {
    log: &'a CallLog,
    cached: Vec<Ipv4Addr>,
}
impl FactSink for CachedSink<'_> {
    fn record(&self, _hostname: &str, _resolved: &ResolvedAddresses) {
        self.log.push("record");
    }
    fn cached_routable_ips(&self, _hostname: &str) -> Vec<Ipv4Addr> {
        self.cached.clone()
    }
}

/// Reconciler that panics if awaited — proves the fast path never blocks
/// on `reconcile_now`, only kicks `request_reconcile`.
struct RequestOnlyReconciler<'a>(&'a CallLog);
impl SyncReconciler for RequestOnlyReconciler<'_> {
    fn reconcile_now(&self, _deadline: Duration) -> ReconcileOutcome {
        panic!("fast path must not await reconcile_now");
    }
    fn request_reconcile(&self) {
        self.0.push("request_reconcile");
    }
}

/// A view that enforces exactly the listed addresses.
struct Enforcing(Vec<Ipv4Addr>);
impl EnforcedAddressView for Enforcing {
    fn is_enforced(&self, ip: Ipv4Addr) -> bool {
        self.0.contains(&ip)
    }
}

/// Reconciler whose runs are known to outlast any answer deadline — the
/// measured production shape (seconds against a 900 ms budget).
struct SlowReconciler<'a>(&'a CallLog);
impl SyncReconciler for SlowReconciler<'_> {
    fn reconcile_now(&self, _deadline: Duration) -> ReconcileOutcome {
        panic!("a wait known to be futile must not be attempted");
    }
    fn request_reconcile(&self) {
        self.0.push("request_reconcile");
    }
    fn typical_run(&self) -> Option<Duration> {
        Some(Duration::from_secs(10))
    }
}

#[test]
fn fast_answers_skips_the_hold_when_every_answered_address_is_enforced() {
    let log = CallLog::default();
    let addr = ip(23, 10, 20, 159);
    let out = handle_a_query(
        "assistant.example",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: true,
        },
        &oracle(&["assistant.example"]),
        &FakeUpstream {
            answer: Ok(resolved(&[addr])),
        },
        &CachedSink {
            log: &log,
            cached: vec![addr],
        },
        &RequestOnlyReconciler(&log),
        &NoopFakeIpAnswerer,
        &OpenLeakGuard,
        &Enforcing(vec![addr]),
    );
    // Answered immediately, and honestly enforced: the policy carries this
    // address right now. The reconcile is still requested so the facts
    // converge.
    assert_eq!(
        out,
        QueryOutcome::Answer {
            ips: vec![addr],
            enforced: true,
        }
    );
    assert_eq!(log.snapshot(), ["record", "request_reconcile"]);
}

#[test]
fn a_cached_address_the_policy_does_not_carry_is_not_the_fast_path() {
    // The defect this gate had: the FQDN cache remembers every address the
    // name ever resolved to, so a rotated CDN address read as covered and
    // the answer went out ahead of its enforcement. Cached is not enforced.
    let log = CallLog::default();
    let addr = ip(23, 10, 20, 158);
    let out = handle_a_query(
        "static.proflcdn.test",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: true,
        },
        &oracle(&["static.proflcdn.test"]),
        &FakeUpstream {
            answer: Ok(resolved(&[addr])),
        },
        &CachedSink {
            log: &log,
            cached: vec![addr],
        },
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::Installed,
        },
        &NoopFakeIpAnswerer,
        &OpenLeakGuard,
        &NoEnforcement,
    );
    // It took the hold instead of the fast path, and only the reconcile's
    // own confirmation makes it enforced.
    assert_eq!(
        out,
        QueryOutcome::Answer {
            ips: vec![addr],
            enforced: true,
        }
    );
    assert_eq!(log.snapshot(), ["record", "reconcile"]);
}

#[test]
fn a_wait_that_cannot_finish_is_not_attempted() {
    // The reconcile runs an order of magnitude past the deadline, so a hold
    // installs nothing and only spends the budget. Answer, say so, and let
    // the learn-from-drops path recover the first connect.
    let log = CallLog::default();
    let addr = ip(23, 10, 20, 158);
    let out = handle_a_query(
        "static.proflcdn.test",
        AnswerHold {
            deadline: Duration::from_millis(900),
            fast_answers: true,
        },
        &oracle(&["static.proflcdn.test"]),
        &FakeUpstream {
            answer: Ok(resolved(&[addr])),
        },
        &CachedSink {
            log: &log,
            cached: vec![addr],
        },
        &SlowReconciler(&log),
        &NoopFakeIpAnswerer,
        &OpenLeakGuard,
        &NoEnforcement,
    );
    assert_eq!(
        out,
        QueryOutcome::Answer {
            ips: vec![addr],
            enforced: false,
        }
    );
    assert_eq!(log.snapshot(), ["record", "request_reconcile"]);
}

/// Slow like production, and records what it was asked to route at once.
struct FirstContactReconciler<'a> {
    log: &'a CallLog,
    routed: Mutex<Vec<Ipv4Addr>>,
}
impl SyncReconciler for FirstContactReconciler<'_> {
    fn reconcile_now(&self, _deadline: Duration) -> ReconcileOutcome {
        panic!("a wait known to be futile must not be attempted");
    }
    fn request_reconcile(&self) {
        self.log.push("request_reconcile");
    }
    fn typical_run(&self) -> Option<Duration> {
        Some(Duration::from_secs(10))
    }
    fn install_first_contact(&self, addresses: &[Ipv4Addr]) -> usize {
        self.routed
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend_from_slice(addresses);
        addresses.len()
    }
}

/// The full run is too slow to wait for, so the address the policy does
/// not carry gets its route before the answer goes out — and only that one.
#[test]
fn a_first_contact_gets_its_route_before_the_answer_goes_out() {
    let log = CallLog::default();
    let known = ip(23, 10, 20, 159);
    let new = ip(23, 10, 20, 160);
    let reconciler = FirstContactReconciler {
        log: &log,
        routed: Mutex::new(Vec::new()),
    };
    for enforced in [vec![known], vec![known, new]] {
        let out = handle_a_query(
            "assistant.example",
            AnswerHold {
                deadline: Duration::from_millis(900),
                fast_answers: true,
            },
            &oracle(&["assistant.example"]),
            &FakeUpstream {
                answer: Ok(resolved(&[known, new])),
            },
            &CachedSink {
                log: &log,
                cached: vec![known, new],
            },
            &reconciler,
            &NoopFakeIpAnswerer,
            &OpenLeakGuard,
            &Enforcing(enforced),
        );
        assert!(matches!(out, QueryOutcome::Answer { .. }), "{out:?}");
    }
    assert_eq!(
        *reconciler.routed.lock().unwrap_or_else(|p| p.into_inner()),
        vec![new],
        "an answer the policy already carries routes nothing"
    );
}

#[test]
fn fast_answers_still_holds_on_first_contact_with_a_new_address() {
    let log = CallLog::default();
    let out = handle_a_query(
        "assistant.example",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: true,
        },
        &oracle(&["assistant.example"]),
        &FakeUpstream {
            answer: Ok(resolved(&[ip(23, 10, 20, 159)])),
        },
        // Cache is empty → the answer introduces a never-seen address and
        // the first connect could race the install: hold as before.
        &FakeSink(&log),
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::Installed,
        },
        &NoopFakeIpAnswerer,
        &OpenLeakGuard,
        &NoEnforcement,
    );
    assert_eq!(
        out,
        QueryOutcome::Answer {
            ips: vec![ip(23, 10, 20, 159)],
            enforced: true,
        }
    );
    assert_eq!(log.snapshot(), ["record", "reconcile"]);
}

#[test]
fn fast_answers_off_awaits_the_reconcile_even_for_cached_addresses() {
    let log = CallLog::default();
    let addr = ip(23, 10, 20, 159);
    let out = handle_a_query(
        "assistant.example",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: false,
        },
        &oracle(&["assistant.example"]),
        &FakeUpstream {
            answer: Ok(resolved(&[addr])),
        },
        &CachedSink {
            log: &log,
            cached: vec![addr],
        },
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::Installed,
        },
        &NoopFakeIpAnswerer,
        &OpenLeakGuard,
        &NoEnforcement,
    );
    assert_eq!(
        out,
        QueryOutcome::Answer {
            ips: vec![addr],
            enforced: true,
        }
    );
    assert_eq!(log.snapshot(), ["record", "reconcile"]);
}

#[test]
fn rule_host_records_then_reconciles_before_answering() {
    let log = CallLog::default();
    let out = handle_a_query(
        "assistant.example",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: false,
        },
        &oracle(&["assistant.example"]),
        &FakeUpstream {
            answer: Ok(resolved(&[ip(23, 10, 20, 159)])),
        },
        &FakeSink(&log),
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::Installed,
        },
        &NoopFakeIpAnswerer,
        &OpenLeakGuard,
        &NoEnforcement,
    );
    assert_eq!(
        out,
        QueryOutcome::Answer {
            ips: vec![ip(23, 10, 20, 159)],
            enforced: true,
        }
    );
    // Ordering invariant: cache upsert happens-before reconcile, and the
    // function only returns after reconcile → install strictly precedes the
    // answer handed back to the app.
    assert_eq!(log.snapshot(), vec!["record", "reconcile"]);
}

#[test]
fn rule_host_answers_but_unenforced_when_deadline_exceeded() {
    let log = CallLog::default();
    let out = handle_a_query(
        "assistant.example",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: false,
        },
        &oracle(&["assistant.example"]),
        &FakeUpstream {
            answer: Ok(resolved(&[ip(23, 10, 20, 159)])),
        },
        &FakeSink(&log),
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::DeadlineExceeded,
        },
        &NoopFakeIpAnswerer,
        &OpenLeakGuard,
        &NoEnforcement,
    );
    // Fail-open on latency: still answer, but flagged unenforced. The fact
    // was recorded, so the async safety tick converges shortly after.
    assert_eq!(
        out,
        QueryOutcome::Answer {
            ips: vec![ip(23, 10, 20, 159)],
            enforced: false,
        }
    );
    assert_eq!(log.snapshot(), vec!["record", "reconcile"]);
}

/// The same missed deadline, but with the guard blocking a link it could
/// not resolve: nothing has a filter for these addresses, so handing them
/// over sends the caller out the main link — the leak the guard exists to
/// prevent (the assistant.example case, HW-0830).
#[test]
fn rule_host_answer_is_withheld_when_the_guard_is_blocking_and_install_missed_the_deadline() {
    let log = CallLog::default();
    let out = handle_a_query(
        "assistant.example",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: false,
        },
        &oracle(&["assistant.example"]),
        &FakeUpstream {
            answer: Ok(resolved(&[ip(23, 10, 20, 159)])),
        },
        &FakeSink(&log),
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::DeadlineExceeded,
        },
        &NoopFakeIpAnswerer,
        &|| true,
        &NoEnforcement,
    );
    assert_eq!(out, QueryOutcome::Withheld);
    // The fact is still recorded: the next reconcile builds the filter, and
    // the re-query moments later is answered normally.
    assert_eq!(log.snapshot(), vec!["record", "reconcile"]);
}

/// A deferred answer is NOT withheld even while the guard blocks: every
/// address in it was already cached-routable, so its filters are installed.
/// Withholding those would cost connectivity the guard never protects.
#[test]
fn deferred_answer_is_not_withheld_while_the_guard_is_blocking() {
    let log = CallLog::default();
    let cached = ip(23, 10, 20, 159);
    let out = handle_a_query(
        "assistant.example",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: true,
        },
        &oracle(&["assistant.example"]),
        &FakeUpstream {
            answer: Ok(resolved(&[cached])),
        },
        &CachedSink {
            log: &log,
            cached: vec![cached],
        },
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::Deferred,
        },
        &NoopFakeIpAnswerer,
        &|| true,
        &NoEnforcement,
    );
    assert_eq!(
        out,
        QueryOutcome::Answer {
            ips: vec![cached],
            enforced: false,
        }
    );
}

#[test]
fn stable_answer_subset_passes_small_sets_through() {
    let resolved = [ip(1, 1, 1, 1), ip(2, 2, 2, 2)];
    assert_eq!(
        stable_answer_subset(&resolved, &[], MAX_RULE_ANSWER_IPS),
        resolved.to_vec()
    );
}

#[test]
fn stable_answer_subset_prefers_cached_then_fills_and_caps() {
    let resolved: Vec<Ipv4Addr> = (1..=6).map(|i| ip(10, 0, 0, i)).collect();
    // Two of the six are already cached — they must lead the answer.
    let cached = [ip(10, 0, 0, 5), ip(10, 0, 0, 3)];
    let out = stable_answer_subset(&resolved, &cached, 4);
    assert_eq!(
        out,
        vec![
            ip(10, 0, 0, 3),
            ip(10, 0, 0, 5),
            ip(10, 0, 0, 1),
            ip(10, 0, 0, 2)
        ],
        "cached first (upstream order), then fresh, capped at 4"
    );
}

#[test]
fn stable_answer_subset_all_cached_caps_without_fresh() {
    let resolved: Vec<Ipv4Addr> = (1..=6).map(|i| ip(10, 0, 0, i)).collect();
    let out = stable_answer_subset(&resolved, &resolved, 4);
    assert_eq!(out.len(), 4);
    assert_eq!(out, resolved[..4].to_vec());
}

#[test]
fn rule_host_answer_is_capped_to_stable_subset() {
    // Seven upstream addresses → the answer (and the recorded fact) must
    // carry only MAX_RULE_ANSWER_IPS of them.
    let log = CallLog::default();
    let many: Vec<Ipv4Addr> = (1..=7).map(|i| ip(23, 10, 20, i)).collect();
    let out = handle_a_query(
        "assistant.example",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: false,
        },
        &oracle(&["assistant.example"]),
        &FakeUpstream {
            answer: Ok(resolved(&many)),
        },
        &FakeSink(&log),
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::Installed,
        },
        &NoopFakeIpAnswerer,
        &OpenLeakGuard,
        &NoEnforcement,
    );
    match out {
        QueryOutcome::Answer { ips, enforced } => {
            assert!(enforced);
            assert_eq!(ips.len(), MAX_RULE_ANSWER_IPS);
            assert_eq!(ips, many[..MAX_RULE_ANSWER_IPS].to_vec());
        }
        other => panic!("expected Answer, got {other:?}"),
    }
    assert_eq!(log.snapshot(), vec!["record", "reconcile"]);
}

#[test]
fn fake_ip_scope_host_is_answered_with_the_virtual_address_and_skips_reconcile() {
    let log = CallLog::default();
    let out = handle_a_query(
        "assistant.example",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: false,
        },
        &oracle(&["assistant.example"]),
        &FakeUpstream {
            answer: Ok(resolved(&[ip(23, 10, 20, 140)])),
        },
        &FakeSink(&log),
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::Installed,
        },
        &FakeFakeIp {
            scope: vec!["assistant.example".to_string()],
            refuse: Vec::new(),
            fake: ip(198, 18, 0, 5),
        },
        &OpenLeakGuard,
        &NoEnforcement,
    );
    // The app gets the FAKE address, flagged enforced (the TUN + relay carry
    // the flow, no per-IP install needed).
    assert_eq!(
        out,
        QueryOutcome::Answer {
            ips: vec![ip(198, 18, 0, 5)],
            enforced: true,
        }
    );
    // The REAL address was still recorded (the relay needs it as upstream),
    // but there is NO reconcile — fake-IP replaces per-IP routing for scope.
    assert_eq!(log.snapshot(), vec!["record"]);
}

#[test]
fn a_rule_host_outside_fake_ip_scope_keeps_the_real_per_ip_path() {
    let log = CallLog::default();
    let out = handle_a_query(
        "bank.example",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: false,
        },
        &oracle(&["bank.example"]),
        &FakeUpstream {
            answer: Ok(resolved(&[ip(23, 10, 20, 138)])),
        },
        &FakeSink(&log),
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::Installed,
        },
        // Fake-IP is on, but this host is NOT in scope (e.g. a P2P/crypto
        // exclusion) → real address + normal reconcile.
        &FakeFakeIp {
            scope: vec!["assistant.example".to_string()],
            refuse: Vec::new(),
            fake: ip(198, 18, 0, 5),
        },
        &OpenLeakGuard,
        &NoEnforcement,
    );
    assert_eq!(
        out,
        QueryOutcome::Answer {
            ips: vec![ip(23, 10, 20, 138)],
            enforced: true,
        }
    );
    assert_eq!(log.snapshot(), vec!["record", "reconcile"]);
}

#[test]
fn scoped_answerer_gives_an_in_scope_host_a_stable_fake_address() {
    let allocator = Arc::new(Mutex::new(FakeIpAllocator::default()));
    let answerer = ScopedFakeIpAnswerer::new(FakeIpScope::enabled(Vec::<String>::new()), allocator);
    let first = answerer.fake_answer("assistant.example").expect("in scope");
    assert_eq!(first.len(), 1);
    assert!(first[0].to_string().starts_with("198.18."));
    // Idempotent: the same host always maps to the same fake address.
    assert_eq!(
        answerer.fake_answer("assistant.example"),
        Some(first.clone())
    );
    // A different host gets a different address.
    let other = answerer.fake_answer("claude.ai").expect("in scope");
    assert_ne!(other, first);
}

#[test]
fn scoped_answerer_returns_none_when_disabled_or_excluded() {
    let allocator = Arc::new(Mutex::new(FakeIpAllocator::default()));
    // Feature off → real path.
    let off = ScopedFakeIpAnswerer::new(FakeIpScope::disabled(), Arc::clone(&allocator));
    assert_eq!(off.fake_answer("assistant.example"), None);
    // On, but the host is excluded / non-routable / a literal → real path.
    let on = ScopedFakeIpAnswerer::new(FakeIpScope::enabled(["bank.example"]), allocator);
    assert_eq!(on.fake_answer("api.bank.example"), None);
    assert_eq!(on.fake_answer("localhost"), None);
    assert_eq!(on.fake_answer("23.10.20.78"), None);
}

#[test]
fn scoped_answerer_honours_a_runtime_exclusion() {
    let allocator = Arc::new(Mutex::new(FakeIpAllocator::default()));
    let exclusions = Arc::new(crate::fake_ip::RuntimeHostExclusions::new());
    let answerer = ScopedFakeIpAnswerer::new(FakeIpScope::enabled(Vec::<String>::new()), allocator)
        .with_runtime_exclusions(Arc::clone(&exclusions));
    // In scope before the exclusion.
    assert!(answerer.fake_answer("vpn.example.com").is_some());
    // The VPN self-heal excludes the server → the answerer falls open to the
    // real path (and covers subdomains).
    exclusions.insert("vpn.example.com");
    assert_eq!(answerer.fake_answer("vpn.example.com"), None);
    assert_eq!(answerer.fake_answer("gw1.vpn.example.com"), None);
    // An unrelated in-scope host is unaffected.
    assert!(answerer.fake_answer("assistant.example").is_some());
}

#[test]
fn gated_answerer_defers_to_the_live_gate() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let up = Arc::new(AtomicBool::new(false));
    let gate_flag = Arc::clone(&up);
    let inner: Arc<dyn FakeIpAnswerer> = Arc::new(FakeFakeIp {
        scope: vec!["assistant.example".to_string()],
        refuse: Vec::new(),
        fake: ip(198, 18, 0, 9),
    });
    let gated = GatedFakeIpAnswerer::new(inner, Arc::new(move || gate_flag.load(Ordering::SeqCst)));
    // Gate closed (stack down / feature off) → real path even for an
    // in-scope host: fake-IP never hands out an address nothing carries.
    assert_eq!(gated.fake_answer("assistant.example"), None);
    // Gate open (stack running) → the inner answerer decides.
    up.store(true, Ordering::SeqCst);
    assert_eq!(
        gated.fake_answer("assistant.example"),
        Some(vec![ip(198, 18, 0, 9)])
    );
    // Still nothing for an out-of-scope host — the gate only enables, the
    // inner answerer still scopes.
    assert_eq!(gated.fake_answer("example.com"), None);
}

#[test]
fn upstream_failure_propagates_without_enforcement() {
    let log = CallLog::default();
    let out = handle_a_query(
        "assistant.example",
        AnswerHold {
            deadline: Duration::from_millis(150),
            fast_answers: false,
        },
        &oracle(&["assistant.example"]),
        &FakeUpstream {
            answer: Err(ResolveError::Unavailable("timeout".into())),
        },
        &FakeSink(&log),
        &FakeReconciler {
            log: &log,
            outcome: ReconcileOutcome::Installed,
        },
        &NoopFakeIpAnswerer,
        &OpenLeakGuard,
        &NoEnforcement,
    );
    assert_eq!(
        out,
        QueryOutcome::Upstream(ResolveError::Unavailable("timeout".into()))
    );
    // No fact recorded, no reconcile: nothing to enforce on a failed resolve.
    assert!(log.snapshot().is_empty());
}
