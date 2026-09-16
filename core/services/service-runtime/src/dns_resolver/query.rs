//! Answering one query: the A path, the AAAA path, and the gates each of them
//! passes through before a reply leaves.
//!
//! This is the only place that turns an upstream answer into something the
//! machine will route on, so every gate that can withhold an address — the
//! leak guard, the enforcement view, fake-IP — is applied here rather than
//! spread over the callers.

use super::*;

pub fn handle_a_query(
    hostname: &str,
    hold: AnswerHold,
    oracle: &dyn RuleHostOracle,
    upstream: &dyn UpstreamResolver,
    sink: &dyn FactSink,
    reconciler: &dyn SyncReconciler,
    fake_ip: &dyn FakeIpAnswerer,
    leak_guard: &dyn LeakGuardPosture,
    enforced_view: &dyn EnforcedAddressView,
) -> QueryOutcome {
    // Upstream resolve is needed for BOTH paths — do it first.
    let resolved = match upstream.resolve(hostname, AddressFamily::Ipv4) {
        // Asked for v4, so nothing is dropped here; the narrowing marks the
        // whole handler as still speaking one family.
        Ok(r) => ResolvedAddressesV4 {
            addresses: crate::dns_wire::only_v4(&r.addresses),
            ttl_seconds: r.ttl_seconds,
        },
        Err(e) => {
            let reason = describe_resolve_failure(&e);
            tracing::debug!(
                target: "nrr::dns-resolver",
                host = %hostname,
                reason = %reason,
                "Mode B: upstream A resolve failed — propagating DNS failure to the app",
            );
            return QueryOutcome::Upstream(e);
        }
    };

    // Fail-open: a non-rule host (the majority) returns immediately with no
    // policy work, so general DNS never depends on enforcement health.
    if !oracle.is_rule_host(hostname) {
        tracing::debug!(
            target: "nrr::dns-resolver",
            host = %hostname,
            rule_host = false,
            addresses = ?resolved.addresses,
            "Mode B: pass-through (non-rule host) — resolved upstream and answering, no policy work (fail-open)",
        );
        return QueryOutcome::Answer {
            ips: resolved.addresses,
            enforced: false,
        };
    }

    // A filtering provider answers a name it blocks with a placeholder instead
    // of refusing it. Whatever cannot be a destination must never become a
    // route or a packet filter, so screen the answer BEFORE any of it is
    // remembered — this is the last gate, and it needs no network.
    let upstream_count = resolved.addresses.len();
    let ttl_seconds = resolved.ttl_seconds;
    let sanity = classify_answer(&resolved.addresses);
    let usable = match sanity {
        AnswerSanity::Clean => resolved.addresses,
        AnswerSanity::Sanitized { keep } => {
            tracing::info!(
                target: "nrr::dns-resolver",
                host = %hostname,
                dropped = ?rejected_addresses(&resolved.addresses),
                kept = ?keep,
                "rule-host answer carried addresses that cannot be a destination — dropped from enforcement",
            );
            keep
        }
        // Nothing survived, and the second-source confirmation upstream of here
        // could not replace it. Answering the client costs nothing (the name is
        // blocked either way); pinning would build enforcement on a fiction.
        AnswerSanity::Unusable => {
            tracing::warn!(
                target: "nrr::dns-resolver",
                host = %hostname,
                rejected = ?rejected_addresses(&resolved.addresses),
                "rule-host answer holds no address that could be a destination — answering the client but NOT pinning it to enforcement",
            );
            return QueryOutcome::Answer {
                ips: resolved.addresses,
                enforced: false,
            };
        }
    };

    // Rule host: install enforcement BEFORE answering. П0-D — answer (and
    // record) a small STABLE subset of the fresh addresses, preferring ones
    // already cached: the client only ever connects to what we enforce, and
    // the pinned set converges to a few addresses instead of the CDN's whole
    // rotating pool (which is what dragged the Google front-end into the
    // kill-switch on 0719). Record the answered subset only, then drive the
    // synchronous bounded reconcile.
    // Remember the FULL answer, not just the subset we are about to hand out.
    // An app with its own address cache may connect to one of the addresses we
    // did not answer with; when that connection is dropped, this memory is what
    // ties the address back to its rule host so it can be enforced instead of
    // staying broken. See `recent_rule_addresses`.
    let displaced = crate::recent_rule_addresses::global_recent_rule_addresses()
        .record_displacing(hostname, &usable);
    // Two unrelated names answered with one identical address set is not a
    // resolution — it is an upstream handing out a stub. Enforcement still
    // proceeds (fail-open; the addresses may be a legitimately shared front
    // end we cannot prove otherwise), but the collision is surfaced.
    if let Some(other) = displaced.filter(|other| !hosts_share_origin(hostname, other)) {
        tracing::warn!(
            target: "nrr::dns-resolver",
            host = %hostname,
            also_answered_for = %other,
            addresses = ?usable,
            "upstream answered two unrelated hostnames with one identical address set — suspect a provider stub rather than a destination",
        );
    }
    let cached = sink.cached_routable_ips(hostname);
    let answered = stable_answer_subset(&usable, &cached, MAX_RULE_ANSWER_IPS);
    sink.record(
        hostname,
        &ResolvedAddresses {
            addresses: answered.iter().copied().map(IpAddr::V4).collect(),
            ttl_seconds,
        },
    );

    // Block D (fake-IP, slice 4) — if this host is in fake-IP scope, hand the
    // application its VIRTUAL address instead of the real ones. The real
    // addresses were just recorded, so the relay can reach the upstream; the app
    // connects to the fake address, the TUN catches the flow, and the relay
    // steers it per-hostname. No WFP reconcile here: fake-IP replaces per-IP
    // routing for scope hosts, and the kill-switch blocks the real addresses
    // separately so a cached / in-app-DoH real IP cannot leak past the fake.
    if !fake_ip.may_substitute(&answered) {
        tracing::info!(
            target: "nrr::dns-resolver",
            host = %hostname,
            addresses = ?answered,
            "answering with the real address: this host lives inside the additional route's own subnet, and a virtual address there would point the caller at our TUN instead of into the tunnel",
        );
    } else if let Some(fake) = fake_ip.fake_answer(hostname) {
        tracing::debug!(
            target: "nrr::dns-resolver",
            host = %hostname,
            rule_host = true,
            fake = ?fake,
            real = ?answered,
            "Mode B: fake-IP — answering with virtual address (real recorded for the relay), no per-IP reconcile",
        );
        return QueryOutcome::Answer {
            ips: fake,
            enforced: true,
        };
    }

    // Hold the answer for the reconcile ONLY when it introduces an address the
    // policy does not carry yet — the one case where the app's first connect
    // can race the install. When every answered address is already enforced,
    // answer immediately and let the reconcile converge in the background.
    // Field measurement: holding every answer blew the deadline on 57% of
    // queries and 1359 clients abandoned the query entirely — a page-wide stall
    // that bought nothing for already-routed addresses.
    //
    // The question is asked of what is INSTALLED, not of the FQDN cache. The
    // cache answers "has this name ever resolved to this address", and using it
    // here read every rotated CDN address as covered: on the reporting machine
    // 2158 rule-host answers went out in a day, not one of them enforced, while
    // the gate reported the steady state.
    let unenforced: Vec<Ipv4Addr> = answered
        .iter()
        .copied()
        .filter(|ip| !enforced_view.is_enforced(*ip))
        .collect();
    let all_enforced = unenforced.is_empty();
    // The full run that would carry these takes seconds; their routes alone
    // take a millisecond, and the route decides which link the first connect
    // leaves through. Their filters still come with the full run.
    let routed_now = if all_enforced {
        0
    } else {
        reconciler.install_first_contact(&unenforced)
    };
    // A reconcile that runs past the deadline cannot install anything inside
    // it, so waiting spends the budget on every query and installs nothing.
    let futile_wait = reconciler
        .typical_run()
        .is_some_and(|typical| typical > hold.deadline);
    let reconcile = if hold.fast_answers && all_enforced {
        reconciler.request_reconcile();
        ReconcileOutcome::Deferred
    } else if futile_wait {
        reconciler.request_reconcile();
        ReconcileOutcome::AheadOfEnforcement
    } else {
        reconciler.reconcile_now(hold.deadline)
    };
    let enforced = all_enforced || matches!(reconcile, ReconcileOutcome::Installed);
    tracing::debug!(
        target: "nrr::dns-resolver",
        host = %hostname,
        rule_host = true,
        addresses = ?answered,
        upstream_count,
        unenforced = unenforced.len(),
        routed_now,
        enforced,
        reconcile = ?reconcile,
        "Mode B: rule host resolved and reconciled before answering",
    );
    // The answer is about to hand a client an address the policy does not
    // carry. Said once per host per occurrence, at INFO: this is the moment a
    // user's first connect gets dropped, and it must not be discoverable only
    // by whoever thinks to turn on debug logging.
    if !all_enforced {
        tracing::info!(
            target: "nrr::dns-resolver",
            host = %hostname,
            addresses = ?unenforced,
            waited = !futile_wait,
            routed_now,
            "answering ahead of enforcement: the filters for these addresses come with the next run; `routed_now` of them already leave through their rule's link",
        );
    }
    // Fail-open on latency is the right trade while the additional link is UP:
    // the worst case is a fraction of a second on the wrong route. It is the
    // wrong one while the guard is blocking a link it could not resolve —
    // there is no route to be early for, nothing has a filter for these
    // addresses yet, and the caller connects the instant it holds them. That is
    // an egress over the main link for exactly the destination the guard exists
    // to hold back, so the answer is withheld instead.
    //
    // Only the missed deadline qualifies: `Deferred` means every answered
    // address was already cached-routable (its filters are installed), and
    // withholding those would cost connectivity the guard never protects.
    if matches!(reconcile, ReconcileOutcome::DeadlineExceeded) && leak_guard.blocking() {
        tracing::warn!(
            target: "nrr::dns-resolver",
            host = %hostname,
            addresses = ?answered,
            "leak guard is blocking with the additional link unresolved and enforcement for this answer did not install in time — withholding the addresses instead of leaking them to the main link",
        );
        return QueryOutcome::Withheld;
    }
    QueryOutcome::Answer {
        ips: answered,
        enforced,
    }
}

/// What an AAAA query for a rule host came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AaaaOutcome {
    /// Answer with these — none when the host has no AAAA worth handing out.
    Answer(Vec<std::net::Ipv6Addr>),
    Upstream(ResolveError),
    /// Enforcement missed its deadline while the leak guard blocks — see
    /// [`handle_a_query`].
    Withheld,
}

/// AAAA for a rule host whose IPv6 rides the additional link: the contract of
/// [`handle_a_query`] — record, reconcile, then answer. Virtual addresses are
/// IPv4-only, so a host they carry never reaches here, and there is no stable
/// subset to prefer: that memory is of IPv4 fronts.
pub fn handle_aaaa_query(
    hostname: &str,
    hold: AnswerHold,
    upstream: &dyn UpstreamResolver,
    sink: &dyn FactSink,
    reconciler: &dyn SyncReconciler,
    leak_guard: &dyn LeakGuardPosture,
) -> AaaaOutcome {
    let resolved = match upstream.resolve(hostname, AddressFamily::Ipv6) {
        Ok(r) => r,
        Err(e) => return AaaaOutcome::Upstream(e),
    };
    let all: Vec<std::net::Ipv6Addr> = resolved
        .addresses
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V6(v6) => Some(*v6),
            IpAddr::V4(_) => None,
        })
        .collect();
    let answered: Vec<std::net::Ipv6Addr> = all
        .iter()
        .copied()
        .filter(|ip| !crate::dns_address_sanity::is_unreachable_v6(ip))
        .take(MAX_RULE_ANSWER_IPS)
        .collect();
    // Nothing a route or a filter could name: answer, pin nothing — the A
    // path's rule for an unusable answer.
    if answered.is_empty() {
        return AaaaOutcome::Answer(all);
    }
    sink.record(
        hostname,
        &ResolvedAddresses {
            addresses: answered.iter().copied().map(IpAddr::V6).collect(),
            ttl_seconds: resolved.ttl_seconds,
        },
    );
    // No "already enforced" shortcut: the installed-address view is IPv4. The
    // wait is skipped only when it is known to be futile, as on the A path.
    let reconcile = if reconciler
        .typical_run()
        .is_some_and(|typical| typical > hold.deadline)
    {
        reconciler.request_reconcile();
        ReconcileOutcome::AheadOfEnforcement
    } else {
        reconciler.reconcile_now(hold.deadline)
    };
    if matches!(reconcile, ReconcileOutcome::DeadlineExceeded) && leak_guard.blocking() {
        tracing::warn!(
            target: "nrr::dns-resolver",
            host = %hostname,
            addresses = ?answered,
            "leak guard is blocking and enforcement for this IPv6 answer did not install in time — withholding it",
        );
        return AaaaOutcome::Withheld;
    }
    tracing::debug!(
        target: "nrr::dns-resolver",
        host = %hostname,
        addresses = ?answered,
        reconcile = ?reconcile,
        "Mode B: rule host IPv6 resolved and reconciled before answering",
    );
    AaaaOutcome::Answer(answered)
}

/// Process-wide fast-DNS-answers toggle.
///
/// Same singleton rationale as `dns_egress::global_dns_via_secondary`: the
/// settings writer that flips the value and the resolver that consults it per
/// query are built in different composition scopes, and a process singleton
/// keeps them on one value by construction. Defaults to `true` (answer
/// immediately when every answered address is already cached-routable); the
/// boot path overwrites it with the persisted setting before the resolver
/// serves its first query.
pub fn global_dns_fast_answers() -> Arc<std::sync::atomic::AtomicBool> {
    static FLAG: std::sync::OnceLock<Arc<std::sync::atomic::AtomicBool>> =
        std::sync::OnceLock::new();
    Arc::clone(FLAG.get_or_init(|| Arc::new(std::sync::atomic::AtomicBool::new(true))))
}
