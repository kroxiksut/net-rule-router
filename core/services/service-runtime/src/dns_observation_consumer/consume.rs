//! One observed resolution, folded into everything that depends on it.
//!
//! This is the hot path — it runs per DNS answer — so every branch here is
//! either a map lookup or a decision already made elsewhere.

use super::*;

impl DnsObservationConsumer {
    /// Consume a batch of observations: cache the ones matching an active
    /// rule, discard the rest. No active user / no rules → nothing matches.
    pub fn consume(&self, observations: &[DnsObservation], now: SystemTime) -> ConsumeSummary {
        let mut summary = ConsumeSummary::default();
        if observations.is_empty() {
            return summary;
        }
        let Some(sid) = (self.active_sid)() else {
            // No routing-active user → nothing to enforce.
            summary.ignored = observations.len() as u32;
            return summary;
        };
        let Some(snapshot) = self.rules_provider.active_rules_for(&sid) else {
            summary.ignored = observations.len() as u32;
            return summary;
        };

        // Built lazily (only when a non-secondary host appears) and once per
        // batch — maps every IPv4 a secondary rule currently routes out the
        // secondary link → the rule host that owns it.
        let mut secondary_owners: Option<HashMap<Ipv4Addr, String>> = None;
        // Secondary usability, read lazily (the gated resolve
        // enumerates adapters) and at most once per batch, mirroring how the
        // conn-observe consumer reads its egress context once per batch.
        let mut secondary_usable_memo: Option<bool> = None;
        // Open the companion-learning batch ONCE for the whole
        // drain. The engine's mutex is taken here rather than per observation,
        // and a principal whose `auto_rules_mode` is `off` yields `None` so the
        // loop below does no learning work at all.
        let mut learning = self
            .auto_rules
            .as_ref()
            .and_then(|engine| engine.begin_batch(&sid));
        // One instant for the whole drain, plus the observation's position in
        // it. The observations carry no timestamps of their own, and stamping
        // them all identically made "which anchor was active most recently" a
        // tie that the ledger broke alphabetically — a companion fetched while
        // one site loaded could be filed under another that merely happened to
        // sort later. The order in the drain IS the order they were resolved.
        let batch_ms = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // Both address-less cases below are steady states, not events: under
        // Mode B every rule host is answered from our own pool on every
        // resolution, and a hosts-file pin never stops being pinned. One line
        // each per observation made them 10% of a verbose session, so the drain
        // counts them and says it once at the end.
        let mut fake_intercepted: BTreeSet<&str> = BTreeSet::new();
        let mut loopback_pinned: BTreeSet<&str> = BTreeSet::new();
        for (index, obs) in observations.iter().enumerate() {
            if obs.ipv4s.is_empty() {
                continue;
            }
            // Drop non-routable IPs (loopback/unspecified) before anything
            // else touches this observation. An ad-blocking hosts file pins
            // ad/tracker domains to 127.0.0.1 / 0.0.0.0; such a mapping must
            // never enter the FQDN cache, become a /32 route, or be flagged
            // as collateral (real logs: `app.example → 127.0.0.1`). If nothing
            // routable remains the ADDRESS is inert; whether the observation
            // itself still means something is decided just below.
            let routable: Vec<Ipv4Addr> = obs
                .ipv4s
                .iter()
                .copied()
                .filter(|ip| !is_non_routable_v4(ip))
                .collect();
            if routable.is_empty() {
                // Two very different reasons the address list can vanish, and
                // they must not be conflated. Under Mode B our own resolver
                // answers a rule host with a fake-pool address, so the ONLY
                // thing missing is a real address — the resolution itself is
                // genuine evidence that the user is on that site. Discarding it
                // silently starved companion learning of every anchor (observed
                // : 24 minutes of Mode B, zero anchors). A real
                // loopback/unspecified pin carries no such meaning: an
                // ad-blocking hosts file made it up, so it must keep going
                // nowhere — not into the cache, not into a route, and never
                // into a suggestion.
                if contains_fake_pool_addr(obs.ipv4s.iter().copied().map(IpAddr::V4)) {
                    // Name-only learning: no address is passed on, so nothing
                    // virtual can reach the cache, a /32, or the census. The
                    // rule match runs only when a principal actually collects
                    // (`learning` is `None` when the mode is off), so this costs
                    // nothing on the default path.
                    if let Some(batch) = learning.as_mut() {
                        let secondary =
                            rule_set_match_origin(&obs.hostname, &snapshot.rule_book.secondary);
                        let primary =
                            rule_set_match_origin(&obs.hostname, &snapshot.rule_book.primary);
                        batch.observe(
                            batch_ms.saturating_add(index as u64),
                            &obs.hostname,
                            crate::auto_rules::AutoRulesEngine::classify(
                                primary.user_authored,
                                secondary.user_authored,
                            ),
                        );
                    }
                    fake_intercepted.insert(obs.hostname.as_str());
                } else {
                    loopback_pinned.insert(obs.hostname.as_str());
                }
                continue;
            }
            // The main link answered, and nothing in the answer can be
            // reached — a filtering provider standing a placeholder in for the
            // site. That is not a companion signal (nobody pulled this host);
            // it is the host saying the main link cannot carry it, which is
            // exactly the case the user otherwise has to diagnose and add by
            // hand. The engine applies its own exclusions, and the main-link
            // probe still gets to disagree before the user is asked.
            if crate::dns_address_sanity::is_provider_placeholder_answer(&obs.ipv4s) {
                // Parked, not offered: the same answer goes to a name a page
                // prefetched and to one the user opened, and only the second
                // one is followed by a connection. See
                // [`crate::placeholder_waitlist`].
                tracing::debug!(
                    target: "nrr::auto-rules",
                    host = %obs.hostname,
                    addresses = ?obs.ipv4s,
                    "the answer for this host is a provider placeholder",
                );
                let parked = crate::placeholder_waitlist::global_placeholder_waitlist().note(
                    &obs.hostname,
                    &obs.ipv4s,
                    crate::conn_observation_consumer::now_unix_ms(),
                );
                tracing::debug!(
                    target: "nrr::auto-rules",
                    host = %obs.hostname,
                    outcome = ?parked,
                    "placeholder answer parked",
                );
                match parked {
                    // Nothing observes connections here, so the answer stands
                    // on its own, as it did before this gate existed.
                    crate::placeholder_waitlist::Parked::ConfirmationUnavailable => {
                        if let Some(engine) = self.auto_rules.as_ref() {
                            engine.note_placeholder_answer_host(&sid, &obs.hostname, now);
                        }
                    }
                    // The connection was seen first: confirmed already.
                    crate::placeholder_waitlist::Parked::AlreadyInUse(host) => {
                        if let Some(engine) = self.auto_rules.as_ref() {
                            engine.note_placeholder_answer_host(&sid, &host, now);
                        }
                    }
                    crate::placeholder_waitlist::Parked::Waiting => {}
                }
            }
            let secondary = rule_set_match_origin(&obs.hostname, &snapshot.rule_book.secondary);
            let primary = rule_set_match_origin(&obs.hostname, &snapshot.rule_book.primary);
            let (in_primary, in_secondary) = (primary.matched, secondary.matched);
            // Feed companion learning BEFORE the keep/discard branch below: a
            // hostname that matches no rule is discarded from the cache by
            // design, and those discarded names are exactly the ones a routed
            // site may be missing. Reuses the two match results just computed,
            // so learning adds no matching work. Hosts pinned to loopback by an
            // ad-blocking hosts file never reach here (the `routable` filter
            // above already dropped them) and so can never be suggested.
            if let Some(batch) = learning.as_mut() {
                batch.observe(
                    batch_ms.saturating_add(index as u64),
                    &obs.hostname,
                    crate::auto_rules::AutoRulesEngine::classify(
                        primary.user_authored,
                        secondary.user_authored,
                    ),
                );
            }
            if in_primary || in_secondary {
                self.upsert_counted(
                    &obs.hostname,
                    &routable,
                    now,
                    StorageResolutionSource::Dns,
                    &mut summary,
                );
            } else {
                summary.ignored = summary.ignored.saturating_add(1);
                // Discarded from the CACHE, kept as a name. An address
                // no rule covers still needs a name the moment its
                // connections start failing on the main link.
                if let Some(names) = self.observed_names.as_ref() {
                    names.record(&obs.hostname, &routable);
                }
            }
            // Collateral: a host that should egress the PRIMARY link (matches
            // a primary rule, or no rule at all) yet resolves to an IP a
            // SECONDARY rule already routes out the secondary/VPN link. The
            // secondary rule's `/32` is more specific than our primary
            // counter-overlay, so this host silently rides the secondary
            // route — IP-level routing cannot separate two hostnames sharing
            // one IP. Pure-secondary hosts are skipped (they belong there).
            if !in_secondary {
                let owners = secondary_owners.get_or_insert_with(|| {
                    build_secondary_ip_owners(
                        &snapshot.rule_book.secondary,
                        self.fqdn_lookup.as_ref(),
                    )
                });
                for ip in &routable {
                    let Some(owner) = owners.get(ip) else {
                        continue;
                    };
                    if owner == &obs.hostname {
                        continue;
                    }
                    // record this direct (non-secondary) host
                    // as a co-tenant of the shared IP so the shared-IP policy can
                    // count `direct_on_ip`. Idempotent upsert; done every
                    // observation (refreshes recency), independent of the
                    // once-per-lifetime WARN dedup below.
                    //
                    // A tenant a MAIN-route rule claims is recorded as such:
                    // pinning its address to the additional route cannot divert
                    // it there, because the user's own rule sends it the other
                    // way — the two orders cancel and the host dies instead.
                    let primary_ruled =
                        match_specificity(&obs.hostname, &snapshot.rule_book.primary).is_some();
                    self.record_direct_tenant(&obs.hostname, *ip, now, primary_ruled);
                    if self.note_collateral_once(&obs.hostname, *ip) {
                        summary.collateral = summary.collateral.saturating_add(1);
                        // While the secondary is UNUSABLE
                        // (unresolved / probe-dead / block-all armed) the
                        // shared IP is NOT pinned to it: the compile side skips
                        // the pin (see `secondary_ip_policy` + the orchestrator
                        // exemption sets), so the direct host stays on the
                        // primary link. Say so at info instead of warning that
                        // it "egresses the secondary" — during the
                        // run that WARN described a pin onto a dead link while
                        // the host was actually being blocked to death.
                        let secondary_usable =
                            *secondary_usable_memo.get_or_insert_with(|| (self.secondary_usable)());
                        if !secondary_usable {
                            tracing::info!(
                                target: "nrr::dns-observe",
                                direct_host = %obs.hostname,
                                shared_ip = %ip,
                                secondary_rule_host = %owner,
                                "collateral pin skipped — secondary unusable: the shared IP is not pinned to a link that cannot carry traffic, so this direct host stays on the primary; the pin re-arms on the next observation/reconcile once the secondary recovers",
                            );
                        }
                        // While fake-IP is live the collateral is being steered
                        // onto the primary by name (a virtual address), so the
                        // shared IP no longer forces this host out the secondary
                        // link — downgrade the WARN to a debug line.
                        else if (self.fake_ip_running)() {
                            tracing::debug!(
                                target: "nrr::dns-observe",
                                direct_host = %obs.hostname,
                                shared_ip = %ip,
                                secondary_rule_host = %owner,
                                "collateral shared IP detected, but fake-IP is live and steers this host onto the primary by name — no action needed",
                            );
                        } else {
                            tracing::warn!(
                                target: "nrr::dns-observe",
                                msg_key = "direct-host-shares-secondary-ip",
                                direct_host = %obs.hostname,
                                shared_ip = %ip,
                                secondary_rule_host = %owner,
                                "collateral: a direct host shares its IP with a secondary rule, so it egresses the secondary (VPN) link, not the primary. IP routing cannot separate two hostnames on one IP — narrow the secondary rule or use per-host routing.",
                            );
                        }
                    }
                }
            }
        }
        if !fake_intercepted.is_empty() {
            tracing::debug!(
                target: "nrr::dns-observe",
                hosts = %name_sample(&fake_intercepted),
                distinct = fake_intercepted.len(),
                "observations answered from our own fake-IP pool (Mode B interception) — no real address to cache or route",
            );
        }
        if !loopback_pinned.is_empty() {
            tracing::debug!(
                target: "nrr::dns-observe",
                hosts = %name_sample(&loopback_pinned),
                distinct = loopback_pinned.len(),
                "observations pinned to loopback/unspecified (hosts file?) — not cached or routed",
            );
        }
        summary
    }
}
