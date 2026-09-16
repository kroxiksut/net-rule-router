//! What the engine is TOLD: observed flows, health, blocks and reachability.
//!
//! Nothing here decides anything — intake only records evidence against a
//! principal's ledger. The verdict is [`super::tick`]'s job, which is what
//! keeps the observation path cheap.

use super::*;

impl AutoRulesEngine {
    /// Opens an observation batch for `sid`, or returns `None` when this
    /// principal collects nothing (`auto_rules_mode = off`) — the caller then
    /// does no work at all, which is what "off" has to mean.
    pub fn begin_batch<'a>(&'a self, sid: &'a str) -> Option<LedgerBatch<'a>> {
        let settings = self.settings(sid);
        if settings.mode == AutoRulesMode::Off {
            return None;
        }
        let eager = settings.eager_delivery_names;
        // Read BEFORE the ledger lock: the store touches SQLite, and holding
        // the observation feed shut for a disk read would stall every caller.
        let saved = match self.evidence_store.as_ref() {
            Some(store) if !self.ledgers_contains(sid) => store.load(sid),
            _ => None,
        };
        let mut ledgers = self.ledgers.lock().unwrap_or_else(|p| p.into_inner());
        match ledgers.get(sid) {
            Some(existing) if existing.eager_delivery_names == eager => {}
            // Setting changed under a live ledger. It cannot be reconfigured in
            // place, so it is replaced; the evidence lost re-accumulates over the
            // next few page loads, which is the same cost as a service restart.
            Some(_) => {
                ledgers.insert(sid.to_string(), SidLedger::new(eager));
            }
            None => {
                evict_if_over_cap(&mut ledgers, sid);
                ledgers.insert(
                    sid.to_string(),
                    match saved {
                        Some(snapshot) if !snapshot.is_empty() => {
                            tracing::info!(
                                target: "nrr::auto-rules",
                                candidates = snapshot.candidates.len(),
                                anchors = snapshot.anchors.len(),
                                "restored companion evidence saved before the last restart",
                            );
                            SidLedger::restored(eager, snapshot)
                        }
                        _ => SidLedger::new(eager),
                    },
                );
            }
        }
        Some(LedgerBatch { ledgers, sid })
    }

    /// A flow to `hostname` just opened — treat it as activity, exactly like a
    /// DNS resolution of the same name.
    ///
    /// Why this exists: a window only opens when the learner is TOLD the site is
    /// in use, and until now the only source of that was a DNS observation. A
    /// browser answering from its own cache, or resolving over DoH, produces no
    /// observation at all — so the anchor stayed shut while the user sat on the
    /// page, and every companion loading beside it attached to nothing. A
    /// connection is the one signal that cannot be cached away: it is the thing
    /// the user is actually doing.
    ///
    /// Called from the relay's poll thread, so it does exactly what the DNS path
    /// does and nothing more: one classification against the rule book, one
    /// ledger write.
    ///
    /// Takes a wall-clock instant, not a duration: the ledger compares this
    /// against windows opened by the DNS path and against the proposal tick,
    /// both of which are wall-clock. A monotonic "millis since this observer
    /// started" reads as 1970 next to them, so every window it opened was
    /// invisible to the other source and every candidate it reported landed
    /// outside all of them.
    pub fn note_flow(&self, sid: &str, hostname: &str, at: SystemTime) {
        if hostname.is_empty() {
            return;
        }
        let at_ms = unix_ms(at).max(0) as u64;
        let Some(snapshot) = self.rules.active_rules_for(sid) else {
            return;
        };
        let kind = Self::classify(
            rule_set_match_origin(hostname, &snapshot.rule_book.primary).user_authored,
            rule_set_match_origin(hostname, &snapshot.rule_book.secondary).user_authored,
        );
        let Some(mut batch) = self.begin_batch(sid) else {
            return;
        };
        batch.observe(at_ms, hostname, kind);
    }

    /// Traffic to `hostname` was seen leaving over the wrong link while a
    /// routed site was open — the half-broken page, observed directly.
    ///
    /// Reported as [`CoActivityKind::CandidateInUse`], which lets a
    /// delivery-named host qualify from the visit that needed it instead of
    /// waiting for a second one. A host that turns out to be a rule host, or
    /// that arrives outside every anchor window, is dropped by the ledger — the
    /// caller does not have to know the rules to report a fact.
    ///
    /// Wall-clock instant, for the reason spelled out on [`Self::note_flow`].
    pub fn note_candidate_in_use(&self, sid: &str, hostname: &str, at: SystemTime) {
        if hostname.is_empty() {
            return;
        }
        let Some(mut batch) = self.begin_batch(sid) else {
            return;
        };
        batch.observe(
            unix_ms(at).max(0) as u64,
            hostname,
            CoActivityKind::CandidateInUse,
        );
    }

    /// Reports how a host behaved on the primary route. Only hosts the ledger
    /// already tracks are affected — an outcome is evidence about a candidate,
    /// never a reason to start tracking one, so a busy machine does not turn
    /// every stalled connection into a suggestion.
    pub fn note_primary_health(&self, sid: &str, hostname: &str, event: PrimaryHealthEvent) {
        if hostname.is_empty() {
            return;
        }
        let Some(mut batch) = self.begin_batch(sid) else {
            return;
        };
        batch.note_primary_health(hostname, event);
    }

    /// A host the main link answered with a placeholder instead of an address
    /// — parked like a companion suggestion, the host signing its own offer.
    pub fn note_placeholder_answer_host(&self, sid: &str, hostname: &str, now: SystemTime) -> bool {
        self.park_self_signed(sid, hostname, AUTO_RULE_SIGNAL_PLACEHOLDER_ANSWER, now)
    }

    /// Connections to this host kept failing on the main link and none ever
    /// completed there — the verdict comes from
    /// [`crate::primary_stall_registry`], which counts what the connection
    /// observer already sees.
    ///
    /// The strongest of the self-signed signals, because it is measured rather
    /// than inferred: the offer says the main link will not carry the site, and
    /// that is exactly what was observed. The same measurement withdraws the
    /// offer the moment the host starts working.
    ///
    /// `reached` says how the host came to be connected to. A host every
    /// measured sighting of which arrived inside another page's burst was never
    /// opened by anyone, and the offer would be about somebody else's ad.
    pub fn note_main_link_blocked_host(
        &self,
        sid: &str,
        hostname: &str,
        reached: HostCounts,
        now: SystemTime,
    ) -> bool {
        if reached.only_pulled_in() {
            tracing::info!(
                target: "nrr::auto-rules",
                sid = %sid,
                host = %hostname,
                companions = reached.companions,
                "not offered: every measured sighting of this host came inside another page's burst",
            );
            return false;
        }
        self.park_self_signed(sid, hostname, AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED, now)
    }

    /// Parks an offer to move a whole program onto the additional route: none
    /// of its connections completed on the main link while it stalled on
    /// several unnamed addresses (see [`nrr_domain::app_offer`]). `stalled`
    /// travels with the offer as what was seen.
    pub fn note_app_main_link_blocked(
        &self,
        sid: &str,
        program: &str,
        stalled: &[std::net::IpAddr],
        now: SystemTime,
    ) -> bool {
        use nrr_shared::ipc_payloads::{
            AUTO_RULE_MATCH_KIND_APPLICATION, AUTO_RULE_SIGNAL_APP_MAIN_LINK_BLOCKED,
        };
        let program = program.trim().to_ascii_lowercase();
        if program.is_empty() || self.mode(sid) == AutoRulesMode::Off {
            return false;
        }
        let Some(snapshot) = self.rules.active_rules_for(sid) else {
            return false;
        };
        if snapshot.behavior_mode.default_route_role() == RouteRole::Secondary
            || app_covered(&snapshot.rule_book, &program)
        {
            return false;
        }
        // A tunnel client dialling its own servers fails on the main link by
        // design; routing it through the tunnel it is building is a loop.
        if crate::vpn_client_registry::global_confirmed_vpn_clients().matches_image(&program) {
            return false;
        }
        let now_ms = unix_ms(now);
        let id = candidate_id(sid, AUTO_RULE_MATCH_KIND_APPLICATION, &program);
        if self.suppressed_ids(sid).contains(&id) {
            return false;
        }
        tracing::info!(
            target: "nrr::auto-rules",
            sid = %sid,
            program = %program,
            stalled = stalled.len(),
            "offering to move a program onto the additional route: none of its connections completed on the main link",
        );
        let candidate = PendingCandidate {
            dto: AutoRuleCandidateDto {
                id,
                anchor: program.clone(),
                proposed_match: program,
                match_kind: AUTO_RULE_MATCH_KIND_APPLICATION.to_string(),
                route: RouteRole::Secondary.slug().to_string(),
                affinity: 0.0,
                observations: None,
                first_seen_unix_ms: now_ms,
                last_seen_unix_ms: now_ms,
                signal: AUTO_RULE_SIGNAL_APP_MAIN_LINK_BLOCKED.to_string(),
                consumers: Vec::new(),
                consumers_changed_unix_ms: 0,
                primary_behavior: primary_behavior_slug(PrimaryBehavior::Stalls).to_string(),
                anchor_refuses_main_link: false,
                observed_members: stalled.iter().map(ToString::to_string).collect(),
                served_by_main_link: false,
                third_party: None,
                secondary_reach: None,
            },
            route: RouteRole::Secondary,
            match_kind: AuthoredMatchKind::Application,
        };
        self.park(sid, vec![candidate], now_ms);
        if matches!(self.mode(sid), AutoRulesMode::Suggest) {
            self.announce_pending(sid, now);
        }
        true
    }

    /// Withdraws the offer about `program` once one of its connections
    /// completes on the main link — the offer's whole claim is that none does.
    pub fn withdraw_app_offer(&self, sid: &str, program: &str, now: SystemTime) {
        let id = candidate_id(
            sid,
            nrr_shared::ipc_payloads::AUTO_RULE_MATCH_KIND_APPLICATION,
            &program.trim().to_ascii_lowercase(),
        );
        let updated = {
            let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            let Some(entry) = guard.get_mut(sid) else {
                return;
            };
            let before = entry.len();
            entry.retain(|c| c.dto.id != id);
            (entry.len() != before).then(|| entry.clone())
        };
        if let Some(updated) = updated {
            self.persist_pending(sid, &updated, unix_ms(now));
        }
    }

    /// What the ADDITIONAL route found for a host that has an offer parked.
    ///
    /// The offer says "move this into the tunnel". If the tunnel cannot reach
    /// the host either, the move would change nothing, and the honest place to
    /// notice that is before the user is asked — an outage upstream of both
    /// links looks exactly like a host worth routing.
    ///
    /// Recorded, never inferred: only a probe that actually ran writes here,
    /// so an unchecked offer stays exactly as visible as it was.
    pub fn note_secondary_reach(&self, sid: &str, hostname: &str, answered: bool, now: SystemTime) {
        let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return;
        }
        let now_ms = unix_ms(now);
        let mut withheld = false;
        let updated = {
            let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            let Some(entry) = guard.get_mut(sid) else {
                return;
            };
            let mut touched = false;
            for candidate in entry.iter_mut() {
                if candidate.dto.proposed_match == host {
                    candidate.dto.secondary_reach = Some(answered);
                    touched = true;
                    withheld |= !answered && is_self_signed_signal(&candidate.dto.signal);
                }
            }
            touched.then(|| entry.clone())
        };
        if let Some(updated) = updated {
            self.persist_pending(sid, &updated, now_ms);
        }
        if withheld {
            self.announce_unreachable(sid, &host, now_ms);
        }
    }

    /// Says, once a day per host, why an offer was withheld. Nothing is marked
    /// told while nobody listens, so the next probe tries again.
    fn announce_unreachable(&self, sid: &str, host: &str, now_ms: i64) {
        let Some(bus) = self.events.as_ref() else {
            return;
        };
        if !bus.has_subscriber_for(sid) {
            return;
        }
        {
            let mut told = self
                .unreachable_told
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            told.retain(|_, at| now_ms.saturating_sub(*at) < UNREACHABLE_NOTICE_GAP_MS);
            let key = (sid.to_string(), host.to_string());
            if told.contains_key(&key) || told.len() >= UNREACHABLE_NOTICE_CAP {
                return;
            }
            told.insert(key, now_ms);
        }
        bus.publish_for(
            sid,
            StatusUpdateEvent::HostUnreachableOnBothRoutes {
                sid: sid.to_string(),
                host: host.to_string(),
            },
        );
    }

    /// The name a self-signed offer should carry: `host` itself, or the
    /// registrable domain when the evidence already reaches that far.
    ///
    /// It reaches that far when a SECOND name under the same domain is already
    /// parked for failing, or when the failing name IS the domain. One failing
    /// subdomain proves nothing about its neighbours: measured on the field
    /// case, one subdomain was cut while the apex and `www` answered normally,
    /// so rolling up on that evidence would move working traffic into the
    /// tunnel.
    ///
    /// Two of them do prove it, and the proof is about the DOMAIN rather than
    /// about the apex: a provider cutting two unrelated names under one domain
    /// is cutting the domain, and the apex still answering is a detail of how
    /// far it has got. One site is one question, so the apex travels with the
    /// site it belongs to. Platform infrastructure never reaches here — it is
    /// refused before any of this — so a roll-up cannot swallow a domain that
    /// belongs to everybody.
    fn rolled_up_target(&self, sid: &str, host: String) -> String {
        let Some(apex) = registrable_domain(&host).map(str::to_string) else {
            return host;
        };
        if apex == host {
            return host;
        }
        if !self.another_name_under(sid, &apex, &host) {
            return host;
        }
        tracing::info!(
            target: "nrr::auto-rules",
            sid = %sid,
            host = %host,
            domain = %apex,
            "a second name under this domain fails on the main link — offering the domain instead of each name",
        );
        apex
    }

    /// Is a DIFFERENT self-signed offer already parked under `apex`?
    fn another_name_under(&self, sid: &str, apex: &str, host: &str) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .is_some_and(|offers| {
                offers.iter().any(|c| {
                    is_self_signed_signal(&c.dto.signal)
                        && c.dto.proposed_match != host
                        && registrable_domain(&c.dto.proposed_match) == Some(apex)
                })
            })
    }

    /// Withdraw self-signed offers the domain-wide one now covers, so the user
    /// is not shown the domain and its parts side by side.
    fn absorb_names_under(&self, sid: &str, apex: &str, now_ms: i64) {
        let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = guard.get_mut(sid) else {
            return;
        };
        let before = entry.len();
        entry.retain(|c| {
            !(is_self_signed_signal(&c.dto.signal)
                && c.dto.proposed_match != apex
                && registrable_domain(&c.dto.proposed_match) == Some(apex))
        });
        let absorbed = before - entry.len();
        let updated = (absorbed > 0).then(|| entry.clone());
        drop(guard);
        if let Some(updated) = updated {
            tracing::debug!(
                target: "nrr::auto-rules",
                sid = %sid,
                domain = %apex,
                absorbed,
                "single names withdrawn in favour of the offer for their domain",
            );
            self.persist_pending(sid, &updated, now_ms);
        }
    }

    /// Park an offer a host makes about ITSELF: no anchor, no companion
    /// arithmetic, just "this host does not work over the main link, and here
    /// is how we know". Shared by every such signal so they cannot drift on the
    /// exclusions — a host already covered by a rule, or a machine whose
    /// default route IS the tunnel, must not be offered anything.
    fn park_self_signed(&self, sid: &str, hostname: &str, signal: &str, now: SystemTime) -> bool {
        let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || self.mode(sid) == AutoRulesMode::Off {
            return false;
        }
        // A host the main link carries has nothing to move. Checked BEFORE
        // parking, not only before the popup: an offer sitting in the inbox for
        // a site that works is the same false statement, made quietly.
        let behavior = self.main_link_behavior(&host);
        if behavior == PrimaryBehavior::Responds {
            return false;
        }
        let Some(snapshot) = self.rules.active_rules_for(sid) else {
            return false;
        };
        let exclusions = RuleBookExclusions {
            book: &snapshot.rule_book,
        };
        // Already covered, or a rule would change nothing (same reasoning
        // `tick` applies to companion proposals).
        //
        // Shared platform infrastructure is refused here for the same reason
        // it is refused as a companion: it belongs to everybody, so routing
        // it drags unrelated traffic along. That it fails on the main link
        // does not change whose host it is — an ad or telemetry endpoint the
        // provider cuts is not a site the user was trying to open.
        if exclusions.is_rule_host(&host)
            || exclusions.is_matched_by_existing_rule(&host)
            || exclusions.is_platform_infrastructure(&host)
            || snapshot.behavior_mode.default_route_role() == RouteRole::Secondary
        {
            return false;
        }
        // One site, one question. A provider that cuts two different names
        // under a domain is cutting the domain, and asking about each name
        // separately makes the user answer the same question twice.
        let host = self.rolled_up_target(sid, host);
        let now_ms = unix_ms(now);
        let id = candidate_id(sid, AUTO_RULE_MATCH_KIND_SUFFIX, &host);
        if self.suppressed_ids(sid).contains(&id) {
            return false;
        }
        let candidate = PendingCandidate {
            dto: AutoRuleCandidateDto {
                id,
                anchor: host.clone(),
                proposed_match: host,
                match_kind: AUTO_RULE_MATCH_KIND_SUFFIX.to_string(),
                route: RouteRole::Secondary.slug().to_string(),
                affinity: 0.0,
                // No pair, no visits — the signal below is what this offer knows.
                observations: None,
                first_seen_unix_ms: now_ms,
                last_seen_unix_ms: now_ms,
                signal: signal.to_string(),
                consumers: Vec::new(),
                consumers_changed_unix_ms: 0,
                primary_behavior: primary_behavior_slug(behavior).to_string(),
                anchor_refuses_main_link: false,
                // The host named itself; nothing else was seen alongside it.
                observed_members: Vec::new(),
                served_by_main_link: false,
                // No site pulled this one in, so whose name it is was never
                // asked — answering "the site's own" called ad hosts the
                // user's own.
                third_party: None,
                // Nobody has asked the additional route about this host yet.
                secondary_reach: None,
            },
            route: RouteRole::Secondary,
            match_kind: AuthoredMatchKind::SuffixDomain,
        };
        self.absorb_names_under(sid, &candidate.dto.proposed_match, now_ms);
        self.park(sid, vec![candidate], now_ms);
        if matches!(self.mode(sid), AutoRulesMode::Suggest) {
            self.announce_pending(sid, now);
        }
        true
    }
}
