//! Observations and independent reachability findings recorded per principal.

use super::*;

impl AutoRulesEngine {
    /// Independent name-specific TLS evidence; it never attributes a browser flow.
    pub(crate) fn note_shared_address_reachability(
        &self,
        sid: &str,
        hostname: &str,
        now: SystemTime,
    ) -> bool {
        self.note_independent_path_reachability(
            sid,
            hostname,
            AUTO_RULE_SIGNAL_SHARED_ADDRESS_REACHABILITY,
            now,
        )
    }

    /// A bounded HTTP exchange differed across the owner's actual links.
    /// No passive completion or navigation credit is inferred from this measurement.
    pub fn note_http_path_reachability(&self, sid: &str, hostname: &str, now: SystemTime) -> bool {
        self.note_independent_path_reachability(
            sid,
            hostname,
            AUTO_RULE_SIGNAL_HTTP_PATH_REACHABILITY,
            now,
        )
    }

    fn note_independent_path_reachability(
        &self,
        sid: &str,
        hostname: &str,
        signal: &str,
        now: SystemTime,
    ) -> bool {
        let host = normalized_host(hostname);
        if host.is_empty()
            || host.len() > 253
            || !host.is_ascii()
            || matches!(
                nrr_domain::rule_value_validation::validate_rule_value("domain", &host),
                nrr_domain::rule_value_validation::RuleValueValidation::Error { .. }
            )
            || !self.learns_for(sid)
            || self.default_route_role(sid) != RouteRole::Primary
        {
            return false;
        }
        let Some(snapshot) = self.rules.active_rules_for(sid) else {
            return false;
        };
        let exclusions = RuleBookExclusions {
            book: &snapshot.rule_book,
        };
        if exclusions.is_rule_host(&host)
            || exclusions.is_matched_by_existing_rule(&host)
            || exclusions.is_platform_infrastructure(&host)
        {
            return false;
        }
        let www = signal == AUTO_RULE_SIGNAL_HTTP_PATH_REACHABILITY
            && automatic_suffix_target(&host) != host;
        let proposed = if www {
            automatic_suffix_target(&host).to_string()
        } else {
            host.clone()
        };
        let (kind, authored_kind) = if www {
            (AUTO_RULE_MATCH_KIND_SUFFIX, AuthoredMatchKind::SuffixDomain)
        } else {
            (AUTO_RULE_MATCH_KIND_EXACT, AuthoredMatchKind::ExactHost)
        };
        let id = candidate_id(sid, kind, &proposed);
        let suppressed = self.suppressed_ids(sid);
        if suppressed.contains(&id)
            || suppressed.contains(&candidate_id(sid, AUTO_RULE_MATCH_KIND_SUFFIX, &host))
        {
            return false;
        }
        let now_ms = unix_ms(now);
        let candidate = PendingCandidate {
            dto: AutoRuleCandidateDto {
                id,
                anchor: host.clone(),
                proposed_match: proposed,
                match_kind: kind.to_string(),
                route: RouteRole::Secondary.slug().to_string(),
                affinity: 0.0,
                observations: None,
                first_seen_unix_ms: now_ms,
                last_seen_unix_ms: now_ms,
                signal: signal.to_string(),
                consumers: Vec::new(),
                consumers_changed_unix_ms: 0,
                primary_behavior: AUTO_RULE_PRIMARY_BEHAVIOR_STALLS.to_string(),
                anchor_refuses_main_link: false,
                observed_members: if www { vec![host] } else { Vec::new() },
                served_by_main_link: false,
                third_party: None,
                secondary_reach: Some(true),
                any_zone_site: String::new(),
                less_certain: String::new(),
            },
            route: RouteRole::Secondary,
            match_kind: authored_kind,
        };
        let checked = www.then(|| {
            let mut observed = candidate.dto.clone();
            observed.proposed_match = observed.anchor.clone();
            observed
        });
        self.park(sid, vec![candidate], now_ms);
        if let Some(observed) = checked {
            self.record_candidate_discovery(
                sid,
                &observed,
                DiscoveryDecision::new("candidate", "ready", "offer-ready"),
                now,
            );
        }
        self.announce_pending(sid, now);
        true
    }

    pub(crate) fn withdraw_shared_address_reachability(
        &self,
        sid: &str,
        hostname: &str,
        now: SystemTime,
    ) {
        self.withdraw_independent_path(
            sid,
            hostname,
            AUTO_RULE_SIGNAL_SHARED_ADDRESS_REACHABILITY,
            now,
        );
    }

    pub fn withdraw_http_path_reachability(&self, sid: &str, hostname: &str, now: SystemTime) {
        self.withdraw_independent_path(sid, hostname, AUTO_RULE_SIGNAL_HTTP_PATH_REACHABILITY, now);
    }

    fn withdraw_independent_path(&self, sid: &str, hostname: &str, signal: &str, now: SystemTime) {
        let host = normalized_host(hostname);
        let target = if signal == AUTO_RULE_SIGNAL_HTTP_PATH_REACHABILITY {
            automatic_suffix_target(&host)
        } else {
            host.as_str()
        };
        let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = guard.get_mut(sid) else {
            return;
        };
        let before = entry.len();
        entry.retain(|candidate| {
            candidate.dto.signal != signal || candidate.dto.proposed_match != target
        });
        let updated = (before != entry.len()).then(|| entry.clone());
        drop(guard);
        if let Some(updated) = updated {
            self.persist_pending(sid, &updated, unix_ms(now));
        }
    }

    /// Active HTTP reachability is carried on a companion's parked evidence,
    /// never inserted into passive browser outcomes or navigation counters.
    pub(crate) fn note_measured_http_primary(
        &self,
        sid: &str,
        hostname: &str,
        answered: bool,
        now: SystemTime,
    ) {
        let host = normalized_host(hostname);
        let at = Instant::now();
        {
            let mut cache = self.http_primary.lock().unwrap_or_else(|p| p.into_inner());
            cache.retain(|_, (_, measured)| {
                at.saturating_duration_since(*measured) < crate::primary_stall_registry::ENTRY_TTL
            });
            let key = (sid.to_string(), host.clone());
            if !cache.contains_key(&key) {
                let owners: HashSet<_> = cache.keys().map(|(owner, _)| owner.as_str()).collect();
                if !owners.contains(sid) && owners.len() >= MAX_TRACKED_PRINCIPALS {
                    if let Some(owner) = cache
                        .iter()
                        .min_by_key(|(_, (_, measured))| *measured)
                        .map(|((owner, _), _)| owner.clone())
                    {
                        cache.retain(|(held, _), _| held != &owner);
                    }
                }
                if cache.keys().filter(|(owner, _)| owner == sid).count()
                    >= MAX_PENDING_PER_PRINCIPAL
                {
                    if let Some(key) = cache
                        .iter()
                        .filter(|((owner, _), _)| owner == sid)
                        .min_by_key(|(_, (_, measured))| *measured)
                        .map(|(key, _)| key.clone())
                    {
                        cache.remove(&key);
                    }
                }
            }
            cache.insert(key, (answered, at));
        }
        if !answered {
            return;
        }
        let updated = {
            let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            let Some(entry) = guard.get_mut(sid) else {
                return;
            };
            let mut changed = false;
            for candidate in entry.iter_mut().filter(|candidate| {
                candidate.dto.proposed_match == host
                    && !is_self_signed_signal(&candidate.dto.signal)
            }) {
                let behavior = AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS;
                changed |= candidate.dto.primary_behavior != behavior;
                candidate.dto.primary_behavior = behavior.to_string();
            }
            changed.then(|| entry.clone())
        };
        if let Some(updated) = updated {
            self.persist_pending(sid, &updated, unix_ms(now));
            self.publish_count(sid, self.pending_count(sid) as u64);
        }
    }

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
                                msg_key = "autorules-intake-evidence-restored",
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

    /// [`Self::note_candidate_in_use`] for a name a reverse lookup produced.
    pub fn note_reverse_named_in_use(&self, sid: &str, hostname: &str, at: SystemTime) {
        if hostname.is_empty() {
            return;
        }
        self.reverse_named
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .observe((sid.to_string(), hostname.to_ascii_lowercase()));
        self.note_candidate_in_use(sid, hostname, at);
    }

    /// Whether `proposed` names or covers a host a reverse lookup named for `sid`.
    pub(super) fn covers_reverse_named(&self, sid: &str, proposed: &str) -> bool {
        let proposed = proposed.to_ascii_lowercase();
        self.reverse_named
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|(owner, host)| {
                owner == sid
                    && (host == &proposed
                        || host
                            .strip_suffix(proposed.as_str())
                            .is_some_and(|rest| rest.ends_with('.')))
            })
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
        let key = (sid.to_string(), normalized_host(hostname));
        if reached.only_pulled_in() {
            self.note_discovery(
                sid,
                Some(hostname),
                None,
                DiscoveryDecision::new("candidate", "not-created", "pulled-in"),
                now,
            );
            self.pulled_in_refusals
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .observe(key);
            tracing::info!(
                target: "nrr::auto-rules",
                msg_key = "autorules-intake-not-offered-companion-burst",
                sid = %sid,
                host = %hostname,
                companions = reached.companions,
                "not offered: every measured sighting of this host came inside another page's burst",
            );
            return false;
        }
        self.pulled_in_refusals
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&key);
        self.park_self_signed(sid, hostname, AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED, now)
    }

    /// Whether a stall of `hostname` should ask again: it was refused as
    /// pulled in. Cheap enough for every stalled connection.
    #[must_use]
    pub fn awaits_main_link_recheck(&self, sid: &str, hostname: &str) -> bool {
        let refusals = self
            .pulled_in_refusals
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        !refusals.is_empty() && refusals.contains(&(sid.to_string(), normalized_host(hostname)))
    }

    /// Another stall of a host refused as pulled in. The verdict that refused
    /// it holds while the host keeps failing, so without this the user's own
    /// retries, measured after that first answer, never reach the offer.
    pub fn recheck_main_link_blocked_host(
        &self,
        sid: &str,
        hostname: &str,
        reached: HostCounts,
        now: SystemTime,
    ) -> bool {
        if !self.awaits_main_link_recheck(sid, hostname) {
            return false;
        }
        let host = normalized_host(hostname);
        if self.main_link_behavior(sid, &host) != PrimaryBehavior::Stalls {
            self.pulled_in_refusals
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&(sid.to_string(), host));
            return false;
        }
        if reached.only_pulled_in() {
            return false;
        }
        self.note_main_link_blocked_host(sid, hostname, reached, now)
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
        use nrr_shared::ipc_payloads::AUTO_RULE_SIGNAL_APP_MAIN_LINK_BLOCKED;
        let Some(gate) = self.app_offer_gate(sid, program) else {
            return false;
        };
        tracing::info!(
            target: "nrr::auto-rules",
            msg_key = "autorules-intake-app-offer-stalled",
            sid = %sid,
            program = %gate.program,
            stalled = stalled.len(),
            "offering to move a program onto the additional route: none of its connections completed on the main link",
        );
        self.park_app_offer(
            sid,
            gate,
            AUTO_RULE_SIGNAL_APP_MAIN_LINK_BLOCKED,
            primary_behavior_slug(PrimaryBehavior::Stalls),
            stalled,
            now,
        )
    }

    /// Parks an offer for a program that looks names up past the system
    /// resolver (see [`nrr_domain::own_resolver`]): rules by name never see
    /// where it goes, so only a rule naming the program reaches it. Offered
    /// only while the additional route has rules by name to miss, and never
    /// over an offer already standing for the same program.
    pub fn note_app_own_resolver(
        &self,
        sid: &str,
        program: &str,
        unnamed: &[std::net::IpAddr],
        now: SystemTime,
    ) -> bool {
        use nrr_shared::ipc_payloads::AUTO_RULE_SIGNAL_APP_OWN_RESOLVER;
        let Some(gate) = self.app_offer_gate(sid, program) else {
            return false;
        };
        if !gate.secondary_names_sites {
            return false;
        }
        let standing = self
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .is_some_and(|entry| entry.iter().any(|c| c.dto.id == gate.id));
        if standing {
            return false;
        }
        tracing::info!(
            target: "nrr::auto-rules",
            msg_key = "autorules-intake-app-offer-own-resolver",
            sid = %sid,
            program = %gate.program,
            unnamed = unnamed.len(),
            "offering a program rule: the program looks names up on its own, so rules by name do not reach it",
        );
        self.park_app_offer(
            sid,
            gate,
            AUTO_RULE_SIGNAL_APP_OWN_RESOLVER,
            "",
            unnamed,
            now,
        )
    }

    /// What every whole-program offer must pass: discovery on, a rule book to
    /// compare against, the main route as the default, no rule naming the
    /// program yet, not a tunnel client, not refused before.
    fn app_offer_gate(&self, sid: &str, program: &str) -> Option<AppOfferGate> {
        use nrr_shared::ipc_payloads::AUTO_RULE_MATCH_KIND_APPLICATION;
        let program = program.trim().to_ascii_lowercase();
        let own = crate::app_observation_lookup::own_process_key();
        if !own.is_empty() && crate::app_observation_lookup::app_key(&program) == own {
            return None;
        }
        if program.is_empty() || self.mode(sid) == AutoRulesMode::Off {
            return None;
        }
        let Some(snapshot) = self.rules.active_rules_for(sid) else {
            tracing::debug!(
                target: "nrr::auto-rules",
                program = %program,
                sid = %sid,
                "not offered: this principal has no active rules to compare against",
            );
            return None;
        };
        if self.default_route_role(sid) == RouteRole::Secondary
            || app_covered(&snapshot.rule_book, &program)
        {
            return None;
        }
        // A tunnel client dialling its own servers fails on the main link by
        // design; routing it through the tunnel it is building is a loop.
        if crate::vpn_client_registry::global_confirmed_vpn_clients()
            .matches_image_for(Some(sid), &program)
        {
            return None;
        }
        let id = candidate_id(sid, AUTO_RULE_MATCH_KIND_APPLICATION, &program);
        if self.suppressed_ids(sid).contains(&id) {
            tracing::debug!(
                target: "nrr::auto-rules",
                program = %program,
                "not offered: the user has refused this one before",
            );
            return None;
        }
        Some(AppOfferGate {
            secondary_names_sites: names_sites(&snapshot.rule_book.secondary),
            program,
            id,
        })
    }

    fn park_app_offer(
        &self,
        sid: &str,
        gate: AppOfferGate,
        signal: &str,
        primary_behavior: &str,
        seen: &[std::net::IpAddr],
        now: SystemTime,
    ) -> bool {
        use nrr_shared::ipc_payloads::AUTO_RULE_MATCH_KIND_APPLICATION;
        let now_ms = unix_ms(now);
        let candidate = PendingCandidate {
            dto: AutoRuleCandidateDto {
                id: gate.id,
                anchor: gate.program.clone(),
                proposed_match: gate.program,
                match_kind: AUTO_RULE_MATCH_KIND_APPLICATION.to_string(),
                route: RouteRole::Secondary.slug().to_string(),
                affinity: 0.0,
                observations: None,
                first_seen_unix_ms: now_ms,
                last_seen_unix_ms: now_ms,
                signal: signal.to_string(),
                consumers: Vec::new(),
                consumers_changed_unix_ms: 0,
                primary_behavior: primary_behavior.to_string(),
                anchor_refuses_main_link: false,
                observed_members: seen.iter().map(ToString::to_string).collect(),
                served_by_main_link: false,
                third_party: None,
                secondary_reach: None,
                any_zone_site: String::new(),
                less_certain: String::new(),
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
        let mut not_opening = false;
        let mut measured = Vec::new();
        let updated = {
            let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            let Some(entry) = guard.get_mut(sid) else {
                return;
            };
            let mut touched = false;
            for candidate in entry.iter_mut() {
                if candidate.dto.proposed_match == host {
                    candidate.dto.secondary_reach = Some(answered);
                    measured.push(candidate.dto.clone());
                    touched = true;
                    withheld |= !answered && is_self_signed_signal(&candidate.dto.signal);
                    // Measured on both links: the site the user opened fails
                    // where it goes and works where it could go.
                    not_opening |=
                        answered && candidate.dto.signal == AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED;
                }
            }
            touched.then(|| entry.clone())
        };
        if let Some(updated) = updated {
            self.persist_pending(sid, &updated, now_ms);
        }
        for dto in measured {
            let decision = if answered {
                DiscoveryDecision::new("candidate", "ready", "offer-ready")
            } else {
                DiscoveryDecision::new("probe", "hidden", "secondary-failed")
            };
            self.record_candidate_discovery(sid, &dto, decision, now);
        }
        if withheld {
            self.announce_unreachable(sid, &host, now_ms);
        }
        if not_opening {
            if let Some(told) = self.site_not_opening.get() {
                told(sid, &host);
            }
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

    /// A standalone offer uses the same exclusions as companion proposals.
    fn park_self_signed(&self, sid: &str, hostname: &str, signal: &str, now: SystemTime) -> bool {
        let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || self.mode(sid) == AutoRulesMode::Off {
            self.note_discovery(
                sid,
                Some(&host),
                None,
                DiscoveryDecision::new("candidate", "not-created", "discovery-disabled"),
                now,
            );
            tracing::debug!(
                target: "nrr::auto-rules",
                host = %host,
                mode = ?self.mode(sid),
                "not offered: no name, or this principal collects nothing",
            );
            return false;
        }
        // `*.intranet` would claim a whole top-level label; only the full name
        // our resolver completed it to can be offered.
        let Some(host) = crate::short_name_completions::global_short_name_completions()
            .qualify(&host)
            .map(std::borrow::Cow::into_owned)
        else {
            self.note_discovery(
                sid,
                Some(&host),
                None,
                DiscoveryDecision::new("name", "not-created", "name-unknown"),
                now,
            );
            tracing::debug!(
                target: "nrr::auto-rules",
                host = %host,
                "not offered: a short name with no known full name",
            );
            return false;
        };
        // A measured response removes the evidence for a standalone failure.
        let behavior = self.main_link_behavior(sid, &host);
        if behavior == PrimaryBehavior::Responds {
            self.note_discovery(
                sid,
                Some(&host),
                None,
                DiscoveryDecision::new("health", "not-created", "primary-responds"),
                now,
            );
            tracing::debug!(
                target: "nrr::auto-rules",
                host = %host,
                signal = %signal,
                "not offered: the main link carries this host, so there is nothing to move",
            );
            return false;
        }
        let Some(snapshot) = self.rules.active_rules_for(sid) else {
            self.note_discovery(
                sid,
                Some(&host),
                None,
                DiscoveryDecision::new("candidate", "not-created", "no-active-rules"),
                now,
            );
            tracing::debug!(
                target: "nrr::auto-rules",
                host = %host,
                sid = %sid,
                "not offered: this principal has no active rules to compare against",
            );
            return false;
        };
        let exclusions = RuleBookExclusions {
            book: &snapshot.rule_book,
        };
        // Shared infrastructure cannot identify the site the user intended.
        if exclusions.is_rule_host(&host)
            || exclusions.is_matched_by_existing_rule(&host)
            || exclusions.is_platform_infrastructure(&host)
            || self.default_route_role(sid) == RouteRole::Secondary
        {
            let reason = if exclusions.is_rule_host(&host)
                || exclusions.is_matched_by_existing_rule(&host)
            {
                "already-covered"
            } else if exclusions.is_platform_infrastructure(&host) {
                "platform-infrastructure"
            } else {
                "default-secondary"
            };
            self.note_discovery(
                sid,
                Some(&host),
                None,
                DiscoveryDecision::new("candidate", "not-created", reason),
                now,
            );
            tracing::debug!(
                target: "nrr::auto-rules",
                host = %host,
                rule_host = exclusions.is_rule_host(&host),
                covered = exclusions.is_matched_by_existing_rule(&host),
                infrastructure = exclusions.is_platform_infrastructure(&host),
                default_is_secondary = self.default_route_role(sid) == RouteRole::Secondary,
                "not offered: a rule already covers this host, or moving it would change nothing",
            );
            return false;
        }
        // Failures name this host, never its healthy neighbours. Leading WWW
        // retains the user's explicit canonical suffix exception.
        let (kind, authored_kind) = host_offer_kind(&host);
        let now_ms = unix_ms(now);
        let id = candidate_id(sid, kind, &host);
        if self.suppressed_ids(sid).contains(&id)
            || self.suppressed_ids(sid).contains(&candidate_id(
                sid,
                AUTO_RULE_MATCH_KIND_SUFFIX,
                &host,
            ))
        {
            let authored = self
                .authored
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(sid)
                .is_some_and(|ids| ids.contains_key(&id));
            self.note_discovery(
                sid,
                Some(&host),
                None,
                DiscoveryDecision::new(
                    "candidate",
                    "hidden",
                    if authored {
                        "already-covered"
                    } else {
                        "user-dismissed"
                    },
                ),
                now,
            );
            tracing::debug!(
                target: "nrr::auto-rules",
                host = %host,
                "not offered: the user has refused this one before",
            );
            return false;
        }
        let candidate = PendingCandidate {
            dto: AutoRuleCandidateDto {
                id,
                anchor: host.clone(),
                proposed_match: host,
                match_kind: kind.to_string(),
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
                any_zone_site: String::new(),
                less_certain: String::new(),
            },
            route: RouteRole::Secondary,
            match_kind: authored_kind,
        };

        let parked = (signal == AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED).then(|| {
            (
                candidate.dto.id.clone(),
                candidate.dto.proposed_match.clone(),
            )
        });
        self.park(sid, vec![candidate], now_ms);
        if matches!(self.mode(sid), AutoRulesMode::Suggest) {
            self.announce_pending(sid, now);
            if let (Some((id, host)), Some(told)) = (parked, self.main_link_blocked_parked.get()) {
                told(sid, &id, &host);
            }
        }
        true
    }
}

/// A program that passed [`AutoRulesEngine::app_offer_gate`].
struct AppOfferGate {
    program: String,
    id: String,
    /// The additional route has an enabled rule by name — something a program
    /// resolving on its own would miss.
    secondary_names_sites: bool,
}

fn names_sites(set: &nrr_domain::canonical::CanonicalRuleSet) -> bool {
    set.rules().iter().any(|r| {
        r.enabled
            && matches!(
                r.address_match,
                Some(
                    CanonicalAddressMatch::ExactFqdn(_)
                        | CanonicalAddressMatch::SuffixDomain(_)
                        | CanonicalAddressMatch::Zone(_)
                )
            )
    })
}

/// A host name as offers are keyed: lower case, no trailing dot.
fn normalized_host(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}
