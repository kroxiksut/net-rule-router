//! The pass that turns accumulated evidence into suggestions, and publishes.
//!
//! Called on a timer, never from the observation path: classification reads
//! the whole ledger, and doing that per connection is the one cost this
//! product cannot pay.

use super::*;

impl AutoRulesEngine {
    /// Classifies one observed hostname for the ledger: a hostname covered by a
    /// rule the USER wrote anchors its own route, everything else is a candidate.
    ///
    /// Takes the match results the caller already computed — the DNS consumer
    /// tests both rule sets to decide whether to cache the resolution, so
    /// learning rides along at zero additional matching cost. Auto-added rules
    /// are deliberately not anchors: see `rule_set_match_origin`.
    pub fn classify(in_primary: bool, in_secondary: bool) -> CoActivityKind {
        if in_secondary {
            CoActivityKind::Anchor {
                route: RouteRole::Secondary,
            }
        } else if in_primary {
            CoActivityKind::Anchor {
                route: RouteRole::Primary,
            }
        } else {
            CoActivityKind::Candidate
        }
    }

    /// An earlier author saved the enforcement view, so the user's stored rules
    /// may hold `<id>+sub` twins they never wrote. Removed once per principal
    /// per run, whatever the mode; a refusal (rules lock, security alert) is
    /// retried after [`REFUSED_REWRITE_RETRY`], not on every tick.
    fn drop_stored_subdomain_twins(&self, sid: &str, now: SystemTime) {
        let resting = match self
            .twin_cleanup
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
        {
            Some(None) => true,
            Some(Some(refused_at)) => still_waiting(*refused_at, REFUSED_REWRITE_RETRY, now),
            None => false,
        };
        if resting {
            return;
        }
        let Some(author) = self.author.get() else {
            return;
        };
        let correlation = format!("auto-rules-cleanup-{}", unix_ms(now));
        let outcome = author.rewrite(sid, &|book| book.without_subdomain_twins(), &correlation);
        let refused_at = match outcome {
            Ok(rewrote) => {
                if rewrote {
                    tracing::info!(
                        target: "nrr::auto-rules",
                        sid = %sid,
                        "stored subdomain twins removed from the user's rules",
                    );
                }
                None
            }
            Err(e) => {
                tracing::debug!(
                    target: "nrr::auto-rules",
                    sid = %sid,
                    code = %e.code,
                    "stored subdomain twins not removed yet",
                );
                Some(now)
            }
        };
        self.twin_cleanup
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(sid.to_owned(), refused_at);
    }

    // ── Proposal tick ────────────────────────────────────────────────────────

    /// Recomputes `sid`'s suggestions and acts on them per the principal's mode.
    ///
    /// Runs on a slow timer. Never call this per observation: the ledger's
    /// answer is stable over a browsing session, so the extra work would produce
    /// the identical list.
    pub fn tick(&self, sid: &str, now: SystemTime) -> TickSummary {
        self.drop_stored_subdomain_twins(sid, now);
        // Whatever the suggestion mode: `?` rules are the user's own.
        self.verify_primary_step(sid, now);
        let mut summary = TickSummary::default();
        let mode = self.mode(sid);
        if mode == AutoRulesMode::Off {
            self.forget(sid);
            return summary;
        }
        // Save what has been learned so far. Rides this tick rather than a
        // timer of its own — the ledger is only worth writing when it has had
        // time to change, and this is the tick that already runs on that scale.
        self.persist_evidence(sid, now);
        let Some(snapshot) = self.rules.active_rules_for(sid) else {
            return summary;
        };
        let now_ms = unix_ms(now);
        self.expire_pending(sid, now_ms);
        // Withdraw offers the rules have since covered, before anything reads
        // the parked set or its count.
        self.retire_covered(sid, &snapshot, now_ms);

        // Compute proposals with the ledger lock held and NOTHING else: the
        // exclusions read the rule book (already in hand) and the authoring path
        // below must never run while the observation feed is blocked.
        let exclusions = RuleBookExclusions {
            book: &snapshot.rule_book,
        };
        let proposals: Vec<CompanionProposal> = {
            let mut ledgers = self.ledgers.lock().unwrap_or_else(|p| p.into_inner());
            match ledgers.get_mut(sid) {
                Some(l) => {
                    // Retire anchors whose rule is gone before reading the
                    // ledger. An anchor was immortal until now, so a rule the
                    // user DELETED went on blocking its own hostname from ever
                    // being suggested back — the exact thing someone does when
                    // they want to see the suggestion.
                    let retired = l.ledger.retain_anchors(|host| {
                        rule_set_match_origin(host, &snapshot.rule_book.primary).user_authored
                            || rule_set_match_origin(host, &snapshot.rule_book.secondary)
                                .user_authored
                    });
                    if retired > 0 {
                        tracing::debug!(
                            target: "nrr::auto-rules",
                            sid = %sid,
                            retired,
                            "hosts that are no longer rules stopped counting as sites to learn around",
                        );
                    }
                    l.ledger.proposals(now_ms.max(0) as u64, &exclusions)
                }
                None => Vec::new(),
            }
        };
        if proposals.is_empty() {
            summary.pending = self.pending_count_under(sid, &snapshot);
            return summary;
        }

        // A suggestion naming the route unmatched traffic already takes changes
        // nothing: the host is uncovered (the exclusions guarantee it), so it
        // goes there anyway. Dropping these is not a matter of taste — offering
        // them asks the user to approve a rule with no effect.
        let default_role = snapshot.behavior_mode.default_route_role();
        let suppressed = self.suppressed_ids(sid);
        let mut inert = 0_usize;
        // One address, one offer. A CDN host pulled by two routed sites yields
        // two proposals with the same id (the id names the address, not the
        // pairing), so the strongest evidence wins and the user is asked once.
        // Held alongside the offer: whose activity actually pulled the address.
        // Not part of the DTO — it decides which anchor SIGNS the offer, and the
        // user is shown the site, not the arithmetic.
        let mut strongest: HashMap<String, (f64, PendingCandidate)> = HashMap::new();
        // Every site pulling each address, winner and losers alike — the losers
        // become `consumers` on the winning DTO instead of being discarded, so
        // the user sees who else needs the host. This is gathered for EVERY
        // proposal, including one an inert or suppressed anchor made: a site on
        // the default route gets no offer of its own (adding it changes
        // nothing) but the user must still see that its traffic rides along.
        let mut consumers: HashMap<String, Vec<(f64, AutoRuleConsumerDto)>> = HashMap::new();
        // Names of a few dropped ones. A bare count answers "how many" but not
        // "was my site among them", which is the question asked of every quiet
        // run; the cap keeps a busy tick from writing a page of hostnames.
        let mut inert_names: Vec<String> = Vec::new();
        for proposal in proposals.iter() {
            // The kind is part of the id only because it used to vary; it is
            // now fixed, and keeping it keeps ids stable across the change.
            let id = candidate_id(sid, AUTO_RULE_MATCH_KIND_SUFFIX, proposal.proposed.value());
            consumers.entry(id.clone()).or_default().push((
                proposal.nearest_share,
                AutoRuleConsumerDto {
                    hostname: proposal.anchor_hostname.clone(),
                    route: proposal.route.slug().to_string(),
                },
            ));
            if proposal.route == default_role {
                inert += 1;
                if inert_names.len() < 8 {
                    inert_names.push(format!(
                        "{} ({})",
                        proposal.proposed.value(),
                        proposal.anchor_hostname
                    ));
                }
                continue;
            }
            if suppressed.contains(&id) {
                continue;
            }
            let candidate = to_candidate(proposal, id.clone());
            let pulled = proposal.nearest_share;
            match strongest.get(&id) {
                Some((held_pulled, held))
                    if !explains_better(pulled, &candidate.dto, *held_pulled, &held.dto) => {}
                _ => {
                    strongest.insert(id, (pulled, candidate));
                }
            }
        }
        let mut fresh: Vec<PendingCandidate> = strongest
            .into_values()
            .map(|(_, mut candidate)| {
                let entries = consumers.remove(&candidate.dto.id).unwrap_or_default();
                candidate.dto.consumers = merge_consumers(&candidate.dto.anchor, entries);
                candidate
            })
            .collect();
        fresh.sort_by(|a, b| a.dto.id.cmp(&b.dto.id));
        // Deduped on the SELECTION, not on the event: this tick runs every ten
        // seconds, and a steady set of dropped companions used to write the
        // same line with the same sample every time. What is worth a line is a
        // set that CHANGED — the same reasoning as "bound adapter still NOT
        // usable (deduped)".
        let note_changed = {
            let mut notes = self.quiet_note.lock().unwrap_or_else(|p| p.into_inner());
            if inert > 0 {
                let note = QuietNote {
                    inert: inert as u64,
                    sample: inert_names.clone(),
                };
                let changed = quiet_note_is_news(notes.get(sid), &note);
                notes.insert(sid.to_string(), note);
                changed
            } else {
                notes.remove(sid);
                false
            }
        };
        if note_changed {
            tracing::debug!(
                target: "nrr::auto-rules",
                sid = %sid,
                dropped = inert,
                default_route = %default_role.slug(),
                sample = %inert_names.join(", "),
                "dropped companion suggestions that would not change where the traffic goes",
            );
        }
        if fresh.is_empty() {
            summary.pending = self.pending_count_under(sid, &snapshot);
            if matches!(mode, AutoRulesMode::Suggest) {
                summary.published = self.announce_pending(sid, now);
            }
            return summary;
        }

        match mode {
            AutoRulesMode::Off => unreachable_off(),
            AutoRulesMode::Auto => {
                summary.authored = self.author_now(sid, &fresh, now);
                summary.pending = self.pending_count_under(sid, &snapshot);
                if summary.authored > 0 {
                    // Informational: the tray drops an event whose pending count
                    // yields no unseen candidates, so this cannot prompt. It
                    // exists so a GUI that wants to show "rules were added for
                    // you" has a signal to hang that on.
                    summary.published =
                        self.publish(sid, summary.pending as u64, &fresh, true, now);
                }
            }
            AutoRulesMode::Suggest => {
                let (added, _) = self.park(sid, fresh.clone(), now_ms);
                summary.parked = added;
                summary.pending = self.pending_count_under(sid, &snapshot);
                if added > 0 {
                    // WHAT was found, not just how many. "5 candidates" cannot
                    // be checked against "the site I just opened offered
                    // nothing"; a list of names can.
                    tracing::info!(
                        target: "nrr::auto-rules",
                        msg_key = "autorules-tick-parked",
                        sid = %sid,
                        offered = %preview(&fresh),
                        "parked new suggestions",
                    );
                }
                summary.published = self.announce_pending(sid, now);
            }
        }
        summary
    }

    /// Announce everything still on offer for `sid` when any of it has not been
    /// announced yet.
    ///
    /// Runs on EVERY `suggest` tick, not only on the tick that parked something:
    /// an arrival that lands inside the quiet gap would otherwise wait for the
    /// next arrival to be mentioned, and there may not be one.
    pub(super) fn announce_pending(&self, sid: &str, now: SystemTime) -> bool {
        let offered = self.pending_snapshot(sid);
        if offered.is_empty() {
            return false;
        }
        // With the additional link down there is no half-loaded page to fix:
        // everything, routed or not, is already going out the main link and
        // working. Offering to "add these to the additional route" then states
        // a problem the user does not have. Learning continues — what is found
        // while the tunnel is off is offered once it comes back.
        if self
            .secondary_ready
            .as_ref()
            .is_some_and(|ready| !ready(sid))
        {
            tracing::debug!(
                target: "nrr::auto-rules",
                sid = %sid,
                pending = offered.len(),
                "suggestions held until the additional route is up",
            );
            return false;
        }
        // Only what the inbox lists by default (`shown_by_default`) is news: a
        // push for hidden rows opens a popup with nothing to show. The verdict
        // is recomputed every tick, so a later stall re-opens the question.
        // Value: the site refuses main-link addresses, which skips the wait
        // below — answering with a refusal is still answering.
        let listed: HashMap<String, bool> = self
            .candidates(sid)
            .into_iter()
            .filter(shown_by_default)
            .map(|dto| (dto.id, dto.anchor_refuses_main_link))
            .collect();
        let pass_can_answer = self
            .main_link_pass_enabled
            .as_ref()
            .map(|read| read(sid))
            .unwrap_or(false);
        let (worth_a_popup, settled): (Vec<PendingCandidate>, Vec<PendingCandidate>) = offered
            .into_iter()
            .partition(|c| match listed.get(&c.dto.id) {
                Some(&refuses) => refuses || !awaiting_the_main_link(&c.dto, pass_can_answer),
                None => false,
            });
        if !settled.is_empty() {
            tracing::debug!(
                target: "nrr::auto-rules",
                sid = %sid,
                held_back = settled.len(),
                sample = %preview(&settled),
                "suggestions kept out of the tray — the inbox does not list them by default, or the main-link pass has not answered for them yet",
            );
        }
        if worth_a_popup.is_empty() {
            return false;
        }
        // The count is what the inbox shows by default, not what popped.
        self.publish(sid, listed.len() as u64, &worth_a_popup, false, now)
    }

    fn pending_snapshot(&self, sid: &str) -> Vec<PendingCandidate> {
        let mut offers: Vec<PendingCandidate> = self
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .cloned()
            .unwrap_or_default();
        for offer in offers.iter_mut() {
            self.refresh_self_signed_behavior(&mut offer.dto);
        }
        offers
    }

    /// What the main link currently does with `hostname`. `Unknown` when no
    /// source is wired, which is how a self-signed offer behaved before one was.
    pub(super) fn main_link_behavior(&self, hostname: &str) -> PrimaryBehavior {
        self.primary_behavior_of
            .as_ref()
            .map_or(PrimaryBehavior::Unknown, |read| read(hostname))
    }

    /// Re-stamp a self-signed offer with the main link's CURRENT verdict.
    ///
    /// A companion offer is rebuilt from the ledger on every tick and so
    /// carries fresh evidence by construction. An offer a host made about
    /// itself is parked once and never recomputed, so without this it would
    /// keep asserting a failure that has since stopped happening.
    pub(super) fn refresh_self_signed_behavior(&self, dto: &mut AutoRuleCandidateDto) {
        // A program has no host verdict; its own measure withdraws the offer.
        if !is_self_signed_signal(&dto.signal) || is_app_offer(dto) {
            return;
        }
        let behavior = self.main_link_behavior(&dto.proposed_match);
        if behavior != PrimaryBehavior::Unknown {
            dto.primary_behavior = primary_behavior_slug(behavior).to_string();
        }
    }

    // ── IPC surface ──────────────────────────────────────────────────────────

    /// `autorules.candidates.list` — the suggestions waiting for `sid`.
    /// What the last tick dropped for this principal, for a screen that has to
    /// explain an empty list. Empty when the last tick had nothing to drop.
    pub fn quiet_note_for(&self, sid: &str) -> QuietNote {
        self.quiet_note
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .cloned()
            .unwrap_or_default()
    }
}
