//! What the user does with a suggestion: list, accept, dismiss, restore, forget.
//!
//! These are the only entry points that author a rule or retire a candidate,
//! so the suppression bookkeeping that keeps a dismissed suggestion from
//! coming straight back lives on this side of the engine.

use super::*;

impl AutoRulesEngine {
    pub fn candidates(&self, sid: &str) -> Vec<AutoRuleCandidateDto> {
        let refusing: Vec<String> = self
            .refusing_anchors
            .as_ref()
            .map(|read| read(sid))
            .unwrap_or_default();
        // An address the rules already cover has nothing left to approve, and
        // it gets covered in ways this engine never observes: a rule typed by
        // hand, a preset import, a revision another session activated, or the
        // user accepting the offer itself. `suppressed_ids` only closes the
        // same-session race — this is the check the read path was documented to
        // make and did not, which left an accepted suggestion standing forever.
        let snapshot = self.rules.active_rules_for(sid);
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .map(|v| {
                v.iter()
                    .filter(|c| !offer_covered(snapshot.as_ref(), &c.dto))
                    .filter_map(|c| {
                        let mut dto = c.dto.clone();
                        self.refresh_self_signed_behavior(&mut dto);
                        // A host that answers on the main link has nothing left
                        // to offer about itself — the inbox drops it outright
                        // rather than showing it greyed out, because unlike a
                        // companion there is no second question it could answer.
                        if settled_self_signed(&dto) {
                            return None;
                        }
                        // Neither link reaches it. The offer would move the
                        // host from one route that cannot carry it to another
                        // that cannot either — which is not a suggestion, it is
                        // somebody else's outage. Only a probe that RAN puts
                        // `Some(false)` here, so an unchecked offer is
                        // untouched by this.
                        if dto.secondary_reach == Some(false) && is_self_signed_signal(&dto.signal)
                        {
                            return None;
                        }
                        dto.anchor_refuses_main_link = refusing.contains(&dto.anchor);
                        // The same judgement the tray notice makes, carried to
                        // the inbox. Withholding an offer from one surface and
                        // presenting it as ordinary in the other is how a host
                        // the main route already serves read as "your site
                        // needs this".
                        dto.served_by_main_link = settled_by_the_main_link(&dto);
                        // Only an offer with a real anchor can answer this: a
                        // self-signed one IS its own anchor, so the comparison
                        // would say "the site's own name" about every host.
                        dto.third_party = (!is_self_signed_signal(&dto.signal))
                            .then(|| !shares_registrable_domain(&dto.anchor, &dto.proposed_match));
                        Some(dto)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Durable half of the read-path checks: drop offers with nothing left to
    /// ask, so they stop being counted (the tray badge reads `pending_count`)
    /// and do not come back after a restart. Runs on the tick, which owns a
    /// clock.
    ///
    /// Two ways an offer runs out of question: a rule now covers its address,
    /// or — for one a host made about itself — the main link started carrying
    /// the host. Both are withdrawals, not refusals: the evidence that earned
    /// the offer stopped being true.
    pub(super) fn retire_covered(&self, sid: &str, snapshot: &ActiveRulesSnapshot, now_ms: i64) {
        let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = guard.get_mut(sid) else {
            return;
        };
        let before = entry.len();
        let exclusions = RuleBookExclusions {
            book: &snapshot.rule_book,
        };
        let mut answered = 0_usize;
        entry.retain(|c| {
            let host = c.dto.proposed_match.as_str();
            if is_app_offer(&c.dto) {
                return !app_covered(&snapshot.rule_book, host);
            }
            if exclusions.is_rule_host(host) || exclusions.is_matched_by_existing_rule(host) {
                return false;
            }
            if is_self_signed_signal(&c.dto.signal)
                && self.main_link_behavior(host) == PrimaryBehavior::Responds
            {
                answered += 1;
                return false;
            }
            true
        });
        let retired = before - entry.len();
        let updated = (retired > 0).then(|| entry.clone());
        drop(guard);
        if let Some(updated) = updated {
            tracing::debug!(
                target: "nrr::auto-rules",
                sid = %sid,
                retired,
                answered_on_the_main_link = answered,
                "suggestions with nothing left to ask were withdrawn",
            );
            self.persist_pending(sid, &updated, now_ms);
        }
    }

    /// Does any parked suggestion for the ADDITIONAL route already cover
    /// `hostname`?
    ///
    /// Read by the DNS answer path, which must not steer such a host onto the
    /// primary link as if it were unrelated collateral — see
    /// [`crate::dns_resolver::CompanionCandidateLookup`]. Every principal is
    /// consulted: the answer path is one per service, and Free has a single
    /// routing-active user, so "any user suspects this host" is the useful
    /// question and the map holds a handful of entries.
    pub fn covers_pending_secondary_host(&self, hostname: &str) -> bool {
        let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return false;
        }
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .flatten()
            .filter(|c| c.dto.route == RouteRole::Secondary.slug())
            // A candidate the tray will not even ask about must not change
            // where traffic goes: leaving it "pinned as if accepted" routed a
            // host the user reaches perfectly well on the main link.
            .filter(|c| !settled_by_the_main_link(&c.dto))
            .any(|c| {
                let m = c.dto.proposed_match.trim_matches('.').to_ascii_lowercase();
                if m.is_empty() {
                    return false;
                }
                // Subdomains count for BOTH kinds, because that is what
                // accepting writes: `CanonicalRuleSet::with_subdomain_rules`
                // expands every exact rule into a suffix one, so an exact
                // suggestion for `cdninsta.test` would cover
                // `static.cdninsta.test` the moment it is accepted.
                // Reading it narrower here let the collateral rescue yank that
                // subdomain onto the primary while its parent was on offer.
                host == m || host.ends_with(&format!(".{m}"))
            })
    }

    /// `autorules.candidates.accept` — author the named suggestions into `sid`'s
    /// own rules with reason `user-confirmed`.
    ///
    /// Ids the pending set no longer holds are counted as `unknown` rather than
    /// failing the call: the set is in-memory and may have been recomputed
    /// between the list and the answer, and refusing the whole batch over one
    /// stale id would lose the user's decision about the others.
    pub fn accept(
        &self,
        sid: &str,
        ids: &[String],
        now: SystemTime,
    ) -> Result<ActionSummary, AuthorError> {
        let (selected, unknown) = self.take_selected(sid, ids, unix_ms(now));
        if selected.is_empty() {
            return Ok(ActionSummary {
                applied: 0,
                unknown,
                pending: self.pending_count(sid),
            });
        }
        let author = self.author.get().ok_or_else(|| {
            // Put the suggestions back — the user's answer was not applied, so
            // the offer must survive for them to answer it again.
            self.park(sid, selected.clone(), unix_ms(now));
            AuthorError {
                code: "authoring-unavailable".to_string(),
                message: "this service build cannot write rules".to_string(),
            }
        })?;
        let rules: Vec<AuthoredRule> = selected
            .iter()
            .map(PendingCandidate::authored_rule)
            .collect();
        let correlation = format!("auto-rules-accept-{}", unix_ms(now));
        match author.author(
            sid,
            &AutoRuleReason::UserConfirmed,
            &rules,
            now,
            &correlation,
        ) {
            Ok(_) => {
                self.remember_authored(sid, &selected);
                tracing::info!(
                    target: "nrr::auto-rules",
                    sid = %sid,
                    accepted = selected.len(),
                    anchor = %top_anchor(&selected),
                    "user accepted suggested addresses — added to their own rules",
                );
                Ok(ActionSummary {
                    applied: selected.len() as u32,
                    unknown,
                    pending: self.pending_count(sid),
                })
            }
            Err(e) => {
                // A refused write (rule cap, unacknowledged security alert, a
                // policy error) leaves the offer standing so the user can retry
                // once they have dealt with the cause.
                self.park(sid, selected, unix_ms(now));
                tracing::warn!(
                    target: "nrr::auto-rules",
                    sid = %sid,
                    code = %e.code,
                    "could not add the accepted addresses: {}",
                    e.message,
                );
                Err(e)
            }
        }
    }

    /// `autorules.candidates.dismiss` — refuse the named suggestions and
    /// remember the refusal across restarts.
    pub fn dismiss(&self, sid: &str, ids: &[String], now: SystemTime) -> ActionSummary {
        let (selected, unknown) = self.take_selected(sid, ids, unix_ms(now));
        if selected.is_empty() {
            return ActionSummary {
                applied: 0,
                unknown,
                pending: self.pending_count(sid),
            };
        }
        let records: Vec<AutoRuleDismissal> =
            selected.iter().map(PendingCandidate::dismissal).collect();
        self.dismissals.record(sid, &records, unix_ms(now));
        {
            let mut guard = self.dismissed.lock().unwrap_or_else(|p| p.into_inner());
            let entry = guard.entry(sid.to_string()).or_default();
            for c in &selected {
                entry.insert(c.dto.id.clone());
            }
        }
        tracing::info!(
            target: "nrr::auto-rules",
            sid = %sid,
            dismissed = selected.len(),
            anchor = %top_anchor(&selected),
            "user declined suggested addresses — they will not be offered again",
        );
        ActionSummary {
            applied: selected.len() as u32,
            unknown,
            pending: self.pending_count(sid),
        }
    }

    /// `autorules.dismissed.list` — refusals `sid` has recorded, most recent
    /// first, for a "review your declined suggestions" surface.
    pub fn list_dismissed(&self, sid: &str) -> Vec<AutoRuleDismissedEntryDto> {
        self.dismissals
            .list(sid)
            .into_iter()
            .map(|r| AutoRuleDismissedEntryDto {
                candidate_id: r.candidate_id,
                anchor: r.anchor,
                proposed_match: r.proposed_match,
                dismissed_at_unix_ms: r.dismissed_at,
            })
            .collect()
    }

    /// `autorules.dismissed.restore` — undoes refusals and puts the offers back
    /// on the list.
    ///
    /// Restoring used to lift the suppression and nothing else, leaving the
    /// host to re-earn its place from fresh observations. In practice the
    /// evidence had usually aged out of the ledger, so the row the user just
    /// asked for simply never came back. The refusal record now carries the
    /// offer itself, so it returns immediately; a refusal written before that
    /// column existed still only lifts the suppression.
    pub fn restore_dismissed(&self, sid: &str, ids: &[String], now: SystemTime) -> ActionSummary {
        let stored: HashMap<String, String> = self
            .dismissals
            .list(sid)
            .into_iter()
            .map(|r| (r.candidate_id, r.dto_json))
            .collect();
        let mut restored = 0_u32;
        let mut unknown = 0_u32;
        let mut back: Vec<PendingCandidate> = Vec::new();
        for id in ids {
            if !self.dismissals.forget(sid, id) {
                unknown += 1;
                continue;
            }
            restored += 1;
            if let Some(candidate) = stored
                .get(id)
                .filter(|json| !json.is_empty())
                .and_then(|json| serde_json::from_str::<AutoRuleCandidateDto>(json).ok())
                .and_then(PendingCandidate::from_dto)
            {
                back.push(candidate);
            }
        }
        {
            let mut guard = self.dismissed.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = guard.get_mut(sid) {
                for id in ids {
                    entry.remove(id);
                }
            }
        }
        // After the suppression is lifted, never before: `park` drops anything
        // still on the refused list.
        let re_offered = if back.is_empty() {
            0
        } else {
            self.park(sid, back, unix_ms(now)).0
        };
        if restored > 0 {
            tracing::info!(
                target: "nrr::auto-rules",
                sid = %sid,
                restored,
                re_offered,
                "user restored declined addresses — back on the list",
            );
        }
        ActionSummary {
            applied: restored,
            unknown,
            pending: self.pending_count(sid),
        }
    }

    /// `autorules.candidates.forget` — erases every trace of these suggestions
    /// for `sid`: the pending offer, the durable refusal, and the quiet period
    /// that follows authoring.
    ///
    /// Distinct from [`Self::restore_dismissed`], which lifts a refusal but
    /// leaves the rest of the service's memory of the answer intact. This is
    /// the "ask me again from scratch" answer, so the host returns the moment
    /// the observation feed earns it a second time.
    pub fn forget_candidates(&self, sid: &str, ids: &[String], now: SystemTime) -> ActionSummary {
        let wanted: HashSet<&str> = ids.iter().map(String::as_str).collect();
        let (dropped, remaining) = {
            let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            let entry = guard.entry(sid.to_string()).or_default();
            let before = entry.len();
            entry.retain(|c| !wanted.contains(c.dto.id.as_str()));
            let snapshot = entry.clone();
            (before - entry.len(), snapshot)
        };
        self.persist_pending(sid, &remaining, unix_ms(now));

        let mut forgotten = dropped as u32;
        for id in ids {
            if self.dismissals.forget(sid, id) {
                forgotten += 1;
            }
        }
        {
            let mut guard = self.dismissed.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = guard.get_mut(sid) {
                entry.retain(|id| !wanted.contains(id.as_str()));
            }
        }
        {
            let mut guard = self.authored.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = guard.get_mut(sid) {
                entry.retain(|id, _| !wanted.contains(id.as_str()));
            }
        }
        if forgotten > 0 {
            tracing::info!(
                target: "nrr::auto-rules",
                sid = %sid,
                forgotten,
                "user erased suggestions — they may be offered again from scratch",
            );
        }
        ActionSummary {
            applied: forgotten,
            unknown: (ids.len() as u32).saturating_sub(forgotten),
            pending: self.pending_count(sid),
        }
    }

    // ── Internals ────────────────────────────────────────────────────────────
}
