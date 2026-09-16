//! Per-principal bookkeeping: settings memos, parking, persistence, expiry.
//!
//! The methods are `pub(super)` rather than private because the split above
//! put their callers in sibling modules; nothing here is part of the engine's
//! public surface.

use super::*;

impl AutoRulesEngine {
    /// `sid`'s companion-discovery settings, memoised for [`MODE_MEMO_TTL`].
    pub(super) fn settings(&self, sid: &str) -> PrincipalSettings {
        let mut memo = self.settings_memo.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((settings, at)) = memo.get(sid) {
            if at.elapsed() < MODE_MEMO_TTL {
                return *settings;
            }
        }
        let settings = PrincipalSettings {
            mode: (self.mode_for)(sid),
            eager_delivery_names: self
                .eager_delivery_for
                .as_ref()
                .is_some_and(|read| read(sid)),
        };
        memo.insert(sid.to_string(), (settings, Instant::now()));
        settings
    }

    pub(super) fn mode(&self, sid: &str) -> AutoRulesMode {
        self.settings(sid).mode
    }

    /// Forces the next settings read to hit the source. Production refreshes on
    /// the [`MODE_MEMO_TTL`] timer; a test cannot wait for it.
    #[cfg(test)]
    pub(super) fn expire_settings_memo(&self) {
        self.settings_memo
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    /// Ages every authored-suppression entry past its window. A test cannot wait
    /// out [`AUTHORED_SUPPRESSION`].
    #[cfg(test)]
    pub(super) fn expire_authored_suppression(&self) {
        let stale = Instant::now() - AUTHORED_SUPPRESSION - Duration::from_secs(1);
        for entry in self
            .authored
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values_mut()
        {
            for at in entry.values_mut() {
                *at = stale;
            }
        }
    }

    /// Drops every trace of a principal that turned collection off.
    pub(super) fn forget(&self, sid: &str) {
        self.ledgers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
        self.pending_store.clear(sid);
        if let Some(store) = self.evidence_store.as_ref() {
            store.clear(sid);
        }
        self.evidence_saved_at
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
    }

    pub(super) fn pending_count(&self, sid: &str) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .map_or(0, Vec::len)
    }

    /// Ids that must not be offered: refused earlier (durable) or authored this
    /// session (the rule exists; the exclusions will catch it on the next read,
    /// this closes the race until then).
    pub(super) fn suppressed_ids(&self, sid: &str) -> HashSet<String> {
        let mut out = {
            let mut guard = self.dismissed.lock().unwrap_or_else(|p| p.into_inner());
            guard
                .entry(sid.to_string())
                .or_insert_with(|| self.dismissals.load(sid))
                .clone()
        };
        let mut guard = self.authored.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(authored) = guard.get_mut(sid) {
            authored.retain(|_, at| at.elapsed() < AUTHORED_SUPPRESSION);
            out.extend(authored.keys().cloned());
        }
        out
    }

    pub(super) fn remember_authored(&self, sid: &str, candidates: &[PendingCandidate]) {
        let mut guard = self.authored.lock().unwrap_or_else(|p| p.into_inner());
        let entry = guard.entry(sid.to_string()).or_default();
        let now = Instant::now();
        for c in candidates {
            entry.insert(c.dto.id.clone(), now);
        }
    }

    /// Merges `fresh` into the pending set, returning `(newly added, total)`.
    ///
    /// Strongest first, so a consumer showing only the top of the list shows the
    /// most defensible offers.
    pub(super) fn park(
        &self,
        sid: &str,
        fresh: Vec<PendingCandidate>,
        now_ms: i64,
    ) -> (u32, usize) {
        let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let entry = guard.entry(sid.to_string()).or_default();
        let mut added = 0_u32;
        for mut candidate in fresh {
            match entry.iter_mut().find(|c| c.dto.id == candidate.dto.id) {
                // Refresh the evidence on an offer already standing — the user
                // sees current numbers whenever they get round to answering.
                // The "new basis" clock only advances when a consumer this
                // offer didn't have before shows up; unchanged evidence keeps
                // its date, which is what lets the tray sort by what's new.
                Some(existing) => {
                    let known: HashSet<&str> = existing
                        .dto
                        .consumers
                        .iter()
                        .map(|c| c.hostname.as_str())
                        .collect();
                    let gained_consumer = candidate
                        .dto
                        .consumers
                        .iter()
                        .any(|c| !known.contains(c.hostname.as_str()));
                    candidate.dto.consumers_changed_unix_ms = if gained_consumer {
                        now_ms
                    } else {
                        existing.dto.consumers_changed_unix_ms
                    };
                    *existing = candidate;
                }
                None => {
                    // A `0` sentinel means this offer was never parked before
                    // (fresh out of `to_candidate`); a nonzero value means it is
                    // being restored after a failed accept/author, and its own
                    // "first appeared" date must survive the round trip.
                    if candidate.dto.consumers_changed_unix_ms == 0 {
                        candidate.dto.consumers_changed_unix_ms = now_ms;
                    }
                    entry.push(candidate);
                    added = added.saturating_add(1);
                }
            }
        }
        sort_and_cap(entry, sid);
        added = added.min(entry.len() as u32);
        let total = entry.len();
        let snapshot = entry.clone();
        drop(guard);
        self.persist_pending(sid, &snapshot, now_ms);
        (added, total)
    }

    /// Writes `sid`'s pending set through to the durable store, so the table
    /// mirrors memory after every change. An empty set clears the row instead
    /// of writing nothing, so a cleared-out queue does not leave a stale row.
    pub(super) fn persist_pending(&self, sid: &str, candidates: &[PendingCandidate], now_ms: i64) {
        if candidates.is_empty() {
            self.pending_store.clear(sid);
            return;
        }
        let records: Vec<AutoRulePendingRecord> = candidates
            .iter()
            .filter_map(|c| match serde_json::to_string(&c.dto) {
                Ok(dto_json) => Some(AutoRulePendingRecord {
                    candidate_id: c.dto.id.clone(),
                    route: c.dto.route.clone(),
                    match_kind: c.dto.match_kind.clone(),
                    dto_json,
                    parked_at: now_ms,
                }),
                Err(e) => {
                    tracing::warn!(
                        target: "nrr::auto-rules",
                        sid = %sid,
                        error = %e,
                        "could not serialize a pending suggestion — it will not survive a restart",
                    );
                    None
                }
            })
            .collect();
        self.pending_store.replace(sid, &records);
    }

    /// Forgets offers whose evidence has gone stale. An unanswered suggestion is
    /// not a debt: if the site still needs the address, the next visit re-earns
    /// it, and if it does not, the offer was noise.
    pub(super) fn expire_pending(&self, sid: &str, now_ms: i64) {
        let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = guard.get_mut(sid) else {
            return;
        };
        let before = entry.len();
        entry.retain(|c| {
            let ttl = if is_self_signed_signal(&c.dto.signal) {
                SELF_SIGNED_PENDING_TTL_MS
            } else {
                PENDING_TTL_MS
            };
            now_ms.saturating_sub(c.dto.last_seen_unix_ms) <= ttl
        });
        let expired = before - entry.len();
        let snapshot = (expired > 0).then(|| entry.clone());
        drop(guard);
        if expired > 0 {
            tracing::debug!(
                target: "nrr::auto-rules",
                sid = %sid,
                expired,
                "dropped suggestions nobody answered and nothing refreshed",
            );
        }
        if let Some(snapshot) = snapshot {
            self.persist_pending(sid, &snapshot, now_ms);
        }
    }

    /// Removes the named candidates from the pending set, returning them
    /// alongside the count of ids that were not there.
    pub(super) fn take_selected(
        &self,
        sid: &str,
        ids: &[String],
        now_ms: i64,
    ) -> (Vec<PendingCandidate>, u32) {
        let wanted: HashSet<&str> = ids.iter().map(String::as_str).collect();
        let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = guard.get_mut(sid) else {
            return (Vec::new(), ids.len() as u32);
        };
        let mut selected = Vec::new();
        entry.retain(|c| {
            if wanted.contains(c.dto.id.as_str()) {
                selected.push(c.clone());
                false
            } else {
                true
            }
        });
        let unknown = (ids.len().saturating_sub(selected.len())) as u32;
        let snapshot = (!selected.is_empty()).then(|| entry.clone());
        drop(guard);
        if let Some(snapshot) = snapshot {
            self.persist_pending(sid, &snapshot, now_ms);
        }
        (selected, unknown)
    }

    /// `auto` mode: write the rules without asking. Returns how many landed.
    pub(super) fn author_now(&self, sid: &str, fresh: &[PendingCandidate], now: SystemTime) -> u32 {
        let Some(author) = self.author.get() else {
            // No author wired: park rather than discard the finding, so wiring
            // authoring later does not start from zero. Nothing was authored.
            self.park(sid, fresh.to_vec(), unix_ms(now));
            return 0;
        };
        let rules: Vec<AuthoredRule> = fresh.iter().map(PendingCandidate::authored_rule).collect();
        let correlation = format!("auto-rules-auto-{}", unix_ms(now));
        match author.author(
            sid,
            &AutoRuleReason::SiteCompanion,
            &rules,
            now,
            &correlation,
        ) {
            Ok(count) => {
                self.remember_authored(sid, fresh);
                if count > 0 {
                    tracing::info!(
                        target: "nrr::auto-rules",
                        sid = %sid,
                        added = count,
                        anchor = %top_anchor(fresh),
                        "added addresses a routed site needs to the user's own rules (auto mode)",
                    );
                }
                count
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::auto-rules",
                    sid = %sid,
                    code = %e.code,
                    anchor = %top_anchor(fresh),
                    "could not add discovered addresses automatically: {}",
                    e.message,
                );
                0
            }
        }
    }

    /// Emits `AutoRuleCandidatesChanged` unless the debounce says otherwise.
    /// `force` bypasses the growth check for the informational `auto`-mode
    /// event, which reports work already done rather than an offer.
    pub(super) fn publish(
        &self,
        sid: &str,
        pending: u64,
        offered: &[PendingCandidate],
        force: bool,
        now: SystemTime,
    ) -> bool {
        let Some(bus) = self.events.as_ref() else {
            return false;
        };
        // A subscription starts at the bus's current head, so a push sent
        // before the tray connected reaches nobody — while the record below
        // would mark the offer announced for good. The service and the tray
        // start together, and the service wins that race routinely.
        // Announcing means having had an audience.
        if !bus.has_subscriber_for(sid) {
            tracing::debug!(
                target: "nrr::auto-rules",
                sid = %sid,
                offered = offered.len(),
                "nothing is listening yet — the offer keeps its news for the next tick",
            );
            return false;
        }
        let mut states = self.publish_state.lock().unwrap_or_else(|p| p.into_inner());
        let state = states.entry(sid.to_string()).or_default();
        let unseen: Vec<&PendingCandidate> = offered
            .iter()
            .filter(|c| !state.announced.contains(&c.dto.id))
            .collect();
        if !force && unseen.is_empty() {
            return false;
        }
        // A clock that went backwards reads as "ready" rather than muting the
        // tray until wall time catches up.
        let quiet_enough = state.announced_at.is_none_or(|at| {
            now.duration_since(at)
                .map_or(true, |since| since >= PUBLISH_MIN_INTERVAL)
        });
        if !quiet_enough {
            return false;
        }
        // Name the site whose suggestions the user has not seen yet.
        let anchor_source: Vec<PendingCandidate> = if unseen.is_empty() {
            offered.to_vec()
        } else {
            unseen.into_iter().cloned().collect()
        };
        // Forget ids no longer on offer (accepted, dismissed, evicted) so the
        // set tracks the live offer instead of growing all session.
        let live: HashSet<&str> = offered.iter().map(|c| c.dto.id.as_str()).collect();
        state.announced.retain(|id| live.contains(id.as_str()));
        state
            .announced
            .extend(offered.iter().map(|c| c.dto.id.clone()));
        state.announced_at = Some(now);
        drop(states);
        bus.publish_for(
            sid,
            StatusUpdateEvent::AutoRuleCandidatesChanged {
                sid: sid.to_string(),
                pending_count: pending,
                top_anchor: top_anchor(&anchor_source),
            },
        );
        true
    }
}
