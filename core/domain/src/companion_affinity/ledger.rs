//! The co-activity ledger's behaviour. The type itself stays in the parent so
//! its private fields remain visible to this module.

use super::*;

impl CompanionAffinityLedger {
    /// Creates a ledger with the given configuration.
    pub fn new(config: CompanionAffinityConfig) -> Self {
        Self {
            config,
            anchors: HashMap::new(),
            candidates: HashMap::new(),
            next_anchor_id: 0,
            next_window_id: 0,
            last_document: None,
            unattributed: VecDeque::new(),
        }
    }

    /// Creates a ledger with the documented default configuration.
    pub fn with_defaults() -> Self {
        Self::new(CompanionAffinityConfig::default())
    }

    /// Everything learned so far, as plain data the caller can persist.
    #[must_use]
    pub fn snapshot(&self) -> CompanionEvidenceSnapshot {
        let mut anchors: Vec<AnchorSnapshot> = self
            .anchors
            .iter()
            .map(|(hostname, state)| AnchorSnapshot {
                hostname: hostname.clone(),
                id: state.id,
                route: state.route,
                window_id: state.window_id,
                window_start_ms: state.window_start_ms,
                window_end_ms: state.window_end_ms,
                last_seen_ms: state.last_seen_ms,
            })
            .collect();
        // Deterministic order so a saved snapshot compares byte-for-byte with
        // itself and a diff of two saves reads.
        anchors.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        let mut candidates: Vec<CandidateSnapshot> = self
            .candidates
            .iter()
            .map(|(hostname, state)| CandidateSnapshot {
                hostname: hostname.clone(),
                first_seen_ms: state.first_seen_ms,
                last_seen_ms: state.last_seen_ms,
                total_windows: state.total_windows,
                total_hits: state.total_hits,
                seen_in_use: state.seen_in_use,
                primary_stalls: state.primary_stalls,
                primary_completions: state.primary_completions,
                pairs: {
                    // By anchor id, because the pairs were APPENDED in the
                    // order a `HashMap` happened to iterate its anchors — which
                    // differs per process. Sorting the outer lists and leaving
                    // this one made the claim above true for two saves in one
                    // run and false across a restart.
                    let mut pairs: Vec<PairSnapshot> = state
                        .pairs
                        .iter()
                        .map(|p| PairSnapshot {
                            anchor_id: p.anchor_id,
                            distinct_windows: p.distinct_windows,
                            last_window_id: p.last_window_id,
                            nearest_hits: p.nearest_hits,
                            uncontested_hits: p.uncontested_hits,
                            foreign_parent_hits: p.foreign_parent_hits,
                        })
                        .collect();
                    pairs.sort_by_key(|p| p.anchor_id);
                    pairs
                },
            })
            .collect();
        candidates.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        CompanionEvidenceSnapshot {
            anchors,
            candidates,
            next_anchor_id: self.next_anchor_id,
            next_window_id: self.next_window_id,
        }
    }

    /// A ledger holding previously saved evidence. `config` comes from this
    /// build and the user's current settings, never from the snapshot — a
    /// threshold the user changed must apply to evidence gathered before it.
    /// Over-cap input is truncated to the configured caps (least recently seen
    /// dropped first), so a snapshot written by a build with roomier caps
    /// cannot push this one past its own bounds.
    #[must_use]
    pub fn restored(config: CompanionAffinityConfig, snapshot: CompanionEvidenceSnapshot) -> Self {
        let mut ledger = Self::new(config);
        let mut anchors = snapshot.anchors;
        anchors.sort_by(|a, b| b.last_seen_ms.cmp(&a.last_seen_ms));
        anchors.truncate(ledger.config.max_anchors);
        let mut candidates = snapshot.candidates;
        candidates.sort_by(|a, b| b.last_seen_ms.cmp(&a.last_seen_ms));
        candidates.truncate(ledger.config.max_candidates);

        let live_ids: std::collections::HashSet<u32> = anchors.iter().map(|a| a.id).collect();
        for a in anchors {
            ledger.anchors.insert(
                a.hostname,
                AnchorState {
                    id: a.id,
                    route: a.route,
                    window_id: a.window_id,
                    window_start_ms: a.window_start_ms,
                    window_end_ms: a.window_end_ms,
                    last_seen_ms: a.last_seen_ms,
                },
            );
        }
        for c in candidates {
            ledger.candidates.insert(
                c.hostname,
                CandidateState {
                    first_seen_ms: c.first_seen_ms,
                    last_seen_ms: c.last_seen_ms,
                    total_windows: c.total_windows,
                    total_hits: c.total_hits,
                    seen_in_use: c.seen_in_use,
                    primary_stalls: c.primary_stalls,
                    primary_completions: c.primary_completions,
                    // Pairs of anchors that did not survive the truncation are
                    // dropped exactly as an eviction would have dropped them;
                    // the historical totals stay, so affinity is only ever
                    // underestimated.
                    pairs: c
                        .pairs
                        .into_iter()
                        .filter(|p| live_ids.contains(&p.anchor_id))
                        .map(|p| PairStats {
                            anchor_id: p.anchor_id,
                            distinct_windows: p.distinct_windows,
                            last_window_id: p.last_window_id,
                            nearest_hits: p.nearest_hits,
                            uncontested_hits: p.uncontested_hits,
                            foreign_parent_hits: p.foreign_parent_hits,
                        })
                        .collect(),
                },
            );
        }
        // Ids must never be reissued: a restored anchor keeps its id, so the
        // next one has to start past every id in the snapshot.
        //
        // Saturating, because these arrive from a file. `id + 1` over a value
        // this process did not produce panics in a debug build and wraps in a
        // release one — and a wrapped counter reissues ids, which hands a new
        // anchor somebody else's pairs. Saturation cannot be reached by the
        // live path (`u32::MAX` anchors in one session), so it only ever means
        // "the file said something impossible".
        ledger.next_anchor_id = snapshot.next_anchor_id.max(
            ledger
                .anchors
                .values()
                .map(|a| a.id.saturating_add(1))
                .max()
                .unwrap_or(0),
        );
        ledger.next_window_id = snapshot.next_window_id.max(
            ledger
                .anchors
                .values()
                .map(|a| a.window_id.saturating_add(1))
                .max()
                .unwrap_or(0),
        );
        ledger
    }

    /// Number of currently tracked anchors (diagnostics/tests).
    pub fn anchor_count(&self) -> usize {
        self.anchors.len()
    }

    /// Number of currently tracked candidates (diagnostics/tests).
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// `true` when the hostname is currently tracked as a candidate.
    pub fn is_tracking_candidate(&self, hostname: &str) -> bool {
        self.candidates.contains_key(hostname)
    }

    /// Records one observation. Cheap and never panics: bounded by the anchor
    /// cap per call, allocation only when a new hostname enters the tracked
    /// set. `at_ms` is caller-supplied monotonic-ish milliseconds; an
    /// out-of-order timestamp is tolerated (windows never shrink, `last_seen`
    /// never moves backwards).
    pub fn observe(&mut self, at_ms: u64, hostname: &str, kind: CoActivityKind) {
        match kind {
            CoActivityKind::Anchor { route } => self.observe_anchor(at_ms, hostname, route),
            CoActivityKind::Candidate => {
                self.observe_candidate(at_ms, hostname, false, Sighting::Live)
            }
            CoActivityKind::CandidateInUse => {
                self.observe_candidate(at_ms, hostname, true, Sighting::Live)
            }
            CoActivityKind::PrimaryHealth(event) => self.note_primary_health(hostname, event),
        }
        // After attribution, never before: a page-shaped host is the parent of
        // what follows it, not of itself.
        if matches!(
            kind,
            CoActivityKind::Anchor { .. }
                | CoActivityKind::Candidate
                | CoActivityKind::CandidateInUse
        ) && is_document_shaped(hostname)
        {
            let newer = self
                .last_document
                .as_ref()
                .is_none_or(|(_, seen_at)| at_ms >= *seen_at);
            if newer {
                self.last_document = Some((hostname.to_string(), at_ms));
            }
        }
    }

    /// Whether the page loading right now says this fetch belonged to somebody
    /// other than `anchor_hostname`.
    ///
    /// Two guards keep this from suppressing honest evidence:
    ///
    /// - **Stale context does not count.** A page seen longer than one window
    ///   ago has no claim on what is being fetched now.
    /// - **A page of the candidate's OWN site only speaks when the candidate is
    ///   a delivery endpoint.** Our data cannot tell a navigation from an XHR to
    ///   an apex, so an anchor's page calling `partner.test` and then
    ///   `one.partner.test` must keep its attribution. A delivery name is
    ///   different: `cdninsta.test` seen while `insta.example` is loading is
    ///   serving Instagram, whichever rule host happens to be open.
    fn document_disowns(&self, at_ms: u64, anchor_hostname: &str, candidate: &str) -> bool {
        let Some((document, seen_at)) = self.last_document.as_ref() else {
            return false;
        };
        if at_ms.saturating_sub(*seen_at) > self.config.window_ms {
            return false;
        }
        if same_site(document, anchor_hostname) {
            return false;
        }
        !same_site(document, candidate) || is_delivery_named(candidate)
    }

    /// Counts one primary-route outcome against an already-tracked candidate.
    /// Untracked hostnames are ignored outright — health is not a reason to
    /// start tracking, and `last_seen_ms` deliberately does not move: a resend
    /// is not a fresh sighting and must not postpone TTL eviction.
    fn note_primary_health(&mut self, hostname: &str, event: PrimaryHealthEvent) {
        let Some(candidate) = self.candidates.get_mut(hostname) else {
            return;
        };
        match event {
            PrimaryHealthEvent::Stalled => {
                candidate.primary_stalls = candidate.primary_stalls.saturating_add(1);
            }
            PrimaryHealthEvent::Completed => {
                candidate.primary_completions = candidate.primary_completions.saturating_add(1);
            }
        }
    }

    fn observe_anchor(&mut self, at_ms: u64, hostname: &str, route: RouteRole) {
        if self.config.max_anchors == 0 {
            return;
        }
        // A hostname promoted to rule host stops being a candidate; its
        // accumulated candidate evidence is discarded.
        self.candidates.remove(hostname);

        let window_ms = self.config.window_ms.min(self.config.max_window_ms);
        // A sighting that predates the window it would join means the clock
        // moved, not that time ran backwards. Everything the ledger holds is
        // stamped in wall-clock milliseconds, so an NTP correction, a resumed
        // virtual machine, or a service that started before the clock was set
        // leaves state dated in a future that has not happened — and the state
        // is persisted, so a restart inherits it.
        //
        // Left alone it is permanent: the attribution filters require
        // `at_ms >= window_start_ms`, so the anchor attributes NOTHING; the
        // "same window" test (`at_ms <= window_end_ms`) keeps extending that
        // window instead of opening a new one; and `last_seen_ms` never moves
        // down, so LRU eviction never picks the poisoned entry either.
        if self
            .anchors
            .get(hostname)
            .is_some_and(|a| at_ms < a.window_start_ms)
        {
            self.rebase_after_clock_step(at_ms);
        }
        if let Some(anchor) = self.anchors.get_mut(hostname) {
            anchor.route = route;
            anchor.last_seen_ms = anchor.last_seen_ms.max(at_ms);
            if at_ms <= anchor.window_end_ms {
                // Same window: extend the idle deadline, but never past the
                // hard cap measured from the window's opening.
                let hard_cap = anchor
                    .window_start_ms
                    .saturating_add(self.config.max_window_ms);
                anchor.window_end_ms = anchor
                    .window_end_ms
                    .max(at_ms.saturating_add(window_ms))
                    .min(hard_cap);
            } else {
                // Previous window closed (idle gap or hard cap): open a new one.
                anchor.window_id = self.next_window_id;
                self.next_window_id = self.next_window_id.saturating_add(1);
                anchor.window_start_ms = at_ms;
                anchor.window_end_ms = at_ms.saturating_add(window_ms);
                self.replay_unattributed(at_ms);
            }
            return;
        }

        if self.anchors.len() >= self.config.max_anchors {
            self.evict_least_recent_anchor();
        }
        let id = self.next_anchor_id;
        self.next_anchor_id = self.next_anchor_id.saturating_add(1);
        let window_id = self.next_window_id;
        self.next_window_id = self.next_window_id.saturating_add(1);
        self.anchors.insert(
            hostname.to_string(),
            AnchorState {
                id,
                route,
                window_id,
                window_start_ms: at_ms,
                window_end_ms: at_ms.saturating_add(window_ms),
                last_seen_ms: at_ms,
            },
        );
        self.replay_unattributed(at_ms);
    }

    /// Remember a companion sighting that had no window to belong to. Bounded
    /// by the look-back itself: anything older than one look-back can never be
    /// claimed, so it is dropped as new sightings arrive.
    fn park_unattributed(&mut self, at_ms: u64, hostname: &str, in_use: bool) {
        if self.config.retro_window_ms == 0 {
            return;
        }
        let cutoff = at_ms.saturating_sub(self.config.retro_window_ms);
        while self
            .unattributed
            .front()
            .is_some_and(|(_, seen_at, _)| *seen_at < cutoff)
        {
            self.unattributed.pop_front();
        }
        // One sighting per host in the buffer: a page firing fifty requests
        // must not push everything else out before a window opens.
        //
        // Re-seated at the back rather than refreshed in place. Both users of
        // this buffer assume it is ordered by sighting time: the prefix
        // clean-up above stops at the first entry that is still young, and the
        // overflow drop below takes the front. An entry refreshed where it sat
        // put a young timestamp in front of old ones — the clean-up then stopped
        // immediately and left expired entries behind it, while the overflow
        // dropped the very entry that had just been refreshed.
        let seen_before = self
            .unattributed
            .iter()
            .position(|(name, _, _)| name == hostname);
        let in_use = match seen_before.and_then(|at| self.unattributed.remove(at)) {
            Some((_, _, was_in_use)) => in_use || was_in_use,
            None => in_use,
        };
        if self.unattributed.len() >= MAX_UNATTRIBUTED {
            self.unattributed.pop_front();
        }
        self.unattributed
            .push_back((hostname.to_string(), at_ms, in_use));
    }

    /// A window just opened at `at_ms`: replay the companions seen in the
    /// look-back before it. Each replayed sighting leaves the buffer — from
    /// here on it is a tracked candidate and its later sightings arrive
    /// through the ordinary path.
    fn replay_unattributed(&mut self, at_ms: u64) {
        if self.config.retro_window_ms == 0 || self.unattributed.is_empty() {
            return;
        }
        let cutoff = at_ms.saturating_sub(self.config.retro_window_ms);
        let mut claimed: Vec<(String, u64, bool)> = Vec::new();
        let mut kept: VecDeque<(String, u64, bool)> = VecDeque::new();
        for entry in std::mem::take(&mut self.unattributed) {
            if entry.1 >= cutoff && entry.1 <= at_ms {
                claimed.push(entry);
            } else if entry.1 > at_ms {
                kept.push_back(entry);
            }
        }
        self.unattributed = kept;
        // Only companions the ledger does not know yet. The look-back exists to
        // let a first sighting count, not to top up statistics that already
        // exist: replaying into a tracked candidate moves its attribution and
        // shifts which anchor owns it (measured on the formula-study trace — a
        // real CDN lost its offer that way).
        //
        // Attributed AT the window's start, not at the sighting's own earlier
        // timestamp: it belongs to this window, and dating it before the
        // window would put it straight back outside.
        for (hostname, _, in_use) in claimed {
            if self.candidates.contains_key(&hostname) {
                continue;
            }
            // Only a sighting that CARRIED TRAFFIC is replayed. The look-back
            // exists because the browser often opens the companion's connection
            // before the page's own, and a name resolved before the window with
            // nothing following it is the other thing that looks like that: a
            // page's prefetch of links nobody clicked. Counting those signed
            // offers for hosts the user had never opened. A prefetched name the
            // user does go to is seen again inside the window, through the
            // ordinary path.
            if self.config.lookback_requires_traffic && !in_use {
                continue;
            }
            self.observe_candidate(at_ms, &hostname, in_use, Sighting::ReplayedIntoWindow);
        }
    }

    fn observe_candidate(&mut self, at_ms: u64, hostname: &str, in_use: bool, sighting: Sighting) {
        if self.config.max_candidates == 0 {
            return;
        }
        // An anchor is never its own companion; the caller normally marks
        // rule hosts as anchors, this is a cheap defensive backstop. An anchor
        // whose RULE is gone is retired by `retain_anchors`, not from here: a
        // single observation is too weak a basis for retiring one.
        if self.anchors.contains_key(hostname) {
            return;
        }
        // Dropped at the door rather than at proposal time: a per-machine name
        // is evidence of nothing, and letting a CDN's node names in would
        // evict real candidates from the tracked set.
        if names_one_machine(hostname) {
            return;
        }
        // Same door for a name that can never be written as a rule — resolver
        // artifacts with empty labels ("..localmachine") or illegal characters.
        // Each one squats a slot in the bounded candidate set until eviction.
        if !crate::rule_value_validation::is_valid_hostname(hostname) {
            return;
        }
        // A candidate seen outside every anchor window carries no signal;
        // not tracking it keeps memory tied to co-activity, not to traffic.
        //
        // "Outside" is not the same as "worthless", though: the browser opens
        // the CDN connection before the one to the page as often as after it.
        // Park the sighting so the window about to open can claim it, and let
        // the look-back decide.
        if !self
            .anchors
            .values()
            .any(|a| at_ms <= a.window_end_ms && at_ms >= a.window_start_ms)
        {
            self.park_unattributed(at_ms, hostname, in_use);
            return;
        }

        if !self.candidates.contains_key(hostname) {
            if self.candidates.len() >= self.config.max_candidates {
                self.evict_least_recent_candidate();
            }
            self.candidates.insert(
                hostname.to_string(),
                CandidateState {
                    first_seen_ms: at_ms,
                    last_seen_ms: at_ms,
                    total_windows: 0,
                    total_hits: 0,
                    seen_in_use: false,
                    primary_stalls: 0,
                    primary_completions: 0,
                    pairs: Vec::new(),
                },
            );
        }

        // The anchor that was active most recently owns this observation;
        // hostname order breaks ties so the attribution is deterministic.
        let nearest = self
            .anchors
            .iter()
            .filter(|(_, a)| at_ms <= a.window_end_ms && at_ms >= a.window_start_ms)
            .max_by(|(name_a, a), (name_b, b)| {
                a.last_seen_ms
                    .cmp(&b.last_seen_ms)
                    .then_with(|| name_a.cmp(name_b))
            })
            .map(|(_, a)| a);
        let nearest_anchor_id = nearest.map(|a| a.id);
        // Whether that lead is worth anything. A rival sighted within the tie
        // margin means the winner was picked by DNS timing, not by the user.
        let uncontested = nearest.is_some_and(|winner| {
            !self.anchors.values().any(|a| {
                a.id != winner.id
                    && at_ms <= a.window_end_ms
                    && at_ms >= a.window_start_ms
                    && a.last_seen_ms
                        .saturating_add(self.config.attribution_tie_ms)
                        >= winner.last_seen_ms
            })
        });

        // Whose page each attributed hit really belonged to. Computed before the
        // split borrow (it reads `last_document`), and only for endpoint-shaped
        // names.
        //
        // A page-shaped candidate is exempt because the document heuristic
        // cannot tell what it would have to tell here: `last_document` is
        // whatever page-shaped name was seen last, so three bare apexes fetched
        // by ONE page load make each the parent of the next, and two of the
        // three lose their attribution. Judging a page by its predecessor is
        // right only when the predecessor is a page — and nothing in this data
        // separates a navigation from a sibling sub-resource that happens to be
        // an apex. Reach is limited at the proposal instead: co-activity alone
        // never generalizes a suffix.
        //
        // A replayed sighting is exempt: the look-back runs from INSIDE
        // `observe_anchor`, while `last_document` is only updated at the end of
        // `observe`, so the page it names is the PREVIOUS one. Judged by it,
        // every sighting the look-back raises reads as somebody else's — one
        // foreign hit against one near hit already trips `mostly_someone_elses`
        // and drops the pair. The look-back and the parent test arrived
        // together and cancelled each other out.
        let foreign_parent: Vec<(u32, bool)> =
            if is_document_shaped(hostname) || sighting == Sighting::ReplayedIntoWindow {
                Vec::new()
            } else {
                self.anchors
                    .iter()
                    .filter(|(_, a)| at_ms <= a.window_end_ms && at_ms >= a.window_start_ms)
                    .map(|(anchor_hostname, a)| {
                        (
                            a.id,
                            self.document_disowns(at_ms, anchor_hostname, hostname),
                        )
                    })
                    .collect()
            };

        // Split borrow: anchors read-only, one candidate mutated.
        let anchors = &self.anchors;
        let Some(candidate) = self.candidates.get_mut(hostname) else {
            return;
        };
        candidate.last_seen_ms = candidate.last_seen_ms.max(at_ms);
        candidate.total_hits = candidate.total_hits.saturating_add(1);
        candidate.seen_in_use |= in_use;
        for anchor in anchors
            .values()
            .filter(|a| at_ms <= a.window_end_ms && at_ms >= a.window_start_ms)
        {
            let is_nearest = nearest_anchor_id == Some(anchor.id);
            match candidate
                .pairs
                .iter_mut()
                .find(|p| p.anchor_id == anchor.id)
            {
                Some(pair) => {
                    if is_nearest {
                        pair.nearest_hits = pair.nearest_hits.saturating_add(1);
                        if uncontested {
                            pair.uncontested_hits = pair.uncontested_hits.saturating_add(1);
                        }
                        if foreign_parent
                            .iter()
                            .any(|(id, foreign)| *id == anchor.id && *foreign)
                        {
                            pair.foreign_parent_hits = pair.foreign_parent_hits.saturating_add(1);
                        }
                    }
                    // Count each window at most once regardless of hit volume.
                    if pair.last_window_id != anchor.window_id {
                        pair.last_window_id = anchor.window_id;
                        pair.distinct_windows = pair.distinct_windows.saturating_add(1);
                        candidate.total_windows = candidate.total_windows.saturating_add(1);
                    }
                }
                None => {
                    let foreign = foreign_parent
                        .iter()
                        .any(|(id, foreign)| *id == anchor.id && *foreign);
                    candidate.pairs.push(PairStats {
                        anchor_id: anchor.id,
                        distinct_windows: 1,
                        last_window_id: anchor.window_id,
                        nearest_hits: u32::from(is_nearest),
                        uncontested_hits: u32::from(is_nearest && uncontested),
                        foreign_parent_hits: u32::from(is_nearest && foreign),
                    });
                    candidate.total_windows = candidate.total_windows.saturating_add(1);
                }
            }
        }
    }

    /// Evicts the least recently seen anchor (ties broken by hostname order
    /// for determinism) and sweeps its pair statistics out of every candidate.
    /// The sweep keeps candidate memory bounded by the LIVE anchor set;
    /// candidate `total_windows` deliberately keeps the historical
    /// contribution (see [`CandidateState::total_windows`]). Never panics —
    /// on an empty map it is a no-op.
    /// Retire every anchor the predicate no longer recognises as a rule host,
    /// and with it the evidence gathered underneath — that evidence said
    /// "companion of a ROUTED site", and the site is not routed any more.
    ///
    /// Why this exists: an anchor used to be immortal. A user who DELETED a
    /// rule left its hostname registered as an anchor for the rest of the
    /// session, and `observe_candidate` refuses to track a host that is an
    /// anchor — so the very hosts someone removes in order to be offered them
    /// again were the ones that could never be proposed. Called from the
    /// proposal tick, which already holds the live rule book.
    ///
    /// Returns how many anchors were retired.
    pub fn retain_anchors<F>(&mut self, is_still_a_rule_host: F) -> usize
    where
        F: Fn(&str) -> bool,
    {
        let retired: Vec<(String, u32)> = self
            .anchors
            .iter()
            .filter(|(name, _)| !is_still_a_rule_host(name))
            .map(|(name, state)| (name.clone(), state.id))
            .collect();
        for (name, id) in &retired {
            self.anchors.remove(name);
            for candidate in self.candidates.values_mut() {
                candidate.pairs.retain(|p| p.anchor_id != *id);
            }
        }
        if !retired.is_empty() {
            // A candidate left with no pairs describes nothing; new sightings
            // rebuild it from scratch if it turns up again.
            self.candidates.retain(|_, c| !c.pairs.is_empty());
        }
        retired.len()
    }

    /// Pull every timestamp that sits in the future back to `at_ms`.
    ///
    /// Called when an observation is seen to predate a window that is already
    /// open — the only evidence a pure ledger can have that the clock behind
    /// its timestamps moved. Bounded work over bounded maps, and it runs only
    /// on that event.
    ///
    /// Windows are CLOSED rather than re-dated: their contents were attributed
    /// under the old reading, and stretching one over the gap would let a
    /// sighting minutes later count as co-active with a page from before the
    /// correction. The next sighting opens an honest window.
    fn rebase_after_clock_step(&mut self, at_ms: u64) {
        for anchor in self.anchors.values_mut() {
            if anchor.window_start_ms > at_ms {
                anchor.window_start_ms = at_ms;
                anchor.window_end_ms = at_ms;
            }
            anchor.last_seen_ms = anchor.last_seen_ms.min(at_ms);
        }
        for candidate in self.candidates.values_mut() {
            candidate.first_seen_ms = candidate.first_seen_ms.min(at_ms);
            candidate.last_seen_ms = candidate.last_seen_ms.min(at_ms);
        }
        self.unattributed
            .retain(|(_, seen_at, _)| *seen_at <= at_ms);
    }

    fn evict_least_recent_anchor(&mut self) {
        let victim = self
            .anchors
            .iter()
            .min_by(|(name_a, a), (name_b, b)| {
                a.last_seen_ms
                    .cmp(&b.last_seen_ms)
                    .then_with(|| name_a.cmp(name_b))
            })
            .map(|(name, state)| (name.clone(), state.id));
        if let Some((name, evicted_id)) = victim {
            self.anchors.remove(&name);
            for candidate in self.candidates.values_mut() {
                candidate.pairs.retain(|p| p.anchor_id != evicted_id);
            }
            // Same clean-up `retain_anchors` does: a candidate whose last pair
            // just went describes nothing, and leaving it behind holds a slot
            // in the bounded set against candidates that still mean something.
            self.candidates.retain(|_, c| !c.pairs.is_empty());
        }
    }

    /// Evicts the least recently seen candidate (ties broken by hostname
    /// order for determinism). Never panics — on an empty map it is a no-op.
    fn evict_least_recent_candidate(&mut self) {
        let victim = self
            .candidates
            .iter()
            .min_by(|(name_a, a), (name_b, b)| {
                a.last_seen_ms
                    .cmp(&b.last_seen_ms)
                    .then_with(|| name_a.cmp(name_b))
            })
            .map(|(name, _)| name.clone());
        if let Some(name) = victim {
            self.candidates.remove(&name);
        }
    }

    /// Decides whether one (candidate, anchor) pair is worth proposing, and on
    /// which grounds. Tiers are tried strongest first; `None` means the pair
    /// stays unproposed — the deliberate default, since a wrong proposal grows
    /// the rule book that every packet is matched against.
    fn qualify(
        &self,
        anchor_hostname: &str,
        candidate_hostname: &str,
        pair: &PairStats,
        candidate: &CandidateState,
        affinity: f64,
    ) -> Option<CompanionSignal> {
        if is_brand_related(anchor_hostname, candidate_hostname) {
            // Brand relation states ownership, not need. An operator's
            // advertising and telemetry domains carry the brand exactly as
            // plainly as the asset host a page cannot render without
            // (an operator's ad domain beside its asset domain under one of
            // that operator's product hosts), so the shared name opens the tier and
            // evidence decides it — one sighting is not a relationship.
            //
            // Ownership is measured with `nearest_share`, not `affinity`:
            // affinity divides by how many OTHER anchors pulled the same
            // candidate, and a brand's shared asset host is pulled by all of
            // them by design — the threshold would drop precisely the companion
            // worth proposing.
            // Exclusivity is the evidence that separates them, and `affinity`
            // measures exactly that: the share of all the windows this candidate
            // was ever seen in that belong to THIS anchor. A site's own hosts
            // ride along with that site; an operator's advertising, telemetry
            // and shared asset domains ride along with everything, which is what
            // drops them to affinities in the thousandths.
            if affinity >= self.config.brand_min_affinity {
                return Some(CompanionSignal::BrandRelated);
            }
            // Not proven as kin — fall through to the tiers below, which judge
            // it on temporal evidence like any other name.
        }
        // Sub-resource, not neighbour in time. Both tiers below rest on temporal
        // attribution, and that attribution is only as good as the assumption
        // that the anchor is the page doing the fetching. When most of the hits
        // this anchor claims happened while somebody else's page was loading,
        // the assumption is false — this is how a rule host in one tab collects
        // another site's CDN (`ypncdn.com` under `www.search.test`,
        // `cdninsta.test` under `cdn.openai.com`). Brand relation above is
        // exempt: a shared name states ownership regardless of timing.
        let mostly_someone_elses =
            pair.foreign_parent_hits > 0 && pair.foreign_parent_hits * 2 > pair.nearest_hits.max(1);
        if mostly_someone_elses {
            return None;
        }
        if is_delivery_named(candidate_hostname) {
            let nearest_share =
                f64::from(pair.nearest_hits) / f64::from(candidate.total_hits.max(1));
            let dominated = pair.distinct_windows >= self.config.delivery_min_distinct_windows
                && nearest_share >= self.config.delivery_min_nearest_share;
            // Observed traffic stands in for the second visit. The second visit
            // was only ever a proxy for "this is real, not a speculative
            // resolution" — a connection answers that directly, and answers it
            // during the visit that needed the address rather than the one
            // after. The name still has to look like a delivery endpoint AND
            // this anchor still has to own the observation.
            //
            // Ownership here must be uncontested: this tier publishes on a
            // single sighting, so a lead of a tenth of a second over another
            // open site would be enough to sign the offer with the wrong name,
            // with no later evidence to correct it.
            let proven_by_use = candidate.seen_in_use
                && pair.uncontested_hits > 0
                && nearest_share >= self.config.delivery_min_nearest_share;
            // The blocked case: the address never carried traffic BECAUSE it
            // was blocked, so `seen_in_use` can never arrive and the tier above
            // is unreachable for exactly the names the user is missing. Two
            // things stand in for it, and both are required. Ownership has to be
            // undivided — one anchor, every observation attributed to it, never
            // a rival open in the same breath — and the name has to have
            // actually FAILED on the main route. Advertising and telemetry
            // endpoints work fine there, so they never reach this tier; the
            // half-loaded page the user is looking at does, during the visit
            // that broke rather than the one after.
            let single_obvious_owner = self.config.propose_delivery_names_with_single_owner
                && candidate.pairs.len() == 1
                && pair.uncontested_hits > 0
                && pair.nearest_hits == candidate.total_hits
                && candidate.primary_behavior() == PrimaryBehavior::Stalls;
            if self.config.propose_delivery_names_without_co_activity
                || dominated
                || proven_by_use
                || single_obvious_owner
            {
                return Some(CompanionSignal::DeliveryName);
            }
        }
        if pair.distinct_windows >= self.config.min_distinct_windows
            && affinity >= self.config.min_affinity
        {
            return Some(CompanionSignal::CoActivity);
        }
        None
    }

    /// Computes companion proposals from the evidence accumulated so far.
    ///
    /// `now_ms` bounds evidence freshness: candidates last seen more than
    /// [`CompanionAffinityConfig::evidence_ttl_ms`] before `now_ms` are
    /// skipped (their counts are retained and revive on the next sighting).
    ///
    /// A pair is emitted when any of the three tiers accepts it (see the module
    /// documentation and [`CompanionSignal`]).
    ///
    /// Pure read — the ledger is not mutated. Output ordering is fully
    /// deterministic: anchor hostname ascending, then signal (strongest first),
    /// then affinity descending, then proposed value ascending; at most
    /// [`CompanionAffinityConfig::max_proposals_per_anchor`] per anchor, so the
    /// cap drops the weakest evidence first.
    ///
    /// Exclusion checks receive every candidate hostname and every
    /// suffix-proposal apex; an excluded apex falls back to exact-host
    /// proposals for its non-excluded members.
    pub fn proposals<E>(&self, now_ms: u64, exclusions: &E) -> Vec<CompanionProposal>
    where
        E: CandidateExclusions + ?Sized,
    {
        struct Member<'a> {
            hostname: &'a str,
            signal: CompanionSignal,
            affinity: f64,
            nearest_share: f64,
            distinct_windows: u32,
            first_seen_ms: u64,
            last_seen_ms: u64,
            primary_behavior: PrimaryBehavior,
        }

        let mut anchors_by_id: HashMap<u32, (&str, RouteRole)> =
            HashMap::with_capacity(self.anchors.len());
        for (name, state) in &self.anchors {
            anchors_by_id.insert(state.id, (name.as_str(), state.route));
        }

        // anchor hostname -> registrable-domain group -> qualifying members.
        // BTreeMaps make iteration (and thus output) order deterministic.
        let mut grouped: BTreeMap<&str, BTreeMap<&str, Vec<Member<'_>>>> = BTreeMap::new();
        let mut routes: HashMap<&str, RouteRole> = HashMap::new();

        for (host, candidate) in &self.candidates {
            if now_ms.saturating_sub(candidate.last_seen_ms) > self.config.evidence_ttl_ms {
                continue;
            }
            if candidate.total_windows == 0 {
                continue;
            }
            if exclusions.is_rule_host(host) || exclusions.is_matched_by_existing_rule(host) {
                continue;
            }
            // Shared infrastructure is held back until the main link is
            // measured to fail for it — see `infrastructure_earns_a_proposal`.
            if exclusions.is_platform_infrastructure(host)
                && !infrastructure_earns_a_proposal(candidate.primary_behavior())
            {
                continue;
            }
            for pair in &candidate.pairs {
                let Some(&(anchor_name, route)) = anchors_by_id.get(&pair.anchor_id) else {
                    continue;
                };
                let affinity =
                    f64::from(pair.distinct_windows) / f64::from(candidate.total_windows);
                let Some(signal) = self.qualify(anchor_name, host, pair, candidate, affinity)
                else {
                    continue;
                };
                let group_key = registrable_domain(host).unwrap_or(host.as_str());
                routes.insert(anchor_name, route);
                grouped
                    .entry(anchor_name)
                    .or_default()
                    .entry(group_key)
                    .or_default()
                    .push(Member {
                        hostname: host.as_str(),
                        signal,
                        affinity,
                        nearest_share: f64::from(pair.nearest_hits)
                            / f64::from(candidate.total_hits.max(1)),
                        distinct_windows: pair.distinct_windows,
                        first_seen_ms: candidate.first_seen_ms,
                        last_seen_ms: candidate.last_seen_ms,
                        primary_behavior: candidate.primary_behavior(),
                    });
            }
        }

        let mut out: Vec<CompanionProposal> = Vec::new();
        for (anchor_name, groups) in &grouped {
            let Some(&route) = routes.get(anchor_name) else {
                continue;
            };
            let mut per_anchor: Vec<CompanionProposal> = Vec::new();
            for (apex, members) in groups {
                let exact = |m: &Member<'_>| CompanionProposal {
                    anchor_hostname: (*anchor_name).to_string(),
                    proposed: ProposedCompanionMatch::ExactHost(m.hostname.to_string()),
                    route,
                    signal: m.signal,
                    affinity: m.affinity,
                    nearest_share: m.nearest_share,
                    distinct_windows: m.distinct_windows,
                    first_seen_ms: m.first_seen_ms,
                    last_seen_ms: m.last_seen_ms,
                    primary_behavior: m.primary_behavior,
                    observed_members: Vec::new(),
                };
                // Only true subdomains justify generalizing to `*.apex` — the
                // apex alone is not evidence that a whole suffix belongs on the
                // route. (It IS covered by the resulting rule, which is why no
                // separate exact proposal is emitted for it below when the
                // suffix proposal fires.)
                let subdomains: Vec<&Member<'_>> =
                    members.iter().filter(|m| m.hostname != *apex).collect();
                // A name that carries the anchor's brand or is a delivery name
                // is evidence about the domain, not just about itself:
                // `static.cdninsta.test` says the whole CDN serves the site.
                // Co-activity alone says nothing of the kind — a host that
                // merely loaded at the same time must not drag its siblings
                // onto the route.
                //
                // The evidence has to hold for the APEX, though, not just for
                // the one subdomain that was seen. `cdn.auth0.com` is a delivery
                // name under a service's own domain: generalizing it moved all
                // of `auth0.com` — sign-in included — onto the additional link
                // on the strength of one asset host. A dedicated delivery apex
                // (`cdninsta.test`, `videocdn.test`, `cdn.example`) carries
                // the mask itself, and that is the shape worth generalizing.
                let generalizes_alone = subdomains.iter().any(|m| match m.signal {
                    CompanionSignal::BrandRelated => {
                        brand_relation(anchor_name, apex) == BrandRelation::Named
                    }
                    CompanionSignal::DeliveryName => is_delivery_named(apex),
                    CompanionSignal::CoActivity => false,
                });
                // Counting only the members whose NAME is the evidence.
                // Co-activity says a host loaded at the same time; two of them
                // say it twice, never that the apex serves the anchor — that
                // reading put a torrent client's whole domain on the tunnel.
                //
                // A short shared token is the same kind of non-evidence, and
                // it needs refusing at BOTH doors: `generalizes_alone` above
                // already declines it, but counting let two subdomains of
                // `q.test` generalize under the anchor `q.example` on the strength of
                // one letter. Kinship survives — it buys the exact host, which
                // is what [`BrandRelation::ShortToken`] is for — the apex does
                // not.
                let apex_brand_is_evidence =
                    brand_relation(anchor_name, apex) == BrandRelation::Named;
                let named_subdomains = subdomains
                    .iter()
                    .filter(|m| m.signal != CompanionSignal::CoActivity)
                    .filter(|m| apex_brand_is_evidence || m.signal != CompanionSignal::BrandRelated)
                    .count();
                // The apex of shared infrastructure follows its members: a
                // domain whose names are measured to fail on the main link is
                // asked about once, instead of once per name. Cutting to the
                // domain is the whole point — a person answering four
                // questions about one service is answering the same question
                // four times.
                let apex_infra_ok = !exclusions.is_platform_infrastructure(apex)
                    || subdomains
                        .iter()
                        .any(|m| infrastructure_earns_a_proposal(m.primary_behavior));
                let suffix_proposed = !subdomains.is_empty()
                    && (generalizes_alone || named_subdomains >= SUFFIX_MIN_DISTINCT_SUBDOMAINS)
                    && !suffix_would_swallow_the_anchor(anchor_name, apex)
                    && !exclusions.is_rule_host(apex)
                    && !exclusions.is_matched_by_existing_rule(apex)
                    && apex_infra_ok;
                // Summarize with the strongest member's evidence and the union
                // of the members' observation span.
                let summarize = |members: &[&Member<'_>], value: String| CompanionProposal {
                    anchor_hostname: (*anchor_name).to_string(),
                    proposed: ProposedCompanionMatch::SuffixDomain(value),
                    route,
                    signal: members
                        .iter()
                        .map(|m| m.signal)
                        .min()
                        .unwrap_or(CompanionSignal::CoActivity),
                    affinity: members.iter().fold(0.0_f64, |acc, m| acc.max(m.affinity)),
                    nearest_share: members
                        .iter()
                        .fold(0.0_f64, |acc, m| acc.max(m.nearest_share)),
                    distinct_windows: members
                        .iter()
                        .map(|m| m.distinct_windows)
                        .max()
                        .unwrap_or(0),
                    first_seen_ms: members.iter().map(|m| m.first_seen_ms).min().unwrap_or(0),
                    last_seen_ms: members.iter().map(|m| m.last_seen_ms).max().unwrap_or(0),
                    primary_behavior: members.iter().fold(PrimaryBehavior::Unknown, |acc, m| {
                        acc.merge(m.primary_behavior)
                    }),
                    observed_members: {
                        let mut names: Vec<String> =
                            members.iter().map(|m| m.hostname.to_string()).collect();
                        names.sort();
                        names.dedup();
                        names
                    },
                };
                if suffix_proposed {
                    per_anchor.push(summarize(&subdomains, (*apex).to_string()));
                } else {
                    // The apex is out of reach — it would swallow the anchor, or
                    // a rule already covers it. Falling straight to one proposal
                    // per host hands the user ten fourth-level names of a single
                    // service to answer one by one; the level those names share
                    // is the service, and one `*.that` says the same thing.
                    // Repeated, because one group can hold several such families.
                    let mut remaining: Vec<&Member<'_>> = subdomains;
                    loop {
                        let hostnames: Vec<&str> = remaining.iter().map(|m| m.hostname).collect();
                        let Some(shared) = deepest_shared_suffix(
                            &hostnames,
                            apex,
                            SUFFIX_MIN_DISTINCT_SUBDOMAINS,
                            |suffix| {
                                !covers_the_anchor(anchor_name, suffix)
                                    && !exclusions.excludes(suffix)
                            },
                        ) else {
                            break;
                        };
                        let shared = shared.to_string();
                        let (covered, rest): (Vec<_>, Vec<_>) =
                            remaining.into_iter().partition(|m| {
                                m.hostname == shared || is_under_suffix(m.hostname, &shared)
                            });
                        per_anchor.push(summarize(&covered, shared));
                        remaining = rest;
                    }
                    per_anchor.extend(remaining.iter().map(|m| exact(m)));
                }
                // `*.apex` already covers the apex; a second exact proposal for
                // it would be a redundant entry in the user's review list.
                if !suffix_proposed {
                    per_anchor.extend(members.iter().filter(|m| m.hostname == *apex).map(exact));
                }
            }
            per_anchor.sort_by(|a, b| {
                a.signal
                    .cmp(&b.signal)
                    .then_with(|| b.affinity.total_cmp(&a.affinity))
                    .then_with(|| a.proposed.value().cmp(b.proposed.value()))
            });
            per_anchor.truncate(self.config.max_proposals_per_anchor);
            out.extend(per_anchor);
        }

        // `grouped` already iterates anchors in ascending order; re-sorting
        // makes the contract explicit and independent of the loop above.
        out.sort_by(|a, b| {
            a.anchor_hostname
                .cmp(&b.anchor_hostname)
                .then_with(|| a.signal.cmp(&b.signal))
                .then_with(|| b.affinity.total_cmp(&a.affinity))
                .then_with(|| a.proposed.value().cmp(b.proposed.value()))
        });
        out
    }
}
