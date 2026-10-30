//! Applying a plan: install, reconcile, remove, clean up.
//!
//! The other half of the orchestrator's impl. The plan (what filters a policy
//! compiles to) lives in `super::plan`; this is what happens to the kernel once
//! the plan exists — including the locking that keeps two triggers for one SID
//! from interleaving.

use super::*;
use nrr_platform_api::wfp::{RetireHeld, WfpReplaceOutcome};

impl PerSidApplyOrchestrator {
    /// Snapshot of the SIDs currently holding filter sets. Sorted for
    /// deterministic test assertions.
    pub fn installed_sids(&self) -> Vec<String> {
        let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut out: Vec<String> = g.keys().cloned().collect();
        out.sort();
        out
    }

    /// Number of WFP filter IDs installed for `sid`. Returns 0 if the
    /// SID has no entry.
    /// The filter ids this orchestrator tracks for `sid`.
    pub fn installed_filter_ids(&self, sid: &str) -> Vec<WfpFilterId> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .map(|s| s.installed.clone())
            .unwrap_or_default()
    }

    pub fn filter_count_for(&self, sid: &str) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .map(|s| s.installed.len())
            .unwrap_or(0)
    }

    /// Confirms every id in `installed_ids` is actually live in WFP after an
    /// install. Missing ids are PHANTOMS (recorded installed but never
    /// materialised). Logs the outcome; returns `Some(phantom_count)` on a
    /// successful enumeration and `None` when the live filters could not be
    /// read (verification skipped). Best-effort — the production caller
    /// ignores the return (the check is a safety net, not a gate); the value
    /// exists so tests can assert on it. `expected` is the count claimed
    /// installed.
    // pub(super): the tests for this live in a sibling module and call it directly.
    pub(super) fn verify_installed_filters_live(
        &self,
        sid: &str,
        installed_ids: &[WfpFilterId],
        expected: usize,
    ) -> Option<usize> {
        if installed_ids.is_empty() {
            return Some(0);
        }
        match self.session.enumerate_our_filters() {
            Ok(live) => {
                let live_ids: std::collections::HashSet<u64> =
                    live.iter().map(|r| r.id.raw).collect();
                let phantom = installed_ids
                    .iter()
                    .filter(|id| !live_ids.contains(&id.raw))
                    .count();
                if phantom > 0 {
                    tracing::error!(
                        target: "nrr::per_sid_orchestrator",
                        msg_key = "persid-apply-phantom-filters",
                        sid,
                        phantom,
                        expected,
                        "verify-after-apply: filters recorded as installed are NOT live in WFP (phantom) — real enforcement is weaker than reported",
                    );
                } else {
                    tracing::debug!(
                        target: "nrr::per_sid_orchestrator",
                        sid,
                        verified = expected,
                        "verify-after-apply: every installed filter confirmed live in WFP",
                    );
                }
                Some(phantom)
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::per_sid_orchestrator",
                    msg_key = "persid-apply-verify-enumerate-failed",
                    sid,
                    error = %e,
                    "verify-after-apply: could not enumerate live WFP filters (skipping check)",
                );
                None
            }
        }
    }

    /// Take this SID's apply lock. Held for the whole compute-and-apply, so two
    /// triggers cannot interleave and leave the engine holding a set neither of
    /// them decided on.
    // pub(super): the tests for this live in a sibling module and call it directly.
    pub(super) fn apply_lock_for(&self, sid: &str) -> Arc<Mutex<()>> {
        Arc::clone(
            self.apply_locks
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entry(sid.to_string())
                .or_default(),
        )
    }

    pub fn install_for_sid(&self, sid: &str) -> Result<usize, OrchestratorError> {
        let lock = self.apply_lock_for(sid);
        let _apply_guard = lock.lock().unwrap_or_else(|p| p.into_inner());
        self.install_for_sid_with(sid, None)
    }

    /// Derive what applying `rules` to `sid` WOULD do, touching nothing.
    ///
    /// The compute is the only thing that knows the real answer — how many
    /// filters, whether two of them collide on id, which app rules resolve to no
    /// executable — so a preview has to run it. What it must not do is publish:
    /// the same function normally refreshes the live status the GUI reads about
    /// the CURRENT policy (block-all posture, unresolved apps, spared shared
    /// IPs, the posture log latch, pending rebind requests). Every one of those
    /// is gated on [`ComputeIntent`], and `preview_for_sid` passes
    /// `Preview` — see the enum's doc for why.
    pub fn preview_for_sid(
        &self,
        sid: &str,
        rules: &ActiveRulesSnapshot,
    ) -> Result<SidApplyPreview, OrchestratorError> {
        let installed_now = self.filter_count_for(sid);
        let computed =
            self.compute_filters_for_sid(sid, false, Some(rules), ComputeIntent::Preview)?;
        let plan = match computed {
            ComputedFilterSet::Install(plan) => plan,
            ComputedFilterSet::NoPolicy => {
                return Ok(SidApplyPreview {
                    sid: sid.to_string(),
                    enforceable: false,
                    filters: 0,
                    installed_now,
                    // Nothing enforceable means everything installed would go.
                    additions: 0,
                    removals: installed_now,
                    colliding_filter_ids: Vec::new(),
                    unresolved_apps: Vec::new(),
                    secondary_binding_unresolved: false,
                });
            }
        };
        // Two specs sharing an id would have the second silently replace the
        // first in the engine, so the plan quietly enforces less than it says.
        let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let mut colliding: Vec<u64> = plan
            .filters
            .iter()
            .filter(|spec| !seen.insert(spec.id.raw))
            .map(|spec| spec.id.raw)
            .collect();
        colliding.sort_unstable();
        colliding.dedup();
        // A configured secondary the OS cannot resolve is why a leak guard sits
        // fail-closed. Asked here rather than carried out of the compute: the
        // resolver is the same one the compute consults, and it answers without
        // deriving anything.
        let secondary_binding_unresolved = self
            .policy_source
            .load_for_sid(sid)
            .is_some_and(|policy| policy.secondary.is_some())
            && (self.kill_switch_resolver)(sid, &(self.machine_reader)()).is_none();
        // The diff is over filter IDS, which are derived from each spec's own
        // identity: an unchanged policy produces the same ids, so this reads 0/0
        // instead of "replace all N". Callers depend on that distinction —
        // "already on baseline" is exactly a zero diff.
        let installed_ids: std::collections::HashSet<u64> = {
            let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            g.get(sid)
                .map(|s| s.installed.iter().map(|id| id.raw).collect())
                .unwrap_or_default()
        };
        let planned_ids: std::collections::HashSet<u64> =
            plan.filters.iter().map(|spec| spec.id.raw).collect();
        let additions = planned_ids.difference(&installed_ids).count();
        let removals = installed_ids.difference(&planned_ids).count();
        Ok(SidApplyPreview {
            sid: sid.to_string(),
            enforceable: true,
            filters: plan.filters.len(),
            installed_now,
            additions,
            removals,
            colliding_filter_ids: colliding,
            unresolved_apps: plan.unresolved_apps,
            secondary_binding_unresolved,
        })
    }

    /// Whether a filter ADD is still allowed. A filter installed after the stop
    /// teardown began outlives the process — the WFP session is non-dynamic, so
    /// nothing takes it down when we exit, and it keeps dropping traffic with no
    /// service left to lift it. Checked at entry AND right before the engine
    /// call: a pass that entered before the latch is still running.
    /// Whether the filtering engine has handed out a session.
    pub fn engine_open(&self) -> bool {
        self.session.is_open()
    }

    /// Whether the filtering engine has yet to hand out a session. Until it
    /// does, a pass is a quiet no-op: the opener settles every user once it
    /// lands, and a refusal recorded on every tick would bury that one fact.
    pub(super) fn engine_pending(&self, stage: &'static str) -> bool {
        if self.session.is_open() {
            return false;
        }
        tracing::debug!(
            target: "nrr::per_sid_orchestrator",
            stage,
            "filtering engine not open yet — pass skipped",
        );
        true
    }

    fn adds_refused(&self, sid: &str, stage: &'static str) -> bool {
        if !(self.teardown_gate)() {
            return false;
        }
        tracing::info!(
            target: "nrr::per_sid_orchestrator",
            msg_key = "persid-apply-adds-refused-teardown",
            sid = %sid,
            stage,
            "teardown in progress — filter adds refused (an added filter outlives the process)",
        );
        true
    }

    fn install_for_sid_with(
        &self,
        sid: &str,
        rules_override: Option<&ActiveRulesSnapshot>,
    ) -> Result<usize, OrchestratorError> {
        if sid.is_empty() {
            return Err(OrchestratorError::EmptySid);
        }
        if self.adds_refused(sid, "install") || self.engine_pending("install") {
            return Ok(0);
        }
        // The admin baseline is never enforced as its own machine-wide
        // filter set — it only reaches the wire as a per-user read-through
        // when a real SID has no revision of its own. With nobody logged
        // in, `reconcile` installs nothing, so the baseline itself never
        // gets a filter set. This guard makes that invariant explicit.
        if sid == nrr_domain::user_principal::BASELINE_PRINCIPAL {
            return Err(OrchestratorError::BaselineNotRoutable);
        }
        let was_known = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(sid);
        // What this SID already carries. A full-replace install only ADDS, so
        // whatever is not in the new set has to be deleted explicitly —
        // otherwise it stays alive in the engine while dropping out of our
        // accounting, and keeps dropping traffic nobody can see or reap.
        let previously_installed: Vec<WfpFilterId> = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .map(|s| s.installed.clone())
            .unwrap_or_default();
        // Derive the full filter set (rule-driven + leak-guard) via the shared
        // `compute_filters_for_sid` path. No policy installs nothing but still
        // records the SID so a later on_disconnect / recompile stays consistent.
        // A book or policy row that does not read is this user's failure, and
        // the health card hears of it the same way as a refused filter set.
        let computed =
            match self.compute_filters_for_sid(sid, true, rules_override, ComputeIntent::Apply) {
                Ok(computed) => computed,
                Err(e) => {
                    self.emit_audit(
                        sid,
                        PerSidApplyAuditKind::Failed,
                        0,
                        &format!("install for {sid}: {e}"),
                    );
                    return Err(e);
                }
            };
        let filters = match computed {
            ComputedFilterSet::NoPolicy => {
                // No policy → record the SID as known (so a later on_disconnect
                // doesn't panic) but install nothing. Anything this SID was
                // carrying has to come down: the empty state would otherwise
                // orphan it.
                self.delete_superseded_filters(sid, &previously_installed, &[]);
                self.upsert_state(sid, Vec::new());
                self.emit_audit(sid, PerSidApplyAuditKind::Applied, 0, "no-policy");
                return Ok(0);
            }
            ComputedFilterSet::Install(plan) => plan.filters,
        };
        // Route before block — same ordering invariant the reconcile enforces
        // (see `reconcile_to_desired`). A cold install lands the whole pin set
        // at once, so every destination it covers must already be routed.
        self.sync_routes_before_pins(sid, &filters);
        // The compute above can run for seconds; the latch may have flipped
        // inside it.
        if self.adds_refused(sid, "install-apply") {
            return Ok(0);
        }
        // Journal before the commit: a batch the engine accepted before a later
        // one failed, or a process killed mid-commit, is otherwise tracked by
        // nobody. Ids are derived from identity, so an id that never landed is
        // an idempotent delete at the next reap.
        if let Some(ledger) = self.ledger.as_ref() {
            let planned: Vec<WfpFilterId> = filters.iter().map(|s| s.id).collect();
            ledger.record(&planned);
        }
        let mode = (self.failure_mode)();
        // MAKE before BREAK inside the session, as in `reconcile_to_desired`:
        // what the new set supersedes is deleted only once it is all up.
        let apply_outcome =
            match self
                .session
                .execute_replacement(&filters, &previously_installed, mode)
            {
                Ok(o) => o,
                Err(e) => {
                    let msg = format!("install for {sid}: {e:?}");
                    self.emit_audit(sid, PerSidApplyAuditKind::Failed, 0, &msg);
                    return Err(OrchestratorError::WfpFailed(msg));
                }
            };
        // Record only the filters that actually installed — best-effort may
        // have skipped some un-materializable ones. Deleting a never-added
        // id later is idempotent, but tracking the real set keeps
        // `filter_count_for` honest.
        let skipped: std::collections::HashSet<u64> =
            apply_outcome.skipped.iter().map(|s| s.id.raw).collect();
        let installed_ids: Vec<WfpFilterId> = filters
            .iter()
            .map(|s| s.id)
            .filter(|id| !skipped.contains(&id.raw))
            .collect();
        let count = installed_ids.len();
        let tracked_ids =
            self.tracked_after_install(sid, &previously_installed, &installed_ids, &apply_outcome);
        // Re-read our live WFP filters and confirm every id we just recorded
        // as installed is actually present in the engine. A missing id is a
        // PHANTOM: counted as installed but never materialised in WFP — the
        // failure mode when an add error gets mis-classified and silently
        // swallowed while `installed=N` still increments. Logged loud
        // (error) so a regression shows up in NDJSON instead of trusting the
        // count. Best-effort: an enumeration failure never fails the apply
        // (the filters are already committed); runs only on a real install,
        // not the frequent coverage-reconcile tick, so the cost is one
        // enumeration per policy change.
        self.verify_installed_filters_live(sid, &installed_ids, count);
        // Destinations this set scopes to, deduplicated. Compared against the
        // previous install BEFORE the state is replaced.
        let (destinations, secondary_resolved) = Self::coverage_of(&filters);
        let networks = Self::rule_networks_of(sid, &filters);
        self.tear_down_flows_to_new_destinations(
            sid,
            &filters,
            &destinations,
            &networks,
            secondary_resolved,
        );
        Self::publish_enforced_addresses(sid, &filters);
        self.upsert_state_with_destinations(
            sid,
            tracked_ids,
            destinations,
            networks,
            secondary_resolved,
        );
        let kind = if was_known {
            PerSidApplyAuditKind::Updated
        } else {
            PerSidApplyAuditKind::Applied
        };
        if apply_outcome.skipped.is_empty() {
            // Log success at info, not just audit, so "did enforcement arm?"
            // is answerable directly from NDJSON.
            tracing::info!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "persid-apply-filters-installed",
                sid,
                installed = count,
                "per-SID WFP filter set installed",
            );
            self.emit_audit(sid, kind, count as u32, "ok");
        } else {
            let n = apply_outcome.skipped.len();
            tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "persid-apply-best-effort-skipped",
                sid,
                installed = count,
                skipped = n,
                "per-SID apply completed best-effort — some rules were not enforceable on this host"
            );
            self.emit_audit(
                sid,
                kind,
                count as u32,
                &format!("ok ({n} rule(s) skipped — not enforceable on this host)"),
            );
        }
        Ok(count)
    }

    /// Wire the narrow route sync tried before the full one; see
    /// [`ScopedRouteSyncHook`].
    #[must_use]
    pub fn with_scoped_route_sync(mut self, hook: ScopedRouteSyncHook) -> Self {
        self.scoped_route_sync = Some(hook);
        self
    }

    /// Route before block for the destination blocks among `adds`. A few new
    /// host pins route just their own addresses; a network pin, a large batch
    /// or an address the narrow plan declined falls back to the full route
    /// pass, which the routes phase of the same tick has usually just run.
    fn sync_routes_before_pins(&self, sid: &str, adds: &[WfpFilterSpec]) {
        let Some(full) = self.route_sync.as_ref() else {
            return;
        };
        let mut pins = adds.iter().filter(|spec| is_destination_block(spec));
        let Some(first) = pins.next() else {
            return;
        };
        if let Some(scoped) = self.scoped_route_sync.as_ref() {
            let pins: Vec<&WfpFilterSpec> = std::iter::once(first).chain(pins).collect();
            let hosts_only = pins.iter().all(|spec| {
                spec.remote_subnet.is_none()
                    && spec.remote_subnet_v6.is_none()
                    && spec.remote_subnet_set.is_empty()
            });
            if hosts_only {
                let mut seen = std::collections::HashSet::new();
                let hosts: Vec<std::net::IpAddr> = pins
                    .iter()
                    .flat_map(|spec| Self::hosts_of(spec))
                    .filter(|ip| seen.insert(*ip))
                    .collect();
                if !hosts.is_empty()
                    && hosts.len() <= SCOPED_ROUTE_SYNC_MAX_HOSTS
                    && scoped(sid, &hosts)
                {
                    return;
                }
            }
        }
        run_route_sync(full);
    }

    /// Window-free, make-before-break reconcile of the per-SID filter set
    /// against the freshly-resolved secondary LUID: grows coverage
    /// additively (newly observed secondary IPs) and reaps tracked filters
    /// no longer desired — critically the dead-LUID egress permits left
    /// after a secondary adapter reconnect. The permit id folds the LUID
    /// (see `killswitch_codegen::permit_luid_seg`), so a reconnect mints a
    /// new permit id and the stale one is superseded and deleted here (a WFP
    /// filter is immutable by key, so an add-only path would swallow the
    /// collision and the stale permit would stick).
    ///
    /// Ordering is strictly ADD-then-DELETE so the kill-switch is never
    /// briefly lifted. A pure LUID flip keeps every BLOCK's id stable, so
    /// only dead-LUID permits get deleted (fail-safe — deleting a permit
    /// only tightens). An up/down mode transition can change a block's
    /// shape (`block_off_secondary` ↔ `ale_block`), putting a superseded
    /// block in the delete set; safety then rests on add-before-delete plus
    /// deferring the whole delete pass whenever a replacement block add was
    /// skipped, so a block is never removed while its replacement is not
    /// yet up. A skipped permit never defers the delete, since skipping a
    /// permit only tightens. The delete set is derived purely from the
    /// desired-vs-tracked id diff, never from stored metadata the untyped
    /// id set lacks.
    ///
    /// Correct across every secondary adapter transition (reconnect,
    /// up→down fail-closed, down→up re-arm) because the diff
    /// drives it. A no-op when desired == tracked. Only acts on an
    /// already-installed SID — [`Self::reconcile`] owns an inactive one.
    /// Returns the count of filters added.
    pub fn reconcile_secondary_coverage(&self, sid: &str) -> Result<usize, OrchestratorError> {
        if self.adds_refused(sid, "leak-guard-coverage") {
            return Ok(0);
        }
        let lock = self.apply_lock_for(sid);
        let _apply_guard = lock.lock().unwrap_or_else(|p| p.into_inner());
        // Snapshot the currently-tracked filters; skip SIDs we have not installed.
        let tracked: Vec<WfpFilterId> = {
            let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            match g.get(sid) {
                Some(s) => s.installed.clone(),
                None => return Ok(0),
            }
        };
        let desired = match self.compute_filters_for_sid(sid, false, None, ComputeIntent::Apply)? {
            ComputedFilterSet::Install(f) => f,
            // No policy → nothing desired; leave the set as-is (full teardown
            // is owned by the stop / policy-change paths).
            ComputedFilterSet::NoPolicy => return Ok(0),
        };
        self.reconcile_to_desired(
            sid,
            tracked,
            desired.filters,
            "LUID-aware permit refresh",
            false,
        )
        .map(|(added, _live_total)| added)
    }

    /// The shared MAKE-then-BREAK core: bring the installed set for an
    /// already-tracked `sid` to exactly `desired`, without ever opening a
    /// window (adds land first; superseded filters are deleted after; an
    /// unchanged filter is never touched). Both the adapter-transition
    /// reconcile and the user-apply recompile funnel through here, so the
    /// leak-safety reasoning above is written once. `audit_note` labels the
    /// audit line with the caller's intent. Returns `(added, live_total)` —
    /// the adds this pass installed, and the tracked set size after the pass
    /// (the recompile path reports the latter to keep the historical
    /// "installed count" contract of the full replace it supersedes).
    /// `audit_no_op` audits even a no-change pass — a user Apply must leave a
    /// record, while the periodic reconcile tick must not spam one every 30 s.
    fn reconcile_to_desired(
        &self,
        sid: &str,
        tracked: Vec<WfpFilterId>,
        desired: Vec<WfpFilterSpec>,
        audit_note: &str,
        audit_no_op: bool,
    ) -> Result<(usize, usize), OrchestratorError> {
        // Entered before the latch flipped, still running after it. Leave the
        // tracked set exactly as it is: the stop strip deletes by tracked id.
        if self.adds_refused(sid, "reconcile-to-desired") {
            return Ok((0, 0));
        }
        let tracked_ids: std::collections::HashSet<u64> = tracked.iter().map(|id| id.raw).collect();
        let desired_ids: std::collections::HashSet<u64> =
            desired.iter().map(|s| s.id.raw).collect();

        let to_add: Vec<WfpFilterSpec> = desired
            .iter()
            .filter(|s| !tracked_ids.contains(&s.id.raw))
            .cloned()
            .collect();
        // Tracked ids no longer desired — the stale dead-LUID permits (and any
        // block-all superseded by a per-dest set on re-arm). Blocks keep stable
        // ids across a LUID flip, so they stay in `desired` and never appear here.
        let to_remove: Vec<WfpFilterId> = tracked
            .iter()
            .copied()
            .filter(|id| !desired_ids.contains(&id.raw))
            .collect();

        if to_add.is_empty() && to_remove.is_empty() {
            // Once per run of passes that changed nothing.
            let first_quiet = audit_no_op
                && self
                    .quiet_since_noop
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(sid.to_owned());
            if first_quiet {
                self.emit_noop_audit(
                    sid,
                    PerSidApplyAuditKind::Updated,
                    0,
                    &format!("reconcile: +0 -0 ({audit_note})"),
                );
            }
            return Ok((0, tracked.len()));
        }

        // (0) ROUTE BEFORE BLOCK. A destination-scoped block only
        // tolerates traffic that egresses the secondary, and what puts a
        // destination on the secondary is its `/32` route. The route pass and
        // this filter pass read the same live FQDN / app-observation stores but
        // at different instants, so an address learned in between is pinned
        // here while the route pass that would have carried it has already run
        // — and every flow to it is dropped until the next route recompute.
        // Driving the route pass here, for NEW destination blocks only, closes
        // that window without ever lifting a block (this runs before the MAKE,
        // and the BREAK below is unchanged). No lock is held at this point.
        // Costs nothing in steady state: an unchanged coverage set adds no
        // destination block and never reaches this call.
        self.sync_routes_before_pins(sid, &to_add);

        // MAKE then BREAK, both inside the session so a batch boundary cannot
        // reorder them: every add commits before the first delete. A pure LUID
        // flip keeps block ids stable, so only dead-LUID permits are retired
        // (deleting one only tightens). An up/down mode transition swaps a
        // block's shape and id; if that replacement block was skipped, the
        // session holds the whole retire pass back — over-coverage until the
        // block materialises, never a leak. An app-only block with an absent
        // exe covers no destination and does not hold it, or stale permits
        // would pile up forever behind a missing program.
        // Journalled before the commit, as in the install path.
        if let Some(ledger) = self.ledger.as_ref() {
            let planned: Vec<WfpFilterId> = to_add.iter().map(|s| s.id).collect();
            ledger.record(&planned);
        }
        let mode = (self.failure_mode)();
        let replaced = match self.session.execute_replacement(&to_add, &to_remove, mode) {
            Ok(o) => o,
            Err(e) => {
                let msg = format!("reconcile coverage for {sid}: {e:?}");
                self.emit_audit(sid, PerSidApplyAuditKind::Failed, 0, &msg);
                return Err(OrchestratorError::WfpFailed(msg));
            }
        };
        let skipped: std::collections::HashSet<u64> =
            replaced.skipped.iter().map(|s| s.id.raw).collect();
        let installed_ids: Vec<WfpFilterId> = to_add
            .iter()
            .map(|s| s.id)
            .filter(|id| !skipped.contains(&id.raw))
            .collect();
        // Anything not retired stays tracked: a filter nobody tracks is one
        // `cleanup_wfp` cannot delete by id, and a retry of a delete that
        // already happened is idempotent.
        let removed: Vec<WfpFilterId> = match replaced.retire_held {
            None => replaced.retired,
            Some(RetireHeld::ReplacementSkipped) => {
                tracing::warn!(
                    target: "nrr::per_sid_orchestrator",
                    msg_key = "persid-apply-delete-deferred",
                    sid,
                    deferred = to_remove.len() as u64,
                    "reconcile coverage: deferred delete of superseded filters — a replacement block add was skipped this tick (fail-safe over-coverage; retry next tick)",
                );
                Vec::new()
            }
            Some(RetireHeld::Failed(e)) => {
                tracing::warn!(
                    target: "nrr::per_sid_orchestrator",
                    msg_key = "persid-apply-delete-superseded-failed",
                    sid,
                    deferred = to_remove.len() as u64,
                    error = %e,
                    "reconcile coverage: delete of superseded filters best-effort failed — keeping them tracked so the next tick retries",
                );
                Vec::new()
            }
        };

        // (3) Update the tracked set = (tracked − removed) ∪ installed. `removed`
        // reflects what was actually deleted (empty when the delete was deferred),
        // so deferred ids stay tracked and are retried on the next tick.
        //
        // The coverage fields travel with it: they must reflect what this
        // pass just changed, not what the last install wrote. Otherwise the
        // addresses this pass starts enforcing never get swept (sockets
        // already open to them finish on the old link) and the *next*
        // install sees those same addresses as new, sweeping connections
        // that had only just been re-established. Likewise `secondary_
        // resolved` must track this pass's own result, or a tunnel that has
        // been up all along reads as one that "just came up" — a needless
        // sweep of every pinned destination.
        let (destinations, secondary_resolved) = Self::coverage_of(&desired);
        let networks = Self::rule_networks_of(sid, &desired);
        self.tear_down_flows_to_new_destinations(
            sid,
            &desired,
            &destinations,
            &networks,
            secondary_resolved,
        );
        Self::publish_enforced_addresses(sid, &desired);
        let live_total = {
            let removed_ids: std::collections::HashSet<u64> =
                removed.iter().map(|id| id.raw).collect();
            let mut g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let entry = g.entry(sid.to_string()).or_insert_with(|| PerSidFilterSet {
                sid: sid.to_string(),
                installed: Vec::new(),
                destinations: Vec::new(),
                secondary_resolved: false,
                networks: Vec::new(),
            });
            entry.destinations = destinations;
            entry.networks = networks;
            entry.secondary_resolved = secondary_resolved;
            entry.installed.retain(|id| !removed_ids.contains(&id.raw));
            let mut have: std::collections::HashSet<u64> =
                entry.installed.iter().map(|id| id.raw).collect();
            for id in installed_ids.iter().copied() {
                if have.insert(id.raw) {
                    entry.installed.push(id);
                }
            }
            entry.installed.len()
        };

        let added = installed_ids.len();
        let removed_count = removed.len();
        self.emit_audit(
            sid,
            PerSidApplyAuditKind::Updated,
            added as u32,
            &format!("reconcile: +{added} -{removed_count} ({audit_note})"),
        );
        Ok((added, live_total))
    }

    /// Remove every filter the orchestrator previously installed for
    /// `sid`. Idempotent on unknown SIDs.
    pub fn remove_for_sid(&self, sid: &str) -> Result<usize, OrchestratorError> {
        if sid.is_empty() {
            return Err(OrchestratorError::EmptySid);
        }
        let lock = self.apply_lock_for(sid);
        let _apply_guard = lock.lock().unwrap_or_else(|p| p.into_inner());
        self.remove_for_sid_locked(sid)
    }

    /// [`Self::remove_for_sid`] for a caller already holding the SID's apply
    /// lock. The lock is not reentrant: taking it again from inside a recompile
    /// wedged the SID for good.
    fn remove_for_sid_locked(&self, sid: &str) -> Result<usize, OrchestratorError> {
        // READ the tracked ids; do not drop the record yet. A delete that fails
        // leaves those filters installed, and forgetting their ids here left
        // them enforcing with nobody accounting for them — `cleanup_wfp`
        // deletes tracked filters BY ID, so an untracked block survives even a
        // graceful stop and can only be found by an enumerate sweep.
        let installed: Vec<WfpFilterId> = {
            let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            g.get(sid).map(|s| s.installed.clone()).unwrap_or_default()
        };
        let count = installed.len();
        if count > 0 {
            let actions: Vec<WfpFilterAction> = installed
                .into_iter()
                .map(WfpFilterAction::DeleteFilter)
                .collect();
            if let Err(e) = self.session.execute_wfp_plan(&actions) {
                let msg = format!("remove for {sid}: {e:?}");
                self.emit_audit(sid, PerSidApplyAuditKind::Failed, count as u32, &msg);
                return Err(OrchestratorError::WfpFailed(msg));
            }
        }
        // Only now is the SID genuinely un-enforced: drop the record and every
        // per-SID latch that describes a posture which no longer exists. The
        // block-id registry has to go too, or the drop learner keeps
        // role-verifying against ids that are gone.
        self.forget_sid_state(sid);
        if count == 0 {
            return Ok(0);
        }
        self.emit_audit(sid, PerSidApplyAuditKind::Withdrawn, count as u32, "ok");
        Ok(count)
    }

    /// Strip **every** WFP filter the service owns (block AND permit, all
    /// SIDs). Used by the graceful-stop teardown hook. Also clears the
    /// in-memory SID→filter map so a subsequent reconcile reinstalls from a
    /// clean slate. Idempotent — a second call deletes nothing.
    ///
    /// two-pass, robust against an enumerate that
    /// under-reports (the `stripped_filters:0` HW anomaly): (1) delete every
    /// filter we KNOW we installed this session **by id** (`FwpmFilterDeleteBy
    /// Key0` does not depend on enumeration, so a graceful stop can never leave
    /// an orphaned block = lockout for this process's filters); (2) enumerate-
    /// sweep for anything untracked (cross-session orphans from a prior
    /// hard-killed instance whose in-memory state is gone). The WFP session is
    /// **non-dynamic** — filters persist until an explicit delete or reboot —
    /// so this explicit strip (not session close) is what removes them.
    pub fn cleanup_wfp(&self) -> Result<usize, OrchestratorError> {
        // A stop that came before the engine answered still owes the machine
        // the strip: one more attempt, bounded by the caller's deadline.
        if !self.session.is_open() {
            self.session.ensure_open().map_err(|e| {
                OrchestratorError::WfpFailed(format!("filtering engine never opened: {e}"))
            })?;
        }
        let locks = self.every_apply_lock();
        let _held: Vec<std::sync::MutexGuard<'_, ()>> = locks
            .iter()
            .map(|l| l.lock().unwrap_or_else(|p| p.into_inner()))
            .collect();
        // (1) This session's known filters and a dead instance's inherited
        // ones, by id: the enumerate below can under-report.
        let inherited = self
            .pending_orphans
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .unwrap_or_default();
        let tracked: Vec<WfpFilterId> = {
            let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            g.values()
                .flat_map(|s| s.installed.iter().copied())
                .collect()
        };
        let tracked_deleted = tracked.len();
        let by_id: Vec<WfpFilterAction> = tracked
            .into_iter()
            .chain(inherited.into_iter().map(|raw| WfpFilterId { raw }))
            .map(WfpFilterAction::DeleteFilter)
            .collect();
        if !by_id.is_empty() {
            // Delete-missing is idempotent (FWP_E_FILTER_NOT_FOUND → ok).
            if let Err(e) = self.session.execute_wfp_plan(&by_id) {
                tracing::warn!(
                    target: "nrr::per_sid_orchestrator",
                    msg_key = "persid-apply-cleanup-delete-failed",
                    error = %e,
                    "cleanup_wfp: delete-by-tracked-id best-effort failed",
                );
            }
        }
        // (2) Enumerate-sweep for untracked orphans.
        let swept = self
            .session
            .cleanup_all()
            .map_err(|e| OrchestratorError::WfpFailed(format!("cleanup_all: {e:?}")))?;
        // Every per-SID record describes filters that no longer exist. Dropping
        // them one SID at a time keeps this in step with `remove_for_sid` —
        // including the block-id registry, which otherwise kept role-verifying
        // drops against ids the strip just deleted, and the posture-log
        // throttle, which would have read a post-cleanup re-arm as a steady
        // state and logged it at debug.
        let known: Vec<String> = {
            let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            g.keys().cloned().collect()
        };
        for sid in &known {
            self.forget_sid_state(sid);
        }
        // Anything the loop above did not cover (a latch left from a SID whose
        // record was already gone).
        self.state.lock().unwrap_or_else(|p| p.into_inner()).clear();
        self.block_all_flush_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        self.outage_hold_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        if let Some(status) = self.block_all_posture_status.as_ref() {
            status.set_outage(false);
        }
        self.fail_closed_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        // Filters are gone; drop the on-disk ledger so the next start has no
        // orphans to reap.
        if let Some(ledger) = self.ledger.as_ref() {
            ledger.clear();
        }
        tracing::info!(
            target: "nrr::per_sid_orchestrator",
            msg_key = "persid-apply-cleanup-stripped",
            tracked_deleted,
            swept,
            "cleanup_wfp: stripped all NRR WFP filters (tracked ids + enumerated sweep)",
        );
        Ok(tracked_deleted + swept)
    }

    /// Every SID's apply lock, in name order: taken together, a transaction in
    /// flight commits first, and nothing holds one of these while waiting on
    /// another, so the order cannot deadlock.
    fn every_apply_lock(&self) -> Vec<Arc<Mutex<()>>> {
        let g = self.apply_locks.lock().unwrap_or_else(|p| p.into_inner());
        let mut named: Vec<(&String, &Arc<Mutex<()>>)> = g.iter().collect();
        named.sort_by(|a, b| a.0.cmp(b.0));
        named.into_iter().map(|(_, l)| Arc::clone(l)).collect()
    }

    /// Strip only **block** (kill-switch / fail-closed) WFP filters, keeping
    /// permit filters. Used on `routing_stop_policy = persist` graceful stop
    /// (matched hosts keep egressing the secondary, but no block ever
    /// persists) and at a start nobody's leak protection asked to hold. Leaves
    /// the in-memory SID→filter map untouched: any now-gone block IDs it still
    /// references are handled idempotently on the next `remove_for_sid`.
    pub fn cleanup_wfp_blocks_only(&self) -> Result<usize, OrchestratorError> {
        self.session
            .cleanup_blocks_only()
            .map_err(|e| OrchestratorError::WfpFailed(format!("cleanup_blocks_only: {e:?}")))
    }

    /// Keep a dead instance's filters in force until the first pass has
    /// re-derived every present user's set: with leak protection on, a strip
    /// before that pass is a leak for the whole boot. The inherited ids stay in
    /// the ledger until they are settled, so a stop before then loses none;
    /// [`Self::adopt_orphans_after_pass`] settles what the pass did not claim.
    pub fn defer_orphans_to_first_pass(&self) {
        let inherited = self.ledger.as_ref().map(|l| l.read()).unwrap_or_default();
        tracing::info!(
            target: "nrr::per_sid_orchestrator",
            msg_key = "persid-apply-orphans-deferred",
            inherited = inherited.len() as u64,
            "startup: a previous instance's filters stay in force until the first pass adopts them",
        );
        *self
            .pending_orphans
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(inherited);
    }

    /// Delete the deferred inherited filters by id now, for a start that may
    /// lift them at once before any pass is wired. Returns how many ids went.
    pub fn strip_inherited_now(&self) -> usize {
        if self.engine_pending("orphan-reap") {
            return 0;
        }
        let Some(inherited) = self
            .pending_orphans
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        else {
            return 0;
        };
        if inherited.is_empty() {
            return 0;
        }
        let actions: Vec<WfpFilterAction> = inherited
            .iter()
            .map(|raw| WfpFilterAction::DeleteFilter(WfpFilterId { raw: *raw }))
            .collect();
        if let Err(e) = self.session.execute_wfp_plan(&actions) {
            tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "persid-apply-cleanup-orphans-failed",
                error = %e,
                "startup: delete of the previous instance's filters by id failed; the first pass settles them",
            );
            *self
                .pending_orphans
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(inherited);
            return 0;
        }
        self.rewrite_ledger_to_tracked();
        // "Cleared", not "reaped N": after a reboot every id is already gone.
        tracing::info!(
            target: "nrr::per_sid_orchestrator",
            msg_key = "persid-apply-cleanup-orphans-cleared",
            ledger_ids = inherited.len() as u64,
            "startup: cleared the previous instance's filter ledger (ids already gone after a reboot are a no-op)",
        );
        inherited.len()
    }

    fn tracked_raw_ids(&self) -> std::collections::BTreeSet<u64> {
        let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
        g.values()
            .flat_map(|s| s.installed.iter().map(|id| id.raw))
            .collect()
    }

    fn rewrite_ledger_to_tracked(&self) {
        if let Some(ledger) = self.ledger.as_ref() {
            let tracked: Vec<u64> = self.tracked_raw_ids().into_iter().collect();
            ledger.rewrite(&tracked);
        }
    }

    /// Delete every filter of ours the pass did not claim: the inherited ids
    /// no SID tracks, and anything else under our provider no SID tracks (the
    /// enumerate covers what the ledger missed, the ledger what the enumerate
    /// under-reports). Every SID's apply lock is held, so a filter a tick adds
    /// meanwhile is never taken for an orphan. Returns `None` when nothing was
    /// deferred.
    pub fn adopt_orphans_after_pass(&self) -> Option<usize> {
        let locks = self.every_apply_lock();
        let _held: Vec<std::sync::MutexGuard<'_, ()>> = locks
            .iter()
            .map(|l| l.lock().unwrap_or_else(|p| p.into_inner()))
            .collect();
        let inherited = self
            .pending_orphans
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()?;
        let tracked = self.tracked_raw_ids();
        let mut doomed: Vec<u64> = inherited
            .into_iter()
            .filter(|raw| !tracked.contains(raw))
            .collect();
        match self.session.enumerate_our_filters() {
            Ok(records) => {
                for record in records {
                    let raw = record.id.raw;
                    if !tracked.contains(&raw) && !doomed.contains(&raw) {
                        doomed.push(raw);
                    }
                }
            }
            Err(e) => tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "persid-apply-orphans-enumerate-failed",
                error = %e,
                "adoption: enumerate failed; only the ledger's ids are settled",
            ),
        }
        if doomed.is_empty() {
            self.rewrite_ledger_to_tracked();
            return Some(0);
        }
        let actions: Vec<WfpFilterAction> = doomed
            .iter()
            .map(|raw| WfpFilterAction::DeleteFilter(WfpFilterId { raw: *raw }))
            .collect();
        match self.session.execute_wfp_plan(&actions) {
            Ok(_) => {
                self.rewrite_ledger_to_tracked();
                tracing::info!(
                    target: "nrr::per_sid_orchestrator",
                    msg_key = "persid-apply-orphans-adopted",
                    removed = doomed.len() as u64,
                    "first pass done: a previous instance's filters nobody claimed are gone",
                )
            }
            // The unclaimed ids stay in the ledger for the next start.
            Err(e) => tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "persid-apply-orphans-adopt-failed",
                error = %e,
                "adoption: delete of unclaimed filters best-effort failed",
            ),
        }
        Some(doomed.len())
    }

    /// Recompile the filter set for `sid` after a policy/rules change. Called
    /// when a user submits `RoutePolicyUpdate` so their new bindings take
    /// effect immediately.
    ///
    /// Window-free: the original remove-then-install replace
    /// opened a measured 1.4–5.8 s hole with NO NetRuleRouter filter installed
    /// — three of those applies ran while the secondary was down, so protected
    /// destinations were reachable off-tunnel for the whole hole. An
    /// already-installed SID now takes the same MAKE-then-BREAK diff the
    /// adapter-transition reconcile uses ([`Self::reconcile_to_desired`]):
    /// adds land first, superseded filters are deleted after, unchanged
    /// filters are never touched. A never-installed SID takes the plain
    /// install path (nothing is up — no window to close), and a SID whose
    /// policy/rules disappeared tears down via the full-replace path so the
    /// empty state and its audits stay exactly as before.
    pub fn recompile_for_sid(&self, sid: &str) -> Result<usize, OrchestratorError> {
        self.settle_if_untracked(sid)?;
        let lock = self.apply_lock_for(sid);
        let _apply_guard = lock.lock().unwrap_or_else(|p| p.into_inner());
        self.recompile_for_sid_impl(sid, None)
    }

    /// Whether `sid` holds a filter set (an empty one counts).
    fn is_tracked(&self, sid: &str) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(sid)
    }

    /// A recompile of a user holding no set is an install, and whether that
    /// user should hold one is the decider's call, not the recompile's: a
    /// replan racing a tray exit used to put the departed user's set back.
    /// With a decider wired, settle membership first; the recompile then
    /// finds the set installed (or still rightly absent).
    fn settle_if_untracked(&self, sid: &str) -> Result<(), OrchestratorError> {
        if self.enforced_sids.is_none() || self.is_tracked(sid) {
            return Ok(());
        }
        self.settle().map(|_| ())
    }

    /// Full recompile with the rules supplied by the caller instead of a
    /// storage read. The activation coordinator dispatches apply BEFORE
    /// committing the active-revision pointer (all-or-nothing: revert must
    /// stay possible), so a storage read at activation time would still see
    /// the previous revision — applying "no-active-rules" at the exact
    /// activation moment and leaving the new rules to reach WFP only via the
    /// next 30 s safety tick. Window-free like [`Self::recompile_for_sid`].
    pub fn recompile_for_sid_with_rules(
        &self,
        sid: &str,
        rules: &ActiveRulesSnapshot,
    ) -> Result<usize, OrchestratorError> {
        self.settle_if_untracked(sid)?;
        let lock = self.apply_lock_for(sid);
        let _apply_guard = lock.lock().unwrap_or_else(|p| p.into_inner());
        let outcome = self.recompile_for_sid_impl(sid, Some(rules));
        self.flush_os_dns_after_rule_change(sid);
        outcome
    }

    /// Flush the OS resolver cache after the rule set changed.
    ///
    /// A host that becomes a rule host was, a moment ago, an ordinary host —
    /// and every cache on the machine still holds the REAL address it was
    /// answered with. The new rule pins those addresses to the additional
    /// route, so until something forces a re-query the application keeps
    /// dialling an address that is now pinned and gets nothing: a pin with no
    /// working path, which reads as "I added the rule and it broke the site".
    /// Flushing here is what makes the next lookup reach our resolver and come
    /// back as a virtual address (or, with fake-IP off, as an address that is
    /// routed rather than blocked).
    ///
    /// Best-effort and cheap: one call per activation, not per reconcile.
    fn flush_os_dns_after_rule_change(&self, sid: &str) {
        match self.dns_cache_control.flush_resolver_cache() {
            Ok(()) => tracing::info!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "persid-apply-dns-flush-ok",
                sid,
                "flushed OS DNS resolver cache after a rule change — hosts that just became rule hosts re-query instead of dialling the address they were answered with before",
            ),
            Err(e) => tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "persid-apply-dns-flush-failed",
                sid,
                error = %e,
                "could not flush the OS DNS resolver cache after a rule change",
            ),
        }
    }

    fn recompile_for_sid_impl(
        &self,
        sid: &str,
        rules_override: Option<&ActiveRulesSnapshot>,
    ) -> Result<usize, OrchestratorError> {
        if sid.is_empty() {
            return Err(OrchestratorError::EmptySid);
        }
        let tracked: Option<Vec<WfpFilterId>> = {
            let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            g.get(sid).map(|s| s.installed.clone())
        };
        // Never installed → nothing is up, so plain install opens no window.
        // Under a decider the install is the decider's alone: the settle that
        // ran before this lock did not name the user, or they left since.
        let Some(tracked) = tracked else {
            if self.enforced_sids.is_some() {
                tracing::info!(
                    target: "nrr::per_sid_orchestrator",
                    msg_key = "persid-apply-recompile-not-enforced",
                    sid,
                    "recompile asked for a user who holds no filter set and is not enforced right now — nothing installed",
                );
                return Ok(0);
            }
            return self.install_for_sid_with(sid, rules_override);
        };
        match self.compute_filters_for_sid(sid, true, rules_override, ComputeIntent::Apply)? {
            // Policy gone → a real teardown; the full-replace path re-records
            // the empty state and emits the same audits as before.
            ComputedFilterSet::NoPolicy => {
                let _ = self.remove_for_sid_locked(sid)?;
                self.install_for_sid_with(sid, rules_override)
            }
            ComputedFilterSet::Install(desired) => self
                .reconcile_to_desired(sid, tracked, desired.filters, "window-free recompile", true)
                .map(|(_added, live_total)| live_total),
        }
    }

    fn emit_audit(&self, sid: &str, kind: PerSidApplyAuditKind, filter_count: u32, message: &str) {
        self.quiet_since_noop
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
        self.emit_noop_audit(sid, kind, filter_count, message);
    }

    /// [`Self::emit_audit`] for a pass that changed nothing: it leaves the
    /// user marked as quiet.
    fn emit_noop_audit(
        &self,
        sid: &str,
        kind: PerSidApplyAuditKind,
        filter_count: u32,
        message: &str,
    ) {
        self.audit.emit(PerSidApplyAuditRecord {
            sid: sid.to_string(),
            kind,
            filter_count,
            message: message.to_string(),
        });
    }

    /// Reconcile orchestrator state with the active set. Called by the
    /// `ActiveSidRegistry` membership-change listener.
    /// - SIDs in `snapshot` but not yet installed → `install_for_sid`.
    /// - SIDs installed but not in `snapshot` → `remove_for_sid`.
    /// - SIDs in both → unchanged.
    ///
    /// One user's failure never stalls the others: every SID is visited, the
    /// first error comes back after the full pass, and what applied stays.
    pub fn reconcile(&self, snapshot: &[String]) -> Result<(), OrchestratorError> {
        let _membership = self
            .membership_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        self.reconcile_locked(snapshot)
    }

    /// Bring the set of enforced users to what the decider says right now.
    ///
    /// The one entry point for every writer that changes membership: the pass,
    /// a tray connect or exit, a pause or resume. The decider is consulted
    /// UNDER the membership lock, so two of them cannot act on two different
    /// ideas of who is signed in — whichever runs second sees the newer state.
    /// Returns the users decided on. An unknown answer touches nothing.
    pub fn settle(&self) -> Result<Vec<String>, OrchestratorError> {
        let _membership = self
            .membership_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let want = self.decide_membership()?;
        self.reconcile_locked(&want)?;
        Ok(want)
    }

    /// [`Self::settle`], then recompile every set still held — for a change
    /// that alters what each set contains (a fake-IP stack transition) and
    /// must not, on its way, put back a set the decider has just withdrawn.
    pub fn settle_and_recompile(&self) -> Result<(), OrchestratorError> {
        let _membership = self
            .membership_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let want = self.decide_membership()?;
        self.reconcile_locked(&want)?;
        let mut first_err = None;
        for sid in self.installed_sids() {
            let lock = self.apply_lock_for(&sid);
            let _apply_guard = lock.lock().unwrap_or_else(|p| p.into_inner());
            if let Err(e) = self.recompile_for_sid_impl(&sid, None) {
                tracing::error!(
                    target: "nrr::per_sid_orchestrator",
                    msg_key = "persid-apply-settle-recompile-failed",
                    sid = %sid,
                    error = %e,
                    "recompile after membership settle failed",
                );
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    fn decide_membership(&self) -> Result<Vec<String>, OrchestratorError> {
        let Some(decider) = self.enforced_sids.as_ref() else {
            // Without a decider the installed set is the answer: nothing to do.
            return Ok(self.installed_sids());
        };
        decider().map_err(|reason| {
            tracing::error!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "persid-apply-membership-unknown",
                error = %reason,
                "who holds a filter set could not be decided — leaving every set as it is",
            );
            OrchestratorError::MembershipUnknown(reason)
        })
    }

    fn reconcile_locked(&self, snapshot: &[String]) -> Result<(), OrchestratorError> {
        // Before the adoption below: an inherited set is settled only by a pass
        // that really ran.
        if self.engine_pending("reconcile") {
            return Ok(());
        }
        let want: std::collections::BTreeSet<String> = snapshot.iter().cloned().collect();
        let have: std::collections::BTreeSet<String> = {
            let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            g.keys().cloned().collect()
        };
        let mut fresh = std::collections::BTreeSet::new();
        // A user whose book or policy does not read (a persistent failure) must
        // not keep the next one unprotected or a departed one's set in the
        // engine: the pass visits every SID and reports the first failure after.
        let mut first_err: Option<OrchestratorError> = None;
        let mut note = |sid: &str, stage: &'static str, e: OrchestratorError| {
            tracing::error!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "persid-apply-reconcile-sid-failed",
                sid = %sid,
                stage,
                error = %e,
                "membership pass: one user failed; the others are still visited",
            );
            if first_err.is_none() {
                first_err = Some(e);
            }
        };
        for sid in want.difference(&have) {
            match self.install_for_sid(sid) {
                Ok(_) => {
                    fresh.insert(sid.clone());
                }
                Err(e) => note(sid, "install", e),
            }
        }
        for sid in have.difference(&want) {
            if let Err(e) = self.remove_for_sid(sid) {
                note(sid, "remove", e);
            }
        }
        let outcome = self.follow_route_table_owner(&fresh);
        // The first pass over somebody present is what a deferred start waits
        // for; a pass over nobody claims nothing and settles nothing. A user
        // whose install failed tracks nothing, so the blocks they inherited
        // are their only protection until their book reads: left standing.
        if !want.is_empty() && outcome.is_ok() && first_err.is_none() {
            self.adopt_orphans_after_pass();
        }
        outcome.and(first_err.map_or(Ok(()), Err))
    }

    /// Delete filters from `previous` that `kept` no longer contains. A
    /// full-replace install only adds, so without this pass a
    /// superseded filter stays live in the engine while dropping out of our
    /// accounting: it keeps dropping traffic that no recompute can explain and
    /// no teardown can reach. Best-effort, and deleting a missing id is
    /// idempotent — an engine error must not fail an install whose filters are
    /// already committed.
    fn delete_superseded_filters(&self, sid: &str, previous: &[WfpFilterId], kept: &[WfpFilterId]) {
        let kept_ids: std::collections::HashSet<u64> = kept.iter().map(|id| id.raw).collect();
        let superseded: Vec<WfpFilterId> = previous
            .iter()
            .copied()
            .filter(|id| !kept_ids.contains(&id.raw))
            .collect();
        if superseded.is_empty() {
            return;
        }
        let actions: Vec<WfpFilterAction> = superseded
            .iter()
            .copied()
            .map(WfpFilterAction::DeleteFilter)
            .collect();
        match self.session.execute_wfp_plan(&actions) {
            Ok(_) => tracing::info!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "persid-apply-install-removed-superseded",
                sid,
                removed = superseded.len() as u64,
                "install: removed filters the new set supersedes",
            ),
            Err(e) => tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "persid-apply-delete-superseded-install-failed",
                sid,
                superseded = superseded.len() as u64,
                error = %e,
                "install: delete of superseded filters best-effort failed",
            ),
        }
    }

    /// Log an install's retire pass and return what the SID now carries: the
    /// filters just installed plus every previous one the pass did not retire,
    /// which is still in the engine.
    fn tracked_after_install(
        &self,
        sid: &str,
        previous: &[WfpFilterId],
        installed: &[WfpFilterId],
        outcome: &WfpReplaceOutcome,
    ) -> Vec<WfpFilterId> {
        let retired: HashSet<u64> = outcome.retired.iter().map(|id| id.raw).collect();
        let mut tracked = installed.to_vec();
        let mut have: HashSet<u64> = installed.iter().map(|id| id.raw).collect();
        for id in previous {
            if !retired.contains(&id.raw) && have.insert(id.raw) {
                tracked.push(*id);
            }
        }
        let kept = (tracked.len() - installed.len()) as u64;
        match &outcome.retire_held {
            None if !retired.is_empty() => tracing::info!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "persid-apply-install-removed-superseded",
                sid,
                removed = retired.len() as u64,
                "install: removed filters the new set supersedes",
            ),
            None => {}
            Some(RetireHeld::ReplacementSkipped) => tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "persid-apply-delete-deferred",
                sid,
                deferred = kept,
                "install: deferred delete of superseded filters — a replacement block add was skipped (fail-safe over-coverage)",
            ),
            Some(RetireHeld::Failed(e)) => tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "persid-apply-delete-superseded-install-failed",
                sid,
                superseded = kept,
                error = %e,
                "install: delete of superseded filters failed — kept tracked",
            ),
        }
        tracked
    }

    fn upsert_state(&self, sid: &str, installed: Vec<WfpFilterId>) {
        // No destinations, so nothing to sweep either way.
        self.upsert_state_with_destinations(sid, installed, Vec::new(), Vec::new(), false);
    }

    /// Publish the addresses this filter set PERMITS, so the resolver can tell
    /// "the policy carries this address" from "a name once resolved to it".
    ///
    /// Permits only: [`Self::coverage_of`] names every address the set touches,
    /// blocks included — the DoH lockdown alone names ~85 — and answering a
    /// client with a blocked address is the opposite of the question being
    /// asked here.
    // `pub(super)` because the impl and its tests are now separate files.
    pub(super) fn publish_enforced_addresses(sid: &str, filters: &[WfpFilterSpec]) {
        let permitted = filters
            .iter()
            .filter(|spec| spec.action == WfpAction::Permit)
            .flat_map(|spec| {
                spec.remote_ip
                    .into_iter()
                    .chain(spec.remote_ip_set.iter().copied())
            });
        crate::enforced_addresses::global_enforced_addresses().publish(sid, permitted);
    }

    /// What a filter set covers: the destinations it scopes to (deduplicated,
    /// in emission order, both families) and whether the leak guard had a
    /// resolved tunnel when it was built. Both are read off the filters, so
    /// the install and the reconcile path cannot derive them differently.
    ///
    /// Only host-scoped filters contribute here; a rule's network is read by
    /// [`Self::rule_networks_of`], since a subnet filter is mostly an exemption.
    pub(super) fn coverage_of(filters: &[WfpFilterSpec]) -> (Vec<std::net::IpAddr>, bool) {
        let mut seen = std::collections::HashSet::new();
        let destinations = filters
            .iter()
            .flat_map(Self::hosts_of)
            .filter(|ip| seen.insert(*ip))
            .collect();
        // The leak-guard emits an egress-via-secondary permit only when it has a
        // resolved adapter, so this is the tunnel's state without asking the OS
        // a second time.
        let secondary_resolved = filters.iter().any(|f| f.local_interface_luid.is_some());
        (destinations, secondary_resolved)
    }

    /// Every single host a filter names, v4 then v6.
    fn hosts_of(spec: &WfpFilterSpec) -> impl Iterator<Item = std::net::IpAddr> + '_ {
        spec.remote_ip
            .into_iter()
            .chain(spec.remote_ip_set.iter().copied())
            .map(std::net::IpAddr::V4)
            .chain(
                spec.remote_ip_set_v6
                    .iter()
                    .copied()
                    .map(std::net::IpAddr::V6),
            )
    }

    pub(super) fn upsert_state_with_destinations(
        &self,
        sid: &str,
        installed: Vec<WfpFilterId>,
        destinations: Vec<std::net::IpAddr>,
        networks: Vec<nrr_shared::ip_block::IpBlock>,
        secondary_resolved: bool,
    ) {
        let mut g = self.state.lock().unwrap_or_else(|p| p.into_inner());
        g.insert(
            sid.to_string(),
            PerSidFilterSet {
                sid: sid.to_string(),
                installed,
                destinations,
                secondary_resolved,
                networks,
            },
        );
    }

    /// The networks `sid`'s rules pin that this filter set carries. The set's
    /// other subnet filters are exemptions (LAN, link-local), which no rule
    /// changed, so only a network the rule book names counts. Empty — one map
    /// miss — while the book holds none.
    pub(super) fn rule_networks_of(
        sid: &str,
        filters: &[WfpFilterSpec],
    ) -> Vec<nrr_shared::ip_block::IpBlock> {
        let Some(index) = crate::fake_ip::global_rule_networks().for_principal(sid) else {
            return Vec::new();
        };
        let named = index.networks();
        let mut out: Vec<nrr_shared::ip_block::IpBlock> = filters
            .iter()
            .filter_map(|spec| {
                let (net, prefix) = spec.remote_subnet?;
                nrr_shared::ip_block::IpBlock::new(std::net::IpAddr::V4(net), prefix)
            })
            .filter(|block| named.contains(block))
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// The course of each destination `filters` name, read the way the engine
    /// arbitrates them: an egress-conditional permit for the additional link
    /// outranks every rule band, so its destination is the tunnel's; a block
    /// with no such permit leaves it no course; plain permits alone put it on
    /// the main link. Networks count only when the rule book names them.
    pub(super) fn courses_of(
        filters: &[WfpFilterSpec],
        rule_networks: &[nrr_shared::ip_block::IpBlock],
    ) -> crate::routed_host_flow_refresh::Courses {
        use crate::routed_host_flow_refresh::{Course, Courses};
        #[derive(Default, Clone, Copy)]
        struct Seen {
            via_secondary: bool,
            blocked: bool,
        }
        impl Seen {
            fn mark(&mut self, spec: &WfpFilterSpec) {
                match spec.action {
                    WfpAction::Permit if spec.local_interface_luid.is_some() => {
                        self.via_secondary = true;
                    }
                    WfpAction::Permit => {}
                    WfpAction::Block => self.blocked = true,
                }
            }
            fn course(self) -> Option<Course> {
                if self.via_secondary {
                    Some(Course::Secondary)
                } else if self.blocked {
                    None
                } else {
                    Some(Course::Primary)
                }
            }
        }
        let mut hosts: std::collections::HashMap<std::net::IpAddr, Seen> =
            std::collections::HashMap::new();
        let mut networks: std::collections::HashMap<nrr_shared::ip_block::IpBlock, Seen> =
            std::collections::HashMap::new();
        for spec in filters {
            for ip in Self::hosts_of(spec) {
                hosts.entry(ip).or_default().mark(spec);
            }
            let named = spec
                .remote_subnet
                .and_then(|(net, prefix)| {
                    nrr_shared::ip_block::IpBlock::new(std::net::IpAddr::V4(net), prefix)
                })
                .or_else(|| {
                    spec.remote_subnet_v6.and_then(|(net, prefix)| {
                        nrr_shared::ip_block::IpBlock::new(std::net::IpAddr::V6(net), prefix)
                    })
                })
                .filter(|block| rule_networks.contains(block));
            if let Some(block) = named {
                networks.entry(block).or_default().mark(spec);
            }
        }
        let mut courses = Courses::default();
        for (host, seen) in hosts {
            if let Some(course) = seen.course() {
                courses.insert_host(host, course);
            }
        }
        for (network, seen) in networks {
            if let Some(course) = seen.course() {
                courses.insert_network(network, course);
            }
        }
        courses
    }

    /// Tear down live connections to destinations this install just started
    /// enforcing, and report which ones those were.
    ///
    /// Why it cannot wait for the drop: a socket opened before the rule existed
    /// keeps the interface it was bound to for life. On a newly pinned
    /// destination the connect-time filters never see it again, so the
    /// half-loaded page the user just added a rule for goes on using the wrong
    /// link until something breaks it.
    ///
    /// Only additions count — re-listing a destination that was already
    /// enforced would tear down the very connections the previous teardown
    /// established — with one exception: when the additional adapter just
    /// became resolvable, every destination steered onto it is swept. Its
    /// addresses did not change while the tunnel was down, so the "new
    /// destinations" rule finds nothing, and the sockets the browser opened
    /// over the main link would ride it until they died on their own.
    ///
    /// Only `sid`'s own connections go, none to an address a direct host
    /// shares, none riding a link that is neither of `sid`'s, and none already
    /// on the link the plan assigns: [`crate::routed_host_flow_refresh::flows_to_reset`].
    pub(super) fn tear_down_flows_to_new_destinations(
        &self,
        sid: &str,
        filters: &[WfpFilterSpec],
        destinations: &[std::net::IpAddr],
        networks: &[nrr_shared::ip_block::IpBlock],
        secondary_resolved: bool,
    ) {
        use crate::routed_host_flow_refresh::Course;
        let Some(reset) = self.stale_flow_reset.as_ref() else {
            return;
        };
        let (previous, previous_networks, was_resolved) = {
            let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            match g.get(sid) {
                Some(state) => (
                    state
                        .destinations
                        .iter()
                        .copied()
                        .collect::<std::collections::HashSet<_>>(),
                    state.networks.clone(),
                    state.secondary_resolved,
                ),
                None => (std::collections::HashSet::new(), Vec::new(), false),
            }
        };
        let tunnel_came_up = secondary_resolved && !was_resolved;
        // Walked only on the edge or once something is connected: this runs on
        // every reconcile, and the courses read every filter.
        let mut courses = tunnel_came_up.then(|| Self::courses_of(filters, networks));
        let (hosts, nets): (Vec<std::net::IpAddr>, Vec<nrr_shared::ip_block::IpBlock>) =
            match courses.as_ref() {
                Some(courses) => (
                    destinations
                        .iter()
                        .copied()
                        .filter(|ip| courses.of(*ip) == Some(Course::Secondary))
                        .collect(),
                    networks
                        .iter()
                        .copied()
                        .filter(|net| courses.of_network(*net) == Some(Course::Secondary))
                        .collect(),
                ),
                None => (
                    destinations
                        .iter()
                        .copied()
                        .filter(|ip| !previous.contains(ip))
                        .collect(),
                    networks
                        .iter()
                        .copied()
                        .filter(|net| !previous_networks.contains(net))
                        .collect(),
                ),
            };
        let fresh = hosts.len() + nets.len();
        let Some(outcome) = crate::routed_host_flow_refresh::reset_owner_flows(
            reset.as_ref(),
            self.fqdn_cache.as_ref(),
            sid,
            &nrr_platform_api::fake_ip::stale_flows::FlowTargets::new(hosts, nets),
            || crate::routed_host_flow_refresh::FlowPaths {
                links: (self.flow_links_resolver)(sid, &(self.machine_reader)()),
                courses: courses
                    .take()
                    .unwrap_or_else(|| Self::courses_of(filters, networks)),
            },
        ) else {
            return;
        };
        let decision = &outcome.decision;
        let torn_down = outcome.torn_down;
        if torn_down > 0 {
            let cause = if tunnel_came_up {
                crate::flow_reset_log::ResetCause::TunnelCameUp
            } else {
                crate::flow_reset_log::ResetCause::NewDestination
            };
            crate::flow_reset_log::log_reset_flows(Some(sid), &decision.reset, |_| (None, cause));
            tracing::info!(
                target: "nrr::per_sid_orchestrator",
                msg_key = "persid-apply-flows-torn-down",
                sid,
                torn_down,
                destinations = fresh,
                tunnel_came_up,
                kept_shared = decision.kept_shared,
                kept_other_owner = decision.kept_other_owner,
                kept_unknown_owner = decision.kept_unknown_owner,
                kept_other_link = decision.kept_other_link,
                kept_on_course = decision.kept_on_course,
                "tore down connections that predate the route now in force (a tunnel that just came up, or destinations this activation started enforcing) — the application reconnects over that route instead of finishing on the old link",
            );
        }
    }
}

/// Past this many new host pins one table plan is cheaper than as many scoped
/// ones, and a batch that large is a rule change, not a learnt address.
const SCOPED_ROUTE_SYNC_MAX_HOSTS: usize = 32;

/// Run the route-before-block hook. A failure does not hold the block back:
/// an unrouted pin is over-coverage until the retry its builder scheduled.
fn run_route_sync(route_sync: &RouteSyncHook) {
    if let Err(error) = route_sync() {
        tracing::warn!(
            target: "nrr::route-coordinator",
            msg_key = "svc-persid-route-sync-before-pin-failed",
            error = %error,
            "route sync before installing new destination pins failed",
        );
    }
}
