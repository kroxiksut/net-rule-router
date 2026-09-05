//! Applying a plan: install, reconcile, remove, clean up.
//!
//! The other half of the orchestrator's impl. The plan (what filters a policy
//! compiles to) lives in `super::plan`; this is what happens to the kernel once
//! the plan exists — including the locking that keeps two triggers for one SID
//! from interleaving.
//!
//! Behaviour is unchanged: the same methods, in the same order, verbatim.

use super::*;

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
    pub fn filter_count_for(&self, sid: &str) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .map(|s| s.installed.len())
            .unwrap_or(0)
    }

    /// Install (or reinstall) the SID's filter set from the latest
    /// policy snapshot. Equivalent to a full
    /// `remove_for_sid` + `install_for_sid` cycle, modulo idempotent
    /// `WfpFilterAdd` (FWP_E_DUPLICATE_OBJECT → ignored).
    ///
    /// filters now come from the WFP codegen
    /// ([`crate::wfp_codegen::generate_filters`]) which iterates the
    /// active rule book × FQDN cache, not from a placeholder permit-
    /// per-binding shape. The per-SID `PerSidPolicySnapshot` is still
    /// loaded — its presence/absence governs whether the orchestrator
    /// processes the SID at all — but the bindings themselves drive
    /// the Windows routing table (block 16.12.A.4+), not the WFP
    /// filter list.
    /// confirm each id in
    /// `installed_ids` is actually live in WFP after an install. Missing ids
    /// are PHANTOMS (recorded installed but never materialised). Logs the
    /// outcome; returns `Some(phantom_count)` on a successful enumeration and
    /// `None` when the live filters could not be read (verification skipped).
    /// Best-effort — the production caller ignores the return (the check is a
    /// safety net, not a gate); the value exists so tests can assert on it.
    /// `expected` is the count we claimed installed.
    // `pub(super)` because the impl and its tests are now separate files.
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
                    sid,
                    "verify-after-apply: could not enumerate live WFP filters (skipping check): {e:?}",
                );
                None
            }
        }
    }

    /// Take this SID's apply lock. Held for the whole compute-and-apply, so two
    /// triggers cannot interleave and leave the engine holding a set neither of
    /// them decided on.
    // `pub(super)` because the impl and its tests are now separate files.
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

    /// [`Self::install_for_sid`] with an optional caller-supplied rules
    /// snapshot (block 16.HW-0716 P0.2 — see `compute_filters_for_sid`).
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
            ComputedFilterSet::NoActiveRules => {
                return Ok(SidApplyPreview {
                    sid: sid.to_string(),
                    enforceable: false,
                    filters: 0,
                    installed_now,
                    additions: 0,
                    removals: installed_now,
                    colliding_filter_ids: Vec::new(),
                    unresolved_apps: Vec::new(),
                    secondary_binding_unresolved: false,
                })
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
            && (self.kill_switch_resolver)(sid).is_none();
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

    fn install_for_sid_with(
        &self,
        sid: &str,
        rules_override: Option<&ActiveRulesSnapshot>,
    ) -> Result<usize, OrchestratorError> {
        if sid.is_empty() {
            return Err(OrchestratorError::EmptySid);
        }
        // the admin baseline is never enforced as its
        // own machine-wide filter set. It only ever reaches the wire as a
        // per-user read-through (a real `S-…` SID resolves the baseline
        // when it has no revision of its own). When NOBODY is logged in,
        // the active-SID set is empty, so `reconcile` installs nothing and
        // routing is passthrough — the baseline never gets a filter set of
        // its own. This guard makes that invariant explicit.
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
        // `compute_filters_for_sid` path. No-policy / no-active-rules install
        // nothing but still record the SID so a later on_disconnect / recompile
        // stays consistent.
        let filters =
            match self.compute_filters_for_sid(sid, true, rules_override, ComputeIntent::Apply)? {
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
                ComputedFilterSet::NoActiveRules => {
                    self.delete_superseded_filters(sid, &previously_installed, &[]);
                    self.upsert_state(sid, Vec::new());
                    let kind = if was_known {
                        PerSidApplyAuditKind::Updated
                    } else {
                        PerSidApplyAuditKind::Applied
                    };
                    self.emit_audit(sid, kind, 0, "no-active-rules");
                    return Ok(0);
                }
                ComputedFilterSet::Install(plan) => plan.filters,
            };
        // Route before block — same ordering invariant the reconcile enforces
        // (see `reconcile_to_desired`). A cold install lands the whole pin set
        // at once, so every destination it covers must already be routed.
        if let Some(route_sync) = self
            .route_sync
            .as_ref()
            .filter(|_| filters.iter().any(is_destination_block))
        {
            route_sync();
        }
        let actions: Vec<WfpFilterAction> = filters
            .iter()
            .cloned()
            .map(WfpFilterAction::AddFilter)
            .collect();
        let mode = (self.failure_mode)();
        let apply_outcome = match self.session.execute_wfp_plan_resilient(&actions, mode) {
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
        // BREAK after MAKE, the same ordering `reconcile_to_desired` uses: the
        // replacement set is already up, so dropping what it supersedes cannot
        // open a window.
        self.delete_superseded_filters(sid, &previously_installed, &installed_ids);
        // re-read our LIVE WFP filters
        // and confirm every id we just recorded as installed is actually
        // present in the engine. A missing id = a PHANTOM: counted as installed
        // but never in WFP — the exact 0715 bug class (a mis-classified error
        // silently swallowed the add while `installed=N` still incremented). A
        // mismatch is logged LOUD (error) so a future regression is caught in
        // NDJSON instead of trusting `installed=N`. Best-effort: an enumeration
        // failure never fails the apply — verification is a safety net, not a
        // gate, and the filters are already committed by this point. Runs only
        // on a real install (this path), not on the frequent coverage-reconcile
        // tick, so the one extra enumeration per policy change is cheap.
        self.verify_installed_filters_live(sid, &installed_ids, count);
        // P3-followup — persist the ids so a hard-kill's orphans reap by id.
        if let Some(ledger) = self.ledger.as_ref() {
            ledger.record(&installed_ids);
        }
        // Destinations this set scopes to, deduplicated. Compared against the
        // previous install BEFORE the state is replaced.
        let (destinations, secondary_resolved) = Self::coverage_of(&filters);
        self.tear_down_flows_to_new_destinations(sid, &destinations, secondary_resolved);
        Self::publish_enforced_addresses(sid, &filters);
        self.upsert_state_with_destinations(sid, installed_ids, destinations, secondary_resolved);
        let kind = if was_known {
            PerSidApplyAuditKind::Updated
        } else {
            PerSidApplyAuditKind::Applied
        };
        if apply_outcome.skipped.is_empty() {
            // a clean install used to be audit-only; the 0716
            // run had to be diagnosed from the ABSENCE of log lines. Log success
            // at info so "did enforcement arm?" is answerable from NDJSON alone.
            tracing::info!(
                target: "nrr::per_sid_orchestrator",
                sid,
                installed = count,
                "per-SID WFP filter set installed",
            );
            self.emit_audit(sid, kind, count as u32, "ok");
        } else {
            let n = apply_outcome.skipped.len();
            tracing::warn!(
                target: "nrr::per_sid_orchestrator",
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

    /// window-free, make-before-break reconcile of
    /// the per-SID filter set against the freshly-resolved secondary LUID.
    ///
    /// This both GROWS coverage additively (freshly-observed secondary IPs, the
    /// block 16.HW-0704 P1 case) AND reaps the tracked filters no longer desired
    /// — critically the **dead-LUID egress permits** left after a secondary adapter reconnect.
    /// (It replaces the earlier add-only `refresh_secondary_coverage`, which
    /// could grow but never reap.) The permit id
    /// now folds the LUID (see `killswitch_codegen::permit_luid_seg`), so a new
    /// LUID mints a new permit id; the stale old-LUID id is superseded and
    /// deleted here. (A WFP filter is immutable by key, so the new permit MUST
    /// be a new id — an add-only path would swallow the collision and the stale
    /// permit would stick, blocking legit secondary-adapter traffic until a policy recompile.)
    ///
    /// Ordering is strictly **ADD-then-DELETE** so the kill-switch is never
    /// briefly lifted. Across a **pure LUID flip** (reconnect) every BLOCK keeps
    /// a LUID-free stable id and stays in both the desired and tracked sets, so
    /// only the dead-LUID permits are deleted (deleting a permit only tightens —
    /// fail-safe). Across an **up↔down mode transition** a block's SHAPE changes
    /// (`block_off_secondary` ↔ `ale_block`, `catch_all_block` ↔ `ale_block`),
    /// so a superseded block CAN enter the delete set — there, safety rests on
    /// (a) add-before-delete installing the replacement block first, and (b) the
    /// delete pass being **deferred whenever a replacement BLOCK add was skipped**
    /// (best-effort), so a block is never removed while its replacement is not yet
    /// up. A skipped PERMIT does not defer the delete (skipping a permit only
    /// tightens), so a pure LUID flip still reaps the dead-LUID permits (gap #2)
    /// even if an app-permit is unmaterializable. The delete set is derived purely
    /// from the desired-vs-tracked id diff — never from stored metadata, which the
    /// untyped id set lacks.
    ///
    /// Correct across every secondary adapter transition (the diff drives it): reconnect
    /// (swap dead permit → live permit), up→down fail-closed (add block-all,
    /// then drop the per-dest set), up→down fail-open (drop the guard so traffic
    /// egresses the primary, the chosen posture), down→up (re-arm). A no-op
    /// (returns 0) when desired == tracked, so it is safe on every DNS-warmup /
    /// adapter / 30 s safety tick. Only acts on an already-installed SID (an
    /// inactive / not-yet-installed SID is owned by [`Self::reconcile`]).
    /// Returns the count of filters added.
    pub fn reconcile_secondary_coverage(&self, sid: &str) -> Result<usize, OrchestratorError> {
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
            // No policy / no active rules → nothing desired; leave the set as-is
            // (full teardown is owned by the stop / policy-change paths).
            ComputedFilterSet::NoPolicy | ComputedFilterSet::NoActiveRules => return Ok(0),
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
            if audit_no_op {
                self.emit_audit(
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
        if let Some(route_sync) = self
            .route_sync
            .as_ref()
            .filter(|_| to_add.iter().any(is_destination_block))
        {
            route_sync();
        }

        // (1) MAKE: add the new filters FIRST — window-free (blocks untouched;
        // the new-LUID permit goes up before the stale one comes down).
        let mut installed_ids: Vec<WfpFilterId> = Vec::new();
        // Gates the delete pass below (leak-safety — see the BREAK comment).
        let mut block_replacement_skipped = false;
        if !to_add.is_empty() {
            let actions: Vec<WfpFilterAction> = to_add
                .iter()
                .cloned()
                .map(WfpFilterAction::AddFilter)
                .collect();
            let mode = (self.failure_mode)();
            let apply_outcome = match self.session.execute_wfp_plan_resilient(&actions, mode) {
                Ok(o) => o,
                Err(e) => {
                    let msg = format!("reconcile coverage for {sid}: {e:?}");
                    self.emit_audit(sid, PerSidApplyAuditKind::Failed, 0, &msg);
                    return Err(OrchestratorError::WfpFailed(msg));
                }
            };
            let skipped: std::collections::HashSet<u64> =
                apply_outcome.skipped.iter().map(|s| s.id.raw).collect();
            // A skipped PERMIT never uncovers a destination (skipping a permit
            // only tightens — the block half stays); only a skipped BLOCK can
            // leave a destination without a covering block. So the BREAK is
            // unsafe iff a *destination-covering* BLOCK add was skipped this tick.
            //
            // the gate previously armed on ANY skipped block, including
            // an app-scoped block (ALE app-id, no remote) whose exe did not
            // resolve (0x80320002). Such a block covers no destination IP, so
            // skipping it cannot uncover anything — yet when the exe is
            // *persistently* absent (e.g. 53 app rules for uninstalled apps on
            // the 0718 boot run) it re-armed the gate every 2 s tick, so the
            // superseded-PERMIT delete pass was deferred forever and the
            // over-coverage backlog grew without bound. Excluding app-only block
            // skips lets the stale permits reap while still deferring on a real
            // destination-block replacement miss (the actual leak case).
            block_replacement_skipped = to_add.iter().any(|s| {
                s.action == WfpAction::Block && skipped.contains(&s.id.raw) && !is_app_only_block(s)
            });
            installed_ids = to_add
                .iter()
                .map(|s| s.id)
                .filter(|id| !skipped.contains(&id.raw))
                .collect();
            if let Some(ledger) = self.ledger.as_ref() {
                ledger.record(&installed_ids);
            }
        }

        // (2) BREAK: delete the superseded filters by id — but defer when a BLOCK
        // replacement was skipped this tick. A pure LUID flip keeps every block id
        // stable, so `to_add` is permits-only and `to_remove` is just dead-LUID
        // permits (inert — deleting them only tightens); `block_replacement_
        // skipped` is false → the BREAK runs and gap #2 reaps the stale permits
        // EVEN when an app-permit is unmaterializable. But an up↔down mode
        // transition swaps a block's SHAPE (`block_off_secondary` ↔ `ale_block`,
        // `catch_all_block` ↔ `ale_block`, different ids), so a superseded BLOCK
        // can land in `to_remove`; if its replacement BLOCK's ADD was best-effort-
        // SKIPPED (e.g. a fail-closed app-block whose exe app-id did not resolve),
        // deleting the old block would UNCOVER the destination → leak. So when any
        // block add was skipped, defer the whole delete pass: harmless over-
        // coverage that the next tick reconciles once the block materialises.
        // Delete-missing is idempotent; the batch is best-effort.
        let removed: Vec<WfpFilterId> = if !to_remove.is_empty() && !block_replacement_skipped {
            let actions: Vec<WfpFilterAction> = to_remove
                .iter()
                .copied()
                .map(WfpFilterAction::DeleteFilter)
                .collect();
            match self.session.execute_wfp_plan(&actions) {
                Ok(()) => to_remove.clone(),
                Err(e) => {
                    tracing::warn!(
                        target: "nrr::per_sid_orchestrator",
                        sid,
                        deferred = to_remove.len() as u64,
                        "reconcile coverage: delete of superseded filters best-effort failed — keeping them tracked so the next tick retries: {e:?}",
                    );
                    // The batch stops at its first failure, so an unknown suffix
                    // of these is still installed. Reporting the whole set as
                    // removed dropped them from the tracked ids — and a filter
                    // nobody tracks is one `cleanup_wfp` cannot delete by id.
                    // A delete of something already gone is idempotent, so
                    // retrying the whole batch next tick costs nothing.
                    Vec::new()
                }
            }
        } else {
            if !to_remove.is_empty() {
                tracing::warn!(
                    target: "nrr::per_sid_orchestrator",
                    sid,
                    deferred = to_remove.len() as u64,
                    "reconcile coverage: deferred delete of superseded filters — a replacement block add was skipped this tick (fail-safe over-coverage; retry next tick)",
                );
            }
            Vec::new()
        };

        // (3) Update the tracked set = (tracked − removed) ∪ installed. `removed`
        // reflects what was actually deleted (empty when the delete was deferred),
        // so deferred ids stay tracked and are retried on the next tick.
        //
        // The coverage fields travel with it. This path used to leave whatever
        // the last install wrote, so the record described a set this pass had
        // already changed: the addresses it started enforcing were never swept
        // (sockets already open to them finished on the old link), and the next
        // install then saw those same addresses as new and swept connections
        // that had just been re-established. `secondary_resolved` drifted the
        // same way, turning a tunnel that had been up all along into one that
        // "just came up" — a sweep of every pinned destination for nothing.
        let (destinations, secondary_resolved) = Self::coverage_of(&desired);
        self.tear_down_flows_to_new_destinations(sid, &destinations, secondary_resolved);
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
            });
            entry.destinations = destinations;
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
        // (1) Delete this session's known filters by id.
        let tracked: Vec<WfpFilterId> = {
            let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            g.values()
                .flat_map(|s| s.installed.iter().copied())
                .collect()
        };
        let tracked_deleted = tracked.len();
        if !tracked.is_empty() {
            let actions: Vec<WfpFilterAction> = tracked
                .into_iter()
                .map(WfpFilterAction::DeleteFilter)
                .collect();
            // Delete-missing is idempotent (FWP_E_FILTER_NOT_FOUND → ok).
            if let Err(e) = self.session.execute_wfp_plan(&actions) {
                tracing::warn!(
                    target: "nrr::per_sid_orchestrator",
                    "cleanup_wfp: delete-by-tracked-id best-effort failed: {e:?}",
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
        // record was already gone). No flush here — teardown itself unblocks
        // nothing the OS cache could hide.
        self.state.lock().unwrap_or_else(|p| p.into_inner()).clear();
        self.block_all_flush_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        self.fail_closed_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        // P3-followup — filters are gone; drop the on-disk ledger so the next
        // start has no orphans to reap.
        if let Some(ledger) = self.ledger.as_ref() {
            ledger.clear();
        }
        tracing::info!(
            target: "nrr::per_sid_orchestrator",
            tracked_deleted,
            swept,
            "cleanup_wfp: stripped all NRR WFP filters (tracked ids + enumerated sweep)",
        );
        Ok(tracked_deleted + swept)
    }

    /// reap a hard-killed PRIOR instance's
    /// orphaned filters at startup. Reads the on-disk ledger (ids the dead
    /// process recorded before it was killed) and deletes each **by id** — no
    /// dependence on `wfp_enumerate_our_filters`, so it works even when
    /// enumerate under-reports (the `stripped_filters:0` anomaly). Idempotent
    /// (delete-missing is a no-op). Drains + truncates the ledger. Returns the
    /// number of ids reaped. No-op (returns 0) when no ledger is wired.
    pub fn cleanup_persisted_orphans(&self) -> usize {
        let Some(ledger) = self.ledger.as_ref() else {
            return 0;
        };
        let ids = ledger.drain();
        if ids.is_empty() {
            return 0;
        }
        let actions: Vec<WfpFilterAction> = ids
            .iter()
            .map(|raw| WfpFilterAction::DeleteFilter(WfpFilterId { raw: *raw }))
            .collect();
        if let Err(e) = self.session.execute_wfp_plan(&actions) {
            tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                "cleanup_persisted_orphans: delete-by-id best-effort failed: {e:?}",
            );
        } else {
            // Deliberately not phrased as "reaped N filters": delete-by-id is a
            // no-op for an id that is already gone, and after a reboot every id
            // in the ledger is (WFP drops non-persistent filters on shutdown).
            // The old wording made a clean boot read like it had just cleared
            // thousands of live blocks.
            tracing::info!(
                target: "nrr::per_sid_orchestrator",
                ledger_ids = ids.len() as u64,
                "startup: cleared the previous instance's filter ledger (ids already gone after a reboot are a no-op)",
            );
        }
        ids.len()
    }

    /// Strip only **block** (kill-switch / fail-closed) WFP filters, keeping
    /// permit filters. Used on `routing_stop_policy = persist` graceful stop
    /// (matched hosts keep egressing the secondary, but no block ever
    /// persists) and — unconditionally — at service startup so an orphaned
    /// kill-switch left by a hard-killed prior instance can never lock the
    /// user out. Leaves the in-memory SID→filter map untouched: any now-gone
    /// block IDs it still references are handled idempotently on the next
    /// `remove_for_sid` (delete-missing → success).
    pub fn cleanup_wfp_blocks_only(&self) -> Result<usize, OrchestratorError> {
        self.session
            .cleanup_blocks_only()
            .map_err(|e| OrchestratorError::WfpFailed(format!("cleanup_blocks_only: {e:?}")))
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
        let lock = self.apply_lock_for(sid);
        let _apply_guard = lock.lock().unwrap_or_else(|p| p.into_inner());
        self.recompile_for_sid_impl(sid, None)
    }

    /// full recompile with the rules supplied by the
    /// caller instead of a storage read. The activation coordinator dispatches
    /// apply BEFORE committing the active-revision pointer (all-or-nothing:
    /// revert must stay possible), so `recompile_for_sid` at activation time
    /// still saw the PREVIOUS revision — the 0716 run applied
    /// "no-active-rules" at the exact activation moment and the new rules only
    /// reached WFP via the next 30 s safety tick. Window-free like
    /// [`Self::recompile_for_sid`].
    pub fn recompile_for_sid_with_rules(
        &self,
        sid: &str,
        rules: &ActiveRulesSnapshot,
    ) -> Result<usize, OrchestratorError> {
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
                sid,
                "flushed OS DNS resolver cache after a rule change — hosts that just became rule hosts re-query instead of dialling the address they were answered with before",
            ),
            Err(e) => tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                sid,
                "could not flush the OS DNS resolver cache after a rule change: {e:?}",
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
        let Some(tracked) = tracked else {
            return self.install_for_sid_with(sid, rules_override);
        };
        match self.compute_filters_for_sid(sid, true, rules_override, ComputeIntent::Apply)? {
            // Policy/rules gone → a real teardown; the full-replace path
            // re-records the empty state and emits the same audits as before.
            ComputedFilterSet::NoPolicy | ComputedFilterSet::NoActiveRules => {
                let _ = self.remove_for_sid(sid)?;
                self.install_for_sid_with(sid, rules_override)
            }
            ComputedFilterSet::Install(desired) => self
                .reconcile_to_desired(sid, tracked, desired.filters, "window-free recompile", true)
                .map(|(_added, live_total)| live_total),
        }
    }

    fn emit_audit(&self, sid: &str, kind: PerSidApplyAuditKind, filter_count: u32, message: &str) {
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
    /// Errors are accumulated; the first error stops reconciliation
    /// for the remaining SIDs but already-applied changes are kept
    /// (consistent with the WFP transactions inside install/remove).
    pub fn reconcile(&self, snapshot: &[String]) -> Result<(), OrchestratorError> {
        let want: std::collections::BTreeSet<String> = snapshot.iter().cloned().collect();
        let have: std::collections::BTreeSet<String> = {
            let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            g.keys().cloned().collect()
        };
        for sid in want.difference(&have) {
            self.install_for_sid(sid)?;
        }
        for sid in have.difference(&want) {
            self.remove_for_sid(sid)?;
        }
        Ok(())
    }

    /// Delete the filters this SID used to carry that the new set no longer
    /// contains. A full-replace install only adds, so without this pass a
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
                sid,
                removed = superseded.len() as u64,
                "install: removed filters the new set supersedes",
            ),
            Err(e) => tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                sid,
                superseded = superseded.len() as u64,
                "install: delete of superseded filters best-effort failed: {e:?}",
            ),
        }
    }

    fn upsert_state(&self, sid: &str, installed: Vec<WfpFilterId>) {
        // No destinations, so nothing to sweep either way.
        self.upsert_state_with_destinations(sid, installed, Vec::new(), false);
    }

    /// What a filter set covers: the destinations it scopes to (deduplicated,
    /// in emission order) and whether the leak guard had a resolved tunnel when
    /// it was built. Both answers are READ OFF the filters, so the install path
    /// and the reconcile path cannot derive them differently — they used to,
    /// and the reconcile path simply left them at their defaults.
    ///
    /// Only host-scoped filters contribute. Every subnet-scoped filter we emit
    /// today is an exemption (loopback / LAN / the fake pool), and there is
    /// nothing to break loose from a permit. A CIDR RULE would change that —
    /// its pin needs the same sweep a `/32` pin gets, through
    /// `StaleFlowReset::reset_flows_to(base, prefix)`.
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

    fn coverage_of(filters: &[WfpFilterSpec]) -> (Vec<std::net::Ipv4Addr>, bool) {
        let mut seen = std::collections::HashSet::new();
        let destinations = filters
            .iter()
            .flat_map(|spec| {
                spec.remote_ip
                    .into_iter()
                    .chain(spec.remote_ip_set.iter().copied())
            })
            .filter(|ip| seen.insert(*ip))
            .collect();
        // The leak-guard emits an egress-via-secondary permit only when it has a
        // resolved adapter, so this is the tunnel's state without asking the OS
        // a second time.
        let secondary_resolved = filters.iter().any(|f| f.local_interface_luid.is_some());
        (destinations, secondary_resolved)
    }

    fn upsert_state_with_destinations(
        &self,
        sid: &str,
        installed: Vec<WfpFilterId>,
        destinations: Vec<std::net::Ipv4Addr>,
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
            },
        );
    }

    /// Tear down live connections to destinations this install just started
    /// enforcing, and report which ones those were.
    ///
    /// Why it cannot wait for the drop: a socket opened before the rule existed
    /// keeps the interface it was bound to for life. On a newly pinned
    /// destination the connect-time filters never see it again, so the
    /// half-loaded page the user just added a rule for goes on using the wrong
    /// link until something breaks it. The connection observer repairs this when
    /// it SEES drops, which is seconds later and only if drops happen; doing it
    /// on the activation edge is the same repair at the moment the user acted.
    ///
    /// Only additions count — re-listing a destination that was already
    /// enforced would tear down the very connections the previous teardown
    /// established — with one exception: when the additional adapter just
    /// became resolvable, EVERY pinned destination is swept. Its addresses did
    /// not change while the tunnel was down, so the "new destinations" rule
    /// finds nothing, and the sockets the browser opened over the main link (or
    /// against a fail-closed block) would ride it until they died on their own.
    fn tear_down_flows_to_new_destinations(
        &self,
        sid: &str,
        destinations: &[std::net::Ipv4Addr],
        secondary_resolved: bool,
    ) {
        let Some(reset) = self.stale_flow_reset.as_ref() else {
            return;
        };
        let (previous, was_resolved) = {
            let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
            match g.get(sid) {
                Some(state) => (
                    state.destinations.iter().copied().collect(),
                    state.secondary_resolved,
                ),
                None => (std::collections::HashSet::new(), false),
            }
        };
        let tunnel_came_up = secondary_resolved && !was_resolved;
        // One sweep for the whole set. Per-address teardown re-read the entire
        // TCP table each time, and "the tunnel came up" hands this every pinned
        // destination at once — hundreds of full table reads on the activation
        // edge, which is exactly the moment that must not stall.
        let victims: Vec<std::net::Ipv4Addr> = destinations
            .iter()
            .copied()
            .filter(|ip| tunnel_came_up || !previous.contains(ip))
            .collect();
        let fresh = victims.len();
        if victims.is_empty() {
            return;
        }
        let torn_down = reset.reset_flows_to_any(&victims).torn_down;
        if torn_down > 0 {
            let reason = if tunnel_came_up {
                "tore down connections still running beside the additional link that just came up — the application reconnects through it instead of finishing on the main one"
            } else {
                "tore down connections that predate the destinations this activation started enforcing — the application reconnects over the route the new rule assigns instead of finishing on the old link"
            };
            tracing::info!(
                target: "nrr::per_sid_orchestrator",
                sid,
                torn_down,
                destinations = fresh,
                tunnel_came_up,
                "{reason}",
            );
        }
    }
}
