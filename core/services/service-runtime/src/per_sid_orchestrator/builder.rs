//! Construction and configuration of [`super::PerSidApplyOrchestrator`].
//!
//! `new` plus twenty-five `with_*` methods, and the posture-log latch helpers
//! that only the configuration reads. Carved out of the orchestrator so the
//! file that answers "what does applying a policy do" is not half answers to
//! "what can be wired into it".
//!
//! Behaviour is unchanged: the same methods, in the same order, verbatim.

use super::*;

impl PerSidApplyOrchestrator {
    pub fn new(
        session: Arc<WfpSession>,
        policy_source: Arc<dyn RoutePolicySource>,
        rules_provider: Arc<dyn RulesProvider>,
        fqdn_cache: Arc<dyn FqdnCacheLookup>,
        audit: Arc<dyn PerSidApplyAudit>,
    ) -> Self {
        Self {
            apply_locks: Mutex::new(std::collections::HashMap::new()),
            #[cfg(windows)]
            shadow_compare_seen: Mutex::new(std::collections::HashMap::new()),
            standing_volume_last: Mutex::new(std::collections::HashMap::new()),
            session,
            policy_source,
            rules_provider,
            fqdn_cache,
            audit,
            // Default to the product default (best-effort). Production
            // overrides via `with_failure_mode_source` to track the
            // admin's persisted `ApplyFailurePolicy`.
            failure_mode: Arc::new(|| FilterFailureMode::BestEffort),
            // Default: kill-switch off (unresolved). Production overrides
            // via `with_kill_switch_resolver`.
            kill_switch_resolver: Arc::new(|_| None),
            // Default: no extra exemptions. Production overrides via
            // `with_fail_closed_exemptions_resolver`.
            fail_closed_exemptions_resolver: Arc::new(|_| FailClosedExemptions::default()),
            // Default: no verified VPN clients. Production wires the learned
            // registry via `with_vpn_client_apps_provider`.
            vpn_client_apps_provider: None,
            // Default: empty observation store → app rules route nothing.
            // Production overrides via `with_app_observations`.
            app_observations: Arc::new(AppObservationStore::new()),
            // Default: no app-path resolver → app rules resolve nothing (unwired
            // = today's no-app-id behaviour, now surfaced as an `AppUnresolved`
            // diagnostic instead of a silent apply-skip). Production overrides
            // via `with_app_resolver`.
            app_resolver: Arc::new(nrr_platform_api::NoopAppPathResolver),
            // Default: the reactive repair only. Production wires the port via
            // `with_stale_flow_reset`.
            stale_flow_reset: None,
            // Default: nobody listens for unresolved rule hosts.
            unresolved_hosts_sink: None,
            state: Mutex::new(HashMap::new()),
            // Default: no on-disk ledger. Production wires one via
            // `with_filter_ledger` so hard-kill orphans self-heal.
            ledger: None,
            // Default: no shared status → `AppUnresolved` diagnostics are
            // INFO-logged only. Production wires one via
            // `with_app_enforcement_status` so the GUI banner can list them.
            app_enforcement_status: None,
            // Default: no shared status → smart-kill-switch exclusions are
            // logged only. Production wires one via
            // `with_shared_ip_exemption_status` for the GUI warning.
            shared_ip_exemption_status: None,
            // Default: no-op flush. Production wires the per-OS mechanism
            // via `with_dns_cache_control`.
            dns_cache_control: Arc::new(nrr_platform_api::NoopDnsCacheControl),
            block_all_flush_state: Mutex::new(HashMap::new()),
            standing_volume_alarmed: Mutex::new(std::collections::HashMap::new()),
            fail_closed_state: Mutex::new(HashMap::new()),
            fail_closed_posture_status: None,
            machine_wide_cut_state: Mutex::new(HashMap::new()),
            cross_set_duplicate_state: Mutex::new(HashMap::new()),
            announced_app_rules: Mutex::new(HashMap::new()),
            events: None,
            posture_log_state: Mutex::new(HashMap::new()),
            // Default: fake-IP out of the plan. Production wires a live
            // provider via `with_fake_ip_context_provider`.
            fake_ip_context: Arc::new(|| None),
            // Default: no known-direct exemptions (strict block-all).
            // Production wires the session registry via
            // `with_known_direct_registry`.
            known_direct: None,
            // Default: no shared posture status → block-all state is log-only.
            // Production wires one via `with_block_all_posture_status`.
            block_all_posture_status: None,
            // Default: no registry → the reactive VPN-endpoint learner's
            // role-verification gate stays permanently closed. Production
            // wires one via `with_killswitch_drop_registry`.
            killswitch_drop_registry: None,
            killswitch_block_ids_by_sid: Mutex::new(HashMap::new()),
            // Default: historical ordering (blocks install without first
            // driving the route pass). Production wires the route coordinator
            // via `with_route_sync`.
            route_sync: None,
            // Default: nobody listens, so a persisting fail-closed posture only
            // announces itself. Production wires the watchdog's queue via
            // `with_rebind_requests`.
            rebind_requests: None,
        }
    }

    /// Wire the queue the resume watchdog drains. A fail-closed posture that
    /// keeps blocking is asked to re-resolve its binding on every heartbeat —
    /// the request is a flag, so the recompute runs on the watchdog's thread,
    /// never re-entering the apply path from inside a compute.
    #[must_use]
    pub fn with_rebind_requests(
        mut self,
        requests: Arc<crate::power_resume::RebindRequests>,
    ) -> Self {
        self.rebind_requests = Some(requests);
        self
    }

    /// Wire the "route before block" ordering hook: the reconcile calls it
    /// immediately before installing a destination-scoped BLOCK it was not
    /// already tracking, so the destination's secondary `/32` is in place
    /// before the block that only tolerates secondary egress. Skipped
    /// entirely when a reconcile adds no new destination block, so the steady
    /// state costs nothing.
    #[must_use]
    pub fn with_route_sync(mut self, hook: RouteSyncHook) -> Self {
        self.route_sync = Some(hook);
        self
    }

    /// Wire the flow-reset port so an activation breaks the connections its new
    /// destinations would otherwise leave on the previous link.
    #[must_use]
    pub fn with_stale_flow_reset(
        mut self,
        reset: Arc<dyn nrr_platform_api::fake_ip::stale_flows::StaleFlowReset>,
    ) -> Self {
        self.stale_flow_reset = Some(reset);
        self
    }

    /// Wire the sink for rule hosts an apply could not enforce.
    ///
    /// Without it a rule naming a host the cache has never confirmed enforces
    /// nothing until something else happens to resolve that host — and a
    /// browser sitting on an established socket never will, which is why
    /// "added the rule, reloaded the page, nothing changed" was reproducible.
    #[must_use]
    pub fn with_unresolved_hosts_sink(mut self, sink: UnresolvedHostsSink) -> Self {
        self.unresolved_hosts_sink = Some(sink);
        self
    }

    /// Attach the push bus so machine-wide-cut notices reach the principals
    /// they concern.
    #[must_use]
    pub fn with_events(mut self, events: Arc<crate::ipc_handlers::event_bus::EventBus>) -> Self {
        self.events = Some(events);
        self
    }

    /// wire the shared "block-all armed" posture the GUI
    /// banner reads via `SnapshotInitial`.
    #[must_use]
    pub fn with_block_all_posture_status(
        mut self,
        status: crate::app_enforcement_status::BlockAllPostureStatus,
    ) -> Self {
        self.block_all_posture_status = Some(status);
        self
    }

    /// Wire the shared "the additional link is unresolved and the guard is
    /// blocking" posture the DNS handler and the hostname seeder read.
    #[must_use]
    pub fn with_fail_closed_posture_status(
        mut self,
        status: crate::app_enforcement_status::FailClosedPostureStatus,
    ) -> Self {
        self.fail_closed_posture_status = Some(status);
        self
    }

    /// Wire the kill-switch/fail-closed Block-id registry so the reactive
    /// VPN-endpoint learner can role-verify a drop. Every filter compute
    /// republishes this SID's current kill-switch/fail-closed BLOCK id set
    /// (see [`Self::killswitch_block_ids_by_sid`]). Without it the registry
    /// stays empty and the learner's gate never opens.
    #[must_use]
    pub fn with_killswitch_drop_registry(
        mut self,
        registry: Arc<crate::killswitch_drop_registry::KillswitchBlockFilterRegistry>,
    ) -> Self {
        self.killswitch_drop_registry = Some(registry);
        self
    }

    /// Record `sid`'s current kill-switch/fail-closed BLOCK id set and
    /// republish the union across every SID this orchestrator has computed
    /// for, to the shared registry. An empty `ids` removes `sid`'s entry
    /// (its leak-guard disarmed or its policy is gone) rather than leaving a
    /// stale set that could role-verify a drop that no longer applies. No-op
    /// when no registry is wired.
    // `pub(super)` only because the impl is now split across files: the
    // plan and apply modules call these. Visibility widened by one module,
    // which is the whole cost of the split.
    pub(super) fn update_killswitch_registry(&self, sid: &str, ids: KillswitchBlockIds) {
        let Some(registry) = self.killswitch_drop_registry.as_ref() else {
            return;
        };
        let mut by_sid = self
            .killswitch_block_ids_by_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if ids.is_empty() {
            by_sid.remove(sid);
        } else {
            by_sid.insert(sid.to_string(), ids);
        }
        let all: HashSet<u64> = by_sid
            .values()
            .flat_map(|v| v.all.iter())
            .copied()
            .collect();
        let app_scoped: HashSet<u64> = by_sid
            .values()
            .flat_map(|v| v.app_scoped.iter())
            .copied()
            .collect();
        let ipv6_cut: HashSet<u64> = by_sid
            .values()
            .flat_map(|v| v.ipv6_cut.iter())
            .copied()
            .collect();
        let dns_lockdown: HashSet<u64> = by_sid
            .values()
            .flat_map(|v| v.dns_lockdown.iter())
            .copied()
            .collect();
        registry.publish_scoped(crate::killswitch_drop_registry::ScopedBlockIds {
            all,
            app_scoped,
            ipv6_cut,
            dns_lockdown,
        });
    }

    /// Proactive VPN-client exemption — wire the verified
    /// VPN-client path provider so a known client is permitted through a
    /// block-all posture at ARMING time, before its first drop of the session.
    #[must_use]
    pub fn with_vpn_client_apps_provider(mut self, provider: VpnClientAppsProvider) -> Self {
        self.vpn_client_apps_provider = Some(provider);
        self
    }

    /// wire the known-direct registry so the block-all
    /// exempts destinations positively established as direct (non-rule) hosts.
    #[must_use]
    pub fn with_known_direct_registry(
        mut self,
        registry: Arc<crate::known_direct::KnownDirectRegistry>,
    ) -> Self {
        self.known_direct = Some(registry);
        self
    }

    /// whether ANY tracked SID currently has the fail-closed
    /// catch-all block-all armed. The Mode-B direct-answer gate keys on this: a
    /// direct host needs its exemption installed BEFORE the answer only while
    /// the catch-all is armed.
    pub fn any_block_all_armed(&self) -> bool {
        self.block_all_flush_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .any(|armed| *armed)
    }

    /// Whether ANY tracked SID currently has the guard blocking because its
    /// additional link is unresolved — the per-IP posture included. See
    /// [`crate::app_enforcement_status::FailClosedPostureStatus`] for why this
    /// is the flag a DNS answer must key on rather than the block-all one.
    pub fn any_fail_closed_armed(&self) -> bool {
        self.fail_closed_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .any(|armed| *armed)
    }

    /// Block D (fake-IP, slice 5) — wire the LIVE fake-IP context provider,
    /// consulted on every compute, so the per-SID codegen suppresses
    /// fake-routed hosts' real `/32` permits, permits the fake pool, and
    /// hard-blocks their non-shared real IPs exactly while the feature is
    /// actually on. See [`FakeIpContextProvider`] for why the read must be
    /// live. A `None` (or disabled-scope) yield is a no-op.
    #[must_use]
    pub fn with_fake_ip_context_provider(mut self, provider: FakeIpContextProvider) -> Self {
        self.fake_ip_context = provider;
        self
    }

    /// Record the kill-switch posture derived by THIS compute and report
    /// whether it differs from the last one logged for the SID. Callers log
    /// at full level on `true` (a real posture change) and at `debug` on
    /// `false` (the ~5 s reconcile re-deriving the same state). A
    /// transition-only view over [`Self::posture_log_event`] for callers
    /// that don't want a periodic heartbeat while the posture persists.
    /// Intent-aware [`Self::posture_changed`]. A preview must not touch the
    /// latch: the next REAL compute would then read its own transition as
    /// unchanged and log it at debug, losing the line an operator needs.
    /// `Steady` is what a preview reports, which is also "say nothing loud".
    // `pub(super)` only because the impl is now split across files: the
    // plan and apply modules call these. Visibility widened by one module,
    // which is the whole cost of the split.
    pub(super) fn posture_changed_for(
        &self,
        intent: ComputeIntent,
        sid: &str,
        posture: &'static str,
    ) -> bool {
        intent.publishes() && self.posture_changed(sid, posture)
    }

    /// Intent-aware [`Self::posture_log_event`] — same reasoning.
    // `pub(super)` only because the impl is now split across files: the
    // plan and apply modules call these. Visibility widened by one module,
    // which is the whole cost of the split.
    pub(super) fn posture_log_event_for(
        &self,
        intent: ComputeIntent,
        sid: &str,
        posture: &'static str,
    ) -> PostureLogEvent {
        if intent.publishes() {
            self.posture_log_event(sid, posture)
        } else {
            PostureLogEvent::Steady
        }
    }

    // `pub(super)` because the impl and its tests are now separate files.
    pub(super) fn posture_changed(&self, sid: &str, posture: &'static str) -> bool {
        !matches!(
            self.posture_log_event_with_interval(sid, posture, Duration::MAX),
            PostureLogEvent::Steady
        )
    }

    /// Same latch as [`Self::posture_changed`], but also re-announces at
    /// full level every [`POSTURE_HEARTBEAT_INTERVAL`] while the posture
    /// persists unchanged, so a long-lived state (e.g. the kill-switch
    /// fail-closed block-all) still leaves a periodic trail instead of
    /// going silent for the whole session after its first line.
    // `pub(super)` because the impl and its tests are now separate files.
    pub(super) fn posture_log_event(&self, sid: &str, posture: &'static str) -> PostureLogEvent {
        self.posture_log_event_with_interval(sid, posture, POSTURE_HEARTBEAT_INTERVAL)
    }

    fn posture_log_event_with_interval(
        &self,
        sid: &str,
        posture: &'static str,
        heartbeat_interval: Duration,
    ) -> PostureLogEvent {
        let mut g = self
            .posture_log_state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let prior = g.get(sid).copied();
        let (event, latch) =
            evaluate_posture_log(prior, posture, Instant::now(), heartbeat_interval);
        g.insert(sid.to_string(), latch);
        event
    }

    /// wire the on-disk filter-id ledger so
    /// installed ids are persisted and a hard-killed prior instance's orphans
    /// can be reaped by id at the next start (see [`Self::cleanup_persisted_orphans`]).
    pub fn with_filter_ledger(
        mut self,
        ledger: Arc<crate::wfp_filter_ledger::WfpFilterLedger>,
    ) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// Override the per-filter apply-failure mode source. Production
    /// wires this to the live `ApplyFailurePolicy` so the
    /// strict / best-effort choice in Settings governs whether one
    /// un-materializable rule rolls back the whole revision.
    pub fn with_failure_mode_source(mut self, source: FilterFailureModeSource) -> Self {
        self.failure_mode = source;
        self
    }

    /// wire the kill-switch resolver.
    /// Without this the kill-switch is inert (the default resolver always
    /// returns `None`). Production passes a closure that resolves the
    /// active user's secondary binding + exemptions through the route
    /// coordinator; the kill-switch then activates only when the user has
    /// also turned on `block_secondary_when_unavailable`.
    pub fn with_kill_switch_resolver(mut self, resolver: KillSwitchResolver) -> Self {
        self.kill_switch_resolver = resolver;
        self
    }

    /// wire the fail-closed exemptions resolver. Only
    /// consulted on the fail-closed path when the secondary is unresolvable
    /// (mode B block-all). Without it, block-all still exempts loopback /
    /// link-local / broadcast but not LAN — production should wire this so a
    /// fail-closed user keeps local manageability and tunnel reconnection.
    pub fn with_fail_closed_exemptions_resolver(
        mut self,
        resolver: FailClosedExemptionsResolver,
    ) -> Self {
        self.fail_closed_exemptions_resolver = resolver;
        self
    }

    /// App-routing via observation — wire the observed app→IP
    /// store the codegen reads for `Application` rules. Without it the default
    /// empty store is used and app rules route nothing. Production passes the
    /// same store the connection-observation consumer writes into.
    pub fn with_app_observations(mut self, store: Arc<dyn AppObservationLookup>) -> Self {
        self.app_observations = store;
        self
    }

    /// wire the app-path resolver the codegen uses to turn an
    /// `Application` rule's exe name/glob into concrete on-disk exe paths (so it
    /// can emit real per-app `ALE_APP_ID` filters). Without it the default
    /// [`nrr_platform_api::NoopAppPathResolver`] resolves nothing and app
    /// rules install no per-process enforcement (surfaced as
    /// [`crate::wfp_codegen::CodegenDiagnostic::AppUnresolved`]). Production
    /// passes a [`nrr_platform_api::WindowsAppPathResolver`].
    pub fn with_app_resolver(
        mut self,
        resolver: Arc<dyn nrr_platform_api::AppPathResolver>,
    ) -> Self {
        self.app_resolver = resolver;
        self
    }

    /// wire the shared status the codegen's `AppUnresolved`
    /// diagnostics publish into on every filter compute, so the
    /// `SnapshotInitial` handler can surface a GUI banner listing app rules
    /// that resolved to no exe path (and are therefore unenforced). Without
    /// it the diagnostics are INFO-logged only.
    pub fn with_app_enforcement_status(
        mut self,
        status: crate::app_enforcement_status::AppEnforcementStatus,
    ) -> Self {
        self.app_enforcement_status = Some(status);
        self
    }

    /// wire the shared count of secondary IPs the
    /// "smart" kill-switch excluded from its pin/block set because the
    /// shared-IP census saw them on direct (non-rule) hosts too. The
    /// `SnapshotInitial` handler reads it for the GUI's "strictness reduced
    /// for N shared IPs" warning. Without it the exclusions are logged only.
    pub fn with_shared_ip_exemption_status(
        mut self,
        status: crate::app_enforcement_status::SharedIpExemptionStatus,
    ) -> Self {
        self.shared_ip_exemption_status = Some(status);
        self
    }

    /// wire the OS resolver-cache flush mechanism.
    /// Fired only on the fail-closed block-all arming/disarming edge so names
    /// cached by the OS resolver before the block armed are re-queried on the
    /// wire, become observable, and earn their suffix/zone permits. Without it
    /// the default no-op leaves the pre-block OS cache in place (tests /
    /// degraded boot / platforms without a flushable cache).
    pub fn with_dns_cache_control(
        mut self,
        control: Arc<dyn nrr_platform_api::DnsCacheControlPort>,
    ) -> Self {
        self.dns_cache_control = control;
        self
    }
    /// Convenience constructor with a no-op audit sink. Useful when
    /// the caller is wiring tests that care about install/remove
    /// behaviour but not audit ordering.
    pub fn with_noop_audit(
        session: Arc<WfpSession>,
        policy_source: Arc<dyn RoutePolicySource>,
        rules_provider: Arc<dyn RulesProvider>,
        fqdn_cache: Arc<dyn FqdnCacheLookup>,
    ) -> Self {
        Self::new(
            session,
            policy_source,
            rules_provider,
            fqdn_cache,
            Arc::new(NoopPerSidApplyAudit),
        )
    }
}
