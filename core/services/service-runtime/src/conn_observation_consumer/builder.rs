//! Wiring the consumer up.
//!
//! Seventeen optional collaborators — learners, drop checks, sinks, the
//! trace ring. Every one of them is an `Option` or a no-op by default,
//! because the consumer has to come up on a boot where half of them could
//! not be built. Reading them together is the only way to see that.
//!
//! Same inherent impl, split across files. Behaviour is unchanged.

use super::*;

impl ConnectionObservationConsumer {
    pub fn new(
        api: Arc<dyn RouteTablePort>,
        coordinator: Arc<SecondaryRouteCoordinator>,
        active_sid: ActiveSidFn,
        log_ndjson: bool,
    ) -> Self {
        Self {
            api,
            coordinator,
            active_sid,
            log_ndjson,
            app_observations: None,
            app_destination_forget: None,
            routed_apps: None,
            trace_ring: None,
            vpn_endpoint_learner: None,
            killswitch_drop_check: None,
            killswitch_app_scope_check: None,
            ipv6_cut_drop_check: None,
            dns_lockdown_drop_check: None,
            vpn_client_app_learner: None,
            reverse_dns_learner: None,
            drop_logged: Mutex::new(HashSet::new()),
            name_for_address: None,
            companion_in_use: None,
            companion_primary_health: None,
            companion_reported: Mutex::new(HashSet::new()),
            torn_down_before: Mutex::new(HashSet::new()),
            last_secondary_at: Mutex::new(None),
            block_notice_name_for_address: None,
            block_notice_sink: None,
            stale_flow_reset: None,
            fail_closed_armed: None,
        }
    }

    /// Wire the live fail-closed posture so a drop during an outage window is
    /// explained as an outage (see [`Self::fail_closed_armed`]).
    #[must_use]
    pub fn with_fail_closed_armed(mut self, armed: FailClosedArmedFn) -> Self {
        self.fail_closed_armed = Some(armed);
        self
    }

    /// Wire the teardown for flows a destination pin caught on the wrong link
    /// (see [`Self::stale_flow_reset`]).
    #[must_use]
    pub fn with_stale_flow_reset(mut self, reset: Arc<dyn StaleFlowReset>) -> Self {
        self.stale_flow_reset = Some(reset);
        self
    }

    /// Wire block-notice reporting: a name for the destination and the sink
    /// that turns a qualifying drop into a `BlockAttempt`. Mirrors
    /// [`Self::with_companion_in_use`]'s shape, but the pairing is not a hard
    /// requirement here — a sink with no name resolver still reports, just
    /// with the raw address standing in for the host.
    #[must_use]
    pub fn with_block_notice(
        mut self,
        name_for_address: NameForAddressFn,
        sink: BlockNoticeSinkFn,
    ) -> Self {
        self.block_notice_name_for_address = Some(name_for_address);
        self.block_notice_sink = Some(sink);
        self
    }

    /// Wire companion discovery from observed traffic: a name for a
    /// destination address, and a sink for the companions found leaving over
    /// the wrong link. Both or neither — a sink with no names would never fire,
    /// and names with no sink would be work for nothing.
    #[must_use]
    pub fn with_companion_in_use(
        mut self,
        name_for_address: NameForAddressFn,
        sink: CompanionInUseFn,
    ) -> Self {
        self.name_for_address = Some(name_for_address);
        self.companion_in_use = Some(sink);
        self
    }

    /// Wire the primary-route health signal. Needs the same name resolution as
    /// [`Self::with_companion_in_use`], so it is only useful alongside it.
    #[must_use]
    pub fn with_companion_primary_health(mut self, sink: CompanionPrimaryHealthFn) -> Self {
        self.companion_primary_health = Some(sink);
        self
    }

    /// Wire the FCrDNS reverse-DNS learner so an
    /// NRR block drop of an as-yet-unlearned destination is named and (if it
    /// matches a rule) cached, closing the "browser cache / DoH hid the name"
    /// blind spot under block-all. Without it the observer does not reverse-learn.
    pub fn with_reverse_dns_learner(mut self, learner: ReverseDnsLearnFn) -> Self {
        self.reverse_dns_learner = Some(learner);
        self
    }

    /// Wire the VPN-endpoint learner together with the role-verification gate
    /// it requires: a kill-switch drop of a VPN-client flow teaches the
    /// exemption set the tunnel's server IP, but only when the dropping
    /// filter's spec id passes `drop_check` (in production: membership in the
    /// live kill-switch/fail-closed Block id registry).
    ///
    /// One call rather than two, because the learner without the gate is
    /// PERMANENTLY INERT — it compiles, it wires, it reports nothing, and
    /// nothing says so. Taking both arguments makes that combination
    /// unrepresentable instead of documented.
    pub fn with_vpn_endpoint_learner(
        mut self,
        learner: VpnEndpointLearnFn,
        drop_check: KillswitchDropCheckFn,
    ) -> Self {
        self.vpn_endpoint_learner = Some(learner);
        self.killswitch_drop_check = Some(drop_check);
        self
    }

    /// Wire the role-verification gate on its own, for the callers that read it
    /// WITHOUT learning: the scope-bug counter classifies a drop by the same
    /// registry and learns nothing. The learner cannot use this path — it takes
    /// its gate in [`Self::with_vpn_endpoint_learner`], so it can never be left
    /// without one.
    pub fn with_killswitch_drop_check(mut self, check: KillswitchDropCheckFn) -> Self {
        self.killswitch_drop_check = Some(check);
        self
    }

    /// Wire the blocking-scope classifier (in production: the same registry's
    /// `is_app_scoped`) so the scope-bug counter can separate an app pin's
    /// expected first-contact drop from a destination pin that outran its
    /// route. Diagnostics only — it never changes what is blocked or learned.
    pub fn with_killswitch_app_scope_check(mut self, check: KillswitchDropCheckFn) -> Self {
        self.killswitch_app_scope_check = Some(check);
        self
    }

    /// Wire the IPv6-cut classifier (in production: the same registry's
    /// `is_ipv6_cut`) so a drop of the closed family is announced as that,
    /// with the switch that governs it, instead of as a rule the user would
    /// search for in vain.
    pub fn with_ipv6_cut_drop_check(mut self, check: KillswitchDropCheckFn) -> Self {
        self.ipv6_cut_drop_check = Some(check);
        self
    }

    /// Wire the DNS-lockdown classifier (in production: the same registry's
    /// `is_dns_lockdown`) so an app's attempt to reach a resolver of its own
    /// is announced as the lockdown that closed it, with the switch that
    /// governs it, instead of as a rule the user never wrote.
    pub fn with_dns_lockdown_drop_check(mut self, check: KillswitchDropCheckFn) -> Self {
        self.dns_lockdown_drop_check = Some(check);
        self
    }

    /// Wire the client-app sink
    /// so a role-verified kill-switch drop registers the CLIENT PROCESS for an
    /// app-scoped exemption (in addition to the per-IP endpoint learner).
    /// Without it the observer never learns client apps. Requires
    /// [`Self::with_killswitch_drop_check`] to ever fire, exactly like the
    /// endpoint learner.
    pub fn with_vpn_client_app_learner(mut self, learner: VpnClientAppLearnFn) -> Self {
        self.vpn_client_app_learner = Some(learner);
        self
    }

    /// Wire the observed app→IP store so this consumer feeds app-routing.
    /// Without it the consumer stays diagnostic-only.
    pub fn with_app_observations(mut self, store: Arc<AppObservationStore>) -> Self {
        self.app_observations = Some(store);
        self
    }

    /// Wire the cross-session delete used when a destination is withdrawn.
    pub fn with_app_destination_forget(mut self, forget: AppDestinationForgetFn) -> Self {
        self.app_destination_forget = Some(forget);
        self
    }

    /// Wire the rule book's routed application patterns, which is what makes
    /// the collateral check able to fire at all.
    pub fn with_routed_apps(mut self, routed: RoutedAppsFn) -> Self {
        self.routed_apps = Some(routed);
        self
    }

    /// Wire the trace ring so resolved connections are
    /// retained for the Diagnostics panel. Without it the observer is log-only.
    pub fn with_trace_ring(mut self, ring: Arc<ConnectionTraceRing>) -> Self {
        self.trace_ring = Some(ring);
        self
    }
}
