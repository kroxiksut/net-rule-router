//! Construction and the optional ports the coordinator can be handed.
//!
//! Every port has a working default, so an unwired coordinator still routes —
//! it simply knows less. That is deliberate: boot must not depend on the order
//! the wiring happens to run in.

use super::*;

impl SecondaryRouteCoordinator {
    pub fn new(
        api: Arc<dyn RouteTablePort>,
        rules_provider: Arc<dyn RulesProvider>,
        route_source: Arc<dyn RoutePolicySource>,
        fqdn_cache: Arc<dyn FqdnCacheLookup>,
        rule_scope_service_driven: RuleScopeProvider,
    ) -> Self {
        Self {
            reconciler: SecondaryRouteReconciler::new(Arc::clone(&api)),
            api,
            rules_provider,
            route_source,
            fqdn_cache,
            next_hop_cache: Mutex::new(HashMap::new()),
            server_ip_cache: Mutex::new(HashMap::new()),
            local_subnet_cache: Mutex::new(HashMap::new()),
            heal_logged: Mutex::new(HashMap::new()),
            not_found_logged: Mutex::new(HashMap::new()),
            not_usable_logged: Mutex::new(HashMap::new()),
            anchor_persisted: Mutex::new(std::collections::HashSet::new()),
            enforcement_status: Mutex::new(HashMap::new()),
            unassigned_tunnel_notified: Mutex::new(HashMap::new()),
            no_next_hop_logged: Mutex::new(std::collections::HashSet::new()),
            probed_ifindex: Mutex::new(HashMap::new()),
            last_resolution: Mutex::new(HashMap::new()),
            rule_scope_service_driven,
            binding_heal_persist: None,
            binding_anchor_persist: None,
            device_status: None,
            local_networks: None,
            events: None,
            server_ip_persist: None,
            server_ip_loader: None,
            paused_check: None,
            liveness: Arc::new(SecondaryLivenessTracker::new(0)),
            reachability_probe: None,
            app_observations: Arc::new(AppObservationStore::new()),
            dns_via_secondary: None,
            learned_vpn_endpoints: None,
        }
    }

    /// Share the DNS-over-secondary toggle so the reconcile emits the resolver
    /// `/32` routes the source-bound query sockets depend on. Chain before the
    /// coordinator is wrapped in `Arc`; pass the SAME flag the egress policy
    /// reads, or the socket and the route table disagree about the path.
    pub fn with_dns_via_secondary(mut self, flag: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.dns_via_secondary = Some(flag);
        self
    }

    /// Share the reactive VPN-endpoint learner's bounded, role-verified server
    /// set so it is merged into the kill-switch/fail-closed exemption bands.
    /// Chain before the coordinator is wrapped in `Arc`. Without it, only
    /// route-observed bootstrap server IPs are exempted (today's behaviour).
    pub fn with_learned_vpn_endpoints(
        mut self,
        learned: Arc<crate::vpn_endpoint_learning::LearnedVpnEndpoints>,
    ) -> Self {
        self.learned_vpn_endpoints = Some(learned);
        self
    }

    /// Share the connection observer's app→destination store with the route
    /// codegen. Chain before the coordinator is wrapped in `Arc`. Pass the same
    /// store the per-SID filter orchestrator gets, so an application rule's
    /// route and its permit are built from one set of observations.
    pub fn with_app_observations(mut self, store: Arc<dyn AppObservationLookup>) -> Self {
        self.app_observations = store;
        self
    }

    /// Attaches the auto-heal persist callback. Chain before the coordinator
    /// is wrapped in `Arc`. Without it, an auto-healed binding is applied
    /// in-memory each reconcile but the stored id stays stale.
    pub fn with_binding_heal_persist(mut self, persist: BindingHealPersistFn) -> Self {
        self.binding_heal_persist = Some(persist);
        self
    }

    /// Wire the OS question "is this adapter gone, or here and broken?".
    /// Without it a missing adapter is always reported as gone.
    #[must_use]
    pub fn with_device_status(mut self, port: Arc<dyn NetworkDeviceStatusPort>) -> Self {
        self.device_status = Some(port);
        self
    }

    /// Attaches the MAC-anchor persist callback. Chain before the coordinator is
    /// wrapped in `Arc`. Without it the anchor is recomputed every resolve and
    /// never stored, so a binding still depends on the GUID and the name alone.
    pub fn with_binding_anchor_persist(mut self, persist: BindingAnchorPersistFn) -> Self {
        self.binding_anchor_persist = Some(persist);
        self
    }

    /// Wire the user's local-network decisions. Chain before the coordinator is
    /// wrapped in `Arc`. Without it only the automatic answer applies.
    pub fn with_local_network_policy(mut self, read: LocalNetworkPolicyFn) -> Self {
        self.local_networks = Some(read);
        self
    }

    /// Share the push bus so the GUI and tray learn when policy stops being
    /// enforced. Chain before the coordinator is wrapped in `Arc`. Without it
    /// the state is logged and nothing else, which is how it stayed invisible.
    pub fn with_event_bus(mut self, events: Arc<crate::ipc_handlers::event_bus::EventBus>) -> Self {
        self.events = Some(events);
        self
    }

    /// attach the VPN-server-IP persistence seam: a
    /// write-through `persist` (called whenever the live route table yields a
    /// fresh server-IP set) and a startup `loader` (unioned into the fail-closed
    /// exemptions). Chain before the coordinator is wrapped in `Arc`. Without it
    /// the server-IP set stays in-memory only and is lost on restart.
    pub fn with_bootstrap_server_persistence(
        mut self,
        persist: ServerIpPersistFn,
        loader: ServerIpLoaderFn,
    ) -> Self {
        self.server_ip_persist = Some(persist);
        self.server_ip_loader = Some(loader);
        self
    }

    /// Attaches the routing-pause predicate (safe-disable ROUTE-half). Chain
    /// before the coordinator is wrapped in `Arc`. When it reports the effective
    /// routing SID paused, [`Self::recompute_active`] tears the route table down
    /// rather than (re)installing it, at the single choke point that covers every
    /// re-drive path. See [`PausedCheckFn`].
    pub fn with_pause_state(mut self, check: PausedCheckFn) -> Self {
        self.paused_check = Some(check);
        self
    }

    /// Attaches the active-probe liveness tracker. `tracker` is shared with
    /// the probe tick (writer of verdicts) and the setting (writer of the
    /// window); `probe` runs the ICMP echo. Chain before the coordinator is
    /// wrapped in `Arc`. Without it the tracker stays disabled → `is_dead` is
    /// always false and the probe tick is a no-op.
    pub fn with_liveness_probe(
        mut self,
        tracker: Arc<SecondaryLivenessTracker>,
        probe: Arc<dyn ReachabilityProbe>,
    ) -> Self {
        self.liveness = tracker;
        self.reachability_probe = Some(probe);
        self
    }
}
