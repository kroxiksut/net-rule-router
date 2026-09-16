//! Construction and the optional ports the consumer can be handed.

use super::*;

impl DnsObservationConsumer {
    pub fn new(
        rules_provider: Arc<dyn RulesProvider>,
        cache: Arc<Mutex<dyn CacheRepository + Send>>,
        fqdn_lookup: Arc<dyn FqdnCacheLookup>,
        active_sid: ActiveSidFn,
    ) -> Self {
        Self {
            rules_provider,
            cache,
            fqdn_lookup,
            active_sid,
            collateral_warned: Mutex::new(BoundedRecentSet::new(WARNED_HOSTS_CAP)),
            dns_cache_read: Arc::new(NoopDnsCacheRead),
            known_direct: None,
            fake_ip_running: Arc::new(|| false),
            secondary_usable: Arc::new(|| true),
            reverse_confirm_memo: Mutex::new(HashMap::new()),
            auto_rules: None,
            census_purged: Mutex::new(BoundedRecentSet::new(WARNED_HOSTS_CAP)),
            observed_names: None,
        }
    }

    /// Inject the index of names for rule-less hosts (see the field doc).
    /// Builder-style; without it nothing is recorded and `consume` behaves
    /// exactly as before.
    #[must_use]
    pub fn with_observed_host_names(
        mut self,
        index: Arc<crate::observed_host_names::ObservedHostNames>,
    ) -> Self {
        self.observed_names = Some(index);
        self
    }

    ///  — inject the companion-domain learner so this consumer's
    /// observations also feed companion discovery. Builder-style; without it the
    /// feature is inert and `consume` behaves exactly as before.
    #[must_use]
    pub fn with_auto_rules(mut self, engine: Arc<crate::auto_rules::AutoRulesEngine>) -> Self {
        self.auto_rules = Some(engine);
        self
    }

    ///  — inject the "secondary is usable" gate (see the field doc).
    /// While it reports `false`, a newly-detected collateral pair is logged as
    /// "pin skipped — secondary unusable" (info) instead of the WARN that
    /// claims the direct host egresses the secondary link. Detection, the
    /// summary count, and the shared-IP census recording are unaffected.
    /// Builder-style; existing call sites and tests keep the always-usable
    /// default.
    pub fn with_secondary_usable_gate(mut self, gate: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        self.secondary_usable = gate;
        self
    }

    /// Block D (fake-IP) — inject the "relay stack is live" gate so the
    /// collateral WARN is silenced (downgraded to debug) while fake-IP is
    /// actively steering those hosts onto the primary. Builder-style; existing
    /// call sites and tests keep the warn-always default.
    pub fn with_fake_ip_gate(mut self, gate: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        self.fake_ip_running = gate;
        self
    }

    /// inject the known-direct registry so
    /// [`learn_reverse_confirmed_direct`] can register positively-direct
    /// destinations for block-all exemptions. Builder-style.
    ///
    /// [`learn_reverse_confirmed_direct`]: DnsObservationConsumer::learn_reverse_confirmed_direct
    pub fn with_known_direct_registry(
        mut self,
        registry: Arc<crate::known_direct::KnownDirectRegistry>,
    ) -> Self {
        self.known_direct = Some(registry);
        self
    }

    /// inject the OS resolver-cache reader that [`seed_from_os_cache`]
    /// uses (Windows `WindowsDnsCacheRead`, Linux `LinuxDnsCacheRead`, or the
    /// `NoopDnsCacheRead` default). Builder-style so existing call sites and
    /// tests are unaffected.
    ///
    /// [`seed_from_os_cache`]: DnsObservationConsumer::seed_from_os_cache
    pub fn with_dns_cache_read(mut self, reader: Arc<dyn DnsCacheReadPort>) -> Self {
        self.dns_cache_read = reader;
        self
    }
}
