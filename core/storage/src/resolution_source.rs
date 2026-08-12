use nrr_domain::decision_lookup::LookupSource;

/// Origin of a resolved address entry as stored in the database.
///
/// This is the storage layer's own vocabulary for how a hostname→IP mapping
/// was obtained.  It is richer than [`LookupSource`] from `nrr-domain` because
/// the database distinguishes between sources that the rule engine does not care
/// about (e.g. `ImportedSeed` vs `CacheRebuild`).
///
/// Persisted as TEXT in SQLite (via [`as_str`][`StorageResolutionSource::as_str`]).
/// Mapped to [`LookupSource`] when constructing a [`LookupResult`] for the rule
/// engine via [`to_lookup_source`][`StorageResolutionSource::to_lookup_source`].
///
/// [`LookupResult`]: nrr_domain::decision_lookup::LookupResult
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageResolutionSource {
    /// Live DNS query performed by the service resolver.
    Dns,
    /// IP was observed directly from WFP traffic, not via DNS.
    ObservedFromTraffic,
    /// Entry was written by a user-initiated manual cache refresh.
    ManualRefresh,
    /// Entry was seeded from a user-imported preset or rules file.
    ImportedSeed,
    /// Entry was reconstructed during a cache rebuild from the rules file.
    CacheRebuild,
    /// Entry was seeded by reading the OS resolver cache
    /// (`DnsCacheReadPort`), for a rule-matching host that resolved before the
    /// service started / was served from the OS cache so the ETW observer never
    /// saw its query. Distinct from [`Dns`][Self::Dns] so the GUI can show it as
    /// "OS cache" and the operator understands why a permit exists without a
    /// live observation.
    OsCacheSeed,
    /// Entry learned by Forward-Confirmed reverse DNS after OUR
    /// enforcement dropped the destination IP under block-all (the browser
    /// answered from its own cache / DoH, so the observer never saw the name).
    /// The name was recovered by PTR and the dropped IP was confirmed present in
    /// the name's forward `A` record (anti-spoofing). Distinct from
    /// [`Dns`][Self::Dns] / [`ObservedFromTraffic`][Self::ObservedFromTraffic] so
    /// the GUI can show it as "reverse-confirmed" and the operator understands the
    /// permit came from a drop, not a live query.
    ReverseConfirmed,
    /// Entry seeded by resolving a rule-matching hostname taken from
    /// the user's OPT-IN browser-history read (a site the user visited before the
    /// service started, so the observer never saw its query). Distinct so the GUI
    /// shows it as "browser history" and the operator understands the permit came
    /// from a one-off consented import, not live traffic.
    BrowserHistorySeed,
}

impl StorageResolutionSource {
    /// Returns the canonical TEXT representation stored in SQLite.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::ObservedFromTraffic => "observed_from_traffic",
            Self::ManualRefresh => "manual_refresh",
            Self::ImportedSeed => "imported_seed",
            Self::CacheRebuild => "cache_rebuild",
            Self::OsCacheSeed => "os_cache_seed",
            Self::ReverseConfirmed => "reverse_confirmed",
            Self::BrowserHistorySeed => "browser_history_seed",
        }
    }

    /// Parses the TEXT representation back from SQLite.
    ///
    /// Returns `None` for unknown values — callers must handle this as a
    /// soft error (treat as `CacheRebuild` or emit a diagnostic flag).
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "dns" => Some(Self::Dns),
            "observed_from_traffic" => Some(Self::ObservedFromTraffic),
            "manual_refresh" => Some(Self::ManualRefresh),
            "imported_seed" => Some(Self::ImportedSeed),
            "cache_rebuild" => Some(Self::CacheRebuild),
            "os_cache_seed" => Some(Self::OsCacheSeed),
            "reverse_confirmed" => Some(Self::ReverseConfirmed),
            "browser_history_seed" => Some(Self::BrowserHistorySeed),
            _ => None,
        }
    }

    /// Converts to the domain-level [`LookupSource`] used by the rule engine.
    ///
    /// `ImportedSeed` and `CacheRebuild` both map to `CacheHit` because from
    /// the rule engine's perspective these entries came from the local cache,
    /// regardless of how they were originally populated.
    pub fn to_lookup_source(&self) -> LookupSource {
        match self {
            Self::Dns => LookupSource::DnsResolution,
            Self::ObservedFromTraffic => LookupSource::ObservedFromTraffic,
            Self::ManualRefresh => LookupSource::ManualRefresh,
            Self::ImportedSeed => LookupSource::CacheHit,
            Self::CacheRebuild => LookupSource::CacheHit,
            // Read from the OS resolver cache — a cache hit from the engine's
            // view (we did not perform the live query ourselves).
            Self::OsCacheSeed => LookupSource::CacheHit,
            // Learned from an NRR-dropped connection, then DNS-confirmed —
            // traffic-driven, like ObservedFromTraffic from the engine's view.
            Self::ReverseConfirmed => LookupSource::ObservedFromTraffic,
            // Resolved from a consented browser-history import — a cache hit from
            // the engine's view (not a live query we drove ourselves).
            Self::BrowserHistorySeed => LookupSource::CacheHit,
        }
    }
}

/// User-selectable cache-source priority strategy.
///
/// The FQDN/IP cache can hold several resolutions for one hostname from
/// different origins ([`StorageResolutionSource`]). When more than one is
/// usable, this strategy decides which source outranks which — both for the IP
/// actually routed ([`select_best_ip`](crate::store)) and for the source
/// reported in explain/diagnostics ([`best_source_of`](crate::store)).
///
/// [`FreshestFirst`][Self::FreshestFirst] is the default ordering (so an
/// un-set user sees the same behaviour as before this strategy was
/// configurable). The alternatives let a user who trusts a different signal
/// reorder the top of the ranking without a full six-way permutation.
///
/// Persisted per-SID as TEXT via [`as_slug`](Self::as_slug); the wire/GUI use
/// the same slugs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CachePriorityStrategy {
    /// Freshest authoritative data wins: `Dns == ManualRefresh` outrank
    /// `ObservedFromTraffic`, which outranks the seed sources. The default.
    #[default]
    FreshestFirst,
    /// Prefer what actually egressed: `ObservedFromTraffic` outranks live DNS.
    /// Useful when a site's authoritative DNS answer differs from the IP the
    /// user's traffic really reached (CDN edge, geo-split).
    ObservedFirst,
    /// Prefer user-pinned entries: `ManualRefresh` outranks everything.
    ManualFirst,
}

impl CachePriorityStrategy {
    /// Canonical slug — persisted per-SID and carried on the wire/GUI.
    pub fn as_slug(self) -> &'static str {
        match self {
            Self::FreshestFirst => "freshest-first",
            Self::ObservedFirst => "observed-first",
            Self::ManualFirst => "manual-first",
        }
    }

    /// Parses the slug. `None` on unknown — callers fall back to the default.
    pub fn from_slug(s: &str) -> Option<Self> {
        match s {
            "freshest-first" => Some(Self::FreshestFirst),
            "observed-first" => Some(Self::ObservedFirst),
            "manual-first" => Some(Self::ManualFirst),
            _ => None,
        }
    }

    /// Every strategy slug, for wire/GUI validation allow-lists.
    pub const ALL_SLUGS: &'static [&'static str] =
        &["freshest-first", "observed-first", "manual-first"];

    /// Coarse rank used by `select_best_ip` as the source tie-break AFTER
    /// freshness (higher wins). `FreshestFirst` uses the
    /// `Dns|ManualRefresh = 2, ObservedFromTraffic = 1, _ = 0` ordering.
    pub fn selection_rank(self, source: &StorageResolutionSource) -> u8 {
        use StorageResolutionSource as S;
        match self {
            Self::FreshestFirst => match source {
                S::Dns | S::ManualRefresh => 2,
                S::ObservedFromTraffic | S::ReverseConfirmed => 1,
                _ => 0,
            },
            Self::ObservedFirst => match source {
                S::ObservedFromTraffic | S::ReverseConfirmed => 3,
                S::Dns | S::ManualRefresh => 2,
                _ => 0,
            },
            Self::ManualFirst => match source {
                S::ManualRefresh => 3,
                S::Dns => 2,
                S::ObservedFromTraffic | S::ReverseConfirmed => 1,
                _ => 0,
            },
        }
    }

    /// Fine six-way rank used by `best_source_of` for the reported/explain
    /// source (higher wins). `FreshestFirst` uses the
    /// `Dns 5 > ManualRefresh 4 > ObservedFromTraffic 3 > OsCacheSeed 2 >
    /// ImportedSeed 1 > CacheRebuild 0` ordering. The alternatives only reorder
    /// the live sources; the seed tier (OsCacheSeed/Imported/Rebuild) is
    /// unchanged.
    pub fn report_rank(self, source: &StorageResolutionSource) -> u8 {
        use StorageResolutionSource as S;
        let seed_or = |s: &S, live: u8| -> u8 {
            match s {
                S::OsCacheSeed | S::BrowserHistorySeed => 2,
                S::ImportedSeed => 1,
                S::CacheRebuild => 0,
                _ => live,
            }
        };
        match self {
            Self::FreshestFirst => match source {
                S::Dns => 5,
                S::ManualRefresh => 4,
                S::ObservedFromTraffic | S::ReverseConfirmed => 3,
                other => seed_or(other, 0),
            },
            Self::ObservedFirst => match source {
                S::ObservedFromTraffic | S::ReverseConfirmed => 5,
                S::Dns => 4,
                S::ManualRefresh => 3,
                other => seed_or(other, 0),
            },
            Self::ManualFirst => match source {
                S::ManualRefresh => 5,
                S::Dns => 4,
                S::ObservedFromTraffic | S::ReverseConfirmed => 3,
                other => seed_or(other, 0),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_VARIANTS: &[StorageResolutionSource] = &[
        StorageResolutionSource::Dns,
        StorageResolutionSource::ObservedFromTraffic,
        StorageResolutionSource::ManualRefresh,
        StorageResolutionSource::ImportedSeed,
        StorageResolutionSource::CacheRebuild,
        StorageResolutionSource::OsCacheSeed,
        StorageResolutionSource::ReverseConfirmed,
        StorageResolutionSource::BrowserHistorySeed,
    ];

    #[test]
    fn as_str_from_str_roundtrip() {
        for variant in ALL_VARIANTS {
            let s = variant.as_str();
            let back = StorageResolutionSource::from_str(s)
                .unwrap_or_else(|| panic!("from_str must succeed for canonical string {s:?}"));
            assert_eq!(variant, &back, "roundtrip failed for {s:?}");
        }
    }

    #[test]
    fn from_str_unknown_returns_none() {
        assert!(StorageResolutionSource::from_str("unknown_value").is_none());
        assert!(StorageResolutionSource::from_str("").is_none());
        assert!(StorageResolutionSource::from_str("DNS").is_none()); // case-sensitive
    }

    #[test]
    fn imported_seed_maps_to_cache_hit() {
        assert_eq!(
            StorageResolutionSource::ImportedSeed.to_lookup_source(),
            LookupSource::CacheHit
        );
    }

    #[test]
    fn cache_rebuild_maps_to_cache_hit() {
        assert_eq!(
            StorageResolutionSource::CacheRebuild.to_lookup_source(),
            LookupSource::CacheHit
        );
    }

    #[test]
    fn dns_maps_to_dns_resolution() {
        assert_eq!(
            StorageResolutionSource::Dns.to_lookup_source(),
            LookupSource::DnsResolution
        );
    }

    #[test]
    fn observed_from_traffic_maps_correctly() {
        assert_eq!(
            StorageResolutionSource::ObservedFromTraffic.to_lookup_source(),
            LookupSource::ObservedFromTraffic
        );
    }

    #[test]
    fn manual_refresh_maps_correctly() {
        assert_eq!(
            StorageResolutionSource::ManualRefresh.to_lookup_source(),
            LookupSource::ManualRefresh
        );
    }

    // ── CachePriorityStrategy ─────────────────────────────────────────────────

    #[test]
    fn strategy_slug_roundtrip() {
        for slug in CachePriorityStrategy::ALL_SLUGS {
            let s = CachePriorityStrategy::from_slug(slug)
                .unwrap_or_else(|| panic!("from_slug must succeed for {slug:?}"));
            assert_eq!(s.as_slug(), *slug);
        }
        assert!(CachePriorityStrategy::from_slug("nope").is_none());
    }

    #[test]
    fn default_strategy_is_freshest_first() {
        assert_eq!(
            CachePriorityStrategy::default(),
            CachePriorityStrategy::FreshestFirst
        );
    }

    #[test]
    fn freshest_first_reproduces_legacy_selection_ranks() {
        // Legacy select_best_ip: Dns|ManualRefresh = 2, Observed = 1, _ = 0.
        let s = CachePriorityStrategy::FreshestFirst;
        assert_eq!(s.selection_rank(&StorageResolutionSource::Dns), 2);
        assert_eq!(s.selection_rank(&StorageResolutionSource::ManualRefresh), 2);
        assert_eq!(
            s.selection_rank(&StorageResolutionSource::ObservedFromTraffic),
            1
        );
        assert_eq!(s.selection_rank(&StorageResolutionSource::OsCacheSeed), 0);
        assert_eq!(s.selection_rank(&StorageResolutionSource::ImportedSeed), 0);
        assert_eq!(s.selection_rank(&StorageResolutionSource::CacheRebuild), 0);
    }

    #[test]
    fn freshest_first_reproduces_legacy_report_ranks() {
        // Legacy best_source_of: Dns 5 > Manual 4 > Observed 3 > OsCacheSeed 2
        // > Imported 1 > Rebuild 0.
        let s = CachePriorityStrategy::FreshestFirst;
        assert_eq!(s.report_rank(&StorageResolutionSource::Dns), 5);
        assert_eq!(s.report_rank(&StorageResolutionSource::ManualRefresh), 4);
        assert_eq!(
            s.report_rank(&StorageResolutionSource::ObservedFromTraffic),
            3
        );
        assert_eq!(s.report_rank(&StorageResolutionSource::OsCacheSeed), 2);
        assert_eq!(s.report_rank(&StorageResolutionSource::ImportedSeed), 1);
        assert_eq!(s.report_rank(&StorageResolutionSource::CacheRebuild), 0);
    }

    #[test]
    fn observed_first_outranks_dns_for_selection_and_report() {
        let s = CachePriorityStrategy::ObservedFirst;
        assert!(
            s.selection_rank(&StorageResolutionSource::ObservedFromTraffic)
                > s.selection_rank(&StorageResolutionSource::Dns)
        );
        assert!(
            s.report_rank(&StorageResolutionSource::ObservedFromTraffic)
                > s.report_rank(&StorageResolutionSource::Dns)
        );
    }

    #[test]
    fn manual_first_outranks_everything() {
        let s = CachePriorityStrategy::ManualFirst;
        let manual = s.selection_rank(&StorageResolutionSource::ManualRefresh);
        for other in [
            StorageResolutionSource::Dns,
            StorageResolutionSource::ObservedFromTraffic,
            StorageResolutionSource::OsCacheSeed,
        ] {
            assert!(
                manual > s.selection_rank(&other),
                "manual must beat {other:?}"
            );
        }
    }
}
