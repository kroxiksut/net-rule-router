//! `SqliteCachePort` — production [`CacheLookupPort`] implementation.
//!
//! Wraps an `Arc<SqliteCacheStore>` from `nrr-storage` and forwards
//! `lookup(fqdn)` to its `build_lookup_envelope` method, then maps the
//! domain-level [`LookupResult`] into a [`CacheLookupOutcome`] consumed by
//! the rule-engine pipeline.
//!
//! ## Mapping
//!
//! `build_lookup_envelope` always returns `Ok(LookupResult)`. The decision
//! layer's outcome enum is reconstructed from the result's `selected_ip`:
//!
//! | `selected_ip` cache state                       | Outcome     |
//! |-------------------------------------------------|-------------|
//! | `Some(Fresh)`                                   | `Hit`       |
//! | `Some(StaleUsable)`                             | `Stale`     |
//! | `Some(StaleNotUsable / Missing / Conflicting)`  | `Miss`      |
//! | `Some(NegativeCached)`                          | `Miss`      |
//! | `None`                                          | `Miss`      |
//!
//! `Hit` carries the populated `LookupResult` so the engine has the IP set
//! and explain metadata for `ExactIp` matching. `Miss` discards the empty
//! envelope; the engine reconstructs an empty one downstream. `Stale`
//! carries the populated envelope — the engine treats stale-usable entries
//! as still-matchable but flags a refresh hint via `was_miss()`.
//!
//! ## Errors
//!
//! Storage failures (DB locked, integrity error, …) are intentionally
//! converted to `Miss` rather than panicking. Callers see no IP, the
//! decision pipeline degrades to FQDN/zone matching, and the underlying
//! error is forwarded to `tracing::warn!` so it lands in the operational
//! NDJSON. This matches the apply-layer contract: a broken cache must not
//! stall traffic.

use std::sync::{Arc, Mutex};

use nrr_domain::decision_lookup::{
    CacheEntryState, FreshnessThresholds, LookupDirection, LookupResult,
};
use nrr_storage::dto::CacheLookupRequest;
use nrr_storage::repository::CacheRepository;
use nrr_storage::store::SqliteCacheStore;

use crate::integration_ports::{CacheLookupOutcome, CacheLookupPort};

/// Production [`CacheLookupPort`] backed by `nrr_fqdn_ip_cache.db`.
///
/// `SqliteCacheStore` uses an internal `RefCell<Connection>` for interior
/// mutability, which makes it `Send` but not `Sync`. The trait requires
/// `Send + Sync`, so the store is wrapped in a `Mutex` here. Lookups are
/// short and serialised; the cache database itself runs in WAL mode, so
/// concurrent readers from other components (write paths in the apply
/// orchestrator) coexist without contention.
pub struct SqliteCachePort {
    store: Arc<Mutex<SqliteCacheStore>>,
    thresholds: FreshnessThresholds,
}

impl SqliteCachePort {
    /// Constructs a port from a shared cache store.
    ///
    /// `thresholds` is consulted on every lookup to classify the freshness
    /// of cached entries. Pass `FreshnessThresholds::default_production()`
    /// in production wiring.
    pub fn new(store: Arc<Mutex<SqliteCacheStore>>, thresholds: FreshnessThresholds) -> Self {
        Self { store, thresholds }
    }
}

impl CacheLookupPort for SqliteCachePort {
    fn lookup(&self, fqdn: &str) -> CacheLookupOutcome {
        let request = CacheLookupRequest {
            hostname: Some(fqdn.to_string()),
            observed_ip: None,
            direction: LookupDirection::HostnameToIp,
            active_revision_id: None,
            requested_at: std::time::SystemTime::now(),
        };

        let envelope = {
            let guard = match self.store.lock() {
                Ok(g) => g,
                Err(_) => {
                    // Poisoned lock — another holder panicked. Degrade to
                    // Miss so the decision pipeline can proceed without
                    // cached IP data; the panic itself is surfaced through
                    // the supervisor's `TaskFailureSink`.
                    return CacheLookupOutcome::Miss;
                }
            };
            // `selected_ip`/`best_source` here follow the active
            // user's cache-priority strategy. Wired to the default until the
            // per-SID strategy cell is threaded in (this port is the decision
            // path's `selected_ip` producer; the WFP codegen path permits every
            // cached IP regardless of strategy).
            match guard.build_lookup_envelope(
                &request,
                &self.thresholds,
                nrr_storage::resolution_source::CachePriorityStrategy::default(),
            ) {
                Ok(env) => env,
                Err(e) => {
                    tracing::warn!(
                        target: "nrr::cache",
                        error = %e,
                        fqdn = %fqdn,
                        "cache lookup failed; degrading to Miss"
                    );
                    return CacheLookupOutcome::Miss;
                }
            }
        };

        classify(envelope)
    }
}

fn classify(envelope: LookupResult) -> CacheLookupOutcome {
    let cache_state = envelope.selected_ip.as_ref().map(|e| e.cache_state.clone());
    match cache_state {
        Some(CacheEntryState::Fresh) => CacheLookupOutcome::Hit(envelope),
        Some(CacheEntryState::StaleUsable) => CacheLookupOutcome::Stale(envelope),
        Some(CacheEntryState::StaleNotUsable)
        | Some(CacheEntryState::Missing)
        | Some(CacheEntryState::Conflicting)
        | Some(CacheEntryState::NegativeCached)
        | None => CacheLookupOutcome::Miss,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_domain::decision_lookup::{
        LookupExplainData, LookupExtendedMetadata, LookupSource, LookupStandardSignals,
        ResolvedAddressEntry,
    };
    use std::net::Ipv4Addr;

    fn make_envelope(state: CacheEntryState) -> LookupResult {
        let entry = ResolvedAddressEntry {
            addr: Ipv4Addr::new(1, 1, 1, 1),
            cache_state: state.clone(),
            source: LookupSource::CacheHit,
            resolved_at: None,
            ttl_seconds: None,
        };
        LookupResult {
            selected_ip: Some(entry),
            is_multi_ip: false,
            has_conflict: false,
            explain_data: LookupExplainData {
                standard: LookupStandardSignals {
                    cache_hit: true,
                    freshness: Some(state),
                    source: Some(LookupSource::CacheHit),
                    errors: Vec::new(),
                },
                extended: LookupExtendedMetadata {
                    all_resolved_ips: Vec::new(),
                    reverse_hostnames: Vec::new(),
                    selected_entry_ttl_secs: None,
                    selected_entry_resolved_at: None,
                },
            },
        }
    }

    fn empty_envelope() -> LookupResult {
        LookupResult {
            selected_ip: None,
            is_multi_ip: false,
            has_conflict: false,
            explain_data: LookupExplainData {
                standard: LookupStandardSignals {
                    cache_hit: false,
                    freshness: None,
                    source: None,
                    errors: Vec::new(),
                },
                extended: LookupExtendedMetadata {
                    all_resolved_ips: Vec::new(),
                    reverse_hostnames: Vec::new(),
                    selected_entry_ttl_secs: None,
                    selected_entry_resolved_at: None,
                },
            },
        }
    }

    #[test]
    fn fresh_envelope_classifies_as_hit() {
        match classify(make_envelope(CacheEntryState::Fresh)) {
            CacheLookupOutcome::Hit(_) => {}
            other => panic!("expected Hit, got {other:?}"),
        }
    }

    #[test]
    fn stale_usable_envelope_classifies_as_stale() {
        match classify(make_envelope(CacheEntryState::StaleUsable)) {
            CacheLookupOutcome::Stale(_) => {}
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn stale_not_usable_envelope_classifies_as_miss() {
        assert_eq!(
            classify(make_envelope(CacheEntryState::StaleNotUsable)),
            CacheLookupOutcome::Miss,
        );
    }

    #[test]
    fn missing_envelope_classifies_as_miss() {
        assert_eq!(
            classify(make_envelope(CacheEntryState::Missing)),
            CacheLookupOutcome::Miss,
        );
    }

    #[test]
    fn conflicting_envelope_classifies_as_miss() {
        assert_eq!(
            classify(make_envelope(CacheEntryState::Conflicting)),
            CacheLookupOutcome::Miss,
        );
    }

    #[test]
    fn negative_cached_envelope_classifies_as_miss() {
        assert_eq!(
            classify(make_envelope(CacheEntryState::NegativeCached)),
            CacheLookupOutcome::Miss,
        );
    }

    #[test]
    fn empty_envelope_classifies_as_miss() {
        assert_eq!(classify(empty_envelope()), CacheLookupOutcome::Miss);
    }
}
