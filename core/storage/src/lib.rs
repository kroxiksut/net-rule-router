#![forbid(unsafe_code)]
// Storage DTO/enum types use inherent `from_str`/`as_str` pairs to (de)serialize
// the exact string forms persisted in SQLite columns. These intentionally do NOT
// implement `std::str::FromStr` (they return `Option`, not `Result`, and are
// scoped to DB round-tripping), so silence the trait-confusion lint crate-wide.
#![allow(clippy::should_implement_trait)]
//! FQDN/IP cache and service-state persistence for NetRuleRouter.
//!
//! # Crate boundaries
//!
//! `nrr-storage` depends on `nrr-domain` for shared types (`LookupResult`,
//! `CacheEntryState`, `FreshnessThresholds`, `RevisionId`) and on
//! `nrr-platform-api` for the production data/log roots — path shape is the
//! platform layer's business, and deriving it a second time here is what made
//! it drift. It must not depend on `nrr-shared`, `nrr-application`, or any UI
//! crate.
//!
//! # Threading model
//!
//! All operations are **synchronous** (`rusqlite` blocking API).  Callers in an
//! async context (service loop) must wrap calls in
//! `tokio::task::spawn_blocking`.  No async runtime primitives live here.
//!
//! # Storage files
//!
//! | File | Kind | On corruption |
//! |------|------|---------------|
//! | `nrr_fqdn_ip_cache.db` | Rebuildable | Delete + rebuild |
//! | `nrr_service_state.db` | Service-critical | Reported at boot, then rolled back to a trusted earlier revision |
//!
//! See [`profile`] for path resolution and [`repository`] for the trait
//! interfaces.

pub mod app_destinations;
pub mod app_pattern_resolutions;
pub mod auto_rule_dismissals;
pub mod auto_rule_evidence;
pub mod auto_rule_pending;
pub mod auto_rules;
pub mod autostart_state;
pub mod backup;
pub mod block_notice_journal;
pub mod block_notice_mutes;
pub mod bootstrap;
pub mod change_generation;
pub mod doh_lockdown;
pub mod dto;
pub mod error;
pub mod explain;
pub mod explain_snapshots;
pub mod local_network_rules;
pub mod log_retention_config;
pub mod migration;
pub mod mutation_tokens;
pub mod pause_state;
pub mod policy_settings;
pub mod principal_purge;
pub mod profile;
pub mod refusing_anchors;
pub mod repository;
pub mod resolution_source;
pub mod retention_settings;
pub mod revision_hmac;
pub mod revisions;
pub mod route_bindings;
pub mod schema;
pub mod service_stability_config;
pub mod store;
// Per-adapter traffic-statistics store over the rebuildable
// nrr_traffic_stats.db. Consumes nrr-domain TrafficDelta.
pub mod traffic_stats;
// Service-global traffic-stats settings singleton in the service-critical
// state DB (master toggle + category toggles + retention).
pub mod traffic_stats_settings;
// VPN self-heal exclusions — persisted hostnames that pre-seed
// the in-memory fake-IP exclusion set at boot.
pub mod fake_ip_heal_exclusions;
pub mod vpn_bootstrap_endpoints;
// Learned VPN client apps — persisted exe paths of role-verified
// VPN client processes; pre-seeds the proactive kill-switch app exemption.
pub mod vpn_client_apps;
pub mod write_ledger;

// Re-export the most commonly used types so callers can write
// `use nrr_storage::{StorageError, StorageProfile, StorageResolutionSource}`
// without needing to navigate sub-modules.
pub use app_pattern_resolutions::{AppPatternResolutionsRepository, MAX_PATHS_PER_PATTERN};
pub use autostart_state::{
    AutostartLastKnownState, AutostartStateRecord, AutostartStateRepository,
};
pub use backup::{backup_database, BackupReason};
pub use bootstrap::{bootstrap_storage_directories, StorageBootstrapResult};
pub use dto::CacheStats;
pub use error::{IntegrityFailureKind, StorageError, StorageResult};
pub use explain::DiagnosticRedactionLevel;
pub use log_retention_config::{LogRetentionConfig, LogRetentionConfigRepository};
pub use migration::{
    open_connection, open_traffic_connection_or_rebuild, read_schema_version,
    SqliteMigrationRunner, TrafficDbOpen,
};
pub use mutation_tokens::{ConsumeOutcome, MutationTokenStoreSqlite, StoredMutationToken};
pub use pause_state::{RoutingPauseRecord, RoutingPauseStateRepository};
pub use policy_settings::{
    ApplyFailurePolicyRecord, ApplyFailurePolicySettingsRepository, DEFAULT_POLICY_SLUG,
    VALID_POLICY_SLUGS,
};
pub use principal_purge::{
    principals_with_state, purge_principal_data, purge_principal_rules, PrincipalPurgeSummary,
};
pub use profile::{resolve_storage_topology, StorageProfile, StorageTopology};
pub use resolution_source::StorageResolutionSource;
pub use retention_settings::{RetentionSettings, RetentionSettingsRepository};
pub use revisions::{
    ActiveRevisionPointer, RetentionPruneSummary, RevisionRecord, RevisionsRepository,
    VerifiedHistoryEntry,
};
pub use route_bindings::{
    BehaviorMode, BindingSource, MigrationStatusRecord, RouteBindingRecord,
    RouteBindingsRepository, RoutePolicyRecord, RoutePolicyValidationError,
};
pub use schema::{
    lookup_direction_as_str, lookup_direction_from_str, AddressFamily, DiagnosticFlags,
    FreshnessStateDb, BASELINE_PRINCIPAL, CACHE_DB_V1_DDL, STATE_DB_V1_DDL, STATE_DB_V2_DDL,
    STATE_DB_V3_DDL, STATE_DB_V4_DDL, STATE_DB_V5_DDL, STATE_DB_V6_DDL, STATE_DB_V7_DDL,
    STATE_DB_V8_DDL, TRAFFIC_DB_V1_DDL,
};
pub use store::{SqliteCacheStore, SqliteStateStore};
pub use traffic_stats::{
    AdapterAddressRow, AdapterHistoryLink, AdapterKeySighting, SqliteTrafficStore,
    TrafficCursorRow, TrafficDayRow, TrafficTotalRow,
};
pub use traffic_stats_settings::{TrafficStatsSettings, TrafficStatsSettingsRepository};
pub use vpn_bootstrap_endpoints::VpnBootstrapEndpointsRepository;
pub use vpn_client_apps::VpnClientAppsRepository;

// Re-export the domain types that appear in our public API so callers do not
// have to add a separate `nrr-domain` dependency just to construct requests.
pub use nrr_domain::decision_lookup::{
    CacheEntryState, FreshnessThresholds, LookupDirection, LookupError, LookupResult,
};
pub use nrr_domain::revision::RevisionId;
