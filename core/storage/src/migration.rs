//! Migration runner and connection factory.
//!
//! # Connection lifecycle
//!
//! ```text
//! open_connection(path)               → Connection
//! SqliteMigrationRunner::for_*(conn)  → SqliteMigrationRunner (takes ownership)
//! runner.run_pending_migrations()     → MigrationSummary
//! runner.verify_schema()              → SchemaVerification
//! runner.into_connection()            → Connection  (hand to repository)
//! ```
//!
//! # Migration model
//!
//! Each database carries a `schema_migrations` table (created by the runner
//! before the first migration runs, as bootstrap infrastructure).  Each
//! migration executes its SQL statements plus the `schema_migrations` INSERT
//! atomically in a single transaction: either both commit or both roll back.
//!
//! # WAL baseline
//!
//! WAL journal mode is mandatory.  [`open_connection`] verifies that the DB
//! actually accepted `PRAGMA journal_mode = WAL` — some network filesystems
//! silently fall back to DELETE mode.  The service always runs on a local NTFS
//! volume so this check should never fire in production.

use std::cell::RefCell;
use std::path::Path;
use std::time::SystemTime;

use rusqlite::{Connection, OptionalExtension};

use crate::dto::{MigrationSummary, SchemaVerification};
use crate::error::{StorageError, StorageResult};
use crate::repository::MigrationRunner;
use crate::schema::{
    CACHE_DB_V1_DDL, CACHE_DB_V2_DDL, CACHE_DB_V3_DDL, CACHE_DB_V4_DDL, STATE_DB_V10_DDL,
    STATE_DB_V11_DDL, STATE_DB_V12_DDL, STATE_DB_V13_DDL, STATE_DB_V14_DDL, STATE_DB_V15_DDL,
    STATE_DB_V16_DDL, STATE_DB_V17_DDL, STATE_DB_V18_DDL, STATE_DB_V19_DDL, STATE_DB_V1_DDL,
    STATE_DB_V20_DDL, STATE_DB_V21_DDL, STATE_DB_V22_DDL, STATE_DB_V23_DDL, STATE_DB_V24_DDL,
    STATE_DB_V25_DDL, STATE_DB_V26_DDL, STATE_DB_V27_DDL, STATE_DB_V28_DDL, STATE_DB_V29_DDL,
    STATE_DB_V2_DDL, STATE_DB_V30_DDL, STATE_DB_V31_DDL, STATE_DB_V32_DDL, STATE_DB_V33_DDL,
    STATE_DB_V34_DDL, STATE_DB_V35_DDL, STATE_DB_V36_DDL, STATE_DB_V37_DDL, STATE_DB_V38_DDL,
    STATE_DB_V39_DDL, STATE_DB_V3_DDL, STATE_DB_V40_DDL, STATE_DB_V41_DDL, STATE_DB_V42_DDL,
    STATE_DB_V43_DDL, STATE_DB_V44_DDL, STATE_DB_V45_DDL, STATE_DB_V46_DDL, STATE_DB_V47_DDL,
    STATE_DB_V48_DDL, STATE_DB_V49_DDL, STATE_DB_V4_DDL, STATE_DB_V50_DDL, STATE_DB_V51_DDL,
    STATE_DB_V52_DDL, STATE_DB_V5_DDL, STATE_DB_V6_DDL, STATE_DB_V7_DDL, STATE_DB_V8_DDL,
    STATE_DB_V9_DDL, TRAFFIC_DB_V1_DDL,
};

// ── schema_migrations bootstrap DDL ──────────────────────────────────────────

const CREATE_SCHEMA_MIGRATIONS: &str = "
CREATE TABLE IF NOT EXISTS schema_migrations (
    version      INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL,
    applied_at   INTEGER NOT NULL,
    checksum     TEXT    NOT NULL,
    app_version  TEXT    NOT NULL
)";

// ── MigrationDef ─────────────────────────────────────────────────────────────

/// A single versioned migration: an ordered list of SQL statements applied
/// atomically within one transaction.
#[derive(Clone, Copy)]
pub(crate) struct MigrationDef {
    pub version: u32,
    pub name: &'static str,
    /// Individual SQL statements executed in order inside a single transaction.
    pub stmts: &'static [&'static str],
}

// ── Migration catalogs ────────────────────────────────────────────────────────

pub(crate) const CACHE_MIGRATIONS: &[MigrationDef] = &[
    MigrationDef {
        version: 1,
        name: "initial_cache_schema",
        stmts: CACHE_DB_V1_DDL,
    },
    // Shared-IP census table (`direct_on_ip` for the shared-IP policy).
    // Additive; rebuildable cache DB.
    MigrationDef {
        version: 2,
        name: "add_shared_ip_census",
        stmts: CACHE_DB_V2_DDL,
    },
    // Persistent fake-IP bindings: a hostname keeps its fake address across
    // service restarts. Additive; rebuildable cache DB.
    MigrationDef {
        version: 3,
        name: "add_fake_ip_bindings",
        stmts: CACHE_DB_V3_DDL,
    },
    // Census tenants claimed by a main-route rule, so the kill-switch can tell
    // "block this and the host dies" from "block this and the host rides the
    // tunnel". Additive; rebuildable cache DB.
    MigrationDef {
        version: 4,
        name: "add_shared_ip_census_primary_ruled",
        stmts: CACHE_DB_V4_DDL,
    },
];

// nrr_traffic_stats.db. Rebuildable, like the cache DB: delete + rebuild on
// corruption. Pre-release, wiped freely — a schema change bumps v1 in place,
// never adds v2.
pub(crate) const TRAFFIC_MIGRATIONS: &[MigrationDef] = &[MigrationDef {
    version: 1,
    name: "initial_traffic_schema",
    stmts: TRAFFIC_DB_V1_DDL,
}];

pub(crate) const STATE_MIGRATIONS: &[MigrationDef] = &[
    MigrationDef {
        version: 1,
        name: "initial_state_schema",
        stmts: STATE_DB_V1_DDL,
    },
    MigrationDef {
        version: 2,
        name: "add_revision_integrity_hashes",
        stmts: STATE_DB_V2_DDL,
    },
    MigrationDef {
        version: 3,
        name: "add_security_alerts",
        stmts: STATE_DB_V3_DDL,
    },
    MigrationDef {
        version: 4,
        name: "add_apply_snapshots",
        stmts: STATE_DB_V4_DDL,
    },
    MigrationDef {
        version: 5,
        name: "add_per_sid_routing_policy",
        stmts: STATE_DB_V5_DDL,
    },
    MigrationDef {
        version: 6,
        name: "add_rules_revisions",
        stmts: STATE_DB_V6_DDL,
    },
    MigrationDef {
        version: 7,
        name: "add_settings_and_pause_state",
        stmts: STATE_DB_V7_DDL,
    },
    MigrationDef {
        version: 8,
        name: "add_service_stability_config",
        stmts: STATE_DB_V8_DDL,
    },
    MigrationDef {
        version: 9,
        name: "add_verbose_logging_to_service_stability_config",
        stmts: STATE_DB_V9_DDL,
    },
    MigrationDef {
        version: 10,
        name: "add_explain_snapshots",
        stmts: STATE_DB_V10_DDL,
    },
    // Per-row HMAC column for tamper detection on
    // the state DB. Lazy backfill (empty default → "unsigned" tag at
    // read time → next mutation populates) keeps the migration
    // platform-agnostic; the DPAPI-protected key lives in
    // nrr-platform-windows and is threaded through the repository at
    // open time, not through this migration.
    MigrationDef {
        version: 11,
        name: "add_revisions_row_hmac",
        stmts: STATE_DB_V11_DDL,
    },
    // Per-principal (per-OS-user) rules revisions.
    // Reset-style: DROP + recreate revisions / active_revision_pointer /
    // mutation_tokens with a `principal` partition column. Pre-release,
    // no production data to preserve. The per-SID routing tables (v5)
    // are untouched.
    MigrationDef {
        version: 12,
        name: "reset_revisions_for_per_principal",
        stmts: STATE_DB_V12_DDL,
    },
    // Two diagnostics toggles on
    // service_stability_config (NDJSON sink + GUI stream), siblings of the
    // v9 verbose_logging flag. Both default 0; existing rows backfill.
    MigrationDef {
        version: 13,
        name: "add_conn_trace_toggles_to_service_stability_config",
        stmts: STATE_DB_V13_DDL,
    },
    // Rule-scope (app-driven vs service-driven) flag on
    // service_stability_config. Default 1 = service-driven. ALTER ADD COLUMN.
    MigrationDef {
        version: 14,
        name: "add_rule_scope_to_service_stability_config",
        stmts: STATE_DB_V14_DDL,
    },
    // Kill-switch failure posture (fail-closed vs fail-open)
    // on secondary_block_policy. Default 1 = fail-closed. ALTER ADD COLUMN.
    MigrationDef {
        version: 15,
        name: "add_kill_switch_fail_closed_to_secondary_block_policy",
        stmts: STATE_DB_V15_DDL,
    },
    // Multi-protocol kill-switch: which IP protocols the
    // emergency block cuts (bitmask) on secondary_block_policy. Default 127 =
    // all protocols. ALTER ADD COLUMN.
    MigrationDef {
        version: 16,
        name: "add_kill_switch_protocols_to_secondary_block_policy",
        stmts: STATE_DB_V16_DDL,
    },
    // Persist-on-stop — routing_stop_policy slug on service_stability_config:
    // 'teardown' (default) vs 'persist' when the service stops. Default
    // 'teardown'; existing rows backfill. ALTER ADD COLUMN.
    MigrationDef {
        version: 17,
        name: "add_routing_stop_policy_to_service_stability_config",
        stmts: STATE_DB_V17_DDL,
    },
    // log_retention_config singleton: operational-log
    // + audit NDJSON retention (age + size caps). CREATE TABLE, purely additive.
    MigrationDef {
        version: 18,
        name: "add_log_retention_config",
        stmts: STATE_DB_V18_DDL,
    },
    // cache_refresh_interval_secs on service_stability_config:
    // user-configurable FQDN cache refresh cadence floor. ALTER ADD COLUMN.
    MigrationDef {
        version: 19,
        name: "add_cache_refresh_interval_to_service_stability_config",
        stmts: STATE_DB_V19_DDL,
    },
    // include_subdomains on secondary_block_policy: expand
    // bare-domain rules to also cover subdomains at enforcement time. The SQL
    // DEFAULT 0 is inert (checksummed DDL; upserts bind every column) — the
    // effective default lives in the application layer and is ON. ALTER ADD
    // COLUMN.
    MigrationDef {
        version: 20,
        name: "add_include_subdomains_to_secondary_block_policy",
        stmts: STATE_DB_V20_DDL,
    },
    // shared_ip_policy on secondary_block_policy: how a
    // SHARED secondary IP is treated (majority-of-ip default). ALTER ADD COLUMN.
    MigrationDef {
        version: 21,
        name: "add_shared_ip_policy_to_secondary_block_policy",
        stmts: STATE_DB_V21_DDL,
    },
    // known_stable_ids on route_bindings: the set of every
    // stable adapter id a binding has matched, so a secondary adapter whose GUID
    // rotated is recognised by any prior id. Default '' (empty set). ALTER ADD COLUMN.
    MigrationDef {
        version: 22,
        name: "add_known_stable_ids_to_route_bindings",
        stmts: STATE_DB_V22_DDL,
    },
    // kill_switch_block_all on secondary_block_policy: split
    // fail-closed blocks ALL egress (catch-all) vs only cached secondary IPs.
    // Default 0 (OFF). ALTER ADD COLUMN.
    MigrationDef {
        version: 23,
        name: "add_kill_switch_block_all_to_secondary_block_policy",
        stmts: STATE_DB_V23_DDL,
    },
    // enforcement_mode on service_stability_config:
    // machine-wide traffic-enforcement mechanism (0 = Reactive default,
    // 1 = Resolver). Global service setting. Default 0. ALTER ADD COLUMN.
    MigrationDef {
        version: 24,
        name: "add_enforcement_mode_to_service_stability_config",
        stmts: STATE_DB_V24_DDL,
    },
    // secondary_liveness_window_secs on service_stability_config:
    // active-ICMP-probe liveness window (seconds) before the kill-switch
    // fail-closes; 0 = DISABLED (default). Global service setting. ALTER ADD COLUMN.
    MigrationDef {
        version: 25,
        name: "add_secondary_liveness_window_to_service_stability_config",
        stmts: STATE_DB_V25_DDL,
    },
    // kill_switch_enabled (MASTER toggle) on
    // secondary_block_policy: full opt-in gate — OFF (default) means NO
    // fail-closed / leak-guard blocking arms at all. DEV schema; wiped freely.
    // ALTER ADD COLUMN.
    MigrationDef {
        version: 26,
        name: "add_kill_switch_enabled_to_secondary_block_policy",
        stmts: STATE_DB_V26_DDL,
    },
    // allow_dns_over_primary (opt-in DNS-over-primary permit)
    // on secondary_block_policy. DEV schema; wiped freely. ALTER ADD COLUMN.
    MigrationDef {
        version: 27,
        name: "add_allow_dns_over_primary_to_secondary_block_policy",
        stmts: STATE_DB_V27_DDL,
    },
    // mode_a_coverage_strategy (Mode-A un-seeded-IP posture) +
    // resolve_hosts_bypass (bypass the OS hosts/adblock file for rule-host
    // resolution, default ON) on secondary_block_policy. DEV schema; wiped
    // freely. Two ALTER ADD COLUMN statements.
    MigrationDef {
        version: 28,
        name: "add_mode_a_coverage_and_hosts_bypass_to_secondary_block_policy",
        stmts: STATE_DB_V28_DDL,
    },
    // Two persistence tables that survive a service
    // restart: `app_pattern_resolutions` (last-good exe-path resolutions,
    // machine-wide) and `vpn_bootstrap_endpoints` (observed VPN server IPs). Both
    // break the VPN-under-kill-switch chicken-and-egg. Purely additive CREATE
    // TABLEs. DEV schema; wiped freely.
    MigrationDef {
        version: 29,
        name: "add_app_pattern_resolutions_and_vpn_bootstrap_endpoints",
        stmts: STATE_DB_V29_DDL,
    },
    // `route_link_provider_apps`: per-(sid, role) executables
    // the user confirmed as establishing the link (VPN client et al.). Service-
    // side SSOT for the kill-switch link-provider exemption; per-binding by
    // construction for Pro. Purely additive CREATE TABLE. DEV schema; wiped
    // freely.
    MigrationDef {
        version: 30,
        name: "add_route_link_provider_apps",
        stmts: STATE_DB_V30_DDL,
    },
    // DoH/DoT lockdown: per-SID toggle + scope on
    // `secondary_block_policy`, plus the shared `doh_resolver_entries` baseline.
    MigrationDef {
        version: 31,
        name: "add_doh_lockdown",
        stmts: STATE_DB_V31_DDL,
    },
    // Opt-in automatic browser-history seed: per-SID toggle on
    // `secondary_block_policy` (default OFF — privacy-sensitive, explicit
    // opt-in). Purely additive ALTER. DEV schema; wiped freely.
    MigrationDef {
        version: 32,
        name: "add_browser_history_auto_seed",
        stmts: STATE_DB_V32_DDL,
    },
    // Kill-switch shared-IP strictness: per-SID toggle on
    // `secondary_block_policy` (default 0 = "smart": census-shared IPs are not
    // pinned/blocked by the kill-switch). Purely additive ALTER. DEV schema;
    // wiped freely.
    MigrationDef {
        version: 33,
        name: "add_kill_switch_strict_shared_ips",
        stmts: STATE_DB_V33_DDL,
    },
    // Machine-wide `fake_ip_enabled` toggle on
    // `service_stability_config` (default 0 = off; fake-IP changes how names
    // resolve, so it is opt-in). Purely additive ALTER. DEV schema; wiped freely.
    MigrationDef {
        version: 34,
        name: "add_fake_ip_enabled",
        stmts: STATE_DB_V34_DDL,
    },
    // Service-global traffic-statistics settings
    // singleton (master toggle + loopback/virtual toggles + retention). New
    // dedicated table (CREATE), additive. DEV schema; wiped freely.
    MigrationDef {
        version: 35,
        name: "add_traffic_stats_settings",
        stmts: STATE_DB_V35_DDL,
    },
    // DNS-over-secondary — machine-wide `dns_via_secondary` toggle on
    // `service_stability_config` (default 0 = off; changes where the service's
    // own upstream DNS queries egress, so it is opt-in). Purely additive ALTER.
    // DEV schema; wiped freely.
    MigrationDef {
        version: 36,
        name: "add_dns_via_secondary",
        stmts: STATE_DB_V36_DDL,
    },
    // VPN self-heal exclusions — persisted `hostname → learned_at`
    // rows pre-seed the in-memory fake-IP exclusion set at boot, so a VPN
    // client's first connect of a session goes direct instead of re-learning
    // through one failed relay round. Purely additive CREATE. DEV schema;
    // wiped freely.
    MigrationDef {
        version: 37,
        name: "add_fake_ip_heal_exclusions",
        stmts: STATE_DB_V37_DDL,
    },
    // Fast DNS answers — `dns_fast_answers` toggle on
    // `service_stability_config` (default 1 = on; the Mode-B resolver only
    // holds an answer for the reconcile deadline when it introduces addresses
    // the routable cache has never seen). Purely additive ALTER. DEV schema;
    // wiped freely.
    MigrationDef {
        version: 38,
        name: "add_dns_fast_answers",
        stmts: STATE_DB_V38_DDL,
    },
    // Fake-IP UDP relay — `fake_ip_udp_relay` toggle on
    // `service_stability_config` (default 0 = off; the pool permit hard-blocks
    // UDP until this is turned on). Purely additive ALTER. DEV schema; wiped
    // freely.
    MigrationDef {
        version: 39,
        name: "add_fake_ip_udp_relay",
        stmts: STATE_DB_V39_DDL,
    },
    // Fake-IP instant reset — `fake_ip_instant_rst` toggle on
    // `service_stability_config` (default 1 = on; a source-policy dial
    // refusal keeps resetting the client instantly unless this is turned
    // off). Purely additive ALTER. DEV schema; wiped freely.
    MigrationDef {
        version: 40,
        name: "add_fake_ip_instant_rst",
        stmts: STATE_DB_V40_DDL,
    },
    // Learned VPN client apps — exe paths of role-verified VPN
    // client processes, persisted so the proactive app-scoped kill-switch
    // exemption survives a service restart (rotating provider check IPs made
    // the per-IP reactive exemption re-drop every session). Purely additive
    // CREATE. DEV schema; wiped freely.
    MigrationDef {
        version: 41,
        name: "add_vpn_client_apps",
        stmts: STATE_DB_V41_DDL,
    },
    // Auto-rules mode — `auto_rules_mode` on
    // `secondary_block_policy` (per-SID; slugs `off` / `suggest` / `auto`,
    // default `suggest` — collects and offers companion-domain findings but
    // applies nothing without confirmation). Purely additive ALTER. DEV schema;
    // wiped freely.
    MigrationDef {
        version: 42,
        name: "add_auto_rules_mode",
        stmts: STATE_DB_V42_DDL,
    },
    // Auto-rule dismissals — `auto_rule_dismissals` table holding
    // the companion-domain suggestions a user explicitly refused. A REFUSAL must
    // outlive a service restart, or the same rejected host is offered again on
    // every start. Purely additive CREATE. DEV schema; wiped freely.
    MigrationDef {
        version: 43,
        name: "add_auto_rule_dismissals",
        stmts: STATE_DB_V43_DDL,
    },
    // Persisted application destinations —
    // `app_observed_destinations` holds the addresses an app the rule book
    // routes over the additional link has been seen using. Without it every
    // session re-learns them from its own refusals, so each address is refused
    // once per restart before its route exists. Purely additive CREATE. DEV
    // schema; wiped freely.
    MigrationDef {
        version: 44,
        name: "add_app_observed_destinations",
        stmts: STATE_DB_V44_DDL,
    },
    // Administrative rules lock — `allow_user_rule_edits` on the
    // machine-wide `service_stability_config` singleton. Frozen rule authoring
    // has to outlive the restricted account it applies to, so the flag cannot
    // live in any per-principal table; this singleton's wire operation already
    // demands elevation to write. Purely additive ALTER, defaults to the
    // permissive value. DEV schema; wiped freely.
    MigrationDef {
        version: 45,
        name: "add_allow_user_rule_edits",
        stmts: STATE_DB_V45_DDL,
    },
    // Eager delivery-name suggestions —
    // `auto_rules_eager_delivery_names` on `secondary_block_policy`, next to the
    // auto-rules mode it refines. Off by default: the evidence it skips is what
    // keeps a CDN shared with half the internet out of the user's rule set.
    // Purely additive ALTER. DEV schema; wiped freely.
    MigrationDef {
        version: 46,
        name: "add_auto_rules_eager_delivery_names",
        stmts: STATE_DB_V46_DDL,
    },
    // Pending companion-domain suggestions — `auto_rule_pending_candidates`.
    // Superseded the "pending re-derives, only refusals persist" assumption:
    // the accumulated set is meant to be worked through over weeks, and that
    // composition does not come back from a few minutes of fresh browsing.
    // Purely additive CREATE. DEV schema; wiped freely.
    MigrationDef {
        version: 47,
        name: "add_auto_rule_pending_candidates",
        stmts: STATE_DB_V47_DDL,
    },
    // The refused offer itself — `dto_json` on `auto_rule_dismissals`, so
    // "allow again" hands the row back instead of waiting for evidence that
    // has already aged out. Purely additive ALTER. DEV schema; wiped freely.
    MigrationDef {
        version: 48,
        name: "add_auto_rule_dismissal_dto",
        stmts: STATE_DB_V48_DDL,
    },
    // Durable block-notice mutes — `block_notice_mutes` table. A restart used
    // to forget every "Do not show" choice and bring back the full drop-storm
    // noise the episode folding exists to tame. Purely additive CREATE. DEV
    // schema; wiped freely.
    MigrationDef {
        version: 49,
        name: "add_block_notice_mutes",
        stmts: STATE_DB_V49_DDL,
    },
    // ISP block-page rule candidates — `isp_block_candidates_enabled` on
    // `service_stability_config`. The detector and its journal shipped with no
    // admin-facing switch, so the feature could never be turned on to test.
    // Purely additive ALTER, defaults off. DEV schema; wiped freely.
    MigrationDef {
        version: 50,
        name: "add_isp_block_candidates_enabled",
        stmts: STATE_DB_V50_DDL,
    },
    // Mute a block notice by REASON — the v49 CHECK enumerated the three
    // scopes that existed then, so the table is rebuilt to widen it. Existing
    // mutes are not carried over. DEV schema; wiped freely.
    MigrationDef {
        version: 51,
        name: "widen_block_notice_mute_scopes",
        stmts: STATE_DB_V51_DDL,
    },
    // Companion-domain evidence across restarts — `auto_rule_evidence`. A
    // restart used to reset the window count that a proposal needs two of, so
    // a machine that restarts often never offered anything. Purely additive
    // CREATE. DEV schema; wiped freely.
    MigrationDef {
        version: 52,
        name: "add_auto_rule_evidence",
        stmts: STATE_DB_V52_DDL,
    },
];

// ── Required schema elements — used by verify_schema ─────────────────────────

const CACHE_REQUIRED_TABLES: &[&str] = &[
    "schema_migrations",
    "hostnames",
    "ip_addresses",
    "hostname_ip_resolutions",
    "shared_ip_direct_hosts",
    "fake_ip_bindings",
    "fake_ip_pool_meta",
    "lookup_events",
    "negative_cache",
    "cache_metadata",
];

const CACHE_REQUIRED_INDEXES: &[&str] = &[
    "idx_hostnames_last_seen",
    "idx_ip_ipv4_packed",
    "idx_ip_last_seen",
    "idx_res_hostname",
    "idx_res_ip",
    "idx_res_expires",
    "idx_res_freshness",
    "idx_res_revision",
    "idx_res_flags",
    "idx_lookup_events_expires",
    "idx_lookup_events_created",
    "idx_neg_cache_expires",
];

const TRAFFIC_REQUIRED_TABLES: &[&str] = &[
    "schema_migrations",
    "interface_daily_traffic",
    "interface_identity",
    "interface_counter_cursor",
    "traffic_metadata",
    "adapter_addresses",
];

// The `(day, adapter_key, role)` primary key is the covering index for every
// query the traffic store runs, so there are no secondary indexes to verify.
const TRAFFIC_REQUIRED_INDEXES: &[&str] = &[];

const STATE_REQUIRED_TABLES: &[&str] = &[
    "schema_migrations",
    "active_revision",
    "last_known_good",
    "integrity_log",
    "apply_snapshots",
    "route_bindings",
    "behavior_mode",
    "secondary_block_policy",
    "migration_state",
    "revisions",
    "active_revision_pointer",
    "mutation_tokens",
    "retention_settings",
    "apply_failure_policy_settings",
    "routing_pause_state",
    "autostart_state",
    // State DB v8.
    "service_stability_config",
    // State DB v10.
    "explain_snapshots",
    // State DB v18.
    "log_retention_config",
    // State DB v29.
    "app_pattern_resolutions",
    "vpn_bootstrap_endpoints",
    // State DB v30.
    "route_link_provider_apps",
    // State DB v31.
    "doh_resolver_entries",
    // State DB v37 — VPN self-heal exclusions.
    "fake_ip_heal_exclusions",
    // State DB v41 — learned VPN client apps.
    "vpn_client_apps",
    // State DB v43 — refused companion-domain suggestions.
    "auto_rule_dismissals",
    // State DB v44 — persisted application destinations.
    "app_observed_destinations",
    // State DB v49 — durable block-notice mutes.
    "block_notice_mutes",
    "auto_rule_evidence",
];

const STATE_REQUIRED_INDEXES: &[&str] = &[
    "idx_integrity_log_checked",
    "idx_apply_snapshots_created",
    "idx_route_bindings_sid",
    "idx_revisions_status",
    "idx_revisions_created",
    // Per-principal active index + principal lookup
    // (replaces the v6 singleton `idx_one_active_revision`).
    "idx_one_active_revision_per_principal",
    "idx_revisions_principal",
    "idx_mutation_tokens_expires",
    "idx_routing_pause_paused",
    // State DB v10.
    "idx_explain_expires_created",
    // State DB v43 — refused companion-domain suggestions.
    "idx_auto_rule_dismissals_sid",
    // State DB v44 — persisted application destinations.
    "idx_app_observed_destinations_learned",
    // State DB v49 — durable block-notice mutes.
    "idx_block_notice_mutes_sid",
];

// ── Connection factory ────────────────────────────────────────────────────────

/// Opens a file-based SQLite connection with mandatory baseline PRAGMAs.
///
/// Sets WAL journal mode (verified, not assumed), enables foreign key
/// enforcement, and configures a 5-second busy timeout.
pub fn open_connection(path: &Path) -> StorageResult<Connection> {
    let conn = Connection::open(path)
        .map_err(|e| StorageError::StorageUnavailable(format!("open {}: {e}", path.display())))?;

    let mode: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
        .map_err(|e| StorageError::Internal(format!("WAL pragma: {e}")))?;
    if mode != "wal" {
        return Err(StorageError::StorageUnavailable(format!(
            "WAL mode not supported at {} (filesystem returned {mode:?}); \
             database must reside on a local NTFS volume",
            path.display()
        )));
    }

    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .map_err(|e| StorageError::Internal(format!("foreign_keys pragma: {e}")))?;

    conn.busy_timeout(std::time::Duration::from_millis(5_000))
        .map_err(|e| StorageError::Internal(format!("busy_timeout: {e}")))?;

    Ok(conn)
}

// ── Rebuildable traffic DB — open with delete + rebuild on failure ───────────

/// Appends a SQLite sidecar suffix (`-wal` / `-shm`) to the full database file
/// name, matching how SQLite itself derives sidecar paths.
fn sidecar_path(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    std::path::PathBuf::from(name)
}

/// Deletes a database file together with its `-wal`/`-shm` sidecars.
/// Missing files are not an error; only genuine I/O failures are reported.
fn remove_database_files(path: &Path) -> std::io::Result<()> {
    for p in [
        path.to_path_buf(),
        sidecar_path(path, "-wal"),
        sidecar_path(path, "-shm"),
    ] {
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// One attempt at opening + migrating the traffic-stats database.
///
/// The connection (and with it the OS file handle) is dropped on any error,
/// so the caller may safely delete the database files afterwards.
fn open_traffic_connection_once(path: &Path) -> StorageResult<Connection> {
    let conn = open_connection(path)?;
    // Rebuildable ledger — relax durability to `synchronous = NORMAL`
    // (WAL-safe); a corrupt traffic DB is deleted + rebuilt, so full fsync
    // durability is wasted overhead. Best-effort: on failure the connection
    // keeps its defaults.
    let _: rusqlite::Result<()> = conn.execute_batch("PRAGMA synchronous = NORMAL;");
    let runner = SqliteMigrationRunner::for_traffic_db(conn);
    runner.run_pending_migrations()?;
    Ok(runner.into_connection())
}

/// Successful outcome of [`open_traffic_connection_or_rebuild`].
pub struct TrafficDbOpen {
    /// Migrated connection, ready for a `SqliteTrafficStore`.
    pub connection: Connection,
    /// `Some(first-attempt error)` when the database was deleted and recreated
    /// because the first open/migration attempt failed; `None` on a clean
    /// open. Callers should surface a rebuild in their operational log once.
    pub rebuilt_reason: Option<String>,
}

/// Opens the rebuildable traffic-stats database, recovering from corruption.
///
/// The traffic ledger carries no service-critical data, so any first-attempt
/// failure — structural corruption, a stale migration checksum after an
/// in-place schema edit, an unreadable file — is resolved by deleting the
/// database together with its WAL sidecars and rebuilding it from scratch,
/// exactly once. A failure of the rebuilt open (or of the deletion itself)
/// is returned to the caller.
pub fn open_traffic_connection_or_rebuild(path: &Path) -> StorageResult<TrafficDbOpen> {
    let first_error = match open_traffic_connection_once(path) {
        Ok(connection) => {
            return Ok(TrafficDbOpen {
                connection,
                rebuilt_reason: None,
            });
        }
        Err(e) => e,
    };

    remove_database_files(path).map_err(|io| {
        StorageError::StorageUnavailable(format!(
            "delete for rebuild of {} failed: {io} (original failure: {first_error})",
            path.display()
        ))
    })?;

    let connection = open_traffic_connection_once(path)?;
    Ok(TrafficDbOpen {
        connection,
        rebuilt_reason: Some(first_error.to_string()),
    })
}

// ── SqliteMigrationRunner ─────────────────────────────────────────────────────

/// Idempotent migration runner for a single SQLite database.
///
/// Takes ownership of the connection (wrapped in [`RefCell`]) so that `&self`
/// trait methods can take a mutable borrow when creating transactions.  After
/// migrations succeed, hand the connection back to the repository via
/// [`into_connection`][Self::into_connection].
pub struct SqliteMigrationRunner {
    conn: RefCell<Connection>,
    migrations: &'static [MigrationDef],
    required_tables: &'static [&'static str],
    required_indexes: &'static [&'static str],
}

impl SqliteMigrationRunner {
    pub fn for_cache_db(conn: Connection) -> Self {
        Self {
            conn: RefCell::new(conn),
            migrations: CACHE_MIGRATIONS,
            required_tables: CACHE_REQUIRED_TABLES,
            required_indexes: CACHE_REQUIRED_INDEXES,
        }
    }

    pub fn for_state_db(conn: Connection) -> Self {
        Self {
            conn: RefCell::new(conn),
            migrations: STATE_MIGRATIONS,
            required_tables: STATE_REQUIRED_TABLES,
            required_indexes: STATE_REQUIRED_INDEXES,
        }
    }

    /// Migration runner for the Block T traffic-stats DB (`nrr_traffic_stats.db`).
    pub fn for_traffic_db(conn: Connection) -> Self {
        Self {
            conn: RefCell::new(conn),
            migrations: TRAFFIC_MIGRATIONS,
            required_tables: TRAFFIC_REQUIRED_TABLES,
            required_indexes: TRAFFIC_REQUIRED_INDEXES,
        }
    }

    /// Consumes the runner and returns the underlying connection for use by the
    /// repository.  Call after [`run_pending_migrations`] and [`verify_schema`]
    /// have both succeeded.
    ///
    /// [`run_pending_migrations`]: MigrationRunner::run_pending_migrations
    /// [`verify_schema`]: MigrationRunner::verify_schema
    pub fn into_connection(self) -> Connection {
        self.conn.into_inner()
    }
}

impl MigrationRunner for SqliteMigrationRunner {
    fn current_schema_version(&self) -> StorageResult<u32> {
        let conn = self.conn.borrow();
        current_version(&conn)
    }

    fn run_pending_migrations(&self) -> StorageResult<MigrationSummary> {
        let from_version = {
            let conn = self.conn.borrow();
            ensure_migrations_table(&conn)?;
            let v = current_version(&conn)?;
            validate_applied_checksums(&conn, self.migrations, v)?;
            v
        };

        let max_available = self.migrations.iter().map(|m| m.version).max().unwrap_or(0);

        if from_version > max_available {
            return Err(StorageError::UnsupportedSchemaVersion {
                found: from_version,
                max_supported: max_available,
            });
        }

        let pending: Vec<&MigrationDef> = self
            .migrations
            .iter()
            .filter(|m| m.version > from_version)
            .collect();

        let mut applied_names: Vec<String> = Vec::with_capacity(pending.len());
        for migration in &pending {
            {
                let mut conn = self.conn.borrow_mut();
                apply_migration(&mut conn, migration)?;
            }
            applied_names.push(migration.name.to_string());
        }

        let to_version = pending.last().map(|m| m.version).unwrap_or(from_version);

        Ok(MigrationSummary {
            from_version,
            to_version,
            migrations_applied: applied_names,
            completed_at: SystemTime::now(),
        })
    }

    fn verify_schema(&self) -> StorageResult<SchemaVerification> {
        let conn = self.conn.borrow();
        let version = current_version(&conn)?;

        let required_tables_present = self
            .required_tables
            .iter()
            .all(|t| relation_exists(&conn, "table", t));

        let foreign_keys_ok: bool = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get::<_, i64>(0))
            .map(|v| v == 1)
            .unwrap_or(false);

        let indexes_ok = self
            .required_indexes
            .iter()
            .all(|idx| relation_exists(&conn, "index", idx));

        Ok(SchemaVerification {
            version,
            required_tables_present,
            foreign_keys_ok,
            indexes_ok,
        })
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn ensure_migrations_table(conn: &Connection) -> StorageResult<()> {
    conn.execute_batch(CREATE_SCHEMA_MIGRATIONS)
        .map_err(|e| StorageError::Internal(format!("create schema_migrations: {e}")))
}

/// Reads the current `schema_migrations` version from an already-open
/// connection **without** taking ownership of it.
///
/// [`SqliteMigrationRunner::current_schema_version`] requires owning the
/// `Connection` (it holds one in a `RefCell`), which doesn't fit callers
/// that only have a shared `Arc<Mutex<Connection>>` opened elsewhere (e.g.
/// the diagnostic archive builder, which reads the version for
/// `health.json` enrichment without disturbing the connection's real
/// owner). Returns `0` when the `schema_migrations` table itself doesn't
/// exist yet (fresh/un-migrated database) — same convention as
/// [`current_version`] internally.
///
/// [`SqliteMigrationRunner::current_schema_version`]: crate::repository::MigrationRunner::current_schema_version
pub fn read_schema_version(conn: &Connection) -> StorageResult<u32> {
    current_version(conn)
}

fn current_version(conn: &Connection) -> StorageResult<u32> {
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type='table' AND name='schema_migrations'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .map_err(|e| StorageError::Internal(format!("check schema_migrations: {e}")))?;

    if !exists {
        return Ok(0);
    }

    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |r| r.get::<_, i64>(0),
    )
    .map(|v| v as u32)
    .map_err(|e| StorageError::Internal(format!("read schema version: {e}")))
}

fn apply_migration(conn: &mut Connection, migration: &MigrationDef) -> StorageResult<()> {
    let from = migration.version.saturating_sub(1);
    let mk_err = |reason: String| StorageError::MigrationFailed {
        from_version: from,
        to_version: migration.version,
        reason,
    };

    let tx = conn
        .transaction()
        .map_err(|e| mk_err(format!("begin transaction: {e}")))?;

    for stmt in migration.stmts {
        tx.execute_batch(stmt)
            .map_err(|e| mk_err(format!("DDL failed: {e}")))?;
    }

    tx.execute(
        "INSERT OR IGNORE INTO schema_migrations
         (version, name, applied_at, checksum, app_version)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            migration.version as i64,
            migration.name,
            system_time_to_ms(SystemTime::now()),
            checksum_of(migration.stmts),
            env!("CARGO_PKG_VERSION"),
        ],
    )
    .map_err(|e| mk_err(format!("record migration: {e}")))?;

    tx.commit().map_err(|e| mk_err(format!("commit: {e}")))?;

    Ok(())
}

/// Validates that checksums stored in `schema_migrations` for already-applied
/// migrations match the checksums computed from the current embedded SQL.
///
/// A mismatch means either the migration SQL was edited after being applied
/// (schema drift) or the database was tampered with.  Either case is fatal —
/// the runner cannot safely determine which migrations to apply next.
fn validate_applied_checksums(
    conn: &Connection,
    migrations: &[MigrationDef],
    applied_up_to: u32,
) -> StorageResult<()> {
    for migration in migrations.iter().filter(|m| m.version <= applied_up_to) {
        let stored: Option<String> = conn
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = ?1",
                rusqlite::params![migration.version as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| {
                StorageError::Internal(format!("read checksum v{}: {e}", migration.version))
            })?;

        if let Some(stored_checksum) = stored {
            let computed = checksum_of(migration.stmts);
            if stored_checksum != computed {
                return Err(StorageError::MigrationFailed {
                    from_version: migration.version.saturating_sub(1),
                    to_version: migration.version,
                    reason: format!(
                        "checksum mismatch for migration '{}' (v{}): \
                         stored={stored_checksum}, computed={computed} — \
                         migration SQL may have changed after it was applied",
                        migration.name, migration.version,
                    ),
                });
            }
        }
    }
    Ok(())
}

fn relation_exists(conn: &Connection, kind: &str, name: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type=?1 AND name=?2",
        rusqlite::params![kind, name],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
    .unwrap_or(false)
}

fn system_time_to_ms(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// FNV-1a 64-bit checksum over all SQL statements, separated by a null byte.
fn checksum_of(stmts: &[&str]) -> String {
    const OFFSET: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;
    let mut h = OFFSET;
    for stmt in stmts {
        for b in stmt.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(PRIME);
        }
        h ^= 0x00;
        h = h.wrapping_mul(PRIME);
    }
    format!("{h:016x}")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::MigrationRunner;

    fn cache_runner(dir: &tempfile::TempDir) -> SqliteMigrationRunner {
        let path = dir.path().join("cache.db");
        let conn = open_connection(&path).expect("open_connection");
        SqliteMigrationRunner::for_cache_db(conn)
    }

    fn state_runner(dir: &tempfile::TempDir) -> SqliteMigrationRunner {
        let path = dir.path().join("state.db");
        let conn = open_connection(&path).expect("open_connection");
        SqliteMigrationRunner::for_state_db(conn)
    }

    // ── open_connection ───────────────────────────────────────────────────────

    #[test]
    fn open_connection_enables_wal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("t.db");
        let conn = open_connection(&path).expect("connect");
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .expect("pragma");
        assert_eq!(mode, "wal");
    }

    #[test]
    fn open_connection_enables_foreign_keys() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("t.db");
        let conn = open_connection(&path).expect("connect");
        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .expect("pragma");
        assert_eq!(fk, 1);
    }

    #[test]
    fn open_connection_reopen_is_consistent() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("t.db");
        let _ = open_connection(&path).expect("first open");
        let conn2 = open_connection(&path).expect("reopen");
        // WAL and FK still enabled on second open
        let mode: String = conn2
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .expect("mode");
        assert_eq!(mode, "wal");
    }

    // ── schema version on fresh db ────────────────────────────────────────────

    #[test]
    fn version_zero_before_migrations() {
        let dir = tempfile::tempdir().expect("temp dir");
        let runner = cache_runner(&dir);
        assert_eq!(runner.current_schema_version().expect("version"), 0);
    }

    #[test]
    fn version_zero_when_migrations_table_absent() {
        // current_schema_version must return 0 even if schema_migrations was
        // never created (e.g. called before run_pending_migrations).
        let dir = tempfile::tempdir().expect("temp dir");
        let runner = cache_runner(&dir);
        assert_eq!(runner.current_schema_version().expect("version"), 0);
    }

    // ── cache DB migrations ───────────────────────────────────────────────────

    #[test]
    fn run_cache_migrations_empty_db() {
        let dir = tempfile::tempdir().expect("temp dir");
        let runner = cache_runner(&dir);

        let s = runner.run_pending_migrations().expect("migrate");
        assert_eq!(s.from_version, 0);
        assert_eq!(s.to_version, 4);
        assert_eq!(
            s.migrations_applied,
            [
                "initial_cache_schema",
                "add_shared_ip_census",
                "add_fake_ip_bindings",
                "add_shared_ip_census_primary_ruled"
            ]
        );
    }

    #[test]
    fn cache_migration_idempotent() {
        let dir = tempfile::tempdir().expect("temp dir");
        let runner = cache_runner(&dir);

        runner.run_pending_migrations().expect("first run");
        let s = runner.run_pending_migrations().expect("second run");
        assert_eq!(s.from_version, 4);
        assert_eq!(s.to_version, 4);
        assert!(
            s.migrations_applied.is_empty(),
            "no migrations on second run"
        );
    }

    #[test]
    fn cache_schema_version_is_4_after_migration() {
        let dir = tempfile::tempdir().expect("temp dir");
        let runner = cache_runner(&dir);
        runner.run_pending_migrations().expect("migrate");
        assert_eq!(runner.current_schema_version().expect("version"), 4);
    }

    // ── state DB migrations ───────────────────────────────────────────────────

    #[test]
    fn run_state_migrations_empty_db() {
        let dir = tempfile::tempdir().expect("temp dir");
        let runner = state_runner(&dir);

        let s = runner.run_pending_migrations().expect("migrate");
        assert_eq!(s.from_version, 0);
        // v1..v4 (baseline) + v5 (per-SID routing)
        // + v6 (rules revisions)
        // + v7 (settings + pause state)
        // + v8 (service stability config)
        // + v9 (verbose_logging column)
        // + v10 (explain_snapshots table)
        // + v11 (revisions.row_hmac column)
        // + v12 (per-principal revisions reset)
        // + v13 (conn-trace toggles on service_stability_config)
        // + v14 (rule-scope on service_stability_config)
        // + v15 (kill-switch fail-closed on secondary_block_policy)
        // + v16 (multi-protocol kill-switch on secondary_block_policy)
        // + v17 (routing_stop_policy on service_stability_config — persist-on-stop)
        // + v18 (log_retention_config table — log/audit retention)
        // + v19 (cache_refresh_interval on service_stability_config)
        // + v20 (include_subdomains on secondary_block_policy)
        // + v21 (shared_ip_policy on secondary_block_policy)
        // + v22 (known_stable_ids on route_bindings)
        // + v23 (kill_switch_block_all on secondary_block_policy)
        // + v24 (enforcement_mode on service_stability_config — Mode B)
        // + v25 (secondary_liveness_window_secs on service_stability_config)
        // + v26 (kill_switch_enabled on secondary_block_policy — master toggle)
        // + v27 (allow_dns_over_primary on secondary_block_policy — DNS opt-in)
        // + v28 (mode_a_coverage_strategy + resolve_hosts_bypass on secondary_block_policy)
        // + v29 (app_pattern_resolutions + vpn_bootstrap_endpoints tables)
        // + v30 (route_link_provider_apps table)
        // + v31 (doh_lockdown fields + doh_resolver_entries table)
        // + v32 (browser_history_auto_seed on secondary_block_policy)
        // + v33 (kill_switch_strict_shared_ips on secondary_block_policy)
        // + v34 (fake_ip_enabled on service_stability_config)
        // + v35 (traffic_stats_settings table)
        // + v36 (dns_via_secondary on service_stability_config)
        // + v37 (fake_ip_heal_exclusions table — VPN self-heal persistence)
        // + v38 (dns_fast_answers on service_stability_config)
        // + v39 (fake_ip_udp_relay on service_stability_config)
        // + v40 (fake_ip_instant_rst on service_stability_config)
        // + v41 (vpn_client_apps table — role-verified VPN client persistence)
        // + v42 (auto_rules_mode on secondary_block_policy)
        // + v43 (auto_rule_dismissals table — refused companion suggestions)
        // + v44 (app_observed_destinations table — persisted app destinations)
        // + v45 (allow_user_rule_edits on service_stability_config)
        // + v46 (auto_rules_eager_delivery_names on secondary_block_policy)
        // + v47 (auto_rule_pending_candidates table — durable pending suggestions)
        // + v48 (auto_rule_dismissals.dto_json — the refused offer, kept verbatim)
        // + v49 (block_notice_mutes table — durable "do not show" choices)
        // + v50 (isp_block_candidates_enabled on service_stability_config)
        assert_eq!(s.to_version, 52);
        assert_eq!(
            s.migrations_applied,
            [
                "initial_state_schema",
                "add_revision_integrity_hashes",
                "add_security_alerts",
                "add_apply_snapshots",
                "add_per_sid_routing_policy",
                "add_rules_revisions",
                "add_settings_and_pause_state",
                "add_service_stability_config",
                "add_verbose_logging_to_service_stability_config",
                "add_explain_snapshots",
                "add_revisions_row_hmac",
                "reset_revisions_for_per_principal",
                "add_conn_trace_toggles_to_service_stability_config",
                "add_rule_scope_to_service_stability_config",
                "add_kill_switch_fail_closed_to_secondary_block_policy",
                "add_kill_switch_protocols_to_secondary_block_policy",
                "add_routing_stop_policy_to_service_stability_config",
                "add_log_retention_config",
                "add_cache_refresh_interval_to_service_stability_config",
                "add_include_subdomains_to_secondary_block_policy",
                "add_shared_ip_policy_to_secondary_block_policy",
                "add_known_stable_ids_to_route_bindings",
                "add_kill_switch_block_all_to_secondary_block_policy",
                "add_enforcement_mode_to_service_stability_config",
                "add_secondary_liveness_window_to_service_stability_config",
                "add_kill_switch_enabled_to_secondary_block_policy",
                "add_allow_dns_over_primary_to_secondary_block_policy",
                "add_mode_a_coverage_and_hosts_bypass_to_secondary_block_policy",
                "add_app_pattern_resolutions_and_vpn_bootstrap_endpoints",
                "add_route_link_provider_apps",
                "add_doh_lockdown",
                "add_browser_history_auto_seed",
                "add_kill_switch_strict_shared_ips",
                "add_fake_ip_enabled",
                "add_traffic_stats_settings",
                "add_dns_via_secondary",
                "add_fake_ip_heal_exclusions",
                "add_dns_fast_answers",
                "add_fake_ip_udp_relay",
                "add_fake_ip_instant_rst",
                "add_vpn_client_apps",
                "add_auto_rules_mode",
                "add_auto_rule_dismissals",
                "add_app_observed_destinations",
                "add_allow_user_rule_edits",
                "add_auto_rules_eager_delivery_names",
                "add_auto_rule_pending_candidates",
                "add_auto_rule_dismissal_dto",
                "add_block_notice_mutes",
                "add_isp_block_candidates_enabled",
                "widen_block_notice_mute_scopes",
                "add_auto_rule_evidence",
            ]
        );
    }

    #[test]
    fn state_migration_idempotent() {
        let dir = tempfile::tempdir().expect("temp dir");
        let runner = state_runner(&dir);

        runner.run_pending_migrations().expect("first run");
        let s = runner.run_pending_migrations().expect("second run");
        assert_eq!(s.from_version, 52);
        assert_eq!(s.to_version, 52);
        assert!(s.migrations_applied.is_empty());
    }

    // ── verify_schema ─────────────────────────────────────────────────────────

    #[test]
    fn verify_cache_schema_after_migration() {
        let dir = tempfile::tempdir().expect("temp dir");
        let runner = cache_runner(&dir);
        runner.run_pending_migrations().expect("migrate");

        let v = runner.verify_schema().expect("verify");
        assert!(v.is_ok(), "cache schema verification failed: {v:?}");
        assert_eq!(v.version, 4);
    }

    #[test]
    fn verify_state_schema_after_migration() {
        let dir = tempfile::tempdir().expect("temp dir");
        let runner = state_runner(&dir);
        runner.run_pending_migrations().expect("migrate");

        let v = runner.verify_schema().expect("verify");
        assert!(v.is_ok(), "state schema verification failed: {v:?}");
        // through v50 (isp_block_candidates_enabled on service_stability_config)
        assert_eq!(v.version, 52);
    }

    #[test]
    fn verify_schema_fails_before_migration() {
        let dir = tempfile::tempdir().expect("temp dir");
        let runner = cache_runner(&dir);
        // No migration run — required tables are missing.
        let v = runner.verify_schema().expect("verify");
        assert!(!v.required_tables_present);
    }

    // ── unsupported future schema version ─────────────────────────────────────

    #[test]
    fn unsupported_future_schema_returns_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("cache.db");

        // Seed a "future" version directly.
        {
            let conn = open_connection(&path).expect("open");
            conn.execute_batch(CREATE_SCHEMA_MIGRATIONS).expect("setup");
            conn.execute(
                "INSERT INTO schema_migrations
                 (version, name, applied_at, checksum, app_version)
                 VALUES (99, 'future', 0, 'deadbeef', '99.0.0')",
                [],
            )
            .expect("insert future version");
        }

        let conn = open_connection(&path).expect("reopen");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        let result = runner.run_pending_migrations();

        assert!(
            matches!(
                result,
                Err(StorageError::UnsupportedSchemaVersion { found: 99, .. })
            ),
            "expected UnsupportedSchemaVersion, got: {result:?}"
        );
    }

    // ── into_connection ───────────────────────────────────────────────────────

    #[test]
    fn into_connection_returns_working_connection() {
        let dir = tempfile::tempdir().expect("temp dir");
        let runner = cache_runner(&dir);
        runner.run_pending_migrations().expect("migrate");

        let conn = runner.into_connection();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
            .expect("query");
        assert_eq!(
            count, 4,
            "schema_migrations must have one row per applied cache migration (v1..v4)"
        );
    }

    // ── schema_migrations record integrity ────────────────────────────────────

    #[test]
    fn migration_record_has_correct_version_and_name() {
        let dir = tempfile::tempdir().expect("temp dir");
        let runner = cache_runner(&dir);
        runner.run_pending_migrations().expect("migrate");

        let conn = runner.into_connection();
        let (version, name, checksum): (i64, String, String) = conn
            .query_row(
                "SELECT version, name, checksum FROM schema_migrations WHERE version = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("query");
        assert_eq!(version, 1);
        assert_eq!(name, "initial_cache_schema");
        assert!(!checksum.is_empty());
    }

    // ── checksum ─────────────────────────────────────────────────────────────

    #[test]
    fn checksum_is_deterministic() {
        let stmts: &[&str] = &["CREATE TABLE foo (id INTEGER)", "CREATE INDEX i ON foo(id)"];
        assert_eq!(checksum_of(stmts), checksum_of(stmts));
    }

    #[test]
    fn checksum_is_16_hex_chars() {
        let c = checksum_of(&["SELECT 1"]);
        assert_eq!(c.len(), 16, "FNV-64 hex must be 16 chars");
        assert!(c.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn checksum_differs_for_different_sql() {
        let a = checksum_of(&["CREATE TABLE foo (id INTEGER)"]);
        let b = checksum_of(&["CREATE TABLE bar (id INTEGER)"]);
        assert_ne!(a, b);
    }

    #[test]
    fn checksum_order_sensitive() {
        let s1: &[&str] = &["AAA", "BBB"];
        let s2: &[&str] = &["BBB", "AAA"];
        assert_ne!(checksum_of(s1), checksum_of(s2));
    }

    // ── busy_timeout ──────────────────────────────────────────────────────────

    #[test]
    fn open_connection_sets_busy_timeout_5000ms() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("t.db");
        let conn = open_connection(&path).expect("connect");
        // sqlite3_busy_timeout() sets the PRAGMA value — verify it was applied.
        let ms: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .expect("pragma");
        assert_eq!(ms, 5_000, "busy_timeout must be 5000 ms baseline");
    }

    // ── interrupted migration — transaction atomicity ─────────────────────────

    #[test]
    fn interrupted_migration_leaves_db_unchanged() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("t.db");
        let mut conn = open_connection(&path).expect("open");
        ensure_migrations_table(&conn).expect("bootstrap");

        // A migration whose second statement contains invalid SQL.
        // The first statement must be rolled back together with the second.
        let bad = MigrationDef {
            version: 1,
            name: "bad",
            stmts: &[
                "CREATE TABLE valid_table (id INTEGER)",
                "THIS IS NOT VALID SQL;;;",
            ],
        };
        let result = apply_migration(&mut conn, &bad);
        assert!(result.is_err(), "bad DDL must fail");

        // Transaction must have been rolled back: version is still 0.
        assert_eq!(current_version(&conn).expect("version"), 0);

        // The first DDL statement must also be rolled back.
        let table_present: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='valid_table'",
                [],
                |r| r.get(0),
            )
            .expect("query");
        assert_eq!(
            table_present, 0,
            "partial DDL must be rolled back by transaction"
        );
    }

    // ── checksum mismatch detection ───────────────────────────────────────────

    #[test]
    fn migration_checksum_mismatch_detected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("cache.db");

        // Run migrations normally.
        {
            let conn = open_connection(&path).expect("open");
            let runner = SqliteMigrationRunner::for_cache_db(conn);
            runner.run_pending_migrations().expect("first run");
        }

        // Corrupt the stored checksum via a direct connection.
        {
            let conn = open_connection(&path).expect("open for corruption");
            conn.execute(
                "UPDATE schema_migrations SET checksum = 'deadbeef00000000' WHERE version = 1",
                [],
            )
            .expect("corrupt checksum");
        }

        // Re-open: run_pending_migrations must detect the mismatch.
        let conn = open_connection(&path).expect("reopen");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        let result = runner.run_pending_migrations();
        assert!(
            matches!(result, Err(StorageError::MigrationFailed { .. })),
            "expected MigrationFailed for checksum mismatch, got: {result:?}"
        );
    }

    // ── traffic DB — delete + rebuild on open/migration failure ──────────────

    #[test]
    fn traffic_db_clean_open_reports_no_rebuild() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("nrr_traffic_stats.db");

        let opened = open_traffic_connection_or_rebuild(&path).expect("open");
        assert!(opened.rebuilt_reason.is_none(), "fresh DB must not rebuild");
        let version = read_schema_version(&opened.connection).expect("version");
        assert_eq!(version, 1);
    }

    #[test]
    fn traffic_db_checksum_mismatch_is_deleted_and_rebuilt() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("nrr_traffic_stats.db");

        // Create + migrate, then leave a marker row a rebuild must discard.
        {
            let opened = open_traffic_connection_or_rebuild(&path).expect("first open");
            assert!(opened.rebuilt_reason.is_none());
            opened
                .connection
                .execute(
                    "INSERT INTO interface_identity (adapter_key, display_name, last_seen)
                     VALUES ('eth0', 'Ethernet', 0)",
                    [],
                )
                .expect("marker row");
        }

        // Corrupt the stored migration checksum — simulates the SQL of an
        // already-applied migration changing in place.
        {
            let conn = open_connection(&path).expect("open for corruption");
            conn.execute(
                "UPDATE schema_migrations SET checksum = 'deadbeef00000000' WHERE version = 1",
                [],
            )
            .expect("corrupt checksum");
        }

        // Reopen: the mismatch must trigger delete + rebuild, not a failure.
        let opened = open_traffic_connection_or_rebuild(&path).expect("rebuild open");
        let reason = opened.rebuilt_reason.as_deref().expect("rebuild reported");
        assert!(
            reason.contains("checksum mismatch"),
            "reason must carry the original failure, got: {reason}"
        );

        // Fresh schema: the marker row is gone, the store is fully usable.
        let markers: i64 = opened
            .connection
            .query_row("SELECT COUNT(*) FROM interface_identity", [], |r| r.get(0))
            .expect("query rebuilt DB");
        assert_eq!(markers, 0, "rebuild must discard old data");
        drop(opened);

        // A subsequent open is clean — the rebuilt DB has valid checksums.
        let opened = open_traffic_connection_or_rebuild(&path).expect("clean reopen");
        assert!(opened.rebuilt_reason.is_none());
    }

    #[test]
    fn traffic_db_garbage_file_is_deleted_and_rebuilt() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("nrr_traffic_stats.db");
        std::fs::write(&path, b"this is not a sqlite database").expect("write garbage");
        // A stray sidecar must be removed together with the main file.
        std::fs::write(sidecar_path(&path, "-wal"), b"stale wal").expect("write sidecar");

        let opened = open_traffic_connection_or_rebuild(&path).expect("rebuild open");
        assert!(opened.rebuilt_reason.is_some(), "garbage file must rebuild");
        let version = read_schema_version(&opened.connection).expect("version");
        assert_eq!(version, 1);
    }

    // ── incremental state DB upgrades ────────────────────────────────────────

    #[test]
    fn upgrade_state_db_from_v1_to_v2() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("state.db");

        // Simulate a DB created by an older binary: only v1 applied.
        {
            let mut conn = open_connection(&path).expect("open");
            ensure_migrations_table(&conn).expect("bootstrap");
            apply_migration(&mut conn, &STATE_MIGRATIONS[0]).expect("apply v1");
        }

        // New binary: runner must detect v1 and apply v2 + v3.
        let conn = open_connection(&path).expect("reopen");
        let runner = SqliteMigrationRunner::for_state_db(conn);

        assert_eq!(runner.current_schema_version().expect("before"), 1);

        let summary = runner.run_pending_migrations().expect("upgrade v1→latest");
        assert_eq!(summary.from_version, 1);
        assert_eq!(summary.to_version, 52);
        assert_eq!(
            summary.migrations_applied,
            [
                "add_revision_integrity_hashes",
                "add_security_alerts",
                "add_apply_snapshots",
                "add_per_sid_routing_policy",
                "add_rules_revisions",
                "add_settings_and_pause_state",
                "add_service_stability_config",
                "add_verbose_logging_to_service_stability_config",
                "add_explain_snapshots",
                "add_revisions_row_hmac",
                "reset_revisions_for_per_principal",
                "add_conn_trace_toggles_to_service_stability_config",
                "add_rule_scope_to_service_stability_config",
                "add_kill_switch_fail_closed_to_secondary_block_policy",
                "add_kill_switch_protocols_to_secondary_block_policy",
                "add_routing_stop_policy_to_service_stability_config",
                "add_log_retention_config",
                "add_cache_refresh_interval_to_service_stability_config",
                "add_include_subdomains_to_secondary_block_policy",
                "add_shared_ip_policy_to_secondary_block_policy",
                "add_known_stable_ids_to_route_bindings",
                "add_kill_switch_block_all_to_secondary_block_policy",
                "add_enforcement_mode_to_service_stability_config",
                "add_secondary_liveness_window_to_service_stability_config",
                "add_kill_switch_enabled_to_secondary_block_policy",
                "add_allow_dns_over_primary_to_secondary_block_policy",
                "add_mode_a_coverage_and_hosts_bypass_to_secondary_block_policy",
                "add_app_pattern_resolutions_and_vpn_bootstrap_endpoints",
                "add_route_link_provider_apps",
                "add_doh_lockdown",
                "add_browser_history_auto_seed",
                "add_kill_switch_strict_shared_ips",
                "add_fake_ip_enabled",
                "add_traffic_stats_settings",
                "add_dns_via_secondary",
                "add_fake_ip_heal_exclusions",
                "add_dns_fast_answers",
                "add_fake_ip_udp_relay",
                "add_fake_ip_instant_rst",
                "add_vpn_client_apps",
                "add_auto_rules_mode",
                "add_auto_rule_dismissals",
                "add_app_observed_destinations",
                "add_allow_user_rule_edits",
                "add_auto_rules_eager_delivery_names",
                "add_auto_rule_pending_candidates",
                "add_auto_rule_dismissal_dto",
                "add_block_notice_mutes",
                "add_isp_block_candidates_enabled",
                "widen_block_notice_mute_scopes",
                "add_auto_rule_evidence",
            ]
        );

        // The integrity_hash column added by v2 must be queryable.
        let conn = runner.into_connection();
        let _hash: Option<String> = conn
            .query_row(
                "SELECT integrity_hash FROM active_revision LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .expect("integrity_hash column must exist after v2");
    }

    #[test]
    fn upgrade_state_db_from_v2_to_v3() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("state.db");

        // Simulate a DB at v2.
        {
            let mut conn = open_connection(&path).expect("open");
            ensure_migrations_table(&conn).expect("bootstrap");
            apply_migration(&mut conn, &STATE_MIGRATIONS[0]).expect("apply v1");
            apply_migration(&mut conn, &STATE_MIGRATIONS[1]).expect("apply v2");
        }

        let conn = open_connection(&path).expect("reopen");
        let runner = SqliteMigrationRunner::for_state_db(conn);

        assert_eq!(runner.current_schema_version().expect("before"), 2);

        let summary = runner.run_pending_migrations().expect("upgrade v2→latest");
        assert_eq!(summary.from_version, 2);
        assert_eq!(summary.to_version, 52);
        assert_eq!(
            summary.migrations_applied,
            [
                "add_security_alerts",
                "add_apply_snapshots",
                "add_per_sid_routing_policy",
                "add_rules_revisions",
                "add_settings_and_pause_state",
                "add_service_stability_config",
                "add_verbose_logging_to_service_stability_config",
                "add_explain_snapshots",
                "add_revisions_row_hmac",
                "reset_revisions_for_per_principal",
                "add_conn_trace_toggles_to_service_stability_config",
                "add_rule_scope_to_service_stability_config",
                "add_kill_switch_fail_closed_to_secondary_block_policy",
                "add_kill_switch_protocols_to_secondary_block_policy",
                "add_routing_stop_policy_to_service_stability_config",
                "add_log_retention_config",
                "add_cache_refresh_interval_to_service_stability_config",
                "add_include_subdomains_to_secondary_block_policy",
                "add_shared_ip_policy_to_secondary_block_policy",
                "add_known_stable_ids_to_route_bindings",
                "add_kill_switch_block_all_to_secondary_block_policy",
                "add_enforcement_mode_to_service_stability_config",
                "add_secondary_liveness_window_to_service_stability_config",
                "add_kill_switch_enabled_to_secondary_block_policy",
                "add_allow_dns_over_primary_to_secondary_block_policy",
                "add_mode_a_coverage_and_hosts_bypass_to_secondary_block_policy",
                "add_app_pattern_resolutions_and_vpn_bootstrap_endpoints",
                "add_route_link_provider_apps",
                "add_doh_lockdown",
                "add_browser_history_auto_seed",
                "add_kill_switch_strict_shared_ips",
                "add_fake_ip_enabled",
                "add_traffic_stats_settings",
                "add_dns_via_secondary",
                "add_fake_ip_heal_exclusions",
                "add_dns_fast_answers",
                "add_fake_ip_udp_relay",
                "add_fake_ip_instant_rst",
                "add_vpn_client_apps",
                "add_auto_rules_mode",
                "add_auto_rule_dismissals",
                "add_app_observed_destinations",
                "add_allow_user_rule_edits",
                "add_auto_rules_eager_delivery_names",
                "add_auto_rule_pending_candidates",
                "add_auto_rule_dismissal_dto",
                "add_block_notice_mutes",
                "add_isp_block_candidates_enabled",
                "widen_block_notice_mute_scopes",
                "add_auto_rule_evidence",
            ]
        );

        // The security_alerts table added by v3 must be queryable.
        let conn = runner.into_connection();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM security_alerts", [], |r| r.get(0))
            .expect("security_alerts table must exist after v3");
        assert_eq!(count, 0, "fresh security_alerts table must be empty");
    }
}
