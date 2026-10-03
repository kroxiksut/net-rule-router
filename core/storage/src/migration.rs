//! Migration catalogues of the three service databases and the connection
//! factory.
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
//! The runner itself — one immediate transaction per run, checksums
//! re-validated on every open, the `schema_migrations` bookkeeping — is
//! `nrr-sqlite-support`, shared with the GUI sidecar.
//!
//! WAL is mandatory and verified on open: some network filesystems silently
//! fall back to DELETE mode.

use std::cell::RefCell;
use std::path::Path;
use std::time::{Duration, SystemTime};

use nrr_sqlite_support::{ConnectionError, MigrationError};
use rusqlite::Connection;

use crate::backup::{backup_database, BackupReason};
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
    STATE_DB_V52_DDL, STATE_DB_V53_DDL, STATE_DB_V54_DDL, STATE_DB_V55_DDL, STATE_DB_V56_DDL,
    STATE_DB_V57_DDL, STATE_DB_V58_DDL, STATE_DB_V59_DDL, STATE_DB_V5_DDL, STATE_DB_V60_DDL,
    STATE_DB_V61_DDL, STATE_DB_V62_DDL, STATE_DB_V63_DDL, STATE_DB_V64_DDL, STATE_DB_V65_DDL,
    STATE_DB_V66_DDL, STATE_DB_V67_DDL, STATE_DB_V6_DDL, STATE_DB_V7_DDL, STATE_DB_V8_DDL,
    STATE_DB_V9_DDL, TRAFFIC_DB_V1_DDL, TRAFFIC_DB_V2_DDL,
};

/// One versioned step; the catalogues below append, never edit.
pub(crate) type MigrationDef = nrr_sqlite_support::Migration;

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
pub(crate) const TRAFFIC_MIGRATIONS: &[MigrationDef] = &[
    MigrationDef {
        version: 1,
        name: "initial_traffic_schema",
        stmts: TRAFFIC_DB_V1_DDL,
    },
    MigrationDef {
        version: 2,
        name: "add_adapter_history_link",
        stmts: TRAFFIC_DB_V2_DDL,
    },
];

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
    // construction. Purely additive CREATE TABLE. DEV schema; wiped
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
    // Per-principal exceptions for LOCAL networks under the kill-switch: the
    // hypervisor segments a user does not want exempted, plus networks we
    // cannot discover (a NAT-mode hypervisor creates no host interface).
    MigrationDef {
        version: 53,
        name: "add_local_network_rules",
        stmts: STATE_DB_V53_DDL,
    },
    // Main-link probing: the per-principal opt-in plus the bounds one pass may
    // cost. Asked for explicitly by the owner: the limits belong to the user,
    // not to a constant in the binary.
    MigrationDef {
        version: 54,
        name: "add_primary_probe_preferences",
        stmts: STATE_DB_V54_DDL,
    },
    // Sites the user says refuse main-link addresses. The only thing no
    // measurement here can establish, so it is recorded rather than inferred.
    MigrationDef {
        version: 55,
        name: "add_refusing_anchors",
        stmts: STATE_DB_V55_DDL,
    },
    // IPv6 under leak protection. Default ON: a rule that closes a host over
    // one address family only has not closed it.
    MigrationDef {
        version: 56,
        name: "add_block_ipv6_when_protected",
        stmts: STATE_DB_V56_DDL,
    },
    // Notices raised with no surface listening. Without this the push channel
    // silently dropped them and a service-only user heard nothing.
    MigrationDef {
        version: 57,
        name: "add_block_notice_journal",
        stmts: STATE_DB_V57_DDL,
    },
    // A local-network answer follows its ADAPTER, not the segment number a
    // hypervisor switch reassigns on every reboot.
    MigrationDef {
        version: 58,
        name: "add_local_network_adapter",
        stmts: STATE_DB_V58_DDL,
    },
    // Opt out of being asked about local networks nobody has seen before.
    MigrationDef {
        version: 59,
        name: "add_local_networks_auto_accept",
        stmts: STATE_DB_V59_DDL,
    },
    // The pre-per-principal singletons, whose last reader was an integrity
    // check that verified its own bookkeeping.
    MigrationDef {
        version: 60,
        name: "drop_legacy_revision_singletons",
        stmts: STATE_DB_V60_DDL,
    },
    // Zone-vs-ExactIp order: documented as a user setting, never stored.
    MigrationDef {
        version: 61,
        name: "add_zone_priority_over_ip",
        stmts: STATE_DB_V61_DDL,
    },
    MigrationDef {
        version: 62,
        name: "sign_active_revision_pointer",
        stmts: STATE_DB_V62_DDL,
    },
    // The opt-in gate for provider-block offers that never got a reader. Two
    // gates already stand in front of those offers; a third one nothing
    // consults only costs the next person a run to rule out. The table is
    // rebuilt because the column carries a CHECK.
    MigrationDef {
        version: 63,
        name: "drop_isp_block_candidates_enabled",
        stmts: STATE_DB_V63_DDL,
    },
    MigrationDef {
        version: 64,
        name: "add_short_name_suffix",
        stmts: STATE_DB_V64_DDL,
    },
    MigrationDef {
        version: 65,
        name: "add_block_notice_launched_by",
        stmts: STATE_DB_V65_DDL,
    },
    MigrationDef {
        version: 66,
        name: "drop_integrity_log_and_apply_snapshots",
        stmts: STATE_DB_V66_DDL,
    },
    MigrationDef {
        version: 67,
        name: "verbose_logging_deadline",
        stmts: STATE_DB_V67_DDL,
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
    "adapter_history_link",
];

// The `(day, adapter_key, role)` primary key is the covering index for every
// query the traffic store runs, so there are no secondary indexes to verify.
const TRAFFIC_REQUIRED_INDEXES: &[&str] = &[];

const STATE_REQUIRED_TABLES: &[&str] = &[
    "schema_migrations",
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
    // State DB v53 — per-principal local-network exceptions.
    "local_network_rules",
    // State DB v55 — sites the user says refuse main-link addresses.
    "refusing_anchors",
    // State DB v57 — notices raised with nobody listening.
    "block_notice_journal",
];

const STATE_REQUIRED_INDEXES: &[&str] = &[
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
    // State DB v57 — notices raised with nobody listening.
    "idx_block_notice_journal_sid",
];

// ── Connection factory ────────────────────────────────────────────────────────

/// How long any connection to a local database waits out another's lock.
pub(crate) const BUSY_TIMEOUT: Duration = Duration::from_millis(5_000);

/// Opens a file-based SQLite connection with the baseline both local
/// databases share: [`BUSY_TIMEOUT`], WAL (verified), foreign keys.
pub fn open_connection(path: &Path) -> StorageResult<Connection> {
    let conn = Connection::open(path)
        .map_err(|e| StorageError::StorageUnavailable(format!("open {}: {e}", path.display())))?;

    nrr_sqlite_support::configure_connection(&conn, BUSY_TIMEOUT).map_err(|e| match e {
        ConnectionError::WalUnsupported { journal_mode } => {
            StorageError::StorageUnavailable(format!(
                "WAL mode not supported at {} (filesystem returned {journal_mode:?}); \
                     database must reside on a local volume",
                path.display()
            ))
        }
        ConnectionError::Sqlite(e) => StorageError::Internal(format!("connection pragmas: {e}")),
    })?;

    // Fold the journal back into the database file and shrink it. WAL's
    // automatic checkpoint copies pages across but never truncates the file, so
    // the journal only grows: on the owner's machine the three databases held
    // 6.2 MB while their journals held 13.4 MB, and the traffic ledger was 28 KB
    // of database behind 4.1 MB of journal — nearly all of that data lived in a
    // file that a crash-cleanup or a restore-from-copy would drop while leaving
    // an intact-looking database behind. Best-effort by design: with another
    // connection open, SQLite refuses to truncate and the next open retries.
    let _ = checkpoint_wal_truncate(&conn);
    crate::write_ledger::watch(&conn, path);

    Ok(conn)
}

/// Folds the write-ahead log back into the database file and truncates it.
///
/// Same call the connection factory makes on open, exposed for the long-uptime
/// case: a service that runs for days never re-opens its databases, and WAL's
/// automatic checkpoint copies pages across without ever shrinking the journal.
/// A second live connection makes SQLite refuse — the caller treats that as a
/// no-op and retries on its next pass.
pub fn checkpoint_wal_truncate(conn: &Connection) -> StorageResult<()> {
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| StorageError::Internal(format!("wal checkpoint: {e}")))
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
/// The traffic ledger carries no service-critical data, so a first-attempt
/// failure — structural corruption, a stale migration checksum after an
/// in-place schema edit, an unreadable file — is resolved by deleting the
/// database together with its WAL sidecars and rebuilding it from scratch,
/// exactly once. A failure of the rebuilt open (or of the deletion itself)
/// is returned to the caller. The one failure that is NOT rebuilt is a
/// database written by a newer build: it is intact, and erasing it would cost
/// the user their whole all-time ledger for starting an older binary once.
pub fn open_traffic_connection_or_rebuild(path: &Path) -> StorageResult<TrafficDbOpen> {
    let first_error = match open_traffic_connection_once(path) {
        Ok(connection) => {
            return Ok(TrafficDbOpen {
                connection,
                rebuilt_reason: None,
            });
        }
        // A database written by a NEWER build is intact, not corrupt: the
        // rebuild would silently erase the user's whole all-time ledger the
        // first time they start an older binary. Refuse instead — an
        // installer downgrade is the caller's problem to report.
        Err(e @ StorageError::UnsupportedSchemaVersion { .. }) => return Err(e),
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
    /// Whether an upgrade of THIS database is snapshotted first; a failed
    /// snapshot then refuses the upgrade. Off for the databases that are
    /// rebuildable by definition: losing them costs a rebuild, not data.
    snapshot_first: bool,
}

impl SqliteMigrationRunner {
    pub fn for_cache_db(conn: Connection) -> Self {
        Self {
            conn: RefCell::new(conn),
            migrations: CACHE_MIGRATIONS,
            required_tables: CACHE_REQUIRED_TABLES,
            required_indexes: CACHE_REQUIRED_INDEXES,
            snapshot_first: false,
        }
    }

    pub fn for_state_db(conn: Connection) -> Self {
        Self {
            conn: RefCell::new(conn),
            migrations: STATE_MIGRATIONS,
            required_tables: STATE_REQUIRED_TABLES,
            required_indexes: STATE_REQUIRED_INDEXES,
            // The only database here that cannot be rebuilt from anything.
            snapshot_first: true,
        }
    }

    /// Migration runner for the traffic-stats DB (`nrr_traffic_stats.db`).
    pub fn for_traffic_db(conn: Connection) -> Self {
        Self {
            conn: RefCell::new(conn),
            migrations: TRAFFIC_MIGRATIONS,
            required_tables: TRAFFIC_REQUIRED_TABLES,
            required_indexes: TRAFFIC_REQUIRED_INDEXES,
            snapshot_first: false,
        }
    }

    /// Snapshot this database before the first pending migration touches it.
    ///
    /// Skipped for a database being created (`from_version == 0`): there is
    /// nothing yet to lose, and every fresh install would otherwise leave a
    /// snapshot of an empty file. Skipped for an in-memory database, which the
    /// tests use and which has no file to snapshot.
    ///
    /// The destination mirrors `StorageTopology::migration_backup_dir`
    /// (`<data dir>/backups/migrations`), derived from the database's own path
    /// so the runner needs no topology of its own.
    fn snapshot_before_migrating(&self, from_version: u32, to_version: u32) -> StorageResult<()> {
        if from_version == 0 {
            return Ok(());
        }
        let source = {
            let conn = self.conn.borrow();
            conn.path().map(std::path::PathBuf::from)
        };
        let Some(source) = source.filter(|p| {
            let s = p.to_string_lossy();
            !s.is_empty() && s != ":memory:"
        }) else {
            return Ok(());
        };
        let dir = source
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("backups")
            .join("migrations");
        std::fs::create_dir_all(&dir).map_err(|e| {
            StorageError::Internal(format!(
                "pre-migration backup: cannot create {}: {e}",
                dir.display()
            ))
        })?;
        backup_database(
            &source,
            &dir,
            &BackupReason::PreMigration {
                from_version,
                to_version,
            },
        )
        .map(|_| ())
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
        read_schema_version(&self.conn.borrow())
    }

    fn run_pending_migrations(&self) -> StorageResult<MigrationSummary> {
        // Taken before the migrating transaction and outside its write lock:
        // the snapshot is a second connection reading the same file. The
        // runner re-reads the version under the lock, so this read only
        // decides whether a snapshot is due.
        if self.snapshot_first {
            let from_version = read_schema_version(&self.conn.borrow())?;
            if let Some(to_version) = self.migrations.last().map(|m| m.version) {
                if from_version < to_version {
                    // An upgrade we could not undo must not start.
                    self.snapshot_before_migrating(from_version, to_version)?;
                }
            }
        }

        let outcome = nrr_sqlite_support::migrate(&mut self.conn.borrow_mut(), self.migrations)
            .map_err(storage_error)?;
        Ok(MigrationSummary {
            from_version: outcome.from_version,
            to_version: outcome.to_version,
            migrations_applied: outcome.applied.into_iter().map(str::to_owned).collect(),
            completed_at: SystemTime::now(),
        })
    }

    fn verify_schema(&self) -> StorageResult<SchemaVerification> {
        let conn = self.conn.borrow();
        let version = read_schema_version(&conn)?;

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

fn storage_error(e: MigrationError) -> StorageError {
    match e {
        MigrationError::SchemaTooNew { found, supported } => {
            StorageError::UnsupportedSchemaVersion {
                found,
                max_supported: supported,
            }
        }
        MigrationError::Sqlite(e) => StorageError::Internal(format!("schema_migrations: {e}")),
        other => {
            let to_version = other.step_version().unwrap_or(0);
            StorageError::MigrationFailed {
                from_version: to_version.saturating_sub(1),
                to_version,
                reason: other.to_string(),
            }
        }
    }
}

/// The recorded schema version of an open connection, `0` when the database
/// was never migrated. Read-only: it does not create the bookkeeping table.
pub fn read_schema_version(conn: &Connection) -> StorageResult<u32> {
    if !relation_exists(conn, "table", "schema_migrations") {
        return Ok(0);
    }
    nrr_sqlite_support::schema_version(conn).map_err(storage_error)
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
