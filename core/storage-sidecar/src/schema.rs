//! Schema DDL for the sidecar database.
//!
//! Each `*_DDL` constant is a slice of SQL statements that the
//! migration runner executes atomically in a single transaction
//! together with the `schema_migrations` bookkeeping row.
//!
//! # Why `STRICT`
//!
//! All sidecar tables are declared with `STRICT` so SQLite enforces
//! column type affinities. The sidecar is a small, well-defined
//! per-user store; we benefit from catching accidental
//! type-coercion bugs in DAO code rather than discovering them only
//! when the GUI starts rendering NULL where a string was expected.
//! `STRICT` requires SQLite ≥ 3.37, which bundled rusqlite 0.32
//! guarantees (it ships 3.46+).

// ── v1: initial sidecar schema ────────────────────────────────────────────────

/// First-revision sidecar schema. Creates three tables:
///
/// * `rule_metadata` — sparse comment store keyed by
///   `type|lower(value)|route` (rule signature). Comments are
///   pure GUI decoration; the routing engine never reads them.
///   Sparse: rules without a comment have no row at all.
///
/// * `passthrough` — captured raw text of foreign-OS / unknown
///   sections (`--- Linux`, `--- MacOS`, `--- Ports`, etc.)
///   recorded at preset-import time. Keyed by route + section_name
///   so a single preset round-trip preserves every block the GUI
///   itself does not understand.
///
/// * `pending_apply` — single-row table (`CHECK(id = 1)`) holding
///   the last `_buildRulesJson()` snapshot the user "parked"
///   because the service was unreachable, plus a precomputed
///   summary for the "Apply pending changes?" toast. TTL via
///   `expires_at`; DAO treats expired rows as absent.
///
/// Indexes are limited to what we actually need:
/// * `idx_rule_metadata_updated_at` for GC sweeps that filter by
///   age once we add an "older-than" purge path.
/// * `idx_passthrough_route` because every read groups by route.
/// * `idx_pending_apply_expires_at` for `WHERE expires_at > now`
///   reads.
pub(crate) const SIDECAR_DB_V1_DDL: &[&str] = &[
    "CREATE TABLE rule_metadata (
        rule_signature TEXT    NOT NULL PRIMARY KEY,
        comment        TEXT    NOT NULL DEFAULT '',
        created_at     INTEGER NOT NULL,
        updated_at     INTEGER NOT NULL
    ) STRICT",
    "CREATE INDEX idx_rule_metadata_updated_at
        ON rule_metadata(updated_at)",
    "CREATE TABLE passthrough (
        route          TEXT    NOT NULL,
        section_name   TEXT    NOT NULL,
        raw_text       TEXT    NOT NULL,
        updated_at     INTEGER NOT NULL,
        PRIMARY KEY (route, section_name)
    ) STRICT",
    "CREATE INDEX idx_passthrough_route
        ON passthrough(route)",
    "CREATE TABLE pending_apply (
        id           INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
        rules_json   TEXT    NOT NULL,
        summary_json TEXT    NOT NULL,
        content_hash TEXT    NOT NULL,
        modified_at  INTEGER NOT NULL,
        expires_at   INTEGER NOT NULL
    ) STRICT",
    "CREATE INDEX idx_pending_apply_expires_at
        ON pending_apply(expires_at)",
    // ── db_state ────────────────────────────────────────────────────
    //
    // Single-row table holding sidecar-level housekeeping data that
    // doesn't belong to any user-facing table.  Today it tracks
    // `last_vacuum_at_ms` so the startup VACUUM check can throttle
    // itself (don't vacuum on every launch even when the size
    // threshold is exceeded — once per day is enough).  Future
    // housekeeping fields (e.g. a future `last_gc_at_ms`) live here
    // too.
    //
    // The row is materialised lazily: `vacuum_*` methods do an
    // `INSERT OR IGNORE` on first access so the table always has
    // either zero rows (fresh DB before any vacuum decision) or
    // exactly one row.
    "CREATE TABLE db_state (
        id                INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
        last_vacuum_at_ms INTEGER NOT NULL DEFAULT 0
    ) STRICT",
];

// ── v2: external IP cache ─────────────────────────────────────────────────────

/// Adds `external_ip_cache` — the last-known reflexive (external) IPv4
/// address observed per adapter, keyed by persistent adapter id (or a
/// name-derived fallback for adapters without one).
///
/// Written whenever a live service response resolves an adapter's
/// external address; read back only to paint a muted "last known"
/// hint when the GUI cannot reach the service to ask again. Sparse:
/// an adapter that was never resolved has no row.
pub(crate) const SIDECAR_DB_V2_DDL: &[&str] = &["CREATE TABLE external_ip_cache (
        adapter_key TEXT    NOT NULL PRIMARY KEY,
        external_ip TEXT    NOT NULL,
        observed_at INTEGER NOT NULL
    ) STRICT"];
