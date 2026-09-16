// ── SQL DDL — nrr_traffic_stats.db (Block T — traffic counter) ────────────────

/// Per-day, per-adapter, per-**role** byte totals. `day` is an opaque epoch-day
/// key computed by the caller in local time; `role` is a `TrafficCategory` slug
/// (`primary`/`secondary`/`loopback`/`virtual`). The role is stored (not derived
/// from the current assignment) so a primary<->secondary swap stays visible in
/// history. Rebuildable DB — carries no service-critical data.
const CREATE_INTERFACE_DAILY_TRAFFIC: &str = "
CREATE TABLE IF NOT EXISTS interface_daily_traffic (
    day         INTEGER NOT NULL,
    adapter_key TEXT    NOT NULL,
    role        TEXT    NOT NULL,
    in_bytes    INTEGER NOT NULL DEFAULT 0,
    out_bytes   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, adapter_key, role)
) WITHOUT ROWID";

/// Friendly display name per `adapter_key` (the stable-name anchor), so the UI
/// can render a human label for a role/adapter without re-enumerating.
const CREATE_INTERFACE_IDENTITY: &str = "
CREATE TABLE IF NOT EXISTS interface_identity (
    adapter_key  TEXT PRIMARY KEY,
    display_name TEXT    NOT NULL,
    last_seen    INTEGER NOT NULL
) WITHOUT ROWID";

/// Last cumulative octet reading per adapter — makes accounting resume-safe
/// across a service restart (the next sample's delta is computed against this
/// baseline, capturing traffic during downtime when no reset occurred).
const CREATE_INTERFACE_COUNTER_CURSOR: &str = "
CREATE TABLE IF NOT EXISTS interface_counter_cursor (
    adapter_key TEXT PRIMARY KEY,
    last_in     INTEGER NOT NULL,
    last_out    INTEGER NOT NULL,
    sampled_at  INTEGER NOT NULL
) WITHOUT ROWID";

/// Singleton schema/rebuild bookkeeping, mirroring `cache_metadata`.
const CREATE_TRAFFIC_METADATA: &str = "
CREATE TABLE IF NOT EXISTS traffic_metadata (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version  INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    last_rebuild_at INTEGER
)";

/// Block T Feature 2 — last observed local + external address per adapter,
/// recorded only from a USER-REQUESTED external-IP probe
/// (`interfaces.refresh`), never from the routine sampler tick. `adapter_key`
/// is the OS friendly interface name (`GetIfTable2 Alias`), matching
/// `interface_daily_traffic.adapter_key` / `interface_identity.adapter_key`
/// exactly, so the GUI can join a traffic row to its last-known addresses.
/// `external_ip` is nullable for forward compatibility (a future writer that
/// only knows the local address); today's only writer always supplies both.
const CREATE_ADAPTER_ADDRESSES: &str = "
CREATE TABLE IF NOT EXISTS adapter_addresses (
    adapter_key    TEXT    PRIMARY KEY,
    local_ip       TEXT    NOT NULL,
    external_ip    TEXT,
    observed_at_ms INTEGER NOT NULL
) WITHOUT ROWID";

/// Ordered DDL for `nrr_traffic_stats.db` v1 (Rebuildable — delete+rebuild on
/// corruption). The `(day, adapter_key, role)` primary key is itself the query
/// index for both "totals for a day" and retention (`day < cutoff`) scans, so no
/// secondary index is required.
pub const TRAFFIC_DB_V1_DDL: &[&str] = &[
    CREATE_INTERFACE_DAILY_TRAFFIC,
    CREATE_INTERFACE_IDENTITY,
    CREATE_INTERFACE_COUNTER_CURSOR,
    CREATE_TRAFFIC_METADATA,
    CREATE_ADAPTER_ADDRESSES,
];

/// DDL for the user's answers to "did this connection continue as that one?".
///
/// A row per pair the user was ASKED about, whichever way they answered:
/// `merged = 1` continues the old key's history under the new one, `merged = 0`
/// keeps them apart. Both are answers, and both must be remembered — a refused
/// pair that came back would be the same question again every session.
///
/// `old_key` is the primary key rather than the pair, because a history can
/// only be continued once: a second successor for the same predecessor is a
/// contradiction, not another answer.
const CREATE_ADAPTER_HISTORY_LINK: &str = "
CREATE TABLE IF NOT EXISTS adapter_history_link (
    old_key      TEXT    PRIMARY KEY,
    new_key      TEXT    NOT NULL,
    merged       INTEGER NOT NULL,
    decided_at_ms INTEGER NOT NULL
) WITHOUT ROWID";

/// DDL for `nrr_traffic_stats.db` schema v2 — the answers above.
///
/// Additive, as its own migration rather than an edit to v1: the checksum of a
/// changed v1 would not match an installed database, and this store's recovery
/// from that is to delete and rebuild — costing the user the whole all-time
/// ledger, which is the very thing the merge question exists to preserve.
pub const TRAFFIC_DB_V2_DDL: &[&str] = &[
    CREATE_ADAPTER_HISTORY_LINK,
    // When a key was first seen, which is half the handover evidence (the other
    // half, `last_seen`, was already here). `0` for a row written by an older
    // build reads as "known since before we tracked this", which correctly
    // makes such a key ineligible as the SUCCESSOR — it did not just appear.
    "ALTER TABLE interface_identity ADD COLUMN first_seen INTEGER NOT NULL DEFAULT 0",
];
