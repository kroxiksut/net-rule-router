// ── SQL DDL — nrr_fqdn_ip_cache.db ───────────────────────────────────────────

/// DDL for the `hostnames` table.
const CREATE_HOSTNAMES: &str = "
CREATE TABLE IF NOT EXISTS hostnames (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    canonical_host TEXT    NOT NULL UNIQUE,
    raw_sample     TEXT,
    first_seen_at  INTEGER NOT NULL,
    last_seen_at   INTEGER NOT NULL,
    flags          INTEGER NOT NULL DEFAULT 0
)";

/// DDL for the `ip_addresses` table.
const CREATE_IP_ADDRESSES: &str = "
CREATE TABLE IF NOT EXISTS ip_addresses (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    address_family TEXT    NOT NULL,
    canonical_ip   TEXT    NOT NULL,
    ipv4_packed    INTEGER,
    first_seen_at  INTEGER NOT NULL,
    last_seen_at   INTEGER NOT NULL,
    flags          INTEGER NOT NULL DEFAULT 0,
    UNIQUE(address_family, canonical_ip)
)";

/// DDL for the `hostname_ip_resolutions` table.
///
/// The UNIQUE constraint on `(hostname_id, ip_id, source)` means each
/// (hostname, IP, source) triple has exactly one live row.  When the same
/// mapping is seen again, the repository issues an `UPDATE` to extend
/// `expires_at` and `last_seen_at` (upsert semantics).
const CREATE_HOSTNAME_IP_RESOLUTIONS: &str = "
CREATE TABLE IF NOT EXISTS hostname_ip_resolutions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname_id         INTEGER NOT NULL REFERENCES hostnames(id) ON DELETE CASCADE,
    ip_id               INTEGER NOT NULL REFERENCES ip_addresses(id) ON DELETE CASCADE,
    source              TEXT    NOT NULL,
    ttl_seconds         INTEGER,
    resolved_at         INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL,
    freshness_state     TEXT    NOT NULL,
    confidence          INTEGER NOT NULL DEFAULT 100,
    active_revision_id  TEXT,
    diagnostic_flags    INTEGER NOT NULL DEFAULT 0,
    UNIQUE(hostname_id, ip_id, source)
)";

/// DDL for the `lookup_events` table (minimal — explain correlation only).
///
/// Raw hostname / IP values are never stored here; correlation is via row `id`
/// only.  Rows carry a short `expires_at` TTL and are removed by the cleanup
/// pass.
const CREATE_LOOKUP_EVENTS: &str = "
CREATE TABLE IF NOT EXISTS lookup_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    direction    TEXT    NOT NULL,
    result_state TEXT    NOT NULL,
    error_code   TEXT,
    duration_ms  INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
)";

/// DDL for the `negative_cache` table.
///
/// `input_hash` is a hex-encoded SHA-256 prefix (16 chars = 8 bytes) of the
/// normalised input.  Raw hostname / IP strings are not stored.
const CREATE_NEGATIVE_CACHE: &str = "
CREATE TABLE IF NOT EXISTS negative_cache (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    input_hash  TEXT    NOT NULL UNIQUE,
    reason      TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    retry_after INTEGER NOT NULL,
    source      TEXT    NOT NULL
)";

/// DDL for the `cache_metadata` singleton table.
///
/// The `CHECK (id = 1)` constraint enforces a single row.  The migration
/// runner inserts the initial row; subsequent writes use `UPDATE`.
const CREATE_CACHE_METADATA: &str = "
CREATE TABLE IF NOT EXISTS cache_metadata (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version   INTEGER NOT NULL,
    created_at       INTEGER NOT NULL,
    last_cleanup_at  INTEGER,
    last_rebuild_at  INTEGER,
    cache_generation INTEGER NOT NULL DEFAULT 0,
    integrity_hash   TEXT
)";

// ── Indexes — nrr_fqdn_ip_cache.db ───────────────────────────────────────────

const IDX_HOSTNAMES_LAST_SEEN: &str = "CREATE INDEX IF NOT EXISTS idx_hostnames_last_seen
     ON hostnames(last_seen_at)";

const IDX_IP_PACKED: &str = "CREATE INDEX IF NOT EXISTS idx_ip_ipv4_packed
     ON ip_addresses(ipv4_packed) WHERE ipv4_packed IS NOT NULL";

const IDX_IP_LAST_SEEN: &str = "CREATE INDEX IF NOT EXISTS idx_ip_last_seen
     ON ip_addresses(last_seen_at)";

const IDX_RES_HOSTNAME: &str = "CREATE INDEX IF NOT EXISTS idx_res_hostname
     ON hostname_ip_resolutions(hostname_id)";

const IDX_RES_IP: &str = "CREATE INDEX IF NOT EXISTS idx_res_ip
     ON hostname_ip_resolutions(ip_id)";

const IDX_RES_EXPIRES: &str = "CREATE INDEX IF NOT EXISTS idx_res_expires
     ON hostname_ip_resolutions(expires_at)";

const IDX_RES_FRESHNESS: &str = "CREATE INDEX IF NOT EXISTS idx_res_freshness
     ON hostname_ip_resolutions(freshness_state)";

const IDX_RES_REVISION: &str = "CREATE INDEX IF NOT EXISTS idx_res_revision
     ON hostname_ip_resolutions(active_revision_id)
     WHERE active_revision_id IS NOT NULL";

const IDX_RES_FLAGS: &str = "CREATE INDEX IF NOT EXISTS idx_res_flags
     ON hostname_ip_resolutions(diagnostic_flags)
     WHERE diagnostic_flags != 0";

const IDX_LOOKUP_EVENTS_EXPIRES: &str = "CREATE INDEX IF NOT EXISTS idx_lookup_events_expires
     ON lookup_events(expires_at)";

const IDX_LOOKUP_EVENTS_CREATED: &str = "CREATE INDEX IF NOT EXISTS idx_lookup_events_created
     ON lookup_events(created_at)";

const IDX_NEG_CACHE_EXPIRES: &str = "CREATE INDEX IF NOT EXISTS idx_neg_cache_expires
     ON negative_cache(expires_at)";

/// Ordered list of all DDL statements for `nrr_fqdn_ip_cache.db` v1.
///
/// Tables are created before indexes.  Foreign keys use `ON DELETE CASCADE`
/// so `PRAGMA foreign_keys = ON` must be set on every connection before
/// executing DML (handled by the migration runner).
pub const CACHE_DB_V1_DDL: &[&str] = &[
    CREATE_HOSTNAMES,
    CREATE_IP_ADDRESSES,
    CREATE_HOSTNAME_IP_RESOLUTIONS,
    CREATE_LOOKUP_EVENTS,
    CREATE_NEGATIVE_CACHE,
    CREATE_CACHE_METADATA,
    IDX_HOSTNAMES_LAST_SEEN,
    IDX_IP_PACKED,
    IDX_IP_LAST_SEEN,
    IDX_RES_HOSTNAME,
    IDX_RES_IP,
    IDX_RES_EXPIRES,
    IDX_RES_FRESHNESS,
    IDX_RES_REVISION,
    IDX_RES_FLAGS,
    IDX_LOOKUP_EVENTS_EXPIRES,
    IDX_LOOKUP_EVENTS_CREATED,
    IDX_NEG_CACHE_EXPIRES,
];

/// Shared-IP census. A **direct** (non-secondary) hostname
/// observed sharing an IPv4 with a secondary rule. Only these rows are recorded
/// (rule hostnames already live in `hostname_ip_resolutions`), so a per-IP
/// `COUNT(DISTINCT hostname)` yields `direct_on_ip` for the shared-IP policy.
/// Rebuildable cache DB → no retention obligation beyond best-effort recency.
const CREATE_SHARED_IP_DIRECT_HOSTS: &str = "
CREATE TABLE IF NOT EXISTS shared_ip_direct_hosts (
    ipv4_packed INTEGER NOT NULL,
    hostname    TEXT    NOT NULL,
    last_seen   INTEGER NOT NULL,
    PRIMARY KEY (ipv4_packed, hostname)
)";

const IDX_SHARED_IP_DIRECT_HOSTS_IP: &str =
    "CREATE INDEX IF NOT EXISTS idx_shared_ip_direct_hosts_ip
     ON shared_ip_direct_hosts(ipv4_packed)";

/// DDL for `nrr_fqdn_ip_cache.db` v2 — adds the shared-IP census table.
pub const CACHE_DB_V2_DDL: &[&str] =
    &[CREATE_SHARED_IP_DIRECT_HOSTS, IDX_SHARED_IP_DIRECT_HOSTS_IP];

/// Does a rule of the user's own send this direct tenant out the MAIN route?
/// Such a tenant may never have its address pinned to the additional one: the
/// pin would block the very traffic the rule asks to go direct, and the host
/// dies instead of merely riding the tunnel as collateral.
const ALTER_SHARED_IP_DIRECT_HOSTS_PRIMARY_RULED: &str =
    "ALTER TABLE shared_ip_direct_hosts ADD COLUMN primary_ruled INTEGER NOT NULL DEFAULT 0";

/// DDL for `nrr_fqdn_ip_cache.db` v4 — marks census tenants claimed by a
/// main-route rule.
pub const CACHE_DB_V4_DDL: &[&str] = &[ALTER_SHARED_IP_DIRECT_HOSTS_PRIMARY_RULED];

/// Persistent `domain -> pool index` fake-IP bindings. A hostname's fake
/// address is its stable identity across service restarts; without this table
/// the in-memory allocator restarts from index 0 and re-deals the same
/// addresses to different hostnames each run. `pool_index` is the identity
/// (v4/v6 both derive from it); `INSERT OR REPLACE` retires both sides of a
/// recycled binding via the two uniqueness constraints. Rebuildable DB — losing
/// the table only re-deals addresses, it never breaks routing.
const CREATE_FAKE_IP_BINDINGS: &str = "
CREATE TABLE IF NOT EXISTS fake_ip_bindings (
    pool_index INTEGER PRIMARY KEY,
    domain     TEXT    NOT NULL UNIQUE,
    touched_at INTEGER NOT NULL
)";

/// Singleton stamp of the pool geometry the bindings were dealt from. A
/// changed pool invalidates every stored index, so a stamp mismatch wipes the
/// bindings table instead of mapping hostnames onto the wrong addresses.
const CREATE_FAKE_IP_POOL_META: &str = "
CREATE TABLE IF NOT EXISTS fake_ip_pool_meta (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    stamp TEXT    NOT NULL
)";

/// DDL for `nrr_fqdn_ip_cache.db` v3 — persistent fake-IP bindings.
pub const CACHE_DB_V3_DDL: &[&str] = &[CREATE_FAKE_IP_BINDINGS, CREATE_FAKE_IP_POOL_META];
