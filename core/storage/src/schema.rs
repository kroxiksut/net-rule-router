//! SQLite schema definitions for the two storage databases.
//!
//! # Entity-Relationship Diagram — `nrr_fqdn_ip_cache.db`
//!
//! ```text
//!  ┌─────────────────────┐       ┌──────────────────────┐
//!  │      hostnames      │       │     ip_addresses      │
//!  │─────────────────────│       │──────────────────────│
//!  │ id PK               │       │ id PK                │
//!  │ canonical_host UNIQ │       │ address_family       │
//!  │ raw_sample          │       │ canonical_ip         │ ← UNIQUE(af, ip)
//!  │ first_seen_at       │       │ ipv4_packed          │
//!  │ last_seen_at        │       │ first_seen_at        │
//!  │ flags               │       │ last_seen_at         │
//!  └────────┬────────────┘       └─────────┬────────────┘
//!           │                              │
//!           │  hostname_ip_resolutions     │
//!           │  ┌───────────────────────── ┐│
//!           └──│ hostname_id FK           ├┘
//!              │ ip_id FK                 │
//!              │ source (TEXT)            │ ← UNIQUE(hostname_id, ip_id, source)
//!              │ ttl_seconds              │
//!              │ resolved_at              │
//!              │ expires_at               │
//!              │ freshness_state (TEXT)   │
//!              │ confidence               │
//!              │ active_revision_id       │
//!              │ diagnostic_flags (INT)   │
//!              └──────────────────────────┘
//!
//!  ┌───────────────────────────────────────────────────────────────┐
//!  │ negative_cache  │ lookup_events  │ cache_metadata (singleton) │
//!  └───────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Schema — `nrr_service_state.db`
//!
//! ```text
//!  active_revision   last_known_good   integrity_log
//! ```
//!
//! # Timestamp convention
//!
//! All persisted timestamps use the `_at` suffix and store **UTC Unix
//! milliseconds as `INTEGER` (`i64`)**.  Duration/TTL fields use the
//! `_seconds` suffix and store plain `INTEGER`.  Monotonic time is runtime-only
//! and must never be written to SQLite.
//!
//! # `FreshnessStateDb` TEXT values
//!
//! | Rust variant     | SQLite TEXT value   |
//! |------------------|---------------------|
//! | `Fresh`          | `"fresh"`           |
//! | `StaleUsable`    | `"stale_usable"`    |
//! | `StaleNotUsable` | `"stale_not_usable"`|
//! | `Conflicting`    | `"conflicting"`     |
//! | `NegativeCached` | `"negative_cached"` |
//!
//! (`Missing` is a runtime-only state; it is not persisted — a missing row
//! implies `Missing`.)

use bitflags::bitflags;
use nrr_domain::decision_lookup::CacheEntryState;

// ── DiagnosticFlags ───────────────────────────────────────────────────────────

bitflags! {
    /// Bitfield stored in `hostname_ip_resolutions.diagnostic_flags` and in
    /// the host-level `flags` columns of `hostnames` / `ip_addresses`.
    ///
    /// Persisted as `INTEGER` in SQLite via `bits() as i64` / `from_bits_truncate`.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct DiagnosticFlags: u32 {
        /// Multiple IPs map to this hostname and they lead to different
        /// rule matches — the router had to pick one.
        const AMBIGUOUS            = 0b0000_0001;
        /// Observed IP is not present in the cached hostname IP set.
        const CONFLICTING          = 0b0000_0010;
        /// Entry is past its TTL (either stale_usable or stale_not_usable).
        const STALE                = 0b0000_0100;
        /// This entry was written as a negative-cache result.
        const NEGATIVE_CACHED      = 0b0000_1000;
        /// The lookup that produced this entry failed or timed out.
        const LOOKUP_FAILED        = 0b0001_0000;
        /// The address family is not supported in Free edition (native IPv6).
        const UNSUPPORTED_ADDR_FAM = 0b0010_0000;
    }
}

impl DiagnosticFlags {
    /// Converts to the `INTEGER` value stored in SQLite.
    pub fn to_db(self) -> i64 {
        self.bits() as i64
    }

    /// Reconstructs from an `INTEGER` value read from SQLite.
    /// Unknown bits are silently discarded (`from_bits_truncate`).
    pub fn from_db(raw: i64) -> Self {
        Self::from_bits_truncate(raw as u32)
    }
}

// ── FreshnessStateDb ──────────────────────────────────────────────────────────

/// TEXT representation of freshness state as stored in SQLite.
///
/// This type handles serialization between the SQLite column and the domain
/// type [`CacheEntryState`].  `Missing` is runtime-only and has no TEXT form —
/// a missing row in the database implies `Missing`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreshnessStateDb {
    Fresh,
    StaleUsable,
    StaleNotUsable,
    Conflicting,
    NegativeCached,
}

impl FreshnessStateDb {
    /// TEXT value written to / read from the `freshness_state` column.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::StaleUsable => "stale_usable",
            Self::StaleNotUsable => "stale_not_usable",
            Self::Conflicting => "conflicting",
            Self::NegativeCached => "negative_cached",
        }
    }

    /// Parses the TEXT value read from SQLite.  Returns `None` for unknown
    /// values (e.g. written by a future schema version).
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "fresh" => Some(Self::Fresh),
            "stale_usable" => Some(Self::StaleUsable),
            "stale_not_usable" => Some(Self::StaleNotUsable),
            "conflicting" => Some(Self::Conflicting),
            "negative_cached" => Some(Self::NegativeCached),
            _ => None,
        }
    }

    /// Converts to the domain-level [`CacheEntryState`] used by the rule engine.
    pub fn to_domain(self) -> CacheEntryState {
        match self {
            Self::Fresh => CacheEntryState::Fresh,
            Self::StaleUsable => CacheEntryState::StaleUsable,
            Self::StaleNotUsable => CacheEntryState::StaleNotUsable,
            Self::Conflicting => CacheEntryState::Conflicting,
            Self::NegativeCached => CacheEntryState::NegativeCached,
        }
    }

    /// Converts from a domain [`CacheEntryState`] to the DB representation.
    ///
    /// Returns `None` for `CacheEntryState::Missing` because `Missing` is a
    /// runtime state (no row present) and must not be persisted.
    pub fn from_domain(state: &CacheEntryState) -> Option<Self> {
        match state {
            CacheEntryState::Fresh => Some(Self::Fresh),
            CacheEntryState::StaleUsable => Some(Self::StaleUsable),
            CacheEntryState::StaleNotUsable => Some(Self::StaleNotUsable),
            CacheEntryState::Conflicting => Some(Self::Conflicting),
            CacheEntryState::NegativeCached => Some(Self::NegativeCached),
            CacheEntryState::Missing => None,
        }
    }
}

// ── AddressFamily ─────────────────────────────────────────────────────────────

/// TEXT representation of the IP address family stored in `ip_addresses`.
///
/// Free edition only uses `Ipv4` for `ExactIp` rule matching.
/// `Ipv6` rows may be inserted as an extension point but are marked with
/// [`DiagnosticFlags::UNSUPPORTED_ADDR_FAM`] and are never returned as usable
/// addresses for matching.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressFamily {
    Ipv4,
    /// Pro-only extension point.  Present in schema but excluded from matching.
    Ipv6,
}

impl AddressFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "ipv4" => Some(Self::Ipv4),
            "ipv6" => Some(Self::Ipv6),
            _ => None,
        }
    }
}

// ── LookupDirection TEXT ──────────────────────────────────────────────────────

/// Returns the TEXT value used in `lookup_events.direction` for a given
/// [`LookupDirection`][nrr_domain::decision_lookup::LookupDirection].
///
/// Free functions rather than trait impls because `LookupDirection` is defined
/// in `nrr-domain` and we cannot add methods to it here.
pub fn lookup_direction_as_str(dir: &nrr_domain::decision_lookup::LookupDirection) -> &'static str {
    use nrr_domain::decision_lookup::LookupDirection;
    match dir {
        LookupDirection::HostnameToIp => "hostname_to_ip",
        LookupDirection::IpToHostname => "ip_to_hostname",
        LookupDirection::Both => "both",
    }
}

pub fn lookup_direction_from_str(s: &str) -> Option<nrr_domain::decision_lookup::LookupDirection> {
    use nrr_domain::decision_lookup::LookupDirection;
    match s {
        "hostname_to_ip" => Some(LookupDirection::HostnameToIp),
        "ip_to_hostname" => Some(LookupDirection::IpToHostname),
        "both" => Some(LookupDirection::Both),
        _ => None,
    }
}

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

// ── SQL DDL — nrr_service_state.db ───────────────────────────────────────────

/// DDL for the `active_revision` singleton table.
const CREATE_ACTIVE_REVISION: &str = "
CREATE TABLE IF NOT EXISTS active_revision (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    revision_id     TEXT    NOT NULL,
    activated_at    INTEGER NOT NULL,
    last_verified_at INTEGER
)";

/// DDL for the `last_known_good` singleton table.
const CREATE_LAST_KNOWN_GOOD: &str = "
CREATE TABLE IF NOT EXISTS last_known_good (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    revision_id  TEXT    NOT NULL,
    promoted_at  INTEGER NOT NULL
)";

/// DDL for the `integrity_log` table (integrity check history).
const CREATE_INTEGRITY_LOG: &str = "
CREATE TABLE IF NOT EXISTS integrity_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    result      TEXT    NOT NULL,
    detail      TEXT,
    checked_at  INTEGER NOT NULL
)";

const IDX_INTEGRITY_LOG_CHECKED: &str = "CREATE INDEX IF NOT EXISTS idx_integrity_log_checked
     ON integrity_log(checked_at)";

/// Ordered list of all DDL statements for `nrr_service_state.db` v1.
pub const STATE_DB_V1_DDL: &[&str] = &[
    CREATE_ACTIVE_REVISION,
    CREATE_LAST_KNOWN_GOOD,
    CREATE_INTEGRITY_LOG,
    IDX_INTEGRITY_LOG_CHECKED,
];

/// DDL for `nrr_service_state.db` schema v2: adds `integrity_hash` columns to
/// the revision pointer tables so that `check_integrity()` can detect tampering.
pub const STATE_DB_V2_DDL: &[&str] = &[
    "ALTER TABLE active_revision  ADD COLUMN integrity_hash TEXT",
    "ALTER TABLE last_known_good  ADD COLUMN integrity_hash TEXT",
];

/// DDL for `nrr_service_state.db` schema v3: adds the `security_alerts` table
/// for persistent tamper-visible alert state.
///
/// Alert events are stored in NDJSON files (`nrr_audit_*.ndjson`); this table
/// only records the mutable alert *state* (Active/Acknowledged/Resolved/Superseded).
/// The `raised_file` / `ack_file` / `resolved_file` columns record which NDJSON
/// file holds the corresponding audit event so the UI can retrieve the full detail.
pub const STATE_DB_V3_DDL: &[&str] = &[
    "
CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id          TEXT    PRIMARY KEY,
    kind              TEXT    NOT NULL,
    state             TEXT    NOT NULL DEFAULT 'active',
    raised_event_seq  INTEGER NOT NULL,
    raised_file       TEXT    NOT NULL,
    ack_event_seq     INTEGER,
    ack_file          TEXT,
    resolved_event_seq INTEGER,
    resolved_file     TEXT,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    reason_code       TEXT    NOT NULL
)",
    "CREATE INDEX IF NOT EXISTS idx_security_alerts_state
 ON security_alerts(state)",
    "CREATE INDEX IF NOT EXISTS idx_security_alerts_created
 ON security_alerts(created_at)",
];

/// DDL for `nrr_service_state.db` schema v4: adds the `apply_snapshots` table
/// for persisting pre-apply platform state.
///
/// Each row is keyed by `attempt_id` (from `ApplyAttemptMarker`). The JSON
/// blob holds a serialized `PlatformStateSnapshot`. Schema version is stored
/// for forward-compatibility: a snapshot with an unknown schema version is
/// rejected with `RecoveryRequired` rather than silently ignored.
///
/// Max 2 rows are kept (current + previous LKG) — rotation is enforced by
/// `ApplySnapshotRepository::rotate_keeping_latest_n(2)` after every
/// successful apply.
pub const STATE_DB_V4_DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS apply_snapshots (
    attempt_id      TEXT    PRIMARY KEY,
    snapshot_hash   TEXT    NOT NULL,
    snapshot_json   TEXT    NOT NULL,
    schema_version  INTEGER NOT NULL DEFAULT 1,
    created_at      INTEGER NOT NULL
)",
    "CREATE INDEX IF NOT EXISTS idx_apply_snapshots_created
 ON apply_snapshots(created_at)",
];

/// Schema v5: per-SID routing policy tables.
///
/// Each OS user (identified by `sid` as `S-1-5-21-...` string) owns an
/// independent route binding pair, behavior mode, secondary-block flag,
/// and migration ledger. The multi-user model reads these
/// per-SID rows when building per-user WFP filter sets.
///
/// `route_bindings` PK is `(sid, role)` — one primary + one secondary
/// per user maximum. `behavior_mode` and `secondary_block_policy` carry
/// SID as the sole PK (one row per user).
///
/// `migration_state` is per-SID per-`migration_id` so each user's GUI
/// migration runs independently. The first migration recorded here is
/// `legacy_preferences_v1` (cleanup of `UiPreferences` policy fields).
pub const STATE_DB_V5_DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS route_bindings (
    sid              TEXT    NOT NULL,
    role             TEXT    NOT NULL CHECK(role IN ('primary','secondary')),
    stable_id        TEXT    NOT NULL,
    display_name     TEXT    NOT NULL,
    user_confirmed   INTEGER NOT NULL DEFAULT 0,
    updated_at       INTEGER NOT NULL,
    binding_source   TEXT    NOT NULL CHECK(binding_source IN
                                ('user-assigned',
                                 'migrated-from-preferences',
                                 'recovery')),
    PRIMARY KEY (sid, role)
)",
    "CREATE INDEX IF NOT EXISTS idx_route_bindings_sid
 ON route_bindings(sid)",
    "CREATE TABLE IF NOT EXISTS behavior_mode (
    sid              TEXT    PRIMARY KEY,
    mode             TEXT    NOT NULL CHECK(mode IN
                                ('prefer-primary',
                                 'prefer-secondary-when-available',
                                 'strict-secondary-fail-closed')),
    updated_at       INTEGER NOT NULL
)",
    "CREATE TABLE IF NOT EXISTS secondary_block_policy (
    sid              TEXT    PRIMARY KEY,
    block_secondary_when_unavailable INTEGER NOT NULL DEFAULT 0,
    updated_at       INTEGER NOT NULL
)",
    "CREATE TABLE IF NOT EXISTS migration_state (
    sid              TEXT    NOT NULL,
    migration_id     TEXT    NOT NULL,
    completed_at     INTEGER NOT NULL,
    detail_json      TEXT,
    PRIMARY KEY (sid, migration_id)
)",
];

/// Schema v6: rules-revision history + active pointer +
/// mutation tokens.
///
/// Per the Variant C decision, revisions version **rules only** — per-SID
/// bindings live in the v5 tables and are not revision-tracked. The
/// `rules_json` column stores a serialised
/// `nrr_domain::rules_revision::RulesRevisionContent` (format opaque to
/// storage; service-runtime owns serialisation).
///
/// Slug values match the enums in `nrr_domain::rules_revision`:
/// - `status`: `RevisionStatus` (5 variants, `'rolled-back'` includes the dash)
/// - `source`: `RulesRevisionSource`
///
/// `idx_one_active_revision` is a partial unique index — exactly one row
/// can carry `status='active'` at a time. Concurrent activations from
/// different threads serialize through this constraint plus the SQL
/// transaction the activation coordinator opens.
///
/// `active_revision_pointer` is a singleton row tracking which revision
/// is currently applied plus the in-flight `apply_attempt_id` (links to
/// `apply_snapshots` from v4). On successful Phase 3a commit the pointer
/// flips to the new revision and `apply_attempt_id` is cleared.
///
/// `mutation_tokens` persists confirmation tokens across service restart
/// so a user with an open review dialog does not lose their token if the
/// service is restarted between issue and consume. The `consumed` flag is
/// kept until expiration for audit replay; `gc_expired` removes rows
/// older than `expires_at + 1 day`.
///
/// `risk_level` CHECK uses 3 values matching `nrr_domain::revision::RiskLevel`
/// (Low/Medium/High) — the risk scoring engine in `nrr-domain::risk` is
/// tuned to 3 levels; Critical is added later (see schema v12).
pub const STATE_DB_V6_DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS revisions (
    revision_id          TEXT    PRIMARY KEY,
    content_hash         TEXT    NOT NULL,
    rules_json           TEXT    NOT NULL,
    status               TEXT    NOT NULL CHECK(status IN
                            ('candidate','active','superseded','rolled-back','rejected')),
    source               TEXT    NOT NULL CHECK(source IN
                            ('gui-rules-edit','preset-import','recovery-lkg','rollback')),
    correlation_id       TEXT    NOT NULL,
    created_at           INTEGER NOT NULL,
    activated_at         INTEGER,
    superseded_at        INTEGER,
    superseded_by        TEXT,
    rejected_reason      TEXT,
    review_summary_json  TEXT,
    risk_level           TEXT    CHECK(risk_level IN ('low','medium','high'))
)",
    "CREATE INDEX IF NOT EXISTS idx_revisions_status
 ON revisions(status)",
    "CREATE INDEX IF NOT EXISTS idx_revisions_created
 ON revisions(created_at DESC)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_revision
 ON revisions(status) WHERE status = 'active'",
    "CREATE TABLE IF NOT EXISTS active_revision_pointer (
    id                INTEGER PRIMARY KEY CHECK(id = 1),
    revision_id       TEXT    REFERENCES revisions(revision_id),
    activated_at      INTEGER NOT NULL,
    apply_attempt_id  TEXT
)",
    "CREATE TABLE IF NOT EXISTS mutation_tokens (
    token                  TEXT    PRIMARY KEY,
    mutation_payload_json  TEXT    NOT NULL,
    issued_at              INTEGER NOT NULL,
    expires_at             INTEGER NOT NULL,
    consumed               INTEGER NOT NULL DEFAULT 0
)",
    "CREATE INDEX IF NOT EXISTS idx_mutation_tokens_expires
 ON mutation_tokens(expires_at)",
];

/// Schema v7: retention / apply-failure-policy /
/// routing-pause / autostart settings tables.
///
/// Four tables, all small:
/// - `retention_settings` (singleton) — drives revision GC pruning.
///   `pin_lkg=1` means the most recent superseded revision is excluded
///   from retention sweeps regardless of count cap.
/// - `apply_failure_policy_settings` (singleton) — global
///   `ApplyFailurePolicy` for the activation coordinator. Slug
///   values match `ApplyFailurePolicy::as_slug`.
/// - `routing_pause_state` (per-SID) — persistent pause flag. Default
///   absent → not paused (single-state reads return `paused=false`).
///   Consulted by the routing-presence wiring on tray connect.
/// - `autostart_state` (singleton) — last-known `HKCU\...\Run` registry
///   state. `last_known_state` slugs:
///   `'enabled' | 'disabled' | 'overridden-externally' | 'absent'`.
///
/// CHECK constraints on numeric fields enforce the validation ranges
/// from the GUI SpinBox bounds (Backend SSoT — GUI mirrors these
/// limits in QML). Insertion of out-of-range values from buggy clients
/// fails with `SqliteFailure(ConstraintViolation)`.
pub const STATE_DB_V7_DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS retention_settings (
    id                    INTEGER PRIMARY KEY CHECK(id = 1),
    superseded_days       INTEGER NOT NULL DEFAULT 30
                                     CHECK(superseded_days BETWEEN 7 AND 365),
    superseded_count_cap  INTEGER NOT NULL DEFAULT 100
                                     CHECK(superseded_count_cap BETWEEN 20 AND 1000),
    rejected_days         INTEGER NOT NULL DEFAULT 7
                                     CHECK(rejected_days BETWEEN 1 AND 90),
    rolledback_days       INTEGER NOT NULL DEFAULT 14
                                     CHECK(rolledback_days BETWEEN 1 AND 90),
    rolledback_count_cap  INTEGER NOT NULL DEFAULT 20
                                     CHECK(rolledback_count_cap BETWEEN 5 AND 100),
    pin_lkg               INTEGER NOT NULL DEFAULT 1 CHECK(pin_lkg IN (0, 1)),
    last_cleanup_at       INTEGER,
    updated_at            INTEGER NOT NULL
)",
    "CREATE TABLE IF NOT EXISTS apply_failure_policy_settings (
    id          INTEGER PRIMARY KEY CHECK(id = 1),
    policy      TEXT    NOT NULL CHECK(policy IN
                            ('all-or-nothing',
                             'best-effort',
                             'pre-flight-then-all-or-nothing')),
    set_by_sid  TEXT,
    set_at      INTEGER NOT NULL
)",
    "CREATE TABLE IF NOT EXISTS routing_pause_state (
    sid           TEXT    PRIMARY KEY,
    paused        INTEGER NOT NULL CHECK(paused IN (0, 1)),
    paused_at     INTEGER,
    pause_reason  TEXT,
    updated_at    INTEGER NOT NULL
)",
    "CREATE INDEX IF NOT EXISTS idx_routing_pause_paused
 ON routing_pause_state(paused) WHERE paused = 1",
    "CREATE TABLE IF NOT EXISTS autostart_state (
    id                INTEGER PRIMARY KEY CHECK(id = 1),
    enabled           INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0, 1)),
    last_known_state  TEXT CHECK(last_known_state IS NULL OR last_known_state IN
                            ('enabled','disabled','overridden-externally','absent')),
    updated_at        INTEGER NOT NULL
)",
];

/// State DB v8. Adds the
/// `service_stability_config` singleton row mirroring
/// `nrr_service_runtime::service_stability::ServiceStabilityConfig`.
///
/// The IPC accept-failure policy is encoded as a discriminator column
/// (`ipc_accept_kind`) plus three nullable parameter columns that are
/// only meaningful when the kind is `recoverable`. A cross-field
/// CHECK constraint enforces consistency: `recoverable` requires all
/// three params to be non-NULL; `critical` requires all three to be
/// NULL. This keeps the table normalised without splitting it into
/// two — at the cost of a slightly hairy CHECK, which is still much
/// simpler than a parallel `service_stability_recoverable_params`
/// child table for one optional row.
///
/// Range CHECKs mirror the documented GUI SpinBox bounds:
///   * `ipc_max_restarts`    ∈ [1, 100], default 20
///   * `ipc_backoff_base_ms` ∈ [50, 5000], default 100
///   * `ipc_backoff_cap_ms`  ∈ [1000, 60000], default 5000
///
/// `set_by_sid` records which user wrote the row most recently (the
/// service-global setter requires admin elevation — see
/// `IpcOperationName::ServiceStabilityConfigSet`).
pub const STATE_DB_V8_DDL: &[&str] = &["CREATE TABLE IF NOT EXISTS service_stability_config (
    id                   INTEGER PRIMARY KEY CHECK(id = 1),
    ipc_accept_kind      TEXT    NOT NULL CHECK(ipc_accept_kind IN
                              ('recoverable', 'critical')),
    ipc_max_restarts     INTEGER CHECK(ipc_max_restarts IS NULL
                              OR ipc_max_restarts BETWEEN 1 AND 100),
    ipc_backoff_base_ms  INTEGER CHECK(ipc_backoff_base_ms IS NULL
                              OR ipc_backoff_base_ms BETWEEN 50 AND 5000),
    ipc_backoff_cap_ms   INTEGER CHECK(ipc_backoff_cap_ms IS NULL
                              OR ipc_backoff_cap_ms BETWEEN 1000 AND 60000),
    set_by_sid           TEXT,
    updated_at           INTEGER NOT NULL,
    CHECK (
        (ipc_accept_kind = 'recoverable'
            AND ipc_max_restarts    IS NOT NULL
            AND ipc_backoff_base_ms IS NOT NULL
            AND ipc_backoff_cap_ms  IS NOT NULL)
        OR
        (ipc_accept_kind = 'critical'
            AND ipc_max_restarts    IS NULL
            AND ipc_backoff_base_ms IS NULL
            AND ipc_backoff_cap_ms  IS NULL)
    )
)"];

/// State DB v9. Adds the `verbose_logging` column to
/// `service_stability_config` so the GUI toggle can persist alongside
/// the existing policy fields. Default `0` (= disabled): only
/// `tracing::info!`/`warn!`/`error!` events reach the operational
/// NDJSON. When set to `1`, the service installs
/// `tracing_subscriber::EnvFilter::new("nrr=debug,info")` instead of
/// the canonical default, surfacing `tracing::debug!` events from the
/// IPC and mutation paths.
///
/// `ALTER TABLE ADD COLUMN` is the simplest forward migration — SQLite
/// supports it without rewriting the row data, and the column-level
/// CHECK is enough (no cross-field constraint involved). Existing
/// rows backfill with the column default (0).
pub const STATE_DB_V9_DDL: &[&str] = &["ALTER TABLE service_stability_config \
ADD COLUMN verbose_logging INTEGER NOT NULL DEFAULT 0 \
CHECK(verbose_logging IN (0, 1))"];

/// State DB v10. Persistent store for the
/// per-`DecisionId` explain snapshot. Without this, every
/// `DiagnosticsFacade::get_explain` call falls through to
/// `Unavailable::DecisionNotFound` and the GUI probe widget renders
/// "explain unavailable" even for decisions the service made seconds
/// ago.
///
/// Row shape:
/// - `decision_id`     — UUID v4 string, PRIMARY KEY. One row per
///   produced `DecisionOutcome`.
/// - `created_at`      — UTC ms the snapshot was written. Sorted-by
///   index uses this for retention sweeps.
/// - `redaction_level` — slug of the redaction mode applied at write
///   time (`compact-ui` / `diagnostics` / `developer-trace`).
/// - `payload_json`    — serialised `ExplainResponse` snapshot. The
///   service rehydrates this on `get_explain`; the GUI never sees the
///   raw JSON, only the projected compact view.
/// - `expires_at`      — UTC ms after which the retention sweep drops
///   the row. Default TTL today is 7 days; the column lets future
///   admin tooling set per-row TTL without a schema bump.
///
/// `idx_explain_expires_created` accelerates the retention sweep
/// (`WHERE expires_at <= ? ORDER BY created_at`); the primary key
/// already covers per-decision-id lookups.
pub const STATE_DB_V10_DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS explain_snapshots (
    decision_id      TEXT    NOT NULL PRIMARY KEY,
    created_at       INTEGER NOT NULL,
    redaction_level  TEXT    NOT NULL CHECK(redaction_level IN
                          ('compact-ui', 'diagnostics', 'developer-trace')),
    payload_json     TEXT    NOT NULL,
    expires_at       INTEGER NOT NULL
)",
    "CREATE INDEX IF NOT EXISTS idx_explain_expires_created
    ON explain_snapshots (expires_at, created_at)",
];

/// State DB v11. Adds the `row_hmac` column to
/// `revisions` so the service can detect external tampering of the
/// state DB (admin or rogue process directly editing SQLite outside
/// the service's own write paths).
///
/// **Lazy backfill.** Pre-existing rows survive the migration with
/// `row_hmac = x''` (empty blob — the DEFAULT). The
/// `RevisionsRepository` read path treats empty HMAC as "unsigned"
/// (NOT "tampered"). On the next successful mutation the new row's
/// HMAC is populated; older rows stay unsigned until a re-sign
/// flow walks the table.
///
/// **No one-shot backfill in the migration.** The HMAC key lives
/// in DPAPI-protected storage that the service-runtime opens AFTER
/// the storage layer; threading a key into the migration would
/// muddy the crate boundary (nrr-storage is platform-agnostic).
/// Lazy backfill keeps the migration pure SQL.
pub const STATE_DB_V11_DDL: &[&str] =
    &["ALTER TABLE revisions ADD COLUMN row_hmac BLOB NOT NULL DEFAULT x''"];

/// Reserved sentinel `principal` value for the admin-managed **baseline**
/// rule book. Stored in the `principal` column of
/// `revisions` / `active_revision_pointer` / `mutation_tokens` exactly like
/// a real OS-user principal, but reserved so it can never collide with a
/// Windows SID (which always begins with `S-`). Per-user revisions are
/// seeded from the baseline on first use; legacy global rules map onto
/// this sentinel via the storage back-compat shims.
///
/// The SSOT for this constant (plus the typed
/// [`nrr_domain::user_principal::UserPrincipal`] view and the reserved
/// cross-OS principal formats) lives in `nrr-domain`; re-exported here
/// so the existing `nrr_storage::BASELINE_PRINCIPAL` call sites are
/// unchanged.
pub use nrr_domain::user_principal::BASELINE_PRINCIPAL;

/// State DB v12. Per-principal (per-OS-user) rules
/// revisions. **Reset-style migration** (pre-release, no production data):
/// the three rules-revision tables are DROPped and recreated with a
/// `principal` partition column rather than performing a data-preserving
/// v11→v12 transform. Dev databases are wiped of revision history; the
/// per-SID routing tables from v5 (`route_bindings` etc.) are untouched.
///
/// Shape changes vs v6/v11:
/// - `revisions` gains `principal TEXT NOT NULL`; PRIMARY KEY becomes
///   `(principal, revision_id)`. `revision_id` stays a globally-unique
///   UUID, so it remains addressable on its own, but the composite key
///   lets two principals each hold their own independent history.
/// - The single-active partial unique index becomes **per-principal**:
///   `idx_one_active_revision_per_principal ON revisions(principal)
///   WHERE status='active'` — at most one active revision *per user*.
/// - `active_revision_pointer` is no longer a singleton. It is keyed by
///   `principal` (PRIMARY KEY) with a composite foreign key
///   `(principal, revision_id) → revisions(principal, revision_id)`.
/// - `mutation_tokens` gains `principal TEXT NOT NULL` so a confirmation
///   token issued for one user cannot be consumed against another's
///   revisions (authorization scoping).
/// - The `risk_level` CHECK now admits `'critical'` (`RiskLevel` gained
///   the slug, but the v6 CHECK predated it — the reset corrects the
///   latent constraint mismatch).
///
/// `row_hmac` (v11) is preserved on the recreated `revisions` table; the
/// HMAC input now includes `principal` (see `revision_hmac::RowFields`).
pub const STATE_DB_V12_DDL: &[&str] = &[
    "DROP TABLE IF EXISTS active_revision_pointer",
    "DROP TABLE IF EXISTS revisions",
    "DROP TABLE IF EXISTS mutation_tokens",
    "CREATE TABLE revisions (
    principal            TEXT    NOT NULL,
    revision_id          TEXT    NOT NULL,
    content_hash         TEXT    NOT NULL,
    rules_json           TEXT    NOT NULL,
    status               TEXT    NOT NULL CHECK(status IN
                            ('candidate','active','superseded','rolled-back','rejected')),
    source               TEXT    NOT NULL CHECK(source IN
                            ('gui-rules-edit','preset-import','recovery-lkg','rollback')),
    correlation_id       TEXT    NOT NULL,
    created_at           INTEGER NOT NULL,
    activated_at         INTEGER,
    superseded_at        INTEGER,
    superseded_by        TEXT,
    rejected_reason      TEXT,
    review_summary_json  TEXT,
    risk_level           TEXT    CHECK(risk_level IN ('low','medium','high','critical')),
    row_hmac             BLOB    NOT NULL DEFAULT x'',
    PRIMARY KEY (principal, revision_id)
)",
    "CREATE INDEX IF NOT EXISTS idx_revisions_status
 ON revisions(status)",
    "CREATE INDEX IF NOT EXISTS idx_revisions_created
 ON revisions(created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_revisions_principal
 ON revisions(principal)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_revision_per_principal
 ON revisions(principal) WHERE status = 'active'",
    "CREATE TABLE active_revision_pointer (
    principal         TEXT    PRIMARY KEY,
    revision_id       TEXT    NOT NULL,
    activated_at      INTEGER NOT NULL,
    apply_attempt_id  TEXT,
    FOREIGN KEY (principal, revision_id)
        REFERENCES revisions(principal, revision_id)
)",
    "CREATE TABLE mutation_tokens (
    token                  TEXT    PRIMARY KEY,
    principal              TEXT    NOT NULL,
    mutation_payload_json  TEXT    NOT NULL,
    issued_at              INTEGER NOT NULL,
    expires_at             INTEGER NOT NULL,
    consumed               INTEGER NOT NULL DEFAULT 0
)",
    "CREATE INDEX IF NOT EXISTS idx_mutation_tokens_expires
 ON mutation_tokens(expires_at)",
];

/// State DB v13. Adds two diagnostics toggles
/// to `service_stability_config`, siblings of `verbose_logging` (v9): whether
/// the opt-in connection-egress trace writes to the operational NDJSON and/or
/// streams to the GUI «Диагностика» panel. Both default `0` (off) — the trace
/// is privacy-sensitive (per-connection process + remote IP), so it never runs
/// unless an administrator turns it on. Same `ALTER TABLE ADD COLUMN` form as
/// v9; existing rows backfill with the column default.
pub const STATE_DB_V13_DDL: &[&str] = &[
    "ALTER TABLE service_stability_config \
ADD COLUMN conn_trace_ndjson INTEGER NOT NULL DEFAULT 0 \
CHECK(conn_trace_ndjson IN (0, 1))",
    "ALTER TABLE service_stability_config \
ADD COLUMN conn_trace_gui INTEGER NOT NULL DEFAULT 0 \
CHECK(conn_trace_gui IN (0, 1))",
];

/// State DB v14. Adds the `rule_scope_service_driven`
/// flag to `service_stability_config`: when `1` (the default) the service
/// enforces the active console user's routing policy continuously — even with
/// no GUI/tray connected, from boot — until the service stops; when `0` the
/// route table is only enforced while a tray is connected (cleared on
/// disconnect). Default `1` (service-driven) so a managed/locked-down install
/// (admin deploys on a non-admin user's machine) routes from boot without the
/// user ever opening the app. Same `ALTER TABLE ADD COLUMN` form as v9/v13;
/// existing rows backfill with the column default.
pub const STATE_DB_V14_DDL: &[&str] = &["ALTER TABLE service_stability_config \
ADD COLUMN rule_scope_service_driven INTEGER NOT NULL DEFAULT 1 \
CHECK(rule_scope_service_driven IN (0, 1))"];

/// State DB v15. Adds the
/// `kill_switch_fail_closed` flag to `secondary_block_policy`, a sibling of the
/// v5 `block_secondary_when_unavailable` toggle it modifies. It governs what the
/// kill-switch does when the secondary (VPN) interface cannot be resolved at
/// apply time (adapter down / GUID stale): `1` (the default) **fails closed** —
/// matched/all traffic is blocked rather than leaking out the primary link under
/// the real address; `0` **fails open** — traffic is allowed and the GUI shows a
/// loud "protection not active" banner. Default `1` so the emergency block lives
/// up to its name. Same `ALTER TABLE ADD COLUMN` form as v9/v13/v14; existing
/// rows backfill with the column default (fail-closed).
pub const STATE_DB_V15_DDL: &[&str] = &["ALTER TABLE secondary_block_policy \
ADD COLUMN kill_switch_fail_closed INTEGER NOT NULL DEFAULT 1 \
CHECK(kill_switch_fail_closed IN (0, 1))"];

/// State DB v16. Adds the
/// `kill_switch_protocols` bitmask to `secondary_block_policy`: which IP
/// protocols the emergency block cuts. Bit layout (LSB→MSB): TCP=1, UDP=2,
/// ICMP=4, IGMP=8, GRE=16, ESP=32, Other=64 (all = 127). Default `127` —
/// block every protocol, a true kill-switch incl. ICMP/ping (which the ALE
/// connect layer can't see; those need the OUTBOUND_IPPACKET layer). Same
/// `ALTER TABLE ADD COLUMN` form as v9/v13/v14/v15; existing rows backfill
/// with the column default (all protocols).
pub const STATE_DB_V16_DDL: &[&str] = &["ALTER TABLE secondary_block_policy \
ADD COLUMN kill_switch_protocols INTEGER NOT NULL DEFAULT 127 \
CHECK(kill_switch_protocols BETWEEN 0 AND 127)"];

/// State DB v17 — persist-on-stop routing policy. Adds the
/// `routing_stop_policy` slug to `service_stability_config`, a sibling of the
/// v14 `rule_scope_service_driven` flag it lives beside: what happens to
/// NRR routing when the Windows service stops. `'teardown'` (the default)
/// removes the NRR `/32` routes and strips every WFP filter so the box
/// returns to its pre-NRR channel (secondary if still up, else direct); `'persist'`
/// keeps the `/32` routes (matched hosts keep egressing the secondary) but
/// STILL strips every block/fail-closed/kill-switch filter — a block with no
/// service to lift it is a lockout, so it is never persisted. Stored as a TEXT
/// slug (mirrors `autostart_state` / `ipc_accept_kind`) with a CHECK; existing
/// rows backfill to `'teardown'`. Same `ALTER TABLE ADD COLUMN` form as
/// v9/v13/v14/v15/v16.
pub const STATE_DB_V17_DDL: &[&str] = &["ALTER TABLE service_stability_config \
ADD COLUMN routing_stop_policy TEXT NOT NULL DEFAULT 'teardown' \
CHECK(routing_stop_policy IN ('teardown', 'persist'))"];

/// `log_retention_config` singleton: user-configurable
/// retention for the OPERATIONAL NDJSON logs and the AUDIT NDJSON trail (age +
/// total-size caps). Drives the service-side cleanup tasks (`CleanupJob::run_
/// logs` / `run_audit`). Defaults mirror CLAUDE.md (logs 90d/50MiB, audit
/// 365d/50MiB). CHECK ranges are deliberately wide so a GUI value (value × unit)
/// is never client-valid-but-storage-rejected; `0` size = age-only (no size
/// cap). Same singleton `id=1` pattern as `retention_settings`.
pub const STATE_DB_V18_DDL: &[&str] = &["CREATE TABLE IF NOT EXISTS log_retention_config (
    id                    INTEGER PRIMARY KEY CHECK(id = 1),
    log_max_age_days      INTEGER NOT NULL DEFAULT 90
                                     CHECK(log_max_age_days BETWEEN 1 AND 3650),
    log_max_size_bytes    INTEGER NOT NULL DEFAULT 52428800
                                     CHECK(log_max_size_bytes BETWEEN 0 AND 1099511627776),
    audit_max_age_days    INTEGER NOT NULL DEFAULT 365
                                     CHECK(audit_max_age_days BETWEEN 1 AND 3650),
    audit_max_size_bytes  INTEGER NOT NULL DEFAULT 52428800
                                     CHECK(audit_max_size_bytes BETWEEN 0 AND 1099511627776),
    updated_at            INTEGER NOT NULL
)"];

/// User-configurable FQDN cache refresh interval on
/// `service_stability_config` (sibling of the v9/v13/v14/v17 flags). Drives the
/// refresh cadence FLOOR (`FreshnessThresholds::fallback_ttl_secs`): a routed
/// site's IPs are re-resolved at most this often. CHECK 60..86400 mirrors the
/// `nrr_domain::decision_lookup::CACHE_REFRESH_{MIN,MAX}_SECS` SSOT so a value
/// can never be client-valid-but-storage-rejected; existing rows backfill to
/// the 5-minute default. Same `ALTER TABLE ADD COLUMN` form as v9/v14/v17.
pub const STATE_DB_V19_DDL: &[&str] = &["ALTER TABLE service_stability_config \
ADD COLUMN cache_refresh_interval_secs INTEGER NOT NULL DEFAULT 300 \
CHECK(cache_refresh_interval_secs BETWEEN 60 AND 86400)"];

/// Opt-in "treat a domain as `domain` + `*.domain`" on
/// `secondary_block_policy` (sibling of the v15/v16 kill-switch flags). When
/// `1`, the enforcement layer expands every bare-domain (`ExactFqdn`) rule with
/// a `SuffixDomain` sibling so a rule for `example.com` also covers its
/// subdomains (apex kept). Applied only to the enforcement rule book, never to
/// the canonical/stored hash. Same `ALTER TABLE ADD COLUMN` form as v15/v16.
///
/// The SQL `DEFAULT 0` below is INERT and must stay as written — the DDL string
/// is checksummed by the migration runner, and every upsert binds this column
/// explicitly. The effective product default lives in the application layer
/// (`RoutePolicyRecord::empty` and the missing-row branch of `load_block_policy`)
/// and is ON by default.
pub const STATE_DB_V20_DDL: &[&str] = &["ALTER TABLE secondary_block_policy \
ADD COLUMN include_subdomains INTEGER NOT NULL DEFAULT 0 \
CHECK(include_subdomains IN (0, 1))"];

/// `shared_ip_policy` on `secondary_block_policy`: how a
/// SHARED secondary IP (an address a secondary rule routes but that other
/// hostnames also resolve to) is treated. `0` = majority-of-ip (default,
/// balanced), `1` = majority-of-rules (conservative), `2` = any-rule-domain
/// (aggressive, historic behaviour). Codes mirror
/// `nrr_domain::shared_ip::SharedIpPolicy::as_code` so a value can never be
/// domain-valid-but-storage-rejected; existing rows backfill to `0`. Same
/// `ALTER TABLE ADD COLUMN` form as v15/v16/v20.
pub const STATE_DB_V21_DDL: &[&str] = &["ALTER TABLE secondary_block_policy \
ADD COLUMN shared_ip_policy INTEGER NOT NULL DEFAULT 0 \
CHECK(shared_ip_policy IN (0, 1, 2))"];

/// `known_stable_ids` on `route_bindings`: a newline-
/// delimited set of every stable adapter id this `(sid, role)` binding has been
/// matched to (the current `stable_id` plus historical GUIDs the auto-heal
/// folded in). The route coordinator matches a live adapter against ANY of
/// these, so a secondary adapter whose GUID rotated across a reinstall/version
/// bump is still recognised without waiting for a friendly-name heal. Seeded to the binding's
/// own `stable_id` on user assignment; the auto-heal unions each newly-matched
/// id. Newline is a safe separator — adapter ids never contain one. Existing
/// rows backfill to `''` (empty set). Same `ALTER TABLE ADD COLUMN` form as
/// v15/v16/v20/v21.
pub const STATE_DB_V22_DDL: &[&str] =
    &["ALTER TABLE route_bindings ADD COLUMN known_stable_ids TEXT NOT NULL DEFAULT ''"];

/// `kill_switch_block_all` on `secondary_block_policy`: when
/// set, split-mode fail-closed blocks ALL egress (catch-all) instead of only the
/// cached secondary destination IPs, so ICMP/ping and rotating/un-cached IPs of
/// secondary-rule hosts cannot leak to the primary while the secondary is down. Default
/// 0 (OFF; the per-IP behavior). ALTER ADD COLUMN, same form as v20/v21.
pub const STATE_DB_V23_DDL: &[&str] = &["ALTER TABLE secondary_block_policy \
ADD COLUMN kill_switch_block_all INTEGER NOT NULL DEFAULT 0 \
CHECK(kill_switch_block_all IN (0, 1))"];

/// `enforcement_mode` on `service_stability_config`:
/// selects the machine-wide traffic-enforcement MECHANISM. `0` = Reactive (the
/// existing reactive kill-switch — passive ETW/seeder learning, the default),
/// `1` = Resolver (a local DNS resolver that installs enforcement before it
/// answers). Global service setting (NOT per-SID), so it lives on the singleton
/// `service_stability_config` row. Codes mirror
/// `nrr_domain::enforcement_mode::EnforcementMode::as_code` so a value can never
/// be domain-valid-but-storage-rejected; existing rows backfill to `0`
/// (Reactive). Same `ALTER TABLE ADD COLUMN` form as v17/v19.
pub const STATE_DB_V24_DDL: &[&str] = &["ALTER TABLE service_stability_config \
ADD COLUMN enforcement_mode INTEGER NOT NULL DEFAULT 0 \
CHECK(enforcement_mode IN (0, 1))"];

/// `secondary_liveness_window_secs` on
/// `service_stability_config`: the active-ICMP-probe liveness window (SECONDS)
/// after which the kill-switch fail-closes when the secondary tunnel next-hop is
/// continuously unreachable. `0` (the default) DISABLES the probe (it never
/// fail-closes — the safe default); a non-zero value is clamped to `5..=3600` by
/// the repository on both read and write. Global service setting (NOT per-SID),
/// so it lives on the singleton `service_stability_config` row. The CHECK admits
/// `0` (disabled) plus the whole `0..=3600` range; existing rows backfill to `0`.
/// Same `ALTER TABLE ADD COLUMN` form as v19/v24.
pub const STATE_DB_V25_DDL: &[&str] = &["ALTER TABLE service_stability_config \
ADD COLUMN secondary_liveness_window_secs INTEGER NOT NULL DEFAULT 0 \
CHECK(secondary_liveness_window_secs BETWEEN 0 AND 3600)"];

/// `kill_switch_enabled` on `secondary_block_policy`: the
/// MASTER kill-switch toggle. `0` (the default) = kill-switch OFF, so NO
/// fail-closed / leak-guard blocking arms at all (full opt-in — any leak while
/// the secondary is down is then the user's explicit choice); `1` = enabled, and
/// only then do the sibling `kill_switch_fail_closed` / `kill_switch_block_all` /
/// `kill_switch_protocols` fields take effect. Existing rows backfill to `0`.
/// DEV schema (v26) — throwaway and wiped freely pre-release.
/// Same `ALTER TABLE ADD COLUMN` form as v20/v21/v23.
pub const STATE_DB_V26_DDL: &[&str] = &["ALTER TABLE secondary_block_policy \
ADD COLUMN kill_switch_enabled INTEGER NOT NULL DEFAULT 0 \
CHECK(kill_switch_enabled IN (0, 1))"];

/// `allow_dns_over_primary` on `secondary_block_policy`: OPT-IN
/// relaxation that keeps name resolution working over the primary link (a
/// port-scoped UDP/TCP-53 permit) while the kill-switch block-all is engaged. `0`
/// (default) = strict (blocks DNS too). DEV schema (v27) — throwaway, wiped freely.
/// Same `ALTER TABLE ADD COLUMN` form as v23/v26.
pub const STATE_DB_V27_DDL: &[&str] = &["ALTER TABLE secondary_block_policy \
ADD COLUMN allow_dns_over_primary INTEGER NOT NULL DEFAULT 0 \
CHECK(allow_dns_over_primary IN (0, 1))"];

/// Two per-SID leak-protection fields on `secondary_block_policy`:
/// `mode_a_coverage_strategy` (INTEGER code, [`nrr_domain::mode_a_coverage::ModeACoverageStrategy`]:
/// 0=per-ip, 1=fail-closed-on-unknown-IP, 2=zone-widening; the SQL `DEFAULT 0`
/// is inert — upserts always bind the column, and the effective default is the
/// Rust-side `ModeACoverageStrategy::default()` = per-ip; the DDL string stays
/// untouched because it is checksummed) — how Mode A
/// treats a routed domain's un-seeded edge IP; and `resolve_hosts_bypass`
/// (`1` = DEFAULT = resolve rule hosts bypassing
/// the OS hosts/adblock file so a routed host gets a routable public IP instead of
/// a `127.0.0.1` pin; `0` = honour the hosts file). DEV schema (v28) — throwaway,
/// wiped freely pre-release. Same `ALTER ADD COLUMN`
/// form as v21/v23/v26/v27.
pub const STATE_DB_V28_DDL: &[&str] = &[
    "ALTER TABLE secondary_block_policy \
ADD COLUMN mode_a_coverage_strategy INTEGER NOT NULL DEFAULT 0 \
CHECK(mode_a_coverage_strategy IN (0, 1, 2))",
    "ALTER TABLE secondary_block_policy \
ADD COLUMN resolve_hosts_bypass INTEGER NOT NULL DEFAULT 1 \
CHECK(resolve_hosts_bypass IN (0, 1))",
];

/// Two persistence tables that break the
/// VPN-under-kill-switch chicken-and-egg by surviving a service restart.
///
/// `app_pattern_resolutions` — last-good exe-path resolutions keyed by the app
/// pattern (name/glob). Modelled on `hostname_ip_resolutions` in the cache DB but
/// lives in the STATE DB because an exe path is machine-wide (NOT per-SID) and
/// must not be wiped by the rebuildable-cache reset. A VPN client that is not
/// currently running and not found by the bounded Program-Files walk otherwise
/// resolves to nothing, so its ALE_APP_ID exemption never installs; persisting the
/// last-good path lets the `PersistentAppPathResolver` decorator fall back to it.
///
/// `vpn_bootstrap_endpoints` — observed (Phase 1) and, later, manually-entered
/// (Phase 2, schema headroom) VPN bootstrap server endpoints. The catch-all
/// kill-switch refuses to arm without at least one server exemption (arming a
/// block-everything with no server hole would trap the tunnel's own reconnection);
/// the live set is derived only from route observation and is lost on restart.
/// Persisting it lets exemptions survive a restart even before the VPN reconnects.
/// Phase 1 writes only `source='observed'` rows carrying `ip`; `port`, `protocol`
/// and `source='manual'` are reserved for Phase 2 corp-VPN endpoint entry.
///
/// DEV schema (v29) — throwaway, wiped freely pre-release. Purely
/// additive `CREATE TABLE`s.
pub const STATE_DB_V29_DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS app_pattern_resolutions (
    pattern       TEXT    NOT NULL,
    resolved_path TEXT    NOT NULL,
    resolved_at   INTEGER NOT NULL,
    PRIMARY KEY (pattern, resolved_path)
)",
    "CREATE TABLE IF NOT EXISTS vpn_bootstrap_endpoints (
    ip         TEXT    NOT NULL,
    port       INTEGER,
    protocol   TEXT,
    source     TEXT    NOT NULL CHECK(source IN ('observed', 'manual')),
    learned_at INTEGER NOT NULL,
    PRIMARY KEY (ip, source)
)",
];

/// `route_link_provider_apps` — the **link-provider
/// applications** of a route binding: executables the user confirmed as
/// establishing/maintaining that link (a VPN client is the common case for the
/// secondary role; a plain Wi-Fi/Ethernet secondary has none). Policy-affecting
/// per-SID data — this is the service-side SSOT the VPN onboarding dialog
/// writes to (the `confirmed_vpn_exe_paths` UI preference is a display-only
/// mirror). Consumed by:
/// - kill-switch codegen — each path earns an `ALE_APP_ID` permit in the
///   `APP_EXEMPT_BASE` band so the provider app can (re)establish its link
///   under any kill-switch posture (the C4 self-blocking class);
/// - the connection-observation endpoint learner — configured basenames
///   extend the built-in `DEFAULT_VPN_EXEMPT_PATTERNS` name globs.
///
/// Keyed `(sid, role, exe_path)`: per-binding by construction, so the Pro
/// multi-adapter model extends it without a reshape (`role` grows beyond
/// 'primary'/'secondary' with the binding model). `source` distinguishes a
/// user-confirmed pick from an auto-discovery suggestion (reserved).
///
/// DEV schema (v30) — throwaway, wiped freely pre-release. Purely
/// additive `CREATE TABLE`.
pub const STATE_DB_V30_DDL: &[&str] = &["CREATE TABLE IF NOT EXISTS route_link_provider_apps (
    sid          TEXT    NOT NULL,
    role         TEXT    NOT NULL CHECK(role IN ('primary', 'secondary')),
    exe_path     TEXT    NOT NULL,
    display_name TEXT    NOT NULL DEFAULT '',
    source       TEXT    NOT NULL DEFAULT 'user-confirmed'
                 CHECK(source IN ('user-confirmed', 'discovered')),
    updated_at   INTEGER NOT NULL,
    PRIMARY KEY (sid, role, exe_path)
)"];

/// The DoH/DoT lockdown state. Two ALTERs add the
/// per-SID toggle + scope to `secondary_block_policy` (same `ALTER ADD COLUMN`
/// form as v28); a CREATE adds the shared baseline resolver list. `doh_lockdown_
/// enabled` defaults `0` (OFF — the lockdown is an explicit opt-in; DoH browsing
/// is not broken out of the box). `doh_lockdown_scope` defaults `0` =
/// leak-protection-only (`nrr_storage::doh_lockdown::DohLockdownScope::as_code`).
/// `doh_resolver_entries` is machine-wide (no `sid`): the resolver set is a
/// shared fact, seeded with public resolvers and edited once (with elevation).
/// DEV schema (v31) — throwaway, wiped freely pre-release.
pub const STATE_DB_V31_DDL: &[&str] = &[
    "ALTER TABLE secondary_block_policy \
ADD COLUMN doh_lockdown_enabled INTEGER NOT NULL DEFAULT 0 \
CHECK(doh_lockdown_enabled IN (0, 1))",
    "ALTER TABLE secondary_block_policy \
ADD COLUMN doh_lockdown_scope INTEGER NOT NULL DEFAULT 0 \
CHECK(doh_lockdown_scope IN (0, 1))",
    "CREATE TABLE IF NOT EXISTS doh_resolver_entries (
    target_kind TEXT    NOT NULL CHECK(target_kind IN ('ip', 'host')),
    target      TEXT    NOT NULL,
    comment     TEXT    NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (target_kind, target)
)",
];

/// Opt-in AUTOMATIC browser-history seed. One ALTER
/// adds the per-SID toggle to `secondary_block_policy` (same `ALTER ADD
/// COLUMN` form as v28/v31). Defaults `0` (OFF): browser history is
/// privacy-sensitive, so the periodic/boot seed is an explicit opt-in; the
/// manual "seed from browser history" button keeps working regardless.
///
/// DEV schema (v32) — throwaway, wiped freely pre-release. Purely
/// additive `ALTER TABLE`.
pub const STATE_DB_V32_DDL: &[&str] = &["ALTER TABLE secondary_block_policy \
ADD COLUMN browser_history_auto_seed INTEGER NOT NULL DEFAULT 0 \
CHECK(browser_history_auto_seed IN (0, 1))"];

/// Kill-switch shared-IP strictness. `0` (default,
/// "smart"): an IP the shared-IP census has seen on a direct (non-rule) host is
/// EXCLUDED from the kill-switch per-IP pin/block set, so blocking a
/// secondary-routed CDN address cannot cut an innocent co-tenant site
/// (e.g. gemini/youtube sharing Google front-end IPs with www.google.com).
/// `1` ("strict"): pin/block every secondary-destined IP regardless of
/// sharing; no leak, accepts the collateral.
///
/// DEV schema (v33) — throwaway, wiped freely pre-release. Purely
/// additive `ALTER TABLE`.
pub const STATE_DB_V33_DDL: &[&str] = &["ALTER TABLE secondary_block_policy \
ADD COLUMN kill_switch_strict_shared_ips INTEGER NOT NULL DEFAULT 0 \
CHECK(kill_switch_strict_shared_ips IN (0, 1))"];

/// Machine-wide `fake_ip_enabled` toggle on
/// `service_stability_config`, sibling of the v9/v13/v14/v17/v19 flags. When `1`
/// the resolver answers in-scope rule hosts with virtual addresses and the
/// per-SID codegen suppresses their real `/32` permits + blocks the leak paths.
/// Default `0` (off — fake-IP changes how names resolve, so it is opt-in).
/// Purely additive ALTER. DEV schema; wiped freely.
pub const STATE_DB_V34_DDL: &[&str] = &["ALTER TABLE service_stability_config \
ADD COLUMN fake_ip_enabled INTEGER NOT NULL DEFAULT 0 \
CHECK(fake_ip_enabled IN (0, 1))"];

/// Block T (traffic counter) — service-global traffic-statistics settings
/// singleton. Lives in the service-critical state DB (NOT the rebuildable
/// `nrr_traffic_stats.db`) so a rebuild of the ledger never loses the user's
/// config. `enabled` is the master accounting toggle (default ON);
/// `count_loopback` / `count_virtual` are the opt-in category toggles (default
/// OFF); `retention_days` bounds the daily-history sweep. The Today/Session
/// display period is a UI preference, not here. New dedicated table on purpose —
/// avoids growing the fragile multi-arg `service_stability_config::set`.
pub const STATE_DB_V35_DDL: &[&str] = &["CREATE TABLE IF NOT EXISTS traffic_stats_settings (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    enabled        INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    count_loopback INTEGER NOT NULL DEFAULT 0 CHECK(count_loopback IN (0, 1)),
    count_virtual  INTEGER NOT NULL DEFAULT 0 CHECK(count_virtual IN (0, 1)),
    retention_days INTEGER NOT NULL DEFAULT 365 CHECK(retention_days BETWEEN 7 AND 3650),
    updated_at     INTEGER NOT NULL DEFAULT 0
)"];

/// DNS-over-the-secondary-link toggle — `dns_via_secondary` on
/// `service_stability_config`, sibling of the v34 `fake_ip_enabled` flag. When
/// `1` AND the secondary adapter is up, the service's own upstream DNS queries
/// egress source-bound through the secondary link to public resolvers instead
/// of the primary provider's resolver (which can stub/poison answers). Default
/// `0` (off — opt-in). Purely additive ALTER. DEV schema; wiped freely.
pub const STATE_DB_V36_DDL: &[&str] = &["ALTER TABLE service_stability_config \
ADD COLUMN dns_via_secondary INTEGER NOT NULL DEFAULT 0 \
CHECK(dns_via_secondary IN (0, 1))"];

/// `fake_ip_heal_exclusions` — hostnames the VPN self-heal
/// excluded from fake-IP (a VPN client was seen reaching this server through
/// the relay). The live set is in-memory and empty on every service start, so
/// the FIRST connect attempt of a session paid one failed round through the
/// relay before the exclusion was re-learned. Persisting the learned hostnames
/// lets boot pre-seed the exclusion set and the first attempt go direct.
/// Additive like `vpn_bootstrap_endpoints`: a briefly-unseen server keeps its
/// row (re-learning refreshes `learned_at`). DEV schema; wiped freely.
pub const STATE_DB_V37_DDL: &[&str] = &["CREATE TABLE IF NOT EXISTS fake_ip_heal_exclusions (
    hostname   TEXT    NOT NULL PRIMARY KEY,
    learned_at INTEGER NOT NULL
)"];

/// Fast DNS answers — `dns_fast_answers` on
/// `service_stability_config`, sibling of the v36 `dns_via_secondary` flag.
/// When `1`, the Mode-B resolver answers a rule-host query IMMEDIATELY when
/// every answered address is already in the routable cache (its routes are
/// installed or converging), and only holds the answer for the reconcile
/// deadline when the answer introduces addresses the cache has never seen
/// (first contact — the one case where the app's first connect could race
/// the route install). Field measurement: 57% of held answers blew the
/// full deadline and a large share of clients abandoned the query, which
/// reads as "every site is slow". Default `1` (on). Purely
/// additive ALTER. DEV schema; wiped freely.
pub const STATE_DB_V38_DDL: &[&str] = &["ALTER TABLE service_stability_config \
ADD COLUMN dns_fast_answers INTEGER NOT NULL DEFAULT 1 \
CHECK(dns_fast_answers IN (0, 1))"];

/// Fake-IP UDP relay — `fake_ip_udp_relay` on
/// `service_stability_config`, sibling of the v34 `fake_ip_enabled` flag. When
/// `1`, the fake-IP pool permit admits UDP (QUIC/HTTP-3) into the pool instead
/// of hard-blocking it, so QUIC rides the relay's TUN stack the same way TCP
/// already does. Meaningful only alongside `fake_ip_enabled`. Default `0`
/// (off — "QUIC dies at connect, browser falls back to TCP" behaviour
/// is preserved until the user opts in). Purely additive ALTER. DEV schema;
/// wiped freely.
pub const STATE_DB_V39_DDL: &[&str] = &["ALTER TABLE service_stability_config \
ADD COLUMN fake_ip_udp_relay INTEGER NOT NULL DEFAULT 0 \
CHECK(fake_ip_udp_relay IN (0, 1))"];

/// Fake-IP instant reset — `fake_ip_instant_rst` on
/// `service_stability_config`, sibling of the v39 `fake_ip_udp_relay` flag.
/// Every VPN reconnect window hits
/// this path: when the relay's dial fails because the source-address policy
/// refused it (the secondary adapter is unresolved — dialing would leak via
/// the primary), the client is reset immediately. When `1` (default), that
/// stays instant. When `0`, ONLY that refusal class
/// is held and retried for a bounded window (~10 s) waiting for the secondary
/// to resolve before refusing as usual; a genuine network error still
/// fails fast. Meaningful only alongside `fake_ip_enabled`. Purely additive
/// ALTER. DEV schema; wiped freely.
pub const STATE_DB_V40_DDL: &[&str] = &["ALTER TABLE service_stability_config \
ADD COLUMN fake_ip_instant_rst INTEGER NOT NULL DEFAULT 1 \
CHECK(fake_ip_instant_rst IN (0, 1))"];

/// `vpn_client_apps` — executable paths of VPN client processes
/// whose role was VERIFIED by a kill-switch drop: the connection observer saw
/// OUR kill-switch/fail-closed Block drop a flow from a VPN-named process and
/// role-verified the dropping filter's spec id. Such a client's own primary-side
/// traffic (server handshake, connectivity checks against rotating provider
/// IPs) IS the tunnel's transport, so it earns a proactive app-scoped exemption
/// whenever a block-all posture arms — before the first drop of a session,
/// instead of one reactive per-IP exemption per rotated endpoint. Machine-wide
/// (an exe path is not per-SID), additive like `vpn_bootstrap_endpoints`:
/// re-learning refreshes `learned_at`; a bounded cap evicts the oldest rows.
/// Paths are compared case-insensitively (Windows file systems are). DEV
/// schema; wiped freely.
pub const STATE_DB_V41_DDL: &[&str] = &["CREATE TABLE IF NOT EXISTS vpn_client_apps (
    exe_path   TEXT    NOT NULL COLLATE NOCASE PRIMARY KEY,
    learned_at INTEGER NOT NULL
)"];

/// Auto-rules mode — `auto_rules_mode` on `secondary_block_policy`,
/// per-SID like every other field of that table (a user's own rule set is their
/// own; the machine-global `service_stability_config` would be the wrong home,
/// and its wire op is privileged whereas `route.policy.update` is open to GUI
/// and tray without elevation).
///
/// Governs what happens to companion domains discovered for a routed site whose
/// rules do not yet cover the CDN/media hosts it needs: `off` (do not collect),
/// `suggest` (collect and offer, apply nothing) or `auto` (apply and record in
/// the user's rules).
///
/// Stored as the wire slug itself (TEXT + CHECK), not an integer code — the
/// column is then self-documenting in a `.dump` and the wire/DB/GUI vocabulary
/// stays one string. Default `suggest`: never applies anything
/// on its own. Modelled as three slugs rather than a bool so a later default
/// flip needs no schema change. Purely additive ALTER. DEV schema; wiped freely.
pub const STATE_DB_V42_DDL: &[&str] = &["ALTER TABLE secondary_block_policy \
ADD COLUMN auto_rules_mode TEXT NOT NULL DEFAULT 'suggest' \
CHECK(auto_rules_mode IN ('off', 'suggest', 'auto'))"];

/// `auto_rule_dismissals` — companion-domain suggestions the user
/// explicitly refused ("Do not suggest").
///
/// A refusal is a decision the user made once, and the evidence that produced
/// the suggestion keeps accumulating, so without a durable record the same
/// rejected host would be offered again after every service restart. That is
/// the one outcome that turns this feature from helpful into nagging, which is
/// why this table exists. Pending (unanswered) suggestions have their own
/// durable table — see [`STATE_DB_V47_DDL`].
///
/// Keyed by `(sid, candidate_id)`: the id is derived from the SID + anchor +
/// proposed match, so it is stable across restarts and re-ticks, and one
/// user's refusal never silences another's suggestion. `anchor` /
/// `proposed_match` are stored alongside purely so the row is legible in a
/// `.dump` and so a future id-scheme change can re-derive rather than lose
/// refusals. A bounded cap evicts the oldest refusals. DEV schema; wiped
/// freely.
pub const STATE_DB_V43_DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS auto_rule_dismissals (
    sid            TEXT    NOT NULL,
    candidate_id   TEXT    NOT NULL,
    anchor         TEXT    NOT NULL,
    proposed_match TEXT    NOT NULL,
    dismissed_at   INTEGER NOT NULL,
    PRIMARY KEY (sid, candidate_id)
)",
    "CREATE INDEX IF NOT EXISTS idx_auto_rule_dismissals_sid
     ON auto_rule_dismissals(sid, dismissed_at DESC)",
];

/// `app_observed_destinations` — destinations an application rule's
/// process has actually been seen connecting to, kept across service restarts.
///
/// An application routed over the additional link is pinned to that link for
/// EVERY destination, but the only thing that puts one of its destinations on
/// the link is a host route derived from an address something has already
/// observed. In-memory observation therefore starts every session empty, and the
/// app's first contact with each address is refused until the observation
/// arrives — correct (it never leaks) but repeated in full after every restart.
/// Persisting the set lets the next session install those routes BEFORE the
/// first connection.
///
/// Written only for applications the rule book routes over the additional link,
/// so the table can never describe an app the user never named. Keyed by the
/// rule's own app pattern (`app_key`) exactly as the codegen queries it, so a
/// reload round-trips without re-deriving anything. `learned_at` is the last
/// time the address was confirmed in use; the reader admits only rows inside
/// the enforcement confirmation window, so an address the app stopped using
/// silently stops being seeded. A bounded per-app cap evicts the oldest rows.
/// DEV schema; wiped freely.
pub const STATE_DB_V44_DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS app_observed_destinations (
    app_key    TEXT    NOT NULL COLLATE NOCASE,
    ip         TEXT    NOT NULL,
    learned_at INTEGER NOT NULL,
    PRIMARY KEY (app_key, ip)
)",
    "CREATE INDEX IF NOT EXISTS idx_app_observed_destinations_learned
     ON app_observed_destinations(app_key, learned_at DESC)",
];

/// Administrative rules lock — `allow_user_rule_edits` on
/// `service_stability_config`.
///
/// Deliberately machine-wide rather than per-SID: the whole point is to stop
/// the very user it restricts from lifting it, and a per-principal row is
/// writable by that principal. It therefore lives on the one singleton whose
/// wire operation already demands elevation, so the restricted account can
/// read the flag but can never write it.
///
/// `1` (the default) keeps today's behaviour — every user maintains their own
/// rule set. `0` freezes rule authoring for non-elevated callers: they keep
/// reading the administrator's baseline, and their own divergence is refused
/// at the service, so a hand-built client or a modified GUI hits the same
/// refusal the shipped one does. Purely additive ALTER. DEV schema; wiped
/// freely.
pub const STATE_DB_V45_DDL: &[&str] = &["ALTER TABLE service_stability_config \
ADD COLUMN allow_user_rule_edits INTEGER NOT NULL DEFAULT 1 \
CHECK(allow_user_rule_edits IN (0, 1))"];

/// Eager delivery-name suggestions — `auto_rules_eager_delivery_names` on
/// `secondary_block_policy`, sibling of the v42 `auto_rules_mode` slug and
/// per-SID for the same reason (a user's rule set is their own).
///
/// Companion discovery normally makes a delivery-shaped host (a CDN endpoint)
/// earn its suggestion across two visits in which the routed site dominates that
/// host's traffic. `1` drops that wait and offers such a host on its first
/// co-occurrence — faster, at the cost of occasionally naming a CDN that serves
/// the routed site and much else besides. `0` (the default) keeps the wait.
/// Only that one tier is affected. Purely additive ALTER. DEV schema; wiped
/// freely.
pub const STATE_DB_V46_DDL: &[&str] = &["ALTER TABLE secondary_block_policy \
ADD COLUMN auto_rules_eager_delivery_names INTEGER NOT NULL DEFAULT 0 \
CHECK(auto_rules_eager_delivery_names IN (0, 1))"];

/// `auto_rule_pending_candidates` — companion-domain suggestions still waiting
/// for an answer, kept across service restarts.
///
/// Superseded assumption: this table did not exist through v46 because a
/// pending suggestion was believed to re-derive itself from the next few
/// minutes of browsing, so only a refusal ([`STATE_DB_V43_DDL`]) needed to
/// survive a restart. In practice the set a user is meant to work through
/// accumulates over weeks — which sites need it, how many, since when — and
/// that composition does not come back from a few minutes of fresh traffic.
/// Pending suggestions are durable from here on; re-derivation still covers
/// the ordinary "service was down for an hour" case, it just no longer has to
/// cover "the user hasn't gotten around to reviewing these yet".
///
/// Keyed by `(sid, candidate_id)`, same identity scheme as
/// `auto_rule_dismissals`. `dto_json` holds the caller's serialized wire DTO
/// verbatim — this crate does not parse it, so a new DTO field never needs a
/// migration here. DEV schema; wiped freely.
pub const STATE_DB_V47_DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS auto_rule_pending_candidates (
    sid            TEXT    NOT NULL,
    candidate_id   TEXT    NOT NULL,
    route          TEXT    NOT NULL,
    match_kind     TEXT    NOT NULL,
    dto_json       TEXT    NOT NULL,
    parked_at      INTEGER NOT NULL,
    PRIMARY KEY (sid, candidate_id)
)",
    "CREATE INDEX IF NOT EXISTS idx_auto_rule_pending_candidates_sid
     ON auto_rule_pending_candidates(sid, parked_at DESC)",
];

/// `auto_rule_dismissals.dto_json` — the offer as it stood when it was refused.
///
/// Undoing a refusal used to only lift the suppression, leaving the user to
/// wait for the observation feed to re-earn the offer — and it often never did,
/// because the evidence had aged out. Keeping the wire DTO makes "allow again"
/// put the row straight back where the user expects it. Same opaque-JSON deal
/// as the pending table: this crate never parses it. Purely additive ALTER;
/// rows written before it restore from `anchor` + `proposed_match` alone.
/// DEV schema; wiped freely.
pub const STATE_DB_V48_DDL: &[&str] = &["ALTER TABLE auto_rule_dismissals \
     ADD COLUMN dto_json TEXT NOT NULL DEFAULT ''"];

/// `block_notice_mutes` — durable "Do not show" choices for blocked-connection
/// notices (`nrr_domain::block_notice::Mute`).
///
/// Without this table a restart forgets every mute and the user is back to the
/// full drop-storm noise the episode folding was built to tame — the same
/// lesson auto-rule suggestions already learned. Storage stays a thin mirror
/// of the domain type: `BlockNoticeLedger::set_mutes` owns the policy, this
/// table only owns durability.
///
/// Keyed by `(sid, scope_kind, scope_value)` so re-muting the same host/app
/// replaces the existing row instead of piling up duplicates, and one user's
/// mute never silences another's notices. `scope_value` is empty only for the
/// `all` scope, enforced by the CHECK. `until_ms` NULL means indefinite,
/// mirroring `Mute::until_ms: Option<u64>`. A bounded per-SID cap evicts the
/// oldest mutes on overflow, same defense-in-depth as the other per-SID
/// tables. DEV schema; wiped freely.
pub const STATE_DB_V49_DDL: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS block_notice_mutes (
    sid         TEXT    NOT NULL,
    scope_kind  TEXT    NOT NULL CHECK(scope_kind IN ('host', 'app', 'all')),
    scope_value TEXT    NOT NULL DEFAULT '',
    until_ms    INTEGER,
    updated_at  INTEGER NOT NULL,
    CHECK ((scope_kind = 'all' AND scope_value = '')
        OR (scope_kind != 'all' AND scope_value != '')),
    PRIMARY KEY (sid, scope_kind, scope_value)
)",
    "CREATE INDEX IF NOT EXISTS idx_block_notice_mutes_sid
     ON block_notice_mutes(sid, updated_at DESC)",
];

/// ISP block-page rule candidates — `isp_block_candidates_enabled` on
/// `service_stability_config`, sibling of `fake_ip_enabled`: an opt-in
/// mechanism gate with no owning administrator flag until now, so the
/// feature could not be turned on to test it. `0` (the default) keeps it
/// off. Purely additive ALTER. DEV schema; wiped freely.
pub const STATE_DB_V50_DDL: &[&str] = &["ALTER TABLE service_stability_config \
ADD COLUMN isp_block_candidates_enabled INTEGER NOT NULL DEFAULT 0 \
CHECK(isp_block_candidates_enabled IN (0, 1))"];

/// Mute by REASON — the fourth block-notice scope. The v49 CHECK enumerated the
/// three scopes that existed, so widening it means rebuilding the table;
/// existing rows are not carried over, which costs a user their current mutes
/// and nothing else. DEV schema; wiped freely.
pub const STATE_DB_V51_DDL: &[&str] = &[
    "DROP TABLE IF EXISTS block_notice_mutes",
    "CREATE TABLE block_notice_mutes (
    sid         TEXT    NOT NULL,
    scope_kind  TEXT    NOT NULL CHECK(scope_kind IN ('host', 'app', 'reason', 'all')),
    scope_value TEXT    NOT NULL DEFAULT '',
    until_ms    INTEGER,
    updated_at  INTEGER NOT NULL,
    CHECK ((scope_kind = 'all' AND scope_value = '')
        OR (scope_kind != 'all' AND scope_value != '')),
    PRIMARY KEY (sid, scope_kind, scope_value)
)",
    "CREATE INDEX IF NOT EXISTS idx_block_notice_mutes_sid
     ON block_notice_mutes(sid, updated_at DESC)",
];

/// Companion-domain evidence that survives a restart — `auto_rule_evidence`.
/// A proposal needs co-occurrence across two windows, and every restart used to
/// reset the count to zero: on a laptop that sleeps and restarts several times
/// a day the second window was never reached, so nothing was ever offered.
/// `snapshot_json` is opaque here, exactly like `auto_rule_pending.dto_json`.
/// Purely additive CREATE. DEV schema; wiped freely.
pub const STATE_DB_V52_DDL: &[&str] = &["CREATE TABLE IF NOT EXISTS auto_rule_evidence (
    sid           TEXT    NOT NULL PRIMARY KEY,
    snapshot_json TEXT    NOT NULL,
    updated_at    INTEGER NOT NULL
)"];

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_domain::decision_lookup::{CacheEntryState, LookupDirection};

    // ── DiagnosticFlags ───────────────────────────────────────────────────────

    #[test]
    fn diagnostic_flags_to_db_from_db_roundtrip() {
        let flags = DiagnosticFlags::AMBIGUOUS | DiagnosticFlags::CONFLICTING;
        assert_eq!(DiagnosticFlags::from_db(flags.to_db()), flags);
    }

    #[test]
    fn diagnostic_flags_empty_is_zero() {
        assert_eq!(DiagnosticFlags::empty().to_db(), 0i64);
        assert_eq!(DiagnosticFlags::from_db(0), DiagnosticFlags::empty());
    }

    #[test]
    fn diagnostic_flags_all_bits_roundtrip() {
        let all = DiagnosticFlags::AMBIGUOUS
            | DiagnosticFlags::CONFLICTING
            | DiagnosticFlags::STALE
            | DiagnosticFlags::NEGATIVE_CACHED
            | DiagnosticFlags::LOOKUP_FAILED
            | DiagnosticFlags::UNSUPPORTED_ADDR_FAM;
        assert_eq!(DiagnosticFlags::from_db(all.to_db()), all);
    }

    #[test]
    fn diagnostic_flags_unknown_bits_truncated() {
        // Bit 7 is not defined; from_db should drop it silently.
        let raw: i64 = 0b1000_0000;
        assert_eq!(DiagnosticFlags::from_db(raw), DiagnosticFlags::empty());
    }

    // ── FreshnessStateDb ──────────────────────────────────────────────────────

    const FRESHNESS_VARIANTS: &[(FreshnessStateDb, &str, CacheEntryState)] = &[
        (FreshnessStateDb::Fresh, "fresh", CacheEntryState::Fresh),
        (
            FreshnessStateDb::StaleUsable,
            "stale_usable",
            CacheEntryState::StaleUsable,
        ),
        (
            FreshnessStateDb::StaleNotUsable,
            "stale_not_usable",
            CacheEntryState::StaleNotUsable,
        ),
        (
            FreshnessStateDb::Conflicting,
            "conflicting",
            CacheEntryState::Conflicting,
        ),
        (
            FreshnessStateDb::NegativeCached,
            "negative_cached",
            CacheEntryState::NegativeCached,
        ),
    ];

    #[test]
    fn freshness_state_as_str_matches_expected() {
        for &(variant, expected_str, _) in FRESHNESS_VARIANTS {
            assert_eq!(variant.as_str(), expected_str);
        }
    }

    #[test]
    fn freshness_state_from_str_roundtrip() {
        for &(variant, s, _) in FRESHNESS_VARIANTS {
            let back = FreshnessStateDb::from_str(s)
                .unwrap_or_else(|| panic!("from_str({s:?}) must succeed"));
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn freshness_state_from_str_unknown_returns_none() {
        assert!(FreshnessStateDb::from_str("missing").is_none());
        assert!(FreshnessStateDb::from_str("FRESH").is_none());
        assert!(FreshnessStateDb::from_str("").is_none());
    }

    #[test]
    fn freshness_state_to_domain_is_correct() {
        for &(variant, _, ref expected_domain) in FRESHNESS_VARIANTS {
            assert_eq!(variant.to_domain(), *expected_domain);
        }
    }

    #[test]
    fn freshness_state_from_domain_roundtrip() {
        for &(expected_variant, _, ref domain) in FRESHNESS_VARIANTS {
            let back = FreshnessStateDb::from_domain(domain)
                .unwrap_or_else(|| panic!("from_domain({domain:?}) must succeed"));
            assert_eq!(back, expected_variant);
        }
    }

    #[test]
    fn freshness_state_missing_has_no_db_form() {
        assert!(FreshnessStateDb::from_domain(&CacheEntryState::Missing).is_none());
    }

    // ── AddressFamily ─────────────────────────────────────────────────────────

    #[test]
    fn address_family_roundtrip() {
        for (variant, s) in [(AddressFamily::Ipv4, "ipv4"), (AddressFamily::Ipv6, "ipv6")] {
            assert_eq!(variant.as_str(), s);
            let back = AddressFamily::from_str(s)
                .unwrap_or_else(|| panic!("from_str({s:?}) must succeed"));
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn address_family_unknown_returns_none() {
        assert!(AddressFamily::from_str("IPv4").is_none());
        assert!(AddressFamily::from_str("").is_none());
    }

    // ── LookupDirection TEXT helpers ──────────────────────────────────────────

    #[test]
    fn lookup_direction_str_roundtrip() {
        let cases = [
            (LookupDirection::HostnameToIp, "hostname_to_ip"),
            (LookupDirection::IpToHostname, "ip_to_hostname"),
            (LookupDirection::Both, "both"),
        ];
        for (dir, expected) in &cases {
            assert_eq!(lookup_direction_as_str(dir), *expected);
            let back = lookup_direction_from_str(expected)
                .unwrap_or_else(|| panic!("from_str({expected:?}) must succeed"));
            assert_eq!(&back, dir);
        }
    }

    #[test]
    fn lookup_direction_unknown_returns_none() {
        assert!(lookup_direction_from_str("HostnameToIp").is_none());
        assert!(lookup_direction_from_str("").is_none());
    }

    // ── DDL execution against in-memory SQLite ────────────────────────────────

    fn open_memory_db() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory SQLite must open");
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
            .expect("pragmas");
        conn
    }

    #[test]
    fn cache_db_v1_ddl_executes_without_error() {
        let conn = open_memory_db();
        for stmt in CACHE_DB_V1_DDL {
            conn.execute_batch(stmt)
                .unwrap_or_else(|e| panic!("DDL failed: {e}\nSQL: {stmt}"));
        }
    }

    #[test]
    fn cache_db_v1_ddl_is_idempotent() {
        let conn = open_memory_db();
        // Run twice — CREATE IF NOT EXISTS must be safe.
        for _ in 0..2 {
            for stmt in CACHE_DB_V1_DDL {
                conn.execute_batch(stmt)
                    .unwrap_or_else(|e| panic!("DDL failed on second run: {e}"));
            }
        }
    }

    #[test]
    fn cache_db_all_expected_tables_exist() {
        let conn = open_memory_db();
        for stmt in CACHE_DB_V1_DDL {
            conn.execute_batch(stmt).expect("DDL");
        }
        let expected_tables = [
            "hostnames",
            "ip_addresses",
            "hostname_ip_resolutions",
            "lookup_events",
            "negative_cache",
            "cache_metadata",
        ];
        for table in &expected_tables {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    rusqlite::params![table],
                    |row| row.get(0),
                )
                .unwrap_or_else(|e| panic!("table check failed for {table}: {e}"));
            assert_eq!(count, 1, "table {table} must exist after DDL");
        }
    }

    #[test]
    fn cache_db_foreign_keys_enforced() {
        let conn = open_memory_db();
        for stmt in CACHE_DB_V1_DDL {
            conn.execute_batch(stmt).expect("DDL");
        }
        // Inserting a resolution with a non-existent hostname_id must fail.
        let result = conn.execute(
            "INSERT INTO hostname_ip_resolutions
             (hostname_id, ip_id, source, resolved_at, expires_at, freshness_state)
             VALUES (9999, 9999, 'dns', 0, 0, 'fresh')",
            [],
        );
        assert!(
            result.is_err(),
            "foreign key violation must be rejected when foreign_keys = ON"
        );
    }

    #[test]
    fn cache_db_cache_metadata_singleton_enforced() {
        let conn = open_memory_db();
        for stmt in CACHE_DB_V1_DDL {
            conn.execute_batch(stmt).expect("DDL");
        }
        conn.execute(
            "INSERT INTO cache_metadata (id, schema_version, created_at, cache_generation)
             VALUES (1, 1, 0, 0)",
            [],
        )
        .expect("first insert");
        let result = conn.execute(
            "INSERT INTO cache_metadata (id, schema_version, created_at, cache_generation)
             VALUES (2, 1, 0, 0)",
            [],
        );
        assert!(result.is_err(), "cache_metadata must allow only id=1");
    }

    #[test]
    fn cache_db_resolution_unique_constraint() {
        let conn = open_memory_db();
        for stmt in CACHE_DB_V1_DDL {
            conn.execute_batch(stmt).expect("DDL");
        }
        // Seed required parent rows.
        conn.execute(
            "INSERT INTO hostnames (canonical_host, first_seen_at, last_seen_at)
             VALUES ('example.com', 0, 0)",
            [],
        )
        .expect("hostname");
        conn.execute(
            "INSERT INTO ip_addresses (address_family, canonical_ip, ipv4_packed, first_seen_at, last_seen_at)
             VALUES ('ipv4', '1.2.3.4', 16909060, 0, 0)",
            [],
        )
        .expect("ip");
        conn.execute(
            "INSERT INTO hostname_ip_resolutions
             (hostname_id, ip_id, source, resolved_at, expires_at, freshness_state)
             VALUES (1, 1, 'dns', 0, 0, 'fresh')",
            [],
        )
        .expect("first resolution");
        // Inserting the same (hostname_id, ip_id, source) again must fail.
        let result = conn.execute(
            "INSERT INTO hostname_ip_resolutions
             (hostname_id, ip_id, source, resolved_at, expires_at, freshness_state)
             VALUES (1, 1, 'dns', 100, 200, 'fresh')",
            [],
        );
        assert!(
            result.is_err(),
            "duplicate (hostname_id, ip_id, source) must be rejected"
        );
    }

    #[test]
    fn state_db_v1_ddl_executes_without_error() {
        let conn = open_memory_db();
        for stmt in STATE_DB_V1_DDL {
            conn.execute_batch(stmt)
                .unwrap_or_else(|e| panic!("state DDL failed: {e}\nSQL: {stmt}"));
        }
    }

    #[test]
    fn state_db_all_expected_tables_exist() {
        let conn = open_memory_db();
        for stmt in STATE_DB_V1_DDL {
            conn.execute_batch(stmt).expect("state DDL");
        }
        for table in &["active_revision", "last_known_good", "integrity_log"] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    rusqlite::params![table],
                    |row| row.get(0),
                )
                .unwrap_or_else(|e| panic!("table check failed for {table}: {e}"));
            assert_eq!(count, 1, "table {table} must exist after state DDL");
        }
    }
}
