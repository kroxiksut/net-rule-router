// ── SQL DDL — nrr_conn_history.db (connection history) ──────────────

/// Each user's connections folded per hour: one row per program, destination,
/// route and verdict in that hour, with the first and last time and how many
/// attempts. `hour` is Unix milliseconds divided by an hour. Empty strings
/// stand for "not known" so the key never holds a NULL.
///
/// The key leads with `(principal, hour)`, which is what every read and the
/// per-user retention pass narrow by.
const CREATE_CONN_HISTORY: &str = "
CREATE TABLE IF NOT EXISTS conn_history (
    principal    TEXT    NOT NULL,
    hour         INTEGER NOT NULL,
    program      TEXT    NOT NULL,
    host         TEXT    NOT NULL,
    remote_ip    TEXT    NOT NULL,
    route        TEXT    NOT NULL,
    verdict      TEXT    NOT NULL,
    blocked_by   TEXT    NOT NULL,
    first_ms     INTEGER NOT NULL,
    last_ms      INTEGER NOT NULL,
    attempts     INTEGER NOT NULL,
    block_reason TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (principal, hour, program, remote_ip, host, route, verdict, blocked_by)
) WITHOUT ROWID";

/// The size cap removes the oldest hours of the whole machine first; this is
/// the oldest-hour scan.
const CREATE_IDX_CONN_HISTORY_HOUR: &str =
    "CREATE INDEX IF NOT EXISTS idx_conn_history_hour ON conn_history(hour)";

/// Rows of each user removed to keep the file under its size cap: the "older
/// entries were removed" figure the reader shows. Expiry by age is the period
/// the user chose and is not counted.
const CREATE_CONN_HISTORY_REMOVED: &str = "
CREATE TABLE IF NOT EXISTS conn_history_removed (
    principal TEXT    PRIMARY KEY,
    rows      INTEGER NOT NULL
) WITHOUT ROWID";

/// Ordered DDL for `nrr_conn_history.db` v1. Rebuildable: a damaged file is
/// deleted and created again, losing only history.
pub const CONN_HISTORY_DB_V1_DDL: &[&str] = &[
    CREATE_CONN_HISTORY,
    CREATE_IDX_CONN_HISTORY_HOUR,
    CREATE_CONN_HISTORY_REMOVED,
];
