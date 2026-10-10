#![forbid(unsafe_code)]
//! SQLite plumbing both local databases share: connection setup and the
//! migration runner; plus the read of a browser's history copy, which both
//! platform readers share ([`browser_history`]).
//!
//! One copy on purpose. While the service store and the GUI sidecar each had
//! their own, every fix to the runner — the history gap below the maximum, the
//! bookkeeping row that must never be rewritten — had to be found and made
//! twice. The on-disk format (the `schema_migrations` table and its FNV-1a
//! checksums) is unchanged, so databases written by either copy open here.

use std::fmt;
use std::time::{Duration, Instant, SystemTime};

use rusqlite::{params, Connection, ErrorCode, OptionalExtension, TransactionBehavior};

pub mod browser_history;

/// Milliseconds since the Unix epoch; zero for a clock set before it. The
/// value is a timestamp column, never a deadline.
pub fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

// ── Connection setup ─────────────────────────────────────────────────────────

/// Why a connection could not be given the baseline both databases require.
#[derive(Debug)]
pub enum ConnectionError {
    Sqlite(rusqlite::Error),
    /// The filesystem refused WAL (a network share, typically).
    WalUnsupported {
        journal_mode: String,
    },
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "sqlite error: {e}"),
            Self::WalUnsupported { journal_mode } => {
                write!(
                    f,
                    "WAL mode not supported (journal_mode = {journal_mode:?})"
                )
            }
        }
    }
}

impl std::error::Error for ConnectionError {}

impl From<rusqlite::Error> for ConnectionError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

/// Busy timeout, WAL (verified, not assumed) and foreign keys.
///
/// The timeout goes first so every later statement waits for another
/// connection's lock instead of failing on it.
pub fn configure_connection(
    conn: &Connection,
    busy_timeout: Duration,
) -> Result<(), ConnectionError> {
    conn.busy_timeout(busy_timeout)?;
    let journal_mode = enable_wal(conn, busy_timeout)?;
    if journal_mode != "wal" {
        return Err(ConnectionError::WalUnsupported { journal_mode });
    }
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    Ok(())
}

/// Converting a fresh file to WAL needs an exclusive lock, and SQLite answers
/// `SQLITE_BUSY` there without consulting the busy handler: two processes
/// opening a new database in the same instant made the loser fail outright.
fn enable_wal(conn: &Connection, budget: Duration) -> rusqlite::Result<String> {
    let deadline = Instant::now() + budget;
    loop {
        match conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0)) {
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == ErrorCode::DatabaseBusy && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            other => return other,
        }
    }
}

// ── Migrations ───────────────────────────────────────────────────────────────

/// One versioned step: statements applied in order, recorded with a checksum
/// over exactly this slice. Never edit a step that has shipped; append one.
#[derive(Clone, Copy, Debug)]
pub struct Migration {
    pub version: u32,
    pub name: &'static str,
    pub stmts: &'static [&'static str],
}

/// What [`migrate`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationOutcome {
    pub from_version: u32,
    pub to_version: u32,
    pub applied: Vec<&'static str>,
}

#[derive(Debug)]
pub enum MigrationError {
    Sqlite(rusqlite::Error),
    /// Written by a newer build; downgrading is refused.
    SchemaTooNew {
        found: u32,
        supported: u32,
    },
    /// `MAX(version)` is not a version at all.
    ImpossibleVersion(i64),
    /// A step below the recorded maximum never ran: nothing would ever apply
    /// it, because only steps above the maximum are pending.
    MissingFromHistory {
        version: u32,
        name: &'static str,
        applied_up_to: u32,
    },
    /// The SQL of an applied step changed, or its row was edited.
    ChecksumMismatch {
        version: u32,
        name: &'static str,
        stored: String,
        computed: String,
    },
    /// A step's own SQL failed; the whole run was rolled back.
    StepFailed {
        version: u32,
        name: &'static str,
        source: rusqlite::Error,
    },
}

impl MigrationError {
    /// The step the error is about, when it is about one.
    pub fn step_version(&self) -> Option<u32> {
        match self {
            Self::MissingFromHistory { version, .. }
            | Self::ChecksumMismatch { version, .. }
            | Self::StepFailed { version, .. } => Some(*version),
            Self::Sqlite(_) | Self::SchemaTooNew { .. } | Self::ImpossibleVersion(_) => None,
        }
    }
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "sqlite error: {e}"),
            Self::SchemaTooNew { found, supported } => {
                write!(
                    f,
                    "schema version {found} is newer than supported {supported}"
                )
            }
            Self::ImpossibleVersion(v) => {
                write!(f, "schema_migrations holds an impossible version {v}")
            }
            Self::MissingFromHistory {
                version,
                name,
                applied_up_to,
            } => write!(
                f,
                "migration '{name}' (v{version}) is missing from the applied history \
                 while v{applied_up_to} is recorded as applied — the upgrade was \
                 interrupted and the schema is incomplete"
            ),
            Self::ChecksumMismatch {
                version,
                name,
                stored,
                computed,
            } => write!(
                f,
                "checksum mismatch for migration '{name}' (v{version}): \
                 stored={stored}, computed={computed} — migration SQL may have \
                 changed after it was applied"
            ),
            Self::StepFailed {
                version,
                name,
                source,
            } => write!(f, "migration '{name}' (v{version}) failed: {source}"),
        }
    }
}

impl std::error::Error for MigrationError {}

impl From<rusqlite::Error> for MigrationError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

const CREATE_SCHEMA_MIGRATIONS: &str = "
CREATE TABLE IF NOT EXISTS schema_migrations (
    version      INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL,
    applied_at   INTEGER NOT NULL,
    checksum     TEXT    NOT NULL,
    app_version  TEXT    NOT NULL
)";

/// Idempotent; [`migrate`] calls it itself.
pub fn ensure_migrations_table(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(CREATE_SCHEMA_MIGRATIONS)
}

/// The recorded schema version. The `schema_migrations` table must exist.
pub fn schema_version(conn: &Connection) -> Result<u32, MigrationError> {
    let max: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |r| r.get(0),
    )?;
    // Never "fresh database": that re-ran the first step and surfaced SQLite's
    // `table already exists` instead of an answer about the schema.
    u32::try_from(max).map_err(|_| MigrationError::ImpossibleVersion(max))
}

/// Brings `conn` to the newest step in `migrations` (sorted by version).
///
/// Everything — the version read, the history check and every pending step
/// with its bookkeeping row — runs in ONE immediate transaction. A second
/// process opening the same file waits on the write lock and then sees the
/// version the first committed; a version read outside the lock let both see
/// the same one and the loser re-ran the DDL. A failing step rolls back the
/// whole run.
pub fn migrate(
    conn: &mut Connection,
    migrations: &[Migration],
) -> Result<MigrationOutcome, MigrationError> {
    debug_assert!(migrations.windows(2).all(|w| w[0].version < w[1].version));
    let supported = migrations.last().map_or(0, |m| m.version);

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure_migrations_table(&tx)?;
    let from_version = schema_version(&tx)?;

    // Before the history is judged: a newer build's steps are unknown here, and
    // "you are running an older binary" is the diagnosis the caller can act on.
    if from_version > supported {
        return Err(MigrationError::SchemaTooNew {
            found: from_version,
            supported,
        });
    }
    validate_history(&tx, migrations, from_version)?;

    let mut applied = Vec::new();
    for step in migrations.iter().filter(|m| m.version > from_version) {
        apply(&tx, step)?;
        applied.push(step.name);
    }
    tx.commit()?;

    Ok(MigrationOutcome {
        from_version,
        to_version: supported.max(from_version),
        applied,
    })
}

fn validate_history(
    conn: &Connection,
    migrations: &[Migration],
    applied_up_to: u32,
) -> Result<(), MigrationError> {
    for step in migrations.iter().filter(|m| m.version <= applied_up_to) {
        let stored: Option<String> = conn
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = ?1",
                params![i64::from(step.version)],
                |r| r.get(0),
            )
            .optional()?;
        let Some(stored) = stored else {
            return Err(MigrationError::MissingFromHistory {
                version: step.version,
                name: step.name,
                applied_up_to,
            });
        };
        let computed = checksum(step.stmts);
        if stored != computed {
            return Err(MigrationError::ChecksumMismatch {
                version: step.version,
                name: step.name,
                stored,
                computed,
            });
        }
    }
    Ok(())
}

fn apply(conn: &Connection, step: &Migration) -> Result<(), MigrationError> {
    let failed = |source| MigrationError::StepFailed {
        version: step.version,
        name: step.name,
        source,
    };
    for stmt in step.stmts {
        conn.execute_batch(stmt).map_err(failed)?;
    }
    // IGNORE, not REPLACE: REPLACE rewrote the stored checksum of an applied
    // step — the guard defeated by the code it guards.
    conn.execute(
        "INSERT OR IGNORE INTO schema_migrations
            (version, name, applied_at, checksum, app_version)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            i64::from(step.version),
            step.name,
            unix_now_ms(),
            checksum(step.stmts),
            env!("CARGO_PKG_VERSION"),
        ],
    )
    .map_err(failed)?;
    Ok(())
}

/// FNV-1a 64-bit over the statements, each followed by a NUL. Stored per step;
/// changing this function would fail every existing database on open.
pub fn checksum(stmts: &[&str]) -> String {
    const OFFSET: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;
    let mut h = OFFSET;
    for stmt in stmts {
        for b in stmt.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(PRIME);
        }
        h ^= 0x00;
        h = h.wrapping_mul(PRIME);
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests;
