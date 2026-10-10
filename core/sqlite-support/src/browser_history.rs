//! The SQLite half of reading a browser's history, shared by the per-OS
//! readers. Finding, verifying and copying the database stay with the OS;
//! this reads the private copy and projects its URL column into hostnames.
//!
//! The file is the user's: defensive mode on, schema untrusted, the source a
//! real table, and every read bounded by [`READ_BUDGET`] and a row cap.

use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags};

/// What is read from one browser family's database. The file is the user's,
/// so `table` must be a real table: a view of that name could run anything.
#[derive(Clone, Copy, Debug)]
pub struct HistoryQuery {
    table: &'static str,
    sql: &'static str,
}

pub const CHROMIUM_QUERY: HistoryQuery = HistoryQuery {
    table: "urls",
    sql: "SELECT url FROM urls",
};
pub const FIREFOX_QUERY: HistoryQuery = HistoryQuery {
    table: "moz_places",
    sql: "SELECT url FROM moz_places WHERE url IS NOT NULL",
};

/// Longest one database may keep the caller's thread busy; past it the read
/// stops with what it has.
pub const READ_BUDGET: Duration = Duration::from_secs(5);

/// Largest History database copied; a bigger one is skipped rather than
/// letting a user-supplied file fill the service's disk.
pub const MAX_HISTORY_BYTES: u64 = 1024 * 1024 * 1024;

/// Upper bound on URL rows read from one source.
const MAX_HISTORY_ROWS: usize = 2_000_000;

/// SQLite's side files, in the order a copy creates them. The WAL holds every
/// commit since the last checkpoint and a hot rollback journal the undo of an
/// interrupted one, so both are copied; the `-shm` index is not, because
/// SQLite rebuilds it from the WAL, and is only ever removed.
pub const SIDE_FILES: [&str; 3] = ["-wal", "-journal", "-shm"];
pub const COPIED_SIDE_FILES: [&str; 2] = ["-wal", "-journal"];

/// One stored URL to its hostname, `None` when it carries none. Supplied by
/// the caller, so this leaf holds no URL policy of its own.
pub type HostOf = fn(&str) -> Option<String>;

/// Distinct hostnames read from one database, sorted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoryHosts {
    pub hosts: Vec<String>,
    /// The read hit [`READ_BUDGET`]; `hosts` is what it had by then.
    pub cut_short: bool,
}

/// Reads a private `copy`, replaying the WAL and hot journal beside it. A WAL
/// copied across a checkpoint may not fit the main file; the checkpointed
/// history alone is then still worth having.
pub fn read_history_copy(
    copy: &Path,
    query: HistoryQuery,
    host_of: HostOf,
) -> Result<HistoryHosts, String> {
    read_hostnames_replaying_journals(copy, query, host_of).or_else(|replay_error| {
        read_hostnames_from_db(copy, query, host_of).map_err(|_| replay_error)
    })
}

/// Opens `db` READ-ONLY as it stands. `immutable=1` ignores the side files,
/// so only checkpointed history is seen.
pub fn read_hostnames_from_db(
    db: &Path,
    query: HistoryQuery,
    host_of: HostOf,
) -> Result<HistoryHosts, String> {
    let conn = Connection::open_with_flags(
        db_uri(db, "?mode=ro&immutable=1"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| format!("open: {e}"))?;
    hostnames_within(&conn, query, READ_BUDGET, host_of)
}

/// SQLite first replays the WAL and rolls back a hot journal found beside
/// `copy`. Both write, so `copy` must be a private copy, never a browser's
/// live file.
fn read_hostnames_replaying_journals(
    copy: &Path,
    query: HistoryQuery,
    host_of: HostOf,
) -> Result<HistoryHosts, String> {
    let conn = Connection::open_with_flags(
        db_uri(copy, ""),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| format!("open: {e}"))?;
    // The copy is about to be deleted; folding the WAL into it is wasted I/O.
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
        .map_err(|e| format!("harden: {e}"))?;
    conn.execute_batch("PRAGMA query_only = ON;")
        .map_err(|e| format!("harden: {e}"))?;
    hostnames_within(&conn, query, READ_BUDGET, host_of)
}

/// `%`, `?` and `#` are URI syntax: left raw, a profile path holding one would
/// name another file or none.
fn db_uri(db: &Path, params: &str) -> String {
    let path = db
        .to_string_lossy()
        .replace('%', "%25")
        .replace('?', "%3f")
        .replace('#', "%23");
    format!("file:{path}{params}")
}

fn hostnames_within(
    conn: &Connection,
    query: HistoryQuery,
    budget: Duration,
    host_of: HostOf,
) -> Result<HistoryHosts, String> {
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|e| format!("harden: {e}"))?;
    conn.execute_batch("PRAGMA trusted_schema = OFF; PRAGMA cell_size_check = ON;")
        .map_err(|e| format!("harden: {e}"))?;
    // Interrupts any statement past the deadline, the schema parse included.
    let deadline = Instant::now() + budget;
    conn.progress_handler(10_000, Some(move || Instant::now() >= deadline));
    require_plain_table(conn, query.table)?;
    let mut stmt = conn
        .prepare(query.sql)
        .map_err(|e| format!("prepare: {e}"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| format!("query: {e}"))?;
    let mut hosts: Vec<String> = rows
        .take(MAX_HISTORY_ROWS)
        .flatten()
        .filter_map(|url| host_of(&url))
        .collect();
    let cut_short = Instant::now() >= deadline;
    hosts.sort_unstable();
    hosts.dedup();
    Ok(HistoryHosts { hosts, cut_short })
}

/// `name` must be an ordinary table whose `url` is a stored column: a view,
/// a virtual table or a generated column would run the file's own SQL.
fn require_plain_table(conn: &Connection, name: &str) -> Result<(), String> {
    let mut stmt = conn
        .prepare("SELECT type, rootpage FROM main.sqlite_master WHERE name = ?1 COLLATE NOCASE")
        .map_err(|e| format!("schema: {e}"))?;
    let entries: Vec<(String, i64)> = stmt
        .query_map([name], |row| Ok((row.get(0)?, row.get(1)?)))
        .and_then(|rows| rows.collect::<Result<Vec<_>, _>>())
        .map_err(|e| format!("schema: {e}"))?;
    if !matches!(entries.as_slice(), [(kind, root)] if kind == "table" && *root > 0) {
        return Err(format!("`{name}` is not a plain table"));
    }
    let stored: bool = conn
        .query_row(
            "SELECT count(*) = 1 FROM pragma_table_xinfo(?1) \
             WHERE name = 'url' COLLATE NOCASE AND hidden = 0",
            [name],
            |row| row.get(0),
        )
        .map_err(|e| format!("schema: {e}"))?;
    if !stored {
        return Err(format!("`{name}.url` is not a stored column"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for the platform's URL parser: `http(s)://host[:port]/…` only.
    fn host_of(url: &str) -> Option<String> {
        let (scheme, rest) = url.split_once("://")?;
        if !matches!(scheme, "http" | "https") {
            return None;
        }
        rest.split(['/', ':'])
            .next()
            .filter(|host| !host.is_empty())
            .map(str::to_ascii_lowercase)
    }

    fn make_db(path: &Path, ddl: &str, urls: &[&str]) {
        let conn = Connection::open(path).expect("create db");
        conn.execute_batch(ddl).expect("schema");
        for url in urls {
            conn.execute("INSERT INTO urls (url) VALUES (?1)", [url])
                .expect("insert");
        }
    }

    const URLS_TABLE: &str = "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT)";

    #[test]
    fn reads_and_dedupes_hostnames_from_chromium_urls_table() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("History");
        make_db(
            &db,
            URLS_TABLE,
            &[
                "https://feed.example/feed",
                "https://feed.example/other", // same host, deduped
                "https://search.example/",
                "about:blank",       // no host, dropped
                "chrome://settings", // pseudo-scheme, dropped
            ],
        );
        let read = read_hostnames_from_db(&db, CHROMIUM_QUERY, host_of).expect("read");
        assert_eq!(read.hosts, ["feed.example", "search.example"]);
        assert!(!read.cut_short);
    }

    #[test]
    fn missing_db_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("nope.sqlite");
        assert!(read_hostnames_from_db(&missing, CHROMIUM_QUERY, host_of).is_err());
        assert!(read_history_copy(&missing, CHROMIUM_QUERY, host_of).is_err());
    }

    #[test]
    fn db_uri_escapes_percent_question_mark_and_hash() {
        assert_eq!(
            db_uri(Path::new("/home/a/50% off#1?/a%3fb/History"), "?mode=ro"),
            "file:/home/a/50%25 off%231%3f/a%253fb/History?mode=ro"
        );
        assert_eq!(
            db_uri(Path::new("/home/a/History"), ""),
            "file:/home/a/History"
        );
    }

    /// Positive end of the escape: such a path opens the file it names.
    #[test]
    fn a_profile_path_with_percent_or_hash_is_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let profile = dir.path().join("50%25 off #1");
        std::fs::create_dir_all(&profile).expect("mkdir");
        let db = profile.join("History");
        make_db(&db, URLS_TABLE, &["https://odd-path.example/"]);
        assert_eq!(
            read_hostnames_from_db(&db, CHROMIUM_QUERY, host_of)
                .expect("read-only open")
                .hosts,
            ["odd-path.example"]
        );
        assert_eq!(
            read_history_copy(&db, CHROMIUM_QUERY, host_of)
                .expect("replaying open")
                .hosts,
            ["odd-path.example"]
        );
    }

    /// A user-planted view named like the table would spin the reader forever;
    /// it is refused before it runs. Same for a generated `url`.
    #[test]
    fn a_view_or_generated_column_in_place_of_the_table_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let view = dir.path().join("view.sqlite");
        make_db(
            &view,
            "CREATE VIEW URLS AS WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) \
             SELECT 'http://a.example/' AS url FROM c WHERE x < 0;",
            &[],
        );
        let started = Instant::now();
        assert!(read_hostnames_replaying_journals(&view, CHROMIUM_QUERY, host_of).is_err());
        assert!(read_hostnames_from_db(&view, CHROMIUM_QUERY, host_of).is_err());
        assert!(started.elapsed() < READ_BUDGET);

        let generated = dir.path().join("generated.sqlite");
        let conn = Connection::open(&generated).expect("create db");
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, raw TEXT, \
             url TEXT GENERATED ALWAYS AS ('http://' || raw || '/'));
             INSERT INTO urls (raw) VALUES ('gen.example');",
        )
        .expect("generated column");
        drop(conn);
        assert!(read_hostnames_from_db(&generated, CHROMIUM_QUERY, host_of).is_err());

        // Positive control: the plain table is read.
        let plain = dir.path().join("plain.sqlite");
        make_db(&plain, URLS_TABLE, &["https://plain.example/"]);
        assert_eq!(
            read_hostnames_from_db(&plain, CHROMIUM_QUERY, host_of)
                .expect("plain")
                .hosts,
            ["plain.example"]
        );
    }

    /// The read stops at its budget instead of running as long as the file
    /// makes it.
    #[test]
    fn a_read_stops_at_its_budget() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("big.sqlite");
        let conn = Connection::open(&db).expect("create");
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
             WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x < 50000)
             INSERT INTO urls (url) SELECT 'https://h' || x || '.example/' FROM c;",
        )
        .expect("fill");
        drop(conn);
        let open = || Connection::open(&db).expect("open");

        let all = hostnames_within(&open(), CHROMIUM_QUERY, Duration::from_secs(60), host_of)
            .expect("unbounded read");
        assert_eq!(all.hosts.len(), 50_000, "positive control: the whole table");
        assert!(!all.cut_short);

        let cut = hostnames_within(&open(), CHROMIUM_QUERY, Duration::ZERO, host_of);
        assert!(
            !matches!(&cut, Ok(read) if read.hosts.len() == 50_000),
            "a spent budget did not stop the read"
        );
    }
}
