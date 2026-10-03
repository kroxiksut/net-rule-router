//! Which tables this process has written, per database file.
//!
//! `PRAGMA data_version` and `total_changes` say only THAT a database moved,
//! and a service writes its journals far more often than anything an
//! enforcement pass reads. Every connection opened through
//! [`crate::migration::open_connection`] reports its row changes here, so a
//! reader can ask about the tables it cares about. A rolled-back change is
//! still counted: the error is an extra pass, never a missed one.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use rusqlite::Connection;

/// Row changes per table, per database path.
type Counts = HashMap<Arc<str>, HashMap<String, u64>>;

fn ledger() -> &'static Mutex<Counts> {
    static LEDGER: OnceLock<Mutex<Counts>> = OnceLock::new();
    LEDGER.get_or_init(|| Mutex::new(HashMap::new()))
}

fn key(path: &Path) -> Arc<str> {
    Arc::from(path.to_string_lossy().as_ref())
}

/// Count every row `conn` changes against the database at `path`.
pub fn watch(conn: &Connection, path: &Path) {
    let db = key(path);
    conn.update_hook(Some(
        move |_: rusqlite::hooks::Action, _: &str, table: &str, _: i64| {
            let mut counts = ledger().lock().unwrap_or_else(|p| p.into_inner());
            let tables = counts.entry(Arc::clone(&db)).or_default();
            match tables.get_mut(table) {
                Some(n) => *n += 1,
                None => {
                    tables.insert(table.to_owned(), 1);
                }
            }
        },
    ));
}

/// Row changes so far per table of the database at `path`.
#[must_use]
pub fn snapshot(path: &Path) -> HashMap<String, u64> {
    let counts = ledger().lock().unwrap_or_else(|p| p.into_inner());
    counts.get(&key(path)).cloned().unwrap_or_default()
}

/// The sum of row changes so far in every table of `path` except `ignored`.
#[must_use]
pub fn changes_outside(path: &Path, ignored: &[&str]) -> u64 {
    let counts = ledger().lock().unwrap_or_else(|p| p.into_inner());
    counts.get(&key(path)).map_or(0, |tables| {
        tables
            .iter()
            .filter(|(table, _)| !ignored.contains(&table.as_str()))
            .map(|(_, n)| *n)
            .sum()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_watched_connection_is_counted_and_ignored_tables_are_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("w.db");
        let first = Connection::open(&path).expect("open");
        first
            .execute_batch(
                "PRAGMA journal_mode = WAL; \
                 CREATE TABLE plan (x INTEGER); CREATE TABLE journal (x INTEGER);",
            )
            .expect("schema");
        let second = Connection::open(&path).expect("open second");
        watch(&first, &path);
        watch(&second, &path);

        let start = changes_outside(&path, &["journal"]);
        second
            .execute("INSERT INTO journal VALUES (1)", [])
            .expect("journal write");
        assert_eq!(
            changes_outside(&path, &["journal"]),
            start,
            "an ignored table moved it"
        );

        second
            .execute("INSERT INTO plan VALUES (1)", [])
            .expect("plan write");
        first.execute("UPDATE plan SET x = 2", []).expect("update");
        assert_eq!(changes_outside(&path, &["journal"]), start + 2);
        assert_eq!(snapshot(&path).get("journal"), Some(&1));
    }
}
