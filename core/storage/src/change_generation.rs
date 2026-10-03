//! A cheap "has another connection written this database" number.

use rusqlite::Connection;

/// `PRAGMA data_version`: moves only on commits from other connections — for a
/// store that counts its own writes by what they mean rather than by rows.
/// `None` when the pragma cannot be read.
#[must_use]
pub fn outside_writes(conn: &Connection) -> Option<u64> {
    let others: i64 = conn
        .query_row("PRAGMA data_version", [], |r| r.get(0))
        .ok()?;
    Some(others as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_another_connections_write_moves_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("g.db");
        let mine = Connection::open(&path).expect("open");
        mine.execute_batch("PRAGMA journal_mode = WAL; CREATE TABLE t (x INTEGER);")
            .expect("schema");
        let other = Connection::open(&path).expect("open other");

        let start = outside_writes(&mine).expect("generation");
        mine.execute("INSERT INTO t VALUES (1)", [])
            .expect("own write");
        assert_eq!(outside_writes(&mine), Some(start), "an own write moved it");

        other
            .execute("INSERT INTO t VALUES (2)", [])
            .expect("outside write");
        assert_ne!(
            outside_writes(&mine),
            Some(start),
            "another connection's write did not move it"
        );
    }
}
