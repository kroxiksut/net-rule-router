//! A cheap "has this database been written since I last looked" number.

use rusqlite::Connection;

/// Combines `PRAGMA data_version`, which moves on commits from OTHER
/// connections, with `total_changes`, which counts this connection's own. Either
/// alone misses half the writers. `None` when the pragma cannot be read.
#[must_use]
pub fn of(conn: &Connection) -> Option<u64> {
    Some((outside_writes(conn)? << 32) ^ conn.total_changes())
}

/// The half of [`of`] that moves only on commits from other connections — for a
/// store that counts its own writes by what they mean rather than by rows.
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
    fn own_and_outside_writes_both_move_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("g.db");
        let mine = Connection::open(&path).expect("open");
        mine.execute_batch("PRAGMA journal_mode = WAL; CREATE TABLE t (x INTEGER);")
            .expect("schema");
        let other = Connection::open(&path).expect("open other");

        let start = of(&mine).expect("generation");
        assert_eq!(of(&mine), Some(start), "a read moved it");

        mine.execute("INSERT INTO t VALUES (1)", [])
            .expect("own write");
        let after_own = of(&mine).expect("generation");
        assert_ne!(after_own, start, "this connection's write did not move it");

        other
            .execute("INSERT INTO t VALUES (2)", [])
            .expect("outside write");
        assert_ne!(
            of(&mine),
            Some(after_own),
            "another connection's write did not move it"
        );
    }
}
