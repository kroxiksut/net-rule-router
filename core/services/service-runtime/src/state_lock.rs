//! The one way to take the shared state-database connection.

use std::sync::{Mutex, MutexGuard};

use rusqlite::Connection;

/// Locks the state connection, forgiving a panic that poisoned it.
///
/// SQLite is consistent at every statement boundary and a `Transaction`
/// dropped during unwinding rolls back, so a poisoned guard holds a usable
/// connection. Refusing it instead froze rule changes until a restart that
/// nothing triggers. A transaction a panic left open by hand is rolled back
/// here, so the next writer does not commit half of it.
pub(crate) fn lock_state(conn: &Mutex<Connection>) -> MutexGuard<'_, Connection> {
    conn.lock().unwrap_or_else(|poisoned| {
        conn.clear_poison();
        let guard = poisoned.into_inner();
        if !guard.is_autocommit() {
            if let Err(e) = guard.execute_batch("ROLLBACK") {
                tracing::warn!(
                    target: "nrr::state",
                    error = %e,
                    "could not roll back the transaction a panic left open",
                );
            }
        }
        tracing::warn!(
            target: "nrr::state",
            "state connection recovered after a panic under its lock",
        );
        guard
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poison_mid_transaction(conn: &Mutex<Connection>) {
        let poisoned = std::thread::scope(|s| {
            s.spawn(|| {
                let guard = conn.lock().expect("unpoisoned yet");
                guard
                    .execute_batch("BEGIN; INSERT INTO t(v) VALUES ('half');")
                    .expect("half-done write");
                panic!("simulated panic under the state lock");
            })
            .join()
        });
        assert!(poisoned.is_err(), "the lock must be poisoned for the test");
    }

    #[test]
    fn a_panic_under_the_state_lock_neither_blocks_later_writes_nor_commits_its_half() {
        let conn = Connection::open_in_memory().expect("open");
        conn.execute_batch("CREATE TABLE t(v TEXT);")
            .expect("schema");
        let conn = Mutex::new(conn);
        poison_mid_transaction(&conn);

        {
            let guard = lock_state(&conn);
            guard
                .execute("INSERT INTO t(v) VALUES ('next')", [])
                .expect("a later write goes through");
        }
        // Readers that map a poisoned lock to "unreadable" see it healed too.
        let guard = conn.lock().expect("poison cleared");
        let rows: Vec<String> = guard
            .prepare("SELECT v FROM t ORDER BY rowid")
            .and_then(|mut s| {
                s.query_map([], |r| r.get(0))
                    .and_then(|rows| rows.collect::<Result<_, _>>())
            })
            .expect("read back");
        assert_eq!(rows, vec!["next".to_string()], "half-done write committed");
    }
}
