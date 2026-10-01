use super::*;

const V1: Migration = Migration {
    version: 1,
    name: "first",
    stmts: &["CREATE TABLE a (id INTEGER PRIMARY KEY)"],
};
const V2: Migration = Migration {
    version: 2,
    name: "second",
    stmts: &[
        "CREATE TABLE b (id INTEGER PRIMARY KEY)",
        "CREATE INDEX idx_b ON b(id)",
    ],
};
const BOTH: &[Migration] = &[V1, V2];

fn open() -> Connection {
    let conn = Connection::open_in_memory().expect("open");
    conn.busy_timeout(Duration::from_millis(1_000))
        .expect("busy timeout");
    conn
}

fn table_exists(conn: &Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        params![name],
        |r| r.get::<_, i64>(0),
    )
    .expect("sqlite_master")
        > 0
}

#[test]
fn a_fresh_database_runs_every_step() {
    let mut conn = open();
    let outcome = migrate(&mut conn, BOTH).expect("migrate");
    assert_eq!(
        outcome,
        MigrationOutcome {
            from_version: 0,
            to_version: 2,
            applied: vec!["first", "second"],
        }
    );
    assert!(table_exists(&conn, "a") && table_exists(&conn, "b"));
    assert_eq!(schema_version(&conn).expect("version"), 2);
}

#[test]
fn a_second_run_is_a_no_op() {
    let mut conn = open();
    migrate(&mut conn, BOTH).expect("first");
    let again = migrate(&mut conn, BOTH).expect("second");
    assert_eq!(again.from_version, 2);
    assert_eq!(again.to_version, 2);
    assert!(again.applied.is_empty());
}

#[test]
fn an_older_database_gets_only_the_missing_steps() {
    let mut conn = open();
    migrate(&mut conn, &[V1]).expect("v1");
    let outcome = migrate(&mut conn, BOTH).expect("upgrade");
    assert_eq!(outcome.from_version, 1);
    assert_eq!(outcome.applied, vec!["second"]);
}

#[test]
fn a_failing_step_rolls_back_the_whole_run() {
    const BAD: Migration = Migration {
        version: 2,
        name: "bad",
        stmts: &["CREATE TABLE c (id INTEGER)", "THIS IS NOT SQL"],
    };
    let mut conn = open();
    let err = migrate(&mut conn, &[V1, BAD]).expect_err("bad step");
    assert!(matches!(err, MigrationError::StepFailed { version: 2, .. }));
    assert!(!table_exists(&conn, "a"), "the good step went back too");
    assert!(!table_exists(&conn, "c"));
    ensure_migrations_table(&conn).expect("table");
    assert_eq!(schema_version(&conn).expect("version"), 0);
}

#[test]
fn an_edited_checksum_is_fatal_and_never_healed() {
    let mut conn = open();
    migrate(&mut conn, BOTH).expect("migrate");
    conn.execute(
        "UPDATE schema_migrations SET checksum = 'deadbeef' WHERE version = 1",
        [],
    )
    .expect("tamper");
    let err = migrate(&mut conn, BOTH).expect_err("mismatch");
    assert!(matches!(
        err,
        MigrationError::ChecksumMismatch { version: 1, .. }
    ));
    assert!(err.to_string().contains("checksum mismatch"));
    let stored: String = conn
        .query_row(
            "SELECT checksum FROM schema_migrations WHERE version = 1",
            [],
            |r| r.get(0),
        )
        .expect("stored");
    assert_eq!(stored, "deadbeef");
}

#[test]
fn a_gap_below_the_maximum_is_rejected() {
    let mut conn = open();
    migrate(&mut conn, BOTH).expect("migrate");
    conn.execute("DELETE FROM schema_migrations WHERE version = 1", [])
        .expect("drop row");
    let err = migrate(&mut conn, BOTH).expect_err("gap");
    assert!(matches!(
        err,
        MigrationError::MissingFromHistory {
            version: 1,
            applied_up_to: 2,
            ..
        }
    ));
    assert!(err.to_string().contains("missing from the applied history"));
}

#[test]
fn a_newer_database_is_refused() {
    let mut conn = open();
    migrate(&mut conn, BOTH).expect("migrate");
    let err = migrate(&mut conn, &[V1]).expect_err("too new");
    assert!(matches!(
        err,
        MigrationError::SchemaTooNew {
            found: 2,
            supported: 1
        }
    ));
}

#[test]
fn an_impossible_version_is_reported_not_treated_as_empty() {
    let mut conn = open();
    migrate(&mut conn, BOTH).expect("migrate");
    conn.execute_batch(
        "DELETE FROM schema_migrations;
         INSERT INTO schema_migrations (version, name, applied_at, checksum, app_version)
         VALUES (-7, 'impossible', 0, 'x', '0');",
    )
    .expect("impossible row");
    assert!(matches!(
        migrate(&mut conn, BOTH),
        Err(MigrationError::ImpossibleVersion(-7))
    ));
}

/// The checksum is stored in every database ever migrated; this pins it.
#[test]
fn the_checksum_function_is_pinned() {
    assert_eq!(checksum(&[]), "cbf29ce484222325");
    assert_eq!(checksum(&["SELECT 1"]), checksum(&["SELECT 1"]));
    assert_ne!(checksum(&["AAA", "BBB"]), checksum(&["BBB", "AAA"]));
    assert_ne!(checksum(&["AB"]), checksum(&["A", "B"]));
    assert_eq!(checksum(&["SELECT 1"]).len(), 16);
}

#[test]
fn a_file_connection_gets_the_baseline_pragmas() {
    let dir = tempfile::tempdir().expect("tmp");
    let conn = Connection::open(dir.path().join("t.db")).expect("open");
    configure_connection(&conn, Duration::from_millis(5_000)).expect("configure");
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .expect("mode");
    let busy: i64 = conn
        .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
        .expect("busy");
    let fk: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .expect("fk");
    assert_eq!((mode.as_str(), busy, fk), ("wal", 5_000, 1));
}

/// An in-memory database cannot do WAL: the refusal is typed, not swallowed.
#[test]
fn a_database_that_refuses_wal_is_reported() {
    let conn = Connection::open_in_memory().expect("open");
    assert!(matches!(
        configure_connection(&conn, Duration::from_millis(100)),
        Err(ConnectionError::WalUnsupported { .. })
    ));
}

#[test]
fn now_is_after_the_epoch() {
    assert!(unix_now_ms() > 1_600_000_000_000);
}
