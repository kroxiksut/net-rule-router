//! A service state database an earlier build left upgrades with every row the
//! user had: a table rebuilt by a later migration must carry each row and each
//! column over. Every release adds a sample of its own schema under
//! `tests/fixtures/`.

use std::cell::RefCell;
use std::collections::BTreeMap;

use rusqlite::types::Value;
use rusqlite::Connection;

use super::*;
use crate::repository::MigrationRunner;

/// `(file, schema version, rows)`.
const RELEASED_SAMPLES: &[(&str, u32, &str)] = &[
    (
        "state_db_v76.sql",
        76,
        include_str!("../../tests/fixtures/state_db_v76.sql"),
    ),
    (
        "state_db_v84.sql",
        84,
        include_str!("../../tests/fixtures/state_db_v84.sql"),
    ),
];

/// Columns a migration removed on purpose, with the version that removed them.
/// A sample older than that loses exactly these; any other lost column is a
/// defect.
const RETIRED_COLUMNS: &[(&str, &str, u32)] = &[
    (
        "secondary_block_policy",
        "block_secondary_when_unavailable",
        79,
    ),
    ("secondary_block_policy", "kill_switch_enabled", 80),
    ("secondary_block_policy", "kill_switch_fail_closed", 80),
    ("secondary_block_policy", "kill_switch_block_all", 80),
    ("secondary_block_policy", "mode_a_coverage_strategy", 80),
    ("secondary_block_policy", "block_ipv6_when_protected", 80),
];

/// Values a migration sets on purpose, as `(table, column, version)`: a sample
/// older than that version may hold anything there afterwards.
const REWRITTEN_COLUMNS: &[(&str, &str, u32)] = &[(
    "secondary_block_policy",
    "kill_switch_strict_shared_ips",
    84,
)];

/// Tables a migration removed on purpose, with that version.
const RETIRED_TABLES: &[(&str, u32)] = &[];

fn retired(list: &[(&str, &str, u32)], table: &str, column: &str, sample: u32) -> bool {
    list.iter()
        .any(|(t, c, since)| *t == table && *c == column && sample < *since)
}

struct Table {
    columns: Vec<String>,
    rows: Vec<Vec<Value>>,
}

/// Every user table and its rows; the migration ledger is the runner's own.
fn contents(conn: &Connection) -> BTreeMap<String, Table> {
    let mut names = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite_%' AND name != 'schema_migrations'",
        )
        .expect("list tables");
    let names: Vec<String> = names
        .query_map([], |r| r.get(0))
        .expect("query tables")
        .collect::<Result<_, _>>()
        .expect("read tables");
    names
        .into_iter()
        .map(|name| {
            let mut select = conn
                .prepare(&format!("SELECT * FROM \"{name}\""))
                .expect("select");
            let columns: Vec<String> = select
                .column_names()
                .into_iter()
                .map(str::to_owned)
                .collect();
            let width = columns.len();
            let rows = select
                .query_map([], |row| {
                    (0..width).map(|i| row.get::<_, Value>(i)).collect()
                })
                .expect("query rows")
                .collect::<Result<Vec<Vec<Value>>, _>>()
                .expect("read rows");
            (name, Table { columns, rows })
        })
        .collect()
}

/// The rows of `table` reduced to `columns`, in a stable order.
fn projected(table: &Table, columns: &[&str]) -> Vec<String> {
    let at: Vec<usize> = columns
        .iter()
        .map(|c| {
            table
                .columns
                .iter()
                .position(|have| have == c)
                .expect("column present")
        })
        .collect();
    let mut rows: Vec<String> = table
        .rows
        .iter()
        .map(|row| format!("{:?}", at.iter().map(|i| &row[*i]).collect::<Vec<_>>()))
        .collect();
    rows.sort();
    rows
}

fn runner_up_to(conn: Connection, version: u32) -> SqliteMigrationRunner {
    let count = STATE_MIGRATIONS
        .iter()
        .take_while(|m| m.version <= version)
        .count();
    SqliteMigrationRunner {
        conn: RefCell::new(conn),
        migrations: &STATE_MIGRATIONS[..count],
        required_tables: STATE_REQUIRED_TABLES,
        required_indexes: STATE_REQUIRED_INDEXES,
        snapshot_first: false,
    }
}

#[test]
fn every_released_state_database_upgrades_without_losing_a_row() {
    for (sample, version, rows) in RELEASED_SAMPLES {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("nrr_service_state.db");

        let older = runner_up_to(open_connection(&path).expect("open"), *version);
        let reached = older.run_pending_migrations().expect("older schema");
        assert_eq!(
            reached.to_version, *version,
            "{sample}: wrong starting schema"
        );
        let conn = older.into_connection();
        conn.execute_batch(rows)
            .unwrap_or_else(|e| panic!("{sample}: rows do not fit schema {version}: {e}"));
        let before = contents(&conn);
        for (name, table) in &before {
            assert!(
                !table.rows.is_empty(),
                "{sample}: `{name}` holds no row, so the sample proves nothing for it"
            );
        }
        drop(conn);

        let current = SqliteMigrationRunner::for_state_db(open_connection(&path).expect("reopen"));
        current.run_pending_migrations().expect("upgrade");
        let after = contents(&current.into_connection());

        for (name, old) in &before {
            let Some(new) = after.get(name) else {
                assert!(
                    RETIRED_TABLES
                        .iter()
                        .any(|(t, since)| t == name && version < since),
                    "{sample}: table `{name}` was lost"
                );
                continue;
            };
            let mut kept = Vec::new();
            for column in &old.columns {
                if !new.columns.contains(column) {
                    assert!(
                        retired(RETIRED_COLUMNS, name, column, *version),
                        "{sample}: column `{name}.{column}` was lost"
                    );
                } else if !retired(REWRITTEN_COLUMNS, name, column, *version) {
                    kept.push(column.as_str());
                }
            }
            assert_eq!(
                projected(new, &kept),
                projected(old, &kept),
                "{sample}: rows of `{name}` were lost or changed"
            );
        }
    }
}
