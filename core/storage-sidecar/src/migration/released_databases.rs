//! A sidecar an earlier build left opens with every comment and section the
//! user had. Every release adds a sample of its own schema under
//! `tests/fixtures/`.

use std::collections::BTreeMap;

use rusqlite::types::Value;
use rusqlite::Connection;

use super::MIGRATIONS;
use crate::SidecarDb;

/// `(file, schema version, rows)`.
const RELEASED_SAMPLES: &[(&str, u32, &str)] = &[
    (
        "sidecar_v1.sql",
        1,
        include_str!("../../tests/fixtures/sidecar_v1.sql"),
    ),
    (
        "sidecar_v2.sql",
        2,
        include_str!("../../tests/fixtures/sidecar_v2.sql"),
    ),
];

/// Tables a migration empties on purpose, with that version: v3 drops the
/// parked change, which is at most a week old and parked again on the next
/// offline edit.
const CLEARED_TABLES: &[(&str, u32)] = &[("pending_apply", 3)];

/// Every table but the migration ledger, as its rows over its columns.
fn contents(conn: &Connection) -> BTreeMap<String, (Vec<String>, Vec<Vec<Value>>)> {
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
            (name, (columns, rows))
        })
        .collect()
}

fn projected(columns: &[String], rows: &[Vec<Value>], keep: &[&str]) -> Vec<String> {
    let at: Vec<usize> = keep
        .iter()
        .filter_map(|k| columns.iter().position(|c| c == k))
        .collect();
    let mut out: Vec<String> = rows
        .iter()
        .map(|row| format!("{:?}", at.iter().map(|i| &row[*i]).collect::<Vec<_>>()))
        .collect();
    out.sort();
    out
}

#[test]
fn every_released_sidecar_opens_without_losing_a_row() {
    for (sample, version, rows) in RELEASED_SAMPLES {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("gui_metadata.db");

        let mut conn = Connection::open(&path).expect("open");
        let count = MIGRATIONS
            .iter()
            .take_while(|m| m.version <= *version)
            .count();
        let reached =
            nrr_sqlite_support::migrate(&mut conn, &MIGRATIONS[..count]).expect("older schema");
        assert_eq!(
            reached.to_version, *version,
            "{sample}: wrong starting schema"
        );
        conn.execute_batch(rows)
            .unwrap_or_else(|e| panic!("{sample}: rows do not fit schema {version}: {e}"));
        let before = contents(&conn);
        for (name, (_, rows)) in &before {
            assert!(
                !rows.is_empty(),
                "{sample}: `{name}` holds no row, so the sample proves nothing for it"
            );
        }
        drop(conn);

        let db = SidecarDb::open(&path).expect("the current build opens it");
        let after = contents(&db.conn());

        for (name, (columns, rows)) in &before {
            if CLEARED_TABLES
                .iter()
                .any(|(t, since)| t == name && version < since)
            {
                continue;
            }
            let (new_columns, new_rows) = after
                .get(name)
                .unwrap_or_else(|| panic!("{sample}: table `{name}` was lost"));
            for column in columns {
                assert!(
                    new_columns.contains(column),
                    "{sample}: column `{name}.{column}` was lost"
                );
            }
            let keep: Vec<&str> = columns.iter().map(String::as_str).collect();
            assert_eq!(
                projected(new_columns, new_rows, &keep),
                projected(columns, rows, &keep),
                "{sample}: rows of `{name}` were lost or changed"
            );
        }
    }
}
