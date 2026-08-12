//! Block T — per-adapter traffic-statistics store (`nrr_traffic_stats.db`).
//!
//! Rebuildable SQLite store for the traffic counter: daily byte totals bucketed
//! by route role, the friendly-name identity table, and the resume-safe counter
//! cursor. Consumes [`TrafficDelta`]s produced by the pure
//! [`nrr_domain::traffic_accountant::TrafficAccountant`].
//!
//! # Threading / write cadence
//!
//! Synchronous `rusqlite`, one connection in a `RefCell` (owned by the service
//! sampler). The sampler accumulates deltas in memory and flushes here on an
//! interval (~30–60 s) + on shutdown + on a day boundary — never once per
//! sample — so the write load stays negligible.
//!
//! # Time-agnostic
//!
//! `day` is an opaque epoch-day integer computed by the caller in local time
//! (this crate never reads the clock for the ledger key), mirroring the
//! decision engine's "no I/O" discipline. `now_ms` timestamps on identity/cursor
//! rows are audit metadata only.

use std::cell::RefCell;

use rusqlite::{params, Connection, OptionalExtension};

use nrr_domain::traffic_accountant::TrafficDelta;

use crate::error::{StorageError, StorageResult};

// ── DTO ───────────────────────────────────────────────────────────────────────

/// One row of the daily ledger, joined with the friendly display name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficDayRow {
    /// Epoch-day key (local calendar day, opaque to this crate).
    pub day: i64,
    /// Stable-name adapter key.
    pub adapter_key: String,
    /// Friendly display name (falls back to `adapter_key` when identity is absent).
    pub display_name: String,
    /// `TrafficCategory` slug — `primary` / `secondary` / `loopback` / `virtual`.
    pub role: String,
    pub in_bytes: u64,
    pub out_bytes: u64,
}

/// A persisted counter cursor (last cumulative reading) for one adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficCursorRow {
    pub adapter_key: String,
    pub last_in: u64,
    pub last_out: u64,
}

/// One all-time aggregate (sum over every retained day) for an adapter+role,
/// joined with the friendly display name. No `day` field on purpose: the row
/// spans the whole retained ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficTotalRow {
    pub adapter_key: String,
    pub display_name: String,
    /// `TrafficCategory` slug — `primary` / `secondary` / `loopback` / `virtual`.
    pub role: String,
    pub in_bytes: u64,
    pub out_bytes: u64,
}

/// Block T Feature 2 — last observed local + external address for one
/// adapter, from a USER-REQUESTED external-IP probe. `adapter_key` matches
/// the traffic ledger's key (the OS friendly interface name) so a GUI row can
/// be joined to its last-known addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterAddressRow {
    pub adapter_key: String,
    pub local_ip: String,
    pub external_ip: Option<String>,
    pub observed_at_ms: i64,
}

// ── Store ─────────────────────────────────────────────────────────────────────

/// SQLite-backed traffic-statistics store. Owns one connection to
/// `nrr_traffic_stats.db` (already migrated by
/// [`SqliteMigrationRunner::for_traffic_db`][crate::migration::SqliteMigrationRunner::for_traffic_db]).
pub struct SqliteTrafficStore {
    conn: RefCell<Connection>,
}

impl SqliteTrafficStore {
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: RefCell::new(conn),
        }
    }

    pub fn into_connection(self) -> Connection {
        self.conn.into_inner()
    }

    /// Records/refreshes the friendly display name for an adapter key.
    pub fn upsert_identity(
        &self,
        adapter_key: &str,
        display_name: &str,
        now_ms: i64,
    ) -> StorageResult<()> {
        let conn = self.conn.borrow();
        conn.execute(
            "INSERT INTO interface_identity (adapter_key, display_name, last_seen)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(adapter_key) DO UPDATE SET
                 display_name = excluded.display_name,
                 last_seen    = excluded.last_seen",
            params![adapter_key, display_name, now_ms],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Adds a tick/flush worth of deltas to the given day's buckets, in one
    /// transaction. A same-day same-adapter row that changes role (a
    /// primary<->secondary swap) accumulates into a separate `(day, key, role)`
    /// row, so both role-eras of the day survive.
    pub fn accumulate(&self, day: i64, deltas: &[TrafficDelta]) -> StorageResult<()> {
        if deltas.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(db_err)?;
        for d in deltas {
            tx.execute(
                "INSERT INTO interface_daily_traffic
                     (day, adapter_key, role, in_bytes, out_bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(day, adapter_key, role) DO UPDATE SET
                     in_bytes  = in_bytes  + excluded.in_bytes,
                     out_bytes = out_bytes + excluded.out_bytes",
                params![
                    day,
                    d.stable_name,
                    d.category.slug(),
                    d.in_delta as i64,
                    d.out_delta as i64,
                ],
            )
            .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)
    }

    /// Reads the persisted cursor for one adapter (`None` when never seen).
    pub fn get_cursor(&self, adapter_key: &str) -> StorageResult<Option<(u64, u64)>> {
        let conn = self.conn.borrow();
        let row: Option<(i64, i64)> = conn
            .query_row(
                "SELECT last_in, last_out FROM interface_counter_cursor
                 WHERE adapter_key = ?1",
                params![adapter_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_err)?;
        Ok(row.map(|(i, o)| (i.max(0) as u64, o.max(0) as u64)))
    }

    /// Persists a batch of cursors (last cumulative readings), in one
    /// transaction. Called on the same cadence as [`accumulate`](Self::accumulate)
    /// so a restart resumes without double-counting or losing a partial delta.
    pub fn set_cursors(&self, cursors: &[TrafficCursorRow], now_ms: i64) -> StorageResult<()> {
        if cursors.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(db_err)?;
        for c in cursors {
            tx.execute(
                "INSERT INTO interface_counter_cursor
                     (adapter_key, last_in, last_out, sampled_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(adapter_key) DO UPDATE SET
                     last_in    = excluded.last_in,
                     last_out   = excluded.last_out,
                     sampled_at = excluded.sampled_at",
                params![c.adapter_key, c.last_in as i64, c.last_out as i64, now_ms],
            )
            .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)
    }

    /// All persisted cursors — used to prime the in-memory accountant on service
    /// start so accounting resumes against the last known baseline.
    pub fn all_cursors(&self) -> StorageResult<Vec<TrafficCursorRow>> {
        let conn = self.conn.borrow();
        let mut stmt = conn
            .prepare("SELECT adapter_key, last_in, last_out FROM interface_counter_cursor")
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(TrafficCursorRow {
                    adapter_key: r.get(0)?,
                    last_in: r.get::<_, i64>(1)?.max(0) as u64,
                    last_out: r.get::<_, i64>(2)?.max(0) as u64,
                })
            })
            .map_err(db_err)?;
        collect_rows(rows)
    }

    /// Ledger rows for one day (role/adapter-ordered), joined with display names.
    pub fn totals_for_day(&self, day: i64) -> StorageResult<Vec<TrafficDayRow>> {
        self.query_rows(
            "WHERE t.day = ?1 ORDER BY t.role, t.adapter_key",
            params![day],
        )
    }

    /// All-time totals per adapter+role, summed over every retained day and
    /// joined with display names (role/adapter-ordered). "All time" is bounded
    /// by the retention sweep: pruned days are gone from the sum too.
    pub fn all_time_totals(&self) -> StorageResult<Vec<TrafficTotalRow>> {
        let conn = self.conn.borrow();
        let mut stmt = conn
            .prepare(
                "SELECT t.adapter_key,
                        COALESCE(i.display_name, t.adapter_key) AS display_name,
                        t.role, SUM(t.in_bytes), SUM(t.out_bytes)
                 FROM interface_daily_traffic t
                 LEFT JOIN interface_identity i ON i.adapter_key = t.adapter_key
                 GROUP BY t.adapter_key, t.role
                 ORDER BY t.role, t.adapter_key",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(TrafficTotalRow {
                    adapter_key: r.get(0)?,
                    display_name: r.get(1)?,
                    role: r.get(2)?,
                    in_bytes: r.get::<_, i64>(3)?.max(0) as u64,
                    out_bytes: r.get::<_, i64>(4)?.max(0) as u64,
                })
            })
            .map_err(db_err)?;
        collect_rows(rows)
    }

    /// Ledger rows across an inclusive day range — feeds the CSV export.
    pub fn rows_in_range(&self, from_day: i64, to_day: i64) -> StorageResult<Vec<TrafficDayRow>> {
        self.query_rows(
            "WHERE t.day BETWEEN ?1 AND ?2 ORDER BY t.day, t.role, t.adapter_key",
            params![from_day, to_day],
        )
    }

    fn query_rows(
        &self,
        where_order: &str,
        p: impl rusqlite::Params,
    ) -> StorageResult<Vec<TrafficDayRow>> {
        let conn = self.conn.borrow();
        let sql = format!(
            "SELECT t.day, t.adapter_key,
                    COALESCE(i.display_name, t.adapter_key) AS display_name,
                    t.role, t.in_bytes, t.out_bytes
             FROM interface_daily_traffic t
             LEFT JOIN interface_identity i ON i.adapter_key = t.adapter_key
             {where_order}"
        );
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let rows = stmt
            .query_map(p, |r| {
                Ok(TrafficDayRow {
                    day: r.get(0)?,
                    adapter_key: r.get(1)?,
                    display_name: r.get(2)?,
                    role: r.get(3)?,
                    in_bytes: r.get::<_, i64>(4)?.max(0) as u64,
                    out_bytes: r.get::<_, i64>(5)?.max(0) as u64,
                })
            })
            .map_err(db_err)?;
        collect_rows(rows)
    }

    /// Retention sweep — drops daily rows older than `cutoff_day`. Identity and
    /// cursor rows are tiny and current, so they are kept. Returns the number of
    /// daily rows deleted.
    pub fn prune_before(&self, cutoff_day: i64) -> StorageResult<u64> {
        let conn = self.conn.borrow();
        let n = conn
            .execute(
                "DELETE FROM interface_daily_traffic WHERE day < ?1",
                params![cutoff_day],
            )
            .map_err(db_err)?;
        Ok(n as u64)
    }

    /// Wipes all ledger data (daily totals, identities, cursors, observed
    /// addresses). Used on an explicit user "reset statistics" action.
    pub fn clear(&self) -> StorageResult<()> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(db_err)?;
        tx.execute("DELETE FROM interface_daily_traffic", [])
            .map_err(db_err)?;
        tx.execute("DELETE FROM interface_identity", [])
            .map_err(db_err)?;
        tx.execute("DELETE FROM interface_counter_cursor", [])
            .map_err(db_err)?;
        tx.execute("DELETE FROM adapter_addresses", [])
            .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    /// Block T Feature 2 — records/refreshes the last observed local +
    /// external address for an adapter. Called only from a USER-REQUESTED
    /// external-IP probe (`interfaces.refresh`) — the routine sampler tick
    /// never calls this, so a row's presence always means the user explicitly
    /// checked at least once.
    pub fn upsert_adapter_address(
        &self,
        adapter_key: &str,
        local_ip: &str,
        external_ip: Option<&str>,
        observed_at_ms: i64,
    ) -> StorageResult<()> {
        let conn = self.conn.borrow();
        conn.execute(
            "INSERT INTO adapter_addresses (adapter_key, local_ip, external_ip, observed_at_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(adapter_key) DO UPDATE SET
                 local_ip       = excluded.local_ip,
                 external_ip    = excluded.external_ip,
                 observed_at_ms = excluded.observed_at_ms",
            params![adapter_key, local_ip, external_ip, observed_at_ms],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// One adapter's persisted address observation (`None` when never
    /// recorded).
    pub fn adapter_address(&self, adapter_key: &str) -> StorageResult<Option<AdapterAddressRow>> {
        let conn = self.conn.borrow();
        conn.query_row(
            "SELECT adapter_key, local_ip, external_ip, observed_at_ms
             FROM adapter_addresses WHERE adapter_key = ?1",
            params![adapter_key],
            |r| {
                Ok(AdapterAddressRow {
                    adapter_key: r.get(0)?,
                    local_ip: r.get(1)?,
                    external_ip: r.get(2)?,
                    observed_at_ms: r.get(3)?,
                })
            },
        )
        .optional()
        .map_err(db_err)
    }

    /// All persisted address observations — feeds the `traffic-stats.get`
    /// response join (today/session/all-time rows are looked up by
    /// `adapter_key`).
    pub fn all_adapter_addresses(&self) -> StorageResult<Vec<AdapterAddressRow>> {
        let conn = self.conn.borrow();
        let mut stmt = conn
            .prepare(
                "SELECT adapter_key, local_ip, external_ip, observed_at_ms FROM adapter_addresses",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok(AdapterAddressRow {
                    adapter_key: r.get(0)?,
                    local_ip: r.get(1)?,
                    external_ip: r.get(2)?,
                    observed_at_ms: r.get(3)?,
                })
            })
            .map_err(db_err)?;
        collect_rows(rows)
    }

    /// SQLite structural integrity — `false` means the rebuildable DB should be
    /// deleted and recreated.
    pub fn integrity_ok(&self) -> StorageResult<bool> {
        let conn = self.conn.borrow();
        let check: String = conn
            .query_row("PRAGMA integrity_check(1)", [], |r| r.get(0))
            .map_err(db_err)?;
        Ok(check == "ok")
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn db_err(e: rusqlite::Error) -> StorageError {
    StorageError::Internal(e.to_string())
}

fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
) -> StorageResult<Vec<T>> {
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(db_err)?);
    }
    Ok(out)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{open_connection, SqliteMigrationRunner};
    use crate::repository::MigrationRunner;
    use nrr_domain::traffic_accountant::TrafficCategory;

    fn open_store(dir: &tempfile::TempDir) -> SqliteTrafficStore {
        let path = dir.path().join("nrr_traffic_stats.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_traffic_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let v = runner.verify_schema().expect("verify");
        assert!(v.is_ok(), "traffic schema verify failed: {v:?}");
        SqliteTrafficStore::new(runner.into_connection())
    }

    fn delta(name: &str, cat: TrafficCategory, in_d: u64, out_d: u64) -> TrafficDelta {
        TrafficDelta {
            stable_name: name.to_string(),
            category: cat,
            in_delta: in_d,
            out_delta: out_d,
        }
    }

    #[test]
    fn accumulate_sums_into_daily_buckets() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        store
            .accumulate(20000, &[delta("eth0", TrafficCategory::Primary, 100, 40)])
            .expect("acc1");
        store
            .accumulate(20000, &[delta("eth0", TrafficCategory::Primary, 60, 10)])
            .expect("acc2");

        let rows = store.totals_for_day(20000).expect("totals");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].adapter_key, "eth0");
        assert_eq!(rows[0].role, "primary");
        assert_eq!(rows[0].in_bytes, 160);
        assert_eq!(rows[0].out_bytes, 50);
    }

    #[test]
    fn role_swap_keeps_both_eras_of_the_day() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        // Same adapter, same day, first as secondary then as primary.
        store
            .accumulate(20001, &[delta("wg0", TrafficCategory::Secondary, 500, 500)])
            .expect("acc sec");
        store
            .accumulate(20001, &[delta("wg0", TrafficCategory::Primary, 200, 100)])
            .expect("acc pri");

        let rows = store.totals_for_day(20001).expect("totals");
        assert_eq!(rows.len(), 2, "role swap must yield two rows");
        let pri = rows.iter().find(|r| r.role == "primary").expect("pri");
        let sec = rows.iter().find(|r| r.role == "secondary").expect("sec");
        assert_eq!((pri.in_bytes, pri.out_bytes), (200, 100));
        assert_eq!((sec.in_bytes, sec.out_bytes), (500, 500));
    }

    #[test]
    fn totals_join_display_name() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        store
            .upsert_identity("wg0", "WireGuard Tunnel", 111)
            .expect("id");
        store
            .accumulate(20002, &[delta("wg0", TrafficCategory::Secondary, 10, 20)])
            .expect("acc");
        let rows = store.totals_for_day(20002).expect("totals");
        assert_eq!(rows[0].display_name, "WireGuard Tunnel");
    }

    #[test]
    fn display_name_falls_back_to_key_when_identity_absent() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        store
            .accumulate(20003, &[delta("eth7", TrafficCategory::Primary, 1, 1)])
            .expect("acc");
        let rows = store.totals_for_day(20003).expect("totals");
        assert_eq!(rows[0].display_name, "eth7");
    }

    #[test]
    fn cursor_round_trips_and_primes_all() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        assert_eq!(store.get_cursor("eth0").expect("get"), None);

        store
            .set_cursors(
                &[
                    TrafficCursorRow {
                        adapter_key: "eth0".into(),
                        last_in: 1000,
                        last_out: 500,
                    },
                    TrafficCursorRow {
                        adapter_key: "wg0".into(),
                        last_in: 7,
                        last_out: 3,
                    },
                ],
                999,
            )
            .expect("set");

        assert_eq!(store.get_cursor("eth0").expect("get"), Some((1000, 500)));
        let all = store.all_cursors().expect("all");
        assert_eq!(all.len(), 2);

        // Overwrite updates in place.
        store
            .set_cursors(
                &[TrafficCursorRow {
                    adapter_key: "eth0".into(),
                    last_in: 2000,
                    last_out: 900,
                }],
                1001,
            )
            .expect("set2");
        assert_eq!(store.get_cursor("eth0").expect("get"), Some((2000, 900)));
    }

    #[test]
    fn prune_before_drops_old_days_only() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        for day in [19998_i64, 19999, 20000] {
            store
                .accumulate(day, &[delta("eth0", TrafficCategory::Primary, 10, 10)])
                .expect("acc");
        }
        let removed = store.prune_before(20000).expect("prune");
        assert_eq!(removed, 2, "days 19998 and 19999 dropped");
        assert!(store.totals_for_day(19998).expect("t").is_empty());
        assert!(store.totals_for_day(19999).expect("t").is_empty());
        assert_eq!(store.totals_for_day(20000).expect("t").len(), 1);
    }

    #[test]
    fn all_time_totals_sum_across_days_and_join_names() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        store
            .upsert_identity("wg0", "WireGuard Tunnel", 1)
            .expect("id");
        store
            .accumulate(100, &[delta("eth0", TrafficCategory::Primary, 10, 1)])
            .expect("a");
        store
            .accumulate(101, &[delta("eth0", TrafficCategory::Primary, 30, 2)])
            .expect("b");
        store
            .accumulate(101, &[delta("wg0", TrafficCategory::Secondary, 5, 5)])
            .expect("c");

        let rows = store.all_time_totals().expect("totals");
        assert_eq!(rows.len(), 2);
        let pri = rows.iter().find(|r| r.role == "primary").expect("pri");
        assert_eq!(pri.adapter_key, "eth0");
        assert_eq!((pri.in_bytes, pri.out_bytes), (40, 3));
        let sec = rows.iter().find(|r| r.role == "secondary").expect("sec");
        assert_eq!(sec.display_name, "WireGuard Tunnel");
        assert_eq!((sec.in_bytes, sec.out_bytes), (5, 5));
    }

    #[test]
    fn rows_in_range_feeds_export() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        store
            .accumulate(100, &[delta("eth0", TrafficCategory::Primary, 1, 1)])
            .expect("a");
        store
            .accumulate(200, &[delta("wg0", TrafficCategory::Secondary, 2, 2)])
            .expect("b");
        store
            .accumulate(300, &[delta("eth0", TrafficCategory::Primary, 3, 3)])
            .expect("c");
        let rows = store.rows_in_range(100, 200).expect("range");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].day, 100);
        assert_eq!(rows[1].day, 200);
    }

    #[test]
    fn clear_wipes_everything() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        store.upsert_identity("eth0", "Ethernet", 1).expect("id");
        store
            .accumulate(1, &[delta("eth0", TrafficCategory::Primary, 5, 5)])
            .expect("acc");
        store
            .set_cursors(
                &[TrafficCursorRow {
                    adapter_key: "eth0".into(),
                    last_in: 5,
                    last_out: 5,
                }],
                1,
            )
            .expect("cur");
        store
            .upsert_adapter_address("eth0", "192.168.1.5", Some("203.0.113.7"), 1)
            .expect("addr");

        store.clear().expect("clear");
        assert!(store.totals_for_day(1).expect("t").is_empty());
        assert!(store.all_cursors().expect("c").is_empty());
        assert_eq!(store.get_cursor("eth0").expect("g"), None);
        assert_eq!(store.adapter_address("eth0").expect("addr"), None);
    }

    // ── adapter_addresses (Block T Feature 2) ────────────────────────────────

    #[test]
    fn adapter_address_absent_when_never_recorded() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        assert_eq!(store.adapter_address("eth0").expect("get"), None);
        assert!(store.all_adapter_addresses().expect("all").is_empty());
    }

    #[test]
    fn upsert_adapter_address_round_trips() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        store
            .upsert_adapter_address("eth0", "192.168.1.5", Some("203.0.113.7"), 1000)
            .expect("upsert");

        let row = store
            .adapter_address("eth0")
            .expect("get")
            .expect("present");
        assert_eq!(row.adapter_key, "eth0");
        assert_eq!(row.local_ip, "192.168.1.5");
        assert_eq!(row.external_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(row.observed_at_ms, 1000);
    }

    #[test]
    fn upsert_adapter_address_overwrites_in_place() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        store
            .upsert_adapter_address("eth0", "192.168.1.5", Some("203.0.113.7"), 1000)
            .expect("first");
        store
            .upsert_adapter_address("eth0", "192.168.1.6", Some("203.0.113.9"), 2000)
            .expect("second");

        let row = store
            .adapter_address("eth0")
            .expect("get")
            .expect("present");
        assert_eq!(row.local_ip, "192.168.1.6");
        assert_eq!(row.external_ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(row.observed_at_ms, 2000);
    }

    #[test]
    fn upsert_adapter_address_accepts_no_external_ip() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        store
            .upsert_adapter_address("eth0", "192.168.1.5", None, 1000)
            .expect("upsert");
        let row = store
            .adapter_address("eth0")
            .expect("get")
            .expect("present");
        assert_eq!(row.external_ip, None);
    }

    #[test]
    fn all_adapter_addresses_returns_every_adapter() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        store
            .upsert_adapter_address("eth0", "192.168.1.5", Some("203.0.113.7"), 1000)
            .expect("a");
        store
            .upsert_adapter_address("wg0", "10.8.0.2", Some("198.51.100.4"), 2000)
            .expect("b");

        let mut all = store.all_adapter_addresses().expect("all");
        all.sort_by(|a, b| a.adapter_key.cmp(&b.adapter_key));
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].adapter_key, "eth0");
        assert_eq!(all[1].adapter_key, "wg0");
    }

    #[test]
    fn integrity_ok_on_fresh_db() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        assert!(store.integrity_ok().expect("integrity"));
    }

    #[test]
    fn empty_accumulate_is_noop() {
        let dir = tempfile::tempdir().expect("dir");
        let store = open_store(&dir);
        store.accumulate(1, &[]).expect("empty");
        assert!(store.totals_for_day(1).expect("t").is_empty());
    }
}
