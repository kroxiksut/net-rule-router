//! `app_observed_destinations` persistence.
//!
//! Destinations an application the rule book routes over the additional link has
//! actually been seen using. The routing layer can only put an application's
//! flow on that link through a host route, and a host route can only be derived
//! from an address something has already observed — so an in-memory-only
//! observation set means every session starts empty and the app's first contact
//! with each address is refused until the observation catches up. Keeping the
//! set across restarts lets the next session install those routes BEFORE the
//! first connection.
//!
//! Each row has an owner (`sid`): the user whose program used the address,
//! where observations are kept per user, or nobody (`''`) for a machine-wide
//! store, whose route table is shared anyway. A row seeds only its owner's
//! store, so one user's history never becomes another user's routes. Rows are
//! written only for applications a rule names.
//!
//! Rows are additive and idempotent per `(sid, app_key, ip)`; re-confirming an
//! address refreshes `learned_at`, which is what the reader's freshness window
//! keys on.

use std::net::IpAddr;

use rusqlite::{params, Connection};

use crate::error::{StorageError, StorageResult};

/// Hard cap on retained destinations per (owner, application). Each row becomes
/// a host route (and, under the leak guard, a per-destination pin), so the set
/// must stay bounded — a busy application touches far more addresses than any
/// of them can enforce. On overflow the OLDEST rows (by `learned_at`) are
/// evicted, so an address still in use always survives.
///
/// 64 is deliberately the enforcement fan-out cap: persisting more than the
/// enforcement layer will ever act on buys nothing and would only crowd the
/// in-memory set that the live observer needs room in.
pub const MAX_DESTINATIONS_PER_APP: usize = 64;

/// The stored owner of a machine-wide row.
const NO_OWNER: &str = "";

/// One remembered destination.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RememberedDestination {
    /// The user whose program used the address; `None` for a machine-wide row,
    /// including every row written before rows had owners.
    pub owner: Option<String>,
    pub app_key: String,
    pub ip: IpAddr,
}

fn stored_owner(owner: Option<&str>) -> &str {
    owner.unwrap_or(NO_OWNER)
}

/// Repository over the `app_observed_destinations` table (state DB).
pub struct AppDestinationsRepository<'c> {
    conn: &'c Connection,
}

impl<'c> AppDestinationsRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Record `ips` as `owner`'s currently-known destinations for `app_key`,
    /// stamping `now` (UTC Unix millis) as the confirmation time. Additive: an
    /// address missing from `ips` is NOT deleted — it keeps its older
    /// `learned_at` and ages out of the reader's freshness window on its own.
    /// Evicts the oldest rows of that owner's application past
    /// [`MAX_DESTINATIONS_PER_APP`]. An empty key or address list is a no-op.
    pub fn upsert(
        &self,
        owner: Option<&str>,
        app_key: &str,
        ips: &[IpAddr],
        now: i64,
    ) -> StorageResult<()> {
        if app_key.trim().is_empty() || ips.is_empty() {
            return Ok(());
        }
        let sid = stored_owner(owner);
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| StorageError::Internal(format!("app_observed_destinations tx: {e}")))?;
        for ip in ips {
            tx.execute(
                "INSERT INTO app_observed_destinations (sid, app_key, ip, learned_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(sid, app_key, ip) DO UPDATE SET learned_at = excluded.learned_at",
                params![sid, app_key, ip.to_string(), now],
            )
            .map_err(|e| {
                StorageError::Internal(format!("app_observed_destinations insert: {e}"))
            })?;
        }
        tx.execute(
            "DELETE FROM app_observed_destinations
             WHERE sid = ?1 AND app_key = ?2 AND ip NOT IN (
                 SELECT ip FROM app_observed_destinations
                 WHERE sid = ?1 AND app_key = ?2
                 ORDER BY learned_at DESC, ip ASC
                 LIMIT ?3
             )",
            params![sid, app_key, MAX_DESTINATIONS_PER_APP as i64],
        )
        .map_err(|e| StorageError::Internal(format!("app_observed_destinations evict: {e}")))?;
        tx.commit()
            .map_err(|e| StorageError::Internal(format!("app_observed_destinations commit: {e}")))
    }

    /// Drop one remembered destination of `owner`'s `app_key`.
    ///
    /// The upsert path is additive, so an address the in-memory set has stopped
    /// carrying would linger here until it aged out of the reader's freshness
    /// window — long enough for the next start to re-seed it and re-install the
    /// host route it produced. A destination withdrawn because it was moving
    /// somebody ELSE's traffic has to leave immediately, hence this explicit
    /// delete. Idempotent: removing what is not there is not an error.
    pub fn forget(&self, owner: Option<&str>, app_key: &str, ip: IpAddr) -> StorageResult<bool> {
        let removed = self
            .conn
            .execute(
                "DELETE FROM app_observed_destinations WHERE sid = ?1 AND app_key = ?2 AND ip = ?3",
                params![stored_owner(owner), app_key, ip.to_string()],
            )
            .map_err(|e| {
                StorageError::Internal(format!("app_observed_destinations delete: {e}"))
            })?;
        Ok(removed > 0)
    }

    /// Every destination confirmed at or after `confirmed_since` (UTC Unix
    /// millis), newest first, with its owner. Rows older than the cutoff are
    /// left in place but withheld: the caller's freshness policy decides what
    /// may be enforced, while a later re-confirmation can still revive the row
    /// in one write.
    ///
    /// A row whose `ip` fails to parse is skipped rather than failing the whole
    /// load — a can't-happen guard against a hand-edited database (this module
    /// only ever writes `IpAddr::to_string`).
    pub fn load_confirmed_since(
        &self,
        confirmed_since: i64,
    ) -> StorageResult<Vec<RememberedDestination>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT sid, app_key, ip FROM app_observed_destinations
                 WHERE learned_at >= ?1
                 ORDER BY learned_at DESC, sid ASC, app_key ASC, ip ASC",
            )
            .map_err(|e| {
                StorageError::Internal(format!("app_observed_destinations prepare: {e}"))
            })?;
        let rows = stmt
            .query_map(params![confirmed_since], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| StorageError::Internal(format!("app_observed_destinations query: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (sid, app_key, raw) = row.map_err(|e| {
                StorageError::Internal(format!("app_observed_destinations row: {e}"))
            })?;
            if let Ok(ip) = raw.parse::<IpAddr>() {
                out.push(RememberedDestination {
                    owner: (sid != NO_OWNER).then_some(sid),
                    app_key,
                    ip,
                });
            }
        }
        Ok(out)
    }

    /// Delete every row last confirmed before `cutoff` (UTC Unix millis),
    /// whoever owns it. Called on the read path's schedule so the table cannot
    /// accumulate destinations of applications whose rules were removed long
    /// ago, nor ownerless rows no store will ever read again.
    pub fn prune_before(&self, cutoff: i64) -> StorageResult<usize> {
        self.conn
            .execute(
                "DELETE FROM app_observed_destinations WHERE learned_at < ?1",
                params![cutoff],
            )
            .map_err(|e| StorageError::Internal(format!("app_observed_destinations prune: {e}")))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::SqliteMigrationRunner;
    use crate::repository::MigrationRunner;

    const ALICE: Option<&str> = Some("uid:1000");
    const BOB: Option<&str> = Some("uid:1001");

    fn migrated_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        runner.into_connection()
    }

    use std::net::Ipv4Addr;

    fn ip(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, d))
    }

    fn net(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, d))
    }

    fn row(owner: Option<&str>, app: &str, ip: IpAddr) -> RememberedDestination {
        RememberedDestination {
            owner: owner.map(str::to_owned),
            app_key: app.to_owned(),
            ip,
        }
    }

    fn loaded(repo: &AppDestinationsRepository<'_>, since: i64) -> Vec<RememberedDestination> {
        let mut rows = repo.load_confirmed_since(since).expect("load");
        rows.sort();
        rows
    }

    #[test]
    fn forget_removes_one_destination_and_is_idempotent() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert(None, "messenger.exe", &[ip(1), ip(2)], 1_000)
            .expect("upsert");

        assert!(repo.forget(None, "messenger.exe", ip(1)).expect("forget"));
        assert!(!repo
            .forget(None, "messenger.exe", ip(1))
            .expect("forget again"));

        assert_eq!(loaded(&repo, 0), vec![row(None, "messenger.exe", ip(2))]);
    }

    #[test]
    fn forget_touches_only_the_named_owner() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert(ALICE, "firefox", &[ip(1)], 1_000)
            .expect("alice");
        repo.upsert(BOB, "firefox", &[ip(1)], 1_000).expect("bob");

        assert!(repo.forget(ALICE, "firefox", ip(1)).expect("forget"));
        assert_eq!(loaded(&repo, 0), vec![row(BOB, "firefox", ip(1))]);
    }

    #[test]
    fn upsert_then_load_round_trips() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert(None, "messenger.exe", &[ip(1), ip(2)], 1_000)
            .expect("upsert");
        assert_eq!(
            loaded(&repo, 0),
            vec![
                row(None, "messenger.exe", ip(1)),
                row(None, "messenger.exe", ip(2))
            ]
        );
    }

    #[test]
    fn each_owner_round_trips_their_own_rows() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert(ALICE, "firefox", &[ip(1)], 1_000)
            .expect("alice");
        repo.upsert(BOB, "firefox", &[ip(1), ip(2)], 1_000)
            .expect("bob");
        repo.upsert(None, "firefox", &[ip(3)], 1_000)
            .expect("machine-wide");
        // An empty owner is no owner, never a user called "".
        repo.upsert(Some(""), "firefox", &[ip(4)], 1_000)
            .expect("empty owner");
        assert_eq!(
            loaded(&repo, 0),
            vec![
                row(None, "firefox", ip(3)),
                row(None, "firefox", ip(4)),
                row(ALICE, "firefox", ip(1)),
                row(BOB, "firefox", ip(1)),
                row(BOB, "firefox", ip(2)),
            ]
        );
    }

    #[test]
    fn re_confirming_refreshes_instead_of_duplicating() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert(None, "messenger.exe", &[ip(1)], 1_000)
            .expect("first");
        repo.upsert(None, "messenger.exe", &[ip(1)], 5_000)
            .expect("second");
        assert_eq!(repo.load_confirmed_since(0).expect("load").len(), 1);
        // The refreshed timestamp is what keeps a still-used address inside the
        // caller's freshness window across sessions.
        assert_eq!(repo.load_confirmed_since(4_999).expect("load").len(), 1);
    }

    #[test]
    fn app_key_matching_is_case_insensitive() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert(None, "Messenger.exe", &[ip(1)], 1_000)
            .expect("first");
        repo.upsert(None, "messenger.exe", &[ip(1)], 2_000)
            .expect("second");
        assert_eq!(
            repo.load_confirmed_since(0).expect("load").len(),
            1,
            "one row — Windows executable names are not case-sensitive"
        );
    }

    #[test]
    fn load_withholds_rows_outside_the_window() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert(None, "messenger.exe", &[ip(1)], 1_000)
            .expect("stale");
        repo.upsert(None, "messenger.exe", &[ip(2)], 9_000)
            .expect("fresh");
        assert_eq!(
            repo.load_confirmed_since(5_000).expect("load"),
            vec![row(None, "messenger.exe", ip(2))]
        );
        // Withheld, not deleted: a re-confirmation revives it in one write.
        repo.upsert(None, "messenger.exe", &[ip(1)], 9_500)
            .expect("again");
        assert_eq!(repo.load_confirmed_since(5_000).expect("load").len(), 2);
    }

    #[test]
    fn upsert_evicts_the_oldest_beyond_the_per_app_cap() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        let total = MAX_DESTINATIONS_PER_APP + 4;
        for i in 0..total {
            repo.upsert(None, "busy.exe", &[net(i as u8)], 1_000 + i as i64)
                .expect("upsert");
        }
        let kept = repo.load_confirmed_since(0).expect("load");
        assert_eq!(kept.len(), MAX_DESTINATIONS_PER_APP);
        assert!(!kept.contains(&row(None, "busy.exe", net(0))));
        assert!(kept.contains(&row(None, "busy.exe", net((total - 1) as u8))));
    }

    /// One user's busy program cannot evict another user's rows for it: the
    /// cap is per (owner, application).
    #[test]
    fn the_cap_is_per_owner() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert(BOB, "busy.exe", &[ip(1)], 1)
            .expect("bob, oldest");
        for i in 0..MAX_DESTINATIONS_PER_APP + 4 {
            repo.upsert(ALICE, "busy.exe", &[net(i as u8)], 1_000 + i as i64)
                .expect("alice");
        }
        let kept = repo.load_confirmed_since(0).expect("load");
        let alices = kept.iter().filter(|r| r.owner.as_deref() == ALICE).count();
        assert_eq!(alices, MAX_DESTINATIONS_PER_APP);
        assert!(kept.contains(&row(BOB, "busy.exe", ip(1))));
    }

    #[test]
    fn caps_are_per_app_not_global() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert(None, "a.exe", &[ip(1)], 1_000).expect("a");
        repo.upsert(None, "b.exe", &[ip(2)], 1_000).expect("b");
        assert_eq!(repo.load_confirmed_since(0).expect("load").len(), 2);
    }

    #[test]
    fn prune_drops_only_rows_older_than_the_cutoff() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert(None, "messenger.exe", &[ip(1)], 1_000)
            .expect("old");
        repo.upsert(None, "messenger.exe", &[ip(2)], 9_000)
            .expect("new");
        assert_eq!(repo.prune_before(5_000).expect("prune"), 1);
        assert_eq!(
            repo.load_confirmed_since(0).expect("load"),
            vec![row(None, "messenger.exe", ip(2))]
        );
    }

    /// Age decides per row: one user's fresh rows keep nobody else's stale
    /// ones alive, and ownerless rows age out like any other.
    #[test]
    fn prune_ages_each_owners_rows_on_their_own() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert(ALICE, "firefox", &[ip(1)], 1_000)
            .expect("alice old");
        repo.upsert(ALICE, "firefox", &[ip(2)], 9_000)
            .expect("alice new");
        repo.upsert(BOB, "firefox", &[ip(1)], 1_000)
            .expect("bob old");
        repo.upsert(None, "firefox", &[ip(3)], 1_000)
            .expect("ownerless old");
        repo.upsert(BOB, "chat", &[ip(4)], 9_000).expect("bob new");

        assert_eq!(repo.prune_before(5_000).expect("prune"), 3);
        assert_eq!(
            loaded(&repo, 0),
            vec![row(ALICE, "firefox", ip(2)), row(BOB, "chat", ip(4))]
        );
    }

    #[test]
    fn empty_inputs_are_no_ops() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert(ALICE, "", &[ip(1)], 1_000).expect("empty key");
        repo.upsert(ALICE, "messenger.exe", &[], 1_000)
            .expect("empty ips");
        assert!(repo.load_confirmed_since(0).expect("load").is_empty());
    }

    /// A program on a dual-stack network uses IPv6 destinations too; one
    /// dropped on load starts every session cold on that family again.
    #[test]
    fn an_ipv6_destination_survives_a_restart() {
        let conn = migrated_conn();
        conn.execute(
            "INSERT INTO app_observed_destinations (sid, app_key, ip, learned_at)
             VALUES ('uid:1000', 'messenger.exe', '2001:db8::5', 1000)",
            [],
        )
        .expect("a v6 row as an earlier session wrote it");
        let repo = AppDestinationsRepository::new(&conn);
        assert_eq!(repo.load_confirmed_since(0).expect("load").len(), 1);
        let v6: IpAddr = "2001:db8::5".parse().expect("v6");
        repo.upsert(ALICE, "messenger.exe", &[v6], 2_000)
            .expect("re-confirm");
        assert_eq!(loaded(&repo, 1_500), vec![row(ALICE, "messenger.exe", v6)]);
        assert!(repo.forget(ALICE, "messenger.exe", v6).expect("forget"));
        assert!(loaded(&repo, 0).is_empty());
    }

    #[test]
    fn load_skips_unparseable_ip_rows() {
        let conn = migrated_conn();
        conn.execute(
            "INSERT INTO app_observed_destinations (sid, app_key, ip, learned_at)
             VALUES ('', 'messenger.exe', 'not-an-ip', 1000)",
            [],
        )
        .expect("inject bad row");
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert(None, "messenger.exe", &[ip(1)], 2_000)
            .expect("good");
        assert_eq!(
            repo.load_confirmed_since(0).expect("load"),
            vec![row(None, "messenger.exe", ip(1))]
        );
    }
}
