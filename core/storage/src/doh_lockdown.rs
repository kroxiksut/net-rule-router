//! DoH/DoT lockdown domain types + persistence.
//!
//! The lockdown blocks browser DNS-over-HTTPS/TLS so the DNS observer sees
//! plaintext queries again (the plaintext-DNS blind-spot class). Two pieces of state:
//!
//! - a **per-SID** enable toggle + application scope (in `secondary_block_policy`,
//!   alongside the other kill-switch fields) — each user decides whether to apply
//!   the lockdown to their own traffic and when;
//! - a **shared baseline** list of resolver entries (the `doh_resolver_entries`
//!   table) — the resolver set is a machine-wide fact, edited once (with
//!   elevation), pre-filled with public resolvers by country.
//!
//! Subnets/CIDR are not supported; a Free entry is a single address of either
//! family or a hostname (resolved to host addresses by the enforcement layer).

use std::net::IpAddr;

use rusqlite::{params, Connection};

use crate::error::{StorageError, StorageResult};
use crate::schema::BASELINE_PRINCIPAL;

/// Where the DoH/DoT lockdown applies. Persisted per-SID as an INTEGER code
/// (like [`crate::resolution_source`]'s policies), carried on the wire as a slug.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DohLockdownScope {
    /// Apply the lockdown ONLY while leak protection (kill switch / block-all) is
    /// armed — DoH hurts observation exactly there. The default: the aggressive
    /// measure acts only when it is needed, so normal browsing keeps DoH/HTTP-3.
    #[default]
    LeakProtectionOnly,
    /// Apply the lockdown ALWAYS while the toggle is on, regardless of the
    /// kill-switch — maximum observability, at the cost of breaking DoH in the
    /// calm state too.
    Always,
}

impl DohLockdownScope {
    /// The INTEGER code stored in SQLite (CHECK-constrained to `0..=1`).
    pub fn as_code(self) -> i64 {
        match self {
            Self::LeakProtectionOnly => 0,
            Self::Always => 1,
        }
    }

    /// Parse the stored code. `None` on an unknown value → callers default.
    pub fn from_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(Self::LeakProtectionOnly),
            1 => Some(Self::Always),
            _ => None,
        }
    }

    /// The wire/GUI slug.
    pub fn as_slug(self) -> &'static str {
        match self {
            Self::LeakProtectionOnly => "leak-protection-only",
            Self::Always => "always",
        }
    }

    /// Parse the slug. `None` on unknown → callers default.
    pub fn from_slug(s: &str) -> Option<Self> {
        match s {
            "leak-protection-only" => Some(Self::LeakProtectionOnly),
            "always" => Some(Self::Always),
            _ => None,
        }
    }

    /// Every slug, for wire/GUI validation allow-lists.
    pub const ALL_SLUGS: &'static [&'static str] = &["leak-protection-only", "always"];
}

/// A resolver-list entry target. Free: a literal address (blocked directly) or
/// a hostname (the enforcement layer resolves it). No CIDR/subnets.
///
/// Both families share the `ip` kind: the column holds text, so an IPv6 row
/// needs no schema change and every IPv4 row written before decodes unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DohTarget {
    /// A single resolver address, either family.
    Ip(IpAddr),
    /// A resolver hostname (e.g. `resolver.example`), resolved to IPs at apply time.
    Host(String),
}

impl DohTarget {
    /// The `target_kind` column value.
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Ip(_) => "ip",
            Self::Host(_) => "host",
        }
    }

    /// The `target` column value (the IP or the lower-cased hostname).
    pub fn value_str(&self) -> String {
        match self {
            Self::Ip(ip) => ip.to_string(),
            Self::Host(h) => h.clone(),
        }
    }

    /// Reconstruct from a `(target_kind, target)` pair. `None` on an unparseable
    /// IP or an empty host — the caller drops the row.
    ///
    /// An address literal is an `Ip` whichever kind it arrived as: a "host"
    /// that is really an address would go to the name cache and resolve to
    /// nothing, leaving the resolver unblocked. A v4-mapped v6 spelling
    /// collapses to its v4 address so one resolver cannot hold two rows.
    pub fn parse(kind: &str, value: &str) -> Option<Self> {
        let v = value.trim();
        match kind {
            "ip" | "host" => {
                if let Ok(ip) = v.parse::<IpAddr>() {
                    return Some(Self::Ip(ip.to_canonical()));
                }
                if kind == "host" && !v.is_empty() {
                    Some(Self::Host(v.to_ascii_lowercase()))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// One resolver-list entry (a row of the shared `doh_resolver_entries` baseline).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DohResolverEntry {
    pub target: DohTarget,
    /// Free-text note (provider/country), shown in the GUI editor.
    pub comment: String,
    /// Whether this entry participates in the lockdown (per-row toggle).
    pub enabled: bool,
}

/// Repository over the shared `doh_resolver_entries` baseline table (no `sid` —
/// machine-wide). Full-replacement semantics like the link-provider repo.
pub struct DohResolverEntriesRepository<'a> {
    conn: &'a Connection,
}

impl<'a> DohResolverEntriesRepository<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Load every resolver entry, ordered by `(target_kind, target)` for a stable
    /// GUI list. Rows whose `(target_kind, target)` fail to parse are skipped
    /// (defensive — the CHECK constraint should prevent them).
    pub fn load_all(&self) -> StorageResult<Vec<DohResolverEntry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT target_kind, target, comment, enabled
                 FROM doh_resolver_entries ORDER BY target_kind ASC, target ASC",
            )
            .map_err(|e| StorageError::Internal(format!("prepare doh entries: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| StorageError::Internal(format!("query doh entries: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (kind, value, comment, enabled) =
                row.map_err(|e| StorageError::Internal(format!("row doh entries: {e}")))?;
            if let Some(target) = DohTarget::parse(&kind, &value) {
                out.push(DohResolverEntry {
                    target,
                    comment,
                    enabled: enabled != 0,
                });
            }
        }
        Ok(out)
    }

    /// Replace the ENTIRE resolver list with `entries` in one transaction
    /// (delete-all + insert). Duplicate `(kind, target)` pairs are collapsed
    /// (last wins). `now_epoch_secs` stamps every row.
    pub fn replace_all(
        &self,
        entries: &[DohResolverEntry],
        now_epoch_secs: i64,
    ) -> StorageResult<()> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| StorageError::Internal(format!("begin doh tx: {e}")))?;
        tx.execute("DELETE FROM doh_resolver_entries", [])
            .map_err(|e| StorageError::Internal(format!("clear doh entries: {e}")))?;
        for e in entries {
            tx.execute(
                "INSERT INTO doh_resolver_entries (target_kind, target, comment, enabled, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(target_kind, target) DO UPDATE SET
                    comment = excluded.comment,
                    enabled = excluded.enabled,
                    updated_at = excluded.updated_at",
                params![
                    e.target.kind_str(),
                    e.target.value_str(),
                    e.comment,
                    e.enabled as i64,
                    now_epoch_secs,
                ],
            )
            .map_err(|err| StorageError::Internal(format!("insert doh entry: {err}")))?;
        }
        tx.commit()
            .map_err(|e| StorageError::Internal(format!("commit doh tx: {e}")))?;
        Ok(())
    }

    /// Bring the list up to the built-in seed `seed_version`.
    ///
    /// An empty list takes every entry. Otherwise only entries introduced after
    /// the last applied version are added, and only where absent: a row the user
    /// deleted belongs to an applied version, so it never comes back, and a row
    /// the user edited keeps the edit. A `retired` entry withdrawn after that
    /// version is removed only while it still carries its seeded comment — rows
    /// record no origin, and a changed comment is the one sign of a user's hand.
    /// Rows and version land in one transaction.
    pub fn apply_seed(
        &self,
        entries: &[SeedEntry],
        retired: &[RetiredSeedEntry],
        seed_version: u32,
        now_epoch_secs: i64,
    ) -> StorageResult<SeedApplied> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| StorageError::Internal(format!("begin doh seed tx: {e}")))?;
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM doh_resolver_entries", [], |r| {
                r.get(0)
            })
            .map_err(|e| StorageError::Internal(format!("count doh entries: {e}")))?;
        let floor = if count == 0 {
            0
        } else {
            // A list seeded before the seed was versioned holds version 1.
            let applied = applied_seed_version(&tx)?.unwrap_or(1);
            if applied >= seed_version {
                return Ok(SeedApplied::default());
            }
            applied
        };
        let mut removed = 0;
        for r in retired.iter().filter(|r| r.retired_in > floor) {
            removed += tx
                .execute(
                    "DELETE FROM doh_resolver_entries
                     WHERE target_kind = ?1 AND target = ?2 AND comment = ?3",
                    params![r.target.kind_str(), r.target.value_str(), r.comment],
                )
                .map_err(|err| StorageError::Internal(format!("retire doh seed entry: {err}")))?;
        }
        let mut inserted = 0;
        for s in entries.iter().filter(|s| s.since > floor) {
            let e = &s.entry;
            inserted += tx
                .execute(
                    "INSERT INTO doh_resolver_entries (target_kind, target, comment, enabled, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(target_kind, target) DO NOTHING",
                    params![
                        e.target.kind_str(),
                        e.target.value_str(),
                        e.comment,
                        e.enabled as i64,
                        now_epoch_secs,
                    ],
                )
                .map_err(|err| StorageError::Internal(format!("insert doh seed entry: {err}")))?;
        }
        tx.execute(
            "INSERT OR IGNORE INTO migration_state (sid, migration_id, completed_at)
             VALUES (?1, ?2, ?3)",
            params![
                BASELINE_PRINCIPAL,
                format!("{SEED_MARKER_PREFIX}{seed_version}"),
                now_epoch_secs
            ],
        )
        .map_err(|e| StorageError::Internal(format!("mark doh seed version: {e}")))?;
        tx.commit()
            .map_err(|e| StorageError::Internal(format!("commit doh seed tx: {e}")))?;
        Ok(SeedApplied { inserted, removed })
    }

    /// The highest built-in seed version applied to this list, if any.
    pub fn applied_seed_version(&self) -> StorageResult<Option<u32>> {
        applied_seed_version(self.conn)
    }
}

/// A built-in seed entry and the seed version that introduced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedEntry {
    pub entry: DohResolverEntry,
    pub since: u32,
}

/// A built-in entry a later seed version withdrew; `comment` is the one it was
/// seeded with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetiredSeedEntry {
    pub target: DohTarget,
    pub comment: String,
    pub retired_in: u32,
}

/// What [`DohResolverEntriesRepository::apply_seed`] changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SeedApplied {
    pub inserted: usize,
    pub removed: usize,
}

/// The applied seed version is a machine fact, so it is a one-time marker in
/// the migration ledger under the baseline principal: one row per version.
const SEED_MARKER_PREFIX: &str = "doh-resolver-seed-v";

fn applied_seed_version(conn: &Connection) -> StorageResult<Option<u32>> {
    let mut stmt = conn
        .prepare(
            "SELECT migration_id FROM migration_state
             WHERE sid = ?1 AND migration_id LIKE 'doh-resolver-seed-v%'",
        )
        .map_err(|e| StorageError::Internal(format!("prepare doh seed version: {e}")))?;
    let ids = stmt
        .query_map([BASELINE_PRINCIPAL], |r| r.get::<_, String>(0))
        .map_err(|e| StorageError::Internal(format!("query doh seed version: {e}")))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| StorageError::Internal(format!("row doh seed version: {e}")))?;
    Ok(ids
        .iter()
        .filter_map(|id| id.strip_prefix(SEED_MARKER_PREFIX)?.parse::<u32>().ok())
        .max())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn seeded_conn() -> Connection {
        use crate::migration::SqliteMigrationRunner;
        use crate::repository::MigrationRunner;
        let conn = Connection::open_in_memory().expect("in-memory");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        runner.into_connection()
    }

    #[test]
    fn resolver_entries_replace_load_roundtrip() {
        let conn = seeded_conn();
        let repo = DohResolverEntriesRepository::new(&conn);
        assert!(repo.load_all().expect("load empty").is_empty());

        let entries = vec![
            DohResolverEntry {
                target: DohTarget::Ip(Ipv4Addr::new(198, 51, 100, 8).into()),
                comment: "Google".into(),
                enabled: true,
            },
            DohResolverEntry {
                target: DohTarget::Host("resolver.example".into()),
                comment: "Google DoH host".into(),
                enabled: false,
            },
        ];
        repo.replace_all(&entries, 1000).expect("replace");
        let loaded = repo.load_all().expect("load");
        assert_eq!(loaded.len(), 2);
        // Ordered host before ip? Order is (target_kind ASC): 'host' < 'ip'.
        assert_eq!(loaded[0].target, DohTarget::Host("resolver.example".into()));
        assert!(!loaded[0].enabled);
        assert_eq!(
            loaded[1].target,
            DohTarget::Ip(Ipv4Addr::new(198, 51, 100, 8).into())
        );
        assert!(loaded[1].enabled);
    }

    fn seed_ip(last: u8, since: u32) -> SeedEntry {
        SeedEntry {
            entry: DohResolverEntry {
                target: DohTarget::Ip(Ipv4Addr::new(192, 0, 2, last).into()),
                comment: format!("seed {last}"),
                enabled: true,
            },
            since,
        }
    }

    fn targets(repo: &DohResolverEntriesRepository<'_>) -> Vec<String> {
        let mut t: Vec<String> = repo
            .load_all()
            .expect("load")
            .into_iter()
            .map(|e| e.target.value_str())
            .collect();
        t.sort();
        t
    }

    #[test]
    fn fresh_list_takes_every_seed_entry_and_records_the_version() {
        let conn = seeded_conn();
        let repo = DohResolverEntriesRepository::new(&conn);
        let seed = [seed_ip(1, 1), seed_ip(2, 2)];
        assert_eq!(repo.apply_seed(&seed, &[], 2, 1).expect("seed").inserted, 2);
        assert_eq!(repo.applied_seed_version().expect("version"), Some(2));
        assert_eq!(
            repo.apply_seed(&seed, &[], 2, 2).expect("again").inserted,
            0
        );
    }

    #[test]
    fn newer_seed_adds_only_new_rows_and_never_restores_a_deleted_one() {
        let conn = seeded_conn();
        let repo = DohResolverEntriesRepository::new(&conn);
        let v1 = [seed_ip(1, 1), seed_ip(2, 1)];
        repo.apply_seed(&v1, &[], 1, 1).expect("v1");
        // The user deletes one v1 row and disables the other.
        let mut kept = repo.load_all().expect("load");
        kept.retain(|e| e.target.value_str() == "192.0.2.1");
        kept[0].enabled = false;
        repo.replace_all(&kept, 2).expect("user edit");

        let v2 = [seed_ip(1, 1), seed_ip(2, 1), seed_ip(3, 2)];
        assert_eq!(repo.apply_seed(&v2, &[], 2, 3).expect("v2").inserted, 1);
        assert_eq!(targets(&repo), ["192.0.2.1", "192.0.2.3"]);
        assert!(
            !repo.load_all().expect("load")[0].enabled,
            "user edit survives"
        );
        assert_eq!(repo.applied_seed_version().expect("version"), Some(2));

        assert_eq!(repo.apply_seed(&v2, &[], 2, 4).expect("rerun").inserted, 0);
        assert_eq!(targets(&repo), ["192.0.2.1", "192.0.2.3"]);
    }

    fn retired_ip(last: u8, retired_in: u32) -> RetiredSeedEntry {
        let s = seed_ip(last, 1);
        RetiredSeedEntry {
            target: s.entry.target,
            comment: s.entry.comment,
            retired_in,
        }
    }

    /// A withdrawn entry leaves an install that still holds it as seeded; one
    /// whose comment the user changed stays, and a rerun changes nothing.
    #[test]
    fn a_retired_entry_is_removed_only_while_it_is_still_the_seeded_row() {
        let conn = seeded_conn();
        let repo = DohResolverEntriesRepository::new(&conn);
        repo.apply_seed(&[seed_ip(1, 1), seed_ip(2, 1), seed_ip(3, 1)], &[], 1, 1)
            .expect("v1");
        let mut rows = repo.load_all().expect("load");
        for row in rows.iter_mut() {
            match row.target.value_str().as_str() {
                "192.0.2.2" => row.comment = "my resolver".into(),
                "192.0.2.3" => row.enabled = false,
                _ => {}
            }
        }
        repo.replace_all(&rows, 2).expect("user edit");

        let retired = [retired_ip(1, 2), retired_ip(2, 2), retired_ip(3, 2)];
        let applied = repo
            .apply_seed(&[seed_ip(4, 2)], &retired, 2, 3)
            .expect("v2");
        assert_eq!(
            applied,
            SeedApplied {
                inserted: 1,
                removed: 2
            }
        );
        assert_eq!(targets(&repo), ["192.0.2.2", "192.0.2.4"]);

        // Withdrawn at a version already applied: never acted on again.
        let later = repo.apply_seed(&[], &[retired_ip(4, 2)], 3, 5).expect("v3");
        assert_eq!(later, SeedApplied::default());
        assert_eq!(targets(&repo), ["192.0.2.2", "192.0.2.4"]);
    }

    /// Installs seeded before the seed carried a version hold version 1.
    #[test]
    fn a_list_without_a_recorded_version_counts_as_version_one() {
        let conn = seeded_conn();
        let repo = DohResolverEntriesRepository::new(&conn);
        repo.replace_all(&[seed_ip(1, 1).entry], 1)
            .expect("legacy seed");
        assert_eq!(repo.applied_seed_version().expect("version"), None);
        let v2 = [seed_ip(1, 1), seed_ip(2, 1), seed_ip(3, 2)];
        assert_eq!(repo.apply_seed(&v2, &[], 2, 2).expect("v2").inserted, 1);
        assert_eq!(targets(&repo), ["192.0.2.1", "192.0.2.3"]);
    }

    /// The marker is a machine fact; a user's full reset must not erase it.
    #[test]
    fn seed_version_is_not_a_users_state() {
        let conn = seeded_conn();
        let repo = DohResolverEntriesRepository::new(&conn);
        repo.apply_seed(&[seed_ip(1, 1)], &[], 1, 1).expect("seed");
        assert!(crate::principal_purge::principals_with_state(&conn)
            .expect("principals")
            .is_empty());
    }

    #[test]
    fn scope_code_and_slug_roundtrip() {
        for s in [
            DohLockdownScope::LeakProtectionOnly,
            DohLockdownScope::Always,
        ] {
            assert_eq!(DohLockdownScope::from_code(s.as_code()), Some(s));
            assert_eq!(DohLockdownScope::from_slug(s.as_slug()), Some(s));
        }
        assert!(DohLockdownScope::from_code(2).is_none());
        assert!(DohLockdownScope::from_slug("nope").is_none());
        assert_eq!(
            DohLockdownScope::default(),
            DohLockdownScope::LeakProtectionOnly
        );
    }

    #[test]
    fn target_parse_and_render() {
        let ip = DohTarget::parse("ip", "198.51.100.8").expect("ip");
        assert_eq!(ip, DohTarget::Ip(Ipv4Addr::new(198, 51, 100, 8).into()));
        assert_eq!(ip.kind_str(), "ip");
        assert_eq!(ip.value_str(), "198.51.100.8");

        let host = DohTarget::parse("host", "RESOLVER.Example").expect("host");
        assert_eq!(host, DohTarget::Host("resolver.example".into()));
        assert_eq!(host.kind_str(), "host");

        assert!(DohTarget::parse("ip", "not-an-ip").is_none());
        assert!(DohTarget::parse("host", "  ").is_none());
        assert!(DohTarget::parse("subnet", "1.2.3.0/24").is_none());
    }

    #[test]
    fn both_families_roundtrip_through_the_table() {
        let conn = seeded_conn();
        let repo = DohResolverEntriesRepository::new(&conn);
        let v6: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53).into();
        let entries = vec![
            DohResolverEntry {
                target: DohTarget::Ip(Ipv4Addr::new(192, 0, 2, 53).into()),
                comment: "v4".into(),
                enabled: true,
            },
            DohResolverEntry {
                target: DohTarget::Ip(v6),
                comment: "v6".into(),
                enabled: true,
            },
        ];
        repo.replace_all(&entries, 1).expect("replace");
        let loaded = repo.load_all().expect("load");
        assert_eq!(loaded.len(), 2);
        assert!(loaded.iter().any(|e| e.target == DohTarget::Ip(v6)));
        assert!(loaded
            .iter()
            .any(|e| e.target == DohTarget::Ip(Ipv4Addr::new(192, 0, 2, 53).into())));
    }

    /// A row written while the list held IPv4 only is plain text in the same
    /// columns; it must still decode.
    #[test]
    fn a_v4_row_written_directly_still_decodes() {
        let conn = seeded_conn();
        conn.execute(
            "INSERT INTO doh_resolver_entries (target_kind, target, comment, enabled, updated_at)
             VALUES ('ip', '192.0.2.1', 'old', 1, 0)",
            [],
        )
        .expect("insert");
        let loaded = DohResolverEntriesRepository::new(&conn)
            .load_all()
            .expect("load");
        assert_eq!(
            loaded[0].target,
            DohTarget::Ip(Ipv4Addr::new(192, 0, 2, 1).into())
        );
    }

    #[test]
    fn v6_targets_parse_and_normalise() {
        let v6 = DohTarget::parse("ip", " 2001:DB8::0053 ").expect("v6");
        assert_eq!(v6.kind_str(), "ip");
        assert_eq!(v6.value_str(), "2001:db8::53");
        // An address typed into the host field is still an address.
        assert_eq!(DohTarget::parse("host", "2001:db8::53"), Some(v6));
        assert_eq!(
            DohTarget::parse("host", "192.0.2.7"),
            Some(DohTarget::Ip(Ipv4Addr::new(192, 0, 2, 7).into()))
        );
        // One resolver, one row: the v4-mapped spelling is the v4 address.
        assert_eq!(
            DohTarget::parse("ip", "::ffff:192.0.2.7"),
            Some(DohTarget::Ip(Ipv4Addr::new(192, 0, 2, 7).into()))
        );
        assert!(DohTarget::parse("ip", "2001:db8::/32").is_none());
    }
}
