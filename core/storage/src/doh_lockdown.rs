//! DoH/DoT lockdown domain types + persistence.
//!
//! The lockdown blocks browser DNS-over-HTTPS/TLS so the DNS observer sees
//! plaintext queries again (the dzen.ru blind-spot class). Two pieces of state:
//!
//! - a **per-SID** enable toggle + application scope (in `secondary_block_policy`,
//!   alongside the other kill-switch fields) — each user decides whether to apply
//!   the lockdown to their own traffic and when;
//! - a **shared baseline** list of resolver entries (the `doh_resolver_entries`
//!   table) — the resolver set is a machine-wide fact, edited once (with
//!   elevation), pre-filled with public resolvers by country.
//!
//! Subnets/CIDR are a Pro feature; a Free entry is a single IPv4 or a hostname
//! (resolved to `/32`s by the enforcement layer).

use std::net::Ipv4Addr;

use rusqlite::{params, Connection};

use crate::error::{StorageError, StorageResult};

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

/// A resolver-list entry target. Free: a literal IPv4 (blocked directly) or a
/// hostname (the enforcement layer resolves it to `/32`s). CIDR/subnets = Pro.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DohTarget {
    /// A single IPv4 resolver address.
    Ip(Ipv4Addr),
    /// A resolver hostname (e.g. `dns.google`), resolved to IPs at apply time.
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
    pub fn parse(kind: &str, value: &str) -> Option<Self> {
        let v = value.trim();
        match kind {
            "ip" => v.parse::<Ipv4Addr>().ok().map(Self::Ip),
            "host" => {
                if v.is_empty() {
                    None
                } else {
                    Some(Self::Host(v.to_ascii_lowercase()))
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

    /// Seed the list with `entries` ONLY if it is currently empty (first run).
    /// Returns the number of rows inserted (0 if the list already had entries, so
    /// a user's edits are never overwritten). Idempotent across restarts.
    pub fn seed_if_empty(
        &self,
        entries: &[DohResolverEntry],
        now_epoch_secs: i64,
    ) -> StorageResult<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM doh_resolver_entries", [], |r| {
                r.get(0)
            })
            .map_err(|e| StorageError::Internal(format!("count doh entries: {e}")))?;
        if count > 0 {
            return Ok(0);
        }
        self.replace_all(entries, now_epoch_secs)?;
        Ok(entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                target: DohTarget::Ip(Ipv4Addr::new(8, 8, 8, 8)),
                comment: "Google".into(),
                enabled: true,
            },
            DohResolverEntry {
                target: DohTarget::Host("dns.google".into()),
                comment: "Google DoH host".into(),
                enabled: false,
            },
        ];
        repo.replace_all(&entries, 1000).expect("replace");
        let loaded = repo.load_all().expect("load");
        assert_eq!(loaded.len(), 2);
        // Ordered host before ip? Order is (target_kind ASC): 'host' < 'ip'.
        assert_eq!(loaded[0].target, DohTarget::Host("dns.google".into()));
        assert!(!loaded[0].enabled);
        assert_eq!(loaded[1].target, DohTarget::Ip(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(loaded[1].enabled);
    }

    #[test]
    fn seed_if_empty_only_seeds_once() {
        let conn = seeded_conn();
        let repo = DohResolverEntriesRepository::new(&conn);
        let seed = vec![DohResolverEntry {
            target: DohTarget::Ip(Ipv4Addr::new(1, 1, 1, 1)),
            comment: "Cloudflare".into(),
            enabled: true,
        }];
        assert_eq!(repo.seed_if_empty(&seed, 1).expect("seed"), 1);
        // Second call is a no-op — user edits (even removing all) are respected
        // only while non-empty; here the list is non-empty so nothing re-seeds.
        assert_eq!(repo.seed_if_empty(&seed, 2).expect("reseed"), 0);
        assert_eq!(repo.load_all().expect("load").len(), 1);
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
        let ip = DohTarget::parse("ip", "8.8.8.8").expect("ip");
        assert_eq!(ip, DohTarget::Ip(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(ip.kind_str(), "ip");
        assert_eq!(ip.value_str(), "8.8.8.8");

        let host = DohTarget::parse("host", "DNS.Google").expect("host");
        assert_eq!(host, DohTarget::Host("dns.google".into()));
        assert_eq!(host.kind_str(), "host");

        assert!(DohTarget::parse("ip", "not-an-ip").is_none());
        assert!(DohTarget::parse("host", "  ").is_none());
        assert!(DohTarget::parse("subnet", "1.2.3.0/24").is_none());
    }
}
