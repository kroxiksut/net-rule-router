//! `external_ip_cache` table — last-known external (reflexive) IPv4
//! address per adapter.
//!
//! The GUI never probes for an external address on its own (see
//! `core/platform/api/src/external_ip/probe.rs` for the only probe
//! path, which runs inside the service). This table only remembers the
//! last address the service actually reported, so the Interfaces
//! screen can paint a muted "last known" hint while the service is
//! unreachable instead of going blank.
//!
//! Sparse, like `rule_metadata`: an adapter that was never resolved
//! has no row. Keyed by [`ExternalIpCacheEntry`]'s caller-supplied
//! adapter key (persistent adapter id, or a name-derived fallback for
//! adapters that never got one) rather than by route role — several
//! adapters can carry a resolved address at once, not just the ones
//! currently bound to primary/secondary.

use std::collections::BTreeMap;

use rusqlite::params;

use crate::db::SidecarDb;
use crate::error::SidecarResult;

/// One cached observation: the address and when it was observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalIpCacheEntry {
    pub external_ip: String,
    pub observed_at_ms: i64,
}

impl SidecarDb {
    /// Every cached entry, keyed by adapter key.
    pub fn read_all_external_ip_cache(
        &self,
    ) -> SidecarResult<BTreeMap<String, ExternalIpCacheEntry>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT adapter_key, external_ip, observed_at FROM external_ip_cache")?;
        let mut rows = stmt.query([])?;
        let mut out = BTreeMap::new();
        while let Some(row) = rows.next()? {
            let key: String = row.get(0)?;
            out.insert(
                key,
                ExternalIpCacheEntry {
                    external_ip: row.get(1)?,
                    observed_at_ms: row.get(2)?,
                },
            );
        }
        Ok(out)
    }

    /// Upsert every entry in one transaction. The GUI hands over the
    /// whole snapshot's worth of resolved addresses in a single RPC
    /// rather than one round trip per adapter.
    pub fn write_external_ip_cache_entries(
        &self,
        entries: &[(String, String, i64)],
    ) -> SidecarResult<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn_mut();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO external_ip_cache (adapter_key, external_ip, observed_at)
                     VALUES (?1, ?2, ?3)
                 ON CONFLICT(adapter_key) DO UPDATE SET
                     external_ip = excluded.external_ip,
                     observed_at = excluded.observed_at",
            )?;
            for (key, ip, observed_at_ms) in entries {
                stmt.execute(params![key, ip, observed_at_ms])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SidecarDb;

    fn open_sidecar(tmp: &tempfile::TempDir) -> SidecarResult<SidecarDb> {
        let path = tmp.path().join("sidecar.db");
        SidecarDb::open(&path)
    }

    #[test]
    fn empty_reads_as_empty_map() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        assert!(db.read_all_external_ip_cache()?.is_empty());
        Ok(())
    }

    #[test]
    fn write_then_read_roundtrip() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_external_ip_cache_entries(&[
            ("adapter-a".to_string(), "203.0.113.10".to_string(), 1_000),
            ("adapter-b".to_string(), "198.51.100.7".to_string(), 2_000),
        ])?;
        let all = db.read_all_external_ip_cache()?;
        assert_eq!(all.len(), 2);
        assert_eq!(all["adapter-a"].external_ip, "203.0.113.10");
        assert_eq!(all["adapter-a"].observed_at_ms, 1_000);
        assert_eq!(all["adapter-b"].external_ip, "198.51.100.7");
        Ok(())
    }

    #[test]
    fn write_overwrites_previous_entry_for_same_key() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_external_ip_cache_entries(&[(
            "adapter-a".to_string(),
            "203.0.113.10".to_string(),
            1_000,
        )])?;
        db.write_external_ip_cache_entries(&[(
            "adapter-a".to_string(),
            "203.0.113.20".to_string(),
            5_000,
        )])?;
        let all = db.read_all_external_ip_cache()?;
        assert_eq!(all.len(), 1);
        assert_eq!(all["adapter-a"].external_ip, "203.0.113.20");
        assert_eq!(all["adapter-a"].observed_at_ms, 5_000);
        Ok(())
    }

    #[test]
    fn empty_batch_is_a_noop() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_external_ip_cache_entries(&[])?;
        assert!(db.read_all_external_ip_cache()?.is_empty());
        Ok(())
    }

    #[test]
    fn unicode_key_survives_reopen() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("sidecar.db");
        {
            let db = SidecarDb::open(&path)?;
            db.write_external_ip_cache_entries(&[(
                "name:Беспроводная сеть".to_string(),
                "203.0.113.55".to_string(),
                42,
            )])?;
        }
        let db = SidecarDb::open(&path)?;
        let all = db.read_all_external_ip_cache()?;
        assert_eq!(all["name:Беспроводная сеть"].external_ip, "203.0.113.55");
        Ok(())
    }
}
