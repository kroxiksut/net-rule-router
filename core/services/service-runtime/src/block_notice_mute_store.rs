//! Durable per-SID record of block-notice mutes.
//!
//! A port rather than a concrete type for the same reason the companion-domain
//! stores are ports (`auto_rules::store`): the IPC handlers must be exercisable
//! without a database, and a degraded boot (no state DB) should still answer
//! "no mutes" rather than refusing to run.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use nrr_domain::block_notice::{Mute, MuteScope};
use rusqlite::Connection;

/// CRUD over one principal's block-notice mutes.
pub trait BlockNoticeMuteStore: Send + Sync {
    /// Every mute `sid` has active at `now_ms`.
    fn list_active(&self, sid: &str, now_ms: i64) -> Vec<Mute>;

    /// Add or refresh one mute for `sid`. Best-effort by contract — a write
    /// failure is logged and the caller sees it via the returned list not
    /// having changed.
    fn upsert(&self, sid: &str, mute: &Mute, now_ms: i64);

    /// Undo one mute. Returns whether one actually existed at that scope.
    fn remove(&self, sid: &str, scope: &MuteScope) -> bool;

    /// Drop every mute `sid` has set.
    fn clear(&self, sid: &str);
}

/// In-memory store: used by tests and as the fallback when the state DB is
/// unavailable. Mutes hold for the process lifetime only.
#[derive(Default)]
pub struct InMemoryBlockNoticeMuteStore {
    by_sid: Mutex<HashMap<String, Vec<Mute>>>,
}

impl InMemoryBlockNoticeMuteStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BlockNoticeMuteStore for InMemoryBlockNoticeMuteStore {
    fn list_active(&self, sid: &str, now_ms: i64) -> Vec<Mute> {
        let mut guard = self.by_sid.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = guard.get_mut(sid) else {
            return Vec::new();
        };
        let now_ms = now_ms as u64;
        entry.retain(|m| m.holds_at(now_ms));
        entry.clone()
    }

    fn upsert(&self, sid: &str, mute: &Mute, now_ms: i64) {
        let mut guard = self.by_sid.lock().unwrap_or_else(|p| p.into_inner());
        let entry = guard.entry(sid.to_string()).or_default();
        entry.retain(|m| m.scope != mute.scope);
        entry.push(mute.clone());
        let _ = now_ms;
    }

    fn remove(&self, sid: &str, scope: &MuteScope) -> bool {
        let mut guard = self.by_sid.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = guard.get_mut(sid) else {
            return false;
        };
        let before = entry.len();
        entry.retain(|m| &m.scope != scope);
        before != entry.len()
    }

    fn clear(&self, sid: &str) {
        self.by_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
    }
}

/// State-DB-backed store — the production implementation.
pub struct SqliteBlockNoticeMuteStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteBlockNoticeMuteStore {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

impl BlockNoticeMuteStore for SqliteBlockNoticeMuteStore {
    fn list_active(&self, sid: &str, now_ms: i64) -> Vec<Mute> {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        match nrr_storage::block_notice_mutes::BlockNoticeMutesRepository::new(&guard)
            .list_active(sid, now_ms)
        {
            Ok(mutes) => mutes,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::block-notice",
                    error = %e,
                    "could not read block-notice mutes — this session shows none active",
                );
                Vec::new()
            }
        }
    }

    fn upsert(&self, sid: &str, mute: &Mute, now_ms: i64) {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(e) = nrr_storage::block_notice_mutes::BlockNoticeMutesRepository::new(&guard)
            .upsert(sid, mute, now_ms)
        {
            tracing::warn!(
                target: "nrr::block-notice",
                error = %e,
                "could not persist a block-notice mute — it holds for this session only",
            );
        }
    }

    fn remove(&self, sid: &str, scope: &MuteScope) -> bool {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        match nrr_storage::block_notice_mutes::BlockNoticeMutesRepository::new(&guard)
            .remove(sid, scope)
        {
            Ok(existed) => existed,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::block-notice",
                    error = %e,
                    "could not remove a block-notice mute — it stays active for this session",
                );
                false
            }
        }
    }

    fn clear(&self, sid: &str) {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(e) =
            nrr_storage::block_notice_mutes::BlockNoticeMutesRepository::new(&guard).clear(sid)
        {
            tracing::warn!(
                target: "nrr::block-notice",
                error = %e,
                "could not clear block-notice mutes — some may stay active for this session",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_mute(host: &str) -> Mute {
        Mute::forever(MuteScope::Host(host.to_string()))
    }

    #[test]
    fn in_memory_store_upserts_lists_and_removes_per_sid() {
        let store = InMemoryBlockNoticeMuteStore::new();
        store.upsert("S-A", &host_mute("cdn.example"), 0);
        assert_eq!(store.list_active("S-A", 0), vec![host_mute("cdn.example")]);
        assert!(store.list_active("S-B", 0).is_empty());

        assert!(store.remove("S-A", &MuteScope::Host("cdn.example".to_string())));
        assert!(store.list_active("S-A", 0).is_empty());
        assert!(!store.remove("S-A", &MuteScope::Host("cdn.example".to_string())));
    }

    #[test]
    fn in_memory_store_re_muting_the_same_scope_replaces_not_duplicates() {
        let store = InMemoryBlockNoticeMuteStore::new();
        let scope = MuteScope::Host("cdn.example".to_string());
        store.upsert("S-A", &Mute::until(scope.clone(), 5_000), 0);
        store.upsert("S-A", &Mute::forever(scope.clone()), 0);
        let mutes = store.list_active("S-A", 0);
        assert_eq!(mutes.len(), 1);
        assert_eq!(mutes[0].until_ms, None);
    }

    #[test]
    fn in_memory_store_expired_mutes_do_not_list_as_active() {
        let store = InMemoryBlockNoticeMuteStore::new();
        store.upsert(
            "S-A",
            &Mute::until(MuteScope::Host("cdn.example".to_string()), 1_000),
            0,
        );
        assert_eq!(store.list_active("S-A", 999).len(), 1);
        assert!(store.list_active("S-A", 1_000).is_empty());
    }

    #[test]
    fn in_memory_store_clear_drops_only_the_named_sid() {
        let store = InMemoryBlockNoticeMuteStore::new();
        store.upsert("S-A", &host_mute("cdn.example"), 0);
        store.upsert("S-B", &host_mute("cdn.example"), 0);
        store.clear("S-A");
        assert!(store.list_active("S-A", 0).is_empty());
        assert_eq!(store.list_active("S-B", 0).len(), 1);
    }
}
