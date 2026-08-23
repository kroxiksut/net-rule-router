//! Durable per-SID backlog of block notices nobody was there to see.
//!
//! A port, like [`crate::block_notice_mute_store`], and for the same reason:
//! the IPC handlers must run without a database, and a degraded boot answers
//! "nothing pending" rather than refusing to serve.
//!
//! The backlog exists because the push channel is live-only. With the tray off
//! and the window closed — the shape a user gets by leaving "run the tray at
//! sign-in" unticked — a raised notice reached the log and no one else.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use nrr_domain::block_notice::BlockNotice;
use nrr_storage::block_notice_journal::JournalledNotice;
use rusqlite::Connection;

/// Append-and-drain over one principal's undelivered notices.
pub trait BlockNoticeJournalStore: Send + Sync {
    /// Record a notice that was raised. Best-effort by contract: a write
    /// failure costs the backlog entry, never the live notice.
    fn append(&self, sid: &str, notice: &BlockNotice, now_ms: i64);

    /// Everything `sid` has not been shown, oldest first.
    fn list_pending(&self, sid: &str, now_ms: i64) -> Vec<JournalledNotice>;

    /// Drop everything up to and including `through_id` — shown at last.
    fn ack_through(&self, sid: &str, through_id: i64) -> usize;
}

/// In-memory store: tests, and the fallback when the state DB is unavailable.
#[derive(Default)]
pub struct InMemoryBlockNoticeJournalStore {
    by_sid: Mutex<HashMap<String, Vec<JournalledNotice>>>,
    next_id: Mutex<i64>,
}

impl InMemoryBlockNoticeJournalStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BlockNoticeJournalStore for InMemoryBlockNoticeJournalStore {
    fn append(&self, sid: &str, notice: &BlockNotice, now_ms: i64) {
        if sid.is_empty() {
            return;
        }
        let id = {
            let mut next = self.next_id.lock().unwrap_or_else(|p| p.into_inner());
            *next += 1;
            *next
        };
        self.by_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(sid.to_string())
            .or_default()
            .push(JournalledNotice {
                id,
                raised_at_ms: now_ms,
                notice: notice.clone(),
            });
    }

    fn list_pending(&self, sid: &str, _now_ms: i64) -> Vec<JournalledNotice> {
        self.by_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .cloned()
            .unwrap_or_default()
    }

    fn ack_through(&self, sid: &str, through_id: i64) -> usize {
        let mut guard = self.by_sid.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = guard.get_mut(sid) else {
            return 0;
        };
        let before = entry.len();
        entry.retain(|e| e.id > through_id);
        before - entry.len()
    }
}

/// State-DB-backed store — the production implementation.
pub struct SqliteBlockNoticeJournalStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteBlockNoticeJournalStore {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

impl BlockNoticeJournalStore for SqliteBlockNoticeJournalStore {
    fn append(&self, sid: &str, notice: &BlockNotice, now_ms: i64) {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(e) = nrr_storage::block_notice_journal::BlockNoticeJournalRepository::new(&guard)
            .append(sid, notice, now_ms)
        {
            tracing::warn!(
                target: "nrr::block-notice",
                error = %e,
                "could not journal a block notice — it is lost if no surface is up",
            );
        }
    }

    fn list_pending(&self, sid: &str, now_ms: i64) -> Vec<JournalledNotice> {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        match nrr_storage::block_notice_journal::BlockNoticeJournalRepository::new(&guard)
            .list_pending(sid, now_ms)
        {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::block-notice",
                    error = %e,
                    "could not read the block-notice backlog — this session shows none",
                );
                Vec::new()
            }
        }
    }

    fn ack_through(&self, sid: &str, through_id: i64) -> usize {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        match nrr_storage::block_notice_journal::BlockNoticeJournalRepository::new(&guard)
            .ack_through(sid, through_id)
        {
            Ok(removed) => removed,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::block-notice",
                    error = %e,
                    "could not clear shown notices — they may be shown again",
                );
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_domain::block_notice::BlockReason;

    fn notice(destination: &str) -> BlockNotice {
        BlockNotice {
            destination: destination.to_string(),
            app: String::new(),
            reason: BlockReason::BlockedByRule,
            first_attempt_ms: 0,
            attempts: 1,
        }
    }

    #[test]
    fn in_memory_store_drains_only_what_was_acknowledged() {
        let store = InMemoryBlockNoticeJournalStore::new();
        store.append("S-1", &notice("a.example"), 10);
        store.append("S-1", &notice("b.example"), 20);
        let pending = store.list_pending("S-1", 30);
        assert_eq!(pending.len(), 2);

        assert_eq!(store.ack_through("S-1", pending[0].id), 1);
        let left = store.list_pending("S-1", 30);
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].notice.destination, "b.example");
    }

    #[test]
    fn in_memory_store_keeps_principals_apart() {
        let store = InMemoryBlockNoticeJournalStore::new();
        store.append("S-1", &notice("a.example"), 10);
        assert!(store.list_pending("S-2", 20).is_empty());
    }
}
