//! The revision an activation is applying, served to every rules read in the
//! window between phase 2 (kernel state installed) and phase 3a (active pointer
//! committed). Readers in that window would otherwise see the previous revision
//! and undo or miss what phase 2 just installed.
//!
//! Keyed by state-DB path: every connection to one database shares its pointer,
//! so they share the overlay too, and no wiring can hand a reader a different
//! instance. An in-memory database has no path and never overlays.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, PoisonError, RwLock};

use rusqlite::Connection;

struct Entry {
    principal: String,
    rules_json: Arc<str>,
    generation: u64,
}

/// Moves on every publish and withdrawal, on any database.
static CHANGES: AtomicU64 = AtomicU64::new(0);

/// A number that moves whenever what the overlay serves changes. An
/// enforcement pass counts it among its inputs: a pass settled from an overlay
/// that is then withdrawn with no stored write (an unrecorded commit) would
/// otherwise keep the withdrawn rules until the next full pass.
pub(crate) fn changes() -> u64 {
    CHANGES.load(Ordering::Acquire)
}

fn registry() -> &'static RwLock<HashMap<String, Entry>> {
    static REGISTRY: OnceLock<RwLock<HashMap<String, Entry>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

fn key_of(conn: &Connection) -> Option<String> {
    conn.path().filter(|p| !p.is_empty()).map(str::to_owned)
}

/// Withdraws the overlay on drop.
#[must_use = "the overlay is withdrawn when the guard drops"]
pub(crate) struct OverlayGuard {
    slot: Option<(String, u64)>,
}

impl Drop for OverlayGuard {
    fn drop(&mut self) {
        let Some((key, generation)) = self.slot.take() else {
            return;
        };
        let mut map = registry().write().unwrap_or_else(PoisonError::into_inner);
        // Only our own entry: a newer publish on the same database must survive.
        if map.get(&key).is_some_and(|e| e.generation == generation) {
            map.remove(&key);
            CHANGES.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// Serve `rules_json` as `principal`'s rules until the guard drops.
pub(crate) fn publish(conn: &Connection, principal: &str, rules_json: &str) -> OverlayGuard {
    static GENERATION: AtomicU64 = AtomicU64::new(0);
    let Some(key) = key_of(conn) else {
        return OverlayGuard { slot: None };
    };
    let generation = GENERATION.fetch_add(1, Ordering::Relaxed);
    registry()
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(
            key.clone(),
            Entry {
                principal: principal.to_owned(),
                rules_json: Arc::from(rules_json),
                generation,
            },
        );
    CHANGES.fetch_add(1, Ordering::AcqRel);
    OverlayGuard {
        slot: Some((key, generation)),
    }
}

/// The rules-JSON being applied for exactly `principal`, if any.
pub(crate) fn applying_for(conn: &Connection, principal: &str) -> Option<Arc<str>> {
    let key = key_of(conn)?;
    let map = registry().read().unwrap_or_else(PoisonError::into_inner);
    map.get(&key)
        .filter(|e| e.principal == principal)
        .map(|e| Arc::clone(&e.rules_json))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn file_conn(dir: &tempfile::TempDir, name: &str) -> Connection {
        Connection::open(dir.path().join(name)).expect("open")
    }

    #[test]
    fn serves_only_the_published_principal_until_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = file_conn(&dir, "state.db");
        let guard = publish(&conn, "S-A", "{new}");
        assert_eq!(applying_for(&conn, "S-A").as_deref(), Some("{new}"));
        assert_eq!(applying_for(&conn, "S-B"), None);
        drop(guard);
        assert_eq!(applying_for(&conn, "S-A"), None);
    }

    #[test]
    fn another_connection_to_the_same_file_sees_it_and_other_files_do_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = file_conn(&dir, "state.db");
        let reader = file_conn(&dir, "state.db");
        let other = file_conn(&dir, "other.db");
        let _guard = publish(&writer, "S-A", "{new}");
        assert_eq!(applying_for(&reader, "S-A").as_deref(), Some("{new}"));
        assert_eq!(applying_for(&other, "S-A"), None);
    }

    #[test]
    fn a_stale_guard_does_not_withdraw_a_newer_publish() {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = file_conn(&dir, "state.db");
        let old = publish(&conn, "S-A", "{old}");
        let _new = publish(&conn, "S-A", "{new}");
        drop(old);
        assert_eq!(applying_for(&conn, "S-A").as_deref(), Some("{new}"));
    }

    #[test]
    fn publishing_and_withdrawing_both_move_the_change_number() {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = file_conn(&dir, "state.db");
        let before = changes();
        let guard = publish(&conn, "S-A", "{new}");
        let published = changes();
        assert!(published > before);
        drop(guard);
        assert!(changes() > published);
    }

    #[test]
    fn in_memory_database_never_overlays() {
        let conn = Connection::open_in_memory().expect("open");
        let _guard = publish(&conn, "S-A", "{new}");
        assert_eq!(applying_for(&conn, "S-A"), None);
    }
}
