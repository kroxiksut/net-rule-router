//! `PersistentAppPathResolver` decorator.
//!
//! Wraps an inner [`AppPathResolver`] with a last-good persistence layer backed
//! by the state DB's `app_pattern_resolutions` table. It exists to break one half
//! of the VPN-under-kill-switch chicken-and-egg: the built-in and user VPN-client
//! exemptions resolve an exe name/glob to concrete on-disk paths, but the inner
//! resolver only sees an exe that is *currently running*, registered under
//! `App Paths`, or reachable by a bounded Program-Files walk. A VPN client that is
//! installed off the beaten path and NOT running resolves to nothing, so its
//! ALE_APP_ID exemption never installs and the kill-switch traps the very client
//! that would bring the tunnel up (observed on hardware as repeated
//! "application rules not enforced" cases).
//!
//! # Behaviour
//!
//! `resolve(pattern)`:
//! 1. Ask the inner resolver.
//! 2. Non-empty → **write-through**: persist the fresh resolution (best-effort;
//!    a storage error is logged and swallowed, never fails the resolve) and
//!    return it. This is how the table gets populated while the client IS
//!    discoverable (e.g. the first time it runs).
//! 3. Empty → **fall back**: load the persisted paths, keep only the ones that
//!    still exist on disk (`Path::is_file`), and return those (possibly empty).
//!    A since-uninstalled binary is thus not resurrected.
//!
//! The decorator is neutral (no Windows APIs) — it composes any inner resolver
//! with any state-DB connection, so it is fully unit-testable with a scripted
//! inner resolver and a temp DB.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use nrr_platform_api::AppPathResolver;
use rusqlite::Connection;

use nrr_storage::AppPatternResolutionsRepository;

/// Persistence decorator over an inner [`AppPathResolver`]. See the module docs.
pub struct PersistentAppPathResolver {
    inner: Arc<dyn AppPathResolver>,
    conn: Arc<Mutex<Connection>>,
    /// Last set written per pattern. `resolve` is called once per application
    /// rule on EVERY filter recompute — a few seconds apart, with an answer
    /// that changes when an application is installed or removed — so writing
    /// through each time put dozens of UPSERTs a tick on the shared state-DB
    /// connection, on the enforcement path, to store what was already there.
    last_written: Mutex<std::collections::HashMap<String, Vec<String>>>,
}

impl PersistentAppPathResolver {
    /// Wrap `inner`, persisting last-good resolutions through `conn` (the shared
    /// state-DB connection). The connection is locked only briefly per resolve,
    /// OUTSIDE any policy recompute, so it never re-enters a held lock.
    pub fn new(inner: Arc<dyn AppPathResolver>, conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            inner,
            conn,
            last_written: Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn now_millis() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Best-effort write-through of a fresh, non-empty resolution. A poisoned
    /// lock or storage error is logged and swallowed — persistence must never
    /// break enforcement.
    fn persist(&self, pattern: &str, paths: &[PathBuf]) {
        let as_str: Vec<String> = paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        // Unchanged since the last write — nothing to store, and the DB lock is
        // not taken at all.
        if self
            .last_written
            .lock()
            .map(|seen| seen.get(pattern).is_some_and(|prev| *prev == as_str))
            .unwrap_or(false)
        {
            return;
        }
        let Ok(guard) = self.conn.lock() else {
            tracing::warn!(
                target: "nrr::persistent-app-resolver",
                pattern,
                "state-DB lock poisoned; skipping app-path persistence (write-through)",
            );
            return;
        };
        let repo = AppPatternResolutionsRepository::new(&guard);
        match repo.upsert(pattern, &as_str, Self::now_millis()) {
            // Remembered only once it is actually stored, so a failed write is
            // retried on the next resolve rather than assumed done.
            Ok(()) => {
                if let Ok(mut seen) = self.last_written.lock() {
                    seen.insert(pattern.to_string(), as_str);
                }
            }
            Err(e) => tracing::warn!(
                target: "nrr::persistent-app-resolver",
                pattern,
                error = %e,
                "failed to persist last-good app-path resolution (write-through) — continuing",
            ),
        }
    }

    /// Load persisted paths for `pattern`, keeping only survivors that still
    /// exist on disk. A poisoned lock / storage error degrades to an empty set.
    fn load_survivors(&self, pattern: &str) -> Vec<PathBuf> {
        let Ok(guard) = self.conn.lock() else {
            tracing::warn!(
                target: "nrr::persistent-app-resolver",
                pattern,
                "state-DB lock poisoned; no persisted app-path fallback available",
            );
            return Vec::new();
        };
        let repo = AppPatternResolutionsRepository::new(&guard);
        match repo.load(pattern) {
            Ok(paths) => paths
                .into_iter()
                .map(PathBuf::from)
                .filter(|p| Path::is_file(p))
                .collect(),
            Err(e) => {
                tracing::warn!(
                    target: "nrr::persistent-app-resolver",
                    pattern,
                    error = %e,
                    "failed to load persisted app-path fallback — treating as none",
                );
                Vec::new()
            }
        }
    }
}

impl AppPathResolver for PersistentAppPathResolver {
    fn resolve(&self, name_or_glob: &str) -> Vec<PathBuf> {
        let live = self.inner.resolve(name_or_glob);
        if !live.is_empty() {
            // Fresh resolution — persist it as the new last-good and use it.
            self.persist(name_or_glob, &live);
            return live;
        }
        // Inner found nothing (client not running / not installed on a known
        // path) — fall back to the last-good on-disk survivors.
        self.load_survivors(name_or_glob)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
    use nrr_storage::repository::MigrationRunner;

    /// Scripted inner resolver: returns whatever is seeded per exact query.
    #[derive(Default)]
    struct ScriptedInner {
        map: StdMutex<HashMap<String, Vec<PathBuf>>>,
    }
    impl ScriptedInner {
        fn set(&self, q: &str, paths: Vec<PathBuf>) {
            self.map.lock().unwrap().insert(q.to_string(), paths);
        }
    }
    impl AppPathResolver for ScriptedInner {
        fn resolve(&self, q: &str) -> Vec<PathBuf> {
            self.map.lock().unwrap().get(q).cloned().unwrap_or_default()
        }
    }

    fn state_conn() -> (tempfile::TempDir, Arc<Mutex<Connection>>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("state.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        (dir, Arc::new(Mutex::new(runner.into_connection())))
    }

    /// `resolve` runs once per application rule on every filter recompute. The
    /// write-through only has something to say when the answer CHANGES.
    #[test]
    fn an_unchanged_resolution_is_not_written_again() {
        let (dir, conn) = state_conn();
        let exe = touch(&dir, "vpn.exe");
        let inner = Arc::new(ScriptedInner::default());
        inner.set("vpn.exe", vec![exe.clone()]);
        let resolver = PersistentAppPathResolver::new(inner.clone(), Arc::clone(&conn));

        let stored_at = |conn: &Arc<Mutex<Connection>>| -> i64 {
            let guard = conn.lock().expect("lock");
            guard
                .query_row(
                    "SELECT resolved_at FROM app_pattern_resolutions WHERE pattern = ?1",
                    ["vpn.exe"],
                    |r| r.get(0),
                )
                .expect("row")
        };

        assert_eq!(resolver.resolve("vpn.exe"), vec![exe.clone()]);
        let first = stored_at(&conn);

        // Rewind the stored timestamp: a second write would move it forward.
        {
            let guard = conn.lock().expect("lock");
            guard
                .execute(
                    "UPDATE app_pattern_resolutions SET resolved_at = ?1 WHERE pattern = ?2",
                    rusqlite::params![first - 10_000, "vpn.exe"],
                )
                .expect("rewind");
        }
        for _ in 0..5 {
            let _ = resolver.resolve("vpn.exe");
        }
        assert_eq!(
            stored_at(&conn),
            first - 10_000,
            "an unchanged answer must not touch the row"
        );

        // A changed answer is written.
        let other = touch(&dir, "vpn2.exe");
        inner.set("vpn.exe", vec![other.clone()]);
        assert_eq!(resolver.resolve("vpn.exe"), vec![other]);
        assert!(stored_at(&conn) > first - 10_000);
    }

    /// Create a real on-disk file so `Path::is_file` survivor filtering passes.
    fn touch(dir: &tempfile::TempDir, name: &str) -> PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, b"x").expect("write file");
        p
    }

    #[test]
    fn write_through_persists_a_fresh_resolution() {
        let (dir, conn) = state_conn();
        let real = touch(&dir, "openvpn.exe");
        let inner = Arc::new(ScriptedInner::default());
        inner.set("openvpn*", vec![real.clone()]);
        let resolver = PersistentAppPathResolver::new(inner, Arc::clone(&conn));

        // Live resolution is returned as-is…
        assert_eq!(resolver.resolve("openvpn*"), vec![real.clone()]);
        // …and persisted for next time.
        let guard = conn.lock().unwrap();
        let persisted = AppPatternResolutionsRepository::new(&guard)
            .load("openvpn*")
            .expect("load");
        assert_eq!(persisted, vec![real.to_string_lossy().into_owned()]);
    }

    #[test]
    fn falls_back_to_persisted_when_inner_is_empty() {
        let (dir, conn) = state_conn();
        let real = touch(&dir, "openvpn.exe");
        // Seed the DB with a last-good resolution (as if a prior run persisted it).
        {
            let guard = conn.lock().unwrap();
            AppPatternResolutionsRepository::new(&guard)
                .upsert("openvpn*", &[real.to_string_lossy().into_owned()], 100)
                .expect("seed");
        }
        // Inner resolver now knows nothing (client not running).
        let inner = Arc::new(ScriptedInner::default());
        let resolver = PersistentAppPathResolver::new(inner, Arc::clone(&conn));

        assert_eq!(
            resolver.resolve("openvpn*"),
            vec![real],
            "empty inner falls back to the persisted survivor",
        );
    }

    #[test]
    fn fallback_filters_out_dead_paths() {
        let (_dir, conn) = state_conn();
        // Persist a path that does NOT exist on disk.
        {
            let guard = conn.lock().unwrap();
            AppPatternResolutionsRepository::new(&guard)
                .upsert("gone*", &[r"C:\definitely\missing.exe".to_string()], 100)
                .expect("seed");
        }
        let inner = Arc::new(ScriptedInner::default());
        let resolver = PersistentAppPathResolver::new(inner, conn);
        assert!(
            resolver.resolve("gone*").is_empty(),
            "a since-uninstalled binary is not resurrected",
        );
    }

    #[test]
    fn write_through_supersedes_stale_persisted_set() {
        let (dir, conn) = state_conn();
        let old = touch(&dir, "old.exe");
        let new = touch(&dir, "new.exe");
        {
            let guard = conn.lock().unwrap();
            AppPatternResolutionsRepository::new(&guard)
                .upsert("vpn*", &[old.to_string_lossy().into_owned()], 100)
                .expect("seed old");
        }
        let inner = Arc::new(ScriptedInner::default());
        inner.set("vpn*", vec![new.clone()]);
        let resolver = PersistentAppPathResolver::new(inner, Arc::clone(&conn));

        // Live wins and replaces the persisted set.
        assert_eq!(resolver.resolve("vpn*"), vec![new.clone()]);
        let guard = conn.lock().unwrap();
        let persisted = AppPatternResolutionsRepository::new(&guard)
            .load("vpn*")
            .expect("load");
        assert_eq!(persisted, vec![new.to_string_lossy().into_owned()]);
    }
}
