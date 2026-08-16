//! File-based snapshot cache.
//!
//! ## Purpose
//!
//! When the IPC channel to the service is up, every successful response is
//! mirrored to a small per-operation JSON file under the user's cache
//! directory (`%LOCALAPPDATA%\<product>\` on Windows,
//! `$XDG_CACHE_HOME/<product>/` on Unix). When the channel later
//! goes down (service restart, killed by user, network glitch on a
//! domain-joined box) the [`crate::IpcBackendFacade`] can hand the GUI a
//! cached snapshot tagged `stale = true` so screens don't blank out.
//!
//! ## Why a file (not in-memory)
//!
//! Both the GUI and tray are *separate processes* from the service.
//! When the GUI launches it should be able to render *something*
//! immediately even if the service is still spinning up — the only
//! durable inter-launch carrier we have without growing a new SQLite
//! file is the user's roaming-app-data directory. JSON files are
//! diffable, hand-inspectable, and fit the tier-of-data well: this is
//! decorative cache, not authoritative state.
//!
//! ## Schema versioning
//!
//! Every cache entry carries a [`CACHE_SCHEMA_VERSION`]. On read, a
//! mismatch (or unparseable JSON) deletes the file rather than
//! returning bad data. The version bumps whenever any DTO under
//! [`nrr_shared::ipc_payloads`] or [`nrr_shared::diagnostics_dto`]
//! changes shape in a way that would corrupt deserialisation.
//!
//! ## Atomicity
//!
//! Writes go to `<key>.json.tmp` and then atomically rename to
//! `<key>.json`. On Windows this maps to `MoveFileEx` with
//! `MOVEFILE_REPLACE_EXISTING`. A reader that opens during a write
//! sees either the previous version or the new one — never a torn
//! file.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use nrr_application::backend_facade::CacheError;
use nrr_shared::ipc_payloads::MutationKind;

/// Bump whenever any cached payload's wire shape changes. Stale files
/// (different version) are deleted on read instead of being returned.
pub const CACHE_SCHEMA_VERSION: u32 = 1;

/// TTL for the service-health entry — short because health flips fast.
pub const HEALTH_TTL_SECS: u64 = 5 * 60;

/// TTL for snapshot entries — longer because snapshots are expensive to
/// recompute and the data is decoration during reconnect.
pub const SNAPSHOT_TTL_SECS: u64 = 60 * 60;

/// The per-operation cache key. Each key maps 1:1 to a JSON file under
/// the cache root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CacheKey {
    /// `service.health.get`
    ServiceHealth,
    /// `snapshot.initial.get` — the bundled first-render snapshot.
    SnapshotInitial,
    /// `snapshot.interfaces.get`
    SnapshotInterfaces,
    /// `snapshot.diagnostics.get`
    SnapshotDiagnostics,
    /// `security.alerts.list`
    SecurityAlerts,
    /// `rules.list` with `route = all`
    RulesAll,
    /// `rules.list` with `route = primary`
    RulesPrimary,
    /// `rules.list` with `route = secondary`
    RulesSecondary,
}

impl CacheKey {
    /// Filename within the cache root. Stable — used as the on-disk key.
    pub fn filename(self) -> &'static str {
        match self {
            Self::ServiceHealth => "service_health.json",
            Self::SnapshotInitial => "snapshot_initial.json",
            Self::SnapshotInterfaces => "snapshot_interfaces.json",
            Self::SnapshotDiagnostics => "snapshot_diagnostics.json",
            Self::SecurityAlerts => "security_alerts.json",
            Self::RulesAll => "rules_list_all.json",
            Self::RulesPrimary => "rules_list_primary.json",
            Self::RulesSecondary => "rules_list_secondary.json",
        }
    }

    /// Operation slug recorded inside the cache entry for diagnostics.
    pub fn operation_slug(self) -> &'static str {
        match self {
            Self::ServiceHealth => "service.health.get",
            Self::SnapshotInitial => "snapshot.initial.get",
            Self::SnapshotInterfaces => "snapshot.interfaces.get",
            Self::SnapshotDiagnostics => "snapshot.diagnostics.get",
            Self::SecurityAlerts => "security.alerts.list",
            Self::RulesAll => "rules.list[all]",
            Self::RulesPrimary => "rules.list[primary]",
            Self::RulesSecondary => "rules.list[secondary]",
        }
    }

    pub fn ttl_secs(self) -> u64 {
        match self {
            Self::ServiceHealth => HEALTH_TTL_SECS,
            _ => SNAPSHOT_TTL_SECS,
        }
    }

    /// Every key that exists today — used by `clear_all` and tests.
    pub const ALL: [Self; 8] = [
        Self::ServiceHealth,
        Self::SnapshotInitial,
        Self::SnapshotInterfaces,
        Self::SnapshotDiagnostics,
        Self::SecurityAlerts,
        Self::RulesAll,
        Self::RulesPrimary,
        Self::RulesSecondary,
    ];
}

/// Cache files invalidated by a successful mutation of the given kind.
///
/// Returned set is intentionally small — only entries whose data
/// definitely changed. Read-only mutations (`PresetExport`,
/// `SettingsExport`) invalidate nothing.
pub fn invalidation_targets(kind: MutationKind) -> &'static [CacheKey] {
    match kind {
        MutationKind::RulesUpdate => &[
            CacheKey::RulesAll,
            CacheKey::RulesPrimary,
            CacheKey::RulesSecondary,
            CacheKey::SnapshotInitial,
        ],
        MutationKind::RouteBindingsUpdate => {
            &[CacheKey::SnapshotInitial, CacheKey::SnapshotInterfaces]
        }
        // A reset discards the caller's per-SID rules and falls back to
        // baseline, so the rules views + initial snapshot all change, same
        // invalidation set as a rules edit.
        MutationKind::PresetImport | MutationKind::RulesResetToBaseline => &[
            CacheKey::RulesAll,
            CacheKey::RulesPrimary,
            CacheKey::RulesSecondary,
            CacheKey::SnapshotInitial,
        ],
        #[allow(deprecated)]
        MutationKind::PresetExport | MutationKind::SettingsExport => &[],
        // Security alert state changes do not currently populate a
        // dedicated cache key, but they affect the alerts section of
        // `SnapshotInitial`, so invalidate that entry to force a re-fetch.
        MutationKind::SecurityAlertAck | MutationKind::SecurityAlertResolve => {
            &[CacheKey::SnapshotInitial]
        }
    }
}

/// On-disk representation of a single cache entry. The `payload` field
/// is intentionally `serde_json::Value` so the cache layer is generic
/// across operations — typed (de)serialisation happens in the IPC
/// facade once it knows which response type to expect.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CacheEntry {
    operation: String,
    cached_at_epoch: u64,
    ttl_secs: u64,
    schema_version: u32,
    payload: Value,
}

/// A successfully read cache entry, including freshness metadata.
#[derive(Clone, Debug)]
pub struct CachedPayload {
    pub payload: Value,
    pub cached_at_epoch: u64,
    pub age_secs: u64,
    /// `true` when `age_secs > ttl_secs` — caller decides whether to
    /// surface the data tagged `stale = true` or treat it as missing.
    pub expired: bool,
}

/// File-backed snapshot cache rooted at a single directory.
///
/// All operations are sync. The cache is *fail-soft*: errors writing
/// to disk are logged via the returned `CacheError` but never panic,
/// and read errors degrade to a cache miss (returning `None`) so a
/// half-corrupted cache directory cannot brick the GUI.
pub struct FileCache {
    root: PathBuf,
}

impl FileCache {
    /// Construct a cache rooted at `%LOCALAPPDATA%\NetRuleRouter\snapshot_cache\`
    /// (Windows). On non-Windows hosts (test crosscompiles only — the
    /// production builds are Windows-only) falls back to
    /// `std::env::temp_dir().join("NetRuleRouter/snapshot_cache")`.
    ///
    /// Creates the directory if it does not exist.
    pub fn at_default_location() -> Result<Self, CacheError> {
        let root = default_cache_root()?;
        Self::with_root(root)
    }

    /// Construct a cache rooted at the given path (used by tests and by
    /// callers who want to redirect cache to a non-default location,
    /// e.g. for portable installs).
    ///
    /// Creates the directory if it does not exist.
    pub fn with_root(root: PathBuf) -> Result<Self, CacheError> {
        fs::create_dir_all(&root).map_err(|e| {
            CacheError::Io(format!(
                "cannot create snapshot cache root {}: {}",
                root.display(),
                e
            ))
        })?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_for(&self, key: CacheKey) -> PathBuf {
        self.root.join(key.filename())
    }

    /// Read a cache entry. Returns `None` for any of: file missing,
    /// JSON unreadable, schema version mismatch (file deleted on the
    /// way out). The freshness flag is computed on the result; callers
    /// that don't want stale data check `CachedPayload::expired`.
    pub fn read(&self, key: CacheKey) -> Option<CachedPayload> {
        let path = self.path_for(key);
        let bytes = fs::read(&path).ok()?;
        let entry: CacheEntry = match serde_json::from_slice(&bytes) {
            Ok(e) => e,
            Err(_) => {
                // Corrupted JSON — treat as a cache miss and remove the
                // bad file so it doesn't keep failing on every read.
                let _ = fs::remove_file(&path);
                return None;
            }
        };
        if entry.schema_version != CACHE_SCHEMA_VERSION {
            let _ = fs::remove_file(&path);
            return None;
        }
        let now = epoch_now();
        let age_secs = now.saturating_sub(entry.cached_at_epoch);
        Some(CachedPayload {
            payload: entry.payload,
            cached_at_epoch: entry.cached_at_epoch,
            age_secs,
            expired: age_secs > entry.ttl_secs,
        })
    }

    /// Atomically write `payload` for `key`. The write goes to a
    /// `<key>.json.tmp` sibling and is renamed on top of the live
    /// file. A concurrent reader sees either the previous version or
    /// the new one, never a torn file.
    pub fn write(&self, key: CacheKey, payload: Value) -> Result<(), CacheError> {
        let entry = CacheEntry {
            operation: key.operation_slug().to_string(),
            cached_at_epoch: epoch_now(),
            ttl_secs: key.ttl_secs(),
            schema_version: CACHE_SCHEMA_VERSION,
            payload,
        };
        let bytes = serde_json::to_vec_pretty(&entry)
            .map_err(|e| CacheError::Serialization(e.to_string()))?;
        let final_path = self.path_for(key);
        atomic_write(&final_path, &bytes).map_err(|e| {
            CacheError::Io(format!(
                "atomic write to {} failed: {}",
                final_path.display(),
                e
            ))
        })
    }

    /// Delete a single entry if present. Missing files are not an error.
    pub fn invalidate(&self, key: CacheKey) -> Result<(), CacheError> {
        let path = self.path_for(key);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(CacheError::Io(format!(
                "cannot remove {}: {}",
                path.display(),
                e
            ))),
        }
    }

    /// Invalidate every entry that becomes stale after a successful
    /// mutation of the given kind (see [`invalidation_targets`]).
    /// Failures on individual files are aggregated and the *first*
    /// error is returned; the cache layer still attempts every
    /// deletion.
    pub fn invalidate_for_mutation(&self, kind: MutationKind) -> Result<(), CacheError> {
        let mut first_err: Option<CacheError> = None;
        for &key in invalidation_targets(kind) {
            if let Err(e) = self.invalidate(key) {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Drop every known cache file. The cache directory itself is
    /// preserved. Used by GUI's "Reset" action and by the IPC facade's
    /// [`crate::IpcBackendFacade::clear_cache`].
    pub fn clear_all(&self) -> Result<(), CacheError> {
        let mut first_err: Option<CacheError> = None;
        for &key in &CacheKey::ALL {
            if let Err(e) = self.invalidate(key) {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Sweep any non-recognised JSON file out of the cache root. Used
    /// at startup so files left over from an earlier
    /// [`CACHE_SCHEMA_VERSION`] are purged proactively rather than only
    /// at first read of each key.
    pub fn purge_unknown_files(&self) -> Result<(), CacheError> {
        let known: HashSet<&str> = CacheKey::ALL.iter().map(|k| k.filename()).collect();
        let entries = fs::read_dir(&self.root).map_err(|e| {
            CacheError::Io(format!(
                "cannot list snapshot cache root {}: {}",
                self.root.display(),
                e
            ))
        })?;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".tmp") {
                    let _ = fs::remove_file(&path);
                    continue;
                }
                if !known.contains(name) {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn default_cache_root() -> Result<PathBuf, CacheError> {
    let local_app_data = std::env::var_os("LOCALAPPDATA").ok_or_else(|| {
        CacheError::Io("environment variable LOCALAPPDATA is not set".to_string())
    })?;
    Ok(PathBuf::from(local_app_data)
        .join(nrr_shared::product_identity::PRODUCT_NAME)
        .join("snapshot_cache"))
}

/// `$XDG_CACHE_HOME/<product>/snapshot_cache`, or `~/.cache/…` when the
/// variable is unset — the XDG default. Deliberately NOT the temp directory:
/// this cache is what the GUI shows while the service is unreachable, and a
/// world-writable location cleared on reboot is the wrong home for it.
#[cfg(not(target_os = "windows"))]
fn default_cache_root() -> Result<PathBuf, CacheError> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .ok_or_else(|| CacheError::Io("neither XDG_CACHE_HOME nor HOME is set".to_string()))?;
    Ok(base
        .join(nrr_shared::product_identity::PRODUCT_NAME_UNIX)
        .join("snapshot_cache"))
}

fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut tmp = path.to_path_buf();
    tmp.set_extension(match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{ext}.tmp"),
        None => "tmp".to_string(),
    });
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn fresh_cache() -> (TempDir, FileCache) {
        let dir = TempDir::new().expect("create tempdir");
        let cache = FileCache::with_root(dir.path().to_path_buf()).expect("construct cache root");
        (dir, cache)
    }

    #[test]
    fn write_then_read_round_trips_payload() {
        let (_dir, cache) = fresh_cache();
        let payload = json!({"hello": "world", "n": 42});
        cache
            .write(CacheKey::ServiceHealth, payload.clone())
            .expect("write");
        let cached = cache.read(CacheKey::ServiceHealth).expect("hit");
        assert_eq!(cached.payload, payload);
        assert!(!cached.expired);
        assert!(cached.age_secs <= 1);
    }

    #[test]
    fn read_returns_none_for_missing_entry() {
        let (_dir, cache) = fresh_cache();
        assert!(cache.read(CacheKey::SnapshotInitial).is_none());
    }

    #[test]
    fn read_returns_none_and_deletes_corrupted_file() {
        let (_dir, cache) = fresh_cache();
        let path = cache.path_for(CacheKey::SnapshotInitial);
        fs::write(&path, b"{not valid json").expect("write garbage");
        assert!(cache.read(CacheKey::SnapshotInitial).is_none());
        assert!(!path.exists(), "corrupted cache file should be removed");
    }

    #[test]
    fn read_returns_none_and_deletes_on_schema_mismatch() {
        let (_dir, cache) = fresh_cache();
        let path = cache.path_for(CacheKey::SecurityAlerts);
        // Hand-craft an entry with a future schema version.
        let bad_entry = serde_json::json!({
            "operation": "security.alerts.list",
            "cached_at_epoch": epoch_now(),
            "ttl_secs": SNAPSHOT_TTL_SECS,
            "schema_version": CACHE_SCHEMA_VERSION + 99,
            "payload": {"alerts": []},
        });
        fs::write(
            &path,
            serde_json::to_vec_pretty(&bad_entry).expect("serialize"),
        )
        .expect("write");
        assert!(cache.read(CacheKey::SecurityAlerts).is_none());
        assert!(!path.exists(), "schema-mismatched file must be deleted");
    }

    #[test]
    fn expired_entry_is_returned_with_expired_flag() {
        let (_dir, cache) = fresh_cache();
        let path = cache.path_for(CacheKey::ServiceHealth);
        // Write a hand-crafted entry whose cached_at_epoch is far in the past.
        let entry = CacheEntry {
            operation: CacheKey::ServiceHealth.operation_slug().to_string(),
            cached_at_epoch: epoch_now().saturating_sub(HEALTH_TTL_SECS + 60),
            ttl_secs: HEALTH_TTL_SECS,
            schema_version: CACHE_SCHEMA_VERSION,
            payload: json!({"state": "running"}),
        };
        fs::write(&path, serde_json::to_vec_pretty(&entry).expect("serialize")).expect("write");
        let cached = cache.read(CacheKey::ServiceHealth).expect("hit");
        assert!(cached.expired);
        assert!(cached.age_secs > HEALTH_TTL_SECS);
    }

    #[test]
    fn invalidate_removes_file() {
        let (_dir, cache) = fresh_cache();
        cache
            .write(CacheKey::SnapshotInterfaces, json!({"adapters": []}))
            .expect("write");
        assert!(cache.path_for(CacheKey::SnapshotInterfaces).exists());
        cache
            .invalidate(CacheKey::SnapshotInterfaces)
            .expect("invalidate");
        assert!(!cache.path_for(CacheKey::SnapshotInterfaces).exists());
    }

    #[test]
    fn invalidate_missing_file_is_ok() {
        let (_dir, cache) = fresh_cache();
        cache
            .invalidate(CacheKey::SnapshotInitial)
            .expect("idempotent");
    }

    #[test]
    fn rules_update_invalidates_rules_files_and_initial_snapshot() {
        let (_dir, cache) = fresh_cache();
        // Seed every key we expect to be wiped.
        for key in [
            CacheKey::RulesAll,
            CacheKey::RulesPrimary,
            CacheKey::RulesSecondary,
            CacheKey::SnapshotInitial,
            CacheKey::ServiceHealth, // should NOT be wiped
        ] {
            cache
                .write(key, json!({"k": key.filename()}))
                .expect("seed");
        }
        cache
            .invalidate_for_mutation(MutationKind::RulesUpdate)
            .expect("invalidate");
        for key in [
            CacheKey::RulesAll,
            CacheKey::RulesPrimary,
            CacheKey::RulesSecondary,
            CacheKey::SnapshotInitial,
        ] {
            assert!(
                !cache.path_for(key).exists(),
                "{:?} should be invalidated",
                key
            );
        }
        assert!(
            cache.path_for(CacheKey::ServiceHealth).exists(),
            "service-health is unaffected by rules updates"
        );
    }

    #[test]
    fn route_bindings_update_invalidates_interfaces_and_initial() {
        let (_dir, cache) = fresh_cache();
        cache
            .write(CacheKey::SnapshotInterfaces, json!({"adapters": []}))
            .unwrap();
        cache
            .write(CacheKey::SnapshotInitial, json!({"x": 1}))
            .unwrap();
        cache
            .write(CacheKey::RulesAll, json!({"rows": []}))
            .unwrap();
        cache
            .invalidate_for_mutation(MutationKind::RouteBindingsUpdate)
            .expect("invalidate");
        assert!(!cache.path_for(CacheKey::SnapshotInterfaces).exists());
        assert!(!cache.path_for(CacheKey::SnapshotInitial).exists());
        assert!(
            cache.path_for(CacheKey::RulesAll).exists(),
            "rules cache survives route-binding changes"
        );
    }

    #[test]
    fn read_only_mutations_invalidate_nothing() {
        #[allow(deprecated)]
        let kinds = [MutationKind::PresetExport, MutationKind::SettingsExport];
        for kind in kinds {
            assert!(invalidation_targets(kind).is_empty(), "{:?}", kind);
        }
    }

    #[test]
    fn clear_all_removes_every_known_entry() {
        let (_dir, cache) = fresh_cache();
        for &key in &CacheKey::ALL {
            cache
                .write(key, json!({"k": key.filename()}))
                .expect("seed");
        }
        cache.clear_all().expect("clear");
        for &key in &CacheKey::ALL {
            assert!(!cache.path_for(key).exists(), "{:?}", key);
        }
    }

    #[test]
    fn purge_unknown_files_removes_strangers_and_tmps() {
        let (dir, cache) = fresh_cache();
        // A known entry — must survive.
        cache
            .write(CacheKey::SnapshotInitial, json!({"x": 1}))
            .expect("seed known");
        // An unknown JSON file from a future cache version.
        fs::write(dir.path().join("future_cache.json"), b"{}").expect("write stranger");
        // A leaked tmp file from an interrupted write.
        fs::write(dir.path().join("snapshot_initial.json.tmp"), b"partial").expect("write tmp");
        cache.purge_unknown_files().expect("purge");
        assert!(cache.path_for(CacheKey::SnapshotInitial).exists());
        assert!(!dir.path().join("future_cache.json").exists());
        assert!(!dir.path().join("snapshot_initial.json.tmp").exists());
    }

    #[test]
    fn atomic_write_overwrites_existing_file() {
        let (_dir, cache) = fresh_cache();
        cache
            .write(CacheKey::ServiceHealth, json!({"state": "running"}))
            .expect("first");
        cache
            .write(CacheKey::ServiceHealth, json!({"state": "degraded"}))
            .expect("overwrite");
        let cached = cache.read(CacheKey::ServiceHealth).expect("hit");
        assert_eq!(cached.payload["state"], "degraded");
    }

    #[test]
    fn invalidation_target_set_is_minimal_and_correct() {
        // Sanity: every kind that mutates user-visible policy state
        // wipes SnapshotInitial (so first re-render after mutation
        // pulls fresh data from the service).
        for kind in [
            MutationKind::RulesUpdate,
            MutationKind::RouteBindingsUpdate,
            MutationKind::PresetImport,
        ] {
            assert!(
                invalidation_targets(kind).contains(&CacheKey::SnapshotInitial),
                "{:?} must wipe SnapshotInitial",
                kind
            );
        }
    }
}
