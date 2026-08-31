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
//! Every cache entry carries the wire-contract fingerprint of the build
//! that wrote it (`nrr_shared::contract_fingerprint`). On read, a
//! mismatch (or unparseable JSON) deletes the file rather than
//! returning bad data — the fingerprint moves with the contracts crate,
//! so nobody has to remember to bump anything.
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
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use nrr_application::backend_facade::CacheError;
use nrr_shared::ipc_payloads::MutationKind;

/// Entries written by a build that speaks a different wire contract are
/// deleted on read rather than returned.
///
/// This used to be a hand-maintained `CACHE_SCHEMA_VERSION`, which is exactly
/// the number nobody remembers to bump: 127 fields in `ipc_payloads` carry
/// `serde(default)`, so a DTO can gain a field, decode "successfully", and hand
/// the GUI a silently wrong value. The fingerprint moves on its own with the
/// contracts crate, and the typed read in the facade catches the rest.
fn contract_fingerprint() -> String {
    nrr_shared::contract_fingerprint()
}

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
    /// Wire-contract fingerprint of the build that wrote this entry.
    /// `serde(default)` so an entry from before this field simply reads as an
    /// empty string — and is then discarded, which is the correct answer.
    #[serde(default)]
    contract: String,
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
        reject_foreign_root(&root)?;
        restrict_to_owner(&root).map_err(|e| {
            CacheError::Io(format!(
                "cannot restrict snapshot cache root {}: {}",
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
        if entry.contract != contract_fingerprint() {
            let _ = fs::remove_file(&path);
            return None;
        }
        let now = epoch_now();
        // TTL comes from the KEY's policy, not from the file: the file is the
        // untrusted side of this comparison, and an entry written by an older
        // build (or edited) would otherwise carry its own idea of how long it
        // stays valid.
        let ttl_secs = key.ttl_secs();
        // A timestamp in the future is not a fresh entry — `saturating_sub`
        // read it as "age 0" and pinned it fresh forever. A clock that moved
        // backwards, or a file copied from another machine, is exactly the
        // case where the cache must be distrusted.
        let expired = match now.checked_sub(entry.cached_at_epoch) {
            Some(age) => age > ttl_secs,
            None => true,
        };
        let age_secs = now.saturating_sub(entry.cached_at_epoch);
        Some(CachedPayload {
            payload: entry.payload,
            cached_at_epoch: entry.cached_at_epoch,
            age_secs,
            expired,
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
            contract: contract_fingerprint(),
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
    /// contract are purged proactively rather than only at first read of
    /// each key.
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
                    // Another process may be mid-write. Only sweep temps that
                    // are demonstrably abandoned — deleting a live one makes
                    // its `rename` fail and loses the entry it was writing.
                    if is_abandoned_temp(&path) {
                        let _ = fs::remove_file(&path);
                    }
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

/// Refuse a cache root this user does not own, or that is a symlink.
///
/// On Unix the default root lives under the shared temp directory, so another
/// local account can create it — or point it at a directory of their choosing —
/// before we do. Permissions alone do not cover that: they are applied to
/// whatever is already there. On Windows the root is inside the user's profile,
/// which no other account can pre-create, so there is nothing to check.
fn reject_foreign_root(root: &Path) -> Result<(), CacheError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(root).map_err(|e| {
            CacheError::Io(format!("cannot stat cache root {}: {e}", root.display()))
        })?;
        if meta.file_type().is_symlink() {
            return Err(CacheError::Io(format!(
                "cache root {} is a symlink; refusing to use it",
                root.display()
            )));
        }
        // SAFETY-free: `geteuid` via the std-exposed metadata of a file we
        // just created ourselves would be circular, so read the process uid
        // from `/proc/self` — available on every platform this runs on.
        let own_uid = fs::metadata("/proc/self")
            .map(|m| m.uid())
            .map_err(|e| CacheError::Io(format!("cannot determine the current user: {e}")))?;
        if meta.uid() != own_uid {
            return Err(CacheError::Io(format!(
                "cache root {} belongs to another user; refusing to use it",
                root.display()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = root;
    }
    Ok(())
}

/// Is this temp file old enough that no one can still be writing it?
///
/// A write is a `create` + `write_all` + `sync_all` + `rename`; anything that
/// has not finished in this long is a leftover from a process that died.
fn is_abandoned_temp(path: &Path) -> bool {
    const ABANDONED_AFTER: std::time::Duration = std::time::Duration::from_secs(60);
    fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|modified| {
            SystemTime::now()
                .duration_since(modified)
                .map(|age| age > ABANDONED_AFTER)
                .unwrap_or(false)
        })
        .unwrap_or(false)
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
    // The temp name carries the writing process and a per-write counter. It
    // used to be derived from the target alone, and the window and the tray —
    // one crate, one cache root, the tray started by the window — then wrote
    // the same temp file at once and renamed a torn one into place.
    static WRITE_SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = WRITE_SEQ.fetch_add(1, AtomicOrdering::Relaxed);
    let mut tmp = path.to_path_buf();
    tmp.set_extension(match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{ext}.{}.{seq}.tmp", std::process::id()),
        None => format!("{}.{seq}.tmp", std::process::id()),
    });
    {
        let mut f = create_owner_only(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Create (or truncate) a file only its owner can read.
///
/// What lands here is one user's rules, route bindings and security alerts.
/// The default 0644 made every local account on a Linux box a reader of every
/// other account's policy; on Windows the file inherits the profile's ACL,
/// which is already owner-scoped, so the mode is a no-op there.
fn create_owner_only(path: &Path) -> io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        fs::File::create(path)
    }
}

/// Keep the cache directory readable by its owner alone, for the same reason.
/// An existing directory is tightened too — a cache written by an older build
/// is still sitting there at 0755.
fn restrict_to_owner(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn an_entry_stamped_in_the_future_is_not_treated_as_fresh() {
        // A clock that jumped back, or a file copied from another machine.
        // `saturating_sub` reported age 0 and the entry stayed "fresh" forever.
        let dir = TempDir::new().expect("tempdir");
        let cache = FileCache::with_root(dir.path().to_path_buf()).expect("cache");
        cache
            .write(CacheKey::RulesAll, json!({ "rules": [] }))
            .expect("write");
        let path = cache.root().join(CacheKey::RulesAll.filename());
        let mut entry: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read")).expect("parse");
        entry["cached_at_epoch"] = json!(epoch_now() + 86_400);
        fs::write(&path, serde_json::to_vec(&entry).expect("serialise")).expect("rewrite");

        let read = cache.read(CacheKey::RulesAll).expect("entry present");
        assert!(read.expired, "a future timestamp must not read as fresh");
    }

    #[test]
    fn the_ttl_comes_from_the_key_not_from_the_file() {
        // The file is the untrusted side: an entry may not extend its own life.
        let dir = TempDir::new().expect("tempdir");
        let cache = FileCache::with_root(dir.path().to_path_buf()).expect("cache");
        cache
            .write(CacheKey::ServiceHealth, json!({ "ok": true }))
            .expect("write");
        let path = cache.root().join(CacheKey::ServiceHealth.filename());
        let mut entry: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read")).expect("parse");
        entry["ttl_secs"] = json!(u64::MAX);
        entry["cached_at_epoch"] = json!(epoch_now() - (CacheKey::ServiceHealth.ttl_secs() + 60));
        fs::write(&path, serde_json::to_vec(&entry).expect("serialise")).expect("rewrite");

        let read = cache.read(CacheKey::ServiceHealth).expect("entry present");
        assert!(read.expired, "the key's TTL decides, not the file's");
    }

    #[cfg(unix)]
    #[test]
    fn a_cache_root_that_is_a_symlink_is_refused() {
        // On a shared temp directory another account can put a link where our
        // root goes; permissions applied afterwards would land on their target.
        let dir = TempDir::new().expect("tempdir");
        let real = dir.path().join("elsewhere");
        fs::create_dir(&real).expect("create target");
        let link = dir.path().join("snapshot_cache");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(
            FileCache::with_root(link).is_err(),
            "a symlinked cache root must be refused"
        );
    }

    /// The cache holds one user's rules, bindings and alerts — on a shared
    /// Linux box the default modes handed them to every local account.
    #[cfg(unix)]
    #[test]
    fn cache_directory_and_files_are_readable_by_their_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().expect("tempdir");
        let cache = FileCache::with_root(dir.path().join("snapshot_cache")).expect("cache");
        cache
            .write(CacheKey::RulesAll, json!({ "rules": [] }))
            .expect("write entry");

        let dir_mode = fs::metadata(cache.root())
            .expect("dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "cache directory must be owner-only");

        let file_mode = fs::metadata(cache.root().join(CacheKey::RulesAll.filename()))
            .expect("file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "cache entry must be owner-only");
    }

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
    fn read_returns_none_and_deletes_an_entry_from_another_contract() {
        let (_dir, cache) = fresh_cache();
        let path = cache.path_for(CacheKey::SecurityAlerts);
        // An entry written by a build that spoke a different wire contract.
        let bad_entry = serde_json::json!({
            "operation": "security.alerts.list",
            "cached_at_epoch": epoch_now(),
            "ttl_secs": SNAPSHOT_TTL_SECS,
            "contract": "0.0.0-from-the-past/rules-0",
            "payload": {"alerts": []},
        });
        fs::write(
            &path,
            serde_json::to_vec_pretty(&bad_entry).expect("serialize"),
        )
        .expect("write");
        assert!(cache.read(CacheKey::SecurityAlerts).is_none());
        assert!(
            !path.exists(),
            "an entry from another contract must be deleted"
        );
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
            contract: contract_fingerprint(),
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
    fn purge_unknown_files_removes_strangers_and_abandoned_tmps() {
        let (dir, cache) = fresh_cache();
        // A known entry — must survive.
        cache
            .write(CacheKey::SnapshotInitial, json!({"x": 1}))
            .expect("seed known");
        // An unknown JSON file from a future cache version.
        fs::write(dir.path().join("future_cache.json"), b"{}").expect("write stranger");
        // A tmp file left by a process that died long ago.
        let stale_tmp = dir.path().join("snapshot_initial.json.999.0.tmp");
        fs::write(&stale_tmp, b"partial").expect("write tmp");
        let long_ago = SystemTime::now() - std::time::Duration::from_secs(3600);
        filetime_set(&stale_tmp, long_ago);
        cache.purge_unknown_files().expect("purge");
        assert!(cache.path_for(CacheKey::SnapshotInitial).exists());
        assert!(!dir.path().join("future_cache.json").exists());
        assert!(!stale_tmp.exists());
    }

    #[test]
    fn a_fresh_tmp_file_survives_the_purge() {
        // It may belong to the other surface's write in flight — the window and
        // the tray share this directory. Deleting it makes that write's rename
        // fail and loses the entry.
        let (dir, cache) = fresh_cache();
        let live_tmp = dir.path().join("snapshot_initial.json.1234.0.tmp");
        fs::write(&live_tmp, b"partial").expect("write tmp");
        cache.purge_unknown_files().expect("purge");
        assert!(live_tmp.exists(), "a write in flight must not be swept");
    }

    /// Backdate a file so the purge sees it as abandoned. `File::set_modified`
    /// keeps this to std — no extra dependency for one test.
    fn filetime_set(path: &Path, when: SystemTime) {
        let f = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open for backdating");
        f.set_modified(when).expect("set mtime");
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
