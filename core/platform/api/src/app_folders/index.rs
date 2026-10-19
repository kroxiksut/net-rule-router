//! Path rule answers kept off the traffic path.
//!
//! A pass asks for every path rule of every user; listing a folder tree each
//! time would put thousands of directory reads on every recompute. The index
//! remembers each folder's listing, watches the folder, and after a change
//! waits for the folder to go quiet, lists it once and tells the listener only
//! when the set of programs really moved. Everything runs on the caller's
//! pass or on one worker thread; nothing here sees a packet.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{Duration, Instant};

use super::{
    AppPath, AppPathKind, FolderListing, PathOutcome, PathPrograms, PlaceOnDisk, ProgramFolders,
    PATH_RULE_PROGRAM_CAP, WATCHED_FOLDER_CAP,
};
use crate::error::PlatformError;
use crate::network_change::{NetworkChangeCallback, NetworkChangeSubscription};

/// Places remembered at once; past it the memory starts over.
const PLACE_CACHE_CAP: usize = 256;

/// How long answers stand and how changes are coalesced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexTiming {
    /// A watched folder's listing, with no change reported.
    pub watched_ttl: Duration,
    /// An unwatched folder's listing, and what sits at a rule's path.
    pub unwatched_ttl: Duration,
    /// Quiet after the last change before the folder is listed again: an
    /// installer writes a burst, and one listing should follow it.
    pub debounce: Duration,
    /// Longest a change waits for quiet, so a folder that never goes quiet is
    /// still listed.
    pub max_delay: Duration,
    /// A folder no pass asked about for this long is dropped with its watch.
    pub forget_after: Duration,
}

impl Default for IndexTiming {
    fn default() -> Self {
        Self {
            watched_ttl: Duration::from_secs(600),
            unwatched_ttl: Duration::from_secs(60),
            debounce: Duration::from_secs(2),
            max_delay: Duration::from_secs(10),
            forget_after: Duration::from_secs(900),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FolderKey {
    folder: PathBuf,
    subfolders: bool,
}

struct Entry {
    listing: FolderListing,
    listed_at: Instant,
    used_at: Instant,
    watch: Option<NetworkChangeSubscription>,
    watch_tried: bool,
}

#[derive(Clone)]
struct Place {
    at: Instant,
    kind: PlaceOnDisk,
    real: Option<PathBuf>,
}

#[derive(Default)]
struct State {
    entries: HashMap<FolderKey, Entry>,
    places: HashMap<String, Place>,
    dirty: HashSet<FolderKey>,
    first_dirty_at: Option<Instant>,
    last_change_at: Option<Instant>,
    worker_running: bool,
}

struct Shared {
    folders: Arc<dyn ProgramFolders>,
    timing: IndexTiming,
    state: Mutex<State>,
    wake: Condvar,
    listener: OnceLock<NetworkChangeCallback>,
    generation: AtomicU64,
}

/// Cached, watched answers of a [`ProgramFolders`] port.
pub struct ProgramFolderIndex {
    shared: Arc<Shared>,
}

impl ProgramFolderIndex {
    #[must_use]
    pub fn new(folders: Arc<dyn ProgramFolders>) -> Self {
        Self::with_timing(folders, IndexTiming::default())
    }

    #[must_use]
    pub fn with_timing(folders: Arc<dyn ProgramFolders>, timing: IndexTiming) -> Self {
        Self {
            shared: Arc::new(Shared {
                folders,
                timing,
                state: Mutex::new(State::default()),
                wake: Condvar::new(),
                listener: OnceLock::new(),
                generation: AtomicU64::new(0),
            }),
        }
    }

    /// Called, off the caller's thread, when a watched folder's programs
    /// changed. Only the first call counts.
    pub fn set_listener(&self, listener: NetworkChangeCallback) {
        let _ = self.shared.listener.set(listener);
    }

    /// Moves whenever a watched folder's programs change.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.shared.generation.load(Ordering::Relaxed)
    }

    /// The path style of the port behind the index.
    #[must_use]
    pub fn path_style(&self) -> super::PathStyle {
        self.shared.folders.path_style()
    }

    /// What `path` covers for `owner` now. A path from a profile folder
    /// covers the owner's own.
    #[must_use]
    pub fn programs(&self, path: &AppPath, owner: &str) -> PathPrograms {
        covered(
            self.shared.folders.as_ref(),
            path,
            owner,
            &|text| {
                let place = self.place(text);
                (place.kind, place.real)
            },
            &|folder, subfolders| self.listing(folder, subfolders),
        )
    }

    /// [`ProgramFolders::writable_by_anyone`] of the port behind the index.
    #[must_use]
    pub fn writable_by_anyone(&self, place: &Path) -> bool {
        self.shared.folders.writable_by_anyone(place)
    }

    fn place(&self, text: &str) -> Place {
        let now = Instant::now();
        {
            let state = self.shared.lock();
            if let Some(place) = state.places.get(text) {
                if now.saturating_duration_since(place.at) < self.shared.timing.unwatched_ttl {
                    return place.clone();
                }
            }
        }
        let path = Path::new(text);
        let kind = self.shared.folders.place(path);
        let real = match kind {
            PlaceOnDisk::Missing => None,
            PlaceOnDisk::File | PlaceOnDisk::Folder => self.shared.folders.real_path(path),
        };
        let place = Place {
            at: now,
            kind,
            real,
        };
        // A missing place is asked again on the next pass: a folder that
        // appears must not wait out a cache to be covered.
        if kind != PlaceOnDisk::Missing {
            let mut state = self.shared.lock();
            if state.places.len() >= PLACE_CACHE_CAP {
                state.places.clear();
            }
            state.places.insert(text.to_string(), place.clone());
        }
        place
    }

    fn listing(&self, folder: PathBuf, subfolders: bool) -> FolderListing {
        let shared = &self.shared;
        let key = FolderKey { folder, subfolders };
        let now = Instant::now();
        let retired = {
            let mut state = shared.lock();
            let retired = shared.forget_stale(&mut state, now);
            if let Some(entry) = state.entries.get_mut(&key) {
                entry.used_at = now;
                let ttl = if entry.watch.is_some() {
                    shared.timing.watched_ttl
                } else {
                    shared.timing.unwatched_ttl
                };
                if now.saturating_duration_since(entry.listed_at) < ttl {
                    let listing = entry.listing.clone();
                    drop(state);
                    drop(retired);
                    return listing;
                }
            }
            retired
        };
        // Subscriptions end outside the lock: ending one waits for its
        // thread, which may be reporting a change and need the lock.
        drop(retired);
        let listing = shared.folders.list(&key.folder, subfolders);
        let wants_watch = {
            let mut state = shared.lock();
            let watched = state.entries.values().filter(|e| e.watch.is_some()).count();
            let entry = state.entries.entry(key.clone()).or_insert_with(|| Entry {
                listing: FolderListing::default(),
                listed_at: now,
                used_at: now,
                watch: None,
                watch_tried: false,
            });
            entry.listing = listing.clone();
            entry.listed_at = now;
            entry.used_at = now;
            let wants = !entry.watch_tried && watched < WATCHED_FOLDER_CAP;
            entry.watch_tried |= wants;
            wants
        };
        if wants_watch {
            if let Some(subscription) = Shared::subscribe(shared, &key) {
                let mut state = shared.lock();
                let unclaimed = match state.entries.get_mut(&key) {
                    Some(entry) => entry.watch.replace(subscription),
                    None => Some(subscription),
                };
                drop(state);
                drop(unclaimed);
            }
        }
        listing
    }

    #[cfg(test)]
    fn wait_idle(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.shared.lock().worker_running && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

/// What a place sits as on disk, and its real path.
pub(super) type PlaceLookup<'a> = &'a dyn Fn(&str) -> (PlaceOnDisk, Option<PathBuf>);

/// The programs of one folder, with or without its subfolders.
pub(super) type FolderLister<'a> = &'a dyn Fn(PathBuf, bool) -> FolderListing;

/// What `path` covers for `owner`, reading the disk through `place` and
/// `list`. A path from a profile folder starts from the owner's own; a place
/// in another user's profile is refused before the disk is touched, and
/// again at its real place behind links.
pub(super) fn covered(
    folders: &dyn ProgramFolders,
    path: &AppPath,
    owner: &str,
    place: PlaceLookup<'_>,
    list: FolderLister<'_>,
) -> PathPrograms {
    let resolved;
    let path = if path.profile_folder().is_some() {
        let Some(profile) = folders.owner_profile(owner) else {
            return PathPrograms::missing();
        };
        match path.for_profile(&profile.to_string_lossy()) {
            Ok(own) => {
                resolved = own;
                &resolved
            }
            Err(_) => return PathPrograms::missing(),
        }
    } else {
        path
    };
    let other_users = || PathPrograms {
        outcome: PathOutcome::OtherUsersFolder,
        place: None,
        programs: Vec::new(),
        over_cap: false,
    };
    if folders.foreign_profile(Path::new(path.place()), owner) {
        return other_users();
    }
    let (kind, real) = place(path.place());
    let is_folder = match kind {
        PlaceOnDisk::Missing => return PathPrograms::missing(),
        PlaceOnDisk::Folder => true,
        PlaceOnDisk::File => false,
    };
    let Some(real) = real else {
        return PathPrograms::missing();
    };
    let Ok(decided) = path.on_disk(&real.to_string_lossy(), is_folder) else {
        return PathPrograms::missing();
    };
    if folders.foreign_profile(&real, owner) {
        return PathPrograms {
            place: Some(decided),
            ..other_users()
        };
    }
    let (mut programs, mut over_cap) = match (decided.kind(), is_folder) {
        (AppPathKind::File, false) if folders.is_program(&real) => (vec![real], false),
        (AppPathKind::Folder, true) => {
            let listing = list(real, false);
            (listing.programs, listing.truncated)
        }
        (AppPathKind::FolderTree, true) => {
            let listing = list(real, true);
            (listing.programs, listing.truncated)
        }
        _ => (Vec::new(), false),
    };
    if programs.len() > PATH_RULE_PROGRAM_CAP {
        programs.truncate(PATH_RULE_PROGRAM_CAP);
        over_cap = true;
    }
    PathPrograms {
        outcome: PathOutcome::Found,
        place: Some(decided),
        programs,
        over_cap,
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Drop folders no pass asked about lately; their watches are handed back
    /// to be ended outside the lock.
    fn forget_stale(&self, state: &mut State, now: Instant) -> Vec<NetworkChangeSubscription> {
        let forget_after = self.timing.forget_after;
        let stale: Vec<FolderKey> = state
            .entries
            .iter()
            .filter(|(_, entry)| now.saturating_duration_since(entry.used_at) >= forget_after)
            .map(|(key, _)| key.clone())
            .collect();
        let mut retired = Vec::new();
        for key in stale {
            state.dirty.remove(&key);
            if let Some(watch) = state.entries.remove(&key).and_then(|entry| entry.watch) {
                retired.push(watch);
            }
        }
        retired
    }

    fn subscribe(shared: &Arc<Self>, key: &FolderKey) -> Option<NetworkChangeSubscription> {
        let weak: Weak<Self> = Arc::downgrade(shared);
        let watched = key.clone();
        let on_change: NetworkChangeCallback = Arc::new(move || {
            if let Some(shared) = weak.upgrade() {
                Shared::note_change(&shared, &watched);
            }
        });
        match shared.folders.watch(&key.folder, key.subfolders, on_change) {
            Ok(subscription) => Some(subscription),
            Err(PlatformError::NotSupported { .. }) => None,
            Err(error) => {
                tracing::debug!(
                    target: "nrr::app-folders",
                    folder = %key.folder.display(),
                    %error,
                    "a rule's folder cannot be watched; it is listed again on the slower refresh",
                );
                None
            }
        }
    }

    fn note_change(shared: &Arc<Self>, key: &FolderKey) {
        let now = Instant::now();
        let start = {
            let mut state = shared.lock();
            if !state.entries.contains_key(key) {
                return;
            }
            state.dirty.insert(key.clone());
            state.first_dirty_at.get_or_insert(now);
            state.last_change_at = Some(now);
            let start = !state.worker_running;
            state.worker_running = true;
            start
        };
        shared.wake.notify_all();
        if start {
            let worker = Arc::clone(shared);
            let spawned = std::thread::Builder::new()
                .name("nrr-app-folders".into())
                .spawn(move || worker.relist_until_quiet());
            if spawned.is_err() {
                // The marks stay; the next change tries to start a worker again.
                shared.lock().worker_running = false;
            }
        }
    }

    /// Wait for quiet, list what changed, report a real change; again while
    /// changes keep arriving.
    fn relist_until_quiet(&self) {
        loop {
            let batch: Vec<FolderKey> = {
                let mut state = self.lock();
                loop {
                    if state.dirty.is_empty() {
                        state.worker_running = false;
                        return;
                    }
                    let now = Instant::now();
                    let due = match (state.last_change_at, state.first_dirty_at) {
                        (Some(last), Some(first)) => {
                            (last + self.timing.debounce).min(first + self.timing.max_delay)
                        }
                        _ => now,
                    };
                    if now >= due {
                        break;
                    }
                    state = self
                        .wake
                        .wait_timeout(state, due - now)
                        .unwrap_or_else(|p| p.into_inner())
                        .0;
                }
                state.first_dirty_at = None;
                state.last_change_at = None;
                state.dirty.drain().collect()
            };
            let mut changed = false;
            for key in batch {
                let listing = self.folders.list(&key.folder, key.subfolders);
                let mut state = self.lock();
                if let Some(entry) = state.entries.get_mut(&key) {
                    if entry.listing != listing {
                        entry.listing = listing;
                        changed = true;
                    }
                    entry.listed_at = Instant::now();
                }
            }
            if changed {
                self.generation.fetch_add(1, Ordering::Relaxed);
                if let Some(listener) = self.listener.get() {
                    // A panic must not end the worker the watches rely on.
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| listener()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
