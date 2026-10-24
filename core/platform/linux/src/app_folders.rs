//! Linux mechanism behind [`ProgramFolders`]: real paths through every link
//! (what `/proc/<pid>/exe` reports), programs as regular files with an
//! execute bit, other users' homes from the account database, and folder
//! watches over inotify.
//!
//! inotify watches one directory at a time, so a folder with its subfolders
//! takes a watch per directory, up to [`MAX_WATCHED_DIRS`]; a directory
//! created later gets its watch when its creation is read, a removed one gives
//! its watch back, a renamed one is watched under its new name. Every folder
//! watch of the process shares one inotify instance and one thread. A burst
//! of events is coalesced by the caller, which lists the folder again and
//! decides.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nrr_platform_api::app_folders::{
    is_program_file, name_may_change_programs, place_of, PathStyle, PlaceOnDisk, ProgramFolders,
    LISTING_MAX_DEPTH,
};
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::network_change::{NetworkChangeCallback, NetworkChangeSubscription};
use nrr_shared::app_path::path_segments;

use crate::inotify_events::{
    InotifyEvent, IN_CREATE, IN_DELETE_SELF, IN_IGNORED, IN_ISDIR, IN_MOVED_FROM, IN_MOVED_TO,
    IN_MOVE_SELF, IN_Q_OVERFLOW,
};

/// Directories one folder watch holds at once. Kept low: inotify watches are
/// counted per user, and root shares its budget with the system's own daemons.
pub const MAX_WATCHED_DIRS: usize = 64;

/// Most bytes of the account database read; a larger one is read in part.
const MAX_PASSWD_BYTES: u64 = 1024 * 1024;

/// Accounts read from it.
const MAX_ACCOUNTS: usize = 4096;

/// How long the homes are remembered: accounts change far less often than a
/// pass runs.
const HOMES_TTL: Duration = Duration::from_secs(60);

/// The first uid `useradd` gives a person, and the overflow uid nobody is.
const FIRST_PERSON_UID: u32 = 1000;
const NOBODY_UID: u32 = 65534;

/// How a stored principal names a Linux user.
const UID_PREFIX: &str = "unix:uid:";

/// Users' homes as `(uid, home segments)`, with the time they were read.
type HomesCache = Option<(Instant, Vec<(u32, Vec<String>)>)>;

/// The Linux [`ProgramFolders`].
#[derive(Default)]
pub struct LinuxProgramFolders {
    homes: Mutex<HomesCache>,
}

impl LinuxProgramFolders {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn homes(&self) -> Vec<(u32, Vec<String>)> {
        let mut cached = self.homes.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((at, homes)) = cached.as_ref() {
            if at.elapsed() < HOMES_TTL {
                return homes.clone();
            }
        }
        let homes = read_passwd()
            .map(|text| homes_from_passwd(&text))
            .unwrap_or_default();
        *cached = Some((Instant::now(), homes.clone()));
        homes
    }
}

impl ProgramFolders for LinuxProgramFolders {
    fn path_style(&self) -> PathStyle {
        PathStyle::Linux
    }

    fn place(&self, path: &Path) -> PlaceOnDisk {
        place_of(path)
    }

    fn real_path(&self, path: &Path) -> Option<PathBuf> {
        std::fs::canonicalize(path).ok()
    }

    fn is_program(&self, path: &Path) -> bool {
        is_program_file(path, PathStyle::Linux)
    }

    fn foreign_profile(&self, place: &Path, owner: &str) -> bool {
        is_foreign_home(&place.to_string_lossy(), owner, &self.homes())
    }

    fn owner_profile(&self, owner: &str) -> Option<PathBuf> {
        home_of(owner, &self.homes())
    }

    #[cfg(unix)]
    fn owner_may_list(&self, place: &Path, owner: &str) -> bool {
        crate::folder_access::uid_may_list(place, owner).unwrap_or(true)
    }

    #[cfg(target_os = "linux")]
    fn watch(
        &self,
        folder: &Path,
        subfolders: bool,
        on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        let watch = mechanism::FolderWatch::start(folder, subfolders, on_change)?;
        Ok(NetworkChangeSubscription::new(Box::new(watch)))
    }

    #[cfg(not(target_os = "linux"))]
    fn watch(
        &self,
        _folder: &Path,
        _subfolders: bool,
        _on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        Err(PlatformError::NotSupported {
            reason: "inotify has no implementation on this host",
        })
    }
}

fn read_passwd() -> Option<String> {
    use std::io::Read;
    let file = std::fs::File::open("/etc/passwd").ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_PASSWD_BYTES).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The homes of the people in `/etc/passwd` text: accounts from the first
/// person uid up, nobody excluded, each home at least two levels deep — a
/// service whose home is `/` or `/var` must not make the system one user's.
/// Accounts only a directory service knows are not seen here.
#[must_use]
pub fn homes_from_passwd(text: &str) -> Vec<(u32, Vec<String>)> {
    text.lines()
        .take(MAX_ACCOUNTS)
        .filter_map(|line| {
            let fields: Vec<&str> = line.splitn(7, ':').collect();
            let uid: u32 = fields.get(2)?.trim().parse().ok()?;
            if uid < FIRST_PERSON_UID || uid == NOBODY_UID {
                return None;
            }
            let home = path_segments(fields.get(5)?.trim(), PathStyle::Linux, false)?;
            (home.len() >= 2).then_some((uid, home))
        })
        .collect()
}

/// Whether `place` lies in a home of someone other than `owner`. An owner
/// that names no user (the machine, the shared baseline) owns no home, so
/// every person's home is someone else's to it.
#[must_use]
pub fn is_foreign_home(place: &str, owner: &str, homes: &[(u32, Vec<String>)]) -> bool {
    let Some(place) = path_segments(place, PathStyle::Linux, false) else {
        return false;
    };
    let owner_uid: Option<u32> = owner
        .strip_prefix(UID_PREFIX)
        .and_then(|uid| uid.parse().ok());
    homes
        .iter()
        .any(|(uid, home)| Some(*uid) != owner_uid && place.starts_with(home))
}

/// The home of the person `owner` names, from `homes`; `None` for an owner
/// that names nobody with a home there (the shared baseline, root).
#[must_use]
pub fn home_of(owner: &str, homes: &[(u32, Vec<String>)]) -> Option<PathBuf> {
    let uid: u32 = owner.strip_prefix(UID_PREFIX)?.parse().ok()?;
    let (_, home) = homes.iter().find(|(person, _)| *person == uid)?;
    Some(PathBuf::from(format!("/{}", home.join("/"))))
}

/// Whether a batch of events may change which programs a watched folder
/// holds: an overflow says anything may have, a log or cache rewritten in
/// place says nothing.
#[cfg(any(test, feature = "fuzzing"))]
#[must_use]
pub(crate) fn events_may_change_programs(events: &[InotifyEvent<'_>]) -> bool {
    events.iter().any(event_may_change_programs)
}

fn event_may_change_programs(event: &InotifyEvent<'_>) -> bool {
    event.mask & IN_Q_OVERFLOW != 0 || name_may_change_programs(event.name)
}

/// What the watch registry asks of the OS; tests stand a fake disk in for it.
pub(crate) trait WatchKernel {
    /// The watch descriptor of `dir`, the same one for a directory already
    /// watched; `None` when it cannot be watched.
    fn add_watch(&mut self, dir: &Path) -> Option<i32>;
    fn remove_watch(&mut self, wd: i32);
    /// The directories directly inside `dir`, links not followed.
    fn subdirs(&mut self, dir: &Path) -> Vec<PathBuf>;
}

pub(crate) type WatchId = u64;

/// One folder watch: the directories it holds, by descriptor.
struct WatchedFolder {
    root: PathBuf,
    subfolders: bool,
    dirs: HashMap<i32, PathBuf>,
    /// `None` while the folder itself is gone; it is looked for again.
    root_wd: Option<i32>,
    on_change: NetworkChangeCallback,
}

/// Every folder watch over one inotify instance. An event goes by descriptor
/// to the watches holding it; a descriptor goes back to the kernel when its
/// last holder lets go. The kernel numbers watches cyclically, so a late
/// `IN_IGNORED` for a given-back descriptor never names a newer watch.
#[derive(Default)]
pub(crate) struct WatchRegistry {
    next_id: WatchId,
    watches: HashMap<WatchId, WatchedFolder>,
    holders: HashMap<i32, Vec<WatchId>>,
}

impl WatchRegistry {
    /// `None` when `root` itself cannot be watched.
    pub(crate) fn subscribe(
        &mut self,
        kernel: &mut impl WatchKernel,
        root: &Path,
        subfolders: bool,
        on_change: NetworkChangeCallback,
    ) -> Option<WatchId> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.watches.insert(
            id,
            WatchedFolder {
                root: root.to_path_buf(),
                subfolders,
                dirs: HashMap::new(),
                root_wd: None,
                on_change,
            },
        );
        let Some(root_wd) = self.watch_dir(kernel, id, root) else {
            self.watches.remove(&id);
            return None;
        };
        if let Some(watch) = self.watches.get_mut(&id) {
            watch.root_wd = Some(root_wd);
        }
        self.add_tree(kernel, id, root);
        Some(id)
    }

    pub(crate) fn unsubscribe(&mut self, kernel: &mut impl WatchKernel, id: WatchId) {
        let Some(watch) = self.watches.remove(&id) else {
            return;
        };
        for wd in watch.dirs.into_keys() {
            self.release(kernel, id, wd);
        }
    }

    /// Applies one read batch; returns the callbacks of the watches whose
    /// programs may have changed, to be called outside the registry's lock.
    pub(crate) fn handle(
        &mut self,
        kernel: &mut impl WatchKernel,
        batch: &[InotifyEvent<'_>],
    ) -> Vec<NetworkChangeCallback> {
        let mut due: Vec<WatchId> = Vec::new();
        for event in batch {
            if event.mask & IN_Q_OVERFLOW != 0 {
                // Creations may be among the dropped events: trees are walked
                // again, a directory already held answers with its own wd.
                let ids: Vec<WatchId> = self.watches.keys().copied().collect();
                for id in ids {
                    if let Some(root) = self.held_root(id) {
                        self.add_tree(kernel, id, &root);
                    }
                    due.push(id);
                }
                continue;
            }
            if event.mask & IN_IGNORED != 0 {
                // The kernel dropped the watch for every holder.
                for id in self.holders.remove(&event.wd).unwrap_or_default() {
                    let Some(watch) = self.watches.get_mut(&id) else {
                        continue;
                    };
                    watch.dirs.remove(&event.wd);
                    if watch.root_wd == Some(event.wd) {
                        self.lose_root(kernel, id);
                    }
                    due.push(id);
                }
                continue;
            }
            let holders = self.holders.get(&event.wd).cloned().unwrap_or_default();
            for id in holders {
                self.apply(kernel, id, event, &mut due);
            }
        }
        self.callbacks(due)
    }

    pub(crate) fn has_lost_roots(&self) -> bool {
        self.watches.values().any(|w| w.root_wd.is_none())
    }

    /// Watches again every folder that is back at its path; their callbacks.
    pub(crate) fn retry_lost_roots(
        &mut self,
        kernel: &mut impl WatchKernel,
    ) -> Vec<NetworkChangeCallback> {
        let lost: Vec<(WatchId, PathBuf)> = self
            .watches
            .iter()
            .filter(|(_, w)| w.root_wd.is_none())
            .map(|(id, w)| (*id, w.root.clone()))
            .collect();
        let mut back = Vec::new();
        for (id, root) in lost {
            let Some(root_wd) = self.watch_dir(kernel, id, &root) else {
                continue;
            };
            if let Some(watch) = self.watches.get_mut(&id) {
                watch.root_wd = Some(root_wd);
            }
            self.add_tree(kernel, id, &root);
            back.push(id);
        }
        self.callbacks(back)
    }

    fn apply(
        &mut self,
        kernel: &mut impl WatchKernel,
        id: WatchId,
        event: &InotifyEvent<'_>,
        due: &mut Vec<WatchId>,
    ) {
        let Some((is_root, dir, subfolders)) = self.watches.get(&id).map(|w| {
            (
                w.root_wd == Some(event.wd),
                w.dirs.get(&event.wd).cloned(),
                w.subfolders,
            )
        }) else {
            return;
        };
        if is_root && event.mask & (IN_DELETE_SELF | IN_MOVE_SELF) != 0 {
            // The folder the rule names is no longer at its path.
            self.lose_root(kernel, id);
            due.push(id);
            return;
        }
        let Some(dir) = dir else {
            return;
        };
        let child_dir =
            event.mask & IN_ISDIR != 0 && !event.name.is_empty() && !event.name.contains('/');
        if child_dir && event.mask & IN_MOVED_FROM != 0 {
            // Its watches keep their descriptors but no longer its path.
            self.forget_subtree(kernel, id, &dir.join(event.name));
        }
        // A new folder below a tree is watched as soon as its creation is
        // read; what was written into it meanwhile the next listing sees.
        if child_dir && subfolders && event.mask & (IN_CREATE | IN_MOVED_TO) != 0 {
            self.add_tree(kernel, id, &dir.join(event.name));
        }
        if event_may_change_programs(event) {
            due.push(id);
        }
    }

    fn held_root(&self, id: WatchId) -> Option<PathBuf> {
        self.watches
            .get(&id)
            .filter(|w| w.root_wd.is_some())
            .map(|w| w.root.clone())
    }

    fn callbacks(&self, mut ids: Vec<WatchId>) -> Vec<NetworkChangeCallback> {
        ids.sort_unstable();
        ids.dedup();
        ids.iter()
            .filter_map(|id| self.watches.get(id))
            .map(|w| Arc::clone(&w.on_change))
            .collect()
    }

    fn watch_dir(&mut self, kernel: &mut impl WatchKernel, id: WatchId, dir: &Path) -> Option<i32> {
        let watch = self.watches.get_mut(&id)?;
        if watch.dirs.len() >= MAX_WATCHED_DIRS {
            return None;
        }
        let wd = kernel.add_watch(dir)?;
        watch.dirs.insert(wd, dir.to_path_buf());
        let holders = self.holders.entry(wd).or_default();
        if !holders.contains(&id) {
            holders.push(id);
        }
        Some(wd)
    }

    /// `top` and, with subfolders, the directories below it, breadth first,
    /// links never followed, to the listing's own depth.
    fn add_tree(&mut self, kernel: &mut impl WatchKernel, id: WatchId, top: &Path) {
        let Some(subfolders) = self.watches.get(&id).map(|w| w.subfolders) else {
            return;
        };
        let mut queue: VecDeque<(PathBuf, u32)> = VecDeque::from([(top.to_path_buf(), 0)]);
        while let Some((dir, depth)) = queue.pop_front() {
            if self.watch_dir(kernel, id, &dir).is_none() {
                if self.is_full(id) {
                    return;
                }
                // One unreadable directory is skipped, not the rest of the tree.
                continue;
            }
            if !subfolders || depth >= LISTING_MAX_DEPTH {
                continue;
            }
            for below in kernel.subdirs(&dir) {
                if queue.len() >= MAX_WATCHED_DIRS {
                    break;
                }
                queue.push_back((below, depth + 1));
            }
        }
    }

    fn is_full(&self, id: WatchId) -> bool {
        self.watches
            .get(&id)
            .is_none_or(|w| w.dirs.len() >= MAX_WATCHED_DIRS)
    }

    /// `id` stops holding `wd`; the last holder gives it back to the kernel.
    fn release(&mut self, kernel: &mut impl WatchKernel, id: WatchId, wd: i32) {
        let Some(holders) = self.holders.get_mut(&wd) else {
            return;
        };
        holders.retain(|holder| *holder != id);
        if holders.is_empty() {
            self.holders.remove(&wd);
            kernel.remove_watch(wd);
        }
    }

    fn lose_root(&mut self, kernel: &mut impl WatchKernel, id: WatchId) {
        let Some(watch) = self.watches.get_mut(&id) else {
            return;
        };
        watch.root_wd = None;
        let held: Vec<i32> = watch.dirs.drain().map(|(wd, _)| wd).collect();
        for wd in held {
            self.release(kernel, id, wd);
        }
    }

    fn forget_subtree(&mut self, kernel: &mut impl WatchKernel, id: WatchId, top: &Path) {
        let Some(watch) = self.watches.get_mut(&id) else {
            return;
        };
        let gone: Vec<i32> = watch
            .dirs
            .iter()
            .filter(|(_, path)| path.starts_with(top))
            .map(|(wd, _)| *wd)
            .collect();
        if watch.root_wd.is_some_and(|root| gone.contains(&root)) {
            self.lose_root(kernel, id);
            return;
        }
        for wd in &gone {
            watch.dirs.remove(wd);
        }
        for wd in gone {
            self.release(kernel, id, wd);
        }
    }

    #[cfg(test)]
    fn watched(&self, id: WatchId) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = self
            .watches
            .get(&id)
            .map(|w| w.dirs.values().cloned().collect())
            .unwrap_or_default();
        dirs.sort();
        dirs
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod mechanism {
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Duration, Instant};

    use nrr_platform_api::app_folders::LISTING_ENTRY_BUDGET;
    use nrr_platform_api::error::PlatformError;
    use nrr_platform_api::network_change::NetworkChangeCallback;

    use super::{WatchId, WatchKernel, WatchRegistry};
    use crate::inotify_events::events;
    use crate::inotify_events::fd::close_fd;

    /// Changes to a directory's own entries that may add or remove a program:
    /// created, removed, renamed in or out, made executable, the directory
    /// itself gone.
    const MASK: u32 = libc::IN_CREATE
        | libc::IN_DELETE
        | libc::IN_MOVED_TO
        | libc::IN_MOVED_FROM
        | libc::IN_ATTRIB
        | libc::IN_DELETE_SELF
        | libc::IN_MOVE_SELF
        | libc::IN_ONLYDIR;

    /// How often a watch whose folder is gone looks for it again.
    const LOST_ROOT_RETRY_MS: libc::c_int = 5_000;

    /// The process's one inotify instance, started by the first folder watch:
    /// instances are counted per user, and root shares that budget with the
    /// system's own daemons.
    static HUB: Mutex<Option<Arc<Hub>>> = Mutex::new(None);

    struct Hub {
        fd: libc::c_int,
        registry: Mutex<WatchRegistry>,
        /// The reader stopped; the next watch starts a new instance.
        dead: AtomicBool,
    }

    struct Inotify(libc::c_int);

    impl WatchKernel for Inotify {
        fn add_watch(&mut self, dir: &Path) -> Option<i32> {
            let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
            // SAFETY: `path` is NUL-terminated and outlives the call; the
            // descriptor is the hub's live inotify instance.
            let wd = unsafe { libc::inotify_add_watch(self.0, path.as_ptr(), MASK) };
            (wd >= 0).then_some(wd)
        }

        fn remove_watch(&mut self, wd: i32) {
            // SAFETY: integers in; a watch the kernel already dropped answers EINVAL.
            unsafe {
                libc::inotify_rm_watch(self.0, wd);
            }
        }

        fn subdirs(&mut self, dir: &Path) -> Vec<PathBuf> {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return Vec::new();
            };
            entries
                .flatten()
                .take(LISTING_ENTRY_BUDGET as usize)
                .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
                .map(|entry| entry.path())
                .collect()
        }
    }

    impl Hub {
        fn registry(&self) -> MutexGuard<'_, WatchRegistry> {
            self.registry.lock().unwrap_or_else(|p| p.into_inner())
        }

        fn shared() -> Result<Arc<Self>, PlatformError> {
            let mut slot = HUB.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(hub) = slot.as_ref() {
                if !hub.dead.load(Ordering::Acquire) {
                    return Ok(Arc::clone(hub));
                }
            }
            // SAFETY: flags in, a descriptor out.
            let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
            if fd < 0 {
                return Err(PlatformError::Transient {
                    operation: "inotify_init1",
                    detail: std::io::Error::last_os_error().to_string(),
                });
            }
            let hub = Arc::new(Self {
                fd,
                registry: Mutex::new(WatchRegistry::default()),
                dead: AtomicBool::new(false),
            });
            let reader = Arc::clone(&hub);
            std::thread::Builder::new()
                .name("nrr-app-folder-watch".to_string())
                .spawn(move || reader.read_forever())
                .map_err(|e| PlatformError::Transient {
                    operation: "spawn app folder watch thread",
                    detail: e.to_string(),
                })?;
            *slot = Some(Arc::clone(&hub));
            Ok(hub)
        }

        fn read_forever(&self) {
            let retry_every = Duration::from_millis(LOST_ROOT_RETRY_MS.unsigned_abs().into());
            let mut retried_at = Instant::now();
            let mut buffer = vec![0u8; 16 * 1024];
            loop {
                let retrying = self.registry().has_lost_roots();
                let timeout = if retrying { LOST_ROOT_RETRY_MS } else { -1 };
                let mut fds = [libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLIN,
                    revents: 0,
                }];
                // SAFETY: `fds` is a live one-element array.
                let rc = unsafe { libc::poll(fds.as_mut_ptr(), 1, timeout) };
                if rc < 0 {
                    if interrupted() {
                        continue;
                    }
                    self.dead.store(true, Ordering::Release);
                    return;
                }
                let mut due = Vec::new();
                if rc > 0 {
                    if fds[0].revents & libc::POLLIN == 0 {
                        self.dead.store(true, Ordering::Release);
                        return;
                    }
                    // SAFETY: `buffer` is live and writable for its own length.
                    let read =
                        unsafe { libc::read(self.fd, buffer.as_mut_ptr().cast(), buffer.len()) };
                    if read < 0 {
                        if interrupted() {
                            continue;
                        }
                        self.dead.store(true, Ordering::Release);
                        return;
                    }
                    let filled = buffer.get(..read as usize).unwrap_or_default();
                    due = self
                        .registry()
                        .handle(&mut Inotify(self.fd), &events(filled));
                }
                if retrying && retried_at.elapsed() >= retry_every {
                    retried_at = Instant::now();
                    due.extend(self.registry().retry_lost_roots(&mut Inotify(self.fd)));
                }
                for on_change in due {
                    // A panic must not end the watch the service relies on.
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| on_change()));
                }
            }
        }
    }

    impl Drop for Hub {
        fn drop(&mut self) {
            close_fd(self.fd);
        }
    }

    fn interrupted() -> bool {
        std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
    }

    /// One folder watch: its share of the hub, given back on drop.
    pub(super) struct FolderWatch {
        hub: Arc<Hub>,
        id: WatchId,
    }

    impl FolderWatch {
        pub(super) fn start(
            folder: &Path,
            subfolders: bool,
            on_change: NetworkChangeCallback,
        ) -> Result<Self, PlatformError> {
            let hub = Hub::shared()?;
            let id = hub
                .registry()
                .subscribe(&mut Inotify(hub.fd), folder, subfolders, on_change)
                .ok_or_else(|| PlatformError::Transient {
                    operation: "inotify_add_watch",
                    detail: std::io::Error::last_os_error().to_string(),
                })?;
            Ok(Self { hub, id })
        }
    }

    impl Drop for FolderWatch {
        fn drop(&mut self) {
            self.hub
                .registry()
                .unsubscribe(&mut Inotify(self.hub.fd), self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inotify_events::events;
    use crate::inotify_events::tests::event;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
        svc:x:998:998::/var/lib/svc:/usr/sbin/nologin\n\
        alice:x:1000:1000:Alice:/home/alice:/bin/bash\n\
        bob:x:1001:1001:Bob:/home/bob:/bin/bash\n\
        odd:x:1002:1002::/:/bin/sh\n\
        nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
        broken line without fields\n";

    #[test]
    fn the_homes_of_people_are_read_and_service_accounts_are_not() {
        let homes = homes_from_passwd(PASSWD);
        let uids: Vec<u32> = homes.iter().map(|(uid, _)| *uid).collect();
        assert_eq!(uids, [1000, 1001], "{homes:?}");
    }

    /// One user's rule never reads another user's folder; the owner's own
    /// home, and a folder that is nobody's, are read.
    #[test]
    fn a_folder_in_another_users_home_is_foreign_to_the_owner() {
        let homes = homes_from_passwd(PASSWD);
        assert!(is_foreign_home("/home/bob/apps", "unix:uid:1000", &homes));
        assert!(!is_foreign_home(
            "/home/alice/apps",
            "unix:uid:1000",
            &homes
        ));
        assert!(!is_foreign_home("/opt/app", "unix:uid:1000", &homes));
        assert!(
            !is_foreign_home("/home/bobby/apps", "unix:uid:1000", &homes),
            "a prefix stops at a folder boundary"
        );
        assert!(
            is_foreign_home("/home/alice/apps", "baseline", &homes),
            "a rule of nobody in particular reads nobody's home"
        );
    }

    /// A rule from `~` starts at the owner's own home; the shared baseline
    /// and an account without a home of its own start nowhere.
    #[test]
    fn the_home_of_an_owner_is_their_own() {
        let homes = homes_from_passwd(PASSWD);
        assert_eq!(
            home_of("unix:uid:1001", &homes),
            Some(PathBuf::from("/home/bob"))
        );
        assert_eq!(home_of("unix:uid:0", &homes), None);
        assert_eq!(home_of("baseline", &homes), None);
        assert_eq!(home_of("unix:uid:x", &homes), None);
    }

    #[test]
    fn a_hostile_account_database_never_panics() {
        for text in [
            "",
            ":::::::::::",
            "a:b:99999999999999999999:c:d:/home/x:/bin/sh",
            "a:b:1000:c:d:relative/home:/bin/sh",
            "a:b:1000:c:d:/home/../etc:/bin/sh",
            "\u{0}\u{1}:x:1000",
        ] {
            let _ = homes_from_passwd(text);
        }
    }

    #[test]
    fn a_log_rewritten_beside_the_programs_is_noise_and_a_new_folder_is_not() {
        assert!(!events_may_change_programs(&events(&event(
            1, 0x100, "app.log"
        ))));
        assert!(events_may_change_programs(&events(&event(
            1,
            0x100 | crate::inotify_events::IN_ISDIR,
            "app-1.0.2"
        ))));
        assert!(events_may_change_programs(&events(&event(
            -1,
            IN_Q_OVERFLOW,
            ""
        ))));
    }

    #[cfg(target_os = "linux")]
    fn counting() -> (
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        NetworkChangeCallback,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        (
            hits,
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        )
    }

    #[cfg(target_os = "linux")]
    fn wait_for(hits: &std::sync::atomic::AtomicUsize, at_least: usize) -> usize {
        use std::sync::atomic::Ordering;
        let deadline = Instant::now() + Duration::from_secs(5);
        while hits.load(Ordering::SeqCst) < at_least && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        hits.load(Ordering::SeqCst)
    }

    /// A self-updating program's shape: a new version folder appears, then a
    /// program inside it. Both reach the callback, the second through the
    /// watch the first one added.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_program_in_a_new_version_folder_is_reported() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().expect("tempdir");
        let (hits, callback) = counting();
        let watch = LinuxProgramFolders::new()
            .watch(dir.path(), true, callback)
            .expect("watch");
        std::fs::create_dir(dir.path().join("app-2")).expect("mkdir");
        assert!(wait_for(&hits, 1) >= 1, "the folder");
        let seen = hits.load(Ordering::SeqCst);
        // Give the watch thread a moment to add the new folder's watch.
        std::thread::sleep(Duration::from_millis(100));
        let tool = dir.path().join("app-2").join("tool");
        std::fs::write(&tool, b"#!/bin/sh\n").expect("write");
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(wait_for(&hits, seen + 1) > seen, "the program inside it");
        let started = Instant::now();
        drop(watch);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "retired at once"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_missing_folder_cannot_be_watched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_hits, callback) = counting();
        assert!(LinuxProgramFolders::new()
            .watch(&dir.path().join("absent"), true, callback)
            .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_path_follows_a_link_to_its_folder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real");
        std::fs::create_dir(&real).expect("mkdir");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("link");
        let folders = LinuxProgramFolders::new();
        assert_eq!(folders.real_path(&link), std::fs::canonicalize(&real).ok());
        assert_eq!(folders.place(&link), PlaceOnDisk::Folder);
    }

    /// A disk of directories and the watches the kernel holds on them.
    #[derive(Default)]
    struct FakeDisk {
        dirs: std::collections::BTreeSet<PathBuf>,
        watches: HashMap<PathBuf, i32>,
        next_wd: i32,
        given_back: Vec<i32>,
    }

    impl FakeDisk {
        fn with(dirs: &[&str]) -> Self {
            Self {
                dirs: dirs.iter().map(PathBuf::from).collect(),
                ..Self::default()
            }
        }

        fn wd(&self, dir: &str) -> i32 {
            self.watches.get(Path::new(dir)).copied().unwrap_or(-1)
        }

        /// The directory is removed; the kernel drops its watch.
        fn remove_dir(&mut self, dir: &str) -> i32 {
            self.dirs.remove(Path::new(dir));
            self.watches.remove(Path::new(dir)).unwrap_or(-1)
        }
    }

    impl WatchKernel for FakeDisk {
        fn add_watch(&mut self, dir: &Path) -> Option<i32> {
            if !self.dirs.contains(dir) {
                return None;
            }
            if let Some(wd) = self.watches.get(dir) {
                return Some(*wd);
            }
            self.next_wd += 1;
            self.watches.insert(dir.to_path_buf(), self.next_wd);
            Some(self.next_wd)
        }

        fn remove_watch(&mut self, wd: i32) {
            self.watches.retain(|_, held| *held != wd);
            self.given_back.push(wd);
        }

        fn subdirs(&mut self, dir: &Path) -> Vec<PathBuf> {
            self.dirs
                .iter()
                .filter(|d| d.parent() == Some(dir))
                .cloned()
                .collect()
        }
    }

    fn ev(wd: i32, mask: u32, name: &str) -> InotifyEvent<'_> {
        InotifyEvent { wd, mask, name }
    }

    fn noop() -> NetworkChangeCallback {
        std::sync::Arc::new(|| {})
    }

    /// Subfolders that come and go never use up the watch: a removed
    /// directory's descriptor is forgotten when the kernel drops it.
    #[test]
    fn subfolders_created_and_removed_never_exhaust_the_watch() {
        let mut disk = FakeDisk::with(&["/opt/app"]);
        let mut registry = WatchRegistry::default();
        let id = registry
            .subscribe(&mut disk, Path::new("/opt/app"), true, noop())
            .expect("watch");
        let root = disk.wd("/opt/app");
        for n in 0..(MAX_WATCHED_DIRS * 2) {
            let name = format!("build-{n}");
            let path = format!("/opt/app/{name}");
            disk.dirs.insert(PathBuf::from(&path));
            registry.handle(&mut disk, &[ev(root, IN_CREATE | IN_ISDIR, &name)]);
            let gone = disk.remove_dir(&path);
            registry.handle(&mut disk, &[ev(gone, IN_IGNORED, "")]);
        }
        disk.dirs.insert(PathBuf::from("/opt/app/latest"));
        registry.handle(&mut disk, &[ev(root, IN_CREATE | IN_ISDIR, "latest")]);
        assert_eq!(
            registry.watched(id),
            [PathBuf::from("/opt/app"), PathBuf::from("/opt/app/latest")]
        );
    }

    /// A renamed folder is watched under its new name, so a folder created
    /// inside it is found where it really is.
    #[test]
    fn a_renamed_subfolder_is_followed_to_its_new_name() {
        let mut disk = FakeDisk::with(&["/opt/app", "/opt/app/old", "/opt/app/old/bin"]);
        let mut registry = WatchRegistry::default();
        let id = registry
            .subscribe(&mut disk, Path::new("/opt/app"), true, noop())
            .expect("watch");
        let root = disk.wd("/opt/app");
        disk.dirs = ["/opt/app", "/opt/app/new", "/opt/app/new/bin"]
            .iter()
            .map(PathBuf::from)
            .collect();
        registry.handle(
            &mut disk,
            &[
                ev(root, IN_MOVED_FROM | IN_ISDIR, "old"),
                ev(root, IN_MOVED_TO | IN_ISDIR, "new"),
            ],
        );
        disk.dirs.insert(PathBuf::from("/opt/app/new/lib"));
        let new = disk.wd("/opt/app/new");
        registry.handle(&mut disk, &[ev(new, IN_CREATE | IN_ISDIR, "lib")]);
        assert_eq!(
            registry.watched(id),
            [
                PathBuf::from("/opt/app"),
                PathBuf::from("/opt/app/new"),
                PathBuf::from("/opt/app/new/bin"),
                PathBuf::from("/opt/app/new/lib"),
            ]
        );
    }

    /// The rule's folder deleted and put back (a reinstall) is watched again.
    #[test]
    fn a_folder_removed_and_put_back_is_watched_again() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&hits);
        let on_change: NetworkChangeCallback = std::sync::Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let mut disk = FakeDisk::with(&["/opt/app"]);
        let mut registry = WatchRegistry::default();
        let id = registry
            .subscribe(&mut disk, Path::new("/opt/app"), false, on_change)
            .expect("watch");
        let gone = disk.remove_dir("/opt/app");
        for call in registry.handle(&mut disk, &[ev(gone, IN_IGNORED, "")]) {
            call();
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the folder's loss is reported"
        );
        assert!(registry.has_lost_roots());
        assert!(
            registry.retry_lost_roots(&mut disk).is_empty(),
            "still gone"
        );
        disk.dirs.insert(PathBuf::from("/opt/app"));
        for call in registry.retry_lost_roots(&mut disk) {
            call();
        }
        assert_eq!(hits.load(Ordering::SeqCst), 2, "its return is reported");
        assert!(!registry.has_lost_roots());
        assert_eq!(registry.watched(id), [PathBuf::from("/opt/app")]);
    }

    /// Two rules over one folder share its watch; it is given back only when
    /// the second lets go, and each hears only of its own folders.
    #[test]
    fn a_folder_two_rules_watch_is_given_back_after_the_last() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&hits);
        let counted: NetworkChangeCallback = std::sync::Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let mut disk = FakeDisk::with(&["/opt/app", "/srv/tools"]);
        let mut registry = WatchRegistry::default();
        let first = registry
            .subscribe(&mut disk, Path::new("/opt/app"), false, noop())
            .expect("first");
        let second = registry
            .subscribe(&mut disk, Path::new("/opt/app"), false, noop())
            .expect("second");
        let other = registry
            .subscribe(&mut disk, Path::new("/srv/tools"), false, counted)
            .expect("other");
        let app = disk.wd("/opt/app");
        for call in registry.handle(&mut disk, &[ev(app, IN_CREATE, "tool")]) {
            call();
        }
        assert_eq!(hits.load(Ordering::SeqCst), 0, "another folder's change");
        registry.unsubscribe(&mut disk, first);
        assert!(disk.given_back.is_empty(), "still held by the second rule");
        registry.unsubscribe(&mut disk, second);
        assert_eq!(disk.given_back, [app]);
        registry.unsubscribe(&mut disk, other);
        assert_eq!(disk.given_back.len(), 2);
    }
}
