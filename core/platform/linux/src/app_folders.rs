//! Linux mechanism behind [`ProgramFolders`]: real paths through every link
//! (what `/proc/<pid>/exe` reports), programs as regular files with an
//! execute bit, other users' homes from the account database, and folder
//! watches over inotify.
//!
//! inotify watches one directory at a time, so a folder with its subfolders
//! takes a watch per directory, up to [`MAX_WATCHED_DIRS`]; a directory
//! created later gets its watch when its creation is read. A burst of events
//! is coalesced by the caller, which lists the folder again and decides.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nrr_platform_api::app_folders::{
    is_program_file, name_may_change_programs, place_of, PathStyle, PlaceOnDisk, ProgramFolders,
};
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::network_change::{NetworkChangeCallback, NetworkChangeSubscription};
use nrr_shared::app_path::path_segments;

use crate::inotify_events::{InotifyEvent, IN_Q_OVERFLOW};

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
#[must_use]
pub(crate) fn events_may_change_programs(events: &[InotifyEvent<'_>]) -> bool {
    events
        .iter()
        .any(|e| e.mask & IN_Q_OVERFLOW != 0 || name_may_change_programs(e.name))
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod mechanism {
    use std::collections::{HashMap, VecDeque};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use nrr_platform_api::app_folders::LISTING_MAX_DEPTH;
    use nrr_platform_api::error::PlatformError;
    use nrr_platform_api::network_change::NetworkChangeCallback;

    use super::{events_may_change_programs, MAX_WATCHED_DIRS};
    use crate::inotify_events::fd::{close_fd, open_wake_pipe, wake};
    use crate::inotify_events::{events, IN_ISDIR};

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

    pub(super) struct FolderWatch {
        wake_writer: libc::c_int,
        reader: Option<std::thread::JoinHandle<()>>,
    }

    /// The directories of one watch, by watch descriptor.
    struct Watched {
        fd: libc::c_int,
        dirs: HashMap<i32, PathBuf>,
        subfolders: bool,
    }

    impl Watched {
        fn add(&mut self, dir: &Path) -> bool {
            if self.dirs.len() >= MAX_WATCHED_DIRS {
                return false;
            }
            let Ok(path) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
                return false;
            };
            // SAFETY: `path` is NUL-terminated and outlives the call; `fd` is
            // the live inotify descriptor this value owns.
            let wd = unsafe { libc::inotify_add_watch(self.fd, path.as_ptr(), MASK) };
            if wd < 0 {
                return false;
            }
            self.dirs.insert(wd, dir.to_path_buf());
            true
        }

        /// `root` and, with subfolders, the directories below it, breadth
        /// first, links never followed, to the listing's own depth.
        fn add_tree(&mut self, root: &Path) {
            let mut queue: VecDeque<(PathBuf, u32)> = VecDeque::new();
            queue.push_back((root.to_path_buf(), 0));
            while let Some((dir, depth)) = queue.pop_front() {
                if self.dirs.len() >= MAX_WATCHED_DIRS {
                    return;
                }
                // One unreadable directory is skipped, not the rest of the tree.
                if !self.add(&dir) {
                    continue;
                }
                if !self.subfolders || depth >= LISTING_MAX_DEPTH {
                    continue;
                }
                let Ok(entries) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for entry in entries.flatten() {
                    if entry.file_type().is_ok_and(|t| t.is_dir()) {
                        queue.push_back((entry.path(), depth + 1));
                    }
                }
            }
        }
    }

    impl FolderWatch {
        pub(super) fn start(
            folder: &Path,
            subfolders: bool,
            on_change: NetworkChangeCallback,
        ) -> Result<Self, PlatformError> {
            // SAFETY: flags in, a descriptor out.
            let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
            if fd < 0 {
                return Err(PlatformError::Transient {
                    operation: "inotify_init1",
                    detail: std::io::Error::last_os_error().to_string(),
                });
            }
            let mut watched = Watched {
                fd,
                dirs: HashMap::new(),
                subfolders,
            };
            if !watched.add(folder) {
                close_fd(fd);
                return Err(PlatformError::Transient {
                    operation: "inotify_add_watch",
                    detail: std::io::Error::last_os_error().to_string(),
                });
            }
            if subfolders {
                // The root again is harmless: inotify answers with its wd.
                watched.add_tree(folder);
            }
            let (wake_reader, wake_writer) = match open_wake_pipe() {
                Ok(pair) => pair,
                Err(e) => {
                    close_fd(fd);
                    return Err(e);
                }
            };
            let reader = std::thread::Builder::new()
                .name("nrr-app-folder-watch".to_string())
                .spawn(move || {
                    read_until_woken(&mut watched, wake_reader, &on_change);
                    close_fd(fd);
                    close_fd(wake_reader);
                })
                .map_err(|e| {
                    close_fd(fd);
                    close_fd(wake_reader);
                    close_fd(wake_writer);
                    PlatformError::Transient {
                        operation: "spawn app folder watch thread",
                        detail: e.to_string(),
                    }
                })?;
            Ok(Self {
                wake_writer,
                reader: Some(reader),
            })
        }
    }

    impl Drop for FolderWatch {
        fn drop(&mut self) {
            wake(self.wake_writer);
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
            close_fd(self.wake_writer);
        }
    }

    fn read_until_woken(
        watched: &mut Watched,
        wake_reader: libc::c_int,
        on_change: &NetworkChangeCallback,
    ) {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            let mut fds = [
                libc::pollfd {
                    fd: watched.fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: wake_reader,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: `fds` is a live two-element array; no timeout.
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
            if rc < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return;
            }
            if fds[1].revents != 0 {
                return;
            }
            if fds[0].revents & libc::POLLIN == 0 {
                continue;
            }
            // SAFETY: `buffer` is live and writable for its own length.
            let read = unsafe { libc::read(watched.fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            if read < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return;
            }
            let filled = buffer.get(..read as usize).unwrap_or_default();
            let batch = events(filled);
            // A new folder below a tree is watched as soon as its creation is
            // read; what was written into it meanwhile the next listing sees.
            if watched.subfolders {
                let created: Vec<PathBuf> = batch
                    .iter()
                    .filter(|e| e.mask & IN_ISDIR != 0)
                    .filter(|e| e.mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0)
                    .filter(|e| !e.name.is_empty() && !e.name.contains('/'))
                    .filter_map(|e| watched.dirs.get(&e.wd).map(|dir| dir.join(e.name)))
                    .collect();
                for dir in created {
                    watched.add_tree(&dir);
                }
            }
            if events_may_change_programs(&batch) {
                // A panic must not end the watch the service relies on.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| on_change()));
            }
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
}
