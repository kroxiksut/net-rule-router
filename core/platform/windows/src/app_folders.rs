//! Windows mechanism behind [`ProgramFolders`]: real paths in the spelling a
//! process image is reported with, programs as `.exe` files, other users'
//! profiles from the machine's profile list, and folder watches over
//! `ReadDirectoryChangesW`.
//!
//! One thread per watched folder parks in `WaitForMultipleObjects` on the
//! change and a stop event: no timer, no wakeup while nothing changes. The
//! records the OS writes are walked by the port's own bounded parser
//! ([`nrr_platform_api::app_folders::notify_buffer_is_relevant`]).

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use nrr_platform_api::app_folders::{
    is_program_file, notify_buffer_is_relevant, place_of, strip_verbatim_drive_prefix, PathStyle,
    PlaceOnDisk, ProgramFolders,
};
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::network_change::{NetworkChangeCallback, NetworkChangeSubscription};
use nrr_shared::app_path::path_segments;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadDirectoryChangesW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED,
    FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
use windows::Win32::System::Threading::{
    CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects, INFINITE,
};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

/// Where Windows lists every profile on the machine, one subkey per SID.
const PROFILE_LIST_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

/// How long the profile list is remembered: profiles appear when someone signs
/// in for the first time, which is rare next to a pass.
const PROFILE_LIST_TTL: Duration = Duration::from_secs(60);

/// Profiles read from the list; a machine with more is not one this guards.
const MAX_PROFILES: usize = 512;

/// How long starting a watch waits for its first request to be queued.
const ARM_WAIT: Duration = Duration::from_secs(2);

/// Missing folder levels climbed to find the one a folder would be created in.
const MAX_WRITABLE_CHECK_LEVELS: usize = 64;

/// Four-byte words `ReadDirectoryChangesW` may fill per call: 64 KiB, the most
/// a network share accepts, and far more than one burst of names needs.
const NOTIFY_BUFFER_WORDS: usize = 16 * 1024;

/// `(SID, profile folder segments)` with the moment they were read.
type ProfilesCache = Option<(Instant, Vec<(String, Vec<String>)>)>;

/// The Windows [`ProgramFolders`].
#[derive(Default)]
pub struct WindowsProgramFolders {
    profiles: Mutex<ProfilesCache>,
}

impl WindowsProgramFolders {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn profiles(&self) -> Vec<(String, Vec<String>)> {
        let mut cached = self.profiles.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((at, profiles)) = cached.as_ref() {
            if at.elapsed() < PROFILE_LIST_TTL {
                return profiles.clone();
            }
        }
        let profiles = read_profile_list();
        *cached = Some((Instant::now(), profiles.clone()));
        profiles
    }
}

impl ProgramFolders for WindowsProgramFolders {
    fn path_style(&self) -> PathStyle {
        PathStyle::Windows
    }

    fn place(&self, path: &Path) -> PlaceOnDisk {
        place_of(path)
    }

    fn real_path(&self, path: &Path) -> Option<PathBuf> {
        std::fs::canonicalize(path)
            .ok()
            .map(strip_verbatim_drive_prefix)
    }

    fn is_program(&self, path: &Path) -> bool {
        is_program_file(path, PathStyle::Windows)
    }

    fn foreign_profile(&self, place: &Path, owner: &str) -> bool {
        let Some(place) = path_segments(&place.to_string_lossy(), PathStyle::Windows, false) else {
            return false;
        };
        self.profiles()
            .iter()
            .any(|(sid, profile)| !sid.eq_ignore_ascii_case(owner) && place.starts_with(profile))
    }

    fn owner_profile(&self, owner: &str) -> Option<PathBuf> {
        self.profiles()
            .into_iter()
            .find(|(sid, _)| sid.eq_ignore_ascii_case(owner))
            .map(|(_, profile)| PathBuf::from(profile.join(r"\")))
    }

    fn owner_may_list(&self, place: &Path, owner: &str) -> bool {
        if !is_user_sid(owner) {
            return true;
        }
        let folder = if place.is_file() {
            place.parent().unwrap_or(place)
        } else {
            place
        };
        if !folder.is_dir() {
            return true;
        }
        // An account the system cannot resolve right now (a domain user off
        // the network) keeps the answer it always had.
        crate::trusted_location::sid_may_list(folder, owner).unwrap_or(true)
    }

    fn writable_by_anyone(&self, place: &Path) -> bool {
        // A file is put there by whoever may write into its folder; a missing
        // folder by whoever may create it in the nearest one that exists.
        let start = if place.is_file() {
            place.parent()
        } else {
            Some(place)
        };
        start
            .into_iter()
            .flat_map(Path::ancestors)
            .take(MAX_WRITABLE_CHECK_LEVELS)
            .find(|level| !level.as_os_str().is_empty() && level.is_dir())
            .is_some_and(|folder| crate::trusted_location::open_to_everyone(folder) == Ok(true))
    }

    fn watch(
        &self,
        folder: &Path,
        subfolders: bool,
        on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        let watch = DirectoryWatch::start(folder, subfolders, on_change)?;
        Ok(NetworkChangeSubscription::new(Box::new(watch)))
    }
}

/// The profile folders of the people who sign in to this machine. Service
/// profiles live under the Windows folder, which the protection already
/// closes, so only user SIDs are read.
fn read_profile_list() -> Vec<(String, Vec<String>)> {
    use crate::win32_ffi::registry;
    registry::enum_subkeys(HKEY_LOCAL_MACHINE, PROFILE_LIST_KEY)
        .into_iter()
        .filter(|sid| is_user_sid(sid))
        .take(MAX_PROFILES)
        .filter_map(|sid| {
            let key = format!(r"{PROFILE_LIST_KEY}\{sid}");
            let raw = registry::read_string(HKEY_LOCAL_MACHINE, &key, Some("ProfileImagePath"))?;
            let expanded = crate::app_path_resolver::expand_env(registry::unquote(&raw));
            let segments = path_segments(&expanded, PathStyle::Windows, false)?;
            // A profile at a drive root would make the whole drive one user's.
            (segments.len() > PathStyle::Windows.root_len()).then_some((sid, segments))
        })
        .collect()
}

/// A local, domain or cloud user account, not a service identity.
fn is_user_sid(sid: &str) -> bool {
    nrr_platform_api::types::is_user_account_sid(sid)
}

/// A raw handle crossing into the watch thread. The thread is its only user
/// until the guard joins it.
#[derive(Clone, Copy)]
struct SendHandle(isize);

impl SendHandle {
    fn of(handle: HANDLE) -> Self {
        Self(handle.0 as isize)
    }
    fn get(self) -> HANDLE {
        HANDLE(self.0 as *mut core::ffi::c_void)
    }
}

/// Owns the stop event and the thread; dropping it retires the thread, which
/// closes the folder handle.
struct DirectoryWatch {
    stop: SendHandle,
    thread: Option<JoinHandle<()>>,
}

impl DirectoryWatch {
    fn start(
        folder: &Path,
        subfolders: bool,
        on_change: NetworkChangeCallback,
    ) -> Result<Self, PlatformError> {
        let wide: Vec<u16> = folder
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is NUL-terminated UTF-16 outliving the call. Backup
        // semantics is what opens a directory; every share mode, so the watch
        // never stops a program from replacing or removing its own files.
        let directory = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_LIST_DIRECTORY.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                None,
            )
        }
        .map_err(|e| PlatformError::Transient {
            operation: "app_folders.open_directory",
            detail: e.to_string(),
        })?;
        // SAFETY: no security attributes, no name; manual reset so a stop
        // signalled before the thread waits is still seen.
        let stop = match unsafe { CreateEventW(None, true, false, PCWSTR::null()) } {
            Ok(event) => event,
            Err(e) => {
                close(directory);
                return Err(PlatformError::Transient {
                    operation: "app_folders.create_stop_event",
                    detail: e.to_string(),
                });
            }
        };
        let (directory, stop) = (SendHandle::of(directory), SendHandle::of(stop));
        let (armed_tx, armed_rx) = std::sync::mpsc::sync_channel(1);
        let spawned = std::thread::Builder::new()
            .name("nrr-app-folder-watch".to_string())
            .spawn(move || {
                watch_until_stopped(
                    directory.get(),
                    subfolders,
                    stop.get(),
                    &on_change,
                    armed_tx,
                );
                close(directory.get());
            });
        match spawned {
            Ok(thread) => {
                // The OS keeps changes only once the first request is queued:
                // a program written before that would never be reported.
                // Bounded, so a stuck thread never holds the caller.
                let _ = armed_rx.recv_timeout(ARM_WAIT);
                Ok(Self {
                    stop,
                    thread: Some(thread),
                })
            }
            Err(e) => {
                close(directory.get());
                close(stop.get());
                Err(PlatformError::Transient {
                    operation: "app_folders.spawn",
                    detail: e.to_string(),
                })
            }
        }
    }
}

impl Drop for DirectoryWatch {
    fn drop(&mut self) {
        // SAFETY: `stop` is the live event created in `start`.
        let _ = unsafe { SetEvent(self.stop.get()) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        close(self.stop.get());
    }
}

fn close(handle: HANDLE) {
    // SAFETY: every caller passes a handle it owns and does not use again.
    let _ = unsafe { CloseHandle(handle) };
}

/// Ask for the next batch of changes, wait for it or for `stop`, report it
/// when it may change which programs the folder holds. Returns when `stop` is
/// signalled or the folder can no longer be watched (removed, unmounted).
fn watch_until_stopped(
    directory: HANDLE,
    subfolders: bool,
    stop: HANDLE,
    on_change: &NetworkChangeCallback,
    armed: std::sync::mpsc::SyncSender<()>,
) {
    // SAFETY: no security attributes, no name; manual reset, cleared before
    // every request.
    let Ok(changed) = (unsafe { CreateEventW(None, true, false, PCWSTR::null()) }) else {
        return;
    };
    // `u32` words: the records must start on a DWORD boundary.
    let mut buffer = vec![0u32; NOTIFY_BUFFER_WORDS];
    let buffer_bytes = (NOTIFY_BUFFER_WORDS * 4) as u32;
    loop {
        let mut overlapped = OVERLAPPED {
            hEvent: changed,
            ..Default::default()
        };
        // SAFETY: `changed` is the live event created above.
        let _ = unsafe { ResetEvent(changed) };
        // SAFETY: `buffer` and `overlapped` outlive the request: every exit
        // below either sees it complete or cancels it and waits for the
        // cancellation before either is dropped.
        let queued = unsafe {
            ReadDirectoryChangesW(
                directory,
                buffer.as_mut_ptr().cast(),
                buffer_bytes,
                subfolders,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME,
                None,
                Some(&mut overlapped),
                None,
            )
        };
        // Sent once; later sends find the receiver gone or the slot full.
        let _ = armed.try_send(());
        if queued.is_err() {
            break;
        }
        // SAFETY: both handles are live events owned by this watch.
        let woke = unsafe { WaitForMultipleObjects(&[changed, stop], false, INFINITE) };
        let mut bytes = 0u32;
        if woke != WAIT_OBJECT_0 {
            // SAFETY: cancelling our own request on our own handle, then
            // waiting for it to unwind before `overlapped` goes out of scope.
            unsafe {
                let _ = CancelIoEx(directory, Some(&overlapped as *const OVERLAPPED));
                let _ = GetOverlappedResult(directory, &overlapped, &mut bytes, true);
            }
            break;
        }
        // SAFETY: the request completed; `overlapped` is still alive.
        let done = unsafe { GetOverlappedResult(directory, &overlapped, &mut bytes, false) };
        if done.is_err() {
            break;
        }
        // Zero bytes is the OS saying its buffer overflowed: anything may
        // have changed, which the parser reads as a change.
        let filled = (bytes as usize).min(NOTIFY_BUFFER_WORDS * 4);
        let records: Vec<u8> = buffer
            .iter()
            .flat_map(|word| word.to_ne_bytes())
            .take(filled)
            .collect();
        if notify_buffer_is_relevant(&records) {
            // A panic must not end the watch the service relies on.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| on_change()));
        }
    }
    close(changed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn counting() -> (Arc<AtomicUsize>, NetworkChangeCallback) {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        (
            hits,
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        )
    }

    fn wait_for(hits: &AtomicUsize, at_least: usize) -> usize {
        let deadline = Instant::now() + Duration::from_secs(5);
        while hits.load(Ordering::SeqCst) < at_least && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        hits.load(Ordering::SeqCst)
    }

    /// The shape of a self-updating program: a new version folder with its
    /// executable appears below the watched one.
    #[test]
    fn a_new_version_folder_below_the_watched_one_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (hits, callback) = counting();
        let watch = WindowsProgramFolders::new()
            .watch(dir.path(), true, callback)
            .expect("watch");
        std::fs::create_dir_all(dir.path().join("app-1.0.2")).expect("mkdir");
        std::fs::write(dir.path().join("app-1.0.2").join("tool.exe"), b"").expect("write");
        assert!(wait_for(&hits, 1) >= 1, "the new version was reported");
        let started = Instant::now();
        drop(watch);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "retired at once"
        );
    }

    #[test]
    fn a_log_rewritten_beside_the_programs_is_not_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("app.log"), b"x").expect("write");
        let (hits, callback) = counting();
        let watch = WindowsProgramFolders::new()
            .watch(dir.path(), false, callback)
            .expect("watch");
        std::fs::write(dir.path().join("app.log"), b"more").expect("rewrite");
        std::thread::sleep(Duration::from_millis(200));
        drop(watch);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_missing_folder_cannot_be_watched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_hits, callback) = counting();
        assert!(WindowsProgramFolders::new()
            .watch(&dir.path().join("absent"), false, callback)
            .is_err());
    }

    #[test]
    fn a_real_path_has_no_verbatim_prefix_and_names_the_folder_behind_a_link() {
        let dir = tempfile::tempdir().expect("tempdir");
        let folders = WindowsProgramFolders::new();
        let real = folders.real_path(dir.path()).expect("real");
        assert!(!real.to_string_lossy().starts_with(r"\\?\"), "{real:?}");
        assert_eq!(folders.place(&real), PlaceOnDisk::Folder);
    }

    #[test]
    fn only_user_accounts_have_profiles_that_close_a_folder() {
        assert!(is_user_sid("S-1-5-21-1-2-3-1001"));
        assert!(is_user_sid("S-1-12-1-1-2-3-4"));
        assert!(!is_user_sid("S-1-5-18"));
        assert!(!is_user_sid("S-1-5-80-1"));
    }
}
