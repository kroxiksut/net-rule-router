//! Linux browser-history read mechanism behind
//! [`BrowserHistoryReadPort`].
//!
//! Reads the History SQLite of Chromium-family browsers (table `urls`) and
//! Firefox-family ones (`places.sqlite`, table `moz_places`) in the principal's
//! home — native, snap and flatpak layouts — plus Thunderbird account servers.
//! Only hostnames leave this module.
//!
//! The daemon runs as root and everything under a home is writable by its
//! owner, so nothing below the home is reached by path: each directory is
//! opened relative to the handle of the one above it with `O_NOFOLLOW`, and
//! every directory and file must belong to the principal (or root). A link
//! anywhere below the home, a file with a second hard link, a FIFO or a device
//! is refused; otherwise a user could point the import at another account's
//! history. The home itself comes from the account database and is trusted as
//! given.
//!
//! The browser holds its database open, so it is copied with its WAL and
//! rollback journal into the daemon's private directory and the copy is read.
//!
//! `$XDG_CONFIG_HOME` lives in the user's session environment, which a system
//! daemon does not see; the default `~/.config` is what is searched.

#![cfg(target_os = "linux")]
// Localized: `getpwuid_r` is the only `unsafe` here. `std` has no account
// database lookup, and `/etc/passwd` alone misses directory-service users.
#![allow(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use nrr_platform_api::browser_history::{
    hostname_from_history_url, mail_server_hostnames_from_prefs, summarize_source_labels,
    BrowserHistoryError, BrowserHistoryReadPort,
};
use nrr_platform_api::enforcement::UserPrincipal;
use nrr_sqlite_support::browser_history::{
    read_history_copy, HistoryQuery, CHROMIUM_QUERY, COPIED_SIDE_FILES, FIREFOX_QUERY,
    MAX_HISTORY_BYTES, SIDE_FILES,
};

/// Production reader. `copy_dir` must be private to the daemon: the copies of
/// a user's history are written there.
pub struct LinuxBrowserHistoryRead {
    copy_dir: PathBuf,
}

impl LinuxBrowserHistoryRead {
    pub fn new(copy_dir: PathBuf) -> Self {
        Self { copy_dir }
    }
}

/// Chromium `User Data` homes, relative to the home directory; profiles are
/// `Default` and `Profile N` inside.
const CHROMIUM_HOMES: &[(&[&str], &str)] = &[
    (&[".config", "google-chrome"], "chrome"),
    (&[".config", "google-chrome-beta"], "chrome"),
    (&[".config", "google-chrome-unstable"], "chrome"),
    (&[".config", "chromium"], "chromium"),
    (&[".config", "BraveSoftware", "Brave-Browser"], "brave"),
    (&[".config", "microsoft-edge"], "edge"),
    (&[".config", "microsoft-edge-beta"], "edge"),
    (&[".config", "microsoft-edge-dev"], "edge"),
    (&[".config", "vivaldi"], "vivaldi"),
    (&[".config", "yandex-browser"], "yandex-browser"),
    (&[".config", "yandex-browser-beta"], "yandex-browser"),
    (&["snap", "chromium", "common", "chromium"], "chromium"),
    (
        &[
            ".var",
            "app",
            "com.google.Chrome",
            "config",
            "google-chrome",
        ],
        "chrome",
    ),
    (
        &[".var", "app", "org.chromium.Chromium", "config", "chromium"],
        "chromium",
    ),
    (
        &[
            ".var",
            "app",
            "com.brave.Browser",
            "config",
            "BraveSoftware",
            "Brave-Browser",
        ],
        "brave",
    ),
    (
        &[
            ".var",
            "app",
            "com.microsoft.Edge",
            "config",
            "microsoft-edge",
        ],
        "edge",
    ),
    (
        &[".var", "app", "com.vivaldi.Vivaldi", "config", "vivaldi"],
        "vivaldi",
    ),
];

/// Opera keeps `History` directly in its flavor directory.
const OPERA_PROFILES: &[(&[&str], &str)] = &[
    (&[".config", "opera"], "opera"),
    (&[".config", "opera-beta"], "opera"),
    (&[".config", "opera-developer"], "opera"),
];

/// Directories whose subdirectories are Firefox-family profiles.
const FIREFOX_HOMES: &[(&[&str], &str)] = &[
    (&[".mozilla", "firefox"], "firefox"),
    (&[".config", "mozilla", "firefox"], "firefox"),
    (
        &["snap", "firefox", "common", ".mozilla", "firefox"],
        "firefox",
    ),
    (
        &[".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"],
        "firefox",
    ),
    (&[".librewolf"], "librewolf"),
    (
        &[".var", "app", "io.gitlab.librewolf-community", ".librewolf"],
        "librewolf",
    ),
    (&[".waterfox"], "waterfox"),
];

/// Directories whose subdirectories are Thunderbird profiles.
const THUNDERBIRD_HOMES: &[&[&str]] = &[
    &[".thunderbird"],
    &["snap", "thunderbird", "common", ".thunderbird"],
    &[".var", "app", "org.mozilla.Thunderbird", ".thunderbird"],
];

const MAX_PREFS_BYTES: u64 = 16 * 1024 * 1024;

impl BrowserHistoryReadPort for LinuxBrowserHistoryRead {
    fn read_history_hostnames(&self, principal: &str) -> Result<Vec<String>, BrowserHistoryError> {
        let uid = UserPrincipal::from_stored(principal)
            .ok()
            .and_then(|p| p.as_unix_uid())
            .ok_or_else(|| BrowserHistoryError::ReadFailed("not a Unix user".into()))?;
        let home_path = home_dir_of(uid)
            .ok_or_else(|| BrowserHistoryError::ReadFailed("the account has no home".into()))?;
        let home = Dir::open_home(&home_path, uid).map_err(BrowserHistoryError::ReadFailed)?;
        let sources = discover_history_sources(&home, uid);
        tracing::info!(
            target: "nrr::browser-history",
            msg_key = "linux-browserhistory-discovery-finished",
            sources = %summarize_source_labels(sources.iter().map(|s| s.label)),
            "browser-history discovery finished",
        );
        let mail_hosts = thunderbird_server_hostnames(&home, uid);
        if !mail_hosts.is_empty() {
            tracing::info!(
                target: "nrr::browser-history",
                msg_key = "linux-browserhistory-mail-hosts-discovered",
                hosts = mail_hosts.len(),
                "mail-client account servers discovered (thunderbird)",
            );
        }
        if sources.is_empty() && mail_hosts.is_empty() {
            return Err(BrowserHistoryError::NoBrowsersFound);
        }
        let mut hosts = mail_hosts;
        let mut any_ok = !hosts.is_empty();
        let mut last_err = None;
        for src in &sources {
            match read_source_hostnames(src, uid, &self.copy_dir) {
                Ok(mut h) => {
                    any_ok = true;
                    hosts.append(&mut h);
                }
                Err(e) => {
                    tracing::debug!(
                        target: "nrr::browser-history",
                        source = src.label,
                        error = %e,
                        "skipping unreadable browser-history source",
                    );
                    last_err = Some(e);
                }
            }
        }
        if !any_ok {
            return Err(BrowserHistoryError::ReadFailed(
                last_err.unwrap_or_else(|| "all sources failed".into()),
            ));
        }
        hosts.sort_unstable();
        hosts.dedup();
        Ok(hosts)
    }

    fn discard_leftover_copies(&self) {
        let removed = discard_copies_in(&self.copy_dir);
        if removed > 0 {
            tracing::info!(
                target: "nrr::browser-history",
                removed,
                "left-over browser-history copies removed",
            );
        }
    }
}

/// Removes every file in `dir` named the way [`TempCopy`] names a copy or its
/// side files; returns how many went. The directory is the daemon's own.
fn discard_copies_in(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let is_file = entry.file_type().is_ok_and(|t| !t.is_dir());
        let is_copy = entry.file_name().to_str().is_some_and(|name| {
            let rest = SIDE_FILES
                .iter()
                .find_map(|suffix| name.strip_suffix(suffix))
                .unwrap_or(name);
            rest.starts_with("nrr-bh-") && rest.ends_with(".sqlite")
        });
        if is_file && is_copy && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// The home directory the account database records for `uid`.
fn home_dir_of(uid: u32) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;

    let mut buf = vec![0u8; 4096];
    loop {
        // SAFETY: `passwd` is plain old data; zeroed is a valid initial value
        // for an out-parameter.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call and `buf.len()` is its
        // true size; the strings `entry` points at live in `buf`, which is
        // read below before it is touched again.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut entry,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut found,
            )
        };
        if rc == libc::ERANGE && buf.len() < 1024 * 1024 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || found.is_null() || entry.pw_dir.is_null() {
            return None;
        }
        // SAFETY: on success `pw_dir` is a NUL-terminated string inside `buf`.
        let dir = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) };
        let path = PathBuf::from(OsStr::from_bytes(dir.to_bytes()));
        return path.is_absolute().then_some(path);
    }
}

/// A directory held open, so what lies below it is looked up in THIS
/// directory however its path changes meanwhile.
struct Dir {
    handle: File,
}

impl Dir {
    /// The home, following a link on the home itself: a relocated home is a
    /// legitimate symlink. It must belong to the user, or to root for root.
    fn open_home(path: &Path, uid: u32) -> Result<Self, String> {
        let handle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(path)
            .map_err(|e| format!("open home: {e}"))?;
        let owner = handle
            .metadata()
            .map_err(|e| format!("stat home: {e}"))?
            .uid();
        if owner != uid {
            return Err("the home directory belongs to another account".into());
        }
        Ok(Self { handle })
    }

    /// `/proc/self/fd/<n>` resolves to exactly the directory this handle
    /// holds, so a lookup below it cannot be redirected by a rename.
    fn below(&self, name: &OsStr) -> Option<PathBuf> {
        let mut parts = Path::new(name).components();
        let plain = matches!(parts.next(), Some(Component::Normal(_))) && parts.next().is_none();
        plain
            .then(|| PathBuf::from(format!("/proc/self/fd/{}", self.handle.as_raw_fd())).join(name))
    }

    fn open_dir(&self, name: &OsStr, uid: u32) -> Result<Self, String> {
        let path = self.below(name).ok_or("not a plain name")?;
        let handle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| format!("open directory: {e}"))?;
        let meta = handle.metadata().map_err(|e| format!("stat: {e}"))?;
        check_owner(meta.uid(), uid)?;
        Ok(Self { handle })
    }

    fn open_path(&self, names: &[&str], uid: u32) -> Result<Self, String> {
        let mut parts = names.iter();
        let first = parts.next().ok_or("empty path")?;
        let mut dir = self.open_dir(OsStr::new(first), uid)?;
        for name in parts {
            dir = dir.open_dir(OsStr::new(name), uid)?;
        }
        Ok(dir)
    }

    /// Entry names, sorted so discovery is deterministic.
    fn entries(&self) -> Vec<OsString> {
        let proc_dir = PathBuf::from(format!("/proc/self/fd/{}", self.handle.as_raw_fd()));
        let mut names: Vec<OsString> = std::fs::read_dir(proc_dir)
            .map(|entries| entries.flatten().map(|e| e.file_name()).collect())
            .unwrap_or_default();
        names.sort();
        names
    }

    fn has_file(&self, name: &str) -> bool {
        self.below(OsStr::new(name))
            .and_then(|path| std::fs::symlink_metadata(path).ok())
            .is_some_and(|meta| meta.file_type().is_file())
    }

    /// The user's regular file `name` in this directory, `None` when absent.
    ///
    /// Checked before the open so a FIFO or device is never opened at all,
    /// and again on the handle, which is what is actually read.
    fn open_file(&self, name: &str, uid: u32, max_bytes: u64) -> Result<Option<File>, String> {
        let path = self.below(OsStr::new(name)).ok_or("not a plain name")?;
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("stat: {e}")),
            Ok(meta) if !meta.file_type().is_file() => {
                return Err("not a regular file".into());
            }
            Ok(_) => {}
        }
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(&path)
        {
            Ok(file) => file,
            // A WAL disappears when its browser closes.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("open: {e}")),
        };
        let meta = file.metadata().map_err(|e| format!("stat: {e}"))?;
        if !meta.is_file() {
            return Err("not a regular file".into());
        }
        // A hard link would carry another file's content under a name here.
        if meta.nlink() != 1 {
            return Err("the file has more than one link".into());
        }
        check_owner(meta.uid(), uid)?;
        if meta.len() > max_bytes {
            return Err("the file exceeds the size cap".into());
        }
        Ok(Some(file))
    }
}

/// Root may own what sits in a home (a browser once run with `sudo`); any
/// other account may not.
fn check_owner(owner: u32, uid: u32) -> Result<(), String> {
    if owner == uid || owner == 0 {
        Ok(())
    } else {
        Err("not owned by the requesting user".into())
    }
}

/// One history database: the directory holding it and how to read it.
struct HistorySource {
    dir: Dir,
    file: &'static str,
    query: HistoryQuery,
    label: &'static str,
}

fn discover_history_sources(home: &Dir, uid: u32) -> Vec<HistorySource> {
    let mut out = Vec::new();
    for (path, label) in CHROMIUM_HOMES {
        let Ok(user_data) = home.open_path(path, uid) else {
            continue;
        };
        for name in user_data.entries() {
            let is_profile =
                name == "Default" || name.to_str().is_some_and(|n| n.starts_with("Profile "));
            if !is_profile {
                continue;
            }
            let Ok(profile) = user_data.open_dir(&name, uid) else {
                continue;
            };
            if profile.has_file("History") {
                out.push(HistorySource {
                    dir: profile,
                    file: "History",
                    query: CHROMIUM_QUERY,
                    label,
                });
            }
        }
    }
    for (path, label) in OPERA_PROFILES {
        let Ok(profile) = home.open_path(path, uid) else {
            continue;
        };
        if profile.has_file("History") {
            out.push(HistorySource {
                dir: profile,
                file: "History",
                query: CHROMIUM_QUERY,
                label,
            });
        }
    }
    for (path, label) in FIREFOX_HOMES {
        let Ok(profiles) = home.open_path(path, uid) else {
            continue;
        };
        for name in profiles.entries() {
            let Ok(profile) = profiles.open_dir(&name, uid) else {
                continue;
            };
            if profile.has_file("places.sqlite") {
                out.push(HistorySource {
                    dir: profile,
                    file: "places.sqlite",
                    query: FIREFOX_QUERY,
                    label,
                });
            }
        }
    }
    out
}

fn thunderbird_server_hostnames(home: &Dir, uid: u32) -> Vec<String> {
    let mut hosts = Vec::new();
    for path in THUNDERBIRD_HOMES {
        let Ok(profiles) = home.open_path(path, uid) else {
            continue;
        };
        for name in profiles.entries() {
            let Ok(profile) = profiles.open_dir(&name, uid) else {
                continue;
            };
            let Ok(Some(file)) = profile.open_file("prefs.js", uid, MAX_PREFS_BYTES) else {
                continue;
            };
            let mut bytes = Vec::new();
            if (&file)
                .take(MAX_PREFS_BYTES)
                .read_to_end(&mut bytes)
                .is_err()
            {
                continue;
            }
            if let Ok(text) = String::from_utf8(bytes) {
                hosts.extend(mail_server_hostnames_from_prefs(&text));
            }
        }
    }
    hosts.sort_unstable();
    hosts.dedup();
    hosts
}

/// Copy the source and its side files, then read the copy.
fn read_source_hostnames(
    src: &HistorySource,
    uid: u32,
    copy_dir: &Path,
) -> Result<Vec<String>, String> {
    let source = src
        .dir
        .open_file(src.file, uid, MAX_HISTORY_BYTES)?
        .ok_or("the database disappeared")?;
    let copy = TempCopy::create_in(copy_dir, src.label)?;
    let mut budget = MAX_HISTORY_BYTES;
    budget = copy.fill("", &source, budget)?;
    drop(source);
    for suffix in COPIED_SIDE_FILES {
        let Some(side) = src
            .dir
            .open_file(&format!("{}{suffix}", src.file), uid, budget)?
        else {
            continue;
        };
        budget = copy.fill(suffix, &side, budget)?;
    }
    let read = read_history_copy(copy.path(), src.query, hostname_from_history_url)?;
    if read.cut_short {
        tracing::info!(
            target: "nrr::browser-history",
            hosts = read.hosts.len(),
            "browser-history read stopped at its time budget; keeping what was read",
        );
    }
    Ok(read.hosts)
}

/// A uniquely named copy in the daemon's private directory, removed with
/// every side file SQLite may have created beside it.
struct TempCopy {
    path: PathBuf,
}

impl TempCopy {
    fn create_in(dir: &Path, label: &str) -> Result<Self, String> {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        std::fs::create_dir_all(dir).map_err(|e| format!("copy directory: {e}"))?;
        let meta = std::fs::symlink_metadata(dir).map_err(|e| format!("copy directory: {e}"))?;
        if !meta.is_dir() {
            return Err("the copy directory is not a plain directory".into());
        }
        // Copies of a user's history must not land where anyone else can look.
        if meta.mode() & 0o077 != 0 {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("copy directory: {e}"))?;
        }
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let name = format!(
            "nrr-bh-{label}-{}-{}-{nanos}.sqlite",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        );
        let copy = Self {
            path: dir.join(name),
        };
        copy.create("")?;
        Ok(copy)
    }

    fn side(&self, suffix: &str) -> PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(suffix);
        PathBuf::from(name)
    }

    /// `create_new` refuses an existing name, a planted link included.
    fn create(&self, suffix: &str) -> Result<File, String> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.side(suffix))
            .map_err(|e| format!("create copy: {e}"))
    }

    /// Copy at most `budget` bytes of `source` into the `suffix` file and
    /// return what is left of the budget.
    fn fill(&self, suffix: &str, source: &File, budget: u64) -> Result<u64, String> {
        let mut out = if suffix.is_empty() {
            OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&self.path)
                .map_err(|e| format!("open copy: {e}"))?
        } else {
            self.create(suffix)?
        };
        let copied = std::io::copy(&mut source.take(budget.saturating_add(1)), &mut out)
            .map_err(|e| format!("copy: {e}"))?;
        if copied > budget {
            return Err("the source exceeds the size cap".into());
        }
        Ok(budget - copied)
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempCopy {
    fn drop(&mut self) {
        for suffix in SIDE_FILES {
            let _ = std::fs::remove_file(self.side(suffix));
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn own_uid() -> u32 {
        // SAFETY: `getuid` has no preconditions and cannot fail.
        unsafe { libc::getuid() }
    }

    #[test]
    fn only_history_copies_are_discarded_at_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kept = ["History", "nrr-bh-notes.txt", "places.sqlite"];
        for name in kept {
            std::fs::write(dir.path().join(name), b"x").expect("write");
        }
        std::fs::create_dir(dir.path().join("nrr-bh-dir.sqlite")).expect("dir");
        // The names a real copy gets.
        let copy = TempCopy::create_in(dir.path(), "chrome").expect("copy");
        drop(copy.create("-wal").expect("wal"));
        let names = [copy.path().to_path_buf(), copy.side("-wal")];

        assert_eq!(discard_copies_in(dir.path()), 2);
        assert!(names.iter().all(|p| !p.exists()));
        drop(copy);
        let mut left: Vec<String> = std::fs::read_dir(dir.path())
            .expect("list")
            .map(|e| e.expect("entry").file_name().into_string().expect("utf-8"))
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "History",
                "nrr-bh-dir.sqlite",
                "nrr-bh-notes.txt",
                "places.sqlite"
            ]
        );
    }

    fn make_db(path: &Path, schema: &str, insert: &str, urls: &[&str]) {
        let conn = rusqlite::Connection::open(path).expect("create db");
        conn.execute_batch(schema).expect("schema");
        for url in urls {
            conn.execute(insert, [url]).expect("insert");
        }
    }

    fn chromium_db(path: &Path, urls: &[&str]) {
        make_db(
            path,
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT)",
            "INSERT INTO urls (url) VALUES (?1)",
            urls,
        );
    }

    fn firefox_db(path: &Path, urls: &[&str]) {
        make_db(
            path,
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT)",
            "INSERT INTO moz_places (url) VALUES (?1)",
            urls,
        );
    }

    struct Fixture {
        root: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                root: tempfile::tempdir().expect("tempdir"),
            }
        }
        fn home(&self) -> PathBuf {
            self.root.path().join("home")
        }
        fn copies(&self) -> PathBuf {
            self.root.path().join("copies")
        }
        fn dir(&self, rel: &str) -> PathBuf {
            let dir = self.home().join(rel);
            std::fs::create_dir_all(&dir).expect("mkdir");
            dir
        }
        fn open_home(&self) -> Dir {
            std::fs::create_dir_all(self.home()).expect("mkdir home");
            Dir::open_home(&self.home(), own_uid()).expect("home")
        }
        fn hosts(&self) -> Vec<String> {
            let home = self.open_home();
            let mut hosts = Vec::new();
            for src in discover_history_sources(&home, own_uid()) {
                hosts.extend(read_source_hostnames(&src, own_uid(), &self.copies()).expect("read"));
            }
            hosts.sort();
            hosts
        }
    }

    #[test]
    fn native_snap_and_flatpak_layouts_are_found() {
        let fx = Fixture::new();
        chromium_db(
            &fx.dir(".config/google-chrome/Default").join("History"),
            &["https://feed.example/a"],
        );
        chromium_db(
            &fx.dir(".config/google-chrome/Profile 1").join("History"),
            &["https://shop.example/"],
        );
        chromium_db(
            &fx.dir(".config/opera").join("History"),
            &["https://news.example/"],
        );
        firefox_db(
            &fx.dir("snap/firefox/common/.mozilla/firefox/ab12.default")
                .join("places.sqlite"),
            &["https://docs.example/x", "about:config"],
        );
        chromium_db(
            &fx.dir(".var/app/org.chromium.Chromium/config/chromium/Default")
                .join("History"),
            &["http://media.example:8080/"],
        );
        // Not a profile directory: ignored.
        chromium_db(
            &fx.dir(".config/google-chrome/System Profile")
                .join("History"),
            &["https://hidden.example/"],
        );

        let home = fx.open_home();
        let sources = discover_history_sources(&home, own_uid());
        assert_eq!(
            summarize_source_labels(sources.iter().map(|s| s.label)),
            "chrome:2 chromium:1 opera:1 firefox:1"
        );
        assert_eq!(
            fx.hosts(),
            vec![
                "docs.example",
                "feed.example",
                "media.example",
                "news.example",
                "shop.example"
            ]
        );
        assert_eq!(
            std::fs::read_dir(fx.copies()).expect("copies").count(),
            0,
            "every copy is removed after the read"
        );
    }

    /// The point of the walk: a link planted below the home must not hand the
    /// import a directory or file the user does not own.
    #[test]
    fn a_link_below_the_home_is_refused() {
        let fx = Fixture::new();
        let foreign = fx.root.path().join("foreign");
        std::fs::create_dir_all(foreign.join("Default")).expect("mkdir");
        chromium_db(
            &foreign.join("Default").join("History"),
            &["https://other.example/"],
        );
        fx.dir(".config");
        std::os::unix::fs::symlink(&foreign, fx.home().join(".config/chromium")).expect("link");
        // And a linked file inside a real profile.
        let profile = fx.dir(".config/google-chrome/Default");
        std::os::unix::fs::symlink(foreign.join("Default/History"), profile.join("History"))
            .expect("file link");

        let home = fx.open_home();
        assert!(discover_history_sources(&home, own_uid()).is_empty());
    }

    #[test]
    fn a_hard_linked_or_special_file_is_refused() {
        let fx = Fixture::new();
        let profile_dir = fx.dir(".config/chromium/Default");
        let outside = fx.root.path().join("outside.sqlite");
        chromium_db(&outside, &["https://other.example/"]);
        std::fs::hard_link(&outside, profile_dir.join("History")).expect("hard link");

        let home = fx.open_home();
        let profile = home
            .open_path(&[".config", "chromium", "Default"], own_uid())
            .expect("profile");
        assert!(profile
            .open_file("History", own_uid(), MAX_HISTORY_BYTES)
            .is_err());

        let fifo = profile_dir.join("History-wal");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .is_ok_and(|s| s.success());
        if made {
            assert!(
                profile
                    .open_file("History-wal", own_uid(), MAX_HISTORY_BYTES)
                    .is_err(),
                "a FIFO is never opened"
            );
        }
        assert!(matches!(
            profile.open_file("absent", own_uid(), MAX_HISTORY_BYTES),
            Ok(None)
        ));
    }

    #[test]
    fn a_file_over_the_cap_is_refused() {
        let fx = Fixture::new();
        std::fs::write(fx.dir(".thunderbird/p1").join("prefs.js"), b"0123456789").expect("write");
        let home = fx.open_home();
        let profile = home
            .open_path(&[".thunderbird", "p1"], own_uid())
            .expect("profile");
        assert!(profile.open_file("prefs.js", own_uid(), 9).is_err());
        assert!(profile.open_file("prefs.js", own_uid(), 10).is_ok());
    }

    #[test]
    fn mail_servers_come_from_thunderbird_profiles() {
        let fx = Fixture::new();
        std::fs::write(
            fx.dir(".thunderbird/xy.default-release").join("prefs.js"),
            "user_pref(\"mail.server.server1.hostname\", \"imap.mail.example\");\n\
             user_pref(\"mail.identity.id1.useremail\", \"someone@example.com\");\n",
        )
        .expect("write");
        let home = fx.open_home();
        assert_eq!(
            thunderbird_server_hostnames(&home, own_uid()),
            vec!["imap.mail.example"]
        );
    }

    #[test]
    fn another_accounts_home_is_refused() {
        let fx = Fixture::new();
        std::fs::create_dir_all(fx.home()).expect("mkdir");
        let stranger = own_uid().wrapping_add(4242);
        assert!(Dir::open_home(&fx.home(), stranger).is_err());
    }

    #[test]
    fn only_the_user_or_root_may_own_what_is_read() {
        assert!(check_owner(1000, 1000).is_ok());
        assert!(check_owner(0, 1000).is_ok());
        assert!(check_owner(1001, 1000).is_err());
    }

    #[test]
    fn a_name_that_is_not_one_plain_component_is_refused() {
        let fx = Fixture::new();
        let home = fx.open_home();
        for bad in ["..", ".", "a/b", "/etc", ""] {
            assert!(home.below(OsStr::new(bad)).is_none(), "{bad:?}");
        }
        assert!(home.below(OsStr::new("Default")).is_some());
    }

    #[test]
    fn a_principal_that_is_not_a_unix_user_reads_nothing() {
        let fx = Fixture::new();
        let reader = LinuxBrowserHistoryRead::new(fx.copies());
        assert!(matches!(
            reader.read_history_hostnames("S-1-5-21-1-2-3-1001"),
            Err(BrowserHistoryError::ReadFailed(_))
        ));
    }

    #[test]
    fn the_running_account_has_a_home() {
        assert!(home_dir_of(own_uid()).is_some_and(|home| home.is_absolute()));
    }
}
