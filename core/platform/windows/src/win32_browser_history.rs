//! Windows browser-history read mechanism.
//!
//! Implements [`BrowserHistoryReadPort`] by reading the History SQLite of the
//! locally-installed Chromium-family browsers (table `urls`) and Firefox-family
//! browsers (`places.sqlite`, table `moz_places`). Only visited HOSTNAMES leave
//! this module (see the port doc); URLs/titles/timestamps never cross the
//! boundary.
//!
//! Discovery covers three layout families:
//! - Chromium `User Data` homes under `%LOCALAPPDATA%` (Chrome, Edge, Brave,
//!   Yandex Browser, Vivaldi, plain Chromium, Perplexity Comet) plus Arc for
//!   Windows, whose MSIX package name carries a publisher-hash suffix and is
//!   found by scanning `Packages\TheBrowserCompany.Arc_*`.
//! - Opera / Opera GX, whose profile lives DIRECTLY under
//!   `%APPDATA%\Opera Software\<flavor>` (no `User Data\Default` nesting).
//! - Firefox-family `Profiles` homes under `%APPDATA%` (Firefox, LibreWolf,
//!   Waterfox).
//!
//! Tor Browser is deliberately unsupported: it does not persist history to
//! disk, and Tor-visited hosts never appear to the OS as direct connections,
//! so seeding them cannot improve enforcement. AI-browser paths (Arc, Comet)
//! are best-effort — vendors ship layout changes faster than docs; the
//! discovery-summary log line below is what lets users report gaps.
//!
//! The browser holds its History DB open, so we COPY it, with its WAL and
//! rollback journal, to private temp files and read the copy — a direct open
//! would race the browser's writer and fail "database is locked", and the
//! main file alone lacks everything not yet checkpointed. Copy + read is
//! best-effort per profile: any browser that is absent or unreadable is
//! skipped, and partial results are valid.
//!
//! Everything under a profile is writable by its user while this runs as
//! LocalSystem, so a source is read only through a handle proven to be the
//! principal's own file, reached from the profile root without a link (see
//! [`open_verified`]); otherwise a planted junction would hand the caller
//! another account's history.
//!
//! Profile discovery is rooted at the PRINCIPAL's profile, not
//! this process's environment. The service runs as LocalSystem, whose
//! `%LOCALAPPDATA%` is the systemprofile (no browsers), so the env-based
//! discovery returned "no supported browser profiles found" on every real
//! seed. The principal SID resolves to its profile root through the
//! `ProfileList` registry key; the process environment remains the fallback
//! for console/dev runs where that lookup fails.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use nrr_platform_api::browser_history::{
    hostname_from_history_url, summarize_source_labels, BrowserHistoryError, BrowserHistoryReadPort,
};
use nrr_sqlite_support::browser_history::{
    read_history_copy, HistoryQuery, CHROMIUM_QUERY, COPIED_SIDE_FILES, FIREFOX_QUERY,
    MAX_HISTORY_BYTES, SIDE_FILES,
};

/// Production browser-history reader (Chromium-, Opera- and Firefox-family
/// browsers on Windows; see the module doc for the exact roster).
pub struct WindowsBrowserHistoryRead;

impl WindowsBrowserHistoryRead {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsBrowserHistoryRead {
    fn default() -> Self {
        Self::new()
    }
}

/// One history source: a SQLite file plus the SQL that lists its URL column.
struct HistorySource {
    /// The live (locked) DB path.
    db_path: PathBuf,
    /// Root the DB must stay under once every link is resolved.
    anchor: PathBuf,
    query: HistoryQuery,
    /// Short label for the temp-copy filename + diagnostics.
    label: &'static str,
}

impl BrowserHistoryReadPort for WindowsBrowserHistoryRead {
    fn read_history_hostnames(&self, principal: &str) -> Result<Vec<String>, BrowserHistoryError> {
        let roots = profile_roots_for(principal);
        let sources = discover_history_sources(&roots);
        // Discovery summary at info: this is the line that tells a user WHY a
        // browser they use did not contribute (absent from the list → its
        // layout was not found), and is the feedback hook for the best-effort
        // AI-browser paths.
        tracing::info!(
            target: "nrr::browser-history",
            msg_key = "win-browserhistory-discovery-finished",
            sources = %summarize_source_labels(sources.iter().map(|s| s.label)),
            "browser-history discovery finished",
        );
        // Mail-client account servers ride the same port: a mail
        // host is dialed by a background client that never touches a browser,
        // so history alone leaves it cold in the cache and it can be blocked
        // under block-all before its first resolution. Only hostnames cross
        // the boundary, same contract as history.
        let mail_hosts = thunderbird_server_hostnames(&roots, principal);
        if !mail_hosts.is_empty() {
            tracing::info!(
                target: "nrr::browser-history",
                msg_key = "win-browserhistory-mail-hosts-discovered",
                hosts = mail_hosts.len(),
                "mail-client account servers discovered (thunderbird)",
            );
        }
        if sources.is_empty() && mail_hosts.is_empty() {
            return Err(BrowserHistoryError::NoBrowsersFound);
        }
        let mut hosts: Vec<String> = mail_hosts;
        let mut any_ok = !hosts.is_empty();
        let mut last_err: Option<String> = None;
        let copy_dirs = copy_dirs();
        for src in &sources {
            match read_source_hostnames(src, principal, &copy_dirs) {
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
        let removed = discard_copies_in(&copy_dirs());
        if removed > 0 {
            tracing::info!(
                target: "nrr::browser-history",
                removed,
                "left-over browser-history copies removed",
            );
        }
    }
}

/// Removes every file in `dirs` named the way [`TempCopy`] names a copy or
/// its side files; returns how many went.
fn discard_copies_in(dirs: &[PathBuf]) -> usize {
    let mut removed = 0;
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let is_file = entry.file_type().is_ok_and(|t| !t.is_dir());
            if is_file
                && entry.file_name().to_str().is_some_and(is_copy_name)
                && std::fs::remove_file(entry.path()).is_ok()
            {
                removed += 1;
            }
        }
    }
    removed
}

/// `nrr-bh-<label>-<32 hex>.sqlite`, optionally with a side-file suffix.
fn is_copy_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("nrr-bh-") else {
        return false;
    };
    let rest = SIDE_FILES
        .iter()
        .find_map(|suffix| rest.strip_suffix(suffix))
        .unwrap_or(rest);
    let Some(stem) = rest.strip_suffix(".sqlite") else {
        return false;
    };
    stem.rsplit_once('-').is_some_and(|(label, nonce)| {
        !label.is_empty() && nonce.len() == 32 && nonce.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

/// Account-server hostnames from every Thunderbird profile under the
/// principal's Roaming AppData (`Thunderbird\Profiles\*\prefs.js`).
/// Best-effort: an absent install or unreadable profile contributes nothing.
fn thunderbird_server_hostnames(roots: &AppDataRoots, principal: &str) -> Vec<String> {
    const MAX_PREFS_BYTES: u64 = 16 * 1024 * 1024;
    let Some(roaming) = roots.roaming.as_ref() else {
        return Vec::new();
    };
    let anchor = roots.anchor(roaming);
    let profiles_dir = roaming.join("Thunderbird").join("Profiles");
    let Ok(entries) = std::fs::read_dir(&profiles_dir) else {
        return Vec::new();
    };
    let mut hosts = Vec::new();
    for entry in entries.flatten() {
        let prefs = entry.path().join("prefs.js");
        if !prefs.is_file() {
            continue;
        }
        let mut bytes = Vec::new();
        let read = open_verified(anchor, &prefs, principal, MAX_PREFS_BYTES).and_then(|f| {
            (&f).take(MAX_PREFS_BYTES)
                .read_to_end(&mut bytes)
                .map_err(|e| format!("read: {e}"))
        });
        if let Err(reason) = read {
            tracing::debug!(
                target: "nrr::browser-history",
                source = "thunderbird",
                error = %reason,
                "skipping mail-client profile",
            );
            continue;
        }
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        hosts.extend(nrr_platform_api::browser_history::mail_server_hostnames_from_prefs(&text));
    }
    hosts.sort_unstable();
    hosts.dedup();
    hosts
}

/// The two AppData roots browser profiles live under, resolved for one
/// principal. Either leg may be absent (unresolvable profile / missing env).
struct AppDataRoots {
    /// `<profile>\AppData\Local` — Chromium-family `User Data` homes.
    local: Option<PathBuf>,
    /// `<profile>\AppData\Roaming` — Firefox profile home.
    roaming: Option<PathBuf>,
    /// The profile directory both legs sit under; `None` when the legs came
    /// from the environment, and each then anchors itself.
    profile: Option<PathBuf>,
}

impl AppDataRoots {
    fn anchor<'a>(&'a self, leg: &'a Path) -> &'a Path {
        self.profile.as_deref().unwrap_or(leg)
    }
}

/// Resolve the AppData roots for `principal` (a Windows SID). Prefers the
/// SID's `ProfileList` registry entry (correct when this process is
/// LocalSystem); falls back to this process's own environment (correct for
/// console/dev runs as the browsing user when the lookup fails).
fn profile_roots_for(principal: &str) -> AppDataRoots {
    if let Some(root) = profile_root::profile_image_path(principal) {
        return AppDataRoots {
            local: Some(root.join("AppData").join("Local")),
            roaming: Some(root.join("AppData").join("Roaming")),
            profile: Some(root),
        };
    }
    AppDataRoots {
        local: std::env::var("LOCALAPPDATA").ok().map(PathBuf::from),
        roaming: std::env::var("APPDATA").ok().map(PathBuf::from),
        profile: None,
    }
}

/// Enumerate the History DBs of every installed Chromium profile + Firefox
/// profile. Chromium keeps one `History` per profile directory (`Default`,
/// `Profile 1`, …) under `<LocalAppData>\<Vendor>\<Product>\User Data`; Firefox
/// keeps `places.sqlite` per profile under `<AppData>\Mozilla\Firefox\Profiles`.
fn discover_history_sources(roots: &AppDataRoots) -> Vec<HistorySource> {
    let mut out = Vec::new();
    if let Some(local) = roots.local.as_ref() {
        for (vendor_product, label) in [
            (r"Google\Chrome\User Data", "chrome"),
            (r"Microsoft\Edge\User Data", "edge"),
            (r"BraveSoftware\Brave-Browser\User Data", "brave"),
            (r"Yandex\YandexBrowser\User Data", "yandex-browser"),
            (r"Vivaldi\User Data", "vivaldi"),
            (r"Chromium\User Data", "chromium"),
            // Perplexity Comet (Chromium): vendor docs only say "a folder named
            // Comet under %LOCALAPPDATA%" — probe both plausible nestings.
            (r"Perplexity\Comet\User Data", "comet"),
            (r"Comet\User Data", "comet"),
        ] {
            let user_data = local.join(vendor_product);
            for profile in chromium_profile_dirs(&user_data) {
                let db = profile.join("History");
                if db.is_file() {
                    out.push(HistorySource {
                        db_path: db,
                        anchor: roots.anchor(local).to_path_buf(),
                        query: CHROMIUM_QUERY,
                        label,
                    });
                }
            }
        }
        // Arc for Windows is MSIX-packaged; the package directory name carries a
        // publisher-hash suffix (`TheBrowserCompany.Arc_<hash>`), so scan for it.
        if let Ok(entries) = std::fs::read_dir(local.join("Packages")) {
            for entry in entries.flatten() {
                if !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("TheBrowserCompany.Arc_")
                {
                    continue;
                }
                let user_data = entry.path().join(r"LocalCache\Local\Arc\User Data");
                for profile in chromium_profile_dirs(&user_data) {
                    let db = profile.join("History");
                    if db.is_file() {
                        out.push(HistorySource {
                            db_path: db,
                            anchor: roots.anchor(local).to_path_buf(),
                            query: CHROMIUM_QUERY,
                            label: "arc",
                        });
                    }
                }
            }
        }
    }
    if let Some(roaming) = roots.roaming.as_ref() {
        // Opera-family: the flavor directory IS the profile — `History` sits
        // directly in it, without the Chromium `User Data\<profile>` nesting.
        for (flavor_dir, label) in [
            (r"Opera Software\Opera Stable", "opera"),
            (r"Opera Software\Opera GX Stable", "opera-gx"),
        ] {
            let db = roaming.join(flavor_dir).join("History");
            if db.is_file() {
                out.push(HistorySource {
                    db_path: db,
                    anchor: roots.anchor(roaming).to_path_buf(),
                    query: CHROMIUM_QUERY,
                    label,
                });
            }
        }
        for (profiles_dir, label) in [
            (r"Mozilla\Firefox\Profiles", "firefox"),
            (r"librewolf\Profiles", "librewolf"),
            (r"Waterfox\Profiles", "waterfox"),
        ] {
            let profiles = roaming.join(profiles_dir);
            if let Ok(entries) = std::fs::read_dir(&profiles) {
                for entry in entries.flatten() {
                    let db = entry.path().join("places.sqlite");
                    if db.is_file() {
                        out.push(HistorySource {
                            db_path: db,
                            anchor: roots.anchor(roaming).to_path_buf(),
                            query: FIREFOX_QUERY,
                            label,
                        });
                    }
                }
            }
        }
    }
    out
}

/// SID → profile-root resolution through the `ProfileList` registry key.
/// Self-contained Win32 FFI, mirroring the registry helpers in
/// [`crate::vpn_discovery`] rather than sharing them (same precedent: a few
/// well-understood calls beat destabilising a load-bearing module).
#[cfg(target_os = "windows")]
mod profile_root {
    use std::path::PathBuf;

    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

    use crate::win32_ffi::registry;

    /// `ProfileImagePath` of `sid` (e.g. `C:\Users\name`), or `None` when the
    /// SID has no local profile, the value carries an unexpanded `%…%`
    /// placeholder (system accounts — not browsing users), or the directory
    /// does not exist.
    pub fn profile_image_path(sid: &str) -> Option<PathBuf> {
        if sid.is_empty() || !sid.starts_with("S-") {
            return None;
        }
        let subkey = format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
        let value = registry::read_string(HKEY_LOCAL_MACHINE, &subkey, Some("ProfileImagePath"))?;
        if value.is_empty() || value.contains('%') {
            return None;
        }
        let path = PathBuf::from(value);
        path.is_dir().then_some(path)
    }
}

/// Non-Windows builds of this crate: no registry — always fall back to env.
#[cfg(not(target_os = "windows"))]
mod profile_root {
    use std::path::PathBuf;

    pub fn profile_image_path(_sid: &str) -> Option<PathBuf> {
        None
    }
}

/// Profile directories inside a Chromium `User Data` folder: `Default` plus any
/// `Profile N`. Returns an empty vec if the folder is absent.
fn chromium_profile_dirs(user_data: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let default = user_data.join("Default");
    if default.is_dir() {
        dirs.push(default);
    }
    if let Ok(entries) = std::fs::read_dir(user_data) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("Profile ") && entry.path().is_dir() {
                dirs.push(entry.path());
            }
        }
    }
    dirs
}

/// Copy `src.db_path` and its side files to private temp files and read the
/// URL column into hostnames, replaying what SQLite has not yet folded into
/// the main file.
fn read_source_hostnames(
    src: &HistorySource,
    principal: &str,
    copy_dirs: &[PathBuf],
) -> Result<Vec<String>, String> {
    let source = open_verified(&src.anchor, &src.db_path, principal, MAX_HISTORY_BYTES)?;
    let mut copy = TempCopy::create_in(copy_dirs, src.label)?;
    // Read through the verified handle: re-opening the path would reopen the
    // race the checks just closed.
    let mut budget = MAX_HISTORY_BYTES;
    let copied = copy.fill_from(&source, budget)?;
    drop(source);
    if copied > budget {
        return Err("source exceeds the size cap".into());
    }
    budget -= copied;
    // After the main file: SQLite drops WAL frames cut off mid-write, and a
    // WAL that no longer fits the main file falls back below.
    for suffix in COPIED_SIDE_FILES {
        let Some(side) = open_side_file(src, suffix, principal, budget)? else {
            continue;
        };
        let copied = copy.fill_side_from(suffix, &side, budget)?;
        if copied > budget {
            return Err("source exceeds the size cap".into());
        }
        budget -= copied;
    }
    copy.close_all();
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

/// The source's `suffix` side file through the same checks as the database,
/// `None` when it does not exist — or stopped existing, as a WAL does when
/// its browser closes.
fn open_side_file(
    src: &HistorySource,
    suffix: &str,
    principal: &str,
    max_bytes: u64,
) -> Result<Option<File>, String> {
    let path = with_suffix(&src.db_path, suffix);
    let absent = || {
        matches!(
            std::fs::symlink_metadata(&path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound
        )
    };
    if absent() {
        return Ok(None);
    }
    match open_verified(&src.anchor, &path, principal, max_bytes) {
        Ok(file) => Ok(Some(file)),
        Err(_) if absent() => Ok(None),
        Err(e) => Err(format!("{suffix}: {e}")),
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Directories the copy may be written to, most private first: the service's
/// own data root when it is machine-owned, else this process's temp directory.
fn copy_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(2);
    if let Some(root) = nrr_platform_api::paths::production_data_root() {
        if !is_link(&root) && os::is_machine_owned_dir(&root) {
            dirs.push(root);
        }
    }
    dirs.push(std::env::temp_dir());
    dirs
}

/// A uniquely named copy, with every side file SQLite may open beside it,
/// all removed however the read ends.
struct TempCopy {
    path: PathBuf,
    file: Option<File>,
    /// One per [`SIDE_FILES`] entry, in that order; created empty.
    sides: Vec<(PathBuf, Option<File>)>,
}

impl TempCopy {
    /// Create an unpredictable, not-yet-existing file and its side files in
    /// the first usable directory. `create_new` refuses an existing name,
    /// including a planted link, so no name SQLite will open — the side files
    /// included — can be guessed or pre-empted.
    fn create_in(dirs: &[PathBuf], label: &str) -> Result<Self, String> {
        let mut last = String::from("no temp directory");
        for dir in dirs {
            let mut nonce = [0u8; 16];
            getrandom::fill(&mut nonce).map_err(|e| format!("temp name: {e}"))?;
            let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            match Self::create_at(dir.join(format!("nrr-bh-{label}-{hex}.sqlite"))) {
                Ok(copy) => return Ok(copy),
                Err(e) => last = format!("create temp copy: {e}"),
            }
        }
        Err(last)
    }

    /// `path` and its side files, all new; on failure nothing is left behind.
    fn create_at(path: PathBuf) -> std::io::Result<Self> {
        let file = create_new(&path)?;
        let mut copy = Self {
            path,
            file: Some(file),
            sides: Vec::with_capacity(SIDE_FILES.len()),
        };
        for suffix in SIDE_FILES {
            let side = with_suffix(&copy.path, suffix);
            // On error `copy` drops, removing only what it created.
            let file = create_new(&side)?;
            copy.sides.push((side, Some(file)));
        }
        Ok(copy)
    }

    /// Copy at most `cap + 1` bytes from `source`, returning how many were
    /// written.
    fn fill_from(&mut self, source: &File, cap: u64) -> Result<u64, String> {
        fill(&mut self.file, source, cap)
    }

    /// As [`Self::fill_from`], into the side file named by `suffix`.
    fn fill_side_from(&mut self, suffix: &str, source: &File, cap: u64) -> Result<u64, String> {
        let slot = SIDE_FILES
            .iter()
            .position(|s| *s == suffix)
            .and_then(|i| self.sides.get_mut(i))
            .ok_or_else(|| format!("no temp side file {suffix}"))?;
        fill(&mut slot.1, source, cap)
    }

    /// Close every handle before SQLite opens the paths.
    fn close_all(&mut self) {
        self.file = None;
        for (_, file) in &mut self.sides {
            *file = None;
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempCopy {
    /// A file is a copy of the user's history, so a refused delete is retried:
    /// an antivirus scan opens a file the moment its writer closes it. What
    /// still stands goes at the next start.
    fn drop(&mut self) {
        self.close_all();
        let mut left: Vec<&Path> = self.sides.iter().map(|(side, _)| side.as_path()).collect();
        left.push(&self.path);
        for pause_ms in [0, 50, 100, 200, 400] {
            std::thread::sleep(std::time::Duration::from_millis(pause_ms));
            left.retain(|path| match std::fs::remove_file(path) {
                Ok(()) => false,
                Err(e) => e.kind() != std::io::ErrorKind::NotFound,
            });
            if left.is_empty() {
                return;
            }
        }
    }
}

fn create_new(path: &Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Copy at most `cap + 1` bytes from `source` into the still-open `slot`,
/// then close it.
fn fill(slot: &mut Option<File>, source: &File, cap: u64) -> Result<u64, String> {
    let mut out = slot
        .take()
        .ok_or_else(|| String::from("temp copy already filled"))?;
    let mut limited = source.take(cap.saturating_add(1));
    std::io::copy(&mut limited, &mut out).map_err(|e| format!("copy: {e}"))
}

/// Open `path` for reading only once it is proven to be the principal's own
/// regular file, reached from `anchor` without any link. Checks, in order:
/// no link on any component below `anchor`; `anchor` is owned by the
/// principal (or a machine principal); the file, opened without following a
/// final link, is a plain single-link file owned likewise; its final path is
/// still under `anchor`'s final path; its size is within `max_bytes`.
fn open_verified(
    anchor: &Path,
    path: &Path,
    principal: &str,
    max_bytes: u64,
) -> Result<File, String> {
    first_redirect_below(anchor, path)?;
    let root = os::open_directory(anchor).map_err(|e| format!("open profile root: {e}"))?;
    os::check_owner(&root, principal)?;
    let root_final = os::final_path(&root).ok_or("profile root has no final path")?;

    let file = os::open_no_follow(path).map_err(|e| format!("open source: {e}"))?;
    os::check_plain_file(&file)?;
    os::check_owner(&file, principal)?;
    let file_final = os::final_path(&file).ok_or("source has no final path")?;
    if !final_path_is_under(&root_final, &file_final) {
        return Err("source resolves outside its profile".into());
    }
    let len = file
        .metadata()
        .map_err(|e| format!("stat source: {e}"))?
        .len();
    if len > max_bytes {
        return Err("source exceeds the size cap".into());
    }
    Ok(file)
}

/// `Err` when `path` is not under `anchor` or any component from just below
/// `anchor` down to `path` itself is a link or reparse point. `anchor` is
/// trusted as given: a relocated profile root is legitimately a junction.
fn first_redirect_below(anchor: &Path, path: &Path) -> Result<(), &'static str> {
    let relative = path
        .strip_prefix(anchor)
        .map_err(|_| "source is not under its profile root")?;
    let mut current = anchor.to_path_buf();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(part) => current.push(part),
            _ => return Err("source path is not plain"),
        }
        if is_link(&current) {
            return Err("a source path component is a link");
        }
    }
    Ok(())
}

/// Whether `path` itself (not its target) is a symlink, junction or other
/// reparse point. An unreadable component counts as one: refusing is safe.
fn is_link(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return true;
    };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

/// Whether final path `file` lies strictly inside final path `root`,
/// compared case-insensitively on a component boundary.
fn final_path_is_under(root: &str, file: &str) -> bool {
    let root = root.trim_end_matches(['\\', '/']).to_lowercase();
    let file = file.to_lowercase();
    match file.strip_prefix(&root) {
        Some(rest) => rest.len() > 1 && (rest.starts_with('\\') || rest.starts_with('/')),
        None => false,
    }
}

/// Windows-only, like the handle walk that consumes them: on another OS the
/// crate still compiles for CI and these would be dead code.
#[cfg(target_os = "windows")]
const SYSTEM_SID: &str = "S-1-5-18";
#[cfg(target_os = "windows")]
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// An administrator's profile and files are owned by the Administrators
/// group rather than the user, so an exact-SID match would refuse them; any
/// other ordinary account as owner means the object is not the caller's.
#[cfg(target_os = "windows")]
fn owner_is_acceptable(owner: &str, principal: &str) -> bool {
    owner.eq_ignore_ascii_case(principal) || owner == SYSTEM_SID || owner == ADMINISTRATORS_SID
}

/// Handle-based file checks for the Windows service.
#[cfg(windows)]
mod os {
    #![allow(unsafe_code)]

    use std::fs::File;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    use windows::core::PWSTR;
    use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
    use windows::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED,
    };

    use super::{owner_is_acceptable, ADMINISTRATORS_SID, SYSTEM_SID};

    fn handle(file: &File) -> HANDLE {
        HANDLE(file.as_raw_handle().cast())
    }

    /// Directories need backup semantics to be opened at all; the root's own
    /// link is followed on purpose (see `first_redirect_below`).
    pub fn open_directory(path: &Path) -> std::io::Result<File> {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
            .open(path)
    }

    /// Opens a final-component link as itself, so `check_plain_file` sees it.
    pub fn open_no_follow(path: &Path) -> std::io::Result<File> {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(path)
    }

    /// A hard link would carry another file's content under a name inside
    /// the profile, and the final path would not reveal it.
    pub fn check_plain_file(file: &File) -> Result<(), String> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the handle is live for the borrow of `file`; `info` is a
        // properly sized out-param.
        unsafe { GetFileInformationByHandle(handle(file), &mut info) }
            .map_err(|e| format!("query source: {e}"))?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err("source is a link".into());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
            return Err("source is a directory".into());
        }
        if info.nNumberOfLinks != 1 {
            return Err("source has more than one link".into());
        }
        Ok(())
    }

    pub fn final_path(file: &File) -> Option<String> {
        let mut buf = vec![0u16; 512];
        loop {
            // SAFETY: the handle is live for the borrow of `file`; the buffer
            // length is passed with the slice.
            let len =
                unsafe { GetFinalPathNameByHandleW(handle(file), &mut buf, FILE_NAME_NORMALIZED) }
                    as usize;
            if len == 0 {
                return None;
            }
            if len < buf.len() {
                return Some(String::from_utf16_lossy(&buf[..len]));
            }
            // On overflow the return value is the size required, NUL included.
            buf.resize(len + 1, 0);
        }
    }

    pub fn owner_sid(file: &File) -> Option<String> {
        let mut owner = PSID::default();
        let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        // SAFETY: the handle is live for the borrow of `file`; `owner` points
        // into `descriptor`, which is freed only after the SID is converted.
        unsafe {
            let rc = GetSecurityInfo(
                handle(file),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(std::ptr::addr_of_mut!(owner)),
                None,
                None,
                None,
                Some(std::ptr::addr_of_mut!(descriptor)),
            );
            if rc != ERROR_SUCCESS {
                return None;
            }
            let mut text = PWSTR::null();
            let sid = if ConvertSidToStringSidW(owner, &mut text).is_ok() && !text.is_null() {
                text.to_string().ok()
            } else {
                None
            };
            if !text.is_null() {
                let _ = LocalFree(HLOCAL(text.0.cast()));
            }
            let _ = LocalFree(HLOCAL(descriptor.0));
            sid
        }
    }

    pub fn check_owner(file: &File, principal: &str) -> Result<(), String> {
        let owner = owner_sid(file).ok_or("owner unreadable")?;
        if owner_is_acceptable(&owner, principal) {
            Ok(())
        } else {
            Err("not owned by the requesting user".into())
        }
    }

    /// Only SYSTEM or Administrators may own a directory the copy is written
    /// to; a directory an ordinary user created first stays theirs to rewrite.
    pub fn is_machine_owned_dir(path: &Path) -> bool {
        let Ok(dir) = open_directory(path) else {
            return false;
        };
        matches!(
            owner_sid(&dir).as_deref(),
            Some(SYSTEM_SID | ADMINISTRATORS_SID)
        )
    }
}

/// Portable stand-ins so the discovery and copy logic stays testable off
/// Windows; the production reader of this crate runs only in the Windows
/// service.
#[cfg(not(windows))]
mod os {
    use std::fs::File;
    use std::path::Path;

    pub fn open_directory(path: &Path) -> std::io::Result<File> {
        File::open(path)
    }

    pub fn open_no_follow(path: &Path) -> std::io::Result<File> {
        File::open(path)
    }

    pub fn check_plain_file(file: &File) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata().map_err(|e| format!("stat source: {e}"))?;
        if !meta.is_file() {
            return Err("source is not a regular file".into());
        }
        if meta.nlink() != 1 {
            return Err("source has more than one link".into());
        }
        Ok(())
    }

    pub fn final_path(file: &File) -> Option<String> {
        use std::os::unix::io::AsRawFd;
        std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    pub fn check_owner(_file: &File, _principal: &str) -> Result<(), String> {
        Ok(())
    }

    pub fn is_machine_owned_dir(_path: &Path) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use nrr_sqlite_support::browser_history::read_hostnames_from_db;

    use super::*;

    #[test]
    fn thunderbird_profiles_are_discovered_under_roaming() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir
            .path()
            .join("Thunderbird")
            .join("Profiles")
            .join("abc123.default-release");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::write(
            profile.join("prefs.js"),
            "user_pref(\"mail.server.server1.hostname\", \"pop.example.org\");\n",
        )
        .unwrap();
        let roots = AppDataRoots {
            local: None,
            roaming: Some(dir.path().to_path_buf()),
            profile: None,
        };
        let me = test_principal(dir.path());
        assert_eq!(
            thunderbird_server_hostnames(&roots, &me),
            vec!["pop.example.org"]
        );
        // Absent install → empty, never an error.
        let empty_roots = AppDataRoots {
            local: None,
            roaming: Some(dir.path().join("nope")),
            profile: None,
        };
        assert!(thunderbird_server_hostnames(&empty_roots, &me).is_empty());
    }

    /// The owner the OS stamps on files this test process creates, i.e. the
    /// SID the checks must accept as "the requesting user".
    fn test_principal(dir: &Path) -> String {
        #[cfg(windows)]
        {
            os::owner_sid(&os::open_directory(dir).unwrap()).unwrap()
        }
        #[cfg(not(windows))]
        {
            let _ = dir;
            "S-1-5-21-1-2-3-1000".to_string()
        }
    }

    /// Link `link` to directory `target` the way an unprivileged user can
    /// (a junction on Windows). `false` when this environment cannot.
    fn make_dir_link(target: &Path, link: &Path) -> bool {
        #[cfg(windows)]
        {
            std::process::Command::new("cmd")
                .arg("/C")
                .arg("mklink")
                .arg("/J")
                .arg(link)
                .arg(target)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        #[cfg(not(windows))]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
    }

    #[test]
    fn final_path_containment_needs_a_component_boundary() {
        let root = r"\\?\C:\Users\ann";
        assert!(final_path_is_under(
            root,
            r"\\?\C:\Users\ann\AppData\Local\History"
        ));
        assert!(final_path_is_under(
            r"\\?\c:\users\ANN\",
            r"\\?\C:\Users\ann\x"
        ));
        assert!(!final_path_is_under(root, r"\\?\C:\Users\anna\History"));
        assert!(!final_path_is_under(root, r"\\?\C:\Users\bob\History"));
        assert!(!final_path_is_under(root, r"\\?\C:\Users\ann"));
        assert!(!final_path_is_under(root, r"\\?\C:\Users\ann\"));
        assert!(final_path_is_under("/home/ann", "/home/ann/History"));
        assert!(!final_path_is_under("/home/ann", "/home/annex/History"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn only_the_caller_or_a_machine_principal_may_own_the_source() {
        let me = "S-1-5-21-1-2-3-1001";
        assert!(owner_is_acceptable(me, me));
        assert!(owner_is_acceptable("s-1-5-21-1-2-3-1001", me));
        assert!(owner_is_acceptable(SYSTEM_SID, me));
        assert!(owner_is_acceptable(ADMINISTRATORS_SID, me));
        assert!(!owner_is_acceptable("S-1-5-21-1-2-3-1002", me));
        assert!(!owner_is_acceptable("S-1-5-32-545", me));
    }

    #[test]
    fn a_link_below_the_profile_root_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profile");
        let foreign = dir.path().join("foreign").join("Default");
        std::fs::create_dir_all(profile.join("Local").join("Real")).unwrap();
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(foreign.join("History"), b"x").unwrap();
        std::fs::write(profile.join("Local").join("Real").join("History"), b"x").unwrap();
        let me = test_principal(dir.path());

        let real = profile.join("Local").join("Real").join("History");
        assert!(open_verified(&profile, &real, &me, 1024).is_ok());

        let link = profile.join("Local").join("Default");
        if !make_dir_link(&foreign, &link) {
            eprintln!("skipping: cannot create a directory link here");
            return;
        }
        let redirected = link.join("History");
        assert!(
            redirected.is_file(),
            "the link must resolve for the test to mean anything"
        );
        assert_eq!(
            first_redirect_below(&profile, &redirected),
            Err("a source path component is a link")
        );
        assert!(open_verified(&profile, &redirected, &me, 1024).is_err());
    }

    #[test]
    fn a_source_outside_its_anchor_or_over_the_cap_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profile");
        std::fs::create_dir_all(&profile).unwrap();
        let inside = profile.join("History");
        let outside = dir.path().join("History");
        std::fs::write(&inside, b"12").unwrap();
        std::fs::write(&outside, b"12").unwrap();
        let me = test_principal(dir.path());

        assert!(open_verified(&profile, &inside, &me, 2).is_ok());
        assert!(open_verified(&profile, &inside, &me, 1).is_err());
        assert!(open_verified(&profile, &outside, &me, 2).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn a_source_owned_by_another_account_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("History");
        std::fs::write(&file, b"x").unwrap();
        let me = test_principal(dir.path());
        assert!(open_verified(dir.path(), &file, &me, 16).is_ok());
        // Placeholder SID no local account carries.
        let stranger = "S-1-5-21-0-0-0-4242";
        if me == ADMINISTRATORS_SID || me == SYSTEM_SID {
            eprintln!("skipping: this process's files are machine-owned");
            return;
        }
        assert!(open_verified(dir.path(), &file, stranger, 16).is_err());
    }

    #[test]
    fn a_source_is_read_through_a_private_copy_that_is_always_removed() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profile");
        let copies = dir.path().join("copies");
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        std::fs::create_dir_all(&copies).unwrap();
        let db = profile.join("Default").join("History");
        make_db(
            &db,
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT)",
            &["https://feed.example/a"],
        );
        let me = test_principal(dir.path());
        let src = HistorySource {
            db_path: db.clone(),
            anchor: profile.clone(),
            query: CHROMIUM_QUERY,
            label: "chrome",
        };
        let copy_dirs = [copies.clone()];
        assert_eq!(
            read_source_hostnames(&src, &me, &copy_dirs).unwrap(),
            vec!["feed.example".to_string()]
        );
        assert_eq!(std::fs::read_dir(&copies).unwrap().count(), 0);

        // A corrupt source fails the read, and its copy is still removed.
        std::fs::write(&db, b"not a database").unwrap();
        assert!(read_source_hostnames(&src, &me, &copy_dirs).is_err());
        assert_eq!(std::fs::read_dir(&copies).unwrap().count(), 0);
    }

    fn history_source(profile: &Path, db: &Path) -> HistorySource {
        HistorySource {
            db_path: db.to_path_buf(),
            anchor: profile.to_path_buf(),
            query: CHROMIUM_QUERY,
            label: "firefox",
        }
    }

    #[test]
    fn rows_not_yet_checkpointed_from_the_wal_are_read() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profile");
        let copies = dir.path().join("copies");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::create_dir_all(&copies).unwrap();
        let db = profile.join("places.sqlite");
        let writer = rusqlite::Connection::open(&db).unwrap();
        writer
            .execute_batch(
                "PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0;
                 CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
                 PRAGMA wal_checkpoint(TRUNCATE);
                 INSERT INTO urls (url) VALUES ('https://checkpointed.example/');
                 PRAGMA wal_checkpoint(TRUNCATE);
                 INSERT INTO urls (url) VALUES ('https://in-wal.example/');
                 INSERT INTO urls (url) VALUES ('https://also-in-wal.example/');",
            )
            .unwrap();
        // The writer stays open, as a running browser does: nothing is
        // checkpointed on close.
        assert!(with_suffix(&db, "-wal").metadata().unwrap().len() > 0);
        let me = test_principal(dir.path());
        let src = history_source(&profile, &db);

        let hosts = read_source_hostnames(&src, &me, std::slice::from_ref(&copies)).unwrap();
        assert_eq!(
            hosts,
            [
                "also-in-wal.example",
                "checkpointed.example",
                "in-wal.example"
            ]
        );
        // Positive control: the main file alone holds only the checkpointed row.
        assert_eq!(
            read_hostnames_from_db(&db, CHROMIUM_QUERY, hostname_from_history_url)
                .unwrap()
                .hosts,
            ["checkpointed.example"]
        );
        assert_eq!(std::fs::read_dir(&copies).unwrap().count(), 0);
        // The live WAL was read, not replayed into the browser's file.
        drop(writer);
    }

    #[test]
    fn a_hot_journal_is_rolled_back_in_the_copy() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profile");
        let copies = dir.path().join("copies");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::create_dir_all(&copies).unwrap();
        let db = profile.join("History");
        let padding = "x".repeat(2_000);
        let committed: Vec<String> = (0..200)
            .map(|i| format!("https://c{i}.committed.example/{padding}"))
            .collect();
        make_db(
            &db,
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT)",
            &committed.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let writer = rusqlite::Connection::open(&db).unwrap();
        // A tiny cache makes the open transaction spill rewritten pages into
        // the main file, leaving it inconsistent without the journal — as
        // after a crash.
        writer
            .execute_batch(
                "PRAGMA cache_size = 2; BEGIN;
                 UPDATE urls SET url = 'https://uncommitted.example/' || id;",
            )
            .unwrap();
        let journal = with_suffix(&db, "-journal");
        assert!(journal.metadata().unwrap().len() > 0, "the journal is hot");
        // Positive control: the main file alone does not read as committed.
        let main_only = dir.path().join("main-only.sqlite");
        std::fs::copy(&db, &main_only).unwrap();
        let main_only =
            read_hostnames_from_db(&main_only, CHROMIUM_QUERY, hostname_from_history_url);
        assert!(
            main_only
                .as_ref()
                .map_or(true, |r| r.hosts.iter().any(|h| h == "uncommitted.example")),
            "{main_only:?}"
        );
        let me = test_principal(dir.path());
        let src = history_source(&profile, &db);

        let hosts = read_source_hostnames(&src, &me, std::slice::from_ref(&copies)).unwrap();
        assert_eq!(hosts.len(), committed.len());
        assert!(hosts.iter().all(|h| h.ends_with(".committed.example")));
        assert_eq!(std::fs::read_dir(&copies).unwrap().count(), 0);
        writer.execute_batch("ROLLBACK;").unwrap();
    }

    #[test]
    fn a_wal_that_does_not_replay_still_leaves_the_checkpointed_history() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profile");
        let copies = dir.path().join("copies");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::create_dir_all(&copies).unwrap();
        let db = profile.join("places.sqlite");
        let writer = rusqlite::Connection::open(&db).unwrap();
        writer
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT);
                 INSERT INTO urls (url) VALUES ('https://checkpointed.example/');",
            )
            .unwrap();
        drop(writer);
        std::fs::write(with_suffix(&db, "-wal"), vec![0xA5; 64 * 1024]).unwrap();
        let me = test_principal(dir.path());
        let src = history_source(&profile, &db);

        let hosts = read_source_hostnames(&src, &me, std::slice::from_ref(&copies)).unwrap();
        assert_eq!(hosts, ["checkpointed.example"]);
        assert_eq!(std::fs::read_dir(&copies).unwrap().count(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn a_copy_a_scanner_still_holds_is_removed_once_it_lets_go() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;

        let dir = tempfile::tempdir().unwrap();
        let mut copy = TempCopy::create_in(&[dir.path().to_path_buf()], "chrome").unwrap();
        copy.close_all();
        let path = copy.path().to_path_buf();
        // Read sharing only, as a scanner opens a file.
        let held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .open(&path)
            .unwrap();
        // Positive control: a single delete is refused while the file is held.
        assert!(std::fs::remove_file(&path).is_err());
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(120));
            drop(held);
        });

        drop(copy);
        releaser.join().unwrap();
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn only_history_copies_are_discarded_at_start() {
        let dir = tempfile::tempdir().unwrap();
        let dirs = [dir.path().to_path_buf()];
        let nonce = "0123456789abcdef0123456789abcdef";
        let kept = [
            "History".to_string(),
            "nrr-bh-notes.txt".to_string(),
            format!("nrr-bh-chrome-{nonce}.sqlite.bak"),
            format!("nrr-bh--{nonce}.sqlite"),
            "nrr-bh-chrome-0123.sqlite".to_string(),
        ];
        for name in &kept {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        std::fs::create_dir(dir.path().join(format!("nrr-bh-dir-{nonce}.sqlite"))).unwrap();
        std::fs::write(
            dir.path()
                .join(format!("nrr-bh-opera-gx-{nonce}.sqlite-wal")),
            b"x",
        )
        .unwrap();
        // The names a real copy gets, side files included.
        let mut copy = TempCopy::create_in(&dirs, "firefox").unwrap();
        copy.close_all();

        assert_eq!(discard_copies_in(&dirs), 2 + SIDE_FILES.len());
        drop(copy);
        let mut left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        let mut expected: Vec<String> = kept.to_vec();
        expected.push(format!("nrr-bh-dir-{nonce}.sqlite"));
        expected.sort();
        assert_eq!(left, expected);
    }

    #[test]
    fn a_side_file_through_a_link_fails_the_source() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profile");
        let foreign = dir.path().join("foreign");
        let copies = dir.path().join("copies");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::create_dir_all(&copies).unwrap();
        let db = profile.join("places.sqlite");
        make_db(
            &db,
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT)",
            &["https://feed.example/"],
        );
        let me = test_principal(dir.path());
        let src = history_source(&profile, &db);
        if !make_dir_link(&foreign, &with_suffix(&db, "-wal")) {
            eprintln!("skipping: cannot create a directory link here");
            return;
        }
        let error = read_source_hostnames(&src, &me, std::slice::from_ref(&copies)).unwrap_err();
        assert!(error.starts_with("-wal:"), "{error}");
        assert_eq!(std::fs::read_dir(&copies).unwrap().count(), 0);
    }

    #[test]
    fn every_side_file_name_is_taken_up_front_and_removed_with_the_copy() {
        let dir = tempfile::tempdir().unwrap();
        let copy = TempCopy::create_in(&[dir.path().to_path_buf()], "chrome").unwrap();
        let names: Vec<PathBuf> = std::iter::once(copy.path().to_path_buf())
            .chain(SIDE_FILES.iter().map(|s| with_suffix(copy.path(), s)))
            .collect();
        assert!(names.iter().all(|p| p.is_file()));
        drop(copy);
        assert!(names.iter().all(|p| !p.exists()), "all removed");

        // A planted side file refuses the whole copy and removes only ours.
        let path = dir.path().join("copy.sqlite");
        let planted = with_suffix(&path, "-journal");
        std::fs::write(&planted, b"planted").unwrap();
        assert!(TempCopy::create_at(path.clone()).is_err());
        assert!(!path.exists() && !with_suffix(&path, "-wal").exists());
        assert_eq!(std::fs::read(&planted).unwrap(), b"planted");
    }

    #[test]
    fn temp_copies_get_distinct_names_and_never_reuse_an_existing_one() {
        let dir = tempfile::tempdir().unwrap();
        let dirs = [dir.path().to_path_buf()];
        let a = TempCopy::create_in(&dirs, "chrome").unwrap();
        let b = TempCopy::create_in(&dirs, "chrome").unwrap();
        assert_ne!(a.path(), b.path());
        let a_path = a.path().to_path_buf();
        drop(a);
        assert!(!a_path.exists());
        // An unusable directory falls through to the next one.
        let dirs = [dir.path().join("missing"), dir.path().to_path_buf()];
        let c = TempCopy::create_in(&dirs, "chrome").unwrap();
        assert!(c.path().starts_with(dir.path()));
        assert!(TempCopy::create_in(&[dir.path().join("missing")], "chrome").is_err());
    }

    fn make_db(path: &Path, ddl: &str, urls: &[&str]) {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch(ddl).unwrap();
        for u in urls {
            conn.execute("INSERT INTO urls (url) VALUES (?1)", [u])
                .unwrap();
        }
    }

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"").unwrap();
    }

    fn roots(base: &Path) -> AppDataRoots {
        AppDataRoots {
            local: Some(base.join("Local")),
            roaming: Some(base.join("Roaming")),
            profile: None,
        }
    }

    // The `touch()` calls below mirror `discover_history_sources`'s join-call
    // GRANULARITY exactly (same literal fragments, same number of `.join()`
    // calls) rather than folding a whole relative path into one string. `\` is
    // not a separator on Linux, so a vendor fragment like `r"Google\Chrome\User
    // Data"` only ever names a real nested directory when it is pushed as its
    // own `.join()` argument, matching production's `local.join(vendor_product)`
    // — collapsed into one giant literal it silently stops matching on Linux,
    // which is what made these tests fail there. This keeps the tests exercising
    // real, portable discovery/grouping logic on both OSes without touching
    // `discover_history_sources` itself.

    #[test]
    fn discovers_opera_family_direct_profile_layout() {
        let dir = tempfile::tempdir().unwrap();
        touch(
            &dir.path()
                .join("Roaming")
                .join(r"Opera Software\Opera Stable")
                .join("History"),
        );
        touch(
            &dir.path()
                .join("Roaming")
                .join(r"Opera Software\Opera GX Stable")
                .join("History"),
        );
        let sources = discover_history_sources(&roots(dir.path()));
        let labels: Vec<_> = sources.iter().map(|s| s.label).collect();
        assert_eq!(labels, vec!["opera", "opera-gx"]);
    }

    #[test]
    fn discovers_firefox_family_profiles_across_vendors() {
        let dir = tempfile::tempdir().unwrap();
        touch(
            &dir.path()
                .join("Roaming")
                .join(r"Mozilla\Firefox\Profiles")
                .join("abc.default")
                .join("places.sqlite"),
        );
        touch(
            &dir.path()
                .join("Roaming")
                .join(r"librewolf\Profiles")
                .join("x.default")
                .join("places.sqlite"),
        );
        touch(
            &dir.path()
                .join("Roaming")
                .join(r"Waterfox\Profiles")
                .join("y.default")
                .join("places.sqlite"),
        );
        let sources = discover_history_sources(&roots(dir.path()));
        let labels: Vec<_> = sources.iter().map(|s| s.label).collect();
        assert_eq!(labels, vec!["firefox", "librewolf", "waterfox"]);
    }

    #[test]
    fn discovers_arc_msix_package_by_prefix_scan() {
        let dir = tempfile::tempdir().unwrap();
        touch(
            &dir.path()
                .join("Local")
                .join("Packages")
                .join("TheBrowserCompany.Arc_ttt1ap7aakyb4")
                .join(r"LocalCache\Local\Arc\User Data")
                .join("Default")
                .join("History"),
        );
        // Unrelated package must not match.
        touch(
            &dir.path()
                .join("Local")
                .join("Packages")
                .join("SomeVendor.App_hash")
                .join(r"LocalCache\Local\Arc\User Data")
                .join("Default")
                .join("History"),
        );
        let sources = discover_history_sources(&roots(dir.path()));
        let labels: Vec<_> = sources.iter().map(|s| s.label).collect();
        assert_eq!(labels, vec!["arc"]);
    }

    #[test]
    fn discovered_sources_are_summarized_per_label_in_order() {
        let dir = tempfile::tempdir().unwrap();
        touch(
            &dir.path()
                .join("Local")
                .join(r"Google\Chrome\User Data")
                .join("Default")
                .join("History"),
        );
        touch(
            &dir.path()
                .join("Local")
                .join(r"Google\Chrome\User Data")
                .join("Profile 1")
                .join("History"),
        );
        touch(
            &dir.path()
                .join("Roaming")
                .join(r"Mozilla\Firefox\Profiles")
                .join("a.default")
                .join("places.sqlite"),
        );
        let sources = discover_history_sources(&roots(dir.path()));
        assert_eq!(
            summarize_source_labels(sources.iter().map(|s| s.label)),
            "chrome:2 firefox:1"
        );
    }

    #[test]
    fn chromium_profile_dirs_finds_default_and_numbered() {
        let dir = tempfile::tempdir().unwrap();
        let ud = dir.path();
        std::fs::create_dir_all(ud.join("Default")).unwrap();
        std::fs::create_dir_all(ud.join("Profile 1")).unwrap();
        std::fs::create_dir_all(ud.join("Profile 2")).unwrap();
        std::fs::create_dir_all(ud.join("Guest Profile")).unwrap(); // not matched
        let dirs = chromium_profile_dirs(ud);
        assert_eq!(dirs.len(), 3, "Default + Profile 1 + Profile 2");
        assert!(dirs.iter().any(|d| d.ends_with("Default")));
        assert!(dirs.iter().any(|d| d.ends_with("Profile 1")));
    }
}
