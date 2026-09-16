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
//! The browser holds its History DB open, so we COPY it to a temp file first and
//! open the copy read-only — a direct open would race the browser's writer and
//! fail "database is locked". Copy + read is best-effort per profile: any browser
//! that is absent or unreadable is skipped, and partial results are valid.
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
    hostname_from_history_url, BrowserHistoryError, BrowserHistoryReadPort,
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
    /// `SELECT <url-col> FROM <table>` for this browser family.
    query: &'static str,
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
            sources = %summarize_sources(&sources),
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
        hosts.extend(parse_mail_server_hostnames(&text));
    }
    hosts.sort_unstable();
    hosts.dedup();
    hosts
}

/// Extract account-server hostnames from a Thunderbird `prefs.js`. Matches
/// the incoming (`mail.server.serverN.hostname`) and outgoing
/// (`mail.smtpserver.smtpN.hostname`) prefs only — nothing else in the file
/// is looked at, so account names, addresses, and credentials never cross.
/// Pure and total: any line that does not match the shape is skipped.
fn parse_mail_server_hostnames(prefs_js: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for line in prefs_js.lines() {
        let Some(rest) = line.trim_start().strip_prefix("user_pref(\"") else {
            continue;
        };
        let mut parts = rest.split('"');
        let Some(key) = parts.next() else { continue };
        let is_server_host = (key.starts_with("mail.server.server")
            || key.starts_with("mail.smtpserver.smtp"))
            && key.ends_with(".hostname");
        if !is_server_host {
            continue;
        }
        // After the key quote: `, ` then the quoted value.
        let Some(_separator) = parts.next() else {
            continue;
        };
        let Some(value) = parts.next() else { continue };
        let host = value.trim().to_ascii_lowercase();
        if !host.is_empty() {
            hosts.push(host);
        }
    }
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
    const CHROMIUM_QUERY: &str = "SELECT url FROM urls";
    const FIREFOX_QUERY: &str = "SELECT url FROM moz_places WHERE url IS NOT NULL";

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
    #![allow(unsafe_code)]

    use std::path::PathBuf;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE,
        REG_SAM_FLAGS, REG_VALUE_TYPE,
    };

    /// `ProfileImagePath` of `sid` (e.g. `C:\Users\name`), or `None` when the
    /// SID has no local profile, the value carries an unexpanded `%…%`
    /// placeholder (system accounts — not browsing users), or the directory
    /// does not exist.
    pub fn profile_image_path(sid: &str) -> Option<PathBuf> {
        if sid.is_empty() || !sid.starts_with("S-") {
            return None;
        }
        let subkey = format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
        let value = read_named_value(HKEY_LOCAL_MACHINE, &subkey, "ProfileImagePath")?;
        if value.is_empty() || value.contains('%') {
            return None;
        }
        let path = PathBuf::from(value);
        path.is_dir().then_some(path)
    }

    fn open_key(hive: HKEY, subkey: &str, access: u32) -> Option<HKEY> {
        let wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey = HKEY::default();
        // SAFETY: `wide` is NUL-terminated UTF-16 outliving the call; `hkey` is
        // a fresh out-param; the hive is a Win32 pseudo-handle.
        let rc = unsafe {
            RegOpenKeyExW(
                hive,
                PCWSTR(wide.as_ptr()),
                0,
                REG_SAM_FLAGS(access),
                &mut hkey,
            )
        };
        (rc == ERROR_SUCCESS).then_some(hkey)
    }

    fn close_key(hkey: HKEY) {
        // SAFETY: `hkey` came from `RegOpenKeyExW`; closing a valid handle is
        // sound. A close failure is non-actionable at this layer.
        unsafe {
            let _ = RegCloseKey(hkey);
        }
    }

    /// Read a NAMED `REG_SZ`/`REG_EXPAND_SZ` value of `hive\subkey`.
    fn read_named_value(hive: HKEY, subkey: &str, value_name: &str) -> Option<String> {
        let hkey = open_key(hive, subkey, KEY_QUERY_VALUE.0)?;
        let name_wide: Vec<u16> = value_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut size: u32 = 0;
        let mut value_type = REG_VALUE_TYPE::default();
        // SAFETY: `name_wide` is NUL-terminated and outlives the call; the size
        // out-param probes the byte length first.
        let rc = unsafe {
            RegQueryValueExW(
                hkey,
                PCWSTR(name_wide.as_ptr()),
                None,
                Some(&mut value_type),
                None,
                Some(&mut size),
            )
        };
        if rc != ERROR_SUCCESS {
            close_key(hkey);
            return None;
        }
        let mut buf: Vec<u16> = vec![0u16; (size as usize) / 2 + 1];
        let mut read: u32 = (buf.len() * 2) as u32;
        // SAFETY: `buf` is sized from the probe; `read` carries its byte length.
        let rc = unsafe {
            RegQueryValueExW(
                hkey,
                PCWSTR(name_wide.as_ptr()),
                None,
                Some(&mut value_type),
                Some(buf.as_mut_ptr().cast()),
                Some(&mut read),
            )
        };
        close_key(hkey);
        if rc != ERROR_SUCCESS {
            return None;
        }
        let chars = (read as usize) / 2;
        let slice = &buf[..chars.min(buf.len())];
        Some(
            String::from_utf16_lossy(slice)
                .trim_end_matches('\0')
                .to_string(),
        )
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

/// Compact per-label source counts for the discovery-summary log line, in
/// first-seen order: `"chrome:2 firefox:1"`; `"none"` when nothing was found.
fn summarize_sources(sources: &[HistorySource]) -> String {
    let mut counts: Vec<(&'static str, usize)> = Vec::new();
    for src in sources {
        match counts.iter_mut().find(|(label, _)| *label == src.label) {
            Some((_, n)) => *n += 1,
            None => counts.push((src.label, 1)),
        }
    }
    if counts.is_empty() {
        return "none".to_string();
    }
    counts
        .iter()
        .map(|(label, n)| format!("{label}:{n}"))
        .collect::<Vec<_>>()
        .join(" ")
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

/// Largest History DB copied; a bigger one is skipped rather than letting a
/// user-supplied file fill the service's disk.
const MAX_HISTORY_BYTES: u64 = 1024 * 1024 * 1024;

/// Upper bound on URL rows read from one source.
const MAX_HISTORY_ROWS: usize = 2_000_000;

/// Copy `src.db_path` to a private temp file and read its URL column into
/// hostnames.
fn read_source_hostnames(
    src: &HistorySource,
    principal: &str,
    copy_dirs: &[PathBuf],
) -> Result<Vec<String>, String> {
    let source = open_verified(&src.anchor, &src.db_path, principal, MAX_HISTORY_BYTES)?;
    let mut copy = TempCopy::create_in(copy_dirs, src.label)?;
    // Read through the verified handle: re-opening the path would reopen the
    // race the checks just closed.
    let copied = copy.fill_from(&source, MAX_HISTORY_BYTES)?;
    drop(source);
    if copied > MAX_HISTORY_BYTES {
        return Err("source exceeds the size cap".into());
    }
    read_hostnames_from_db(copy.path(), src.query)
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

/// A uniquely named copy that is removed however the read ends.
struct TempCopy {
    path: PathBuf,
    file: Option<File>,
}

impl TempCopy {
    /// Create an unpredictable, not-yet-existing file in the first usable
    /// directory. `create_new` refuses an existing name, including a planted
    /// link, so the name can be neither guessed nor pre-empted.
    fn create_in(dirs: &[PathBuf], label: &str) -> Result<Self, String> {
        let mut last = String::from("no temp directory");
        for dir in dirs {
            let mut nonce = [0u8; 16];
            getrandom::fill(&mut nonce).map_err(|e| format!("temp name: {e}"))?;
            let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            let path = dir.join(format!("nrr-bh-{label}-{hex}.sqlite"));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                    })
                }
                Err(e) => last = format!("create temp copy: {e}"),
            }
        }
        Err(last)
    }

    /// Copy at most `cap + 1` bytes from `source`, returning how many were
    /// written; the file handle is closed before SQLite opens the path.
    fn fill_from(&mut self, source: &File, cap: u64) -> Result<u64, String> {
        let mut out = self
            .file
            .take()
            .ok_or_else(|| String::from("temp copy already filled"))?;
        let mut limited = source.take(cap.saturating_add(1));
        std::io::copy(&mut limited, &mut out).map_err(|e| format!("copy: {e}"))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempCopy {
    fn drop(&mut self) {
        self.file = None;
        let _ = std::fs::remove_file(&self.path);
    }
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

const SYSTEM_SID: &str = "S-1-5-18";
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// An administrator's profile and files are owned by the Administrators
/// group rather than the user, so an exact-SID match would refuse them; any
/// other ordinary account as owner means the object is not the caller's.
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

/// Open `db` READ-ONLY and project `query`'s single URL column into distinct
/// hostnames. Testable in isolation against a synthetic DB. `immutable=1` lets us
/// read even a copy that still carries a stale WAL/lock header. The file is
/// user-supplied, so SQLite's defensive mode is on and the schema untrusted.
pub fn read_hostnames_from_db(db: &Path, query: &str) -> Result<Vec<String>, String> {
    use rusqlite::config::DbConfig;
    use rusqlite::OpenFlags;
    let uri = format!(
        "file:{}?mode=ro&immutable=1",
        db.to_string_lossy().replace('?', "%3f")
    );
    let conn = rusqlite::Connection::open_with_flags(
        &uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| format!("open: {e}"))?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|e| format!("harden: {e}"))?;
    conn.execute_batch("PRAGMA trusted_schema = OFF; PRAGMA cell_size_check = ON;")
        .map_err(|e| format!("harden: {e}"))?;
    let mut stmt = conn.prepare(query).map_err(|e| format!("prepare: {e}"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| format!("query: {e}"))?;
    let mut hosts: Vec<String> = Vec::new();
    for url in rows.take(MAX_HISTORY_ROWS).flatten() {
        if let Some(host) = hostname_from_history_url(&url) {
            hosts.push(host);
        }
    }
    hosts.sort_unstable();
    hosts.dedup();
    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mail_prefs_parser_keeps_only_server_hostnames() {
        let prefs = r#"
user_pref("mail.server.server1.hostname", "imap.mail.example");
user_pref("mail.server.server2.hostname", "MAIL.UNIV.EXAMPLE");
user_pref("mail.server.server2.name", "work account");
user_pref("mail.smtpserver.smtp1.hostname", "smtp.mail.example");
user_pref("mail.smtpserver.smtp1.username", "someone@example.com");
user_pref("mail.identity.id1.useremail", "someone@example.com");
user_pref("network.dns.disableIPv6", true);
"#;
        let hosts = parse_mail_server_hostnames(prefs);
        assert_eq!(
            hosts,
            vec![
                "imap.mail.example",
                "mail.univ.example",
                "smtp.mail.example"
            ],
            "only *.hostname prefs may cross, lower-cased; identities and \
             usernames must never leak"
        );
    }

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
            query: "SELECT url FROM urls",
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

    #[test]
    fn reads_and_dedupes_hostnames_from_chromium_urls_table() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("History");
        make_db(
            &db,
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT)",
            &[
                "https://feed.example/feed",
                "https://feed.example/other", // same host, deduped
                "https://search.example/",
                "about:blank",       // no host, dropped
                "chrome://settings", // pseudo-scheme, dropped
            ],
        );
        let hosts = read_hostnames_from_db(&db, "SELECT url FROM urls").unwrap();
        assert_eq!(
            hosts,
            vec!["feed.example".to_string(), "search.example".to_string()]
        );
    }

    #[test]
    fn missing_db_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.sqlite");
        assert!(read_hostnames_from_db(&missing, "SELECT url FROM urls").is_err());
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
    fn summarize_sources_counts_per_label_in_order() {
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
        assert_eq!(summarize_sources(&sources), "chrome:2 firefox:1");
        assert_eq!(summarize_sources(&[]), "none");
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
