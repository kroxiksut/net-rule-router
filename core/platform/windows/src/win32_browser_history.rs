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
//! Profile discovery is rooted at the PRINCIPAL's profile, not
//! this process's environment. The service runs as LocalSystem, whose
//! `%LOCALAPPDATA%` is the systemprofile (no browsers), so the env-based
//! discovery returned "no supported browser profiles found" on every real
//! seed. The principal SID resolves to its profile root through the
//! `ProfileList` registry key; the process environment remains the fallback
//! for console/dev runs where that lookup fails.

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
        let mail_hosts = thunderbird_server_hostnames(&roots);
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
        for src in &sources {
            match read_source_hostnames(src) {
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
fn thunderbird_server_hostnames(roots: &AppDataRoots) -> Vec<String> {
    let Some(roaming) = roots.roaming.as_ref() else {
        return Vec::new();
    };
    let profiles_dir = roaming.join("Thunderbird").join("Profiles");
    let Ok(entries) = std::fs::read_dir(&profiles_dir) else {
        return Vec::new();
    };
    let mut hosts = Vec::new();
    for entry in entries.flatten() {
        let prefs = entry.path().join("prefs.js");
        let Ok(text) = std::fs::read_to_string(&prefs) else {
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
        };
    }
    AppDataRoots {
        local: std::env::var("LOCALAPPDATA").ok().map(PathBuf::from),
        roaming: std::env::var("APPDATA").ok().map(PathBuf::from),
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

/// Copy `src.db_path` to a temp file and read its URL column into hostnames.
fn read_source_hostnames(src: &HistorySource) -> Result<Vec<String>, String> {
    // Copy under a per-source temp name so concurrent sources don't collide, and
    // clean it up on the way out (best-effort).
    let mut tmp = std::env::temp_dir();
    tmp.push(format!("nrr-bh-{}.sqlite", src.label));
    std::fs::copy(&src.db_path, &tmp).map_err(|e| format!("copy {}: {e}", src.label))?;
    let result = read_hostnames_from_db(&tmp, src.query);
    let _ = std::fs::remove_file(&tmp);
    result
}

/// Open `db` READ-ONLY and project `query`'s single URL column into distinct
/// hostnames. Testable in isolation against a synthetic DB. `immutable=1` lets us
/// read even a copy that still carries a stale WAL/lock header.
pub fn read_hostnames_from_db(db: &Path, query: &str) -> Result<Vec<String>, String> {
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
    let mut stmt = conn.prepare(query).map_err(|e| format!("prepare: {e}"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| format!("query: {e}"))?;
    let mut hosts: Vec<String> = Vec::new();
    for url in rows.flatten() {
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
user_pref("mail.server.server1.hostname", "imap.yandex.com");
user_pref("mail.server.server2.hostname", "MAIL.ISTU.EDU");
user_pref("mail.server.server2.name", "work account");
user_pref("mail.smtpserver.smtp1.hostname", "smtp.yandex.com");
user_pref("mail.smtpserver.smtp1.username", "someone@example.com");
user_pref("mail.identity.id1.useremail", "someone@example.com");
user_pref("network.dns.disableIPv6", true);
"#;
        let hosts = parse_mail_server_hostnames(prefs);
        assert_eq!(
            hosts,
            vec!["imap.yandex.com", "mail.istu.edu", "smtp.yandex.com"],
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
        };
        assert_eq!(
            thunderbird_server_hostnames(&roots),
            vec!["pop.example.org"]
        );
        // Absent install → empty, never an error.
        let empty_roots = AppDataRoots {
            local: None,
            roaming: Some(dir.path().join("nope")),
        };
        assert!(thunderbird_server_hostnames(&empty_roots).is_empty());
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
                "https://dzen.ru/feed",
                "https://dzen.ru/other", // same host, deduped
                "https://ya.ru/",
                "about:blank",       // no host, dropped
                "chrome://settings", // pseudo-scheme, dropped
            ],
        );
        let hosts = read_hostnames_from_db(&db, "SELECT url FROM urls").unwrap();
        assert_eq!(hosts, vec!["dzen.ru".to_string(), "ya.ru".to_string()]);
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
        }
    }

    #[test]
    fn discovers_opera_family_direct_profile_layout() {
        let dir = tempfile::tempdir().unwrap();
        touch(
            &dir.path()
                .join(r"Roaming\Opera Software\Opera Stable\History"),
        );
        touch(
            &dir.path()
                .join(r"Roaming\Opera Software\Opera GX Stable\History"),
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
                .join(r"Roaming\Mozilla\Firefox\Profiles\abc.default\places.sqlite"),
        );
        touch(
            &dir.path()
                .join(r"Roaming\librewolf\Profiles\x.default\places.sqlite"),
        );
        touch(
            &dir.path()
                .join(r"Roaming\Waterfox\Profiles\y.default\places.sqlite"),
        );
        let sources = discover_history_sources(&roots(dir.path()));
        let labels: Vec<_> = sources.iter().map(|s| s.label).collect();
        assert_eq!(labels, vec!["firefox", "librewolf", "waterfox"]);
    }

    #[test]
    fn discovers_arc_msix_package_by_prefix_scan() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join(
            r"Local\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data\Default\History",
        ));
        // Unrelated package must not match.
        touch(&dir.path().join(
            r"Local\Packages\SomeVendor.App_hash\LocalCache\Local\Arc\User Data\Default\History",
        ));
        let sources = discover_history_sources(&roots(dir.path()));
        let labels: Vec<_> = sources.iter().map(|s| s.label).collect();
        assert_eq!(labels, vec!["arc"]);
    }

    #[test]
    fn summarize_sources_counts_per_label_in_order() {
        let dir = tempfile::tempdir().unwrap();
        touch(
            &dir.path()
                .join(r"Local\Google\Chrome\User Data\Default\History"),
        );
        touch(
            &dir.path()
                .join(r"Local\Google\Chrome\User Data\Profile 1\History"),
        );
        touch(
            &dir.path()
                .join(r"Roaming\Mozilla\Firefox\Profiles\a.default\places.sqlite"),
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
