//! `AppPathResolver` platform port: exe name/glob → concrete paths.
//!
//! An `Application` rule names an executable by its file **name** or a filename
//! **glob** (`2gis.exe`, `DiskO*.exe`, `vk.exe`). But the WFP `ALE_APP_ID`
//! condition keys on a real, on-disk **file path** (`FwpmGetAppIdFromFileName0`),
//! not a name — so without a name→path bridge those rules are silently skipped.
//! This port turns a name/glob into the set of concrete exe paths present on the
//! machine so the WFP codegen (a separate worker) can emit one filter per path.
//!
//! Per the policy/mechanism seam (mirrors [`crate::dns_redirect`]):
//!
//! - The [`AppPathResolver`] trait is **neutral** and compiles everywhere; the
//!   decision "which paths does this name resolve to" is the only contract.
//! - [`NoopAppPathResolver`] is the off-Windows / disabled default (empty set).
//! - The real mechanism lives in [`WindowsAppPathResolver`]
//!   (`#[cfg(target_os = "windows")]`), which unions three OS sources behind
//!   small internal functions. The pure glue — the glob matcher, the
//!   case-insensitive union/dedup, and the resolve cache — is unit-testable
//!   without touching the registry, the process list, or the filesystem.
//!
//! Resolution is **never an error**: an app that is not installed / not found
//! simply resolves to an empty `Vec`. Every OS failure degrades to "this source
//! contributed nothing," never a panic or a propagated error.

// `HashMap` and `PathBuf` are used only by the Windows-only `ResolveCache`; gate
// them so non-Windows builds don't flag an unused import.
#[cfg(target_os = "windows")]
use std::collections::HashMap;
#[cfg(target_os = "windows")]
use std::path::PathBuf;

// The neutral `AppPathResolver` PORT + off-platform `NoopAppPathResolver`,
// the pure glob/union helpers (`glob_match` / `dedup_paths`), and the
// `MockAppPathResolver` test double all live in `nrr-platform-api`; re-export so
// `nrr_platform_windows::app_path_resolver::*` paths keep resolving unchanged. Only
// the Windows MECHANISM (`WindowsAppPathResolver` + its `ResolveCache`) stays here.
pub use nrr_platform_api::app_path_resolver::{
    dedup_paths, glob_match, AppPathResolver, MockAppPathResolver, NoopAppPathResolver,
};

// ── Resolve cache (neutral logic; only wired by the Windows impl) ─────────────
//
// Gated to Windows to avoid a dead-code warning on other OSes where no resolver
// consumes it. The clock is injected as an explicit `Instant` in the internal
// methods so the TTL logic is unit-testable with simulated time — the public
// wrapper stamps `Instant::now()`.

/// Short-lived name/glob → paths cache so `resolve` does not re-scan the
/// registry + running processes + filesystem on every policy recompute.
#[cfg(target_os = "windows")]
struct ResolveCache {
    ttl: std::time::Duration,
    entries: std::sync::Mutex<HashMap<String, CacheEntry>>,
}

#[cfg(target_os = "windows")]
struct CacheEntry {
    stored_at: std::time::Instant,
    paths: Vec<PathBuf>,
}

#[cfg(target_os = "windows")]
impl ResolveCache {
    fn new(ttl: std::time::Duration) -> Self {
        Self {
            ttl,
            entries: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Fresh cached value for `key` relative to `now`, or `None` if absent /
    /// expired. A poisoned lock degrades to a cache miss (never panics).
    fn get_at(&self, key: &str, now: std::time::Instant) -> Option<Vec<PathBuf>> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(key)?;
        (now.saturating_duration_since(entry.stored_at) < self.ttl).then(|| entry.paths.clone())
    }

    fn put_at(&self, key: &str, paths: Vec<PathBuf>, now: std::time::Instant) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(
                key.to_string(),
                CacheEntry {
                    stored_at: now,
                    paths,
                },
            );
        }
    }

    /// Return the cached value if fresh at `now`, else compute, store, return.
    fn get_or_compute_at<F: FnOnce() -> Vec<PathBuf>>(
        &self,
        key: &str,
        now: std::time::Instant,
        compute: F,
    ) -> Vec<PathBuf> {
        if let Some(hit) = self.get_at(key, now) {
            return hit;
        }
        let computed = compute();
        self.put_at(key, computed.clone(), now);
        computed
    }

    /// Production entry point — stamps the current instant.
    fn get_or_compute<F: FnOnce() -> Vec<PathBuf>>(&self, key: &str, compute: F) -> Vec<PathBuf> {
        self.get_or_compute_at(key, std::time::Instant::now(), compute)
    }
}

// ── Production impl (Win32) ───────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod windows_impl {
    #![allow(unsafe_code)]

    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, FALSE, FILETIME,
    };
    use windows::Win32::System::ProcessStatus::EnumProcesses;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, REG_SAM_FLAGS, REG_VALUE_TYPE,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::{dedup_paths, glob_match, ResolveCache};
    use crate::app_path_resolver::AppPathResolver;

    /// `App Paths` registry subkey (relative to the hive root).
    const APP_PATHS_SUBKEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";

    /// Bounded recursive Program-Files walk limits — cost ceiling for the most
    /// expensive source.
    const FS_WALK_MAX_DEPTH: u32 = 4;
    const FS_WALK_MAX_FILES: u32 = 4000;

    /// Windows [`AppPathResolver`]: unions three sources (App Paths registry,
    /// running-process images, Program Files walk), case-insensitively dedups,
    /// keeps only existing exe files, and caches the result briefly.
    pub struct WindowsAppPathResolver {
        cache: ResolveCache,
    }

    impl WindowsAppPathResolver {
        /// Resolve-cache TTL. 30 s keeps `resolve` off the registry/process/FS
        /// scan on back-to-back policy recomputes while staying fresh enough to
        /// pick up an app the user just installed or launched.
        pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(30);

        pub fn new() -> Self {
            Self {
                cache: ResolveCache::new(Self::DEFAULT_CACHE_TTL),
            }
        }

        /// Construct with a custom cache TTL (tuning / tests).
        pub fn with_ttl(ttl: Duration) -> Self {
            Self {
                cache: ResolveCache::new(ttl),
            }
        }
    }

    impl Default for WindowsAppPathResolver {
        fn default() -> Self {
            Self::new()
        }
    }

    impl AppPathResolver for WindowsAppPathResolver {
        fn resolve(&self, name_or_glob: &str) -> Vec<PathBuf> {
            let key = name_or_glob.trim().to_ascii_lowercase();
            if key.is_empty() {
                return Vec::new();
            }
            self.cache.get_or_compute(&key, || resolve_uncached(&key))
        }
    }

    /// Union all three sources for `key` (already trimmed + lowercased).
    fn resolve_uncached(key: &str) -> Vec<PathBuf> {
        let is_glob = key.contains('*') || key.contains('?');

        let mut out = resolve_from_app_paths(key, is_glob);
        out.extend(resolve_from_processes(key));

        // The filesystem walk is the costliest source. For an exact (non-glob)
        // name already located via the registry or a running process, skip it to
        // keep the common recompute path fast. A glob always walks — an app can
        // be installed in a non-standard directory the registry/process sources
        // never see, and a glob is meant to catch every such install.
        if is_glob || out.is_empty() {
            out.extend(resolve_from_program_files(key));
        }

        // The port contract is "concrete, existing exe file paths": a stale App
        // Paths entry can point at a since-uninstalled binary, so drop anything
        // that is not a real file before the case-insensitive dedup.
        out.retain(|p| p.is_file());
        dedup_paths(out)
    }

    // ── Source 1: App Paths registry (HKLM + HKCU) ────────────────────────────

    /// Read the `App Paths` default (unnamed) values across both hives.
    /// Non-glob: open `App Paths\<name>` directly. Glob: enumerate the subkeys
    /// under `App Paths` and read the default value of each matching subkey.
    fn resolve_from_app_paths(query: &str, is_glob: bool) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
            if is_glob {
                for sub in enum_subkeys(hive, APP_PATHS_SUBKEY) {
                    if glob_match(query, &sub) {
                        let full = format!(r"{APP_PATHS_SUBKEY}\{sub}");
                        if let Some(raw) = read_default_value(hive, &full) {
                            push_registry_path(&mut out, &raw);
                        }
                    }
                }
            } else {
                let full = format!(r"{APP_PATHS_SUBKEY}\{query}");
                if let Some(raw) = read_default_value(hive, &full) {
                    push_registry_path(&mut out, &raw);
                }
            }
        }
        out
    }

    /// Normalize a raw registry value (strip surrounding quotes, expand
    /// `%VAR%` tokens) and push it if non-empty.
    fn push_registry_path(out: &mut Vec<PathBuf>, raw: &str) {
        let unquoted = unquote(raw);
        let expanded = expand_env(unquoted);
        if !expanded.is_empty() {
            out.push(PathBuf::from(expanded));
        }
    }

    /// Strip a single pair of surrounding double quotes, if present.
    fn unquote(raw: &str) -> &str {
        let trimmed = raw.trim();
        trimmed
            .strip_prefix('"')
            .and_then(|r| r.strip_suffix('"'))
            .unwrap_or(trimmed)
    }

    /// Expand `%VAR%` tokens against the process environment. Unknown variables
    /// and unterminated `%` are left verbatim; `%%` collapses to a literal `%`.
    /// Handles the `REG_EXPAND_SZ` `App Paths` values (e.g. `%ProgramFiles%\…`).
    fn expand_env(input: &str) -> String {
        if !input.contains('%') {
            return input.to_string();
        }
        let mut out = String::with_capacity(input.len());
        let mut rest = input;
        while let Some(start) = rest.find('%') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            match after.find('%') {
                Some(end) => {
                    let name = &after[..end];
                    if name.is_empty() {
                        out.push('%'); // "%%" → literal '%'
                    } else if let Ok(val) = std::env::var(name) {
                        out.push_str(&val);
                    } else {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                    rest = &after[end + 1..];
                }
                None => {
                    out.push('%');
                    out.push_str(after);
                    rest = "";
                    break;
                }
            }
        }
        out.push_str(rest);
        out
    }

    /// Open `hive\subkey` with `access`. `None` on any failure (never an error).
    fn open_key(hive: HKEY, subkey: &str, access: u32) -> Option<HKEY> {
        let wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey = HKEY::default();
        // SAFETY: `wide` is NUL-terminated UTF-16 that outlives the call; `hkey`
        // is a fresh out-param; the hive is a Win32 pseudo-handle.
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

    /// Read the default (unnamed) `REG_SZ`/`REG_EXPAND_SZ` value of `hive\subkey`.
    fn read_default_value(hive: HKEY, subkey: &str) -> Option<String> {
        let hkey = open_key(hive, subkey, KEY_QUERY_VALUE.0)?;

        let mut size: u32 = 0;
        let mut value_type = REG_VALUE_TYPE::default();
        // First call probes the byte size of the default value.
        // SAFETY: `PCWSTR::null()` selects the default value; the out-params are
        // valid stack locations that outlive the call.
        let rc = unsafe {
            RegQueryValueExW(
                hkey,
                PCWSTR::null(),
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
                PCWSTR::null(),
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
        let s = String::from_utf16_lossy(slice);
        Some(s.trim_end_matches('\0').to_string())
    }

    /// Enumerate the immediate subkey names of `hive\subkey`.
    fn enum_subkeys(hive: HKEY, subkey: &str) -> Vec<String> {
        let mut out = Vec::new();
        let access = KEY_ENUMERATE_SUB_KEYS.0 | KEY_QUERY_VALUE.0;
        let Some(hkey) = open_key(hive, subkey, access) else {
            return out;
        };
        let mut index: u32 = 0;
        loop {
            // Registry key names are bounded at 255 chars; 256 fits name + NUL.
            let mut name_buf = [0u16; 256];
            let mut name_len = name_buf.len() as u32;
            let mut _last_write = FILETIME::default();
            // SAFETY: `name_buf`/`name_len` are valid in/out params sized above;
            // the class + reserved params are unused (null / None).
            let rc = unsafe {
                RegEnumKeyExW(
                    hkey,
                    index,
                    PWSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    PWSTR::null(),
                    None,
                    Some(&mut _last_write),
                )
            };
            if rc == ERROR_NO_MORE_ITEMS || rc != ERROR_SUCCESS {
                break;
            }
            out.push(String::from_utf16_lossy(&name_buf[..name_len as usize]));
            index += 1;
            if index > 10_000 {
                break; // pathological hive guard
            }
        }
        close_key(hkey);
        out
    }

    // ── Source 2: running-process image paths ─────────────────────────────────

    /// Match every running process's image **basename** against `query`,
    /// returning the full image paths of the matches.
    fn resolve_from_processes(query: &str) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for pid in enum_process_ids() {
            let Some(path) = process_image_path(pid) else {
                continue; // PID exited or not openable (access denied) — skip.
            };
            let basename = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !basename.is_empty() && glob_match(query, &basename) {
                out.push(path);
            }
        }
        out
    }

    /// Snapshot the running-process PID set via `EnumProcesses`, growing the
    /// buffer until it is not saturated. Empty on failure.
    fn enum_process_ids() -> Vec<u32> {
        let mut pids = vec![0u32; 1024];
        loop {
            let cap_bytes = (pids.len() * std::mem::size_of::<u32>()) as u32;
            let mut needed: u32 = 0;
            // SAFETY: `pids` is a valid `cap_bytes`-sized buffer; `needed` is a
            // fresh out-param receiving the bytes written.
            let ok = unsafe { EnumProcesses(pids.as_mut_ptr(), cap_bytes, &mut needed) };
            if ok.is_err() {
                return Vec::new();
            }
            let returned = (needed as usize) / std::mem::size_of::<u32>();
            if returned < pids.len() {
                pids.truncate(returned);
                return pids;
            }
            // Buffer was full — some PIDs may have been dropped; grow and retry.
            if pids.len() >= 65_536 {
                pids.truncate(returned.min(pids.len()));
                return pids;
            }
            pids.resize(pids.len() * 2, 0);
        }
    }

    /// Resolve a PID to its full image path. `None` for PID 0, an exited
    /// process, or a protected PID `OpenProcess` cannot open (access denied).
    fn process_image_path(pid: u32) -> Option<PathBuf> {
        if pid == 0 {
            return None;
        }
        // SAFETY: `OpenProcess` with QUERY_LIMITED rights on a PID; the handle is
        // closed on every return path. `QueryFullProcessImageNameW` writes at
        // most `size` UTF-16 units into `buf` and updates `size` to the count
        // written (excluding the NUL).
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid).ok()?;
            if handle.is_invalid() {
                return None;
            }
            let mut buf = [0u16; 260]; // MAX_PATH — Win32 image paths fit.
            let mut size = buf.len() as u32;
            let query = QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut size,
            );
            let _ = CloseHandle(handle);
            query.ok()?;
            if size == 0 {
                return None;
            }
            Some(PathBuf::from(String::from_utf16_lossy(
                &buf[..size as usize],
            )))
        }
    }

    // ── Source 3: bounded Program Files walk ──────────────────────────────────

    /// Walk the standard install roots (`%ProgramFiles%`, `%ProgramFiles(x86)%`,
    /// `%ProgramW6432%`, `%LocalAppData%\Programs`) to a bounded depth / file
    /// budget, collecting `*.exe` whose basename matches `query`. `std::fs` only.
    fn resolve_from_program_files(query: &str) -> Vec<PathBuf> {
        let mut roots: Vec<PathBuf> = Vec::new();
        for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
            if let Ok(v) = std::env::var(var) {
                if !v.is_empty() {
                    roots.push(PathBuf::from(v));
                }
            }
        }
        if let Ok(local) = std::env::var("LocalAppData") {
            if !local.is_empty() {
                roots.push(PathBuf::from(local).join("Programs"));
            }
        }
        // `%ProgramFiles%` and `%ProgramW6432%` frequently coincide — dedup so
        // the shared file budget is not spent walking the same tree twice.
        let roots = dedup_paths(roots);

        let mut out = Vec::new();
        let mut budget = FS_WALK_MAX_FILES;
        for root in roots {
            if budget == 0 {
                break;
            }
            walk_dir_bounded(&root, query, FS_WALK_MAX_DEPTH, &mut budget, &mut out);
        }
        out
    }

    fn walk_dir_bounded(
        dir: &Path,
        query: &str,
        depth: u32,
        budget: &mut u32,
        out: &mut Vec<PathBuf>,
    ) {
        if *budget == 0 {
            return;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) => {
                // Best-effort: an unreadable dir (permissions, junction) skips.
                tracing::trace!(
                    target: "nrr::app_path_resolver",
                    dir = %dir.display(),
                    %err,
                    "skipping unreadable directory during Program Files walk"
                );
                return;
            }
        };
        for entry in entries.flatten() {
            if *budget == 0 {
                return;
            }
            let path = entry.path();
            // `file_type()` does not follow symlinks, so a linked directory is
            // reported as a symlink (not a dir) and never recursed into — no
            // cycle risk.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                if depth > 0 {
                    walk_dir_bounded(&path, query, depth - 1, budget, out);
                }
            } else if file_type.is_file() {
                *budget = budget.saturating_sub(1);
                if let Some(name) = path.file_name() {
                    let name = name.to_string_lossy();
                    if name.to_ascii_lowercase().ends_with(".exe") && glob_match(query, &name) {
                        out.push(path);
                    }
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn unquote_strips_a_single_surrounding_pair() {
            assert_eq!(unquote(r#""C:\a\b.exe""#), r"C:\a\b.exe");
            assert_eq!(unquote(r"C:\a\b.exe"), r"C:\a\b.exe");
            // Unbalanced quote is left as-is.
            assert_eq!(unquote(r#""C:\a\b.exe"#), r#""C:\a\b.exe"#);
        }

        #[test]
        fn expand_env_expands_known_and_preserves_unknown() {
            std::env::set_var("NRR_APR_TEST_ROOT", r"C:\Prog");
            assert_eq!(
                expand_env(r"%NRR_APR_TEST_ROOT%\app.exe"),
                r"C:\Prog\app.exe"
            );
            // Unknown variable is left verbatim.
            assert_eq!(
                expand_env(r"%NRR_APR_DEFINITELY_MISSING%\x.exe"),
                r"%NRR_APR_DEFINITELY_MISSING%\x.exe"
            );
            // No token → identity.
            assert_eq!(expand_env(r"C:\plain\path.exe"), r"C:\plain\path.exe");
            // "%%" collapses to a literal '%'.
            assert_eq!(expand_env("a%%b"), "a%b");
            std::env::remove_var("NRR_APR_TEST_ROOT");
        }

        #[test]
        fn windows_resolver_is_constructible_with_default_and_custom_ttl() {
            let _ = WindowsAppPathResolver::new();
            let r = WindowsAppPathResolver::with_ttl(Duration::from_secs(1));
            // Empty query resolves to nothing without touching the OS.
            assert!(r.resolve("   ").is_empty());
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_impl::WindowsAppPathResolver;

// ── Tests — only the Windows-only cache TTL logic remains here; the pure
// glob / dedup / Noop / Mock tests moved to `nrr-platform-api` with their code. ─

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn cache_serves_within_ttl_and_recomputes_after_expiry() {
        use std::cell::Cell;
        use std::time::{Duration, Instant};

        let cache = ResolveCache::new(Duration::from_secs(30));
        let calls = Cell::new(0u32);
        let compute = |ret: &'static str| {
            calls.set(calls.get() + 1);
            vec![p(ret)]
        };

        let t0 = Instant::now();
        let first = cache.get_or_compute_at("vk.exe", t0, || compute("a"));
        assert_eq!(first, vec![p("a")]);
        assert_eq!(calls.get(), 1);

        // Within TTL → cached; the (different) closure must NOT run.
        let within =
            cache.get_or_compute_at("vk.exe", t0 + Duration::from_secs(5), || compute("b"));
        assert_eq!(within, vec![p("a")], "served from cache");
        assert_eq!(calls.get(), 1, "compute not re-invoked within TTL");

        // After TTL → recompute, new value cached.
        let after =
            cache.get_or_compute_at("vk.exe", t0 + Duration::from_secs(31), || compute("c"));
        assert_eq!(after, vec![p("c")]);
        assert_eq!(calls.get(), 2, "compute re-invoked after TTL expiry");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn cache_zero_ttl_always_recomputes() {
        use std::cell::Cell;
        use std::time::{Duration, Instant};

        let cache = ResolveCache::new(Duration::ZERO);
        let calls = Cell::new(0u32);
        let now = Instant::now();
        for _ in 0..3 {
            let _ = cache.get_or_compute_at("x.exe", now, || {
                calls.set(calls.get() + 1);
                vec![p("x")]
            });
        }
        assert_eq!(calls.get(), 3, "zero TTL means every call recomputes");
    }
}
