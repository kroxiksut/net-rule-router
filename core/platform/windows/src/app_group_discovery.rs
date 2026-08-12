//! Windows application-group discovery mechanism.
//!
//! Implements [`nrr_platform_api::AppGroupDiscoveryPort`] by unioning three
//! non-privileged OS sources and classifying each string through the neutral
//! [`nrr_platform_api::classify_app`] dictionary:
//!
//! 1. **Running processes** — every process image basename (`EnumProcesses` +
//!    `QueryFullProcessImageNameW`), so an active member surfaces with
//!    `running = true` and its real exe path.
//! 2. **Installed programs** — the `Uninstall` registry keys (HKLM + the 32-bit
//!    `WOW6432Node` view + HKCU), matched on `DisplayName`, with a best-effort
//!    exe path from `DisplayIcon` / `InstallLocation`.
//! 3. **Kernel-NAT features** — WSL and Hyper-V have no user-facing installed
//!    program and often no matching running process when idle, yet the user
//!    still needs to see them (read-only, primary-pinned). Their service
//!    registry keys (`LxssManager`, `vmms`) are a cheap always-present signal,
//!    surfaced as [`AppDiscoverySource::SystemFeature`]. (Docker Desktop DOES
//!    have an installed-program entry, so source #2 covers it.)
//!
//! No source needs elevation, so this runs in the non-elevated GUI / launcher
//! during onboarding. Every OS failure degrades to "this source contributed
//! nothing". The Win32 helpers mirror [`crate::vpn_discovery`] rather than
//! sharing them — same deliberate self-containment precedent (a few
//! well-understood FFI calls beat coupling two load-bearing discovery modules).

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::path::PathBuf;

use nrr_platform_api::app_group_discovery::{
    classify_app, merge_discovered, AppDiscoverySource, AppGroupDiscoveryPort, AppGroupKind,
    DiscoveredApp,
};
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
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// The three `Uninstall` roots that hold installed-program metadata: the native
/// 64-bit view, the 32-bit `WOW6432Node` view, and the per-user hive.
const UNINSTALL_ROOTS: &[(HKEY, &str)] = &[
    (
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
    (
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
    (
        HKEY_CURRENT_USER,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    ),
];

/// Service registry keys whose presence signals a kernel-NAT stack is installed
/// even when no matching process is running. `display_name` is a stable label
/// (the GUI wraps it with `tr()`); every one classifies as
/// [`AppGroupKind::KernelVirtualNet`].
const KERNEL_NAT_SERVICES: &[(&str, &str)] = &[
    (r"SYSTEM\CurrentControlSet\Services\LxssManager", "WSL"),
    (r"SYSTEM\CurrentControlSet\Services\vmms", "Hyper-V"),
];

/// Windows [`AppGroupDiscoveryPort`]: running processes + installed programs +
/// kernel-NAT service features.
#[derive(Debug, Default)]
pub struct WindowsAppGroupDiscovery;

impl WindowsAppGroupDiscovery {
    pub const fn new() -> Self {
        Self
    }
}

impl AppGroupDiscoveryPort for WindowsAppGroupDiscovery {
    fn discover_app_groups(&self) -> Vec<DiscoveredApp> {
        let mut out = discover_from_processes();
        out.extend(discover_from_installed_programs());
        out.extend(discover_kernel_nat_features());
        merge_discovered(out)
    }
}

// ── Source 1: running processes ───────────────────────────────────────────────

fn discover_from_processes() -> Vec<DiscoveredApp> {
    let mut out = Vec::new();
    for pid in enum_process_ids() {
        let Some(path) = process_image_path(pid) else {
            continue;
        };
        let basename = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        if basename.is_empty() {
            continue;
        }
        if let Some(kind) = classify_app(&basename) {
            out.push(DiscoveredApp {
                kind,
                display_name: basename,
                exe_path: Some(path.to_string_lossy().into_owned()),
                running: true,
                source: AppDiscoverySource::RunningProcess,
            });
        }
    }
    out
}

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
        if pids.len() >= 65_536 {
            pids.truncate(returned.min(pids.len()));
            return pids;
        }
        pids.resize(pids.len() * 2, 0);
    }
}

fn process_image_path(pid: u32) -> Option<PathBuf> {
    if pid == 0 {
        return None;
    }
    // SAFETY: QUERY_LIMITED rights on a PID; the handle is closed on every
    // return path. `QueryFullProcessImageNameW` writes at most `size` UTF-16
    // units and updates `size` to the count written.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid).ok()?;
        if handle.is_invalid() {
            return None;
        }
        let mut buf = [0u16; 260];
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

// ── Source 2: installed programs (Uninstall registry) ─────────────────────────

fn discover_from_installed_programs() -> Vec<DiscoveredApp> {
    let mut out = Vec::new();
    for (hive, root) in UNINSTALL_ROOTS {
        for sub in enum_subkeys(*hive, root) {
            let full = format!(r"{root}\{sub}");
            let Some(display_name) = read_named_value(*hive, &full, "DisplayName") else {
                continue;
            };
            let display_name = display_name.trim().to_string();
            let Some(kind) = classify_app(&display_name) else {
                continue;
            };
            // Best-effort exe path: DisplayIcon ("C:\...\app.exe,0") first, then
            // InstallLocation (a directory hint even without a specific exe).
            let exe_path = read_named_value(*hive, &full, "DisplayIcon")
                .and_then(|raw| exe_from_display_icon(&raw))
                .or_else(|| {
                    read_named_value(*hive, &full, "InstallLocation")
                        .map(|loc| unquote(&loc).to_string())
                        .filter(|s| !s.trim().is_empty())
                });
            out.push(DiscoveredApp {
                kind,
                display_name,
                exe_path,
                running: false,
                source: AppDiscoverySource::InstalledProgram,
            });
        }
    }
    out
}

// ── Source 3: kernel-NAT service features ─────────────────────────────────────

fn discover_kernel_nat_features() -> Vec<DiscoveredApp> {
    let mut out = Vec::new();
    for (subkey, display_name) in KERNEL_NAT_SERVICES {
        // The service key existing is the "installed" signal; a read-only open
        // is enough (no value needed).
        if let Some(hkey) = open_key(HKEY_LOCAL_MACHINE, subkey, KEY_QUERY_VALUE.0) {
            close_key(hkey);
            out.push(DiscoveredApp {
                kind: AppGroupKind::KernelVirtualNet,
                display_name: (*display_name).to_string(),
                exe_path: None,
                running: false,
                source: AppDiscoverySource::SystemFeature,
            });
        }
    }
    out
}

/// Extract an exe path from a `DisplayIcon` value: strip a trailing `,<index>`
/// icon selector and surrounding quotes, keep it only if it ends in `.exe`.
fn exe_from_display_icon(raw: &str) -> Option<String> {
    let unquoted = unquote(raw.trim());
    let candidate = match unquoted.rsplit_once(',') {
        Some((path, idx)) if idx.chars().all(|c| c.is_ascii_digit() || c == '-') => path,
        _ => unquoted,
    };
    let candidate = candidate.trim();
    if candidate.to_ascii_lowercase().ends_with(".exe") {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn unquote(raw: &str) -> &str {
    let trimmed = raw.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .unwrap_or(trimmed)
}

// ── Win32 registry helpers ────────────────────────────────────────────────────

fn open_key(hive: HKEY, subkey: &str, access: u32) -> Option<HKEY> {
    let wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut hkey = HKEY::default();
    // SAFETY: `wide` is NUL-terminated UTF-16 outliving the call; `hkey` is a
    // fresh out-param; the hive is a Win32 pseudo-handle.
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
    // SAFETY: `hkey` came from `RegOpenKeyExW`; closing a valid handle is sound.
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

fn enum_subkeys(hive: HKEY, subkey: &str) -> Vec<String> {
    let mut out = Vec::new();
    let access = KEY_ENUMERATE_SUB_KEYS.0 | KEY_QUERY_VALUE.0;
    let Some(hkey) = open_key(hive, subkey, access) else {
        return out;
    };
    let mut index: u32 = 0;
    loop {
        let mut name_buf = [0u16; 256];
        let mut name_len = name_buf.len() as u32;
        let mut _last_write = FILETIME::default();
        // SAFETY: `name_buf`/`name_len` are valid in/out params sized above.
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
        if index > 20_000 {
            break; // pathological hive guard
        }
    }
    close_key(hkey);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_from_display_icon_strips_index_and_quotes() {
        assert_eq!(
            exe_from_display_icon(r#""C:\Prog\VBoxSVC.exe,0""#).as_deref(),
            Some(r"C:\Prog\VBoxSVC.exe")
        );
        assert_eq!(
            exe_from_display_icon(r"C:\Prog\qbittorrent.exe").as_deref(),
            Some(r"C:\Prog\qbittorrent.exe")
        );
        assert_eq!(exe_from_display_icon(r"C:\Prog\icon.ico"), None);
        assert_eq!(exe_from_display_icon(""), None);
    }

    #[test]
    fn discovery_is_constructible_and_runs_without_panicking() {
        // Smoke test: enumerates the live machine (content is environment-
        // dependent; we only assert it does not panic and returns well-formed
        // rows). The Win32 calls are exercised here.
        let found = WindowsAppGroupDiscovery::new().discover_app_groups();
        for a in &found {
            assert!(!a.display_name.trim().is_empty());
            // Every returned row must be a real dictionary/feature classification.
            if a.source != AppDiscoverySource::SystemFeature {
                assert!(
                    classify_app(&a.display_name).is_some() || a.exe_path.is_some(),
                    "process/installed rows classify or carry a path: {a:?}"
                );
            }
        }
    }
}
