//! Windows host system-information collector for the diagnostic archive.
//!
//! Enriches the cross-platform [`SystemInfo::from_std`] baseline with the
//! Windows-specific fields: OS product name + version (from the
//! `CurrentVersion` registry key), CPU model (from the `CentralProcessor`
//! registry key), the native OS architecture (from the `PROCESSOR_ARCHITECTURE`
//! environment variable), and total physical RAM (`GlobalMemoryStatusEx`).
//!
//! Best-effort: every reader returns `None` / `0` on failure and the field
//! stays at its baseline value, so the collector never fails — a diagnostic
//! archive must build on any host.

#![allow(unsafe_code)]

use std::ffi::c_void;

use nrr_shared::system_info::SystemInfo;
use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{RegGetValueW, HKEY, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

/// Collect this Windows host's system information for the diagnostic archive.
pub fn collect() -> SystemInfo {
    let mut info = SystemInfo::from_std();

    // Native OS architecture (e.g. AMD64 / ARM64) — more accurate than the
    // build arch for a host descriptor. Falls back to the baseline on absence.
    if let Ok(arch) = std::env::var("PROCESSOR_ARCHITECTURE") {
        if !arch.trim().is_empty() {
            info.arch = arch;
        }
    }

    // OS product name + version from the canonical CurrentVersion key.
    const CUR_VER: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let product = reg_sz(HKEY_LOCAL_MACHINE, CUR_VER, "ProductName");
    let display = reg_sz(HKEY_LOCAL_MACHINE, CUR_VER, "DisplayVersion");
    let build = reg_sz(HKEY_LOCAL_MACHINE, CUR_VER, "CurrentBuild");
    info.os_version = format_os_version(product, display, build);

    // CPU model string from the first logical processor's registry node.
    if let Some(cpu) = reg_sz(
        HKEY_LOCAL_MACHINE,
        r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        "ProcessorNameString",
    ) {
        let cpu = cpu.trim().to_string();
        if !cpu.is_empty() {
            info.cpu_model = cpu;
        }
    }

    // Total physical RAM.
    if let Some(bytes) = total_physical_ram_bytes() {
        info.total_ram_bytes = bytes;
    }

    info
}

/// Compose a human-readable OS version from the registry pieces, tolerating
/// any subset being absent. Pure — unit-tested.
fn format_os_version(
    product: Option<String>,
    display: Option<String>,
    build: Option<String>,
) -> String {
    let build_number = build
        .as_deref()
        .and_then(|b| b.trim().parse::<u32>().ok())
        .unwrap_or(0);
    let mut parts: Vec<String> = Vec::new();
    if let Some(p) = product.filter(|s| !s.trim().is_empty()) {
        parts.push(correct_windows_11_product(p.trim(), build_number));
    }
    if let Some(d) = display.filter(|s| !s.trim().is_empty()) {
        parts.push(d.trim().to_string());
    }
    let mut s = parts.join(" ");
    if let Some(b) = build.filter(|s| !s.trim().is_empty()) {
        if s.is_empty() {
            s = format!("build {}", b.trim());
        } else {
            s = format!("{s} (build {})", b.trim());
        }
    }
    if s.is_empty() {
        nrr_shared::system_info::UNKNOWN.to_string()
    } else {
        s
    }
}

/// First build that is Windows 11; `ProductName` keeps saying "Windows 10"
/// there, so the build number is the only honest source of the generation.
const WINDOWS_11_FIRST_BUILD: u32 = 22000;

/// Rewrite a stale "Windows 10 …" product name on a Windows 11 build, keeping
/// the edition intact ("Windows 10 Enterprise LTSC 2024" → "Windows 11 …").
fn correct_windows_11_product(product: &str, build: u32) -> String {
    if build < WINDOWS_11_FIRST_BUILD {
        return product.to_string();
    }
    match product.strip_prefix("Windows 10") {
        Some(rest) => format!("Windows 11{rest}"),
        None => product.to_string(),
    }
}

/// Read a `REG_SZ` value. Two-pass (size, then read). `None` on any failure.
fn reg_sz(root: HKEY, subkey: &str, value: &str) -> Option<String> {
    let subkey_w = wide(subkey);
    let value_w = wide(value);
    let mut size: u32 = 0;
    // SAFETY: valid NUL-terminated wide pointers; first call sizes the buffer
    // (pvdata = null), writing the required byte count into `size`.
    let rc = unsafe {
        RegGetValueW(
            root,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(value_w.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut size),
        )
    };
    if rc != ERROR_SUCCESS || size == 0 {
        return None;
    }
    // `size` is a byte count for a UTF-16 string; allocate u16 units (+1 slack).
    let mut buf: Vec<u16> = vec![0u16; (size as usize) / 2 + 1];
    let mut size2 = size;
    // SAFETY: `buf` holds at least `size2` bytes; the call writes the string.
    let rc2 = unsafe {
        RegGetValueW(
            root,
            PCWSTR(subkey_w.as_ptr()),
            PCWSTR(value_w.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut c_void),
            Some(&mut size2),
        )
    };
    if rc2 != ERROR_SUCCESS {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    if len == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..len]))
}

/// Total physical RAM in bytes via `GlobalMemoryStatusEx`. `None` on failure.
fn total_physical_ram_bytes() -> Option<u64> {
    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    // SAFETY: `status.dwLength` is set to the struct size as the API requires;
    // the call fills the struct and returns a BOOL.
    let ok = unsafe { GlobalMemoryStatusEx(&mut status) }.is_ok();
    if ok {
        Some(status.ullTotalPhys)
    } else {
        None
    }
}

/// NUL-terminated UTF-16 for a `PCWSTR` argument.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::system_info::UNKNOWN;

    #[test]
    fn format_os_version_combines_available_parts() {
        assert_eq!(
            format_os_version(
                Some("Windows 11 Pro".into()),
                Some("23H2".into()),
                Some("22631".into())
            ),
            "Windows 11 Pro 23H2 (build 22631)"
        );
        // Missing display version.
        assert_eq!(
            format_os_version(Some("Windows 10 Pro".into()), None, Some("19045".into())),
            "Windows 10 Pro (build 19045)"
        );
        // Only a build number.
        assert_eq!(
            format_os_version(None, None, Some("22000".into())),
            "build 22000"
        );
        // Nothing → UNKNOWN, never empty.
        assert_eq!(format_os_version(None, None, None), UNKNOWN);
        // Windows 11 keeps a stale "Windows 10" product name in the registry —
        // the build decides the generation, the edition is preserved.
        assert_eq!(
            format_os_version(
                Some("Windows 10 Enterprise LTSC 2024".into()),
                Some("24H2".into()),
                Some("26100".into())
            ),
            "Windows 11 Enterprise LTSC 2024 24H2 (build 26100)"
        );
        // A genuine Windows 10 build is left alone.
        assert_eq!(
            format_os_version(
                Some("Windows 10 Enterprise".into()),
                None,
                Some("19045".into())
            ),
            "Windows 10 Enterprise (build 19045)"
        );
        // A product name that is already correct is untouched.
        assert_eq!(
            format_os_version(Some("Windows 11 Home".into()), None, Some("26100".into())),
            "Windows 11 Home (build 26100)"
        );
        // Blank strings are treated as absent.
        assert_eq!(
            format_os_version(Some("  ".into()), Some("".into()), None),
            UNKNOWN
        );
    }

    #[cfg(windows)]
    #[test]
    fn collect_fills_ram_and_cores_on_this_host() {
        // Runs on the Windows CI/dev host: RAM and cores must be real.
        let info = collect();
        assert!(info.cpu_logical_cores >= 1);
        assert!(
            info.total_ram_bytes > 0,
            "GlobalMemoryStatusEx should report RAM"
        );
        assert_eq!(info.os, "windows");
    }
}
