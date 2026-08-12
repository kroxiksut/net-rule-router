//! Linux host system-information collector for the
//! diagnostic archive.
//!
//! The Linux analog of `nrr_platform_windows::system_info`: enriches the
//! cross-platform [`SystemInfo::from_std`] baseline with the fields that need an
//! OS-specific source. On Linux those come from the procfs / sysfs pseudo-files
//! and `/etc/os-release` rather than the registry + Win32 calls Windows uses:
//!
//! - `os_version`  ← `/etc/os-release` (`PRETTY_NAME`, else `NAME` + `VERSION`)
//! - `cpu_model`   ← `/proc/cpuinfo` (`model name`)
//! - `total_ram_bytes` ← `/proc/meminfo` (`MemTotal`, reported in KiB)
//!
//! `arch` and `cpu_logical_cores` already come from the portable baseline
//! (`std::env::consts::ARCH` + `available_parallelism`), so they are not
//! re-derived here.
//!
//! Best-effort and pure-`std`: every reader falls back to the baseline value on
//! any parse/read failure, so the collector never fails — a diagnostic archive
//! must build on any host. The parse helpers take the file *contents* as a
//! string, so they are unit-testable on the Windows dev host too (the crate
//! takes no Linux-only dependency).

use nrr_shared::system_info::SystemInfo;

/// Collect this Linux host's system information for the diagnostic archive.
///
/// Reads the procfs / os-release pseudo-files at their canonical paths. The
/// pure parsing lives in the `parse_*` helpers below so the file layout is the
/// only Linux-specific part.
pub fn collect() -> SystemInfo {
    let mut info = SystemInfo::from_std();

    if let Ok(os_release) = std::fs::read_to_string("/etc/os-release") {
        if let Some(v) = parse_os_release(&os_release) {
            info.os_version = v;
        }
    }
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        if let Some(m) = parse_cpu_model(&cpuinfo) {
            info.cpu_model = m;
        }
    }
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        if let Some(b) = parse_mem_total_bytes(&meminfo) {
            info.total_ram_bytes = b;
        }
    }

    info
}

/// Derive a human-readable OS version from `/etc/os-release`.
///
/// Prefers `PRETTY_NAME` (e.g. `Ubuntu 24.04.1 LTS`); otherwise joins `NAME`
/// and `VERSION`. Values may be double-quoted per the os-release format.
/// Returns `None` when no usable field is present (caller keeps the baseline).
fn parse_os_release(contents: &str) -> Option<String> {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    for line in contents.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            let v = unquote(v);
            if !v.is_empty() {
                return Some(v);
            }
        } else if let Some(v) = line.strip_prefix("NAME=") {
            let v = unquote(v);
            if !v.is_empty() {
                name = Some(v);
            }
        } else if let Some(v) = line.strip_prefix("VERSION=") {
            let v = unquote(v);
            if !v.is_empty() {
                version = Some(v);
            }
        }
    }
    match (name, version) {
        (Some(n), Some(v)) => Some(format!("{n} {v}")),
        (Some(n), None) => Some(n),
        (None, Some(v)) => Some(v),
        (None, None) => None,
    }
}

/// First `model name` entry from `/proc/cpuinfo` (identical across cores on
/// homogeneous hosts). `None` when the field is absent.
fn parse_cpu_model(contents: &str) -> Option<String> {
    for line in contents.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim() == "model name" {
                let model = value.trim();
                if !model.is_empty() {
                    return Some(model.to_string());
                }
            }
        }
    }
    None
}

/// `MemTotal` from `/proc/meminfo`, converted from the reported KiB to bytes.
/// The line looks like `MemTotal:       16311412 kB`. `None` on absence /
/// parse failure.
fn parse_mem_total_bytes(contents: &str) -> Option<u64> {
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kib: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return kib.checked_mul(1024);
        }
    }
    None
}

/// Strip one layer of surrounding double quotes from an os-release value.
fn unquote(v: &str) -> String {
    let v = v.trim();
    v.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(v)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_prefers_pretty_name() {
        let sample = "NAME=\"Ubuntu\"\nVERSION=\"24.04.1 LTS (Noble Numbat)\"\n\
             PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n";
        assert_eq!(
            parse_os_release(sample).as_deref(),
            Some("Ubuntu 24.04.1 LTS")
        );
    }

    #[test]
    fn os_release_falls_back_to_name_and_version() {
        let sample = "NAME=\"Alpine Linux\"\nVERSION=\"3.20.0\"\nID=alpine\n";
        assert_eq!(
            parse_os_release(sample).as_deref(),
            Some("Alpine Linux 3.20.0")
        );
    }

    #[test]
    fn os_release_empty_yields_none() {
        assert_eq!(parse_os_release("ID=whatever\n"), None);
    }

    #[test]
    fn cpu_model_reads_first_model_name() {
        let sample = "processor\t: 0\nvendor_id\t: GenuineIntel\n\
             model name\t: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz\nprocessor\t: 1\n";
        assert_eq!(
            parse_cpu_model(sample).as_deref(),
            Some("Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz")
        );
    }

    #[test]
    fn cpu_model_absent_yields_none() {
        assert_eq!(parse_cpu_model("processor\t: 0\n"), None);
    }

    #[test]
    fn mem_total_converts_kib_to_bytes() {
        let sample = "MemTotal:       16311412 kB\nMemFree:  1234 kB\n";
        assert_eq!(parse_mem_total_bytes(sample), Some(16_311_412 * 1024));
    }

    #[test]
    fn mem_total_absent_yields_none() {
        assert_eq!(parse_mem_total_bytes("MemFree:  1234 kB\n"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_fills_ram_and_cores_on_this_host() {
        let info = collect();
        assert!(info.cpu_logical_cores >= 1);
        assert!(info.total_ram_bytes > 0, "/proc/meminfo should report RAM");
        assert_eq!(info.os, "linux");
    }
}
