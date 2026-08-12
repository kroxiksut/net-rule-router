//! Neutral host system-information descriptor for the diagnostic archive.
//!
//! The archive embeds a `system_info.json` so a bug report carries the exact
//! host it came from (OS + version, CPU, RAM, architecture) alongside the app
//! version. Behind the platform policy/mechanism seam this type is
//! OS-neutral; each platform crate provides a `collect_system_info()` that
//! fills the
//! OS-specific fields (`nrr_platform_windows` via the registry + Win32,
//! `nrr_platform_linux` via `/proc` + `/etc/os-release`). [`SystemInfo::from_std`]
//! gives the cross-platform baseline (os / arch / logical cores) every OS
//! shares; the per-OS collector enriches the rest.

use serde::{Deserialize, Serialize};

/// Placeholder used when a field could not be determined on this host.
pub const UNKNOWN: &str = "unknown";

/// Host system information embedded in a diagnostic archive.
///
/// Every field is best-effort: a value that could not be read is [`UNKNOWN`]
/// (strings) or `0` (numbers), never an error — a diagnostic archive must
/// build even on a locked-down or unusual host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SystemInfo {
    /// OS family: `"windows"` | `"linux"` | `"macos"` (from `std::env::consts::OS`).
    pub os: String,
    /// Human-readable OS version, e.g. `"Windows 11 Pro 23H2 (build 22631)"`
    /// or `"Ubuntu 22.04.4 LTS (kernel 5.15.0)"`. [`UNKNOWN`] until a per-OS
    /// collector fills it.
    pub os_version: String,
    /// CPU architecture, e.g. `"AMD64"` / `"ARM64"` / `"x86_64"`.
    pub arch: String,
    /// CPU model string, e.g. `"Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz"`.
    /// [`UNKNOWN`] until a per-OS collector fills it.
    pub cpu_model: String,
    /// Number of logical processors (`std::thread::available_parallelism`).
    pub cpu_logical_cores: u32,
    /// Total physical RAM in bytes, or `0` if it could not be read.
    pub total_ram_bytes: u64,
}

impl SystemInfo {
    /// The cross-platform baseline: OS family, CPU architecture, and logical
    /// core count — all from `std`, no OS-specific calls. A per-OS collector
    /// starts here and enriches `os_version`, `cpu_model`, and `total_ram_bytes`.
    pub fn from_std() -> Self {
        let cpu_logical_cores = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(0);
        Self {
            os: std::env::consts::OS.to_string(),
            os_version: UNKNOWN.to_string(),
            // `env::consts::ARCH` is the BUILD arch, which matches the running
            // binary's arch — sufficient for a diagnostic. A per-OS collector
            // may overwrite this with the true OS/native arch.
            arch: std::env::consts::ARCH.to_string(),
            cpu_model: UNKNOWN.to_string(),
            cpu_logical_cores,
            total_ram_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_std_fills_the_cross_platform_baseline() {
        let info = SystemInfo::from_std();
        // OS family is always known (the compile target).
        assert!(!info.os.is_empty() && info.os != UNKNOWN);
        assert!(!info.arch.is_empty() && info.arch != UNKNOWN);
        // `available_parallelism` is >= 1 on any real host.
        assert!(info.cpu_logical_cores >= 1);
        // OS-specific fields await a per-OS collector.
        assert_eq!(info.os_version, UNKNOWN);
        assert_eq!(info.cpu_model, UNKNOWN);
    }

    #[test]
    fn round_trips_through_json() {
        let info = SystemInfo {
            os: "windows".into(),
            os_version: "Windows 11 Pro 23H2 (build 22631)".into(),
            arch: "AMD64".into(),
            cpu_model: "Intel(R) Core(TM) i7".into(),
            cpu_logical_cores: 12,
            total_ram_bytes: 34_359_738_368,
        };
        let json = serde_json::to_string(&info).expect("serialize");
        let back: SystemInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(info, back);
    }
}
