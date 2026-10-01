//! Windows VPN-client discovery mechanism.
//!
//! Implements [`nrr_platform_api::VpnDiscoveryPort`] by unioning two
//! non-privileged OS sources and matching each against the neutral
//! [`nrr_platform_api::looks_like_vpn`] keyword policy:
//!
//! 1. **Running processes** — every process image basename (via
//!    `EnumProcesses` + `QueryFullProcessImageNameW`), so an active VPN client
//!    surfaces with `running = true` and its real exe path.
//! 2. **Installed programs** — the `Uninstall` registry keys (HKLM + the
//!    32-bit `WOW6432Node` view + HKCU), matched on `DisplayName`, with a
//!    best-effort exe path from `DisplayIcon` / `InstallLocation`.
//!
//! Neither source needs elevation, so this runs in the (non-elevated) GUI /
//! launcher during onboarding, before the background service is even
//! installed. Every OS failure degrades to "this source contributed nothing".

#![cfg(target_os = "windows")]

use crate::win32_ffi::{process, registry};
use nrr_platform_api::vpn_discovery::{
    looks_like_vpn, merge_candidates, VpnCandidate, VpnCandidateSource, VpnDiscoveryPort,
};

/// Windows [`VpnDiscoveryPort`]: running processes + installed programs.
#[derive(Debug, Default)]
pub struct WindowsVpnDiscovery;

impl WindowsVpnDiscovery {
    pub const fn new() -> Self {
        Self
    }
}

impl VpnDiscoveryPort for WindowsVpnDiscovery {
    fn discover_vpn_candidates(&self) -> Vec<VpnCandidate> {
        let mut out = discover_from_processes();
        out.extend(discover_from_installed_programs());
        merge_candidates(out)
    }
}

// ── Source 1: running processes ───────────────────────────────────────────────

fn discover_from_processes() -> Vec<VpnCandidate> {
    let mut out = Vec::new();
    for pid in process::enum_process_ids() {
        let Some(path) = process::process_image_path(pid) else {
            continue;
        };
        let basename = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !basename.is_empty() && looks_like_vpn(&basename) {
            out.push(VpnCandidate {
                display_name: basename,
                exe_path: Some(path.to_string_lossy().into_owned()),
                running: true,
                source: VpnCandidateSource::RunningProcess,
            });
        }
    }
    out
}

// ── Source 2: installed programs (Uninstall registry) ─────────────────────────

fn discover_from_installed_programs() -> Vec<VpnCandidate> {
    let mut out = Vec::new();
    for program in registry::installed_programs() {
        let Some(display_name) = program.display_name() else {
            continue;
        };
        if !looks_like_vpn(&display_name) {
            continue;
        }
        out.push(VpnCandidate {
            display_name,
            exe_path: program.exe_path(),
            running: false,
            source: VpnCandidateSource::InstalledProgram,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_is_constructible_and_runs_without_panicking() {
        // Smoke test: enumerates the live machine (result content is
        // environment-dependent; we only assert it does not panic and returns
        // a well-formed list). The Win32 calls are exercised here.
        let found = WindowsVpnDiscovery::new().discover_vpn_candidates();
        for c in &found {
            assert!(!c.display_name.trim().is_empty());
        }
    }
}
