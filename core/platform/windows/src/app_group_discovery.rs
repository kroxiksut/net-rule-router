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
//! nothing".

#![cfg(target_os = "windows")]

use nrr_platform_api::app_group_discovery::{
    classify_app, merge_discovered, AppDiscoverySource, AppGroupDiscoveryPort, AppGroupKind,
    DiscoveredApp,
};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

use crate::win32_ffi::{process, registry};

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

/// By image name alone: the arguments that tell a bridged QEMU guest apart are
/// not read here (see `AppGroupDiscoveryPort`).
fn discover_from_processes() -> Vec<DiscoveredApp> {
    let mut out = Vec::new();
    for pid in process::enum_process_ids() {
        let Some(path) = process::process_image_path(pid) else {
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

// ── Source 2: installed programs (Uninstall registry) ─────────────────────────

fn discover_from_installed_programs() -> Vec<DiscoveredApp> {
    let mut out = Vec::new();
    for program in registry::installed_programs() {
        let Some(display_name) = program.display_name() else {
            continue;
        };
        let Some(kind) = classify_app(&display_name) else {
            continue;
        };
        out.push(DiscoveredApp {
            kind,
            display_name,
            exe_path: program.exe_path(),
            running: false,
            source: AppDiscoverySource::InstalledProgram,
        });
    }
    out
}

// ── Source 3: kernel-NAT service features ─────────────────────────────────────

fn discover_kernel_nat_features() -> Vec<DiscoveredApp> {
    let mut out = Vec::new();
    for (subkey, display_name) in KERNEL_NAT_SERVICES {
        // The service key existing is the "installed" signal.
        if registry::key_exists(HKEY_LOCAL_MACHINE, subkey) {
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

#[cfg(test)]
mod tests {
    use super::*;

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
