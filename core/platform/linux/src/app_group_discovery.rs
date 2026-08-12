//! Linux application-group discovery (SEAM + design; stub).
//!
//! Implements [`nrr_platform_api::AppGroupDiscoveryPort`] so the neutral
//! onboarding flow has a Linux backend to name. The mechanism is DESIGNED here
//! but returns an empty list until it is built and verifiable on real Linux —
//! an honest stub, matching [`crate::vpn_discovery`] and the other Linux stub ports.
//!
//! ## Planned mechanism (all non-elevated, unioned then `merge_discovered`)
//!
//! 1. **Running processes** — read `/proc/<pid>/comm` (or the `/proc/<pid>/exe`
//!    symlink basename) for every numeric `/proc` entry and pass it through the
//!    neutral [`nrr_platform_api::classify_app`] dictionary. Own-user processes
//!    are always readable; others are best-effort. Note the dictionary keywords
//!    are extension-free, so `qbittorrent`, `transmission-daemon`,
//!    `VBoxHeadless`, `qemu-system-x86_64`, `syncthing`, `bitcoind` all match
//!    the same entries the Windows names do.
//!
//! 2. **Installed applications — desktop entries** (distro-agnostic): scan
//!    `.desktop` files in the XDG dirs (`/usr/share/applications`,
//!    `~/.local/share/applications`, Flatpak `/var/lib/flatpak/exports/...`,
//!    Snap `/var/lib/snapd/desktop/applications`), classify `Name=` / `Exec=`,
//!    take the exe from `Exec=`.
//!
//! 3. **Kernel-NAT equivalents** — the Linux analog of WSL/Hyper-V/Docker is
//!    libvirt/KVM (`virbr0` bridge, `libvirtd`) and Docker/Podman (`docker0`
//!    bridge, `dockerd`/`containerd`). Detect via the bridge interfaces
//!    (`/sys/class/net/virbr0`, `/sys/class/net/docker0`) or the daemon
//!    processes, surfaced as [`nrr_platform_api::AppDiscoverySource::SystemFeature`]
//!    with [`nrr_platform_api::AppGroupKind::KernelVirtualNet`]. Whether a
//!    Linux container's traffic is route-assignable differs from Windows and is
//!    decided when this is built against real hardware.
//!
//! Package-name → exe resolution (when a CLI-only client has no `.desktop`)
//! reuses the same `$PATH`/`.desktop` lookup as #2.

use nrr_platform_api::app_group_discovery::{AppGroupDiscoveryPort, DiscoveredApp};

/// Linux [`AppGroupDiscoveryPort`]. Returns an empty list until the mechanism
/// above is implemented and verifiable on real Linux.
#[derive(Debug, Default)]
pub struct LinuxAppGroupDiscovery;

impl LinuxAppGroupDiscovery {
    pub const fn new() -> Self {
        Self
    }
}

impl AppGroupDiscoveryPort for LinuxAppGroupDiscovery {
    fn discover_app_groups(&self) -> Vec<DiscoveredApp> {
        // TODO: implement the /proc + .desktop + bridge/daemon sources
        // documented above once a Linux target is available to verify against.
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_is_constructible_and_empty() {
        assert!(LinuxAppGroupDiscovery::new()
            .discover_app_groups()
            .is_empty());
    }
}
