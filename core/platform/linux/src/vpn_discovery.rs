//! Linux VPN-client discovery (SEAM + design; stub).
//!
//! Implements [`nrr_platform_api::VpnDiscoveryPort`] so the neutral onboarding
//! flow has a Linux backend to name. The mechanism is DESIGNED here but returns
//! an empty list until it is built and can be verified on real Linux — an
//! honest stub, matching how the other Linux stub ports landed (no hardware to
//! verify against in this environment yet).
//!
//! ## Planned mechanism (all non-elevated, unioned then `merge_candidates`)
//!
//! 1. **Running processes** — read `/proc/<pid>/exe` (a symlink to the running
//!    binary) and/or `/proc/<pid>/comm` for every numeric `/proc` entry, match
//!    the basename against [`nrr_platform_api::looks_like_vpn`]. No subprocess,
//!    no privilege (own-user processes always readable; others best-effort).
//!
//! 2. **Installed applications — desktop entries** (distro-agnostic): scan
//!    `.desktop` files in the XDG dirs
//!    (`/usr/share/applications`, `/usr/local/share/applications`,
//!    `~/.local/share/applications`, plus Flatpak
//!    `/var/lib/flatpak/exports/share/applications` and Snap
//!    `/var/lib/snapd/desktop/applications`), match `Name=` / `Exec=`,
//!    take the exe from `Exec=`. This is the portable path — it needs no
//!    package manager and covers Flatpak/Snap/AppImage-with-.desktop.
//!
//! 3. **Installed packages — native package DB** (distro-SPECIFIC, refinement
//!    on top of #2 for CLI-only clients with no `.desktop`): query the local
//!    package database by family, detected from which tool exists on `PATH`:
//!    - deb (Debian/Ubuntu/Mint): `dpkg-query -W -f='${Package}\n'`
//!    - rpm (Fedora/RHEL/openSUSE): `rpm -qa --qf '%{NAME}\n'`
//!    - arch: `pacman -Qq`
//!    - alpine: `apk info`
//!    Match the package name against the keyword policy. The higher-level
//!    `apt`/`dnf`/`yum`/`zypper` front-ends are NOT used for QUERYING — the
//!    low-level DB tools above are faster, non-interactive, and network-free.
//!    Each is a bounded read-only subprocess; absence of the tool = that
//!    source contributes nothing (never an error).
//!
//! Package-name → exe resolution for #3 (when needed) goes through the same
//! `.desktop`/`$PATH` lookup as #2, so a matched package still yields a real
//! executable path where one exists.

use nrr_platform_api::vpn_discovery::{VpnCandidate, VpnDiscoveryPort};

/// Linux [`VpnDiscoveryPort`]. Returns an empty list until the mechanism above
/// is implemented and verifiable on real Linux.
#[derive(Debug, Default)]
pub struct LinuxVpnDiscovery;

impl LinuxVpnDiscovery {
    pub const fn new() -> Self {
        Self
    }
}

impl VpnDiscoveryPort for LinuxVpnDiscovery {
    fn discover_vpn_candidates(&self) -> Vec<VpnCandidate> {
        // TODO: implement the /proc + .desktop + package-DB sources
        // documented above once a Linux target is available to verify against.
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_is_constructible_and_empty() {
        assert!(LinuxVpnDiscovery::new()
            .discover_vpn_candidates()
            .is_empty());
    }
}
