//! Linux application-group discovery.
//!
//! Implements [`nrr_platform_api::AppGroupDiscoveryPort`] by unioning three
//! non-privileged sources and classifying each string through the neutral
//! [`nrr_platform_api::classify_app`] dictionary:
//!
//! 1. **Running processes** — every numeric `/proc` entry, named by the
//!    `/proc/<pid>/exe` basename when readable (own-user processes) and by
//!    `/proc/<pid>/comm` otherwise.
//! 2. **Installed applications** — XDG `.desktop` entries (system, per-user,
//!    Flatpak and Snap exports), classified on `Name=`, the `Exec=` program and
//!    the entry's file stem (a Flatpak app id carries the app's name).
//! 3. **Kernel-NAT stacks** — libvirt and Docker/Podman, detected by their
//!    bridge in `/sys/class/net` or their daemon process, surfaced as
//!    [`AppDiscoverySource::SystemFeature`].
//!
//! Every read is bounded and every failure means "this source contributed
//! nothing"; the roots are injectable so the parsing is tested on temp dirs.

use std::collections::HashSet;
use std::path::PathBuf;

use nrr_platform_api::app_group_discovery::{
    classify_app, guest_network_bypasses_process, merge_discovered, AppDiscoverySource,
    AppGroupDiscoveryPort, AppGroupKind, DiscoveredApp,
};

use crate::app_scan::{
    application_dirs, desktop_apps_in, read_capped, running_processes, DesktopApp, ProcessSeen,
};

/// A hypervisor's command line with every device spelled out; larger is not one.
const MAX_CMDLINE_BYTES: u64 = 256 * 1024;

/// A kernel-NAT stack: its display label (the GUI wraps it with `tr()`), the
/// bridges it creates, and the daemons that run it.
struct KernelNatStack {
    display_name: &'static str,
    bridges: &'static [&'static str],
    daemons: &'static [&'static str],
}

const KERNEL_NAT_STACKS: &[KernelNatStack] = &[
    KernelNatStack {
        display_name: "libvirt",
        bridges: &["virbr0"],
        daemons: &["libvirtd", "virtqemud", "virtnetworkd"],
    },
    KernelNatStack {
        display_name: "Docker",
        bridges: &["docker0"],
        daemons: &["dockerd"],
    },
    KernelNatStack {
        display_name: "Podman",
        bridges: &["podman0", "cni-podman0"],
        daemons: &[],
    },
];

/// Linux [`AppGroupDiscoveryPort`]: running processes + desktop entries +
/// kernel-NAT stacks.
#[derive(Debug, Clone)]
pub struct LinuxAppGroupDiscovery {
    proc_root: PathBuf,
    sys_class_net: PathBuf,
    application_dirs: Vec<PathBuf>,
}

impl Default for LinuxAppGroupDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxAppGroupDiscovery {
    /// The real system locations, plus this user's own data directories.
    #[must_use]
    pub fn new() -> Self {
        Self::with_roots(
            PathBuf::from("/proc"),
            PathBuf::from("/sys/class/net"),
            application_dirs(),
        )
    }

    #[must_use]
    pub fn with_roots(
        proc_root: PathBuf,
        sys_class_net: PathBuf,
        application_dirs: Vec<PathBuf>,
    ) -> Self {
        Self {
            proc_root,
            sys_class_net,
            application_dirs,
        }
    }
}

impl AppGroupDiscoveryPort for LinuxAppGroupDiscovery {
    fn discover_app_groups(&self) -> Vec<DiscoveredApp> {
        let processes = running_processes(&self.proc_root);
        let running_names: HashSet<String> = processes
            .iter()
            .flat_map(|p| [p.comm.as_deref(), p.exe_basename()])
            .flatten()
            .map(str::to_ascii_lowercase)
            .collect();

        let mut out = Vec::new();
        let mut folded_daemons: HashSet<&str> = HashSet::new();
        for stack in KERNEL_NAT_STACKS {
            let daemon_running = stack.daemons.iter().any(|d| running_names.contains(*d));
            let bridge_seen = stack
                .bridges
                .iter()
                .any(|b| self.sys_class_net.join(b).exists());
            if daemon_running || bridge_seen {
                folded_daemons.extend(stack.daemons.iter().copied());
                out.push(DiscoveredApp {
                    kind: AppGroupKind::KernelVirtualNet,
                    display_name: stack.display_name.to_string(),
                    exe_path: None,
                    running: daemon_running,
                    source: AppDiscoverySource::SystemFeature,
                });
            }
        }

        // A stack's daemon is already its feature row; listing it again as a
        // process would show one stack twice.
        out.extend(
            processes
                .iter()
                .filter_map(ProcessSeen::classify)
                .filter(|app| {
                    !folded_daemons.contains(app.display_name.to_ascii_lowercase().as_str())
                }),
        );
        for dir in &self.application_dirs {
            out.extend(desktop_apps_in(dir).iter().filter_map(classify_desktop_app));
        }
        merge_discovered(out)
    }
}

// ── Source 1: running processes ───────────────────────────────────────────────

impl ProcessSeen {
    fn classify(&self) -> Option<DiscoveredApp> {
        // `comm` is truncated to 15 bytes, so the full exe name wins when known.
        let (name, kind) = [self.exe_basename(), self.comm.as_deref()]
            .into_iter()
            .flatten()
            .find_map(|name| classify_app(name).map(|kind| (name, kind)))?;
        let kind = if kind == AppGroupKind::Hypervisor && self.guest_on_a_bridge() {
            AppGroupKind::KernelVirtualNet
        } else {
            kind
        };
        Some(DiscoveredApp {
            kind,
            display_name: name.to_string(),
            exe_path: self.exe.as_ref().map(|p| p.to_string_lossy().into_owned()),
            running: true,
            source: AppDiscoverySource::RunningProcess,
        })
    }

    /// Read only for hypervisors: the arguments are NUL-separated.
    fn guest_on_a_bridge(&self) -> bool {
        read_capped(&self.dir.join("cmdline"), MAX_CMDLINE_BYTES)
            .is_some_and(|text| guest_network_bypasses_process(text.split('\0')))
    }
}

// ── Source 2: desktop entries ─────────────────────────────────────────────────

fn classify_desktop_app(app: &DesktopApp) -> Option<DiscoveredApp> {
    let kind = app.labels().find_map(classify_app)?;
    Some(DiscoveredApp {
        kind,
        display_name: app.display_name(),
        exe_path: app.own_exe_path().map(str::to_string),
        running: false,
        source: AppDiscoverySource::InstalledProgram,
    })
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::Path;

    use super::*;
    use crate::app_scan::MAX_DESKTOP_ENTRY_BYTES;

    fn write(path: &Path, text: &str) {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).expect("dir");
        }
        std::fs::write(path, text).expect("write");
    }

    struct Fixture {
        _root: tempfile::TempDir,
        proc_root: PathBuf,
        net: PathBuf,
        apps: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("root");
            let proc_root = root.path().join("proc");
            let net = root.path().join("net");
            let apps = root.path().join("applications");
            for dir in [&proc_root, &net, &apps] {
                std::fs::create_dir_all(dir).expect("dir");
            }
            Self {
                _root: root,
                proc_root,
                net,
                apps,
            }
        }

        fn process(&self, pid: u32, comm: &str) {
            write(&self.proc_root.join(pid.to_string()).join("comm"), comm);
        }

        fn discovery(&self) -> LinuxAppGroupDiscovery {
            LinuxAppGroupDiscovery::with_roots(
                self.proc_root.clone(),
                self.net.clone(),
                vec![self.apps.clone(), self.apps.join("missing")],
            )
        }
    }

    #[test]
    fn running_processes_are_classified_by_comm() {
        let fx = Fixture::new();
        fx.process(101, "qbittorrent\n");
        fx.process(102, "bash\n");
        fx.process(103, "qemu-system-x86\n");
        write(&fx.proc_root.join("self").join("comm"), "qbittorrent\n");
        write(&fx.proc_root.join("uptime"), "1.0 1.0\n");

        let found = fx.discovery().discover_app_groups();
        let rows: Vec<(&str, AppGroupKind, bool)> = found
            .iter()
            .map(|a| (a.display_name.as_str(), a.kind, a.running))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("qemu-system-x86", AppGroupKind::Hypervisor, true),
                ("qbittorrent", AppGroupKind::BitTorrent, true),
            ],
            "non-numeric /proc entries are not processes"
        );
        assert!(found
            .iter()
            .all(|a| a.source == AppDiscoverySource::RunningProcess && a.exe_path.is_none()));
    }

    /// libvirt's system machines hang on `virbr0`; their qemu carries none of
    /// the guest's traffic, so its row must not offer a route.
    #[test]
    fn a_qemu_on_a_tap_device_is_not_route_assignable() {
        let fx = Fixture::new();
        fx.process(301, "qemu-system-x86\n");
        write(
            &fx.proc_root.join("301").join("cmdline"),
            "qemu-system-x86_64\0-netdev\0{\"type\":\"tap\",\"fd\":\"30\"}\0",
        );
        fx.process(302, "qemu-system-x86\n");
        write(
            &fx.proc_root.join("302").join("cmdline"),
            "qemu-system-x86_64\0-netdev\0user,id=n0\0",
        );
        let kinds: Vec<AppGroupKind> = fx
            .discovery()
            .discover_app_groups()
            .iter()
            .map(|a| a.kind)
            .collect();
        assert!(kinds.contains(&AppGroupKind::KernelVirtualNet), "{kinds:?}");
        assert!(kinds.contains(&AppGroupKind::Hypervisor), "{kinds:?}");
    }

    #[test]
    fn processes_with_the_same_name_collapse() {
        let fx = Fixture::new();
        fx.process(201, "syncthing\n");
        fx.process(202, "syncthing\n");
        assert_eq!(fx.discovery().discover_app_groups().len(), 1);
    }

    #[test]
    fn desktop_entries_classify_by_name_exec_or_file_stem() {
        let fx = Fixture::new();
        write(
            &fx.apps.join("transmission-gtk.desktop"),
            "[Desktop Entry]\nType=Application\nName=Transmission\nName[xx]=Other\nExec=transmission-gtk %U\n",
        );
        write(
            &fx.apps.join("node.desktop"),
            "[Desktop Entry]\nType=Application\nName=Full Node\nExec=\"/opt/node/bin/bitcoind\" -daemon\n",
        );
        write(
            &fx.apps.join("org.example.RetroArch.desktop"),
            "[Desktop Entry]\nType=Application\nName=Game Launcher\nExec=/usr/bin/flatpak run org.example.RetroArch\n",
        );
        write(
            &fx.apps.join("editor.desktop"),
            "[Desktop Entry]\nType=Application\nName=Text Editor\nExec=/usr/bin/editor\n",
        );

        let found = fx.discovery().discover_app_groups();
        let rows: Vec<(&str, AppGroupKind, Option<&str>)> = found
            .iter()
            .map(|a| (a.display_name.as_str(), a.kind, a.exe_path.as_deref()))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("Game Launcher", AppGroupKind::ConsoleEmulator, None),
                ("Transmission", AppGroupKind::BitTorrent, None),
                (
                    "Full Node",
                    AppGroupKind::CryptoNode,
                    Some("/opt/node/bin/bitcoind")
                ),
            ]
        );
        assert!(found
            .iter()
            .all(|a| a.source == AppDiscoverySource::InstalledProgram && !a.running));
    }

    #[test]
    fn entries_in_a_vendor_subfolder_are_found_but_not_deeper() {
        let fx = Fixture::new();
        write(
            &fx.apps.join("kde4").join("qbittorrent.desktop"),
            "[Desktop Entry]\nType=Application\nName=qBittorrent\nExec=qbittorrent %U\n",
        );
        write(
            &fx.apps
                .join("wine")
                .join("deep")
                .join("transmission.desktop"),
            "[Desktop Entry]\nType=Application\nName=Transmission\nExec=transmission-gtk\n",
        );
        let names: Vec<String> = fx
            .discovery()
            .discover_app_groups()
            .into_iter()
            .map(|a| a.display_name)
            .collect();
        assert_eq!(names, vec!["qBittorrent".to_string()]);
    }

    #[test]
    fn hidden_non_application_and_oversized_entries_are_skipped() {
        let fx = Fixture::new();
        write(
            &fx.apps.join("a.desktop"),
            "[Desktop Entry]\nType=Application\nName=qBittorrent\nHidden=true\n",
        );
        write(
            &fx.apps.join("b.desktop"),
            "[Desktop Entry]\nType=Link\nName=qBittorrent\n",
        );
        write(
            &fx.apps.join("c.desktop"),
            "[Desktop Action New]\nName=qBittorrent\n",
        );
        write(
            &fx.apps.join("d.txt"),
            "[Desktop Entry]\nName=qBittorrent\n",
        );
        let big = fx.apps.join("e.desktop");
        let file = File::create(&big).expect("create");
        file.set_len(MAX_DESKTOP_ENTRY_BYTES + 1).expect("grow");
        assert!(fx.discovery().discover_app_groups().is_empty());
    }

    #[test]
    fn kernel_nat_stacks_are_features_and_absorb_their_daemons() {
        let fx = Fixture::new();
        std::fs::create_dir_all(fx.net.join("virbr0")).expect("bridge");
        fx.process(301, "dockerd\n");

        let found = fx.discovery().discover_app_groups();
        let rows: Vec<(&str, bool)> = found
            .iter()
            .map(|a| (a.display_name.as_str(), a.running))
            .collect();
        assert_eq!(rows, vec![("Docker", true), ("libvirt", false)]);
        assert!(found
            .iter()
            .all(|a| a.kind == AppGroupKind::KernelVirtualNet
                && a.source == AppDiscoverySource::SystemFeature));
    }

    #[test]
    fn missing_roots_find_nothing() {
        let fx = Fixture::new();
        let gone = fx.proc_root.join("nowhere");
        let discovery = LinuxAppGroupDiscovery::with_roots(gone.clone(), gone.clone(), vec![gone]);
        assert!(discovery.discover_app_groups().is_empty());
    }

    #[test]
    fn the_live_machine_is_scanned_without_panicking() {
        for app in LinuxAppGroupDiscovery::new().discover_app_groups() {
            assert!(!app.display_name.trim().is_empty());
        }
    }
}
