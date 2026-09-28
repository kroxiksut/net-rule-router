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
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use nrr_platform_api::app_group_discovery::{
    classify_app, guest_network_bypasses_process, merge_discovered, AppDiscoverySource,
    AppGroupDiscoveryPort, AppGroupKind, DiscoveredApp,
};

/// `comm` is at most 16 bytes; anything longer is not a `comm` file.
const MAX_COMM_BYTES: u64 = 256;
/// A hypervisor's command line with every device spelled out; larger is not one.
const MAX_CMDLINE_BYTES: u64 = 256 * 1024;
/// Desktop entries are a few KiB; a larger file is not one worth parsing.
const MAX_DESKTOP_ENTRY_BYTES: u64 = 64 * 1024;
/// Guards against a pathological directory (or `/proc`) listing.
const MAX_ENTRIES_PER_DIR: usize = 65_536;

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

/// Launchers whose path in `Exec=` is not the application's own executable.
/// Keeping them out of `exe_path` matters: the merge dedups by path, so every
/// Flatpak app would otherwise collapse into one row.
const EXEC_WRAPPERS: &[&str] = &["env", "flatpak", "sh", "bash", "snap"];

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
        let mut application_dirs: Vec<PathBuf> = [
            "/usr/share/applications",
            "/usr/local/share/applications",
            "/var/lib/flatpak/exports/share/applications",
            "/var/lib/snapd/desktop/applications",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        if let Some(data_home) = user_data_home() {
            application_dirs.push(data_home.join("applications"));
            application_dirs.push(data_home.join("flatpak/exports/share/applications"));
        }
        Self::with_roots(
            PathBuf::from("/proc"),
            PathBuf::from("/sys/class/net"),
            application_dirs,
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
            out.extend(desktop_entries_in(dir));
        }
        merge_discovered(out)
    }
}

/// `$XDG_DATA_HOME` when absolute (the spec ignores a relative one), else
/// `~/.local/share`.
fn user_data_home() -> Option<PathBuf> {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .map(|home| home.join(".local/share"))
        })
}

// ── Source 1: running processes ───────────────────────────────────────────────

struct ProcessSeen {
    dir: PathBuf,
    exe: Option<PathBuf>,
    comm: Option<String>,
}

impl ProcessSeen {
    fn exe_basename(&self) -> Option<&str> {
        self.exe
            .as_deref()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
    }

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
}

impl ProcessSeen {
    /// Read only for hypervisors: the arguments are NUL-separated.
    fn guest_on_a_bridge(&self) -> bool {
        read_capped(&self.dir.join("cmdline"), MAX_CMDLINE_BYTES)
            .is_some_and(|text| guest_network_bypasses_process(text.split('\0')))
    }
}

fn running_processes(proc_root: &Path) -> Vec<ProcessSeen> {
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return Vec::new();
    };
    entries
        .flatten()
        .take(MAX_ENTRIES_PER_DIR)
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
        .filter_map(|entry| {
            let dir = entry.path();
            let exe = std::fs::read_link(dir.join("exe")).ok().map(|target| {
                // A replaced binary reads as `/path/app (deleted)`.
                let text = target.to_string_lossy();
                match text.strip_suffix(" (deleted)") {
                    Some(live) => PathBuf::from(live),
                    None => target,
                }
            });
            let comm = read_capped(&dir.join("comm"), MAX_COMM_BYTES)
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty());
            (exe.is_some() || comm.is_some()).then_some(ProcessSeen { dir, exe, comm })
        })
        .collect()
}

// ── Source 2: desktop entries ─────────────────────────────────────────────────

/// The entries in `dir` and in its direct subdirectories: XDG allows vendor
/// folders (`kde4/`, `wine/`). One level only, which also rules out a loop.
fn desktop_entries_in(dir: &Path) -> Vec<DiscoveredApp> {
    let mut out = Vec::new();
    for subdir in desktop_entries_one_level(dir, &mut out) {
        desktop_entries_one_level(&subdir, &mut out);
    }
    out
}

/// Classify the entries directly in `dir` into `out`; returns its subdirectories.
fn desktop_entries_one_level(dir: &Path, out: &mut Vec<DiscoveredApp>) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut subdirs = Vec::new();
    for entry in entries.flatten().take(MAX_ENTRIES_PER_DIR) {
        let path = entry.path();
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            subdirs.push(path);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("desktop") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Some(app) = read_capped(&path, MAX_DESKTOP_ENTRY_BYTES)
            .and_then(|text| desktop_entry_app(stem, &text))
        {
            out.push(app);
        }
    }
    subdirs
}

/// Classify one desktop entry. `stem` is its file name without `.desktop`.
fn desktop_entry_app(stem: &str, text: &str) -> Option<DiscoveredApp> {
    let entry = parse_desktop_entry(text)?;
    if entry.hidden || entry.kind.as_deref().is_some_and(|k| k != "Application") {
        return None;
    }
    let program = entry.exec.as_deref().and_then(exec_program);
    let program_name = program
        .as_deref()
        .and_then(|p| Path::new(p).file_name())
        .and_then(|n| n.to_str());
    let kind = [entry.name.as_deref(), program_name, Some(stem)]
        .into_iter()
        .flatten()
        .find_map(classify_app)?;
    let display_name = entry
        .name
        .or_else(|| program_name.map(str::to_string))
        .unwrap_or_else(|| stem.to_string());
    // Only a path that names the app itself: a wrapper's path would merge
    // unrelated apps, and a relative one is resolved through `$PATH` at launch.
    // `Exec=` is a Unix path whatever the host, so no `Path::is_absolute`.
    let exe_path = program.filter(|p| {
        let path = Path::new(p);
        p.starts_with('/')
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| !EXEC_WRAPPERS.contains(&n))
    });
    Some(DiscoveredApp {
        kind,
        display_name,
        exe_path,
        running: false,
        source: AppDiscoverySource::InstalledProgram,
    })
}

#[derive(Default)]
struct DesktopEntry {
    name: Option<String>,
    exec: Option<String>,
    kind: Option<String>,
    hidden: bool,
}

/// The unlocalized keys of the `[Desktop Entry]` group; other groups (actions)
/// and localized `Name[xx]=` keys are ignored.
fn parse_desktop_entry(text: &str) -> Option<DesktopEntry> {
    let mut entry = DesktopEntry::default();
    let mut in_main_group = false;
    let mut seen_main_group = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_main_group = line == "[Desktop Entry]";
            seen_main_group |= in_main_group;
            continue;
        }
        if !in_main_group {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "Name" if !value.is_empty() => entry.name = Some(value.to_string()),
            "Exec" if !value.is_empty() => entry.exec = Some(value.to_string()),
            "Type" => entry.kind = Some(value.to_string()),
            "Hidden" => entry.hidden = value == "true",
            _ => {}
        }
    }
    seen_main_group.then_some(entry)
}

/// The program an `Exec=` line runs: the first token after an optional
/// `env VAR=value …` prefix, with the spec's double-quote escaping undone.
fn exec_program(exec: &str) -> Option<String> {
    let mut tokens = exec_tokens(exec).into_iter().peekable();
    if tokens
        .peek()
        .is_some_and(|t| Path::new(t).file_name().and_then(|n| n.to_str()) == Some("env"))
    {
        tokens.next();
        while tokens
            .peek()
            .is_some_and(|t| t.contains('=') || t.starts_with('-'))
        {
            tokens.next();
        }
    }
    tokens.next().filter(|t| !t.is_empty())
}

fn exec_tokens(exec: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = exec.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => in_quotes = !in_quotes,
            '\\' if in_quotes => {
                if let Some(escaped) = chars.next() {
                    current.push(escaped);
                }
            }
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// The whole file as text, or `None` when unreadable or larger than `cap`.
fn read_capped(path: &Path, cap: u64) -> Option<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(cap + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= cap).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn exec_program_undoes_quoting_and_skips_env() {
        assert_eq!(
            exec_program(r#""/opt/My App/bin/app" --x"#).as_deref(),
            Some("/opt/My App/bin/app")
        );
        assert_eq!(
            exec_program("env LANG=C GDK_BACKEND=x11 qbittorrent %U").as_deref(),
            Some("qbittorrent")
        );
        assert_eq!(
            exec_program(r#""/opt/a\"b/app""#).as_deref(),
            Some("/opt/a\"b/app")
        );
        assert_eq!(exec_program("   "), None);
    }

    #[test]
    fn an_oversized_comm_is_not_read() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("comm");
        write(&path, &"x".repeat(MAX_COMM_BYTES as usize + 1));
        assert!(read_capped(&path, MAX_COMM_BYTES).is_none());
    }

    #[test]
    fn the_live_machine_is_scanned_without_panicking() {
        for app in LinuxAppGroupDiscovery::new().discover_app_groups() {
            assert!(!app.display_name.trim().is_empty());
        }
    }
}
