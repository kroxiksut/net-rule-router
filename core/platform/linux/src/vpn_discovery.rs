//! Linux VPN-client discovery.
//!
//! Implements [`VpnDiscoveryPort`] by unioning five unprivileged sources and
//! handing them to [`merge_candidates`]:
//!
//! 1. **Running processes** — every numeric `/proc` entry, named by the `exe`
//!    basename (own-user processes) or `comm`, matched through [`looks_like_vpn`].
//! 2. **Desktop entries** — XDG `.desktop` files (system, per-user, Flatpak,
//!    Snap), matched on `Name=`, the `Exec=` program and the file stem.
//! 3. **The native package DB** — `dpkg-query`, `rpm`, `pacman` or `apk`,
//!    whichever is installed: the low-level tools, not the `apt`/`dnf` front
//!    ends, so the query is offline and non-interactive. Covers command-line
//!    clients that ship no desktop entry.
//! 4. **systemd tunnel units** — enabled or active `openvpn*@` instances.
//! 5. **NetworkManager** VPN connections.
//!
//! A kernel WireGuard/AmneziaWG tunnel has no program: the kernel sends its
//! handshake, so no application rule can carry it. It is offered as one
//! [`VpnCandidateSource::KernelTunnel`] row per link, found by the link's own
//! `DEVTYPE` and never by its name; a `wg-quick@`/`awg-quick@` unit or a
//! NetworkManager WireGuard connection only labels it, or reports it down when
//! its link is absent. The `wg`/`awg` tool packages contribute no row.
//!
//! An executable is looked up only in the fixed system bin dirs, never through
//! the inherited `PATH`, and canonicalised, so one binary seen by several
//! sources (a running `openvpn`, its package, its unit) merges into one row.
//! Every read and helper call is bounded and any failure means "this source
//! contributed nothing"; the roots and the helper runner are injectable so the
//! whole flow is tested on temp dirs and literal command output.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nrr_platform_api::vpn_discovery::{
    looks_like_vpn, merge_candidates, VpnCandidate, VpnCandidateSource, VpnDiscoveryPort,
};

use crate::app_scan::{
    application_dirs, desktop_apps_in, running_processes, DesktopApp, ProcessSeen,
};
use crate::command::{self, is_executable_file, DEFAULT_COMMAND_TIMEOUT};
use crate::interface_traffic::read_sysfs_facts;

/// Where a package's executable is looked for, in this order.
const BIN_DIRS: [&str; 5] = ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/bin", "/sbin"];

/// `DEVTYPE` of a link whose tunnel the kernel runs.
const KERNEL_TUNNEL_DEVTYPES: &[&str] = &["wireguard", "amneziawg"];

/// Packages that only configure a kernel tunnel; the tunnel is offered as its
/// link instead. The userspace `*-go` implementations are programs and stay.
const KERNEL_TUNNEL_PACKAGES: &[&str] = &[
    "wireguard",
    "wireguard-tools",
    "amneziawg",
    "amneziawg-tools",
];

/// Links read from sysfs; a host has a handful.
const MAX_LINKS: usize = 4096;

/// `rpm -qa` reads the whole database, which takes seconds on a large install.
const PACKAGE_QUERY_TIMEOUT: Duration = Duration::from_secs(15);

/// Lines read from one helper's answer.
const MAX_OUTPUT_LINES: usize = 200_000;

/// Runs a system helper by bare name; `Some(stdout)` only when it exists, ran
/// and succeeded.
pub type HelperRunner = fn(tool: &str, args: &[&str], timeout: Duration) -> Option<String>;

fn run_system_helper(tool: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let out = command::output_with_timeout(tool, args, timeout).ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

struct PackageQuery {
    tool: &'static str,
    args: &'static [&'static str],
    parse: fn(&str) -> Vec<String>,
}

/// Each family's DB tool; an absent tool contributes nothing, so a machine
/// carrying a second family's tool (`rpm` on Debian) only costs one empty query.
const PACKAGE_QUERIES: &[PackageQuery] = &[
    PackageQuery {
        tool: "dpkg-query",
        // `-W` also lists removed packages whose config files remain.
        args: &["-W", "--showformat=${Status} ${Package}\\n"],
        parse: parse_dpkg_packages,
    },
    PackageQuery {
        tool: "rpm",
        args: &["-qa", "--queryformat", "%{NAME}\\n"],
        parse: parse_package_lines,
    },
    PackageQuery {
        tool: "pacman",
        args: &["-Qq"],
        parse: parse_package_lines,
    },
    PackageQuery {
        tool: "apk",
        args: &["info"],
        parse: parse_package_lines,
    },
];

/// A systemd template that brings up a tunnel, and the binary its instances
/// run. `wg-quick`/`awg-quick` have none: their instance names the kernel
/// interface they create.
struct TunnelTemplate {
    name: &'static str,
    exe: Option<&'static str>,
}

const TUNNEL_TEMPLATES: &[TunnelTemplate] = &[
    TunnelTemplate {
        name: "wg-quick",
        exe: None,
    },
    TunnelTemplate {
        name: "awg-quick",
        exe: None,
    },
    TunnelTemplate {
        name: "openvpn",
        exe: Some("openvpn"),
    },
    TunnelTemplate {
        name: "openvpn-client",
        exe: Some("openvpn"),
    },
    TunnelTemplate {
        name: "openvpn-server",
        exe: Some("openvpn"),
    },
];

/// Linux [`VpnDiscoveryPort`].
#[derive(Debug, Clone)]
pub struct LinuxVpnDiscovery {
    proc_root: PathBuf,
    sysfs_net: PathBuf,
    application_dirs: Vec<PathBuf>,
    bin_dirs: Vec<PathBuf>,
    run: HelperRunner,
}

/// One instance of a [`TUNNEL_TEMPLATES`] unit.
struct TunnelUnit {
    template: &'static TunnelTemplate,
    instance: String,
    running: bool,
}

/// One NetworkManager VPN or WireGuard connection.
#[derive(Debug, PartialEq, Eq)]
struct NmConnection {
    name: String,
    wireguard: bool,
    active: bool,
    /// The link an active connection runs over.
    device: Option<String>,
}

impl Default for LinuxVpnDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxVpnDiscovery {
    /// The real system locations and helpers.
    #[must_use]
    pub fn new() -> Self {
        Self::with_roots(
            PathBuf::from("/proc"),
            PathBuf::from("/sys/class/net"),
            application_dirs(),
            BIN_DIRS.iter().map(PathBuf::from).collect(),
            run_system_helper,
        )
    }

    #[must_use]
    pub fn with_roots(
        proc_root: PathBuf,
        sysfs_net: PathBuf,
        application_dirs: Vec<PathBuf>,
        bin_dirs: Vec<PathBuf>,
        run: HelperRunner,
    ) -> Self {
        Self {
            proc_root,
            sysfs_net,
            application_dirs,
            bin_dirs,
            run,
        }
    }
}

impl VpnDiscoveryPort for LinuxVpnDiscovery {
    fn discover_vpn_candidates(&self) -> Vec<VpnCandidate> {
        // Human names first: a merged row keeps the first one's display name.
        let mut out: Vec<VpnCandidate> = self
            .application_dirs
            .iter()
            .flat_map(|dir| desktop_apps_in(dir))
            .filter_map(|app| self.desktop_candidate(&app))
            .collect();
        out.extend(
            self.installed_packages()
                .iter()
                .filter_map(|name| self.package_candidate(name)),
        );
        let units = self.tunnel_units();
        let connections = self.network_manager_connections();
        out.extend(units.iter().filter_map(|unit| self.unit_candidate(unit)));
        out.extend(
            connections
                .iter()
                .filter(|c| !c.wireguard)
                .map(|c| VpnCandidate {
                    display_name: c.name.clone(),
                    exe_path: None,
                    running: c.active,
                    source: VpnCandidateSource::InstalledProgram,
                    interface: None,
                }),
        );
        out.extend(kernel_tunnels(
            &self.kernel_tunnel_links(),
            &units,
            &connections,
        ));
        out.extend(
            running_processes(&self.proc_root)
                .iter()
                .filter_map(|p| self.process_candidate(p)),
        );
        merge_candidates(out)
    }
}

/// Only the first byte decides: a user process always has an argv[0].
fn is_kernel_thread(process: &ProcessSeen) -> bool {
    use std::io::Read;
    let mut first = [0u8; 1];
    std::fs::File::open(process.dir.join("cmdline"))
        .and_then(|mut f| f.read(&mut first))
        .map_or(true, |read| read == 0)
}

impl LinuxVpnDiscovery {
    // ── Source 1: running processes ───────────────────────────────────────────

    fn process_candidate(&self, process: &ProcessSeen) -> Option<VpnCandidate> {
        let (name, exe_path) = match process.exe_basename().filter(|n| looks_like_vpn(n)) {
            Some(name) => (
                name,
                process
                    .exe
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned()),
            ),
            None => {
                let comm = process.comm.as_deref().filter(|c| looks_like_vpn(c))?;
                // A kernel thread has a name and no program behind it; its
                // empty command line, readable for any process, says so.
                if is_kernel_thread(process) {
                    return None;
                }
                // Another user's process names only itself, and the system
                // binary of that name is its likeliest image. A readable image
                // under another name is an interpreter: a rule on it would
                // cover every script it runs.
                let exe = match process.exe {
                    None => self.resolve_program(comm),
                    Some(_) => None,
                };
                (comm, exe)
            }
        };
        Some(VpnCandidate {
            display_name: name.to_string(),
            exe_path,
            running: true,
            source: VpnCandidateSource::RunningProcess,
            interface: None,
        })
    }

    // ── Source 2: desktop entries ─────────────────────────────────────────────

    fn desktop_candidate(&self, app: &DesktopApp) -> Option<VpnCandidate> {
        if !app.labels().any(looks_like_vpn) {
            return None;
        }
        Some(VpnCandidate {
            display_name: app.display_name(),
            exe_path: app.own_program().and_then(|p| self.resolve_program(p)),
            running: false,
            source: VpnCandidateSource::InstalledProgram,
            interface: None,
        })
    }

    // ── Source 3: native package DB ───────────────────────────────────────────

    fn installed_packages(&self) -> BTreeSet<String> {
        PACKAGE_QUERIES
            .iter()
            .filter_map(|q| {
                (self.run)(q.tool, q.args, PACKAGE_QUERY_TIMEOUT).map(|t| (q.parse)(&t))
            })
            .flatten()
            .collect()
    }

    fn package_candidate(&self, name: &str) -> Option<VpnCandidate> {
        if !looks_like_vpn(name) || is_auxiliary_package(name) || is_kernel_tunnel_tooling(name) {
            return None;
        }
        Some(VpnCandidate {
            display_name: name.to_string(),
            exe_path: self.resolve_program(name),
            running: false,
            source: VpnCandidateSource::InstalledProgram,
            interface: None,
        })
    }

    // ── Source 4: systemd tunnel units ────────────────────────────────────────

    fn tunnel_units(&self) -> Vec<TunnelUnit> {
        let patterns: Vec<String> = TUNNEL_TEMPLATES
            .iter()
            .map(|t| format!("{}@*", t.name))
            .collect();
        let query = |leading: &[&'static str]| {
            let mut args: Vec<&str> = leading.to_vec();
            args.extend(["--plain", "--no-legend", "--no-pager", "--type=service"]);
            args.extend(patterns.iter().map(String::as_str));
            (self.run)("systemctl", &args, DEFAULT_COMMAND_TIMEOUT)
        };
        let active = query(&["list-units", "--all"])
            .map(|t| parse_running_units(&t))
            .unwrap_or_default();
        let enabled = query(&["list-unit-files"])
            .map(|t| parse_enabled_unit_files(&t))
            .unwrap_or_default();
        active
            .iter()
            .map(|unit| (unit, true))
            .chain(enabled.iter().map(|unit| (unit, false)))
            .filter_map(|(unit, running)| parse_tunnel_unit(unit, running))
            .collect()
    }

    /// A program row for a unit whose template runs one; kernel tunnel units
    /// only label their link.
    fn unit_candidate(&self, unit: &TunnelUnit) -> Option<VpnCandidate> {
        let exe = unit.template.exe?;
        Some(VpnCandidate {
            display_name: format!("{} ({})", unit.instance, unit.template.name),
            exe_path: self.resolve_program(exe),
            running: unit.running,
            source: VpnCandidateSource::InstalledProgram,
            interface: None,
        })
    }

    // ── Source 5: NetworkManager connections ──────────────────────────────────

    fn network_manager_connections(&self) -> Vec<NmConnection> {
        (self.run)(
            "nmcli",
            &["-t", "-f", "NAME,TYPE,ACTIVE,DEVICE", "connection", "show"],
            DEFAULT_COMMAND_TIMEOUT,
        )
        .map(|t| parse_nm_vpn_connections(&t))
        .unwrap_or_default()
    }

    // ── Kernel tunnel links ───────────────────────────────────────────────────

    /// Links whose kernel driver runs a tunnel, whatever they are called.
    fn kernel_tunnel_links(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.sysfs_net) else {
            return Vec::new();
        };
        entries
            .flatten()
            .take(MAX_LINKS)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| {
                read_sysfs_facts(&self.sysfs_net, name)
                    .devtype
                    .is_some_and(|d| KERNEL_TUNNEL_DEVTYPES.contains(&d.as_str()))
            })
            .collect()
    }

    // ── Executable resolution ─────────────────────────────────────────────────

    /// An absolute program as given, a bare name from the system bin dirs;
    /// either canonicalised to the path its running process reports.
    fn resolve_program(&self, program: &str) -> Option<String> {
        let path = if program.starts_with('/') {
            PathBuf::from(program)
        } else {
            if program.contains('/') || program == "." || program == ".." {
                return None;
            }
            self.bin_dirs
                .iter()
                .map(|dir| dir.join(program))
                .find(|p| is_executable_file(p))?
        };
        // A script's process image is its interpreter, so a rule on the script
        // would match nothing.
        if is_script(&path) {
            return None;
        }
        let real = std::fs::canonicalize(&path).unwrap_or(path);
        Some(real.to_string_lossy().into_owned())
    }
}

fn is_script(path: &Path) -> bool {
    let mut head = [0u8; 2];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && &head == b"#!"
}

/// Libraries, NetworkManager plugins and development/debug/documentation
/// subpackages: the client itself is a package of its own.
fn is_auxiliary_package(name: &str) -> bool {
    const PREFIXES: &[&str] = &["lib", "network-manager-", "networkmanager-"];
    const SUFFIXES: &[&str] = &[
        "-doc",
        "-docs",
        "-dev",
        "-devel",
        "-dbg",
        "-dbgsym",
        // A kernel module, not a program anything could route.
        "-dkms",
        "-debuginfo",
        "-debugsource",
        "-lang",
        "-libs",
        "-static",
    ];
    let lower = name.to_ascii_lowercase();
    PREFIXES.iter().any(|p| lower.starts_with(p)) || SUFFIXES.iter().any(|s| lower.ends_with(s))
}

fn is_kernel_tunnel_tooling(name: &str) -> bool {
    KERNEL_TUNNEL_PACKAGES.contains(&name.to_ascii_lowercase().as_str())
}

/// `<template>@<instance>.service` of a known tunnel template.
fn parse_tunnel_unit(unit: &str, running: bool) -> Option<TunnelUnit> {
    let (template, instance) = unit.strip_suffix(".service")?.split_once('@')?;
    let template = TUNNEL_TEMPLATES.iter().find(|t| t.name == template)?;
    if instance.is_empty() {
        return None;
    }
    Some(TunnelUnit {
        template,
        instance: unescape_unit_name(instance),
        running,
    })
}

/// One row per kernel tunnel. Only a link seen in sysfs is up: a unit or a
/// connection that names a missing link reports the tunnel down.
fn kernel_tunnels(
    links: &[String],
    units: &[TunnelUnit],
    connections: &[NmConnection],
) -> Vec<VpnCandidate> {
    #[derive(Default)]
    struct Tunnel {
        label: Option<String>,
        up: bool,
    }
    let mut by_link: BTreeMap<String, Tunnel> = BTreeMap::new();
    for link in links {
        by_link.entry(link.clone()).or_default().up = true;
    }
    // wg-quick names the interface after its config, so the instance is the link.
    for unit in units.iter().filter(|u| u.template.exe.is_none()) {
        by_link
            .entry(unit.instance.clone())
            .or_default()
            .label
            .get_or_insert_with(|| format!("{} ({})", unit.instance, unit.template.name));
    }
    let mut detached = Vec::new();
    for conn in connections.iter().filter(|c| c.wireguard) {
        match &conn.device {
            // The user's own name for the connection beats the unit spelling.
            Some(device) => {
                by_link.entry(device.clone()).or_default().label = Some(conn.name.clone())
            }
            None => detached.push(VpnCandidate::kernel_tunnel(conn.name.clone(), None, false)),
        }
    }
    by_link
        .into_iter()
        .map(|(link, tunnel)| {
            VpnCandidate::kernel_tunnel(
                tunnel.label.unwrap_or_else(|| link.clone()),
                Some(link),
                tunnel.up,
            )
        })
        .chain(detached)
        .collect()
}

// ── Pure parsers ──────────────────────────────────────────────────────────────

/// `dpkg-query -W --showformat='${Status} ${Package}\n'`: the installed ones.
fn parse_dpkg_packages(text: &str) -> Vec<String> {
    text.lines()
        .take(MAX_OUTPUT_LINES)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (_want, _flag, state, name) = (
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next()?,
            );
            (state == "installed" && fields.next().is_none()).then(|| name.to_string())
        })
        .collect()
}

/// One package name per line (`rpm -qa --queryformat`, `pacman -Qq`, `apk info`).
fn parse_package_lines(text: &str) -> Vec<String> {
    text.lines()
        .take(MAX_OUTPUT_LINES)
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.contains(char::is_whitespace))
        .map(str::to_string)
        .collect()
}

/// `systemctl list-units --plain --no-legend`: units that are up or coming up.
/// A failed unit is marked with a leading bullet.
fn parse_running_units(text: &str) -> Vec<String> {
    text.lines()
        .take(MAX_OUTPUT_LINES)
        .filter_map(|line| {
            let mut fields = line
                .split_whitespace()
                .skip_while(|f| *f == "●" || *f == "*");
            let (unit, _load, active) = (fields.next()?, fields.next()?, fields.next()?);
            matches!(active, "active" | "activating" | "reloading" | "refreshing")
                .then(|| unit.to_string())
        })
        .collect()
}

/// `systemctl list-unit-files --plain --no-legend`: enabled instances.
fn parse_enabled_unit_files(text: &str) -> Vec<String> {
    text.lines()
        .take(MAX_OUTPUT_LINES)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (unit, state) = (fields.next()?, fields.next()?);
            state.starts_with("enabled").then(|| unit.to_string())
        })
        .collect()
}

/// systemd escapes an instance name's special bytes as `\xNN`.
fn unescape_unit_name(escaped: &str) -> String {
    let bytes = escaped.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && bytes.get(i + 1) == Some(&b'x') {
            if let Some(byte) = escaped
                .get(i + 2..i + 4)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `nmcli -t -f NAME,TYPE,ACTIVE,DEVICE connection show`: VPN and WireGuard
/// connections.
fn parse_nm_vpn_connections(text: &str) -> Vec<NmConnection> {
    text.lines()
        .take(MAX_OUTPUT_LINES)
        .filter_map(|line| match split_terse(line).as_slice() {
            [name, kind, active, device]
                if !name.is_empty() && matches!(kind.as_str(), "vpn" | "wireguard") =>
            {
                Some(NmConnection {
                    name: name.clone(),
                    wireguard: kind == "wireguard",
                    active: active == "yes",
                    device: (!device.is_empty() && device != "--").then(|| device.clone()),
                })
            }
            _ => None,
        })
        .collect()
}

/// One terse `nmcli` line: fields split on `:`, with `\:` and `\\` escaped.
fn split_terse(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => current.extend(chars.next()),
            ':' => fields.push(std::mem::take(&mut current)),
            c => current.push(c),
        }
    }
    fields.push(current);
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _root: tempfile::TempDir,
        proc_root: PathBuf,
        sysfs: PathBuf,
        apps: PathBuf,
        bin: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("root");
            let proc_root = root.path().join("proc");
            let sysfs = root.path().join("sys-class-net");
            let apps = root.path().join("applications");
            let bin = root.path().join("bin");
            for dir in [&proc_root, &sysfs, &apps, &bin] {
                std::fs::create_dir_all(dir).expect("dir");
            }
            Self {
                _root: root,
                proc_root,
                sysfs,
                apps,
                bin,
            }
        }

        fn write(&self, path: &Path, text: &str) {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir).expect("dir");
            }
            std::fs::write(path, text).expect("write");
        }

        fn process(&self, pid: u32, comm: &str) {
            let dir = self.proc_root.join(pid.to_string());
            self.write(&dir.join("comm"), comm);
            self.write(&dir.join("cmdline"), &format!("{comm}\0"));
        }

        fn kernel_thread(&self, pid: u32, comm: &str) {
            let dir = self.proc_root.join(pid.to_string());
            self.write(&dir.join("comm"), comm);
            self.write(&dir.join("cmdline"), "");
        }

        /// An executable in the fixture's bin dir, a binary or a script.
        fn executable(&self, name: &str, body: &str) -> String {
            let path = self.bin.join(name);
            self.write(&path, body);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                    .expect("chmod");
            }
            std::fs::canonicalize(&path)
                .expect("canonical")
                .to_string_lossy()
                .into_owned()
        }

        fn discovery(&self, run: HelperRunner) -> LinuxVpnDiscovery {
            LinuxVpnDiscovery::with_roots(
                self.proc_root.clone(),
                self.sysfs.clone(),
                vec![self.apps.clone()],
                vec![self.bin.clone(), self.bin.join("missing")],
                run,
            )
        }
    }

    fn no_helpers(_: &str, _: &[&str], _: Duration) -> Option<String> {
        None
    }

    fn rows(found: &[VpnCandidate]) -> Vec<(&str, Option<&str>, bool, VpnCandidateSource)> {
        found
            .iter()
            .map(|c| {
                (
                    c.display_name.as_str(),
                    c.exe_path.as_deref(),
                    c.running,
                    c.source,
                )
            })
            .collect()
    }

    #[test]
    fn dpkg_lists_only_installed_packages() {
        let text = "install ok installed openvpn\n\
                    deinstall ok config-files wireguard\n\
                    install ok installed coreutils\n\
                    \n\
                    garbage\n";
        assert_eq!(parse_dpkg_packages(text), vec!["openvpn", "coreutils"]);
    }

    #[test]
    fn one_name_per_line_skips_blanks() {
        assert_eq!(
            parse_package_lines("openvpn\n\n  wireguard-tools \nnot a name\n"),
            vec!["openvpn", "wireguard-tools"]
        );
    }

    #[test]
    fn running_units_include_coming_up_and_skip_the_failed_bullet() {
        let text = "wg-quick@wg0.service loaded active exited WireGuard via wg-quick(8) for wg0\n\
                    \u{25cf} openvpn-client@tun0.service loaded failed failed OpenVPN tunnel for tun0\n\
                    openvpn@tun1.service loaded activating start OpenVPN connection to tun1\n\
                    awg-quick@wg1.service loaded inactive dead AmneziaWG via awg-quick(8) for wg1\n";
        assert_eq!(
            parse_running_units(text),
            vec!["wg-quick@wg0.service", "openvpn@tun1.service"]
        );
    }

    #[test]
    fn unit_files_keep_enabled_instances() {
        let text = "wg-quick@.service disabled enabled\n\
                    wg-quick@wg0.service enabled enabled\n\
                    openvpn-client@tun0.service enabled-runtime -\n\
                    openvpn@tun1.service masked -\n";
        assert_eq!(
            parse_enabled_unit_files(text),
            vec!["wg-quick@wg0.service", "openvpn-client@tun0.service"]
        );
    }

    #[test]
    fn unit_names_map_to_their_template_and_unescape() {
        let wg = parse_tunnel_unit("wg-quick@wg\\x2dexample.service", true);
        assert_eq!(
            wg.as_ref()
                .map(|u| (u.template.name, u.instance.as_str(), u.running)),
            Some(("wg-quick", "wg-example", true))
        );
        assert!(parse_tunnel_unit("wg-quick@.service", true).is_none());
        assert!(parse_tunnel_unit("sshd@tun0.service", true).is_none());
        assert!(parse_tunnel_unit("wg-quick@wg0.timer", true).is_none());
    }

    #[test]
    fn only_a_program_template_makes_a_unit_row() {
        let fx = Fixture::new();
        let openvpn = fx.executable("openvpn", "\x7fELF");
        let d = fx.discovery(no_helpers);
        let row = |unit: &str| {
            parse_tunnel_unit(unit, false)
                .and_then(|u| d.unit_candidate(&u))
                .map(|c| (c.display_name, c.exe_path))
        };
        assert_eq!(
            row("openvpn-client@tun0.service"),
            Some(("tun0 (openvpn-client)".to_string(), Some(openvpn)))
        );
        assert_eq!(row("wg-quick@wg-example.service"), None);
        assert_eq!(row("awg-quick@wg-example.service"), None);
    }

    #[test]
    fn nmcli_terse_output_yields_vpn_connections() {
        let text = "wg-example:wireguard:yes:wg0\n\
                    Wired connection 1:802-3-ethernet:yes:eth0\n\
                    office\\:vpn:vpn:no:\n\
                    back\\\\slash:vpn:yes:tun0\n\
                    idle-example:wireguard:no:--\n\
                    :vpn:yes:tun1\n\
                    short:vpn:yes\n";
        let conn = |name: &str, wireguard, active, device: Option<&str>| NmConnection {
            name: name.to_string(),
            wireguard,
            active,
            device: device.map(str::to_string),
        };
        assert_eq!(
            parse_nm_vpn_connections(text),
            vec![
                conn("wg-example", true, true, Some("wg0")),
                conn("office:vpn", false, false, None),
                conn("back\\slash", false, true, Some("tun0")),
                conn("idle-example", true, false, None),
            ]
        );
    }

    #[test]
    fn packages_resolve_their_binary_and_skip_plugins_and_libraries() {
        let fx = Fixture::new();
        let openvpn = fx.executable("openvpn", "\x7fELF");
        fx.executable("wg", "\x7fELF");
        let d = fx.discovery(no_helpers);

        let exe_of = |name: &str| d.package_candidate(name).map(|c| c.exe_path);
        assert_eq!(exe_of("openvpn"), Some(Some(openvpn)));
        assert_eq!(exe_of("amnezia-vpn"), Some(None), "no binary of that name");
        for skipped in [
            "wireguard",
            "wireguard-tools",
            "amneziawg",
            "amneziawg-tools",
            "network-manager-openvpn",
            "NetworkManager-openvpn",
            "libopenvpn3",
            "openvpn-doc",
            "amneziawg-dkms",
            "openvpn-devel",
            "coreutils",
        ] {
            assert!(d.package_candidate(skipped).is_none(), "{skipped}");
        }
    }

    #[test]
    fn a_script_is_never_the_exe() {
        let fx = Fixture::new();
        fx.executable("protonvpn-app", "#!/usr/bin/python3\n");
        fx.write(
            &fx.apps.join("proton.desktop"),
            "[Desktop Entry]\nType=Application\nName=Proton VPN\nExec=protonvpn-app\n",
        );
        let found = fx.discovery(no_helpers).discover_vpn_candidates();
        assert_eq!(
            rows(&found),
            vec![(
                "Proton VPN",
                None,
                false,
                VpnCandidateSource::InstalledProgram
            )]
        );
    }

    #[test]
    fn desktop_entries_resolve_a_bare_program_but_not_a_wrapper() {
        let fx = Fixture::new();
        let client = fx.executable("mullvad-vpn", "\x7fELF");
        fx.write(
            &fx.apps.join("mullvad-vpn.desktop"),
            "[Desktop Entry]\nType=Application\nName=Mullvad VPN\nExec=mullvad-vpn %U\n",
        );
        fx.executable("flatpak", "\x7fELF");
        fx.write(
            &fx.apps.join("org.example.WireGuard.desktop"),
            "[Desktop Entry]\nType=Application\nName=Tunnels\nExec=flatpak run org.example.WireGuard\n",
        );
        fx.write(
            &fx.apps.join("editor.desktop"),
            "[Desktop Entry]\nType=Application\nName=Text Editor\nExec=editor\n",
        );
        let found = fx.discovery(no_helpers).discover_vpn_candidates();
        assert_eq!(
            rows(&found),
            vec![
                (
                    "Mullvad VPN",
                    Some(client.as_str()),
                    false,
                    VpnCandidateSource::InstalledProgram
                ),
                ("Tunnels", None, false, VpnCandidateSource::InstalledProgram),
            ]
        );
    }

    fn whole_machine(tool: &str, args: &[&str], _: Duration) -> Option<String> {
        match (tool, args.first().copied()) {
            ("dpkg-query", _) => Some(
                "install ok installed openvpn\n\
                 install ok installed network-manager-openvpn\n\
                 install ok installed wireguard-tools\n\
                 install ok installed coreutils\n"
                    .into(),
            ),
            ("systemctl", Some("list-units")) => Some(
                "openvpn-client@tun0.service loaded active running OpenVPN tunnel for tun0\n\
                 wg-quick@wg0.service loaded active exited WireGuard via wg-quick(8) for wg0\n"
                    .into(),
            ),
            ("systemctl", Some("list-unit-files")) => Some(
                "wg-quick@wg0.service enabled enabled\nwg-quick@wg1.service enabled enabled\n"
                    .into(),
            ),
            ("nmcli", _) => Some("office-example:wireguard:no:\n".into()),
            _ => None,
        }
    }

    /// A root-owned `openvpn` (comm only), its package and its unit are one
    /// binary, so they collapse into one running row. With no tunnel link in
    /// sysfs, every kernel tunnel the units and connections name is down.
    #[test]
    fn every_source_merges_into_one_row_per_binary() {
        let fx = Fixture::new();
        let openvpn = fx.executable("openvpn", "\x7fELF");
        fx.process(101, "openvpn\n");
        fx.process(102, "bash\n");

        let found = fx.discovery(whole_machine).discover_vpn_candidates();
        assert_eq!(
            rows(&found),
            vec![
                (
                    "openvpn",
                    Some(openvpn.as_str()),
                    true,
                    VpnCandidateSource::RunningProcess
                ),
                (
                    "office-example",
                    None,
                    false,
                    VpnCandidateSource::KernelTunnel
                ),
                (
                    "wg0 (wg-quick)",
                    None,
                    false,
                    VpnCandidateSource::KernelTunnel
                ),
                (
                    "wg1 (wg-quick)",
                    None,
                    false,
                    VpnCandidateSource::KernelTunnel
                ),
            ]
        );
        let links: Vec<Option<&str>> = found.iter().map(|c| c.interface.as_deref()).collect();
        assert_eq!(links, vec![None, None, Some("wg0"), Some("wg1")]);
    }

    fn unit(name: &str) -> TunnelUnit {
        parse_tunnel_unit(name, false).expect("tunnel unit")
    }

    fn tunnel_rows(found: &[VpnCandidate]) -> Vec<(&str, Option<&str>, bool)> {
        found
            .iter()
            .map(|c| (c.display_name.as_str(), c.interface.as_deref(), c.running))
            .collect()
    }

    /// The link decides; a unit or a connection only names it.
    #[test]
    fn a_kernel_tunnel_is_its_link_labelled_by_what_brought_it_up() {
        let links = vec!["home".to_string(), "office-vpn".to_string()];
        let units = [
            unit("wg-quick@home.service"),
            unit("awg-quick@wg-example.service"),
            unit("openvpn@tun0.service"),
        ];
        let connections = [
            NmConnection {
                name: "office-example".into(),
                wireguard: true,
                active: true,
                device: Some("office-vpn".into()),
            },
            NmConnection {
                name: "idle-example".into(),
                wireguard: true,
                active: false,
                device: None,
            },
            NmConnection {
                name: "corp-example".into(),
                wireguard: false,
                active: true,
                device: Some("tun9".into()),
            },
        ];
        let found = kernel_tunnels(&links, &units, &connections);
        assert_eq!(
            tunnel_rows(&found),
            vec![
                ("home (wg-quick)", Some("home"), true),
                ("office-example", Some("office-vpn"), true),
                ("wg-example (awg-quick)", Some("wg-example"), false),
                ("idle-example", None, false),
            ]
        );
        assert!(found
            .iter()
            .all(|c| c.source == VpnCandidateSource::KernelTunnel && c.exe_path.is_none()));
    }

    /// Found by `DEVTYPE` in sysfs, whatever the link is called.
    #[cfg(target_os = "linux")]
    #[test]
    fn tunnel_links_are_found_by_device_type_not_name() {
        let fx = Fixture::new();
        for (link, uevent) in [
            ("home", "DEVTYPE=wireguard\nINTERFACE=home\n"),
            (
                "office-example",
                "DEVTYPE=amneziawg\nINTERFACE=office-example\n",
            ),
            ("wg-example", "INTERFACE=wg-example\n"),
            ("br-example", "DEVTYPE=bridge\nINTERFACE=br-example\n"),
        ] {
            fx.write(&fx.sysfs.join(link).join("uevent"), uevent);
        }
        let found = fx
            .discovery(|tool, args, _| match (tool, args.first().copied()) {
                ("systemctl", Some("list-unit-files")) => {
                    Some("wg-quick@home.service enabled enabled\n".into())
                }
                _ => None,
            })
            .discover_vpn_candidates();
        assert_eq!(
            tunnel_rows(&found),
            vec![
                ("home (wg-quick)", Some("home"), true),
                ("office-example", Some("office-example"), true),
            ]
        );
    }

    /// A kernel thread carries a name and nothing to route.
    #[test]
    fn a_kernel_thread_is_not_a_client() {
        let fx = Fixture::new();
        fx.kernel_thread(
            301, "openvpn
",
        );
        assert!(fx
            .discovery(no_helpers)
            .discover_vpn_candidates()
            .is_empty());
    }

    /// An own-user process exposes its image; when only `comm` names a VPN,
    /// that image is an interpreter and must not become the exe.
    #[cfg(unix)]
    #[test]
    fn an_interpreted_client_gets_no_exe() {
        let fx = Fixture::new();
        let dir = fx.proc_root.join("201");
        fx.process(201, "protonvpn-app\n");
        std::os::unix::fs::symlink("/usr/bin/python3.12", dir.join("exe")).expect("link");
        let dir = fx.proc_root.join("202");
        fx.process(202, "openvpn\n");
        std::os::unix::fs::symlink("/opt/vpn/openvpn (deleted)", dir.join("exe")).expect("link");

        let found = fx.discovery(no_helpers).discover_vpn_candidates();
        assert_eq!(
            rows(&found),
            vec![
                (
                    "openvpn",
                    Some("/opt/vpn/openvpn"),
                    true,
                    VpnCandidateSource::RunningProcess
                ),
                (
                    "protonvpn-app",
                    None,
                    true,
                    VpnCandidateSource::RunningProcess
                ),
            ]
        );
    }

    #[test]
    fn missing_roots_and_helpers_find_nothing() {
        let fx = Fixture::new();
        let gone = fx.proc_root.join("nowhere");
        let d = LinuxVpnDiscovery::with_roots(
            gone.clone(),
            gone.clone(),
            vec![gone.clone()],
            vec![gone],
            no_helpers,
        );
        assert!(d.discover_vpn_candidates().is_empty());
    }

    #[test]
    fn the_live_machine_is_scanned_without_panicking() {
        for candidate in LinuxVpnDiscovery::new().discover_vpn_candidates() {
            assert!(!candidate.display_name.trim().is_empty());
        }
    }
}
