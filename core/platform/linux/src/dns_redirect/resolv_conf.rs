//! System DNS redirect by rewriting `/etc/resolv.conf` itself — the machine
//! where nothing manages the file.
//!
//! The file the system had is copied into the service's data directory before
//! ours replaces it, and put back on restore (a symlink as a symlink). Whatever
//! rewrites the file while we hold it (a DHCP client) wins the next inspect:
//! its version becomes the copy and ours goes back on top.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use nrr_platform_api::dns::{SystemDnsServersPort, UpstreamDnsCandidate};
use nrr_platform_api::dns_redirect::{RedirectHandle, RedirectState, SystemDnsRedirectPort};
use nrr_platform_api::dns_scope::{InterfaceDnsScope, InterfaceDnsScopePort};
use nrr_platform_api::error::PlatformError;

use super::DnsFiles;

/// First line of every file we write. How a later run, the stop hook and the
/// guard tell ours from the system's.
pub(crate) const OURS_MARKER: &str =
    "# NetRuleRouter answers DNS here; the system's own file returns when it stops.";

/// Is `text` a file we wrote?
pub(crate) fn is_ours(text: &str) -> bool {
    text.lines().next().is_some_and(|l| l.trim() == OURS_MARKER)
}

/// The system resolver configuration.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

/// The `nameserver` addresses, IPv4 only, in file order.
#[must_use]
pub(crate) fn nameservers(text: &str) -> Vec<Ipv4Addr> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        // IPv6 nameservers are skipped rather than mis-parsed: this resolver
        // asks for A records, and the transport it asks over is v4.
        if let Ok(server) = rest.trim().parse::<Ipv4Addr>() {
            if !servers.contains(&server) {
                servers.push(server);
            }
        }
    }
    servers
}

/// `servers` without loopback ones. A loopback server is our own listener or
/// a local cache (dnsmasq, unbound, resolved's stub) that forwards to whatever
/// `resolv.conf` names — us, once redirected — so forwarding to it loops until
/// the budget runs out on every query.
pub(crate) fn forwardable(servers: Vec<Ipv4Addr>) -> Vec<Ipv4Addr> {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let before = servers.len();
    let kept: Vec<Ipv4Addr> = servers.into_iter().filter(|s| !s.is_loopback()).collect();
    if kept.len() < before && !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            target: "nrr::dns-resolver",
            dropped = before - kept.len(),
            "the machine's DNS names a local resolver on loopback; it forwards to this service \
             once redirected, so it is not used as an upstream",
        );
    }
    kept
}

/// The `search` and `domain` suffixes, lower-cased, without dots at the ends.
pub(crate) fn search_domains(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if !matches!(words.next(), Some("search" | "domain")) {
            continue;
        }
        for word in words {
            let suffix = word.trim_matches('.').to_ascii_lowercase();
            if !suffix.is_empty() && !out.contains(&suffix) {
                out.push(suffix);
            }
        }
    }
    out
}

/// Replace `path` in one step: a reader never sees half a file. A symlink at
/// `path` is replaced by the file, not followed. Durable on return: the saved
/// copy must survive a power cut that the `resolv.conf` written after it does.
pub(crate) fn write_atomically(path: &Path, text: &str) -> Result<(), PlatformError> {
    let failed = |e: std::io::Error| PlatformError::Transient {
        operation: "write a DNS configuration file",
        detail: format!("{}: {e}", path.display()),
    };
    let dir = path.parent().unwrap_or_else(|| Path::new("/"));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = dir.join(format!(".{name}.netrulerouter-new"));
    {
        let mut file = std::fs::File::create(&temp).map_err(failed)?;
        file.write_all(text.as_bytes()).map_err(failed)?;
        file.sync_all().map_err(failed)?;
    }
    set_world_readable(&temp).map_err(failed)?;
    std::fs::rename(&temp, path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        failed(e)
    })?;
    sync_dir(dir).map_err(failed)
}

/// Make a rename in `dir` durable.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_world_readable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
}

#[cfg(not(unix))]
fn set_world_readable(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// The whole-file redirect.
pub struct ResolvConfFileRedirect {
    files: DnsFiles,
}

impl ResolvConfFileRedirect {
    pub fn new(files: DnsFiles) -> Self {
        Self { files }
    }

    fn live(&self) -> Option<String> {
        std::fs::read_to_string(&self.files.resolv_conf).ok()
    }

    /// Keep the system's current file, unless the current file is ours.
    fn save_system_copy(&self, live: &str) -> Result<(), PlatformError> {
        if is_ours(live) {
            return Ok(());
        }
        write_atomically(&self.files.system_copy(), live)?;
        match std::fs::read_link(&self.files.resolv_conf) {
            Ok(target) => {
                write_atomically(&self.files.system_link(), &target.to_string_lossy())?;
            }
            Err(_) => {
                let _ = std::fs::remove_file(self.files.system_link());
            }
        }
        Ok(())
    }

    fn state(&self, listener: Ipv4Addr) -> RedirectState {
        match self.live() {
            Some(text) if is_ours(&text) && nameservers(&text) == [listener] => {
                RedirectState::Active
            }
            _ => RedirectState::Inactive,
        }
    }
}

/// Our file: the listener as the only server, the system's search list and
/// options kept, so short names and resolver options behave as before.
fn render(listener: Ipv4Addr, system: &str) -> String {
    let mut text = format!("{OURS_MARKER}\nnameserver {listener}\n");
    for line in system.lines() {
        let keyword = line.split_whitespace().next();
        if matches!(keyword, Some("search" | "domain" | "options")) {
            text.push_str(line.trim());
            text.push('\n');
        }
    }
    text
}

impl SystemDnsRedirectPort for ResolvConfFileRedirect {
    fn redirect_to(&self, listener: SocketAddr) -> Result<RedirectHandle, PlatformError> {
        let listener_v4 = super::loopback_listener_v4(listener)?;
        let mut live = self.live().ok_or(PlatformError::NotSupported {
            reason: "the machine has no /etc/resolv.conf to point at the listener",
        })?;
        if is_ours(&live) && !self.files.system_copy().exists() {
            // Ours with nothing to put back: restoring would leave it forever.
            // Recover the system's file first, or refuse.
            restore_system_file(&self.files)?;
            live = self.live().unwrap_or_default();
        }
        let written = self.save_system_copy(&live).and_then(|()| {
            let system = std::fs::read_to_string(self.files.system_copy()).map_err(|e| {
                PlatformError::Transient {
                    operation: "read the saved system resolv.conf",
                    detail: e.to_string(),
                }
            })?;
            write_atomically(&self.files.resolv_conf, &render(listener_v4, &system))
        });
        if let Err(error) = written {
            let _ = restore_system_file(&self.files);
            return Err(error);
        }
        Ok(RedirectHandle {
            marker: "resolv.conf".to_string(),
            listener,
        })
    }

    fn restore(&self, _handle: &RedirectHandle) -> Result<(), PlatformError> {
        restore_system_file(&self.files)
    }

    fn verify(&self, handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
        Ok(self.state(super::loopback_listener_v4(handle.listener)?))
    }

    fn inspect(&self, handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
        self.verify(handle)
    }
}

/// Put the system's file back if ours is in place, then forget the copy.
/// Idempotent; also the orphan cleanup after a crash.
///
/// Ours in place with the copy gone (a power cut, a wiped data directory)
/// would name a dead listener on every boot: it is pointed at resolved's stub
/// when resolved runs, and reported as an error otherwise.
pub(crate) fn restore_system_file(files: &DnsFiles) -> Result<(), PlatformError> {
    let copy = files.system_copy();
    let Ok(system) = std::fs::read_to_string(&copy) else {
        let ours_in_place =
            std::fs::read_to_string(&files.resolv_conf).is_ok_and(|text| is_ours(&text));
        if !ours_in_place {
            return Ok(());
        }
        let _ = std::fs::remove_file(files.system_link());
        if files.resolved_stub.exists() {
            return relink(&files.resolv_conf, &files.resolved_stub);
        }
        return Err(PlatformError::Transient {
            operation: "restore the system resolv.conf",
            detail: format!(
                "{} is still ours and the saved system copy is gone; \
                 write the machine's resolver configuration back by hand",
                files.resolv_conf.display()
            ),
        });
    };
    let ours_in_place = std::fs::read_to_string(&files.resolv_conf)
        .map(|text| is_ours(&text))
        .unwrap_or(true);
    if ours_in_place {
        match std::fs::read_to_string(files.system_link()) {
            Ok(target) => relink(&files.resolv_conf, Path::new(target.trim()))?,
            Err(_) => write_atomically(&files.resolv_conf, &system)?,
        }
    }
    // Someone else's file stands there now: it is newer than our copy.
    let _ = std::fs::remove_file(&copy);
    let _ = std::fs::remove_file(files.system_link());
    Ok(())
}

#[cfg(unix)]
fn relink(path: &Path, target: &Path) -> Result<(), PlatformError> {
    let failed = |e: std::io::Error| PlatformError::Transient {
        operation: "restore the resolv.conf symlink",
        detail: format!("{} -> {}: {e}", path.display(), target.display()),
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = path.with_file_name(format!(".{name}.netrulerouter-link"));
    let _ = std::fs::remove_file(&temp);
    std::os::unix::fs::symlink(target, &temp).map_err(failed)?;
    std::fs::rename(&temp, path).map_err(failed)?;
    sync_dir(path.parent().unwrap_or_else(|| Path::new("/"))).map_err(failed)
}

#[cfg(not(unix))]
fn relink(_path: &Path, _target: &Path) -> Result<(), PlatformError> {
    Err(PlatformError::NotSupported {
        reason: "symlinks are restored only on Unix",
    })
}

/// The servers the system's file names: the copy while ours stands in its
/// place, the live file otherwise. Never our own listener.
pub struct ResolvConfFileServers {
    pub files: DnsFiles,
}

impl ResolvConfFileServers {
    fn system_text(&self) -> String {
        std::fs::read_to_string(self.files.system_copy())
            .ok()
            .or_else(|| {
                std::fs::read_to_string(&self.files.resolv_conf)
                    .ok()
                    .filter(|t| !is_ours(t))
            })
            .unwrap_or_default()
    }
}

impl SystemDnsServersPort for ResolvConfFileServers {
    fn upstream_candidates_v4(&self) -> Vec<UpstreamDnsCandidate> {
        forwardable(nameservers(&self.system_text()))
            .into_iter()
            .map(|s| UpstreamDnsCandidate::new(None, s))
            .collect()
    }
}

impl InterfaceDnsScopePort for ResolvConfFileServers {
    fn dns_scopes(&self) -> Vec<InterfaceDnsScope> {
        let text = self.system_text();
        let servers: Vec<Ipv4Addr> = nameservers(&text)
            .into_iter()
            .filter(|s| *s != super::LOOPBACK_LISTENER_V4)
            .collect();
        search_domains(&text)
            .into_iter()
            .map(|suffix| InterfaceDnsScope {
                adapter_id: "resolv.conf".to_string(),
                display_name: "resolv.conf".to_string(),
                suffix,
                servers: servers.clone(),
            })
            .collect()
    }
}

impl DnsFiles {
    /// The system's file, kept while ours stands in its place.
    pub(crate) fn system_copy(&self) -> PathBuf {
        self.data_dir.join("resolv.conf.system")
    }

    /// Where the system's file pointed, when it was a symlink.
    pub(crate) fn system_link(&self) -> PathBuf {
        self.data_dir.join("resolv.conf.system-link")
    }
}
