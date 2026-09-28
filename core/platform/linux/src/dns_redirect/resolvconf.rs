//! System DNS redirect through `resolvconf` — Debian's resolvconf or
//! openresolv (Debian without resolved, Gentoo, Arch).
//!
//! The listener is added as a record of its own. openresolv takes it
//! exclusively; Debian's resolvconf does not know exclusivity, but it lists a
//! `lo.*` record first and cuts the list after a loopback server, which is
//! where the listener sits. Records live under `/run`, so a reboot forgets
//! ours even if nothing else does.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use nrr_platform_api::dns::{SystemDnsServersPort, UpstreamDnsCandidate};
use nrr_platform_api::dns_redirect::{RedirectHandle, RedirectState, SystemDnsRedirectPort};
use nrr_platform_api::dns_scope::{InterfaceDnsScope, InterfaceDnsScopePort};
use nrr_platform_api::error::PlatformError;

use super::resolv_conf::{forwardable, nameservers, search_domains};
use super::{DnsCommands, DnsFiles};

/// Our record's name. `lo.` puts it at the head of Debian's interface order.
pub fn resolvconf_record() -> String {
    format!("lo.{}", nrr_shared::product_identity::PRODUCT_NAME_UNIX)
}

/// Does `resolvconf` write this file? Either spelling of its header, or a
/// symlink into its run directory.
pub fn resolvconf_writes(resolv_conf: &str, link_target: Option<&str>) -> bool {
    let header = resolv_conf
        .lines()
        .take_while(|l| l.starts_with('#'))
        .any(|l| l.contains("resolvconf"));
    header || link_target.is_some_and(|t| t.contains("resolvconf"))
}

/// Is `resolvconf` installed and writing the machine's `resolv.conf`?
pub fn resolvconf_redirect_available(commands: &dyn DnsCommands, files: &DnsFiles) -> bool {
    let text = std::fs::read_to_string(&files.resolv_conf).unwrap_or_default();
    let target = std::fs::read_link(&files.resolv_conf)
        .ok()
        .map(|t| t.to_string_lossy().into_owned());
    // Any answer means the program exists; Debian's rejects `--version`.
    resolvconf_writes(&text, target.as_deref())
        && commands.run("resolvconf", &["--version"]).is_ok()
}

fn checked(
    commands: &dyn DnsCommands,
    args: &[&str],
    input: Option<&str>,
) -> Result<bool, PlatformError> {
    let reply = match input {
        Some(input) => commands.run_with_input("resolvconf", args, input)?,
        None => commands.run("resolvconf", args)?,
    };
    Ok(reply.success)
}

/// Exclusively where openresolv allows it, as a plain record otherwise.
fn add_record(commands: &dyn DnsCommands, name: &str, record: &str) -> Result<(), PlatformError> {
    if checked(commands, &["-x", "-a", name], Some(record))?
        || checked(commands, &["-a", name], Some(record))?
    {
        Ok(())
    } else {
        Err(PlatformError::Transient {
            operation: "add the listener's resolvconf record",
            detail: "resolvconf refused the record".to_string(),
        })
    }
}

/// The records other interfaces hold, by record name.
fn records(files: &DnsFiles) -> Vec<(String, String)> {
    let record_name = resolvconf_record();
    let mut out = Vec::new();
    for dir in &files.resolvconf_record_dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut found: Vec<(String, String)> = entries
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                if name == record_name || name.starts_with('.') {
                    return None;
                }
                std::fs::read_to_string(e.path()).ok().map(|t| (name, t))
            })
            .collect();
        found.sort();
        out.extend(found);
    }
    out
}

fn record_exists(files: &DnsFiles) -> bool {
    files
        .resolvconf_record_dirs
        .iter()
        .any(|d| d.join(resolvconf_record()).exists())
}

/// The interface a record belongs to: `eth0.dhclient` → `eth0`.
fn interface_of(record: &str) -> &str {
    record.split('.').next().unwrap_or(record)
}

/// The `resolvconf` redirect.
pub struct ResolvconfDnsRedirect<C: DnsCommands> {
    commands: C,
    files: DnsFiles,
}

impl<C: DnsCommands> ResolvconfDnsRedirect<C> {
    pub fn new(commands: C, files: DnsFiles) -> Self {
        Self { commands, files }
    }
}

impl<C: DnsCommands> SystemDnsRedirectPort for ResolvconfDnsRedirect<C> {
    fn redirect_to(&self, listener: SocketAddr) -> Result<RedirectHandle, PlatformError> {
        let listener_v4 = super::loopback_listener_v4(listener)?;
        let name = resolvconf_record();
        let record = format!("nameserver {listener_v4}\n");
        // A refused call may still have written the record before failing.
        if let Err(error) = add_record(&self.commands, &name, &record) {
            let _ = clear_resolvconf_redirect(&self.commands, &self.files);
            return Err(error);
        }
        Ok(RedirectHandle {
            marker: format!("resolvconf:{name}"),
            listener,
        })
    }

    fn restore(&self, _handle: &RedirectHandle) -> Result<(), PlatformError> {
        clear_resolvconf_redirect(&self.commands, &self.files)
    }

    fn verify(&self, handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
        let listener = super::loopback_listener_v4(handle.listener)?;
        // The C library asks the first server; Debian may list others after
        // ours, which are asked only if ours does not answer.
        let first = std::fs::read_to_string(&self.files.resolv_conf)
            .ok()
            .and_then(|text| nameservers(&text).first().copied());
        Ok(if first == Some(listener) {
            RedirectState::Active
        } else {
            RedirectState::Inactive
        })
    }

    fn inspect(&self, handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
        self.verify(handle)
    }
}

/// Delete our record. Idempotent; also the orphan cleanup after a crash.
pub(crate) fn clear_resolvconf_redirect(
    commands: &dyn DnsCommands,
    files: &DnsFiles,
) -> Result<(), PlatformError> {
    if !record_exists(files) {
        return Ok(());
    }
    // openresolv wants `-f` to stay quiet about a record that just went away;
    // Debian's does not know it.
    let name = resolvconf_record();
    if checked(commands, &["-f", "-d", &name], None)? || checked(commands, &["-d", &name], None)? {
        Ok(())
    } else {
        Err(PlatformError::Transient {
            operation: "remove the listener's resolvconf record",
            detail: "resolvconf refused to delete the record".to_string(),
        })
    }
}

/// The servers other interfaces' records name.
pub struct ResolvconfDnsServers {
    pub files: DnsFiles,
}

impl SystemDnsServersPort for ResolvconfDnsServers {
    fn upstream_candidates_v4(&self) -> Vec<UpstreamDnsCandidate> {
        let mut out: Vec<UpstreamDnsCandidate> = Vec::new();
        for (record, text) in records(&self.files) {
            let index = super::link_index(interface_of(&record));
            for server in forwardable(nameservers(&text)) {
                if out.iter().any(|c| c.server == server) {
                    continue;
                }
                out.push(UpstreamDnsCandidate::new(index, server));
            }
        }
        out
    }
}

impl InterfaceDnsScopePort for ResolvconfDnsServers {
    fn dns_scopes(&self) -> Vec<InterfaceDnsScope> {
        let mut out = Vec::new();
        for (record, text) in records(&self.files) {
            let servers: Vec<Ipv4Addr> = nameservers(&text);
            let interface = interface_of(&record).to_string();
            for suffix in search_domains(&text) {
                out.push(InterfaceDnsScope {
                    adapter_id: interface.clone(),
                    display_name: interface.clone(),
                    suffix,
                    servers: servers.clone(),
                });
            }
        }
        out
    }
}

/// Where Debian's resolvconf and openresolv keep their records.
pub(crate) fn system_record_dirs() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/run/resolvconf/interface"),
        PathBuf::from("/run/resolvconf/interfaces"),
    ]
}
