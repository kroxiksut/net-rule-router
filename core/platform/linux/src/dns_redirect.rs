//! System DNS redirect through systemd-resolved.
//!
//! A dummy link of our own carries the listener's address, and resolved is told
//! that link's server answers every name (`~.`). Two facts measured on a live
//! machine shape it:
//!
//! - resolved sends a link's queries through a socket bound to that link, so a
//!   server on `127.0.0.1` configured on a dummy link is never asked. The
//!   listener therefore owns an address ON the link.
//! - with `~.` on two links resolved asks both and takes the first answer, so a
//!   VPN claiming every name keeps receiving them. While the redirect is active
//!   `~.` is taken from other links and handed back on restore; their narrower
//!   routing domains stay theirs — resolved already routes those past us.
//!
//! The link dies with the service (`restore`, the unit's stop hook, a reboot),
//! and resolved forgets everything configured on it. The `~.` taken from other
//! links is written down first, so a crash cannot keep it.
//!
//! Compiled on every host: the commands go through [`ResolvedCommands`], so the
//! whole state machine is tested against a fake.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use nrr_platform_api::dns::{SystemDnsServersPort, UpstreamDnsCandidate};
use nrr_platform_api::dns_redirect::{
    DnsNamespaceExemption, RedirectHandle, RedirectState, SystemDnsRedirectPort,
};
use nrr_platform_api::dns_scope::{InterfaceDnsScope, InterfaceDnsScopePort};
use nrr_platform_api::error::PlatformError;

/// Our link. The product's own name, so `ip link` and `resolvectl` say whose it is.
pub const REDIRECT_LINK: &str = nrr_shared::product_identity::PRODUCT_NAME_UNIX;

/// The listener's address on [`REDIRECT_LINK`]. Link-local: never routed, and
/// a `/32` on a link of our own cannot collide with a network's addressing.
pub const LISTENER_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 53, 53);

/// The listener's socket address. Port 53: resolved takes a port only from
/// version 246 on.
pub const LISTENER_ADDR: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(LISTENER_V4), 53);

const CATCH_ALL: &str = "~.";

/// What one command said.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommandReply {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Runs `ip` and `resolvectl`. The seam the tests replace.
pub trait ResolvedCommands: Send + Sync {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandReply, PlatformError>;
}

/// The real programs, each under the crate's command budget.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolvedCommands;

impl ResolvedCommands for SystemResolvedCommands {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandReply, PlatformError> {
        let output = crate::command::output_with_timeout(
            program,
            args,
            crate::command::DEFAULT_COMMAND_TIMEOUT,
        )
        .map_err(|e| PlatformError::Transient {
            operation: "run a DNS configuration command",
            detail: format!("{program}: {e}"),
        })?;
        Ok(CommandReply {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// One `Link N (name): values…` line of `resolvectl dns` / `resolvectl domain`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedLink {
    pub index: u32,
    pub name: String,
    pub values: Vec<String>,
}

/// Parse the per-link lines; the `Global:` line and anything else is skipped.
pub fn parse_resolvectl_links(text: &str) -> Vec<ResolvedLink> {
    text.lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("Link ")?;
            let (index, rest) = rest.split_once(' ')?;
            let index = index.parse().ok()?;
            let rest = rest.trim_start().strip_prefix('(')?;
            let (name, rest) = rest.split_once(')')?;
            let values = rest
                .trim_start()
                .strip_prefix(':')?
                .split_whitespace()
                .map(str::to_string)
                .collect();
            Some(ResolvedLink {
                index,
                name: name.trim().to_string(),
                values,
            })
        })
        .collect()
}

/// Does resolved stand between programs and DNS? Only in `stub` and `static`
/// mode does `/etc/resolv.conf` point at resolved; in `uplink` and `foreign`
/// mode programs ask the servers directly and a redirect would catch nothing.
pub fn resolved_mode_carries_programs(status_output: &str) -> bool {
    status_output.lines().any(|line| {
        line.trim()
            .strip_prefix("resolv.conf mode:")
            .is_some_and(|mode| matches!(mode.trim(), "stub" | "static"))
    })
}

/// Can this machine's DNS be redirected through resolved?
pub fn resolved_redirect_available(commands: &dyn ResolvedCommands) -> bool {
    commands
        .run("resolvectl", &["status"])
        .is_ok_and(|reply| reply.success && resolved_mode_carries_programs(&reply.stdout))
}

/// The redirect. `taken_file` records the links whose `~.` we hold, so a crash
/// can give it back ([`clear_orphan_redirect`]).
pub struct ResolvedDnsRedirect<C: ResolvedCommands> {
    commands: C,
    taken_file: PathBuf,
}

impl<C: ResolvedCommands> ResolvedDnsRedirect<C> {
    pub fn new(commands: C, taken_file: PathBuf) -> Self {
        Self {
            commands,
            taken_file,
        }
    }

    /// Create the link and put the listener's address on it. The listener
    /// binds that address, so this runs before the listener exists — the
    /// redirect itself comes later. Idempotent.
    pub fn prepare_link(&self) -> Result<(), PlatformError> {
        let exists = self
            .commands
            .run("ip", &["link", "show", "dev", REDIRECT_LINK])?
            .success;
        if !exists {
            self.checked(
                "ip",
                &["link", "add", REDIRECT_LINK, "type", "dummy"],
                "create the DNS link",
            )?;
        }
        let address = format!("{LISTENER_V4}/32");
        self.checked(
            "ip",
            &["addr", "replace", &address, "dev", REDIRECT_LINK],
            "address the DNS link",
        )?;
        self.checked(
            "ip",
            &["link", "set", REDIRECT_LINK, "up"],
            "bring the DNS link up",
        )
    }

    fn checked(
        &self,
        program: &str,
        args: &[&str],
        operation: &'static str,
    ) -> Result<(), PlatformError> {
        let reply = self.commands.run(program, args)?;
        if reply.success {
            return Ok(());
        }
        let detail = reply.stderr.trim().to_string();
        Err(
            if detail.contains("Operation not permitted") || detail.contains("Access denied") {
                PlatformError::AccessDenied { operation }
            } else {
                PlatformError::Transient { operation, detail }
            },
        )
    }

    fn links(&self, what: &str) -> Result<Vec<ResolvedLink>, PlatformError> {
        let reply = self.commands.run("resolvectl", &[what])?;
        if !reply.success {
            return Err(PlatformError::Transient {
                operation: "read resolved's per-link configuration",
                detail: reply.stderr.trim().to_string(),
            });
        }
        Ok(parse_resolvectl_links(&reply.stdout))
    }

    fn set_domains(&self, link: &str, domains: &[String]) -> Result<(), PlatformError> {
        let mut args = vec!["domain", link];
        if domains.is_empty() {
            // An empty argument clears the list; no argument would print it.
            args.push("");
        } else {
            args.extend(domains.iter().map(String::as_str));
        }
        self.checked("resolvectl", &args, "set a link's routing domains")
    }

    fn remember_taken(&self, links: &[String]) -> Result<(), PlatformError> {
        let mut known = read_taken(&self.taken_file);
        for link in links {
            if !known.contains(link) {
                known.push(link.clone());
            }
        }
        write_taken(&self.taken_file, &known)
    }

    /// Hand `~.` back to every link we took it from that still exists.
    fn give_back(&self) -> Result<(), PlatformError> {
        let taken = read_taken(&self.taken_file);
        if taken.is_empty() {
            return Ok(());
        }
        let current = self.links("domain")?;
        for name in &taken {
            let Some(link) = current.iter().find(|l| &l.name == name) else {
                continue; // The connection is gone; it reclaims on its return.
            };
            if link.values.iter().any(|v| v == CATCH_ALL) {
                continue;
            }
            let mut domains = link.values.clone();
            domains.push(CATCH_ALL.to_string());
            self.set_domains(name, &domains)?;
        }
        let _ = std::fs::remove_file(&self.taken_file);
        Ok(())
    }

    fn state(&self) -> Result<RedirectState, PlatformError> {
        let domains = self.links("domain")?;
        let servers = self.links("dns")?;
        let ours_claims = domains
            .iter()
            .any(|l| l.name == REDIRECT_LINK && l.values.iter().any(|v| v == CATCH_ALL));
        let ours_serves = servers.iter().any(|l| {
            l.name == REDIRECT_LINK && l.values.iter().any(|v| server_ip(v) == Some(LISTENER_V4))
        });
        let shared = domains
            .iter()
            .any(|l| l.name != REDIRECT_LINK && l.values.iter().any(|v| v == CATCH_ALL));
        Ok(if ours_claims && ours_serves && !shared {
            RedirectState::Active
        } else {
            RedirectState::Inactive
        })
    }
}

impl<C: ResolvedCommands> SystemDnsRedirectPort for ResolvedDnsRedirect<C> {
    fn redirect_to(&self, listener: SocketAddr) -> Result<RedirectHandle, PlatformError> {
        if listener != LISTENER_ADDR {
            // resolved reaches only the address on our link; any other listener
            // would take the machine's DNS to nowhere.
            return Err(PlatformError::NotSupported {
                reason: "resolved can reach the listener only at the DNS link's own address",
            });
        }
        self.prepare_link()?;
        // Write down whose `~.` we take before taking it.
        let claimants: Vec<String> = self
            .links("domain")?
            .into_iter()
            .filter(|l| l.name != REDIRECT_LINK && l.values.iter().any(|v| v == CATCH_ALL))
            .map(|l| l.name)
            .collect();
        self.remember_taken(&claimants)?;
        let listener_ip = LISTENER_V4.to_string();
        self.checked(
            "resolvectl",
            &["dns", REDIRECT_LINK, &listener_ip],
            "point the DNS link at the listener",
        )?;
        self.set_domains(REDIRECT_LINK, &[CATCH_ALL.to_string()])?;
        self.checked(
            "resolvectl",
            &["default-route", REDIRECT_LINK, "yes"],
            "make the DNS link the default route for names",
        )?;
        for link in self.links("domain")? {
            if link.name == REDIRECT_LINK || !link.values.iter().any(|v| v == CATCH_ALL) {
                continue;
            }
            let kept: Vec<String> = link.values.into_iter().filter(|v| v != CATCH_ALL).collect();
            self.set_domains(&link.name, &kept)?;
        }
        Ok(RedirectHandle {
            marker: format!("resolved:{REDIRECT_LINK}"),
            listener,
        })
    }

    fn restore(&self, _handle: &RedirectHandle) -> Result<(), PlatformError> {
        // Give `~.` back first: with our link gone and nobody claiming every
        // name, resolved falls back to the links marked as default route.
        let given_back = self.give_back();
        let removed = remove_link(&self.commands);
        given_back.and(removed)
    }

    fn verify(&self, _handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
        // resolved's own report is the configuration in force.
        self.state()
    }

    fn inspect(&self, _handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
        // A VPN that reconnects claims `~.` again; `Inactive` makes the guard
        // redirect once more, which takes it back.
        self.state()
    }

    fn flush_cache(&self) -> Result<(), PlatformError> {
        self.checked("resolvectl", &["flush-caches"], "flush resolved's cache")
    }

    fn exempt_namespaces(
        &self,
        exemptions: &[DnsNamespaceExemption],
    ) -> Result<usize, PlatformError> {
        // A link's own routing domains outrank our `~.` inside resolved, and
        // the redirect leaves them in place: every claim is already honoured.
        Ok(exemptions.len())
    }
}

fn remove_link(commands: &dyn ResolvedCommands) -> Result<(), PlatformError> {
    if !commands
        .run("ip", &["link", "show", "dev", REDIRECT_LINK])?
        .success
    {
        return Ok(());
    }
    let reply = commands.run("ip", &["link", "del", REDIRECT_LINK])?;
    if reply.success {
        Ok(())
    } else {
        Err(PlatformError::Transient {
            operation: "remove the DNS link",
            detail: reply.stderr.trim().to_string(),
        })
    }
}

/// Undo whatever a previous run left behind: its link, and the `~.` it took.
/// Run at start-up and by the unit's stop hook.
pub fn clear_orphan_redirect(
    commands: impl ResolvedCommands,
    taken_file: PathBuf,
) -> Result<(), PlatformError> {
    let redirect = ResolvedDnsRedirect::new(commands, taken_file);
    let given_back = redirect.give_back();
    let removed = remove_link(&redirect.commands);
    given_back.and(removed)
}

fn read_taken(path: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn write_taken(path: &std::path::Path, links: &[String]) -> Result<(), PlatformError> {
    let mut text = links.join("\n");
    text.push('\n');
    std::fs::write(path, text).map_err(|e| PlatformError::Transient {
        operation: "record the links whose DNS catch-all was taken",
        detail: e.to_string(),
    })
}

/// A `resolvectl dns` value: `192.0.2.1`, `192.0.2.1:53`, `192.0.2.1#name`.
fn server_ip(value: &str) -> Option<Ipv4Addr> {
    let host = value.split(['#', '%']).next()?;
    host.parse()
        .ok()
        .or_else(|| host.rsplit_once(':').and_then(|(ip, _)| ip.parse().ok()))
}

/// The machine's DNS servers per link, as resolved holds them — never through
/// `/etc/resolv.conf`, which under the redirect names resolved itself, i.e. us.
pub struct ResolvedDnsServers<C: ResolvedCommands>(pub C);

impl<C: ResolvedCommands> SystemDnsServersPort for ResolvedDnsServers<C> {
    fn upstream_candidates_v4(&self) -> Vec<UpstreamDnsCandidate> {
        let Ok(reply) = self.0.run("resolvectl", &["dns"]) else {
            return Vec::new();
        };
        if !reply.success {
            return Vec::new();
        }
        let mut out: Vec<UpstreamDnsCandidate> = Vec::new();
        for link in parse_resolvectl_links(&reply.stdout) {
            if link.name == REDIRECT_LINK {
                continue;
            }
            for server in link.values.iter().filter_map(|v| server_ip(v)) {
                if server.is_loopback() || out.iter().any(|c| c.server == server) {
                    continue;
                }
                out.push(UpstreamDnsCandidate::new(Some(link.index), server));
            }
        }
        out
    }
}

/// The namespaces links claim: their routing domains other than `~.`, with
/// the servers that answer for them.
pub struct ResolvedDnsScopes<C: ResolvedCommands>(pub C);

impl<C: ResolvedCommands> InterfaceDnsScopePort for ResolvedDnsScopes<C> {
    fn dns_scopes(&self) -> Vec<InterfaceDnsScope> {
        let read = |what: &str| {
            self.0
                .run("resolvectl", &[what])
                .ok()
                .filter(|r| r.success)
                .map(|r| parse_resolvectl_links(&r.stdout))
                .unwrap_or_default()
        };
        let servers = read("dns");
        let mut out = Vec::new();
        for link in read("domain") {
            if link.name == REDIRECT_LINK {
                continue;
            }
            let link_servers: Vec<Ipv4Addr> = servers
                .iter()
                .find(|s| s.name == link.name)
                .map(|s| s.values.iter().filter_map(|v| server_ip(v)).collect())
                .unwrap_or_default();
            for domain in &link.values {
                let suffix = domain
                    .trim_start_matches('~')
                    .trim_matches('.')
                    .to_ascii_lowercase();
                if suffix.is_empty() {
                    continue;
                }
                out.push(InterfaceDnsScope {
                    adapter_id: link.name.clone(),
                    display_name: link.name.clone(),
                    suffix,
                    servers: link_servers.clone(),
                });
            }
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
