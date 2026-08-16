//! System DNS redirect port.
//!
//! Points the OS resolver at NetRuleRouter's loopback DNS listener so rule-host
//! queries transit our resolver (`EnforcementMode::Resolver`), and restores the
//! prior configuration cleanly on stop / crash. This is the genuinely
//! OS-specific half of Mode B — the listener and the rule-host policy are
//! neutral. Per the policy/mechanism seam it sits behind the
//! [`SystemDnsRedirectPort`] trait, with per-OS impls:
//!
//! - **Windows** — NRPT (Name Resolution Policy Table) via the
//!   `*-DnsClientNrptRule` cmdlets. NRPT routes a namespace (here `.`, i.e. all
//!   names) to our loopback resolver without touching per-adapter DNS, and is
//!   cleanly reversible — preferred over rewriting adapter DNS servers.
//! - **Linux / macOS** — systemd-resolved / `resolv.conf`, `scutil` (future).
//!
//! No `unsafe`: the Windows impl drives the cmdlets through a
//! [`CommandRunner`] (`powershell.exe`), which also makes the redirect/restore
//! **logic unit-testable** with a fake runner — the OS is exercised only by the
//! thin, Windows-gated [`PowerShellRunner`].

use std::net::{Ipv4Addr, SocketAddr};

use nrr_platform_api::dns::UpstreamDnsCandidate;

use crate::error::PlatformError;

/// Comment stamped on OUR NRPT rule so `restore` / `verify` only ever touch the
/// rule this service created, never a VPN client's or an admin's own rule.
const NRPT_MARKER: &str = "NetRuleRouter-ModeB-DnsRedirect";

// The neutral system-DNS-redirect PORT + its handle/state types live
// in `nrr-platform-api`; re-export so `nrr_platform_windows::dns_redirect::*`
// paths keep resolving unchanged. The Windows NRPT MECHANISM below impls it via
// the internal `CommandRunner` (PowerShell) abstraction, which stays here.
pub use nrr_platform_api::dns_redirect::{RedirectHandle, RedirectState, SystemDnsRedirectPort};

/// Output of a shell command: whether it succeeded plus its captured streams.
#[derive(Clone, Debug)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Runs a PowerShell script and returns its outcome. Abstracted so the NRPT
/// redirect logic is unit-testable without a live Windows DNS client.
pub trait CommandRunner: Send + Sync {
    fn run_powershell(&self, script: &str) -> Result<CommandOutput, PlatformError>;
}

// ── Pure PowerShell command builders (unit-tested) ────────────────────────────
//
// `listener_ip` is our own loopback address (never user input), and `marker` is
// a fixed constant, so these interpolations carry no injection risk.

/// Idempotently install our NRPT catch-all rule pointing all names (`.`) at
/// `listener_ip`: remove any stale rule of ours first, then add.
fn add_script(listener_ip: &str, marker: &str) -> String {
    format!(
        "$ErrorActionPreference='Stop'; \
         Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{marker}' }} | \
         ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}; \
         Add-DnsClientNrptRule -Namespace '.' -NameServers '{listener_ip}' -Comment '{marker}'"
    )
}

/// Remove every NRPT rule carrying our marker (restore to prior state).
fn remove_script(marker: &str) -> String {
    format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{marker}' }} | \
         ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}"
    )
}

/// Flush the Windows DNS client cache so warm entries re-resolve through the
/// freshly-installed (or freshly-removed) redirect.
fn flush_script() -> &'static str {
    "Clear-DnsClientCache"
}

/// PowerShell listing candidate upstream IPv4 DNS servers as `<ifIndex> <server>`
/// lines, excluding our own loopback listener. Emits the DNS server(s) of the
/// interface that owns the DEFAULT ROUTE (the active egress, lowest route
/// metric) FIRST, then the servers of every CONNECTED interface as a fallback.
/// The interface column lets the caller prefer the link its routing policy uses.
///
/// Both halves are gated on `ConnectionState -eq 'Connected'`: a disconnected
/// adapter — an unplugged NIC, an idle Wi-Fi radio, a Bluetooth PAN — keeps its
/// statically configured DNS server, and that entry is indistinguishable from a
/// live one in the raw list. Taking it forwards every query into a black hole,
/// which is exactly what happens at boot: the service arms before any default
/// route exists, so only the fallback half runs.
///
/// The fallback is ordered by interface metric rather than by interface index,
/// because index order is arbitrary with respect to which link the machine
/// actually uses. Neither ordering is a liveness claim — the caller probes —
/// but a better first guess saves a probe timeout on every boot.
///
/// If the interface query itself yields nothing (it is the newest of these
/// cmdlets, and the DNS list is the older, more universally available one), the
/// gate opens rather than starving the caller of candidates: an unprobed list
/// beats no list, since the probe is what actually decides.
fn upstream_dns_script() -> &'static str {
    "$ErrorActionPreference='SilentlyContinue'; \
     $live = @(Get-NetIPInterface -AddressFamily IPv4 | \
       Where-Object { $_.ConnectionState -eq 'Connected' } | \
       Sort-Object -Property InterfaceMetric | \
       Select-Object -ExpandProperty ifIndex); \
     if ($live.Count -eq 0) { \
       $live = @(Get-DnsClientServerAddress -AddressFamily IPv4 | \
         Select-Object -ExpandProperty InterfaceIndex) \
     }; \
     $idx = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | \
       Sort-Object -Property RouteMetric | \
       Select-Object -First 1 -ExpandProperty ifIndex; \
     $order = @(); \
     if ($idx -and ($live -contains $idx)) { $order += $idx }; \
     $order += $live; \
     foreach ($i in $order) { \
       Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4 | \
       Select-Object -ExpandProperty ServerAddresses | \
       Where-Object { $_ -and $_ -ne '127.0.0.1' } | \
       ForEach-Object { \"$i $_\" } \
     }"
}

/// Every routable upstream candidate the script emits, best first, deduplicated
/// by server address.
///
/// The caller probes these in order and rotates on failure, so the list matters
/// more than its head: an adapter can be connected and still have an
/// unreachable resolver (captive portal, VPN mid-handshake).
pub fn capture_upstream_dns_candidates_v4<R: CommandRunner>(
    runner: &R,
) -> Vec<UpstreamDnsCandidate> {
    let Ok(out) = runner.run_powershell(upstream_dns_script()) else {
        return Vec::new();
    };
    if !out.success {
        return Vec::new();
    }
    let mut seen: Vec<UpstreamDnsCandidate> = Vec::new();
    for line in out.stdout.lines() {
        let Some(candidate) = parse_candidate_line(line) else {
            continue;
        };
        if !seen.iter().any(|c| c.server == candidate.server) {
            seen.push(candidate);
        }
    }
    seen
}

/// `"17 192.168.0.1"` → candidate. A bare address (no interface column) still
/// parses, so a future/degraded emitter never silently yields nothing.
fn parse_candidate_line(line: &str) -> Option<UpstreamDnsCandidate> {
    let line = line.trim();
    let (index, addr) = match line.split_once(char::is_whitespace) {
        Some((idx, rest)) => (idx.trim().parse::<u32>().ok(), rest.trim()),
        None => (None, line),
    };
    let server = addr.parse::<Ipv4Addr>().ok()?;
    (!server.is_loopback() && !server.is_unspecified() && !server.is_broadcast())
        .then_some(UpstreamDnsCandidate::new(index, server))
}

/// The preferred upstream — the head of [`capture_upstream_dns_candidates_v4`].
/// `None` when none can be determined; the caller MUST then NOT redirect, or
/// general (non-rule) DNS would break. Generic over [`CommandRunner`] so it is
/// unit-testable.
pub fn capture_upstream_dns_v4<R: CommandRunner>(runner: &R) -> Option<Ipv4Addr> {
    capture_upstream_dns_candidates_v4(runner)
        .into_iter()
        .next()
        .map(|c| c.server)
}

/// Windows implementation of [`SystemDnsServersPort`] over the live PowerShell
/// runner. Gated with the runner it drives — the enumeration logic above stays
/// portable so it keeps its tests on any host.
#[cfg(target_os = "windows")]
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsSystemDnsServers;

#[cfg(target_os = "windows")]
impl nrr_platform_api::dns::SystemDnsServersPort for WindowsSystemDnsServers {
    fn upstream_candidates_v4(&self) -> Vec<UpstreamDnsCandidate> {
        capture_upstream_dns_candidates_v4(&PowerShellRunner)
    }
}

/// Remove any orphaned NetRuleRouter Mode-B NRPT rule left by a prior crashed
/// Resolver session, so a dead `:53` from a previous run never lingers and
/// breaks all name resolution. Safe to call unconditionally at EVERY boot,
/// regardless of the current enforcement mode. Marker-scoped: never touches a
/// VPN client's or an admin's own NRPT rule. Generic over [`CommandRunner`] for
/// unit-testing.
pub fn clear_orphan_redirect<R: CommandRunner>(runner: &R) -> Result<(), PlatformError> {
    let out = runner.run_powershell(&remove_script(NRPT_MARKER))?;
    if !out.success {
        return Err(PlatformError::Transient {
            operation: "nrpt.clear_orphan",
            detail: format!("orphan NRPT cleanup failed: {}", out.stderr.trim()),
        });
    }
    Ok(())
}

/// Echo our marker iff a rule of ours is present (empty stdout otherwise).
fn verify_script(marker: &str) -> String {
    format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{marker}' }} | \
         Select-Object -First 1 -ExpandProperty Comment"
    )
}

/// Windows NRPT implementation of [`SystemDnsRedirectPort`], generic over the
/// [`CommandRunner`] so the redirect/restore/verify flow is testable with a fake
/// runner. Production wires [`PowerShellRunner`].
pub struct NrptDnsRedirect<R: CommandRunner> {
    runner: R,
}

impl<R: CommandRunner> NrptDnsRedirect<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R: CommandRunner> SystemDnsRedirectPort for NrptDnsRedirect<R> {
    fn redirect_to(&self, listener: SocketAddr) -> Result<RedirectHandle, PlatformError> {
        let ip = listener.ip().to_string();
        let out = self.runner.run_powershell(&add_script(&ip, NRPT_MARKER))?;
        if !out.success {
            return Err(PlatformError::Transient {
                operation: "nrpt.redirect_to",
                detail: format!("NRPT add failed: {}", out.stderr.trim()),
            });
        }
        Ok(RedirectHandle {
            marker: NRPT_MARKER.to_string(),
            listener,
        })
    }

    fn restore(&self, handle: &RedirectHandle) -> Result<(), PlatformError> {
        let out = self.runner.run_powershell(&remove_script(&handle.marker))?;
        if !out.success {
            return Err(PlatformError::Transient {
                operation: "nrpt.restore",
                detail: format!("NRPT remove failed: {}", out.stderr.trim()),
            });
        }
        Ok(())
    }

    fn verify(&self, handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
        let out = self.runner.run_powershell(&verify_script(&handle.marker))?;
        Ok(if out.stdout.contains(&handle.marker) {
            RedirectState::Active
        } else {
            RedirectState::Inactive
        })
    }

    fn flush_cache(&self) -> Result<(), PlatformError> {
        let out = self.runner.run_powershell(flush_script())?;
        if !out.success {
            return Err(PlatformError::Transient {
                operation: "nrpt.flush_cache",
                detail: format!("Clear-DnsClientCache failed: {}", out.stderr.trim()),
            });
        }
        Ok(())
    }
}

/// Production [`CommandRunner`] over `powershell.exe`. Windows-only; the rest of
/// this module compiles everywhere so the redirect logic stays testable on CI.
#[cfg(target_os = "windows")]
pub struct PowerShellRunner;

#[cfg(target_os = "windows")]
impl CommandRunner for PowerShellRunner {
    fn run_powershell(&self, script: &str) -> Result<CommandOutput, PlatformError> {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW — never flash a console window from the background
        // service. (Not `unsafe`: it is a plain process-creation flag.)
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| PlatformError::Transient {
                operation: "nrpt.powershell.spawn",
                detail: e.to_string(),
            })?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct FakeRunner {
        scripts: Mutex<Vec<String>>,
        output: CommandOutput,
    }
    impl FakeRunner {
        fn new(output: CommandOutput) -> Self {
            Self {
                scripts: Mutex::new(Vec::new()),
                output,
            }
        }
        fn scripts(&self) -> Vec<String> {
            self.scripts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        }
    }
    impl CommandRunner for FakeRunner {
        fn run_powershell(&self, script: &str) -> Result<CommandOutput, PlatformError> {
            self.scripts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(script.to_string());
            Ok(self.output.clone())
        }
    }

    fn ok(stdout: &str) -> CommandOutput {
        CommandOutput {
            success: true,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    fn listener() -> SocketAddr {
        "127.0.0.1:53".parse().unwrap()
    }

    #[test]
    fn capture_upstream_dns_picks_first_routable_v4_skipping_loopback() {
        let runner = FakeRunner::new(ok("127.0.0.1\n192.168.1.1\n8.8.8.8\n"));
        assert_eq!(
            capture_upstream_dns_v4(&runner),
            Some("192.168.1.1".parse().unwrap())
        );
        assert!(runner.scripts()[0].contains("Get-DnsClientServerAddress"));
    }

    #[test]
    fn capture_upstream_dns_none_when_only_loopback_or_junk() {
        let runner = FakeRunner::new(ok("127.0.0.1\n\ngarbage\n0.0.0.0\n"));
        assert_eq!(capture_upstream_dns_v4(&runner), None);
    }

    #[test]
    fn candidates_keep_order_and_drop_repeats() {
        // The script lists the default-route interface first and then every
        // connected one, so the preferred server legitimately appears twice.
        let runner = FakeRunner::new(ok(
            "17 192.168.0.1\n17 0.0.0.0\n17 192.168.0.1\n48 1.1.1.1\n",
        ));
        assert_eq!(
            capture_upstream_dns_candidates_v4(&runner),
            vec![
                UpstreamDnsCandidate::new(Some(17), "192.168.0.1".parse().unwrap()),
                UpstreamDnsCandidate::new(Some(48), "1.1.1.1".parse().unwrap()),
            ],
            "the caller probes down the list, so a repeat would cost a second probe"
        );
    }

    #[test]
    fn a_candidate_line_without_an_interface_column_still_parses() {
        let runner = FakeRunner::new(ok("8.8.8.8\n"));
        assert_eq!(
            capture_upstream_dns_candidates_v4(&runner),
            vec![UpstreamDnsCandidate::new(None, "8.8.8.8".parse().unwrap())],
            "a degraded emitter must not silently yield nothing"
        );
    }

    #[test]
    fn the_candidate_script_excludes_disconnected_adapters_and_still_yields_a_list() {
        let s = upstream_dns_script();
        assert!(
            s.contains("ConnectionState -eq 'Connected'"),
            "a disconnected NIC or an idle Wi-Fi radio keeps stale static DNS"
        );
        assert!(
            s.contains("Sort-Object -Property InterfaceMetric"),
            "at boot there is no default route, so metric order is the only guess left"
        );
        assert!(
            s.contains("$live.Count -eq 0"),
            "no interface query result must not mean no candidates"
        );
    }

    #[test]
    fn add_script_targets_all_names_at_the_listener_with_our_marker() {
        let s = add_script("127.0.0.1", NRPT_MARKER);
        assert!(s.contains("-Namespace '.'"), "catch-all namespace");
        assert!(s.contains("-NameServers '127.0.0.1'"), "points at listener");
        assert!(s.contains(NRPT_MARKER), "carries our marker");
        assert!(s.contains("Add-DnsClientNrptRule"));
        // Idempotent: removes a stale rule of ours before adding.
        assert!(s.contains("Remove-DnsClientNrptRule"));
    }

    #[test]
    fn redirect_runs_add_and_returns_handle() {
        let runner = FakeRunner::new(ok(""));
        let h = NrptDnsRedirect::new(runner)
            .redirect_to(listener())
            .expect("redirect");
        assert_eq!(h.marker, NRPT_MARKER);
        assert_eq!(h.listener, listener());
    }

    #[test]
    fn redirect_maps_command_failure_to_transient() {
        let runner = FakeRunner::new(CommandOutput {
            success: false,
            stdout: String::new(),
            stderr: "Access is denied".into(),
        });
        let err = NrptDnsRedirect::new(runner)
            .redirect_to(listener())
            .unwrap_err();
        assert!(matches!(err, PlatformError::Transient { .. }));
        assert!(format!("{err}").contains("Access is denied"));
    }

    #[test]
    fn restore_runs_remove_by_marker() {
        let runner = FakeRunner::new(ok(""));
        let redir = NrptDnsRedirect::new(runner);
        let handle = RedirectHandle {
            marker: NRPT_MARKER.to_string(),
            listener: listener(),
        };
        redir.restore(&handle).expect("restore");
        let scripts = redir.runner.scripts();
        assert_eq!(scripts.len(), 1);
        assert!(scripts[0].contains("Remove-DnsClientNrptRule"));
        assert!(scripts[0].contains(NRPT_MARKER));
    }

    #[test]
    fn verify_reads_marker_presence_from_stdout() {
        let handle = RedirectHandle {
            marker: NRPT_MARKER.to_string(),
            listener: listener(),
        };
        // Rule present → Active.
        let active = NrptDnsRedirect::new(FakeRunner::new(ok(NRPT_MARKER)))
            .verify(&handle)
            .expect("verify");
        assert_eq!(active, RedirectState::Active);
        // Empty stdout → Inactive.
        let inactive = NrptDnsRedirect::new(FakeRunner::new(ok("")))
            .verify(&handle)
            .expect("verify");
        assert_eq!(inactive, RedirectState::Inactive);
    }
}
