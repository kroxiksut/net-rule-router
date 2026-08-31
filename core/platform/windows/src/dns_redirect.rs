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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use nrr_platform_api::adapters::names_indicate_virtual_machine_network;
use nrr_platform_api::dns::UpstreamDnsCandidate;
use nrr_platform_api::fake_ip::FakeIpPoolConfig;

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

/// Remove every NRPT rule carrying our marker (restore to prior state) and
/// echo how many there were. The count is what lets the boot sweep report
/// whether it healed anything — a silent sweep leaves the next crash analysis
/// unable to tell "nothing to clean" from "never ran".
fn remove_script(marker: &str) -> String {
    format!(
        "$r = @(Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{marker}' }}); \
         $r | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force }}; \
         $r.Count"
    )
}

/// Parse the trailing count [`remove_script`] echoes. An unreadable answer
/// means "removed something, count unknown" rather than an error: the removal
/// itself already succeeded.
fn removed_count(stdout: &str) -> usize {
    stdout
        .lines()
        .rev()
        .find_map(|line| line.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

/// Flush the Windows DNS client cache so warm entries re-resolve through the
/// freshly-installed (or freshly-removed) redirect.
fn flush_script() -> &'static str {
    "Clear-DnsClientCache"
}

/// PowerShell listing candidate upstream IPv4 DNS servers as tab-separated
/// `<ifIndex> <server> <adapter description> <adapter name>` lines. Emits the
/// DNS server(s) of the interface that owns the DEFAULT ROUTE (the active
/// egress, lowest route metric) FIRST, then the servers of every CONNECTED
/// interface as a fallback. The interface column lets the caller prefer the link
/// its routing policy uses.
///
/// It rejects nothing on its own: WHICH of these is a resolver we may forward to
/// is a policy question, and it is decided in Rust by [`is_usable_upstream`],
/// against the same adapter classifier the kill-switch and the traffic counter
/// use. The two name columns exist for exactly that — a filter spelled here
/// would be a second, invisible definition of "adapter we ignore".
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
       $a = Get-NetAdapter -InterfaceIndex $i -IncludeHidden | Select-Object -First 1; \
       Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4 | \
       Select-Object -ExpandProperty ServerAddresses | \
       Where-Object { $_ } | \
       ForEach-Object { \"$i`t$_`t$($a.InterfaceDescription)`t$($a.Name)\" } \
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
        let Some(parsed) = parse_candidate_line(line) else {
            continue;
        };
        if !is_usable_upstream(&parsed) {
            continue;
        }
        if !seen.iter().any(|c| c.server == parsed.server) {
            seen.push(UpstreamDnsCandidate::new(parsed.index, parsed.server));
        }
    }
    seen
}

/// One emitted candidate line, split into its columns.
struct CandidateLine<'a> {
    index: Option<u32>,
    server: Ipv4Addr,
    description: &'a str,
    friendly_name: &'a str,
}

/// `"17\t192.168.0.1\tIntel(R) I219-V\tEthernet"` → columns. A bare address, or
/// the older space-separated `<index> <addr>` shape, still parses (with no
/// names), so a degraded emitter never silently yields nothing.
fn parse_candidate_line(line: &str) -> Option<CandidateLine<'_>> {
    let mut columns = line.trim_end().split('\t');
    let head = columns.next()?.trim();
    let (index, addr) = match columns.next() {
        Some(addr) => (head.parse::<u32>().ok(), addr.trim()),
        None => match head.split_once(char::is_whitespace) {
            Some((idx, rest)) => (idx.trim().parse::<u32>().ok(), rest.trim()),
            None => (None, head),
        },
    };
    Some(CandidateLine {
        index,
        server: addr.parse::<Ipv4Addr>().ok()?,
        description: columns.next().unwrap_or_default().trim(),
        friendly_name: columns.next().unwrap_or_default().trim(),
    })
}

/// Whether this line names a resolver we may actually forward to.
///
/// Three ways it is not. The address is not routable. The address comes out of
/// our own fake-IP pool — our TUN carries the lowest interface metric on the
/// box, so it heads this very list, and forwarding there points the resolver at
/// itself. Or the adapter is a hypervisor's host-only / NAT network, whose DNS
/// answers its guests and black-holes everything else: a NAT adapter that has
/// been given a resolver looks exactly like a live link here, and every query
/// then burns a probe timeout.
///
/// Names we could not read leave the gate open — an unprobed candidate beats no
/// candidate, and the caller probes. Dropping the last real upstream would cost
/// general name resolution, which is the worse failure by far.
fn is_usable_upstream(line: &CandidateLine<'_>) -> bool {
    let server = line.server;
    if server.is_loopback() || server.is_unspecified() || server.is_broadcast() {
        return false;
    }
    if FakeIpPoolConfig::is_default_pool_addr(IpAddr::V4(server)) {
        return false;
    }
    !names_indicate_virtual_machine_network(line.description, line.friendly_name)
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
pub fn clear_orphan_redirect<R: CommandRunner>(runner: &R) -> Result<usize, PlatformError> {
    let out = runner.run_powershell(&remove_script(NRPT_MARKER))?;
    if !out.success {
        return Err(PlatformError::Transient {
            operation: "nrpt.clear_orphan",
            detail: format!("orphan NRPT cleanup failed: {}", out.stderr.trim()),
        });
    }
    Ok(removed_count(&out.stdout))
}

/// Echo the namespace our redirect governs iff the OS is ACTUALLY resolving
/// through `listener_ip` (empty stdout otherwise).
///
/// Reads `Get-DnsClientNrptPolicy` — the table in force — and deliberately not
/// `Get-DnsClientNrptRule`, which reads back the very configuration we just
/// wrote and therefore can only ever answer "present", never "in effect".
/// Windows accepts the write and evaluates the table afterwards; a rule it
/// rejects stays listed as configured, and the rejection surfaces nowhere except
/// a DNS-Client event.
fn effective_policy_script(listener_ip: &str) -> String {
    format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         Get-DnsClientNrptPolicy | \
         Where-Object {{ $_.NameServers -contains '{listener_ip}' }} | \
         Select-Object -First 1 -ExpandProperty Namespace"
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
        let handle = RedirectHandle {
            marker: NRPT_MARKER.to_string(),
            listener,
        };
        // The cmdlet exiting 0 says the rule was WRITTEN, not that the OS honours
        // it. Confirm against the table in force, and take a rejected rule back
        // out: left in place it buys nothing and leaves the DNS client holding a
        // policy it refuses, while the resolver above believes Mode B is armed.
        match self.verify(&handle) {
            Ok(RedirectState::Active) => Ok(handle),
            Ok(RedirectState::Inactive) => {
                let _ = self.runner.run_powershell(&remove_script(NRPT_MARKER));
                Err(PlatformError::Transient {
                    operation: "nrpt.redirect_to",
                    detail: "NRPT rule was written but is absent from the policy table \
                             Windows is using; the rule was withdrawn and system DNS \
                             left untouched"
                        .to_string(),
                })
            }
            // Could not ask. Keep the redirect rather than tear down a working
            // one: an unreadable answer is not a rejection, and treating it as
            // one would disable Mode B wherever the query is unavailable.
            Err(error) => {
                tracing::warn!(
                    target: "nrr::dns-redirect",
                    "NRPT redirect installed but could not be confirmed against the \
                     effective policy table ({error}); proceeding as armed",
                );
                Ok(handle)
            }
        }
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
        let ip = handle.listener.ip().to_string();
        let out = self.runner.run_powershell(&effective_policy_script(&ip))?;
        // A query that did not run answers nothing — reporting that as `Inactive`
        // would make "we could not look" indistinguishable from "the OS is not
        // using it", which is the exact conflation this method exists to end.
        if !out.success {
            return Err(PlatformError::Transient {
                operation: "nrpt.verify",
                detail: format!("NRPT policy query failed: {}", out.stderr.trim()),
            });
        }
        Ok(if out.stdout.trim().is_empty() {
            RedirectState::Inactive
        } else {
            RedirectState::Active
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

/// Longest one NRPT cmdlet may take before it is given up on and killed.
///
/// Generous on purpose: a cold `powershell.exe` plus the WMI round-trip these
/// cmdlets make is seconds, not milliseconds, and killing a healthy-but-slow
/// call would leave the redirect half-applied. Bounded all the same — every
/// caller here is a boot step, a stop step or a recovery command, and each of
/// them turns an unbounded wait into the failure it is trying to prevent.
#[cfg(target_os = "windows")]
const POWERSHELL_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// How often the spawned process is checked while waiting.
#[cfg(target_os = "windows")]
const POWERSHELL_POLL: std::time::Duration = std::time::Duration::from_millis(50);

#[cfg(target_os = "windows")]
impl CommandRunner for PowerShellRunner {
    fn run_powershell(&self, script: &str) -> Result<CommandOutput, PlatformError> {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW — never flash a console window from the background
        // service. (Not `unsafe`: it is a plain process-creation flag.)
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        // Spawned rather than `output()`ed: `output()` waits forever, and every
        // caller of this runner is a boot step, a stop step or a recovery
        // command. A `powershell.exe` that never returns would hang the very
        // paths that exist to unstick a machine.
        let mut child = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| PlatformError::Transient {
                operation: "nrpt.powershell.spawn",
                detail: e.to_string(),
            })?;

        // Polling rather than draining the pipes concurrently: every script in
        // this module answers with a marker or a count, far below the pipe
        // buffer, so the child cannot block on a full pipe while we wait.
        let deadline = std::time::Instant::now() + POWERSHELL_BUDGET;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(PlatformError::Transient {
                        operation: "nrpt.powershell.timeout",
                        detail: format!(
                            "powershell did not answer within {:?}; the call was killed",
                            POWERSHELL_BUDGET
                        ),
                    });
                }
                Ok(None) => std::thread::sleep(POWERSHELL_POLL),
                Err(e) => {
                    let _ = child.kill();
                    return Err(PlatformError::Transient {
                        operation: "nrpt.powershell.wait",
                        detail: e.to_string(),
                    });
                }
            }
        }

        let output = child
            .wait_with_output()
            .map_err(|e| PlatformError::Transient {
                operation: "nrpt.powershell.output",
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

    /// Answers each script separately: the first rule whose needle the script
    /// contains wins, else `default`. Keyed on CONTENT rather than call order,
    /// so reordering the calls cannot make a test pass for the wrong reason.
    struct ScriptedRunner {
        rules: Vec<(&'static str, CommandOutput)>,
        default: CommandOutput,
        scripts: Mutex<Vec<String>>,
    }
    impl ScriptedRunner {
        fn new(rules: Vec<(&'static str, CommandOutput)>) -> Self {
            Self {
                rules,
                default: ok(""),
                scripts: Mutex::new(Vec::new()),
            }
        }
        fn scripts(&self) -> Vec<String> {
            self.scripts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        }
    }
    impl CommandRunner for ScriptedRunner {
        fn run_powershell(&self, script: &str) -> Result<CommandOutput, PlatformError> {
            self.scripts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(script.to_string());
            Ok(self
                .rules
                .iter()
                .find(|(needle, _)| script.contains(needle))
                .map_or_else(|| self.default.clone(), |(_, out)| out.clone()))
        }
    }

    /// A runner whose add succeeds and whose effective-policy query reports the
    /// catch-all in force — the ordinary, accepted case.
    fn accepting_runner() -> ScriptedRunner {
        ScriptedRunner::new(vec![("Get-DnsClientNrptPolicy", ok(".\n"))])
    }

    /// How many scripts are a STANDALONE withdrawal. `add_script` names the same
    /// cmdlet to clear a stale rule of ours before adding, so a bare "mentions
    /// Remove-DnsClientNrptRule" would be true of every redirect ever attempted.
    fn withdrawals(scripts: &[String]) -> usize {
        scripts
            .iter()
            .filter(|s| {
                s.contains("Remove-DnsClientNrptRule") && !s.contains("Add-DnsClientNrptRule")
            })
            .count()
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
        let redirect = NrptDnsRedirect::new(accepting_runner());
        let h = redirect.redirect_to(listener()).expect("redirect");
        assert_eq!(h.marker, NRPT_MARKER);
        assert_eq!(h.listener, listener());
        let scripts = redirect.runner.scripts();
        assert!(scripts[0].contains("Add-DnsClientNrptRule"));
        assert!(
            scripts[1].contains("Get-DnsClientNrptPolicy"),
            "a successful add must still be confirmed against the table in force"
        );
    }

    #[test]
    fn redirect_withdraws_a_rule_the_os_does_not_honour() {
        // Add reports success (the rule IS written), the effective table comes
        // back empty: Windows evaluated the rule and refused it.
        let redirect = NrptDnsRedirect::new(ScriptedRunner::new(vec![(
            "Get-DnsClientNrptPolicy",
            ok("   \n"),
        )]));
        let err = redirect.redirect_to(listener()).unwrap_err();
        assert!(matches!(err, PlatformError::Transient { .. }));
        assert_eq!(
            withdrawals(&redirect.runner.scripts()),
            1,
            "a rule the OS refuses must not be left behind for the next boot to trip over"
        );
    }

    #[test]
    fn redirect_survives_an_unreadable_policy_table() {
        // The query itself failed. That is not a rejection, and treating it as
        // one would disable Mode B on every host where the cmdlet is missing.
        let redirect = NrptDnsRedirect::new(ScriptedRunner::new(vec![(
            "Get-DnsClientNrptPolicy",
            CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "cmdlet not found".into(),
            },
        )]));
        redirect
            .redirect_to(listener())
            .expect("an unreadable answer must not tear down a working redirect");
        assert_eq!(
            withdrawals(&redirect.runner.scripts()),
            0,
            "nothing was refused, so nothing may be withdrawn"
        );
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
    fn clear_orphan_reports_how_many_rules_it_removed() {
        let runner = FakeRunner::new(ok("2
"));
        assert_eq!(clear_orphan_redirect(&runner).expect("clear"), 2);
        // Nothing to clean is a successful sweep of zero, not a failure.
        let empty = FakeRunner::new(ok("0"));
        assert_eq!(clear_orphan_redirect(&empty).expect("clear"), 0);
        // An answer we cannot parse still means the removal itself succeeded.
        let noisy = FakeRunner::new(ok("WARNING: something
"));
        assert_eq!(clear_orphan_redirect(&noisy).expect("clear"), 0);
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
    fn verify_asks_the_effective_policy_table_not_our_own_write() {
        let handle = RedirectHandle {
            marker: NRPT_MARKER.to_string(),
            listener: listener(),
        };
        let redirect = NrptDnsRedirect::new(FakeRunner::new(ok(".\n")));
        assert_eq!(
            redirect.verify(&handle).expect("verify"),
            RedirectState::Active
        );
        let script = &redirect.runner.scripts()[0];
        assert!(
            script.contains("Get-DnsClientNrptPolicy"),
            "reading back our own configuration can only answer 'present'"
        );
        assert!(
            !script.contains("Get-DnsClientNrptRule"),
            "the configured table is the wrong source for 'is it in effect'"
        );
        assert!(
            script.contains("127.0.0.1"),
            "the redirect is ours only if the policy points at OUR listener"
        );

        // Nothing in force → Inactive.
        assert_eq!(
            NrptDnsRedirect::new(FakeRunner::new(ok("")))
                .verify(&handle)
                .expect("verify"),
            RedirectState::Inactive
        );

        // A query that could not run is an error, not "Inactive".
        assert!(NrptDnsRedirect::new(FakeRunner::new(CommandOutput {
            success: false,
            stdout: String::new(),
            stderr: "denied".into(),
        }))
        .verify(&handle)
        .is_err());
    }

    #[test]
    fn upstream_candidates_drop_hypervisor_networks_and_our_own_pool() {
        let runner = FakeRunner::new(ok(concat!(
            "16\t192.168.0.1\tIntel(R) Ethernet Connection (2) I219-V\tEthernet\n",
            "24\t1.1.1.1\tTAP-Windows Adapter V9\thidemy.name VPN OpenVPN Adapter\n",
            "4\t192.168.140.2\tVMware Virtual Ethernet Adapter for VMnet8\tVMware Network Adapter VMnet8\n",
            "28\t172.20.80.1\tHyper-V Virtual Ethernet Adapter\tvEthernet (Default Switch)\n",
            "14\t192.168.56.1\tVirtualBox Host-Only Ethernet Adapter\tVirtualBox Host-Only Network\n",
            "57\t198.18.0.1\tNetRuleRouter Tunnel\tNetRuleRouter\n",
        )));
        assert_eq!(
            capture_upstream_dns_candidates_v4(&runner),
            vec![
                UpstreamDnsCandidate::new(Some(16), "192.168.0.1".parse().unwrap()),
                UpstreamDnsCandidate::new(Some(24), "1.1.1.1".parse().unwrap()),
            ],
            "a hypervisor's NAT/host-only resolver answers its guests and black-holes \
             us; our own TUN would point the resolver at itself; a VPN's resolver is \
             a legitimate upstream and must survive"
        );
    }

    #[test]
    fn an_unnamed_adapter_still_yields_its_candidate() {
        // Names we could not read must not cost us the last real upstream.
        let runner = FakeRunner::new(ok("16\t192.168.0.1\t\t\n"));
        assert_eq!(
            capture_upstream_dns_candidates_v4(&runner),
            vec![UpstreamDnsCandidate::new(
                Some(16),
                "192.168.0.1".parse().unwrap()
            )]
        );
    }
}
