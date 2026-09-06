//! System DNS redirect port.
//!
//! Points the OS resolver at NetRuleRouter's loopback DNS listener so rule-host
//! queries transit our resolver (`EnforcementMode::Resolver`), and restores the
//! prior configuration cleanly on stop / crash. This is the genuinely
//! OS-specific half of Mode B — the listener and the rule-host policy are
//! neutral. Per the policy/mechanism seam it sits behind the
//! [`SystemDnsRedirectPort`] trait, with per-OS impls:
//!
//! - **Windows** — NRPT (Name Resolution Policy Table). NRPT routes a namespace
//!   (here `.`, i.e. all names) to our loopback resolver without touching
//!   per-adapter DNS, and is cleanly reversible — preferred over rewriting
//!   adapter DNS servers. The rule is written straight into the registry inside
//!   one transaction ([`NrptRuleStore`]): the DNS client re-reads the table on
//!   every change and rejects a half-written rule — with the whole table — so
//!   the seven values must land at once. Only the read of the table *in force*
//!   still goes through PowerShell ([`CommandRunner`]); it has no registry form.
//! - **Linux / macOS** — systemd-resolved / `resolv.conf`, `scutil` (future).
//!
//! Both mechanisms sit behind traits with fakes, so the redirect / restore /
//! verify logic keeps its tests on any host; only the thin Windows-gated
//! [`PowerShellRunner`] and [`TransactedNrptStore`] touch the OS.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use nrr_platform_api::adapters::names_indicate_virtual_machine_network;
use nrr_platform_api::dns::{DnsCacheControlPort, UpstreamDnsCandidate};
// The flush is a real API call on Windows; other hosts, where only the
// fake-backed tests of this module run, get the no-op.
#[cfg(not(target_os = "windows"))]
use nrr_platform_api::dns::NoopDnsCacheControl as DefaultDnsCacheControl;
use nrr_platform_api::fake_ip::FakeIpPoolConfig;

#[cfg(target_os = "windows")]
use crate::dns::WindowsDnsCacheControl as DefaultDnsCacheControl;
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

/// Registry key of OUR rule under `DnsPolicyConfig`. Fixed for the product's
/// lifetime, like the marker: the rule is created and replaced in place, and
/// the sweep can name it without a scan.
const NRPT_RULE_KEY: &str = "{5E0C2A17-8B3D-4F61-9C4A-2D7E6F1B0A93}";

/// `ConfigOptions` bit: the rule carries generic DNS servers.
const NRPT_CONFIG_GENERIC_DNS_SERVERS: u32 = 0x8;

/// Rule schema the Windows 8+ DNS client reads.
const NRPT_RULE_VERSION: u32 = 2;

/// The three storage kinds the DNS client's rule schema uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryValueKind {
    Sz,
    MultiSz,
    Dword,
}

/// One registry value of an NRPT rule, bytes exactly as the DNS client reads
/// them (UTF-16LE with the terminators the kind demands; little-endian DWORD).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryValue {
    pub name: &'static str,
    pub kind: RegistryValueKind,
    pub data: Vec<u8>,
}

fn utf16_bytes(text: &str, terminators: usize) -> Vec<u8> {
    text.encode_utf16()
        .chain(std::iter::repeat_n(0, terminators))
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn sz(name: &'static str, text: &str) -> RegistryValue {
    RegistryValue {
        name,
        kind: RegistryValueKind::Sz,
        data: utf16_bytes(text, 1),
    }
}

/// A one-entry `REG_MULTI_SZ`: the entry's terminator plus the list's.
fn multi_sz(name: &'static str, text: &str) -> RegistryValue {
    RegistryValue {
        name,
        kind: RegistryValueKind::MultiSz,
        data: utf16_bytes(text, 2),
    }
}

fn dword(name: &'static str, value: u32) -> RegistryValue {
    RegistryValue {
        name,
        kind: RegistryValueKind::Dword,
        data: value.to_le_bytes().to_vec(),
    }
}

/// The seven values of a catch-all rule sending every name (`.`) to
/// `listener_ip` — the exact set `Add-DnsClientNrptRule` writes. Any subset
/// is a rule the DNS client rejects, and it rejects the whole table with it.
pub fn nrpt_rule_values(listener_ip: &str, marker: &str) -> Vec<RegistryValue> {
    vec![
        sz("Comment", marker),
        sz("DisplayName", ""),
        sz("IPSECCARestriction", ""),
        multi_sz("Name", "."),
        sz("GenericDNSServers", listener_ip),
        dword("ConfigOptions", NRPT_CONFIG_GENERIC_DNS_SERVERS),
        dword("Version", NRPT_RULE_VERSION),
    ]
}

/// What a scan of the rule table found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NrptTableScan {
    /// Our rule is under its key with every expected value, byte for byte.
    pub ours_intact: bool,
    /// Rules without a `Version` — left by a writer that died mid-rule. The DNS
    /// client rejects the whole table over one of these.
    pub damaged: usize,
}

/// The rule table itself — the registry on Windows, a map in tests.
///
/// A write is atomic: the DNS client re-reads the table on every change and a
/// rule must appear whole or not at all.
pub trait NrptRuleStore: Send + Sync {
    /// Create or replace the rule under `key` with exactly `values`.
    fn write_rule(&self, key: &str, values: &[RegistryValue]) -> Result<(), PlatformError>;
    /// Delete the rule under `key`; `Ok(false)` when there was none.
    fn delete_rule(&self, key: &str) -> Result<bool, PlatformError>;
    /// Check our rule under `key` against `expected` and count damaged rules.
    fn scan(&self, key: &str, expected: &[RegistryValue]) -> Result<NrptTableScan, PlatformError>;
    /// Delete what must not be there: every rule without a `Version`, and every
    /// rule carrying `marker` under a key other than `keep` (copies from before
    /// the key was fixed). Returns how many went.
    fn sweep_orphans(&self, marker: &str, keep: &str) -> Result<usize, PlatformError>;
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
/// breaks all name resolution — plus the debris that breaks it another way: a
/// half-written rule makes the DNS client reject the whole table. Safe to call
/// unconditionally at EVERY boot, regardless of the current enforcement mode.
/// Never touches a VPN client's or an admin's own rule. Returns how many rules
/// went, so the boot log can tell "nothing to clean" from "never ran".
pub fn clear_orphan_redirect<S: NrptRuleStore>(store: &S) -> Result<usize, PlatformError> {
    let own = usize::from(store.delete_rule(NRPT_RULE_KEY)?);
    Ok(own + store.sweep_orphans(NRPT_MARKER, "")?)
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
/// rule store and the [`CommandRunner`] so the redirect/restore/verify flow is
/// testable with fakes. Production wires [`TransactedNrptStore`] and
/// [`PowerShellRunner`].
pub struct NrptDnsRedirect<R: CommandRunner, S: NrptRuleStore> {
    runner: R,
    store: S,
    /// The cache flush, which is an API call rather than a script. It sits
    /// behind the port because the same flush is wanted from elsewhere in the
    /// service, and two ways to flush one cache is how they drift apart.
    cache: Arc<dyn DnsCacheControlPort>,
}

impl<R: CommandRunner, S: NrptRuleStore> NrptDnsRedirect<R, S> {
    pub fn new(runner: R, store: S) -> Self {
        Self::with_cache_control(runner, store, Arc::new(DefaultDnsCacheControl))
    }

    /// Same, with the cache flush injected — tests use it to observe the flush
    /// without touching the machine's resolver cache.
    pub fn with_cache_control(runner: R, store: S, cache: Arc<dyn DnsCacheControlPort>) -> Self {
        Self {
            runner,
            store,
            cache,
        }
    }
}

impl<R: CommandRunner, S: NrptRuleStore> SystemDnsRedirectPort for NrptDnsRedirect<R, S> {
    fn redirect_to(&self, listener: SocketAddr) -> Result<RedirectHandle, PlatformError> {
        let ip = listener.ip().to_string();
        // Debris first: a half-written rule, ours or anyone's, makes the DNS
        // client reject the table our rule is about to join.
        let swept = self.store.sweep_orphans(NRPT_MARKER, NRPT_RULE_KEY)?;
        if swept > 0 {
            tracing::warn!(
                target: "nrr::dns-redirect",
                swept,
                "removed NRPT rules that would have had the DNS client reject the whole table",
            );
        }
        self.store
            .write_rule(NRPT_RULE_KEY, &nrpt_rule_values(&ip, NRPT_MARKER))?;
        let handle = RedirectHandle {
            marker: NRPT_MARKER.to_string(),
            listener,
        };
        // Written is not honoured. Confirm against the table in force, and take
        // a rejected rule back out: left in place it buys nothing and leaves
        // the DNS client holding a policy it refuses, while the resolver above
        // believes Mode B is armed.
        match self.verify(&handle) {
            Ok(RedirectState::Active) => Ok(handle),
            Ok(RedirectState::Inactive) => {
                let _ = self.store.delete_rule(NRPT_RULE_KEY);
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

    fn restore(&self, _handle: &RedirectHandle) -> Result<(), PlatformError> {
        self.store.delete_rule(NRPT_RULE_KEY).map(drop)
    }

    fn inspect(&self, handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
        let ip = handle.listener.ip().to_string();
        let scan = self
            .store
            .scan(NRPT_RULE_KEY, &nrpt_rule_values(&ip, &handle.marker))?;
        Ok(if scan.ours_intact && scan.damaged == 0 {
            RedirectState::Active
        } else {
            RedirectState::Inactive
        })
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
        // `DnsFlushResolverCache`, not `Clear-DnsClientCache` through
        // PowerShell. This runs inside the service teardown, where it was the
        // only step that spawned a process — and the one that made the stop
        // budget a question at all: the NRPT restore beside it is a single
        // registry delete. The API call is the same flush without the process.
        self.cache
            .flush_resolver_cache()
            .map_err(|error| PlatformError::Transient {
                operation: "nrpt.flush_cache",
                detail: format!("resolver cache flush failed: {error:?}"),
            })
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
        let mut child = std::process::Command::new(crate::system_shell::system_powershell())
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

#[cfg(target_os = "windows")]
pub use transacted::TransactedNrptStore;

/// The registry mechanism behind [`NrptRuleStore`].
///
/// A rule is written inside one kernel transaction (KTM): the DNS client, which
/// re-reads `DnsPolicyConfig` on every change, sees the rule appear whole at
/// commit and never a half-written one. Measured on the machine that reported
/// the problem: seven separate value writes drew seven "policy table corrupt"
/// events, one transaction held open for a second and a half drew none.
#[cfg(target_os = "windows")]
mod transacted {
    #![allow(unsafe_code)]

    use super::{NrptTableScan, RegistryValue, RegistryValueKind};
    use crate::error::PlatformError;
    use windows::core::{HSTRING, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, HANDLE, WIN32_ERROR,
    };
    use windows::Win32::Storage::FileSystem::{
        CommitTransaction, CreateTransaction, RollbackTransaction,
    };
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyTransactedW, RegDeleteTreeW, RegEnumKeyExW, RegOpenKeyExW,
        RegQueryValueExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD,
        REG_MULTI_SZ, REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE,
    };

    /// Where the DNS client keeps locally configured rules.
    const TABLE: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

    /// Rule keys are GUID strings; anything longer is not a rule.
    const MAX_KEY_NAME: usize = 256;

    #[derive(Debug, Default, Clone, Copy)]
    pub struct TransactedNrptStore;

    fn win32(operation: &'static str, code: WIN32_ERROR) -> PlatformError {
        PlatformError::Transient {
            operation,
            detail: format!("win32 error {}", code.0),
        }
    }

    fn rule_path(key: &str) -> HSTRING {
        HSTRING::from(format!("{TABLE}\\{key}"))
    }

    /// An open registry key, closed on drop.
    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful open/create and is
            // closed exactly once, here.
            let _ = unsafe { RegCloseKey(self.0) };
        }
    }

    /// `None` when the key does not exist.
    fn open(path: &HSTRING, operation: &'static str) -> Result<Option<Key>, PlatformError> {
        let mut hkey = HKEY::default();
        // SAFETY: `path` is a valid NUL-terminated wide string and `hkey` a
        // valid out-pointer for the call's duration.
        let code = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &mut hkey) };
        match code {
            ERROR_SUCCESS => Ok(Some(Key(hkey))),
            ERROR_FILE_NOT_FOUND => Ok(None),
            other => Err(win32(operation, other)),
        }
    }

    fn subkeys(table: &Key) -> Result<Vec<String>, PlatformError> {
        let mut names = Vec::new();
        let mut buf = [0u16; MAX_KEY_NAME];
        for index in 0.. {
            let mut len = buf.len() as u32;
            // SAFETY: `buf` outlives the call, `len` reports its capacity in
            // characters and receives the name length.
            let code = unsafe {
                RegEnumKeyExW(
                    table.0,
                    index,
                    PWSTR::from_raw(buf.as_mut_ptr()),
                    &mut len,
                    None,
                    PWSTR::null(),
                    None,
                    None,
                )
            };
            match code {
                ERROR_SUCCESS => names.push(String::from_utf16_lossy(&buf[..len as usize])),
                ERROR_NO_MORE_ITEMS => break,
                other => return Err(win32("nrpt.enumerate", other)),
            }
        }
        Ok(names)
    }

    /// `None` when the value does not exist.
    fn read_value(
        key: &Key,
        name: &str,
    ) -> Result<Option<(REG_VALUE_TYPE, Vec<u8>)>, PlatformError> {
        let name = HSTRING::from(name);
        let mut kind = REG_VALUE_TYPE::default();
        let mut size = 0u32;
        // SAFETY: a size query — no data pointer, `size` receives the length.
        let code =
            unsafe { RegQueryValueExW(key.0, &name, None, Some(&mut kind), None, Some(&mut size)) };
        match code {
            ERROR_SUCCESS => {}
            ERROR_FILE_NOT_FOUND => return Ok(None),
            other => return Err(win32("nrpt.read_value", other)),
        }
        let mut data = vec![0u8; size as usize];
        // SAFETY: `data` holds exactly the `size` bytes the query reported.
        let code = unsafe {
            RegQueryValueExW(
                key.0,
                &name,
                None,
                Some(&mut kind),
                Some(data.as_mut_ptr()),
                Some(&mut size),
            )
        };
        match code {
            ERROR_SUCCESS => {
                data.truncate(size as usize);
                Ok(Some((kind, data)))
            }
            ERROR_FILE_NOT_FOUND => Ok(None),
            other => Err(win32("nrpt.read_value", other)),
        }
    }

    fn kind_of(value: &RegistryValue) -> REG_VALUE_TYPE {
        match value.kind {
            RegistryValueKind::Sz => REG_SZ,
            RegistryValueKind::MultiSz => REG_MULTI_SZ,
            RegistryValueKind::Dword => REG_DWORD,
        }
    }

    fn holds(key: &Key, expected: &RegistryValue) -> Result<bool, PlatformError> {
        Ok(read_value(key, expected.name)?
            .is_some_and(|(kind, data)| kind == kind_of(expected) && data == expected.data))
    }

    fn delete_tree(path: &HSTRING) -> Result<bool, PlatformError> {
        // SAFETY: `path` is a valid NUL-terminated wide string.
        match unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, path) } {
            ERROR_SUCCESS => Ok(true),
            ERROR_FILE_NOT_FOUND => Ok(false),
            other => Err(win32("nrpt.delete_rule", other)),
        }
    }

    /// A kernel transaction, rolled back on drop unless committed.
    struct Transaction(HANDLE);

    impl Transaction {
        fn begin() -> Result<Self, PlatformError> {
            // SAFETY: every pointer argument is documented optional (null) and
            // the description may be null.
            let handle = unsafe {
                CreateTransaction(
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    0,
                    0,
                    0,
                    0,
                    PCWSTR::null(),
                )
            }
            .map_err(|e| PlatformError::Transient {
                operation: "nrpt.transaction.begin",
                detail: e.to_string(),
            })?;
            Ok(Self(handle))
        }

        fn commit(self) -> Result<(), PlatformError> {
            // SAFETY: the handle is a live transaction owned by `self`.
            let result = unsafe { CommitTransaction(self.0) };
            let handle = self.0;
            std::mem::forget(self);
            // SAFETY: closed exactly once, after the commit attempt.
            let _ = unsafe { CloseHandle(handle) };
            result.map_err(|e| PlatformError::Transient {
                operation: "nrpt.transaction.commit",
                detail: e.to_string(),
            })
        }
    }

    impl Drop for Transaction {
        fn drop(&mut self) {
            // SAFETY: an uncommitted live transaction; rolling back releases
            // every change made under it, then the handle is closed once.
            unsafe {
                let _ = RollbackTransaction(self.0);
                let _ = CloseHandle(self.0);
            }
        }
    }

    impl super::NrptRuleStore for TransactedNrptStore {
        fn write_rule(&self, key: &str, values: &[RegistryValue]) -> Result<(), PlatformError> {
            let tx = Transaction::begin()?;
            let mut hkey = HKEY::default();
            // SAFETY: the path is a valid wide string, `hkey` a valid
            // out-pointer, the transaction handle live for the call.
            let code = unsafe {
                RegCreateKeyTransactedW(
                    HKEY_LOCAL_MACHINE,
                    &rule_path(key),
                    0,
                    PCWSTR::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_WRITE,
                    None,
                    &mut hkey,
                    None,
                    tx.0,
                    None,
                )
            };
            if code != ERROR_SUCCESS {
                return Err(win32("nrpt.write_rule", code));
            }
            let rule = Key(hkey);
            for value in values {
                // SAFETY: `rule` is open for writing under the transaction; the
                // data slice outlives the call.
                let code = unsafe {
                    RegSetValueExW(
                        rule.0,
                        &HSTRING::from(value.name),
                        0,
                        kind_of(value),
                        Some(&value.data),
                    )
                };
                if code != ERROR_SUCCESS {
                    return Err(win32("nrpt.write_rule", code));
                }
            }
            // The key must be closed before the commit, or the commit sees an
            // open handle on the transacted key.
            drop(rule);
            tx.commit()
        }

        fn delete_rule(&self, key: &str) -> Result<bool, PlatformError> {
            delete_tree(&rule_path(key))
        }

        fn scan(
            &self,
            key: &str,
            expected: &[RegistryValue],
        ) -> Result<NrptTableScan, PlatformError> {
            let Some(table) = open(&HSTRING::from(TABLE), "nrpt.scan")? else {
                return Ok(NrptTableScan::default());
            };
            let mut scan = NrptTableScan::default();
            for name in subkeys(&table)? {
                let Some(rule) = open(&rule_path(&name), "nrpt.scan")? else {
                    continue;
                };
                if name.eq_ignore_ascii_case(key) {
                    let mut intact = true;
                    for value in expected {
                        intact &= holds(&rule, value)?;
                    }
                    scan.ours_intact = intact;
                } else if read_value(&rule, "Version")?.is_none() {
                    scan.damaged += 1;
                }
            }
            Ok(scan)
        }

        fn sweep_orphans(&self, marker: &str, keep: &str) -> Result<usize, PlatformError> {
            let Some(table) = open(&HSTRING::from(TABLE), "nrpt.sweep")? else {
                return Ok(0);
            };
            let ours = super::sz("Comment", marker);
            let mut removed = 0;
            for name in subkeys(&table)? {
                let path = rule_path(&name);
                let Some(rule) = open(&path, "nrpt.sweep")? else {
                    continue;
                };
                let half_written = read_value(&rule, "Version")?.is_none();
                let stale_copy = !name.eq_ignore_ascii_case(keep) && holds(&rule, &ours)?;
                drop(rule);
                if (half_written || stale_copy) && delete_tree(&path)? {
                    removed += 1;
                }
            }
            Ok(removed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// The rule table as a map; the same rules the registry store applies.
    #[derive(Default)]
    struct FakeStore {
        rules: Mutex<BTreeMap<String, Vec<RegistryValue>>>,
        writes: Mutex<Vec<String>>,
    }
    impl FakeStore {
        fn with(rules: &[(&str, Vec<RegistryValue>)]) -> Self {
            let store = Self::default();
            for (key, values) in rules {
                store
                    .rules
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert((*key).to_string(), values.clone());
            }
            store
        }
        fn keys(&self) -> Vec<String> {
            self.rules
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .keys()
                .cloned()
                .collect()
        }
        fn writes(&self) -> Vec<String> {
            self.writes
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        }
    }
    fn has(values: &[RegistryValue], expected: &RegistryValue) -> bool {
        values.iter().any(|v| v == expected)
    }
    impl NrptRuleStore for FakeStore {
        fn write_rule(&self, key: &str, values: &[RegistryValue]) -> Result<(), PlatformError> {
            self.writes
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(key.to_string());
            self.rules
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(key.to_string(), values.to_vec());
            Ok(())
        }
        fn delete_rule(&self, key: &str) -> Result<bool, PlatformError> {
            Ok(self
                .rules
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(key)
                .is_some())
        }
        fn scan(
            &self,
            key: &str,
            expected: &[RegistryValue],
        ) -> Result<NrptTableScan, PlatformError> {
            let rules = self.rules.lock().unwrap_or_else(|p| p.into_inner());
            let mut scan = NrptTableScan::default();
            for (name, values) in rules.iter() {
                if name == key {
                    scan.ours_intact = expected.iter().all(|e| has(values, e));
                } else if !values.iter().any(|v| v.name == "Version") {
                    scan.damaged += 1;
                }
            }
            Ok(scan)
        }
        fn sweep_orphans(&self, marker: &str, keep: &str) -> Result<usize, PlatformError> {
            let ours = sz("Comment", marker);
            let mut rules = self.rules.lock().unwrap_or_else(|p| p.into_inner());
            let before = rules.len();
            rules.retain(|name, values| {
                let half_written = !values.iter().any(|v| v.name == "Version");
                let stale_copy = name != keep && has(values, &ours);
                !(half_written || stale_copy)
            });
            Ok(before - rules.len())
        }
    }

    /// A complete rule of ours, as the pre-fixed-key cmdlet era wrote it.
    fn ours(ip: &str) -> Vec<RegistryValue> {
        nrpt_rule_values(ip, NRPT_MARKER)
    }

    /// Somebody else's complete rule — a VPN client's split-DNS suffix.
    fn theirs() -> Vec<RegistryValue> {
        vec![
            sz("Comment", "AcmeVPN"),
            multi_sz("Name", ".corp.example"),
            sz("GenericDNSServers", "10.0.0.53"),
            dword("ConfigOptions", 8),
            dword("Version", 2),
        ]
    }

    /// A rule whose writer died after the first value.
    fn half_written() -> Vec<RegistryValue> {
        vec![multi_sz("Name", ".")]
    }

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

    fn listener() -> SocketAddr {
        "127.0.0.1:53".parse().unwrap()
    }

    fn handle() -> RedirectHandle {
        RedirectHandle {
            marker: NRPT_MARKER.to_string(),
            listener: listener(),
        }
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
    fn a_rule_is_the_seven_values_the_dns_client_requires() {
        let values = nrpt_rule_values("127.0.0.1", NRPT_MARKER);
        let names: Vec<_> = values.iter().map(|v| v.name).collect();
        assert_eq!(
            names,
            [
                "Comment",
                "DisplayName",
                "IPSECCARestriction",
                "Name",
                "GenericDNSServers",
                "ConfigOptions",
                "Version",
            ]
        );
        // The catch-all namespace as a one-entry list: the entry's terminator
        // plus the list's.
        assert!(has(
            &values,
            &RegistryValue {
                name: "Name",
                kind: RegistryValueKind::MultiSz,
                data: vec![b'.', 0, 0, 0, 0, 0],
            }
        ));
        assert!(has(
            &values,
            &RegistryValue {
                name: "GenericDNSServers",
                kind: RegistryValueKind::Sz,
                data: "127.0.0.1\0"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
            }
        ));
        assert!(has(&values, &dword("ConfigOptions", 8)));
        assert!(has(&values, &dword("Version", 2)));
        assert!(has(&values, &sz("Comment", NRPT_MARKER)));
    }

    #[test]
    fn redirect_writes_our_rule_under_its_fixed_key_and_confirms_it() {
        let redirect = NrptDnsRedirect::new(accepting_runner(), FakeStore::default());
        let h = redirect.redirect_to(listener()).expect("redirect");
        assert_eq!(h.marker, NRPT_MARKER);
        assert_eq!(h.listener, listener());
        assert_eq!(redirect.store.writes(), [NRPT_RULE_KEY]);
        assert_eq!(redirect.store.keys(), [NRPT_RULE_KEY]);
        assert!(
            redirect.runner.scripts()[0].contains("Get-DnsClientNrptPolicy"),
            "a successful write must still be confirmed against the table in force"
        );
    }

    #[test]
    fn redirect_clears_the_debris_that_would_have_the_table_rejected() {
        // A half-written rule (its writer died) and a copy of ours under a
        // random key (the cmdlet era) both go; the VPN client's rule stays.
        let store = FakeStore::with(&[
            ("{HALF}", half_written()),
            ("{OLD-OURS}", ours("127.0.0.1")),
            ("{VPN}", theirs()),
        ]);
        let redirect = NrptDnsRedirect::new(accepting_runner(), store);
        redirect.redirect_to(listener()).expect("redirect");
        assert_eq!(redirect.store.keys(), [NRPT_RULE_KEY, "{VPN}"]);
    }

    #[test]
    fn redirect_withdraws_a_rule_the_os_does_not_honour() {
        // The rule IS written; the effective table comes back empty: Windows
        // evaluated the rule and refused it.
        let redirect = NrptDnsRedirect::new(
            ScriptedRunner::new(vec![("Get-DnsClientNrptPolicy", ok("   \n"))]),
            FakeStore::default(),
        );
        let err = redirect.redirect_to(listener()).unwrap_err();
        assert!(matches!(err, PlatformError::Transient { .. }));
        assert!(
            redirect.store.keys().is_empty(),
            "a rule the OS refuses must not be left behind for the next boot to trip over"
        );
    }

    #[test]
    fn redirect_survives_an_unreadable_policy_table() {
        // The query itself failed. That is not a rejection, and treating it as
        // one would disable Mode B on every host where the cmdlet is missing.
        let redirect = NrptDnsRedirect::new(
            ScriptedRunner::new(vec![(
                "Get-DnsClientNrptPolicy",
                CommandOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: "cmdlet not found".into(),
                },
            )]),
            FakeStore::default(),
        );
        redirect
            .redirect_to(listener())
            .expect("an unreadable answer must not tear down a working redirect");
        assert_eq!(
            redirect.store.keys(),
            [NRPT_RULE_KEY],
            "nothing was refused, so nothing may be withdrawn"
        );
    }

    #[test]
    fn clear_orphan_counts_our_rule_and_the_debris_but_not_a_stranger() {
        let store = FakeStore::with(&[
            (NRPT_RULE_KEY, ours("127.0.0.1")),
            ("{HALF}", half_written()),
            ("{OLD-OURS}", ours("127.0.0.1")),
            ("{VPN}", theirs()),
        ]);
        assert_eq!(clear_orphan_redirect(&store).expect("clear"), 3);
        assert_eq!(store.keys(), ["{VPN}"]);
        // Nothing to clean is a successful sweep of zero, not a failure.
        assert_eq!(clear_orphan_redirect(&store).expect("clear"), 0);
    }

    /// The teardown's only process spawn used to be here. The NRPT restore
    /// beside it is a single registry delete, so this flush was the whole
    /// reason the stop step needed a multi-second budget.
    #[test]
    fn flushing_the_cache_calls_the_api_and_spawns_no_process() {
        #[derive(Default)]
        struct CountingFlush(std::sync::atomic::AtomicUsize);
        impl DnsCacheControlPort for CountingFlush {
            fn flush_resolver_cache(
                &self,
            ) -> Result<(), nrr_platform_api::dns::DnsCacheFlushError> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            }
        }

        let flush = Arc::new(CountingFlush::default());
        let redirect = NrptDnsRedirect::with_cache_control(
            FakeRunner::new(ok("")),
            FakeStore::default(),
            flush.clone(),
        );
        redirect.flush_cache().expect("flush");
        assert_eq!(flush.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            redirect.runner.scripts().is_empty(),
            "the flush must not run PowerShell"
        );
    }

    #[test]
    fn restore_deletes_only_our_key_and_spawns_nothing() {
        let store = FakeStore::with(&[(NRPT_RULE_KEY, ours("127.0.0.1")), ("{VPN}", theirs())]);
        let redirect = NrptDnsRedirect::new(FakeRunner::new(ok("")), store);
        redirect.restore(&handle()).expect("restore");
        assert_eq!(redirect.store.keys(), ["{VPN}"]);
        assert!(redirect.runner.scripts().is_empty());
        redirect
            .restore(&handle())
            .expect("restoring twice is a no-op");
    }

    #[test]
    fn inspect_reads_our_configuration_and_the_table_around_it() {
        fn inspect(store: FakeStore) -> RedirectState {
            let redirect = NrptDnsRedirect::new(FakeRunner::new(ok("")), store);
            let state = redirect.inspect(&handle()).expect("inspect");
            assert!(
                redirect.runner.scripts().is_empty(),
                "the guard's check must never cost a process"
            );
            state
        }
        assert_eq!(
            inspect(FakeStore::with(&[
                (NRPT_RULE_KEY, ours("127.0.0.1")),
                ("{VPN}", theirs()),
            ])),
            RedirectState::Active
        );
        // Ours gone.
        assert_eq!(
            inspect(FakeStore::with(&[("{VPN}", theirs())])),
            RedirectState::Inactive
        );
        // Ours intact, but a half-written stranger has the whole table rejected.
        assert_eq!(
            inspect(FakeStore::with(&[
                (NRPT_RULE_KEY, ours("127.0.0.1")),
                ("{HALF}", half_written()),
            ])),
            RedirectState::Inactive
        );
        // Ours edited to point elsewhere is not ours.
        assert_eq!(
            inspect(FakeStore::with(&[(NRPT_RULE_KEY, ours("10.0.0.1"))])),
            RedirectState::Inactive
        );
    }

    #[test]
    fn verify_asks_the_effective_policy_table_not_our_own_write() {
        let redirect = NrptDnsRedirect::new(FakeRunner::new(ok(".\n")), FakeStore::default());
        assert_eq!(
            redirect.verify(&handle()).expect("verify"),
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
            NrptDnsRedirect::new(FakeRunner::new(ok("")), FakeStore::default())
                .verify(&handle())
                .expect("verify"),
            RedirectState::Inactive
        );

        // A query that could not run is an error, not "Inactive".
        assert!(NrptDnsRedirect::new(
            FakeRunner::new(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "denied".into(),
            }),
            FakeStore::default()
        )
        .verify(&handle())
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
