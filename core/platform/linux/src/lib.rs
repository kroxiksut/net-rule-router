//! Linux platform backend.
//!
//! Mirrors `nrr-platform-windows`: the same neutral port traits from
//! `nrr-platform-api`. The observation and host-integration ports are real
//! (autostart, key store, service control, local time, interface counters,
//! network change, reachability, app-path resolution, peer credentials, adapter
//! enumeration); the ENFORCEMENT port [`LinuxApi`] is still a stub whose routing
//! and packet-filter calls answer [`PlatformError::NotSupported`], because the
//! nftables / rtnetlink mechanism has not landed. The caller constructs
//! [`LinuxApi`] under `#[cfg(target_os = "linux")]` exactly where it constructs
//! `ProductionWindowsApi` under `#[cfg(windows)]`, so `service-runtime` links
//! and runs on Linux and fails closed instead of routing anything.
//!
//! The real mechanism (nftables `WfpEnginePort`, rtnetlink `RouteTablePort`,
//! systemd service, unix-socket IPC, …) still needs a VM with root to build
//! and verify against.
//!
//! Because it is pure Rust over the api traits, this crate compiles on *every*
//! target (it takes no Linux-only dependency yet), so it can be built and
//! unit-tested from the Windows dev host too.

/// Linux autostart mechanism (XDG `.desktop`) — the first REAL (non-stub) port
/// impl in this crate. Unlike the enforcement ports below (which need root /
/// kernel and stay stubs until their mechanism lands), autostart is
/// pure filesystem work, so it is fully implemented and unit-tested now.
pub mod autostart;

/// Linux DB-MAC signing-key store (`0600` file in a `0700` dir) — the Linux
/// analog of Windows DPAPI. `#[cfg(unix)]` because it sets Unix mode bits;
/// unit-tested on WSL2. Real (non-stub) mechanism, like [`autostart`].
#[cfg(unix)]
pub mod key_store;

/// Unix mechanism behind
/// `nrr_platform_api::path_registration::PathRegistrationPort` — puts the
/// administrative console's directory on the user's `PATH` by adding a line to
/// their shell start-up file. Like [`autostart`] it is a REAL (non-stub) impl:
/// the whole of it is `std` filesystem work over an injected environment, so it
/// compiles and its tests run on every host. The mechanism is POSIX-shell
/// generic rather than Linux-specific, so the future macOS backend reuses this
/// module instead of copying it.
pub mod path_registration;

/// Linux privilege-elevation primitive (polkit `pkexec`) — the analog of the
/// Windows UAC broker's command construction. Portable `std` (exit-code logic +
/// `Command`), so its pure tests run anywhere; wiring into the launcher and the
/// pkexec-helper-vs-polkit-IPC model decision are deferred to the Linux session
/// phase. See the module doc for why elevation does not port like the others.
pub mod elevation;

/// Linux IPC caller-identity via `SO_PEERCRED` — the analog of the Windows
/// named-pipe token inspection (`windows-service/named_pipe_identity.rs`). Reads
/// an accepted `AF_UNIX` client's pid/uid/gid and resolves the uid to a
/// [`nrr_platform_api::enforcement::UserPrincipal`]. `#[cfg(target_os = "linux")]`
/// because `SO_PEERCRED`/`struct ucred` are Linux-specific; the future
/// `linux-service` daemon consumes it per accepted connection. Unit-tested on
/// WSL2 (no root/systemd needed — socketpair + a bound `UnixListener`).
#[cfg(target_os = "linux")]
pub mod peer_cred;

/// Unix mechanism for pointing this process's error stream at a file
/// (`dup2` onto descriptor 2) — the analog of the Windows standard-handle
/// table. Compiled on every host so the launcher can select it under
/// `cfg(unix)`; on a non-Linux host it answers `NotSupported` until that
/// platform's slice lands.
pub mod process_error_stream;

/// Linux systemd service mechanism (`Type=notify` unit rendering + `sd_notify`
/// readiness protocol) — the analog of the Windows SCM entrypoint
/// (`core/services/windows-service`). `#[cfg(target_os = "linux")]` because it
/// uses the Linux abstract-namespace socket form; unit-tested on WSL2. The
/// daemon entrypoint that consumes it (a `linux-service` sibling of
/// `windows-service`) needs a real systemd host and lands in a later slice.
#[cfg(target_os = "linux")]
pub mod systemd;

/// The systemd implementation of
/// `nrr_platform_api::service_control::ServiceControlPort` — install, remove,
/// start, stop and inspect the background service. The analog of
/// `nrr_platform_windows::service_control`, built on the pure plans in
/// [`systemd`]. `#[cfg(target_os = "linux")]` for the same reason [`systemd`]
/// is; unit-tested on WSL2 against captured `systemctl` output and a recording
/// stand-in for the host, so no test needs root or a live service manager.
#[cfg(target_os = "linux")]
pub mod service_control;

/// Logrotate backstop drop-in for the operational NDJSON logs
/// under `/var/log/netrulerouter`. Pure config rendering; the in-app
/// `nrr-diagnostics` retention remains the rotation AUTHORITY (identical on
/// every OS), and this drop-in is only an out-of-process safety net for when
/// the service is stopped and its cleanup task is not running. Consumed by
/// [`systemd::plan_install`]. `#[cfg(target_os = "linux")]` because it is a
/// Linux-only install artefact; unit-tested on WSL2.
#[cfg(target_os = "linux")]
pub mod logrotate;

/// Linux host system-information collector for the diagnostic archive — the
/// analog of `nrr_platform_windows::system_info`. Reads procfs / `os-release`
/// (`/proc/cpuinfo`, `/proc/meminfo`, `/etc/os-release`) to enrich the
/// portable [`nrr_shared::system_info::SystemInfo::from_std`] baseline. Pure
/// `std` with string-parsing helpers, so it compiles and its parse tests run
/// on every host; the file reads only return data on a real Linux host.
pub mod system_info;

/// The nftables ruleset our lowering produces, as our own type rather than any
/// one library's schema. Two mechanisms render it — `nft --json` today, a
/// direct-netlink crate later — so swapping them cannot change what is
/// enforced. Pure data: buildable and testable on any host.
pub mod nft_ir;

/// Linux LOWERING of the neutral `EnforcementPlan` into [`nft_ir`] — the
/// counterpart of `nrr_platform_windows::lower_windows`. Windows arbitrates
/// with weight bands; here the same arbitration is rule ORDER plus terminal
/// verdicts. Pure, so it is unit-tested on every host including the Windows dev
/// machine; delivering the result to the kernel is a separate concern.
pub mod lower_linux;

/// Delivery of an [`nft_ir`] ruleset to the kernel through `nft --json`.
/// Rendering the transaction is pure and tested on every host; only the call
/// into `nft` is Linux-gated. A direct-netlink crate will replace this
/// mechanism behind the same IR.
pub mod nft_apply;

/// The Linux `EnforcementBackend` — the neutral plan reconciled onto nftables.
/// Thin by design: it joins [`lower_linux`] (pure) with [`nft_apply`] (the
/// mechanism) and reports what could not be expressed rather than dropping it.
pub mod nft_backend;

/// Linux VPN-client discovery seam (design + stub).
/// The neutral port lives in `nrr_platform_api::vpn_discovery`; this backend
/// documents the /proc + `.desktop` + package-DB mechanism and returns an
/// empty list until it can be verified on real Linux.
pub mod vpn_discovery;

/// Linux application-group discovery seam (design + stub).
/// The neutral port lives in `nrr_platform_api::app_group_discovery`; this
/// backend documents the /proc + `.desktop` + bridge/daemon mechanism and
/// returns an empty list until it can be verified on real Linux.
pub mod app_group_discovery;

/// Linux fake-IP TUN seam. The kernel provides
/// `/dev/net/tun` natively, so unlike Windows there is no third-party driver to
/// ship or attribute; the stub fails closed until it can be verified on a real
/// Linux host with `CAP_NET_ADMIN`.
pub mod fake_ip;

/// Linux OS resolver-cache read seam (design + stub). The neutral port
/// lives in `nrr_platform_api::dns::DnsCacheReadPort`; this backend documents the
/// systemd-resolved D-Bus mechanism and returns an empty snapshot until it can be
/// verified on a real resolved host.
pub mod dns_cache_read;

/// Linux civil-time-offset backend behind
/// `nrr_platform_api::local_time::LocalTimeZonePort`. `localtime_r` against the
/// machine's tz database, so the answer is daylight-aware; the traffic ledger
/// keys its rows by the user's local day and would otherwise roll them at
/// midnight UTC.
pub mod local_time;

/// Linux per-interface octet counters behind
/// `nrr_platform_api::interface_traffic::InterfaceCounterSource`.
/// `/proc/net/dev` for the numbers, `/sys/class/net` for what each interface
/// is. Parsing and classification are pure, so their tests run on every host.
pub mod interface_traffic;

/// Linux name→path resolution behind
/// `nrr_platform_api::app_path_resolver::AppPathResolver`. Looks through
/// `$PATH` and the Flatpak/Snap export directories, stripping the `.exe` the
/// neutral layer guarantees — the one place that key meets a real filesystem.
pub mod app_path_resolver;

/// Linux network-topology change feed behind
/// `nrr_platform_api::network_change::NetworkChangeObserver`. An rtnetlink
/// socket on the link/address/route groups, so a tunnel coming up is known when
/// it happens instead of at the next poll. Message framing is parsed by a pure
/// function tested on every host; only the socket half is Linux-only.
pub mod network_change;

/// Linux active-reachability backend behind
/// `nrr_platform_api::reachability::ReachabilityProbe`. ICMP echo over an
/// unprivileged datagram ICMP socket. The packet codec is pure and tested on
/// every host; only the socket half is Linux-only.
pub mod reachability;

/// Linux adapter enumeration — the answer Windows gets from one
/// `GetAdaptersAddresses` call, assembled from `/sys/class/net` (identity, link
/// state), `/proc/net/route` (gateways) and `getifaddrs` (addresses). Parsers
/// are pure and tested on every host; only the reads are Linux-only.
pub mod adapters;

/// Abstract-socket mechanism behind
/// `nrr_platform_api::single_instance::SingleInstancePort`.
pub mod single_instance;

/// The address half of adapter enumeration, kept apart because it is the one
/// part that needs a syscall rather than a file.
#[cfg(target_os = "linux")]
mod adapters_addr;

use nrr_platform_api::adapters::AdapterInfo;
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::types::{
    RouteEntry, WfpEngineToken, WfpFilterId, WfpFilterRecord, WfpFilterSpec,
};
use nrr_platform_api::windows_api::WindowsApiPort;

/// Reason string every stub returns until the real Linux backend lands. Read by
/// a user in an error message, so it says what is missing, not where it is
/// tracked.
const NOT_YET: &str = "the Linux platform backend is not implemented yet";

/// Convenience: the `NotSupported` error every stub returns.
fn not_yet<T>() -> Result<T, PlatformError> {
    Err(PlatformError::NotSupported { reason: NOT_YET })
}

/// Linux stub of the enforcement port ([`WindowsApiPort`], the route-table +
/// packet-filter engine). Every operation returns
/// [`PlatformError::NotSupported`]; the real nftables / rtnetlink backend is
/// not implemented yet. Selected by the consumer under `#[cfg(target_os = "linux")]`
/// where Windows selects `nrr_platform_windows::ProductionWindowsApi`.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxApi;

impl WindowsApiPort for LinuxApi {
    fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError> {
        not_yet()
    }

    fn create_ip_forward_entry(&self, _entry: &RouteEntry) -> Result<(), PlatformError> {
        not_yet()
    }

    fn delete_ip_forward_entry(&self, _entry: &RouteEntry) -> Result<(), PlatformError> {
        not_yet()
    }

    /// Implemented: enumeration is observation, not enforcement, so it does not
    /// wait on the nftables backend the rest of this port is blocked behind.
    /// Without it the routing layer cannot even name a link, and the GUI shows
    /// mock interfaces on a real machine.
    #[cfg(target_os = "linux")]
    fn get_adapter_infos(&self) -> Result<Vec<AdapterInfo>, PlatformError> {
        crate::adapters::collect_adapter_infos()
    }

    #[cfg(not(target_os = "linux"))]
    fn get_adapter_infos(&self) -> Result<Vec<AdapterInfo>, PlatformError> {
        not_yet()
    }

    fn interface_luid_for_index(&self, _ifindex: u32) -> Result<u64, PlatformError> {
        not_yet()
    }

    fn wfp_engine_open(&self) -> Result<WfpEngineToken, PlatformError> {
        not_yet()
    }

    fn wfp_engine_close(&self, _token: WfpEngineToken) -> Result<(), PlatformError> {
        not_yet()
    }

    fn wfp_transaction_begin(&self, _token: &WfpEngineToken) -> Result<(), PlatformError> {
        not_yet()
    }

    fn wfp_transaction_commit(&self, _token: &WfpEngineToken) -> Result<(), PlatformError> {
        not_yet()
    }

    fn wfp_transaction_abort(&self, _token: &WfpEngineToken) {
        // Nothing to abort — no session was ever opened.
    }

    fn wfp_filter_add(
        &self,
        _token: &WfpEngineToken,
        _spec: &WfpFilterSpec,
    ) -> Result<WfpFilterId, PlatformError> {
        not_yet()
    }

    fn wfp_filter_delete(
        &self,
        _token: &WfpEngineToken,
        _id: WfpFilterId,
    ) -> Result<(), PlatformError> {
        not_yet()
    }

    fn wfp_enumerate_our_filters(
        &self,
        _token: &WfpEngineToken,
    ) -> Result<Vec<WfpFilterRecord>, PlatformError> {
        not_yet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_enforcement_op_reports_not_supported() {
        let api = LinuxApi;
        assert!(matches!(
            api.get_ip_forward_table(),
            Err(PlatformError::NotSupported { .. })
        ));
        assert!(matches!(
            api.create_ip_forward_entry(&sample_route()),
            Err(PlatformError::NotSupported { .. })
        ));
        assert!(matches!(
            api.interface_luid_for_index(3),
            Err(PlatformError::NotSupported { .. })
        ));
        assert!(matches!(
            api.wfp_engine_open(),
            Err(PlatformError::NotSupported { .. })
        ));
    }

    /// Enumeration is the exception, and deliberately so: it observes rather
    /// than enforces, so it is not blocked behind the nftables backend.
    #[cfg(target_os = "linux")]
    #[test]
    fn adapter_enumeration_answers_on_a_live_host() {
        let adapters = LinuxApi
            .get_adapter_infos()
            .expect("enumeration must work without the enforcement backend");
        let loopback = adapters
            .iter()
            .find(|a| a.adapter_name == "lo")
            .expect("every Linux host has a loopback interface");
        assert!(
            loopback
                .ipv4_addresses
                .contains(&std::net::Ipv4Addr::LOCALHOST),
            "loopback must carry 127.0.0.1, got {:?}",
            loopback.ipv4_addresses
        );
        assert_eq!(
            loopback.interface_type,
            nrr_platform_api::adapters::InterfaceType::Loopback
        );
        // The live-host lesson that cost a day: `operstate` reads `unknown` for
        // loopback forever, and reading that as "down" hides a working link.
        assert_ne!(
            loopback.oper_status,
            nrr_platform_api::adapters::IfOperStatus::Down
        );
    }

    fn sample_route() -> RouteEntry {
        RouteEntry {
            destination: std::net::Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 8,
            next_hop: std::net::Ipv4Addr::new(0, 0, 0, 0),
            interface_index: 1,
            metric: 0,
            is_ours: true,
            table: nrr_platform_api::RouteTableRef::Main,
        }
    }
}
