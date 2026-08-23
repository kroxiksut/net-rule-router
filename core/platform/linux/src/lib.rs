//! Linux platform backend.
//!
//! Mirrors `nrr-platform-windows`: the same neutral port traits from
//! `nrr-platform-api`. Enforcement is real — packet filters through `nft`
//! ([`nft_backend`], [`nft_policy_enforcer`]) and routes through rtnetlink
//! ([`LinuxApi`] as [`nrr_platform_api::route_table::RouteTablePort`]) — as are
//! the observation and host-integration ports (autostart, key store, service
//! control, local time, interface counters, network change, reachability,
//! app-path resolution, peer credentials, adapter enumeration, logind).
//! Honest stubs remain, each saying so in its own module: fake-IP TUN, VPN and
//! app-group discovery, the resolver-cache read.
//!
//! Much of the crate is pure Rust over the api traits — message encoding, plan
//! lowering, parsers — so those parts compile and their tests run on the Windows
//! dev host too; only the syscalls and the `nft`/`loginctl` calls sit behind
//! `#[cfg(target_os = "linux")]`.

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

/// Wire codec for the DNS messages the resolver exchanges — pure over bytes, so
/// its tests run on any host.
pub mod dns_message;

/// Passive observation of DNS resolutions through systemd-resolved's query
/// monitor — the Linux analog of the ETW DNS-Client source. Silent by design on
/// a machine whose programs bypass resolved; the module doc says how to tell.
#[cfg(target_os = "linux")]
pub mod dns_observe;

/// The active DNS resolver: asks the machine's own nameservers over UDP (with
/// the protocol's TCP retry) so an answer carries a TTL, which `getaddrinfo`
/// discards.
#[cfg(target_os = "linux")]
pub mod dns_resolver;

/// Passive observation of outbound connections from procfs — the Linux analog
/// of the WFP net-event / ETW sources. Reports sockets that exist when it polls
/// and never a verdict; the module doc says what that costs.
#[cfg(target_os = "linux")]
pub mod conn_observe;

/// The Linux authorization mechanism: polkit, consulted through `pkcheck`.
/// Answers "may this caller do this", including asking them for a password
/// through their own session — the reason no elevation broker is needed here.
#[cfg(target_os = "linux")]
pub mod polkit;

/// Graceful-stop signals (`SIGTERM`/`SIGINT`) — the Linux analog of the SCM
/// stop control. Without it the daemon dies on the default disposition and its
/// filters and routes outlive the service that installed them.
#[cfg(target_os = "linux")]
pub mod signals;

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

/// Who currently has a live login, asked of `logind` through `loginctl`. The
/// Linux answer to the question the Windows side answers by watching for a tray
/// connection — and a better one for a machine reached over SSH, where the work
/// outlives the terminal that started it.
#[cfg(target_os = "linux")]
pub mod logind;

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
pub mod nft_policy_enforcer;

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
// The IPv4 route table over rtnetlink — the mechanism behind `RouteTablePort`'s
// route half.
pub mod route_table;

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
use nrr_platform_api::route_table::RouteTablePort;
use nrr_platform_api::types::RouteEntry;

/// Reason returned by the route methods when this crate is compiled for a
/// non-Linux host — the mechanism is rtnetlink, and there is none to reach.
/// Read by a user in an error message, so it says what is missing.
#[cfg(not(target_os = "linux"))]
const NOT_YET: &str = "the Linux route backend needs a Linux kernel";

/// Convenience: the `NotSupported` error the off-Linux fallbacks return.
#[cfg(not(target_os = "linux"))]
fn not_yet<T>() -> Result<T, PlatformError> {
    Err(PlatformError::NotSupported { reason: NOT_YET })
}

/// Linux implementation of [`RouteTablePort`].
///
/// Route reads and mutations go through rtnetlink ([`crate::route_table`]);
/// adapter enumeration reads sysfs and `/proc/net/route`. The WFP filter engine
/// is deliberately absent rather than stubbed — it is a Windows mechanism, and
/// this type no longer has to pretend otherwise now that the two ports are
/// separate. Packet filtering on Linux is
/// [`crate::nft_backend::NftablesEnforcement`].
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxApi;

impl RouteTablePort for LinuxApi {
    #[cfg(target_os = "linux")]
    fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError> {
        crate::route_table::get_ipv4_routes()
    }

    #[cfg(not(target_os = "linux"))]
    fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError> {
        not_yet()
    }

    #[cfg(target_os = "linux")]
    fn create_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        crate::route_table::add_ipv4_route(entry)
    }

    #[cfg(not(target_os = "linux"))]
    fn create_ip_forward_entry(&self, _entry: &RouteEntry) -> Result<(), PlatformError> {
        not_yet()
    }

    #[cfg(target_os = "linux")]
    fn delete_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        crate::route_table::delete_ipv4_route(entry)
    }

    #[cfg(not(target_os = "linux"))]
    fn delete_ip_forward_entry(&self, _entry: &RouteEntry) -> Result<(), PlatformError> {
        not_yet()
    }

    /// Implemented: enumeration is observation, not enforcement, so it does not
    /// wait on the route backend the rest of this port is blocked behind.
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

    /// On Linux the interface index IS the stable identity — there is no second
    /// identifier to convert to. The port only requires that the value be
    /// stable for the life of the interface and non-zero, and `ifindex` is
    /// both; index 0 means "unspecified" and is never a real interface.
    fn interface_luid_for_index(&self, ifindex: u32) -> Result<u64, PlatformError> {
        if ifindex == 0 {
            return Err(PlatformError::StateCorrupted {
                detail: "interface index 0 is the unspecified index, not an interface".to_string(),
            });
        }
        Ok(u64::from(ifindex))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The filter-engine methods are not in this list because they are no
    /// longer part of this port at all: `WfpEnginePort` is a Windows mechanism,
    /// and Linux filters with nftables instead. What remains stubbed here is
    /// route-table mutation, until the rtnetlink backend lands.
    #[test]
    fn the_interface_index_is_its_own_stable_identity() {
        assert_eq!(LinuxApi.interface_luid_for_index(3).expect("index 3"), 3);
    }

    /// Index 0 is "unspecified" in every kernel API. Returning it as an
    /// identity would hand enforcement a pin that matches no interface, which
    /// on the Windows side is exactly the `luid == 0` case the kill-switch
    /// fails open on.
    #[test]
    fn the_unspecified_index_is_refused() {
        assert!(matches!(
            LinuxApi.interface_luid_for_index(0),
            Err(PlatformError::StateCorrupted { .. })
        ));
    }

    /// Off Linux the route methods have no mechanism to reach.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn route_table_access_reports_not_supported_off_linux() {
        let api = LinuxApi;
        assert!(matches!(
            api.get_ip_forward_table(),
            Err(PlatformError::NotSupported { .. })
        ));
        assert!(matches!(
            api.create_ip_forward_entry(&sample_route()),
            Err(PlatformError::NotSupported { .. })
        ));
    }

    /// On a live kernel the dump must actually answer. Reading routes needs no
    /// privilege, so this runs as an ordinary user in CI and in WSL.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_route_dump_answers_on_a_live_kernel() {
        let routes = LinuxApi
            .get_ip_forward_table()
            .expect("reading the route table needs no privilege");
        assert!(
            routes.iter().all(|r| r.interface_index != 0),
            "every returned route must name an interface"
        );
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

    /// Only the off-Linux fallbacks take a route argument; on Linux the same
    /// paths reach the kernel and are covered by `tests/route_live.rs`.
    #[cfg(not(target_os = "linux"))]
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
