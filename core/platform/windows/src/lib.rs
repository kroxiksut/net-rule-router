//! `nrr-platform-windows` — Windows platform apply layer.
//!
//! ## Dependency direction
//!
//! ```text
//! nrr-platform-windows → nrr-shared
//! ```
//!
//! Forbidden dependencies (enforced by `tests/dependency_boundary.rs`):
//! `nrr-application`, `nrr-service-runtime`, `nrr-desktop-gui`,
//! `nrr-desktop-tray`, `nrr-launcher`, `nrr-mock-backend`.
//!
//! `nrr-service-runtime` consumes this crate, not the other way around.
//!
//! ## `unsafe` policy
//!
//! Win32 FFI calls require `unsafe`. All `unsafe { }` blocks are:
//! - ≤ 10 lines
//! - preceded by a `// SAFETY:` comment explaining the invariant
//! - located in `windows_api.rs` only (production impl)
//! - never contain business logic
//!
//! The workspace `#[deny(unsafe_code)]` lint is overridden per-file with
//! `#[allow(unsafe_code)]` at the top of `windows_api.rs`, where the real
//! Win32 FFI lives.
//!
//! ## Module layout
//!
//! | Module | Implements |
//! |--------|------------|
//! | `apply`    | `WindowsApplyEngine` — main orchestrator |
//! | `wfp`      | `WfpSession`, `WfpTransactionGuard` (RAII) |
//! | `routing`  | `RoutingTransaction` — compensating-action batch |
//! | `adapters` | `AdapterMonitor` — realtime adapter events |
//! | `notify`   | `BlockNotificationEmitter` |
//! | `verify`   | `verify_apply` — post-apply drift detection |
//! | `windows_api` | `WindowsApiPort` trait + impls |
//! | `error`    | `PlatformError`, `ErrorClass` |
//! | `types`    | `RouteEntry`, `WfpFilterSpec`, `ApplyActionPlan`, … |
//! | `interface_manager` | Adapter enumeration |

pub mod adapters;
pub mod app_path_resolver;
pub mod apply;
pub mod autostart;
#[cfg(feature = "browser-stub")]
pub mod browser_stub;
pub mod conn_observe;
pub mod constants;
pub mod dns;
pub mod dns_observe;
pub mod dns_redirect;
pub mod error;
pub mod fail_closed;
// Windows TUN mechanism on WireGuard LLC's signed Wintun driver, plus the
// third-party integrity report the GUI shows.
pub mod fake_ip;
// VPN self-heal mechanism: name the process that owns a relayed TCP flow via
// the OS connection table.
pub mod flow_owner;
pub mod hosts_file;
pub mod interface_manager;
pub mod interface_rows;
// Windows octet-counter source over `GetIfTable2`.
pub mod interface_traffic;
pub mod key_store;
// Windows lowering of the neutral `EnforcementPlan` into WFP filters (see the
// module doc).
pub mod lower_windows;
pub mod network_change;
pub mod notify;
// Per-user environment mechanism behind
// `nrr_platform_api::path_registration::PathRegistrationPort` — appends the
// administrative console's directory to `HKCU\Environment`'s `Path` value and
// broadcasts the change. The planning logic is generic over the store, so it
// compiles and is tested on every host; only the registry backend is Win32.
pub mod path_registration;
/// Windows mechanism for pointing this process's error stream at a file, so a
/// process started by another process stops writing into its parent's log.
pub mod process_error_stream;
pub mod reachability;
pub mod rollback;
pub mod routing;
// SCM mechanism behind `nrr_platform_api::service_control::ServiceControlPort`.
// Windows-only: the module talks to the Service Control Manager.
#[cfg(windows)]
pub mod service_control;
pub mod snapshot;
// Fake-IP mechanism behind `nrr_platform_api::fake_ip::stale_flows::StaleFlowReset`:
// tears down TCP flows a restart left pointing at now-dead fake addresses.
pub mod stale_flows;
pub mod strategy;
// Local civil-time offset (traffic ledger keys rows by the user's local day).
pub mod local_time;
pub mod system_info;
pub mod types;
pub mod verify;
// Windows VPN-client discovery (processes + Uninstall registry).
// `#![cfg(target_os = "windows")]` inside the module file.
pub mod vpn_discovery;
// Windows application-group discovery (VMs/emulators + P2P): processes +
// Uninstall registry + kernel-NAT service keys.
pub mod app_group_discovery;
pub mod wfp;
// Opt-in browser-history read (Chrome/Edge/Firefox History SQLite → visited
// hostnames). Pure rusqlite + std; compiles cross-platform (the profile
// discovery finds nothing off-Windows and returns NoBrowsersFound).
pub mod win32_browser_history;
pub mod win32_ffi;
pub mod windows_api;

pub use win32_browser_history::WindowsBrowserHistoryRead;

pub use adapters::{
    classify_availability, is_virtual_adapter, AdapterAvailability, AdapterAvailabilityChange,
    AdapterAvailabilitySnapshot, AdapterEventSource, AdapterInfo, AdapterMonitor, IfOperStatus,
    InterfaceType, MockAdapterEventSource, WindowsApiAdapterSource,
};
#[cfg(target_os = "windows")]
pub use app_group_discovery::WindowsAppGroupDiscovery;
#[cfg(target_os = "windows")]
pub use app_path_resolver::WindowsAppPathResolver;
pub use app_path_resolver::{AppPathResolver, MockAppPathResolver, NoopAppPathResolver};
pub use apply::{EngineResult, WindowsApplyEngine};
#[cfg(target_os = "windows")]
pub use autostart::ProductionAutostartRegistry;
pub use autostart::{
    AutostartCurrentState, AutostartError, AutostartHelper, AutostartRegistryPort,
    MockAutostartRegistry, AUTOSTART_SUBKEY, AUTOSTART_VALUE_NAME,
};
pub use conn_observe::egress::{
    classify_role, ifindex_for_local_addr, resolve_egress, EgressInterface, EgressRole,
};
#[cfg(target_os = "windows")]
pub use conn_observe::etw_tcpip::EtwKernelNetworkObserver;
#[cfg(target_os = "windows")]
pub use conn_observe::wfp_events::WfpConnectionObserver;
pub use conn_observe::{
    ConnectionObservation, ConnectionObservationSource, ConnectionVerdict,
    MockConnectionObservationSource, TransportProtocol,
};
#[cfg(target_os = "windows")]
pub use dns::WindowsDnsCacheControl;
#[cfg(target_os = "windows")]
pub use dns::WindowsDnsCacheRead;
pub use dns::{
    DnsCacheControlPort, DnsCacheFlushError, DnsCacheReadError, DnsCacheReadPort,
    MockDnsCacheControl, MockDnsCacheRead, NoopDnsCacheControl, NoopDnsCacheRead,
    OsCachedResolution,
};
pub use dns_observe::{DnsObservation, DnsObservationSource, MockDnsObservationSource};
pub use error::{ErrorClass, PlatformError};
pub use fail_closed::{
    compute_block_filters, compute_unblock_filter_ids, fail_closed_filter_id,
    is_exempt_from_blocking, BlockReason, FailClosedPlan, FailClosedRuleSpec,
};
pub use hosts_file::{
    default_hosts_path, normalize_hostname, parse_hosts_map, HostsFileReader, HostsPin,
    OsHostsFileReader, StaticHostsFileReader,
};
pub use interface_rows::{
    apply_external_probe, build_derived_assessment, build_observed_facts, collect_interfaces_rows,
    external_probe_target, fallback_rows, unknown_recommendation, BasicAvailabilityStatus,
    DerivedInterfaceAssessment, InterfaceRouteRow, InterfacesDataSource, ObservedInterfaceFacts,
    RouteRoleRecommendation,
};
#[cfg(windows)]
pub use key_store::WindowsDpapiKeyStore;
pub use key_store::{generate_signing_key, InMemKeyStore, KeyStore, SIGNING_KEY_BYTE_LEN};
pub use nrr_platform_api::app_group_discovery::{
    classify_app, AppDiscoverySource, AppGroupDiscoveryPort, AppGroupKind, AppGroupTab,
    DiscoveredApp, MockAppGroupDiscovery, NoopAppGroupDiscovery,
};
pub use nrr_platform_api::vpn_discovery::{
    looks_like_vpn, MockVpnDiscovery, NoopVpnDiscovery, VpnCandidate, VpnCandidateSource,
    VpnDiscoveryPort,
};
pub use rollback::{invert_action_plan, snapshot_to_desired, RollbackEngine, RollbackResult};
pub use snapshot::{
    compute_action_plan, compute_snapshot_hash, DesiredPlatformState, PlatformStateSnapshot,
    RoutingStateSnapshot, WfpFilterSnapshot, SNAPSHOT_SCHEMA_VERSION,
};
pub use strategy::{is_ipv6_address, rule_strategy, RuleImplementationStrategy};
pub use types::{
    ApplyActionPlan, RouteEntry, RoutingAction, WfpAction, WfpFilterAction, WfpFilterId,
    WfpFilterRecord, WfpFilterSpec, WfpLayerKey,
};
pub use verify::{DriftItem, DriftKind, DriftSeverity, VerifyEngine, VerifyResult};
#[cfg(target_os = "windows")]
pub use vpn_discovery::WindowsVpnDiscovery;
// NT-device → Win32 path mapping for WFP-sourced process paths: the
// learned-VPN-client sink re-enters the enforcement layer, whose
// `ALE_APP_ID` builder needs the drive-letter form.
#[cfg(target_os = "windows")]
pub use win32_ffi::app_id::win32_path_from_nt_path;
pub use windows_api::{MockWindowsApi, ProductionWindowsApi, WindowsApiPort};
