//! Neutral platform-port API.
//!
//! This crate is the OS-agnostic seam between the transport/decision layers
//! (`service-runtime`, which is pure policy) and the per-OS mechanism backends
//! (`nrr-platform-windows` today; `-linux` / `-macos` later). It holds only the
//! **definitions** — port traits and their neutral value types — that both sides
//! share. Concrete implementations (Win32 / nftables / pf) live in the backend
//! crates and `impl` these traits.
//!
//! ## Invariants
//!
//! - **No OS-specific dependencies.** This crate must compile on every target;
//!   it never links `windows`, `nftables`, or any platform SDK. A trait signature
//!   here uses only `std` + neutral domain/shared types.
//! - **Definitions, not logic.** Decision logic (hysteresis, policy) stays in
//!   `domain`/`service-runtime`; only the mechanism boundary is declared here.
//!
//! Ports are re-exported from the backend for source compatibility, so the
//! Windows build never changes behaviour while the seam is carved.

pub mod adapters;
pub mod app_group_discovery;
pub mod app_path_resolver;
pub mod autostart;
// Opt-in browser-history read (visited hostnames → seed rule-matching hosts
// into the FQDN cache, closing the pre-service-start blind spot). Neutral
// port; per-OS mechanism in the platform crates.
pub mod browser_history;
pub mod conn_observe;
pub mod dns;
pub mod dns_observe;
pub mod dns_redirect;
// The neutral cross-OS enforcement data model. Deliberately NOT crate-root
// re-exported until a lowering path consumes it, so it stays inert until wired
// in.
pub mod enforcement;
pub mod error;
// Per-adapter external (reflexive) address discovery over STUN. Portable as
// written — the transport is `std::net` and the codec is pure bytes — so there
// is no per-OS mechanism to hide behind a trait here.
pub mod external_ip;
pub mod fail_closed;
// The neutral fake-IP contract: address pool + hostname<->fake-address map,
// the scope policy (who gets a fake address), and the `TunAdapterPort` seam
// whose mechanism is per-OS (Wintun / `/dev/net/tun` / `utun`). Pure and
// testable on every platform.
pub mod fake_ip;
pub mod hosts_file;
pub mod interface_rows;
// Neutral per-interface octet-counter port. Mechanism is per-OS (`GetIfTable2`
// / `/proc/net/dev` / `if_data`); this holds the value type + trait only.
// Consumed by `nrr-domain::traffic_accountant`.
pub mod interface_traffic;
// Local civil-time offset port: the traffic ledger keys rows by the user's
// LOCAL day; only the OS knows the machine's time zone.
pub mod key_store;
pub mod local_time;
pub mod network_change;
// Make a directory reachable by name from the user's shell (the administrative
// console's directory on PATH). The decision — is it already there, what does
// the list become — is pure and lives here; the mechanism is per-OS (per-user
// environment store on Windows, a shell start-up file on Unix).
pub mod path_registration;
// Suspend/resume. The OS notifications that fire while the machine sleeps are
// gone by the time we run again, so this is the only way to learn a wake
// happened; the mechanism is per-OS, the reaction is neutral.
pub mod power;
// Where a process's own unstructured error output ends up. The decision (which
// file) is the caller's; the mechanism (std-handle table / file descriptor) is
// per-OS.
pub mod process_error_stream;
pub mod reachability;
pub mod routing;
// Register / remove / start / stop / inspect the background service. The OS
// backends implement it over SCM (Windows) and systemd (Linux); the console and
// the service binary's own verbs code against the trait.
pub mod service_control;
pub mod snapshot;
pub mod strategy;
// Attribution + provenance of the third-party binaries we ship (today:
// WireGuard LLC's signed `wintun.dll` on Windows). Neutral descriptors +
// verdict derivation; the hashing/signature MECHANISM is per-OS.
pub mod third_party;
pub mod types;
// VPN-client discovery port (processes + installed programs →
// user-confirmable candidates), replacing the silent `*vpn*` glob.
pub mod vpn_discovery;
pub mod wfp;
// Behavioral equivalence over `WfpFilterSpec`, the oracle the relocated
// `lower_windows` codegen is checked against (weight/id ignored). Pure +
// neutral; reachable by both service-runtime (current codegen) and the future
// platform-windows `lower_windows`.
pub mod wfp_behavioral;
pub mod windows_api;

// Crate-root re-exports of the NEUTRAL surface, mirroring the
// `nrr-platform-windows` crate root so consumers (`service-runtime`,
// `mock-backend`) can write `nrr_platform_api::RouteEntry` exactly as they
// wrote `nrr_platform_windows::RouteEntry`. Windows-only concretes
// (ProductionWindowsApi, WindowsApplyEngine, fail_closed/rollback/strategy/
// verify, the Etw*/Wfp*/Dpapi impls, collect_interfaces_rows) are
// intentionally NOT re-exported here — they live only in the Windows backend
// and are consumed under `#[cfg(windows)]`.
pub use adapters::{
    classify_availability, description_matches_virtual_software, is_virtual_adapter,
    AdapterAvailability, AdapterAvailabilityChange, AdapterAvailabilitySnapshot,
    AdapterEventSource, AdapterInfo, AdapterMonitor, IfOperStatus, InterfaceType,
    MockAdapterEventSource,
};
pub use app_group_discovery::{
    classify_app, merge_discovered, AppDiscoverySource, AppGroupDiscoveryPort, AppGroupEntry,
    AppGroupKind, AppGroupTab, DiscoveredApp, MockAppGroupDiscovery, NoopAppGroupDiscovery,
    APP_GROUP_DICTIONARY,
};
pub use app_path_resolver::{AppPathResolver, MockAppPathResolver, NoopAppPathResolver};
pub use autostart::{
    AutostartCurrentState, AutostartError, AutostartHelper, AutostartRegistryPort,
    MockAutostartRegistry,
};
pub use conn_observe::egress::{
    classify_role, ifindex_for_local_addr, resolve_egress, EgressInterface, EgressRole,
};
pub use conn_observe::{
    ConnectionObservation, ConnectionObservationSource, ConnectionVerdict,
    MockConnectionObservationSource, TransportProtocol,
};
pub use dns::{
    DnsCacheControlPort, DnsCacheFlushError, DnsCacheReadError, DnsCacheReadPort,
    MockDnsCacheControl, MockDnsCacheRead, NoopDnsCacheControl, NoopDnsCacheRead,
    OsCachedResolution,
};
pub use dns_observe::{DnsObservation, DnsObservationSource, MockDnsObservationSource};
pub use error::{ErrorClass, PlatformError};
pub use external_ip::{probe_external_ipv4_batch, ExternalIpProbeOutcome};
pub use fail_closed::{
    compute_block_filters, compute_unblock_filter_ids, fail_closed_filter_id,
    is_exempt_from_blocking, BlockReason, FailClosedPlan, FailClosedRuleSpec,
};
pub use fake_ip::{
    FakeIpAllocator, FakeIpBinding, FakeIpError, FakeIpPoolConfig, FakeIpScope, FakeIpVerdict,
    FlowOwnerLookup, MockFlowOwnerLookup, MockTunAdapter, NoopFlowOwnerLookup, NoopTunAdapter,
    RealIpReason, TunAdapterConfig, TunAdapterPort, TunControl, TunDevice,
};
pub use hosts_file::{
    default_hosts_path, normalize_hostname, parse_hosts_map, HostsFileReader, HostsPin,
    OsHostsFileReader, StaticHostsFileReader,
};
pub use interface_rows::{
    apply_external_probe, build_derived_assessment, build_observed_facts, external_probe_target,
    fallback_rows, unknown_recommendation, BasicAvailabilityStatus, DerivedInterfaceAssessment,
    InterfaceRouteRow, InterfacesDataSource, ObservedInterfaceFacts, RouteRoleRecommendation,
};
pub use interface_traffic::{
    InterfaceCounterSource, InterfaceCounters, MockInterfaceCounterSource,
    NoopInterfaceCounterSource,
};
pub use key_store::{generate_signing_key, InMemKeyStore, KeyStore, SIGNING_KEY_BYTE_LEN};
pub use local_time::{local_epoch_day, FixedTimeZone, LocalTimeZonePort, UtcTimeZone};
pub use path_registration::{
    decide_path_registration, list_contains_directory, path_entries, render_entry,
    MockPathRegistration, PathDecision, PathListStyle, PathRegistrationError, PathRegistrationPlan,
    PathRegistrationPort, PathRegistrationReport, PathRegistrationRequest, PathRegistrationStep,
    PathScope,
};
pub use power::{
    NoopPowerEventObserver, PowerEvent, PowerEventCallback, PowerEventObserver,
    PowerEventSubscription,
};
pub use snapshot::{
    compute_action_plan, compute_snapshot_hash, DesiredPlatformState, PlatformStateSnapshot,
    RoutingStateSnapshot, WfpFilterSnapshot, SNAPSHOT_SCHEMA_VERSION,
};
pub use strategy::{is_ipv6_address, rule_strategy, RuleImplementationStrategy};
pub use third_party::{
    IntegrityVerdict, MockThirdPartyIntegrity, NoopThirdPartyIntegrity, SignatureStatus,
    ThirdPartyComponent, ThirdPartyComponentStatus, ThirdPartyIntegrityPort,
    THIRD_PARTY_BINARY_COMPONENTS, WINTUN_COMPONENT,
};
pub use types::{
    ApplyActionPlan, RouteEntry, RoutingAction, WfpAction, WfpFilterAction, WfpFilterId,
    WfpFilterRecord, WfpFilterSpec, WfpLayerKey,
};
pub use vpn_discovery::{
    looks_like_vpn, merge_candidates, MockVpnDiscovery, NoopVpnDiscovery, VpnCandidate,
    VpnCandidateSource, VpnDiscoveryPort, VPN_NAME_KEYWORDS,
};
// `RouteEntry` carries a `RouteTableRef`, so re-export it at the crate root
// next to `RouteEntry` (consumers construct `RouteEntry` with
// `RouteTableRef::Main` on the Windows path).
pub use enforcement::RouteTableRef;
pub use windows_api::{MockWindowsApi, WindowsApiPort};
