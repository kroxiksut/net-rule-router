//! Wire-format request and response payload types for production IPC
//! handlers, living in `nrr-shared` so that both server and client crates
//! can reference the same types without crossing the
//! `nrr-ipc-client → nrr-service-runtime` forbidden boundary.
//!
//! The kind-specific validation lives in the
//! `nrr-service-runtime::ipc_handlers::providers::MutationExecutor`
//! impl; this module only defines the wire shapes.
//!
//! These types are deliberately distinct from the domain-shaped DTOs in
//! [`crate::ipc_dto`] (those exist for cross-crate type-checking, not
//! transport) and from internal service-runtime state types. Each
//! handler deserialises an `IpcRequestEnvelope` payload into the
//! matching `*Request` here, transforms, and serialises a `*Response`
//! back to the envelope.
//!
//! Field naming uses kebab-case to stay consistent with
//! `IpcRequestEnvelope` / `IpcResponseEnvelope` (also kebab-case). All
//! types are owned (no borrowed lifetimes).

use serde::{Deserialize, Serialize};

use crate::auto_rule::RuleOrigin;
use crate::diagnostics_dto::{
    AuditEntryDto, AuditEntryFilter, DiagnosticsStatusDto, LogEntryDto, LogEntryFilter,
    SecurityAlertDto,
};
use crate::pagination::{PageResult, PaginationParams};
use crate::third_party::ThirdPartyComponentStatus;
use crate::RouteRole;

// ── ContractNegotiate ────────────────────────────────────────────────────────

/// Stable identifier for the kind of client. Used for audit attribution and,
/// where the OS cannot prove what connected, as a self-declaration that can
/// only NARROW what the caller may do — see [`crate::ipc::IpcClientProfile`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContractNegotiateClientKind {
    Gui,
    Tray,
    /// The administrative console (`nrr-cli`). It reads and diagnoses; it never
    /// changes policy, and says so on connect.
    Console,
}

impl ContractNegotiateClientKind {
    /// The profile a caller declaring this kind may hold at most.
    ///
    /// A declaration can only take capability away. On Windows the profile is
    /// PROVEN from the connecting executable, so this narrows an already-known
    /// answer; on Unix nothing proves the executable, so a caller that declares
    /// itself a console is simply held to a console's limits. Neither case lets
    /// a declaration grant anything.
    pub const fn declared_ceiling(self) -> crate::ipc::IpcClientProfile {
        match self {
            Self::Gui => crate::ipc::IpcClientProfile::GuiInteractive,
            Self::Tray => crate::ipc::IpcClientProfile::TrayLightweight,
            Self::Console => crate::ipc::IpcClientProfile::AdminConsole,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ContractNegotiateRequest {
    pub client_version: u32,
    pub client_kind: ContractNegotiateClientKind,
    #[serde(default)]
    pub supported_features: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ContractNegotiateResponse {
    pub server_version: u32,
    pub negotiated_protocol: u32,
    pub session_id: String,
    /// Semver of the running service binary
    /// (`env!("CARGO_PKG_VERSION")` of `nrr-windows-service`). Carried
    /// over the wire so the GUI can show "Service X.Y.Z vs App
    /// A.B.C" in the compatibility banner without a second probe.
    ///
    /// `#[serde(default)]` keeps the field optional: older services
    /// that don't emit it round-trip as an empty string on newer
    /// clients, and the GUI degrades by showing only the protocol
    /// numbers in that case.
    #[serde(default)]
    pub service_version: String,
}

// ── ServiceHealth ────────────────────────────────────────────────────────────

/// Empty request body for `ServiceHealthGet`. We model it explicitly
/// instead of accepting any JSON — handlers reject malformed bodies
/// uniformly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ServiceHealthRequest {}

/// Wire-format mirror of the GUI's "service health" surface. `components`
/// carries the aggregator's per-component breakdown, so a `worst_severity` of
/// "degraded" always names what is degraded. `degraded_modes` stays empty until
/// the runtime tracks named modes; the field is in the schema so filling it
/// later is non-breaking.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServiceHealthResponse {
    pub service_state: String,
    pub worst_severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision_id: Option<String>,
    pub components: Vec<HealthComponentResponse>,
    pub degraded_modes: Vec<String>,
    /// Live fake-IP datapath status. `desired && !running` means the
    /// user's fake-IP toggle is ON but the datapath is down — the GUI
    /// must surface that outage instead of staying silent. Optional
    /// (`#[serde(default)]`): older services omit the field and older
    /// clients ignore it, so the wire schema stays compatible both ways.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fake_ip_datapath: Option<FakeIpDatapathDto>,
}

/// Wire mirror of the service's fake-IP datapath probe, carried inside
/// [`ServiceHealthResponse`]. Kebab-case on the wire: `"fake-ip-datapath"`
/// with `"desired"` / `"running"` / `"zombies"` members.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FakeIpDatapathDto {
    /// What the user's toggle last requested.
    pub desired: bool,
    /// Whether a live stack thread is currently attached.
    pub running: bool,
    /// Detached stack threads that ignored the stop grace and are still
    /// being reaped. Non-zero means a start may be deferred.
    pub zombies: u32,
}

/// Per-component health entry. Currently every response has an empty
/// `components` vector; reserved for future wiring.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HealthComponentResponse {
    pub component: String,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ── SnapshotInterfaces ───────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct SnapshotInterfacesRequest {
    /// When `true`, the handler asks the adapter monitor to drop its
    /// cached snapshot and re-enumerate adapters synchronously.
    #[serde(default)]
    pub force_refresh: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SnapshotInterfacesResponse {
    /// `"windows-live"` in production, `"fallback-mock"` when the
    /// adapter monitor is in fallback mode.
    pub data_source: String,
    pub adapters: Vec<AdapterEntry>,
    /// Runtime routing state for the secondary route role.
    /// Drives the Fail-Closed banner in `InterfacesRoutesSection.qml`.
    /// `None` from older servers / when route-policy hasn't been
    /// resolved yet — the GUI treats `None` as "no banner".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary: Option<SecondaryRouteStateDto>,
    /// Rich, GUI-shaped adapter rows for the live
    /// "Interfaces & routes" list. The thin [`adapters`](Self::adapters)
    /// field above is preserved for back-compat (binding validation,
    /// fail-closed probe); this field carries the enrichment the GUI
    /// needs to re-render the list on every "Refresh interfaces" without
    /// relaunching the process.
    ///
    /// `#[serde(default)]` (empty vec) keeps the wire schema backward
    /// compatible both ways: an older server omits the field (a newer
    /// client reads `[]` → keeps its current list), and a newer server's
    /// payload still deserialises on an older client.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rows: Vec<InterfaceRowDto>,
}

/// Wire mirror of the enriched adapter row the GUI list
/// renders. Slug strings match the GUI cold-start `interface_rows_json`
/// shape one-to-one, so a live-refresh row renders identically to a
/// cold-start one. The `From<&InterfaceRouteRow>` builder lives in
/// `nrr-platform-windows::interface_rows` (the only crate that sees both
/// the enriched row type and this DTO without crossing a dependency
/// boundary).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct InterfaceRowDto {
    pub persistent_id: String,
    pub adapter_name: String,
    pub windows_name: String,
    pub interface_description: String,
    pub interface_type: String,
    pub is_bluetooth_like: bool,
    pub local_ip: String,
    pub gateway: String,
    pub dns_servers: String,
    pub has_default_route: bool,
    /// Whether traffic can actually leave through this interface: a classic
    /// gateway, or a default-style route on it with a real next-hop. Distinct
    /// from `has_default_route`, which the enumeration derives as "a gateway
    /// is present" and which therefore reads `false` for every healthy
    /// gateway-less tunnel (OpenVPN / WireGuard install split-default routes
    /// instead of a gateway). Lets the GUI tell "no way
    /// out" (host-only virtual adapter) from "no gateway, but routed".
    ///
    /// Deliberately three-valued: `None` = the sender did not evaluate it (a
    /// service that predates the field, or a query that failed), which is NOT
    /// the same as `Some(false)` = "evaluated, and there is no way out".
    /// Collapsing the two would let a missing signal manufacture a warning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_forwarding_path: Option<bool>,
    /// `"available"` / `"unavailable"` / `"requires-check"`.
    pub availability: String,
    /// `"primary"` / `"secondary"` / `None` when unbound. The service
    /// leaves this `None` on a live refresh; the GUI re-applies the
    /// user's role bindings from its preferences.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_role: Option<String>,
    /// `RouteSelectionState` slug (e.g. `"not-selected"`, `"selected"`).
    pub route_state: String,
    pub observed_facts: InterfaceObservedFactsDto,
    pub derived_assessment: InterfaceDerivedAssessmentDto,
    pub recommendation: InterfaceRecommendationDto,
}

/// Observed connectivity facts (kebab-case wire shape).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct InterfaceObservedFactsDto {
    pub connectivity_state: String,
    pub external_ip_status: String,
    #[serde(default)]
    pub external_ip: Option<String>,
    pub external_probe_attempted: bool,
    pub external_probe_note: String,
}

/// Heuristic VPN/virtual/service classification (kebab-case).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct InterfaceDerivedAssessmentDto {
    pub vpn_tunnel_likelihood: String,
    pub virtual_interface_likelihood: String,
    pub service_interface_likelihood: String,
    pub classification: String,
    pub confidence_percent: u8,
    pub heuristic_only: bool,
    pub signals: Vec<String>,
}

/// Advisory route-role recommendation (kebab-case wire shape).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct InterfaceRecommendationDto {
    pub class: String,
    pub confidence: String,
    pub advisory_only: bool,
    pub summary: String,
    pub key_signals: Vec<String>,
    pub excluded_alternatives: Vec<String>,
}

/// Runtime state for the secondary route role. Carried
/// alongside the adapter list so the GUI can render decision-time
/// posture without a separate IPC roundtrip.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct SecondaryRouteStateDto {
    /// `true` ⇒ behavior_mode is `StrictSecondaryFailClosed` AND the
    /// secondary adapter is currently unavailable, so traffic that
    /// would route through secondary is being blocked. The GUI
    /// surfaces this as a top-level banner. The flag is decision-time
    /// runtime state, not stored policy.
    #[serde(default)]
    pub fail_closed_active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AdapterEntry {
    pub persistent_id: String,
    pub adapter_name: String,
    pub ipv6_if_index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_address: Option<String>,
    pub windows_name: String,
    pub interface_description: String,
    pub interface_type: String,
    pub oper_status: String,
}

// ── SnapshotDiagnostics ──────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct SnapshotDiagnosticsRequest {
    /// When `true`, the handler additionally pulls a synthetic explain
    /// sample from the diagnostics facade and embeds it in the response.
    /// Reserved for future wiring; today the field is parsed but
    /// the response always carries `explain_sample = None`.
    #[serde(default)]
    pub include_explain_sample: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SnapshotDiagnosticsResponse {
    pub status: DiagnosticsStatusDto,
    /// Reserved: explain sample DTO. Today always `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explain_sample: Option<serde_json::Value>,
}

// ── LogsList / AuditList ─────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LogsListRequest {
    #[serde(default)]
    pub filter: LogEntryFilter,
    #[serde(default)]
    pub pagination: PaginationParams,
}

pub type LogsListResponse = PageResult<LogEntryDto>;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AuditListRequest {
    #[serde(default)]
    pub filter: AuditEntryFilter,
    #[serde(default)]
    pub pagination: PaginationParams,
}

pub type AuditListResponse = PageResult<AuditEntryDto>;

// ── SecurityAlerts ───────────────────────────────────────────────────────────

/// Payload schema for `MutationKind::SecurityAlertAck` and
/// `MutationKind::SecurityAlertResolve`. Both kinds share the same
/// shape — the executor branches on `mutation_kind`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SecurityAlertMutationPayload {
    pub alert_id: String,
    /// Optional human-readable reason recorded alongside the audit
    /// event. Empty / missing ⇒ a generic system-generated reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SecurityAlertsRequest {
    /// Reserved: state filter (`"active"`, `"acknowledged"`,
    /// `"resolved"`, `"all"`). Today the handler always returns active
    /// alerts and ignores the field.
    #[serde(default)]
    pub state_filter: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SecurityAlertsResponse {
    pub alerts: Vec<SecurityAlertDto>,
}

// ── RulesList ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RulesRouteFilter {
    Primary,
    Secondary,
    #[default]
    All,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RulesListRequest {
    #[serde(default)]
    pub route: RulesRouteFilter,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RulesListResponse {
    pub rows: Vec<RuleRowEntry>,
    /// Stable rule-type slugs supported by the current revision
    /// (`"zone"`, `"domain"`, `"exact-ip"`, `"application"`).
    pub supported_rule_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleRowEntry {
    pub id: String,
    pub rule_type: String,
    pub match_value: String,
    /// Display route slug: `"primary"`, `"secondary"`, or `"block"`. The
    /// producer emits `"block"` for a `RuleAction::Block` rule regardless of
    /// which bucket it lives in; the GUI maps it back to the «Блокировать»
    /// label and its own bucket-plus-`action` wire form on save.
    pub target_route: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub enabled: bool,
    /// `"ok"` / `"warning"` / `"error"` — derived from
    /// `rule_value_validation::validate_rule_value`.
    pub validation_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_message_key: Option<String>,
    /// Read-only annotation: when the OS `hosts` file pins this rule's
    /// hostname to an address, the service fills this so the GUI can show
    /// a "Blocked in hosts" / "Redirected by system" badge. The `hosts`
    /// file is applied by the resolver BEFORE traffic reaches NRR, so NRR
    /// cannot override it — this is purely informational. Additive +
    /// optional: older peers and non-hostname rules simply omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts_override: Option<HostsOverrideDto>,
    /// Provenance of a rule the application authored on the user's behalf,
    /// carried straight through from
    /// [`RuleDto::origin`](crate::rules_json::RuleDto::origin) so the rules
    /// table can mark the row and name the site it belongs to. `None` — the
    /// overwhelmingly common case — means the user typed the rule. Additive
    /// and optional: a peer that predates the field simply omits it, and no
    /// row loses its identity for the lack of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<RuleOrigin>,
}

/// Read-only OS `hosts`-file override annotation for one rule row.
///
/// Populated only when a rule's exact hostname matches an entry in the OS
/// `hosts` file. `blocking` is `true` when the pinned IP is loopback
/// (`127.0.0.0/8`) or unspecified (`0.0.0.0`) — the ad-block "black-hole"
/// convention; `false` for a real redirect target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HostsOverrideDto {
    /// The IPv4 address the `hosts` file maps the hostname to, as a string
    /// (e.g. `"127.0.0.1"`, `"203.0.113.7"`).
    pub ip: String,
    /// `true` → the hostname is blocked (loopback/unspecified); `false` →
    /// redirected to the real `ip`.
    pub blocking: bool,
}

// ── PresetImport ─────────────────────────────────────────────────────────────

/// Wire payload schema for `MutationKind::PresetImport`.
///
/// Carries the bytes of one or both rules-file presets plus the host-side
/// settings needed to canonicalize them. Service-side deserialization +
/// validation lives in `nrr-service-runtime::production_mutation_executor`.
///
/// # Single-route vs both-routes
///
/// - **Single-route import**: exactly one of `primary_bytes_b64` /
///   `secondary_bytes_b64` is `Some`. The `route` field disambiguates if
///   both could have been intended (and the other route's rules in the
///   resulting revision are carried over from the current active config).
/// - **Both-routes import**: both `*_bytes_b64` fields are `Some`. One
///   revision covers both routes. `route` is ignored.
/// - At least one of the two byte fields must be `Some`; an empty payload
///   is rejected with `payload-invalid`.
///
/// # Byte encoding
///
/// File bytes are base64-encoded (RFC 4648 standard alphabet, padding
/// required). The service decodes them with [`base64::engine::general_purpose::STANDARD`]
/// and then runs them through `validate_preset_bytes` — which enforces
/// the 1 MiB cap and UTF-8 encoding before parse.
///
/// # Idempotency
///
/// Optional `content_hash_*` fields let the client pre-compute the SHA-256
/// of the file bytes (over canonical bytes) so the executor can skip the
/// activation when the hash matches the current active revision's hash
/// for that route. This is a fast path for auto-open-on-launch where the
/// file hasn't changed; the executor still falls back to a full
/// re-canonicalize-and-compare when the hash is `None`.
///
/// # Correlation
///
/// `correlation_id` is the client-issued identifier surfaced in
/// `StatusUpdateEvent::MutationProgress` push events. When absent, the
/// service generates one.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PresetImportPayload {
    /// Target route for single-route import. Required when exactly one of
    /// `primary_bytes_b64` / `secondary_bytes_b64` is `Some` **and** the
    /// caller wants to be explicit (omitting it is allowed if the present
    /// byte field unambiguously names the target). Ignored when both byte
    /// fields are `Some`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<RouteRole>,

    /// Base64-encoded UTF-8 bytes for the primary route's rules file.
    /// When `Some`, primary's rules are replaced by these bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_bytes_b64: Option<String>,

    /// Base64-encoded UTF-8 bytes for the secondary route's rules file.
    /// When `Some`, secondary's rules are replaced by these bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_bytes_b64: Option<String>,

    /// Mirrors `UiPreferences::include_child_processes`. Threads through
    /// to `canonicalize_preset_rules` so application rules are matched
    /// against child processes consistently with GUI-edited rules.
    pub include_child_processes: bool,

    /// When `true`, rules that are *disabled* in the source preset
    /// (commented recognizable lines, e.g. application rules left off
    /// pending per-process routing) are dropped during import instead of
    /// stored as toggled-off rules. Backs the GUI "import only active
    /// rules" toggle. Defaults to `false` (import everything, including
    /// disabled) for back-compat when an older client omits the field.
    #[serde(default)]
    pub import_only_active: bool,

    /// Optional SHA-256 hex of the primary file's canonical bytes,
    /// computed client-side. Enables idempotent skip when it matches the
    /// active revision's hash for primary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash_primary: Option<String>,

    /// Optional SHA-256 hex of the secondary file's canonical bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash_secondary: Option<String>,

    /// Optional GUI-issued correlation ID. Surfaced verbatim in
    /// `MutationProgress` push events for end-to-end tracing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

/// Decoded import target after [`PresetImportPayload::target`] validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresetImportTarget {
    /// Only one of the two byte fields is populated. The variant carries
    /// the route the bytes belong to.
    SingleRoute(RouteRole),
    /// Both byte fields are populated. The resulting revision replaces
    /// rules for both routes in one atomic submit.
    BothRoutes,
}

/// Why a [`PresetImportPayload`] failed structural validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresetImportPayloadError {
    /// Neither `primary_bytes_b64` nor `secondary_bytes_b64` is `Some` —
    /// nothing to import.
    NoBytesSupplied,
    /// Exactly one of the byte fields is `Some`, the caller specified a
    /// `route`, and the `route` does not match the populated byte field.
    /// (e.g. `route = Secondary` but only `primary_bytes_b64` is set.)
    RouteMismatch,
}

impl PresetImportPayload {
    /// Resolves the import target from the byte-field combination,
    /// cross-checking the explicit `route` hint when supplied.
    pub fn target(&self) -> Result<PresetImportTarget, PresetImportPayloadError> {
        match (
            self.primary_bytes_b64.as_ref(),
            self.secondary_bytes_b64.as_ref(),
        ) {
            (None, None) => Err(PresetImportPayloadError::NoBytesSupplied),
            (Some(_), Some(_)) => Ok(PresetImportTarget::BothRoutes),
            (Some(_), None) => match self.route {
                None | Some(RouteRole::Primary) => {
                    Ok(PresetImportTarget::SingleRoute(RouteRole::Primary))
                }
                Some(RouteRole::Secondary) => Err(PresetImportPayloadError::RouteMismatch),
            },
            (None, Some(_)) => match self.route {
                None | Some(RouteRole::Secondary) => {
                    Ok(PresetImportTarget::SingleRoute(RouteRole::Secondary))
                }
                Some(RouteRole::Primary) => Err(PresetImportPayloadError::RouteMismatch),
            },
        }
    }
}

// ── PresetExportGet ──────────────────────────────────────────────────────────

/// Read-only export of the active revision's rules for
/// one route as a canonical rules-file txt blob.
///
/// The service:
/// 1. Loads the active revision via `RevisionsRepository::get_active`.
/// 2. Decodes the relevant route's `rules_json` via
///    [`crate::rules_json::CanonicalRuleSet::from_canonical_string`].
/// 3. Maps the canonical rule set back to a `RulesFileParsed`.
/// 4. Serialises through `nrr_domain::rules_file::write_rules_file`,
///    optionally prepending preset metadata.
/// 5. Wraps the resulting UTF-8 bytes in base64 (standard alphabet,
///    padded) for wire framing.
///
/// Unknown (Pro) sections from the original import are **not** preserved
/// in this revision (the canonical store drops them). Round-trip Pro
/// preservation is a follow-up.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PresetExportGetRequest {
    /// Which route's rules to export.
    pub route: RouteRole,
    /// When `true`, prepend `# NetRuleRouter preset — version 1` and any
    /// available preset metadata headers (name/description/author/preset-version).
    /// When `false`, the output starts directly with the first section.
    #[serde(default)]
    pub include_metadata: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PresetExportGetResponse {
    /// Base64-encoded canonical txt bytes of the rules file for the
    /// requested route. UTF-8 inside the base64 wrapper.
    pub file_bytes_b64: String,
    /// SHA-256 hex of the unwrapped UTF-8 bytes. The GUI uses this as
    /// `last_file_synced_hash_<role>` for divergence detection on
    /// subsequent close-window events.
    pub content_hash: String,
}

// ── SettingsExportFull ───────────────────────────────────────────────────────

/// Read-only export of the full user settings as a YAML
/// blob conforming to docs/en/rules-file-format.md Settings Export Format
///
/// Includes: adapter bindings (system ID, user label, confirmation
/// status), rules file paths (paths only — the on-disk content lives in
/// the txt files separately), behavior settings (route mode).
///
/// Excludes: UI preferences (theme, language, accessibility, route
/// display labels) — device-specific, carried over per device on a
/// Free→Pro migration; internal revision metadata; runtime probe state.
///
/// # Client-supplied fields
///
/// The service is the source of truth for adapter bindings and route
/// behavior mode, but NOT for the user's chosen rules-file paths on
/// disk (those live in `UiPreferences::last_saved_path_<role>` —
/// device-local). The caller forwards the paths in this request; the
/// service splices them into the YAML at the `rules_files:` block.
/// When omitted, the corresponding YAML field is left empty.
///
/// # Migration note
///
/// `file_change_behavior` and `include_child_processes` (per docs/en/rules-file-format.md Settings Export Format) are GUI preferences that are migrating to per-SID service
/// storage but are not yet wired. This export emits the YAML without
/// those keys; they'll be added as a follow-up once that storage settles.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SettingsExportFullRequest {
    /// User-chosen path of the primary rules file (from
    /// `UiPreferences::last_saved_path_primary`). Empty/omitted ⇒ no
    /// path written to YAML.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules_file_path_primary: Option<String>,
    /// Same for secondary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules_file_path_secondary: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SettingsExportFullResponse {
    /// Base64-encoded UTF-8 YAML bytes. Top-level key is
    /// `nrr_settings_export` per docs/en/rules-file-format.md Settings Export Format The GUI writes these
    /// to the user-chosen path via `Qt.labs.platform.FileDialog::Save`.
    pub yaml_bytes_b64: String,
    /// SHA-256 hex of the unwrapped UTF-8 YAML bytes. Reserved for
    /// future "save back" symmetry with preset exports; not used yet,
    /// but plumbed now so a later round doesn't need a wire bump.
    pub content_hash: String,
}

// ── RulesMergePreview ─────────────────────────────────────────────────────────

/// Request for the two-way merge preview op
/// (`rules.merge-preview`). The service reconciles the caller's linked
/// rules-file *text* against its OWN active revision (resolved per-SID with
/// read-through to the shared baseline, like `rules.list`), so the request
/// carries only the file text, the conflict policy, and any per-conflict
/// resolutions the user has picked. Called twice: first with an empty
/// `resolutions` list (buckets + unresolved conflicts under Union), then again
/// with the picks (final merged rules-json).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MergePreviewRequest {
    /// Canonical rules-file text of the primary bound file. Parsed and
    /// canonicalised by the domain parser (NOT the raw preset parser) so its
    /// rules pair with the already-canonical service revision by identity.
    #[serde(default)]
    pub primary_text: String,
    /// Canonical rules-file text of the secondary bound file.
    #[serde(default)]
    pub secondary_text: String,
    /// Conflict-resolution policy. Defaults to
    /// [`crate::merge_dto::MergePolicyDto::Union`].
    #[serde(default)]
    pub policy: crate::merge_dto::MergePolicyDto,
    /// Per-conflict user picks. Empty on the first (preview) call.
    #[serde(default)]
    pub resolutions: Vec<crate::merge_dto::ConflictResolutionDto>,
    /// The current global "apply rules to child processes" setting, applied
    /// uniformly to app rules during file canonicalisation (must match the
    /// value used at import time so identity keys pair).
    #[serde(default)]
    pub include_child_processes: bool,
}

/// Response for `rules.merge-preview`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MergePreviewResponse {
    /// The merge outcome: three buckets, the conflicts, and the merged book
    /// serialised as canonical rules-json for `startRulesReviewFlow`.
    pub result: crate::merge_dto::MergeResultDto,
}

// ── MutationSubmit ───────────────────────────────────────────────────────────

/// Stable kind tag. The wire layer doesn't validate the per-kind
/// payload schema — that's the responsibility of the
/// `MutationExecutor` impl in `nrr-service-runtime`, which owns the
/// kind-specific validation and storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MutationKind {
    RulesUpdate,
    RouteBindingsUpdate,
    /// Import a preset txt file (one route or both). Payload
    /// schema: [`PresetImportPayload`].
    PresetImport,
    /// Deprecated — use the read-only IPC op
    /// `PresetExportGet` instead. The mutation-submit variant is wire-stable
    /// but unused; new clients must not send it.
    #[deprecated(
        since = "0.1.0",
        note = "use IpcOperationName::PresetExportGet (read-only) instead; \
                this variant is wire-stable for backwards compatibility but \
                handlers return `not-implemented`"
    )]
    PresetExport,
    /// Deprecated — use the read-only IPC op
    /// `SettingsExportFull` instead. The mutation-submit variant is
    /// wire-stable but unused.
    #[deprecated(
        since = "0.1.0",
        note = "use IpcOperationName::SettingsExportFull (read-only) instead; \
                this variant is wire-stable for backwards compatibility but \
                handlers return `not-implemented`"
    )]
    SettingsExport,
    /// Acknowledge a security alert. Wire payload schema:
    /// `{alert-id: string, reason?: string}`. Acknowledgement creates a
    /// new audit event and updates the alert state to `Acknowledged`.
    SecurityAlertAck,
    /// Resolve a security alert. Wire payload schema:
    /// `{alert-id: string, reason?: string}`. Resolution is the terminal
    /// state and creates a new audit event.
    SecurityAlertResolve,
    /// Discard the caller principal's own per-SID rule
    /// divergence and fall back to the admin baseline (read-through
    /// resumes). Wire payload schema: `{correlation-id?: string}` — reset
    /// carries no content. Routed as a `user-scoped-mutation` (the user
    /// resets *its own* rules; non-elevated). The server derives the
    /// target principal from the caller SID, so a reset can only ever
    /// clear the caller's own partition, never the baseline.
    RulesResetToBaseline,
}

impl MutationKind {
    /// Whether this kind changes which traffic goes where — i.e. whether the
    /// administrative rules lock applies to it.
    ///
    /// Declared once, next to the enum, so a new variant is decided here
    /// rather than being silently omitted by whichever gate happens to list
    /// kinds. Security-alert acknowledgement and the deprecated export kinds
    /// are not rule changes: a locked-down user must still be able to clear an
    /// alert banner, and refusing that would only teach them to ignore it.
    #[allow(deprecated)] // the export variants stay wire-stable
    pub fn changes_rules(self) -> bool {
        match self {
            Self::RulesUpdate
            | Self::PresetImport
            | Self::RulesResetToBaseline
            | Self::RouteBindingsUpdate => true,
            Self::PresetExport
            | Self::SettingsExport
            | Self::SecurityAlertAck
            | Self::SecurityAlertResolve => false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MutationSubmitRequest {
    pub mutation_kind: MutationKind,
    pub payload: serde_json::Value,
    /// `true` ⇒ compute review summary, return a confirmation token,
    /// don't persist anything. `false` ⇒ resolve the
    /// envelope-level `confirmation_token` against the token store,
    /// execute the mutation, return an `operation_id`.
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewRiskLevel {
    Low,
    Medium,
    High,
    /// Reserved for catastrophic configurations
    /// (lock-out scenarios). No production scoring path emits this
    /// today; the level exists so the wire contract is stable when
    /// future binding-aware detection lands.
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ReviewSummaryResponse {
    pub diff_summary: String,
    pub provenance: String,
    pub risk_level: ReviewRiskLevel,
    pub requires_review: bool,
    pub changed_fields: Vec<String>,
    /// Structured risk signals the codegen surfaced
    /// for this candidate. Each signal carries a `kind` discriminator
    /// (kebab-case) and zero or more typed payload fields. Emitted in
    /// the order `score_candidate` produces them so the review UI can
    /// render them as a deterministic, sorted list. Empty vector when
    /// `risk_level == Low` (no signals contributed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risk_signals: Vec<RiskSignalDto>,
    /// Per-rule diff buckets projected from the
    /// domain `ReviewSummary`. Rendered in the GUI's
    /// `ReviewDiffDialog` as three columns: Added | Removed |
    /// Modified+Retargeted. Each `RuleSummaryEntryDto` carries a
    /// stable `id`, a pre-formatted `display` string, and the
    /// `route` slug (`"primary"` / `"secondary"`).
    ///
    /// All four vectors are sorted deterministically (Added →
    /// Removed → Modified → Retargeted, lexicographic by id within
    /// each bucket) so two equal inputs always produce the same
    /// wire bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules_added: Vec<RuleSummaryEntryDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules_removed: Vec<RuleSummaryEntryDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules_modified: Vec<RuleSummaryEntryDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules_retargeted: Vec<RuleSummaryEntryDto>,
    /// Pro-only sections preserved verbatim from the
    /// imported preset file. Each entry names a section (e.g. `CIDR`,
    /// `Ports`) that the Free edition parses but does not apply, plus
    /// the number of entries it carries. The GUI renders them in the
    /// review diff with a `pro.svg` badge so the user knows the file
    /// contains Pro-tier rules being preserved unchanged.
    ///
    /// Currently always empty — the active revision storage drops
    /// unknown sections. The wire field is plumbed now so a future
    /// schema-bump that adds `unknown_sections_json` to the `revisions`
    /// table requires only server-side population — the GUI is ready.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pro_sections: Vec<ProSectionSummaryDto>,
}

/// One Pro-only section preserved from the imported
/// preset file. See [`ReviewSummaryResponse::pro_sections`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProSectionSummaryDto {
    /// Raw section name as it appeared in the file, e.g. `"CIDR"`,
    /// `"Ports"`. Not localized — readers display it verbatim.
    pub name: String,
    /// Number of rule entries (active + disabled) in this section.
    /// Displayed as "<name>: N rules preserved as-is (Pro feature)".
    pub preserved_count: u32,
}

/// Wire-form of `nrr_domain::review::RuleSummaryEntry`.
///
/// One row in the review diff. `display` is pre-formatted server-
/// side via `nrr_domain::review::RuleSummary` (e.g.
/// `"api.example.com"` for ExactFqdn, `"*.example.com"` for
/// SuffixDomain, `"chrome.exe (app)"` for application rules, with
/// the `(from → to)` suffix for retargets). The GUI renders the
/// string as-is — locale-agnostic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleSummaryEntryDto {
    /// Stable rule id (e.g. `"r-001"`).
    pub id: String,
    /// Human-readable display for the review UI.
    pub display: String,
    /// `"primary"` or `"secondary"`. For retargeted rules: the
    /// destination route.
    pub route: String,
    /// Whether the rule takes part in routing. A disabled rule is a
    /// real diff entry (it is stored and shipped to the service) but
    /// enforces nothing, so the review UI marks it instead of listing
    /// it as an ordinary change.
    ///
    /// Additive on the wire: an omitted field reads as `true` and an
    /// enabled entry serialises exactly as before this field existed,
    /// so a peer on either side of the upgrade sees unchanged bytes
    /// for the common case.
    #[serde(
        default = "rule_summary_enabled_default",
        skip_serializing_if = "rule_summary_enabled_is_default"
    )]
    pub enabled: bool,
}

/// Wire default for [`RuleSummaryEntryDto::enabled`] — a peer that
/// predates the field only ever reported rules it would enforce.
fn rule_summary_enabled_default() -> bool {
    true
}

/// Keeps the default out of the serialised form (see the field docs).
fn rule_summary_enabled_is_default(enabled: &bool) -> bool {
    *enabled == rule_summary_enabled_default()
}

/// Wire-form mirror of `nrr_domain::risk::RiskSignal`.
///
/// Tagged enum with kebab-case `kind` discriminator: `broad-suffix-scope`,
/// `moderate-suffix-scope`, `default-behavior-changed`,
/// `mass-change-count`, `secondary-reroute`,
/// `unstable-interface-binding`, `unknown-source`,
/// `linked-suspicious-delta`, `rule-set-emptied`, `high-removal-ratio`,
/// `overlapping-rules`, `fail-closed-activation`.
///
/// Field names use kebab-case at the JSON layer. Payloads carry the
/// minimum metadata the GUI needs to render a localized message
/// (label / count / apex / prev_total / removed_pct).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// `rename_all_fields = "kebab-case"` is essential: the QML reads
// e.g. `signal["rule-count"]`, but without this attribute the
// serializer would keep `rule_count` (snake_case) on the wire and
// the GUI's substitution `{rule-count}` → value silently no-ops.
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum RiskSignalDto {
    BroadSuffixScope {
        label: String,
    },
    ModerateSuffixScope {
        label: String,
    },
    DefaultBehaviorChanged,
    MassChangeCount {
        count: u32,
    },
    SecondaryReroute {
        rule_count: u32,
    },
    UnstableInterfaceBinding,
    UnknownSource,
    LinkedSuspiciousDelta,
    /// Previous active revision had `prev_total`
    /// rules and the candidate has zero.
    RuleSetEmptied {
        prev_total: u32,
    },
    /// `removed_pct` % of the previous revision's
    /// rules are being removed.
    HighRemovalRatio {
        removed_pct: u8,
    },
    /// `apex` has both an `ExactFqdn` rule and a
    /// `SuffixDomain` rule in the candidate.
    OverlappingRules {
        apex: String,
    },
    /// `behavior_mode` is transitioning to
    /// `StrictSecondaryFailClosed`.
    FailClosedActivation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MutationDryRunResponse {
    pub review_summary: ReviewSummaryResponse,
    pub confirmation_token: String,
    pub review_risk_level: ReviewRiskLevel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MutationConfirmResponse {
    pub operation_id: String,
}

// ── OperationStatusGet ───────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct OperationStatusRequest {
    pub operation_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct OperationStatusResponse {
    /// `"queued"` / `"running"` / `"completed"` / `"failed"`.
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_hint: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<OperationErrorResponse>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct OperationErrorResponse {
    pub code: String,
    pub message: String,
}

// ── ProductImpactDisableTemporary ────────────────────────────────────────────

/// Same two-phase shape as `MutationSubmitRequest` — dry-run mints a
/// confirmation token (envelope class = `ReadSnapshot`) and confirm
/// consumes it (envelope class = `SafeDisable`). The runtime never
/// disables the apply layer without a fresh user-visible review.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProductImpactDisableRequest {
    /// Free-form reason captured for audit. The handler does not parse
    /// it — operators read it in audit reviews.
    pub reason: String,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProductImpactDisableDryRunResponse {
    pub review_summary: ReviewSummaryResponse,
    pub confirmation_token: String,
    pub review_risk_level: ReviewRiskLevel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ProductImpactDisableConfirmResponse {
    pub operation_id: String,
}

// ── InterfacesRefreshRequest ─────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct InterfacesRefreshRequest {}

/// Synchronous: the client blocks until the underlying adapter
/// re-enumeration completes (5-second budget enforced by the
/// production provider impl).
pub type InterfacesRefreshResponse = SnapshotInterfacesResponse;

// ── StatusUpdatesSubscribe ───────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct StatusUpdatesSubscribeRequest {
    /// Stable client id chosen by the GUI/Tray (not the per-pipe
    /// session id). Lets the server attribute dropped-event counters
    /// across reconnects of the same client process.
    pub client_id: String,
    /// Last `event_id` the client successfully processed before the
    /// previous disconnect. `None` ⇒ first-time subscribe; the client
    /// will pick up from the current head.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_event_id: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct StatusUpdatesSubscribeResponse {
    pub subscription_id: String,
    pub current_event_id: u64,
    /// `true` when the client's `last_seen_event_id` is older than the
    /// oldest event still buffered. The client should issue a
    /// `SnapshotInitialGet` to resync; pushed events from this point
    /// on are *new* events only, the gap is not replayed.
    pub gap_detected: bool,
}

/// Status events the service broadcasts to every subscriber. New
/// variants append; clients that don't recognise a kind drop it.
///
/// Wire-tagged externally (`tag = "type"`) so a client can demux by
/// reading just the discriminator before deserialising the body. We
/// use `"type"` rather than `"kind"` because some variants carry a
/// per-variant `kind` field of their own (e.g. `AlertRaised.kind`).
#[derive(Clone, Debug, Serialize, Deserialize)]
// `rename_all` renames the VARIANTS only. Without `rename_all_fields` the
// payload fields stay snake_case while every QML reader indexes kebab-case,
// so multi-word fields silently read as undefined.
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    tag = "type"
)]
pub enum StatusUpdateEvent {
    /// Service-level health changed (e.g. `Running` → `Degraded`). The
    /// client should refresh its `ServiceHealthGet` snapshot.
    HealthChanged {
        service_state: String,
        worst_severity: String,
    },
    /// Adapter set changed (interface added/removed/role-changed). The
    /// client should refresh `SnapshotInterfacesGet`.
    AdaptersChanged { data_source: String },
    /// New security alert raised. Subscribers paint the alert badge
    /// without a separate roundtrip.
    AlertRaised { alert_id: String, kind: String },
    /// An operation handle reached `Completed` (mutation, rollback,
    /// safe-disable). Carries the terminal `state` slug
    /// (`"completed"` / `"failed"`).
    OperationFinished {
        operation_id: String,
        state: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_code: Option<String>,
    },
    /// Buffer overflow signal — client should issue
    /// `SnapshotInitialGet` to fully resync. Carries the count of
    /// events dropped on the way out.
    Overflow { dropped_count: u64 },
    // ── Settings push events ──────────────────────────────────────
    /// A revision row's status changed (candidate → active → superseded
    /// / rolled-back / rejected). GUI may refresh its pending list.
    RevisionStatusChanged { revision_id: String, status: String },
    /// A SID's routing-pause state flipped. GUI flips the chip / tray
    /// menu without a re-snapshot.
    RoutingPauseStateChanged { sid: String, paused: bool },
    /// The service-wide `ApplyFailurePolicy` was changed.
    ApplyFailurePolicyChanged { policy: String },
    /// Autostart configuration changed (toggle, registry observation,
    /// or external-override detection). GUI re-renders the General
    /// settings panel.
    AutostartStateChanged {
        enabled: bool,
        last_known_state: String,
    },
    /// Retention settings row was rewritten.
    RetentionSettingsChanged,
    // ── Mutation push events ────────────────────────────────────────
    /// A `MutationSubmit` correlation-id reached a
    /// new lifecycle phase. Tracks the per-mutation flow so the GUI
    /// can drive `MutationsModel.hasInFlight` without polling.
    ///
    /// Distinct from `OperationFinished` (which is operation-id
    /// keyed and only fires on terminal states): `MutationProgress`
    /// is correlation-id keyed (caller-supplied, not service-issued)
    /// and fires on every lifecycle phase — `started`, `completed`,
    /// `failed`. The GUI uses correlation-id to match the event to
    /// the original `rpcMutationSubmit` callback in `pendingRpc`.
    MutationProgress {
        /// Caller-supplied correlation id from `rpcMutationSubmit`.
        correlation_id: String,
        /// Mutation kind slug (matches `MutationKind::as_slug`):
        /// `"rules-update"`, `"route-bindings-update"`, etc.
        mutation_kind: String,
        /// One of: `"started"`, `"completed"`, `"failed"`.
        phase: String,
        /// Wire error code for `phase == "failed"` (matches
        /// `IpcErrorCode` slugs).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_code: Option<String>,
    },
    /// A SID's set of pending auto-rule candidates changed — the service
    /// noticed further hosts a routed site needs and parked them for review
    /// (`auto-rules-mode = suggest`). The tray fetches the list and offers it;
    /// `top_anchor` is the routed host most of the candidates were seen
    /// alongside, used to name the site in the prompt.
    AutoRuleCandidatesChanged {
        sid: String,
        pending_count: u64,
        top_anchor: String,
    },
    /// The additional route (re)connected and the service observed the address
    /// the outside world sees behind it. The tray shows it for a few seconds —
    /// an additional link whose own client cannot report its exit address is
    /// common, and this is the only place the user learns it without leaving
    /// the product.
    ///
    /// Only ever published WITH an address: a probe that found nothing is a
    /// diagnostic, not a notification, so there is no "unknown" spelling here
    /// for a client to have to render.
    SecondaryExternalAddressObserved {
        sid: String,
        /// Human-readable adapter description (the name the interfaces list
        /// shows), so the notice says which link the address belongs to.
        adapter_name: String,
        /// Dotted-quad IPv4 as observed from outside the local NAT.
        external_address: String,
    },
    /// A new block episode was recorded for `sid` and survived muting — the
    /// tray shows it as a notice. Fires once per episode (see
    /// `nrr_domain::block_notice`), not once per retried packet: a blocked
    /// application retries hard, and a notice per attempt would be unusable.
    BlockNoticeRaised {
        sid: String,
        /// What the user is told the destination is — the hostname when
        /// known, the raw address otherwise.
        destination: String,
        /// Image name of the process that tried; empty when unknown.
        app: String,
        /// Reason slug (`"route-unavailable"` / `"not-covered-by-rules"` /
        /// `"blocked-by-rule"` / `"unattributed"`), drives the notice wording.
        reason: String,
        /// Attempts folded into this episode so far.
        attempts: u64,
    },
}

/// Wire frame used for *push* delivery of an event on an existing
/// subscription. Wrapped inside an `IpcResponseEnvelope` whose
/// `request_id = ""` and `correlation_id = subscription_id` (per
/// spec).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct StatusUpdatePushFrame {
    pub event_id: u64,
    pub event: StatusUpdateEvent,
}

// ── StatusUpdatesPoll (deprecated) ───────────────────────────────────────────

/// Marker request type — accepts any payload shape, the handler does
/// not parse the body. Polling is deprecated by design (push events
/// via `StatusUpdatesSubscribe` are the replacement); the handler always
/// surfaces `RecoveryRequired` so a client trying to poll learns the
/// migration story explicitly.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct StatusUpdatesPollRequest {}

// ── RollbackRequest ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RollbackRequest {
    /// `None` ⇒ rollback to LKG.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_revision_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RollbackResponse {
    pub operation_id: String,
}

// ── SnapshotInitial ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SnapshotInitialRequest {}

/// Bundles everything the GUI's first render needs in a single
/// round-trip. Server-side composer; per-section handlers can also be
/// called individually.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SnapshotInitialResponse {
    pub health: ServiceHealthResponse,
    pub adapters: SnapshotInterfacesResponse,
    pub diagnostics: DiagnosticsStatusDto,
    pub active_alerts_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision_id: Option<String>,
    /// Per-SID route policy snapshot for the calling user.
    /// `None` if the GUI has not yet sent a `RoutePolicyUpdate` for this
    /// SID — the caller is expected to drive the migration flow in that
    /// case (read `MigrationStatusGet` first).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_policy: Option<RoutePolicyDto>,
    // ── Settings snapshot ────────────────────────────────────────────
    /// Compact summaries of pending and recent revisions (most recent
    /// candidate + last few terminal entries). Empty on fresh installs
    /// or when `PolicyManager::pending_revisions` returns an empty list.
    #[serde(default)]
    pub pending_revisions: Vec<RevisionSummaryDto>,
    /// Id of the most recent superseded revision suitable for rollback.
    /// `None` until a second activation has supplied an LKG.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_known_good: Option<String>,
    /// Active service-wide `ApplyFailurePolicy`. `None` is treated by
    /// the GUI as the default `"all-or-nothing"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_failure_policy: Option<ApplyFailurePolicyDto>,
    /// Whether the calling SID is currently routing-paused.
    #[serde(default)]
    pub routing_paused: bool,
    /// Caller's autostart configuration with the most recent registry
    /// observation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autostart: Option<AutostartDto>,
    /// Active retention policy (singleton row). `None` during recovery
    /// when the storage layer is not yet open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_settings: Option<RetentionSettingsDto>,
    /// Application rules whose exe could not be resolved
    /// to an on-disk path (app not installed / not running / not in App
    /// Paths), so their per-process `ALE_APP_ID` filter was not built and the
    /// rule is silently unenforced. Each entry is the rule's app pattern
    /// (e.g. `"vk.exe"`), sorted + deduped. Surfaced so the GUI can show a
    /// banner. Empty when every app rule resolved (or there are none). Wire
    /// key: `unenforced-app-rules`.
    #[serde(default)]
    pub unenforced_app_rules: Vec<String>,
    /// How many secondary-destined IPs the "smart"
    /// kill-switch excluded from its per-IP pin/block set this compute because
    /// the shared-IP census saw them on direct (non-rule) hosts too. `0` under
    /// the strict policy, while the leak-guard is disarmed, or when nothing is
    /// shared. Surfaced so the GUI can warn "kill-switch strictness reduced
    /// for N shared IPs". Wire key: `kill-switch-shared-ip-exemptions`.
    #[serde(default)]
    pub kill_switch_shared_ip_exemptions: u32,
    /// The excluded addresses themselves (dotted-quad IPv4 strings), for the
    /// GUI's "show details" list next to the warning above. Capped well below
    /// `kill_switch_shared_ip_exemptions` when the exclusion set is large — the
    /// count is always exact, this list may be a prefix of it. Empty when the
    /// count is zero. Wire key: `kill-switch-shared-ip-exemption-addresses`.
    #[serde(default)]
    pub kill_switch_shared_ip_exemption_addresses: Vec<String>,
    /// Whether the fail-closed catch-all block-all is
    /// currently armed for any active user (kill-switch fail-closed + the
    /// secondary adapter unresolved — e.g. it vanished after a reboot). The
    /// GUI shows a warning banner: unknown traffic is being cut until the VPN
    /// reconnects / the adapter is re-bound. Dismissible via a UI preference —
    /// deliberately running the service with the VPN down is a legitimate
    /// setup. Wire key: `kill-switch-block-all-armed`.
    #[serde(default)]
    pub kill_switch_block_all_armed: bool,
}

/// Compact summary of a revision row surfaced in
/// `SnapshotInitialResponse.pending_revisions`. Field shape mirrors a
/// subset of `nrr-storage::RevisionRecord`; the full
/// `rules_json` payload stays inside the storage layer.
///
/// `status` slug values: `"candidate" | "active" | "superseded" |
/// "rolled-back" | "rejected"` (matches
/// `nrr-domain::rules_revision::RevisionStatus::as_slug`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RevisionSummaryDto {
    pub revision_id: String,
    pub status: String,
    pub source: String,
    pub correlation_id: String,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activated_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    pub content_hash: String,
}

// ── RoutePolicy ────────────────────────────────────────────────────────────

/// Source of a binding write — propagated to the audit trail and
/// stored in the `route_bindings` row alongside the binding itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindingSourceDto {
    /// User chose this binding through the GUI directly.
    UserAssigned,
    /// GUI migrated this binding from the legacy `UiPreferences`
    /// fields on first launch after upgrade.
    MigratedFromPreferences,
    /// Service-side recovery write (e.g. previously-bound adapter
    /// disappeared and a fallback was selected).
    Recovery,
}

/// Behavior mode for the (primary, secondary) pair. Slugs match
/// `nrr_shared::RouteBehaviorMode` so wire and storage agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BehaviorModeDto {
    PreferPrimary,
    PreferSecondaryWhenAvailable,
    StrictSecondaryFailClosed,
}

/// One binding row — either primary or secondary slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RouteBindingDto {
    /// Stable adapter identity (`AdapterName` in `nrr-shared`). Server
    /// validates this against the live `AdapterMonitor` snapshot before
    /// writing.
    pub stable_id: String,
    /// Display name shown in GUI. Cached at write time so the UI does
    /// not need a round-trip to resolve names.
    pub display_name: String,
    /// User explicitly confirmed this role (vs auto-suggested).
    pub user_confirmed: bool,
}

/// Full per-SID policy snapshot. Used as both `RoutePolicyUpdate`
/// response payload and the `route_policy` field of
/// `SnapshotInitialResponse`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RoutePolicyDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<RouteBindingDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secondary: Option<RouteBindingDto>,
    pub mode: BehaviorModeDto,
    pub block_secondary_when_unavailable: bool,
    /// Kill-switch failure posture. `true` (default) =
    /// fail-closed (block when the secondary can't be resolved); `false` =
    /// fail-open (allow + GUI warning banner). `#[serde(default)]` keeps it
    /// additive — an older service that omits it reads as fail-closed.
    #[serde(default = "kill_switch_fail_closed_default")]
    pub kill_switch_fail_closed: bool,
    /// Which IP protocols the emergency block cuts, as a
    /// bitmask (TCP=1, UDP=2, ICMP=4, IGMP=8, GRE=16, ESP=32, Other=64; all
    /// = 127). `#[serde(default)]` (= all) keeps it additive — an older peer
    /// that omits it reads as "block every protocol".
    #[serde(default = "kill_switch_protocols_default")]
    pub kill_switch_protocols: u16,
    /// When `true`, split-mode fail-closed blocks ALL egress
    /// (catch-all) instead of only cached secondary IPs (see backend). Default
    /// `false` (per-IP). `#[serde(default)]` keeps it additive.
    #[serde(default)]
    pub kill_switch_block_all: bool,
    /// MASTER kill-switch toggle. `false` (default) = OFF,
    /// so NO fail-closed blocking arms at all (full opt-in); the sibling
    /// kill-switch fields are only consulted when this is `true`.
    /// `#[serde(default)]` = `false` keeps it additive.
    #[serde(default)]
    pub kill_switch_enabled: bool,
    /// "Allow name resolution over the primary link while
    /// the kill-switch block-all is engaged". Default `true` — with DNS cut,
    /// an armed block-all is a total blackout and the FQDN cache never
    /// fills; strict users opt out.
    /// `#[serde(default = "default_true")]` keeps it additive.
    #[serde(default = "default_true")]
    pub allow_dns_over_primary: bool,
    /// "Treat a domain as `domain` + `*.domain`". When
    /// `true`, the enforcement layer expands bare-domain rules to also cover
    /// subdomains. Default `true` (the widening only adds coverage towards
    /// the route the rule already names, so it cannot leak to an unintended
    /// route). `#[serde(default = "default_true")]` keeps it
    /// additive — an older peer that omits it reads as the new default, ON.
    #[serde(default = "default_true")]
    pub include_subdomains: bool,
    /// How a SHARED secondary IP is treated. Slug:
    /// `majority-of-ip` (default) | `majority-of-rules` | `any-rule-domain`
    /// (matches `nrr_domain::shared_ip::SharedIpPolicy::as_slug`).
    /// `#[serde(default)]` = balanced default keeps it additive.
    #[serde(default = "shared_ip_policy_default")]
    pub shared_ip_policy: String,
    /// Mode-A un-seeded-IP coverage strategy slug: `per-ip` |
    /// `fail-closed-unknown` (default) | `zone-widening` (matches
    /// `nrr_domain::mode_a_coverage::ModeACoverageStrategy::as_slug`).
    /// `#[serde(default)]` = fail-closed-unknown keeps it additive.
    #[serde(default = "mode_a_coverage_strategy_default")]
    pub mode_a_coverage_strategy: String,
    /// Resolve rule hosts bypassing the OS hosts/adblock file. `true`
    /// (DEFAULT) forces a routable public IP; `false` honours the hosts file.
    /// Defaults to `true` when an older peer omits it (the intended posture).
    #[serde(default = "resolve_hosts_bypass_default")]
    pub resolve_hosts_bypass: bool,
    /// The secondary binding's **link-provider apps**:
    /// executables the user confirmed as establishing/maintaining the
    /// secondary link (VPN client et al.). READ-ONLY here — written through
    /// the dedicated `route.link-provider.set` op, surfaced in this snapshot
    /// DTO so the GUI can display the configured set without a UI-preference
    /// mirror. `#[serde(default)]` (= empty) keeps it additive.
    #[serde(default)]
    pub secondary_link_provider_apps: Vec<LinkProviderAppDto>,
    /// DoH/DoT lockdown MASTER toggle for this SID. `false`
    /// (default) = off. `#[serde(default)]` keeps it additive.
    #[serde(default)]
    pub doh_lockdown_enabled: bool,
    /// When the lockdown applies: `leak-protection-only`
    /// (default) | `always` (matches
    /// `nrr_storage::doh_lockdown::DohLockdownScope::as_slug`).
    #[serde(default = "doh_lockdown_scope_default")]
    pub doh_lockdown_scope: String,
    /// Opt-in AUTOMATIC browser-history seed for this SID:
    /// when `true` the service runs the rule-gated history seed on its own at
    /// boot. `false` (default) = manual button only (privacy-sensitive read —
    /// explicit opt-in). `#[serde(default)]` keeps it additive.
    #[serde(default)]
    pub browser_history_auto_seed: bool,
    /// Kill-switch shared-IP strictness. `false` (default,
    /// "smart"): IPs the shared-IP census has seen on direct (non-rule) hosts
    /// are excluded from the kill-switch per-IP pin/block set (an innocent
    /// co-tenant site is never cut). `true` ("strict"): pin/block every
    /// secondary-destined IP regardless of sharing. `#[serde(default)]`
    /// keeps it additive.
    #[serde(default)]
    pub kill_switch_strict_shared_ips: bool,
    /// What the service may do with the companion domains it
    /// discovers for a routed site (the CDN/media hosts its rules do not
    /// cover). Slug: `off` (do not collect) | `suggest` (default — collect and
    /// offer; apply nothing without confirmation) | `auto` (apply and record in
    /// the user's rules). Matches `nrr_storage::auto_rules::AutoRulesMode::as_slug`.
    /// `#[serde(default = "auto_rules_mode_default")]` keeps it additive — an
    /// older peer that omits it must never read as `off` (silently disabling
    /// discovery) nor as `auto` (silently applying).
    #[serde(default = "auto_rules_mode_default")]
    pub auto_rules_mode: String,
    /// Offer a delivery-shaped companion host (a CDN endpoint) on its
    /// first co-occurrence instead of waiting for the routed site to dominate
    /// that host's traffic across two visits. `false` (default) keeps the wait,
    /// which is what stops a CDN shared with half the internet from being
    /// suggested. Only meaningful while `auto_rules_mode` collects anything.
    /// `#[serde(default)]` keeps it additive — an older peer that omits it must
    /// never read as opted in.
    #[serde(default)]
    pub auto_rules_eager_delivery_names: bool,
    pub binding_source: BindingSourceDto,
}

/// Additive default for [`RoutePolicyDto::auto_rules_mode`] /
/// [`RoutePolicyUpdateRequest::auto_rules_mode`] — `suggest`. v1 deliberately
/// applies nothing on its own; kept in sync with
/// `nrr_storage::auto_rules::AutoRulesMode::default().as_slug()`.
pub fn auto_rules_mode_default() -> String {
    "suggest".to_string()
}

/// Additive default for [`RoutePolicyDto::doh_lockdown_scope`] /
/// [`RoutePolicyUpdateRequest::doh_lockdown_scope`] — leak-protection-only.
pub fn doh_lockdown_scope_default() -> String {
    "leak-protection-only".to_string()
}

/// One link-provider application of a route binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LinkProviderAppDto {
    /// User-facing Win32 path of the executable (`C:\...\client.exe`).
    pub exe_path: String,
    /// Display name shown in the GUI. May be empty.
    #[serde(default)]
    pub display_name: String,
}

/// `route.link-provider.set` request — replace the caller's link-provider app
/// set for one binding role. Full-replacement semantics: an empty list clears
/// the set ("I don't use a VPN"). `role` defaults to `secondary` (the only
/// role with a provider-app story in Free; Pro grows more roles/bindings).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RouteLinkProviderSetRequest {
    #[serde(default = "link_provider_role_default")]
    pub role: String,
    #[serde(default)]
    pub link_provider_apps: Vec<LinkProviderAppDto>,
}

/// Wire default for [`RouteLinkProviderSetRequest::role`].
fn link_provider_role_default() -> String {
    "secondary".to_string()
}

/// `route.link-provider.set` response — the stored set after the write
/// (deduplicated, path-ordered), for GUI confirmation display.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RouteLinkProviderSetResponse {
    pub role: String,
    pub link_provider_apps: Vec<LinkProviderAppDto>,
}

/// One row of the shared DoH/DoT resolver baseline list.
/// `target_kind` is `ip` | `host`; `target` is the IPv4 literal or hostname.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DohResolverEntryDto {
    /// `ip` or `host` (matches `nrr_storage::doh_lockdown::DohTarget::kind_str`).
    pub target_kind: String,
    /// The IPv4 literal (`8.8.8.8`) or hostname (`dns.google`).
    pub target: String,
    /// Free-text note (provider/country).
    #[serde(default)]
    pub comment: String,
    /// Whether this entry participates in the lockdown (per-row toggle).
    #[serde(default = "doh_entry_enabled_default")]
    pub enabled: bool,
}

/// Wire default for [`DohResolverEntryDto::enabled`] — enabled.
fn doh_entry_enabled_default() -> bool {
    true
}

/// `doh.resolvers.get` response — the full shared resolver baseline list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DohResolversGetResponse {
    pub resolvers: Vec<DohResolverEntryDto>,
}

/// `doh.resolvers.set` request — replace the ENTIRE shared resolver baseline
/// list (full-replacement semantics; an empty list clears it). Privileged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DohResolversSetRequest {
    #[serde(default)]
    pub resolvers: Vec<DohResolverEntryDto>,
}

/// `doh.resolvers.set` response — the stored list after the write.
pub type DohResolversSetResponse = DohResolversGetResponse;

/// `diagnostics.seed-from-browser-history` response. The seed runs asynchronously
/// on a service worker; `started` is `true` when the worker was launched (a
/// browser-history reader is wired), `false` when the feature is unavailable on
/// this build/platform. Per-host counts are logged, not returned (the resolve
/// outlives this reply).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SeedFromBrowserHistoryResponse {
    pub started: bool,
}

/// Wire default for `kill_switch_fail_closed`: fail-closed (`true`). An
/// older peer that omits the field must never silently downgrade an
/// installed fail-closed posture to fail-open on a round-trip.
fn kill_switch_fail_closed_default() -> bool {
    true
}

/// Wire default for `kill_switch_protocols`: `127` (all protocols). An
/// omitting peer must never silently narrow what the emergency block cuts.
fn kill_switch_protocols_default() -> u16 {
    0x7F
}

/// Wire default for `shared_ip_policy`: `majority-of-ip` (balanced). Kept in
/// sync with `nrr_domain::shared_ip::SharedIpPolicy::default().as_slug()`.
fn shared_ip_policy_default() -> String {
    "majority-of-ip".to_string()
}

/// Wire default for `mode_a_coverage_strategy`: `per-ip` — the permissive
/// default installs no catch-all, so default/primary-destined and
/// zone→primary traffic is not blocked; fail-closed-unknown is a paranoid opt-in.
/// Kept in sync with `nrr_domain::mode_a_coverage::ModeACoverageStrategy::default().as_slug()`.
///
/// Public because it is the NORMATIVE spelling of this default: the
/// `UiPreferences` mirror in `nrr-ui-support` and the legacy-preferences
/// migration in the launcher both read it instead of retyping the slug — the
/// three spellings had already drifted apart once.
pub fn mode_a_coverage_strategy_default() -> String {
    "per-ip".to_string()
}

/// Wire default for `resolve_hosts_bypass`: `true` (bypass the hosts file). An
/// omitting peer must read the intended default, not `bool`'s `false`.
fn resolve_hosts_bypass_default() -> bool {
    true
}

/// Request payload for `RoutePolicyUpdate`. Atomically replaces the
/// caller's per-SID policy: send `Some(...)` to bind a slot,
/// `None` to clear it. `binding_source = MigratedFromPreferences` is
/// only valid during the GUI migration flow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RoutePolicyUpdateRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<RouteBindingDto>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary: Option<RouteBindingDto>,
    pub mode: BehaviorModeDto,
    pub block_secondary_when_unavailable: bool,
    /// Kill-switch failure posture (see [`RoutePolicyDto`]).
    /// Defaults to fail-closed when an older GUI omits it.
    #[serde(default = "kill_switch_fail_closed_default")]
    pub kill_switch_fail_closed: bool,
    /// Protocol bitmask the emergency block cuts (see
    /// [`RoutePolicyDto`]). Defaults to all protocols when an older GUI omits it.
    #[serde(default = "kill_switch_protocols_default")]
    pub kill_switch_protocols: u16,
    /// When `true`, split-mode fail-closed blocks ALL egress
    /// (catch-all) instead of only cached secondary IPs (see backend). Default
    /// `false` (per-IP). `#[serde(default)]` keeps it additive.
    #[serde(default)]
    pub kill_switch_block_all: bool,
    /// MASTER kill-switch toggle (see [`RoutePolicyDto`]).
    /// Defaults to OFF (no blocking at all) when an older GUI omits it.
    #[serde(default)]
    pub kill_switch_enabled: bool,
    /// "Allow DNS over the primary link while blocked"
    /// (see [`RoutePolicyDto`]). Defaults to ON when
    /// an older GUI omits it (an armed block-all with DNS cut is a total
    /// blackout).
    #[serde(default = "default_true")]
    pub allow_dns_over_primary: bool,
    /// "Treat a domain as `domain` + `*.domain`" (see
    /// [`RoutePolicyDto`]). Defaults to ON when an older GUI omits it.
    #[serde(default = "default_true")]
    pub include_subdomains: bool,
    /// Shared-IP policy slug (see [`RoutePolicyDto`]).
    /// Defaults to `majority-of-ip` when an older GUI omits it.
    #[serde(default = "shared_ip_policy_default")]
    pub shared_ip_policy: String,
    /// Mode-A un-seeded-IP coverage strategy slug (see [`RoutePolicyDto`]).
    /// Defaults to `fail-closed-unknown` when an older GUI omits it.
    #[serde(default = "mode_a_coverage_strategy_default")]
    pub mode_a_coverage_strategy: String,
    /// Resolve rule hosts bypassing the hosts file (see [`RoutePolicyDto`]).
    /// Defaults to `true` when an older GUI omits it.
    #[serde(default = "resolve_hosts_bypass_default")]
    pub resolve_hosts_bypass: bool,
    /// DoH/DoT lockdown toggle (see [`RoutePolicyDto`]). Defaults
    /// to `false` (off) when an older GUI omits it.
    #[serde(default)]
    pub doh_lockdown_enabled: bool,
    /// DoH/DoT lockdown scope slug (see [`RoutePolicyDto`]).
    /// Defaults to `leak-protection-only` when an older GUI omits it.
    #[serde(default = "doh_lockdown_scope_default")]
    pub doh_lockdown_scope: String,
    /// Opt-in automatic browser-history seed (see
    /// [`RoutePolicyDto`]). Defaults to `false` (off) when an older GUI omits it.
    #[serde(default)]
    pub browser_history_auto_seed: bool,
    /// Kill-switch shared-IP strictness (see
    /// [`RoutePolicyDto`]). Defaults to `false` ("smart") when an older GUI
    /// omits it.
    #[serde(default)]
    pub kill_switch_strict_shared_ips: bool,
    /// Auto-rules mode slug (see [`RoutePolicyDto`]). Defaults to
    /// `suggest` when an older GUI omits it.
    #[serde(default = "auto_rules_mode_default")]
    pub auto_rules_mode: String,
    /// Eager delivery-name suggestions (see [`RoutePolicyDto`]).
    /// Defaults to `false` (wait for the evidence) when an older GUI omits it.
    #[serde(default)]
    pub auto_rules_eager_delivery_names: bool,
    pub binding_source: BindingSourceDto,
}

impl RoutePolicyUpdateRequest {
    /// Would applying this request move the routing policy away from what
    /// `current` already expresses?
    ///
    /// Clients read-modify-write the whole row, so a save that merely
    /// re-states the stored policy has to stay acceptable even where the
    /// policy itself is frozen — otherwise freezing the policy would freeze
    /// the settings surface around it.
    ///
    /// Provenance and display metadata are deliberately not compared: a
    /// binding's `display_name` / `user_confirmed` and the row's
    /// `binding_source` cannot alter enforcement, and the stored spelling
    /// drifts on its own (adapter identity healing, recovery writes), which
    /// would turn an honest echo into a spurious difference. Adapter identity
    /// (`stable_id`) and whether a slot is bound at all are compared.
    ///
    /// The exhaustive destructuring is load-bearing: a field added to either
    /// struct stops compiling here until someone decides whether it is part of
    /// the policy.
    #[must_use]
    pub fn changes_policy(&self, current: &RoutePolicyDto) -> bool {
        let Self {
            primary,
            secondary,
            mode,
            block_secondary_when_unavailable,
            kill_switch_fail_closed,
            kill_switch_protocols,
            kill_switch_block_all,
            kill_switch_enabled,
            allow_dns_over_primary,
            include_subdomains,
            shared_ip_policy,
            mode_a_coverage_strategy,
            resolve_hosts_bypass,
            doh_lockdown_enabled,
            doh_lockdown_scope,
            browser_history_auto_seed,
            kill_switch_strict_shared_ips,
            auto_rules_mode,
            auto_rules_eager_delivery_names,
            binding_source: _,
        } = self;
        let RoutePolicyDto {
            primary: stored_primary,
            secondary: stored_secondary,
            mode: stored_mode,
            block_secondary_when_unavailable: stored_block_secondary,
            kill_switch_fail_closed: stored_fail_closed,
            kill_switch_protocols: stored_protocols,
            kill_switch_block_all: stored_block_all,
            kill_switch_enabled: stored_kill_switch,
            allow_dns_over_primary: stored_dns_over_primary,
            include_subdomains: stored_include_subdomains,
            shared_ip_policy: stored_shared_ip_policy,
            mode_a_coverage_strategy: stored_mode_a_strategy,
            resolve_hosts_bypass: stored_hosts_bypass,
            secondary_link_provider_apps: _,
            doh_lockdown_enabled: stored_doh_enabled,
            doh_lockdown_scope: stored_doh_scope,
            browser_history_auto_seed: stored_history_seed,
            kill_switch_strict_shared_ips: stored_strict_shared_ips,
            auto_rules_mode: stored_auto_rules_mode,
            auto_rules_eager_delivery_names: stored_eager_delivery,
            binding_source: _,
        } = current;

        bound_adapter_id(primary) != bound_adapter_id(stored_primary)
            || bound_adapter_id(secondary) != bound_adapter_id(stored_secondary)
            || mode != stored_mode
            || block_secondary_when_unavailable != stored_block_secondary
            || kill_switch_fail_closed != stored_fail_closed
            || kill_switch_protocols != stored_protocols
            || kill_switch_block_all != stored_block_all
            || kill_switch_enabled != stored_kill_switch
            || allow_dns_over_primary != stored_dns_over_primary
            || include_subdomains != stored_include_subdomains
            || shared_ip_policy != stored_shared_ip_policy
            || mode_a_coverage_strategy != stored_mode_a_strategy
            || resolve_hosts_bypass != stored_hosts_bypass
            || doh_lockdown_enabled != stored_doh_enabled
            || doh_lockdown_scope != stored_doh_scope
            || browser_history_auto_seed != stored_history_seed
            || kill_switch_strict_shared_ips != stored_strict_shared_ips
            || auto_rules_mode != stored_auto_rules_mode
            || auto_rules_eager_delivery_names != stored_eager_delivery
    }
}

/// The adapter a slot is bound to, or `None` when the slot is unbound.
fn bound_adapter_id(binding: &Option<RouteBindingDto>) -> Option<&str> {
    binding.as_ref().map(|b| b.stable_id.as_str())
}

/// Response payload — the full new policy snapshot after the write.
/// GUI uses this to update its in-memory cache without re-calling
/// `SnapshotInitial`.
pub type RoutePolicyUpdateResponse = RoutePolicyDto;

// ── Migration status ──────────────────────────────────────────────────────

/// Stable migration ids known to the service. Each id has independent
/// per-SID lifecycle in `migration_state`.
pub const MIGRATION_ID_LEGACY_PREFERENCES_V1: &str = "legacy_preferences_v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MigrationStatusGetRequest {
    pub migration_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MigrationStatusGetResponse {
    pub completed: bool,
    /// Epoch seconds at completion. `None` when `completed = false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<u64>,
    /// Free-form JSON detail recorded at mark time (e.g. count of
    /// migrated fields). `None` when `completed = false` or no detail
    /// was supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_json: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MigrationMarkCompleteRequest {
    pub migration_id: String,
    /// Free-form JSON the GUI may attach (e.g.
    /// `{"migrated_fields_count": 7}`). Audit will quote it verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail_json: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MigrationMarkCompleteResponse {
    /// `true` when this call performed the write; `false` when the row
    /// already existed (idempotent path). The GUI treats both as success.
    pub recorded: bool,
    pub completed_at: u64,
}

// ── Retention settings ────────────────────────────────────────────────────

/// Singleton record describing how long superseded / rejected /
/// rolled-back revisions are retained before pruning. Field shape is
/// 1:1 with `nrr-storage::retention_settings::RetentionSettings`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RetentionSettingsDto {
    pub superseded_days: u32,
    pub superseded_count_cap: u32,
    pub rejected_days: u32,
    pub rolledback_days: u32,
    pub rolledback_count_cap: u32,
    pub pin_lkg: bool,
    /// Epoch seconds. `None` until the first cleanup pass writes a row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_cleanup_at: Option<u64>,
    pub updated_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RetentionSettingsGetRequest {}

pub type RetentionSettingsGetResponse = RetentionSettingsDto;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RetentionSettingsSetRequest {
    pub superseded_days: u32,
    pub superseded_count_cap: u32,
    pub rejected_days: u32,
    pub rolledback_days: u32,
    pub rolledback_count_cap: u32,
    pub pin_lkg: bool,
}

pub type RetentionSettingsSetResponse = RetentionSettingsDto;

// ── Log/audit retention config ───────────────────────────────────────────────

/// Singleton record for operational-log + audit NDJSON retention. Field shape
/// is 1:1 with `nrr-storage::log_retention_config::LogRetentionConfig`. Sizes
/// are BYTES on the wire; `0` = age-only (no size cap).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LogRetentionConfigDto {
    pub log_max_age_days: u32,
    pub log_max_size_bytes: u64,
    pub audit_max_age_days: u32,
    pub audit_max_size_bytes: u64,
    pub updated_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct LogRetentionConfigGetRequest {}

pub type LogRetentionConfigGetResponse = LogRetentionConfigDto;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LogRetentionConfigSetRequest {
    pub log_max_age_days: u32,
    pub log_max_size_bytes: u64,
    pub audit_max_age_days: u32,
    pub audit_max_size_bytes: u64,
}

pub type LogRetentionConfigSetResponse = LogRetentionConfigDto;

// ── Apply failure policy ──────────────────────────────────────────────────

/// Slug values recognised by the service: `"all-or-nothing"`,
/// `"best-effort"`, `"pre-flight-then-all-or-nothing"`. The GUI MUST
/// echo back one of these — the service rejects unknown slugs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ApplyFailurePolicyDto {
    pub policy: String,
    /// Epoch seconds of the last write.
    pub updated_at: u64,
    /// SID of the principal who last set the policy. `None` for the
    /// default row materialised on first read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_by_sid: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ApplyFailurePolicyGetRequest {}

pub type ApplyFailurePolicyGetResponse = ApplyFailurePolicyDto;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ApplyFailurePolicySetRequest {
    pub policy: String,
}

pub type ApplyFailurePolicySetResponse = ApplyFailurePolicyDto;

// ── Storage usage ─────────────────────────────────────────────────────────

/// On-disk byte counts for service-owned storage, sampled at request
/// time. Counts include only files currently present; no rolling
/// average. `None` means the file is absent or unreadable — the GUI
/// renders that as "Unavailable".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct StorageUsageDto {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_db_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_db_bytes: Option<u64>,
    pub operational_logs_bytes: u64,
    pub audit_logs_bytes: u64,
    pub total_bytes: u64,
    /// Epoch seconds when the scan was performed.
    pub scanned_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct StorageUsageGetRequest {}

pub type StorageUsageGetResponse = StorageUsageDto;

// ── Routing pause ─────────────────────────────────────────────────────────

/// Per-SID routing-pause record. `paused = false` is returned for SIDs
/// that have never been paused (no row in `routing_pause_state`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RoutingPauseDto {
    pub sid: String,
    pub paused: bool,
    /// Epoch seconds of the most recent pause transition. `None` when
    /// `paused = false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_reason: Option<String>,
    pub updated_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RoutingPauseGetRequest {}

pub type RoutingPauseGetResponse = RoutingPauseDto;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RoutingPauseToggleRequest {
    pub paused: bool,
    /// Free-form annotation persisted alongside the pause row. Audit
    /// quotes it verbatim. `None` clears the previous reason on resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub type RoutingPauseToggleResponse = RoutingPauseDto;

// ── Autostart ─────────────────────────────────────────────────────────────

/// Autostart status combining the user's stored intent (`enabled`)
/// with the most recent observation of `HKCU\…\Run`
/// (`last_known_state`). Slug values for `last_known_state`:
/// `"enabled" | "disabled" | "overridden-externally" | "absent"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutostartDto {
    pub enabled: bool,
    pub last_known_state: String,
    /// When `last_known_state == "overridden-externally"` carries the
    /// foreign registry value so the GUI can surface it for the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overridden_value: Option<String>,
    pub updated_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct AutostartGetRequest {}

pub type AutostartGetResponse = AutostartDto;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutostartToggleRequest {
    pub enabled: bool,
}

pub type AutostartToggleResponse = AutostartDto;

// ── ExplainGet ────────────────────────────────────────────────────────────

/// Explain query request. Two phases:
/// - Historical: caller passes a `decision-id` previously emitted by the
///   service into the audit/log trail.
/// - Synthetic: caller passes an `input-sample`; the service simulates a
///   decision against the active rule set without writing audit.
///
/// `detail-level` selects the redaction policy:
/// - `compact-ui` — minimum surface (default GUI view)
/// - `diagnostics` — adds IPs, full match metadata, cache TTLs
/// - `developer-trace` — adds internal trace fields (developer / support)
///
/// At most one of `decision-id` / `input-sample` must be `Some`. Both
/// `None` is a malformed request; both `Some` is also malformed (the
/// service uses the first non-empty in defensive parsing but rejects on
/// ambiguity).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ExplainGetRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_sample: Option<ExplainInputSampleDto>,
    /// Defaults to `compact-ui` server-side when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail_level: Option<String>,
}

/// Wire form of `nrr_diagnostics::explain::query::RuntimeInputSample`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ExplainInputSampleDto {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
}

/// Explain response envelope. Carries a flat compact view
/// for the existing `DiagnosticsSection.qml` 3-line display PLUS the
/// full structured `nrr_diagnostics::explain::response::ExplainResponse`
/// passthrough for future detail surfaces.
///
/// The compact view uses pre-localised plaintext keys; the full payload
/// uses `snake_case` fields (mirrors the producer's serde shape — the
/// service does NOT rewrite to kebab-case here to keep the cross-module
/// invariant that the explain response is owned by `nrr-diagnostics`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExplainGetResponse {
    pub compact: ExplainCompactViewDto,
    /// Passthrough of `nrr_diagnostics::ExplainResponse` (snake_case
    /// fields preserved). May be `null` when the underlying explain is
    /// `Unavailable` and the service decides to short-circuit.
    pub full: serde_json::Value,
    /// Audit-log diagnostic-id correlations enriched by the service
    /// AFTER the engine produced the outcome. Empty for synthetic
    /// queries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostic_ids: Vec<String>,
}

/// Compact 3-field view rendered today by `DiagnosticsSection.qml`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExplainCompactViewDto {
    /// Display label for the input — hostname, IP, or process name
    /// depending on what was the primary lookup key.
    pub input: String,
    /// Route role applied: `"primary"`, `"secondary"`, `"none"`,
    /// `"blocked"`. Matches `ExplainFinalActionSection::route_role` +
    /// "blocked" when fail-closed.
    pub route: String,
    /// Localisation key for the reason. The GUI resolves via `tr(key)`.
    pub reason_key: String,
    /// Kill-switch ENFORCEMENT verdict on top of the rule
    /// verdict, so the probe stops saying "primary" for a host the armed
    /// block-all would in fact drop. Slug, empty
    /// when nothing applies: `blocked-unknown-under-block-all` (coverage =
    /// fail-closed-unknown, kill-switch on, hostname absent from the FQDN
    /// cache → no permit compiles while armed) |
    /// `fail-closed-when-secondary-down` (secondary-routed host under an
    /// enabled fail-closed kill-switch). Also covers the shared-IP
    /// collateral slugs: `collateral-blocked-strict` (strict policy — the
    /// host's census-shared IPs stay pinned, so it is cut whenever the
    /// secondary is down) | `collateral-smart-exempt` (smart policy — shared
    /// IPs exempted; host works, secondary traffic on them unprotected) |
    /// `collateral-risk-subdomain-rules` (host un-cached but rule-cached
    /// subdomains exist under it — same-front-end collateral likely).
    /// Additive; the GUI renders it via
    /// `tr("diag.explain.enforcement.<slug>")`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub enforcement: String,
    /// For the collateral slugs: how many of the probe host's cached
    /// IPs the shared-IP census flags. `0` otherwise. Wire key:
    /// `enforcement-shared-ips`.
    #[serde(default)]
    pub enforcement_shared_ips: u32,
    /// For the collateral slugs: the probe host's total cached IP
    /// count (the "M" in "N of M IPs are shared"). `0` otherwise. Wire key:
    /// `enforcement-total-ips`.
    #[serde(default)]
    pub enforcement_total_ips: u32,
    /// The VIRTUAL (fake) IPv4 address currently
    /// answering for the probe host when fake-IP is active, empty otherwise.
    /// Shown next to the real route verdict so "why does this host resolve to
    /// 198.18.x.x" is answered in place. Wire key: `fake-ip`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fake_ip: String,
}

// ── DiagnosticsExportArchive ─────────────────────────────────────────────────

/// Archive export request. Service writes a zip into the
/// per-user `archives/` directory and returns its path. Inclusion flags
/// let the operator slim down the archive when only a specific category
/// is needed for support; all default to `true` for the canonical
/// support snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DiagnosticsExportArchiveRequest {
    #[serde(default = "default_true")]
    pub include_logs: bool,
    #[serde(default = "default_true")]
    pub include_audit_summary: bool,
    #[serde(default = "default_true")]
    pub include_troubleshooting_playbooks: bool,
    /// How much detail to export:
    /// `"standard"` (default — redacted, the sections a normal bug report
    /// needs) or `"diagnostics"` (adds `cache_health.json`,
    /// `storage_health.json`, `explain_samples.json` and relaxes redaction to
    /// the diagnostics tier). An unknown/absent value falls back to
    /// `"standard"` — the export never fails on a bad level. Older clients that
    /// omit the field get exactly today's behavior.
    #[serde(default)]
    pub redaction_level: Option<String>,
    /// "Current session only" log trimming. When set,
    /// `logs.ndjson` drops entries older than this UTC-ms instant. The GUI
    /// passes the local-midnight floor of its session start,
    /// so yesterday's rotated segments stay out of a routine support archive
    /// while an app or service restart mid-day cannot silently drop the same
    /// day's earlier history from the bundle. Absent → full log history as
    /// before (additive; older clients are unaffected).
    #[serde(default)]
    pub logs_from_ms: Option<i64>,
}

impl Default for DiagnosticsExportArchiveRequest {
    fn default() -> Self {
        Self {
            include_logs: true,
            include_audit_summary: true,
            include_troubleshooting_playbooks: true,
            redaction_level: None,
            logs_from_ms: None,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Wire request for `LogsClear`. Maps 1:1 to
/// `nrr_diagnostics::facade::dto::ClearLogsRequest`. Audit trail is
/// never deleted — see the design invariant in
/// `core/diagnostics/src/facade/service.rs:11`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LogsClearRequest {
    /// When `true`, also remove archived diagnostics-export zips. The
    /// GUI never sets this today (we only expose the rotating-log
    /// cleanup); kept on the wire for parity with the facade.
    #[serde(default)]
    pub include_archives: bool,
    /// When `true`, report what would be deleted without acting.
    #[serde(default)]
    pub dry_run: bool,
}

/// Wire response for `LogsClear`. Lets the GUI
/// echo back a friendly toast (`files_deleted` rotated NDJSON files
/// freed `bytes_freed` bytes).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LogsClearResponse {
    pub files_deleted: u64,
    pub bytes_freed: u64,
    pub dry_run: bool,
}

/// Wire request for `CacheClear`. Clears the rebuildable
/// FQDN/IP resolution cache (`nrr_fqdn_ip_cache.db`) on explicit user
/// request. The audit / service-state DBs are never touched.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CacheClearRequest {
    /// When `true`, report the row counts that would be deleted without
    /// acting (routes to a stats read instead of the delete).
    #[serde(default)]
    pub dry_run: bool,
    /// When `true`, ALSO flush the OS resolver cache
    /// (`DnsFlushResolverCache` via `DnsCacheControlPort`). The GUI splits
    /// "Clear cache" into two buttons: the app's SQLite FQDN/IP cache (this
    /// request with `flush_os_cache = false`, the historic behaviour) and the
    /// OS DNS cache (`clear_app_cache = false`, `flush_os_cache = true`).
    /// `#[serde(default)]` = `false` keeps it additive — an older GUI that
    /// omits it gets the app-cache-only behaviour unchanged.
    #[serde(default)]
    pub flush_os_cache: bool,
    /// When `false`, DO NOT touch the app's SQLite cache (used by
    /// the OS-DNS-only button). Defaults to `true` (via `clear_app_cache_default`)
    /// so an older GUI that omits it keeps clearing the app cache — the
    /// original single-button behaviour.
    #[serde(default = "clear_app_cache_default")]
    pub clear_app_cache: bool,
}

/// Wire default for [`CacheClearRequest::clear_app_cache`]: `true` — an
/// omitting GUI must keep clearing the app cache.
fn clear_app_cache_default() -> bool {
    true
}

impl Default for CacheClearRequest {
    /// Matches the serde defaults (NOT the derived all-`false`): the app cache
    /// is cleared, the OS cache is not — the original single-button behaviour.
    fn default() -> Self {
        Self {
            dry_run: false,
            flush_os_cache: false,
            clear_app_cache: true,
        }
    }
}

/// Wire response for `CacheClear`. Lets the GUI echo a
/// friendly toast and re-pull the cache-health card.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CacheClearResponse {
    /// Hostname→IP resolution rows removed (or that would be removed on a
    /// dry run).
    pub resolutions_removed: u64,
    /// Negative-cache entries removed (or that would be removed).
    pub negative_cache_removed: u64,
    /// Echoes the request's `dry-run` flag.
    pub dry_run: bool,
    /// Outcome of the OS-resolver-cache flush: `Some(true)` flushed,
    /// `Some(false)` requested but failed (or no port wired), `None` not
    /// requested. `#[serde(default)]` keeps it additive for older peers.
    #[serde(default)]
    pub os_cache_flushed: Option<bool>,
}

/// Wire request for `CacheEntriesList`. Read-only, paginated
/// view of the FQDN/IP resolution cache. Offset-based paging is carried
/// through the shared [`PaginationParams`] cursor (the handler encodes the
/// next offset in the cursor); the cache is bounded so offset paging is
/// cheap and stable.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CacheEntriesListRequest {
    #[serde(default)]
    pub pagination: PaginationParams,
    /// Optional server-side search term. When non-empty the
    /// service filters the cache by a case-insensitive substring match on the
    /// canonical host and IP (WHERE LIKE) so a large cache is searched in SQLite
    /// instead of being drained page-by-page into the GUI (the search freeze).
    /// Empty = no filter (full listing).
    #[serde(default)]
    pub query: String,
}

/// One row in the read-only cache-entries viewer. Field naming
/// stays snake_case (matching [`crate::diagnostics_dto::LogEntryDto`], which
/// also flows through [`PageResult`]).
///
/// `hostname` / `ip` are already redaction-processed by the service before
/// serialisation: in the compact tier `hostname` is the registrable domain
/// (eTLD+1) and `ip` is a `<private-ipv4>` / `<public-ipv4>` marker; in the
/// diagnostics tier both are the full values. `freshness` and `source` are
/// stable backend slugs (`fresh`, `stale_usable`, `dns`,
/// `observed_from_traffic`, …) — the GUI wraps them with `tr()`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheEntryDto {
    pub hostname: String,
    pub ip: String,
    /// Freshness-state slug (`fresh`, `stale_usable`, `stale_not_usable`,
    /// `conflicting`, `negative_cached`).
    pub freshness: String,
    /// Resolution-source slug (`dns`, `observed_from_traffic`,
    /// `manual_refresh`, `imported_seed`, `cache_rebuild`).
    pub source: String,
    /// When the mapping was resolved (UTC ms).
    pub resolved_at_ms: i64,
    /// When the mapping expires (UTC ms).
    pub expires_at_ms: i64,
    /// Where routing policy would send this host: `secondary`
    /// (matches a secondary rule by name, or its IP is owned by a secondary
    /// rule — the shared-IP collateral case), `primary` (matches a primary
    /// rule), or empty (no rule expectation derived). Stamped at read time by
    /// the handler, mirroring [`ConnTraceEntryDto::expected_route`]; the GUI
    /// renders it via the same route labels.
    #[serde(default)]
    pub expected_route: String,
    /// Kind of the strongest address rule covering this
    /// entry: `exact-fqdn`, `subdomain`, `zone`, `exact-ip`, or empty (no
    /// address rule matched). Stamped at read time alongside
    /// `expected_route`; the cache viewer sorts direct rule matches above
    /// zone-derived entries.
    #[serde(default)]
    pub rule_match_kind: String,
    /// The VIRTUAL (fake) IPv4 address currently
    /// bound to this hostname when fake-IP is active, empty otherwise. Shown
    /// next to the real cached address in the cache viewer. Stamped at read
    /// time from the live allocator (not persisted in the cache DB).
    #[serde(default)]
    pub fake_ip: String,
}

/// Wire response for `CacheEntriesList`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CacheEntriesListResponse {
    /// One page of `(hostname, ip)` entries plus the offset cursor for the
    /// next page (`next_cursor == None` on the last page).
    pub page: PageResult<CacheEntryDto>,
    /// `true` when the compact redaction tier is active (values are reduced
    /// for privacy). Lets the GUI show a "enable diagnostic mode for full
    /// detail" notice.
    pub redacted: bool,
}

/// Wire request for `ConnTraceEntriesList`. Read-only,
/// paginated view of recently-observed outbound connections. Offset paging via
/// the shared [`PaginationParams`] cursor (the handler encodes the next offset).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnTraceEntriesListRequest {
    #[serde(default)]
    pub pagination: PaginationParams,
}

/// One row in the connection-trace viewer. Field naming
/// stays snake_case (like [`CacheEntryDto`]). `remote` / `local` are
/// redaction-processed by the service (the IP is masked in the compact tier);
/// `process` is the executable name only. `proto`, `egress_role` and `verdict`
/// are stable backend slugs the GUI wraps with `tr()`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnTraceEntryDto {
    /// Executable name (e.g. `chrome.exe`), or `?` when unknown.
    pub process: String,
    /// Full executable path (device/NT path) for the hover tooltip, or empty
    /// when unknown. Only populated for the local
    /// own-machine viewer (not redacted away), matching the cache viewer.
    #[serde(default)]
    pub process_path: String,
    /// Transport slug (`tcp`, `udp`, `other`).
    pub proto: String,
    /// Local socket `ip:port` (IP masked in the compact tier).
    pub local: String,
    /// Remote socket `ip:port` (IP masked in the compact tier).
    pub remote: String,
    /// Egress-role slug (`primary`, `secondary`, `other`, `unknown`).
    pub egress_role: String,
    /// Egress interface index (0 when unresolved).
    pub egress_ifindex: u32,
    /// Verdict slug (`permit`, `block`, `unknown`).
    pub verdict: String,
    /// Drop attribution slug: `netrulerouter` (an NRR filter dropped it),
    /// `other` (Windows Firewall / antivirus / another WFP filter), or empty
    /// (an allow, or the owner could not be resolved), so the trace never
    /// blames NRR for a foreign drop. GUI wraps with tr().
    #[serde(default)]
    pub blocked_by: String,
    /// Where routing policy EXPECTS this remote to egress:
    /// `secondary` (the remote IP belongs to a secondary rule per the current
    /// rule book + FQDN cache) or empty (no expectation derived). Stamped at
    /// read time by the handler. The GUI flags `expected_route == "secondary"`
    /// with `egress_role == "primary"` on a permitted flow as a LEAK indicator
    /// (decision-vs-actual mismatch).
    #[serde(default)]
    pub expected_route: String,
    /// When the connection was observed (UTC ms), or 0 when unknown.
    pub observed_at_ms: i64,
    /// The hostname this flow was dialled ON BEHALF OF, when the
    /// service itself opened it as the fake-IP relay: the application talks to
    /// a virtual address and the service carries the traffic to the real one.
    /// Empty for every ordinary flow. Without it the relay reads as the service
    /// going out to the internet on its own account.
    #[serde(default)]
    pub relay_for: String,
}

/// Wire response for `ConnTraceEntriesList`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnTraceEntriesListResponse {
    /// One page of connection-trace rows plus the offset cursor for the next
    /// page (`next_cursor == None` on the last page).
    pub page: PageResult<ConnTraceEntryDto>,
    /// `true` when the compact redaction tier is active (IPs masked).
    pub redacted: bool,
}

/// Wire request for `DiagnosticModeSet`. The response
/// is the fresh [`crate::diagnostics_dto::DiagnosticModeStateDto`] — an
/// authoritative echo of the resulting session state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DiagnosticModeSetRequest {
    /// Enable (true) or disable (false) extended diagnostics. Absent → false
    /// (a bare payload is a disable request).
    #[serde(default)]
    pub enabled: bool,
    /// TTL in milliseconds (clamped service-side to 4h). Ignored when
    /// `enabled = false` or `until_restart = true`.
    #[serde(default)]
    pub duration_ms: Option<i64>,
    /// No expiry — active until the service restarts. Overrides `duration_ms`.
    #[serde(default)]
    pub until_restart: bool,
    /// Scope slug (`all` by default).
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DiagnosticsExportArchiveResponse {
    /// Absolute path to the freshly-written zip. Lives under the
    /// service's per-user `archives/` directory and inherits the
    /// `Users:RX` ACL applied to that directory.
    pub archive_path: String,
    /// Size of the archive in bytes. Surface in the GUI confirmation
    /// toast so the operator knows roughly what was produced.
    pub size_bytes: u64,
    /// UTC milliseconds when the archive was finalised. Allows the GUI
    /// to format a friendly timestamp without a second IPC roundtrip.
    pub generated_at_ms: i64,
    /// The log cutoff the service ACTUALLY applied. For a
    /// session-only export the service narrows the request's midnight-floor
    /// cutoff to the start of the current service session — the latest
    /// service start that followed at least thirty minutes of downtime —
    /// and echoes the result here so the launcher trims its raw log
    /// attachments to the same window. `None` = full-history export
    /// (additive; older peers are unaffected).
    #[serde(default)]
    pub logs_from_ms_effective: Option<i64>,
}

// ── ServiceStabilityConfig ────────────────────────────────────────────────

/// Wire shape for `nrr_service_runtime::service_stability::ServiceStabilityConfig`.
/// Carries the IPC accept-failure policy as a tagged enum payload plus
/// the verbose-logging toggle.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServiceStabilityConfigDto {
    pub ipc_accept_policy: IpcAcceptFailurePolicyDto,
    /// When `true` the supervisor installs
    /// `EnvFilter::new("nrr=debug,info")` instead of the canonical
    /// `"nrr=info,info"`, so operational NDJSON captures `tracing::debug!`
    /// events. `#[serde(default)]` keeps the field additive — older
    /// GUI builds that omit it deserialise as `false`, matching the
    /// previous server behaviour.
    #[serde(default)]
    pub verbose_logging: bool,
    /// When `true` the opt-in connection-egress
    /// trace writes each observed connection to the operational NDJSON.
    /// `#[serde(default)]` keeps it additive (older GUIs deserialise `false`).
    #[serde(default)]
    pub conn_trace_ndjson: bool,
    /// When `true` the trace streams to the GUI
    /// «Диагностика» panel. Independent of `conn_trace_ndjson`.
    #[serde(default)]
    pub conn_trace_gui: bool,
    /// Routing scope. `true` (default) = service-driven
    /// (the service enforces continuously while it runs, even with no GUI/tray
    /// connected); `false` = app-driven (enforced only while a tray is
    /// connected). The wire default is `true` so an older GUI that omits the
    /// field cannot silently flip an installed service-driven policy to
    /// app-driven on a round-trip Save.
    #[serde(default = "rule_scope_default")]
    pub rule_scope_service_driven: bool,
    /// Persist-on-stop — what happens to NRR routing/filters when the service
    /// stops. `"teardown"` (default) removes NRR `/32` routes and strips every
    /// WFP filter so the box returns to its pre-NRR channel; `"persist"` keeps
    /// the `/32` routes but STILL strips every block/fail-closed/kill-switch
    /// filter (an orphaned block with no service to lift it is a lockout).
    /// Stored as a slug (mirrors the storage column). The serde default is the
    /// teardown slug so an older GUI that omits the field can never silently
    /// flip an installed policy to `persist` on a round-trip Save.
    #[serde(default = "routing_stop_policy_default")]
    pub routing_stop_policy: String,
    /// User-configurable FQDN cache refresh cadence
    /// (seconds): how often a routed site's IPs are re-resolved. The service
    /// clamps this to `nrr_domain::decision_lookup::CACHE_REFRESH_{MIN,MAX}_SECS`
    /// (60 s..24 h) on both write and read — the GUI limit is a convenience, the
    /// backend is authoritative. `#[serde(default)]` keeps it additive (older
    /// GUIs deserialise the 5-minute default).
    #[serde(default = "cache_refresh_interval_default")]
    pub cache_refresh_interval_secs: u32,
    /// Machine-wide traffic-enforcement mechanism
    /// slug. `"resolver"` (default) selects the local DNS resolver;
    /// `"reactive"` selects the legacy reactive kill-switch. Global service
    /// setting (NOT per-SID). Stored as a slug (mirrors
    /// `nrr_domain::enforcement_mode::EnforcementMode::as_slug`). The serde
    /// default tracks the domain default: an omitted field must mean "the
    /// product default", never "the other mode".
    #[serde(default = "enforcement_mode_default")]
    pub enforcement_mode: String,
    /// Secondary-tunnel liveness window (SECONDS): how long the
    /// tunnel next-hop must be continuously unreachable (active ICMP probe) before
    /// the kill-switch fail-closes. `0` (the default) DISABLES the probe — it never
    /// fail-closes (safe default). The service clamps any non-zero value to
    /// `5..=3600` on both write and read (the GUI limit is a convenience, the
    /// backend is authoritative). `#[serde(default)]` keeps it additive — older
    /// GUIs that omit the field deserialise `0` (disabled). Wire key
    /// `"secondary-liveness-window-secs"` (kebab-case). Global service setting (NOT
    /// per-SID).
    #[serde(default = "secondary_liveness_window_default")]
    pub secondary_liveness_window_secs: u32,
    /// Machine-wide fake-IP toggle: when `true` AND
    /// `enforcement_mode == "resolver"`, routed (scope) hosts are answered
    /// with virtual addresses and relayed through the local TUN adapter, so a
    /// routed site never shares a real address with a direct one. Off by
    /// default (opt-in; on Windows it loads the bundled Wintun driver).
    /// `#[serde(default)]` keeps the field additive — an older GUI that omits
    /// it can never silently switch the feature ON, and the full-row Set from
    /// an older build turns it OFF (safe direction). Wire key
    /// `"fake-ip-enabled"`. Global service setting (NOT per-SID).
    #[serde(default)]
    pub fake_ip_enabled: bool,
    /// DNS-over-the-secondary-link toggle: when `true` AND the
    /// secondary adapter is up with a usable IPv4 source, the service's own
    /// upstream DNS queries (Mode-B resolver, raw forward, seeder/refresh)
    /// egress source-bound through the secondary link to well-known public
    /// resolvers, instead of the primary link's provider resolver. Benefit:
    /// name answers can no longer be spoofed or stubbed by the primary
    /// provider. Falls back to the primary path whenever the secondary is
    /// down/unresolved (availability over purity). Off by default (opt-in).
    /// `#[serde(default)]` keeps the field additive — an older GUI's full-row
    /// Set turns it OFF (safe direction). Wire key `"dns-via-secondary"`.
    /// Global service setting (NOT per-SID).
    #[serde(default)]
    pub dns_via_secondary: bool,
    /// Fast DNS answers: when `true` (the default), the Mode-B
    /// resolver answers a routed-host query immediately whenever every
    /// answered address is already known to the routable cache, and only
    /// holds the answer for the route-install deadline when the answer
    /// introduces addresses the cache has never seen (first contact).
    /// Benefit: pages stop stalling on name resolution while enforcement
    /// converges in the background. The wire default is `true` so an older
    /// GUI that omits the field cannot silently re-enable the measured
    /// "hold every answer" stall on a round-trip Save. Wire key
    /// `"dns-fast-answers"`. Global service setting (NOT per-SID).
    #[serde(default = "dns_fast_answers_default")]
    pub dns_fast_answers: bool,
    /// Fake-IP UDP relay: when `true`, the fake-IP pool permit
    /// admits UDP (QUIC/HTTP-3) into the pool instead of hard-blocking it, so
    /// QUIC rides the relay's TUN stack the same way TCP already does.
    /// Meaningful only alongside `fake_ip_enabled`. Off by default —
    /// `#[serde(default)]` keeps the field additive, and an older GUI's
    /// full-row Set turns it OFF (safe direction: QUIC keeps falling back to
    /// TCP rather than silently starting to ride an unreviewed relay path).
    /// Wire key `"fake-ip-udp-relay"`. Global service setting (NOT per-SID).
    #[serde(default)]
    pub fake_ip_udp_relay: bool,
    /// Fake-IP instant reset: when `true` (the default), a relay
    /// dial that fails because the source-address policy refused it (most
    /// commonly: the secondary adapter is unresolved during a VPN reconnect)
    /// resets the client immediately — today's behaviour. When `false`, that
    /// ONE refusal class is held and retried for a bounded window (~10 s)
    /// instead of resetting the client outright; a genuine network error
    /// still fails fast either way. The wire default is `true` so an older
    /// GUI that omits the field, or a full-row Set from a pre-this-feature
    /// build, can never silently switch an installed service onto the
    /// held-dial path. Wire key `"fake-ip-instant-rst"`. Global service
    /// setting (NOT per-SID).
    #[serde(default = "fake_ip_instant_rst_default")]
    pub fake_ip_instant_rst: bool,
    /// Administrative rules lock: `Some(true)` lets every user maintain their
    /// own rule set (the product default); `Some(false)` freezes rule
    /// authoring for non-elevated callers — they keep reading the
    /// administrator's baseline while the service refuses their own edits, so
    /// a modified client cannot talk its way past the GUI.
    ///
    /// Modelled as an `Option` rather than a plain `bool` with a serde default,
    /// unlike every other field here, and that is the point: `None` means
    /// "leave the stored value alone". The full-row Set has no sparse shape, so
    /// a plain default would force a choice between a stale client silently
    /// LIFTING an administrator's lock (`true`) and a stale client silently
    /// IMPOSING one nobody asked for (`false`). Neither is acceptable for a
    /// setting whose only job is to be hard to remove, so the wire carries the
    /// three-state answer instead. A Get always answers `Some`.
    ///
    /// Wire key `"allow-user-rule-edits"`. Machine-wide (NOT per-SID) and
    /// writable only by an elevated caller; reading is open to everyone so a
    /// client can render the rules section read-only with an explanation.
    #[serde(default)]
    pub allow_user_rule_edits: Option<bool>,
    /// ISP block-page rule candidates: when `true`, a host the service
    /// recognises as blocked by the ISP (rather than genuinely unreachable) is
    /// offered as a suggestion to move into the additional route. Off by
    /// default (opt-in). `#[serde(default)]` keeps the field additive — an
    /// older GUI's full-row Set turns it OFF (safe direction). Wire key
    /// `"isp-block-candidates-enabled"`. Global service setting (NOT per-SID).
    #[serde(default)]
    pub isp_block_candidates_enabled: bool,
}

/// Wire default for `ServiceStabilityConfigDto::dns_fast_answers`: `true`.
/// See the field doc — answering immediately is the safe/default posture.
fn dns_fast_answers_default() -> bool {
    true
}

/// Wire default for `ServiceStabilityConfigDto::fake_ip_instant_rst`: `true`.
/// See the field doc — instant reset is today's behaviour and the safe
/// default posture.
fn fake_ip_instant_rst_default() -> bool {
    true
}

/// Wire default for `ServiceStabilityConfigDto::secondary_liveness_window_secs`:
/// `0` (DISABLED — the liveness probe never fail-closes). See the field doc.
fn secondary_liveness_window_default() -> u32 {
    0
}

/// Wire default for `ServiceStabilityConfigDto::enforcement_mode`: the resolver
/// slug. Mirrors `nrr_domain::enforcement_mode::EnforcementMode::default`
/// (kept as a literal here to avoid a contracts→domain dependency), and the
/// mirroring is the point: when this literal and the domain default disagreed,
/// an omitted field meant "quietly fall back to the other mode" instead of
/// "use the default", which is how a wiped service DB ended up enforcing in a
/// mode the user never chose.
fn enforcement_mode_default() -> String {
    "resolver".to_string()
}

/// Wire default for `ServiceStabilityConfigDto::cache_refresh_interval_secs`:
/// 5 minutes. Mirrors `nrr_domain::decision_lookup::CACHE_REFRESH_DEFAULT_SECS`
/// (kept as a literal here to avoid a contracts→domain dependency).
fn cache_refresh_interval_default() -> u32 {
    300
}

/// Wire default for `ServiceStabilityConfigDto::rule_scope_service_driven`:
/// service-driven (`true`). See the field doc for the rationale.
fn rule_scope_default() -> bool {
    true
}

/// Wire default for `ServiceStabilityConfigDto::routing_stop_policy`: the
/// teardown slug. See the field doc — teardown must be the default at every
/// layer so a stop can never silently leave routing/blocks in place.
fn routing_stop_policy_default() -> String {
    "teardown".to_string()
}

impl Default for ServiceStabilityConfigDto {
    fn default() -> Self {
        Self {
            ipc_accept_policy: IpcAcceptFailurePolicyDto::default(),
            verbose_logging: false,
            conn_trace_ndjson: false,
            conn_trace_gui: false,
            // Preserve the historical Rust-side default (`false`) for this
            // field; the wire/serde default is `true` via `rule_scope_default`.
            rule_scope_service_driven: false,
            routing_stop_policy: routing_stop_policy_default(),
            cache_refresh_interval_secs: cache_refresh_interval_default(),
            enforcement_mode: enforcement_mode_default(),
            secondary_liveness_window_secs: secondary_liveness_window_default(),
            fake_ip_enabled: false,
            dns_via_secondary: false,
            dns_fast_answers: dns_fast_answers_default(),
            fake_ip_udp_relay: false,
            fake_ip_instant_rst: fake_ip_instant_rst_default(),
            // `None` = "no opinion": a default-constructed DTO is what a
            // degraded read falls back to, and it must never be mistaken for
            // an administrator's decision in either direction.
            allow_user_rule_edits: None,
            isp_block_candidates_enabled: false,
        }
    }
}

/// Wire shape for `nrr_service_runtime::service_stability::IpcAcceptFailurePolicy`.
/// Tagged enum so the wire stays self-describing for future variants.
///
/// `rename_all` propagates to variant tags (`Recoverable` → `recoverable`);
/// `rename_all_fields` propagates to fields INSIDE struct variants
/// (`max_restarts` → `max-restarts`). Both are required for kebab-case
/// consistency with the rest of the wire schema.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum IpcAcceptFailurePolicyDto {
    Recoverable {
        max_restarts: u32,
        /// Initial back-off (ms).
        backoff_base_ms: u32,
        /// Cap on exponential back-off (ms).
        backoff_cap_ms: u32,
    },
    Critical,
}

impl Default for IpcAcceptFailurePolicyDto {
    fn default() -> Self {
        // Matches `IpcAcceptFailurePolicy::default()` semantics —
        // canonical constants kept in service-runtime to avoid an
        // import cycle.
        Self::Recoverable {
            max_restarts: 20,
            backoff_base_ms: 100,
            backoff_cap_ms: 5_000,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ServiceStabilityConfigGetRequest {}

pub type ServiceStabilityConfigGetResponse = ServiceStabilityConfigDto;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServiceStabilityConfigSetRequest {
    pub config: ServiceStabilityConfigDto,
    /// Free-form writer attribution
    /// (`"user:enforcement-mode"`, `"user:verbose-toggle"`,
    /// `"offline-pending-apply"`, …), logged by the Set handler. Purely
    /// diagnostic: without it, a stability write of unknown provenance can
    /// clobber a user toggle and the NDJSON has no way to say WHICH GUI code
    /// path wrote it. Optional so older clients stay valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

/// Set echoes the persisted config so the GUI can confirm the write
/// took effect (e.g. defaults were applied to omitted fields).
pub type ServiceStabilityConfigSetResponse = ServiceStabilityConfigDto;

/// Wire request for `ThirdPartyComponentsList`. No
/// parameters — the service reports on every third-party binary this build
/// ships. Kept as a struct (not `()`) so fields can be added compatibly.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ThirdPartyComponentsListRequest {}

/// Attribution + live integrity of the shipped third-party
/// binaries. **An empty list is the normal answer on Linux and macOS**, which
/// ship none: the GUI hides the whole surface rather than rendering an empty
/// block, so "no components" and "component missing" never look alike.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ThirdPartyComponentsListResponse {
    pub components: Vec<ThirdPartyComponentStatus>,
}

// ── Traffic counter ───────────────────────────────────────────────────────

/// One per-adapter, per-role traffic total (bytes) on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrafficRowDto {
    pub adapter_key: String,
    pub display_name: String,
    /// `TrafficCategory` slug — `primary` / `secondary` / `loopback` / `virtual`.
    pub role: String,
    pub in_bytes: u64,
    pub out_bytes: u64,
    /// Last observed local IPv4 address behind this adapter, from a
    /// user-requested external-IP probe (`interfaces.refresh`). Absent when
    /// no probe has resolved one for this adapter yet. Defaulted so an older
    /// service/GUI pair still parses the payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<String>,
    /// Last observed external (internet-facing) IPv4 address behind this
    /// adapter, from the same probe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ip: Option<String>,
    /// Epoch-ms timestamp of the observation above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ip_observed_at_ms: Option<i64>,
}

/// Service-global traffic-statistics settings on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrafficStatsSettingsDto {
    pub enabled: bool,
    pub count_loopback: bool,
    pub count_virtual: bool,
    pub retention_days: u32,
}

/// `traffic-stats.get` request — the day for "today" totals plus an optional
/// inclusive CSV export range (epoch-days, computed by the client in local time).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrafficStatsGetRequest {
    pub day: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_from_day: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_to_day: Option<i64>,
    /// Byte-count unit slug for the exported received/sent columns — `bytes`
    /// (default) / `kb` / `mb` / `gb`. Absent or unrecognised exports raw
    /// bytes, so an export is never silently mislabelled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_unit: Option<String>,
}

/// `traffic-stats.get` response — today + session totals, current settings, and
/// an optional CSV blob (present iff both export bounds were supplied).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrafficStatsGetResponse {
    pub today: Vec<TrafficRowDto>,
    pub session: Vec<TrafficRowDto>,
    /// All-time totals per adapter+role, summed over every retained day
    /// (bounded by the retention sweep). Defaulted so an older service reads
    /// as "no aggregate available" rather than failing to parse.
    #[serde(default)]
    pub all_time: Vec<TrafficRowDto>,
    /// Whether an additional-adapter session is live right now. `false` means
    /// `session` is the frozen snapshot of the last session (empty when no
    /// session happened since service start). Defaulted so an older service
    /// reads as "no live session" rather than failing to parse.
    #[serde(default)]
    pub session_active: bool,
    pub settings: TrafficStatsSettingsDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csv: Option<String>,
}

/// `traffic-stats.set` request — the new service-global settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrafficStatsSetRequest {
    pub settings: TrafficStatsSettingsDto,
}

// ── Companion-domain suggestions ─────────────────────────────────────────────

/// Slug for [`AutoRuleCandidateDto::match_kind`] when the suggestion is one
/// exact hostname.
pub const AUTO_RULE_MATCH_KIND_EXACT: &str = "exact";

/// Slug for [`AutoRuleCandidateDto::match_kind`] when the suggestion covers a
/// whole domain's subdomains.
pub const AUTO_RULE_MATCH_KIND_SUFFIX: &str = "suffix";

/// [`AutoRuleCandidateDto::signal`]: the host and the routed site share a brand
/// name, so the relation is visible in the name itself.
pub const AUTO_RULE_SIGNAL_BRAND_RELATED: &str = "brand-related";

/// [`AutoRuleCandidateDto::signal`]: the host is named like a delivery endpoint
/// (a CDN node) and the routed site dominates its traffic. This is the class the
/// `auto-rules-eager-delivery-names` toggle releases early, so the GUI's warning
/// about that toggle and this badge must name the same thing.
pub const AUTO_RULE_SIGNAL_DELIVERY_NAME: &str = "delivery-name";

/// [`AutoRuleCandidateDto::signal`]: neither name test applied — the host earned
/// the suggestion purely by appearing alongside the routed site.
pub const AUTO_RULE_SIGNAL_CO_ACTIVITY: &str = "co-activity";

/// Every [`AutoRuleCandidateDto::signal`] slug, for GUI allow-lists. Pinned
/// 1:1 with `CompanionSignal` — see [`AUTO_RULE_SIGNAL_ISP_BLOCK_PAGE`] for
/// the one signal that stays outside this set on purpose.
pub const AUTO_RULE_SIGNAL_SLUGS: &[&str] = &[
    AUTO_RULE_SIGNAL_BRAND_RELATED,
    AUTO_RULE_SIGNAL_DELIVERY_NAME,
    AUTO_RULE_SIGNAL_CO_ACTIVITY,
];

/// [`AutoRuleCandidateDto::signal`]: an ISP notice page answered right after
/// this host — blocked upstream, not merely broken. Has no `CompanionSignal`
/// counterpart, so it stays out of [`AUTO_RULE_SIGNAL_SLUGS`].
pub const AUTO_RULE_SIGNAL_ISP_BLOCK_PAGE: &str = "isp-block-page";

/// [`AutoRuleCandidateDto::primary_behavior`]: connections to the host went
/// through on the main route — it already works without the tunnel.
pub const AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS: &str = "responds";

/// [`AutoRuleCandidateDto::primary_behavior`]: connections to the host kept
/// stalling on the main route.
pub const AUTO_RULE_PRIMARY_BEHAVIOR_STALLS: &str = "stalls";

/// [`AutoRuleCandidateDto::primary_behavior`]: connections to the host were torn
/// down right after the handshake, carrying nothing — the path refused it rather
/// than failed to reach it.
pub const AUTO_RULE_PRIMARY_BEHAVIOR_CUT: &str = "cut";

/// Every [`AutoRuleCandidateDto::primary_behavior`] slug, for GUI allow-lists.
/// The absent/empty value — "nothing conclusive was observed" — is deliberately
/// NOT a slug: it is the default, not a verdict.
pub const AUTO_RULE_PRIMARY_BEHAVIOR_SLUGS: &[&str] = &[
    AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
    AUTO_RULE_PRIMARY_BEHAVIOR_CUT,
];

/// One site relying on a companion host — an element of
/// [`AutoRuleCandidateDto::consumers`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleConsumerDto {
    /// The routed hostname that pulled this host.
    pub hostname: String,
    /// Route slug the consumer's own rule lives on ([`crate::RouteRole::slug`]).
    pub route: String,
}

/// One pending suggestion: a host a routed site turned out to need, which the
/// caller's rules do not cover.
///
/// `id` is derived from the SID plus the anchor plus the proposed match, so it
/// is stable across service restarts and across proposal recomputations — the
/// tray keeps a set of already-offered ids and must not see a suggestion renamed
/// out from under it, and a persisted refusal must still match after a restart.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleCandidateDto {
    /// Stable id; the unit `accept` / `dismiss` act on.
    pub id: String,
    /// The routed host this candidate kept appearing alongside — the site the
    /// prompt names to the user.
    pub anchor: String,
    /// The hostname or domain the rule would match.
    pub proposed_match: String,
    /// [`AUTO_RULE_MATCH_KIND_EXACT`] or [`AUTO_RULE_MATCH_KIND_SUFFIX`].
    pub match_kind: String,
    /// Route slug the rule would be added to ([`crate::RouteRole::slug`]) —
    /// always the anchor's own route.
    pub route: String,
    /// How exclusively this host belongs to the anchor, `0.0..=1.0`. Near 1.0
    /// means it was never seen anywhere else.
    pub affinity: f64,
    /// Distinct visits the pair was observed in.
    pub observations: u32,
    /// First and most recent sighting, UTC Unix milliseconds.
    pub first_seen_unix_ms: i64,
    pub last_seen_unix_ms: i64,
    /// Why this host was suggested — one of [`AUTO_RULE_SIGNAL_SLUGS`]. The
    /// user is being asked to add something to their own rules, so the answer to
    /// "how do you know?" travels with the offer rather than being inferred from
    /// the numbers.
    ///
    /// Additive on the wire: absent (and omitted when empty) for peers that
    /// predate it, so existing messages keep their exact byte shape.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signal: String,
    /// Every site currently relying on this host, strongest evidence first —
    /// element 0 is always `anchor`. A host needed by two routed sites is one
    /// offer, not two, but the user still gets to see who else it affects,
    /// including a site on the OTHER route whose own proposal is inert (its
    /// route already gets the host by default).
    ///
    /// Additive on the wire: empty (and omitted) for peers that predate it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consumers: Vec<AutoRuleConsumerDto>,
    /// Unix ms when a hostname not already in `consumers` last joined it.
    /// Unchanged by a recomputation that finds the same consumers — this is
    /// "when did the evidence grow", not "when was this last seen".
    ///
    /// Additive on the wire: `0` for peers that predate it.
    #[serde(default)]
    pub consumers_changed_unix_ms: i64,
    /// How the host behaves when reached over the main route — one of
    /// [`AUTO_RULE_PRIMARY_BEHAVIOR_SLUGS`], or empty when nothing conclusive
    /// was observed. The offer is "move this into the tunnel", so "it already
    /// works without one" is what most changes the answer.
    ///
    /// Additive on the wire: absent (and omitted when empty) for peers that
    /// predate it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub primary_behavior: String,
}

/// `autorules.candidates.list` request — no parameters; the caller's own SID
/// scopes the read. Present as a type so the op has the same
/// request/response pairing as every other operation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleCandidatesListRequest {}

/// `autorules.candidates.list` response.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleCandidatesListResponse {
    pub candidates: Vec<AutoRuleCandidateDto>,
}

/// Request shared by `autorules.candidates.accept` and
/// `autorules.candidates.dismiss`: the ids the user answered for. Ids the
/// service no longer holds are ignored rather than rejected — the pending set
/// is in-memory and may have been re-derived between the list and the answer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleCandidatesActionRequest {
    #[serde(default)]
    pub ids: Vec<String>,
}

/// Response shared by `autorules.candidates.accept` and
/// `autorules.candidates.dismiss`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleCandidatesActionResponse {
    /// How many of the requested ids were actually acted on.
    pub applied: u32,
    /// How many ids were not found in the caller's pending set.
    pub unknown: u32,
    /// Pending suggestions left for this caller after the action.
    pub pending: u64,
}

/// One suggestion the caller previously declined, as reviewed and possibly
/// restored on `autorules.dismissed.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleDismissedEntryDto {
    /// Same stable id `autorules.candidates.dismiss` accepted; also what
    /// `autorules.dismissed.restore` acts on.
    pub candidate_id: String,
    /// The routed host the suggestion was made alongside.
    pub anchor: String,
    /// The hostname or domain that was declined.
    pub proposed_match: String,
    /// When the refusal was recorded, or last re-affirmed.
    pub dismissed_at_unix_ms: i64,
}

/// `autorules.dismissed.list` request — no parameters; the caller's own SID
/// scopes the read.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleDismissedListRequest {}

/// `autorules.dismissed.list` response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleDismissedListResponse {
    /// Most recently declined first — the order a review surface wants.
    pub dismissed: Vec<AutoRuleDismissedEntryDto>,
}

/// `autorules.dismissed.restore` request: candidate ids to un-decline. Ids the
/// caller never declined (or already restored) are ignored rather than
/// rejected — same tolerance as the accept/dismiss request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleDismissedRestoreRequest {
    #[serde(default)]
    pub ids: Vec<String>,
}

/// `autorules.dismissed.restore` response. Restoring only lifts the
/// suppression — it does not resurrect the original offer — so, unlike
/// [`AutoRuleCandidatesActionResponse`], there is no `pending` count to report.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleDismissedRestoreResponse {
    /// How many of the requested ids were actually restored.
    pub restored: u32,
    /// How many ids were not found in the caller's declined set.
    pub unknown: u32,
}

// ── Block-notice mutes ───────────────────────────────────────────────────────

/// Wire form of `nrr_domain::block_notice::MuteScope`. A tagged enum rather
/// than a bare struct because `all` carries no name to check against —
/// mirrors the shape of [`crate::RuleOrigin`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum BlockNoticeMuteScopeDto {
    /// One destination, by the name shown to the user.
    Host { host: String },
    /// Every block from one application, by image name.
    App { app: String },
    /// Every block that happened for one reason, by `BlockReason` slug.
    Reason { reason: String },
    /// Block notices as a whole.
    All,
}

/// One active mute, as listed or just written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMuteDto {
    pub scope: BlockNoticeMuteScopeDto,
    /// Wall-clock Unix ms after which the mute lapses; absent means
    /// indefinitely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_unix_ms: Option<u64>,
}

/// `block-notices.mutes.list` request — no parameters; the caller's own SID
/// scopes the read.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesListRequest {}

/// `block-notices.mutes.list` response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesListResponse {
    pub mutes: Vec<BlockNoticeMuteDto>,
}

/// `block-notices.mutes.set` request — add or refresh one mute for the
/// caller. An absent expiry means "until removed".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesSetRequest {
    pub scope: BlockNoticeMuteScopeDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_unix_ms: Option<u64>,
}

/// `block-notices.mutes.set` response — the caller's active mutes after the
/// write, so the tray can refresh in one round trip.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesSetResponse {
    pub mutes: Vec<BlockNoticeMuteDto>,
}

/// `block-notices.mutes.remove` request — undo one mute. A scope that was
/// never muted is a no-op, not an error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesRemoveRequest {
    pub scope: BlockNoticeMuteScopeDto,
}

/// `block-notices.mutes.remove` response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesRemoveResponse {
    /// Whether a mute actually existed at that scope.
    pub removed: bool,
    pub mutes: Vec<BlockNoticeMuteDto>,
}

/// `block-notices.mutes.clear` request — no parameters; drops every mute the
/// caller has set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesClearRequest {}

/// `block-notices.mutes.clear` response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesClearResponse {
    pub mutes: Vec<BlockNoticeMuteDto>,
}

// ── Block-notice-driven routing ──────────────────────────────────────────────

/// `block-notices.route-to-secondary` request — turn one blocked destination
/// into a rule that routes it over the additional link. `destination` is the
/// notice's own `destination` field (a hostname; an address with no known
/// hostname cannot be routed by a suffix rule and is refused).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeRouteToSecondaryRequest {
    pub destination: String,
}

/// `block-notices.route-to-secondary` response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeRouteToSecondaryResponse {
    /// `false` when an equivalent rule already covered the host — the
    /// destination is routed either way, nothing new was written.
    pub authored: bool,
}

// ── Full-reset auxiliary-state purge ─────────────────────────────────────────

/// `principal-data.purge` request — no parameters; scopes to the caller's
/// own principal, same shape as `block-notices.mutes.clear`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrincipalDataPurgeRequest {}

/// `principal-data.purge` response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrincipalDataPurgeResponse {
    /// Total rows deleted across every purged table.
    pub rows_deleted: u64,
    /// How many of the purged tables actually held a row for this caller.
    pub tables_touched: u32,
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ServiceHealthResponse / FakeIpDatapathDto ────────────────────────────

    #[test]
    fn service_health_response_fake_ip_datapath_round_trips_as_kebab_case() {
        let resp = ServiceHealthResponse {
            service_state: "running".to_string(),
            worst_severity: "ok".to_string(),
            active_revision_id: None,
            components: Vec::new(),
            degraded_modes: Vec::new(),
            fake_ip_datapath: Some(FakeIpDatapathDto {
                desired: true,
                running: false,
                zombies: 2,
            }),
        };
        let json = serde_json::to_value(&resp).expect("serialise");
        assert_eq!(json["fake-ip-datapath"]["desired"], true);
        assert_eq!(json["fake-ip-datapath"]["running"], false);
        assert_eq!(json["fake-ip-datapath"]["zombies"], 2);
        let back: ServiceHealthResponse = serde_json::from_value(json).expect("deserialise");
        assert_eq!(back, resp);
    }

    #[test]
    fn service_health_response_without_fake_ip_datapath_stays_compatible() {
        // A pre-field service payload must still deserialise (back-compat),
        // and an unset field must not appear on the wire (forward-compat).
        let old_wire = serde_json::json!({
            "service-state": "running",
            "worst-severity": "ok",
            "components": [],
            "degraded-modes": [],
        });
        let parsed: ServiceHealthResponse =
            serde_json::from_value(old_wire).expect("deserialise old payload");
        assert!(parsed.fake_ip_datapath.is_none());

        let json = serde_json::to_value(&parsed).expect("serialise");
        assert!(json.get("fake-ip-datapath").is_none());
    }

    // ── RuleSummaryEntryDto ─────────────────────────────────────────────────

    #[test]
    fn rule_summary_entry_without_enabled_reads_as_enabled() {
        // A service that predates the flag only ever reported enforceable
        // rules — its payloads must keep parsing, and as "enabled".
        let old_wire = serde_json::json!({
            "id": "r-001",
            "display": "example.com",
            "route": "secondary",
        });
        let parsed: RuleSummaryEntryDto =
            serde_json::from_value(old_wire).expect("deserialise pre-field payload");
        assert!(parsed.enabled);
    }

    #[test]
    fn rule_summary_entry_keeps_the_pre_field_bytes_when_enabled() {
        // Additive by construction: an enabled entry serialises exactly as
        // it did before the field existed, so only disabled rules pay for it.
        let entry = RuleSummaryEntryDto {
            id: "r-001".to_string(),
            display: "example.com".to_string(),
            route: "secondary".to_string(),
            enabled: true,
        };
        let json = serde_json::to_value(&entry).expect("serialise");
        assert!(json.get("enabled").is_none());

        let disabled = RuleSummaryEntryDto {
            enabled: false,
            ..entry
        };
        let json = serde_json::to_value(&disabled).expect("serialise");
        assert_eq!(
            json["enabled"], false,
            "the review diff in ReviewDiffColumn.qml reads `enabled`"
        );
        let back: RuleSummaryEntryDto = serde_json::from_value(json).expect("deserialise");
        assert_eq!(back, disabled);
    }

    // ── RoutePolicyDto / RoutePolicyUpdateRequest — auto-rules mode ──────────

    /// The three auto-rules slugs are a cross-process contract: the
    /// `auto_rules_mode` CHECK constraint in `nrr-storage`'s state schema,
    /// `nrr_storage::auto_rules::AutoRulesMode::as_slug`, and the
    /// `autoRulesMode` combo box in
    /// `apps/desktop/qml/sections/settings/RoutingSettings.qml` all repeat these
    /// literals. Pinned here so a rename has to be deliberate on every side.
    const AUTO_RULES_MODE_WIRE_SLUGS: [&str; 3] = ["off", "suggest", "auto"];

    fn route_policy_update_request_sample(auto_rules_mode: &str) -> RoutePolicyUpdateRequest {
        RoutePolicyUpdateRequest {
            primary: None,
            secondary: None,
            mode: BehaviorModeDto::PreferPrimary,
            block_secondary_when_unavailable: true,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            kill_switch_enabled: false,
            allow_dns_over_primary: true,
            include_subdomains: false,
            shared_ip_policy: shared_ip_policy_default(),
            mode_a_coverage_strategy: mode_a_coverage_strategy_default(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: doh_lockdown_scope_default(),
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: false,
            auto_rules_mode: auto_rules_mode.to_string(),
            auto_rules_eager_delivery_names: false,
            binding_source: BindingSourceDto::UserAssigned,
        }
    }

    #[test]
    fn auto_rules_mode_travels_as_kebab_case_key_with_pinned_slugs() {
        for slug in AUTO_RULES_MODE_WIRE_SLUGS {
            let json = serde_json::to_value(route_policy_update_request_sample(slug))
                .expect("serialise request");
            assert_eq!(
                json["auto-rules-mode"], slug,
                "the QML combo box in RoutingSettings.qml reads `auto-rules-mode`"
            );
        }
    }

    #[test]
    fn auto_rules_mode_defaults_to_suggest_when_an_older_peer_omits_it() {
        // v1 ships with application disabled: an omitted field must read as
        // "collect and offer", never as `off` (silently disabling discovery)
        // and never as `auto` (silently applying rules unattended).
        let mut json =
            serde_json::to_value(route_policy_update_request_sample("auto")).expect("serialise");
        let obj = json.as_object_mut().expect("object payload");
        obj.remove("auto-rules-mode");
        let parsed: RoutePolicyUpdateRequest =
            serde_json::from_value(json).expect("deserialise pre-field payload");
        assert_eq!(parsed.auto_rules_mode, "suggest");
        assert_eq!(auto_rules_mode_default(), "suggest");
    }

    #[test]
    fn eager_delivery_names_travels_as_kebab_case_and_defaults_off() {
        let mut on = route_policy_update_request_sample("suggest");
        on.auto_rules_eager_delivery_names = true;
        let json = serde_json::to_value(&on).expect("serialise");
        assert_eq!(
            json["auto-rules-eager-delivery-names"], true,
            "the QML checkbox reads `auto-rules-eager-delivery-names`"
        );

        // Opting a user in is theirs to do: an omitted field is never "on".
        let mut json = json;
        let obj = json.as_object_mut().expect("object payload");
        obj.remove("auto-rules-eager-delivery-names");
        let parsed: RoutePolicyUpdateRequest =
            serde_json::from_value(json).expect("deserialise pre-field payload");
        assert!(!parsed.auto_rules_eager_delivery_names);
    }

    /// Every push event a client can receive. Kept here rather than built ad
    /// hoc so the shape test below covers new variants by construction.
    fn every_status_update_event() -> Vec<StatusUpdateEvent> {
        vec![
            StatusUpdateEvent::HealthChanged {
                service_state: "running".into(),
                worst_severity: "info".into(),
            },
            StatusUpdateEvent::AdaptersChanged {
                data_source: "os".into(),
            },
            StatusUpdateEvent::AlertRaised {
                alert_id: "a-1".into(),
                kind: "tamper".into(),
            },
            StatusUpdateEvent::OperationFinished {
                operation_id: "op-1".into(),
                state: "completed".into(),
                error_code: None,
            },
            StatusUpdateEvent::Overflow { dropped_count: 3 },
            StatusUpdateEvent::RevisionStatusChanged {
                revision_id: "rev-1".into(),
                status: "active".into(),
            },
            StatusUpdateEvent::RoutingPauseStateChanged {
                sid: "S-1-5-21".into(),
                paused: false,
            },
            StatusUpdateEvent::ApplyFailurePolicyChanged {
                policy: "best-effort".into(),
            },
            StatusUpdateEvent::AutostartStateChanged {
                enabled: true,
                last_known_state: "enabled".into(),
            },
            StatusUpdateEvent::RetentionSettingsChanged,
            StatusUpdateEvent::MutationProgress {
                correlation_id: "corr-1".into(),
                mutation_kind: "rules-update".into(),
                phase: "completed".into(),
                error_code: None,
            },
            StatusUpdateEvent::AutoRuleCandidatesChanged {
                sid: "S-1-5-21".into(),
                pending_count: 59,
                top_anchor: "example.com".into(),
            },
            StatusUpdateEvent::SecondaryExternalAddressObserved {
                sid: "S-1-5-21".into(),
                adapter_name: "Tunnel".into(),
                external_address: "203.0.113.7".into(),
            },
            StatusUpdateEvent::BlockNoticeRaised {
                sid: "S-1-5-21".into(),
                destination: "cdn.example".into(),
                app: "telegram.exe".into(),
                reason: "not-covered-by-rules".into(),
                attempts: 1,
            },
        ]
    }

    /// `rename_all` renames variants, NOT their fields. Without
    /// `rename_all_fields` every multi-word field ships snake_case while the
    /// QML readers index kebab-case, so the value reads as undefined and the
    /// event silently does nothing — the tray showed "0 pending" while the
    /// service was publishing 59.
    #[test]
    fn every_push_event_field_travels_as_kebab_case() {
        for event in every_status_update_event() {
            let json = serde_json::to_value(&event).expect("serialise event");
            let object = json.as_object().expect("event serialises to an object");
            for key in object.keys() {
                assert!(
                    !key.contains('_'),
                    "push event field `{key}` ships snake_case; QML reads kebab-case: {json}"
                );
            }
        }
    }

    /// The exact keys the tray and the main window index, pinned by name. A
    /// rename that keeps the kebab-case shape but changes a word would pass
    /// the test above and still break the reader.
    #[test]
    fn push_event_keys_the_ui_reads_are_stable() {
        let pending = serde_json::to_value(StatusUpdateEvent::AutoRuleCandidatesChanged {
            sid: "S-1-5-21".into(),
            pending_count: 59,
            top_anchor: "example.com".into(),
        })
        .expect("serialise");
        assert_eq!(pending["pending-count"], 59);
        assert_eq!(pending["top-anchor"], "example.com");

        let address = serde_json::to_value(StatusUpdateEvent::SecondaryExternalAddressObserved {
            sid: "S-1-5-21".into(),
            adapter_name: "Tunnel".into(),
            external_address: "203.0.113.7".into(),
        })
        .expect("serialise");
        assert_eq!(address["external-address"], "203.0.113.7");
        assert_eq!(address["adapter-name"], "Tunnel");

        let progress = serde_json::to_value(StatusUpdateEvent::MutationProgress {
            correlation_id: "corr-1".into(),
            mutation_kind: "rules-update".into(),
            phase: "completed".into(),
            error_code: None,
        })
        .expect("serialise");
        assert_eq!(progress["correlation-id"], "corr-1");
        assert_eq!(progress["mutation-kind"], "rules-update");

        let revision = serde_json::to_value(StatusUpdateEvent::RevisionStatusChanged {
            revision_id: "rev-1".into(),
            status: "active".into(),
        })
        .expect("serialise");
        assert_eq!(revision["revision-id"], "rev-1");

        let notice = serde_json::to_value(StatusUpdateEvent::BlockNoticeRaised {
            sid: "S-1-5-21".into(),
            destination: "cdn.example".into(),
            app: "telegram.exe".into(),
            reason: "not-covered-by-rules".into(),
            attempts: 1,
        })
        .expect("serialise");
        assert_eq!(notice["type"], "block-notice-raised");
        assert_eq!(notice["destination"], "cdn.example");
        assert_eq!(notice["reason"], "not-covered-by-rules");
        assert_eq!(notice["attempts"], 1);
    }

    // ── PresetImportPayload ──────────────────────────────────────────────────

    #[test]
    fn preset_import_payload_serializes_as_kebab_case() {
        let payload = PresetImportPayload {
            route: Some(RouteRole::Primary),
            primary_bytes_b64: Some("Zm9v".to_string()),
            secondary_bytes_b64: None,
            include_child_processes: true,
            import_only_active: true,
            content_hash_primary: Some("abc".to_string()),
            content_hash_secondary: None,
            correlation_id: Some("corr-1".to_string()),
        };
        let json = serde_json::to_value(&payload).expect("serialise");
        assert_eq!(json["route"], "primary");
        assert_eq!(json["primary-bytes-b64"], "Zm9v");
        assert_eq!(json["include-child-processes"], true);
        assert_eq!(json["import-only-active"], true);
        assert_eq!(json["content-hash-primary"], "abc");
        assert_eq!(json["correlation-id"], "corr-1");
        // Optional unset fields must not appear in output.
        assert!(json.get("secondary-bytes-b64").is_none());
        assert!(json.get("content-hash-secondary").is_none());
    }

    #[test]
    fn preset_import_payload_deserializes_minimal_form() {
        let json = serde_json::json!({
            "primary-bytes-b64": "Zm9v",
            "include-child-processes": false,
        });
        let payload: PresetImportPayload = serde_json::from_value(json).expect("deserialise");
        assert_eq!(payload.primary_bytes_b64.as_deref(), Some("Zm9v"));
        assert!(payload.secondary_bytes_b64.is_none());
        assert!(payload.route.is_none());
        assert!(payload.content_hash_primary.is_none());
        assert!(payload.correlation_id.is_none());
        assert!(!payload.include_child_processes);
        // Omitted on the wire → serde default false (back-compat: an older
        // client that doesn't know the flag imports everything).
        assert!(!payload.import_only_active);
    }

    #[test]
    fn preset_import_target_single_primary_implicit() {
        let payload = PresetImportPayload {
            primary_bytes_b64: Some("x".to_string()),
            include_child_processes: false,
            ..Default::default()
        };
        assert_eq!(
            payload.target(),
            Ok(PresetImportTarget::SingleRoute(RouteRole::Primary))
        );
    }

    #[test]
    fn preset_import_target_single_secondary_implicit() {
        let payload = PresetImportPayload {
            secondary_bytes_b64: Some("x".to_string()),
            include_child_processes: false,
            ..Default::default()
        };
        assert_eq!(
            payload.target(),
            Ok(PresetImportTarget::SingleRoute(RouteRole::Secondary))
        );
    }

    #[test]
    fn preset_import_target_single_with_matching_route_hint() {
        let payload = PresetImportPayload {
            route: Some(RouteRole::Primary),
            primary_bytes_b64: Some("x".to_string()),
            include_child_processes: false,
            ..Default::default()
        };
        assert_eq!(
            payload.target(),
            Ok(PresetImportTarget::SingleRoute(RouteRole::Primary))
        );
    }

    #[test]
    fn preset_import_target_route_mismatch_is_rejected() {
        // primary bytes supplied but caller claims it's for secondary.
        let payload = PresetImportPayload {
            route: Some(RouteRole::Secondary),
            primary_bytes_b64: Some("x".to_string()),
            include_child_processes: false,
            ..Default::default()
        };
        assert_eq!(
            payload.target(),
            Err(PresetImportPayloadError::RouteMismatch)
        );
    }

    #[test]
    fn preset_import_target_both_routes_ignores_route_hint() {
        let payload = PresetImportPayload {
            route: Some(RouteRole::Primary), // ignored when both bytes present.
            primary_bytes_b64: Some("a".to_string()),
            secondary_bytes_b64: Some("b".to_string()),
            include_child_processes: false,
            ..Default::default()
        };
        assert_eq!(payload.target(), Ok(PresetImportTarget::BothRoutes));
    }

    #[test]
    fn preset_import_target_no_bytes_is_rejected() {
        let payload = PresetImportPayload {
            include_child_processes: false,
            ..Default::default()
        };
        assert_eq!(
            payload.target(),
            Err(PresetImportPayloadError::NoBytesSupplied)
        );
    }

    #[test]
    fn auto_rule_candidate_dto_uses_the_kebab_wire_names_the_tray_reads() {
        // The tray reads these exact keys out of the response; a rename here
        // silently empties its prompt, so pin them.
        let dto = AutoRuleCandidateDto {
            id: "arc-1".into(),
            anchor: "site.example".into(),
            proposed_match: "cdn.example".into(),
            match_kind: AUTO_RULE_MATCH_KIND_EXACT.into(),
            route: crate::RouteRole::Secondary.slug().into(),
            affinity: 1.0,
            observations: 2,
            first_seen_unix_ms: 1,
            last_seen_unix_ms: 2,
            signal: AUTO_RULE_SIGNAL_DELIVERY_NAME.into(),
            consumers: vec![AutoRuleConsumerDto {
                hostname: "site.example".into(),
                route: crate::RouteRole::Secondary.slug().into(),
            }],
            consumers_changed_unix_ms: 2,
            primary_behavior: AUTO_RULE_PRIMARY_BEHAVIOR_STALLS.into(),
        };
        let json = serde_json::to_value(&dto).expect("serialise");
        for key in [
            "id",
            "anchor",
            "proposed-match",
            "match-kind",
            "route",
            "affinity",
            "observations",
            "first-seen-unix-ms",
            "last-seen-unix-ms",
            "signal",
            "consumers",
            "consumers-changed-unix-ms",
            "primary-behavior",
        ] {
            assert!(json.get(key).is_some(), "missing wire key {key}");
        }
        let back: AutoRuleCandidateDto = serde_json::from_value(json).expect("deserialise");
        assert_eq!(back, dto);
    }

    /// `signal` is additive in both directions: a candidate without one
    /// serialises to the exact set of keys the field predates, and a message
    /// written before the field still parses.
    #[test]
    fn auto_rule_candidate_signal_is_additive_in_both_directions() {
        let mut dto = AutoRuleCandidateDto {
            id: "arc-1".into(),
            anchor: "site.example".into(),
            proposed_match: "cdn.example".into(),
            match_kind: AUTO_RULE_MATCH_KIND_EXACT.into(),
            route: crate::RouteRole::Secondary.slug().into(),
            affinity: 1.0,
            observations: 2,
            first_seen_unix_ms: 1,
            last_seen_unix_ms: 2,
            signal: String::new(),
            consumers: Vec::new(),
            consumers_changed_unix_ms: 0,
            primary_behavior: String::new(),
        };
        let json = serde_json::to_value(&dto).expect("serialise");
        let keys: Vec<&String> = json.as_object().expect("object").keys().collect::<Vec<_>>();
        assert!(
            !keys.iter().any(|k| k.as_str() == "signal"),
            "an unset signal must not add a key: {keys:?}"
        );
        assert!(
            !keys.iter().any(|k| k.as_str() == "consumers"),
            "an empty consumer list must not add a key: {keys:?}"
        );
        assert!(
            !keys.iter().any(|k| k.as_str() == "primary-behavior"),
            "an unobserved primary behaviour must not add a key: {keys:?}"
        );
        let back: AutoRuleCandidateDto = serde_json::from_value(json).expect("deserialise");
        assert_eq!(back, dto);

        dto.signal = AUTO_RULE_SIGNAL_CO_ACTIVITY.into();
        let json = serde_json::to_value(&dto).expect("serialise");
        assert_eq!(json["signal"], AUTO_RULE_SIGNAL_CO_ACTIVITY);
    }

    /// The badge slugs are a cross-process contract with the tray/GUI text and
    /// with `nrr_domain::companion_affinity::CompanionSignal`. Pin the literals.
    #[test]
    fn auto_rule_signal_slugs_are_pinned() {
        assert_eq!(
            AUTO_RULE_SIGNAL_SLUGS,
            ["brand-related", "delivery-name", "co-activity"]
        );
    }

    #[test]
    fn auto_rule_action_request_defaults_to_an_empty_id_list() {
        let parsed: AutoRuleCandidatesActionRequest =
            serde_json::from_str("{}").expect("deserialise");
        assert!(parsed.ids.is_empty());
        let parsed: AutoRuleCandidatesActionRequest =
            serde_json::from_str(r#"{"ids":["a","b"]}"#).expect("deserialise");
        assert_eq!(parsed.ids, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn auto_rule_dismissed_restore_request_defaults_to_an_empty_id_list() {
        let parsed: AutoRuleDismissedRestoreRequest =
            serde_json::from_str("{}").expect("deserialise");
        assert!(parsed.ids.is_empty());
        let parsed: AutoRuleDismissedRestoreRequest =
            serde_json::from_str(r#"{"ids":["a","b"]}"#).expect("deserialise");
        assert_eq!(parsed.ids, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn auto_rule_dismissed_entry_dto_uses_the_kebab_wire_names_the_gui_reads() {
        let dto = AutoRuleDismissedEntryDto {
            candidate_id: "arc-1".into(),
            anchor: "site.example".into(),
            proposed_match: "cdn.example".into(),
            dismissed_at_unix_ms: 1_700_000_000_000,
        };
        let json = serde_json::to_value(&dto).expect("serialise");
        for key in [
            "candidate-id",
            "anchor",
            "proposed-match",
            "dismissed-at-unix-ms",
        ] {
            assert!(json.get(key).is_some(), "missing wire key {key}");
        }
        let back: AutoRuleDismissedEntryDto = serde_json::from_value(json).expect("deserialise");
        assert_eq!(back, dto);
    }

    #[test]
    fn preset_import_payload_round_trips_through_json() {
        let original = PresetImportPayload {
            route: None,
            primary_bytes_b64: Some("YWxwaGE=".to_string()),
            secondary_bytes_b64: Some("YmV0YQ==".to_string()),
            include_child_processes: true,
            import_only_active: false,
            content_hash_primary: Some("h1".to_string()),
            content_hash_secondary: Some("h2".to_string()),
            correlation_id: None,
        };
        let json = serde_json::to_string(&original).expect("serialise");
        let parsed: PresetImportPayload = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(parsed.primary_bytes_b64, original.primary_bytes_b64);
        assert_eq!(parsed.secondary_bytes_b64, original.secondary_bytes_b64);
        assert!(parsed.include_child_processes);
        assert_eq!(parsed.content_hash_primary, original.content_hash_primary);
        assert_eq!(parsed.target(), Ok(PresetImportTarget::BothRoutes));
    }

    // ── Block-notice mutes / routing ─────────────────────────────────────────

    #[test]
    fn block_notice_mute_scope_dto_round_trips_every_variant() {
        for (scope, expect_kind, expect_key) in [
            (
                BlockNoticeMuteScopeDto::Host {
                    host: "cdn.example".into(),
                },
                "host",
                Some("host"),
            ),
            (
                BlockNoticeMuteScopeDto::App {
                    app: "telegram.exe".into(),
                },
                "app",
                Some("app"),
            ),
            (BlockNoticeMuteScopeDto::All, "all", None),
        ] {
            let json = serde_json::to_value(&scope).expect("serialise");
            assert_eq!(json["kind"], expect_kind);
            if let Some(key) = expect_key {
                assert!(json.get(key).is_some(), "missing wire key {key}: {json}");
            }
            let back: BlockNoticeMuteScopeDto = serde_json::from_value(json).expect("deserialise");
            assert_eq!(back, scope);
        }
    }

    #[test]
    fn block_notice_mute_dto_omits_until_when_forever() {
        let forever = BlockNoticeMuteDto {
            scope: BlockNoticeMuteScopeDto::All,
            until_unix_ms: None,
        };
        let json = serde_json::to_value(&forever).expect("serialise");
        assert!(json.get("until-unix-ms").is_none());
        let back: BlockNoticeMuteDto = serde_json::from_value(json).expect("deserialise");
        assert_eq!(back, forever);

        let bounded = BlockNoticeMuteDto {
            scope: BlockNoticeMuteScopeDto::Host {
                host: "cdn.example".into(),
            },
            until_unix_ms: Some(5_000),
        };
        let json = serde_json::to_value(&bounded).expect("serialise");
        assert_eq!(json["until-unix-ms"], 5_000);
        let back: BlockNoticeMuteDto = serde_json::from_value(json).expect("deserialise");
        assert_eq!(back, bounded);
    }

    #[test]
    fn block_notice_mutes_set_request_uses_kebab_wire_keys() {
        let req = BlockNoticeMutesSetRequest {
            scope: BlockNoticeMuteScopeDto::App {
                app: "telegram.exe".into(),
            },
            until_unix_ms: Some(1_000),
        };
        let json = serde_json::to_value(&req).expect("serialise");
        assert_eq!(json["scope"]["kind"], "app");
        assert_eq!(json["scope"]["app"], "telegram.exe");
        assert_eq!(json["until-unix-ms"], 1_000);
        let back: BlockNoticeMutesSetRequest = serde_json::from_value(json).expect("deserialise");
        assert_eq!(back, req);
    }

    #[test]
    fn block_notice_route_to_secondary_round_trips() {
        let req = BlockNoticeRouteToSecondaryRequest {
            destination: "cdn.example".into(),
        };
        let json = serde_json::to_value(&req).expect("serialise");
        assert_eq!(json["destination"], "cdn.example");
        let back: BlockNoticeRouteToSecondaryRequest =
            serde_json::from_value(json).expect("deserialise");
        assert_eq!(back, req);

        let resp = BlockNoticeRouteToSecondaryResponse { authored: true };
        let json = serde_json::to_value(&resp).expect("serialise");
        assert_eq!(json["authored"], true);
    }
}
