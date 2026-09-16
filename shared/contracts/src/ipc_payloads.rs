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
    /// The sender could not read IP / gateway / DNS for ANY adapter, so every
    /// row's `local_ip` is `"-"` because the query failed — not because the
    /// adapters have no address. Absent on the wire means "the data is real".
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub runtime_data_unavailable: bool,
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

mod rules;
pub use rules::*;
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
    /// The protection in force for this principal does not match what their
    /// settings ask for, or is in force because of somebody ELSE's settings.
    ///
    /// Two situations, one event, because the user's question is the same
    /// ("why is my network behaving like this?"):
    /// - `blanket-block-not-armed`: the settings ask for a blanket block, but
    ///   the service does not know the additional link's address and will not
    ///   plan a block that would cut the tunnel it is protecting;
    /// - `machine-wide-cut-by-another-user`: another logged-in principal armed
    ///   protection whose packet-layer half cannot be scoped to one user (the
    ///   WFP packet layer carries no user context), so ICMP and IPv6 are cut
    ///   machine-wide.
    ///
    /// `reason` is a slug — the GUI renders it through `tr()`, never raw.
    ProtectionCoverageChanged { reason: String },
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
    /// This SID's active rules name the same traffic on BOTH routes, with both
    /// copies enabled. Which one wins is then decided by evaluation order
    /// rather than by the user, and nothing in the running policy says so —
    /// hence a notice rather than a screen they would have to visit.
    ///
    /// `sample` is what one of the duplicated rules matches, for a notice that
    /// names something recognisable instead of a bare count.
    RuleDuplicatesDetected {
        sid: String,
        count: u64,
        sample: String,
    },
    /// A host that stalls on the main link did not answer the probe through
    /// the additional one either, so no offer was shown: moving it would change
    /// nothing. Said quietly, in the notice list only — it is somebody else's
    /// outage — so that "why was nothing offered" has an answer.
    HostUnreachableOnBothRoutes { sid: String, host: String },
    /// An application rule reached this SID for the first time.
    ///
    /// The route for an application is built from the addresses the service has
    /// SEEN it use, so the app's first contact with each new address has no
    /// route yet, egresses the main link and is refused — that refusal is what
    /// teaches the address. A program with a large address pool spends that as
    /// a run of failures, and one that gives up after the first is simply
    /// broken until it is restarted. The user is told rather than left to
    /// guess.
    AppRuleLearningDestinations { sid: String, apps: Vec<String> },
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
    /// A tunnel came up while this SID has no additional route assigned, so
    /// nothing the rules send there can go anywhere.
    ///
    /// Only raised for a tunnel that looks like a PERSONAL VPN. A corporate
    /// client is normally installed by an employer and is not meant to become
    /// the additional route, and telling that user to assign it would be the
    /// product guessing at their IT policy. The two mistakes cost different
    /// amounts: an unwanted notice is dismissed once, a missing one leaves the
    /// user testing against a route that was never assigned.
    UnassignedTunnelDetected {
        sid: String,
        /// Adapter description as the interfaces list shows it, so the notice
        /// can name the connection the user just started.
        adapter_name: String,
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
        /// `"blocked-by-rule"` / `"ipv6-blocked"` / `"dns-lockdown"` /
        /// `"unattributed"`), drives the notice wording.
        reason: String,
        /// Attempts folded into this episode so far.
        attempts: u64,
    },
    /// Whether this SID's policy is actually being enforced, and what the user
    /// has to do when it is not.
    ///
    /// Exists because "the service is running" and "your rules are in force"
    /// are different facts, and only the first one was ever visible: a binding
    /// the service cannot resolve, or a missing primary, left the product
    /// looking healthy while it routed nothing. Published on CHANGE only —
    /// `status = "ok"` clears a standing notice.
    EnforcementStatusChanged {
        sid: String,
        /// `"ok"` | `"adapter-choice-needed"` | `"adapter-gone"` |
        /// `"adapter-failed"` |
        /// `"no-primary-route"` | `"no-policy"` | `"secondary-down"` |
        /// `"adapters-unreadable"`. A client that does not recognise a value
        /// shows the generic "your rules are not being applied" wording rather
        /// than nothing.
        status: String,
        /// Binding role the status is about (`"primary"` / `"secondary"`);
        /// empty when it is not about one role.
        role: String,
        /// Adapters the user could pick from, by the name the interfaces list
        /// shows. Populated for the statuses that ask the user to choose:
        /// `"adapter-choice-needed"` (too many answer to the saved name) and
        /// `"adapter-gone"` (none does) and `"adapter-failed"` (the bound one
        /// is still installed but its driver will not start).
        #[serde(default)]
        candidates: Vec<String>,
    },
}

impl StatusUpdateEvent {
    /// The principal this event is ABOUT, when it is about one.
    ///
    /// An event that names a SID in its own payload is, by construction, that
    /// user's news: their pause, their coverage, their tunnel. Broadcasting it
    /// tells every other session what they are doing, and makes every other GUI
    /// react to a change that is not theirs. The bus routes on this answer, so
    /// the two cannot disagree.
    ///
    /// The match is exhaustive on purpose — a new variant does not compile until
    /// someone has said who it belongs to, which is the only way this stays true.
    #[must_use]
    pub fn addressee(&self) -> Option<&str> {
        match self {
            Self::RoutingPauseStateChanged { sid, .. }
            | Self::AutoRuleCandidatesChanged { sid, .. }
            | Self::RuleDuplicatesDetected { sid, .. }
            | Self::HostUnreachableOnBothRoutes { sid, .. }
            | Self::AppRuleLearningDestinations { sid, .. }
            | Self::SecondaryExternalAddressObserved { sid, .. }
            | Self::UnassignedTunnelDetected { sid, .. }
            | Self::BlockNoticeRaised { sid, .. }
            | Self::EnforcementStatusChanged { sid, .. } => Some(sid.as_str()),
            Self::HealthChanged { .. }
            | Self::ProtectionCoverageChanged { .. }
            | Self::AdaptersChanged { .. }
            | Self::AlertRaised { .. }
            | Self::OperationFinished { .. }
            | Self::Overflow { .. }
            | Self::RevisionStatusChanged { .. }
            | Self::ApplyFailurePolicyChanged { .. }
            | Self::AutostartStateChanged { .. }
            | Self::RetentionSettingsChanged
            | Self::MutationProgress { .. } => None,
        }
    }
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
    /// (e.g. `"ab.exe"`), sorted + deduped. Surfaced so the GUI can show a
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

mod route_policy;
pub use route_policy::*;
mod settings;
pub use settings::*;
mod diagnostics;
pub use diagnostics::*;
mod stability;
pub use stability::*;
mod traffic;
pub use traffic::*;
mod suggestions;
pub use suggestions::*;
// ── Serde defaults shared by more than one payload group ─────────────────
//
// A default named by two groups belongs to neither: a child module cannot
// reach a sibling's private item, and the glob re-export carries public
// items only. Here every group sees them through `use super::*`.

fn default_true() -> bool {
    true
}

/// Wire default for `shared_ip_policy`: `majority-of-ip` (balanced). Kept in
/// sync with `nrr_domain::shared_ip::SharedIpPolicy::default().as_slug()`.
fn shared_ip_policy_default() -> String {
    "majority-of-ip".to_string()
}

// Probing bounds a peer that omits them agrees to. The same three numbers live
// in the stored row (`nrr-storage::route_bindings`) and in the QML defaults
// table, which cannot read Rust; `the_probe_defaults_agree_across_the_wire_and_
// the_stored_row` and `the_qml_defaults_table_mirrors_the_wire_probe_defaults`
// hold those copies to these.
fn default_probe_timeout_ms() -> u32 {
    1500
}
fn default_probe_max_targets() -> u32 {
    8
}
fn default_probe_repeat_secs() -> u32 {
    300
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
