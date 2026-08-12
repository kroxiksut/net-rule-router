//! IPC server / facade boundary for GUI/tray.
//!
//! This module owns the **protocol layer** of the service IPC:
//!
//! - request / response envelopes (versioning, correlation, payload)
//! - operation classes and per-class authorization
//! - error model
//! - single-writer mutation queue
//! - confirmation token flow for dangerous actions
//! - audit hook for privileged mutations
//!
//! The **transport layer** (Windows Named Pipe + ACL) is a thin shell
//! that sits on top of `dispatch_request`. The Named Pipe wire-up lives
//! in `nrr-windows-service` because it needs `windows-service` /
//! `windows-sys`; this module stays platform-neutral so it can be
//! exercised end-to-end by unit tests on any OS.
//!
//! ## Pipe naming / versioning
//!
//! - Pipe name: `\\.\pipe\NetRuleRouter\service-v1`
//! - Protocol version: `IPC_PROTOCOL_VERSION = 1`
//! - Single instance (the service is a single-instance daemon by
//!   design — block 14.2 enforces the SCM lifetime).
//! - Max message size: 1 MiB (request and response). Enforced at the
//!   transport boundary; envelopes larger than that are rejected with
//!   `MalformedRequest`. Bumped from 64 KiB to fit preset bytes ferried
//!   through `MutationSubmit::PresetImport` and `PresetExportGet` /
//!   `SettingsExportFull` responses.
//! - Connect timeout: 5 seconds. Read/write timeout: 30 seconds.
//!
//! ## ACL baseline
//!
//! On install (block 14.10) the pipe is ACL'd to:
//! - `NT AUTHORITY\LocalSystem` — full (the service runs here)
//! - The service account — full
//! - `BUILTIN\Administrators` — Read+Write (for the GUI/tray launched by
//!   an admin user)
//! - Standard users — none
//!
//! Privileged operation classes (`MutationRequest`,
//! `ReviewConfirmation`, `RecoveryAction`, `SafeDisable`) additionally
//! require the connecting client's token to be elevated; see the
//! `caller_is_elevated` field on `IpcRequestContext`. The transport
//! layer fills it in from `GetTokenInformation(TokenElevation)` —
//! validation lives in this module so the rule is one place.
//!
//! ## No raw storage paths
//!
//! Response payloads are JSON DTOs only. They never carry absolute
//! file paths to service-owned databases or log directories. The GUI
//! receives logical handles (`archive_handle`, `revision_id`, …) and
//! re-opens whatever it needs through dedicated IPC operations.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use nrr_domain::user_principal::UserPrincipal;
use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

// Serde adapter for `IpcOperationName` — the contract type lives in
// `nrr-shared` and intentionally has no `serde` dependency, so we
// serialise it as its slug string here. Round-trips through every known
// operation slug from the IPC operation catalogue.
mod operation_serde {
    use super::*;

    pub fn serialize<S: serde::Serializer>(op: &IpcOperationName, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(op.slug())
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<IpcOperationName, D::Error> {
        use serde::Deserialize;
        let raw = String::deserialize(d)?;
        IpcOperationName::ALL
            .iter()
            .copied()
            .find(|op| op.slug() == raw.as_str())
            .ok_or_else(|| serde::de::Error::custom(format!("unknown ipc operation: {raw}")))
    }
}

// ── Protocol version ─────────────────────────────────────────────────────────

/// Protocol version negotiated through the `ContractNegotiate`
/// operation. Bumped only on incompatible wire-format changes; all
/// changes are tracked in the IPC version-compatibility matrix in
/// `nrr-shared::ipc`.
pub const IPC_PROTOCOL_VERSION: u32 = 1;

/// Maximum size, in bytes, of a serialised request or response envelope.
/// 1 MiB fits the base64-wrapped preset bytes carried by
/// `MutationSubmit::PresetImport` / `PresetExportGet` /
/// `SettingsExportFull`. Larger payloads (diagnostic archives,
/// paginated logs) still use dedicated handle-based operations.
///
/// moved the canonical definition into `nrr-shared::ipc_transport`
/// so client and server crates share a single source of truth. This is a
/// re-export to keep the existing `nrr_service_runtime::IPC_MAX_MESSAGE_BYTES`
/// import path stable.
pub use nrr_shared::ipc_transport::IPC_MAX_MESSAGE_BYTES;

// ── Operation class ──────────────────────────────────────────────────────────

/// Coarse operation class derived per task 14.5 углублённой
/// декомпозиции. Drives:
/// - whether the request bypasses the mutation queue (`ReadSnapshot`,
///   `DiagnosticQuery` are read-only);
/// - whether elevation is required;
/// - whether a confirmation token must be carried (`MutationRequest`,
///   `RecoveryAction`, `SafeDisable`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpcOperationClass {
    ReadSnapshot,
    DiagnosticQuery,
    DiagnosticAction,
    MutationRequest,
    ReviewConfirmation,
    RecoveryAction,
    SafeDisable,
    /// per-SID user configuration write. Mutating (flows
    /// through the mutation queue, audited before execution) but does
    /// **not** require client elevation — the data is the user's own
    /// per-SID configuration, not service-global policy. Single-step
    /// (no two-phase confirmation token).
    UserScopedConfiguration,
    /// per-principal rules/preset mutation. Like
    /// [`Self::MutationRequest`] it is two-phase (a confirmation token
    /// from a prior dry-run is mandatory), flows through the mutation
    /// queue, and is audited before execution — but it does **not**
    /// require client elevation. The target principal is the caller's
    /// own SID (`IpcRequestContext.caller_stored()`), never service-global
    /// baseline, so a non-admin GUI session can commit *its own* rules.
    /// Editing the admin baseline still goes through
    /// [`Self::MutationRequest`] (elevation required).
    UserScopedMutation,
}

impl IpcOperationClass {
    /// Whether this class flows through the single-writer mutation
    /// queue. `false` for read-only and lightweight diagnostic queries.
    pub const fn is_mutating(self) -> bool {
        match self {
            Self::ReadSnapshot | Self::DiagnosticQuery => false,
            Self::DiagnosticAction
            | Self::MutationRequest
            | Self::ReviewConfirmation
            | Self::RecoveryAction
            | Self::SafeDisable
            | Self::UserScopedConfiguration
            | Self::UserScopedMutation => true,
        }
    }

    /// Whether the caller's process token must be elevated. Read-only
    /// operations, diagnostic actions that persist nothing (e.g. an
    /// on-demand adapter re-enumeration), and per-SID user configuration
    /// writes are safe for non-admin GUI sessions; everything else
    /// requires an elevated client.
    pub const fn requires_elevation(self) -> bool {
        !matches!(
            self,
            Self::ReadSnapshot
                | Self::DiagnosticQuery
                | Self::DiagnosticAction
                | Self::UserScopedConfiguration
                | Self::UserScopedMutation
        )
    }

    /// Whether the request envelope must carry a `confirmation_token`
    /// (issued by an earlier dry-run response). Dangerous classes
    /// require explicit two-step acknowledgement to prevent accidental
    /// network policy mutation from a stuck GUI.
    pub const fn requires_confirmation_token(self) -> bool {
        matches!(
            self,
            Self::MutationRequest
                | Self::RecoveryAction
                | Self::SafeDisable
                | Self::UserScopedMutation
        )
    }
}

// ── Error model ──────────────────────────────────────────────────────────────

/// Canonical error codes exposed in the response envelope. Block
/// moved the SSOT to `nrr-shared::ipc_transport` so
/// `nrr-ipc-client` can preserve the typed code on the inbound
/// path without breaking the "no dependency on `nrr-service-runtime`"
/// boundary. This re-export keeps the ~200 existing call sites
/// (`crate::ipc::IpcErrorCode`, `IpcErrorCode::Forbidden`, etc.)
/// untouched.
pub use nrr_shared::ipc_transport::IpcErrorCode;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpcError {
    pub code: IpcErrorCode,
    /// English human-readable message for operators; UI also shows
    /// `code` plus a localized string keyed off it.
    pub message: String,
    /// Diagnostic id correlating with the audit/log trail (when
    /// available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics_id: Option<String>,
}

// ── Envelopes ────────────────────────────────────────────────────────────────

/// Caller-side context the transport injects into every request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpcRequestContext {
    pub client_profile: IpcClientProfile,
    /// Whether the connected client's process token reports
    /// `TokenElevation = TRUE` (Windows). On non-Windows transports
    /// this is whatever the test harness sets.
    pub caller_is_elevated: bool,
    /// The caller's OS identity as the neutral cross-OS [`UserPrincipal`].
    /// `None` when the transport could not attribute the request — a
    /// non-Windows transport, or a test harness that omits the
    /// identity; per-principal handlers (e.g. `RoutePolicyUpdate`) reject such
    /// requests. On Windows the transport wraps the captured SID via
    /// `UserPrincipal::from_windows_sid` in `named_pipe_identity`; a future
    /// Linux transport uses `UserPrincipal::from_linux_uid`. Storage stays
    /// string-keyed via [`UserPrincipal::as_stored`] (see [`Self::caller_stored`]).
    pub caller_principal: Option<UserPrincipal>,
}

impl IpcRequestContext {
    /// Stored-string form of the caller identity (a Windows SID, a
    /// `unix:uid:<n>`, …), or `""` when unauthenticated. Preserves the
    /// `caller_sid` semantics for the `&str`-keyed storage / coordinator
    /// APIs downstream, which stay partitioned by the opaque principal
    /// string.
    pub fn caller_stored(&self) -> &str {
        self.caller_principal
            .as_ref()
            .map_or("", UserPrincipal::as_stored)
    }
}

/// Wire-format request envelope. Field names use kebab-case in JSON to
/// stay consistent with the rest of `nrr-shared`'s serialization style.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct IpcRequestEnvelope {
    pub protocol_version: u32,
    pub request_id: String,
    /// Caller-supplied correlation id linking related requests (e.g.
    /// dry-run + confirm pair). Optional; when absent the service
    /// generates one and echoes it on the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(with = "operation_serde")]
    pub operation: IpcOperationName,
    pub operation_class: IpcOperationClass,
    /// Confirmation token returned by an earlier dry-run; required for
    /// classes where `IpcOperationClass::requires_confirmation_token()`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_token: Option<String>,
    /// Operation-specific payload. Untyped at this layer; handlers
    /// deserialise it themselves.
    pub payload: serde_json::Value,
}

/// Wire-format response envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct IpcResponseEnvelope {
    pub request_id: String,
    /// Echoes the request `correlation_id` (or a server-generated one
    /// when the caller didn't supply one).
    pub correlation_id: String,
    /// `Some(handle)` when the operation runs asynchronously; the
    /// client polls `OperationStatusGet` with this id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    /// `true` for success; `false` when `error` is set.
    pub ok: bool,
    /// Indicates a successful read served from a cached snapshot that
    /// is older than the freshness budget. UI displays a "stale"
    /// banner and may issue a refresh.
    pub stale: bool,
    /// Diagnostic id correlating with the audit/log trail. Always
    /// present on `ok = false`; optional on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics_id: Option<String>,
    /// Marker for clients to surface "user action required" UI even
    /// on successful responses (e.g. recovery-required confirmation).
    pub user_action_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
}

impl IpcResponseEnvelope {
    pub fn ok_payload(request: &IpcRequestEnvelope, payload: serde_json::Value) -> Self {
        Self {
            request_id: request.request_id.clone(),
            correlation_id: request
                .correlation_id
                .clone()
                .unwrap_or_else(|| request.request_id.clone()),
            operation_id: None,
            ok: true,
            stale: false,
            diagnostics_id: None,
            user_action_required: false,
            payload: Some(payload),
            error: None,
        }
    }

    pub fn err(request: &IpcRequestEnvelope, error: IpcError) -> Self {
        Self {
            request_id: request.request_id.clone(),
            correlation_id: request
                .correlation_id
                .clone()
                .unwrap_or_else(|| request.request_id.clone()),
            operation_id: None,
            ok: false,
            stale: false,
            diagnostics_id: error.diagnostics_id.clone(),
            user_action_required: matches!(error.code, IpcErrorCode::RecoveryRequired),
            payload: None,
            error: Some(error),
        }
    }
}

// ── Audit hook ───────────────────────────────────────────────────────────────

/// Trait the IPC layer calls before executing a privileged mutation
/// request. The audit emitter must persist the event durably; failure
/// should propagate as `IpcErrorCode::Internal` so the mutation does
/// not run silently. Real `AuditWriter` wiring lives in 14.6/14.11.
///
/// `Send + Sync` is required because the named-pipe IPC server (block
/// ) shares the audit emitter across worker threads via `Arc`.
pub trait IpcAuditEmitter: Send + Sync {
    fn record_request(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<(), String>;
}

#[derive(Default)]
pub struct NoopAuditEmitter;

impl IpcAuditEmitter for NoopAuditEmitter {
    fn record_request(
        &self,
        _request: &IpcRequestEnvelope,
        _ctx: &IpcRequestContext,
    ) -> Result<(), String> {
        Ok(())
    }
}

// ── Handler registry ─────────────────────────────────────────────────────────

/// What a request handler returns. Handlers don't build the full
/// `IpcResponseEnvelope` themselves — the router does that — they just
/// return the payload (or error).
pub type HandlerOutcome = Result<serde_json::Value, IpcError>;

/// Per-operation handler. The router looks one up by `IpcOperationName`
/// after envelope validation.
///
/// `Send + Sync` is required because the named-pipe IPC server (block
/// ) dispatches requests from multiple worker threads concurrently.
pub trait IpcHandler: Send + Sync {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome;
}

/// Registry of `IpcOperationName -> handler`. Cheap O(N) lookup over a
/// `Vec` because the catalogue is tiny (<20 operations).
#[derive(Default)]
pub struct IpcHandlerRegistry {
    entries: Vec<(IpcOperationName, Box<dyn IpcHandler>)>,
}

impl IpcHandlerRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn register<H: IpcHandler + 'static>(&mut self, op: IpcOperationName, handler: H) {
        self.entries.push((op, Box::new(handler)));
    }

    fn find(&self, op: IpcOperationName) -> Option<&dyn IpcHandler> {
        self.entries
            .iter()
            .find(|(name, _)| *name == op)
            .map(|(_, h)| h.as_ref())
    }
}

// ── Mutation queue ───────────────────────────────────────────────────────────

/// Single-writer guard for mutating operations. Ensures that two
/// mutations cannot run concurrently and that `BusyConflict` surfaces
/// when one is already in flight.
#[derive(Default)]
pub struct MutationQueue {
    /// Live request ids currently being processed.
    in_flight: Mutex<VecDeque<String>>,
    /// Soft cap on queue depth (post-14.7 the queue will be wired with
    /// per-class fairness; today this just protects against runaway
    /// retries from a stuck GUI).
    capacity: usize,
}

impl MutationQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            in_flight: Mutex::new(VecDeque::new()),
            capacity,
        }
    }

    /// Try to claim a slot for `request_id`. Returns `Err(BusyConflict)`
    /// when the queue is full. The returned guard releases the slot on
    /// drop.
    pub fn try_enter(&self, request_id: &str) -> Result<MutationGuard<'_>, IpcError> {
        let mut guard = self.in_flight.lock().map_err(|_| IpcError {
            code: IpcErrorCode::Internal,
            message: "mutation queue lock poisoned".into(),
            diagnostics_id: None,
        })?;
        if guard.len() >= self.capacity {
            return Err(IpcError {
                code: IpcErrorCode::BusyConflict,
                message: "another mutation is already in flight".into(),
                diagnostics_id: None,
            });
        }
        guard.push_back(request_id.to_string());
        Ok(MutationGuard {
            queue: self,
            request_id: request_id.to_string(),
        })
    }
}

#[must_use = "drop releases the mutation queue slot"]
pub struct MutationGuard<'a> {
    queue: &'a MutationQueue,
    request_id: String,
}

impl Drop for MutationGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.queue.in_flight.lock() {
            if let Some(pos) = guard.iter().position(|r| r == &self.request_id) {
                guard.remove(pos);
            }
        }
    }
}

// ── Router ───────────────────────────────────────────────────────────────────

/// The thing the transport calls per-request. Validates envelope,
/// enforces authorization, claims a mutation slot when needed, runs
/// the audit hook, dispatches to the registered handler.
pub struct IpcRouter {
    registry: IpcHandlerRegistry,
    audit: Arc<dyn IpcAuditEmitter>,
    queue: MutationQueue,
}

impl IpcRouter {
    pub fn new(
        registry: IpcHandlerRegistry,
        audit: Arc<dyn IpcAuditEmitter>,
        mutation_queue_capacity: usize,
    ) -> Self {
        Self {
            registry,
            audit,
            queue: MutationQueue::new(mutation_queue_capacity),
        }
    }

    /// Synchronous request dispatch. Always returns a response — never
    /// panics. Audit failures during privileged mutations surface as
    /// `IpcErrorCode::Internal`.
    pub fn dispatch(
        &self,
        request: IpcRequestEnvelope,
        ctx: IpcRequestContext,
    ) -> IpcResponseEnvelope {
        let dispatch_started = std::time::Instant::now();
        let op_slug = request.operation.slug();
        let class = request.operation_class;
        // Demoted from info → debug. Every IPC request was emitting
        // two operational-log lines; with the GUI's 5 s health-check
        // tick that meant 24 lines/min of noise even when nothing
        // was happening. Failures still produce a warn-level record
        // in the `else` branch below — those remain visible at
        // default verbosity. Bump `NRR_LOG=nrr=debug` to recover
        // the per-request trace when diagnosing.
        tracing::debug!(
            target: "nrr::ipc::dispatch",
            request_id = %request.request_id,
            op = op_slug,
            class = ?class,
            client_profile = ?ctx.client_profile,
            elevated = ctx.caller_is_elevated,
            has_token = request.confirmation_token.as_deref().map(|s| !s.is_empty()).unwrap_or(false),
            "ipc request received",
        );
        let response = self.dispatch_inner(request, ctx);
        let dur_us = dispatch_started.elapsed().as_micros() as u64;
        if response.ok {
            tracing::debug!(
                target: "nrr::ipc::dispatch",
                request_id = %response.request_id,
                op = op_slug,
                class = ?class,
                duration_us = dur_us,
                "ipc request ok",
            );
        } else {
            let (code, msg) = response
                .error
                .as_ref()
                .map(|e| (format!("{:?}", e.code), e.message.clone()))
                .unwrap_or_else(|| ("Unknown".into(), String::new()));
            tracing::warn!(
                target: "nrr::ipc::dispatch",
                request_id = %response.request_id,
                op = op_slug,
                class = ?class,
                duration_us = dur_us,
                error_code = %code,
                error_message = %msg,
                "ipc request failed",
            );
        }
        response
    }

    fn dispatch_inner(
        &self,
        request: IpcRequestEnvelope,
        ctx: IpcRequestContext,
    ) -> IpcResponseEnvelope {
        // 1. Protocol version.
        if request.protocol_version != IPC_PROTOCOL_VERSION {
            return IpcResponseEnvelope::err(
                &request,
                IpcError {
                    code: IpcErrorCode::InvalidVersion,
                    message: format!(
                        "client speaks v{}, service speaks v{}",
                        request.protocol_version, IPC_PROTOCOL_VERSION
                    ),
                    diagnostics_id: None,
                },
            );
        }

        // 2. Confirmation token presence (for classes that require it).
        if request.operation_class.requires_confirmation_token()
            && request
                .confirmation_token
                .as_ref()
                .is_none_or(|t| t.is_empty())
        {
            return IpcResponseEnvelope::err(
                &request,
                IpcError {
                    code: IpcErrorCode::PreconditionFailed,
                    message: "operation requires a confirmation token from a prior dry-run".into(),
                    diagnostics_id: None,
                },
            );
        }

        // 3. Elevation check.
        if request.operation_class.requires_elevation() && !ctx.caller_is_elevated {
            return IpcResponseEnvelope::err(
                &request,
                IpcError {
                    code: IpcErrorCode::Forbidden,
                    message: "operation requires an elevated client".into(),
                    diagnostics_id: None,
                },
            );
        }

        // 4. Audit privileged mutations *before* execution.
        if request.operation_class.is_mutating() {
            if let Err(e) = self.audit.record_request(&request, &ctx) {
                return IpcResponseEnvelope::err(
                    &request,
                    IpcError {
                        code: IpcErrorCode::Internal,
                        message: format!("audit write failed: {e}"),
                        diagnostics_id: None,
                    },
                );
            }
        }

        // 5. Mutation queue (only for mutating ops).
        let _slot = if request.operation_class.is_mutating() {
            match self.queue.try_enter(&request.request_id) {
                Ok(guard) => Some(guard),
                Err(e) => return IpcResponseEnvelope::err(&request, e),
            }
        } else {
            None
        };

        // 6. Handler dispatch.
        let handler = match self.registry.find(request.operation) {
            Some(h) => h,
            None => {
                return IpcResponseEnvelope::err(
                    &request,
                    IpcError {
                        code: IpcErrorCode::MalformedRequest,
                        message: format!("operation {} has no handler", request.operation.slug()),
                        diagnostics_id: None,
                    },
                );
            }
        };

        match handler.handle(&request, &ctx) {
            Ok(payload) => IpcResponseEnvelope::ok_payload(&request, payload),
            Err(error) => IpcResponseEnvelope::err(&request, error),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn req(
        op: IpcOperationName,
        class: IpcOperationClass,
        version: u32,
        token: Option<&str>,
    ) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: version,
            request_id: format!("req-{:?}", op),
            correlation_id: None,
            operation: op,
            operation_class: class,
            confirmation_token: token.map(|s| s.to_string()),
            payload: serde_json::json!({}),
        }
    }

    fn elevated_gui() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: None,
        }
    }

    fn unprivileged_tray() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::TrayLightweight,
            caller_is_elevated: false,
            caller_principal: None,
        }
    }

    struct EchoHandler;
    impl IpcHandler for EchoHandler {
        fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
            Ok(serde_json::json!({ "echo": request.operation.slug() }))
        }
    }

    fn make_router() -> IpcRouter {
        let mut reg = IpcHandlerRegistry::new();
        reg.register(IpcOperationName::ServiceHealthGet, EchoHandler);
        reg.register(IpcOperationName::MutationSubmit, EchoHandler);
        reg.register(IpcOperationName::RollbackRequest, EchoHandler);
        reg.register(IpcOperationName::InterfacesRefreshRequest, EchoHandler);
        IpcRouter::new(reg, Arc::new(NoopAuditEmitter), 1)
    }

    #[test]
    fn invalid_protocol_version_is_rejected() {
        let router = make_router();
        let r = router.dispatch(
            req(
                IpcOperationName::ServiceHealthGet,
                IpcOperationClass::ReadSnapshot,
                999,
                None,
            ),
            elevated_gui(),
        );
        assert!(!r.ok);
        assert_eq!(r.error.unwrap().code, IpcErrorCode::InvalidVersion);
    }

    #[test]
    fn read_snapshot_does_not_require_elevation() {
        let router = make_router();
        let r = router.dispatch(
            req(
                IpcOperationName::ServiceHealthGet,
                IpcOperationClass::ReadSnapshot,
                IPC_PROTOCOL_VERSION,
                None,
            ),
            unprivileged_tray(),
        );
        assert!(r.ok, "{:?}", r.error);
    }

    #[test]
    fn diagnostic_classes_do_not_require_elevation() {
        // Regression pins: InterfacesRefreshRequest (adapter re-enumeration
        // and external-address probe) is a DiagnosticQuery since HW-0730 —
        // read-class dispatch, outside the mutation queue, callable by a
        // non-elevated client without a UAC prompt. DiagnosticAction keeps
        // the same non-elevating property for the ops that still use it.
        let router = make_router();
        for class in [
            IpcOperationClass::DiagnosticQuery,
            IpcOperationClass::DiagnosticAction,
        ] {
            let r = router.dispatch(
                req(
                    IpcOperationName::InterfacesRefreshRequest,
                    class,
                    IPC_PROTOCOL_VERSION,
                    None,
                ),
                unprivileged_tray(),
            );
            assert!(r.ok, "{class:?}: {:?}", r.error);
        }
    }

    #[test]
    fn mutation_from_unprivileged_client_is_forbidden() {
        let router = make_router();
        let r = router.dispatch(
            req(
                IpcOperationName::MutationSubmit,
                IpcOperationClass::MutationRequest,
                IPC_PROTOCOL_VERSION,
                Some("ok"),
            ),
            unprivileged_tray(),
        );
        assert!(!r.ok);
        assert_eq!(r.error.unwrap().code, IpcErrorCode::Forbidden);
    }

    #[test]
    fn mutation_without_confirmation_token_is_rejected() {
        let router = make_router();
        let r = router.dispatch(
            req(
                IpcOperationName::MutationSubmit,
                IpcOperationClass::MutationRequest,
                IPC_PROTOCOL_VERSION,
                None,
            ),
            elevated_gui(),
        );
        assert!(!r.ok);
        assert_eq!(r.error.unwrap().code, IpcErrorCode::PreconditionFailed);
    }

    #[test]
    fn unknown_operation_returns_malformed_request() {
        let router = make_router();
        let r = router.dispatch(
            req(
                IpcOperationName::SnapshotInitialGet,
                IpcOperationClass::ReadSnapshot,
                IPC_PROTOCOL_VERSION,
                None,
            ),
            elevated_gui(),
        );
        assert!(!r.ok);
        assert_eq!(r.error.unwrap().code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn mutation_queue_serializes_concurrent_requests() {
        // Two mutations submitted in series; the second must succeed
        // because the first's guard is dropped between dispatches.
        // Concurrent in-flight is tested by manually claiming a slot.
        let router = make_router();
        let _slot = router.queue.try_enter("manual").unwrap();
        let r = router.dispatch(
            req(
                IpcOperationName::MutationSubmit,
                IpcOperationClass::MutationRequest,
                IPC_PROTOCOL_VERSION,
                Some("ok"),
            ),
            elevated_gui(),
        );
        assert!(!r.ok);
        assert_eq!(r.error.unwrap().code, IpcErrorCode::BusyConflict);
        drop(_slot);
        let r2 = router.dispatch(
            req(
                IpcOperationName::MutationSubmit,
                IpcOperationClass::MutationRequest,
                IPC_PROTOCOL_VERSION,
                Some("ok"),
            ),
            elevated_gui(),
        );
        assert!(r2.ok, "{:?}", r2.error);
    }

    #[test]
    fn audit_failure_during_mutation_blocks_handler() {
        struct FailingAudit {
            count: AtomicUsize,
        }
        impl IpcAuditEmitter for FailingAudit {
            fn record_request(
                &self,
                _r: &IpcRequestEnvelope,
                _c: &IpcRequestContext,
            ) -> Result<(), String> {
                self.count.fetch_add(1, Ordering::SeqCst);
                Err("simulated audit failure".into())
            }
        }
        let mut reg = IpcHandlerRegistry::new();
        reg.register(IpcOperationName::MutationSubmit, EchoHandler);
        let audit = Arc::new(FailingAudit {
            count: AtomicUsize::new(0),
        });
        let router = IpcRouter::new(reg, audit.clone(), 1);
        let r = router.dispatch(
            req(
                IpcOperationName::MutationSubmit,
                IpcOperationClass::MutationRequest,
                IPC_PROTOCOL_VERSION,
                Some("ok"),
            ),
            elevated_gui(),
        );
        assert!(!r.ok);
        assert_eq!(r.error.unwrap().code, IpcErrorCode::Internal);
        assert_eq!(audit.count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn read_snapshot_bypasses_mutation_queue() {
        let router = make_router();
        // Pre-fill the queue.
        let _slot = router.queue.try_enter("manual").unwrap();
        let r = router.dispatch(
            req(
                IpcOperationName::ServiceHealthGet,
                IpcOperationClass::ReadSnapshot,
                IPC_PROTOCOL_VERSION,
                None,
            ),
            elevated_gui(),
        );
        assert!(r.ok, "{:?}", r.error);
    }

    #[test]
    fn operation_class_invariants() {
        // Sanity: read-only is non-mutating, all others are mutating.
        for class in [
            IpcOperationClass::ReadSnapshot,
            IpcOperationClass::DiagnosticQuery,
        ] {
            assert!(!class.is_mutating());
            assert!(!class.requires_elevation());
            assert!(!class.requires_confirmation_token());
        }
        for class in [
            IpcOperationClass::MutationRequest,
            IpcOperationClass::RecoveryAction,
            IpcOperationClass::SafeDisable,
        ] {
            assert!(class.is_mutating());
            assert!(class.requires_elevation());
            assert!(class.requires_confirmation_token());
        }
        // ReviewConfirmation: mutating, requires elevation, but the
        // confirmation token in this case IS the request itself, not a
        // gate on it. Documented invariant.
        assert!(IpcOperationClass::ReviewConfirmation.is_mutating());
        assert!(IpcOperationClass::ReviewConfirmation.requires_elevation());
        assert!(!IpcOperationClass::ReviewConfirmation.requires_confirmation_token());

        // UserScopedConfiguration: mutating + non-elevated,
        // single-step (no confirmation token).
        assert!(IpcOperationClass::UserScopedConfiguration.is_mutating());
        assert!(!IpcOperationClass::UserScopedConfiguration.requires_elevation());
        assert!(!IpcOperationClass::UserScopedConfiguration.requires_confirmation_token());

        // UserScopedMutation: mutating + non-elevated like
        // UserScopedConfiguration, BUT two-phase — a confirmation token
        // from a prior dry-run is mandatory (per-principal rules/preset).
        assert!(IpcOperationClass::UserScopedMutation.is_mutating());
        assert!(!IpcOperationClass::UserScopedMutation.requires_elevation());
        assert!(IpcOperationClass::UserScopedMutation.requires_confirmation_token());

        // DiagnosticAction: mutating (audited before dispatch) but must
        // not require client elevation — it is the class used by the
        // external-address probe / adapter refresh, which must never
        // surface a UAC prompt. Single-step, no confirmation token.
        assert!(IpcOperationClass::DiagnosticAction.is_mutating());
        assert!(!IpcOperationClass::DiagnosticAction.requires_elevation());
        assert!(!IpcOperationClass::DiagnosticAction.requires_confirmation_token());
    }

    #[test]
    fn response_envelope_round_trips_through_json() {
        let request = req(
            IpcOperationName::ServiceHealthGet,
            IpcOperationClass::ReadSnapshot,
            IPC_PROTOCOL_VERSION,
            None,
        );
        let response = IpcResponseEnvelope::ok_payload(&request, serde_json::json!({ "ok": true }));
        let json = serde_json::to_string(&response).unwrap();
        let back: IpcResponseEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, response);
        // Stable field naming — verify the wire shape so a future
        // accidental rename trips this test.
        assert!(json.contains("\"correlation-id\""));
        assert!(json.contains("\"user-action-required\""));
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn enforces_max_message_size_constant_is_reasonable() {
        // Guardrail: set to 1 MiB so preset bytes fit. Lower bound pins
        // the constant against accidental shrinking;
        // upper bound ensures we don't allow runaway-payload DoS.
        assert!(IPC_MAX_MESSAGE_BYTES >= 1024 * 1024);
        assert!(IPC_MAX_MESSAGE_BYTES <= 4 * 1024 * 1024);
    }
}
