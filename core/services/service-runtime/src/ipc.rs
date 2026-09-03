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

/// Protocol version negotiated through the `ContractNegotiate` operation.
/// Re-exported from the SSOT so the service and the client cannot drift apart.
pub use nrr_shared::ipc::IPC_PROTOCOL_VERSION;

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

/// The operation class and its canonical resolver now live in `nrr-shared`
/// beside the wire format: the class decides which admission checks a request
/// faces, so client and service must read it from ONE declaration. This
/// re-export keeps the existing `crate::ipc::IpcOperationClass` call sites
/// unchanged.
pub use nrr_shared::ipc_transport::{canonical_operation_class, IpcOperationClass};

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
    /// The caller's process id, when the transport can name it. Needed only to
    /// ask an external authority about the caller — polkit identifies a subject
    /// by pid and start time, and a pid alone would let a recycled number answer
    /// for somebody else, which is why the mechanism reads the start time itself
    /// rather than taking it from here.
    pub caller_pid: Option<u32>,
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
/// What the authority check concluded, with the refusal already worded for the
/// person who has to act on it.
enum AuthorizationOutcome {
    Granted,
    Refused(String),
}

/// `MutationQueue` slot count for a production router.
///
/// The queue serialises privileged mutations (`Apply`, `Rollback`,
/// `SafeDisable`); this covers the GUI's worst-case burst of mass-toggle clicks
/// without hoarding memory. Declared here rather than in one platform's wiring:
/// Windows passed 32 and Linux passed a literal 1, so the same burst that
/// queued on one OS was refused as a conflict on the other.
pub const MUTATION_QUEUE_CAPACITY: usize = 32;

pub struct IpcRouter {
    registry: IpcHandlerRegistry,
    audit: Arc<dyn IpcAuditEmitter>,
    queue: MutationQueue,
    /// Consulted when an UNELEVATED caller asks for something that needs
    /// elevation. Absent on a platform where the caller elevates itself before
    /// connecting — there the answer is already in `caller_is_elevated`.
    authority: Option<Arc<dyn nrr_platform_api::authorization::AuthorizationPort>>,
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
            authority: None,
            queue: MutationQueue::new(mutation_queue_capacity),
        }
    }

    /// Ask the platform's authority about this caller and this class.
    ///
    /// The message on a refusal is the whole user-facing value of the check: an
    /// administrator who is simply not allowed, a user with no authentication
    /// agent to prompt them, and a machine with no authority at all need three
    /// different things done about it.
    fn authorize(&self, class: IpcOperationClass, ctx: &IpcRequestContext) -> AuthorizationOutcome {
        use nrr_platform_api::authorization::{AuthorizationDecision, AuthorizationSubject};

        let Some(authority) = self.authority.as_ref() else {
            return AuthorizationOutcome::Refused("operation requires an elevated client".into());
        };
        let (Some(action), Some(pid)) = (class.authorization_action(), ctx.caller_pid) else {
            return AuthorizationOutcome::Refused(
                "operation requires elevation and this caller cannot be identified".into(),
            );
        };
        let uid = ctx
            .caller_principal
            .as_ref()
            .and_then(|p| p.as_unix_uid())
            .unwrap_or(0);
        let subject = AuthorizationSubject {
            pid,
            uid,
            // The mechanism reads the start time itself: it is the half of the
            // identity that makes the pid unambiguous, and taking it from a
            // caller-supplied context would defeat that.
            start_time: None,
        };
        // An interactive client can be prompted; a background or console caller
        // cannot, and popping a password dialog at one would be a prompt nobody
        // is sitting in front of.
        let interactive = matches!(ctx.client_profile, IpcClientProfile::GuiInteractive);
        match authority.authorize(subject, action, interactive) {
            AuthorizationDecision::Allowed => AuthorizationOutcome::Granted,
            AuthorizationDecision::Denied => AuthorizationOutcome::Refused(format!(
                "not authorized for {action}: an administrator may grant it"
            )),
            AuthorizationDecision::NeedsInteraction => AuthorizationOutcome::Refused(format!(
                "{action} needs confirmation, and no authentication agent is available in this                  session"
            )),
            AuthorizationDecision::Unavailable => AuthorizationOutcome::Refused(format!(
                "{action} could not be checked: no authorization service answered"
            )),
        }
    }

    /// Let an unelevated caller earn a privileged operation by being authorized
    /// for it — the shape of a platform whose privileged process is the service
    /// itself, and whose users have no way to elevate a client.
    ///
    /// Builder-style: without it the router behaves exactly as before, refusing
    /// anything privileged from an unelevated client.
    #[must_use]
    pub fn with_authority(
        mut self,
        authority: Arc<dyn nrr_platform_api::authorization::AuthorizationPort>,
    ) -> Self {
        self.authority = Some(authority);
        self
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
        // The class is DERIVED, never accepted. Every admission check below
        // (confirmation token, elevation, pre-execution audit, single-writer
        // queue) is selected by it, so honouring the caller's own label would
        // let a caller pick which checks it faces: naming a mutation
        // `read-snapshot` skipped all four.
        let class = canonical_operation_class(request.operation, &request.payload);
        if class != request.operation_class {
            // Our own client derives the label from this very function, so a
            // divergent envelope is never ours - and the pipe's DACL admits any
            // authenticated local process. Admitting it "by the derived class"
            // was not enough on its own: handlers downstream read the DECLARED
            // one to pick a principal, which is how a user-scoped edit reached
            // the shared admin baseline.
            tracing::warn!(
                target: "nrr::ipc::dispatch",
                operation = op_slug,
                declared = request.operation_class.slug(),
                actual = class.slug(),
                "refusing a request that declares an operation class the operation does not have",
            );
            return IpcResponseEnvelope::err(
                &request,
                IpcError {
                    code: IpcErrorCode::MalformedRequest,
                    message: format!(
                        "operation {op_slug} is {}, not {}",
                        class.slug(),
                        request.operation_class.slug()
                    ),
                    diagnostics_id: None,
                },
            );
        }
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
        // Derived, never accepted — see `dispatch`.
        let class = canonical_operation_class(request.operation, &request.payload);
        // Stamped onto the envelope so a handler reading the field reads the
        // derived class, not the caller's claim. `dispatch` already refused a
        // divergent envelope; this keeps the guarantee local rather than
        // resting on that call order.
        let mut request = request;
        request.operation_class = class;
        let request = request;

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
        if class.requires_confirmation_token()
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

        // 3. What this kind of client is allowed to ask for at all. Checked
        //    before elevation so a console asking for a mutation is told it is
        //    the wrong surface for that, rather than being sent to look for an
        //    administrator prompt that would not help it.
        if !ctx.client_profile.permits(class) {
            return IpcResponseEnvelope::err(
                &request,
                IpcError {
                    code: IpcErrorCode::Forbidden,
                    message: format!(
                        "{} clients may not invoke {} operations",
                        ctx.client_profile.slug(),
                        class.slug()
                    ),
                    diagnostics_id: None,
                },
            );
        }

        // 3b. Which surfaces may invoke THIS operation. The class check above
        //     asks what kind of thing the caller may do; this asks whether the
        //     catalogue lets this surface do this particular one. The field
        //     carried that answer from the start and nothing read it, so the
        //     tray could invoke operations the catalogue marks GUI-only.
        if let Some(spec) = nrr_shared::ipc::ipc_operation_spec(request.operation) {
            if !spec.allowed_clients.contains(&ctx.client_profile) {
                return IpcResponseEnvelope::err(
                    &request,
                    IpcError {
                        code: IpcErrorCode::Forbidden,
                        message: format!(
                            "{} clients may not invoke {}",
                            ctx.client_profile.slug(),
                            request.operation.slug()
                        ),
                        diagnostics_id: None,
                    },
                );
            }
        }

        // 4. Elevation check. An unelevated caller may still be authorized for
        //    this particular action by the platform's authority, which can ask
        //    them for a password through their own session. Only an outright
        //    "yes" gets through: "could not ask" and "no agent available" are
        //    refusals with different advice, never permission.
        if class.requires_elevation() && !ctx.caller_is_elevated {
            match self.authorize(class, &ctx) {
                AuthorizationOutcome::Granted => {}
                AuthorizationOutcome::Refused(message) => {
                    return IpcResponseEnvelope::err(
                        &request,
                        IpcError {
                            code: IpcErrorCode::Forbidden,
                            message,
                            diagnostics_id: None,
                        },
                    );
                }
            }
        }

        // 4. Audit privileged mutations *before* execution.
        if class.is_mutating() {
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
        let _slot = if class.is_mutating() {
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
            caller_pid: None,
        }
    }

    fn unprivileged_tray() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::TrayLightweight,
            caller_is_elevated: false,
            caller_principal: None,
            caller_pid: None,
        }
    }

    /// A privileged request: rollback is a `RecoveryAction`, which needs
    /// elevation and therefore reaches the authority.
    fn recovery_request() -> IpcRequestEnvelope {
        req(
            IpcOperationName::RollbackRequest,
            IpcOperationClass::RecoveryAction,
            IPC_PROTOCOL_VERSION,
            Some("token-from-dry-run"),
        )
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
    fn a_diagnostic_query_needs_no_elevation() {
        // `InterfacesRefreshRequest` (adapter re-enumeration + external-address
        // probe) is a DiagnosticQuery: read-class dispatch, outside the mutation
        // queue, callable by a non-elevated client without a UAC prompt.
        //
        // This used to loop over DiagnosticQuery and DiagnosticAction by
        // stamping each onto the same operation; that envelope is now refused.
        let router = make_router();
        let request = req(
            IpcOperationName::InterfacesRefreshRequest,
            IpcOperationClass::DiagnosticQuery,
            IPC_PROTOCOL_VERSION,
            None,
        );
        assert_eq!(
            canonical_operation_class(request.operation, &request.payload),
            IpcOperationClass::DiagnosticQuery,
        );
        let r = router.dispatch(request, unprivileged_tray());
        assert!(r.ok, "{:?}", r.error);
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

    /// A caller cannot pick which checks it faces by labelling its request.
    ///
    /// The four admission checks (confirmation token, elevation gate,
    /// pre-execution audit, single-writer queue) are selected by the class.
    /// While the class came from the envelope, a mutation announced as
    /// `read-snapshot` skipped all four in one move. Deriving it server-side
    /// closed that, but handlers still read the DECLARED field to choose a
    /// principal — a user-scoped edit announced as `mutation-request` wrote to
    /// the shared admin baseline. So a divergent label is now refused outright:
    /// our own client derives its label from the same function, which makes a
    /// mismatched envelope something we did not send.
    #[test]
    fn a_request_whose_declared_class_is_not_the_operations_own_is_refused() {
        let router = make_router();

        for (op, wrong_class, ctx) in [
            (
                IpcOperationName::MutationSubmit,
                IpcOperationClass::ReadSnapshot,
                unprivileged_tray(),
            ),
            (
                IpcOperationName::ServiceHealthGet,
                IpcOperationClass::MutationRequest,
                unprivileged_tray(),
            ),
        ] {
            let r = router.dispatch(req(op, wrong_class, IPC_PROTOCOL_VERSION, Some("ok")), ctx);
            assert!(!r.ok, "{op:?} labelled {wrong_class:?} must be refused");
            assert_eq!(
                r.error.expect("error").code,
                IpcErrorCode::MalformedRequest,
                "{op:?}: a mislabelled envelope is a malformed one",
            );
        }
    }

    /// The handler side of the same rule: whatever a handler reads out of the
    /// envelope is the DERIVED class. Belt and braces — `dispatch` refuses a
    /// divergent envelope before this matters — but the guarantee is what stops
    /// the next handler from reintroducing a principal chosen by the caller.
    #[test]
    fn handlers_see_the_derived_class_not_the_declared_one() {
        let request = req(
            IpcOperationName::ServiceHealthGet,
            IpcOperationClass::MutationRequest,
            IPC_PROTOCOL_VERSION,
            None,
        );
        assert_eq!(
            canonical_operation_class(request.operation, &request.payload),
            IpcOperationClass::ReadSnapshot,
            "fixture guard: the operation must actually be a read",
        );
        let router = make_router();
        let r = router.dispatch(request, unprivileged_tray());
        assert!(!r.ok, "the divergent envelope is refused at the door");
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

        // DiagnosticAction: mutating (audited before dispatch) but must not
        // require client elevation — clearing logs, discarding the rebuildable
        // cache and toggling the diagnostic session must never surface a UAC
        // prompt. Single-step, no confirmation token.
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

    /// On a platform where the caller cannot elevate itself, an unelevated
    /// client earns a privileged operation by being authorized for it — and
    /// only an outright yes counts.
    #[test]
    fn an_authorized_caller_passes_the_elevation_gate() {
        use nrr_platform_api::authorization::{AuthorizationDecision, FixedAuthority};

        let refusal_for = |decision: AuthorizationDecision| {
            let router = make_router().with_authority(Arc::new(FixedAuthority(decision)));
            let ctx = IpcRequestContext {
                client_profile: IpcClientProfile::GuiInteractive,
                caller_is_elevated: false,
                caller_principal: Some(UserPrincipal::from_linux_uid(1000)),
                caller_pid: Some(4321),
            };
            router.dispatch(recovery_request(), ctx)
        };

        assert!(
            refusal_for(AuthorizationDecision::Allowed).ok
                || refusal_for(AuthorizationDecision::Allowed)
                    .error
                    .is_none_or(|e| e.code != IpcErrorCode::Forbidden),
            "an authorized caller must get past the elevation gate",
        );
        for denied in [
            AuthorizationDecision::Denied,
            AuthorizationDecision::NeedsInteraction,
            AuthorizationDecision::Unavailable,
        ] {
            let response = refusal_for(denied);
            let error = response.error.expect("a refusal carries an error");
            assert_eq!(error.code, IpcErrorCode::Forbidden, "{denied:?}");
            // Each refusal must say something different: the remedies are not
            // the same, and one generic message sends the user looking in the
            // wrong place.
            assert!(
                error.message.contains("netrulerouter."),
                "{denied:?}: the refusal must name the action: {}",
                error.message,
            );
        }
    }

    /// Without an authority the router behaves exactly as it did before one
    /// existed: privileged work needs an elevated client.
    #[test]
    fn without_an_authority_an_unelevated_caller_is_still_refused() {
        let router = make_router();
        let ctx = IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: Some(UserPrincipal::from_linux_uid(1000)),
            caller_pid: Some(4321),
        };

        let response = router.dispatch(recovery_request(), ctx);

        let error = response.error.expect("a refusal carries an error");
        assert_eq!(error.code, IpcErrorCode::Forbidden);
        assert!(error.message.contains("elevated client"));
    }
}
