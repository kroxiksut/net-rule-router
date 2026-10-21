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
//!   design; the SCM enforces its lifetime).
//! - Max message size: 1 MiB (request and response). Enforced at the
//!   transport boundary; envelopes larger than that are rejected with
//!   `MalformedRequest`. Bumped from 64 KiB to fit preset bytes ferried
//!   through `MutationSubmit::PresetImport` and `PresetExportGet` /
//!   `SettingsExportFull` responses.
//! - Connect timeout: 5 seconds. Read/write timeout: 30 seconds.
//!
//! ## Who may connect, and who decides
//!
//! The pipe ACL admits SYSTEM, Administrators and Authenticated Users (read
//! and write, but not the right to add pipe instances), so an ordinary user
//! connects. The connection itself is therefore not a privilege boundary:
//!
//! - The caller's exe basename maps to an `IpcClientProfile`. That is a
//!   coarse, advisory filter (a process can carry any name); it narrows what
//!   an honest client can ask for, it does not authenticate anyone.
//! - The operation class decides elevation: classes with
//!   `requires_elevation()` need an elevated token (`caller_is_elevated`),
//!   or an authorization from the platform authority. Per-user classes do
//!   not. Machine-wide values written through a per-user class are compared
//!   by value in the handler, and only a real change demands rights.
//! - Log and audit reads are scoped by `DiagnosticsAudience`, derived from
//!   the connection, never from the request.
//!
//! ## Paths
//!
//! Most responses are JSON DTOs with logical handles. The diagnostics archive
//! export is the exception: it returns the absolute `archive_path` of the file
//! the service wrote.

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
/// The canonical definition lives in `nrr-shared::ipc_transport` so client and
/// server crates share a single source of truth. This re-export keeps the
/// existing `nrr_service_runtime::IPC_MAX_MESSAGE_BYTES` import path stable.
pub use nrr_shared::ipc_transport::IPC_MAX_MESSAGE_BYTES;

// ── Operation class ──────────────────────────────────────────────────────────

/// The operation class and its canonical resolver now live in `nrr-shared`
/// beside the wire format: the class decides which admission checks a request
/// faces, so client and service must read it from ONE declaration. This
/// re-export keeps the existing `crate::ipc::IpcOperationClass` call sites
/// unchanged.
pub use nrr_shared::ipc_transport::{canonical_operation_class, IpcOperationClass};

// ── Error model ──────────────────────────────────────────────────────────────

pub use nrr_shared::diagnostics_dto::DiagnosticsAudience;
/// Canonical error codes exposed in the response envelope. The SSOT lives in
/// `nrr-shared::ipc_transport` so `nrr-ipc-client` can preserve the typed code
/// on the inbound path without breaking the "no dependency on
/// `nrr-service-runtime`" boundary. This re-export keeps the ~200 existing
/// call sites (`crate::ipc::IpcErrorCode`, `IpcErrorCode::Forbidden`, etc.)
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

impl IpcError {
    /// A handler's refusal of something only an administrator may do. Typed by
    /// its leading slug, so the router can ask the platform authority and run
    /// the request again with rights, and a Windows client's broker sees an
    /// ordinary `Forbidden`.
    pub fn needs_administrator(detail: impl std::fmt::Display) -> Self {
        Self {
            code: IpcErrorCode::Forbidden,
            message: format!(
                "{}: {detail}",
                nrr_shared::ipc_transport::NEEDS_ADMINISTRATOR_SLUG
            ),
            diagnostics_id: None,
        }
    }
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
    /// The caller's process, when the transport can name it. Needed only to
    /// ask an external authority about the caller.
    pub caller_pid: Option<CallerProcess>,
}

/// The connecting process as the transport saw it at accept. polkit names a
/// subject by pid AND start time: a pid alone could be recycled and answer for
/// somebody else, and a start time read later, at the check, would only narrow
/// that window. Read while the peer holds its end open, it closes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallerProcess {
    pub pid: u32,
    /// `None` when it could not be read; the authority is then never asked.
    pub start_time: Option<u64>,
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

    /// Whose diagnostics records this caller may read.
    ///
    /// The audit trail and the operational log are machine-wide files the
    /// filesystem keeps away from ordinary users; an elevated caller has that
    /// access already, everyone else gets their own records plus the ones that
    /// belong to the machine rather than to a person. Derived from the
    /// connection, so a request cannot ask to be somebody else's audience.
    pub fn diagnostics_audience(&self) -> DiagnosticsAudience {
        if self.caller_is_elevated {
            DiagnosticsAudience::Machine
        } else {
            DiagnosticsAudience::Principal(self.caller_stored().to_owned())
        }
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
/// request, once its handler's precheck has accepted it. The audit emitter
/// must persist the event durably; failure should propagate as
/// `IpcErrorCode::Internal` so the mutation does not run silently.
///
/// `Send + Sync` is required because the named-pipe IPC server shares the
/// audit emitter across worker threads via `Arc`.
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

/// Per-operation handler for an operation that never changes state. The router
/// looks one up by `IpcOperationName` after envelope validation.
///
/// A mutating operation implements [`CheckedIpcHandler`] instead; registered
/// through [`IpcHandlerRegistry::register`], a mutating request to it is
/// refused before anything is audited or run.
///
/// `Send + Sync` is required because the named-pipe IPC server dispatches
/// requests from multiple worker threads concurrently.
pub trait IpcHandler: Send + Sync {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome;
}

/// A handler whose request is validated before it is audited.
///
/// The audit trail records requests the service admitted. A payload that does
/// not decode, or that its handler would refuse anyway, must not leave a record
/// of a mutation that never happened: refusals cost the caller nothing, and a
/// loop of them would push the genuine history out of a size-capped trail. So
/// the router runs [`Self::precheck`] first, audits only what it accepted, and
/// hands [`Self::execute`] nothing but the checked value.
pub trait CheckedIpcHandler: Send + Sync {
    /// The decoded, validated request.
    type Checked: 'static;

    /// Decode and validate. Bounded, and changes nothing the request is about:
    /// it may read the state a check compares against, and may spend a one-shot
    /// confirmation token, which a refused confirm burns anyway. A refusal here
    /// goes back to the caller with no audit record.
    fn precheck(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<Self::Checked, IpcError>;

    /// Act on a request that passed [`Self::precheck`] and has been audited.
    fn execute(
        &self,
        checked: Prechecked<Self::Checked>,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> HandlerOutcome;
}

/// A request value its handler's precheck produced. Only this module builds
/// one, so `execute` is unreachable with a payload nobody checked.
pub struct Prechecked<T>(T);

impl<T> Prechecked<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> std::ops::Deref for Prechecked<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

/// Direct calls (composition, unit tests) run precheck then execute with no
/// audit, exactly what calling the handler did before the split. The router
/// never takes this path for a checked handler.
impl<H: CheckedIpcHandler> IpcHandler for H {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let checked = Prechecked(self.precheck(request, ctx)?);
        self.execute(checked, request, ctx)
    }
}

/// The work a handler has left once its request was accepted.
type PreparedRun<'a> = Box<dyn FnOnce() -> HandlerOutcome + 'a>;

/// Object-safe face of [`CheckedIpcHandler`] for the registry.
trait ErasedCheckedHandler: Send + Sync {
    fn prepare<'a>(
        &'a self,
        request: &'a IpcRequestEnvelope,
        ctx: &'a IpcRequestContext,
    ) -> Result<PreparedRun<'a>, IpcError>;
}

impl<H: CheckedIpcHandler> ErasedCheckedHandler for H {
    fn prepare<'a>(
        &'a self,
        request: &'a IpcRequestEnvelope,
        ctx: &'a IpcRequestContext,
    ) -> Result<PreparedRun<'a>, IpcError> {
        let checked = Prechecked(self.precheck(request, ctx)?);
        Ok(Box::new(move || self.execute(checked, request, ctx)))
    }
}

/// How a registered handler meets the "validated before audited" rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrecheckCoverage {
    /// Registered with [`IpcHandlerRegistry::register`]: right for an
    /// operation that never mutates; a mutating request to it is refused.
    ReadOnly,
    /// Registered with [`IpcHandlerRegistry::register_checked`].
    Prechecked,
    /// Registered with [`IpcHandlerRegistry::register_transitional`]: audited,
    /// then validated by the handler, as every mutation once was.
    Transitional,
}

enum RegisteredHandler {
    ReadOnly(Box<dyn IpcHandler>),
    Checked(Box<dyn ErasedCheckedHandler>),
    Transitional(Box<dyn IpcHandler>),
}

impl RegisteredHandler {
    fn coverage(&self) -> PrecheckCoverage {
        match self {
            Self::ReadOnly(_) => PrecheckCoverage::ReadOnly,
            Self::Checked(_) => PrecheckCoverage::Prechecked,
            Self::Transitional(_) => PrecheckCoverage::Transitional,
        }
    }
}

/// Registry of `IpcOperationName -> handler`. Cheap O(N) lookup over a
/// `Vec` because the catalogue is small.
#[derive(Default)]
pub struct IpcHandlerRegistry {
    entries: Vec<(IpcOperationName, RegisteredHandler)>,
}

impl IpcHandlerRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// A handler for an operation that never mutates.
    pub fn register<H: IpcHandler + 'static>(&mut self, op: IpcOperationName, handler: H) {
        self.entries
            .push((op, RegisteredHandler::ReadOnly(Box::new(handler))));
    }

    /// A handler whose requests are validated before they are audited.
    pub fn register_checked<H: CheckedIpcHandler + 'static>(
        &mut self,
        op: IpcOperationName,
        handler: H,
    ) {
        self.entries
            .push((op, RegisteredHandler::Checked(Box::new(handler))));
    }

    /// A mutating handler not yet split into precheck and execute: audited
    /// first, as before. Every use is listed in the production coverage test.
    pub fn register_transitional<H: IpcHandler + 'static>(
        &mut self,
        op: IpcOperationName,
        handler: H,
    ) {
        self.entries
            .push((op, RegisteredHandler::Transitional(Box::new(handler))));
    }

    /// How `op`'s handler is registered, or `None` when it has none.
    pub fn coverage(&self, op: IpcOperationName) -> Option<PrecheckCoverage> {
        self.find(op).map(RegisteredHandler::coverage)
    }

    fn find(&self, op: IpcOperationName) -> Option<&RegisteredHandler> {
        self.entries
            .iter()
            .find(|(name, _)| *name == op)
            .map(|(_, h)| h)
    }
}

/// How many precheck refusals reach the operational log per window. A refused
/// request costs its sender nothing, so an uncapped loop of them would rotate
/// the log away just as it once flooded the audit trail.
const REFUSAL_LOG_PER_WINDOW: u32 = 20;
const REFUSAL_LOG_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Default)]
struct RefusalLogBudget {
    window: Mutex<RefusalLogWindow>,
}

#[derive(Default)]
struct RefusalLogWindow {
    started: Option<std::time::Instant>,
    logged: u32,
    suppressed: u64,
}

impl RefusalLogBudget {
    /// `Some(n)` when this refusal may be logged, `n` being how many were
    /// dropped since the last one that was; `None` when it is over budget.
    fn admit(&self, now: std::time::Instant) -> Option<u64> {
        // A poisoned lock costs the cap, never the line.
        let Ok(mut w) = self.window.lock() else {
            return Some(0);
        };
        if w.started
            .is_none_or(|s| now.duration_since(s) >= REFUSAL_LOG_WINDOW)
        {
            w.started = Some(now);
            w.logged = 0;
        }
        if w.logged >= REFUSAL_LOG_PER_WINDOW {
            w.suppressed = w.suppressed.saturating_add(1);
            return None;
        }
        w.logged += 1;
        Some(std::mem::take(&mut w.suppressed))
    }
}

// ── Mutation queue ───────────────────────────────────────────────────────────

/// Cap on mutating requests in flight at once; past it a request gets
/// `BusyConflict`. It does NOT serialise them — the activation gate in
/// `ActivationCoordinator` is what keeps two activations apart.
#[derive(Default)]
pub struct MutationQueue {
    /// Live request ids currently being processed.
    in_flight: Mutex<VecDeque<String>>,
    /// Soft cap on queue depth — protects against runaway retries from a
    /// stuck GUI.
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

/// What the authority check concluded, with the refusal already worded for the
/// person who has to act on it.
enum AuthorizationOutcome {
    Granted,
    Refused(String),
}

/// `MutationQueue` slot count for a production router.
///
/// Bounds how many mutating requests run at once; covers the GUI's worst-case
/// burst of mass-toggle clicks without hoarding memory. Declared here, not in
/// one platform's wiring: Windows passed 32 and Linux a literal 1, so the same
/// burst queued on one OS and was refused as a conflict on the other.
pub const MUTATION_QUEUE_CAPACITY: usize = 32;

/// The thing the transport calls per-request. Validates the envelope,
/// enforces authorization, claims a mutation slot when needed, runs the audit
/// hook, dispatches to the registered handler.
pub struct IpcRouter {
    registry: IpcHandlerRegistry,
    audit: Arc<dyn IpcAuditEmitter>,
    queue: MutationQueue,
    /// Consulted when an UNELEVATED caller asks for something that needs
    /// elevation. Absent on a platform where the caller elevates itself before
    /// connecting — there the answer is already in `caller_is_elevated`.
    authority: Option<Arc<dyn nrr_platform_api::authorization::AuthorizationPort>>,
    refusal_log: RefusalLogBudget,
}

/// How far a request got through the router.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Disposition {
    /// Answered by the router or the handler, as before the precheck existed.
    Answered,
    /// Refused by its handler's precheck: nothing audited, nothing run.
    RefusedByPrecheck,
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
            refusal_log: RefusalLogBudget::default(),
        }
    }

    /// Ask the platform's authority whether this caller may take `action`.
    ///
    /// The refusal begins with a slug naming the outcome, because the remedy
    /// differs: an administrator who is not allowed, a caller nobody can prompt
    /// (a terminal starts its own agent then), and a machine with no authority
    /// at all (a terminal is told to start elevated).
    fn authorize(
        &self,
        action: Option<&'static str>,
        what: &str,
        ctx: &IpcRequestContext,
    ) -> AuthorizationOutcome {
        use nrr_platform_api::authorization::{AuthorizationDecision, AuthorizationSubject};
        use nrr_shared::ipc_transport::{
            ELEVATION_AGENT_MISSING_CLIENT_SLUG, ELEVATION_DECLINED_CLIENT_SLUG,
            ELEVATION_UNAVAILABLE_CLIENT_SLUG, TERMINAL_NEEDS_ELEVATION_CLIENT_SLUG,
        };
        use nrr_shared::product_identity::BinaryRole;

        let terminal = ctx.client_profile == IpcClientProfile::Tui;
        let start_elevated = || {
            AuthorizationOutcome::Refused(format!(
                "{TERMINAL_NEEDS_ELEVATION_CLIENT_SLUG}: {what} needs an administrator; start {} \
                 elevated (sudo, or an administrator terminal)",
                BinaryRole::Tui.unix_file_name(),
            ))
        };
        let Some(authority) = self.authority.as_ref() else {
            if terminal {
                return start_elevated();
            }
            return AuthorizationOutcome::Refused("operation requires an elevated client".into());
        };
        let unidentified = || {
            AuthorizationOutcome::Refused(
                "operation requires elevation and this caller cannot be identified".into(),
            )
        };
        let (Some(action), Some(process)) = (action, ctx.caller_pid) else {
            return unidentified();
        };
        // Never a default uid: 0 would ask polkit about root.
        let Some(uid) = ctx
            .caller_principal
            .as_ref()
            .and_then(UserPrincipal::as_unix_uid)
        else {
            return unidentified();
        };
        let subject = AuthorizationSubject {
            pid: process.pid,
            uid,
            start_time: process.start_time,
        };
        // The window and the terminal have a person in front of them; the tray
        // and the console do not, and a prompt there would wait for nobody.
        let interactive = ctx.client_profile.may_prompt_for_elevation();
        match authority.authorize(subject, action, interactive) {
            AuthorizationDecision::Allowed => AuthorizationOutcome::Granted,
            AuthorizationDecision::Denied => AuthorizationOutcome::Refused(format!(
                "{ELEVATION_DECLINED_CLIENT_SLUG}: not authorized for {action}: an administrator \
                 may grant it"
            )),
            AuthorizationDecision::NeedsInteraction => AuthorizationOutcome::Refused(format!(
                "{ELEVATION_AGENT_MISSING_CLIENT_SLUG}: {action} needs confirmation, and no \
                 authentication agent answers for this caller"
            )),
            AuthorizationDecision::Unavailable if terminal => start_elevated(),
            AuthorizationDecision::Unavailable => AuthorizationOutcome::Refused(format!(
                "{ELEVATION_UNAVAILABLE_CLIENT_SLUG}: {action} could not be checked: no \
                 authorization service answered"
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
                msg_key = "ipctop-operation-class-mismatch",
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
        // Debug level, not info: logging two lines per IPC request would be
        // 24 lines/min of noise even when nothing is happening, given the
        // GUI's 5 s health-check tick. Failures still produce a warn-level
        // record in the `else` branch below, visible at default verbosity.
        // Bump `NRR_LOG=nrr=debug` to recover the per-request trace when
        // diagnosing.
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
        let (response, disposition) = self.dispatch_inner(request, ctx);
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
            let suppressed = match disposition {
                Disposition::Answered => Some(0),
                Disposition::RefusedByPrecheck => self.refusal_log.admit(std::time::Instant::now()),
            };
            if let Some(suppressed) = suppressed {
                let (code, msg) = response
                    .error
                    .as_ref()
                    .map(|e| (format!("{:?}", e.code), e.message.clone()))
                    .unwrap_or_else(|| ("Unknown".into(), String::new()));
                tracing::warn!(
                    target: "nrr::ipc::dispatch",
                    msg_key = "ipc-request-failed",
                    request_id = %response.request_id,
                    op = op_slug,
                    class = ?class,
                    duration_us = dur_us,
                    error_code = %code,
                    error_message = %msg,
                    refusals_not_logged = suppressed,
                    "ipc request failed",
                );
            }
        }
        response
    }

    fn dispatch_inner(
        &self,
        request: IpcRequestEnvelope,
        ctx: IpcRequestContext,
    ) -> (IpcResponseEnvelope, Disposition) {
        let mut disposition = Disposition::Answered;
        // Kept only where the service itself could lift a handler's refusal.
        let retry = (self.authority.is_some()
            && !ctx.caller_is_elevated
            && nrr_shared::ipc_transport::handler_may_need_administrator(request.operation))
        .then(|| (request.clone(), ctx.clone()));
        let response = self.admit_and_run(request, ctx, &mut disposition);
        let Some((request, ctx)) = retry else {
            return (response, disposition);
        };
        // Only a precheck refusal: nothing ran, nothing was audited, no
        // confirmation token was spent, so running it again is the same request.
        let needs_administrator = disposition == Disposition::RefusedByPrecheck
            && response.error.as_ref().is_some_and(|e| {
                e.code == IpcErrorCode::Forbidden
                    && nrr_shared::ipc_transport::is_needs_administrator(&e.message)
            });
        if !needs_administrator {
            return (response, disposition);
        }
        self.run_authorized(request, ctx)
    }

    /// The service's twin of the Windows broker: a handler refused a value only
    /// an administrator may set, so the authority is asked (with a prompt, for
    /// a client that has a person in front of it) and, on a yes, the request
    /// runs again with rights. The caller stays who they are: only the
    /// elevation flag changes, never the principal the request belongs to.
    fn run_authorized(
        &self,
        request: IpcRequestEnvelope,
        ctx: IpcRequestContext,
    ) -> (IpcResponseEnvelope, Disposition) {
        let op = request.operation;
        let action = nrr_shared::ipc_transport::needs_administrator_action(op);
        match self.authorize(Some(action), op.slug(), &ctx) {
            AuthorizationOutcome::Granted => {
                tracing::info!(
                    target: "nrr::ipc::dispatch",
                    op = op.slug(),
                    action,
                    caller = %ctx.caller_stored(),
                    "authorized by the platform authority; running the request with rights",
                );
                let elevated = IpcRequestContext {
                    caller_is_elevated: true,
                    ..ctx
                };
                let mut disposition = Disposition::Answered;
                let response = self.admit_and_run(request, elevated, &mut disposition);
                (response, disposition)
            }
            AuthorizationOutcome::Refused(message) => (
                IpcResponseEnvelope::err(
                    &request,
                    IpcError {
                        code: IpcErrorCode::Forbidden,
                        message,
                        diagnostics_id: None,
                    },
                ),
                Disposition::Answered,
            ),
        }
    }

    fn admit_and_run(
        &self,
        request: IpcRequestEnvelope,
        ctx: IpcRequestContext,
        disposition: &mut Disposition,
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

        // 1b. A start parked in recovery answers reads, so the reason can be
        //     shown, and refuses everything that would change state: nothing
        //     behind the handlers has been brought up.
        if crate::lifecycle::recovery_required()
            && !matches!(
                class,
                IpcOperationClass::ReadSnapshot | IpcOperationClass::DiagnosticQuery
            )
        {
            return IpcResponseEnvelope::err(
                &request,
                IpcError {
                    code: IpcErrorCode::RecoveryRequired,
                    message: "the service did not start: recovery is required; the health status \
                              names the reason"
                        .into(),
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
            match self.authorize(class.authorization_action(), class.slug(), &ctx) {
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

        // 5. Mutation queue (only for mutating ops). Claimed before the
        //    precheck, which may spend a confirmation token: a request turned
        //    away as busy keeps its token, and is not recorded either.
        let _slot = if class.is_mutating() {
            match self.queue.try_enter(&request.request_id) {
                Ok(guard) => Some(guard),
                Err(e) => return IpcResponseEnvelope::err(&request, e),
            }
        } else {
            None
        };

        // 6. The handler, and its verdict on the payload. Only a request that
        //    passed it goes on to the audit and execution: a refusal here
        //    leaves no record of a mutation that never ran.
        let Some(handler) = self.registry.find(request.operation) else {
            return IpcResponseEnvelope::err(
                &request,
                IpcError {
                    code: IpcErrorCode::MalformedRequest,
                    message: format!("operation {} has no handler", request.operation.slug()),
                    diagnostics_id: None,
                },
            );
        };
        let run: PreparedRun<'_> = match handler {
            RegisteredHandler::Checked(h) => match h.prepare(&request, &ctx) {
                Ok(run) => run,
                Err(error) => {
                    *disposition = Disposition::RefusedByPrecheck;
                    return IpcResponseEnvelope::err(&request, error);
                }
            },
            // Fails closed: a mutation whose handler cannot check it first
            // neither runs unaudited nor writes a record before it is checked.
            RegisteredHandler::ReadOnly(_) if class.is_mutating() => {
                return IpcResponseEnvelope::err(
                    &request,
                    IpcError {
                        code: IpcErrorCode::Internal,
                        message: format!(
                            "operation {op} changes state and its handler has no precheck",
                            op = request.operation.slug()
                        ),
                        diagnostics_id: None,
                    },
                );
            }
            RegisteredHandler::ReadOnly(h) | RegisteredHandler::Transitional(h) => {
                let (request, ctx) = (&request, &ctx);
                Box::new(move || h.handle(request, ctx))
            }
        };

        // 7. Audit privileged mutations *before* execution; a failed write
        //    is a refusal, so an unaudited mutation never runs.
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

        // 8. Execution.
        match run() {
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

    /// A privileged request: rolling back the shared baseline is an edit of
    /// it, which needs elevation and therefore reaches the authority.
    fn baseline_rollback_request() -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            payload: serde_json::json!({ "admin-baseline": true }),
            ..req(
                IpcOperationName::RollbackRequest,
                IpcOperationClass::MutationRequest,
                IPC_PROTOCOL_VERSION,
                Some("token-from-dry-run"),
            )
        }
    }

    struct EchoHandler;
    impl CheckedIpcHandler for EchoHandler {
        type Checked = ();
        fn precheck(
            &self,
            _request: &IpcRequestEnvelope,
            _ctx: &IpcRequestContext,
        ) -> Result<(), IpcError> {
            Ok(())
        }
        fn execute(
            &self,
            _checked: Prechecked<()>,
            request: &IpcRequestEnvelope,
            _ctx: &IpcRequestContext,
        ) -> HandlerOutcome {
            Ok(serde_json::json!({ "echo": request.operation.slug() }))
        }
    }

    fn make_router() -> IpcRouter {
        let mut reg = IpcHandlerRegistry::new();
        reg.register(IpcOperationName::ServiceHealthGet, EchoHandler);
        reg.register_checked(IpcOperationName::MutationSubmit, EchoHandler);
        reg.register_checked(IpcOperationName::RollbackRequest, EchoHandler);
        reg.register(IpcOperationName::InterfacesRefreshRequest, EchoHandler);
        IpcRouter::new(reg, Arc::new(NoopAuditEmitter), 1)
    }

    /// Counts audit records.
    #[derive(Default)]
    struct CountingAudit {
        records: AtomicUsize,
    }
    impl IpcAuditEmitter for CountingAudit {
        fn record_request(
            &self,
            _r: &IpcRequestEnvelope,
            _c: &IpcRequestContext,
        ) -> Result<(), String> {
            self.records.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Accepts only `{"value": <u8>}` and notes, when it runs, how many audit
    /// records existed at that moment.
    struct StrictHandler {
        audit: Arc<CountingAudit>,
        records_seen_at_execute: Arc<Mutex<Vec<usize>>>,
    }
    impl CheckedIpcHandler for StrictHandler {
        type Checked = u8;
        fn precheck(
            &self,
            request: &IpcRequestEnvelope,
            _ctx: &IpcRequestContext,
        ) -> Result<u8, IpcError> {
            request
                .payload
                .get("value")
                .and_then(serde_json::Value::as_u64)
                .and_then(|v| u8::try_from(v).ok())
                .ok_or_else(|| IpcError {
                    code: IpcErrorCode::MalformedRequest,
                    message: "value must be a u8".into(),
                    diagnostics_id: None,
                })
        }
        fn execute(
            &self,
            checked: Prechecked<u8>,
            _request: &IpcRequestEnvelope,
            _ctx: &IpcRequestContext,
        ) -> HandlerOutcome {
            if let Ok(mut seen) = self.records_seen_at_execute.lock() {
                seen.push(self.audit.records.load(Ordering::SeqCst));
            }
            Ok(serde_json::json!({ "value": *checked }))
        }
    }

    fn strict_router() -> (IpcRouter, Arc<CountingAudit>, Arc<Mutex<Vec<usize>>>) {
        let audit = Arc::new(CountingAudit::default());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut reg = IpcHandlerRegistry::new();
        reg.register_checked(
            IpcOperationName::RoutingPauseToggle,
            StrictHandler {
                audit: Arc::clone(&audit),
                records_seen_at_execute: Arc::clone(&seen),
            },
        );
        (IpcRouter::new(reg, audit.clone(), 1), audit, seen)
    }

    fn user_config_request(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            payload,
            ..req(
                IpcOperationName::RoutingPauseToggle,
                IpcOperationClass::UserScopedConfiguration,
                IPC_PROTOCOL_VERSION,
                None,
            )
        }
    }

    /// A payload its handler refuses is answered with that refusal and leaves
    /// no audit record: the trail holds requests the service admitted, not
    /// whatever a caller chose to send.
    #[test]
    fn a_request_its_precheck_refuses_is_never_audited() {
        let (router, audit, seen) = strict_router();
        for payload in [
            serde_json::json!({}),
            serde_json::json!({ "value": "x" }),
            serde_json::json!({ "value": 300 }),
        ] {
            let r = router.dispatch(user_config_request(payload.clone()), elevated_gui());
            assert_eq!(
                r.error.map(|e| e.code),
                Some(IpcErrorCode::MalformedRequest),
                "{payload}"
            );
        }
        assert_eq!(audit.records.load(Ordering::SeqCst), 0);
        assert!(seen.lock().map(|s| s.is_empty()).unwrap_or(false));
    }

    /// An accepted request is recorded exactly once, and the record exists
    /// before the handler acts.
    #[test]
    fn an_accepted_mutation_is_audited_once_before_it_runs() {
        let (router, audit, seen) = strict_router();
        let r = router.dispatch(
            user_config_request(serde_json::json!({ "value": 7 })),
            elevated_gui(),
        );
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(audit.records.load(Ordering::SeqCst), 1);
        assert_eq!(seen.lock().map(|s| s.clone()).unwrap_or_default(), vec![1]);
    }

    /// A mutating operation registered without a precheck fails closed: it
    /// neither runs nor writes a record ahead of a check.
    #[test]
    fn a_mutation_registered_without_a_precheck_is_refused_unaudited() {
        struct Plain;
        impl IpcHandler for Plain {
            fn handle(&self, _r: &IpcRequestEnvelope, _c: &IpcRequestContext) -> HandlerOutcome {
                Ok(serde_json::json!({ "ran": true }))
            }
        }
        let audit = Arc::new(CountingAudit::default());
        let mut reg = IpcHandlerRegistry::new();
        reg.register(IpcOperationName::RoutingPauseToggle, Plain);
        let router = IpcRouter::new(reg, audit.clone(), 1);
        let r = router.dispatch(
            user_config_request(serde_json::json!({ "value": 1 })),
            elevated_gui(),
        );
        assert_eq!(r.error.map(|e| e.code), Some(IpcErrorCode::Internal));
        assert_eq!(audit.records.load(Ordering::SeqCst), 0);
    }

    /// The transitional path keeps the old order: audited, then handled.
    #[test]
    fn a_transitional_handler_is_still_audited_before_it_runs() {
        struct Plain(Arc<CountingAudit>);
        impl IpcHandler for Plain {
            fn handle(&self, _r: &IpcRequestEnvelope, _c: &IpcRequestContext) -> HandlerOutcome {
                Ok(serde_json::json!({ "records": self.0.records.load(Ordering::SeqCst) }))
            }
        }
        let audit = Arc::new(CountingAudit::default());
        let mut reg = IpcHandlerRegistry::new();
        reg.register_transitional(
            IpcOperationName::RoutingPauseToggle,
            Plain(Arc::clone(&audit)),
        );
        assert_eq!(
            reg.coverage(IpcOperationName::RoutingPauseToggle),
            Some(PrecheckCoverage::Transitional)
        );
        let router = IpcRouter::new(reg, audit.clone(), 1);
        let r = router.dispatch(user_config_request(serde_json::json!({})), elevated_gui());
        assert_eq!(r.payload, Some(serde_json::json!({ "records": 1 })));
    }

    /// A dry run is a read: prechecked and run, never audited.
    #[test]
    fn a_checked_handler_serving_a_read_is_not_audited() {
        let audit = Arc::new(CountingAudit::default());
        let mut reg = IpcHandlerRegistry::new();
        reg.register_checked(IpcOperationName::MutationSubmit, EchoHandler);
        let router = IpcRouter::new(reg, audit.clone(), 1);
        let request = IpcRequestEnvelope {
            payload: serde_json::json!({ "dry-run": true }),
            ..req(
                IpcOperationName::MutationSubmit,
                IpcOperationClass::ReadSnapshot,
                IPC_PROTOCOL_VERSION,
                None,
            )
        };
        let r = router.dispatch(request, elevated_gui());
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(audit.records.load(Ordering::SeqCst), 0);
    }

    /// Precheck refusals reach the log up to the budget per window; the rest
    /// are counted and reported on the next line that is written.
    #[test]
    fn precheck_refusals_are_logged_within_a_budget() {
        let budget = RefusalLogBudget::default();
        let t0 = std::time::Instant::now();
        for _ in 0..REFUSAL_LOG_PER_WINDOW {
            assert_eq!(budget.admit(t0), Some(0));
        }
        assert_eq!(budget.admit(t0), None);
        assert_eq!(budget.admit(t0), None);
        assert_eq!(budget.admit(t0 + REFUSAL_LOG_WINDOW), Some(2));
        assert_eq!(budget.admit(t0 + REFUSAL_LOG_WINDOW), Some(0));
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
    fn a_full_mutation_queue_refuses_until_a_slot_frees() {
        // `make_router` builds a one-slot queue: a held slot refuses the next
        // mutation, and releasing it lets the same request through.
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
        reg.register_checked(IpcOperationName::MutationSubmit, EchoHandler);
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
        // Guardrail: sized so a full rule book list fits. Lower bound pins
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
                caller_pid: Some(CallerProcess {
                    pid: 4321,
                    start_time: Some(1),
                }),
            };
            router.dispatch(baseline_rollback_request(), ctx)
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

    /// The terminal asks the authority like the window does (it answers the
    /// prompt with its own agent); only where nobody can be asked at all is it
    /// told to start elevated. Elevated (`sudo nrr-tui`), it passes.
    #[test]
    fn a_terminal_is_asked_and_told_to_start_elevated_only_without_an_authority() {
        use nrr_platform_api::authorization::{AuthorizationDecision, FixedAuthority};
        use nrr_shared::ipc_transport::{
            ELEVATION_AGENT_MISSING_CLIENT_SLUG, TERMINAL_NEEDS_ELEVATION_CLIENT_SLUG,
        };

        let tui = |elevated: bool| {
            let uid = if elevated { 0 } else { 1000 };
            IpcRequestContext {
                client_profile: IpcClientProfile::Tui,
                caller_is_elevated: elevated,
                caller_principal: Some(UserPrincipal::from_linux_uid(uid)),
                caller_pid: Some(CallerProcess {
                    pid: 4321,
                    start_time: Some(1),
                }),
            }
        };
        let passes = |response: IpcResponseEnvelope| {
            response
                .error
                .is_none_or(|e| e.code != IpcErrorCode::Forbidden)
        };
        let refusal = |router: &IpcRouter| {
            router
                .dispatch(baseline_rollback_request(), tui(false))
                .error
                .expect("refused")
        };
        let authority = |decision| make_router().with_authority(Arc::new(FixedAuthority(decision)));

        assert!(passes(
            authority(AuthorizationDecision::Allowed)
                .dispatch(baseline_rollback_request(), tui(false))
        ));
        let no_agent = refusal(&authority(AuthorizationDecision::NeedsInteraction));
        assert!(
            no_agent
                .message
                .starts_with(ELEVATION_AGENT_MISSING_CLIENT_SLUG),
            "{}",
            no_agent.message
        );
        for router in [authority(AuthorizationDecision::Unavailable), make_router()] {
            let error = refusal(&router);
            assert_eq!(error.code, IpcErrorCode::Forbidden);
            assert!(
                error
                    .message
                    .starts_with(TERMINAL_NEEDS_ELEVATION_CLIENT_SLUG),
                "{}",
                error.message
            );
            assert!(
                passes(router.dispatch(baseline_rollback_request(), tui(true))),
                "an elevated terminal passes the elevation gate"
            );
        }
    }

    /// Refuses a change unless the caller is elevated, like a setting the whole
    /// machine shares, and counts the runs that had the rights.
    struct MachineValueHandler {
        elevated_runs: Arc<AtomicUsize>,
    }
    impl CheckedIpcHandler for MachineValueHandler {
        type Checked = ();
        fn precheck(
            &self,
            _request: &IpcRequestEnvelope,
            ctx: &IpcRequestContext,
        ) -> Result<(), IpcError> {
            if ctx.caller_is_elevated {
                Ok(())
            } else {
                Err(IpcError::needs_administrator(
                    "the test setting is the machine's",
                ))
            }
        }
        fn execute(
            &self,
            _checked: Prechecked<()>,
            _request: &IpcRequestEnvelope,
            ctx: &IpcRequestContext,
        ) -> HandlerOutcome {
            if ctx.caller_is_elevated {
                self.elevated_runs.fetch_add(1, Ordering::SeqCst);
            }
            Ok(serde_json::json!({}))
        }
    }

    fn machine_value_router(
        authority: Option<Arc<dyn nrr_platform_api::authorization::AuthorizationPort>>,
    ) -> (IpcRouter, Arc<AtomicUsize>) {
        let elevated_runs = Arc::new(AtomicUsize::new(0));
        let mut reg = IpcHandlerRegistry::new();
        reg.register_checked(
            IpcOperationName::TrafficStatsSet,
            MachineValueHandler {
                elevated_runs: Arc::clone(&elevated_runs),
            },
        );
        let router = IpcRouter::new(reg, Arc::new(NoopAuditEmitter), 1);
        let router = match authority {
            Some(authority) => router.with_authority(authority),
            None => router,
        };
        (router, elevated_runs)
    }

    fn machine_value_request() -> IpcRequestEnvelope {
        let payload = serde_json::json!({});
        IpcRequestEnvelope {
            operation_class: canonical_operation_class(IpcOperationName::TrafficStatsSet, &payload),
            payload,
            ..req(
                IpcOperationName::TrafficStatsSet,
                IpcOperationClass::UserScopedConfiguration,
                IPC_PROTOCOL_VERSION,
                None,
            )
        }
    }

    fn linux_gui_user() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: Some(UserPrincipal::from_linux_uid(1000)),
            caller_pid: Some(CallerProcess {
                pid: 4321,
                start_time: Some(9),
            }),
        }
    }

    /// The service's twin of the broker: a value only an administrator may set
    /// is asked about and, on a yes, run again with rights for the same user.
    #[test]
    fn a_machine_value_is_run_with_rights_once_the_authority_allows_it() {
        let authority = Arc::new(RecordingAuthority::default());
        let (router, elevated_runs) = machine_value_router(Some(
            authority.clone() as Arc<dyn nrr_platform_api::authorization::AuthorizationPort>
        ));
        let response = router.dispatch(machine_value_request(), linux_gui_user());
        assert!(response.ok, "{:?}", response.error);
        assert_eq!(elevated_runs.load(Ordering::SeqCst), 1);
        let asked = authority.0.lock().expect("lock").clone();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].uid, 1000);
    }

    /// Each outcome of the question reaches the client as its own code, and
    /// nothing runs; without an authority the handler's own refusal stands, for
    /// the Windows broker to lift.
    #[test]
    fn a_refused_machine_value_names_why_and_runs_nothing() {
        use nrr_platform_api::authorization::{AuthorizationDecision, FixedAuthority};
        use nrr_shared::ipc_transport::{
            forbidden_client_code, is_needs_administrator, ELEVATION_AGENT_MISSING_CLIENT_SLUG,
            ELEVATION_DECLINED_CLIENT_SLUG, ELEVATION_UNAVAILABLE_CLIENT_SLUG,
        };

        for (decision, code) in [
            (
                AuthorizationDecision::Denied,
                ELEVATION_DECLINED_CLIENT_SLUG,
            ),
            (
                AuthorizationDecision::NeedsInteraction,
                ELEVATION_AGENT_MISSING_CLIENT_SLUG,
            ),
            (
                AuthorizationDecision::Unavailable,
                ELEVATION_UNAVAILABLE_CLIENT_SLUG,
            ),
        ] {
            let (router, elevated_runs) =
                machine_value_router(Some(Arc::new(FixedAuthority(decision))
                    as Arc<dyn nrr_platform_api::authorization::AuthorizationPort>));
            let error = router
                .dispatch(machine_value_request(), linux_gui_user())
                .error
                .expect("refused");
            assert_eq!(error.code, IpcErrorCode::Forbidden);
            assert_eq!(forbidden_client_code(&error.message), code, "{decision:?}");
            assert_eq!(elevated_runs.load(Ordering::SeqCst), 0);
        }

        let (router, _) = machine_value_router(None);
        let error = router
            .dispatch(machine_value_request(), linux_gui_user())
            .error
            .expect("refused");
        assert!(is_needs_administrator(&error.message), "{}", error.message);
    }

    /// Remembers the subjects it was asked about and allows them.
    #[derive(Default)]
    struct RecordingAuthority(
        std::sync::Mutex<Vec<nrr_platform_api::authorization::AuthorizationSubject>>,
    );

    impl nrr_platform_api::authorization::AuthorizationPort for RecordingAuthority {
        fn authorize(
            &self,
            subject: nrr_platform_api::authorization::AuthorizationSubject,
            _action: &str,
            _allow_interaction: bool,
        ) -> nrr_platform_api::authorization::AuthorizationDecision {
            if let Ok(mut asked) = self.0.lock() {
                asked.push(subject);
            }
            nrr_platform_api::authorization::AuthorizationDecision::Allowed
        }
    }

    /// The start time the transport read at accept is what polkit is asked
    /// with; without it the Linux authority answers "could not ask" to every
    /// GUI request.
    #[test]
    fn the_authority_is_asked_with_the_start_time_read_at_accept() {
        let authority = Arc::new(RecordingAuthority::default());
        let router = make_router().with_authority(authority.clone());
        let ctx = IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: Some(UserPrincipal::from_linux_uid(1000)),
            caller_pid: Some(CallerProcess {
                pid: 4321,
                start_time: Some(987_654),
            }),
        };
        let _ = router.dispatch(baseline_rollback_request(), ctx);
        let asked = authority.0.lock().expect("lock").clone();
        assert_eq!(
            asked,
            vec![nrr_platform_api::authorization::AuthorizationSubject {
                pid: 4321,
                uid: 1000,
                start_time: Some(987_654),
            }]
        );
    }

    /// A caller with no unix identity is refused without asking: a default uid
    /// of 0 would have asked polkit about root.
    #[test]
    fn a_caller_without_a_unix_uid_is_refused_unasked() {
        let authority = Arc::new(RecordingAuthority::default());
        let router = make_router().with_authority(authority.clone());
        for principal in [
            None,
            UserPrincipal::from_windows_sid("S-1-5-21-1-2-3-1001").ok(),
        ] {
            let ctx = IpcRequestContext {
                client_profile: IpcClientProfile::GuiInteractive,
                caller_is_elevated: false,
                caller_principal: principal,
                caller_pid: Some(CallerProcess {
                    pid: 4321,
                    start_time: Some(1),
                }),
            };
            let error = router
                .dispatch(baseline_rollback_request(), ctx)
                .error
                .expect("refused");
            assert_eq!(error.code, IpcErrorCode::Forbidden);
        }
        assert!(authority.0.lock().expect("lock").is_empty());
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
            caller_pid: Some(CallerProcess {
                pid: 4321,
                start_time: Some(1),
            }),
        };

        let response = router.dispatch(baseline_rollback_request(), ctx);

        let error = response.error.expect("a refusal carries an error");
        assert_eq!(error.code, IpcErrorCode::Forbidden);
        assert!(error.message.contains("elevated client"));
    }
}
