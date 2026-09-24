//! IPC handlers for the diagnostics operations
//! (`ExplainGet`, `DiagnosticsExportArchive`).
//!
//! Both handlers consume the production `DiagnosticsFacade` trait
//! object wired in `runtime_deps.rs`. The facade itself is shared
//! across multiple handlers (snapshot + logs + audit + alerts) — see
//! `IpcHandlerDeps.diagnostics`.
//!
//! ## ExplainGetHandler
//!
//! Maps wire `ExplainGetRequest` (decision_id OR input_sample +
//! optional detail_level) into the in-process `ExplainQuery` /
//! `ExplainDetailLevel` types, calls `DiagnosticsFacade::get_explain`,
//! and projects the resulting `ExplainResponse` into the wire
//! `ExplainGetResponse` shape (compact view + full passthrough).
//!
//! Both-fields-set or neither-set requests are rejected at the
//! handler boundary as `MalformedRequest` so the facade only sees
//! exactly one variant.
//!
//! ## DiagnosticsExportArchiveHandler
//!
//! Builds a zip archive via `nrr_diagnostics::archive::ArchiveBuilder`
//! using data collected from the facade (health snapshot, log + audit
//! pages). Writes the result to the per-user `archives/` directory
//! (sibling of `logs/` and `audit/`, closed to ordinary users like the rest
//! of the tree — the finished file is then handed to its requester through
//! `FileHandoffPort`).
//! Returns the absolute path so the GUI can open the containing folder
//! in Explorer.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use nrr_diagnostics::archive::{
    builder::{ArchiveBuilder, ArchiveInput, AttachedLog},
    request::DiagnosticArchiveRequest,
};
use nrr_diagnostics::explain::{ExplainQuery, ExplainResponse, RuntimeInputSample};
use nrr_diagnostics::facade::dto::{
    ClearLogsRequest, DiagnosticArchiveHealthEnrichmentDto, SetDiagnosticModeRequest,
};
use nrr_diagnostics::facade::pagination::{PaginationParams, MAX_PAGE_SIZE};
use nrr_diagnostics::facade::service::DiagnosticsFacade;
use nrr_diagnostics::privacy::mode::RedactionMode;
use nrr_diagnostics::privacy::redact::{redact_hostname, redact_ipv4_str};
use nrr_diagnostics::redaction::ExplainDetailLevel;
use nrr_domain::decision_explain::DecisionId;
use nrr_shared::ipc_payloads::{
    CacheClearRequest, CacheClearResponse, CacheEntriesListRequest, CacheEntriesListResponse,
    CacheEntryDto, ConnTraceEntriesListRequest, ConnTraceEntriesListResponse, ConnTraceEntryDto,
    DiagnosticModeSetRequest, DiagnosticsExportArchiveRequest, DiagnosticsExportArchiveResponse,
    ExplainCompactViewDto, ExplainGetRequest, ExplainGetResponse, LogsClearRequest,
    LogsClearResponse,
};
use nrr_shared::pagination::{PageCursor, PageResult};
use nrr_storage::dto::CacheResetReason;
use nrr_storage::repository::CacheRepository;

use crate::conn_observation_consumer::{proto_str, role_str, verdict_str, ConnectionTraceRing};
use crate::dns_observation_consumer::{
    build_secondary_ip_owners, rule_set_match_kind, rule_set_matches, ActiveSidFn,
};
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::ipc_handlers::providers::{
    AdaptersSnapshotProvider, RoutePolicyProvider, ServiceStabilityConfigProvider,
};
use crate::per_sid_orchestrator::RulesProvider;

/// Inputs for the conn-trace `expected_route` stamp: the active
/// user's rule book + the FQDN cache + the routing-active-SID resolver.
pub type ConnTraceExpectation = (
    Arc<dyn RulesProvider>,
    Arc<dyn FqdnCacheLookup>,
    ActiveSidFn,
);

use crate::ipc::DiagnosticsAudience;
use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};

fn malformed(op: &'static str, e: serde_json::Error) -> IpcError {
    IpcError {
        code: IpcErrorCode::MalformedRequest,
        message: format!("{op} payload invalid: {e}"),
        diagnostics_id: None,
    }
}

fn malformed_msg(op: &'static str, msg: impl Into<String>) -> IpcError {
    IpcError {
        code: IpcErrorCode::MalformedRequest,
        message: format!("{op}: {}", msg.into()),
        diagnostics_id: None,
    }
}

fn internal(op: &'static str, msg: impl Into<String>) -> IpcError {
    IpcError {
        code: IpcErrorCode::Internal,
        message: format!("{op}: {}", msg.into()),
        diagnostics_id: None,
    }
}

fn serialise(op: &'static str, value: impl serde::Serialize) -> HandlerOutcome {
    serde_json::to_value(value).map_err(|e| internal(op, format!("response serialisation: {e}")))
}

fn millis_since_epoch() -> i64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn system_time_to_ms(t: SystemTime) -> i64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

mod archive;
mod cache;
mod conn_trace;
mod explain;

pub use archive::*;
pub use cache::*;
pub use conn_trace::*;
pub use explain::*;

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
