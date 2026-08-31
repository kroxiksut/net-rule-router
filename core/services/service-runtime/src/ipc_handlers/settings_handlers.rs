//! IPC handlers for the settings catalog.
//!
//! Nine handlers landing together because they share thin wire shapes
//! (deserialize → call provider/writer → serialize) and identical error
//! mapping. Real backends are wired in `production_settings.rs`; here
//! the handlers only consume the provider/writer traits from
//! [`super::providers`].
//!
//! `caller_sid.is_empty()` is treated as a transport error (`Internal`)
//! for per-SID writers (routing pause, autostart). The two singleton
//! mutators (retention, apply failure policy) are admin-gated upstream
//! by `IpcOperationSpec::requires_service_mutation_privilege = true`;
//! the handlers themselves do not re-check elevation.

use std::sync::Arc;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::{
    ApplyFailurePolicyGetRequest, ApplyFailurePolicySetRequest, AutostartGetRequest,
    AutostartToggleRequest, LogRetentionConfigGetRequest, LogRetentionConfigSetRequest,
    RetentionSettingsDto, RetentionSettingsGetRequest, RetentionSettingsSetRequest,
    RoutingPauseGetRequest, RoutingPauseToggleRequest, StorageUsageGetRequest,
    TrafficStatsGetRequest, TrafficStatsSetRequest,
};
use crate::ipc_handlers::providers::{
    ApplyFailurePolicyProvider, ApplyFailurePolicyWriter, AutostartProvider, AutostartWriter,
    LogRetentionConfigProvider, LogRetentionConfigWriter, RetentionSettingsProvider,
    RetentionSettingsWriter, RoutingPauseProvider, RoutingPauseWriter, SettingsWriteError,
    StorageUsageProvider, TrafficStatsProvider, TrafficStatsWriter,
};

fn malformed(op: &'static str, e: serde_json::Error) -> IpcError {
    IpcError {
        code: IpcErrorCode::MalformedRequest,
        message: format!("{op} payload invalid: {e}"),
        diagnostics_id: None,
    }
}

fn serialise(op: &'static str, value: impl serde::Serialize) -> HandlerOutcome {
    serde_json::to_value(value).map_err(|e| IpcError {
        code: IpcErrorCode::Internal,
        message: format!("{op} response serialisation failed: {e}"),
        diagnostics_id: None,
    })
}

fn map_settings_write_error(err: SettingsWriteError) -> IpcError {
    let code = match &err {
        SettingsWriteError::Invalid(_) => IpcErrorCode::PreconditionFailed,
        SettingsWriteError::Storage(_) => IpcErrorCode::Internal,
        SettingsWriteError::AccessDenied(_) => IpcErrorCode::Forbidden,
    };
    IpcError {
        code,
        message: err.to_string(),
        diagnostics_id: None,
    }
}

// ── Retention ────────────────────────────────────────────────────────────────

pub struct RetentionSettingsGetHandler {
    provider: Arc<dyn RetentionSettingsProvider>,
}

impl RetentionSettingsGetHandler {
    pub fn new(provider: Arc<dyn RetentionSettingsProvider>) -> Self {
        Self { provider }
    }
}

impl IpcHandler for RetentionSettingsGetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let _: RetentionSettingsGetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("settings.retention.get", e))?;
        serialise("settings.retention.get", self.provider.get())
    }
}

/// Retention is one policy for the machine's whole log and audit store, so a
/// change to it needs an administrator - but saving the settings page
/// unchanged must not, or the page becomes a UAC prompt for the very users the
/// restriction applies to. See `machine_scoped`.
pub struct RetentionSettingsSetHandler {
    writer: Arc<dyn RetentionSettingsWriter>,
    provider: Arc<dyn RetentionSettingsProvider>,
}

impl RetentionSettingsSetHandler {
    pub fn new(
        writer: Arc<dyn RetentionSettingsWriter>,
        provider: Arc<dyn RetentionSettingsProvider>,
    ) -> Self {
        Self { writer, provider }
    }
}

impl IpcHandler for RetentionSettingsSetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: RetentionSettingsSetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("settings.retention.set", e))?;
        if !crate::machine_scoped::machine_scoped_write_allowed(
            &retention_fields(&req),
            &retention_fields_of(&self.provider.get()),
            ctx.caller_is_elevated,
        ) {
            return Err(crate::machine_scoped::machine_scoped_refusal(
                "The retention policy",
            ));
        }
        match self.writer.set(&req) {
            Ok(dto) => serialise("settings.retention.set", dto),
            Err(e) => Err(map_settings_write_error(e)),
        }
    }
}

/// The fields a caller can actually set, in one comparable tuple. `updated_at`
/// and `last_cleanup_at` are the service's own bookkeeping and are deliberately
/// left out - comparing them would make every save look like a change.
fn retention_fields(req: &RetentionSettingsSetRequest) -> (u32, u32, u32, u32, u32, bool) {
    (
        req.superseded_days,
        req.superseded_count_cap,
        req.rejected_days,
        req.rolledback_days,
        req.rolledback_count_cap,
        req.pin_lkg,
    )
}

fn retention_fields_of(dto: &RetentionSettingsDto) -> (u32, u32, u32, u32, u32, bool) {
    (
        dto.superseded_days,
        dto.superseded_count_cap,
        dto.rejected_days,
        dto.rolledback_days,
        dto.rolledback_count_cap,
        dto.pin_lkg,
    )
}

// ── Log/audit retention config (#20) ─────────────────────────────────────────

pub struct LogRetentionConfigGetHandler {
    provider: Arc<dyn LogRetentionConfigProvider>,
}

impl LogRetentionConfigGetHandler {
    pub fn new(provider: Arc<dyn LogRetentionConfigProvider>) -> Self {
        Self { provider }
    }
}

impl IpcHandler for LogRetentionConfigGetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let _: LogRetentionConfigGetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("settings.log-retention.get", e))?;
        serialise("settings.log-retention.get", self.provider.get())
    }
}

/// Log and audit retention govern the machine's single log store, so the same
/// rule as `RetentionSettingsSetHandler` applies: echo freely, change with an
/// administrator.
pub struct LogRetentionConfigSetHandler {
    writer: Arc<dyn LogRetentionConfigWriter>,
    provider: Arc<dyn LogRetentionConfigProvider>,
}

impl LogRetentionConfigSetHandler {
    pub fn new(
        writer: Arc<dyn LogRetentionConfigWriter>,
        provider: Arc<dyn LogRetentionConfigProvider>,
    ) -> Self {
        Self { writer, provider }
    }
}

impl IpcHandler for LogRetentionConfigSetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: LogRetentionConfigSetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("settings.log-retention.set", e))?;
        // The same row drives the SCHEDULED audit pass, so accepting a value
        // under the floor would let a settings edit erase the audit trail the
        // product promises no user action can erase. Refused here, not clamped
        // silently, so the GUI can say why.
        if req.audit_max_age_days < nrr_diagnostics::MIN_AUDIT_MAX_AGE_DAYS
            || (req.audit_max_size_bytes > 0
                && req.audit_max_size_bytes < nrr_diagnostics::MIN_AUDIT_MAX_SIZE_BYTES)
        {
            return Err(IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: format!(
                    "audit retention must keep at least {} days and {} bytes",
                    nrr_diagnostics::MIN_AUDIT_MAX_AGE_DAYS,
                    nrr_diagnostics::MIN_AUDIT_MAX_SIZE_BYTES
                ),
                diagnostics_id: None,
            });
        }
        let current = self.provider.get();
        if !crate::machine_scoped::machine_scoped_write_allowed(
            &(
                req.log_max_age_days,
                req.log_max_size_bytes,
                req.audit_max_age_days,
                req.audit_max_size_bytes,
            ),
            &(
                current.log_max_age_days,
                current.log_max_size_bytes,
                current.audit_max_age_days,
                current.audit_max_size_bytes,
            ),
            ctx.caller_is_elevated,
        ) {
            return Err(crate::machine_scoped::machine_scoped_refusal(
                "The log and audit retention policy",
            ));
        }
        match self.writer.set(&req) {
            Ok(dto) => serialise("settings.log-retention.set", dto),
            Err(e) => Err(map_settings_write_error(e)),
        }
    }
}

// ── Apply failure policy ─────────────────────────────────────────────────────

pub struct ApplyFailurePolicyGetHandler {
    provider: Arc<dyn ApplyFailurePolicyProvider>,
}

impl ApplyFailurePolicyGetHandler {
    pub fn new(provider: Arc<dyn ApplyFailurePolicyProvider>) -> Self {
        Self { provider }
    }
}

impl IpcHandler for ApplyFailurePolicyGetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let _: ApplyFailurePolicyGetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("settings.apply-failure-policy.get", e))?;
        serialise("settings.apply-failure-policy.get", self.provider.get())
    }
}

/// Stored as a singleton - `set_by_sid` only records WHO wrote it - so the
/// policy governs every principal's applies, not just the caller's.
pub struct ApplyFailurePolicySetHandler {
    writer: Arc<dyn ApplyFailurePolicyWriter>,
    provider: Arc<dyn ApplyFailurePolicyProvider>,
}

impl ApplyFailurePolicySetHandler {
    pub fn new(
        writer: Arc<dyn ApplyFailurePolicyWriter>,
        provider: Arc<dyn ApplyFailurePolicyProvider>,
    ) -> Self {
        Self { writer, provider }
    }
}

impl IpcHandler for ApplyFailurePolicySetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: ApplyFailurePolicySetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("settings.apply-failure-policy.set", e))?;
        if !crate::machine_scoped::machine_scoped_write_allowed(
            &req.policy,
            &self.provider.get().policy,
            ctx.caller_is_elevated,
        ) {
            return Err(crate::machine_scoped::machine_scoped_refusal(
                "The apply-failure policy",
            ));
        }
        let sid = if ctx.caller_stored().is_empty() {
            None
        } else {
            Some(ctx.caller_stored())
        };
        match self.writer.set(&req.policy, sid) {
            Ok(dto) => serialise("settings.apply-failure-policy.set", dto),
            Err(e) => Err(map_settings_write_error(e)),
        }
    }
}

// ── Probing a suggestion against the main link ────────────────────────────────

pub struct AutoRuleCandidatesProbeHandler {
    runner: Arc<dyn crate::ipc_handlers::providers::AutoRuleProbeRunner>,
}

impl AutoRuleCandidatesProbeHandler {
    pub fn new(runner: Arc<dyn crate::ipc_handlers::providers::AutoRuleProbeRunner>) -> Self {
        Self { runner }
    }
}

impl IpcHandler for AutoRuleCandidatesProbeHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: nrr_shared::ipc_payloads::AutoRuleCandidatesProbeRequest =
            serde_json::from_value(request.payload.clone())
                .map_err(|e| malformed("autorules.candidates.probe", e))?;
        let sid = ctx.caller_stored();
        if sid.is_empty() {
            return Err(IpcError {
                code: IpcErrorCode::Internal,
                message: "autorules.candidates.probe: caller SID unavailable".into(),
                diagnostics_id: None,
            });
        }
        serialise(
            "autorules.candidates.probe",
            self.runner
                .probe(sid.as_ref(), &req.ids, &req.rule_hostnames),
        )
    }
}

// ── Sites that refuse main-link addresses ────────────────────────────────────

pub struct RefusingAnchorSetHandler {
    writer: Arc<dyn crate::ipc_handlers::providers::RefusingAnchorsWriter>,
}

impl RefusingAnchorSetHandler {
    pub fn new(writer: Arc<dyn crate::ipc_handlers::providers::RefusingAnchorsWriter>) -> Self {
        Self { writer }
    }
}

impl IpcHandler for RefusingAnchorSetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: nrr_shared::ipc_payloads::RefusingAnchorSetRequest =
            serde_json::from_value(request.payload.clone())
                .map_err(|e| malformed("autorules.refusing-anchor.set", e))?;
        let sid = ctx.caller_stored();
        if sid.is_empty() {
            return Err(IpcError {
                code: IpcErrorCode::Internal,
                message: "autorules.refusing-anchor.set: caller SID unavailable".into(),
                diagnostics_id: None,
            });
        }
        serialise(
            "autorules.refusing-anchor.set",
            self.writer.set(sid.as_ref(), &req.hostname, req.refusing),
        )
    }
}

// ── Local networks under the kill-switch ─────────────────────────────────────

pub struct LocalNetworksGetHandler {
    provider: Arc<dyn crate::ipc_handlers::providers::LocalNetworksProvider>,
}

impl LocalNetworksGetHandler {
    pub fn new(provider: Arc<dyn crate::ipc_handlers::providers::LocalNetworksProvider>) -> Self {
        Self { provider }
    }
}

impl IpcHandler for LocalNetworksGetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let _: nrr_shared::ipc_payloads::LocalNetworksGetRequest =
            serde_json::from_value(request.payload.clone())
                .map_err(|e| malformed("settings.local-networks.get", e))?;
        let sid = ctx.caller_stored();
        serialise(
            "settings.local-networks.get",
            self.provider.list(sid.as_ref()),
        )
    }
}

pub struct LocalNetworksSetHandler {
    provider: Arc<dyn crate::ipc_handlers::providers::LocalNetworksProvider>,
}

impl LocalNetworksSetHandler {
    pub fn new(provider: Arc<dyn crate::ipc_handlers::providers::LocalNetworksProvider>) -> Self {
        Self { provider }
    }
}

impl IpcHandler for LocalNetworksSetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: nrr_shared::ipc_payloads::LocalNetworksSetRequest =
            serde_json::from_value(request.payload.clone())
                .map_err(|e| malformed("settings.local-networks.set", e))?;
        // These exemptions are per-principal; an unattributable caller must not
        // be able to write into someone else's set (or into an empty-SID row
        // nothing would ever read).
        let sid = ctx.caller_stored();
        if sid.is_empty() {
            return Err(IpcError {
                code: IpcErrorCode::Internal,
                message: "settings.local-networks.set: caller SID unavailable".into(),
                diagnostics_id: None,
            });
        }
        serialise(
            "settings.local-networks.set",
            self.provider.set(sid.as_ref(), &req),
        )
    }
}

// ── Storage usage ────────────────────────────────────────────────────────────

pub struct StorageUsageGetHandler {
    provider: Arc<dyn StorageUsageProvider>,
}

impl StorageUsageGetHandler {
    pub fn new(provider: Arc<dyn StorageUsageProvider>) -> Self {
        Self { provider }
    }
}

impl IpcHandler for StorageUsageGetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let _: StorageUsageGetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("storage.usage.get", e))?;
        serialise("storage.usage.get", self.provider.measure())
    }
}

// ── Traffic stats ────────────────────────────────────────────────────────────

pub struct TrafficStatsGetHandler {
    provider: Arc<dyn TrafficStatsProvider>,
}

impl TrafficStatsGetHandler {
    pub fn new(provider: Arc<dyn TrafficStatsProvider>) -> Self {
        Self { provider }
    }
}

impl IpcHandler for TrafficStatsGetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: TrafficStatsGetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("traffic-stats.get", e))?;
        serialise("traffic-stats.get", self.provider.get(&req))
    }
}

pub struct TrafficStatsSetHandler {
    writer: Arc<dyn TrafficStatsWriter>,
}

impl TrafficStatsSetHandler {
    pub fn new(writer: Arc<dyn TrafficStatsWriter>) -> Self {
        Self { writer }
    }
}

impl IpcHandler for TrafficStatsSetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: TrafficStatsSetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("traffic-stats.set", e))?;
        // Accounting is machine-wide — the counters come from the adapters, not
        // from a user — so turning it off or shortening its history is a
        // decision for everyone. Unchanged saves still pass: the settings page
        // sends the whole row back whether or not the user touched this part.
        let current = self.writer.settings().map_err(map_settings_write_error)?;
        if !crate::machine_scoped::machine_scoped_write_allowed(
            &req.settings,
            &current,
            ctx.caller_is_elevated,
        ) {
            return Err(crate::machine_scoped::machine_scoped_refusal(
                "Traffic statistics",
            ));
        }
        match self.writer.set(&req.settings) {
            Ok(dto) => serialise("traffic-stats.set", dto),
            Err(e) => Err(map_settings_write_error(e)),
        }
    }
}

pub struct TrafficStatsClearHandler {
    writer: Arc<dyn TrafficStatsWriter>,
}

impl TrafficStatsClearHandler {
    pub fn new(writer: Arc<dyn TrafficStatsWriter>) -> Self {
        Self { writer }
    }
}

impl IpcHandler for TrafficStatsClearHandler {
    fn handle(&self, _request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        // No request body — reset unconditionally.
        match self.writer.clear() {
            Ok(dto) => serialise("traffic-stats.clear", dto),
            Err(e) => Err(map_settings_write_error(e)),
        }
    }
}

// ── Routing pause ────────────────────────────────────────────────────────────

pub struct RoutingPauseGetHandler {
    provider: Arc<dyn RoutingPauseProvider>,
}

impl RoutingPauseGetHandler {
    pub fn new(provider: Arc<dyn RoutingPauseProvider>) -> Self {
        Self { provider }
    }
}

impl IpcHandler for RoutingPauseGetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let _: RoutingPauseGetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("routing.pause.get", e))?;
        if ctx.caller_stored().is_empty() {
            return Err(IpcError {
                code: IpcErrorCode::Internal,
                message:
                    "caller SID unavailable; transport must populate IpcRequestContext.caller_stored()"
                        .into(),
                diagnostics_id: None,
            });
        }
        serialise("routing.pause.get", self.provider.get(ctx.caller_stored()))
    }
}

pub struct RoutingPauseToggleHandler {
    writer: Arc<dyn RoutingPauseWriter>,
}

impl RoutingPauseToggleHandler {
    pub fn new(writer: Arc<dyn RoutingPauseWriter>) -> Self {
        Self { writer }
    }
}

impl IpcHandler for RoutingPauseToggleHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: RoutingPauseToggleRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("routing.pause.toggle", e))?;
        if ctx.caller_stored().is_empty() {
            return Err(IpcError {
                code: IpcErrorCode::Internal,
                message:
                    "caller SID unavailable; transport must populate IpcRequestContext.caller_stored()"
                        .into(),
                diagnostics_id: None,
            });
        }
        match self
            .writer
            .toggle(ctx.caller_stored(), req.paused, req.reason.as_deref())
        {
            Ok(dto) => serialise("routing.pause.toggle", dto),
            Err(e) => Err(map_settings_write_error(e)),
        }
    }
}

// ── Autostart ────────────────────────────────────────────────────────────────

pub struct AutostartGetHandler {
    provider: Arc<dyn AutostartProvider>,
}

impl AutostartGetHandler {
    pub fn new(provider: Arc<dyn AutostartProvider>) -> Self {
        Self { provider }
    }
}

impl IpcHandler for AutostartGetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let _: AutostartGetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("autostart.get", e))?;
        serialise("autostart.get", self.provider.get())
    }
}

pub struct AutostartToggleHandler {
    writer: Arc<dyn AutostartWriter>,
}

impl AutostartToggleHandler {
    pub fn new(writer: Arc<dyn AutostartWriter>) -> Self {
        Self { writer }
    }
}

impl IpcHandler for AutostartToggleHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: AutostartToggleRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("autostart.toggle", e))?;
        match self.writer.toggle(req.enabled) {
            Ok(dto) => serialise("autostart.toggle", dto),
            Err(e) => Err(map_settings_write_error(e)),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::payloads::{
        ApplyFailurePolicyDto, AutostartDto, RetentionSettingsDto, RoutingPauseDto,
        StorageUsageDto, TrafficStatsSettingsDto,
    };
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use std::sync::Mutex;

    fn ctx(sid: &str) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: crate::UserPrincipal::from_windows_sid(sid).ok(),
            caller_pid: None,
        }
    }

    /// An ordinary, non-elevated caller - the everyday case for a settings
    /// page.
    fn plain_ctx(sid: &str) -> IpcRequestContext {
        IpcRequestContext {
            caller_is_elevated: false,
            ..ctx(sid)
        }
    }

    fn req(op: IpcOperationName, payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "req-1".into(),
            correlation_id: None,
            operation: op,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    // ── Traffic statistics ───────────────────────────────────────────────────

    struct FakeTrafficStats {
        current: TrafficStatsSettingsDto,
        written: Mutex<Vec<TrafficStatsSettingsDto>>,
    }

    impl TrafficStatsWriter for FakeTrafficStats {
        fn set(
            &self,
            settings: &TrafficStatsSettingsDto,
        ) -> Result<TrafficStatsSettingsDto, SettingsWriteError> {
            self.written
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(settings.clone());
            Ok(settings.clone())
        }
        fn clear(&self) -> Result<TrafficStatsSettingsDto, SettingsWriteError> {
            Ok(self.current.clone())
        }
        fn settings(&self) -> Result<TrafficStatsSettingsDto, SettingsWriteError> {
            Ok(self.current.clone())
        }
    }

    fn traffic_settings(enabled: bool, retention_days: u32) -> TrafficStatsSettingsDto {
        TrafficStatsSettingsDto {
            enabled,
            count_loopback: false,
            count_virtual: false,
            retention_days,
        }
    }

    fn traffic_handler(
        current: TrafficStatsSettingsDto,
    ) -> (TrafficStatsSetHandler, Arc<FakeTrafficStats>) {
        let fake = Arc::new(FakeTrafficStats {
            current,
            written: Mutex::new(Vec::new()),
        });
        (TrafficStatsSetHandler::new(fake.clone()), fake)
    }

    /// Accounting is machine-wide — the counters come from the adapters, not
    /// from a user — so turning it off or shortening its history decides for
    /// everyone. But the settings page sends the whole row back on every save,
    /// and an untouched save must not demand rights it does not need.
    #[test]
    fn traffic_settings_refuse_a_change_without_rights_and_allow_an_unchanged_save() {
        let current = traffic_settings(true, 90);

        let (handler, fake) = traffic_handler(current.clone());
        let err = handler
            .handle(
                &req(
                    IpcOperationName::TrafficStatsSet,
                    serde_json::json!({ "settings": traffic_settings(false, 90) }),
                ),
                &plain_ctx("S-1-5-21-1-1-1-1001"),
            )
            .expect_err("switching accounting off is a decision for the whole machine");
        assert_eq!(err.code, IpcErrorCode::Forbidden);
        assert!(
            fake.written
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty(),
            "a refused write must not reach the store"
        );

        let (handler, fake) = traffic_handler(current.clone());
        handler
            .handle(
                &req(
                    IpcOperationName::TrafficStatsSet,
                    serde_json::json!({ "settings": current }),
                ),
                &plain_ctx("S-1-5-21-1-1-1-1001"),
            )
            .expect("saving the row back unchanged is the everyday case");
        assert_eq!(
            fake.written.lock().unwrap_or_else(|p| p.into_inner()).len(),
            1
        );

        let (handler, fake) = traffic_handler(traffic_settings(true, 90));
        handler
            .handle(
                &req(
                    IpcOperationName::TrafficStatsSet,
                    serde_json::json!({ "settings": traffic_settings(false, 30) }),
                ),
                &ctx("S-1-5-21-1-1-1-1001"),
            )
            .expect("an administrator may change it");
        assert_eq!(
            fake.written.lock().unwrap_or_else(|p| p.into_inner()).len(),
            1
        );
    }

    // ── Retention ────────────────────────────────────────────────────────────

    struct FakeRetention {
        dto: RetentionSettingsDto,
    }

    impl RetentionSettingsProvider for FakeRetention {
        fn get(&self) -> RetentionSettingsDto {
            self.dto.clone()
        }
    }

    #[test]
    fn retention_get_returns_dto() {
        let dto = RetentionSettingsDto {
            superseded_days: 30,
            superseded_count_cap: 100,
            rejected_days: 7,
            rolledback_days: 14,
            rolledback_count_cap: 20,
            pin_lkg: true,
            last_cleanup_at: None,
            updated_at: 100,
        };
        let h = RetentionSettingsGetHandler::new(Arc::new(FakeRetention { dto: dto.clone() }));
        let value = h
            .handle(
                &req(
                    IpcOperationName::RetentionSettingsGet,
                    serde_json::json!({}),
                ),
                &ctx("S"),
            )
            .unwrap();
        let parsed: RetentionSettingsDto = serde_json::from_value(value).unwrap();
        assert_eq!(parsed, dto);
    }

    struct FakeRetentionWriter {
        last: Mutex<Option<RetentionSettingsSetRequest>>,
        force_invalid: bool,
    }
    impl RetentionSettingsWriter for FakeRetentionWriter {
        fn set(
            &self,
            request: &RetentionSettingsSetRequest,
        ) -> Result<RetentionSettingsDto, SettingsWriteError> {
            if self.force_invalid {
                return Err(SettingsWriteError::Invalid("out of range".into()));
            }
            *self.last.lock().unwrap() = Some(request.clone());
            Ok(RetentionSettingsDto {
                superseded_days: request.superseded_days,
                superseded_count_cap: request.superseded_count_cap,
                rejected_days: request.rejected_days,
                rolledback_days: request.rolledback_days,
                rolledback_count_cap: request.rolledback_count_cap,
                pin_lkg: request.pin_lkg,
                last_cleanup_at: None,
                updated_at: 200,
            })
        }
    }

    /// Retention is one policy for the machine's whole store. A non-elevated
    /// caller may still save the settings page - clients send the whole row
    /// back - but not actually change it.
    #[test]
    fn retention_change_without_elevation_is_refused_but_an_echo_is_not() {
        let current = RetentionSettingsDto {
            superseded_days: 30,
            superseded_count_cap: 100,
            rejected_days: 7,
            rolledback_days: 14,
            rolledback_count_cap: 20,
            pin_lkg: true,
            last_cleanup_at: None,
            updated_at: 100,
        };
        let writer = Arc::new(FakeRetentionWriter {
            last: Mutex::new(None),
            force_invalid: false,
        });
        let h = RetentionSettingsSetHandler::new(
            writer.clone(),
            Arc::new(FakeRetention {
                dto: current.clone(),
            }),
        );

        let echo = serde_json::json!({
            "superseded-days": 30,
            "superseded-count-cap": 100,
            "rejected-days": 7,
            "rolledback-days": 14,
            "rolledback-count-cap": 20,
            "pin-lkg": true,
        });
        assert!(
            h.handle(
                &req(IpcOperationName::RetentionSettingsSet, echo),
                &plain_ctx("S"),
            )
            .is_ok(),
            "saving the page unchanged must not need an administrator",
        );

        let change = serde_json::json!({
            "superseded-days": 1,
            "superseded-count-cap": 100,
            "rejected-days": 7,
            "rolledback-days": 14,
            "rolledback-count-cap": 20,
            "pin-lkg": true,
        });
        let err = h
            .handle(
                &req(IpcOperationName::RetentionSettingsSet, change),
                &plain_ctx("S"),
            )
            .expect_err("a real change needs an administrator");
        assert_eq!(err.code, IpcErrorCode::Forbidden);
    }

    #[test]
    fn retention_set_round_trips() {
        let w = Arc::new(FakeRetentionWriter {
            last: Mutex::new(None),
            force_invalid: false,
        });
        // The set path now also reads the current value, to tell an actual
        // change from a settings page saving itself back.
        let h = RetentionSettingsSetHandler::new(
            w.clone(),
            Arc::new(FakeRetention {
                dto: RetentionSettingsDto {
                    superseded_days: 30,
                    superseded_count_cap: 100,
                    rejected_days: 7,
                    rolledback_days: 14,
                    rolledback_count_cap: 20,
                    pin_lkg: true,
                    last_cleanup_at: None,
                    updated_at: 100,
                },
            }),
        );
        let payload = serde_json::json!({
            "superseded-days": 10,
            "superseded-count-cap": 50,
            "rejected-days": 5,
            "rolledback-days": 7,
            "rolledback-count-cap": 12,
            "pin-lkg": false,
        });
        let value = h
            .handle(
                &req(IpcOperationName::RetentionSettingsSet, payload),
                &ctx("S"),
            )
            .unwrap();
        let parsed: RetentionSettingsDto = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.superseded_days, 10);
        assert!(!parsed.pin_lkg);
        assert!(w.last.lock().unwrap().is_some());
    }

    #[test]
    fn retention_set_invalid_returns_precondition_failed() {
        let w = Arc::new(FakeRetentionWriter {
            last: Mutex::new(None),
            force_invalid: true,
        });
        let h = RetentionSettingsSetHandler::new(
            w,
            Arc::new(FakeRetention {
                dto: RetentionSettingsDto {
                    superseded_days: 30,
                    superseded_count_cap: 100,
                    rejected_days: 7,
                    rolledback_days: 14,
                    rolledback_count_cap: 20,
                    pin_lkg: true,
                    last_cleanup_at: None,
                    updated_at: 100,
                },
            }),
        );
        let payload = serde_json::json!({
            "superseded-days": 1,
            "superseded-count-cap": 1,
            "rejected-days": 1,
            "rolledback-days": 1,
            "rolledback-count-cap": 1,
            "pin-lkg": true,
        });
        let err = h
            .handle(
                &req(IpcOperationName::RetentionSettingsSet, payload),
                &ctx("S"),
            )
            .unwrap_err();
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
    }

    // ── Apply failure policy ─────────────────────────────────────────────────

    struct FakePolicy {
        dto: ApplyFailurePolicyDto,
    }
    impl ApplyFailurePolicyProvider for FakePolicy {
        fn get(&self) -> ApplyFailurePolicyDto {
            self.dto.clone()
        }
    }

    struct FakePolicyWriter {
        last: Mutex<Option<(String, Option<String>)>>,
    }
    impl ApplyFailurePolicyWriter for FakePolicyWriter {
        fn set(
            &self,
            slug: &str,
            sid: Option<&str>,
        ) -> Result<ApplyFailurePolicyDto, SettingsWriteError> {
            *self.last.lock().unwrap() = Some((slug.to_string(), sid.map(str::to_string)));
            Ok(ApplyFailurePolicyDto {
                policy: slug.to_string(),
                updated_at: 300,
                set_by_sid: sid.map(str::to_string),
            })
        }
    }

    #[test]
    fn apply_failure_policy_set_records_caller_sid() {
        let w = Arc::new(FakePolicyWriter {
            last: Mutex::new(None),
        });
        let h = ApplyFailurePolicySetHandler::new(
            w.clone(),
            Arc::new(FakePolicy {
                dto: ApplyFailurePolicyDto {
                    policy: "all-or-nothing".into(),
                    updated_at: 0,
                    set_by_sid: None,
                },
            }),
        );
        let payload = serde_json::json!({"policy": "best-effort"});
        let value = h
            .handle(
                &req(IpcOperationName::ApplyFailurePolicySet, payload),
                &ctx("S-1-5-21"),
            )
            .unwrap();
        let parsed: ApplyFailurePolicyDto = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.policy, "best-effort");
        let recorded = w.last.lock().unwrap().clone().unwrap();
        assert_eq!(recorded.0, "best-effort");
        assert_eq!(recorded.1.as_deref(), Some("S-1-5-21"));
    }

    #[test]
    fn apply_failure_policy_set_with_empty_sid_passes_none() {
        let w = Arc::new(FakePolicyWriter {
            last: Mutex::new(None),
        });
        let h = ApplyFailurePolicySetHandler::new(
            w.clone(),
            Arc::new(FakePolicy {
                dto: ApplyFailurePolicyDto {
                    policy: "all-or-nothing".into(),
                    updated_at: 0,
                    set_by_sid: None,
                },
            }),
        );
        let payload = serde_json::json!({"policy": "all-or-nothing"});
        let _ = h
            .handle(
                &req(IpcOperationName::ApplyFailurePolicySet, payload),
                &ctx(""),
            )
            .unwrap();
        let recorded = w.last.lock().unwrap().clone().unwrap();
        assert!(recorded.1.is_none());
    }

    // ── Storage usage ────────────────────────────────────────────────────────

    struct FakeUsage;
    impl StorageUsageProvider for FakeUsage {
        fn measure(&self) -> StorageUsageDto {
            StorageUsageDto {
                state_db_bytes: Some(1024),
                cache_db_bytes: Some(2048),
                operational_logs_bytes: 4096,
                audit_logs_bytes: 8192,
                total_bytes: 15360,
                scanned_at: 99,
            }
        }
    }

    #[test]
    fn storage_usage_returns_totals() {
        let h = StorageUsageGetHandler::new(Arc::new(FakeUsage));
        let value = h
            .handle(
                &req(IpcOperationName::StorageUsageGet, serde_json::json!({})),
                &ctx("S"),
            )
            .unwrap();
        let parsed: StorageUsageDto = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.total_bytes, 15360);
    }

    // ── Routing pause ────────────────────────────────────────────────────────

    struct FakePause;
    impl RoutingPauseProvider for FakePause {
        fn get(&self, sid: &str) -> RoutingPauseDto {
            RoutingPauseDto {
                sid: sid.into(),
                paused: false,
                paused_at: None,
                pause_reason: None,
                updated_at: 0,
            }
        }
    }

    #[test]
    fn routing_pause_get_requires_sid() {
        let h = RoutingPauseGetHandler::new(Arc::new(FakePause));
        let err = h
            .handle(
                &req(IpcOperationName::RoutingPauseGet, serde_json::json!({})),
                &ctx(""),
            )
            .unwrap_err();
        assert_eq!(err.code, IpcErrorCode::Internal);
    }

    struct FakePauseWriter {
        last: Mutex<Option<(String, bool, Option<String>)>>,
    }
    impl RoutingPauseWriter for FakePauseWriter {
        fn toggle(
            &self,
            sid: &str,
            paused: bool,
            reason: Option<&str>,
        ) -> Result<RoutingPauseDto, SettingsWriteError> {
            *self.last.lock().unwrap() = Some((sid.into(), paused, reason.map(str::to_string)));
            Ok(RoutingPauseDto {
                sid: sid.into(),
                paused,
                paused_at: if paused { Some(42) } else { None },
                pause_reason: reason.map(str::to_string),
                updated_at: 42,
            })
        }
    }

    #[test]
    fn routing_pause_toggle_round_trips() {
        let w = Arc::new(FakePauseWriter {
            last: Mutex::new(None),
        });
        let h = RoutingPauseToggleHandler::new(w.clone());
        let payload = serde_json::json!({"paused": true, "reason": "user request"});
        let value = h
            .handle(
                &req(IpcOperationName::RoutingPauseToggle, payload),
                &ctx("S-A"),
            )
            .unwrap();
        let parsed: RoutingPauseDto = serde_json::from_value(value).unwrap();
        assert!(parsed.paused);
        assert_eq!(parsed.pause_reason.as_deref(), Some("user request"));
    }

    // ── Autostart ────────────────────────────────────────────────────────────

    #[allow(dead_code)]
    struct FakeAutostart;
    impl AutostartProvider for FakeAutostart {
        fn get(&self) -> AutostartDto {
            AutostartDto {
                enabled: false,
                last_known_state: "absent".into(),
                overridden_value: None,
                updated_at: 0,
            }
        }
    }

    struct FakeAutostartWriter {
        last: Mutex<Option<bool>>,
    }
    impl AutostartWriter for FakeAutostartWriter {
        fn toggle(&self, enabled: bool) -> Result<AutostartDto, SettingsWriteError> {
            *self.last.lock().unwrap() = Some(enabled);
            Ok(AutostartDto {
                enabled,
                last_known_state: if enabled { "enabled" } else { "disabled" }.into(),
                overridden_value: None,
                updated_at: 99,
            })
        }
    }

    #[test]
    fn autostart_toggle_records_intent() {
        let w = Arc::new(FakeAutostartWriter {
            last: Mutex::new(None),
        });
        let h = AutostartToggleHandler::new(w.clone());
        let payload = serde_json::json!({"enabled": true});
        let value = h
            .handle(
                &req(IpcOperationName::AutostartToggle, payload),
                &ctx("S-A"),
            )
            .unwrap();
        let parsed: AutostartDto = serde_json::from_value(value).unwrap();
        assert!(parsed.enabled);
        assert_eq!(parsed.last_known_state, "enabled");
        assert_eq!(*w.last.lock().unwrap(), Some(true));
    }
}
