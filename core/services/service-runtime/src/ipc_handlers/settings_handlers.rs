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
    RetentionSettingsGetRequest, RetentionSettingsSetRequest, RoutingPauseGetRequest,
    RoutingPauseToggleRequest, StorageUsageGetRequest, TrafficStatsGetRequest,
    TrafficStatsSetRequest,
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

pub struct RetentionSettingsSetHandler {
    writer: Arc<dyn RetentionSettingsWriter>,
}

impl RetentionSettingsSetHandler {
    pub fn new(writer: Arc<dyn RetentionSettingsWriter>) -> Self {
        Self { writer }
    }
}

impl IpcHandler for RetentionSettingsSetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: RetentionSettingsSetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("settings.retention.set", e))?;
        match self.writer.set(&req) {
            Ok(dto) => serialise("settings.retention.set", dto),
            Err(e) => Err(map_settings_write_error(e)),
        }
    }
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

pub struct LogRetentionConfigSetHandler {
    writer: Arc<dyn LogRetentionConfigWriter>,
}

impl LogRetentionConfigSetHandler {
    pub fn new(writer: Arc<dyn LogRetentionConfigWriter>) -> Self {
        Self { writer }
    }
}

impl IpcHandler for LogRetentionConfigSetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: LogRetentionConfigSetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("settings.log-retention.set", e))?;
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

pub struct ApplyFailurePolicySetHandler {
    writer: Arc<dyn ApplyFailurePolicyWriter>,
}

impl ApplyFailurePolicySetHandler {
    pub fn new(writer: Arc<dyn ApplyFailurePolicyWriter>) -> Self {
        Self { writer }
    }
}

impl IpcHandler for ApplyFailurePolicySetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: ApplyFailurePolicySetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("settings.apply-failure-policy.set", e))?;
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
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: TrafficStatsSetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("traffic-stats.set", e))?;
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
        ApplyFailurePolicyDto, AutostartDto, RetentionSettingsDto, RoutingPauseDto, StorageUsageDto,
    };
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use std::sync::Mutex;

    fn ctx(sid: &str) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: crate::UserPrincipal::from_windows_sid(sid).ok(),
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

    #[test]
    fn retention_set_round_trips() {
        let w = Arc::new(FakeRetentionWriter {
            last: Mutex::new(None),
            force_invalid: false,
        });
        let h = RetentionSettingsSetHandler::new(w.clone());
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
        let h = RetentionSettingsSetHandler::new(w);
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

    #[allow(dead_code)]
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
        let h = ApplyFailurePolicySetHandler::new(w.clone());
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
        let h = ApplyFailurePolicySetHandler::new(w.clone());
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
