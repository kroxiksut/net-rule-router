//! Runs the real handler of every value-gated operation as an unelevated
//! caller: a change must be refused before it reaches storage, an echo of the
//! stored value must pass, and an administrator's change must pass.
//!
//! The operations come from [`MachineScopedSetting::written_by`] and each
//! setting's rig from an exhaustive match, so a new value-gated operation
//! cannot compile without a probe, and deleting a handler's check fails here.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
use nrr_shared::ipc_transport::canonical_operation_class;

use super::{machine_scoped_refusal, MachineScopedSetting};
use crate::ipc::{
    IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope, IPC_PROTOCOL_VERSION,
};
use crate::ipc_handlers::doh_resolvers::{DohResolverListStore, DohResolversSetHandler};
use crate::ipc_handlers::local_dns_suffixes::{
    LocalDnsSuffixStore, LocalDnsSuffixesSetHandler, NoLocalDnsSuffixContext,
};
use crate::ipc_handlers::payloads::{
    ApplyFailurePolicyDto, DohResolverEntryDto, LogRetentionConfigDto,
    LogRetentionConfigSetRequest, RetentionSettingsDto, RetentionSettingsSetRequest,
    ServiceStabilityConfigDto, TrafficStatsSettingsDto,
};
use crate::ipc_handlers::providers::{
    ApplyFailurePolicyProvider, ApplyFailurePolicyWriter, LogRetentionConfigProvider,
    LogRetentionConfigWriter, RetentionSettingsProvider, RetentionSettingsWriter,
    RoutePolicyWriteError, ServiceStabilityConfigProvider, ServiceStabilityConfigWriter,
    SettingsWriteError, TrafficStatsWriter,
};
use crate::ipc_handlers::service_stability_handlers::ServiceStabilityConfigSetHandler;
use crate::ipc_handlers::settings_handlers::{
    ApplyFailurePolicySetHandler, LogRetentionConfigSetHandler, RetentionSettingsSetHandler,
    TrafficStatsSetHandler,
};

/// One setting's real handler over a stored value, with payloads that echo
/// and that change it, and a count of writes that reached storage.
struct Rig {
    handler: Box<dyn IpcHandler>,
    echo: serde_json::Value,
    change: serde_json::Value,
    writes: Arc<AtomicUsize>,
}

fn rig(setting: MachineScopedSetting) -> Rig {
    let writes = Arc::new(AtomicUsize::new(0));
    let w = Arc::clone(&writes);
    match setting {
        MachineScopedSetting::DohResolvers => {
            let entry = |target: &str| DohResolverEntryDto {
                target_kind: "ip".into(),
                target: target.into(),
                comment: String::new(),
                enabled: true,
            };
            let stored = vec![entry("192.0.2.53")];
            let store = Arc::new(DohStore {
                stored: stored.clone(),
                writes: w,
            });
            Rig {
                handler: Box::new(DohResolversSetHandler::new(store, None)),
                echo: serde_json::json!({ "resolvers": stored }),
                change: serde_json::json!({ "resolvers": [entry("192.0.2.54")] }),
                writes,
            }
        }
        MachineScopedSetting::LocalDnsSuffixes => {
            let stored = vec!["lan".to_string()];
            let store = Arc::new(SuffixStore {
                stored: stored.clone(),
                writes: w,
            });
            Rig {
                handler: Box::new(LocalDnsSuffixesSetHandler::new(
                    store,
                    Arc::new(NoLocalDnsSuffixContext),
                )),
                echo: serde_json::json!({ "suffixes": stored }),
                change: serde_json::json!({ "suffixes": ["lan", "corp.example"] }),
                writes,
            }
        }
        MachineScopedSetting::Retention => {
            let stored = RetentionSettingsSetRequest {
                superseded_days: 30,
                superseded_count_cap: 100,
                rejected_days: 7,
                rolledback_days: 14,
                rolledback_count_cap: 20,
                pin_lkg: true,
            };
            let changed = RetentionSettingsSetRequest {
                superseded_days: 1,
                ..stored.clone()
            };
            let fake = Arc::new(Retention {
                stored: stored.clone(),
                writes: w,
            });
            Rig {
                handler: Box::new(RetentionSettingsSetHandler::new(fake.clone(), fake)),
                echo: to_json(&stored),
                change: to_json(&changed),
                writes,
            }
        }
        MachineScopedSetting::LogRetention => {
            let stored = LogRetentionConfigSetRequest {
                log_max_age_days: 14,
                log_max_size_bytes: 0,
                audit_max_age_days: 365,
                audit_max_size_bytes: 0,
            };
            // Above the audit floor, so only the gate can refuse it.
            let changed = LogRetentionConfigSetRequest {
                audit_max_age_days: 400,
                ..stored.clone()
            };
            let fake = Arc::new(LogRetention {
                stored: stored.clone(),
                writes: w,
            });
            Rig {
                handler: Box::new(LogRetentionConfigSetHandler::new(fake.clone(), fake)),
                echo: to_json(&stored),
                change: to_json(&changed),
                writes,
            }
        }
        MachineScopedSetting::ApplyFailurePolicy => {
            let fake = Arc::new(ApplyFailurePolicy {
                stored: "all-or-nothing",
                writes: w,
            });
            Rig {
                handler: Box::new(ApplyFailurePolicySetHandler::new(fake.clone(), fake)),
                echo: serde_json::json!({ "policy": "all-or-nothing" }),
                change: serde_json::json!({ "policy": "best-effort" }),
                writes,
            }
        }
        MachineScopedSetting::ServiceStability => {
            let stored = ServiceStabilityConfigDto::default();
            // A machine-wide field that is not the rules lock, which has its
            // own refusal.
            let changed = ServiceStabilityConfigDto {
                fake_ip_enabled: !stored.fake_ip_enabled,
                ..stored.clone()
            };
            let fake = Arc::new(ServiceStability {
                stored: stored.clone(),
                writes: w,
            });
            Rig {
                handler: Box::new(ServiceStabilityConfigSetHandler::new(fake.clone(), fake)),
                echo: serde_json::json!({ "config": stored }),
                change: serde_json::json!({ "config": changed }),
                writes,
            }
        }
        MachineScopedSetting::TrafficStats => {
            let stored = TrafficStatsSettingsDto {
                enabled: true,
                count_loopback: false,
                count_virtual: false,
                retention_days: 90,
            };
            let changed = TrafficStatsSettingsDto {
                enabled: false,
                ..stored.clone()
            };
            let fake = Arc::new(TrafficStats {
                stored: stored.clone(),
                writes: w,
            });
            Rig {
                handler: Box::new(TrafficStatsSetHandler::new(fake)),
                echo: serde_json::json!({ "settings": stored }),
                change: serde_json::json!({ "settings": changed }),
                writes,
            }
        }
    }
}

fn to_json(value: &impl serde::Serialize) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

fn ctx(elevated: bool) -> IpcRequestContext {
    IpcRequestContext {
        client_profile: IpcClientProfile::GuiInteractive,
        caller_is_elevated: elevated,
        caller_principal: crate::UserPrincipal::from_windows_sid("S-1-5-21-10-20-30-1001").ok(),
        caller_pid: None,
    }
}

fn envelope(op: IpcOperationName, payload: serde_json::Value) -> IpcRequestEnvelope {
    IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "probe".into(),
        correlation_id: None,
        operation: op,
        operation_class: canonical_operation_class(op, &payload),
        confirmation_token: None,
        payload,
    }
}

fn value_gated_settings() -> Vec<MachineScopedSetting> {
    IpcOperationName::ALL
        .into_iter()
        .filter_map(MachineScopedSetting::written_by)
        .collect()
}

#[test]
fn every_value_gated_write_refuses_an_unelevated_change() {
    let settings = value_gated_settings();
    assert!(!settings.is_empty(), "no value-gated operation found");
    for setting in settings {
        let op = setting.operation();
        let rig = rig(setting);
        let outcome = rig
            .handler
            .handle(&envelope(op, rig.change.clone()), &ctx(false));
        assert_eq!(
            outcome,
            Err(machine_scoped_refusal(setting)),
            "{}: an unelevated change must get the typed machine-scoped refusal",
            op.slug()
        );
        assert_eq!(
            rig.writes.load(Ordering::SeqCst),
            0,
            "{}: a refused change reached storage",
            op.slug()
        );
    }
}

#[test]
fn every_value_gated_write_takes_an_unelevated_echo() {
    for setting in value_gated_settings() {
        let op = setting.operation();
        let rig = rig(setting);
        let outcome = rig
            .handler
            .handle(&envelope(op, rig.echo.clone()), &ctx(false));
        assert!(
            outcome.is_ok(),
            "{}: saving the stored value back must not need an administrator: {outcome:?}",
            op.slug()
        );
        assert_eq!(rig.writes.load(Ordering::SeqCst), 1, "{}", op.slug());
    }
}

/// Without this the refusal above could come from anything but the gate.
#[test]
fn every_value_gated_write_takes_an_administrators_change() {
    for setting in value_gated_settings() {
        let op = setting.operation();
        let rig = rig(setting);
        let outcome = rig
            .handler
            .handle(&envelope(op, rig.change.clone()), &ctx(true));
        assert!(
            outcome.is_ok(),
            "{}: an elevated caller may change it: {outcome:?}",
            op.slug()
        );
        assert_eq!(rig.writes.load(Ordering::SeqCst), 1, "{}", op.slug());
    }
}

#[test]
fn the_refusal_code_is_forbidden_for_every_setting() {
    for setting in value_gated_settings() {
        assert_eq!(
            machine_scoped_refusal(setting).code,
            IpcErrorCode::Forbidden,
            "{}",
            setting.operation().slug()
        );
    }
}

// ── Fakes: one stored value each, counting writes ───────────────────────────

struct DohStore {
    stored: Vec<DohResolverEntryDto>,
    writes: Arc<AtomicUsize>,
}

impl DohResolverListStore for DohStore {
    fn get_all(&self) -> Result<Vec<DohResolverEntryDto>, RoutePolicyWriteError> {
        Ok(self.stored.clone())
    }
    fn replace_all(
        &self,
        entries: &[DohResolverEntryDto],
    ) -> Result<Vec<DohResolverEntryDto>, RoutePolicyWriteError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(entries.to_vec())
    }
}

struct SuffixStore {
    stored: Vec<String>,
    writes: Arc<AtomicUsize>,
}

impl LocalDnsSuffixStore for SuffixStore {
    fn get_all(&self) -> Result<Vec<String>, RoutePolicyWriteError> {
        Ok(self.stored.clone())
    }
    fn replace_all(&self, suffixes: &[String]) -> Result<Vec<String>, RoutePolicyWriteError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(suffixes.to_vec())
    }
}

struct Retention {
    stored: RetentionSettingsSetRequest,
    writes: Arc<AtomicUsize>,
}

fn retention_dto(r: &RetentionSettingsSetRequest) -> RetentionSettingsDto {
    RetentionSettingsDto {
        superseded_days: r.superseded_days,
        superseded_count_cap: r.superseded_count_cap,
        rejected_days: r.rejected_days,
        rolledback_days: r.rolledback_days,
        rolledback_count_cap: r.rolledback_count_cap,
        pin_lkg: r.pin_lkg,
        last_cleanup_at: None,
        updated_at: 1,
    }
}

impl RetentionSettingsProvider for Retention {
    fn get(&self) -> RetentionSettingsDto {
        retention_dto(&self.stored)
    }
}

impl RetentionSettingsWriter for Retention {
    fn set(
        &self,
        request: &RetentionSettingsSetRequest,
    ) -> Result<RetentionSettingsDto, SettingsWriteError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(retention_dto(request))
    }
}

struct LogRetention {
    stored: LogRetentionConfigSetRequest,
    writes: Arc<AtomicUsize>,
}

fn log_retention_dto(r: &LogRetentionConfigSetRequest) -> LogRetentionConfigDto {
    LogRetentionConfigDto {
        log_max_age_days: r.log_max_age_days,
        log_max_size_bytes: r.log_max_size_bytes,
        audit_max_age_days: r.audit_max_age_days,
        audit_max_size_bytes: r.audit_max_size_bytes,
        updated_at: 1,
    }
}

impl LogRetentionConfigProvider for LogRetention {
    fn get(&self) -> LogRetentionConfigDto {
        log_retention_dto(&self.stored)
    }
}

impl LogRetentionConfigWriter for LogRetention {
    fn set(
        &self,
        request: &LogRetentionConfigSetRequest,
    ) -> Result<LogRetentionConfigDto, SettingsWriteError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(log_retention_dto(request))
    }
}

struct ApplyFailurePolicy {
    stored: &'static str,
    writes: Arc<AtomicUsize>,
}

impl ApplyFailurePolicyProvider for ApplyFailurePolicy {
    fn get(&self) -> ApplyFailurePolicyDto {
        ApplyFailurePolicyDto {
            policy: self.stored.to_string(),
            updated_at: 1,
        }
    }
}

impl ApplyFailurePolicyWriter for ApplyFailurePolicy {
    fn set(
        &self,
        policy_slug: &str,
        _set_by_sid: Option<&str>,
    ) -> Result<ApplyFailurePolicyDto, SettingsWriteError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(ApplyFailurePolicyDto {
            policy: policy_slug.to_string(),
            updated_at: 2,
        })
    }
}

struct ServiceStability {
    stored: ServiceStabilityConfigDto,
    writes: Arc<AtomicUsize>,
}

impl ServiceStabilityConfigProvider for ServiceStability {
    fn get(&self) -> ServiceStabilityConfigDto {
        self.stored.clone()
    }
}

impl ServiceStabilityConfigWriter for ServiceStability {
    fn set(
        &self,
        dto: &ServiceStabilityConfigDto,
        _set_by_sid: Option<&str>,
    ) -> Result<ServiceStabilityConfigDto, SettingsWriteError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(dto.clone())
    }
}

struct TrafficStats {
    stored: TrafficStatsSettingsDto,
    writes: Arc<AtomicUsize>,
}

impl TrafficStatsWriter for TrafficStats {
    fn set(
        &self,
        settings: &TrafficStatsSettingsDto,
    ) -> Result<TrafficStatsSettingsDto, SettingsWriteError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(settings.clone())
    }
    fn clear(&self) -> Result<TrafficStatsSettingsDto, SettingsWriteError> {
        Ok(self.stored.clone())
    }
    fn settings(&self) -> Result<TrafficStatsSettingsDto, SettingsWriteError> {
        Ok(self.stored.clone())
    }
    fn set_history_link(
        &self,
        _old_key: &str,
        _new_key: &str,
        _merged: bool,
    ) -> Result<(), SettingsWriteError> {
        Ok(())
    }
}
