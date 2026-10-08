//! The screen's calls, run on the jobs thread. Each one reads or writes
//! through the operation the GUI uses and hands back what changes on screen.

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use nrr_client_logic::{route_policy, stability};
use nrr_ipc_client::{ipc_operation_timeout, IpcClient};
use nrr_platform_api::service_control::ServiceControlError;
use nrr_shared::ipc::IpcOperationName as Op;
use nrr_shared::ipc_payloads::{
    ApplyFailurePolicyDto, BlockNoticeMuteDto, BlockNoticeMuteScopeDto, BlockNoticeMutesListResponse,
    LogRetentionConfigDto, LogRetentionConfigSetRequest, LogsClearResponse, RetentionSettingsDto,
    RetentionSettingsSetRequest, SettingsExportFullResponse, StorageUsageDto, TrafficStatsGetResponse,
    TrafficStatsSettingsDto,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};

use super::items::Words;
use super::{text, Failure, Loadable, ServiceInfo};
use crate::backend::{Job, RegistrationProbe, Reply};
use crate::state::AppState;

/// How long a start or a stop may take before the screen says so.
const SERVICE_WAIT: Duration = Duration::from_secs(30);
/// Written into the service's log with every stability write.
const ORIGIN: &str = "user:tui";

fn call(client: &dyn IpcClient, op: Op, payload: Value) -> Result<Value, Failure> {
    client
        .call(op, payload, ipc_operation_timeout(op))
        .map_err(|e| Failure::from_ipc(&e))
}

fn read<T: DeserializeOwned>(client: &dyn IpcClient, op: Op, payload: Value) -> Result<T, Failure> {
    let value = call(client, op, payload)?;
    serde_json::from_value(value).map_err(|e| Failure {
        slug: "bad-response".to_owned(),
        elevation: false,
        detail: e.to_string(),
    })
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn loaded<T>(result: Result<T, Failure>) -> Loadable<T> {
    match result {
        Ok(value) => Loadable::Ready(value),
        Err(failure) => Loadable::Failed(failure),
    }
}

fn job(run: impl FnOnce(&dyn IpcClient) -> Reply + Send + 'static) -> Job {
    Box::new(run)
}

/// A write's outcome: on success `apply` stores what came back and the screen
/// says `done`; on failure nothing is stored and the screen says why.
fn written<T: Send + 'static>(
    result: Result<T, Failure>,
    done: Words,
    apply: impl FnOnce(&mut AppState, T) + Send + 'static,
) -> Reply {
    Reply::new(move |app| match result {
        Ok(value) => {
            apply(app, value);
            app.settings.done(done);
        }
        Err(failure) => app.settings.failed(text::NOT_SAVED, failure),
    })
}

// ── Reads ────────────────────────────────────────────────────────────────────

/// The live `route-policy`, raw: a write echoes back every field it carries.
fn policy_of(client: &dyn IpcClient) -> Result<Map<String, Value>, Failure> {
    let snapshot = call(client, Op::SnapshotInitialGet, json!({}))?;
    Ok(object(snapshot.get("route-policy").cloned().unwrap_or(Value::Null)))
}

pub fn load_policy() -> Job {
    job(|client| {
        let result = loaded(policy_of(client));
        Reply::new(move |app| app.settings.data.policy = result)
    })
}

pub fn load_stability() -> Job {
    job(|client| {
        let result = loaded(call(client, Op::ServiceStabilityConfigGet, json!({})).map(object));
        Reply::new(move |app| app.settings.data.stability = result)
    })
}

pub fn load_mutes() -> Job {
    job(|client| {
        let result = loaded(
            read::<BlockNoticeMutesListResponse>(client, Op::BlockNoticeMutesList, json!({}))
                .map(|r| r.mutes),
        );
        Reply::new(move |app| app.settings.data.mutes = result)
    })
}

pub fn load_failure_policy() -> Job {
    job(|client| {
        let result = loaded(
            read::<ApplyFailurePolicyDto>(client, Op::ApplyFailurePolicyGet, json!({}))
                .map(|p| p.policy),
        );
        Reply::new(move |app| app.settings.data.failure_policy = result)
    })
}

pub fn load_retention() -> Job {
    job(|client| {
        let result = loaded(read::<RetentionSettingsDto>(
            client,
            Op::RetentionSettingsGet,
            json!({}),
        ));
        Reply::new(move |app| app.settings.data.retention = result)
    })
}

pub fn load_log_retention() -> Job {
    job(|client| {
        let result = loaded(read::<LogRetentionConfigDto>(
            client,
            Op::LogRetentionConfigGet,
            json!({}),
        ));
        Reply::new(move |app| app.settings.data.log_retention = result)
    })
}

pub fn load_storage() -> Job {
    job(|client| {
        let result = loaded(read::<StorageUsageDto>(client, Op::StorageUsageGet, json!({})));
        Reply::new(move |app| app.settings.data.storage = result)
    })
}

fn traffic_of(client: &dyn IpcClient, day: i64) -> Result<TrafficStatsGetResponse, Failure> {
    read(client, Op::TrafficStatsGet, json!({ "day": day }))
}

pub fn load_traffic(day: i64) -> Job {
    job(move |client| {
        let result = loaded(traffic_of(client, day));
        Reply::new(move |app| app.settings.data.traffic = result)
    })
}

fn service_failure(error: &ServiceControlError) -> Failure {
    match error {
        ServiceControlError::AccessDenied => Failure::elevation(),
        other => Failure::detail(other.to_string()),
    }
}

fn query_service(probe: RegistrationProbe) -> Result<ServiceInfo, Failure> {
    let Some(port) = probe() else {
        return Ok(ServiceInfo::NoManager);
    };
    match port.query() {
        Ok(None) => Ok(ServiceInfo::NotInstalled),
        Ok(Some(report)) => Ok(ServiceInfo::Registered(report)),
        Err(ServiceControlError::NotInstalled) => Ok(ServiceInfo::NotInstalled),
        Err(error) => Err(service_failure(&error)),
    }
}

/// Asks the service manager, not the service: the question matters most when
/// the service does not answer.
pub fn load_service(probe: RegistrationProbe) -> Job {
    job(move |_| {
        let result = loaded(query_service(probe));
        Reply::new(move |app| app.settings.data.service = result)
    })
}

// ── Writes ───────────────────────────────────────────────────────────────────

/// The contract's mode, for a policy row that names none yet.
fn default_mode() -> &'static str {
    match route_policy::field_default("mode") {
        Some(route_policy::FieldDefault::Text(mode)) => mode,
        _ => "prefer-primary",
    }
}

/// `route.policy.update` replaces the whole row, so it is built on a fresh
/// read; a failed read sends nothing, since the defaults would switch the
/// user's protections off.
pub fn write_policy(changes: Map<String, Value>) -> Job {
    job(move |client| {
        let result = (|| {
            let current = policy_of(client)?;
            let base = route_policy::build_full_update_request(&current, default_mode());
            let mut request = base.clone();
            request.extend(changes);
            // Only what changed: a whole row would revert what the tray wrote since.
            let Some(named) = route_policy::name_changes(&base, request.clone()) else {
                return Ok(current);
            };
            call(client, Op::RoutePolicyUpdate, Value::Object(named))?;
            Ok(policy_of(client).unwrap_or(request))
        })();
        written(result, Words::Key(text::SAVED), |app, policy| {
            app.settings.data.policy = Loadable::Ready(policy);
        })
    })
}

/// The stability row is replaced whole too: the live row, with this change.
pub fn write_stability(partial: Map<String, Value>) -> Job {
    job(move |client| {
        let result = (|| {
            let live = object(call(client, Op::ServiceStabilityConfigGet, json!({}))?);
            let config = stability::merge_write(&live, &Map::new(), &Map::new(), &partial);
            let answer = call(
                client,
                Op::ServiceStabilityConfigSet,
                json!({ "config": config, "origin": ORIGIN }),
            )?;
            Ok(match answer {
                Value::Object(map) => map,
                _ => config,
            })
        })();
        written(result, Words::Key(text::SAVED), |app, config| {
            app.settings.data.stability = Loadable::Ready(config);
        })
    })
}

pub fn set_mute(request: Value, from_form: bool) -> Job {
    job(move |client| {
        let result = read::<BlockNoticeMutesListResponse>(client, Op::BlockNoticeMutesSet, request)
            .map(|r| r.mutes);
        let done = Words::Key(if from_form { text::MUTE_ADDED } else { text::SAVED });
        written(result, done, move |app, mutes| {
            app.settings.data.mutes = Loadable::Ready(mutes);
            if from_form {
                app.settings.mute_form.target.clear();
            }
        })
    })
}

/// Lifts each mute in turn: clearing them all would also show again the
/// notice kinds the table above hides.
pub fn remove_mutes(scopes: Vec<BlockNoticeMuteScopeDto>) -> Job {
    job(move |client| {
        let result = (|| {
            let mut mutes: Option<Vec<BlockNoticeMuteDto>> = None;
            for scope in scopes {
                let answer: BlockNoticeMutesListResponse =
                    read(client, Op::BlockNoticeMutesRemove, json!({ "scope": scope }))?;
                mutes = Some(answer.mutes);
            }
            Ok(mutes)
        })();
        written(result, Words::Key(text::SAVED), |app, mutes| {
            if let Some(mutes) = mutes {
                app.settings.data.mutes = Loadable::Ready(mutes);
            }
        })
    })
}

pub fn set_failure_policy(policy: &'static str) -> Job {
    job(move |client| {
        let result = read::<ApplyFailurePolicyDto>(
            client,
            Op::ApplyFailurePolicySet,
            json!({ "policy": policy }),
        )
        .map(|p| p.policy);
        written(result, Words::Key(text::SAVED), |app, policy| {
            app.settings.data.failure_policy = Loadable::Ready(policy);
        })
    })
}

pub fn set_retention(request: RetentionSettingsSetRequest) -> Job {
    job(move |client| {
        let result = serde_json::to_value(&request)
            .map_err(|e| Failure::detail(e.to_string()))
            .and_then(|payload| read::<RetentionSettingsDto>(client, Op::RetentionSettingsSet, payload));
        written(result, Words::Key(text::SAVED), |app, settings| {
            app.settings.data.retention = Loadable::Ready(settings);
        })
    })
}

pub fn set_log_retention(request: LogRetentionConfigSetRequest) -> Job {
    job(move |client| {
        let result = serde_json::to_value(&request)
            .map_err(|e| Failure::detail(e.to_string()))
            .and_then(|payload| {
                read::<LogRetentionConfigDto>(client, Op::LogRetentionConfigSet, payload)
            });
        written(result, Words::Key(text::SAVED), |app, config| {
            app.settings.data.log_retention = Loadable::Ready(config);
        })
    })
}

/// Clears the operational logs only; the audit trail is never touched here.
pub fn clear_logs() -> Job {
    job(|client| {
        let result = read::<LogsClearResponse>(
            client,
            Op::LogsClear,
            json!({ "dry-run": false, "include-archives": false }),
        );
        let storage = loaded(read::<StorageUsageDto>(client, Op::StorageUsageGet, json!({})));
        Reply::new(move |app| match result {
            Ok(cleared) => {
                app.settings.data.storage = storage;
                app.settings.done(Words::Fill(
                    text::LOGS_CLEARED,
                    vec![
                        ("count", cleared.files_deleted.to_string()),
                        (
                            "size",
                            nrr_client_logic::units::format_storage_bytes(cleared.bytes_freed),
                        ),
                    ],
                ));
            }
            Err(failure) => app.settings.failed(text::NOT_SAVED, failure),
        })
    })
}

pub fn set_traffic(settings: TrafficStatsSettingsDto, day: i64) -> Job {
    job(move |client| {
        let result = call(client, Op::TrafficStatsSet, json!({ "settings": settings }))
            .and_then(|_| traffic_of(client, day));
        written(result, Words::Key(text::SAVED), |app, stats| {
            app.settings.data.traffic = Loadable::Ready(stats);
        })
    })
}

pub fn clear_traffic(day: i64) -> Job {
    job(move |client| {
        let result =
            call(client, Op::TrafficStatsClear, json!({})).and_then(|_| traffic_of(client, day));
        written(result, Words::Key(text::TRAFFIC_RESET_DONE), |app, stats| {
            app.settings.data.traffic = Loadable::Ready(stats);
        })
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceOp {
    Start,
    Stop,
    Restart,
}

/// Runs a start or a stop through the service manager with the rights the
/// terminal has; without them the answer says how to get them.
pub fn control_service(op: ServiceOp, probe: RegistrationProbe) -> Job {
    job(move |_| {
        let outcome = match probe() {
            None => Err(Failure::detail(String::new())),
            Some(port) => match op {
                ServiceOp::Start => port.start(SERVICE_WAIT),
                ServiceOp::Stop => port.stop(SERVICE_WAIT),
                ServiceOp::Restart => port.restart(SERVICE_WAIT),
            }
            .map_err(|e| service_failure(&e)),
        };
        let after = loaded(query_service(probe));
        Reply::new(move |app| {
            match outcome {
                Ok(()) => {
                    let state = match &after {
                        Loadable::Ready(ServiceInfo::Registered(report)) => {
                            super::items::run_state_word(report.run_state).0
                        }
                        _ => text::RUN_UNKNOWN,
                    };
                    app.settings.done(Words::FillWords(
                        text::SERVICE_DONE,
                        vec![("state", Words::Key(state))],
                    ));
                }
                Err(failure) if failure.detail.is_empty() && !failure.elevation => {
                    app.settings.refuse(Words::Key(text::SERVICE_NO_MANAGER));
                }
                Err(failure) => app.settings.failed(text::NOT_SAVED, failure),
            }
            app.settings.data.service = after;
        })
    })
}

enum ExportError {
    Service(Failure),
    Exists,
    Write(String),
}

/// Writes the service's YAML to a new file; an existing file is never
/// overwritten.
fn export_to(client: &dyn IpcClient, path: &std::path::Path) -> Result<(), ExportError> {
    let answer: SettingsExportFullResponse =
        read(client, Op::SettingsExportFull, json!({})).map_err(ExportError::Service)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(answer.yaml_bytes_b64.as_bytes())
        .map_err(|e| {
            ExportError::Service(Failure {
                slug: "bad-response".to_owned(),
                elevation: false,
                detail: e.to_string(),
            })
        })?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                ExportError::Exists
            } else {
                ExportError::Write(e.to_string())
            }
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.flush())
        .map_err(|e| ExportError::Write(e.to_string()))
}

pub fn export_settings(path: PathBuf) -> Job {
    job(move |client| {
        let outcome = export_to(client, &path);
        let shown = path.display().to_string();
        Reply::new(move |app| match outcome {
            Ok(()) => app
                .settings
                .done(Words::Fill(text::EXPORT_DONE, vec![("path", shown)])),
            Err(ExportError::Exists) => app
                .settings
                .refuse(Words::Fill(text::EXPORT_EXISTS, vec![("path", shown)])),
            Err(ExportError::Write(error)) => app.settings.failed(
                text::EXPORT_WRITE_FAILED,
                Failure::detail(error),
            ),
            Err(ExportError::Service(failure)) => app.settings.failed(text::NOT_SAVED, failure),
        })
    })
}
