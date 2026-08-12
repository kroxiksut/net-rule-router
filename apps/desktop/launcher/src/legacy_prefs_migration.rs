//! GUI-driven migration of legacy `UiPreferences` policy fields into
//! service-owned per-SID storage.
//!
//! ## Flow
//!
//! 1. `MigrationStatusGet { migration_id: "legacy_preferences_v1" }` —
//!    if the service reports the migration as completed for the caller's
//!    SID, return [`MigrationOutcome::AlreadyDone`] without touching
//!    preferences.
//! 2. If not completed and [`UiPreferences`] carries non-default
//!    legacy policy fields ([`has_legacy_policy_fields`] returns
//!    `true`), pack a [`RoutePolicyUpdateRequest`] with
//!    `binding_source = MigratedFromPreferences` and call
//!    `RoutePolicyUpdate`.
//! 3. On success, call `MigrationMarkComplete` with a small JSON
//!    detail that records what was migrated (mostly for audit).
//! 4. Zero the in-memory legacy fields via
//!    [`cleanup_legacy_policy_fields`]. The launcher persists the
//!    cleaned-up [`UiPreferences`] on the next save (it already does
//!    this on every `NRR_PREFS_JSON:` round-trip).
//!
//! ## Idempotency / failure handling
//!
//! - If the IPC client is not connected (`ConnectionStatus != Connected`),
//!   the helper returns [`MigrationOutcome::Skipped`] with reason
//!   `"ipc-not-connected"` so the next launcher start retries.
//! - Any IPC error during steps 1–3 surfaces as
//!   [`MigrationOutcome::Failed`] with a typed reason. The helper
//!   guarantees that on `Failed` the legacy fields are **not** zeroed;
//!   the next start retries from step 1.
//! - If the user has no legacy policy data (nothing to migrate), the
//!   helper still calls `MigrationMarkComplete` so subsequent starts
//!   short-circuit at step 1.
//!
//! ## Wiring status
//!
//! The helper is library-grade (no I/O outside the injected
//! `IpcClient`) and unit-tested with a fake client. The production call
//! from `launcher::run_primary` is not yet wired in; once the IPC client
//! is available past launcher startup, call
//! `run_legacy_preferences_migration` between
//! `load_preferences_with_fallback` and `emit_context`.

use std::time::Duration;

use nrr_ipc_client::{ConnectionStatus, IpcClient, IpcClientError};
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    BehaviorModeDto, BindingSourceDto, MigrationMarkCompleteRequest, MigrationMarkCompleteResponse,
    MigrationStatusGetRequest, MigrationStatusGetResponse, RouteBindingDto, RoutePolicyDto,
    RoutePolicyUpdateRequest, MIGRATION_ID_LEGACY_PREFERENCES_V1,
};
use nrr_shared::RouteBehaviorMode;
use nrr_ui_support::ui_preferences::{
    cleanup_legacy_policy_fields, has_legacy_policy_fields, UiPreferences,
};

/// Default per-call timeout for the migration round-trip. Each call is
/// a single SQLite write or read — 1 s is generous; the launcher does
/// not retry on timeout.
pub const MIGRATION_CALL_TIMEOUT: Duration = Duration::from_secs(1);

/// Result of [`run_legacy_preferences_migration`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// Service reports the migration as already completed for this
    /// caller's SID. Preferences are not modified.
    AlreadyDone,
    /// Migration ran end-to-end successfully:
    /// `RoutePolicyUpdate` (if there were legacy values) +
    /// `MigrationMarkComplete`. Preferences have been cleaned up.
    Completed { had_legacy_data: bool },
    /// Helper short-circuited without contacting the service. The
    /// preferences are not modified; next start retries.
    Skipped { reason: SkipReason },
    /// Helper contacted the service but a step failed. The
    /// preferences are not modified; next start retries.
    Failed {
        stage: FailureStage,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// IPC client did not reach `Connected` state before the helper
    /// gave up. The launcher carries on without migration; next start
    /// will retry.
    IpcNotConnected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureStage {
    /// `MigrationStatusGet` returned an error.
    StatusQuery,
    /// `RoutePolicyUpdate` returned an error.
    PolicyUpdate,
    /// `MigrationMarkComplete` returned an error.
    MarkComplete,
    /// One of the responses failed to deserialise.
    ResponseDecode,
}

/// Run the legacy-preferences migration flow against `client`,
/// mutating `prefs` in place. See module docs for the full state
/// machine. Synchronous — uses `IpcClient::call` with a fixed
/// per-call timeout.
pub fn run_legacy_preferences_migration<C: IpcClient + ?Sized>(
    client: &C,
    prefs: &mut UiPreferences,
) -> MigrationOutcome {
    if !matches!(client.connection_status(), ConnectionStatus::Connected) {
        return MigrationOutcome::Skipped {
            reason: SkipReason::IpcNotConnected,
        };
    }

    let status_resp = match query_migration_status(client) {
        Ok(r) => r,
        Err(e) => {
            return MigrationOutcome::Failed {
                stage: e.stage,
                message: e.message,
            };
        }
    };
    if status_resp.completed {
        return MigrationOutcome::AlreadyDone;
    }

    let had_legacy_data = has_legacy_policy_fields(prefs);

    if had_legacy_data {
        if let Err(e) = push_route_policy(client, prefs) {
            return MigrationOutcome::Failed {
                stage: e.stage,
                message: e.message,
            };
        }
    }

    if let Err(e) = mark_migration_complete(client, had_legacy_data) {
        return MigrationOutcome::Failed {
            stage: e.stage,
            message: e.message,
        };
    }

    cleanup_legacy_policy_fields(prefs);
    MigrationOutcome::Completed { had_legacy_data }
}

// ── Internals ────────────────────────────────────────────────────────────────

struct StageError {
    stage: FailureStage,
    message: String,
}

fn query_migration_status<C: IpcClient + ?Sized>(
    client: &C,
) -> Result<MigrationStatusGetResponse, StageError> {
    let req = MigrationStatusGetRequest {
        migration_id: MIGRATION_ID_LEGACY_PREFERENCES_V1.into(),
    };
    let payload = serde_json::to_value(&req).map_err(|e| StageError {
        stage: FailureStage::StatusQuery,
        message: format!("status request encode failed: {e}"),
    })?;
    let value = client
        .call(
            IpcOperationName::MigrationStatusGet,
            payload,
            MIGRATION_CALL_TIMEOUT,
        )
        .map_err(|e| StageError {
            stage: FailureStage::StatusQuery,
            message: ipc_error_to_string(e),
        })?;
    serde_json::from_value::<MigrationStatusGetResponse>(value).map_err(|e| StageError {
        stage: FailureStage::ResponseDecode,
        message: format!("status response decode failed: {e}"),
    })
}

#[allow(deprecated)]
fn push_route_policy<C: IpcClient + ?Sized>(
    client: &C,
    prefs: &UiPreferences,
) -> Result<RoutePolicyDto, StageError> {
    let req = RoutePolicyUpdateRequest {
        primary: build_binding_dto(
            &prefs.selected_primary_interface_id,
            &prefs.selected_primary_interface_name,
            prefs.primary_role_user_confirmed,
        ),
        secondary: build_binding_dto(
            &prefs.selected_secondary_interface_id,
            &prefs.selected_secondary_interface_name,
            prefs.secondary_role_user_confirmed,
        ),
        mode: behavior_mode_to_dto(prefs.route_behavior_mode),
        block_secondary_when_unavailable: prefs.block_secondary_traffic_when_unavailable,
        // No legacy pref for the failure posture — migrate to the safe
        // default (fail-closed). The user can switch it in Routing settings.
        kill_switch_fail_closed: true,
        kill_switch_protocols: 0x7F,
        // No legacy pref for the aggressive kill-switch scope — migrate to the
        // safe default (OFF; per-IP block). The user can enable it in Routing.
        kill_switch_block_all: false,
        // MASTER kill-switch toggle. Migrate the UiPrefs mirror (defaults OFF
        // for legacy prefs that predate it — the full opt-in default).
        kill_switch_enabled: prefs.route_kill_switch_enabled,
        // Migrate the DNS-over-primary opt-in mirror (defaults OFF/strict for
        // legacy prefs that predate it).
        allow_dns_over_primary: prefs.route_allow_dns_over_primary,
        // No legacy pref for subdomain-coverage — migrate to the current
        // default (ON: a rule for a site also covers that site's
        // subdomains; the widening only adds coverage towards the route the
        // rule already names). The user can turn it off in Routing settings.
        include_subdomains: true,
        shared_ip_policy: "majority-of-ip".into(),
        // No legacy pref for either; migrate to the contract default (never
        // a slug retyped here: the migration must land the user on the same
        // Mode-A posture a fresh install gets) and resolve rule hosts
        // bypassing the hosts file. The user can change both in Routing.
        mode_a_coverage_strategy: nrr_shared::ipc_payloads::mode_a_coverage_strategy_default(),
        resolve_hosts_bypass: true,
        doh_lockdown_enabled: false,
        doh_lockdown_scope: "leak-protection-only".into(),
        // No legacy pref; migrate to the safe default (OFF — automatic
        // browser-history reads stay an explicit opt-in).
        browser_history_auto_seed: false,
        // No legacy pref; migrate to the default ("smart": census-shared
        // IPs are not pinned by the kill-switch).
        kill_switch_strict_shared_ips: false,
        auto_rules_mode: "suggest".to_string(),
        // No legacy pref; migrate to the default (wait for the evidence before
        // suggesting a delivery-named host). The user can opt in in Routing.
        auto_rules_eager_delivery_names: false,
        binding_source: BindingSourceDto::MigratedFromPreferences,
    };
    let payload = serde_json::to_value(&req).map_err(|e| StageError {
        stage: FailureStage::PolicyUpdate,
        message: format!("update request encode failed: {e}"),
    })?;
    let value = client
        .call(
            IpcOperationName::RoutePolicyUpdate,
            payload,
            MIGRATION_CALL_TIMEOUT,
        )
        .map_err(|e| StageError {
            stage: FailureStage::PolicyUpdate,
            message: ipc_error_to_string(e),
        })?;
    serde_json::from_value::<RoutePolicyDto>(value).map_err(|e| StageError {
        stage: FailureStage::ResponseDecode,
        message: format!("update response decode failed: {e}"),
    })
}

fn mark_migration_complete<C: IpcClient + ?Sized>(
    client: &C,
    had_legacy_data: bool,
) -> Result<MigrationMarkCompleteResponse, StageError> {
    let detail = format!(r#"{{"had_legacy_data":{had_legacy_data}}}"#);
    let req = MigrationMarkCompleteRequest {
        migration_id: MIGRATION_ID_LEGACY_PREFERENCES_V1.into(),
        detail_json: Some(detail),
    };
    let payload = serde_json::to_value(&req).map_err(|e| StageError {
        stage: FailureStage::MarkComplete,
        message: format!("mark request encode failed: {e}"),
    })?;
    let value = client
        .call(
            IpcOperationName::MigrationMarkComplete,
            payload,
            MIGRATION_CALL_TIMEOUT,
        )
        .map_err(|e| StageError {
            stage: FailureStage::MarkComplete,
            message: ipc_error_to_string(e),
        })?;
    serde_json::from_value::<MigrationMarkCompleteResponse>(value).map_err(|e| StageError {
        stage: FailureStage::ResponseDecode,
        message: format!("mark response decode failed: {e}"),
    })
}

fn build_binding_dto(
    stable_id: &str,
    display_name: &str,
    user_confirmed: bool,
) -> Option<RouteBindingDto> {
    let id = stable_id.trim();
    if id.is_empty() {
        return None;
    }
    Some(RouteBindingDto {
        stable_id: id.to_string(),
        display_name: display_name.trim().to_string(),
        user_confirmed,
    })
}

fn behavior_mode_to_dto(mode: RouteBehaviorMode) -> BehaviorModeDto {
    match mode {
        RouteBehaviorMode::PreferPrimary => BehaviorModeDto::PreferPrimary,
        RouteBehaviorMode::PreferSecondaryWhenAvailable => {
            BehaviorModeDto::PreferSecondaryWhenAvailable
        }
        RouteBehaviorMode::StrictSecondaryFailClosed => BehaviorModeDto::StrictSecondaryFailClosed,
    }
}

fn ipc_error_to_string(e: IpcClientError) -> String {
    format!("{e:?}")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(deprecated)] // Tests construct UiPreferences with legacy fields
                     // to drive the migration flow; this is the explicit pre-migration shape.
mod tests {
    use super::*;
    use serde_json::Value;
    use std::sync::Mutex;

    /// Mock `IpcClient` that yields scripted responses per-operation.
    struct MockClient {
        connected: Mutex<bool>,
        // (operation, response) — response is `Result<Value, IpcClientError>`
        calls: Mutex<Vec<(IpcOperationName, Value)>>,
        responses: Mutex<Vec<(IpcOperationName, Result<Value, IpcClientError>)>>,
    }

    impl MockClient {
        fn connected(responses: Vec<(IpcOperationName, Result<Value, IpcClientError>)>) -> Self {
            Self {
                connected: Mutex::new(true),
                calls: Mutex::new(Vec::new()),
                responses: Mutex::new(responses),
            }
        }
        fn disconnected() -> Self {
            Self {
                connected: Mutex::new(false),
                calls: Mutex::new(Vec::new()),
                responses: Mutex::new(Vec::new()),
            }
        }
        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
        fn last_request(&self, op: IpcOperationName) -> Option<Value> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(o, _)| *o == op)
                .map(|(_, v)| v.clone())
        }
    }

    impl IpcClient for MockClient {
        fn call(
            &self,
            operation: IpcOperationName,
            payload: Value,
            _timeout: Duration,
        ) -> Result<Value, IpcClientError> {
            self.calls.lock().unwrap().push((operation, payload));
            let mut rs = self.responses.lock().unwrap();
            if rs.is_empty() {
                return Err(IpcClientError::Disconnected);
            }
            let (expected_op, response) = rs.remove(0);
            assert_eq!(expected_op, operation, "unexpected op in mock");
            response
        }
        fn connection_status(&self) -> ConnectionStatus {
            if *self.connected.lock().unwrap() {
                ConnectionStatus::Connected
            } else {
                ConnectionStatus::Disconnected {
                    last_error: "test fake".into(),
                }
            }
        }
        fn force_reconnect(&self) {}
    }

    fn legacy_prefs() -> UiPreferences {
        UiPreferences {
            selected_primary_interface_id: "Wi-Fi".into(),
            selected_primary_interface_name: "Wireless".into(),
            primary_role_user_confirmed: true,
            selected_secondary_interface_id: "TAP".into(),
            selected_secondary_interface_name: "OpenVPN TAP".into(),
            secondary_role_user_confirmed: false,
            route_behavior_mode: RouteBehaviorMode::PreferSecondaryWhenAvailable,
            block_secondary_traffic_when_unavailable: true,
            ..Default::default()
        }
    }

    #[test]
    fn skipped_when_client_disconnected() {
        let client = MockClient::disconnected();
        let mut prefs = legacy_prefs();
        let outcome = run_legacy_preferences_migration(&client, &mut prefs);
        assert_eq!(
            outcome,
            MigrationOutcome::Skipped {
                reason: SkipReason::IpcNotConnected,
            },
        );
        assert!(has_legacy_policy_fields(&prefs));
        assert_eq!(client.call_count(), 0);
    }

    #[test]
    fn already_done_when_status_returns_completed() {
        let status = MigrationStatusGetResponse {
            completed: true,
            completed_at: Some(99),
            detail_json: None,
        };
        let client = MockClient::connected(vec![(
            IpcOperationName::MigrationStatusGet,
            Ok(serde_json::to_value(status).unwrap()),
        )]);
        let mut prefs = legacy_prefs();
        let outcome = run_legacy_preferences_migration(&client, &mut prefs);
        assert_eq!(outcome, MigrationOutcome::AlreadyDone);
        assert!(has_legacy_policy_fields(&prefs));
        assert_eq!(client.call_count(), 1);
    }

    #[test]
    fn full_flow_with_legacy_data_completes_and_cleans_up() {
        let policy_dto = RoutePolicyDto {
            primary: Some(RouteBindingDto {
                stable_id: "Wi-Fi".into(),
                display_name: "Wireless".into(),
                user_confirmed: true,
            }),
            secondary: Some(RouteBindingDto {
                stable_id: "TAP".into(),
                display_name: "OpenVPN TAP".into(),
                user_confirmed: false,
            }),
            mode: BehaviorModeDto::PreferSecondaryWhenAvailable,
            block_secondary_when_unavailable: true,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            kill_switch_enabled: false,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: "majority-of-ip".into(),
            mode_a_coverage_strategy: "fail-closed-unknown".into(),
            resolve_hosts_bypass: true,
            secondary_link_provider_apps: Vec::new(),
            doh_lockdown_enabled: false,
            doh_lockdown_scope: "leak-protection-only".into(),
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: false,
            auto_rules_mode: "suggest".to_string(),
            auto_rules_eager_delivery_names: false,
            binding_source: BindingSourceDto::MigratedFromPreferences,
        };
        let mark = MigrationMarkCompleteResponse {
            recorded: true,
            completed_at: 1,
        };
        let client = MockClient::connected(vec![
            (
                IpcOperationName::MigrationStatusGet,
                Ok(serde_json::to_value(MigrationStatusGetResponse {
                    completed: false,
                    completed_at: None,
                    detail_json: None,
                })
                .unwrap()),
            ),
            (
                IpcOperationName::RoutePolicyUpdate,
                Ok(serde_json::to_value(policy_dto).unwrap()),
            ),
            (
                IpcOperationName::MigrationMarkComplete,
                Ok(serde_json::to_value(mark).unwrap()),
            ),
        ]);
        let mut prefs = legacy_prefs();
        let outcome = run_legacy_preferences_migration(&client, &mut prefs);
        assert_eq!(
            outcome,
            MigrationOutcome::Completed {
                had_legacy_data: true
            },
        );
        assert!(!has_legacy_policy_fields(&prefs));
        assert_eq!(client.call_count(), 3);

        // Validate request shape sent to RoutePolicyUpdate.
        let update_req = client
            .last_request(IpcOperationName::RoutePolicyUpdate)
            .unwrap();
        let parsed: RoutePolicyUpdateRequest = serde_json::from_value(update_req).unwrap();
        assert_eq!(
            parsed.binding_source,
            BindingSourceDto::MigratedFromPreferences
        );
        assert_eq!(parsed.primary.unwrap().stable_id, "Wi-Fi");
        assert_eq!(parsed.secondary.unwrap().stable_id, "TAP");
        assert_eq!(parsed.mode, BehaviorModeDto::PreferSecondaryWhenAvailable);
        assert!(parsed.block_secondary_when_unavailable);
    }

    #[test]
    fn flow_without_legacy_data_skips_update_but_marks_complete() {
        // No legacy data → status is not completed → migration should
        // skip RoutePolicyUpdate but still mark complete.
        let mark = MigrationMarkCompleteResponse {
            recorded: true,
            completed_at: 1,
        };
        let client = MockClient::connected(vec![
            (
                IpcOperationName::MigrationStatusGet,
                Ok(serde_json::to_value(MigrationStatusGetResponse {
                    completed: false,
                    completed_at: None,
                    detail_json: None,
                })
                .unwrap()),
            ),
            (
                IpcOperationName::MigrationMarkComplete,
                Ok(serde_json::to_value(mark).unwrap()),
            ),
        ]);
        let mut prefs = UiPreferences::default();
        let outcome = run_legacy_preferences_migration(&client, &mut prefs);
        assert_eq!(
            outcome,
            MigrationOutcome::Completed {
                had_legacy_data: false
            },
        );
        assert_eq!(client.call_count(), 2);
    }

    #[test]
    fn policy_update_failure_does_not_clean_up_prefs() {
        let client = MockClient::connected(vec![
            (
                IpcOperationName::MigrationStatusGet,
                Ok(serde_json::to_value(MigrationStatusGetResponse {
                    completed: false,
                    completed_at: None,
                    detail_json: None,
                })
                .unwrap()),
            ),
            (
                IpcOperationName::RoutePolicyUpdate,
                Err(IpcClientError::Disconnected),
            ),
        ]);
        let mut prefs = legacy_prefs();
        let before = prefs.clone();
        let outcome = run_legacy_preferences_migration(&client, &mut prefs);
        match outcome {
            MigrationOutcome::Failed { stage, .. } => {
                assert_eq!(stage, FailureStage::PolicyUpdate);
            }
            other => panic!("expected Failed(PolicyUpdate), got {other:?}"),
        }
        assert!(has_legacy_policy_fields(&prefs));
        assert_eq!(prefs, before);
    }

    #[test]
    fn status_failure_short_circuits_without_other_calls() {
        let client = MockClient::connected(vec![(
            IpcOperationName::MigrationStatusGet,
            Err(IpcClientError::Disconnected),
        )]);
        let mut prefs = legacy_prefs();
        let outcome = run_legacy_preferences_migration(&client, &mut prefs);
        match outcome {
            MigrationOutcome::Failed { stage, .. } => {
                assert_eq!(stage, FailureStage::StatusQuery);
            }
            other => panic!("expected Failed(StatusQuery), got {other:?}"),
        }
        assert_eq!(client.call_count(), 1);
        assert!(has_legacy_policy_fields(&prefs));
    }

    #[test]
    fn malformed_status_response_maps_to_response_decode() {
        let client = MockClient::connected(vec![(
            IpcOperationName::MigrationStatusGet,
            Ok(serde_json::json!({"bogus": true})),
        )]);
        let mut prefs = legacy_prefs();
        let outcome = run_legacy_preferences_migration(&client, &mut prefs);
        match outcome {
            MigrationOutcome::Failed { stage, .. } => {
                assert_eq!(stage, FailureStage::ResponseDecode);
            }
            other => panic!("expected Failed(ResponseDecode), got {other:?}"),
        }
    }
}
