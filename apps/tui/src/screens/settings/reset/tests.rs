#![allow(clippy::expect_used)]

use std::cell::Cell;
use std::sync::Mutex;
use std::time::Duration;

use nrr_ipc_client::{ConnectionStatus, IpcClientError};
use nrr_shared::ipc_transport::IpcErrorCode;
use serde_json::json;

use super::*;
use crate::link::Link;
use crate::testing::{app_at, missing_from_locales, texts_en, Fixture};

/// A service that answers everything with an empty success, except the
/// operations it is told to refuse for want of administrator rights.
struct Script {
    forbid: Vec<Op>,
    calls: Mutex<Vec<(Op, Value)>>,
}

impl Script {
    fn new(forbid: &[Op]) -> Self {
        Self {
            forbid: forbid.to_vec(),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn ops(&self) -> Vec<Op> {
        self.calls
            .lock()
            .expect("lock")
            .iter()
            .map(|c| c.0)
            .collect()
    }

    fn payload(&self, op: Op) -> Value {
        self.calls
            .lock()
            .expect("lock")
            .iter()
            .find(|c| c.0 == op)
            .map(|c| c.1.clone())
            .expect("the operation was called")
    }
}

impl IpcClient for Script {
    fn call(&self, op: Op, payload: Value, _timeout: Duration) -> Result<Value, IpcClientError> {
        self.calls.lock().expect("lock").push((op, payload));
        if self.forbid.contains(&op) {
            return Err(IpcClientError::ServerError {
                op,
                code: IpcErrorCode::Forbidden,
                message: "non-admin".into(),
            });
        }
        Ok(json!({ "review-summary": {} }))
    }

    fn connection_status(&self) -> ConnectionStatus {
        ConnectionStatus::Connected
    }

    fn force_reconnect(&self) {}
}

fn stopped() -> Outcome {
    Outcome::Ok
}

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_from_locales(&keys());
    assert!(missing.is_empty(), "{missing:?}");
}

#[test]
fn the_steps_run_in_the_windows_order_and_the_service_stops_last() {
    let client = Script::new(&[]);
    let stops = Cell::new(0);
    let end = drive(&client, false, &|| {
        // Every service-side step has already run when the stop comes, and
        // none wrote a rule book: the user is left reading the baseline.
        assert_eq!(client.ops(), [Op::LogsClear, Op::PrincipalDataPurge]);
        stops.set(stops.get() + 1);
        stopped()
    });
    assert_eq!(end, Next::Finish { cleared: true });
    assert_eq!(stops.get(), 1);
}

#[test]
fn the_purge_takes_the_rules_history_and_only_the_callers_own_data_by_default() {
    let client = Script::new(&[]);
    drive(&client, false, &stopped);
    let purge = client.payload(Op::PrincipalDataPurge);
    assert_eq!(purge["include-rules-history"], json!(true));
    assert_eq!(purge["all-principals"], json!(false));
    let logs = client.payload(Op::LogsClear);
    assert_eq!(logs["include-archives"], json!(true));
    assert_eq!(logs["dry-run"], json!(false));
}

#[test]
fn clearing_everyones_data_is_asked_for_in_the_request() {
    let client = Script::new(&[]);
    drive(&client, true, &stopped);
    assert_eq!(
        client.payload(Op::PrincipalDataPurge)["all-principals"],
        json!(true)
    );
}

#[test]
fn a_refused_purge_stops_before_the_rules_and_the_service_are_touched() {
    let client = Script::new(&[Op::PrincipalDataPurge]);
    let end = drive(&client, true, &|| panic!("the service must not be stopped"));
    assert_eq!(
        end,
        Next::NeedsElevation {
            step: Step::PurgePrincipalData
        }
    );
    assert!(!client.ops().contains(&Op::MutationSubmit));
}

#[test]
fn a_refused_purge_of_everyones_data_erases_nothing_first() {
    let client = Script::new(&[Op::PrincipalDataPurge]);
    drive(&client, true, &|| panic!("the service must not be stopped"));
    assert_eq!(client.ops(), [Op::PrincipalDataPurge], "no log was cleared");
}

#[test]
fn everyones_data_is_purged_once() {
    let client = Script::new(&[]);
    let end = drive(&client, true, &stopped);
    assert_eq!(end, Next::Finish { cleared: true });
    let purges = client
        .ops()
        .into_iter()
        .filter(|op| *op == Op::PrincipalDataPurge)
        .count();
    assert_eq!(purges, 1);
}

#[test]
fn a_reset_stopped_for_rights_keeps_the_shared_settings_file() {
    let dir = crate::testing::Scratch::new("reset-stopped-keeps");
    let store =
        nrr_shared::user_settings::UserSettingsStore::at(dir.path().join("user-settings.json"));
    store
        .update(|s| s.set_primary_file("/home/me/p.txt"))
        .expect("written");
    let script = Script::new(&[Op::PrincipalDataPurge]);
    let reply = full_reset(true, no_manager, Some(store.path().to_path_buf()))(&script);
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    (reply.0)(&mut app);
    let after = store.load().expect("read").unwrap_or_default();
    assert!(!after.rules_files.primary.is_empty(), "the binding stays");
}

#[test]
fn a_refused_log_clear_does_not_stop_the_reset() {
    let client = Script::new(&[Op::LogsClear]);
    let end = drive(&client, false, &stopped);
    assert_eq!(end, Next::Finish { cleared: true });
}

fn no_manager() -> Option<Box<dyn nrr_platform_api::service_control::ServiceControlPort>> {
    None
}

/// A service manager holding one service in `state`, counting starts.
struct Manager {
    state: ServiceRunState,
    starts: Cell<u32>,
}

impl Manager {
    fn holding(state: ServiceRunState) -> Self {
        Self {
            state,
            starts: Cell::new(0),
        }
    }
}

impl ServiceControlPort for Manager {
    fn install(
        &self,
        _spec: &nrr_platform_api::service_control::ServiceInstallSpec,
    ) -> Result<nrr_platform_api::service_control::ServiceInstallReport, ServiceControlError> {
        Err(ServiceControlError::Unsupported {
            operation: "install",
        })
    }

    fn uninstall(
        &self,
        _spec: &nrr_platform_api::service_control::ServiceUninstallSpec,
    ) -> Result<nrr_platform_api::service_control::ServiceUninstallReport, ServiceControlError>
    {
        Err(ServiceControlError::Unsupported {
            operation: "uninstall",
        })
    }

    fn start(&self, _timeout: Duration) -> Result<(), ServiceControlError> {
        self.starts.set(self.starts.get() + 1);
        Ok(())
    }

    fn stop(&self, _timeout: Duration) -> Result<(), ServiceControlError> {
        Ok(())
    }

    fn query(
        &self,
    ) -> Result<Option<nrr_platform_api::service_control::ServiceStatusReport>, ServiceControlError>
    {
        Ok(Some(
            nrr_platform_api::service_control::ServiceStatusReport {
                run_state: self.state,
                start_mode: None,
                binary_path: None,
                running_since: None,
            },
        ))
    }
}

#[test]
fn a_stopped_service_is_started_before_the_steps_and_answers_first() {
    let manager = Manager::holding(ServiceRunState::Stopped);
    let client = Script::new(&[]);
    assert!(start_if_stopped(Some(&manager), &client, Duration::ZERO));
    assert_eq!(manager.starts.get(), 1);
    assert_eq!(client.ops(), [Op::PrincipalDataCount]);
}

#[test]
fn a_running_or_absent_service_is_left_as_it_is() {
    let running = Manager::holding(ServiceRunState::Running);
    let client = Script::new(&[]);
    assert!(!start_if_stopped(Some(&running), &client, Duration::ZERO));
    assert_eq!(running.starts.get(), 0);
    assert!(!start_if_stopped(None, &client, Duration::ZERO));
    assert!(client.ops().is_empty());
}

#[test]
fn a_started_service_that_never_answers_gives_up_on_time() {
    let manager = Manager::holding(ServiceRunState::Stopped);
    let client = Script::new(&[Op::PrincipalDataCount]);
    assert!(!start_if_stopped(Some(&manager), &client, Duration::ZERO));
    assert_eq!(client.ops(), [Op::PrincipalDataCount]);
}

fn run_on_screen(script: &Script, everyone: bool) -> String {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    let reply = full_reset(everyone, no_manager, None)(script);
    (reply.0)(&mut app);
    app.settings
        .message
        .as_ref()
        .map(|m| m.words.resolve(&texts_en()))
        .expect("the reset says how it went")
}

#[test]
fn the_shared_settings_file_goes_back_to_a_fresh_install() {
    use nrr_shared::user_settings::{UserSettings, UserSettingsStore};
    let dir = crate::testing::Scratch::new("reset-settings");
    let store = UserSettingsStore::at(dir.path().join("user-settings.json"));
    store
        .update(|s| {
            s.set_rules_folder("/home/me/sets");
            s.set_primary_file("/home/me/p.txt");
            s.selected_set = "user:mine".into();
            s.accepted_eula = 1;
            s.service_intent
                .insert("route-policy".into(), json!({ "a": 1 }));
        })
        .expect("written");
    assert!(clear_user_settings(Some(store.path())));
    let after = store.load().expect("read").unwrap_or_default();
    assert_eq!(
        (after.rules_folder.as_str(), after.selected_set.as_str()),
        ("", "")
    );
    assert!(after.rules_files.primary.is_empty());
    assert!(after.service_intent.is_empty());
    assert_eq!(after.accepted_eula, UserSettings::default().accepted_eula);
    assert!(clear_user_settings(None), "no file is nothing to clear");
}

#[test]
fn a_damaged_settings_file_is_left_alone_and_reported() {
    let dir = crate::testing::Scratch::new("reset-damaged");
    let file = dir.path().join("user-settings.json");
    std::fs::write(&file, "{ not json").expect("write");
    assert!(!clear_user_settings(Some(&file)));
    assert_eq!(std::fs::read_to_string(&file).expect("read"), "{ not json");
}

#[test]
fn a_service_that_cannot_be_stopped_is_reported_as_not_fully_cleared() {
    let said = run_on_screen(&Script::new(&[]), false);
    assert_eq!(said, texts_en().get(PARTIAL));
}

#[test]
fn a_refusal_says_how_to_start_the_terminal_with_the_rights() {
    let said = run_on_screen(&Script::new(&[Op::PrincipalDataPurge]), true);
    assert!(
        said.ends_with(&crate::screens::settings::elevation_text(&texts_en())),
        "{said}"
    );
}

#[test]
fn the_scope_choice_appears_only_when_other_users_have_rules() {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    let rows = |app: &AppState| {
        super::super::items::items(app, super::super::Category::Presets)
            .into_iter()
            .map(|i| i.id)
            .collect::<Vec<_>>()
    };
    assert!(!rows(&app).contains(&super::super::items::ItemId::Reset(ResetRow::Scope)));
    app.settings.reset.others = Loadable::Ready(2);
    let listed = rows(&app);
    assert!(listed.contains(&super::super::items::ItemId::Reset(ResetRow::Scope)));
    assert!(listed.contains(&super::super::items::ItemId::Reset(ResetRow::Run)));
}

#[test]
fn the_reset_is_queued_and_announced_as_running() {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    activate(&mut app, ResetRow::Run, Input::Run);
    assert_eq!(app.outbox.take().len(), 1);
    assert_eq!(
        app.settings
            .message
            .as_ref()
            .map(|m| m.words.resolve(&texts_en())),
        Some(texts_en().get(RUNNING))
    );
}
