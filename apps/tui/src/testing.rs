//! A scripted stand-in for the service and the snapshots it answers with, for
//! the screens' and the backend's tests.

use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Mutex;
use std::time::Duration;

use nrr_ipc_client::{ConnectionStatus, IpcClient, IpcClientError};
use nrr_shared::diagnostics_dto::DiagnosticsStatusDto;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::SnapshotInitialResponse;
use serde_json::{json, Value};

pub struct FakeService {
    status: Mutex<ConnectionStatus>,
    answers: Mutex<Vec<(IpcOperationName, Value)>>,
    refusals: Mutex<Vec<(IpcOperationName, nrr_shared::ipc_transport::IpcErrorCode)>>,
    calls: Mutex<Vec<IpcOperationName>>,
    sent: Mutex<Vec<(IpcOperationName, Value)>>,
    pending_push: Mutex<Option<SyncSender<Value>>>,
    push: Mutex<Option<SyncSender<Value>>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl FakeService {
    pub fn new(status: ConnectionStatus) -> Self {
        Self {
            status: Mutex::new(status),
            answers: Mutex::new(vec![(
                IpcOperationName::StatusUpdatesSubscribe,
                json!({ "subscription-id": "sub-1", "current-event-id": 0, "gap-detected": false }),
            )]),
            refusals: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
            sent: Mutex::new(Vec::new()),
            pending_push: Mutex::new(None),
            push: Mutex::new(None),
        }
    }

    /// The payload every later call of `op` gets.
    pub fn answer(&self, op: IpcOperationName, payload: Value) {
        let mut answers = lock(&self.answers);
        answers.retain(|(o, _)| *o != op);
        answers.push((op, payload));
    }

    /// Every later call of `op` is refused with `code`, ahead of any answer.
    pub fn refuse(&self, op: IpcOperationName, code: nrr_shared::ipc_transport::IpcErrorCode) {
        lock(&self.refusals).push((op, code));
    }

    /// `op` is answered again: the refusal is lifted.
    pub fn stop_refusing(&self, op: IpcOperationName) {
        lock(&self.refusals).retain(|(o, _)| *o != op);
    }

    /// Deliver a push frame to the committed subscriber.
    pub fn push(&self, frame: Value) {
        if let Some(tx) = lock(&self.push).as_ref() {
            let _ = tx.try_send(frame);
        }
    }

    pub fn operations(&self) -> Vec<IpcOperationName> {
        lock(&self.calls).clone()
    }

    /// The payloads `op` was called with, oldest first.
    pub fn sent(&self, op: IpcOperationName) -> Vec<Value> {
        lock(&self.sent)
            .iter()
            .filter(|(o, _)| *o == op)
            .map(|(_, v)| v.clone())
            .collect()
    }
}

impl IpcClient for FakeService {
    fn call(
        &self,
        operation: IpcOperationName,
        payload: Value,
        _timeout: Duration,
    ) -> Result<Value, IpcClientError> {
        lock(&self.calls).push(operation);
        lock(&self.sent).push((operation, payload));
        if let Some((_, code)) = lock(&self.refusals).iter().find(|(op, _)| *op == operation) {
            return Err(IpcClientError::ServerError {
                op: operation,
                code: *code,
                message: "scripted refusal".to_owned(),
            });
        }
        lock(&self.answers)
            .iter()
            .find(|(op, _)| *op == operation)
            .map(|(_, v)| v.clone())
            .ok_or_else(|| IpcClientError::BadResponse {
                reason: format!("no scripted answer for {}", operation.slug()),
            })
    }

    fn connection_status(&self) -> ConnectionStatus {
        lock(&self.status).clone()
    }

    fn force_reconnect(&self) {}

    fn subscribe_push(&self) -> Option<Receiver<Value>> {
        let (tx, rx) = sync_channel(64);
        *lock(&self.pending_push) = Some(tx);
        Some(rx)
    }

    fn commit_push(&self) {
        let pending = lock(&self.pending_push).take();
        if pending.is_some() {
            *lock(&self.push) = pending;
        }
    }

    fn abandon_push(&self) {
        lock(&self.pending_push).take();
    }
}

/// One bound adapter as the fixtures describe it.
#[derive(Clone, Debug)]
pub struct Bound {
    pub id: &'static str,
    pub name: &'static str,
    /// The row's `availability`; `None` = no such row (the adapter is gone).
    pub availability: Option<&'static str>,
}

/// The parts of a snapshot the Status screen reads.
#[derive(Clone, Debug)]
pub struct Fixture {
    pub primary: Option<Bound>,
    pub secondary: Option<Bound>,
    pub paused: bool,
}

impl Fixture {
    /// Both connections chosen and up.
    pub fn healthy() -> Self {
        Self {
            primary: Some(Bound {
                id: "{00000000-0000-0000-0000-000000000001}",
                name: "Ethernet",
                availability: Some("available"),
            }),
            secondary: Some(Bound {
                id: "{00000000-0000-0000-0000-000000000002}",
                name: "Example Tunnel",
                availability: Some("available"),
            }),
            paused: false,
        }
    }

    pub fn snapshot(&self) -> SnapshotInitialResponse {
        serde_json::from_value(snapshot_json(self))
            .unwrap_or_else(|e| panic!("fixture snapshot must parse: {e}"))
    }
}

fn row(bound: &Bound, availability: &str) -> Value {
    json!({
        "persistent-id": bound.id,
        "adapter-name": bound.id,
        "name": bound.name,
        "interface-description": "Example Network Adapter",
        "interface-type": "ethernet",
        "kind": "ethernet",
        "is-bluetooth-like": false,
        "local-ip": "192.0.2.10",
        "gateway": "192.0.2.1",
        "dns-servers": "192.0.2.53",
        "has-default-route": true,
        "has-forwarding-path": true,
        "availability": availability,
        "route-state": "selected",
        "observed-facts": {
            "connectivity-state": "internet",
            "external-ip-status": "unknown",
            "external-ip": null,
            "external-probe-attempted": false,
            "external-probe-note": ""
        },
        "derived-assessment": {
            "vpn-tunnel-likelihood": "unlikely",
            "virtual-interface-likelihood": "unlikely",
            "service-interface-likelihood": "unlikely",
            "classification": "regular-interface",
            "confidence-percent": 90,
            "heuristic-only": true,
            "signals": []
        },
        "recommendation": {
            "class": "preferred-primary",
            "confidence": "high",
            "advisory-only": true,
            "key-signals": [],
            "excluded-alternatives": []
        }
    })
}

fn binding(bound: &Bound) -> Value {
    json!({ "stable-id": bound.id, "display-name": bound.name, "user-confirmed": true })
}

/// The `snapshot.initial.get` payload for a fixture, in the service's wire form.
pub fn snapshot_json(f: &Fixture) -> Value {
    let rows: Vec<Value> = [&f.primary, &f.secondary]
        .into_iter()
        .flatten()
        .filter_map(|b| b.availability.map(|a| row(b, a)))
        .collect();
    let mut policy = json!({
        "mode": "prefer-primary",
        "leak-protection": "off",
        "binding-source": "user-assigned"
    });
    if let Some(p) = &f.primary {
        policy["primary"] = binding(p);
    }
    if let Some(s) = &f.secondary {
        policy["secondary"] = binding(s);
    }
    json!({
        "health": {
            "service-state": "running",
            "worst-severity": "ok",
            "components": []
        },
        "adapters": { "data-source": "windows-live", "adapters": [], "rows": rows },
        "diagnostics": serde_json::to_value(DiagnosticsStatusDto::unavailable())
            .unwrap_or(Value::Null),
        "active-alerts-count": 0,
        "route-policy": policy,
        "routing-paused": f.paused
    })
}

#[derive(Debug, PartialEq, Eq)]
enum SnapshotPlan {
    Compare,
    Rewrite,
    WriteMissing,
    Refuse(&'static str),
}

/// Writing a snapshot is a developer's review step: under `CI` nothing is
/// written, so a changed screen cannot turn the gate green by itself.
fn snapshot_plan(update_requested: bool, under_ci: bool, file_exists: bool) -> SnapshotPlan {
    match (update_requested, under_ci, file_exists) {
        (true, true, _) => SnapshotPlan::Refuse("snapshots are not rewritten under CI"),
        (true, false, _) => SnapshotPlan::Rewrite,
        (false, _, true) => SnapshotPlan::Compare,
        (false, true, false) => SnapshotPlan::Refuse("snapshot is missing"),
        (false, false, false) => SnapshotPlan::WriteMissing,
    }
}

/// Compare `actual` with `tests/snapshots/<name>.txt`. A missing file is
/// written on a developer machine (review it before keeping it);
/// `NRR_TUI_UPDATE_SNAPSHOTS` rewrites a file that differs. Under `CI` both
/// fail instead.
pub fn assert_snapshot(name: &str, actual: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(format!("{name}.txt"));
    let write = || {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        }
        std::fs::write(&path, actual).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    };
    let existing = std::fs::read_to_string(&path).ok();
    let plan = snapshot_plan(
        std::env::var_os("NRR_TUI_UPDATE_SNAPSHOTS").is_some(),
        std::env::var_os("CI").is_some(),
        existing.is_some(),
    );
    match plan {
        SnapshotPlan::Refuse(why) => panic!("{}: {why}", path.display()),
        SnapshotPlan::Rewrite => {
            write();
            return;
        }
        SnapshotPlan::WriteMissing => {
            write();
            eprintln!("snapshot {} written; review it", path.display());
            return;
        }
        SnapshotPlan::Compare => {}
    }
    let expected = existing.unwrap_or_default();
    assert_eq!(
        expected.replace("\r\n", "\n"),
        actual,
        "snapshot {name} differs; if intended, re-run with NRR_TUI_UPDATE_SNAPSHOTS=1 and review"
    );
}

pub fn texts_en() -> crate::i18n::Texts {
    crate::i18n::Texts::load(Some("en"), &[])
}

/// An interface that has heard `link` and, when given, the fixture's snapshot.
/// The snapshot arrives while connected, as it does in the program.
pub fn app_at(link: crate::link::Link, fixture: Option<&Fixture>) -> crate::state::AppState {
    use crate::backend::BackendEvent;
    let texts = texts_en();
    let now = std::time::Instant::now();
    let mut app = crate::state::AppState::new(crate::screens::ScreenId::Status, false);
    if let Some(f) = fixture {
        app.apply(
            BackendEvent::Link(crate::link::Link::Connected),
            &texts,
            now,
        );
        // The reads every connect starts are not what these tests look at.
        app.outbox.take();
        app.apply(BackendEvent::Snapshot(Box::new(f.snapshot())), &texts, now);
    }
    app.apply(BackendEvent::Link(link), &texts, now);
    app
}

/// The service's report about one role's rules.
pub fn enforcement(status: &str, role: &str) -> crate::backend::BackendEvent {
    crate::backend::BackendEvent::Push(crate::backend::PushEvent::Status(Box::new(
        nrr_shared::ipc_payloads::StatusUpdateEvent::EnforcementStatusChanged {
            sid: "S".into(),
            status: status.into(),
            role: role.into(),
            candidates: Vec::new(),
            since_unix_ms: None,
            quiet: false,
        },
    )))
}

/// A service manager holding a stopped service; a start does what `start`
/// says.
pub struct StoppedService {
    pub start: Result<(), nrr_platform_api::service_control::ServiceControlError>,
}

impl nrr_platform_api::service_control::ServiceControlPort for StoppedService {
    fn install(
        &self,
        _spec: &nrr_platform_api::service_control::ServiceInstallSpec,
    ) -> Result<
        nrr_platform_api::service_control::ServiceInstallReport,
        nrr_platform_api::service_control::ServiceControlError,
    > {
        Err(
            nrr_platform_api::service_control::ServiceControlError::Unsupported {
                operation: "install",
            },
        )
    }

    fn uninstall(
        &self,
        _spec: &nrr_platform_api::service_control::ServiceUninstallSpec,
    ) -> Result<
        nrr_platform_api::service_control::ServiceUninstallReport,
        nrr_platform_api::service_control::ServiceControlError,
    > {
        Err(
            nrr_platform_api::service_control::ServiceControlError::Unsupported {
                operation: "uninstall",
            },
        )
    }

    fn start(
        &self,
        _timeout: Duration,
    ) -> Result<(), nrr_platform_api::service_control::ServiceControlError> {
        self.start.clone()
    }

    fn stop(
        &self,
        _timeout: Duration,
    ) -> Result<(), nrr_platform_api::service_control::ServiceControlError> {
        Ok(())
    }

    fn query(
        &self,
    ) -> Result<
        Option<nrr_platform_api::service_control::ServiceStatusReport>,
        nrr_platform_api::service_control::ServiceControlError,
    > {
        Ok(Some(
            nrr_platform_api::service_control::ServiceStatusReport {
                run_state: nrr_platform_api::service_control::ServiceRunState::Stopped,
                start_mode: None,
                binary_path: None,
                running_since: None,
            },
        ))
    }
}

/// A probe finding a stopped service that starts.
pub fn stopped_service() -> Option<Box<dyn nrr_platform_api::service_control::ServiceControlPort>> {
    Some(Box::new(StoppedService { start: Ok(()) }))
}

/// A probe finding a stopped service whose start is refused for want of rights.
pub fn stopped_service_refusing(
) -> Option<Box<dyn nrr_platform_api::service_control::ServiceControlPort>> {
    Some(Box::new(StoppedService {
        start: Err(nrr_platform_api::service_control::ServiceControlError::AccessDenied),
    }))
}

/// The ids of `keys` that either locale file lacks, as `lang:id`.
pub fn missing_from_locales(keys: &[crate::i18n::Key]) -> Vec<String> {
    let mut missing = Vec::new();
    for language in ["en", "ru"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../locales")
            .join(format!("{language}.json"));
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let root: Value = serde_json::from_str(raw.trim_start_matches('\u{feff}'))
            .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        for k in keys {
            let found =
                k.id.split('.')
                    .try_fold(&root, |node, part| node.get(part))
                    .and_then(Value::as_str)
                    .is_some();
            if !found {
                missing.push(format!("{language}:{}", k.id));
            }
        }
    }
    missing
}

/// A directory of a test's own under the temp folder, removed when the test
/// ends.
pub struct Scratch(std::path::PathBuf);

impl Scratch {
    pub fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("nrr-tui-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        Self(dir)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A file this process can no longer open while the value lives: held without
/// sharing, as another program locks it (Windows), or with every permission
/// taken away (Unix).
pub struct HeldFile {
    #[cfg(windows)]
    _held: std::fs::File,
    #[cfg(not(windows))]
    path: std::path::PathBuf,
}

/// `None` where nothing shuts this process out (root on Unix): the caller
/// skips rather than proves nothing.
pub fn hold_unreadable(path: &std::path::Path) -> Option<HeldFile> {
    #[cfg(windows)]
    let held = {
        use std::os::windows::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(path)
            .unwrap_or_else(|e| panic!("hold {}: {e}", path.display()));
        HeldFile { _held: file }
    };
    #[cfg(not(windows))]
    let held = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000))
            .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
        HeldFile {
            path: path.to_owned(),
        }
    };
    std::fs::File::open(path).is_err().then_some(held)
}

#[cfg(not(windows))]
impl Drop for HeldFile {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o644));
    }
}

#[cfg(test)]
mod snapshot_plan_tests {
    use super::{snapshot_plan, SnapshotPlan};

    #[test]
    fn ci_never_rewrites_a_snapshot_even_when_asked() {
        for exists in [true, false] {
            assert!(
                matches!(snapshot_plan(true, true, exists), SnapshotPlan::Refuse(_)),
                "an update request under CI must fail, not rewrite (file exists: {exists})"
            );
        }
        assert!(matches!(
            snapshot_plan(false, true, false),
            SnapshotPlan::Refuse(_)
        ));
        assert_eq!(snapshot_plan(false, true, true), SnapshotPlan::Compare);
    }
}
