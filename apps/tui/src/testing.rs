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
        "block-secondary-when-unavailable": true,
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
            "components": [],
            "degraded-modes": []
        },
        "adapters": { "data-source": "windows-live", "adapters": [], "rows": rows },
        "diagnostics": serde_json::to_value(DiagnosticsStatusDto::unavailable())
            .unwrap_or(Value::Null),
        "active-alerts-count": 0,
        "route-policy": policy,
        "routing-paused": f.paused
    })
}

/// Compare `actual` with `tests/snapshots/<name>.txt`. A missing file is
/// written on a developer machine (review it before keeping it) and fails under
/// `CI`; `NRR_TUI_UPDATE_SNAPSHOTS` rewrites a file that differs.
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
    if std::env::var_os("NRR_TUI_UPDATE_SNAPSHOTS").is_some() {
        write();
        return;
    }
    let Ok(expected) = std::fs::read_to_string(&path) else {
        assert!(
            std::env::var_os("CI").is_none(),
            "snapshot {} is missing",
            path.display()
        );
        write();
        eprintln!("snapshot {} written; review it", path.display());
        return;
    };
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
        },
    )))
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
