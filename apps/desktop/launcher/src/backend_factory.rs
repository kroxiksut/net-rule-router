//! Backend selection logic for the launcher.
//!
//! The GUI launcher boots in one of three backend modes:
//! - `mock` — `MockBackendFacade` (deterministic snapshots, no IPC).
//! - `preview-local` — `PreviewLocalBackendFacade` (same shape as mock
//!   today but reserved for future local-only enforcement preview).
//! - default — the real `IpcBackendFacade` over the named-pipe transport
//!   to the running service. If the IPC connect probe times out, the
//!   launcher falls back to `MockBackendFacade` and surfaces the
//!   degradation through [`BackendConnectionStatus::Disconnected`] so
//!   the connection banner in QML can paint.
//!
//! Mode selection: the `NRR_BACKEND` env var. Unset / unrecognised →
//! default IPC mode. Recognised slugs are case-insensitive.
//!
//! ## Why this lives in the launcher (and not GUI lib)
//!
//! The launcher is the only process that has both `nrr-application`
//! (`MockBackendFacade`, `BackendFacade` trait) and `nrr-ipc-client`
//! (`ServiceIpcClient`, `IpcBackendFacade`) in scope. The GUI lib
//! (`nrr-desktop-gui`) consumes the resulting `Arc<dyn BackendFacade>`
//! through its public function signatures; it never instantiates a
//! facade itself.

use std::sync::Arc;
use std::time::{Duration, Instant};

use nrr_application::backend_facade::{
    BackendConnectionStatus, BackendFacade, MockBackendFacade, PreviewLocalBackendFacade,
};
use nrr_ipc_client::{ConnectionStatus, IpcBackendFacade, ServiceIpcClient};

/// How long the launcher waits for the named-pipe client to reach
/// `Connected` before deciding the service is unreachable. The IPC
/// worker thread keeps reconnecting in the background regardless;
/// this only governs cold-start UX.
///
/// A running service connects in well under 100ms, so the common case
/// is unaffected; when the service is OFF this is the only place startup
/// blocks, so a tight budget keeps the window appearing fast. If the
/// service is unreachable here, the GUI starts on the mock backend with
/// a `Connecting` status and the 3s `backendStatusPoll` upgrades it to
/// live data once the background client connects.
pub const IPC_PROBE_TIMEOUT: Duration = Duration::from_millis(800);
/// Longer re-probe budget after auto-starting a DemandStart service. The
/// service was just launched, so the pipe is coming up; the reconnect
/// worker's backoff (capped at 5 s) needs more headroom than the cold
/// 800 ms probe.
pub const IPC_REPROBE_AFTER_START: Duration = Duration::from_secs(6);

/// Backend selection requested by the operator (or default).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendChoice {
    /// Hard-coded mock data; no IPC transport spun up.
    Mock,
    /// Same shape as [`Self::Mock`] today; reserved for the future
    /// local-only enforcement preview path.
    PreviewLocal,
    /// Production: try real IPC first, fall back to mock with
    /// `Disconnected` status if the service is unreachable.
    Ipc,
}

impl BackendChoice {
    /// Reads `NRR_BACKEND` from the process env. Unrecognised /
    /// unset → [`Self::Ipc`] (the production default).
    pub fn from_env() -> Self {
        match std::env::var("NRR_BACKEND") {
            Ok(raw) => Self::from_slug(raw.trim()),
            Err(_) => Self::Ipc,
        }
    }

    /// Case-insensitive slug parser for use by `from_env` and by tests
    /// that want to override the choice without mutating env vars.
    pub fn from_slug(raw: &str) -> Self {
        match raw.to_ascii_lowercase().as_str() {
            "mock" => Self::Mock,
            "preview-local" | "preview_local" | "previewlocal" => Self::PreviewLocal,
            // empty string OR "ipc" OR anything we don't recognise →
            // production default. We deliberately don't error on
            // unknown values; ops sometimes typo the env var and we'd
            // rather degrade gracefully than refuse to launch.
            _ => Self::Ipc,
        }
    }
}

/// Built backend bundle returned to the launcher.
pub struct BackendBundle {
    pub facade: Arc<dyn BackendFacade>,
    pub status: BackendConnectionStatus,
    pub choice: BackendChoice,
}

/// Construct the backend per `choice`. For [`BackendChoice::Ipc`] this
/// briefly probes the named-pipe transport; on connect failure the
/// returned facade is a `MockBackendFacade` and `status` is
/// `Disconnected{...}` so the GUI can paint a banner.
///
/// The IPC client is spun up regardless on the IPC path — the worker
/// thread keeps reconnecting in the background even when the initial
/// probe failed, so a service that comes online after the GUI started
/// will still surface live data on the next IPC round-trip.
pub fn create_backend(choice: BackendChoice) -> BackendBundle {
    match choice {
        BackendChoice::Mock => BackendBundle {
            facade: Arc::new(MockBackendFacade) as Arc<dyn BackendFacade>,
            status: BackendConnectionStatus::Connected,
            choice,
        },
        BackendChoice::PreviewLocal => BackendBundle {
            facade: Arc::new(PreviewLocalBackendFacade) as Arc<dyn BackendFacade>,
            status: BackendConnectionStatus::Connected,
            choice,
        },
        BackendChoice::Ipc => build_ipc_bundle(),
    }
}

fn build_ipc_bundle() -> BackendBundle {
    let client = Arc::new(ServiceIpcClient::start());
    let connected = wait_for_connect(&client, IPC_PROBE_TIMEOUT);
    if connected {
        match IpcBackendFacade::with_service_transport(Arc::clone(&client)) {
            Ok(facade) => BackendBundle {
                facade: Arc::new(facade) as Arc<dyn BackendFacade>,
                status: BackendConnectionStatus::Connected,
                choice: BackendChoice::Ipc,
            },
            Err(e) => {
                eprintln!(
                    "nrr-launcher: IPC facade construction failed ({e}); falling back to mock"
                );
                fallback_with_status(BackendConnectionStatus::Disconnected {
                    last_error: format!("ipc facade init failed: {e}"),
                })
            }
        }
    } else if let Some(bundle) = try_demand_start_on_this_os(&client) {
        bundle
    } else {
        let status = ipc_status_to_backend_status(client.connection_status());
        eprintln!("nrr-launcher: IPC connect probe failed ({status:?}); using mock backend");
        fallback_with_status(status)
    }
}

/// When the first IPC probe fails, the service may be configured
/// DemandStart (start on app launch). If so, the interactive user holds a
/// `SERVICE_START` grant, so start it now (no UAC) and re-probe. A
/// non-DemandStart service (no grant) returns `NotStartable` → `None`, and
/// the caller falls straight through to the mock backend. Returns
/// `Some(bundle)` only when the service started AND the IPC re-probe
/// connected.
#[cfg(target_os = "windows")]
fn try_demand_start_on_this_os(client: &Arc<ServiceIpcClient>) -> Option<BackendBundle> {
    use nrr_broker::DemandStartOutcome;
    let outcome = nrr_broker::try_start_demand_service();
    if !matches!(
        outcome,
        DemandStartOutcome::Started | DemandStartOutcome::AlreadyRunning
    ) {
        return None;
    }
    eprintln!("nrr-launcher: started DemandStart service ({outcome:?}); re-probing IPC");
    if !wait_for_connect(client, IPC_REPROBE_AFTER_START) {
        return None;
    }
    match IpcBackendFacade::with_service_transport(Arc::clone(client)) {
        Ok(facade) => Some(BackendBundle {
            facade: Arc::new(facade) as Arc<dyn BackendFacade>,
            status: BackendConnectionStatus::Connected,
            choice: BackendChoice::Ipc,
        }),
        Err(e) => {
            eprintln!("nrr-launcher: IPC facade init failed after demand-start ({e}); using mock");
            None
        }
    }
}

/// Unix has no analog: the service is a systemd unit, started by systemd, and
/// nothing the desktop session may start on demand without asking for a
/// privilege. A failed connect is simply a failed connect here.
#[cfg(not(target_os = "windows"))]
fn try_demand_start_on_this_os(_client: &Arc<ServiceIpcClient>) -> Option<BackendBundle> {
    None
}

fn fallback_with_status(status: BackendConnectionStatus) -> BackendBundle {
    BackendBundle {
        facade: Arc::new(MockBackendFacade) as Arc<dyn BackendFacade>,
        status,
        choice: BackendChoice::Ipc,
    }
}

/// Polls the client status with a short sleep cadence until either
/// `Connected` is reached or the deadline elapses. Returns `true` on
/// connect, `false` on timeout / terminal failure.
fn wait_for_connect(client: &ServiceIpcClient, deadline: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        match client.connection_status() {
            ConnectionStatus::Connected => return true,
            ConnectionStatus::ProtocolMismatch { .. } | ConnectionStatus::NotInstalled => {
                return false
            }
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    false
}

fn ipc_status_to_backend_status(s: ConnectionStatus) -> BackendConnectionStatus {
    match s {
        ConnectionStatus::Connected => BackendConnectionStatus::Connected,
        ConnectionStatus::Connecting => BackendConnectionStatus::Connecting,
        ConnectionStatus::Disconnected { last_error } => {
            BackendConnectionStatus::Disconnected { last_error }
        }
        ConnectionStatus::ServiceStopped => BackendConnectionStatus::ServiceStopped,
        ConnectionStatus::NotInstalled => BackendConnectionStatus::ServiceNotInstalled,
        ConnectionStatus::ProtocolMismatch {
            server_version,
            client_version,
        } => BackendConnectionStatus::ProtocolMismatch {
            server_version,
            client_version,
        },
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_slug_recognises_mock_and_preview_local_case_insensitive() {
        assert_eq!(BackendChoice::from_slug("mock"), BackendChoice::Mock);
        assert_eq!(BackendChoice::from_slug("MOCK"), BackendChoice::Mock);
        assert_eq!(
            BackendChoice::from_slug("preview-local"),
            BackendChoice::PreviewLocal
        );
        assert_eq!(
            BackendChoice::from_slug("Preview_Local"),
            BackendChoice::PreviewLocal
        );
        assert_eq!(
            BackendChoice::from_slug("previewlocal"),
            BackendChoice::PreviewLocal
        );
    }

    #[test]
    fn from_slug_unknown_falls_through_to_ipc() {
        assert_eq!(BackendChoice::from_slug(""), BackendChoice::Ipc);
        assert_eq!(BackendChoice::from_slug("ipc"), BackendChoice::Ipc);
        assert_eq!(BackendChoice::from_slug("real"), BackendChoice::Ipc);
        assert_eq!(BackendChoice::from_slug("typo"), BackendChoice::Ipc);
    }

    #[test]
    fn create_backend_mock_returns_connected() {
        let bundle = create_backend(BackendChoice::Mock);
        assert_eq!(bundle.choice, BackendChoice::Mock);
        assert_eq!(bundle.status, BackendConnectionStatus::Connected);
        // Smoke: status snapshot is callable and returns the mock data.
        let _ = bundle.facade.status_snapshot();
    }

    #[test]
    fn create_backend_preview_local_returns_connected() {
        let bundle = create_backend(BackendChoice::PreviewLocal);
        assert_eq!(bundle.choice, BackendChoice::PreviewLocal);
        assert_eq!(bundle.status, BackendConnectionStatus::Connected);
        let _ = bundle.facade.status_snapshot();
    }

    /// IPC mode in a test environment falls back to mock because no
    /// service is bound on the test pipe. The fallback is observable
    /// through `BackendConnectionStatus::Disconnected` (or one of the
    /// sibling failure variants); the facade still serves snapshots
    /// from the mock so the GUI never sees `None`.
    #[test]
    fn create_backend_ipc_falls_back_to_mock_when_service_unreachable() {
        // Constrain the probe so the test isn't slow.
        let bundle = create_backend(BackendChoice::Ipc);
        assert_eq!(bundle.choice, BackendChoice::Ipc);
        assert!(
            !matches!(bundle.status, BackendConnectionStatus::Connected),
            "expected non-Connected fallback status, got {:?}",
            bundle.status
        );
        // Mock fallback must still be callable.
        let _ = bundle.facade.status_snapshot();
    }

    #[test]
    fn ipc_status_mapping_round_trip() {
        assert_eq!(
            ipc_status_to_backend_status(ConnectionStatus::Connected),
            BackendConnectionStatus::Connected,
        );
        assert_eq!(
            ipc_status_to_backend_status(ConnectionStatus::Connecting),
            BackendConnectionStatus::Connecting,
        );
        assert_eq!(
            ipc_status_to_backend_status(ConnectionStatus::Disconnected {
                last_error: "x".into(),
            }),
            BackendConnectionStatus::Disconnected {
                last_error: "x".into(),
            },
        );
        assert_eq!(
            ipc_status_to_backend_status(ConnectionStatus::ServiceStopped),
            BackendConnectionStatus::ServiceStopped,
        );
        assert_eq!(
            ipc_status_to_backend_status(ConnectionStatus::NotInstalled),
            BackendConnectionStatus::ServiceNotInstalled,
        );
        assert_eq!(
            ipc_status_to_backend_status(ConnectionStatus::ProtocolMismatch {
                server_version: 2,
                client_version: 1,
            }),
            BackendConnectionStatus::ProtocolMismatch {
                server_version: 2,
                client_version: 1,
            },
        );
    }
}
