//! Connection state machine + reconnect policy.
//!
//! ## State machine
//!
//! ```text
//! NotInstalled ──[SCM detects install]──► Disconnected
//! Disconnected ──[connect attempt]────────► Connecting
//! Connecting ──[CreateFileW OK + handshake OK]──► Connected
//! Connecting ──[CreateFileW fail]─────────► Disconnected (backoff)
//! Connecting ──[handshake fail]───────────► ProtocolMismatch (terminal)
//! Connected ──[read error / EOF]──────────► Disconnected (backoff)
//! Any state ──[client drop]───────────────► Closed
//! ```
//!
//! ## Reconnect policy (exponential backoff with jitter)
//!
//! - Initial delay: 100ms
//! - Multiplier: 2x
//! - Max delay (when in `Disconnected`): 5s
//! - Max delay (when in `ServiceStopped` / `NotInstalled`): 30s
//!   (no point hammering when SCM says service isn't there)
//! - Jitter: ±20% random
//! - Reset backoff on successful Connect
//!
//! No max retries — the client tries forever (service may be reinstalled
//! or restarted at any time).

use std::time::Duration;

use serde_json::Value;

use nrr_shared::ipc::IpcOperationName;

/// Public connection status surfaced to GUI for UX banners.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Pipe handshake succeeded; client is talking to the service.
    Connected,
    /// In the middle of a connect or handshake attempt.
    Connecting,
    /// Pipe is currently down. `last_error` is a human-readable English
    /// detail for diagnostics; the client is reconnecting in the
    /// background.
    Disconnected { last_error: String },
    /// SCM says the service exists but is not running. Auto-reconnect
    /// keeps polling SCM; resumes connect attempts when service starts.
    ServiceStopped,
    /// SCM says the service is not installed. No connect attempts; the
    /// client polls SCM at low frequency until install is detected.
    NotInstalled,
    /// Server protocol version is incompatible with this client. Terminal:
    /// no auto-reconnect; user must update one side.
    ProtocolMismatch {
        server_version: u32,
        client_version: u32,
    },
}

impl ConnectionStatus {
    /// True when the client can serve `call()` requests.
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }

    /// True when the client is in a state where reconnect attempts
    /// are happening (or about to happen).
    pub fn is_reconnecting(&self) -> bool {
        matches!(self, Self::Connecting | Self::Disconnected { .. })
    }

    /// True when the underlying issue requires user action (install
    /// service, update one side, start service from Settings).
    pub fn requires_user_action(&self) -> bool {
        matches!(
            self,
            Self::NotInstalled | Self::ServiceStopped | Self::ProtocolMismatch { .. }
        )
    }
}

/// Errors returned by `NamedPipeIpcClient::call`.
#[derive(Debug)]
pub enum IpcClientError {
    /// Client is not connected; the request was not sent.
    Disconnected,
    /// Request sent but no response within the per-call timeout.
    Timeout,
    /// Server returned a malformed response or the wire codec failed.
    BadResponse { reason: String },
    /// Server returned a structured error envelope. The router-level
    /// `IpcErrorCode` is preserved alongside the message so downstream
    /// surfaces (launcher RPC dispatcher → QML `errors.<code>.*` locale
    /// keys → OperationToast body) can render localized text instead of a
    /// generic catch-all.
    ServerError {
        op: nrr_shared::ipc::IpcOperationName,
        code: nrr_shared::ipc_transport::IpcErrorCode,
        message: String,
    },
    /// Serialisation of the request payload failed (programmer error).
    SerializationFailed(String),
    /// Internal channel (request/response queue) was closed.
    ClientShutdown,
}

impl std::fmt::Display for IpcClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "ipc client is not connected to the service"),
            Self::Timeout => write!(f, "ipc request timed out"),
            Self::BadResponse { reason } => write!(f, "ipc bad response: {reason}"),
            Self::ServerError { op, code, message } => {
                write!(
                    f,
                    "ipc server error for {} (code={:?}): {message}",
                    op.slug(),
                    code
                )
            }
            Self::SerializationFailed(s) => write!(f, "ipc request serialization failed: {s}"),
            Self::ClientShutdown => write!(f, "ipc client is shutting down"),
        }
    }
}

impl std::error::Error for IpcClientError {}

/// Abstract sink the [`crate::IpcBackendFacade`] talks to.
///
/// In production this is implemented by [`crate::NamedPipeIpcClient`].
/// In tests, [`crate::IpcBackendFacade`] consumes a
/// fake implementation so the cache-fallback semantics can be exercised
/// without spinning up a real Win32 named pipe.
///
/// `Send + Sync` because the facade lives behind an `Arc` and is
/// shared between the GUI worker thread and the QML render thread.
pub trait IpcClient: Send + Sync {
    /// Issue one operation and block up to `timeout` for the response
    /// payload (already extracted from the IPC envelope).
    fn call(
        &self,
        operation: IpcOperationName,
        payload: Value,
        timeout: Duration,
    ) -> Result<Value, IpcClientError>;

    /// Snapshot of the current connection state.
    fn connection_status(&self) -> ConnectionStatus;

    /// Hint to drop any current connection and reconnect immediately.
    /// Production impl flips an atomic flag the worker thread polls;
    /// fakes can use it to simulate the "Retry connection" GUI button.
    fn force_reconnect(&self);

    /// Register a push-frame receiver for `StatusUpdatesSubscribe`-style
    /// server-pushed events. Default impl returns `None` (no push support);
    /// the production `NamedPipeIpcClient` overrides to forward unsolicited
    /// frames. Returning `None` is fine for tests / facades that don't need
    /// push delivery — the launcher's RPC dispatcher handles `None` by
    /// responding with `not-supported` to subscribe attempts.
    fn subscribe_push(&self) -> Option<std::sync::mpsc::Receiver<Value>> {
        None
    }

    /// Id the server currently knows this client's status subscription by, or
    /// `None` when it has never subscribed. NOT a constant: a reconnect
    /// re-subscribes and the server allocates a NEW id, so anything that labels
    /// forwarded push frames has to re-read it rather than cache the first one.
    /// Default impl returns `None` (no push support).
    fn active_subscription_id(&self) -> Option<String> {
        None
    }

    /// Snapshot of the most recent successful `ContractNegotiate` handshake.
    /// Default impl returns `None` (no negotiate-info tracking); the
    /// production `NamedPipeIpcClient` overrides to surface the cached
    /// payload for the GUI's compatibility banner.
    fn negotiate_info(&self) -> Option<NegotiateInfo> {
        None
    }
}

/// What a successful `ContractNegotiate` handshake reported. Carried
/// separately from `ConnectionStatus::Connected` because callers compare
/// these against their own `CLIENT_PROTOCOL_VERSION` / `gui_version` to
/// surface version drift even while the connection itself is fine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiateInfo {
    /// Protocol version the service speaks (`server-version` field of
    /// `ContractNegotiateResponse`).
    pub server_protocol: u32,
    /// Semver of the service binary (`env!("CARGO_PKG_VERSION")` of
    /// `nrr-windows-service`). Empty string when the server didn't emit
    /// the field.
    pub service_version: String,
    /// Opaque session id allocated by the server.
    pub session_id: String,
}

/// Backoff calculator. `attempt` starts at 0 (initial connect) and
/// increments on each failure.
pub struct ReconnectBackoff {
    base: Duration,
    cap: Duration,
    attempt: u32,
}

impl ReconnectBackoff {
    /// Default: 100ms initial, 5s cap. Used by `Disconnected` state.
    pub fn fast() -> Self {
        Self {
            base: Duration::from_millis(100),
            cap: Duration::from_secs(5),
            attempt: 0,
        }
    }

    /// Slower: 1s initial, 5s cap. Used by `ServiceStopped` /
    /// `NotInstalled` so SCM polling doesn't hammer the system while the
    /// service is down, while still letting the reconnecting worker
    /// re-probe within ~5s once the service comes back (so the GUI's red
    /// "no connection" banner clears promptly instead of sleeping out a
    /// long backoff after an extended outage).
    pub fn slow() -> Self {
        Self {
            base: Duration::from_secs(1),
            cap: Duration::from_secs(5),
            attempt: 0,
        }
    }

    /// Returns the delay to wait before the *next* attempt, then
    /// increments the internal counter. Includes ±20% jitter so multiple
    /// clients don't synchronise (relevant when GUI + Tray reconnect at
    /// the same time after service restart).
    pub fn next_delay(&mut self) -> Duration {
        let multiplier = 2u32.saturating_pow(self.attempt.min(10));
        let exp_ms = (self.base.as_millis() as u64).saturating_mul(multiplier as u64);
        let cap_ms = self.cap.as_millis() as u64;
        let target_ms = exp_ms.min(cap_ms);

        // Jitter ±20% using a tiny LCG seeded by attempt count + nanos.
        // No external dep on `rand` for a transport detail.
        let jitter_ratio = lcg_jitter(self.attempt);
        let jittered_ms = ((target_ms as i64) + (target_ms as i64 * jitter_ratio / 100))
            .max(self.base.as_millis() as i64) as u64;

        self.attempt = self.attempt.saturating_add(1);
        Duration::from_millis(jittered_ms)
    }

    /// Reset to initial state (used after a successful Connect).
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// Small deterministic-but-varied jitter generator returning ±20.
/// Source: linear congruential generator seeded by attempt + nanos so
/// concurrent clients don't pick identical sequences.
fn lcg_jitter(attempt: u32) -> i64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let seed = (attempt as u64).wrapping_mul(2_862_933_555_777_941_757) ^ nanos as u64;
    let r = seed.wrapping_mul(6_364_136_223_846_793_005);
    let bucket = (r >> 32) as u32 % 41; // 0..=40
    bucket as i64 - 20 // -20..=+20
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_status_helpers_classify_correctly() {
        let c = ConnectionStatus::Connected;
        assert!(c.is_connected());
        assert!(!c.is_reconnecting());
        assert!(!c.requires_user_action());
    }

    #[test]
    fn disconnected_is_reconnecting_not_user_action() {
        let d = ConnectionStatus::Disconnected {
            last_error: "x".into(),
        };
        assert!(!d.is_connected());
        assert!(d.is_reconnecting());
        assert!(!d.requires_user_action());
    }

    #[test]
    fn not_installed_requires_user_action() {
        let n = ConnectionStatus::NotInstalled;
        assert!(!n.is_connected());
        assert!(n.requires_user_action());
    }

    #[test]
    fn service_stopped_requires_user_action() {
        let s = ConnectionStatus::ServiceStopped;
        assert!(s.requires_user_action());
    }

    #[test]
    fn protocol_mismatch_requires_user_action() {
        let p = ConnectionStatus::ProtocolMismatch {
            server_version: 2,
            client_version: 1,
        };
        assert!(p.requires_user_action());
        assert!(!p.is_connected());
    }

    #[test]
    fn fast_backoff_first_attempt_under_200ms() {
        let mut b = ReconnectBackoff::fast();
        let d = b.next_delay();
        assert!(d <= Duration::from_millis(200), "{d:?}");
    }

    #[test]
    fn fast_backoff_caps_at_around_5s() {
        let mut b = ReconnectBackoff::fast();
        for _ in 0..50 {
            let _ = b.next_delay();
        }
        let d = b.next_delay();
        assert!(d <= Duration::from_secs(7), "{d:?}");
    }

    #[test]
    fn slow_backoff_caps_at_around_5s() {
        let mut b = ReconnectBackoff::slow();
        for _ in 0..50 {
            let _ = b.next_delay();
        }
        let d = b.next_delay();
        // 5s cap + up to ±20% jitter.
        assert!(d <= Duration::from_secs(7), "{d:?}");
    }

    #[test]
    fn reset_returns_to_initial_delay() {
        let mut b = ReconnectBackoff::fast();
        for _ in 0..10 {
            let _ = b.next_delay();
        }
        b.reset();
        let d = b.next_delay();
        assert!(d <= Duration::from_millis(200), "{d:?}");
    }

    #[test]
    fn jitter_stays_in_bounds() {
        for attempt in 0..1000u32 {
            let j = lcg_jitter(attempt);
            assert!((-20..=20).contains(&j), "jitter {j} outside [-20,20]");
        }
    }

    #[test]
    fn ipc_client_error_display_includes_context() {
        let e = IpcClientError::Timeout;
        assert!(e.to_string().contains("timed out"));
        let e = IpcClientError::Disconnected;
        assert!(e.to_string().contains("not connected"));
    }
}
