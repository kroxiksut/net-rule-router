//! Launcher-side handle to the session elevation broker.
//!
//! The non-elevated launcher calls [`Broker::call`] when the service
//! rejects a privileged mutation with `Forbidden`. The first such call
//! spawns the elevated broker (one UAC prompt) and caches the session;
//! every later call reuses it with no prompt. If the broker has died, the
//! next call re-spawns it once.
//!
//! Calls are serialized by an internal mutex — privileged mutations are
//! inherently one-at-a-time (a single apply/commit at a time), and
//! serializing keeps the spawn/reuse bookkeeping race-free.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::protocol::derive_pipe_name;
#[cfg(target_os = "windows")]
use crate::protocol::{build_broker_argv, BrokerRequest, BrokerResponse, BROKER_PING};

/// How long the readiness ping waits for the freshly spawned broker to
/// create its pipe (covers process startup after UAC was granted).
#[cfg(target_os = "windows")]
const READY_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// Connect timeout for a normal call to an already-running broker.
#[cfg(target_os = "windows")]
const CALL_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Shared, cloneable handle. Mirrors `SidecarHandle`'s `Arc` shape so the
/// RPC dispatcher can pass it to per-request worker threads.
pub type BrokerHandle = Arc<Broker>;

/// Construct a fresh broker handle (no process spawned yet — lazy on the
/// first privileged call).
pub fn new_handle() -> BrokerHandle {
    Arc::new(Broker {
        state: Mutex::new(None),
        last_used: Mutex::new(None),
    })
}

/// The live broker session, once spawned.
#[derive(Clone)]
struct Session {
    pipe_name: String,
    nonce: String,
}

pub struct Broker {
    state: Mutex<Option<Session>>,
    /// When the live session was last USED for a privileged call (set on
    /// spawn and refreshed on every successful relay; cleared on shutdown).
    /// Drives the idle auto-revoke: an elevated helper should not outlive
    /// the work it was approved for. Guarded separately from `state` — the
    /// two are only ever briefly out of sync, and the consumer
    /// (`revoke_if_idle`) tolerates staleness of one call.
    last_used: Mutex<Option<std::time::Instant>>,
}

/// Outcome of a broker-relayed call.
#[derive(Debug)]
pub enum BrokerCallError {
    /// User dismissed the UAC prompt. Surface "needs administrator".
    Declined,
    /// The broker could not be spawned/reached. The caller keeps the
    /// original `Forbidden` response.
    Unavailable(String),
    /// The broker reached the service, which returned a typed error.
    ServerError { code: String, message: String },
}

impl Broker {
    /// Relay one privileged operation through the elevated broker. Spawns
    /// the broker on first use; reuses (or re-spawns once) afterwards.
    pub fn call(
        &self,
        operation: &str,
        payload: &serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, BrokerCallError> {
        #[cfg(target_os = "windows")]
        {
            self.call_windows(operation, payload, timeout)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (operation, payload, timeout, &self.state, derive_pipe_name);
            Err(BrokerCallError::Unavailable(
                "elevation broker is only available on Windows".to_string(),
            ))
        }
    }

    /// Is an elevated broker session currently live? A cheap local read —
    /// no pipe round-trip, so a broker that died since its spawn still
    /// reads `true` until the next `call` notices and re-spawns. That
    /// staleness is acceptable for its one consumer: the GUI's
    /// "administrator rights are held" indicator, which polls this and
    /// self-corrects on the next tick after any state change.
    pub fn is_session_active(&self) -> bool {
        let guard = match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.is_some()
    }

    /// Mark the session as just-used (spawn and every successful relay).
    fn touch(&self) {
        let mut guard = match self.last_used.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *guard = Some(std::time::Instant::now());
    }

    /// Retire the elevated session if it has sat UNUSED for at least `idle`.
    /// Returns `true` when a session was actually revoked by this call.
    /// Never spawns; a no-op when no session is live. The idle clock restarts
    /// on every successful privileged relay (see `touch`), so a user actively
    /// working never loses the session mid-series — only an abandoned one is
    /// cleaned up.
    pub fn revoke_if_idle(&self, idle: Duration) -> bool {
        let idle_since = {
            let guard = match self.last_used.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            match *guard {
                Some(t) => t,
                None => return false,
            }
        };
        if idle_since.elapsed() < idle {
            return false;
        }
        self.shutdown_if_active()
    }

    /// Gracefully retire the broker IF a session is currently live. Backs the
    /// GUI's "revoke administrator approval"
    /// action: the elevated broker process exits, so the next privileged op
    /// prompts UAC again. NEVER spawns — with no live session this is a no-op
    /// (nothing to revoke). Best-effort: the local session handle is dropped
    /// regardless of whether the shutdown frame round-trips (a dead/unreachable
    /// broker is already effectively revoked). Returns `true` if a session was
    /// live and has now been retired.
    pub fn shutdown_if_active(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            {
                let mut used = match self.last_used.lock() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                *used = None;
            }
            let mut guard = match self.state.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let Some(session) = guard.take() else {
                return false;
            };
            let _ = perform_call(
                &session,
                crate::protocol::BROKER_SHUTDOWN,
                &serde_json::json!({}),
                Duration::from_secs(2),
                CALL_CONNECT_TIMEOUT,
            );
            true
        }
        #[cfg(not(target_os = "windows"))]
        {
            false
        }
    }
}

#[cfg(target_os = "windows")]
impl Broker {
    fn call_windows(
        &self,
        operation: &str,
        payload: &serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, BrokerCallError> {
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        // Ensure a session, spawning (one UAC) if needed.
        let session = match guard.as_ref() {
            Some(s) => s.clone(),
            None => {
                let s = self.spawn_session()?;
                *guard = Some(s.clone());
                s
            }
        };

        let result = match perform_call(&session, operation, payload, timeout, CALL_CONNECT_TIMEOUT)
        {
            Ok(resp) => map_response(resp),
            Err(transport) => {
                // Broker likely died (app idle, killed, crashed). Drop the
                // dead session and re-spawn once (a fresh UAC prompt).
                eprintln!("[nrr-broker] call transport failure ({transport}); re-spawning");
                *guard = None;
                let session = self.spawn_session()?;
                *guard = Some(session.clone());
                match perform_call(&session, operation, payload, timeout, CALL_CONNECT_TIMEOUT) {
                    Ok(resp) => map_response(resp),
                    Err(e) => Err(BrokerCallError::Unavailable(e)),
                }
            }
        };
        // Any relay that reached the broker counts as "used" — including a
        // typed server error (the user is actively working; only transport
        // failure means the session was already gone).
        if !matches!(result, Err(BrokerCallError::Unavailable(_))) {
            self.touch();
        }
        result
    }

    /// Spawn the elevated broker (one UAC) and confirm readiness with a
    /// nonce-authenticated ping.
    fn spawn_session(&self) -> Result<Session, BrokerCallError> {
        use crate::spawn::{
            generate_nonce, generate_pipe_suffix, spawn_elevated_broker, write_token_file,
            SpawnOutcome,
        };
        use crate::windows_sys::current_process_user_sid;

        let own_sid = current_process_user_sid()
            .map_err(|e| BrokerCallError::Unavailable(format!("own SID: {e}")))?;
        let nonce =
            generate_nonce().map_err(|e| BrokerCallError::Unavailable(format!("nonce: {e}")))?;
        let suffix = generate_pipe_suffix()
            .map_err(|e| BrokerCallError::Unavailable(format!("suffix: {e}")))?;
        let pid = std::process::id();
        let pipe_name = derive_pipe_name(pid, &suffix);
        let token_file = write_token_file(pid, &suffix, &nonce)
            .map_err(|e| BrokerCallError::Unavailable(format!("token file: {e}")))?;
        let exe = std::env::current_exe()
            .map_err(|e| BrokerCallError::Unavailable(format!("current_exe: {e}")))?;
        let token_file_str = token_file.to_string_lossy().to_string();
        let argv = build_broker_argv(&pipe_name, pid, &own_sid, &token_file_str);

        let outcome = spawn_elevated_broker(&exe, &argv);
        match outcome {
            SpawnOutcome::Launched => {}
            SpawnOutcome::Declined => {
                let _ = std::fs::remove_file(&token_file);
                return Err(BrokerCallError::Declined);
            }
            SpawnOutcome::Failed(e) => {
                let _ = std::fs::remove_file(&token_file);
                return Err(BrokerCallError::Unavailable(e));
            }
        }

        let session = Session { pipe_name, nonce };
        // Readiness handshake: a nonce-authenticated ping with a generous
        // connect timeout (the broker is still starting after UAC).
        let ping = perform_call(
            &session,
            BROKER_PING,
            &serde_json::json!({}),
            Duration::from_secs(2),
            READY_CONNECT_TIMEOUT,
        );
        // Token file is consumed by the broker; clean up any leftover.
        let _ = std::fs::remove_file(&token_file);
        match ping {
            Ok(resp) if resp.ok => Ok(session),
            Ok(_) => Err(BrokerCallError::Unavailable(
                "broker rejected readiness ping".to_string(),
            )),
            Err(e) => Err(BrokerCallError::Unavailable(format!(
                "broker did not become ready: {e}"
            ))),
        }
    }
}

#[cfg(target_os = "windows")]
fn map_response(resp: BrokerResponse) -> Result<serde_json::Value, BrokerCallError> {
    if resp.ok {
        Ok(resp.payload.unwrap_or(serde_json::Value::Null))
    } else {
        Err(BrokerCallError::ServerError {
            code: resp.error_code.unwrap_or_else(|| "internal".to_string()),
            message: resp.error_message.unwrap_or_default(),
        })
    }
}

/// Open a fresh connection, send one request, read one response. Returns
/// `Err(String)` only for TRANSPORT failures (connect/read/write) — a
/// well-formed error response from the broker is returned as `Ok` and
/// mapped by [`map_response`].
#[cfg(target_os = "windows")]
fn perform_call(
    session: &Session,
    operation: &str,
    payload: &serde_json::Value,
    timeout: Duration,
    connect_timeout: Duration,
) -> Result<BrokerResponse, String> {
    use nrr_ipc_client::wire::{read_frame, write_frame};

    use crate::windows_sys::{connect_pipe, PipeIo};

    let handle =
        connect_pipe(&session.pipe_name, connect_timeout).map_err(|e| format!("connect: {e}"))?;
    let mut io = PipeIo::new(handle.raw()).map_err(|e| format!("pipe io: {e}"))?;
    let request = BrokerRequest {
        nonce: session.nonce.clone(),
        operation: operation.to_string(),
        payload: payload.clone(),
        timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
    };
    write_frame(&mut io, &request).map_err(|e| format!("write: {e}"))?;
    let response: BrokerResponse = read_frame(&mut io).map_err(|e| format!("read: {e}"))?;
    Ok(response)
    // `handle` (OwnedHandle) drops here → CloseHandle.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_handle_starts_with_no_session() {
        let h = new_handle();
        assert!(h.state.lock().unwrap().is_none());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn call_is_unavailable_off_windows() {
        let h = new_handle();
        let r = h.call(
            "mutation.submit",
            &serde_json::json!({}),
            Duration::from_secs(1),
        );
        assert!(matches!(r, Err(BrokerCallError::Unavailable(_))));
    }
}
