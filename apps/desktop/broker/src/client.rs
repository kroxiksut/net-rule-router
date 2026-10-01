//! Launcher-side handle to the session elevation broker.
//!
//! The non-elevated launcher calls [`Broker::call`] when the service rejects a
//! privileged mutation with `Forbidden`. The first call spawns the elevated
//! broker (one UAC prompt); later calls reuse it. A broker is re-spawned only
//! once it is proven gone — nothing serves its pipe name any more — and a
//! request that may have reached it is never sent again: a second `reinstall`
//! on top of a running one is not a retry.
//!
//! Relays are serialized here because the broker answers one connection at a
//! time: queueing in the launcher keeps each call's wait about its own work,
//! not about whatever was ahead of it.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use crate::protocol::{build_broker_argv, derive_pipe_name, BrokerRequest, BROKER_SHUTDOWN};
use crate::protocol::{client_answer_timeout, BrokerResponse, BROKER_PING};
#[cfg(target_os = "windows")]
use crate::windows_sys::NoFlush;

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
        relay: Mutex::new(()),
        unanswered: Mutex::new(None),
    })
}

/// The live broker session, once spawned.
#[derive(Clone, Debug)]
struct Session {
    pipe_name: String,
    nonce: String,
}

pub struct Broker {
    state: Mutex<Option<Session>>,
    /// When the live session was last used for a privileged call. Drives the
    /// idle auto-revoke: an elevated helper should not outlive the work it was
    /// approved for. Separate from `state`; `revoke_if_idle` tolerates one
    /// call of staleness.
    last_used: Mutex<Option<Instant>>,
    /// Held for one whole relay. Never taken by the status poll or by revoke.
    relay: Mutex<()>,
    /// Pipe of the session still working on a request we stopped waiting for.
    /// Until it finishes the broker answers nothing else, so the next call
    /// asks whether it is free before handing it more work.
    unanswered: Mutex<Option<String>>,
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
    /// The broker is alive and still busy — with this request, which may yet
    /// complete, or with an earlier one, in which case this one was not sent.
    StillRunning(String),
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl Broker {
    /// Relay one privileged operation through the elevated broker. Spawns
    /// the broker on first use; reuses it afterwards. `timeout` bounds a
    /// relayed service call; broker-local operations carry their own budget.
    pub fn call(
        &self,
        operation: &str,
        payload: &serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, BrokerCallError> {
        #[cfg(target_os = "windows")]
        {
            self.relay(&PipeTransport, operation, payload, timeout)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (operation, payload, timeout);
            Err(BrokerCallError::Unavailable(
                "elevation broker is only available on Windows".to_string(),
            ))
        }
    }

    /// Is an elevated broker session currently live? A cheap local read —
    /// no pipe round-trip, so a broker that died since its spawn still reads
    /// `true` until the next `call` notices. Fine for its one consumer, the
    /// GUI's "administrator rights are held" indicator, which polls.
    pub fn is_session_active(&self) -> bool {
        lock(&self.state).is_some()
    }

    /// Mark the session as just-used (every relay that reached the broker).
    fn touch(&self) {
        *lock(&self.last_used) = Some(Instant::now());
    }

    /// Retire the elevated session if it has sat UNUSED for at least `idle`.
    /// Returns `true` when a session was actually revoked by this call.
    /// Never spawns; the idle clock restarts on every relay that reached the
    /// broker, so a user actively working never loses the session mid-series.
    pub fn revoke_if_idle(&self, idle: Duration) -> bool {
        let idle_since = match *lock(&self.last_used) {
            Some(t) => t,
            None => return false,
        };
        if idle_since.elapsed() < idle {
            return false;
        }
        self.shutdown_if_active()
    }

    /// Gracefully retire the broker IF a session is currently live — the GUI's
    /// "revoke administrator approval". NEVER spawns. Best-effort: the local
    /// session is dropped whether or not the shutdown frame round-trips. Returns
    /// `true` if a session was live and has now been retired.
    pub fn shutdown_if_active(&self) -> bool {
        *lock(&self.last_used) = None;
        let Some(session) = lock(&self.state).take() else {
            return false;
        };
        *lock(&self.unanswered) = None;
        #[cfg(target_os = "windows")]
        {
            // Sent with no lock held: the session is already gone from our
            // state, so nothing else can be waiting on the answer.
            let _ = perform_call(
                &session,
                BROKER_SHUTDOWN,
                &serde_json::json!({}),
                Duration::ZERO,
                client_answer_timeout(BROKER_SHUTDOWN, Duration::ZERO),
                CALL_CONNECT_TIMEOUT,
            );
        }
        #[cfg(not(target_os = "windows"))]
        let _ = session;
        true
    }

    /// The relay state machine, over any transport.
    fn relay<T: Transport>(
        &self,
        transport: &T,
        operation: &str,
        payload: &serde_json::Value,
        requested: Duration,
    ) -> Result<serde_json::Value, BrokerCallError> {
        let _serial = lock(&self.relay);
        let mut session = self.session_or_spawn(transport)?;
        let mut respawned = false;
        if self.is_unanswered(&session) && !self.previous_request_finished(transport, &session)? {
            session = self.respawn(transport, &session)?;
            respawned = true;
        }
        let answer_timeout = client_answer_timeout(operation, requested);
        let result = loop {
            let failure =
                match transport.exchange(&session, operation, payload, requested, answer_timeout) {
                    Ok(response) => break map_response(response),
                    Err(failure) => failure,
                };
            let gone = match &failure {
                CallFailure::Absent(_) => true,
                CallFailure::Undelivered(_) => !transport.pipe_served(&session),
                _ => false,
            };
            if gone && !respawned {
                // Nothing was delivered, so sending it to a new broker runs it once.
                eprintln!("[nrr-broker] broker is gone ({failure}); re-spawning");
                session = self.respawn(transport, &session)?;
                respawned = true;
                continue;
            }
            break Err(self.after_failure(transport, &session, failure, answer_timeout));
        };
        if !matches!(result, Err(BrokerCallError::Unavailable(_))) {
            self.touch();
        }
        result
    }

    /// Whether the broker finished the request we stopped waiting for.
    /// `Ok(false)` means it is gone and a new one may be spawned: nothing of
    /// THIS call has been sent yet.
    fn previous_request_finished<T: Transport>(
        &self,
        transport: &T,
        session: &Session,
    ) -> Result<bool, BrokerCallError> {
        let ping = transport.exchange(
            session,
            BROKER_PING,
            &serde_json::json!({}),
            Duration::ZERO,
            client_answer_timeout(BROKER_PING, Duration::ZERO),
        );
        match ping {
            Ok(response) if response.ok => {
                *lock(&self.unanswered) = None;
                Ok(true)
            }
            Ok(_) => Err(BrokerCallError::Unavailable(
                "broker rejected the liveness ping".to_string(),
            )),
            Err(CallFailure::Absent(_)) => Ok(false),
            Err(CallFailure::Impostor(reason)) => {
                eprintln!("[nrr-broker] refusing broker pipe server: {reason}");
                self.forget_session(session);
                Err(BrokerCallError::Unavailable(reason))
            }
            Err(other) if !transport.pipe_served(session) => {
                eprintln!("[nrr-broker] broker is gone ({other})");
                Ok(false)
            }
            Err(_) => Err(BrokerCallError::StillRunning(
                "an earlier administrator operation is still running; this one was not started"
                    .to_string(),
            )),
        }
    }

    fn after_failure<T: Transport>(
        &self,
        transport: &T,
        session: &Session,
        failure: CallFailure,
        answer_timeout: Duration,
    ) -> BrokerCallError {
        match failure {
            CallFailure::Unanswered(_) => {
                *lock(&self.unanswered) = Some(session.pipe_name.clone());
                BrokerCallError::StillRunning(format!(
                    "no answer within {}s; the operation is still running and may complete",
                    answer_timeout.as_secs()
                ))
            }
            CallFailure::Lost(detail) => {
                if !transport.pipe_served(session) {
                    self.forget_session(session);
                }
                BrokerCallError::Unavailable(format!(
                    "broker closed the connection before answering ({detail}); \
                     the operation may or may not have run"
                ))
            }
            CallFailure::Impostor(reason) => {
                // Re-spawning would only raise another prompt for the same
                // squatter; the call fails instead of pretending to apply.
                eprintln!("[nrr-broker] refusing broker pipe server: {reason}");
                self.forget_session(session);
                BrokerCallError::Unavailable(reason)
            }
            CallFailure::Absent(detail) => {
                self.forget_session(session);
                BrokerCallError::Unavailable(detail)
            }
            CallFailure::Undelivered(detail) => BrokerCallError::Unavailable(detail),
        }
    }

    /// Returns the live session, spawning one (a single UAC prompt) if needed.
    /// The state lock is held across the spawn so two callers cannot raise two
    /// prompts.
    fn session_or_spawn<T: Transport>(&self, transport: &T) -> Result<Session, BrokerCallError> {
        let mut guard = lock(&self.state);
        if let Some(session) = guard.as_ref() {
            return Ok(session.clone());
        }
        let session = transport.spawn()?;
        *guard = Some(session.clone());
        Ok(session)
    }

    fn respawn<T: Transport>(
        &self,
        transport: &T,
        dead: &Session,
    ) -> Result<Session, BrokerCallError> {
        self.forget_session(dead);
        self.session_or_spawn(transport)
    }

    /// Drops `session` unless it has already been replaced.
    fn forget_session(&self, session: &Session) {
        let mut guard = lock(&self.state);
        if guard
            .as_ref()
            .is_some_and(|live| live.pipe_name == session.pipe_name)
        {
            *guard = None;
        }
        drop(guard);
        let mut unanswered = lock(&self.unanswered);
        if unanswered.as_deref() == Some(session.pipe_name.as_str()) {
            *unanswered = None;
        }
    }

    fn is_unanswered(&self, session: &Session) -> bool {
        lock(&self.unanswered).as_deref() == Some(session.pipe_name.as_str())
    }
}

/// Why a broker round-trip produced no response.
#[derive(Debug)]
enum CallFailure {
    /// Nothing serves the pipe name: the broker is gone, nothing was sent.
    Absent(String),
    /// Connecting or writing failed; the request did not reach the broker.
    Undelivered(String),
    /// Delivered, and no answer within the broker's own bound plus a margin.
    Unanswered(String),
    /// Delivered, and the connection closed before an answer.
    Lost(String),
    /// Something other than our elevated broker holds the pipe name.
    Impostor(String),
}

impl std::fmt::Display for CallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent(detail)
            | Self::Undelivered(detail)
            | Self::Unanswered(detail)
            | Self::Lost(detail)
            | Self::Impostor(detail) => f.write_str(detail),
        }
    }
}

/// The broker's process and wire, behind a seam so the respawn rules are
/// tested without a UAC prompt.
trait Transport {
    /// Spawn an elevated broker (one UAC prompt) and wait until it answers.
    fn spawn(&self) -> Result<Session, BrokerCallError>;
    /// One request and its answer on a fresh connection.
    fn exchange(
        &self,
        session: &Session,
        operation: &str,
        payload: &serde_json::Value,
        requested: Duration,
        answer_timeout: Duration,
    ) -> Result<BrokerResponse, CallFailure>;
    /// Whether anything still serves the session's pipe. The broker holds the
    /// name for its whole life, so `false` means it is gone.
    fn pipe_served(&self, session: &Session) -> bool;
}

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

#[cfg(target_os = "windows")]
struct PipeTransport;

#[cfg(target_os = "windows")]
impl Transport for PipeTransport {
    fn spawn(&self) -> Result<Session, BrokerCallError> {
        spawn_session()
    }

    fn exchange(
        &self,
        session: &Session,
        operation: &str,
        payload: &serde_json::Value,
        requested: Duration,
        answer_timeout: Duration,
    ) -> Result<BrokerResponse, CallFailure> {
        perform_call(
            session,
            operation,
            payload,
            requested,
            answer_timeout,
            CALL_CONNECT_TIMEOUT,
        )
    }

    fn pipe_served(&self, session: &Session) -> bool {
        crate::windows_sys::pipe_name_served(&session.pipe_name)
    }
}

/// Spawn the elevated broker (one UAC) and confirm readiness with a
/// nonce-authenticated ping.
#[cfg(target_os = "windows")]
fn spawn_session() -> Result<Session, BrokerCallError> {
    use crate::spawn::{
        generate_nonce, generate_pipe_suffix, spawn_elevated_broker, write_token_file, SpawnOutcome,
    };
    use crate::windows_sys::current_process_user_sid;

    let own_sid = current_process_user_sid()
        .map_err(|e| BrokerCallError::Unavailable(format!("own SID: {e}")))?;
    let nonce =
        generate_nonce().map_err(|e| BrokerCallError::Unavailable(format!("nonce: {e}")))?;
    let suffix =
        generate_pipe_suffix().map_err(|e| BrokerCallError::Unavailable(format!("suffix: {e}")))?;
    let pid = std::process::id();
    let pipe_name = derive_pipe_name(pid, &suffix);
    let token_file = write_token_file(pid, &suffix, &nonce)
        .map_err(|e| BrokerCallError::Unavailable(format!("token file: {e}")))?;
    let exe = std::env::current_exe()
        .map_err(|e| BrokerCallError::Unavailable(format!("current_exe: {e}")))?;
    let token_file_str = token_file.to_string_lossy().to_string();
    let argv = build_broker_argv(&pipe_name, pid, &own_sid, &token_file_str);

    match spawn_elevated_broker(&exe, &argv) {
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
    // The broker is still starting after UAC: a generous connect timeout.
    let ping = perform_call(
        &session,
        BROKER_PING,
        &serde_json::json!({}),
        Duration::ZERO,
        client_answer_timeout(BROKER_PING, Duration::ZERO),
        READY_CONNECT_TIMEOUT,
    );
    // Token file is consumed by the broker; clean up any leftover.
    let _ = std::fs::remove_file(&token_file);
    match ping {
        Ok(resp) if resp.ok => Ok(session),
        Ok(_) => Err(BrokerCallError::Unavailable(
            "broker rejected readiness ping".to_string(),
        )),
        Err(CallFailure::Impostor(reason)) => {
            eprintln!("[nrr-broker] refusing broker pipe server: {reason}");
            Err(BrokerCallError::Unavailable(reason))
        }
        Err(e) => Err(BrokerCallError::Unavailable(format!(
            "broker did not become ready: {e}"
        ))),
    }
}

/// Why the server end of `pipe` is not our broker, or `None` when it is.
#[cfg(target_os = "windows")]
fn broker_impostor_reason(pipe: windows::Win32::Foundation::HANDLE) -> Option<String> {
    let own_exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => return Some(format!("cannot resolve our own executable: {e}")),
    };
    let mut facts = match crate::windows_sys::pipe_server_facts(pipe) {
        Ok(facts) => facts,
        Err(e) => return Some(format!("cannot identify the broker pipe server: {e}")),
    };
    // Canonical forms when both resolve, so a short name or link spelling of
    // the same file is not read as a different binary.
    let own_exe = std::fs::canonicalize(&own_exe).unwrap_or(own_exe);
    if let Ok(image) = &facts.image {
        if let Ok(canonical) = std::fs::canonicalize(image) {
            facts.image = Ok(canonical);
        }
    }
    crate::server_identity::impostor_reason(&own_exe, &facts)
}

/// Open a fresh connection, verify who serves it, send one request, read one
/// response. A well-formed error response from the broker is `Ok` and mapped
/// by [`map_response`].
#[cfg(target_os = "windows")]
fn perform_call(
    session: &Session,
    operation: &str,
    payload: &serde_json::Value,
    requested: Duration,
    answer_timeout: Duration,
    connect_timeout: Duration,
) -> Result<BrokerResponse, CallFailure> {
    use nrr_ipc_client::wire::{read_frame, write_frame, WireError};

    use crate::protocol::duration_ms;
    use crate::windows_sys::{connect_pipe, is_pipe_absent_code, PipeIo};

    let handle = connect_pipe(&session.pipe_name, connect_timeout).map_err(|e| {
        if is_pipe_absent_code(e.code) {
            CallFailure::Absent(format!("connect: {e}"))
        } else {
            CallFailure::Undelivered(format!("connect: {e}"))
        }
    })?;
    // Before the first byte: the request carries the session nonce.
    if let Some(reason) = broker_impostor_reason(handle.raw()) {
        return Err(CallFailure::Impostor(reason));
    }
    let mut io =
        PipeIo::new(handle.raw()).map_err(|e| CallFailure::Undelivered(format!("pipe io: {e}")))?;
    io.set_timeout(answer_timeout);
    let request = BrokerRequest {
        nonce: session.nonce.clone(),
        operation: operation.to_string(),
        payload: payload.clone(),
        timeout_ms: duration_ms(requested),
    };
    write_frame(&mut NoFlush(&mut io), &request)
        .map_err(|e| CallFailure::Undelivered(format!("write: {e}")))?;
    read_frame(&mut io).map_err(|e| match e {
        WireError::Io(io_err) if io_err.kind() == std::io::ErrorKind::TimedOut => {
            CallFailure::Unanswered(format!("read: {io_err}"))
        }
        other => CallFailure::Lost(format!("read: {other}")),
    })
    // `handle` (OwnedHandle) drops here → CloseHandle.
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;
    use crate::protocol::{broker_answer_bound, BROKER_SERVICE_CONTROL};

    /// How the fake broker behaves on the next exchange.
    #[derive(Clone, Copy)]
    enum Reply {
        /// Answers `ok` after this long; a wait shorter than that times out.
        After(Duration),
        /// Its pipe name is gone.
        Absent,
        /// Takes the request, then closes without answering.
        Lost,
    }

    struct FakeTransport {
        spawns: Cell<u32>,
        /// Operations sent, with the session they went to.
        sent: RefCell<Vec<(String, String)>>,
        /// Consumed front to back; the last one repeats.
        replies: RefCell<Vec<Reply>>,
        served: Cell<bool>,
    }

    impl FakeTransport {
        fn new(replies: Vec<Reply>) -> Self {
            Self {
                spawns: Cell::new(0),
                sent: RefCell::new(Vec::new()),
                replies: RefCell::new(replies),
                served: Cell::new(true),
            }
        }

        fn sent_ops(&self) -> Vec<String> {
            self.sent
                .borrow()
                .iter()
                .map(|(op, _)| op.clone())
                .collect()
        }
    }

    impl Transport for FakeTransport {
        fn spawn(&self) -> Result<Session, BrokerCallError> {
            let n = self.spawns.get() + 1;
            self.spawns.set(n);
            self.served.set(true);
            Ok(Session {
                pipe_name: format!("broker-{n}"),
                nonce: "nonce".to_string(),
            })
        }

        fn exchange(
            &self,
            session: &Session,
            operation: &str,
            _payload: &serde_json::Value,
            _requested: Duration,
            answer_timeout: Duration,
        ) -> Result<BrokerResponse, CallFailure> {
            let reply = {
                let mut replies = self.replies.borrow_mut();
                if replies.len() > 1 {
                    replies.remove(0)
                } else {
                    replies[0]
                }
            };
            if matches!(reply, Reply::Absent) {
                self.served.set(false);
                return Err(CallFailure::Absent("connect: not found".to_string()));
            }
            self.sent
                .borrow_mut()
                .push((operation.to_string(), session.pipe_name.clone()));
            match reply {
                Reply::After(took) if took <= answer_timeout => {
                    Ok(BrokerResponse::ok(serde_json::json!({ "op": operation })))
                }
                Reply::After(_) => Err(CallFailure::Unanswered("read: timed out".to_string())),
                Reply::Lost => {
                    self.served.set(false);
                    Err(CallFailure::Lost("read: broken pipe".to_string()))
                }
                Reply::Absent => unreachable!("handled above"),
            }
        }

        fn pipe_served(&self, _session: &Session) -> bool {
            self.served.get()
        }
    }

    fn reinstall(
        broker: &Broker,
        fake: &FakeTransport,
    ) -> Result<serde_json::Value, BrokerCallError> {
        broker.relay(
            fake,
            BROKER_SERVICE_CONTROL,
            &serde_json::json!({ "action": "reinstall" }),
            Duration::from_secs(60),
        )
    }

    #[test]
    fn new_handle_starts_with_no_session() {
        let h = new_handle();
        assert!(!h.is_session_active());
    }

    #[test]
    fn a_reinstall_that_takes_the_whole_broker_budget_still_succeeds_on_one_broker() {
        let worst = broker_answer_bound(BROKER_SERVICE_CONTROL, Duration::from_secs(60));
        let fake = FakeTransport::new(vec![Reply::After(worst)]);
        let broker = new_handle();

        let result = reinstall(&broker, &fake);

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(fake.spawns.get(), 1);
        assert_eq!(fake.sent_ops(), vec![BROKER_SERVICE_CONTROL.to_string()]);
    }

    #[test]
    fn a_timeout_reports_still_running_without_a_new_broker_or_a_second_send() {
        let fake = FakeTransport::new(vec![Reply::After(Duration::from_secs(3600))]);
        let broker = new_handle();

        let result = reinstall(&broker, &fake);

        assert!(
            matches!(result, Err(BrokerCallError::StillRunning(_))),
            "{result:?}"
        );
        assert_eq!(fake.spawns.get(), 1, "no second UAC prompt");
        assert_eq!(fake.sent_ops(), vec![BROKER_SERVICE_CONTROL.to_string()]);
        assert!(broker.is_session_active(), "the busy broker is kept");
    }

    #[test]
    fn while_the_earlier_request_runs_the_next_one_is_not_sent() {
        let fake = FakeTransport::new(vec![Reply::After(Duration::from_secs(3600))]);
        let broker = new_handle();
        let _ = reinstall(&broker, &fake);

        let second = reinstall(&broker, &fake);

        assert!(
            matches!(second, Err(BrokerCallError::StillRunning(_))),
            "{second:?}"
        );
        assert_eq!(fake.spawns.get(), 1);
        assert_eq!(
            fake.sent_ops(),
            vec![BROKER_SERVICE_CONTROL.to_string(), BROKER_PING.to_string()],
            "only a ping follows the unanswered request"
        );
    }

    #[test]
    fn once_the_earlier_request_finishes_the_same_broker_takes_the_next() {
        let fake = FakeTransport::new(vec![
            Reply::After(Duration::from_secs(3600)),
            Reply::After(Duration::ZERO),
        ]);
        let broker = new_handle();
        let _ = reinstall(&broker, &fake);

        let second = reinstall(&broker, &fake);

        assert!(second.is_ok(), "{second:?}");
        assert_eq!(fake.spawns.get(), 1);
        assert_eq!(
            fake.sent_ops(),
            vec![
                BROKER_SERVICE_CONTROL.to_string(),
                BROKER_PING.to_string(),
                BROKER_SERVICE_CONTROL.to_string(),
            ]
        );
    }

    #[test]
    fn a_dead_pipe_respawns_once_and_sends_once() {
        let fake = FakeTransport::new(vec![
            Reply::After(Duration::ZERO),
            Reply::Absent,
            Reply::After(Duration::ZERO),
        ]);
        let broker = new_handle();
        assert!(reinstall(&broker, &fake).is_ok());

        let result = reinstall(&broker, &fake);

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(fake.spawns.get(), 2);
        let sent = fake.sent.borrow();
        assert_eq!(
            sent.len(),
            2,
            "the op reached a broker exactly once per call"
        );
        assert_eq!(sent[1].1, "broker-2");
    }

    #[test]
    fn a_pipe_that_stays_dead_is_not_respawned_twice() {
        let fake = FakeTransport::new(vec![Reply::Absent]);
        let broker = new_handle();

        let result = reinstall(&broker, &fake);

        assert!(
            matches!(result, Err(BrokerCallError::Unavailable(_))),
            "{result:?}"
        );
        assert_eq!(fake.spawns.get(), 2);
        assert!(fake.sent_ops().is_empty());
    }

    #[test]
    fn a_broker_that_dies_holding_the_request_is_not_sent_it_again() {
        let fake = FakeTransport::new(vec![Reply::Lost, Reply::After(Duration::ZERO)]);
        let broker = new_handle();

        let result = reinstall(&broker, &fake);

        assert!(
            matches!(result, Err(BrokerCallError::Unavailable(_))),
            "{result:?}"
        );
        assert_eq!(fake.spawns.get(), 1);
        assert_eq!(fake.sent_ops(), vec![BROKER_SERVICE_CONTROL.to_string()]);
        assert!(
            !broker.is_session_active(),
            "the next call starts a new broker"
        );
    }

    #[test]
    fn a_broker_that_died_while_busy_is_replaced_before_the_next_send() {
        let fake = FakeTransport::new(vec![
            Reply::After(Duration::from_secs(3600)),
            Reply::Absent,
            Reply::After(Duration::ZERO),
        ]);
        let broker = new_handle();
        let _ = reinstall(&broker, &fake);

        let second = reinstall(&broker, &fake);

        assert!(second.is_ok(), "{second:?}");
        assert_eq!(fake.spawns.get(), 2);
        let sent = fake.sent.borrow();
        assert_eq!(sent.len(), 2);
        assert_eq!(
            sent[1],
            (BROKER_SERVICE_CONTROL.to_string(), "broker-2".to_string())
        );
    }

    /// The request is written without a flush; the broker must still read it
    /// whole over a real pipe while the client waits for the answer.
    #[cfg(target_os = "windows")]
    #[test]
    fn an_unflushed_request_reaches_the_server_and_the_answer_comes_back() {
        use nrr_ipc_client::wire::{read_frame, write_frame};

        use crate::protocol::BrokerRequest;
        use crate::windows_sys::{
            accept_with_parent_watch, connect_pipe, create_owner_restricted_pipe,
            current_process_user_sid, disconnect_and_close, open_parent_process, AcceptResult,
            PipeIo,
        };

        let sid = current_process_user_sid().expect("own sid");
        let name = format!(
            r"\\.\pipe\NetRuleRouter\broker-noflush-{}",
            std::process::id()
        );
        let server_name = name.clone();
        let server = std::thread::spawn(move || {
            let pipe = create_owner_restricted_pipe(&server_name, &sid, true).expect("create pipe");
            let parent = open_parent_process(std::process::id()).expect("parent self");
            assert!(matches!(
                accept_with_parent_watch(pipe.raw(), parent.raw()),
                AcceptResult::Connected
            ));
            let mut io = PipeIo::new(pipe.raw()).expect("server io");
            let request: BrokerRequest = read_frame(&mut io).expect("read request");
            write_frame(
                &mut io,
                &BrokerResponse::ok(serde_json::json!(request.operation)),
            )
            .expect("write response");
            disconnect_and_close(pipe.into_raw());
        });

        let handle = connect_pipe(&name, Duration::from_secs(5)).expect("connect");
        let mut io = PipeIo::new(handle.raw()).expect("client io");
        io.set_timeout(Duration::from_secs(5));
        let request = BrokerRequest {
            nonce: "n".to_string(),
            operation: BROKER_PING.to_string(),
            payload: serde_json::json!({}),
            timeout_ms: 0,
        };
        write_frame(&mut NoFlush(&mut io), &request).expect("write request");
        let response: BrokerResponse = read_frame(&mut io).expect("read response");

        assert_eq!(response.payload, Some(serde_json::json!(BROKER_PING)));
        server.join().expect("server thread");
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
