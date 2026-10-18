//! An administrator's password, typed in this terminal.
//!
//! When a request needs rights, the service asks the platform authority; with
//! no agent in this session to show the prompt (an SSH login, a console with
//! no desktop) the answer is "nobody could be asked". The terminal then starts
//! an agent for its own process, hands the screen over while the agent asks,
//! and sends the request once more. Only where no such agent exists does the
//! user hear to start the terminal elevated.

use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use nrr_ipc_client::{
    ipc_request_timeout, ConnectionStatus, IpcClient, IpcClientError, NegotiateInfo,
    AUTHORIZATION_PROMPT_BUDGET,
};
use nrr_platform_api::authorization::TerminalPromptAgent;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_transport::{
    forbidden_client_code, IpcErrorCode, ELEVATION_AGENT_MISSING_CLIENT_SLUG,
};
use serde_json::Value;

/// How long the screen may take to be handed over before the request is
/// answered with the refusal instead.
const HAND_OVER_WAIT: Duration = Duration::from_secs(2);
/// The agent registers a moment after it starts; a question asked before then
/// still finds nobody to prompt.
const REGISTRATION_WAIT: Duration = Duration::from_secs(3);
const REGISTRATION_POLL: Duration = Duration::from_millis(150);

/// The jobs thread asking the interface thread for the screen. The interface
/// answers `ready` once the terminal is back to normal, and takes the screen
/// back when `done` closes.
pub struct PromptRequest {
    pub ready: Sender<bool>,
    pub done: Receiver<()>,
}

/// Whether this refusal is the one a terminal agent can lift.
fn nobody_could_prompt(error: &IpcClientError) -> bool {
    matches!(
        error,
        IpcClientError::ServerError {
            code: IpcErrorCode::Forbidden,
            message,
            ..
        } if forbidden_client_code(message) == ELEVATION_AGENT_MISSING_CLIENT_SLUG
    )
}

/// The client the screens' jobs run through: the service's own, plus the
/// password prompt in this terminal when the service could not ask anyone.
pub struct PromptingClient {
    inner: Arc<dyn IpcClient>,
    agent: Option<Box<dyn TerminalPromptAgent>>,
    prompts: Sender<PromptRequest>,
}

impl PromptingClient {
    pub fn new(
        inner: Arc<dyn IpcClient>,
        agent: Option<Box<dyn TerminalPromptAgent>>,
        prompts: Sender<PromptRequest>,
    ) -> Self {
        Self {
            inner,
            agent,
            prompts,
        }
    }

    /// `None` when the prompt could not be arranged; the first refusal stands.
    fn call_with_prompt(
        &self,
        agent: &dyn TerminalPromptAgent,
        operation: IpcOperationName,
        payload: Value,
        timeout: Duration,
    ) -> Option<Result<Value, IpcClientError>> {
        let (ready_tx, ready) = channel();
        let (done, done_rx) = channel::<()>();
        self.prompts
            .send(PromptRequest {
                ready: ready_tx,
                done: done_rx,
            })
            .ok()?;
        if !ready.recv_timeout(HAND_OVER_WAIT).unwrap_or(false) {
            return None;
        }
        // Dropped on every way out, which gives the screen back.
        let _screen = done;
        let mut session = match agent.start() {
            Ok(session) => session,
            Err(why) => {
                eprintln!("{why}");
                return None;
            }
        };
        let deadline = Instant::now() + REGISTRATION_WAIT;
        loop {
            let answer = self.inner.call(
                operation,
                payload.clone(),
                timeout.max(AUTHORIZATION_PROMPT_BUDGET),
            );
            match answer {
                Err(ref error)
                    if nobody_could_prompt(error)
                        && session.is_running()
                        && Instant::now() < deadline =>
                {
                    thread::sleep(REGISTRATION_POLL);
                }
                other => return Some(other),
            }
        }
    }
}

impl IpcClient for PromptingClient {
    fn call(
        &self,
        operation: IpcOperationName,
        payload: Value,
        timeout: Duration,
    ) -> Result<Value, IpcClientError> {
        // The session's own agent may already be showing the prompt.
        let timeout = timeout.max(ipc_request_timeout(operation, &payload));
        let Some(agent) = self.agent.as_deref() else {
            return self.inner.call(operation, payload, timeout);
        };
        match self.inner.call(operation, payload.clone(), timeout) {
            Err(error) if nobody_could_prompt(&error) => self
                .call_with_prompt(agent, operation, payload, timeout)
                .unwrap_or(Err(error)),
            other => other,
        }
    }

    fn connection_status(&self) -> ConnectionStatus {
        self.inner.connection_status()
    }

    fn force_reconnect(&self) {
        self.inner.force_reconnect();
    }

    fn subscribe_push(&self) -> Option<Receiver<Value>> {
        self.inner.subscribe_push()
    }

    fn commit_push(&self) {
        self.inner.commit_push();
    }

    fn abandon_push(&self) {
        self.inner.abandon_push();
    }

    fn active_subscription_id(&self) -> Option<String> {
        self.inner.active_subscription_id()
    }

    fn negotiate_info(&self) -> Option<NegotiateInfo> {
        self.inner.negotiate_info()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::authorization::PromptAgentSession;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Refuses with "nobody could prompt" until an agent has been started,
    /// then answers.
    struct Service {
        agents: Arc<AtomicUsize>,
        calls: AtomicUsize,
    }

    impl IpcClient for Service {
        fn call(
            &self,
            operation: IpcOperationName,
            _payload: Value,
            _timeout: Duration,
        ) -> Result<Value, IpcClientError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.agents.load(Ordering::SeqCst) == 0 {
                return Err(IpcClientError::ServerError {
                    op: operation,
                    code: IpcErrorCode::Forbidden,
                    message: format!("{ELEVATION_AGENT_MISSING_CLIENT_SLUG}: nobody"),
                });
            }
            Ok(serde_json::json!({ "ok": true }))
        }
        fn connection_status(&self) -> ConnectionStatus {
            ConnectionStatus::Connected
        }
        fn force_reconnect(&self) {}
    }

    struct Agent(Arc<AtomicUsize>);
    struct Running;
    impl PromptAgentSession for Running {
        fn is_running(&mut self) -> bool {
            true
        }
    }
    impl TerminalPromptAgent for Agent {
        fn start(&self) -> Result<Box<dyn PromptAgentSession>, String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Running))
        }
    }

    fn rig(with_agent: bool) -> (PromptingClient, Arc<Service>, Receiver<PromptRequest>) {
        let agents = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(Service {
            agents: Arc::clone(&agents),
            calls: AtomicUsize::new(0),
        });
        let (prompts, requests) = channel();
        let agent: Option<Box<dyn TerminalPromptAgent>> = if with_agent {
            Some(Box::new(Agent(agents)))
        } else {
            None
        };
        let client = PromptingClient::new(service.clone(), agent, prompts);
        (client, service, requests)
    }

    /// The interface side: hands the screen over and records that it got it
    /// back.
    fn interface(requests: Receiver<PromptRequest>) -> Arc<Mutex<usize>> {
        let returned = Arc::new(Mutex::new(0));
        let seen = Arc::clone(&returned);
        thread::spawn(move || {
            while let Ok(request) = requests.recv() {
                let _ = request.ready.send(true);
                let _ = request.done.recv();
                if let Ok(mut n) = seen.lock() {
                    *n += 1;
                }
            }
        });
        returned
    }

    #[test]
    fn nobody_to_prompt_starts_an_agent_and_sends_the_request_again() {
        let (client, service, requests) = rig(true);
        let returned = interface(requests);
        let answer = client.call(
            IpcOperationName::TrafficStatsSet,
            serde_json::json!({}),
            Duration::from_secs(1),
        );
        assert!(answer.is_ok(), "{answer:?}");
        assert_eq!(service.calls.load(Ordering::SeqCst), 2);
        let deadline = Instant::now() + Duration::from_secs(5);
        while returned.lock().map(|n| *n).unwrap_or(0) == 0 {
            assert!(Instant::now() < deadline, "the screen was not given back");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn without_an_agent_the_refusal_stands_and_nothing_is_retried() {
        let (client, service, _requests) = rig(false);
        let answer = client.call(
            IpcOperationName::TrafficStatsSet,
            serde_json::json!({}),
            Duration::from_secs(1),
        );
        assert!(
            answer.as_ref().is_err_and(nobody_could_prompt),
            "{answer:?}"
        );
        assert_eq!(service.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_screen_that_is_not_handed_over_leaves_the_refusal() {
        let (client, service, requests) = rig(true);
        // Line mode answers "no": its input thread would read the password.
        thread::spawn(move || {
            while let Ok(request) = requests.recv() {
                let _ = request.ready.send(false);
            }
        });
        let answer = client.call(
            IpcOperationName::TrafficStatsSet,
            serde_json::json!({}),
            Duration::from_secs(1),
        );
        assert!(answer.is_err());
        assert_eq!(service.calls.load(Ordering::SeqCst), 1);
    }
}
