//! The console's connection to the service, for the verbs that ask the service
//! rather than the disk.

use std::time::{Duration, Instant};

use nrr_ipc_client::{ConnectionStatus, IpcClient, ServiceIpcClient};
use nrr_shared::ipc_payloads::ContractNegotiateClientKind;

/// How long to wait for the connection itself. Short: this is a liveness
/// question, not the work.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// What became of the attempt to reach the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Link {
    Connected,
    /// The service manager says it is stopped or not installed.
    NotRunning,
    /// No connection within the budget: stopped where the client cannot ask
    /// the manager, or up but not accepting connections.
    NotAnswering,
    /// The service is up and has answered: it refused this caller, or speaks
    /// another protocol version. Its answer stands.
    Refused(String),
}

/// Connect as the console. The kind is declared BEFORE connecting: on Unix it
/// is the only thing that tells us apart from the application, and it can only
/// narrow what we may ask for.
pub fn open() -> (ServiceIpcClient, Link) {
    open_within(CONNECT_TIMEOUT)
}

/// [`open`] with a budget of the caller's choosing.
pub fn open_within(budget: Duration) -> (ServiceIpcClient, Link) {
    nrr_ipc_client::declare_client_kind(ContractNegotiateClientKind::Console);
    let client = ServiceIpcClient::start();
    let link = wait(&client, budget);
    (client, link)
}

/// Poll until the client settles or the budget runs out. The client connects
/// asynchronously, so a call issued at once would fail for a reason that says
/// nothing about the service.
pub fn wait(client: &dyn IpcClient, budget: Duration) -> Link {
    let deadline = Instant::now() + budget;
    loop {
        match client.connection_status() {
            ConnectionStatus::Connected => return Link::Connected,
            ConnectionStatus::ServiceStopped | ConnectionStatus::NotInstalled => {
                return Link::NotRunning
            }
            ConnectionStatus::Refused { reason } => return Link::Refused(reason),
            ConnectionStatus::ProtocolMismatch {
                server_version,
                client_version,
            } => {
                return Link::Refused(format!(
                    "it speaks protocol {server_version}, this console {client_version}"
                ))
            }
            ConnectionStatus::Connecting | ConnectionStatus::Disconnected { .. } => {}
        }
        if Instant::now() >= deadline {
            return Link::NotAnswering;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
pub mod testing {
    //! A scripted stand-in for the service, for the verbs' own tests.

    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::Duration;

    use nrr_ipc_client::{ConnectionStatus, IpcClient, IpcClientError};
    use nrr_shared::ipc::IpcOperationName;
    use serde_json::Value;

    pub struct FakeService {
        pub status: ConnectionStatus,
        answers: Mutex<VecDeque<Result<Value, IpcClientError>>>,
        calls: Mutex<Vec<(IpcOperationName, Value)>>,
    }

    impl FakeService {
        pub fn new(status: ConnectionStatus) -> Self {
            Self {
                status,
                answers: Mutex::new(VecDeque::new()),
                calls: Mutex::new(Vec::new()),
            }
        }

        pub fn answer(self, answer: Result<Value, IpcClientError>) -> Self {
            self.answers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push_back(answer);
            self
        }

        pub fn calls(&self) -> Vec<(IpcOperationName, Value)> {
            self.calls.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }
    }

    impl IpcClient for FakeService {
        fn call(
            &self,
            operation: IpcOperationName,
            payload: Value,
            _timeout: Duration,
        ) -> Result<Value, IpcClientError> {
            self.calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((operation, payload));
            self.answers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pop_front()
                .unwrap_or(Err(IpcClientError::Disconnected))
        }

        fn connection_status(&self) -> ConnectionStatus {
            self.status.clone()
        }

        fn force_reconnect(&self) {}
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FakeService;
    use super::*;

    #[test]
    fn a_settled_status_is_answered_without_waiting_out_the_budget() {
        let long = Duration::from_secs(60);
        let at = Instant::now();
        assert_eq!(
            wait(&FakeService::new(ConnectionStatus::Connected), long),
            Link::Connected
        );
        assert_eq!(
            wait(&FakeService::new(ConnectionStatus::ServiceStopped), long),
            Link::NotRunning
        );
        assert_eq!(
            wait(&FakeService::new(ConnectionStatus::NotInstalled), long),
            Link::NotRunning
        );
        assert!(matches!(
            wait(
                &FakeService::new(ConnectionStatus::Refused {
                    reason: "no slot".into()
                }),
                long
            ),
            Link::Refused(_)
        ));
        assert!(matches!(
            wait(
                &FakeService::new(ConnectionStatus::ProtocolMismatch {
                    server_version: 2,
                    client_version: 1,
                }),
                long
            ),
            Link::Refused(_)
        ));
        assert!(at.elapsed() < long);
    }

    #[test]
    fn a_client_that_never_connects_is_not_answering() {
        let silent = FakeService::new(ConnectionStatus::Disconnected {
            last_error: "no endpoint".into(),
        });
        assert_eq!(wait(&silent, Duration::ZERO), Link::NotAnswering);
    }
}
