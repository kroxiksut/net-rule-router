//! The connection to the service, as the user is told about it, and the exact
//! command that fixes each state the user can fix.

use nrr_ipc_client::ConnectionStatus;
use nrr_platform_api::service_control::{ServiceRunState, ServiceStatusReport};
use nrr_shared::platform_profile::PlatformProfile;
use nrr_shared::product_identity::BinaryRole;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Link {
    Connecting,
    Connected,
    /// Not reachable, for a reason the service manager does not explain.
    Offline,
    Stopped,
    NotInstalled,
    ProtocolMismatch {
        server: u32,
        client: u32,
    },
    Refused {
        reason: String,
    },
}

impl Link {
    /// What the client reports, refined by the service manager where the
    /// client cannot tell: the Unix client knows only "no answer".
    pub fn from_status(
        status: ConnectionStatus,
        registration: Option<Option<ServiceStatusReport>>,
    ) -> Self {
        match status {
            ConnectionStatus::Connected => Self::Connected,
            ConnectionStatus::Connecting => Self::Connecting,
            ConnectionStatus::ServiceStopped => Self::Stopped,
            ConnectionStatus::NotInstalled => Self::NotInstalled,
            ConnectionStatus::ProtocolMismatch {
                server_version,
                client_version,
            } => Self::ProtocolMismatch {
                server: server_version,
                client: client_version,
            },
            ConnectionStatus::Refused { reason } => Self::Refused { reason },
            ConnectionStatus::Disconnected { .. } => match registration {
                Some(None) => Self::NotInstalled,
                Some(Some(report)) if report.run_state == ServiceRunState::Stopped => Self::Stopped,
                _ => Self::Offline,
            },
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }

    /// Whether asking the service manager could sharpen this state.
    pub fn wants_registration(status: &ConnectionStatus) -> bool {
        matches!(status, ConnectionStatus::Disconnected { .. })
    }
}

/// The console command name, as the user types it.
pub fn console_command() -> &'static str {
    command_name(BinaryRole::Console)
}

/// This program's command name.
pub fn tui_command() -> &'static str {
    command_name(BinaryRole::Tui)
}

fn command_name(role: BinaryRole) -> &'static str {
    let file = role.host_file_name();
    file.strip_suffix(".exe").unwrap_or(file)
}

/// The console verb run with the rights it needs on this OS. The terminal
/// interface never elevates itself: over SSH there is no desktop to ask on.
pub fn admin_command(verb: &str) -> String {
    let console = console_command();
    if PlatformProfile::current().elevation_model == "uac" {
        format!("{console} {verb} --elevate")
    } else {
        format!("sudo {console} {verb}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(run_state: ServiceRunState) -> ServiceStatusReport {
        ServiceStatusReport {
            run_state,
            start_mode: None,
            binary_path: None,
            running_since: None,
        }
    }

    #[test]
    fn the_service_manager_sharpens_an_unexplained_drop() {
        let offline = || ConnectionStatus::Disconnected {
            last_error: "x".into(),
        };
        assert_eq!(Link::from_status(offline(), Some(None)), Link::NotInstalled);
        assert_eq!(
            Link::from_status(offline(), Some(Some(report(ServiceRunState::Stopped)))),
            Link::Stopped
        );
        assert_eq!(
            Link::from_status(offline(), Some(Some(report(ServiceRunState::Running)))),
            Link::Offline
        );
        assert_eq!(Link::from_status(offline(), None), Link::Offline);
    }

    #[test]
    fn the_client_answer_stands_when_it_has_one() {
        assert_eq!(
            Link::from_status(ConnectionStatus::ServiceStopped, Some(None)),
            Link::Stopped
        );
    }

    #[test]
    fn the_fix_names_the_console_and_the_verb() {
        let command = admin_command("install");
        assert!(command.contains(console_command()), "{command}");
        assert!(command.contains("install"), "{command}");
        assert!(!console_command().ends_with(".exe"));
    }
}
