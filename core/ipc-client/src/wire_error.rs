//! Canonical mapping from [`IpcClientError`] to a stable kebab-case wire
//! slug + human-readable message.
//!
//! The slug matches the `errors.<slug>` locale keys. The launcher dispatcher
//! and the elevation broker share this one mapping. It reads the code only,
//! never the message: the message is English prose for a person.

use crate::connection::IpcClientError;
use nrr_shared::client_error_codes as codes;
use nrr_shared::ipc_transport::{forbidden_client_code, IpcErrorCode};

/// Map an [`IpcClientError`] to `(wire_slug, message)`.
pub fn ipc_error_to_wire(err: &IpcClientError) -> (&'static str, String) {
    match err {
        IpcClientError::Disconnected => (codes::TRANSPORT_DISCONNECTED, err.to_string()),
        IpcClientError::Timeout => (codes::TIMEOUT, err.to_string()),
        IpcClientError::BadResponse { reason } => (codes::BAD_RESPONSE, reason.clone()),
        IpcClientError::SerializationFailed(s) => (codes::SERIALIZATION_FAILED, s.clone()),
        IpcClientError::ClientShutdown => (codes::CLIENT_SHUTDOWN, err.to_string()),
        // `rules-locked` and `security-alert-unacknowledged` keep their own
        // slugs: the rules section keys its read-only state off the first, and
        // `forbidden` would send the second to the elevated broker, which
        // cannot lift the alert gate.
        // The elevation gate's outcome (no agent, no authority, declined) is
        // its own code; every other `Forbidden` stays the one a broker retries.
        IpcClientError::ServerError {
            code: IpcErrorCode::Forbidden,
            message,
            ..
        } => (forbidden_client_code(message), message.clone()),
        IpcClientError::ServerError { code, message, .. } => (code.client_slug(), message.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::ipc::IpcOperationName;
    use nrr_shared::ipc_transport::IpcErrorCode;

    #[test]
    fn forbidden_maps_to_forbidden_slug() {
        let e = IpcClientError::ServerError {
            op: IpcOperationName::RoutePolicyUpdate,
            code: IpcErrorCode::Forbidden,
            message: "non-admin".into(),
        };
        let (slug, msg) = ipc_error_to_wire(&e);
        assert_eq!(slug, "forbidden");
        assert_eq!(msg, "non-admin");
    }

    fn server_error(code: IpcErrorCode, message: &str) -> IpcClientError {
        IpcClientError::ServerError {
            op: IpcOperationName::MutationSubmit,
            code,
            message: message.into(),
        }
    }

    #[test]
    fn the_elevation_gates_outcome_reaches_the_client_as_its_own_code() {
        let no_agent = server_error(
            IpcErrorCode::Forbidden,
            "elevation-agent-missing: no authentication agent",
        );
        assert_eq!(ipc_error_to_wire(&no_agent).0, "elevation-agent-missing");
        let needs = server_error(IpcErrorCode::Forbidden, "needs-administrator: retention");
        assert_eq!(ipc_error_to_wire(&needs).0, "forbidden");
    }

    #[test]
    fn confirmation_codes_map_to_their_slugs() {
        let expired = server_error(IpcErrorCode::ConfirmationExpired, "any text");
        assert_eq!(ipc_error_to_wire(&expired).0, "confirmation-expired");
        let unknown = server_error(IpcErrorCode::ConfirmationUnknown, "any text");
        assert_eq!(ipc_error_to_wire(&unknown).0, "confirmation-unknown");
    }

    /// The message is for people: a precondition failure whose text happens to
    /// say "expired" or "unknown" is still just a precondition failure.
    #[test]
    fn precondition_failed_ignores_the_message_wording() {
        for message in [
            "operation_id `op-1` is unknown or expired",
            "unknown link-provider role \"x\"",
            "confirmation token expired — re-run dry-run",
        ] {
            let err = server_error(IpcErrorCode::PreconditionFailed, message);
            assert_eq!(
                ipc_error_to_wire(&err).0,
                "precondition-failed",
                "{message}"
            );
        }
    }

    #[test]
    fn rules_locked_keeps_its_own_slug() {
        let e = IpcClientError::ServerError {
            op: IpcOperationName::MutationSubmit,
            code: IpcErrorCode::RulesLocked,
            message: "rule changes are disabled by the administrator".into(),
        };
        let (slug, _) = ipc_error_to_wire(&e);
        assert_eq!(
            slug, "rules-locked",
            "the lock must not collapse into the generic forbidden slug"
        );
    }

    #[test]
    fn the_alert_gate_keeps_its_own_slug() {
        let e = server_error(
            IpcErrorCode::SecurityAlertUnacknowledged,
            "acknowledge first",
        );
        assert_eq!(ipc_error_to_wire(&e).0, "security-alert-unacknowledged");
    }

    #[test]
    fn disconnected_maps_to_transport_slug() {
        assert_eq!(
            ipc_error_to_wire(&IpcClientError::Disconnected).0,
            "transport-disconnected"
        );
    }
}
