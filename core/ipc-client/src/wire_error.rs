//! Canonical mapping from [`IpcClientError`] to a stable kebab-case wire
//! slug + human-readable message.
//!
//! The slug matches the `errors.<slug>` locale keys. The launcher dispatcher
//! and the elevation broker share this one mapping. It reads the code only,
//! never the message: the message is English prose for a person.

use crate::connection::IpcClientError;
use nrr_shared::ipc_transport::IpcErrorCode;

/// Map an [`IpcClientError`] to `(wire_slug, message)`.
pub fn ipc_error_to_wire(err: &IpcClientError) -> (&'static str, String) {
    match err {
        IpcClientError::Disconnected => ("transport-disconnected", err.to_string()),
        IpcClientError::Timeout => ("timeout", err.to_string()),
        IpcClientError::BadResponse { reason } => ("bad-response", reason.clone()),
        IpcClientError::SerializationFailed(s) => ("serialization-failed", s.clone()),
        IpcClientError::ClientShutdown => ("client-shutdown", err.to_string()),
        IpcClientError::ServerError { code, message, .. } => {
            let slug = match code {
                IpcErrorCode::Unauthorized => "unauthorized",
                IpcErrorCode::Forbidden => "forbidden",
                // Kept separate from `forbidden` all the way to the GUI: this
                // is the slug the rules section keys its read-only state off,
                // not a one-off toast.
                IpcErrorCode::RulesLocked => nrr_shared::ipc_transport::RULES_LOCKED_CLIENT_SLUG,
                // Not `forbidden`: the launcher would retry that through the
                // elevated broker, and elevation cannot lift the alert gate.
                IpcErrorCode::SecurityAlertUnacknowledged => {
                    nrr_shared::ipc_transport::SECURITY_ALERT_UNACKNOWLEDGED_CLIENT_SLUG
                }
                IpcErrorCode::InvalidVersion => "invalid-version",
                IpcErrorCode::MalformedRequest => "malformed-request",
                IpcErrorCode::BusyConflict => "busy-conflict",
                IpcErrorCode::PreconditionFailed => "precondition-failed",
                IpcErrorCode::ConfirmationExpired => "confirmation-expired",
                IpcErrorCode::ConfirmationUnknown => "confirmation-unknown",
                IpcErrorCode::ServiceDegraded => "service-degraded",
                IpcErrorCode::RecoveryRequired => "recovery-required",
                IpcErrorCode::Internal => "internal",
            };
            (slug, message.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::ipc::IpcOperationName;

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
