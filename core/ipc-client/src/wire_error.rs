//! Canonical mapping from [`IpcClientError`] to a stable kebab-case wire
//! slug + human-readable message.
//!
//! The slug matches the `errors.<slug>` locale-key naming so the GUI can
//! do a one-shot lookup. This used to live in the launcher's
//! `rpc_dispatcher`; it was hoisted here (the natural home — it maps this
//! crate's own error type) so the launcher dispatcher AND the session
//! elevation broker (`nrr-broker`) share one mapping instead of two
//! drifting copies.

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
                IpcErrorCode::RulesLocked => "rules-locked",
                IpcErrorCode::InvalidVersion => "invalid-version",
                IpcErrorCode::MalformedRequest => "malformed-request",
                IpcErrorCode::BusyConflict => "busy-conflict",
                IpcErrorCode::PreconditionFailed => {
                    // The wire schema has no dedicated `ConfirmationExpired`
                    // code; the server uses `PreconditionFailed` with a
                    // distinguishing message. Promote the expiration /
                    // unknown cases so the GUI can react without parsing
                    // English text on the QML side.
                    if message.contains("expired") {
                        "confirmation-expired"
                    } else if message.contains("unknown") {
                        "confirmation-unknown"
                    } else {
                        "precondition-failed"
                    }
                }
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

    #[test]
    fn precondition_expired_promoted() {
        let e = IpcClientError::ServerError {
            op: IpcOperationName::MutationSubmit,
            code: IpcErrorCode::PreconditionFailed,
            message: "confirmation token expired — re-run dry-run".into(),
        };
        assert_eq!(ipc_error_to_wire(&e).0, "confirmation-expired");
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
    fn disconnected_maps_to_transport_slug() {
        assert_eq!(
            ipc_error_to_wire(&IpcClientError::Disconnected).0,
            "transport-disconnected"
        );
    }
}
