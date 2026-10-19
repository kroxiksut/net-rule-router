//! Every error code a client (window, tray, terminal) can be handed.
//!
//! A client shows a code as the text of its `errors.<code>` locale key, so a
//! code missing from [`CLIENT_ERROR_CODES`] is one the Russian window prints
//! in English. `tests/client_error_codes_are_translated.rs` holds the locales
//! to this list and every producer that spells a code itself to the list.

use crate::ipc_transport::{
    IpcErrorCode, ELEVATION_AGENT_MISSING_CLIENT_SLUG, ELEVATION_DECLINED_CLIENT_SLUG,
    ELEVATION_UNAVAILABLE_CLIENT_SLUG,
};

// A call that got no usable answer from the service.
pub const TRANSPORT_DISCONNECTED: &str = "transport-disconnected";
pub const TIMEOUT: &str = "timeout";
pub const BAD_RESPONSE: &str = "bad-response";
pub const SERIALIZATION_FAILED: &str = "serialization-failed";
pub const CLIENT_SHUTDOWN: &str = "client-shutdown";

// The launcher's refusals of the window's own requests.
pub const UNKNOWN_OPERATION: &str = "unknown-operation";
pub const BROKER_UNAVAILABLE: &str = "broker-unavailable";
/// The elevated broker is alive but still busy with an earlier operation.
pub const ELEVATED_OPERATION_RUNNING: &str = "elevated-operation-running";
pub const AUTOSTART_LOCAL_ERROR: &str = "autostart-local-error";
pub const CONSOLE_PATH_ERROR: &str = "console-path-error";
pub const SIDECAR_ERROR: &str = "sidecar-error";
pub const MISSING_FIELD: &str = "missing-field";
pub const MALFORMED_INPUT: &str = "malformed-input";
pub const CANONICALISATION_FAILED: &str = "canonicalisation-failed";
pub const UNKNOWN_PRESET_OPERATION: &str = "unknown-preset-operation";
pub const MALFORMED_PRESET_PAYLOAD: &str = "malformed-preset-payload";
pub const USER_SETTINGS_READ_ONLY: &str = "user-settings-read-only";
pub const USER_SETTINGS_UNAVAILABLE: &str = "user-settings-unavailable";

// Service control, run by the launcher on Unix and by the elevation broker on
// Windows.
pub const SERVICE_NOT_INSTALLED: &str = "service-not-installed";
pub const SERVICE_CONTROL_FAILED: &str = "service-control-failed";
pub const SERVICE_RELOCATION_FAILED: &str = "service-relocation-failed";
pub const UNSUPPORTED_PLATFORM: &str = "unsupported-platform";

/// The catalogue. Service refusals are spelled here as their producers in
/// `nrr-service-runtime` spell them; the contract test scans those producers.
pub const CLIENT_ERROR_CODES: &[&str] = &[
    // Envelope codes.
    IpcErrorCode::Unauthorized.client_slug(),
    IpcErrorCode::Forbidden.client_slug(),
    IpcErrorCode::RulesLocked.client_slug(),
    IpcErrorCode::SecurityAlertUnacknowledged.client_slug(),
    IpcErrorCode::InvalidVersion.client_slug(),
    IpcErrorCode::MalformedRequest.client_slug(),
    IpcErrorCode::BusyConflict.client_slug(),
    IpcErrorCode::PreconditionFailed.client_slug(),
    IpcErrorCode::ConfirmationExpired.client_slug(),
    IpcErrorCode::ConfirmationUnknown.client_slug(),
    IpcErrorCode::ServiceDegraded.client_slug(),
    IpcErrorCode::RecoveryRequired.client_slug(),
    IpcErrorCode::Internal.client_slug(),
    // Transport.
    TRANSPORT_DISCONNECTED,
    TIMEOUT,
    BAD_RESPONSE,
    SERIALIZATION_FAILED,
    CLIENT_SHUTDOWN,
    // A refused or failed change, from the service's mutation executor.
    "malformed-payload",
    "rule-cap-exceeded",
    "auto-rule-cap-exceeded",
    "unsupported-rule-shape",
    "control-character",
    "invalid-rule-value",
    "network-on-both-routes",
    "folder-on-both-routes",
    "path-in-other-users-profile",
    "network-covers-link",
    "network-covers-fake-ip-pool",
    "rule-kind-unknown",
    "wrong-channel",
    "malformed-revision-id",
    "rolled-back-on-failure",
    "pre-flight-failed",
    "apply-layer-unavailable",
    "safe-disable-teardown-failed",
    "confirmation-required",
    "token-not-found",
    "token-already-consumed",
    "token-expired",
    "token-revision-mismatch",
    "revision-not-found",
    "revision-status-mismatch",
    "no-last-known-good",
    "storage-failure",
    "marker-write-failed",
    "activation-not-recorded",
    "revision-integrity-rejected",
    "rules-changed-elsewhere",
    "not-implemented",
    // Rule-file import.
    "payload-too-large",
    "file-encoding",
    "too-many-rules",
    "match-value-too-long",
    "inline-comment-too-long",
    "canonicalize-rejected",
    "preset-validation-failed",
    // Security alerts and the audit trail.
    "alert-not-found",
    "illegal-state-transition",
    "alerts-storage-failure",
    "alerts-store-unavailable",
    "audit-unavailable",
    "audit-write-failed",
    "audit-chain-changed",
    "audit-chain-intact",
    "restart-key-unavailable",
    // Launcher.
    UNKNOWN_OPERATION,
    BROKER_UNAVAILABLE,
    ELEVATED_OPERATION_RUNNING,
    AUTOSTART_LOCAL_ERROR,
    CONSOLE_PATH_ERROR,
    SIDECAR_ERROR,
    MISSING_FIELD,
    MALFORMED_INPUT,
    CANONICALISATION_FAILED,
    UNKNOWN_PRESET_OPERATION,
    MALFORMED_PRESET_PAYLOAD,
    USER_SETTINGS_READ_ONLY,
    USER_SETTINGS_UNAVAILABLE,
    // Elevation and service control.
    ELEVATION_DECLINED_CLIENT_SLUG,
    ELEVATION_AGENT_MISSING_CLIENT_SLUG,
    ELEVATION_UNAVAILABLE_CLIENT_SLUG,
    SERVICE_NOT_INSTALLED,
    SERVICE_CONTROL_FAILED,
    SERVICE_RELOCATION_FAILED,
    UNSUPPORTED_PLATFORM,
    // The terminal's elevation refusal, one code per host family.
    "terminal-needs-elevation-windows",
    "terminal-needs-elevation-unix",
    // Invented by the window itself: an empty code, an answer past its
    // deadline, a request it could not build, an unwired bridge.
    "unknown",
    "rpc-timed-out",
    "gui-internal",
    "safe-disable-rpc-pending",
];
