//! Launcher-side handlers for `local.*` RPC operations.
//!
//! These operations are pure functions over their input payloads —
//! no service hop, no sidecar state, no I/O beyond CPU. The
//! dispatcher in `rpc_dispatcher.rs` matches request operations by
//! the `local.` prefix and routes them through
//! [`handle_local_request`] instead of the IPC client.
//!
//! ## Operation catalogue
//!
//! | Slug                            | Description                                                       |
//! |---------------------------------|-------------------------------------------------------------------|
//! | `local.canonical-rules-hash`    | Drift detection — canonicalise rules-json via                     |
//! |                                 | `nrr_shared::rules_json::to_canonical_string` and SHA-256 the     |
//! |                                 | result. GUI hashes file / rulesModel / service-baseline through   |
//! |                                 | this op so all three legs of the drift triangle pass through the  |
//! |                                 | service-equivalent canonicalization SSOT.                         |
//!
//! Slug shape mirrors the IpcOperationName convention
//! (`<domain>.<resource>.<verb>`) — though `local.*` has no verb tier
//! today, the prefix is reserved for future pure-local ops (e.g. a
//! `local.config-validate` that lints rules without applying).
//!
//! Errors fold into the same [`LocalHandlerError`] shape used by
//! `preset_handlers.rs` so callers see consistent envelope codes.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use nrr_ipc_client::IpcClient;
use nrr_shared::rules_json::{to_canonical_string, CanonicalRulesJsonV1, RulesJsonCodecError};

/// GUI/launcher protocol version. Mirrors
/// `nrr_ipc_client::CLIENT_PROTOCOL_VERSION` which is a `pub(crate)`
/// constant — we duplicate it here so the compatibility banner can
/// report the number without making the constant public on the
/// client API surface. Keep these two values in sync; if you bump
/// one, bump the other.
const GUI_PROTOCOL_VERSION: u32 = 1;

/// GUI/launcher semver. Pulled from this crate's `Cargo.toml` via
/// `env!`. `nrr-launcher`'s `CARGO_PKG_VERSION` is the source of
/// truth for "the GUI app version" the user sees in the
/// compatibility banner. The legacy `about.version` field in the
/// QML context is sourced from `nrr-application`'s version which
/// today is the same number (workspace-pinned to 0.1.0); should
/// the two diverge, this constant follows the launcher binary.
const GUI_SEMVER: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Error)]
pub enum LocalHandlerError {
    #[error("unknown local operation: {0}")]
    UnknownOperation(String),
    #[error("missing required payload field: {0}")]
    MissingField(&'static str),
    #[error("malformed rules-json: {0}")]
    MalformedRulesJson(#[from] serde_json::Error),
    #[error("canonicalization failed: {0}")]
    CanonicalisationFailed(#[from] RulesJsonCodecError),
}

impl LocalHandlerError {
    /// Wire-protocol error code surfaced to QML callbacks. Kept narrow
    /// — the GUI degrades drift detection gracefully on any failure
    /// (skips that hash leg, banner stays hidden) and surface text
    /// goes through the localised status line, not the code itself.
    pub fn wire_code(&self) -> &'static str {
        match self {
            LocalHandlerError::UnknownOperation(_) => "unknown-operation",
            LocalHandlerError::MissingField(_) => "missing-field",
            LocalHandlerError::MalformedRulesJson(_) => "malformed-input",
            LocalHandlerError::CanonicalisationFailed(_) => "canonicalisation-failed",
        }
    }
}

pub type LocalHandlerResult = Result<Value, LocalHandlerError>;

/// Handle one request whose operation slug starts with `local.`. The
/// dispatcher already verified the prefix; we match on the suffix
/// here. `client` is passed for the (rare) ops that need to read
/// IPC-client state — pure ops can ignore it.
pub fn handle_local_request(
    operation: &str,
    payload: &Value,
    client: &dyn IpcClient,
) -> LocalHandlerResult {
    match operation {
        "local.canonical-rules-hash" => handle_canonical_rules_hash(payload),
        "local.service-info" => handle_service_info(client),
        "local.vpn.discover" => handle_vpn_discover(),
        "local.app-groups.discover" => handle_app_groups_discover(),
        other => Err(LocalHandlerError::UnknownOperation(other.to_string())),
    }
}

/// Scan the machine for likely VPN clients (running processes + installed
/// programs) and return the merged candidate list for
/// the onboarding UI. Runs LOCALLY in the launcher: process enumeration and
/// HKCU/HKLM reads need no elevation and no background service, so onboarding
/// works before the service is installed. The OS mechanism is
/// [`nrr_platform_windows::WindowsVpnDiscovery`] on Windows, a Noop elsewhere
/// (the neutral port keeps the seam — the Linux backend fills it in later).
fn handle_vpn_discover() -> LocalHandlerResult {
    let candidates = discover_vpn_candidates_os();
    Ok(json!({ "candidates": candidates }))
}

/// Windows mechanism. The other-OS branch returns nothing until the Linux /
/// macOS backends implement the port (the seam is already in
/// `nrr_platform_api::VpnDiscoveryPort`).
#[cfg(target_os = "windows")]
fn discover_vpn_candidates_os() -> Vec<nrr_platform_api::VpnCandidate> {
    use nrr_platform_windows::VpnDiscoveryPort;
    nrr_platform_windows::WindowsVpnDiscovery::new().discover_vpn_candidates()
}

#[cfg(not(target_os = "windows"))]
fn discover_vpn_candidates_os() -> Vec<nrr_platform_api::VpnCandidate> {
    Vec::new()
}

/// Scan the machine for known application-group members (VMs / emulators +
/// torrents / P2P) and return the merged, tab-sorted list for the
/// onboarding UI. Runs LOCALLY in the launcher for the same reason as VPN
/// discovery (non-elevated process + registry enumeration, no service needed),
/// so the route-assignment onboarding works before the service is installed.
/// The OS mechanism is [`nrr_platform_windows::WindowsAppGroupDiscovery`] on
/// Windows, a Noop elsewhere until the Linux / macOS backends fill the seam.
fn handle_app_groups_discover() -> LocalHandlerResult {
    let apps = discover_app_groups_os();
    Ok(json!({ "apps": apps }))
}

#[cfg(target_os = "windows")]
fn discover_app_groups_os() -> Vec<nrr_platform_api::DiscoveredApp> {
    use nrr_platform_windows::AppGroupDiscoveryPort;
    nrr_platform_windows::WindowsAppGroupDiscovery::new().discover_app_groups()
}

#[cfg(not(target_os = "windows"))]
fn discover_app_groups_os() -> Vec<nrr_platform_api::DiscoveredApp> {
    Vec::new()
}

/// Surface the GUI's own version pair and the cached `ContractNegotiate`
/// info from the IPC client. Used by the
/// compatibility banner to compare the two protocol numbers and
/// render a "Service X.Y.Z (vN), App A.B.C (vM)" diagnostic line
/// with a direction-aware "update the [Service|App]" CTA.
///
/// When the IPC handshake hasn't completed yet (cold-start race or
/// service unreachable), the service-side fields are emitted as
/// empty / zero. QML treats those as "service version unknown" and
/// hides the banner.
fn handle_service_info(client: &dyn IpcClient) -> LocalHandlerResult {
    let info = client.negotiate_info();
    let (service_protocol, service_version, session_id) = match info {
        Some(i) => (i.server_protocol, i.service_version, i.session_id),
        None => (0u32, String::new(), String::new()),
    };
    let registration = service_registration();
    let registered = registration
        .as_ref()
        .and_then(|r| r.binary_path.clone())
        .filter(|p| !p.as_os_str().is_empty());
    let expected = sibling_service_binary();
    // "Another copy is registered" and "the registered copy is older" are two
    // different faults with one fix, so answer both and let QML offer it once.
    let elsewhere = match (registered.as_ref(), expected.as_ref()) {
        (Some(registered), Some(expected)) => !same_path(registered, expected),
        _ => false,
    };
    let older = version_is_older(&service_version, GUI_SEMVER);
    // An update written over the SAME folder leaves the registration untouched
    // and the version string unchanged, so neither check above sees it — but
    // the process still runs the code it loaded before the file was replaced.
    let stale_process = registration
        .as_ref()
        .and_then(binary_is_newer_than_process)
        .unwrap_or(false);
    Ok(json!({
        "gui-protocol":     GUI_PROTOCOL_VERSION,
        "gui-version":      GUI_SEMVER,
        "service-protocol": service_protocol,
        "service-version":  service_version,
        "session-id":       session_id,
        "service-registered-path": registered
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        "service-expected-path": expected
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        "service-registered-elsewhere": elsewhere,
        "service-older-than-app": older,
        "service-binary-replaced": stale_process,
        "service-update-available": elsewhere || older,
        "service-restart-needed": stale_process && !elsewhere,
    }))
}

/// What the service manager has registered, read straight from it.
/// Unprivileged and answerable with the service stopped — the state in which
/// the question matters most.
fn service_registration() -> Option<nrr_platform_api::service_control::ServiceStatusReport> {
    #[cfg(windows)]
    {
        use nrr_platform_api::service_control::ServiceControlPort;
        nrr_platform_windows::service_control::WindowsServiceControl::new()
            .query()
            .ok()
            .flatten()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Whether the registered binary on disk is newer than the process running from
/// it — i.e. an update was written in place and the old code is still live.
///
/// `None` whenever the answer cannot be established (service stopped, no start
/// time from the OS, unreadable file): the caller must not turn "unknown" into
/// a prompt telling the user their service is stale.
fn binary_is_newer_than_process(
    report: &nrr_platform_api::service_control::ServiceStatusReport,
) -> Option<bool> {
    let started = report.running_since?;
    let path = report.binary_path.as_ref()?;
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    // A second of slack: the file timestamp and the process clock come from
    // different sources, and a start that races its own binary's write would
    // otherwise report itself stale.
    Some(modified > started + std::time::Duration::from_secs(1))
}

/// The service binary shipped alongside this application — the one an updated
/// copy should be running.
fn sibling_service_binary() -> Option<std::path::PathBuf> {
    let exe_name = if cfg!(windows) {
        "nrr-service.exe"
    } else {
        "nrr-serviced"
    };
    let candidate = std::env::current_exe().ok()?.parent()?.join(exe_name);
    candidate.is_file().then_some(candidate)
}

/// Case- and spelling-insensitive path comparison. Canonicalisation resolves
/// `\\?\` prefixes, 8.3 names and links; a path that cannot be canonicalised
/// (removed since, permission) falls back to a plain case-insensitive compare.
fn same_path(left: &std::path::Path, right: &std::path::Path) -> bool {
    match (
        std::fs::canonicalize(left).ok(),
        std::fs::canonicalize(right).ok(),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => left
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy()),
    }
}

/// Numeric-component semver comparison, `true` only when `service` is provably
/// behind `app`. Unknown, unparseable or equal versions answer `false`: an
/// update prompt on a guess is worse than no prompt.
fn version_is_older(service: &str, app: &str) -> bool {
    let parse = |raw: &str| -> Option<Vec<u64>> {
        let core = raw.trim().trim_start_matches('v');
        let core = core.split(['-', '+']).next()?;
        let parts: Vec<u64> = core
            .split('.')
            .map(|p| p.parse::<u64>().ok())
            .collect::<Option<_>>()?;
        (!parts.is_empty()).then_some(parts)
    };
    let (Some(service), Some(app)) = (parse(service), parse(app)) else {
        return false;
    };
    let len = service.len().max(app.len());
    for i in 0..len {
        let s = service.get(i).copied().unwrap_or(0);
        let a = app.get(i).copied().unwrap_or(0);
        if s != a {
            return s < a;
        }
    }
    false
}

fn handle_canonical_rules_hash(payload: &Value) -> LocalHandlerResult {
    let rules_json = payload
        .get("rules-json")
        .and_then(Value::as_str)
        .ok_or(LocalHandlerError::MissingField("rules-json"))?;
    // Parse the GUI-side JS-serialised text into the struct-typed
    // DTO. `serde_json::from_str` is forgiving of field order, which
    // is exactly the point — the GUI emits insertion-order JSON and
    // we re-emit in declaration order via `to_canonical_string`.
    let dto: CanonicalRulesJsonV1 = serde_json::from_str(rules_json)?;
    let canonical = to_canonical_string(&dto)?;
    // SHA-256 of the canonical bytes. Matches the service's
    // `content_hash` exactly when both sides receive equal rules,
    // because both sides feed the same DTO through the same
    // canonicalization function. Hex-encoded so the wire payload
    // stays printable ASCII (32-byte binary would need base64).
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest.iter() {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    Ok(json!({
        "hash": hex,
        "canonical-bytes": canonical.len(),
    }))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use nrr_ipc_client::{ConnectionStatus, IpcClient, IpcClientError, NegotiateInfo};
    use nrr_shared::ipc::IpcOperationName;
    use serde_json::json;
    use std::time::Duration;

    /// Minimal `IpcClient` stub for tests. The `local.*` handlers
    /// today only consult `negotiate_info()`; `call` and the rest
    /// are unreachable in this test surface.
    struct FakeClient {
        negotiate: Option<NegotiateInfo>,
    }

    impl IpcClient for FakeClient {
        fn call(
            &self,
            _operation: IpcOperationName,
            _payload: Value,
            _timeout: Duration,
        ) -> Result<Value, IpcClientError> {
            Err(IpcClientError::Disconnected)
        }
        fn connection_status(&self) -> ConnectionStatus {
            ConnectionStatus::Disconnected {
                last_error: "test stub".into(),
            }
        }
        fn force_reconnect(&self) {}
        fn negotiate_info(&self) -> Option<NegotiateInfo> {
            self.negotiate.clone()
        }
    }

    fn empty_client() -> FakeClient {
        FakeClient { negotiate: None }
    }

    fn hash_of(payload: &Value) -> String {
        let response = handle_canonical_rules_hash(payload).expect("hash ok");
        response["hash"].as_str().expect("hex string").to_string()
    }

    #[test]
    fn empty_rules_set_hashes_deterministically() {
        let p = json!({
            "rules-json": r#"{"schema-version":1,"primary":[],"secondary":[]}"#,
        });
        let h1 = hash_of(&p);
        let h2 = hash_of(&p);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn key_order_does_not_affect_hash() {
        // GUI may emit in {schema-version, primary, secondary} order;
        // a hand-rolled fixture may emit them reversed. Canonical
        // re-serialisation collapses both to the declaration order so
        // hashes match.
        let canonical_order = json!({
            "rules-json": r#"{"schema-version":1,"primary":[],"secondary":[]}"#,
        });
        let reversed = json!({
            "rules-json": r#"{"secondary":[],"primary":[],"schema-version":1}"#,
        });
        assert_eq!(hash_of(&canonical_order), hash_of(&reversed));
    }

    #[test]
    fn empty_comment_collapses_to_absent() {
        // Rule with `comment: ""` and rule with comment omitted must
        // produce the same canonical bytes (see rules_json.rs doc-
        // comment about `skip_serializing_if = "String::is_empty"`).
        let with_empty = json!({
            "rules-json": r#"{"schema-version":1,"primary":[{"id":"r1","enabled":true,"address-match":{"kind":"zone","name":"ru"},"comment":""}],"secondary":[]}"#,
        });
        let without = json!({
            "rules-json": r#"{"schema-version":1,"primary":[{"id":"r1","enabled":true,"address-match":{"kind":"zone","name":"ru"}}],"secondary":[]}"#,
        });
        assert_eq!(hash_of(&with_empty), hash_of(&without));
    }

    #[test]
    fn different_rules_produce_different_hashes() {
        let a = json!({
            "rules-json": r#"{"schema-version":1,"primary":[{"id":"r1","enabled":true,"address-match":{"kind":"zone","name":"ru"}}],"secondary":[]}"#,
        });
        let b = json!({
            "rules-json": r#"{"schema-version":1,"primary":[{"id":"r1","enabled":true,"address-match":{"kind":"zone","name":"su"}}],"secondary":[]}"#,
        });
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn missing_field_surfaces_error() {
        let err =
            handle_canonical_rules_hash(&json!({})).expect_err("missing rules-json should fail");
        assert_eq!(err.wire_code(), "missing-field");
    }

    #[test]
    fn malformed_input_surfaces_error() {
        let err = handle_canonical_rules_hash(&json!({
            "rules-json": "{not json",
        }))
        .expect_err("malformed json should fail");
        assert_eq!(err.wire_code(), "malformed-input");
    }

    #[test]
    fn unknown_operation_rejected() {
        let client = empty_client();
        let err = handle_local_request("local.bogus", &json!({}), &client)
            .expect_err("unknown op should fail");
        assert_eq!(err.wire_code(), "unknown-operation");
    }

    #[test]
    fn service_info_when_negotiate_pending() {
        let client = empty_client();
        let resp = handle_local_request("local.service-info", &json!({}), &client).expect("ok");
        assert_eq!(resp["gui-protocol"], 1);
        assert_eq!(resp["gui-version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(resp["service-protocol"], 0);
        assert_eq!(resp["service-version"], "");
    }

    #[test]
    fn service_info_with_negotiate_filled() {
        let client = FakeClient {
            negotiate: Some(NegotiateInfo {
                server_protocol: 7,
                service_version: "0.2.0".into(),
                session_id: "sess-deadbeef".into(),
            }),
        };
        let resp = handle_local_request("local.service-info", &json!({}), &client).expect("ok");
        assert_eq!(resp["service-protocol"], 7);
        assert_eq!(resp["service-version"], "0.2.0");
        assert_eq!(resp["session-id"], "sess-deadbeef");
    }

    #[test]
    fn an_older_service_version_is_recognised() {
        assert!(version_is_older("0.1.0", "0.2.0"));
        assert!(version_is_older("0.1.9", "0.2.0"));
        assert!(version_is_older("1.2.3", "1.2.4"));
        // Fewer components: the missing ones read as zero.
        assert!(version_is_older("1.2", "1.2.1"));
    }

    #[test]
    fn equal_newer_or_unreadable_versions_never_prompt_for_an_update() {
        assert!(!version_is_older("0.2.0", "0.2.0"));
        assert!(!version_is_older("0.3.0", "0.2.0"));
        // Handshake has not happened yet — the field is empty.
        assert!(!version_is_older("", "0.2.0"));
        assert!(!version_is_older("nightly", "0.2.0"));
        // Pre-release/build metadata is ignored, not guessed at.
        assert!(!version_is_older("0.2.0-prealpha", "0.2.0"));
    }

    #[test]
    fn service_info_answers_the_update_questions() {
        let client = empty_client();
        let resp = handle_local_request("local.service-info", &json!({}), &client).expect("ok");
        // Present on every answer, so QML never has to test for existence.
        for key in [
            "service-registered-path",
            "service-expected-path",
            "service-registered-elsewhere",
            "service-older-than-app",
            "service-update-available",
        ] {
            assert!(resp.get(key).is_some(), "{key} must always be reported");
        }
        // With no handshake and no registration the answer is "nothing to do".
        assert_eq!(resp["service-older-than-app"], false);
    }
}
