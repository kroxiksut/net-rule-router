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
//! | `local.rules-overlaps`          | Rules cleanup — every exact rule a wildcard already covers,       |
//! |                                 | via `nrr_shared::rules_overlap::find_overlaps`; and the Overlaps  |
//! |                                 | section — rules of the two routes claiming the same hosts, via    |
//! |                                 | `find_route_overlaps`.                                            |
//! | `local.canonical-rules-hash`    | Drift detection — canonicalise rules-json via                     |
//! |                                 | `nrr_shared::rules_json::to_canonical_string` and SHA-256 the     |
//! |                                 | result. GUI hashes file / rulesModel / service-baseline through   |
//! |                                 | this op so all three legs of the drift triangle pass through the  |
//! |                                 | service-equivalent canonicalization SSOT.                         |
//! | `local.system-theme`            | The system appearance right now, so a desktop that switches       |
//! |                                 | light/dark under a running window is answered by the same probe   |
//! |                                 | the cold start used.                                              |
//! | `local.rule-value-verdict`      | The Add/Edit rule dialog's gate — the verdict the rules table     |
//! |                                 | shows for one value, via `rule_value_validation`.                 |
//! | `local.rule-values-classify`    | A pasted address list, each line sorted into exact IP / subnet /  |
//! |                                 | range with that type's verdict.                                   |
//! | `local.user-settings.intent-*`  | What the user decided about the service's settings, read from and |
//! |                                 | recorded in their own settings file, for "Restore my settings".   |
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

use crate::launcher::sibling_service_binary;
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
    #[error("user settings: {message}")]
    UserSettings { code: &'static str, message: String },
}

impl From<crate::user_settings_bridge::IntentError> for LocalHandlerError {
    fn from(error: crate::user_settings_bridge::IntentError) -> Self {
        Self::UserSettings {
            code: error.wire_code(),
            message: error.to_string(),
        }
    }
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
            LocalHandlerError::UserSettings { code, .. } => code,
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
        "local.rules-overlaps" => handle_rules_overlaps(payload),
        "local.rule-value-verdict" => handle_rule_value_verdict(payload),
        "local.rule-values-classify" => handle_rule_values_classify(payload),
        "local.service-info" => handle_service_info(client),
        "local.vpn.discover" => handle_vpn_discover(),
        "local.app-groups.discover" => handle_app_groups_discover(),
        "local.vm-inventory.list" => handle_vm_inventory_list(payload),
        "local.vm-nat.bind" => handle_vm_nat_bind(payload),
        "local.system-theme" => Ok(handle_system_theme()),
        "local.user-settings.intent-get" => Ok(crate::user_settings_bridge::intent_get()?),
        "local.user-settings.intent-record" => {
            Ok(crate::user_settings_bridge::intent_record(payload)?)
        }
        other => Err(LocalHandlerError::UnknownOperation(other.to_string())),
    }
}

/// The system appearance as this process's [`SystemThemePort`] reports it now.
///
/// The shell resolves the theme once, from the context file written before the
/// window existed. When the desktop flips light/dark under a running window,
/// the host's Qt hint fires and the shell asks HERE instead of reading the OS
/// itself: one probe, one answer, high contrast included.
///
/// [`SystemThemePort`]: nrr_platform_api::system_theme::SystemThemePort
fn handle_system_theme() -> Value {
    let resolution = nrr_ui_support::theme::resolve_theme(nrr_shared::ThemeMode::System);
    json!({
        "systemMode": resolution.system_mode.slug(),
        "systemModeDetected": resolution.system_mode_detected,
    })
}

/// Scan the machine for likely VPN clients (running processes + installed
/// programs) and return the merged candidate list for
/// the onboarding UI. Runs LOCALLY in the launcher: every source is readable
/// without elevation or the background service, so onboarding works before the
/// service is installed. macOS finds nothing until its backend fills the seam.
fn handle_vpn_discover() -> LocalHandlerResult {
    let candidates = discover_vpn_candidates_os();
    Ok(json!({ "candidates": candidates }))
}

#[cfg(target_os = "windows")]
fn discover_vpn_candidates_os() -> Vec<nrr_platform_api::VpnCandidate> {
    use nrr_platform_windows::VpnDiscoveryPort;
    nrr_platform_windows::WindowsVpnDiscovery::new().discover_vpn_candidates()
}

#[cfg(target_os = "linux")]
fn discover_vpn_candidates_os() -> Vec<nrr_platform_api::VpnCandidate> {
    use nrr_platform_api::VpnDiscoveryPort;
    nrr_platform_linux::vpn_discovery::LinuxVpnDiscovery::new().discover_vpn_candidates()
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn discover_vpn_candidates_os() -> Vec<nrr_platform_api::VpnCandidate> {
    Vec::new()
}

/// Scan the machine for known application-group members (VMs / emulators +
/// torrents / P2P) and return the merged, tab-sorted list for the
/// onboarding UI. Runs LOCALLY in the launcher for the same reason as VPN
/// discovery (non-elevated process + registry enumeration, no service needed),
/// so the route-assignment onboarding works before the service is installed.
/// macOS finds nothing until its backend fills the seam.
fn handle_app_groups_discover() -> LocalHandlerResult {
    let apps = discover_app_groups_os();
    Ok(json!({ "apps": apps }))
}

#[cfg(target_os = "windows")]
fn discover_app_groups_os() -> Vec<nrr_platform_api::DiscoveredApp> {
    use nrr_platform_windows::AppGroupDiscoveryPort;
    nrr_platform_windows::WindowsAppGroupDiscovery::new().discover_app_groups()
}

#[cfg(target_os = "linux")]
fn discover_app_groups_os() -> Vec<nrr_platform_api::DiscoveredApp> {
    use nrr_platform_api::AppGroupDiscoveryPort;
    nrr_platform_linux::app_group_discovery::LinuxAppGroupDiscovery::new().discover_app_groups()
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn discover_app_groups_os() -> Vec<nrr_platform_api::DiscoveredApp> {
    Vec::new()
}

/// The hypervisors on this machine with their virtual machines, for the rules
/// screen that routes them. Local for the same reason as the discoveries above:
/// the settings files are the user's own and the service is not needed.
/// The payload names the additional adapter the way the preferences store it,
/// so each NAT pin can be read against its current address.
fn handle_vm_inventory_list(payload: &Value) -> LocalHandlerResult {
    let mut hypervisors = vm_inventory_os();
    let (host, additional) = host_addresses(&live_interface_rows(), &AdapterRef::from(payload));
    nrr_platform_api::classify_bindings(&mut hypervisors, &host, additional);
    Ok(json!({ "hypervisors": hypervisors }))
}

/// Pins a machine's NAT adapter to the additional adapter's current address
/// (`"route": "additional"`), or removes the pin (`"route": "rules"`). Answers
/// `{ "ok": true }` or `{ "ok": false, "error": <slug>, "message": <tool text> }`
/// — a refusal is an outcome the screen explains, not a transport failure.
fn handle_vm_nat_bind(payload: &Value) -> LocalHandlerResult {
    let hypervisor = match payload.get("hypervisor").and_then(Value::as_str) {
        Some("virtualbox") => nrr_platform_api::Hypervisor::VirtualBox,
        _ => {
            return Ok(bind_outcome(Err(
                nrr_platform_api::VmControlError::Unsupported,
            )))
        }
    };
    let machine_id = payload
        .get("machineId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let slot = payload
        .get("slot")
        .and_then(Value::as_u64)
        .and_then(|slot| u32::try_from(slot).ok());
    let Some(slot) = slot else {
        return Ok(bind_outcome(Err(
            nrr_platform_api::VmControlError::InvalidTarget,
        )));
    };
    let address = match payload.get("route").and_then(Value::as_str) {
        Some("rules") => None,
        Some("additional") => {
            let (_, additional) =
                host_addresses(&live_interface_rows(), &AdapterRef::from(payload));
            match additional {
                Some(address) => Some(address),
                None => return Ok(json!({ "ok": false, "error": "no-additional-address" })),
            }
        }
        _ => {
            return Ok(bind_outcome(Err(
                nrr_platform_api::VmControlError::InvalidTarget,
            )))
        }
    };
    Ok(bind_outcome(vm_bind_nat_os(
        hypervisor, machine_id, slot, address,
    )))
}

fn bind_outcome(result: Result<(), nrr_platform_api::VmControlError>) -> Value {
    match result {
        Ok(()) => json!({ "ok": true }),
        Err(error) => {
            let message = match &error {
                nrr_platform_api::VmControlError::Failed(text) => text.clone(),
                _ => String::new(),
            };
            json!({ "ok": false, "error": error.slug(), "message": message })
        }
    }
}

/// The additional adapter as the preferences name it: by id, else by name.
struct AdapterRef<'a> {
    id: &'a str,
    name: &'a str,
}

impl<'a> From<&'a Value> for AdapterRef<'a> {
    fn from(payload: &'a Value) -> Self {
        let field = |key: &str| payload.get(key).and_then(Value::as_str).unwrap_or_default();
        Self {
            id: field("additionalInterfaceId"),
            name: field("additionalInterfaceName"),
        }
    }
}

/// Every IPv4 address the host's adapters carry, and the additional adapter's.
fn host_addresses(
    rows: &[nrr_platform_api::InterfaceRouteRow],
    additional: &AdapterRef<'_>,
) -> (Vec<std::net::Ipv4Addr>, Option<std::net::Ipv4Addr>) {
    let ipv4 = |row: &nrr_platform_api::InterfaceRouteRow| {
        row.local_ip
            .split(|c: char| c == ',' || c.is_whitespace())
            .find_map(|part| part.parse::<std::net::Ipv4Addr>().ok())
    };
    let host = rows.iter().filter_map(ipv4).collect();
    // The same resolver the interfaces screen binds roles with.
    let address = nrr_platform_api::interface_rows::find_adapter_index(
        rows,
        Some(additional.id),
        Some(additional.name),
        None,
    )
    .and_then(|index| ipv4(&rows[index]));
    (host, address)
}

/// Live adapter rows; the placeholder rows a failed enumeration falls back to
/// would pin a machine to an address the host does not have.
fn live_interface_rows() -> Vec<nrr_platform_api::InterfaceRouteRow> {
    match nrr_mock_backend::network_interfaces::local_interface_rows().collect_rows(false) {
        (source, rows) if source.is_live() => rows,
        _ => Vec::new(),
    }
}

#[cfg(target_os = "windows")]
fn vm_bind_nat_os(
    hypervisor: nrr_platform_api::Hypervisor,
    machine_id: &str,
    slot: u32,
    address: Option<std::net::Ipv4Addr>,
) -> Result<(), nrr_platform_api::VmControlError> {
    use nrr_platform_api::VmInventoryPort;
    nrr_platform_windows::WindowsVmInventory::new().bind_nat(hypervisor, machine_id, slot, address)
}

#[cfg(target_os = "linux")]
fn vm_bind_nat_os(
    hypervisor: nrr_platform_api::Hypervisor,
    machine_id: &str,
    slot: u32,
    address: Option<std::net::Ipv4Addr>,
) -> Result<(), nrr_platform_api::VmControlError> {
    use nrr_platform_api::VmInventoryPort;
    nrr_platform_linux::vm_inventory::LinuxVmInventory::new()
        .bind_nat(hypervisor, machine_id, slot, address)
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn vm_bind_nat_os(
    hypervisor: nrr_platform_api::Hypervisor,
    machine_id: &str,
    slot: u32,
    address: Option<std::net::Ipv4Addr>,
) -> Result<(), nrr_platform_api::VmControlError> {
    use nrr_platform_api::VmInventoryPort;
    nrr_platform_api::NoopVmInventory.bind_nat(hypervisor, machine_id, slot, address)
}

#[cfg(target_os = "windows")]
fn vm_inventory_os() -> Vec<nrr_platform_api::HypervisorInventory> {
    use nrr_platform_api::VmInventoryPort;
    nrr_platform_windows::WindowsVmInventory::new().inventory()
}

#[cfg(target_os = "linux")]
fn vm_inventory_os() -> Vec<nrr_platform_api::HypervisorInventory> {
    use nrr_platform_api::VmInventoryPort;
    nrr_platform_linux::vm_inventory::LinuxVmInventory::new().inventory()
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn vm_inventory_os() -> Vec<nrr_platform_api::HypervisorInventory> {
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
    let mut dto: CanonicalRulesJsonV1 = serde_json::from_str(rules_json)?;
    // Hash what the rules MEAN, not how they were typed: the window and the
    // bound `.txt` keep the user's spelling while the service stores the
    // validated one, so an unfolded hash reported a permanent app-vs-service
    // difference over nothing but letter case.
    nrr_shared::rules_json::fold_for_comparison(&mut dto);
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

/// The verdict on one typed rule value — the one the rules table shows for it,
/// which for a zone or domain is the service's own import pipeline.
fn handle_rule_value_verdict(payload: &Value) -> LocalHandlerResult {
    let text = |field: &'static str| {
        payload
            .get(field)
            .and_then(Value::as_str)
            .ok_or(LocalHandlerError::MissingField(field))
    };
    let verdict = nrr_application::rule_value_validation::validate_rule_value(
        text("rule-type")?,
        text("match-value")?,
    );
    Ok(json!({
        "status": verdict.status_slug(),
        "message-key": verdict.message_key(),
        "args": verdict.args(),
    }))
}

/// Locale key of a pasted line that is no address, network or range.
const UNRECOGNIZED_LINE_KEY: &str = "rules.paste.line-unrecognized";

/// A pasted list, one entry per line (commas and semicolons also separate),
/// each sorted into the address type it is and judged as that type. Blank
/// entries and `#` comment lines are skipped; past the Free rule cap the list
/// is cut, since nothing beyond it could be added.
fn handle_rule_values_classify(payload: &Value) -> LocalHandlerResult {
    let text = payload
        .get("text")
        .and_then(Value::as_str)
        .ok_or(LocalHandlerError::MissingField("text"))?;
    let mut entries = text
        .split(['\n', '\r', ',', ';'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty() && !entry.starts_with('#'));
    let rows: Vec<Value> = entries
        .by_ref()
        .take(nrr_shared::rules_json::FREE_MAX_RULES)
        .map(classify_rule_value)
        .collect();
    let truncated = entries.next().is_some();
    Ok(json!({ "rows": rows, "truncated": truncated }))
}

fn classify_rule_value(value: &str) -> Value {
    use nrr_application::ip_network_policy::IpValueKind;
    let Some(kind) = IpValueKind::of(value) else {
        return json!({
            "value": value,
            "rule-type": "",
            "status": "error",
            "message-key": UNRECOGNIZED_LINE_KEY,
            "args": {},
        });
    };
    let rule_type = kind.rule_type_slug();
    let verdict = nrr_application::rule_value_validation::validate_rule_value(rule_type, value);
    json!({
        "value": value,
        "rule-type": rule_type,
        "status": verdict.status_slug(),
        "message-key": verdict.message_key(),
        "args": verdict.args(),
    })
}

/// Every exact rule already covered by a wildcard rule, so the rules screen
/// can offer the redundant ones for removal, and every pair of rules on the
/// two routes that claim the same hosts. Local because it is a pure function
/// of the rules the window already holds — asking the service would answer
/// about the APPLIED set, not the one on screen.
fn handle_rules_overlaps(payload: &Value) -> LocalHandlerResult {
    let rules_json = payload
        .get("rules-json")
        .and_then(Value::as_str)
        .ok_or(LocalHandlerError::MissingField("rules-json"))?;
    let dto: CanonicalRulesJsonV1 = serde_json::from_str(rules_json)?;
    // Absent means on: that is the product default for subdomain coverage.
    let include_subdomains = payload
        .get("include-subdomains")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let pairs = nrr_shared::rules_overlap::find_overlaps(&dto);
    let route_overlaps = nrr_shared::rules_overlap::find_route_overlaps(&dto, include_subdomains);
    Ok(json!({
        "pairs": pairs,
        "redundant-count": pairs.iter().filter(|p| p.redundant).count(),
        "route-overlaps": route_overlaps,
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

    /// The dialog's gate answers with the verdict the rules table shows.
    #[test]
    fn the_dialog_gets_the_rules_table_verdict() {
        let ask = |rule_type: &str, value: &str| {
            handle_local_request(
                "local.rule-value-verdict",
                &json!({ "rule-type": rule_type, "match-value": value }),
                &empty_client(),
            )
            .expect("verdict")
        };
        assert_eq!(ask("zone", ".ru")["status"], "valid");
        assert_eq!(ask("domain", "example.com.")["status"], "valid");
        let refused = ask("domain", "192.168.1.1");
        assert_eq!(refused["status"], "error");
        assert_eq!(
            refused["message-key"],
            "rules.validation.match-value-invalid.domain"
        );
        let out_of_range = ask("exact-ip", "300.1.1.1");
        assert_eq!(out_of_range["args"]["octet"], "300");
        assert!(matches!(
            handle_local_request(
                "local.rule-value-verdict",
                &json!({ "rule-type": "zone" }),
                &empty_client(),
            ),
            Err(LocalHandlerError::MissingField("match-value"))
        ));
    }

    fn classify(text: &str) -> Value {
        handle_local_request(
            "local.rule-values-classify",
            &json!({ "text": text }),
            &empty_client(),
        )
        .expect("classification")
    }

    /// A mixed paste comes back sorted by type, each line with that type's
    /// verdict, and a line that is no address says so.
    #[test]
    fn a_pasted_list_is_sorted_into_addresses_subnets_and_ranges() {
        let answer = classify(concat!(
            "203.0.113.7\r\n198.51.100.0/24\n\n# office\n",
            "192.0.2.10 - 192.0.2.20, 2001:db8::/48; example.com\n",
            "198.0.0.0/7\n198.51.100.9/24",
        ));
        assert_eq!(answer["truncated"], json!(false));
        let rows = answer["rows"].as_array().expect("rows");
        let summary: Vec<(&str, &str, &str)> = rows
            .iter()
            .map(|r| {
                (
                    r["value"].as_str().expect("value"),
                    r["rule-type"].as_str().expect("rule-type"),
                    r["status"].as_str().expect("status"),
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                ("203.0.113.7", "exact-ip", "valid"),
                ("198.51.100.0/24", "subnet", "valid"),
                ("192.0.2.10 - 192.0.2.20", "ip-range", "valid"),
                ("2001:db8::/48", "subnet", "valid"),
                ("example.com", "", "error"),
                ("198.0.0.0/7", "subnet", "error"),
                ("198.51.100.9/24", "subnet", "warning"),
            ]
        );
        assert_eq!(rows[4]["message-key"], UNRECOGNIZED_LINE_KEY);
        assert_eq!(
            rows[5]["message-key"],
            "rules.validation.match-value-invalid.network-too-wide"
        );
        assert_eq!(
            rows[6]["message-key"],
            "rules.validation.match-value-warning.subnet-host-bits"
        );
        assert_eq!(rows[6]["args"]["network"], "198.51.100.0/24");
    }

    /// Nothing past the Free cap could be added, so the answer stops there
    /// and says it did.
    #[test]
    fn a_paste_longer_than_the_rule_cap_is_cut_and_flagged() {
        let cap = nrr_shared::rules_json::FREE_MAX_RULES;
        let text = (0..=cap)
            .map(|i| format!("10.{}.{}.1", i / 256, i % 256))
            .collect::<Vec<_>>()
            .join("\n");
        let answer = classify(&text);
        assert_eq!(answer["rows"].as_array().expect("rows").len(), cap);
        assert_eq!(answer["truncated"], json!(true));
        assert!(matches!(
            handle_local_request("local.rule-values-classify", &json!({}), &empty_client()),
            Err(LocalHandlerError::MissingField("text"))
        ));
    }

    /// The live probe answers with a slug the shell already knows how to
    /// resolve, and it never dresses a fallback up as an observation — the
    /// same contract the cold-start context is held to.
    #[test]
    fn the_live_appearance_answer_is_a_slug_the_shell_understands() {
        let answer = handle_system_theme();
        let mode = answer["systemMode"].as_str().expect("systemMode");
        assert!(
            ["light", "dark", "high-contrast"].contains(&mode),
            "unknown appearance slug: {mode}"
        );
        assert!(
            answer["systemModeDetected"].is_boolean(),
            "an undetected system must be told apart from a light one"
        );
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

    /// The seven rules that kept the amber banner up through a whole session:
    /// same routing, different letter case on each side.
    #[test]
    fn the_reported_divergence_folds_away() {
        let typed = json!({ "rules-json": "{\"schema-version\": 1, \"primary\": [{\"id\": \"r1\", \"enabled\": true, \"app-match\": {\"pattern\": {\"kind\": \"exact\", \"value\": \"Cloud.exe\"}, \"include-child-processes\": false}}, {\"id\": \"r2\", \"enabled\": true, \"app-match\": {\"pattern\": {\"kind\": \"glob\", \"value\": \"DiskO*.exe\"}, \"include-child-processes\": false}}, {\"id\": \"r3\", \"enabled\": true, \"app-match\": {\"pattern\": {\"kind\": \"glob\", \"value\": \"VendorDis*.exe\"}, \"include-child-processes\": false}}, {\"id\": \"r4\", \"enabled\": true, \"app-match\": {\"pattern\": {\"kind\": \"exact\", \"value\": \"ExampleVPN 3.0.exe\"}, \"include-child-processes\": false}}], \"secondary\": []}" });
        let service = json!({ "rules-json": "{\"schema-version\": 1, \"primary\": [{\"id\": \"r93\", \"enabled\": true, \"app-match\": {\"pattern\": {\"kind\": \"exact\", \"value\": \"examplevpn 3.0.exe\"}, \"include-child-processes\": false}}, {\"id\": \"r92\", \"enabled\": true, \"app-match\": {\"pattern\": {\"kind\": \"glob\", \"value\": \"vendordis*.exe\"}, \"include-child-processes\": false}}, {\"id\": \"r91\", \"enabled\": true, \"app-match\": {\"pattern\": {\"kind\": \"glob\", \"value\": \"disko*.exe\"}, \"include-child-processes\": false}}, {\"id\": \"r90\", \"enabled\": true, \"app-match\": {\"pattern\": {\"kind\": \"exact\", \"value\": \"cloud.exe\"}, \"include-child-processes\": false}}], \"secondary\": []}" });
        assert_eq!(hash_of(&typed), hash_of(&service));
    }

    /// The window and the bound `.txt` keep the user's spelling; the service
    /// stores the validated one. Both must hash alike or the app-vs-service
    /// alarm fires forever over letter case alone.
    #[test]
    fn app_name_spelling_does_not_change_the_hash() {
        let typed = json!({
            "rules-json": r#"{"schema-version":1,"primary":[{"id":"r1","enabled":true,"app-match":{"pattern":{"kind":"exact","value":"Cloud.exe"},"include-child-processes":false}}],"secondary":[]}"#,
        });
        let validated = json!({
            "rules-json": r#"{"schema-version":1,"primary":[{"id":"r9","enabled":true,"app-match":{"pattern":{"kind":"exact","value":"cloud.exe"},"include-child-processes":false}}],"secondary":[]}"#,
        });
        assert_eq!(hash_of(&typed), hash_of(&validated));
    }

    /// Two sides may list the same rules in different orders — the service
    /// returns them in its canonical order, a file in the user's.
    #[test]
    fn rule_order_does_not_change_the_hash() {
        let one = json!({
            "rules-json": r#"{"schema-version":1,"primary":[{"id":"r1","enabled":true,"address-match":{"kind":"zone","name":"ru"}},{"id":"r2","enabled":true,"address-match":{"kind":"zone","name":"su"}}],"secondary":[]}"#,
        });
        let other = json!({
            "rules-json": r#"{"schema-version":1,"primary":[{"id":"r2","enabled":true,"address-match":{"kind":"zone","name":"su"}},{"id":"r1","enabled":true,"address-match":{"kind":"zone","name":"ru"}}],"secondary":[]}"#,
        });
        assert_eq!(hash_of(&one), hash_of(&other));
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
    fn route_overlaps_follow_the_subdomain_setting() {
        let rules = json!({
            "schema-version": 1,
            "primary": [{"id": "P1", "enabled": true,
                "address-match": {"kind": "exact-fqdn", "value": "site.example"}}],
            "secondary": [{"id": "S1", "enabled": true,
                "address-match": {"kind": "exact-fqdn", "value": "www.site.example"}}],
        })
        .to_string();
        let count = |include: Option<bool>| {
            let mut payload = json!({ "rules-json": rules });
            if let Some(include) = include {
                payload["include-subdomains"] = json!(include);
            }
            handle_rules_overlaps(&payload).expect("ok")["route-overlaps"]
                .as_array()
                .expect("array")
                .len()
        };
        assert_eq!(count(Some(false)), 0);
        assert_eq!(count(Some(true)), 1);
        assert_eq!(count(None), 1, "absent means the product default, on");
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

    /// The virtual machines screen reads `hypervisors` and hides itself when
    /// the list is empty, so the key must be there on every answer.
    #[test]
    fn vm_inventory_always_answers_with_a_hypervisor_list() {
        let resp = handle_local_request("local.vm-inventory.list", &json!({}), &empty_client())
            .expect("ok");
        assert!(resp["hypervisors"].is_array(), "{resp}");
    }

    fn row(id: &str, name: &str, ip: &str) -> nrr_platform_api::InterfaceRouteRow {
        let mut row = nrr_platform_api::interface_rows::fallback_rows()
            .into_iter()
            .next()
            .expect("a preview row");
        row.persistent_id = id.to_string();
        row.name = name.to_string();
        row.local_ip = ip.to_string();
        row
    }

    #[test]
    fn the_additional_address_is_found_by_id_else_by_name() {
        let rows = [
            row("id-a", "Ethernet", "192.0.2.10"),
            row("id-b", "Tunnel", "198.51.100.7"),
            row("id-c", "Offline", "-"),
        ];
        let by_id = AdapterRef {
            id: "id-b",
            name: "Ethernet",
        };
        let (host, additional) = host_addresses(&rows, &by_id);
        assert_eq!(host.len(), 2, "an adapter without an address adds none");
        assert_eq!(additional, Some(std::net::Ipv4Addr::new(198, 51, 100, 7)));
        let by_name = AdapterRef {
            id: "",
            name: "Tunnel",
        };
        assert_eq!(host_addresses(&rows, &by_name).1, additional);
        // A setting the interfaces screen resolves must resolve here too.
        let loosely_named = AdapterRef {
            id: "",
            name: "tunnel ",
        };
        assert_eq!(host_addresses(&rows, &loosely_named).1, additional);
        let unset = AdapterRef { id: "", name: "" };
        assert_eq!(host_addresses(&rows, &unset).1, None);
    }

    /// A refusal is an answer the screen explains, not a transport error.
    #[test]
    fn a_pin_that_cannot_be_made_answers_with_a_reason() {
        let client = empty_client();
        for (payload, error) in [
            (
                json!({ "hypervisor": "other", "machineId": "x", "slot": 0, "route": "rules" }),
                "unsupported",
            ),
            (
                json!({ "hypervisor": "virtualbox", "machineId": "x", "route": "rules" }),
                "invalid-target",
            ),
            (
                json!({ "hypervisor": "virtualbox", "machineId": "x", "slot": 0, "route": "sideways" }),
                "invalid-target",
            ),
            (
                json!({ "hypervisor": "virtualbox", "machineId": "--help", "slot": 0, "route": "rules" }),
                "invalid-target",
            ),
        ] {
            let resp = handle_local_request("local.vm-nat.bind", &payload, &client).expect("ok");
            assert_eq!(resp["ok"], false, "{payload}");
            assert_eq!(resp["error"], error, "{payload}");
        }
    }
}
