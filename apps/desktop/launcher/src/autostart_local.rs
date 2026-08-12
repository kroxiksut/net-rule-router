//! User-context autostart, owned by the launcher.
//!
//! The Windows service runs as `LocalSystem`, so inside it
//! `HKEY_CURRENT_USER` is the SYSTEM account's hive, NOT the interactive
//! user's. The tray autostart Run key therefore never landed in the user's
//! hive and never fired at logon — the Settings toggle silently did nothing.
//!
//! The launcher runs AS the interactive user, so it owns autostart. It answers
//! `autostart.get` / `autostart.toggle` locally (correct hive) and patches the
//! `autostart` field of the `snapshot.initial.get` response so the GUI's
//! initial display reflects the real user-hive state. This mirrors
//! [`crate::archive_localize`]: the launcher fixes up a service response with
//! user-context data the service cannot see. The service-side autostart
//! handlers/provider stay compiled but are shadowed for these ops (the
//! dispatcher intercepts them before the pipe hop).

use serde_json::Value;

/// `true` for the two autostart ops the launcher answers locally. Windows
/// only: the launcher-owned path exists solely to dodge the `LocalSystem`
/// `HKEY_CURRENT_USER` mismatch. On every other OS the service runs in the
/// user's own context and owns autostart (XDG `.desktop` / launchd), so these
/// ops must fall through to the service unchanged.
#[cfg(windows)]
pub fn is_local_autostart_op(operation: &str) -> bool {
    operation == "autostart.get" || operation == "autostart.toggle"
}

#[cfg(not(windows))]
pub fn is_local_autostart_op(_operation: &str) -> bool {
    false
}

/// Handle `autostart.get` / `autostart.toggle` against the user's real HKCU.
/// Returns the `AutostartDto` JSON on success, or an error string mapped to a
/// wire response by the caller. Only call when [`is_local_autostart_op`] is
/// true.
#[cfg(windows)]
pub fn handle_local_autostart(operation: &str, payload: &Value) -> Result<Value, String> {
    match operation {
        "autostart.get" => imp::get(),
        "autostart.toggle" => {
            let enabled = payload
                .get("enabled")
                .and_then(Value::as_bool)
                .ok_or_else(|| "autostart.toggle payload missing bool `enabled`".to_string())?;
            imp::toggle(enabled)
        }
        other => Err(format!("not a local autostart op: {other}")),
    }
}

/// Non-Windows fallback: no user-hive autostart mechanism here, so decline to
/// handle locally (the caller forwards to the service unchanged).
#[cfg(not(windows))]
pub fn handle_local_autostart(_operation: &str, _payload: &Value) -> Result<Value, String> {
    Err("local autostart handling is Windows-only".to_string())
}

/// Replace the `autostart` field of a `snapshot.initial.get` response with a
/// fresh local (user-hive) probe, so the GUI's first paint shows the real
/// state instead of the service's SYSTEM-hive reading. Best-effort: on any
/// probe failure (or non-object response) the value passes through unchanged.
///
/// The insert is unconditional on a successful probe: this helper is only ever
/// called on a `SnapshotInitialResponse`, whose schema always carries an
/// `autostart` field (it is merely `skip_serializing_if = Option::is_none`
/// when the service had nothing to report). Seeding the user-hive truth even
/// when the service omitted it — e.g. a storage-recovery snapshot — is the
/// most correct behaviour, since the service's own reading is exactly the
/// SYSTEM-hive value this fix exists to override.
#[cfg(windows)]
pub fn patch_snapshot_autostart(mut value: Value) -> Value {
    if let (Value::Object(map), Ok(dto)) = (&mut value, imp::get()) {
        map.insert("autostart".to_string(), dto);
    }
    value
}

#[cfg(not(windows))]
pub fn patch_snapshot_autostart(value: Value) -> Value {
    value
}

#[cfg(windows)]
mod imp {
    use serde_json::Value;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use nrr_platform_windows::autostart::{
        AutostartCurrentState, AutostartHelper, ProductionAutostartRegistry,
    };
    use nrr_shared::ipc_payloads::AutostartDto;

    /// The tray binary the Run key points at — resolved next to the running
    /// launcher (`NetRuleRouterTray.exe` ships alongside `NetRuleRouter.exe`).
    fn tray_binary_path() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let dir = exe.parent()?;
        Some(dir.join("NetRuleRouterTray.exe"))
    }

    fn helper() -> AutostartHelper<ProductionAutostartRegistry> {
        AutostartHelper::new(ProductionAutostartRegistry::new())
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Map a probed registry state to the typed `AutostartDto`, then to its
    /// wire JSON. Building the real contract struct (rather than hand-rolling
    /// the kebab-case object) guarantees the launcher-local response stays
    /// byte-identical to the service's `record_to_dto`/`merge_observation`
    /// shape if the DTO ever grows a field.
    ///
    /// For the launcher-local path there is no separate stored "intent" row to
    /// consult, so `enabled` is derived from the live registry truth: an entry
    /// that is present and ours → enabled; anything else (absent, or a foreign
    /// override) → not enabled.
    fn state_to_dto(state: &AutostartCurrentState) -> Value {
        let dto = match state {
            AutostartCurrentState::Enabled { matches_ours, .. } => {
                if *matches_ours {
                    AutostartDto {
                        enabled: true,
                        last_known_state: "enabled".to_string(),
                        overridden_value: None,
                        updated_at: now_secs(),
                    }
                } else {
                    AutostartDto {
                        enabled: false,
                        last_known_state: "overridden-externally".to_string(),
                        overridden_value: Some(String::new()),
                        updated_at: now_secs(),
                    }
                }
            }
            AutostartCurrentState::Disabled => AutostartDto {
                enabled: false,
                last_known_state: "disabled".to_string(),
                overridden_value: None,
                updated_at: now_secs(),
            },
            AutostartCurrentState::OverriddenExternally { value } => AutostartDto {
                enabled: false,
                last_known_state: "overridden-externally".to_string(),
                overridden_value: Some(value.clone()),
                updated_at: now_secs(),
            },
        };
        // `to_value` on a plain derive-Serialize struct with string keys is
        // infallible; the fallback is dead but keeps the crate `unwrap`-free.
        serde_json::to_value(dto).unwrap_or(Value::Null)
    }

    pub(super) fn get() -> Result<Value, String> {
        let tray =
            tray_binary_path().ok_or_else(|| "cannot resolve tray binary path".to_string())?;
        let state = helper()
            .get_state(&tray)
            .map_err(|e| format!("autostart probe failed: {e:?}"))?;
        Ok(state_to_dto(&state))
    }

    pub(super) fn toggle(enabled: bool) -> Result<Value, String> {
        let tray =
            tray_binary_path().ok_or_else(|| "cannot resolve tray binary path".to_string())?;
        let h = helper();
        let outcome = if enabled {
            h.set_enabled(&tray)
        } else {
            h.clear()
        };
        outcome.map_err(|e| format!("autostart write failed: {e:?}"))?;
        let state = h
            .get_state(&tray)
            .map_err(|e| format!("autostart re-probe failed: {e:?}"))?;
        Ok(state_to_dto(&state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn recognises_the_two_local_autostart_ops() {
        assert!(is_local_autostart_op("autostart.get"));
        assert!(is_local_autostart_op("autostart.toggle"));
        assert!(!is_local_autostart_op("autostart.something-else"));
        assert!(!is_local_autostart_op("route.policy.update"));
    }

    #[cfg(not(windows))]
    #[test]
    fn autostart_ops_are_not_local_off_windows() {
        // Off Windows the service owns autostart; the launcher never intercepts.
        assert!(!is_local_autostart_op("autostart.get"));
        assert!(!is_local_autostart_op("autostart.toggle"));
    }

    /// On Windows the probe is unconditional: an object snapshot gains a
    /// well-formed `autostart` DTO even when the service omitted the field
    /// (recovery snapshot). The registry probe against the test machine's own
    /// HKCU succeeds (Disabled at worst), so the field is always inserted.
    #[cfg(windows)]
    #[test]
    fn patch_inserts_autostart_into_object_snapshot() {
        let v = serde_json::json!({ "service-health": { "state": "running" } });
        let patched = patch_snapshot_autostart(v);
        let autostart = patched
            .get("autostart")
            .expect("autostart field inserted on Windows");
        assert!(autostart.get("enabled").and_then(|e| e.as_bool()).is_some());
        assert!(autostart
            .get("last-known-state")
            .and_then(|s| s.as_str())
            .is_some());
        // The unrelated field is preserved.
        assert!(patched.get("service-health").is_some());
    }

    /// Off Windows the patch is a pure passthrough — the service owns
    /// autostart there, so the snapshot is returned verbatim.
    #[cfg(not(windows))]
    #[test]
    fn patch_is_passthrough_off_windows() {
        let v = serde_json::json!({ "service-health": { "state": "running" } });
        assert_eq!(patch_snapshot_autostart(v.clone()), v);
    }

    /// A non-object response never gains an `autostart` field on any OS —
    /// the `Value::Object` guard (Windows) / passthrough (else) both decline.
    #[test]
    fn patch_leaves_non_object_untouched() {
        let v = serde_json::json!("not-an-object");
        assert_eq!(patch_snapshot_autostart(v.clone()), v);
    }
}
