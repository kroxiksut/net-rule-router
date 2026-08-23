//! User-context autostart, owned by the launcher.
//!
//! "Launch at login" is a PER-USER setting, so the process that executes the
//! mechanism must be the user's own. The launcher is; no background service is.
//! On Windows the service runs as `LocalSystem`, where `HKEY_CURRENT_USER` is
//! the SYSTEM hive; on Linux the daemon runs as root (the unit carries no
//! `User=`), where `$HOME` is `/root`. Either one would write an entry the
//! user's session never reads, and read back a state that cannot be true for
//! the user.
//!
//! The launcher therefore answers `autostart.get` / `autostart.toggle` locally
//! and patches the `autostart` field of the `snapshot.initial.get` response so
//! the GUI's initial display reflects the real user-context state. This mirrors
//! [`crate::archive_localize`]: the launcher fixes up a service response with
//! user-context data the service cannot see. The service-side autostart
//! handlers/provider stay compiled but are shadowed for these ops (the
//! dispatcher intercepts them before the pipe hop).
//!
//! macOS is deliberately out: the launchd mechanism does not exist yet, so
//! these ops fall through to the service rather than failing locally.

use serde_json::Value;

/// `true` for the two autostart ops the launcher answers locally — on every OS
/// where a user-context mechanism exists. See the module docs for why this is
/// the launcher's job rather than the service's.
#[cfg(any(windows, target_os = "linux"))]
pub fn is_local_autostart_op(operation: &str) -> bool {
    operation == "autostart.get" || operation == "autostart.toggle"
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn is_local_autostart_op(_operation: &str) -> bool {
    false
}

/// Handle `autostart.get` / `autostart.toggle` against the user's own context.
/// Returns the `AutostartDto` JSON on success, or an error string mapped to a
/// wire response by the caller. Only call when [`is_local_autostart_op`] is
/// true.
#[cfg(any(windows, target_os = "linux"))]
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

/// Fallback where no user-context mechanism is implemented: decline to handle
/// locally (the caller forwards to the service unchanged).
#[cfg(not(any(windows, target_os = "linux")))]
pub fn handle_local_autostart(_operation: &str, _payload: &Value) -> Result<Value, String> {
    Err("local autostart handling is not implemented on this OS".to_string())
}

/// Replace the `autostart` field of a `snapshot.initial.get` response with a
/// fresh local (user-context) probe, so the GUI's first paint shows the real
/// state instead of the service's system-context reading. Best-effort: on any
/// probe failure (or non-object response) the value passes through unchanged.
///
/// The insert is unconditional on a successful probe: this helper is only ever
/// called on a `SnapshotInitialResponse`, whose schema always carries an
/// `autostart` field (it is merely `skip_serializing_if = Option::is_none`
/// when the service had nothing to report). Seeding the user-context truth even
/// when the service omitted it — e.g. a storage-recovery snapshot — is the
/// most correct behaviour, since the service's own reading is exactly the
/// system-context value this fix exists to override.
#[cfg(any(windows, target_os = "linux"))]
pub fn patch_snapshot_autostart(mut value: Value) -> Value {
    if let (Value::Object(map), Ok(dto)) = (&mut value, imp::get()) {
        map.insert("autostart".to_string(), dto);
    }
    value
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn patch_snapshot_autostart(value: Value) -> Value {
    value
}

#[cfg(any(windows, target_os = "linux"))]
mod imp {
    use serde_json::Value;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use nrr_platform_api::autostart::{AutostartCurrentState, AutostartHelper};
    use nrr_shared::ipc_payloads::AutostartDto;
    use nrr_shared::product_identity::BinaryRole;

    /// The tray binary the autostart entry points at, resolved next to the
    /// running launcher — the two ship side by side. The role is the same on
    /// every OS: the tray is the session agent, and login is exactly when a
    /// session agent should come up.
    fn tray_binary_path() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let dir = exe.parent()?;
        Some(dir.join(BinaryRole::Tray.host_file_name()))
    }

    /// The user-context mechanism for this OS: the real `HKEY_CURRENT_USER`
    /// hive on Windows, the XDG autostart directory under the user's own
    /// `$HOME` on Linux.
    #[cfg(windows)]
    fn helper(
    ) -> Result<AutostartHelper<nrr_platform_windows::autostart::ProductionAutostartRegistry>, String>
    {
        Ok(AutostartHelper::new(
            nrr_platform_windows::autostart::ProductionAutostartRegistry::new(),
        ))
    }

    #[cfg(target_os = "linux")]
    fn helper(
    ) -> Result<AutostartHelper<nrr_platform_linux::autostart::XdgAutostartRegistry>, String> {
        let registry = nrr_platform_linux::autostart::XdgAutostartRegistry::new()
            .map_err(|e| format!("cannot resolve the autostart directory: {e:?}"))?;
        Ok(AutostartHelper::new(registry))
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Map a probed state to the typed `AutostartDto`, then to its wire JSON.
    /// Building the real contract struct (rather than hand-rolling the
    /// kebab-case object) guarantees the launcher-local response stays
    /// byte-identical to the service's `record_to_dto`/`merge_observation`
    /// shape if the DTO ever grows a field.
    ///
    /// For the launcher-local path there is no separate stored "intent" row to
    /// consult, so `enabled` is derived from the live mechanism: an entry that
    /// is present and ours → enabled; anything else (absent, or a foreign
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
        let state = helper()?
            .get_state(&tray)
            .map_err(|e| format!("autostart probe failed: {e:?}"))?;
        Ok(state_to_dto(&state))
    }

    pub(super) fn toggle(enabled: bool) -> Result<Value, String> {
        let tray =
            tray_binary_path().ok_or_else(|| "cannot resolve tray binary path".to_string())?;
        let h = helper()?;
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

    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn recognises_the_two_local_autostart_ops() {
        assert!(is_local_autostart_op("autostart.get"));
        assert!(is_local_autostart_op("autostart.toggle"));
        assert!(!is_local_autostart_op("autostart.something-else"));
        assert!(!is_local_autostart_op("route.policy.update"));
    }

    /// Where no user-context mechanism is implemented the ops travel to the
    /// service unchanged rather than failing locally.
    #[cfg(not(any(windows, target_os = "linux")))]
    #[test]
    fn autostart_ops_are_not_local_without_a_mechanism() {
        assert!(!is_local_autostart_op("autostart.get"));
        assert!(!is_local_autostart_op("autostart.toggle"));
    }

    /// A successful probe inserts a well-formed `autostart` DTO even when the
    /// service omitted the field (recovery snapshot), and leaves everything
    /// else alone. The probe can legitimately fail in a bare test environment
    /// (Linux with no `HOME`/`XDG_CONFIG_HOME`), which is a passthrough — so
    /// the assertion is on the SHAPE when the field appears.
    #[cfg(any(windows, target_os = "linux"))]
    #[test]
    fn patch_inserts_a_well_formed_autostart_or_passes_through() {
        let v = serde_json::json!({ "service-health": { "state": "running" } });
        let patched = patch_snapshot_autostart(v);
        if let Some(autostart) = patched.get("autostart") {
            assert!(autostart.get("enabled").and_then(|e| e.as_bool()).is_some());
            assert!(autostart
                .get("last-known-state")
                .and_then(|s| s.as_str())
                .is_some());
        }
        // The unrelated field survives either way.
        assert!(patched.get("service-health").is_some());
    }

    /// A non-object response never gains an `autostart` field on any OS — the
    /// `Value::Object` guard and the passthrough both decline.
    #[test]
    fn patch_leaves_non_object_untouched() {
        let v = serde_json::json!("not-an-object");
        assert_eq!(patch_snapshot_autostart(v.clone()), v);
    }
}
