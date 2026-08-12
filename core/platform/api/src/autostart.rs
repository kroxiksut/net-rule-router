//! Autostart coordinator — the neutral port.
//!
//! Decides what "launch at login" should look like (compare the observed OS
//! state to our desired state, classify an existing entry as ours vs. an
//! external override) without ever touching the OS mechanism directly. Per
//! the policy/mechanism seam, the coordination logic
//! ([`AutostartHelper`]) and the [`AutostartRegistryPort`] trait it drives
//! live here; each OS backend implements the port against its native
//! mechanism:
//!
//! - **Windows** — `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` via
//!   the Win32 Registry API (in `nrr-platform-windows`).
//! - **Linux / macOS** — XDG autostart `.desktop` file / launchd agent
//!   (future).
//!
//! Tests exercise [`AutostartHelper`] against [`MockAutostartRegistry`], a
//! simple `Mutex<Option<String>>` — same pattern as the existing
//! `WindowsApiPort` / `MockWindowsApi` split.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

// ── Public DTOs / errors ──────────────────────────────────────────────────────

/// What the registry probe found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AutostartCurrentState {
    /// Registry value present and points at a binary that matches our
    /// binary path (`matches_ours = true`) or at our binary verbatim.
    /// `binary_path` is the parsed value with surrounding quotes
    /// stripped.
    Enabled {
        binary_path: PathBuf,
        matches_ours: bool,
    },
    /// Registry value absent. Default state on a clean install.
    Disabled,
    /// Registry value present but parses to a path other than ours
    /// (e.g. a different installation directory or an unrelated
    /// program). Surfaced so the GUI can warn the user before
    /// overwriting.
    OverriddenExternally { value: String },
}

/// Coordinator-level errors. Distinct from `PlatformError` because the
/// autostart helper is independent of the apply layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AutostartError {
    /// Registry call failed. `code` is the Win32 `LSTATUS` (`u32`)
    /// returned by the registry function; `message` is
    /// operator-readable.
    RegistryAccess { code: u32, message: String },
    /// Caller-supplied path is not absolute or is empty.
    InvalidPath,
}

// ── Port trait ────────────────────────────────────────────────────────────────

/// Read/write/delete a single named "launch at login" entry. The
/// implementation is responsible for locating and opening the underlying
/// OS mechanism (registry key, `.desktop` file, launchd agent, ...) with
/// the right access rights.
pub trait AutostartRegistryPort: Send + Sync {
    /// Reads the value if present. Returns `Ok(None)` when the value is
    /// absent (NOT an error).
    fn read_value(&self) -> Result<Option<String>, AutostartError>;
    /// Writes the value, replacing any existing entry.
    fn write_value(&self, value: &str) -> Result<(), AutostartError>;
    /// Deletes the value. Idempotent — absent value is `Ok(())`.
    fn delete_value(&self) -> Result<(), AutostartError>;
}

// ── Helper struct ─────────────────────────────────────────────────────────────

pub struct AutostartHelper<P: AutostartRegistryPort> {
    port: P,
}

impl<P: AutostartRegistryPort> AutostartHelper<P> {
    pub const fn new(port: P) -> Self {
        Self { port }
    }

    /// Writes the value pointing at `target_exe`. The path is quoted to
    /// survive the (unlikely) case of a space in the install directory.
    pub fn set_enabled(&self, target_exe: &Path) -> Result<(), AutostartError> {
        let value = format_registry_value(target_exe)?;
        self.port.write_value(&value)
    }

    /// Removes the value. Idempotent.
    pub fn clear(&self) -> Result<(), AutostartError> {
        self.port.delete_value()
    }

    /// Probes the port and classifies the current state. The
    /// `our_binary_path` argument is used to decide whether an existing
    /// value matches us or has been overridden.
    pub fn get_state(
        &self,
        our_binary_path: &Path,
    ) -> Result<AutostartCurrentState, AutostartError> {
        let raw = self.port.read_value()?;
        let raw = match raw {
            None => return Ok(AutostartCurrentState::Disabled),
            Some(s) if s.trim().is_empty() => return Ok(AutostartCurrentState::Disabled),
            Some(s) => s,
        };
        let parsed = parse_registry_value(&raw);
        if paths_match(&parsed, our_binary_path) {
            Ok(AutostartCurrentState::Enabled {
                binary_path: parsed,
                matches_ours: true,
            })
        } else {
            Ok(AutostartCurrentState::OverriddenExternally { value: raw })
        }
    }
}

// ── Pure helpers ──────────────────────────────────────────────────────────────

/// Builds the value to write — `"<path>"` (quoted to be safe across
/// consumers that split on whitespace).
fn format_registry_value(target: &Path) -> Result<String, AutostartError> {
    if target.as_os_str().is_empty() {
        return Err(AutostartError::InvalidPath);
    }
    if !target.is_absolute() {
        return Err(AutostartError::InvalidPath);
    }
    let s = target.to_string_lossy().to_string();
    Ok(format!("\"{s}\""))
}

/// Strips surrounding quotes and any trailing argument tokens. Returns
/// the bare path component as a `PathBuf`.
pub(crate) fn parse_registry_value(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    // Two cases: quoted (`"path with space" args...`) or bare (`path
    // args...`). For bare, splitting on whitespace is good enough —
    // unquoted paths with spaces would already be ambiguous.
    if let Some(rest) = trimmed.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return PathBuf::from(&rest[..end]);
        }
    }
    let bare = trimmed.split_whitespace().next().unwrap_or("");
    PathBuf::from(bare)
}

/// Case-insensitive path equality (Windows convention). We compare
/// canonicalised string forms — symlinks are out of scope for this
/// flow (the tray binary lives in our install directory).
pub(crate) fn paths_match(a: &Path, b: &Path) -> bool {
    let a = a.to_string_lossy();
    let b = b.to_string_lossy();
    a.eq_ignore_ascii_case(&b)
}

// ── Mock impl for tests ───────────────────────────────────────────────────────

/// In-memory registry port. The constructor seeds the slot to whatever
/// value tests need; `force_error_on_read/write/delete` lets tests
/// simulate Win32 failures.
pub struct MockAutostartRegistry {
    value: Mutex<Option<String>>,
    force_read_error: Mutex<Option<AutostartError>>,
    force_write_error: Mutex<Option<AutostartError>>,
    force_delete_error: Mutex<Option<AutostartError>>,
}

impl Default for MockAutostartRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Test-only mock: lock-poisoning `expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl MockAutostartRegistry {
    pub fn new() -> Self {
        Self {
            value: Mutex::new(None),
            force_read_error: Mutex::new(None),
            force_write_error: Mutex::new(None),
            force_delete_error: Mutex::new(None),
        }
    }

    pub fn with_value(value: &str) -> Self {
        let m = Self::new();
        *m.value.lock().expect("mock mutex") = Some(value.to_string());
        m
    }

    pub fn current_value(&self) -> Option<String> {
        self.value.lock().expect("mock mutex").clone()
    }

    pub fn set_value(&self, value: Option<String>) {
        *self.value.lock().expect("mock mutex") = value;
    }

    pub fn force_read_error(&self, err: AutostartError) {
        *self.force_read_error.lock().expect("mock mutex") = Some(err);
    }

    pub fn force_write_error(&self, err: AutostartError) {
        *self.force_write_error.lock().expect("mock mutex") = Some(err);
    }

    pub fn force_delete_error(&self, err: AutostartError) {
        *self.force_delete_error.lock().expect("mock mutex") = Some(err);
    }
}

// Test-only mock: lock-poisoning `expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl AutostartRegistryPort for MockAutostartRegistry {
    fn read_value(&self) -> Result<Option<String>, AutostartError> {
        if let Some(err) = self.force_read_error.lock().expect("mock mutex").take() {
            return Err(err);
        }
        Ok(self.value.lock().expect("mock mutex").clone())
    }

    fn write_value(&self, value: &str) -> Result<(), AutostartError> {
        if let Some(err) = self.force_write_error.lock().expect("mock mutex").take() {
            return Err(err);
        }
        *self.value.lock().expect("mock mutex") = Some(value.to_string());
        Ok(())
    }

    fn delete_value(&self) -> Result<(), AutostartError> {
        if let Some(err) = self.force_delete_error.lock().expect("mock mutex").take() {
            return Err(err);
        }
        *self.value.lock().expect("mock mutex") = None;
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ours() -> PathBuf {
        PathBuf::from(r"C:\Program Files\NetRuleRouter\NetRuleRouterTray.exe")
    }

    fn helper(reg: MockAutostartRegistry) -> AutostartHelper<MockAutostartRegistry> {
        AutostartHelper::new(reg)
    }

    // ── Pure helpers ──────────────────────────────────────────────────────────

    #[test]
    fn parse_quoted_value_strips_outer_quotes() {
        assert_eq!(
            parse_registry_value(r#""C:\path\binary.exe""#),
            PathBuf::from(r"C:\path\binary.exe"),
        );
    }

    #[test]
    fn parse_quoted_value_with_args_keeps_only_the_path() {
        assert_eq!(
            parse_registry_value(r#""C:\path\binary.exe" --arg=value"#),
            PathBuf::from(r"C:\path\binary.exe"),
        );
    }

    #[test]
    fn parse_unquoted_value_picks_first_token() {
        assert_eq!(
            parse_registry_value(r"C:\bin.exe --foo"),
            PathBuf::from(r"C:\bin.exe"),
        );
    }

    #[test]
    fn paths_match_is_case_insensitive() {
        assert!(paths_match(
            Path::new(r"C:\Path\binary.exe"),
            Path::new(r"c:\path\BINARY.EXE"),
        ));
        assert!(!paths_match(
            Path::new(r"C:\Path\binary.exe"),
            Path::new(r"C:\Other\binary.exe"),
        ));
    }

    // ── set_enabled / get_state / clear ───────────────────────────────────────

    #[test]
    fn set_enabled_writes_quoted_value() {
        let reg = MockAutostartRegistry::new();
        let h = helper(reg);
        // `format_registry_value` rejects non-absolute paths, and a `C:\…` path
        // is only `is_absolute()` on Windows — use a host-absolute path so this
        // neutral-crate test also runs green on Linux/macOS.
        let exe = if cfg!(windows) {
            PathBuf::from(r"C:\Program Files\NetRuleRouter\NetRuleRouterTray.exe")
        } else {
            PathBuf::from("/opt/netrulerouter/NetRuleRouterTray.exe")
        };
        h.set_enabled(&exe).expect("set");
        let v = match h.port.current_value() {
            Some(s) => s,
            None => panic!("expected value to be written"),
        };
        assert!(v.starts_with('"') && v.ends_with('"'));
        assert!(v.contains("NetRuleRouterTray.exe"));
    }

    #[test]
    fn set_enabled_rejects_relative_path() {
        let h = helper(MockAutostartRegistry::new());
        assert!(matches!(
            h.set_enabled(Path::new("relative\\path.exe")),
            Err(AutostartError::InvalidPath)
        ));
    }

    #[test]
    fn set_enabled_rejects_empty_path() {
        let h = helper(MockAutostartRegistry::new());
        assert!(matches!(
            h.set_enabled(Path::new("")),
            Err(AutostartError::InvalidPath)
        ));
    }

    #[test]
    fn get_state_disabled_when_value_absent() {
        let h = helper(MockAutostartRegistry::new());
        let s = h.get_state(&ours()).expect("get");
        assert_eq!(s, AutostartCurrentState::Disabled);
    }

    #[test]
    fn get_state_disabled_when_value_is_empty_string() {
        let h = helper(MockAutostartRegistry::with_value(""));
        assert_eq!(
            h.get_state(&ours()).expect("get"),
            AutostartCurrentState::Disabled
        );
    }

    #[test]
    fn get_state_enabled_matches_ours() {
        let reg = MockAutostartRegistry::with_value(
            r#""C:\Program Files\NetRuleRouter\NetRuleRouterTray.exe""#,
        );
        let h = helper(reg);
        match h.get_state(&ours()).expect("get") {
            AutostartCurrentState::Enabled { matches_ours, .. } => {
                assert!(matches_ours);
            }
            other => panic!("expected Enabled, got {other:?}"),
        }
    }

    #[test]
    fn get_state_enabled_matches_ours_case_insensitive() {
        let reg = MockAutostartRegistry::with_value(
            r#""C:\PROGRAM FILES\netrulerouter\netrulerOuterTray.exe""#,
        );
        let h = helper(reg);
        match h.get_state(&ours()).expect("get") {
            AutostartCurrentState::Enabled {
                matches_ours: true, ..
            } => {}
            other => panic!("expected Enabled+matches_ours, got {other:?}"),
        }
    }

    #[test]
    fn get_state_overridden_when_value_points_elsewhere() {
        let reg = MockAutostartRegistry::with_value(r#""C:\OtherVendor\evil.exe""#);
        let h = helper(reg);
        match h.get_state(&ours()).expect("get") {
            AutostartCurrentState::OverriddenExternally { value } => {
                assert!(value.contains("evil.exe"));
            }
            other => panic!("expected OverriddenExternally, got {other:?}"),
        }
    }

    #[test]
    fn clear_removes_value() {
        let reg = MockAutostartRegistry::with_value(r#""C:\bin.exe""#);
        let h = helper(reg);
        h.clear().expect("clear");
        assert!(h.port.current_value().is_none());
    }

    #[test]
    fn clear_is_idempotent_on_absent_value() {
        let h = helper(MockAutostartRegistry::new());
        h.clear().expect("first clear");
        h.clear().expect("second clear");
    }

    #[test]
    fn registry_access_error_propagates() {
        let reg = MockAutostartRegistry::new();
        reg.force_read_error(AutostartError::RegistryAccess {
            code: 5,
            message: "access denied".into(),
        });
        let h = helper(reg);
        match h.get_state(&ours()) {
            Err(AutostartError::RegistryAccess { code: 5, .. }) => {}
            other => panic!("expected RegistryAccess(5), got {other:?}"),
        }
    }
}
