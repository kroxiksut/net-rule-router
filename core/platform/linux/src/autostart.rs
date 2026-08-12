//! Linux autostart mechanism (XDG `.desktop` at login).
//!
//! The neutral autostart coordinator — the [`AutostartRegistryPort`] trait,
//! the generic [`AutostartHelper`], the state/error types and the
//! [`MockAutostartRegistry`] test double — lives in `nrr-platform-api`, shared
//! with Windows. This module implements the port's MECHANISM for Linux: a
//! per-user **XDG autostart** entry, the desktop-session analog of Windows'
//! `HKCU\…\Run` value.
//!
//! ## Why XDG autostart and not a systemd user unit
//!
//! The entry launches `NetRuleRouterTray` when the user logs into their
//! graphical session — exactly what a desktop autostart hook is for. A
//! `.desktop` file dropped in `$XDG_CONFIG_HOME/autostart/` is the portable
//! cross-desktop (GNOME/KDE/XFCE) mechanism for that; a systemd `--user`
//! service activates on the user bus, not on graphical login, and would need
//! `systemctl` orchestration. The port models a single string value, which
//! maps cleanly onto the `.desktop` `Exec=` field.
//!
//! ## Faithful round-trip
//!
//! The port is a dumb key/value store over a file: `write_value` embeds the
//! helper-supplied string verbatim in `Exec=`, `read_value` returns that same
//! string. All quoting/parsing of the binary path stays in the neutral
//! `AutostartHelper` (`format_registry_value` / `parse_registry_value`), so
//! this impl never second-guesses the coordinator.
//!
//! ## Testability
//!
//! [`XdgAutostartRegistry::new`] resolves the real XDG directory;
//! [`XdgAutostartRegistry::with_autostart_dir`] points at an arbitrary dir so
//! unit tests round-trip through a tempdir without touching the user's real
//! `~/.config/autostart/`. The `.desktop` render/parse is pure and tested
//! directly. Because the impl is portable `std` (`fs`/`path`/`env`), it
//! compiles and its tests run on the Windows dev host too — the consumer still
//! selects it only under `#[cfg(target_os = "linux")]`.

use std::io::ErrorKind;
use std::path::PathBuf;

// Re-export the neutral coordinator so `nrr_platform_linux::autostart::*`
// paths mirror `nrr_platform_windows::autostart::*`.
pub use nrr_platform_api::autostart::{
    AutostartCurrentState, AutostartError, AutostartHelper, AutostartRegistryPort,
    MockAutostartRegistry,
};

/// The `.desktop` basename we own. Stable across versions — renaming it would
/// orphan existing autostart entries on user upgrades.
pub const AUTOSTART_DESKTOP_FILE: &str = "netrulerouter-tray.desktop";

/// `Name=` shown in a desktop environment's "Startup Applications" list. A
/// proper noun, so not localized. Localized `Name[ru]=` / `Comment` keys are a
/// follow-up when the Linux GUI packaging lands.
const DESKTOP_ENTRY_NAME: &str = "NetRuleRouter";

/// XDG autostart `AutostartRegistryPort` — reads/writes/deletes the single
/// `.desktop` entry that launches the tray at graphical login.
pub struct XdgAutostartRegistry {
    autostart_dir: PathBuf,
}

impl XdgAutostartRegistry {
    /// Production: resolve `$XDG_CONFIG_HOME/autostart`, falling back to
    /// `$HOME/.config/autostart` per the XDG Base Directory spec.
    pub fn new() -> Result<Self, AutostartError> {
        let config_home = match env_non_empty("XDG_CONFIG_HOME") {
            Some(xdg) => PathBuf::from(xdg),
            None => match env_non_empty("HOME") {
                Some(home) => PathBuf::from(home).join(".config"),
                None => {
                    return Err(AutostartError::RegistryAccess {
                        code: 0,
                        message: "cannot resolve XDG autostart dir: neither \
                                  XDG_CONFIG_HOME nor HOME is set"
                            .to_string(),
                    });
                }
            },
        };
        Ok(Self {
            autostart_dir: config_home.join("autostart"),
        })
    }

    /// Tests: point at an arbitrary autostart directory (a tempdir) instead of
    /// the user's real `~/.config/autostart/`.
    pub fn with_autostart_dir(dir: PathBuf) -> Self {
        Self { autostart_dir: dir }
    }

    fn desktop_path(&self) -> PathBuf {
        self.autostart_dir.join(AUTOSTART_DESKTOP_FILE)
    }
}

impl AutostartRegistryPort for XdgAutostartRegistry {
    fn read_value(&self) -> Result<Option<String>, AutostartError> {
        match std::fs::read_to_string(self.desktop_path()) {
            Ok(contents) => Ok(parse_exec_from_desktop(&contents)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(fs_error("read", e)),
        }
    }

    fn write_value(&self, value: &str) -> Result<(), AutostartError> {
        std::fs::create_dir_all(&self.autostart_dir).map_err(|e| fs_error("create dir", e))?;
        std::fs::write(self.desktop_path(), render_desktop_entry(value))
            .map_err(|e| fs_error("write", e))
    }

    fn delete_value(&self) -> Result<(), AutostartError> {
        match std::fs::remove_file(self.desktop_path()) {
            Ok(()) => Ok(()),
            // Absent entry is success — matches the trait's idempotent contract.
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(fs_error("delete", e)),
        }
    }
}

// ── Pure helpers ──────────────────────────────────────────────────────────────

/// Renders a minimal, spec-valid autostart `.desktop` file whose `Exec=`
/// carries `exec_value` verbatim (the helper already quoted the path).
fn render_desktop_entry(exec_value: &str) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={DESKTOP_ENTRY_NAME}\n\
         Exec={exec_value}\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n"
    )
}

/// Extracts the `Exec=` value verbatim from a `.desktop` file. Returns `None`
/// when no `Exec=` key is present. Comment lines (`#…`) are skipped.
fn parse_exec_from_desktop(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            return None;
        }
        trimmed.strip_prefix("Exec=").map(str::to_string)
    })
}

/// Resolves an env var, treating empty as unset (XDG spec convention).
fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Maps a filesystem error onto the neutral [`AutostartError`]. The variant is
/// `RegistryAccess` (Windows-shaped name in the shared api); `code` carries the
/// errno so operators can correlate, `message` names the operation.
fn fs_error(op: &str, e: std::io::Error) -> AutostartError {
    AutostartError::RegistryAccess {
        code: e.raw_os_error().unwrap_or(0) as u32,
        message: format!("autostart .desktop {op} failed: {e}"),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Absolute path that is `is_absolute()` on the host, so the neutral
    // `AutostartHelper` (which rejects relative paths) runs green here too.
    fn tray_exe() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\Program Files\NetRuleRouter\NetRuleRouterTray.exe")
        } else {
            PathBuf::from("/opt/netrulerouter/NetRuleRouterTray")
        }
    }

    /// Unique temp autostart dir with best-effort recursive cleanup on drop.
    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn temp_autostart_dir() -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "nrr-autostart-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        TempDir(p)
    }

    // ── Pure render / parse ────────────────────────────────────────────────────

    #[test]
    fn rendered_desktop_entry_is_spec_shaped() {
        let out = render_desktop_entry(r#""/opt/netrulerouter/NetRuleRouterTray""#);
        assert!(out.starts_with("[Desktop Entry]\n"));
        assert!(out.contains("Type=Application\n"));
        assert!(out.contains("Exec=\"/opt/netrulerouter/NetRuleRouterTray\"\n"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn render_then_parse_round_trips_exec_verbatim() {
        let value = r#""/opt/net rule/NetRuleRouterTray""#;
        let parsed = parse_exec_from_desktop(&render_desktop_entry(value));
        assert_eq!(parsed.as_deref(), Some(value));
    }

    #[test]
    fn parse_returns_none_without_exec_key() {
        assert_eq!(
            parse_exec_from_desktop("[Desktop Entry]\nType=Application\n"),
            None
        );
    }

    #[test]
    fn parse_skips_commented_exec() {
        let contents = "[Desktop Entry]\n#Exec=/ignored\nExec=/real/bin\n";
        assert_eq!(
            parse_exec_from_desktop(contents).as_deref(),
            Some("/real/bin")
        );
    }

    // ── Port + AutostartHelper end-to-end over the real filesystem ──────────────

    #[test]
    fn read_value_is_none_when_file_absent() {
        let dir = temp_autostart_dir();
        let reg = XdgAutostartRegistry::with_autostart_dir(dir.0.clone());
        assert_eq!(reg.read_value().expect("read"), None);
    }

    #[test]
    fn delete_is_idempotent_when_file_absent() {
        let dir = temp_autostart_dir();
        let reg = XdgAutostartRegistry::with_autostart_dir(dir.0.clone());
        reg.delete_value().expect("delete absent is ok");
    }

    #[test]
    fn helper_set_get_clear_cycle_over_xdg_file() {
        let dir = temp_autostart_dir();
        let reg = XdgAutostartRegistry::with_autostart_dir(dir.0.clone());
        let helper = AutostartHelper::new(reg);
        let exe = tray_exe();

        // Disabled on a clean dir.
        assert_eq!(
            helper.get_state(&exe).expect("state"),
            AutostartCurrentState::Disabled
        );

        // Enable → a real .desktop file appears and classifies as ours.
        helper.set_enabled(&exe).expect("set_enabled");
        assert!(dir.0.join(AUTOSTART_DESKTOP_FILE).exists());
        match helper.get_state(&exe).expect("state") {
            AutostartCurrentState::Enabled { matches_ours, .. } => assert!(matches_ours),
            other => panic!("expected Enabled, got {other:?}"),
        }

        // Clear → file gone, back to Disabled.
        helper.clear().expect("clear");
        assert!(!dir.0.join(AUTOSTART_DESKTOP_FILE).exists());
        assert_eq!(
            helper.get_state(&exe).expect("state"),
            AutostartCurrentState::Disabled
        );
    }

    #[test]
    fn external_override_detected_when_exec_points_elsewhere() {
        let dir = temp_autostart_dir();
        std::fs::create_dir_all(&dir.0).expect("mkdir");
        std::fs::write(
            dir.0.join(AUTOSTART_DESKTOP_FILE),
            render_desktop_entry("\"/other/vendor/thing\""),
        )
        .expect("seed foreign entry");
        let reg = XdgAutostartRegistry::with_autostart_dir(dir.0.clone());
        let helper = AutostartHelper::new(reg);
        match helper.get_state(Path::new("/opt/netrulerouter/NetRuleRouterTray")) {
            Ok(AutostartCurrentState::OverriddenExternally { value }) => {
                assert!(value.contains("thing"));
            }
            other => panic!("expected OverriddenExternally, got {other:?}"),
        }
    }
}
