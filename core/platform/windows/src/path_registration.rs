//! Windows mechanism for [`nrr_platform_api::path_registration`]: the per-user
//! environment block under `HKEY_CURRENT_USER\Environment`.
//!
//! ## Why the user hive and never the machine one
//!
//! Windows composes a process's `PATH` from the machine list
//! (`HKLM\…\Session Manager\Environment`) followed by the user list
//! (`HKCU\Environment`). Only the second is writable without elevation, and the
//! console it makes reachable is a per-user convenience — nothing about it needs
//! to exist for accounts that never asked for it. So this backend writes the
//! user list only; a [`PathScope::AllUsers`] request is refused rather than
//! quietly downgraded, because a user who asked for "everyone" and got "just me"
//! has been misled.
//!
//! ## Why the raw registry value and not the process `PATH`
//!
//! `std::env::var("PATH")` returns the *composed and expanded* list this process
//! inherited: machine entries mixed with user ones, and `%USERPROFILE%` already
//! resolved. Writing that back into the user hive would copy every machine entry
//! into the user's list and freeze today's expansion of every variable in it.
//! The value written back is therefore always derived from the raw user-hive
//! read, and its `REG_SZ` / `REG_EXPAND_SZ` type is preserved so unexpanded
//! entries keep working.
//!
//! ## Why the broadcast
//!
//! Writing the registry alone updates nothing that is already running: Explorer
//! caches the environment it hands to every program it launches. Broadcasting
//! `WM_SETTINGCHANGE` with `"Environment"` makes Explorer (and anything else
//! that listens) re-read the hive, so a shell opened *after* the change inherits
//! the new list without a sign-out. Shells already open keep their inherited
//! copy — no OS rewrites a running process's environment — which is what
//! [`PathRegistrationPlan::current_session_command`] is for.

use std::path::PathBuf;

use nrr_platform_api::path_registration::{
    decide_path_registration, PathDecision, PathListStyle, PathRegistrationError,
    PathRegistrationPlan, PathRegistrationPort, PathRegistrationReport, PathRegistrationRequest,
    PathRegistrationStep, PathScope,
};

/// Registry sub-key holding the per-user environment block. The
/// `HKEY_CURRENT_USER\` prefix is implicit — the production store opens that
/// hive.
pub const USER_ENVIRONMENT_SUBKEY: &str = "Environment";

/// The value name inside that key. Windows itself spells it `Path`; the lookup
/// is case-insensitive, but writing a second value that differs only in case
/// would create a duplicate the system ignores.
pub const PATH_VALUE_NAME: &str = "Path";

// ── Store seam ───────────────────────────────────────────────────────────────

/// A per-user `PATH` value as the registry holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserEnvironmentValue {
    /// The list exactly as stored — unexpanded, so `%USERPROFILE%\bin` stays
    /// written that way.
    pub text: String,
    /// Whether the value is `REG_EXPAND_SZ` (as opposed to plain `REG_SZ`).
    /// Preserved on write: demoting an expandable value to a literal one turns
    /// every `%VAR%` entry on the user's list into a directory that does not
    /// exist.
    pub expandable: bool,
}

/// Read and write the per-user environment block.
///
/// Split out from [`WindowsUserPathRegistration`] so the planning and applying
/// logic above it is exercised without a registry — the same split
/// `autostart.rs` uses for the `Run` key.
pub trait UserEnvironmentStore {
    /// Read the stored `PATH` value. `Ok(None)` means the value does not exist
    /// yet (a clean profile) — an ordinary state, not a failure.
    fn read_path(&self) -> Result<Option<UserEnvironmentValue>, PathRegistrationError>;

    /// Write the `PATH` value, creating it if absent.
    fn write_path(&self, value: &UserEnvironmentValue) -> Result<(), PathRegistrationError>;

    /// Announce that the environment changed, so programs launched afterwards
    /// inherit the new value. Best-effort by nature: failing to notify is not a
    /// failure to register.
    fn announce_change(&self) -> Result<(), PathRegistrationError>;
}

// ── The port implementation ──────────────────────────────────────────────────

/// Windows implementation of [`PathRegistrationPort`] over a per-user
/// environment store.
pub struct WindowsUserPathRegistration<S: UserEnvironmentStore> {
    store: S,
}

impl<S: UserEnvironmentStore> WindowsUserPathRegistration<S> {
    /// Wrap a store.
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// Reject the scopes this backend deliberately does not implement.
    fn check_scope(scope: PathScope) -> Result<(), PathRegistrationError> {
        match scope {
            PathScope::CurrentUser => Ok(()),
            PathScope::AllUsers => Err(PathRegistrationError::Unsupported {
                detail: "the machine-wide list is privileged; this backend writes the \
                         current user's environment only"
                    .to_string(),
            }),
        }
    }
}

impl<S: UserEnvironmentStore> PathRegistrationPort for WindowsUserPathRegistration<S> {
    fn style(&self) -> PathListStyle {
        PathListStyle::Windows
    }

    fn plan(
        &self,
        request: &PathRegistrationRequest,
    ) -> Result<PathRegistrationPlan, PathRegistrationError> {
        Self::check_scope(request.scope)?;
        let stored = self.store.read_path()?;
        let current = stored.as_ref().map(|v| v.text.as_str()).unwrap_or("");
        let decision = decide_path_registration(current, &request.directory, self.style())?;
        let entry = nrr_platform_api::path_registration::render_entry(
            &request.directory,
            PathListStyle::Windows,
        );
        // PowerShell form: it is the shell this product's own scripts use, and
        // the one a Windows user is most likely to have open.
        let current_session_command = format!("$env:PATH += \";{entry}\"");

        let steps = match &decision {
            PathDecision::AlreadyPresent => Vec::new(),
            PathDecision::Append { updated_list } => vec![
                PathRegistrationStep::SetUserEnvironmentVariable {
                    name: PATH_VALUE_NAME.to_string(),
                    value: updated_list.clone(),
                },
                PathRegistrationStep::AnnounceEnvironmentChange,
            ],
        };

        Ok(PathRegistrationPlan {
            directory: request.directory.clone(),
            scope: request.scope,
            decision,
            steps,
            current_session_command,
        })
    }

    fn apply(
        &self,
        plan: &PathRegistrationPlan,
    ) -> Result<PathRegistrationReport, PathRegistrationError> {
        Self::check_scope(plan.scope)?;
        // The stored type is read back here rather than carried in the plan: the
        // plan is a neutral value, and `REG_EXPAND_SZ` is a registry detail that
        // has no meaning in it.
        let expandable = self
            .store
            .read_path()?
            .map(|v| v.expandable)
            // A value we create ourselves is expandable, so a user who later
            // adds a `%VAR%` entry by hand gets the behaviour they expect.
            .unwrap_or(true);

        let mut changed = false;
        for step in &plan.steps {
            match step {
                PathRegistrationStep::SetUserEnvironmentVariable { name, value } => {
                    if !name.eq_ignore_ascii_case(PATH_VALUE_NAME) {
                        return Err(PathRegistrationError::Unsupported {
                            detail: format!(
                                "this backend owns the {PATH_VALUE_NAME:?} value only, not {name:?}"
                            ),
                        });
                    }
                    self.store.write_path(&UserEnvironmentValue {
                        text: value.clone(),
                        expandable,
                    })?;
                    changed = true;
                }
                PathRegistrationStep::AnnounceEnvironmentChange => {
                    // Best-effort: the registration itself already succeeded, and
                    // a missed broadcast only costs the user a new shell.
                    let _ = self.store.announce_change();
                }
                PathRegistrationStep::AppendShellProfileLine { .. } => {
                    return Err(PathRegistrationError::Unsupported {
                        detail: "Windows has no shell start-up file to append to".to_string(),
                    });
                }
            }
        }

        Ok(PathRegistrationReport {
            changed,
            files_written: Vec::new(),
            restart_shell_required: changed,
        })
    }
}

// ── Production store (Win32 registry) ────────────────────────────────────────

#[cfg(target_os = "windows")]
mod production {
    #![allow(unsafe_code)]

    use super::{
        PathRegistrationError, UserEnvironmentStore, UserEnvironmentValue, PATH_VALUE_NAME,
        USER_ENVIRONMENT_SUBKEY,
    };

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, LPARAM, WIN32_ERROR, WPARAM,
    };
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER,
        KEY_QUERY_VALUE, KEY_SET_VALUE, REG_EXPAND_SZ, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };

    /// How long the environment-change broadcast waits on a hung top-level
    /// window before giving up on it and moving to the next.
    const BROADCAST_TIMEOUT_MS: u32 = 5_000;

    /// Null-terminated UTF-16, the form every `…W` entry point wants.
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Map a Win32 status onto the port's error taxonomy, so callers can react
    /// to "you need rights for this" without matching on numbers.
    fn registry_error(status: WIN32_ERROR, what: &str) -> PathRegistrationError {
        if status == ERROR_ACCESS_DENIED {
            return PathRegistrationError::AccessDenied;
        }
        PathRegistrationError::Mechanism {
            detail: format!("{what} failed (Win32 error {})", status.0),
        }
    }

    /// The real `HKEY_CURRENT_USER\Environment` key.
    pub struct RegistryUserEnvironment;

    impl RegistryUserEnvironment {
        pub const fn new() -> Self {
            Self
        }

        fn open(&self, access: REG_SAM_FLAGS) -> Result<HKEY, PathRegistrationError> {
            let subkey = wide(USER_ENVIRONMENT_SUBKEY);
            let mut hkey = HKEY::default();
            // SAFETY: `subkey` is null-terminated UTF-16 that outlives the call,
            // `hkey` is a freshly-initialised out-parameter, and
            // `HKEY_CURRENT_USER` is a Win32 pseudo-handle.
            let status = unsafe {
                RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    PCWSTR(subkey.as_ptr()),
                    0,
                    access,
                    &mut hkey,
                )
            };
            if status == ERROR_SUCCESS {
                Ok(hkey)
            } else {
                Err(registry_error(
                    status,
                    &format!("RegOpenKeyExW(HKCU\\{USER_ENVIRONMENT_SUBKEY})"),
                ))
            }
        }

        fn close(hkey: HKEY) {
            // SAFETY: `hkey` came from `RegOpenKeyExW`. A close failure is not
            // actionable from here.
            unsafe {
                let _ = RegCloseKey(hkey);
            }
        }
    }

    impl Default for RegistryUserEnvironment {
        fn default() -> Self {
            Self::new()
        }
    }

    impl UserEnvironmentStore for RegistryUserEnvironment {
        fn read_path(&self) -> Result<Option<UserEnvironmentValue>, PathRegistrationError> {
            let hkey = match self.open(KEY_QUERY_VALUE) {
                Ok(h) => h,
                // A profile with no user environment block at all: nothing is
                // registered, which is a state, not a failure.
                Err(PathRegistrationError::Mechanism { .. }) => return Ok(None),
                Err(e) => return Err(e),
            };
            let name = wide(PATH_VALUE_NAME);
            let mut size: u32 = 0;
            let mut value_type = REG_VALUE_TYPE::default();

            // First call sizes the buffer. `RegQueryValueExW` (unlike
            // `RegGetValueW`) returns REG_EXPAND_SZ data UNEXPANDED, which is
            // exactly what must be written back.
            // SAFETY: every pointer refers to a local that outlives the call.
            let status = unsafe {
                RegQueryValueExW(
                    hkey,
                    PCWSTR(name.as_ptr()),
                    None,
                    Some(&mut value_type),
                    None,
                    Some(&mut size),
                )
            };
            if WIN32_ERROR(status.0 as u32) == ERROR_FILE_NOT_FOUND {
                Self::close(hkey);
                return Ok(None);
            }
            if status != ERROR_SUCCESS {
                Self::close(hkey);
                return Err(registry_error(status, "RegQueryValueExW (size probe)"));
            }

            let mut buf: Vec<u16> = vec![0u16; (size as usize) / 2 + 1];
            let mut read_size = (buf.len() * 2) as u32;
            // SAFETY: same pointer rules; `buf` is now sized for the value.
            let status = unsafe {
                RegQueryValueExW(
                    hkey,
                    PCWSTR(name.as_ptr()),
                    None,
                    Some(&mut value_type),
                    Some(buf.as_mut_ptr().cast()),
                    Some(&mut read_size),
                )
            };
            Self::close(hkey);
            if status != ERROR_SUCCESS {
                return Err(registry_error(status, "RegQueryValueExW (read)"));
            }

            let chars = (read_size as usize) / 2;
            let end = chars.min(buf.len()).saturating_sub(1); // drop the NUL
            Ok(Some(UserEnvironmentValue {
                text: String::from_utf16_lossy(&buf[..end]),
                expandable: value_type == REG_EXPAND_SZ,
            }))
        }

        fn write_path(&self, value: &UserEnvironmentValue) -> Result<(), PathRegistrationError> {
            let hkey = self.open(KEY_SET_VALUE)?;
            let name = wide(PATH_VALUE_NAME);
            let data = wide(&value.text);
            let byte_len = data.len() * 2;
            let kind = if value.expandable {
                REG_EXPAND_SZ
            } else {
                REG_SZ
            };
            // SAFETY: `data` is null-terminated UTF-16 that outlives the call,
            // and the byte length passed matches the slice constructed from it.
            let status = unsafe {
                RegSetValueExW(
                    hkey,
                    PCWSTR(name.as_ptr()),
                    0,
                    kind,
                    Some(std::slice::from_raw_parts(
                        data.as_ptr().cast::<u8>(),
                        byte_len,
                    )),
                )
            };
            Self::close(hkey);
            if status == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(registry_error(status, "RegSetValueExW"))
            }
        }

        fn announce_change(&self) -> Result<(), PathRegistrationError> {
            let target = wide("Environment");
            // SAFETY: `target` is null-terminated UTF-16 that outlives the call.
            // `SMTO_ABORTIFHUNG` plus a finite timeout bounds the broadcast, so
            // one unresponsive top-level window cannot block this thread.
            unsafe {
                SendMessageTimeoutW(
                    HWND_BROADCAST,
                    WM_SETTINGCHANGE,
                    WPARAM(0),
                    LPARAM(target.as_ptr() as isize),
                    SMTO_ABORTIFHUNG,
                    BROADCAST_TIMEOUT_MS,
                    None,
                );
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
pub use production::RegistryUserEnvironment;

#[cfg(target_os = "windows")]
impl WindowsUserPathRegistration<RegistryUserEnvironment> {
    /// The port over the real per-user environment block.
    pub const fn production() -> Self {
        Self::new(RegistryUserEnvironment::new())
    }
}

/// The console directory as it would be registered: the directory holding the
/// running executable. Callers pass the result to
/// [`PathRegistrationRequest::for_current_user`].
pub fn current_executable_directory() -> Result<PathBuf, PathRegistrationError> {
    let exe = std::env::current_exe().map_err(|e| PathRegistrationError::Mechanism {
        detail: format!("cannot locate the running executable: {e}"),
    })?;
    exe.parent()
        .map(PathBuf::from)
        .ok_or_else(|| PathRegistrationError::Mechanism {
            detail: "the running executable has no parent directory".to_string(),
        })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;

    /// In-memory stand-in for the registry key.
    struct FakeStore {
        value: Mutex<Option<UserEnvironmentValue>>,
        announcements: Mutex<u32>,
        write_error: Mutex<Option<PathRegistrationError>>,
    }

    #[allow(clippy::unwrap_used, clippy::expect_used)]
    impl FakeStore {
        fn empty() -> Self {
            Self {
                value: Mutex::new(None),
                announcements: Mutex::new(0),
                write_error: Mutex::new(None),
            }
        }

        fn with(text: &str, expandable: bool) -> Self {
            let s = Self::empty();
            *s.value.lock().expect("fake mutex") = Some(UserEnvironmentValue {
                text: text.to_string(),
                expandable,
            });
            s
        }

        fn stored(&self) -> Option<UserEnvironmentValue> {
            self.value.lock().expect("fake mutex").clone()
        }

        fn announcements(&self) -> u32 {
            *self.announcements.lock().expect("fake mutex")
        }

        fn fail_writes_with(&self, err: PathRegistrationError) {
            *self.write_error.lock().expect("fake mutex") = Some(err);
        }
    }

    #[allow(clippy::unwrap_used, clippy::expect_used)]
    impl UserEnvironmentStore for FakeStore {
        fn read_path(&self) -> Result<Option<UserEnvironmentValue>, PathRegistrationError> {
            Ok(self.stored())
        }

        fn write_path(&self, value: &UserEnvironmentValue) -> Result<(), PathRegistrationError> {
            if let Some(err) = self.write_error.lock().expect("fake mutex").take() {
                return Err(err);
            }
            *self.value.lock().expect("fake mutex") = Some(value.clone());
            Ok(())
        }

        fn announce_change(&self) -> Result<(), PathRegistrationError> {
            *self.announcements.lock().expect("fake mutex") += 1;
            Ok(())
        }
    }

    fn console_dir() -> PathBuf {
        PathBuf::from(r"C:\Program Files\NetRuleRouter")
    }

    fn request() -> PathRegistrationRequest {
        PathRegistrationRequest::for_current_user(console_dir())
    }

    #[test]
    fn registering_appends_to_the_user_list_and_announces() {
        let port = WindowsUserPathRegistration::new(FakeStore::with(r"C:\Windows", false));
        let report = port.register(&request()).expect("register");

        assert!(report.changed);
        assert!(report.restart_shell_required);
        assert!(report.files_written.is_empty());

        let stored = port.store.stored().expect("value written");
        assert_eq!(stored.text, r"C:\Windows;C:\Program Files\NetRuleRouter");
        assert_eq!(port.store.announcements(), 1);
    }

    #[test]
    fn a_clean_profile_gets_an_expandable_value() {
        // No value yet: the one we create is REG_EXPAND_SZ, so a `%VAR%` entry
        // the user adds later behaves the way they expect.
        let port = WindowsUserPathRegistration::new(FakeStore::empty());
        port.register(&request()).expect("register");
        let stored = port.store.stored().expect("value written");
        assert!(stored.expandable);
        assert_eq!(stored.text, r"C:\Program Files\NetRuleRouter");
    }

    #[test]
    fn an_expandable_value_stays_expandable() {
        let port = WindowsUserPathRegistration::new(FakeStore::with(r"%USERPROFILE%\bin", true));
        port.register(&request()).expect("register");
        let stored = port.store.stored().expect("value written");
        assert!(stored.expandable, "REG_EXPAND_SZ must survive the write");
        // The unexpanded entry is preserved verbatim.
        assert!(stored.text.starts_with(r"%USERPROFILE%\bin"));
    }

    #[test]
    fn a_literal_value_stays_literal() {
        let port = WindowsUserPathRegistration::new(FakeStore::with(r"C:\Windows", false));
        port.register(&request()).expect("register");
        assert!(!port.store.stored().expect("value written").expandable);
    }

    #[test]
    fn registering_twice_writes_once() {
        let port = WindowsUserPathRegistration::new(FakeStore::with(r"C:\Windows", false));
        port.register(&request()).expect("first");
        let after_first = port.store.stored().expect("value written");

        let report = port.register(&request()).expect("second");
        assert!(!report.changed);
        assert_eq!(port.store.stored(), Some(after_first));
        // No second broadcast either — nothing changed to announce.
        assert_eq!(port.store.announcements(), 1);
    }

    #[test]
    fn an_entry_differing_only_in_case_counts_as_present() {
        let port = WindowsUserPathRegistration::new(FakeStore::with(
            r"C:\Windows;c:\program files\netrulerouter\",
            false,
        ));
        assert!(port.is_registered(&request()).expect("probe"));
        let report = port.register(&request()).expect("register");
        assert!(!report.changed);
    }

    #[test]
    fn planning_touches_nothing() {
        let port = WindowsUserPathRegistration::new(FakeStore::with(r"C:\Windows", false));
        let plan = port.plan(&request()).expect("plan");
        assert!(plan.changes_anything());
        assert_eq!(
            port.store.stored().map(|v| v.text),
            Some(r"C:\Windows".to_string())
        );
        assert_eq!(port.store.announcements(), 0);
    }

    #[test]
    fn the_plan_carries_a_command_for_shells_that_are_already_open() {
        let port = WindowsUserPathRegistration::new(FakeStore::empty());
        let plan = port.plan(&request()).expect("plan");
        assert_eq!(
            plan.current_session_command,
            r#"$env:PATH += ";C:\Program Files\NetRuleRouter""#
        );
    }

    #[test]
    fn the_machine_wide_scope_is_refused() {
        let port = WindowsUserPathRegistration::new(FakeStore::empty());
        let req = PathRegistrationRequest {
            directory: console_dir(),
            scope: PathScope::AllUsers,
        };
        assert!(matches!(
            port.plan(&req),
            Err(PathRegistrationError::Unsupported { .. })
        ));
        assert!(port.store.stored().is_none());
    }

    #[test]
    fn a_shell_profile_step_is_refused_rather_than_skipped() {
        let port = WindowsUserPathRegistration::new(FakeStore::empty());
        let plan = PathRegistrationPlan {
            directory: console_dir(),
            scope: PathScope::CurrentUser,
            decision: PathDecision::Append {
                updated_list: r"C:\Program Files\NetRuleRouter".to_string(),
            },
            steps: vec![PathRegistrationStep::AppendShellProfileLine {
                path: PathBuf::from("/home/u/.bashrc"),
                line: "export PATH=…".to_string(),
            }],
            current_session_command: String::new(),
        };
        assert!(matches!(
            port.apply(&plan),
            Err(PathRegistrationError::Unsupported { .. })
        ));
    }

    #[test]
    fn a_foreign_variable_name_is_refused() {
        // This backend owns PATH. Anything else in a plan is a wiring mistake.
        let port = WindowsUserPathRegistration::new(FakeStore::empty());
        let plan = PathRegistrationPlan {
            directory: console_dir(),
            scope: PathScope::CurrentUser,
            decision: PathDecision::Append {
                updated_list: "x".to_string(),
            },
            steps: vec![PathRegistrationStep::SetUserEnvironmentVariable {
                name: "PATHEXT".to_string(),
                value: ".COM;.EXE".to_string(),
            }],
            current_session_command: String::new(),
        };
        assert!(matches!(
            port.apply(&plan),
            Err(PathRegistrationError::Unsupported { .. })
        ));
        assert!(port.store.stored().is_none());
    }

    #[test]
    fn a_denied_write_surfaces_as_access_denied() {
        let store = FakeStore::with(r"C:\Windows", false);
        store.fail_writes_with(PathRegistrationError::AccessDenied);
        let port = WindowsUserPathRegistration::new(store);
        assert!(matches!(
            port.register(&request()),
            Err(PathRegistrationError::AccessDenied)
        ));
    }

    #[test]
    fn a_relative_directory_never_reaches_the_store() {
        let port = WindowsUserPathRegistration::new(FakeStore::empty());
        let req = PathRegistrationRequest::for_current_user(Path::new(r"tools\bin"));
        assert!(matches!(
            port.plan(&req),
            Err(PathRegistrationError::InvalidDirectory { .. })
        ));
    }

    /// Read-only exercise of the real registry backend: it opens the running
    /// user's `Environment` key and reads the stored value. Ignored by default
    /// because the result depends on the machine, but it is the only thing that
    /// proves the Win32 read path works at all — every other test here runs
    /// against a fake store. Run with
    /// `cargo test -p nrr-platform-windows -- --ignored reads_the_real_user_hive`.
    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "reads this machine's registry"]
    fn reads_the_real_user_hive() {
        let store = RegistryUserEnvironment::new();
        let value = store.read_path().expect("read HKCU Environment");
        // Absent is legitimate on a profile that never customised PATH; the
        // point is that the call completed without a mechanism error.
        if let Some(v) = value {
            assert!(!v.text.is_empty(), "a present value should carry a list");
        }
    }

    #[test]
    fn the_style_is_the_windows_convention() {
        let port = WindowsUserPathRegistration::new(FakeStore::empty());
        assert_eq!(port.style(), PathListStyle::Windows);
        assert!(!port.style().case_sensitive());
        assert_eq!(port.style().separator(), ';');
    }
}
