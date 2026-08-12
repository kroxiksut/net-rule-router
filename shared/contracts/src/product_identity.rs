//! Product identity — the single source of truth for how the product spells
//! its own name, and the rule by which every derived name is produced.
//!
//! There are exactly **three** spellings of one identifier:
//!
//! | Spelling | Value | Used for |
//! |---|---|---|
//! | canonical | `NetRuleRouter` | Windows service name, display names, Windows/macOS directories |
//! | unix | `netrulerouter` | systemd unit, Unix directories and package names |
//! | reverse-DNS | *not chosen yet* | launchd label, macOS bundle id, Windows AppUserModelID |
//!
//! Everything else — the SCM service name, the systemd unit file name, the
//! executable file names — is **derived** here and nowhere else. Literal
//! unification is deliberately NOT applied: `NetRuleRouter.service` would break
//! Unix expectations and tab-completion, which is why the unix spelling exists
//! as its own row rather than as a lower-cased accident.
//!
//! Executable naming rule: **the crate name states the platform, the executable
//! name states the role**, and the role name is the same on every OS. The `d`
//! suffix on the Unix daemon is the traditional spelling; the alias without it
//! keeps cross-platform scripts on a single name.
//!
//! The reverse-DNS spelling is intentionally absent: a macOS bundle id cannot
//! be changed after the first release, so it is chosen before the first macOS
//! build and added here — not guessed now.

// ── The three spellings ──────────────────────────────────────────────────────

/// Canonical product name. Windows SCM service name, display names, and the
/// `%ProgramData%` / `Application Support` directory leaf.
pub const PRODUCT_NAME: &str = "NetRuleRouter";

/// Unix spelling. systemd unit stem, `/etc` + `/var/lib` directory leaf,
/// package names, and the GUI executable name on Unix.
pub const PRODUCT_NAME_UNIX: &str = "netrulerouter";

/// One-line product descriptor appended to display names. Not a name in its
/// own right — never used to build a path or an identifier.
pub const PRODUCT_TAGLINE: &str = "Network Policy Manager";

// ── Derived service identity ─────────────────────────────────────────────────

/// Internal Windows service name registered with SCM. Stable across versions:
/// changing it breaks every operator script and `sc.exe` invocation.
pub const WINDOWS_SERVICE_NAME: &str = PRODUCT_NAME;

/// Human-readable one-line name of the background service, on every OS: the
/// Services MMC display name on Windows and the systemd unit `Description=` on
/// Linux. One line, one declaration — a unit whose description drifts from the
/// Windows display name is two products as far as an operator is concerned.
pub const SERVICE_DISPLAY_NAME: &str = "NetRuleRouter — Network Policy Manager";

/// Display name shown in the Services MMC console. Spelled separately from
/// [`SERVICE_DISPLAY_NAME`] only because callers name the Windows concept.
pub const WINDOWS_SERVICE_DISPLAY_NAME: &str = SERVICE_DISPLAY_NAME;

/// Description shown in the Services MMC console. Plain English: the service
/// is an operator-facing surface and is not localised.
pub const WINDOWS_SERVICE_DESCRIPTION: &str =
    "Applies and enforces NetRuleRouter routing policy across configured \
     Windows network interfaces. Maintains the rule cache, decision \
     audit trail, and fail-closed enforcement when configured. Required \
     for the GUI/tray to apply policy changes.";

/// Event Log source registered during install.
pub const WINDOWS_EVENT_SOURCE_NAME: &str = PRODUCT_NAME;

/// systemd unit file name. The stem is the unix spelling; the suffix is
/// systemd's, not ours.
pub const SYSTEMD_UNIT_NAME: &str = "netrulerouter.service";

// ── Executable names by role ─────────────────────────────────────────────────

/// A shipped executable, named by the role it performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryRole {
    /// Background service / daemon that applies and enforces policy.
    Service,
    /// Administrative console.
    Console,
    /// End-user graphical shell.
    Gui,
    /// Tray shell.
    Tray,
}

impl BinaryRole {
    /// Every role, in the order they are documented.
    pub const ALL: &'static [BinaryRole] = &[
        BinaryRole::Service,
        BinaryRole::Console,
        BinaryRole::Gui,
        BinaryRole::Tray,
    ];

    /// Windows executable file name, including the `.exe` extension.
    ///
    /// `const` so callers can derive their own `const NAME: &str` from it
    /// instead of retyping the literal.
    pub const fn windows_file_name(self) -> &'static str {
        match self {
            Self::Service => "nrr-service.exe",
            Self::Console => "nrr-cli.exe",
            Self::Gui => "NetRuleRouter.exe",
            Self::Tray => "NetRuleRouterTray.exe",
        }
    }

    /// Unix executable file name.
    pub const fn unix_file_name(self) -> &'static str {
        match self {
            Self::Service => "nrr-serviced",
            Self::Console => "nrr-cli",
            Self::Gui => "netrulerouter",
            Self::Tray => "netrulerouter-tray",
        }
    }

    /// Additional Unix name installed as a symlink so cross-platform scripts
    /// can spell the daemon the same way on every OS. Only the daemon has one:
    /// it is the only role whose Unix name differs from its Windows name.
    pub const fn unix_alias(self) -> Option<&'static str> {
        match self {
            Self::Service => Some("nrr-service"),
            _ => None,
        }
    }

    /// File name for the host the code is compiled for. Callers that need the
    /// name of a binary on *another* OS (installer generators, documentation
    /// tables) use the explicit per-OS accessors instead.
    pub const fn host_file_name(self) -> &'static str {
        if cfg!(windows) {
            self.windows_file_name()
        } else {
            self.unix_file_name()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_spelling_is_the_canonical_name_lowercased() {
        assert_eq!(PRODUCT_NAME_UNIX, PRODUCT_NAME.to_ascii_lowercase());
    }

    #[test]
    fn systemd_unit_name_derives_from_the_unix_spelling() {
        assert_eq!(SYSTEMD_UNIT_NAME, format!("{PRODUCT_NAME_UNIX}.service"));
    }

    #[test]
    fn service_display_name_is_the_canonical_name_plus_the_tagline() {
        assert_eq!(
            WINDOWS_SERVICE_DISPLAY_NAME,
            format!("{PRODUCT_NAME} — {PRODUCT_TAGLINE}")
        );
    }

    #[test]
    fn gui_executable_carries_the_product_name_on_both_families() {
        assert_eq!(
            BinaryRole::Gui.windows_file_name(),
            format!("{PRODUCT_NAME}.exe")
        );
        assert_eq!(BinaryRole::Gui.unix_file_name(), PRODUCT_NAME_UNIX);
        assert_eq!(
            BinaryRole::Tray.unix_file_name(),
            format!("{PRODUCT_NAME_UNIX}-tray")
        );
    }

    #[test]
    fn only_the_daemon_has_an_alias_and_it_matches_its_windows_stem() {
        for role in BinaryRole::ALL {
            match role.unix_alias() {
                Some(alias) => {
                    assert_eq!(*role, BinaryRole::Service);
                    let windows_stem = role
                        .windows_file_name()
                        .strip_suffix(".exe")
                        .expect("windows names carry the .exe extension");
                    assert_eq!(
                        alias, windows_stem,
                        "the alias exists so scripts can name one binary"
                    );
                    assert_eq!(
                        role.unix_file_name(),
                        format!("{alias}d"),
                        "the daemon spelling is the alias plus the traditional d suffix"
                    );
                }
                None => assert_ne!(*role, BinaryRole::Service),
            }
        }
    }

    #[test]
    fn every_role_has_distinct_names_on_both_families() {
        let windows: Vec<&str> = BinaryRole::ALL
            .iter()
            .map(|r| r.windows_file_name())
            .collect();
        let unix: Vec<&str> = BinaryRole::ALL.iter().map(|r| r.unix_file_name()).collect();
        for names in [&windows, &unix] {
            let mut sorted = names.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                sorted.len(),
                names.len(),
                "role names must be unique: {names:?}"
            );
        }
    }

    #[test]
    fn unix_names_never_carry_uppercase_or_an_extension() {
        for role in BinaryRole::ALL {
            let name = role.unix_file_name();
            assert_eq!(name, name.to_ascii_lowercase(), "{name} must be lower-case");
            assert!(!name.contains('.'), "{name} must not carry an extension");
        }
    }

    #[test]
    fn windows_names_all_carry_the_exe_extension() {
        for role in BinaryRole::ALL {
            assert!(
                role.windows_file_name().ends_with(".exe"),
                "{} must carry the .exe extension",
                role.windows_file_name()
            );
        }
    }
}
