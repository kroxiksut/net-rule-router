//! Unix mechanism for [`nrr_platform_api::path_registration`]: a line in the
//! user's shell start-up file.
//!
//! ## Why this looks nothing like the Windows backend
//!
//! Unix has no per-user environment store. `PATH` is inherited from whatever
//! started the process, and the only durable way for a user to change their own
//! is to have their shell set it at start-up. So the mechanism here is not
//! "write a value" but "add a line to a file the shell reads" — and *which*
//! file, and in *which* syntax, depends on the shell.
//!
//! ## Render first, write only when asked
//!
//! [`UnixPathRegistration::plan`] renders the exact line and names the exact
//! file, and touches nothing. [`UnixPathRegistration::apply`] is the only call
//! that writes. This is the same split
//! [`crate::systemd::plan_install`](crate::systemd) uses for the service unit,
//! and it exists for a stronger reason here: a shell start-up file is the user's
//! own document, often under version control, so a tool that edits it must be
//! able to show what it will add before it adds anything. A UI that never calls
//! `apply` still has everything it needs to tell the user what to paste.
//!
//! ## Appending, never prepending
//!
//! The rendered line puts our directory at the END of `PATH`, so nothing already
//! installed is shadowed by it.
//!
//! ## macOS
//!
//! The mechanism is POSIX-shell-generic, not Linux-specific — the file names and
//! the syntax are identical on macOS. The module is named for what it implements
//! rather than the crate it currently sits in, so a future `nrr-platform-macos`
//! reuses it as-is instead of growing a copy that drifts.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use nrr_platform_api::path_registration::{
    decide_path_registration, render_entry, PathListStyle, PathRegistrationError,
    PathRegistrationPlan, PathRegistrationPort, PathRegistrationReport, PathRegistrationRequest,
    PathRegistrationStep, PathScope,
};

/// Comment written above the line we add, so a human reading their start-up
/// file months later knows what put it there and what to delete to undo it.
pub const PROFILE_MARKER: &str = "# NetRuleRouter: administrative console on PATH";

// ── Shell flavours ───────────────────────────────────────────────────────────

/// The syntax family a shell start-up file is written in.
///
/// Only two matter for setting `PATH`: everything descended from the Bourne
/// shell shares one syntax, and fish deliberately does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellFlavour {
    /// `sh`, `bash`, `zsh`, `ksh`, `dash` — `export PATH="$PATH:…"`.
    Posix,
    /// fish — no `export`, and a dedicated builtin for `PATH`.
    Fish,
}

/// Classify a shell from the `$SHELL` path (or its absence).
///
/// Unknown and absent shells are treated as POSIX: that syntax is understood by
/// every Bourne-family shell, and `~/.profile` (the file chosen for it) is read
/// by login shells generally, so the fallback degrades to "works" rather than
/// "works only if you happen to run bash".
pub fn shell_flavour_for(shell_path: Option<&str>) -> ShellFlavour {
    let name = shell_path
        .and_then(|p| p.rsplit('/').next())
        .unwrap_or_default();
    if name == "fish" {
        ShellFlavour::Fish
    } else {
        ShellFlavour::Posix
    }
}

/// The start-up file to add the line to, for a given `$SHELL` and home
/// directory.
///
/// - **fish** — a drop-in under `conf.d`, which fish sources automatically. Its
///   own file means "undo" is deleting one file, not editing a shared one.
/// - **zsh** — `~/.zshrc`.
/// - **bash** — `~/.bashrc`, the file an interactive bash session reads. (On
///   many distributions `~/.bashrc` is also sourced from `~/.bash_profile`, so
///   login shells pick it up too.)
/// - **anything else, including no `$SHELL`** — `~/.profile`, the traditional
///   Bourne-family login file.
pub fn profile_file_for(shell_path: Option<&str>, home: &Path) -> PathBuf {
    let name = shell_path
        .and_then(|p| p.rsplit('/').next())
        .unwrap_or_default();
    match name {
        "fish" => home.join(".config/fish/conf.d/netrulerouter.fish"),
        "zsh" => home.join(".zshrc"),
        "bash" => home.join(".bashrc"),
        _ => home.join(".profile"),
    }
}

/// Characters that would change the MEANING of the rendered line rather than
/// just its text — quotes, expansion and escape characters, and newlines.
///
/// A directory containing one of these is refused instead of being escaped. The
/// escaping rules differ per shell and per quoting context, and a `PATH` entry
/// that needs them is pathological; refusing keeps a mis-escaped line from ever
/// reaching a file that every future shell of this user will execute.
fn unsafe_for_shell_line(entry: &str) -> Option<char> {
    entry
        .chars()
        .find(|c| matches!(c, '"' | '\'' | '$' | '`' | '\\' | '\n' | '\r'))
}

/// Render the block to append: the marker comment plus the line that extends
/// `PATH`. Ends with a newline so the next append starts on its own line.
pub fn render_profile_block(
    directory: &Path,
    flavour: ShellFlavour,
) -> Result<String, PathRegistrationError> {
    let entry = render_entry(directory, PathListStyle::Unix);
    if let Some(c) = unsafe_for_shell_line(&entry) {
        return Err(PathRegistrationError::InvalidDirectory {
            detail: format!("the directory contains {c:?}, which cannot appear in a shell line"),
        });
    }
    Ok(match flavour {
        ShellFlavour::Posix => format!("{PROFILE_MARKER}\nexport PATH=\"$PATH:{entry}\"\n"),
        // `--append` keeps our directory behind everything already installed;
        // fish's default is to prepend.
        ShellFlavour::Fish => format!("{PROFILE_MARKER}\nfish_add_path --append '{entry}'\n"),
    })
}

/// Render the one-liner for a shell that is already open.
pub fn render_current_session_command(
    directory: &Path,
    flavour: ShellFlavour,
) -> Result<String, PathRegistrationError> {
    let entry = render_entry(directory, PathListStyle::Unix);
    if let Some(c) = unsafe_for_shell_line(&entry) {
        return Err(PathRegistrationError::InvalidDirectory {
            detail: format!("the directory contains {c:?}, which cannot appear in a shell line"),
        });
    }
    Ok(match flavour {
        ShellFlavour::Posix => format!("export PATH=\"$PATH:{entry}\""),
        ShellFlavour::Fish => format!("fish_add_path --append '{entry}'"),
    })
}

/// Whether an existing start-up file already puts this directory on `PATH`.
///
/// Comment lines are ignored, and a match must stand on its own: `/opt/nrr` is
/// not considered declared by a line mentioning `/opt/nrr-old`. Getting this
/// wrong in the permissive direction appends a duplicate line on every click;
/// getting it wrong in the strict direction silently does nothing.
pub fn profile_declares_directory(contents: &str, directory: &Path) -> bool {
    let entry = render_entry(directory, PathListStyle::Unix);
    if entry.is_empty() {
        return false;
    }
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .any(|line| line_mentions_entry(line, &entry))
}

/// Whether `line` references `entry` as a whole path rather than as the prefix
/// of a longer one.
fn line_mentions_entry(line: &str, entry: &str) -> bool {
    let bounds_ok = |c: Option<char>| match c {
        None => true,
        Some(c) => !(c.is_alphanumeric() || matches!(c, '/' | '.' | '-' | '_' | '~')),
    };
    let mut from = 0;
    while let Some(offset) = line[from..].find(entry) {
        let start = from + offset;
        let end = start + entry.len();
        let before = line[..start].chars().next_back();
        let after = line[end..].chars().next();
        if bounds_ok(before) && bounds_ok(after) {
            return true;
        }
        // Advance past this occurrence; `entry` is non-empty so this terminates.
        from = start + entry.len();
    }
    false
}

// ── The port implementation ──────────────────────────────────────────────────

/// Unix implementation of [`PathRegistrationPort`].
///
/// The environment it reads (`$HOME`, `$SHELL`, `$PATH`) is held as data rather
/// than read at each call, so the whole port — planning, rendering, and applying
/// — is exercised on any host with no environment mutation and no root.
pub struct UnixPathRegistration {
    home: PathBuf,
    shell: Option<String>,
    current_path: String,
}

impl UnixPathRegistration {
    /// Build from explicit values.
    pub fn new(home: impl Into<PathBuf>, shell: Option<String>, current_path: String) -> Self {
        Self {
            home: home.into(),
            shell,
            current_path,
        }
    }

    /// Build from the calling process's environment.
    ///
    /// `$HOME` is the only one that must be present: without it there is no
    /// start-up file to name. A missing `$PATH` is treated as an empty list, and
    /// a missing `$SHELL` selects the POSIX fallback.
    pub fn from_environment() -> Result<Self, PathRegistrationError> {
        let home = std::env::var("HOME").map_err(|_| PathRegistrationError::Mechanism {
            detail: "HOME is not set, so the shell start-up file cannot be located".to_string(),
        })?;
        Ok(Self::new(
            home,
            std::env::var("SHELL").ok(),
            std::env::var("PATH").unwrap_or_default(),
        ))
    }

    /// The syntax family of the user's shell.
    pub fn flavour(&self) -> ShellFlavour {
        shell_flavour_for(self.shell.as_deref())
    }

    /// The start-up file this port would write to.
    pub fn profile_file(&self) -> PathBuf {
        profile_file_for(self.shell.as_deref(), &self.home)
    }

    /// Reject the scopes this backend deliberately does not implement.
    fn check_scope(scope: PathScope) -> Result<(), PathRegistrationError> {
        match scope {
            PathScope::CurrentUser => Ok(()),
            PathScope::AllUsers => Err(PathRegistrationError::Unsupported {
                detail: "a machine-wide entry means a root-owned file under /etc; this backend \
                         writes the current user's start-up file only"
                    .to_string(),
            }),
        }
    }
}

impl PathRegistrationPort for UnixPathRegistration {
    fn style(&self) -> PathListStyle {
        PathListStyle::Unix
    }

    fn plan(
        &self,
        request: &PathRegistrationRequest,
    ) -> Result<PathRegistrationPlan, PathRegistrationError> {
        Self::check_scope(request.scope)?;
        let flavour = self.flavour();
        let current_session_command = render_current_session_command(&request.directory, flavour)?;
        let decision =
            decide_path_registration(&self.current_path, &request.directory, self.style())?;
        let profile = self.profile_file();

        // Already on this process's PATH: nothing to add, whatever the file says.
        if !decision.changes_anything() {
            return Ok(PathRegistrationPlan::already_present(
                request.directory.clone(),
                request.scope,
                current_session_command,
            ));
        }

        // Not on PATH, but the file already declares it — the user has simply
        // not started a new shell since. Adding a second line would not help and
        // would accumulate on every attempt.
        let existing = fs::read_to_string(&profile).unwrap_or_default();
        if profile_declares_directory(&existing, &request.directory) {
            return Ok(PathRegistrationPlan::already_present(
                request.directory.clone(),
                request.scope,
                current_session_command,
            ));
        }

        let line = render_profile_block(&request.directory, flavour)?;
        Ok(PathRegistrationPlan {
            directory: request.directory.clone(),
            scope: request.scope,
            decision,
            steps: vec![PathRegistrationStep::AppendShellProfileLine {
                path: profile,
                line,
            }],
            current_session_command,
        })
    }

    fn apply(
        &self,
        plan: &PathRegistrationPlan,
    ) -> Result<PathRegistrationReport, PathRegistrationError> {
        Self::check_scope(plan.scope)?;
        let mut files_written = Vec::new();

        for step in &plan.steps {
            match step {
                PathRegistrationStep::AppendShellProfileLine { path, line } => {
                    append_line(path, line)?;
                    files_written.push(path.clone());
                }
                PathRegistrationStep::SetUserEnvironmentVariable { .. }
                | PathRegistrationStep::AnnounceEnvironmentChange => {
                    return Err(PathRegistrationError::Unsupported {
                        detail: "Unix has no per-user environment store to write or announce"
                            .to_string(),
                    });
                }
            }
        }

        let changed = !files_written.is_empty();
        Ok(PathRegistrationReport {
            changed,
            files_written,
            restart_shell_required: changed,
        })
    }
}

/// Append `line` to `path`, creating the file (and any missing parent
/// directories) first.
///
/// A file that does not end in a newline gets one before the append, so the
/// added block never lands on the tail of an unrelated command.
fn append_line(path: &Path, line: &str) -> Result<(), PathRegistrationError> {
    let mechanism = |what: &str, e: std::io::Error| PathRegistrationError::Mechanism {
        detail: format!("{what} {}: {e}", path.display()),
    };

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| mechanism("cannot create", e))?;
        }
    }

    let existing = fs::read_to_string(path).unwrap_or_default();
    let needs_leading_newline = !existing.is_empty() && !existing.ends_with('\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| mechanism("cannot open", e))?;
    if needs_leading_newline {
        file.write_all(b"\n")
            .map_err(|e| mechanism("cannot write to", e))?;
    }
    file.write_all(line.as_bytes())
        .map_err(|e| mechanism("cannot write to", e))?;
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::path_registration::PathDecision;
    use std::sync::atomic::{AtomicU32, Ordering};

    const HOME: &str = "/home/tester";
    const CONSOLE_DIR: &str = "/opt/netrulerouter/bin";

    fn console_dir() -> PathBuf {
        PathBuf::from(CONSOLE_DIR)
    }

    fn request() -> PathRegistrationRequest {
        PathRegistrationRequest::for_current_user(console_dir())
    }

    fn port(shell: Option<&str>, current_path: &str) -> UnixPathRegistration {
        UnixPathRegistration::new(HOME, shell.map(str::to_string), current_path.to_string())
    }

    /// A scratch directory that cleans up after itself, so the apply tests run
    /// on any host without a temp-file dependency.
    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[allow(clippy::expect_used)]
    fn scratch() -> Scratch {
        static N: AtomicU32 = AtomicU32::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "nrr-path-registration-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("create scratch dir");
        Scratch(p)
    }

    // ── Shell classification ─────────────────────────────────────────────────

    #[test]
    fn known_shells_pick_their_own_start_up_file() {
        let home = Path::new(HOME);
        assert_eq!(
            profile_file_for(Some("/bin/bash"), home),
            home.join(".bashrc")
        );
        assert_eq!(
            profile_file_for(Some("/usr/bin/zsh"), home),
            home.join(".zshrc")
        );
        assert_eq!(
            profile_file_for(Some("/usr/local/bin/fish"), home),
            home.join(".config/fish/conf.d/netrulerouter.fish")
        );
    }

    #[test]
    fn an_unknown_or_absent_shell_falls_back_to_profile() {
        let home = Path::new(HOME);
        assert_eq!(
            profile_file_for(Some("/bin/ksh"), home),
            home.join(".profile")
        );
        assert_eq!(profile_file_for(None, home), home.join(".profile"));
        assert_eq!(shell_flavour_for(Some("/bin/ksh")), ShellFlavour::Posix);
        assert_eq!(shell_flavour_for(None), ShellFlavour::Posix);
        assert_eq!(shell_flavour_for(Some("/usr/bin/fish")), ShellFlavour::Fish);
    }

    // ── Rendering ────────────────────────────────────────────────────────────

    #[test]
    fn the_posix_line_appends_to_the_existing_path() {
        let block = render_profile_block(&console_dir(), ShellFlavour::Posix).expect("render");
        assert!(block.contains(PROFILE_MARKER), "{block}");
        assert!(
            block.contains(&format!("export PATH=\"$PATH:{CONSOLE_DIR}\"")),
            "{block}"
        );
        assert!(block.ends_with('\n'), "the block must end its own line");
    }

    #[test]
    fn the_fish_line_uses_fish_syntax_and_appends() {
        let block = render_profile_block(&console_dir(), ShellFlavour::Fish).expect("render");
        assert!(block.contains("fish_add_path --append"), "{block}");
        assert!(!block.contains("export"), "fish has no export: {block}");
    }

    #[test]
    fn a_trailing_separator_is_not_carried_into_the_line() {
        let block = render_profile_block(Path::new("/opt/netrulerouter/bin/"), ShellFlavour::Posix)
            .expect("render");
        assert!(block.contains(&format!(":{CONSOLE_DIR}\"")), "{block}");
    }

    #[test]
    fn a_directory_that_would_change_the_meaning_of_the_line_is_refused() {
        for hostile in [
            "/opt/$(whoami)",
            "/opt/a\"b",
            "/opt/a'b",
            "/opt/a`b`",
            "/opt/a\nexport EVIL=1",
        ] {
            assert!(
                matches!(
                    render_profile_block(Path::new(hostile), ShellFlavour::Posix),
                    Err(PathRegistrationError::InvalidDirectory { .. })
                ),
                "{hostile} must be refused"
            );
        }
    }

    #[test]
    fn the_current_session_command_matches_the_shell() {
        assert_eq!(
            render_current_session_command(&console_dir(), ShellFlavour::Posix).expect("render"),
            format!("export PATH=\"$PATH:{CONSOLE_DIR}\"")
        );
        assert_eq!(
            render_current_session_command(&console_dir(), ShellFlavour::Fish).expect("render"),
            format!("fish_add_path --append '{CONSOLE_DIR}'")
        );
    }

    // ── Existing-declaration detection ───────────────────────────────────────

    #[test]
    fn an_existing_declaration_is_recognised() {
        let contents = format!("export EDITOR=vi\nexport PATH=\"$PATH:{CONSOLE_DIR}\"\n");
        assert!(profile_declares_directory(&contents, &console_dir()));
    }

    #[test]
    fn a_commented_out_declaration_does_not_count() {
        let contents = format!("# export PATH=\"$PATH:{CONSOLE_DIR}\"\n");
        assert!(!profile_declares_directory(&contents, &console_dir()));
    }

    #[test]
    fn a_longer_path_that_merely_starts_with_ours_does_not_count() {
        let contents = "export PATH=\"$PATH:/opt/netrulerouter/bin-old\"\n";
        assert!(!profile_declares_directory(contents, &console_dir()));
        let contents = "export PATH=\"$PATH:/opt/netrulerouter/binaries\"\n";
        assert!(!profile_declares_directory(contents, &console_dir()));
    }

    #[test]
    fn a_declaration_in_any_position_of_the_list_counts() {
        let contents = format!("export PATH=\"{CONSOLE_DIR}:$PATH\"\n");
        assert!(profile_declares_directory(&contents, &console_dir()));
        let contents = format!("export PATH=\"/a:{CONSOLE_DIR}:/b\"\n");
        assert!(profile_declares_directory(&contents, &console_dir()));
    }

    #[test]
    fn an_empty_file_declares_nothing() {
        assert!(!profile_declares_directory("", &console_dir()));
    }

    // ── Planning ─────────────────────────────────────────────────────────────

    #[test]
    fn planning_names_the_file_and_the_line_without_writing() {
        let scratch = scratch();
        let p = UnixPathRegistration::new(
            scratch.0.clone(),
            Some("/bin/bash".into()),
            "/usr/bin".into(),
        );
        let plan = p.plan(&request()).expect("plan");

        assert!(plan.changes_anything());
        match plan.steps.as_slice() {
            [PathRegistrationStep::AppendShellProfileLine { path, line }] => {
                assert_eq!(path, &scratch.0.join(".bashrc"));
                assert!(line.contains(CONSOLE_DIR));
            }
            other => panic!("expected one append step, got {other:?}"),
        }
        // Nothing was created.
        assert!(!scratch.0.join(".bashrc").exists());
    }

    #[test]
    fn a_directory_already_on_path_needs_no_line() {
        let p = port(Some("/bin/bash"), &format!("/usr/bin:{CONSOLE_DIR}"));
        let plan = p.plan(&request()).expect("plan");
        assert_eq!(plan.decision, PathDecision::AlreadyPresent);
        assert!(plan.steps.is_empty());
    }

    #[test]
    fn path_membership_is_case_sensitive_here() {
        // Unlike Windows, a differently-cased entry is a different directory.
        let p = port(Some("/bin/bash"), "/usr/bin:/opt/NETRULEROUTER/BIN");
        assert!(p.plan(&request()).expect("plan").changes_anything());
    }

    #[test]
    fn a_file_that_already_declares_it_is_not_appended_to_twice() {
        let scratch = scratch();
        let profile = scratch.0.join(".bashrc");
        fs::write(&profile, format!("export PATH=\"$PATH:{CONSOLE_DIR}\"\n"))
            .expect("seed profile");

        // The directory is NOT on this process's PATH — the user just has not
        // opened a new shell yet.
        let p = UnixPathRegistration::new(
            scratch.0.clone(),
            Some("/bin/bash".into()),
            "/usr/bin".into(),
        );
        let plan = p.plan(&request()).expect("plan");
        assert!(!plan.changes_anything(), "a second line would be noise");
        assert!(!plan.current_session_command.is_empty());
    }

    #[test]
    fn the_machine_wide_scope_is_refused() {
        let p = port(Some("/bin/bash"), "/usr/bin");
        let req = PathRegistrationRequest {
            directory: console_dir(),
            scope: PathScope::AllUsers,
        };
        assert!(matches!(
            p.plan(&req),
            Err(PathRegistrationError::Unsupported { .. })
        ));
    }

    #[test]
    fn a_relative_directory_is_refused() {
        let p = port(Some("/bin/bash"), "/usr/bin");
        let req = PathRegistrationRequest::for_current_user("relative/bin");
        assert!(matches!(
            p.plan(&req),
            Err(PathRegistrationError::InvalidDirectory { .. })
        ));
    }

    // ── Applying ─────────────────────────────────────────────────────────────

    #[test]
    fn applying_creates_the_file_and_writes_the_block() {
        let scratch = scratch();
        let p = UnixPathRegistration::new(
            scratch.0.clone(),
            Some("/bin/bash".into()),
            "/usr/bin".into(),
        );
        let report = p.register(&request()).expect("register");

        assert!(report.changed);
        assert!(report.restart_shell_required);
        assert_eq!(report.files_written, vec![scratch.0.join(".bashrc")]);

        let contents = fs::read_to_string(scratch.0.join(".bashrc")).expect("read back");
        assert!(contents.contains(PROFILE_MARKER));
        assert!(contents.contains(&format!("export PATH=\"$PATH:{CONSOLE_DIR}\"")));
    }

    #[test]
    fn applying_creates_missing_parent_directories() {
        // The fish drop-in lives three levels down and usually does not exist.
        let scratch = scratch();
        let p = UnixPathRegistration::new(
            scratch.0.clone(),
            Some("/usr/bin/fish".into()),
            "/usr/bin".into(),
        );
        p.register(&request()).expect("register");

        let dropin = scratch.0.join(".config/fish/conf.d/netrulerouter.fish");
        let contents = fs::read_to_string(&dropin).expect("drop-in written");
        assert!(contents.contains("fish_add_path --append"));
    }

    #[test]
    fn applying_never_lands_on_the_tail_of_an_existing_command() {
        let scratch = scratch();
        let profile = scratch.0.join(".bashrc");
        // A file whose last line has no terminating newline.
        fs::write(&profile, "alias ll='ls -l'").expect("seed profile");

        let p = UnixPathRegistration::new(
            scratch.0.clone(),
            Some("/bin/bash".into()),
            "/usr/bin".into(),
        );
        p.register(&request()).expect("register");

        let contents = fs::read_to_string(&profile).expect("read back");
        assert!(contents.starts_with("alias ll='ls -l'\n"), "{contents}");
        assert!(contents.contains(PROFILE_MARKER));
    }

    #[test]
    fn applying_preserves_what_was_already_in_the_file() {
        let scratch = scratch();
        let profile = scratch.0.join(".bashrc");
        fs::write(&profile, "export EDITOR=vi\n").expect("seed profile");

        let p = UnixPathRegistration::new(
            scratch.0.clone(),
            Some("/bin/bash".into()),
            "/usr/bin".into(),
        );
        p.register(&request()).expect("register");

        let contents = fs::read_to_string(&profile).expect("read back");
        assert!(contents.starts_with("export EDITOR=vi\n"));
    }

    #[test]
    fn registering_twice_adds_one_block() {
        let scratch = scratch();
        let p = UnixPathRegistration::new(
            scratch.0.clone(),
            Some("/bin/bash".into()),
            "/usr/bin".into(),
        );
        p.register(&request()).expect("first");
        let report = p.register(&request()).expect("second");

        assert!(!report.changed);
        let contents = fs::read_to_string(scratch.0.join(".bashrc")).expect("read back");
        assert_eq!(
            contents.matches(PROFILE_MARKER).count(),
            1,
            "one click, one line: {contents}"
        );
    }

    #[test]
    fn an_environment_step_is_refused_rather_than_skipped() {
        let scratch = scratch();
        let p = UnixPathRegistration::new(
            scratch.0.clone(),
            Some("/bin/bash".into()),
            "/usr/bin".into(),
        );
        let plan = PathRegistrationPlan {
            directory: console_dir(),
            scope: PathScope::CurrentUser,
            decision: PathDecision::Append {
                updated_list: CONSOLE_DIR.to_string(),
            },
            steps: vec![PathRegistrationStep::SetUserEnvironmentVariable {
                name: "PATH".to_string(),
                value: CONSOLE_DIR.to_string(),
            }],
            current_session_command: String::new(),
        };
        assert!(matches!(
            p.apply(&plan),
            Err(PathRegistrationError::Unsupported { .. })
        ));
    }

    #[test]
    fn the_style_is_the_unix_convention() {
        let p = port(Some("/bin/bash"), "/usr/bin");
        assert_eq!(p.style(), PathListStyle::Unix);
        assert!(p.style().case_sensitive());
        assert_eq!(p.style().separator(), ':');
    }
}
