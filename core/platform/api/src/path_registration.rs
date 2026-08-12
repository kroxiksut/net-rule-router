//! Neutral "make this directory reachable from the user's shell" port.
//!
//! Putting the administrative console's directory on the user's `PATH` is one
//! capability with two unrelated mechanisms: Windows keeps a per-user
//! environment block in the registry, while Unix has no per-user environment
//! store at all and reaches the same outcome by adding a line to a shell
//! start-up file. What is IDENTICAL on both is the *decision*: given the list as
//! it stands today and the directory that should be reachable, is there anything
//! to do, and what does the resulting list look like. That decision lives here —
//! pure, and tested against both list conventions — and the OS backends only
//! carry it out.
//!
//! ## Shape of the seam
//!
//! [`PathRegistrationPort::plan`] computes a [`PathRegistrationPlan`]: a
//! side-effect-free description of what would change, including the exact steps
//! and a one-line command the user can paste into an already-open shell.
//! [`PathRegistrationPort::apply`] is the only call that touches the machine.
//! Splitting the two is what lets a UI show "here is what this button will do"
//! before anything is written, and it mirrors the install-plan/executor split
//! the Linux service install already uses.
//!
//! ## What this port deliberately does NOT do
//!
//! - **It is never invoked implicitly.** Registration happens on an explicit
//!   human action; nothing in the install path calls it. A tool that silently
//!   rewrites `PATH` is a tool the user cannot reason about.
//! - **It does not rewrite existing entries.** The only edit ever made is
//!   appending one directory. Whatever else is on the list — including entries
//!   with odd quoting or trailing separators — is preserved byte-for-byte,
//!   because a "helpful" normalisation of somebody else's `PATH` is a bug that
//!   surfaces days later in an unrelated program.
//! - **It appends, never prepends.** A prepended directory shadows every
//!   same-named tool already installed; that is a decision for the user, not for
//!   us.
//! - **It does not modify the machine-wide list.** A system-scope request is
//!   answered with [`PathRegistrationError::Unsupported`]: that store is
//!   privileged, and reaching it needs the elevation broker rather than a
//!   silent write from a non-elevated process.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

// ── List conventions ─────────────────────────────────────────────────────────

/// How a host writes its `PATH` list.
///
/// The two axes that actually change the decision are the entry separator and
/// whether two spellings of one directory compare equal. Everything else about
/// a path list is identical across the platforms we target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathListStyle {
    /// `;`-separated, compared case-insensitively, with `\` and `/` both
    /// accepted as directory separators.
    Windows,
    /// `:`-separated, compared exactly, with `/` as the only directory
    /// separator.
    Unix,
}

impl PathListStyle {
    /// The convention of the host this build targets.
    pub const fn host() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Unix
        }
    }

    /// The character that separates two entries in the list.
    pub const fn separator(self) -> char {
        match self {
            Self::Windows => ';',
            Self::Unix => ':',
        }
    }

    /// Whether two entries differing only in case name different directories.
    pub const fn case_sensitive(self) -> bool {
        matches!(self, Self::Unix)
    }

    /// Whether `c` separates directory components on this host.
    const fn is_directory_separator(self, c: char) -> bool {
        match self {
            Self::Windows => c == '\\' || c == '/',
            Self::Unix => c == '/',
        }
    }
}

// ── Scope ────────────────────────────────────────────────────────────────────

/// Whose `PATH` a request talks about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathScope {
    /// The list of the user running the process. Needs no privilege on any
    /// supported OS, which is why it is the only scope implemented.
    CurrentUser,
    /// The machine-wide list, shared by every account. Privileged everywhere;
    /// declared so a caller can express the request and get a clear
    /// [`PathRegistrationError::Unsupported`] instead of a surprise.
    AllUsers,
}

impl PathScope {
    /// Stable slug for logs and UI round-trips.
    pub const fn slug(self) -> &'static str {
        match self {
            Self::CurrentUser => "current-user",
            Self::AllUsers => "all-users",
        }
    }
}

// ── Request / decision ───────────────────────────────────────────────────────

/// One "make this directory reachable" request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathRegistrationRequest {
    /// Absolute directory to make reachable. A relative entry on `PATH`
    /// resolves against the current working directory, which is a way to get a
    /// different program than the one you asked for — so it is rejected.
    pub directory: PathBuf,
    /// Whose list to change.
    pub scope: PathScope,
}

impl PathRegistrationRequest {
    /// Request registration on the current user's list.
    pub fn for_current_user(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            scope: PathScope::CurrentUser,
        }
    }
}

/// What the pure decision concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathDecision {
    /// The directory is already on the list — registering again would only
    /// lengthen it.
    AlreadyPresent,
    /// The directory is missing; `updated_list` is the list to store, which is
    /// the current list with exactly one entry appended.
    Append { updated_list: String },
}

impl PathDecision {
    /// Whether carrying this decision out changes anything.
    pub const fn changes_anything(&self) -> bool {
        matches!(self, Self::Append { .. })
    }
}

// ── Plan / report ────────────────────────────────────────────────────────────

/// One concrete action an [`apply`](PathRegistrationPort::apply) performs.
///
/// The variants are named after the *outcome* rather than the API that achieves
/// it, so the enum stays neutral: "persist a per-user environment value" is the
/// registry on Windows and has no Unix analogue, while "append a shell start-up
/// line" is the Unix answer and has no Windows analogue. A backend rejects a
/// step it does not implement rather than silently skipping it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathRegistrationStep {
    /// Persist `value` under `name` in the OS's per-user environment store, so
    /// programs started afterwards inherit it.
    SetUserEnvironmentVariable { name: String, value: String },
    /// Append `line` to the shell start-up file at `path`, creating the file if
    /// it does not exist.
    AppendShellProfileLine { path: PathBuf, line: String },
    /// Tell the system the environment changed, so newly launched programs pick
    /// the new value up without a sign-out.
    AnnounceEnvironmentChange,
}

/// A computed, side-effect-free description of a registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathRegistrationPlan {
    /// The directory the plan is about.
    pub directory: PathBuf,
    /// The list the plan targets.
    pub scope: PathScope,
    /// What the pure decision concluded.
    pub decision: PathDecision,
    /// The steps to perform, in order. Empty when the decision is
    /// [`PathDecision::AlreadyPresent`].
    pub steps: Vec<PathRegistrationStep>,
    /// A single command the user can paste into a shell that is already open,
    /// to get the directory on `PATH` in that session without waiting for a new
    /// one. Shell syntax, so each backend fills it in.
    pub current_session_command: String,
}

impl PathRegistrationPlan {
    /// A plan that does nothing because the directory is already reachable.
    pub fn already_present(
        directory: PathBuf,
        scope: PathScope,
        current_session_command: String,
    ) -> Self {
        Self {
            directory,
            scope,
            decision: PathDecision::AlreadyPresent,
            steps: Vec::new(),
            current_session_command,
        }
    }

    /// Whether applying this plan would change the machine.
    pub fn changes_anything(&self) -> bool {
        self.decision.changes_anything()
    }
}

/// What an [`apply`](PathRegistrationPort::apply) actually did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathRegistrationReport {
    /// Whether anything was written. `false` for an already-present directory.
    pub changed: bool,
    /// Files written, in the order they were written. Empty on hosts whose
    /// mechanism is not file-based.
    pub files_written: Vec<PathBuf>,
    /// Whether shells that are already open still need to be restarted (or the
    /// [`PathRegistrationPlan::current_session_command`] run) before the
    /// directory is reachable in them. True for every mechanism we have: no OS
    /// rewrites the environment of a running process.
    pub restart_shell_required: bool,
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Why a registration could not be planned or carried out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathRegistrationError {
    /// The directory is empty, relative, or contains the character this host
    /// uses to separate list entries — none of which can be expressed as a
    /// single entry.
    InvalidDirectory { detail: String },
    /// This host has no mechanism for the requested scope or step.
    Unsupported { detail: String },
    /// The caller lacks the privilege the store requires.
    AccessDenied,
    /// Anything else the OS reported, verbatim.
    Mechanism { detail: String },
}

impl std::fmt::Display for PathRegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDirectory { detail } => write!(f, "invalid directory: {detail}"),
            Self::Unsupported { detail } => write!(f, "not supported here: {detail}"),
            Self::AccessDenied => write!(f, "access denied"),
            Self::Mechanism { detail } => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for PathRegistrationError {}

// ── Pure decision logic ──────────────────────────────────────────────────────

/// Strip one layer of surrounding double quotes, if present. `PATH` entries are
/// occasionally quoted by installers that worry about spaces.
fn strip_quotes(s: &str) -> &str {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        &t[1..t.len() - 1]
    } else {
        t
    }
}

/// Drop trailing directory separators without destroying a root. `C:\bin\`
/// becomes `C:\bin`, while `/` and `C:\` are left as they are — those ARE the
/// directory, not a decoration on one.
fn strip_trailing_separators(s: &str, style: PathListStyle) -> &str {
    let mut end = s.len();
    while end > 0 {
        let last = match s[..end].chars().next_back() {
            Some(c) => c,
            None => break,
        };
        if !style.is_directory_separator(last) {
            break;
        }
        let candidate = &s[..end - last.len_utf8()];
        // Never strip a lone separator ("/") nor the one that completes a
        // Windows drive root ("C:\").
        if candidate.is_empty() || candidate.ends_with(':') {
            break;
        }
        end -= last.len_utf8();
    }
    &s[..end]
}

/// The form of an entry used for equality on this host.
///
/// Quotes and trailing separators are cosmetic everywhere; on Windows the case
/// and the choice of `\` vs `/` are cosmetic too. Returns `None` for an entry
/// that carries no directory at all (empty or whitespace), which is how a list
/// with stray separators is skipped.
fn comparison_key(raw: &str, style: PathListStyle) -> Option<String> {
    let cleaned = strip_trailing_separators(strip_quotes(raw).trim(), style);
    if cleaned.is_empty() {
        return None;
    }
    Some(match style {
        PathListStyle::Windows => cleaned.replace('/', "\\").to_lowercase(),
        PathListStyle::Unix => cleaned.to_string(),
    })
}

/// Iterate the directories on a list, skipping empty entries.
pub fn path_entries(list: &str, style: PathListStyle) -> impl Iterator<Item = &str> {
    list.split(style.separator())
        .map(|e| strip_quotes(e).trim())
        .filter(|e| !e.is_empty())
}

/// Whether `directory` is already on `list`.
///
/// Comparison is by [`comparison_key`], so a quoted entry, a trailing
/// separator, and (on Windows) a different case or slash direction all count as
/// the same directory. This is the whole point of the pure layer: "already
/// there" must not depend on how somebody else spelled it.
pub fn list_contains_directory(list: &str, directory: &Path, style: PathListStyle) -> bool {
    let Some(target) = comparison_key(&directory.to_string_lossy(), style) else {
        return false;
    };
    list.split(style.separator())
        .filter_map(|entry| comparison_key(entry, style))
        .any(|entry| entry == target)
}

/// The text form an entry takes when we append it: the directory as given,
/// unquoted and without a trailing separator.
pub fn render_entry(directory: &Path, style: PathListStyle) -> String {
    let raw = directory.to_string_lossy();
    strip_trailing_separators(strip_quotes(&raw).trim(), style).to_string()
}

/// Whether a directory is absolute under `style`.
///
/// Deliberately not `Path::is_absolute`: that answers for the host the code is
/// running on, so a Windows path would read as relative in a Linux test run and
/// the rule being enforced would silently change with the test machine.
fn is_absolute_for(directory: &str, style: PathListStyle) -> bool {
    match style {
        PathListStyle::Unix => directory.starts_with('/'),
        PathListStyle::Windows => {
            // UNC share (`\\server\share`) or a drive-qualified root (`C:\`).
            if directory.starts_with("\\\\") || directory.starts_with("//") {
                return true;
            }
            let mut chars = directory.chars();
            matches!(
                (chars.next(), chars.next(), chars.next()),
                (Some(drive), Some(':'), Some(sep))
                    if drive.is_ascii_alphabetic() && style.is_directory_separator(sep)
            )
        }
    }
}

/// Validate a directory as a `PATH` entry and return its rendered form.
fn validate_directory(
    directory: &Path,
    style: PathListStyle,
) -> Result<String, PathRegistrationError> {
    let entry = render_entry(directory, style);
    if entry.is_empty() {
        return Err(PathRegistrationError::InvalidDirectory {
            detail: "the directory is empty".to_string(),
        });
    }
    if entry.contains(style.separator()) {
        return Err(PathRegistrationError::InvalidDirectory {
            detail: format!(
                "the directory contains {:?}, which separates entries on this system",
                style.separator()
            ),
        });
    }
    if !is_absolute_for(&entry, style) {
        return Err(PathRegistrationError::InvalidDirectory {
            detail: format!("{entry:?} is not an absolute path"),
        });
    }
    Ok(entry)
}

/// The pure heart of this port: given the list as it stands and the directory
/// that should be reachable, decide whether anything must change and what the
/// stored list becomes.
///
/// The current list is never re-formatted. Only two things happen to it: a
/// trailing separator (very common on Windows) is not doubled, and one entry is
/// appended.
pub fn decide_path_registration(
    current_list: &str,
    directory: &Path,
    style: PathListStyle,
) -> Result<PathDecision, PathRegistrationError> {
    let entry = validate_directory(directory, style)?;
    if list_contains_directory(current_list, directory, style) {
        return Ok(PathDecision::AlreadyPresent);
    }
    let base = current_list
        .trim_end()
        .trim_end_matches(style.separator())
        .trim_end();
    let updated_list = if base.is_empty() {
        entry
    } else {
        format!("{base}{}{entry}", style.separator())
    };
    Ok(PathDecision::Append { updated_list })
}

// ── The port ─────────────────────────────────────────────────────────────────

/// Make a directory reachable by name from the user's shell.
///
/// One implementation per OS mechanism. Implementations hold no state beyond
/// what they need to locate the store (a registry hive, a home directory).
pub trait PathRegistrationPort {
    /// The list convention this host uses. Callers render hints and diagnostics
    /// from it instead of re-deriving it from `cfg!`.
    fn style(&self) -> PathListStyle;

    /// Compute what registering `request` would do. No side effects: nothing is
    /// written, no process is spawned, and the machine is only read.
    fn plan(
        &self,
        request: &PathRegistrationRequest,
    ) -> Result<PathRegistrationPlan, PathRegistrationError>;

    /// Carry out a plan produced by [`plan`](Self::plan). Applying an
    /// already-present plan is a successful no-op.
    ///
    /// The plan is computed against the list as it was read; a plan held across
    /// an unrelated change to the same list would append against stale content.
    /// Plans are meant to be applied immediately after they are computed —
    /// re-plan rather than re-apply.
    fn apply(
        &self,
        plan: &PathRegistrationPlan,
    ) -> Result<PathRegistrationReport, PathRegistrationError>;

    /// Whether the directory is already reachable. Derived from
    /// [`plan`](Self::plan) so the two answers can never disagree.
    fn is_registered(
        &self,
        request: &PathRegistrationRequest,
    ) -> Result<bool, PathRegistrationError> {
        Ok(!self.plan(request)?.changes_anything())
    }

    /// Plan and apply in one call — the shape a UI button wants.
    fn register(
        &self,
        request: &PathRegistrationRequest,
    ) -> Result<PathRegistrationReport, PathRegistrationError> {
        let plan = self.plan(request)?;
        self.apply(&plan)
    }
}

// ── Test double ──────────────────────────────────────────────────────────────

/// In-memory port over a plain list string. Lets callers (and a UI preview) be
/// exercised on any host, in either list convention, with no OS store involved.
pub struct MockPathRegistration {
    style: PathListStyle,
    list: Mutex<String>,
    applied: Mutex<Vec<PathRegistrationStep>>,
}

// Test double: lock-poisoning `expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl MockPathRegistration {
    /// A port whose list starts out as `list`.
    pub fn new(style: PathListStyle, list: &str) -> Self {
        Self {
            style,
            list: Mutex::new(list.to_string()),
            applied: Mutex::new(Vec::new()),
        }
    }

    /// The list as it stands now.
    pub fn current_list(&self) -> String {
        self.list.lock().expect("mock mutex").clone()
    }

    /// Every step applied so far, in order.
    pub fn applied_steps(&self) -> Vec<PathRegistrationStep> {
        self.applied.lock().expect("mock mutex").clone()
    }
}

// Test double: lock-poisoning `expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl PathRegistrationPort for MockPathRegistration {
    fn style(&self) -> PathListStyle {
        self.style
    }

    fn plan(
        &self,
        request: &PathRegistrationRequest,
    ) -> Result<PathRegistrationPlan, PathRegistrationError> {
        if request.scope != PathScope::CurrentUser {
            return Err(PathRegistrationError::Unsupported {
                detail: "the in-memory port models one user's list only".to_string(),
            });
        }
        let list = self.current_list();
        let decision = decide_path_registration(&list, &request.directory, self.style)?;
        let steps = match &decision {
            PathDecision::AlreadyPresent => Vec::new(),
            PathDecision::Append { updated_list } => vec![
                PathRegistrationStep::SetUserEnvironmentVariable {
                    name: "PATH".to_string(),
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
            current_session_command: String::new(),
        })
    }

    fn apply(
        &self,
        plan: &PathRegistrationPlan,
    ) -> Result<PathRegistrationReport, PathRegistrationError> {
        let mut changed = false;
        for step in &plan.steps {
            if let PathRegistrationStep::SetUserEnvironmentVariable { value, .. } = step {
                *self.list.lock().expect("mock mutex") = value.clone();
                changed = true;
            }
            self.applied.lock().expect("mock mutex").push(step.clone());
        }
        Ok(PathRegistrationReport {
            changed,
            files_written: Vec::new(),
            restart_shell_required: changed,
        })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const WIN: PathListStyle = PathListStyle::Windows;
    const UNIX: PathListStyle = PathListStyle::Unix;

    fn win_dir() -> PathBuf {
        PathBuf::from(r"C:\Program Files\NetRuleRouter")
    }

    fn unix_dir() -> PathBuf {
        PathBuf::from("/opt/netrulerouter/bin")
    }

    // ── Conventions ──────────────────────────────────────────────────────────

    #[test]
    fn separators_and_case_rules_follow_the_convention() {
        assert_eq!(WIN.separator(), ';');
        assert_eq!(UNIX.separator(), ':');
        assert!(!WIN.case_sensitive());
        assert!(UNIX.case_sensitive());
    }

    #[test]
    fn host_style_matches_the_build_target() {
        let expected = if cfg!(windows) { WIN } else { UNIX };
        assert_eq!(PathListStyle::host(), expected);
    }

    // ── Normalisation ────────────────────────────────────────────────────────

    #[test]
    fn trailing_separators_are_cosmetic_but_roots_are_not() {
        assert_eq!(strip_trailing_separators(r"C:\bin\", WIN), r"C:\bin");
        assert_eq!(strip_trailing_separators(r"C:\bin\\\", WIN), r"C:\bin");
        assert_eq!(strip_trailing_separators(r"C:\", WIN), r"C:\");
        assert_eq!(strip_trailing_separators("/usr/bin/", UNIX), "/usr/bin");
        assert_eq!(strip_trailing_separators("/", UNIX), "/");
    }

    #[test]
    fn a_backslash_is_not_a_separator_on_unix() {
        // A Unix directory may legitimately contain a backslash in its name.
        assert_eq!(strip_trailing_separators(r"/tmp/odd\", UNIX), r"/tmp/odd\");
    }

    #[test]
    fn quotes_around_an_entry_are_stripped() {
        assert_eq!(
            strip_quotes(r#""C:\Program Files\x""#),
            r"C:\Program Files\x"
        );
        assert_eq!(strip_quotes("  /usr/bin  "), "/usr/bin");
        // A lone quote is not a quoted entry.
        assert_eq!(strip_quotes(r#""unbalanced"#), r#""unbalanced"#);
    }

    #[test]
    fn windows_keys_ignore_case_and_slash_direction() {
        assert_eq!(
            comparison_key(r"C:\Program Files\NetRuleRouter", WIN),
            comparison_key(r"c:/PROGRAM FILES/netrulerouter/", WIN)
        );
    }

    #[test]
    fn unix_keys_are_exact() {
        assert_ne!(
            comparison_key("/opt/NRR", UNIX),
            comparison_key("/opt/nrr", UNIX)
        );
        // …but trailing separators and quotes still are not part of the name.
        assert_eq!(
            comparison_key("/opt/nrr/", UNIX),
            comparison_key(r#""/opt/nrr""#, UNIX)
        );
    }

    #[test]
    fn an_empty_entry_has_no_key() {
        assert_eq!(comparison_key("", WIN), None);
        assert_eq!(comparison_key("   ", UNIX), None);
        assert_eq!(comparison_key(r#""""#, UNIX), None);
    }

    // ── Membership ───────────────────────────────────────────────────────────

    #[test]
    fn membership_is_case_insensitive_on_windows() {
        let list = r"C:\Windows;c:\program files\netrulerouter;C:\Tools";
        assert!(list_contains_directory(list, &win_dir(), WIN));
    }

    #[test]
    fn membership_is_case_sensitive_on_unix() {
        let list = "/usr/bin:/OPT/NETRULEROUTER/BIN";
        assert!(!list_contains_directory(list, &unix_dir(), UNIX));
        assert!(list_contains_directory(
            "/usr/bin:/opt/netrulerouter/bin",
            &unix_dir(),
            UNIX
        ));
    }

    #[test]
    fn membership_sees_through_quotes_and_trailing_separators() {
        let win_list = r#"C:\Windows;"C:\Program Files\NetRuleRouter\";C:\Tools"#;
        assert!(list_contains_directory(win_list, &win_dir(), WIN));

        let unix_list = r#"/usr/bin:"/opt/netrulerouter/bin/":/usr/local/bin"#;
        assert!(list_contains_directory(unix_list, &unix_dir(), UNIX));
    }

    #[test]
    fn membership_is_not_fooled_by_a_prefix() {
        // A sibling directory whose name starts with ours is a different place.
        assert!(!list_contains_directory(
            r"C:\Program Files\NetRuleRouterOld",
            &win_dir(),
            WIN
        ));
        assert!(!list_contains_directory(
            "/opt/netrulerouter/bin-old",
            &unix_dir(),
            UNIX
        ));
    }

    #[test]
    fn stray_separators_do_not_count_as_entries() {
        assert!(!list_contains_directory(";;;", &win_dir(), WIN));
        assert_eq!(path_entries(";;;", WIN).count(), 0);
        assert_eq!(
            path_entries("/a::/b:", UNIX).collect::<Vec<_>>(),
            ["/a", "/b"]
        );
    }

    // ── Decision ─────────────────────────────────────────────────────────────

    #[test]
    fn an_already_present_directory_is_a_no_op_on_both_conventions() {
        assert_eq!(
            decide_path_registration(
                r"C:\Windows;C:\Program Files\NetRuleRouter",
                &win_dir(),
                WIN
            ),
            Ok(PathDecision::AlreadyPresent)
        );
        assert_eq!(
            decide_path_registration("/usr/bin:/opt/netrulerouter/bin", &unix_dir(), UNIX),
            Ok(PathDecision::AlreadyPresent)
        );
    }

    #[test]
    fn appending_preserves_the_existing_list_verbatim() {
        // Note the odd spelling of the existing entries: it survives untouched.
        let list = r#"C:\Windows;"c:\weird\ENTRY\";C:\Tools"#;
        let decision = decide_path_registration(list, &win_dir(), WIN).expect("decide");
        match decision {
            PathDecision::Append { updated_list } => {
                assert_eq!(
                    updated_list,
                    format!(r#"{list};C:\Program Files\NetRuleRouter"#)
                );
            }
            other => panic!("expected Append, got {other:?}"),
        }
    }

    #[test]
    fn appending_does_not_double_a_trailing_separator() {
        let decision = decide_path_registration("/usr/bin:", &unix_dir(), UNIX).expect("decide");
        assert_eq!(
            decision,
            PathDecision::Append {
                updated_list: "/usr/bin:/opt/netrulerouter/bin".to_string()
            }
        );

        let decision = decide_path_registration(r"C:\Windows;  ", &win_dir(), WIN).expect("decide");
        assert_eq!(
            decision,
            PathDecision::Append {
                updated_list: r"C:\Windows;C:\Program Files\NetRuleRouter".to_string()
            }
        );
    }

    #[test]
    fn appending_to_an_empty_list_yields_a_bare_entry() {
        for (list, dir, style, expected) in [
            ("", win_dir(), WIN, r"C:\Program Files\NetRuleRouter"),
            (";;", win_dir(), WIN, r"C:\Program Files\NetRuleRouter"),
            ("", unix_dir(), UNIX, "/opt/netrulerouter/bin"),
            ("::", unix_dir(), UNIX, "/opt/netrulerouter/bin"),
        ] {
            assert_eq!(
                decide_path_registration(list, &dir, style),
                Ok(PathDecision::Append {
                    updated_list: expected.to_string()
                }),
                "list {list:?}"
            );
        }
    }

    #[test]
    fn the_appended_entry_is_never_quoted_and_never_trails_a_separator() {
        let decision =
            decide_path_registration("", Path::new(r#""C:\Program Files\NetRuleRouter\""#), WIN)
                .expect("decide");
        assert_eq!(
            decision,
            PathDecision::Append {
                updated_list: r"C:\Program Files\NetRuleRouter".to_string()
            }
        );
    }

    #[test]
    fn appending_is_idempotent() {
        // Applying the decision, then deciding again, must conclude "nothing to do".
        let first = decide_path_registration("/usr/bin", &unix_dir(), UNIX).expect("decide");
        let list = match first {
            PathDecision::Append { updated_list } => updated_list,
            other => panic!("expected Append, got {other:?}"),
        };
        assert_eq!(
            decide_path_registration(&list, &unix_dir(), UNIX),
            Ok(PathDecision::AlreadyPresent)
        );
    }

    // ── Rejections ───────────────────────────────────────────────────────────

    #[test]
    fn a_relative_directory_is_rejected_on_both_conventions() {
        assert!(matches!(
            decide_path_registration("", Path::new(r"tools\bin"), WIN),
            Err(PathRegistrationError::InvalidDirectory { .. })
        ));
        assert!(matches!(
            decide_path_registration("", Path::new("tools/bin"), UNIX),
            Err(PathRegistrationError::InvalidDirectory { .. })
        ));
        // A drive-relative Windows path ("C:tools") is relative too.
        assert!(matches!(
            decide_path_registration("", Path::new("C:tools"), WIN),
            Err(PathRegistrationError::InvalidDirectory { .. })
        ));
    }

    #[test]
    fn absolute_forms_are_accepted_per_convention() {
        assert!(is_absolute_for(r"C:\bin", WIN));
        assert!(is_absolute_for("C:/bin", WIN));
        assert!(is_absolute_for(r"\\server\share", WIN));
        assert!(!is_absolute_for("/usr/bin", WIN)); // no drive: not a Windows root
        assert!(is_absolute_for("/usr/bin", UNIX));
        assert!(!is_absolute_for(r"C:\bin", UNIX));
    }

    #[test]
    fn an_empty_directory_is_rejected() {
        assert!(matches!(
            decide_path_registration("", Path::new(""), UNIX),
            Err(PathRegistrationError::InvalidDirectory { .. })
        ));
    }

    #[test]
    fn a_directory_containing_the_separator_is_rejected() {
        // It could never be told apart from two entries.
        assert!(matches!(
            decide_path_registration("", Path::new("/opt/a:b"), UNIX),
            Err(PathRegistrationError::InvalidDirectory { .. })
        ));
        assert!(matches!(
            decide_path_registration("", Path::new(r"C:\a;b"), WIN),
            Err(PathRegistrationError::InvalidDirectory { .. })
        ));
    }

    // ── Port behaviour over the test double ──────────────────────────────────

    #[test]
    fn the_port_registers_then_reports_already_registered() {
        let port = MockPathRegistration::new(UNIX, "/usr/bin");
        let request = PathRegistrationRequest::for_current_user(unix_dir());

        assert!(!port.is_registered(&request).expect("probe"));
        let report = port.register(&request).expect("register");
        assert!(report.changed);
        assert!(report.restart_shell_required);
        assert_eq!(port.current_list(), "/usr/bin:/opt/netrulerouter/bin");
        assert!(port.is_registered(&request).expect("probe"));

        // Second run changes nothing and writes nothing.
        let report = port.register(&request).expect("register again");
        assert!(!report.changed);
        assert_eq!(port.current_list(), "/usr/bin:/opt/netrulerouter/bin");
    }

    #[test]
    fn an_already_present_plan_has_no_steps() {
        let port = MockPathRegistration::new(WIN, r"C:\Program Files\NetRuleRouter");
        let plan = port
            .plan(&PathRegistrationRequest::for_current_user(win_dir()))
            .expect("plan");
        assert_eq!(plan.decision, PathDecision::AlreadyPresent);
        assert!(plan.steps.is_empty());
        assert!(!plan.changes_anything());
    }

    #[test]
    fn planning_writes_nothing() {
        let port = MockPathRegistration::new(UNIX, "/usr/bin");
        let _ = port
            .plan(&PathRegistrationRequest::for_current_user(unix_dir()))
            .expect("plan");
        assert_eq!(port.current_list(), "/usr/bin");
        assert!(port.applied_steps().is_empty());
    }

    #[test]
    fn the_machine_wide_scope_is_refused_rather_than_guessed_at() {
        let port = MockPathRegistration::new(UNIX, "/usr/bin");
        let request = PathRegistrationRequest {
            directory: unix_dir(),
            scope: PathScope::AllUsers,
        };
        assert!(matches!(
            port.plan(&request),
            Err(PathRegistrationError::Unsupported { .. })
        ));
    }

    #[test]
    fn scope_slugs_are_distinct_lowercase() {
        assert_eq!(PathScope::CurrentUser.slug(), "current-user");
        assert_eq!(PathScope::AllUsers.slug(), "all-users");
    }
}
