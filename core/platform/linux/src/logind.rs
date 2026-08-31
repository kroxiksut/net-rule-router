//! Who on this machine currently has a live login — the Linux answer to
//! "whose policy should be in effect".
//!
//! Windows answers it by watching for a tray connection: the tray runs in the
//! user's session, so its presence means the person is there. Linux has no tray
//! yet, and would not be well served by one either — a user can log in over SSH,
//! start work under `screen`, and disconnect the terminal while the work keeps
//! running. Their traffic does not stop when their terminal closes, so neither
//! should their routing.
//!
//! `logind` already tracks exactly this and nothing else does. It is asked
//! through `loginctl`, the same way nftables is driven through `nft` — a stable
//! documented interface instead of a private one. `/run/systemd/users/<uid>`
//! holds the same facts and says so itself: *"This is private data. Do not
//! parse."*
//!
//! ## What counts as live
//!
//! - `active` / `online` — a session exists, attached or not.
//! - `lingering` — no session, but the user enabled linger
//!   (`loginctl enable-linger`), so their services keep running. This is the
//!   `screen`-after-logout case working as intended.
//! - `closing` — on the way out; not counted, or a logout would keep enforcing
//!   for a user who is gone.
//!
//! ## The gap this does NOT cover, stated plainly
//!
//! A user who leaves processes behind WITHOUT linger (a bare `nohup`) has no
//! logind user state once their last session closes. Their traffic can outlive
//! the answer this module gives. logind is the authority on logins, not on
//! processes, and inventing a second authority here would produce two truths
//! about who is present.

#![cfg(target_os = "linux")]

use serde::Deserialize;

/// A user with a live login, as logind sees them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveUser {
    pub uid: u32,
    /// Account name, for logs. Never used for identity — the uid is.
    pub name: String,
    /// `true` when the user has no session but linger keeps their services
    /// running. Worth distinguishing in a log line: "nobody is logged in but we
    /// are still enforcing for them" is surprising until it is explained.
    pub lingering: bool,
}

/// One row of `loginctl list-users --output=json`.
#[derive(Debug, Deserialize)]
struct LoginctlUser {
    uid: u32,
    #[serde(default)]
    user: String,
    #[serde(default)]
    linger: bool,
    #[serde(default)]
    state: String,
}

/// Everyone logind currently considers logged in.
///
/// An empty vector is a legitimate answer (nobody is logged in). `Err` means
/// the question could not be asked at all — no `loginctl`, or it failed — which
/// is NOT the same as "nobody", and the caller must not treat it as such:
/// enforcing nothing because the question failed would silently drop every
/// user's protection.
pub fn live_users() -> Result<Vec<LiveUser>, LogindError> {
    // Budgeted: this runs on EVERY enforcement tick, and a `loginctl` blocked on
    // an unreachable D-Bus used to stop the apply loop for good.
    let out = crate::command::output_with_timeout(
        "loginctl",
        &["list-users", "--output=json", "--no-legend"],
        crate::command::DEFAULT_COMMAND_TIMEOUT,
    )
    .map_err(|e| LogindError::Unavailable(e.to_string()))?;
    if !out.status.success() {
        return Err(LogindError::Failed {
            status: out.status.to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    parse_live_users(&String::from_utf8_lossy(&out.stdout))
}

/// Everything that can go wrong asking the question.
#[derive(Debug)]
pub enum LogindError {
    /// `loginctl` is not installed or not on `PATH` — a system without logind,
    /// or a container built without it.
    Unavailable(String),
    /// It ran and failed. Carries the exit status and whatever it said.
    Failed { status: String, stderr: String },
    /// It answered in a shape this build cannot read. The usual cause is a
    /// systemd too old for `--output=json` on `list-users`, which prints the
    /// table instead. Deliberately NOT falling back to parsing that table: its
    /// column count changed between versions and its footer line
    /// ("2 users listed.") reads as a uid to any parser naive enough to take
    /// the first field — which is exactly the bug the first version of this
    /// module shipped with, caught by its own test.
    Unreadable(String),
}

impl std::fmt::Display for LogindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(e) => write!(f, "loginctl is not available: {e}"),
            Self::Failed { status, stderr } => {
                write!(f, "loginctl failed ({status}): {stderr}")
            }
            Self::Unreadable(e) => write!(
                f,
                "loginctl answered in an unreadable shape (systemd too old for \
                 `list-users --output=json`?): {e}"
            ),
        }
    }
}

impl std::error::Error for LogindError {}

/// Rows in, live users out. Pure over the bytes, so it is tested on every OS.
fn parse_live_users(stdout: &str) -> Result<Vec<LiveUser>, LogindError> {
    let text = stdout.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let rows: Vec<LoginctlUser> =
        serde_json::from_str(text).map_err(|e| LogindError::Unreadable(e.to_string()))?;
    Ok(rows.into_iter().filter_map(to_live_user).collect())
}

/// Which states mean "enforce for this user".
///
/// - `active` / `online` — a session exists, attached or not.
/// - `lingering` — no session, but linger keeps their services running.
/// - anything else, `closing` included — not counted. A state this version does
///   not know is not evidence of presence.
fn to_live_user(row: LoginctlUser) -> Option<LiveUser> {
    let state = row.state.to_ascii_lowercase();
    let live = matches!(state.as_str(), "active" | "online" | "lingering");
    live.then(|| LiveUser {
        uid: row.uid,
        name: row.user,
        lingering: row.linger || state == "lingering",
    })
}

/// The [`ActivePrincipalSource`] the daemon consults on Linux.
///
/// Thin on purpose: the judgement about which logind states count as present
/// lives in `to_live_user`, and the judgement about what to do with the answer
/// lives in the neutral policy above the port. This only maps uid to principal.
pub struct LogindActivePrincipals;

impl nrr_platform_api::active_principals::ActivePrincipalSource for LogindActivePrincipals {
    fn active_principals(
        &self,
    ) -> Result<
        Vec<nrr_platform_api::enforcement::UserPrincipal>,
        nrr_platform_api::active_principals::ActivePrincipalError,
    > {
        let users = live_users().map_err(|e| {
            nrr_platform_api::active_principals::ActivePrincipalError::new(e.to_string())
        })?;
        Ok(users
            .into_iter()
            .map(|u| nrr_platform_api::enforcement::UserPrincipal::from_linux_uid(u.uid))
            .collect())
    }

    fn authority(&self) -> &'static str {
        "logind"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_attached_session_counts() {
        let users =
            parse_live_users(r#"[{"uid":1000,"user":"krox","linger":false,"state":"active"}]"#)
                .expect("parses");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].uid, 1000);
        assert_eq!(users[0].name, "krox");
        assert!(!users[0].lingering);
    }

    #[test]
    fn a_detached_session_still_counts() {
        // The case this module exists for: the terminal is gone, the work is
        // not. `online` means sessions exist without one being in the
        // foreground.
        let users =
            parse_live_users(r#"[{"uid":1000,"user":"krox","linger":false,"state":"online"}]"#)
                .expect("parses");
        assert_eq!(users.len(), 1);
    }

    #[test]
    fn linger_without_a_session_counts_and_is_flagged() {
        let users =
            parse_live_users(r#"[{"uid":900,"user":"svc","linger":true,"state":"lingering"}]"#)
                .expect("parses");
        assert!(
            users[0].lingering,
            "the caller logs this differently: nobody is logged in, yet we enforce"
        );
    }

    #[test]
    fn a_user_on_the_way_out_does_not_count() {
        // Enforcing for someone who just logged out would outlive them.
        let users =
            parse_live_users(r#"[{"uid":1000,"user":"krox","linger":false,"state":"closing"}]"#)
                .expect("parses");
        assert!(users.is_empty());
    }

    #[test]
    fn an_unknown_state_does_not_count() {
        let users =
            parse_live_users(r#"[{"uid":1000,"user":"krox","linger":false,"state":"whatever"}]"#)
                .expect("parses");
        assert!(users.is_empty());
    }

    #[test]
    fn nobody_logged_in_is_an_answer_not_an_error() {
        assert!(parse_live_users("[]").expect("parses").is_empty());
        assert!(parse_live_users("").expect("empty output").is_empty());
    }

    #[test]
    fn several_users_are_all_reported() {
        let users = parse_live_users(
            r#"[{"uid":1000,"user":"a","linger":false,"state":"active"},
                {"uid":1001,"user":"b","linger":false,"state":"online"},
                {"uid":1002,"user":"c","linger":false,"state":"closing"}]"#,
        )
        .expect("parses");
        assert_eq!(users.len(), 2, "the closing one is dropped");
        assert_eq!(users[0].uid, 1000);
        assert_eq!(users[1].uid, 1001);
    }

    #[test]
    fn a_table_instead_of_json_is_refused_not_guessed() {
        // What an older systemd prints. Its footer ("2 users listed.") reads as
        // uid 2 to a first-field parser — a fabricated user is worse than a
        // refusal, so this must be an error.
        let err = parse_live_users(
            "1000 krox no active
2 users listed.
",
        )
        .expect_err("a table is not JSON");
        assert!(matches!(err, LogindError::Unreadable(_)));
    }
}
