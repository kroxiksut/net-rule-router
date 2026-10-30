//! The administrative console on the user's own `PATH`: the state every client
//! shows and the two actions it offers. Registration is a human decision,
//! never a side effect of installing, so nothing here runs on its own; both
//! actions are safe to repeat.
//!
//! The decision is [`crate::path_registration`], the mechanism the per-OS
//! [`PathRegistrationPort`]; the caller supplies the port for its host and the
//! directory it runs from.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use nrr_shared::product_identity::BinaryRole;

use crate::path_registration::{
    list_contains_directory, PathListStyle, PathRegistrationPlan, PathRegistrationPort,
    PathRegistrationRequest, PathRegistrationStep,
};

/// What a client needs to show the action and its result.
///
/// Two facts, and they answer different questions. `reachable` is "would
/// typing the console's name work" — the composed `PATH`, machine entries
/// included — and it drives the status line. `owned_entry_present` is "is OUR
/// entry in OUR store", and it drives the action: on Unix a removal cannot
/// change this process's inherited `PATH`, so an action watching reachability
/// would snap straight back and read as "it did not work".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsolePathState {
    /// The directory holding the console executable.
    pub directory: PathBuf,
    /// Whether the directory is reachable from a newly started shell.
    pub reachable: bool,
    /// Whether the entry WE would write is in the store we write to.
    pub owned_entry_present: bool,
    /// The command to paste into a shell that is ALREADY open: no OS updates a
    /// running process's environment.
    pub current_session_command: String,
    /// The file the registration writes to, where the mechanism is file-based
    /// (Unix). `None` on hosts with a real per-user environment store.
    pub target_file: Option<PathBuf>,
}

impl ConsolePathState {
    #[must_use]
    pub fn from_plan(
        plan: &PathRegistrationPlan,
        reachable: bool,
        owned_entry_present: bool,
    ) -> Self {
        let target_file = plan.steps.iter().find_map(|step| match step {
            PathRegistrationStep::AppendShellProfileLine { path, .. } => Some(path.clone()),
            _ => None,
        });
        Self {
            directory: plan.directory.clone(),
            reachable,
            owned_entry_present,
            current_session_command: plan.current_session_command.clone(),
            target_file,
        }
    }

    /// Something else already puts the folder on `PATH`: there is nothing for
    /// either action to do.
    #[must_use]
    pub fn reachable_but_not_ours(&self) -> bool {
        self.reachable && !self.owned_entry_present
    }
}

/// Whether typing the console's name works with the `PATH` this process
/// inherited — the composed list, deliberately: a directory reachable through
/// a machine-wide entry is still reachable.
fn reachable_on_process_path(directory: &Path, port: &dyn PathRegistrationPort) -> bool {
    let list = std::env::var_os("PATH").unwrap_or_default();
    reachable_on(&list, directory, port.style())
}

/// `directory` is on `list`, or the first console the name finds there
/// resolves to the one in `directory`: a package links `/usr/bin/nrr-cli` to
/// the binary in its private folder. The link is only resolved, never run.
#[must_use]
pub fn reachable_on(list: &OsStr, directory: &Path, style: PathListStyle) -> bool {
    if list_contains_directory(&list.to_string_lossy(), directory, style) {
        return true;
    }
    let name = BinaryRole::Console.host_file_name();
    let Ok(ours) = directory.join(name).canonicalize() else {
        return false;
    };
    // A relative entry depends on the shell's current folder.
    std::env::split_paths(list)
        .filter(|entry| entry.is_absolute())
        .map(|entry| entry.join(name))
        .find(|candidate| candidate.is_file())
        .and_then(|found| found.canonicalize().ok())
        .is_some_and(|found| found == ours)
}

/// The current state, without changing anything.
pub fn state(
    port: &dyn PathRegistrationPort,
    directory: &Path,
) -> Result<ConsolePathState, String> {
    let request = PathRegistrationRequest::for_current_user(directory.to_path_buf());
    let plan = port.plan(&request).map_err(|e| e.to_string())?;
    let owned = port
        .owned_entry_present(&request)
        .map_err(|e| e.to_string())?;
    let reachable = reachable_on_process_path(&request.directory, port);
    Ok(ConsolePathState::from_plan(&plan, reachable, owned))
}

/// Put `directory` on the current user's `PATH`; with it already there this
/// writes nothing and still answers a state to show.
pub fn register(
    port: &dyn PathRegistrationPort,
    directory: &Path,
) -> Result<ConsolePathState, String> {
    let request = PathRegistrationRequest::for_current_user(directory.to_path_buf());
    let plan = port.plan(&request).map_err(|e| e.to_string())?;
    if plan.changes_anything() {
        port.apply(&plan).map_err(|e| e.to_string())?;
    }
    // Re-read: the entry is in the store now, but this process still holds
    // the `PATH` it started with.
    let reachable = reachable_on_process_path(&request.directory, port);
    Ok(ConsolePathState::from_plan(&plan, reachable, true))
}

/// Take OUR entry back off the current user's `PATH`; with nothing of ours
/// there this writes nothing and still answers a state to show.
pub fn unregister(
    port: &dyn PathRegistrationPort,
    directory: &Path,
) -> Result<ConsolePathState, String> {
    let request = PathRegistrationRequest::for_current_user(directory.to_path_buf());
    port.unregister(&request).map_err(|e| e.to_string())?;
    // Re-planned after the write: the plan carries the command for open
    // shells and the target file of the world as it is now.
    let plan = port.plan(&request).map_err(|e| e.to_string())?;
    let reachable = reachable_on_process_path(&request.directory, port);
    Ok(ConsolePathState::from_plan(&plan, reachable, false))
}

/// The folder of `exe`, accepted only with the console beside it: registering
/// a folder that never gains the program would leave the user a change to
/// find and undo by hand. An installed copy's `bin` (links to the console and
/// the terminal UI only) wins: every folder on PATH is a DLL search location.
pub fn console_directory_beside(exe: &Path) -> Result<PathBuf, String> {
    let dir = exe
        .parent()
        .ok_or_else(|| "the running executable has no parent directory".to_string())?;
    let links = dir.join("bin");
    if verify_console_present(&links).is_ok() {
        return Ok(links);
    }
    verify_console_present(dir)?;
    Ok(dir.to_path_buf())
}

fn verify_console_present(dir: &Path) -> Result<(), String> {
    let name = BinaryRole::Console.host_file_name();
    if dir.join(name).is_file() {
        Ok(())
    } else {
        Err(format!("{name} is not present in {}", dir.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_registration::{PathDecision, PathScope};

    fn plan_with(steps: Vec<PathRegistrationStep>, decision: PathDecision) -> PathRegistrationPlan {
        PathRegistrationPlan {
            directory: PathBuf::from("/opt/netrulerouter/bin"),
            scope: PathScope::CurrentUser,
            decision,
            steps,
            current_session_command: "export PATH=\"$PATH:/opt/netrulerouter/bin\"".to_string(),
        }
    }

    #[test]
    fn a_file_based_plan_surfaces_the_file_it_would_write() {
        let plan = plan_with(
            vec![PathRegistrationStep::AppendShellProfileLine {
                path: PathBuf::from("/home/u/.bashrc"),
                line: "export PATH=…".to_string(),
            }],
            PathDecision::Append {
                updated_list: "/usr/bin:/opt/netrulerouter/bin".to_string(),
            },
        );
        let state = ConsolePathState::from_plan(&plan, false, false);
        assert_eq!(state.target_file, Some(PathBuf::from("/home/u/.bashrc")));
        assert!(!state.reachable);
        assert!(!state.owned_entry_present);
        assert!(state
            .current_session_command
            .contains("/opt/netrulerouter/bin"));
    }

    #[test]
    fn an_environment_store_plan_names_no_file() {
        let plan = plan_with(
            vec![PathRegistrationStep::SetUserEnvironmentVariable {
                name: "Path".to_string(),
                value: "…".to_string(),
            }],
            PathDecision::Append {
                updated_list: "…".to_string(),
            },
        );
        assert_eq!(
            ConsolePathState::from_plan(&plan, false, false).target_file,
            None
        );
    }

    #[test]
    fn an_already_registered_state_still_carries_the_command_for_open_shells() {
        // The user may have registered it in a previous session; the terminal
        // they have open right now still predates the change.
        let plan = plan_with(Vec::new(), PathDecision::AlreadyPresent);
        let state = ConsolePathState::from_plan(&plan, true, true);
        assert!(state.reachable);
        assert!(state.owned_entry_present);
        assert_eq!(state.target_file, None);
        assert!(!state.current_session_command.is_empty());
    }

    /// `private/` holds the console; each name in `others` is a folder made
    /// beside it.
    fn layout(others: &[&str]) -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().expect("temp dir");
        let private = root.path().join("private");
        std::fs::create_dir(&private).expect("private dir");
        std::fs::write(
            private.join(BinaryRole::Console.host_file_name()),
            b"console",
        )
        .expect("console");
        for other in others {
            std::fs::create_dir(root.path().join(other)).expect("dir");
        }
        (root, private)
    }

    fn list(dirs: &[PathBuf]) -> std::ffi::OsString {
        std::env::join_paths(dirs).expect("joinable")
    }

    #[test]
    fn the_console_folder_on_the_list_is_reachable() {
        let (root, private) = layout(&["elsewhere"]);
        let path = list(&[root.path().join("elsewhere"), private.clone()]);
        assert!(reachable_on(&path, &private, PathListStyle::host()));
        let path = list(&[root.path().join("elsewhere")]);
        assert!(!reachable_on(&path, &private, PathListStyle::host()));
    }

    #[test]
    fn another_program_of_the_same_name_is_not_the_console() {
        let (root, private) = layout(&["bin"]);
        let bin = root.path().join("bin");
        std::fs::write(bin.join(BinaryRole::Console.host_file_name()), b"other")
            .expect("look-alike");
        assert!(!reachable_on(
            &list(&[bin]),
            &private,
            PathListStyle::host()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_on_the_path_to_the_console_makes_it_reachable() {
        let name = BinaryRole::Console.host_file_name();
        let (root, private) = layout(&["bin", "shadow"]);
        let bin = root.path().join("bin");
        std::os::unix::fs::symlink(private.join(name), bin.join(name)).expect("link");
        assert!(reachable_on(
            &list(std::slice::from_ref(&bin)),
            &private,
            PathListStyle::host()
        ));
        // The name runs the first match; one shadowing the link is not ours.
        let shadow = root.path().join("shadow");
        std::fs::write(shadow.join(name), b"other").expect("shadow");
        assert!(!reachable_on(
            &list(&[shadow, bin]),
            &private,
            PathListStyle::host()
        ));
    }

    #[test]
    fn a_directory_without_the_console_binary_is_refused() {
        let (root, private) = layout(&["empty"]);
        let empty = root.path().join("empty");
        let err = console_directory_beside(&empty.join("nrr-tui")).expect_err("must refuse");
        assert!(err.contains(BinaryRole::Console.host_file_name()), "{err}");
        let found = console_directory_beside(&private.join("nrr-tui")).expect("console there");
        assert_eq!(found, private);
    }

    /// An installed copy keeps its libraries beside the program; a folder on
    /// PATH is searched for DLLs by every program, so only `bin` may go there.
    #[test]
    fn the_links_folder_is_registered_instead_of_the_program_folder() {
        let (_root, private) = layout(&[]);
        let bin = private.join("bin");
        std::fs::create_dir(&bin).expect("bin dir");
        std::fs::write(bin.join(BinaryRole::Console.host_file_name()), b"link").expect("link");
        let found = console_directory_beside(&private.join("nrr-tui")).expect("console there");
        assert_eq!(found, bin);
    }
}
