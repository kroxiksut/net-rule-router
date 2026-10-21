//! The GUI's reader of the installer's first-run answer sheet.
//!
//! The format, the bounded parse and the search order are `nrr_shared::
//! first_run_sheet`, which the terminal client reads through too; this file
//! only supplies where this process looks and how it proves authorship.

use std::env;
use std::path::Path;

use nrr_platform_api::admin_authored::AdminAuthoredFiles;
pub use nrr_shared::first_run_sheet::LoadedProvisioning;
use nrr_shared::first_run_sheet::{candidate_paths, search, Candidate};

/// The machine folder may predate the service, created by any local account,
/// so a sheet there counts only when `machine_files` says no ordinary account
/// could have written it.
pub fn load(machine_files: &dyn AdminAuthoredFiles) -> Option<LoadedProvisioning> {
    let executable = env::current_exe().ok();
    let candidates = candidates(executable.as_deref().and_then(Path::parent));
    let outcome = search(&candidates, &|path| machine_files.untrusted_because(path));
    for note in &outcome.ignored {
        eprintln!("nrr-gui: ignoring {note}");
    }
    outcome.found
}

fn candidates(executable_dir: Option<&Path>) -> Vec<Candidate> {
    candidate_paths(
        executable_dir,
        nrr_platform_api::paths::machine_first_run_dir().as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Linux state root is `0700`: a sheet there was invisible to the GUI.
    #[test]
    fn the_admin_sheet_is_read_from_a_folder_the_session_can_open() {
        let machine: Vec<_> = candidates(None)
            .into_iter()
            .filter(|candidate| candidate.admin_only)
            .map(|candidate| candidate.path)
            .collect();
        if cfg!(target_os = "linux") {
            assert_eq!(
                machine,
                [std::path::PathBuf::from(
                    "/etc/netrulerouter/first-run.json"
                )]
            );
        } else if cfg!(windows) {
            let data_root = nrr_platform_api::paths::production_data_root().expect("ProgramData");
            assert_eq!(machine, [data_root.join("first-run.json")]);
        }
    }
}
