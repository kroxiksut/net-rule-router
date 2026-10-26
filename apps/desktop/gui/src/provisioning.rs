//! The GUI's reader of the installer's first-run answer sheet.
//!
//! The format, the bounded parse and the search order are `nrr_shared::
//! first_run_sheet`, the places are `nrr_platform_api::paths::
//! first_run_sheet_candidates`, both shared with the terminal client; this
//! file only supplies the running program's folder and how authorship is
//! proved.

use std::env;
use std::path::Path;

use nrr_platform_api::admin_authored::AdminAuthoredFiles;
use nrr_shared::first_run_sheet::search;
pub use nrr_shared::first_run_sheet::LoadedProvisioning;

/// A sheet that must come from an administrator counts only when
/// `machine_files` says no ordinary account could have written it.
pub fn load(machine_files: &dyn AdminAuthoredFiles) -> Option<LoadedProvisioning> {
    let executable = env::current_exe().ok();
    load_from(executable.as_deref().and_then(Path::parent), machine_files)
}

fn load_from(
    executable_dir: Option<&Path>,
    machine_files: &dyn AdminAuthoredFiles,
) -> Option<LoadedProvisioning> {
    let candidates = nrr_platform_api::paths::first_run_sheet_candidates(executable_dir);
    let outcome = search(&candidates, &|path| machine_files.open_admin_authored(path));
    for note in &outcome.ignored {
        eprintln!("nrr-gui: ignoring {note}");
    }
    outcome.found
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::first_run_sheet::PROVISIONING_FILE_NAME;

    struct Verdict(Option<&'static str>);

    impl AdminAuthoredFiles for Verdict {
        fn open_admin_authored(
            &self,
            path: &Path,
        ) -> nrr_platform_api::admin_authored::AdminAuthored {
            use nrr_platform_api::admin_authored::AdminAuthored;
            match (self.0, std::fs::File::open(path)) {
                (_, Err(_)) => AdminAuthored::Missing,
                (Some(why), Ok(_)) => AdminAuthored::Refused(why.to_owned()),
                (None, Ok(file)) => AdminAuthored::Opened(file),
            }
        }
    }

    /// A folder standing for the program's own, removed on drop.
    struct InstallDir(std::path::PathBuf);

    impl InstallDir {
        fn with_sheet(name: &str) -> Self {
            let dir = env::temp_dir().join(format!("nrr-gui-{name}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("mkdir");
            std::fs::write(
                dir.join(PROVISIONING_FILE_NAME),
                r#"{"leak-protection":"off","doh-lockdown":false,"fake-ip":false,"rule-set":"none"}"#,
            )
            .expect("write");
            Self(dir)
        }
    }

    impl Drop for InstallDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The sheet an administrator left beside the program sets the window up,
    /// wherever the program was installed.
    #[test]
    fn a_sheet_beside_the_program_in_an_administrators_folder_is_read() {
        let install = InstallDir::with_sheet("admin");
        let found = load_from(Some(&install.0), &Verdict(None)).expect("sheet");
        assert_eq!(found.source_path, install.0.join(PROVISIONING_FILE_NAME));
    }

    /// On Windows a copy of the program in a folder anyone can write must not
    /// seed the setup of whoever runs it.
    #[cfg(windows)]
    #[test]
    fn a_sheet_beside_the_program_in_a_folder_anyone_can_write_is_refused() {
        let install = InstallDir::with_sheet("open");
        assert_eq!(
            load_from(Some(&install.0), &Verdict(Some("anyone can add files"))),
            None
        );
    }
}
