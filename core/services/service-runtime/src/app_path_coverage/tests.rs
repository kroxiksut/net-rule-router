use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use nrr_domain::rules_file::HostPlatform;
use nrr_platform_api::app_folders::{FolderListing, PathStyle, PlaceOnDisk};

use super::*;

const ALICE: &str = "unix:uid:1000";
const BOB: &str = "unix:uid:1001";

/// Two homes, a shared scratch folder, a program folder under `/opt`, and a
/// count of every time the disk was looked at.
#[derive(Default)]
struct Machine {
    looked: AtomicUsize,
}

impl ProgramFolders for Machine {
    fn path_style(&self) -> PathStyle {
        PathStyle::Linux
    }

    fn place(&self, path: &Path) -> PlaceOnDisk {
        self.looked.fetch_add(1, Ordering::SeqCst);
        let known = [
            "/home/a/apps",
            "/home/b/apps",
            "/tmp/tools",
            "/opt/tool",
            "/usr/bin",
        ];
        if known.iter().any(|folder| path == Path::new(folder)) {
            PlaceOnDisk::Folder
        } else {
            PlaceOnDisk::Missing
        }
    }

    fn real_path(&self, path: &Path) -> Option<PathBuf> {
        Some(path.to_path_buf())
    }

    fn is_program(&self, _path: &Path) -> bool {
        true
    }

    fn list(&self, folder: &Path, _subfolders: bool) -> FolderListing {
        self.looked.fetch_add(1, Ordering::SeqCst);
        FolderListing {
            programs: (0..3).map(|i| folder.join(format!("run{i}"))).collect(),
            truncated: false,
        }
    }

    fn foreign_profile(&self, place: &Path, owner: &str) -> bool {
        (place.starts_with("/home/a") && owner != ALICE)
            || (place.starts_with("/home/b") && owner != BOB)
    }

    fn owner_profile(&self, owner: &str) -> Option<PathBuf> {
        match owner {
            ALICE => Some(PathBuf::from("/home/a")),
            BOB => Some(PathBuf::from("/home/b")),
            _ => None,
        }
    }

    fn writable_by_anyone(&self, place: &Path) -> bool {
        place.starts_with("/tmp")
    }
}

fn ask(machine: &Arc<Machine>, value: &str, route: &str, owner: &str) -> AppPathCoverageResponse {
    let coverage = AppPathCoverage::new(Arc::clone(machine) as Arc<dyn ProgramFolders>, true);
    let request = AppPathCoverageRequest {
        value: value.to_string(),
        route: route.to_string(),
    };
    coverage.coverage_in(
        &request,
        owner,
        &ProtectedPlaces::defaults(HostPlatform::Linux),
    )
}

/// One rule from `~` counts the asker's own programs and says where they are.
#[test]
fn a_rule_from_the_home_folder_counts_the_askers_own_programs() {
    let machine = Arc::new(Machine::default());
    let answer = ask(&machine, "~/apps/*", "secondary", ALICE);
    assert_eq!(answer.outcome, APP_PATH_COVERAGE_FOUND);
    assert_eq!(answer.form, "folder-tree");
    assert_eq!(answer.programs, 3);
    assert!(!answer.truncated);
    assert_eq!(answer.place, "/home/a/apps/*");
    assert!(!answer.anyone_can_write);
    assert!(answer.refusal_key.is_empty());
    let bobs = ask(&machine, "~/apps/*", "secondary", BOB);
    assert_eq!(bobs.place, "/home/b/apps/*");
}

/// A rule of one user on another user's folder is refused, and that folder
/// is not even looked at.
#[test]
fn a_folder_in_another_users_home_is_refused_unread() {
    let machine = Arc::new(Machine::default());
    let answer = ask(&machine, "/home/b/apps/*", "primary", ALICE);
    assert_eq!(answer.outcome, APP_PATH_COVERAGE_REFUSED);
    assert_eq!(answer.refusal_key, OTHER_USERS_FOLDER_KEY);
    assert_eq!(answer.programs, 0);
    assert_eq!(machine.looked.load(Ordering::SeqCst), 0);
    assert_eq!(
        ask(&machine, "/home/b/apps/*", "primary", BOB).outcome,
        APP_PATH_COVERAGE_FOUND
    );
}

#[test]
fn a_folder_anyone_may_write_into_is_counted_with_a_warning() {
    let machine = Arc::new(Machine::default());
    let answer = ask(&machine, "/tmp/tools/*", "secondary", ALICE);
    assert_eq!(answer.outcome, APP_PATH_COVERAGE_FOUND);
    assert!(answer.anyone_can_write);
    let missing = ask(&machine, "/tmp/later/", "secondary", ALICE);
    assert_eq!(missing.outcome, APP_PATH_COVERAGE_MISSING);
    assert!(missing.anyone_can_write, "a folder not made yet warns too");
}

/// A protected folder is refused before it is listed.
#[test]
fn a_protected_folder_is_refused_before_it_is_listed() {
    let machine = Arc::new(Machine::default());
    let answer = ask(&machine, "/usr/bin/*", "block", ALICE);
    assert_eq!(answer.outcome, APP_PATH_COVERAGE_REFUSED);
    assert!(
        answer
            .refusal_key
            .starts_with("rules.validation.match-value-invalid.protected-"),
        "{}",
        answer.refusal_key
    );
    assert_eq!(machine.looked.load(Ordering::SeqCst), 0);
}

#[test]
fn names_and_broken_paths_are_answered_without_the_disk() {
    let machine = Arc::new(Machine::default());
    let name = ask(&machine, "firefox +children", "primary", ALICE);
    assert_eq!(name.form, "name");
    assert_eq!(name.outcome, APP_PATH_COVERAGE_NOT_A_PATH);
    let broken = ask(&machine, "~bob/apps/", "primary", ALICE);
    assert_eq!(broken.form, "path-unknown-variable");
    assert_eq!(broken.outcome, APP_PATH_COVERAGE_INVALID);
    let nothing = ask(&machine, "/opt/absent/", "primary", ALICE);
    assert_eq!(nothing.outcome, APP_PATH_COVERAGE_MISSING);
    assert_eq!(nothing.place, "/opt/absent/");
    let nobody = ask(&machine, "~/apps/", "primary", "baseline");
    assert_eq!(nobody.outcome, APP_PATH_COVERAGE_MISSING);
    assert!(nobody.place.is_empty());
}

#[test]
fn a_platform_without_path_rules_says_so() {
    let coverage = AppPathCoverage::new(Arc::new(Machine::default()), false);
    let request = AppPathCoverageRequest {
        value: "/opt/tool/*".into(),
        route: String::new(),
    };
    assert_eq!(
        coverage.coverage(&request, ALICE).outcome,
        APP_PATH_COVERAGE_UNSUPPORTED
    );
}

/// The shared baseline may name a user's folder only through a profile
/// folder; a user only their own.
#[test]
fn a_full_path_into_a_profile_is_foreign_to_everyone_but_its_owner() {
    let coverage = AppPathCoverage::new(Arc::new(Machine::default()), true);
    let bobs = AppPath::parse("/home/b/apps/*", PathStyle::Linux).expect("path");
    assert!(coverage.names_foreign_profile(&bobs, ALICE));
    assert!(!coverage.names_foreign_profile(&bobs, BOB));
    assert!(coverage.names_foreign_profile(&bobs, nrr_storage::BASELINE_PRINCIPAL));
    let own = AppPath::parse("~/apps/*", PathStyle::Linux).expect("path");
    assert!(!coverage.names_foreign_profile(&own, nrr_storage::BASELINE_PRINCIPAL));
}
