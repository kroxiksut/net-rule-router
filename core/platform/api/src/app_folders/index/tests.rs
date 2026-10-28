use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::app_folders::{path_programs_once, PathStyle};

const OWNER: &str = "uid:1000";
const OTHER: &str = "uid:1001";

/// A port over a scripted machine: one folder whose programs the test sets,
/// a link, a file, and watches whose callbacks the test fires by hand.
#[derive(Default)]
struct FakeFolders {
    programs: Mutex<Vec<PathBuf>>,
    lists: AtomicUsize,
    places: AtomicUsize,
    callbacks: Mutex<Vec<NetworkChangeCallback>>,
    /// Profiles: `(owner, folder prefix)` pairs that belong to that owner.
    profiles: Vec<(&'static str, &'static str)>,
    /// Which folder object sits at the rule's path; a swap changes it.
    identity: Mutex<u128>,
}

impl FakeFolders {
    fn holding(count: usize) -> Self {
        let fake = Self::default();
        fake.set_programs(count);
        fake
    }

    fn set_programs(&self, count: usize) {
        *self.programs.lock().expect("lock") = (0..count)
            .map(|i| PathBuf::from(format!("/opt/app/bin{i}")))
            .collect();
    }

    fn fire(&self) {
        let callbacks = self.callbacks.lock().expect("lock").clone();
        for callback in callbacks {
            callback();
        }
    }
}

impl ProgramFolders for FakeFolders {
    fn path_style(&self) -> PathStyle {
        PathStyle::Linux
    }

    fn place(&self, path: &Path) -> PlaceOnDisk {
        self.places.fetch_add(1, Ordering::SeqCst);
        match path.to_string_lossy().trim_end_matches('/') {
            "/opt/app" | "/opt/link" | "/home/b/app" => PlaceOnDisk::Folder,
            "/opt/tool" => PlaceOnDisk::File,
            _ => PlaceOnDisk::Missing,
        }
    }

    fn real_path(&self, path: &Path) -> Option<PathBuf> {
        let text = path.to_string_lossy();
        let text = text.trim_end_matches('/');
        Some(PathBuf::from(if text == "/opt/link" {
            "/opt/app"
        } else {
            text
        }))
    }

    fn is_program(&self, _path: &Path) -> bool {
        true
    }

    fn list(&self, _folder: &Path, _subfolders: bool) -> FolderListing {
        self.lists.fetch_add(1, Ordering::SeqCst);
        FolderListing {
            programs: self.programs.lock().expect("lock").clone(),
            truncated: false,
        }
    }

    fn foreign_profile(&self, place: &Path, owner: &str) -> bool {
        let place = place.to_string_lossy();
        self.profiles
            .iter()
            .any(|(who, prefix)| *who != owner && place.starts_with(prefix))
    }

    fn watch(
        &self,
        _folder: &Path,
        _subfolders: bool,
        on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        self.callbacks.lock().expect("lock").push(on_change);
        Ok(NetworkChangeSubscription::inert())
    }

    fn identity(&self, _folder: &Path) -> Option<u128> {
        Some(*self.identity.lock().expect("lock"))
    }
}

fn rule(text: &str) -> AppPath {
    AppPath::parse(text, PathStyle::Linux).expect("a path")
}

fn quick() -> IndexTiming {
    IndexTiming {
        debounce: Duration::from_millis(40),
        max_delay: Duration::from_secs(2),
        ..IndexTiming::default()
    }
}

fn counting(index: &ProgramFolderIndex) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    index.set_listener(Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    }));
    calls
}

#[test]
fn a_folder_rule_covers_what_the_folder_holds_and_is_listed_once_per_pass_burst() {
    let fake = Arc::new(FakeFolders::holding(3));
    let index = ProgramFolderIndex::new(Arc::clone(&fake) as Arc<dyn ProgramFolders>);
    let first = index.programs(&rule("/opt/app/*"), OWNER);
    assert_eq!(first.outcome, PathOutcome::Found);
    assert_eq!(first.programs.len(), 3);
    assert!(!first.over_cap);
    assert_eq!(
        first.place.as_ref().map(AppPath::as_str),
        Some("/opt/app/*")
    );
    for _ in 0..5 {
        assert_eq!(index.programs(&rule("/opt/app/*"), OWNER), first);
    }
    assert_eq!(
        fake.lists.load(Ordering::SeqCst),
        1,
        "remembered, not re-listed"
    );
    assert_eq!(fake.places.load(Ordering::SeqCst), 1, "the place too");
    assert_eq!(
        fake.callbacks.lock().expect("lock").len(),
        1,
        "watched once"
    );
}

/// An installer writes a burst; one listing follows it, and the listener hears
/// of it once — the re-apply runs off the traffic path, not per file.
#[test]
fn a_burst_of_changes_is_listed_once_and_reported_once() {
    let fake = Arc::new(FakeFolders::holding(2));
    let index =
        ProgramFolderIndex::with_timing(Arc::clone(&fake) as Arc<dyn ProgramFolders>, quick());
    let calls = counting(&index);
    let _ = index.programs(&rule("/opt/app/*"), OWNER);
    fake.set_programs(3);
    for _ in 0..10 {
        fake.fire();
    }
    index.wait_idle();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(index.generation(), 1);
    assert_eq!(
        fake.lists.load(Ordering::SeqCst),
        2,
        "one listing for the burst"
    );
    // The pass that follows reads the new set without listing again.
    assert_eq!(index.programs(&rule("/opt/app/*"), OWNER).programs.len(), 3);
    assert_eq!(fake.lists.load(Ordering::SeqCst), 2);
}

/// An updater renames the folder away and puts a new one in its place. The
/// watch follows the old folder and stays silent; the new folder's programs
/// must still be covered without waiting out the long watched refresh.
#[test]
fn a_folder_swapped_in_by_rename_is_listed_again_and_watched_anew() {
    let fake = Arc::new(FakeFolders::holding(2));
    let index = ProgramFolderIndex::with_timing(
        Arc::clone(&fake) as Arc<dyn ProgramFolders>,
        IndexTiming {
            unwatched_ttl: Duration::ZERO,
            ..quick()
        },
    );
    assert_eq!(index.programs(&rule("/opt/app/*"), OWNER).programs.len(), 2);
    assert_eq!(index.programs(&rule("/opt/app/*"), OWNER).programs.len(), 2);
    assert_eq!(
        fake.lists.load(Ordering::SeqCst),
        1,
        "unchanged: no relisting"
    );

    fake.set_programs(3);
    *fake.identity.lock().expect("lock") = 7;
    assert_eq!(index.programs(&rule("/opt/app/*"), OWNER).programs.len(), 3);
    assert_eq!(
        fake.callbacks.lock().expect("lock").len(),
        2,
        "the folder now at the path is watched"
    );
}

/// A log written beside the programs reaches the watch, but the set did not
/// move: nobody is asked to re-apply.
#[test]
fn a_change_that_leaves_the_programs_alone_is_not_reported() {
    let fake = Arc::new(FakeFolders::holding(2));
    let index =
        ProgramFolderIndex::with_timing(Arc::clone(&fake) as Arc<dyn ProgramFolders>, quick());
    let calls = counting(&index);
    let _ = index.programs(&rule("/opt/app/"), OWNER);
    fake.fire();
    index.wait_idle();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(index.generation(), 0);
    assert_eq!(fake.lists.load(Ordering::SeqCst), 2, "it was looked at");
}

#[test]
fn a_folder_larger_than_the_cap_is_covered_in_part_and_says_so() {
    let fake = Arc::new(FakeFolders::holding(PATH_RULE_PROGRAM_CAP + 10));
    let index = ProgramFolderIndex::new(fake as Arc<dyn ProgramFolders>);
    let answer = index.programs(&rule("/opt/app/*"), OWNER);
    assert_eq!(answer.programs.len(), PATH_RULE_PROGRAM_CAP);
    assert!(answer.over_cap);
}

/// One user's rule never reads another user's folder, and never decides for
/// the programs in it.
#[test]
fn a_folder_in_another_users_profile_is_not_read_for_the_owner() {
    let fake = Arc::new(FakeFolders {
        profiles: vec![(OTHER, "/home/b")],
        ..FakeFolders::holding(2)
    });
    let index = ProgramFolderIndex::new(Arc::clone(&fake) as Arc<dyn ProgramFolders>);
    let refused = index.programs(&rule("/home/b/app/*"), OWNER);
    assert_eq!(refused.outcome, PathOutcome::OtherUsersFolder);
    assert!(refused.programs.is_empty());
    assert_eq!(fake.lists.load(Ordering::SeqCst), 0, "not even listed");
    let own = index.programs(&rule("/home/b/app/*"), OTHER);
    assert_eq!(own.outcome, PathOutcome::Found);
    assert_eq!(own.programs.len(), 2);
}

#[test]
fn the_disk_decides_an_undecided_path_and_its_real_place() {
    let fake = Arc::new(FakeFolders::holding(1));
    let index = ProgramFolderIndex::new(fake as Arc<dyn ProgramFolders>);
    let file = index.programs(&rule("/opt/tool"), OWNER);
    assert_eq!(file.programs, vec![PathBuf::from("/opt/tool")]);
    assert_eq!(
        file.place.as_ref().map(AppPath::kind),
        Some(AppPathKind::File)
    );
    let folder = index.programs(&rule("/opt/link"), OWNER);
    assert_eq!(
        folder.place.as_ref().map(AppPath::as_str),
        Some("/opt/app/"),
        "a link is followed to the folder it names"
    );
    assert_eq!(
        folder.place.as_ref().map(AppPath::kind),
        Some(AppPathKind::Folder)
    );
}

/// A folder that does not exist yet is asked about again on the next pass,
/// so it is covered as soon as it appears.
#[test]
fn a_missing_place_is_asked_again_every_time() {
    let fake = Arc::new(FakeFolders::holding(1));
    let index = ProgramFolderIndex::new(Arc::clone(&fake) as Arc<dyn ProgramFolders>);
    for _ in 0..3 {
        assert_eq!(
            index.programs(&rule("/opt/later/*"), OWNER).outcome,
            PathOutcome::Missing
        );
    }
    assert_eq!(fake.places.load(Ordering::SeqCst), 3);
}

/// A folder no pass asked about for a while is forgotten with its watch:
/// a deleted rule does not keep a folder watched for the life of the service.
#[test]
fn a_folder_no_rule_asks_about_is_forgotten() {
    let fake = Arc::new(FakeFolders::holding(1));
    let timing = IndexTiming {
        forget_after: Duration::ZERO,
        ..quick()
    };
    let index =
        ProgramFolderIndex::with_timing(Arc::clone(&fake) as Arc<dyn ProgramFolders>, timing);
    let calls = counting(&index);
    let _ = index.programs(&rule("/opt/app/*"), OWNER);
    // The next ask for another folder sweeps the first one out.
    let _ = index.programs(&rule("/opt/link/"), OWNER);
    fake.set_programs(4);
    let callbacks = fake.callbacks.lock().expect("lock").clone();
    if let Some(first) = callbacks.first() {
        first();
    }
    index.wait_idle();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a forgotten folder reports nothing"
    );
}

/// Two users' homes, each holding `apps/run`.
struct Homes;

impl ProgramFolders for Homes {
    fn path_style(&self) -> PathStyle {
        PathStyle::Linux
    }

    fn place(&self, path: &Path) -> PlaceOnDisk {
        if path.starts_with("/home/a/apps") || path.starts_with("/home/b/apps") {
            PlaceOnDisk::Folder
        } else {
            PlaceOnDisk::Missing
        }
    }

    fn real_path(&self, path: &Path) -> Option<PathBuf> {
        Some(PathBuf::from(
            path.to_string_lossy().trim_end_matches('/').to_string(),
        ))
    }

    fn is_program(&self, _path: &Path) -> bool {
        true
    }

    fn list(&self, folder: &Path, _subfolders: bool) -> FolderListing {
        FolderListing {
            programs: vec![folder.join("run")],
            truncated: false,
        }
    }

    fn foreign_profile(&self, place: &Path, owner: &str) -> bool {
        (place.starts_with("/home/a") && owner != OWNER)
            || (place.starts_with("/home/b") && owner != OTHER)
    }

    fn owner_profile(&self, owner: &str) -> Option<PathBuf> {
        match owner {
            OWNER => Some(PathBuf::from("/home/a")),
            OTHER => Some(PathBuf::from("/home/b")),
            _ => None,
        }
    }
}

/// One rule written from `~` covers each owner's own folder; an owner with no
/// profile gets nothing rather than somebody else's.
#[test]
fn a_rule_from_the_home_folder_covers_each_owners_own() {
    let index = ProgramFolderIndex::new(Arc::new(Homes));
    let from_home = rule("~/apps/*");
    assert_eq!(
        index.programs(&from_home, OWNER).programs,
        vec![PathBuf::from("/home/a/apps/run")]
    );
    assert_eq!(
        index.programs(&from_home, OTHER).programs,
        vec![PathBuf::from("/home/b/apps/run")]
    );
    let nobody = index.programs(&from_home, "baseline");
    assert_eq!(nobody.outcome, PathOutcome::Missing);
    assert!(nobody.programs.is_empty());
}

/// A literal path in another user's home is refused before the disk is
/// looked at, by the index and by the one-off read alike.
#[test]
fn another_users_folder_is_refused_before_the_disk_is_read() {
    let fake = Arc::new(FakeFolders {
        profiles: vec![(OTHER, "/home/b")],
        ..FakeFolders::holding(2)
    });
    let once = path_programs_once(fake.as_ref(), &rule("/home/b/app/*"), OWNER);
    assert_eq!(once.outcome, PathOutcome::OtherUsersFolder);
    assert_eq!(fake.places.load(Ordering::SeqCst), 0, "not even looked at");
    let own = path_programs_once(fake.as_ref(), &rule("/home/b/app/*"), OTHER);
    assert_eq!(own.outcome, PathOutcome::Found);
    assert_eq!(own.programs.len(), 2);
    assert!(
        fake.callbacks.lock().expect("lock").is_empty(),
        "nothing watched"
    );
}
