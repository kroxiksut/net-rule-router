//! `ProgramFolders` platform port: which programs a rule by program path
//! covers on this machine.
//!
//! A rule may name one program file, the programs of one folder, or those of a
//! folder and every folder below it. Enforcement acts on real executables, so
//! the port answers what only the OS knows: what sits at a path (a file, a
//! folder, nothing), its real path behind junctions and links, which programs
//! a folder holds, and when a watched folder changes. [`ProgramFolderIndex`]
//! keeps the answers off the traffic path: listings are remembered and
//! watched, a change is listed again after a quiet moment, and the listener
//! hears only of a set of programs that really changed.
//!
//! A listing reads names the OS reports for folders other users may write
//! into: every walk is bounded in entries, depth and results, follows no link
//! and never panics. A folder larger than the bounds is covered in part and
//! says so ([`FolderListing::truncated`]).

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

pub use nrr_shared::app_path::{AppPath, AppPathKind, PathStyle};

use crate::error::PlatformError;
use crate::network_change::{NetworkChangeCallback, NetworkChangeSubscription};

mod index;
mod notify_records;

pub use index::{IndexTiming, ProgramFolderIndex};
pub use notify_records::{
    notify_buffer_is_relevant, notify_records, NotifyRecord, MAX_NOTIFY_RECORDS,
};

/// Most programs one path rule covers. Past it the rule covers this many and
/// reports the folder as larger than it can cover.
pub const PATH_RULE_PROGRAM_CAP: usize = 64;

/// Entries (files and folders) one listing reads, whatever it finds.
pub const LISTING_ENTRY_BUDGET: u32 = 20_000;

/// Folder levels a listing with subfolders descends below the rule's folder.
pub const LISTING_MAX_DEPTH: u32 = 12;

/// Folders watched at once. A rule past them is listed again on the slower
/// refresh instead.
pub const WATCHED_FOLDER_CAP: usize = 32;

/// What sits at a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlaceOnDisk {
    File,
    Folder,
    /// Nothing, or nothing this process may look at.
    Missing,
}

/// The bounds of one listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListingLimits {
    pub entries: u32,
    pub depth: u32,
    pub programs: usize,
}

impl Default for ListingLimits {
    fn default() -> Self {
        Self {
            entries: LISTING_ENTRY_BUDGET,
            depth: LISTING_MAX_DEPTH,
            programs: PATH_RULE_PROGRAM_CAP,
        }
    }
}

/// The programs one listing found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FolderListing {
    /// In walk order: the folder's own programs first, each level sorted.
    pub programs: Vec<PathBuf>,
    /// A bound stopped the walk: the folder holds more than was listed.
    pub truncated: bool,
}

/// How a path rule met the disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathOutcome {
    /// The place exists; [`PathPrograms::programs`] is what it holds.
    Found,
    /// Nothing is there yet.
    Missing,
    /// The place lies in another user's profile and is not read for this
    /// rule's owner.
    OtherUsersFolder,
    /// This platform cannot apply rules by path.
    Unsupported,
}

impl PathOutcome {
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Found => "found",
            Self::Missing => "missing",
            Self::OtherUsersFolder => "other-users-folder",
            Self::Unsupported => "unsupported",
        }
    }
}

/// What a rule by program path covers for one owner, as one pass finds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathPrograms {
    pub outcome: PathOutcome,
    /// The rule as the disk has it: its real place, with a path that waited
    /// for the disk decided. `None` when nothing is there.
    pub place: Option<AppPath>,
    /// Real paths of the programs covered, at most [`PATH_RULE_PROGRAM_CAP`].
    pub programs: Vec<PathBuf>,
    /// The folder holds more than the rule covers.
    pub over_cap: bool,
}

impl PathPrograms {
    #[must_use]
    pub fn unsupported() -> Self {
        Self::empty(PathOutcome::Unsupported)
    }

    #[must_use]
    pub fn missing() -> Self {
        Self::empty(PathOutcome::Missing)
    }

    fn empty(outcome: PathOutcome) -> Self {
        Self {
            outcome,
            place: None,
            programs: Vec::new(),
            over_cap: false,
        }
    }
}

/// The OS half of path rules. Every method is best-effort: a path the OS will
/// not answer for reads as missing, never as an error.
pub trait ProgramFolders: Send + Sync {
    /// How this platform spells and compares paths.
    fn path_style(&self) -> PathStyle;

    /// What sits at `path`, following links.
    fn place(&self, path: &Path) -> PlaceOnDisk;

    /// The real path of `path`: every junction and link resolved, in the
    /// spelling the OS reports a running program's image with.
    fn real_path(&self, path: &Path) -> Option<PathBuf>;

    /// Whether the file at `path` is a program this platform runs.
    fn is_program(&self, path: &Path) -> bool;

    /// The programs of `folder` (and, with `subfolders`, of every folder
    /// below it), within [`ListingLimits::default`].
    fn list(&self, folder: &Path, subfolders: bool) -> FolderListing {
        list_programs(
            folder,
            subfolders,
            self.path_style(),
            &|path| self.is_program(path),
            ListingLimits::default(),
        )
    }

    /// Whether `place` lies in the profile of a user other than `owner`
    /// (a stored principal: a SID, `uid:N`). Such a folder is not read for
    /// `owner`: one user's rule never decides for another user's programs.
    fn foreign_profile(&self, _place: &Path, _owner: &str) -> bool {
        false
    }

    /// The profile (home) folder of `owner`, where a rule written from
    /// `%LOCALAPPDATA%` or `~` starts for that owner. `None` for an owner
    /// that names no user, or one this machine keeps no profile for: such a
    /// rule then covers nothing for them.
    fn owner_profile(&self, _owner: &str) -> Option<PathBuf> {
        None
    }

    /// Whether `owner` may list the folder at `place` (for a file, the folder
    /// holding it) under the file system's own permissions. The service reads
    /// every folder; an answer about one closed to `owner` tells them what
    /// they could not see. Best-effort: a place or an owner the OS cannot
    /// judge reads as `true`, as it did before anyone asked.
    fn owner_may_list(&self, _place: &Path, _owner: &str) -> bool {
        true
    }

    /// Whether any account may put a program at `place`, or create it first
    /// where it is missing (`/tmp`, `C:\Users\Public`). What runs from such
    /// a place vouches for nothing. Best-effort: unreadable reads as `false`.
    fn writable_by_anyone(&self, place: &Path) -> bool {
        writable_by_anyone_unix(place)
    }

    /// Calls `on_change` when something in `folder` (and, with `subfolders`,
    /// below it) may have changed which programs it holds. Dropping the
    /// subscription ends the watch. Coalescing is the caller's job.
    ///
    /// # Errors
    ///
    /// [`PlatformError::NotSupported`] where the platform has no watch; the
    /// caller then lists the folder again on its slower refresh.
    fn watch(
        &self,
        _folder: &Path,
        _subfolders: bool,
        _on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        Err(PlatformError::NotSupported {
            reason: "no folder watch on this platform",
        })
    }

    /// Which folder object sits at `folder` now (volume and file id, device
    /// and inode). A watch follows the folder it opened; when another folder
    /// is renamed into its place this answer changes. `None`: unknown.
    fn identity(&self, _folder: &Path) -> Option<u128> {
        None
    }
}

/// What `path` covers for `owner` now, read straight from `folders`: nothing
/// remembered, nothing watched, within the same bounds. For a question asked
/// once, such as the count a rule form shows; a pass asks a
/// [`ProgramFolderIndex`].
#[must_use]
pub fn path_programs_once(
    folders: &dyn ProgramFolders,
    path: &AppPath,
    owner: &str,
) -> PathPrograms {
    index::covered(
        folders,
        path,
        owner,
        &|text| {
            let at = Path::new(text);
            let kind = folders.place(at);
            let real = match kind {
                PlaceOnDisk::Missing => None,
                PlaceOnDisk::File | PlaceOnDisk::Folder => folders.real_path(at),
            };
            (kind, real)
        },
        &|folder, subfolders| {
            let listing = folders.list(&folder, subfolders);
            visible_to_owner(listing, &folder, &|dir| folders.owner_may_list(dir, owner))
        },
    )
}

/// `listing` with the programs of every subfolder `may_list` closes left out:
/// the walk reads as the service, and a count of what is inside a folder the
/// owner cannot open tells them what they could not see. `root` was judged
/// before the walk. Each folder is asked once.
fn visible_to_owner(
    mut listing: FolderListing,
    root: &Path,
    may_list: &dyn Fn(&Path) -> bool,
) -> FolderListing {
    let mut judged: std::collections::HashMap<PathBuf, bool> = std::collections::HashMap::new();
    listing.programs.retain(|program| {
        let mut dir = program.parent();
        while let Some(at) = dir.filter(|at| *at != root && at.starts_with(root)) {
            let open = *judged
                .entry(at.to_path_buf())
                .or_insert_with(|| may_list(at));
            if !open {
                return false;
            }
            dir = at.parent();
        }
        true
    });
    listing
}

/// The programs under `folder`, breadth first, each folder's entries sorted
/// as `style` compares names, so the same folder lists the same way on every
/// pass and a bound cuts it at the same place.
///
/// Links are never followed: a link back up the tree cannot make the walk
/// loop, and a link out of it cannot widen the rule. The entry budget is spent
/// per entry read, programs or not; a folder whose entries outrun it is left
/// out whole rather than in an order the OS happened to return.
#[must_use]
pub fn list_programs(
    folder: &Path,
    subfolders: bool,
    style: PathStyle,
    is_program: &dyn Fn(&Path) -> bool,
    limits: ListingLimits,
) -> FolderListing {
    let mut out = FolderListing::default();
    let mut budget = limits.entries;
    let mut queue: VecDeque<(PathBuf, u32)> = VecDeque::new();
    queue.push_back((folder.to_path_buf(), 0));
    while let Some((dir, depth)) = queue.pop_front() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut listed: Vec<(PathBuf, std::fs::FileType)> = Vec::new();
        for entry in entries.flatten() {
            if budget == 0 {
                out.truncated = true;
                return out;
            }
            budget -= 1;
            if let Ok(file_type) = entry.file_type() {
                listed.push((entry.path(), file_type));
            }
        }
        listed.sort_by_cached_key(|(path, _)| sort_key(path, style));
        for (path, file_type) in listed {
            if file_type.is_dir() {
                if !subfolders {
                    continue;
                }
                if depth < limits.depth {
                    queue.push_back((path, depth + 1));
                } else {
                    out.truncated = true;
                }
            } else if file_type.is_file() && is_program(&path) {
                if out.programs.len() >= limits.programs {
                    out.truncated = true;
                    return out;
                }
                out.programs.push(path);
            }
        }
    }
    out
}

fn sort_key(path: &Path, style: PathStyle) -> String {
    let text = path.to_string_lossy();
    if style.case_insensitive() {
        text.to_lowercase()
    } else {
        text.into_owned()
    }
}

/// `\\?\C:\…` to `C:\…`, the spelling Windows reports a running program's
/// image with. A share (`\\?\UNC\…`) and any other path are left alone.
#[must_use]
pub fn strip_verbatim_drive_prefix(path: PathBuf) -> PathBuf {
    let stripped = path
        .to_str()
        .and_then(|text| text.strip_prefix(r"\\?\"))
        .filter(|rest| rest.as_bytes().get(1) == Some(&b':'))
        .map(PathBuf::from);
    stripped.unwrap_or(path)
}

/// Extensions of the files programs keep writing beside themselves: logs,
/// caches, locks. A change feed entry for one of them cannot change which
/// programs a folder holds, and a busy log must not keep listing its folder.
const NOISE_EXTENSIONS: &[&str] = &[
    ".log",
    ".tmp",
    ".etl",
    ".lock",
    ".json",
    ".txt",
    ".ldb",
    ".db",
    ".db-journal",
    ".db-wal",
    ".db-shm",
    ".dmp",
    ".old",
    ".bak",
];

/// Whether a change feed entry for `name` (a file or folder name, possibly
/// with the levels below the watched folder) may change which programs the
/// folder holds. A cheap pre-filter: the listing that follows decides.
#[must_use]
pub fn name_may_change_programs(name: &str) -> bool {
    let last = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let last = last.to_ascii_lowercase();
    !NOISE_EXTENSIONS.iter().any(|ext| last.ends_with(ext))
}

/// Whether `name` is spelled like a Windows program.
#[must_use]
pub fn name_is_windows_program(name: &str) -> bool {
    name.len() > 4
        && name
            .get(name.len() - 4..)
            .is_some_and(|ext| ext.eq_ignore_ascii_case(".exe"))
}

/// The portable mechanism: `std::fs` for places, real paths and listings, no
/// watch. What a platform without a backend of its own uses, macOS included.
#[derive(Clone, Copy, Debug)]
pub struct StdProgramFolders {
    style: PathStyle,
}

impl StdProgramFolders {
    #[must_use]
    pub const fn new(style: PathStyle) -> Self {
        Self { style }
    }

    /// The style of the platform this build runs on.
    #[must_use]
    pub fn for_this_platform() -> Self {
        Self::new(nrr_domain::rules_file::HostPlatform::compiled().path_style())
    }
}

impl ProgramFolders for StdProgramFolders {
    fn path_style(&self) -> PathStyle {
        self.style
    }

    fn place(&self, path: &Path) -> PlaceOnDisk {
        place_of(path)
    }

    fn real_path(&self, path: &Path) -> Option<PathBuf> {
        std::fs::canonicalize(path)
            .ok()
            .map(strip_verbatim_drive_prefix)
    }

    fn is_program(&self, path: &Path) -> bool {
        is_program_file(path, self.style)
    }
}

/// [`ProgramFolders::place`] over `std::fs`.
#[must_use]
pub fn place_of(path: &Path) -> PlaceOnDisk {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => PlaceOnDisk::Folder,
        Ok(meta) if meta.is_file() => PlaceOnDisk::File,
        _ => PlaceOnDisk::Missing,
    }
}

/// A Windows program ends in `.exe`; a Unix one is a regular file with an
/// execute bit.
#[must_use]
pub fn is_program_file(path: &Path, style: PathStyle) -> bool {
    match style {
        PathStyle::Windows => {
            path.extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
                && path.is_file()
        }
        PathStyle::Linux | PathStyle::MacOS => has_execute_bit(path),
    }
}

#[cfg(unix)]
fn has_execute_bit(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn has_execute_bit(_path: &Path) -> bool {
    false
}

/// Folder levels [`writable_by_anyone_unix`] climbs; a deeper path is judged
/// by its lowest levels only.
#[cfg(unix)]
const WRITABLE_CHECK_DEPTH: usize = 64;

/// [`ProgramFolders::writable_by_anyone`] by Unix permissions: the place, or
/// any folder above it, carries the write bit for others (`/tmp`, `/var/tmp`
/// and `/dev/shm` do, sticky or not: anyone may create a folder there first).
#[cfg(unix)]
#[must_use]
pub fn writable_by_anyone_unix(place: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    place
        .ancestors()
        .take(WRITABLE_CHECK_DEPTH)
        .filter_map(|level| std::fs::metadata(level).ok())
        .any(|meta| meta.is_dir() && meta.permissions().mode() & 0o002 != 0)
}

#[cfg(not(unix))]
#[must_use]
pub fn writable_by_anyone_unix(_place: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests;
