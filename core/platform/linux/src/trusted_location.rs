//! Whether a file root relies on is out of reach of ordinary accounts.
//!
//! A path is only as safe as every directory above it: whoever may rename or
//! replace an entry anywhere up the chain can put another file at the same
//! name. So the file, its folder and each ancestor must belong to root and be
//! writable by nobody else. Above the folder a sticky directory (`/tmp`) is
//! accepted: there nobody may rename what they do not own.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const ROOT_UID: u32 = 0;
const WRITABLE_BY_OTHERS: u32 = 0o022;
const STICKY: u32 = 0o1000;

/// Who besides root could change `file`, if anyone: why not, in words, or
/// `None` when only root can. A link at the file itself counts.
pub fn untrusted_writer(file: &Path) -> Result<Option<String>, String> {
    untrusted_writer_trusting(file, &[ROOT_UID])
}

fn untrusted_writer_trusting(file: &Path, trusted: &[u32]) -> Result<Option<String>, String> {
    let meta =
        fs::symlink_metadata(file).map_err(|e| format!("inspect {}: {e}", file.display()))?;
    if meta.file_type().is_symlink() {
        return Ok(Some(format!("{} is a link", file.display())));
    }
    if !meta.is_file() {
        return Ok(Some(format!("{} is not a regular file", file.display())));
    }
    if let Some(why) = open_to_others(file, &meta, trusted, false) {
        return Ok(Some(why));
    }
    let parent = match file.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let folder =
        fs::canonicalize(parent).map_err(|e| format!("resolve {}: {e}", parent.display()))?;
    for (depth, dir) in folder.ancestors().enumerate() {
        let meta =
            fs::symlink_metadata(dir).map_err(|e| format!("inspect {}: {e}", dir.display()))?;
        if let Some(why) = open_to_others(dir, &meta, trusted, depth > 0) {
            return Ok(Some(why));
        }
    }
    Ok(None)
}

fn open_to_others(
    path: &Path,
    meta: &fs::Metadata,
    trusted: &[u32],
    sticky_is_enough: bool,
) -> Option<String> {
    if !trusted.contains(&meta.uid()) {
        return Some(format!("{} belongs to uid {}", path.display(), meta.uid()));
    }
    let mode = meta.mode();
    let sticky_dir = meta.is_dir() && mode & STICKY != 0;
    if mode & WRITABLE_BY_OTHERS != 0 && !(sticky_is_enough && sticky_dir) {
        return Some(format!(
            "{} is writable by group or others (mode {:o})",
            path.display(),
            mode & 0o7777
        ));
    }
    None
}

/// [`open_root_authored`] behind the neutral port.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxAdminAuthoredFiles;

impl nrr_platform_api::admin_authored::AdminAuthoredFiles for LinuxAdminAuthoredFiles {
    fn open_admin_authored(&self, path: &Path) -> nrr_platform_api::admin_authored::AdminAuthored {
        use nrr_platform_api::admin_authored::AdminAuthored;
        match open_root_authored(path) {
            Ok(Some(file)) => AdminAuthored::Opened(file),
            Ok(None) => AdminAuthored::Missing,
            Err(why) => AdminAuthored::Refused(why),
        }
    }
}

/// `file` opened for reading when it and every folder on its path belong to
/// root and nobody else may write them, as [`untrusted_writer`] judges, and no
/// component is a link. Each folder is opened below the handle of the one
/// above it with `O_NOFOLLOW` and judged on that handle, and the file returned
/// is the one judged, so nothing can be swapped between the check and the
/// read. `Ok(None)` when the file or a folder on the way is absent.
pub fn open_root_authored(file: &Path) -> Result<Option<fs::File>, String> {
    open_trusting(file, &[ROOT_UID])
}

fn open_trusting(file: &Path, trusted: &[u32]) -> Result<Option<fs::File>, String> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    use std::path::{Component, PathBuf};

    let (Some(parent), Some(name)) = (file.parent(), file.file_name()) else {
        return Err(format!("{} names no file in a folder", file.display()));
    };
    if !file.is_absolute() {
        return Err(format!("{} is not an absolute path", file.display()));
    }
    let mut folders = Vec::new();
    for component in parent.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => folders.push(name),
            _ => return Err(format!("{} is not a plain path", file.display())),
        }
    }
    // Below a handle by its `/proc` name, so a rename above cannot redirect it.
    let below = |dir: &fs::File, name: &std::ffi::OsStr| {
        PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name)
    };
    let refused_open = |shown: &Path, e: std::io::Error| match e.raw_os_error() {
        Some(libc::ELOOP) | Some(libc::ENOTDIR) => format!("{} is a link", shown.display()),
        _ => format!("open {}: {e}", shown.display()),
    };
    let open_dir = |path: &Path| {
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
    };
    let mut shown = PathBuf::from("/");
    let mut dir = open_dir(&shown).map_err(|e| refused_open(&shown, e))?;
    let judge_dir = |dir: &fs::File, shown: &Path, is_folder: bool| {
        let meta = dir
            .metadata()
            .map_err(|e| format!("inspect {}: {e}", shown.display()))?;
        match open_to_others(shown, &meta, trusted, !is_folder) {
            Some(why) => Err(why),
            None => Ok(()),
        }
    };
    judge_dir(&dir, &shown, folders.is_empty())?;
    for (index, folder) in folders.iter().enumerate() {
        shown.push(folder);
        dir = match open_dir(&below(&dir, folder)) {
            Ok(next) => next,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(refused_open(&shown, e)),
        };
        judge_dir(&dir, &shown, index + 1 == folders.len())?;
    }
    let opened = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(below(&dir, name))
    {
        Ok(opened) => opened,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(refused_open(file, e)),
    };
    let meta = opened
        .metadata()
        .map_err(|e| format!("inspect {}: {e}", file.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", file.display()));
    }
    if let Some(why) = open_to_others(file, &meta, trusted, false) {
        return Err(why);
    }
    Ok(Some(opened))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// What this process creates belongs to it.
    fn my_uid() -> u32 {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::metadata(dir.path()).expect("meta").uid()
    }

    fn private_dir_with_file() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod dir");
        let file = dir.path().join("first-run.json");
        fs::write(&file, b"{}").expect("write");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("chmod file");
        (dir, file)
    }

    #[test]
    fn a_file_an_ordinary_account_owns_is_refused() {
        if my_uid() == ROOT_UID {
            return;
        }
        let (_dir, file) = private_dir_with_file();
        let why = untrusted_writer(&file).expect("readable");
        assert!(why.is_some_and(|why| why.contains("belongs to uid")));
    }

    #[test]
    fn a_trusted_owner_with_a_closed_chain_is_accepted() {
        let (_dir, file) = private_dir_with_file();
        assert_eq!(
            untrusted_writer_trusting(&file, &[ROOT_UID, my_uid()]),
            Ok(None)
        );
    }

    #[test]
    fn a_file_others_may_write_is_refused() {
        let (_dir, file) = private_dir_with_file();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).expect("chmod");
        let why = untrusted_writer_trusting(&file, &[ROOT_UID, my_uid()]).expect("readable");
        assert!(why.is_some_and(|why| why.contains("writable by group or others")));
    }

    #[test]
    fn a_file_its_group_may_write_is_refused() {
        let (_dir, file) = private_dir_with_file();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o664)).expect("chmod");
        let why = untrusted_writer_trusting(&file, &[ROOT_UID, my_uid()]).expect("readable");
        assert!(why.is_some_and(|why| why.contains("writable by group or others")));
    }

    #[test]
    fn a_folder_its_group_may_write_is_refused() {
        let (dir, file) = private_dir_with_file();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o775)).expect("chmod");
        let why = untrusted_writer_trusting(&file, &[ROOT_UID, my_uid()]).expect("readable");
        assert!(why.is_some_and(|why| why.contains("writable by group or others")));
    }

    #[test]
    fn a_folder_further_up_that_others_may_write_is_refused() {
        let outer = tempfile::tempdir().expect("tempdir");
        let inner = outer.path().join("netrulerouter");
        fs::create_dir(&inner).expect("mkdir");
        fs::set_permissions(&inner, fs::Permissions::from_mode(0o755)).expect("chmod inner");
        let file = inner.join("first-run.json");
        fs::write(&file, b"{}").expect("write");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("chmod file");
        fs::set_permissions(outer.path(), fs::Permissions::from_mode(0o777)).expect("chmod outer");
        let why = untrusted_writer_trusting(&file, &[ROOT_UID, my_uid()]).expect("readable");
        assert!(
            why.is_some_and(|why| why.contains("writable by group or others")),
            "whoever may rename the folder can swap the sheet"
        );
    }

    #[test]
    fn a_folder_others_may_write_is_refused_even_when_sticky() {
        let (dir, file) = private_dir_with_file();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o1777)).expect("chmod");
        let why = untrusted_writer_trusting(&file, &[ROOT_UID, my_uid()]).expect("readable");
        assert!(why.is_some(), "the binary's own folder must be closed");
    }

    /// A copy of the program in a user's own folder must not seed the setup
    /// from a sheet left beside it.
    #[test]
    fn a_sheet_in_a_folder_an_ordinary_account_owns_is_not_opened() {
        if my_uid() == ROOT_UID {
            return;
        }
        let (_dir, file) = private_dir_with_file();
        let why = open_root_authored(&file).expect_err("refused");
        assert!(why.contains("belongs to uid"), "{why}");
    }

    #[test]
    fn a_sheet_in_a_closed_chain_is_opened_and_is_the_file_judged() {
        let (_dir, file) = private_dir_with_file();
        let mut opened = open_trusting(&file, &[ROOT_UID, my_uid()])
            .expect("trusted")
            .expect("present");
        let mut read = String::new();
        std::io::Read::read_to_string(&mut opened, &mut read).expect("read");
        assert_eq!(read, "{}");
    }

    /// Whoever controls a link on the way decides which folder the read
    /// lands in, between the check and the read; a link anywhere is refused,
    /// even to a folder that would pass.
    #[test]
    fn a_link_to_a_closed_folder_on_the_way_is_refused() {
        let (dir, _file) = private_dir_with_file();
        let holder = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(holder.path(), fs::Permissions::from_mode(0o700)).expect("chmod");
        let link = holder.path().join("install");
        std::os::unix::fs::symlink(dir.path(), &link).expect("symlink");
        let why = open_trusting(&link.join("first-run.json"), &[ROOT_UID, my_uid()])
            .expect_err("refused");
        assert!(why.contains("is a link"), "{why}");
    }

    #[test]
    fn a_sheet_others_may_write_or_a_link_in_its_place_is_not_opened() {
        let (dir, file) = private_dir_with_file();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o664)).expect("chmod");
        let why = open_trusting(&file, &[ROOT_UID, my_uid()]).expect_err("refused");
        assert!(why.contains("writable by group or others"), "{why}");
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&file, &link).expect("symlink");
        let why = open_trusting(&link, &[ROOT_UID, my_uid()]).expect_err("refused");
        assert!(why.contains("is a link"), "{why}");
        assert!(matches!(
            open_trusting(&dir.path().join("absent.json"), &[ROOT_UID, my_uid()]),
            Ok(None)
        ));
    }

    #[test]
    fn a_link_is_refused_whatever_it_points_at() {
        let (dir, file) = private_dir_with_file();
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&file, &link).expect("symlink");
        let why = untrusted_writer_trusting(&link, &[ROOT_UID, my_uid()]).expect("readable");
        assert!(why.is_some_and(|why| why.contains("is a link")));
    }
}
