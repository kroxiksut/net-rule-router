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

/// [`untrusted_writer`] behind the neutral port.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxAdminAuthoredFiles;

impl nrr_platform_api::admin_authored::AdminAuthoredFiles for LinuxAdminAuthoredFiles {
    fn untrusted_because(&self, path: &Path) -> Option<String> {
        untrusted_writer(path).unwrap_or_else(Some)
    }
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
    fn a_folder_others_may_write_is_refused_even_when_sticky() {
        let (dir, file) = private_dir_with_file();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o1777)).expect("chmod");
        let why = untrusted_writer_trusting(&file, &[ROOT_UID, my_uid()]).expect("readable");
        assert!(why.is_some(), "the binary's own folder must be closed");
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
