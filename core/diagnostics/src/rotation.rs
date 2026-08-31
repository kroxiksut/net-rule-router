//! File rotation naming shared by the audit and operational log writers.
//!
//! Both write `<prefix><YYYYMMDD>-<N>.ndjson` and both used to name the next
//! file by "first index that does not exist yet", ordered by plain string
//! comparison. Retention deletes the oldest files, so those indices come free
//! again and get reused; string order then puts the newest file first. For the
//! logs that only reordered a view, for the audit trail it forked the hash
//! chain. The naming rule lives here so the two cannot drift apart again.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

/// Chronological sort key for a rotated file name: `(stem, index)`.
///
/// A name without a numeric `-N` suffix sorts by its whole stem ahead of any
/// numbered sibling.
pub fn rotation_sort_key(path: &Path) -> (String, u32) {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    match stem.rsplit_once('-') {
        Some((head, index)) => match index.parse::<u32>() {
            Ok(n) => (head.to_string(), n),
            Err(_) => (stem.to_string(), 0),
        },
        None => (stem.to_string(), 0),
    }
}

/// Sorts rotated files chronologically in place.
pub fn sort_chronologically(files: &mut [PathBuf]) {
    files.sort_by_key(|p| rotation_sort_key(p));
}

/// Opens the next rotation file for `prefix` in `dir`, creating it exclusively.
///
/// The index is one past the HIGHEST that exists — never a number retention
/// freed. `create_new` makes the claim atomic, so two service instances racing
/// a restart cannot interleave two chains into one file: the loser sees
/// `AlreadyExists` and takes the next index.
pub fn open_next_rotation(dir: &Path, prefix: &str) -> std::io::Result<(File, PathBuf)> {
    let mut index = highest_index(dir, prefix) + 1;
    loop {
        let path = dir.join(format!("{prefix}{index}.ndjson"));
        match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => index += 1,
            Err(e) => return Err(e),
        }
    }
}

fn highest_index(dir: &Path, prefix: &str) -> u32 {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|name| {
            let stem = name.strip_suffix(".ndjson")?;
            stem.strip_prefix(prefix)?.parse::<u32>().ok()
        })
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_eleventh_rotation_sorts_after_the_ninth() {
        let mut files = vec![
            PathBuf::from("nrr_audit_20260830-11.ndjson"),
            PathBuf::from("nrr_audit_20260830-2.ndjson"),
            PathBuf::from("nrr_audit_20260829-9.ndjson"),
        ];
        sort_chronologically(&mut files);
        let names: Vec<_> = files
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "nrr_audit_20260829-9.ndjson",
                "nrr_audit_20260830-2.ndjson",
                "nrr_audit_20260830-11.ndjson",
            ]
        );
    }

    #[test]
    fn a_number_retention_freed_is_not_handed_out_again() {
        let dir = tempfile::tempdir().expect("temp");
        std::fs::write(dir.path().join("nrr_x_20260830-3.ndjson"), "").unwrap();

        let (_, path) = open_next_rotation(dir.path(), "nrr_x_20260830-").expect("open");
        assert_eq!(
            path.file_name().unwrap().to_string_lossy(),
            "nrr_x_20260830-4.ndjson"
        );
    }

    #[test]
    fn a_second_writer_never_lands_in_the_first_writers_file() {
        let dir = tempfile::tempdir().expect("temp");
        let (_a, first) = open_next_rotation(dir.path(), "nrr_x_20260830-").expect("first");
        let (_b, second) = open_next_rotation(dir.path(), "nrr_x_20260830-").expect("second");
        assert_ne!(first, second);
    }
}
