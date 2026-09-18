//! Files an elevated process exchanges with its unelevated user through that
//! user's temp directory.
//!
//! Any process of the user can rearrange that directory while a UAC prompt is
//! up, and a junction needs no privilege. So each operation pins the directory
//! (no reparse point, held open without `FILE_SHARE_DELETE`), refuses a link at
//! the file itself, and proves through the two handles that the file sits in
//! the pinned directory — otherwise an administrator's create, read or delete
//! lands wherever the swapped link points.
//!
//! Pinning the directory is not enough on its own: a link one level up carries
//! the whole exchange elsewhere while the pinned directory still looks
//! blameless. So the caller names the root the exchange must stay under and the
//! directory's RESOLVED path is checked against it. That root comes from
//! [`user_temp_root`], which asks Windows — reading `%TEMP%` here would take the
//! answer from the environment the attacker controls.
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{BOOLEAN, HANDLE};
use windows::Win32::Storage::FileSystem::{
    FileDispositionInfo, GetFinalPathNameByHandleW, GetLongPathNameW, SetFileInformationByHandle,
    DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_NAME_NORMALIZED,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

/// The user's own temp root, as Windows names it.
pub fn user_temp_root() -> io::Result<PathBuf> {
    crate::system_shell::local_app_data_directory()
        .map(|local| local.join("Temp"))
        .ok_or_else(|| io::Error::other("the shell did not name the local app-data folder"))
}

/// Where an elevated process and the user who started it exchange files. Not
/// created here — each operation creates what it needs.
pub fn handoff_dir() -> io::Result<PathBuf> {
    Ok(user_temp_root()?.join(nrr_shared::product_identity::PRODUCT_NAME))
}

/// Creates `path` as a new file; an existing file or link at that name is
/// refused, as is a directory that is not the one the path names or that
/// resolves outside `trusted_root`.
pub fn create_new(trusted_root: &Path, path: &Path) -> io::Result<File> {
    let dir = pin_directory(trusted_root, path)?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .access_mode(FILE_GENERIC_WRITE.0 | DELETE.0)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    if let Err(e) = check_in_place(&file, &dir, path) {
        let _ = delete_by_handle(&file);
        return Err(e);
    }
    Ok(file)
}

/// Reads `path` and deletes it through the same handle. The delete is
/// best-effort: a leftover file is harmless, a read from elsewhere is not.
pub fn take(trusted_root: &Path, path: &Path) -> io::Result<String> {
    let dir = pin_directory(trusted_root, path)?;
    let mut file = OpenOptions::new()
        .access_mode(FILE_GENERIC_READ.0 | DELETE.0)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    check_in_place(&file, &dir, path)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let _ = delete_by_handle(&file);
    Ok(text)
}

fn refused(what: &str, path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{what}: {}", path.display()),
    )
}

fn is_reparse_point(meta: &Metadata) -> bool {
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
}

fn pin_directory(trusted_root: &Path, path: &Path) -> io::Result<File> {
    let dir_path = path
        .parent()
        .ok_or_else(|| refused("file has no directory", path))?;
    let dir = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES.0)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(dir_path)?;
    let meta = dir.metadata()?;
    if is_reparse_point(&meta) || !meta.is_dir() {
        return Err(refused("directory is a link", dir_path));
    }
    // The root is compared as written, never resolved: resolving it would
    // follow the same planted link as the directory and agree with itself.
    // Only its 8.3 short names are spelled out, since the handle path always
    // carries long ones (a profile registered as `RUNNER~1` names its temp
    // that way).
    if !resolves_under(&final_path(&dir)?, &long_form(trusted_root)?) {
        return Err(refused(
            "directory resolved outside the trusted root",
            dir_path,
        ));
    }
    Ok(dir)
}

/// Whether a resolved path sits under `root`, compared the way the filesystem
/// compares: component by component, case-insensitively, and without the
/// `\\?\` prefix `GetFinalPathNameByHandleW` returns.
fn resolves_under(resolved: &Path, root: &Path) -> bool {
    fn parts(p: &Path) -> Vec<String> {
        let text = p.to_string_lossy();
        let text = match text.strip_prefix(r"\\?\UNC\") {
            Some(rest) => format!(r"\\{rest}"),
            None => text.trim_start_matches(r"\\?\").to_string(),
        };
        text.split('\\')
            .filter(|c| !c.is_empty())
            .map(str::to_lowercase)
            .collect()
    }
    let root = parts(root);
    !root.is_empty() && parts(resolved).starts_with(&root)
}

fn check_in_place(file: &File, dir: &File, path: &Path) -> io::Result<()> {
    let meta = file.metadata()?;
    if is_reparse_point(&meta) || !meta.is_file() {
        return Err(refused("file is a link", path));
    }
    // An ancestor swapped between the two opens puts the file elsewhere than
    // the pinned directory; the handles cannot disagree about where they are.
    if final_path(file)?.parent() != Some(final_path(dir)?.as_path()) {
        return Err(refused("file resolved outside its directory", path));
    }
    Ok(())
}

/// The path with every short component spelled long. A text lookup per
/// component, not a resolution: a junction keeps its own name.
fn long_form(path: &Path) -> io::Result<PathBuf> {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: `wide` is NUL-terminated and outlives the call; the call
        // writes at most `buf.len()` units and returns that count, or the
        // size it needs when the buffer is too small.
        let len = unsafe { GetLongPathNameW(PCWSTR(wide.as_ptr()), Some(&mut buf)) } as usize;
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        if len < buf.len() {
            return Ok(PathBuf::from(OsString::from_wide(&buf[..len])));
        }
        buf.resize(len + 1, 0);
    }
}

fn final_path(file: &File) -> io::Result<PathBuf> {
    let handle = HANDLE(file.as_raw_handle().cast());
    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: `handle` stays open for the borrow of `file`; the call writes
        // at most `buf.len()` units and returns that count, or the size it
        // needs when the buffer is too small.
        let len =
            unsafe { GetFinalPathNameByHandleW(handle, &mut buf, FILE_NAME_NORMALIZED) } as usize;
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        if len < buf.len() {
            return Ok(PathBuf::from(OsString::from_wide(&buf[..len])));
        }
        buf.resize(len + 1, 0);
    }
}

fn delete_by_handle(file: &File) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO {
        DeleteFile: BOOLEAN(1),
    };
    // SAFETY: a live handle opened with DELETE access, and a fully initialised
    // struct of exactly the size this information class takes.
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle().cast()),
            FileDispositionInfo,
            std::ptr::from_ref(&info).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    /// `mklink /J` needs no privilege, which is exactly why the attack works.
    fn junction(link: &Path, target: &Path) {
        let status = Command::new(crate::system_shell::system32_exe("cmd.exe"))
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(Stdio::null())
            .status()
            .expect("mklink");
        assert!(status.success(), "junction {}", link.display());
    }

    #[test]
    fn a_new_file_is_created_once_and_never_over_an_existing_one() {
        let root = tempfile::tempdir().expect("temp dir");
        let path = root.path().join("report.json");
        {
            let mut file = create_new(root.path(), &path).expect("first create");
            std::io::Write::write_all(&mut file, b"{}").expect("write");
        }
        assert!(
            create_new(root.path(), &path).is_err(),
            "an existing file was reused"
        );
        assert_eq!(std::fs::read(&path).expect("read"), b"{}");
    }

    #[test]
    fn take_reads_and_deletes() {
        let root = tempfile::tempdir().expect("temp dir");
        let path = root.path().join("t.token");
        std::fs::write(&path, "nonce").expect("write");
        assert_eq!(take(root.path(), &path).expect("take"), "nonce");
        assert!(!path.exists());
    }

    #[test]
    fn a_junction_in_place_of_the_directory_is_refused_both_ways() {
        let root = tempfile::tempdir().expect("temp dir");
        let victim = root.path().join("victim");
        std::fs::create_dir(&victim).expect("victim dir");
        std::fs::write(victim.join("t.token"), "nonce").expect("victim file");
        let link = root.path().join("link");
        junction(&link, &victim);

        assert!(create_new(root.path(), &link.join("report.json")).is_err());
        assert!(
            !victim.join("report.json").exists(),
            "created through a junction"
        );
        assert!(take(root.path(), &link.join("t.token")).is_err());
        assert!(
            victim.join("t.token").exists(),
            "deleted through a junction"
        );
        let _ = std::fs::remove_dir(&link);
    }

    #[test]
    fn a_junction_above_the_exchange_directory_is_refused() {
        // The directory the file sits in is a real one and pins cleanly; it is
        // its PARENT that was swapped, which is what the trusted root catches.
        let root = tempfile::tempdir().expect("temp dir");
        let expected = root.path().join("temp");
        std::fs::create_dir(&expected).expect("expected root");
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("NetRuleRouter")).expect("victim tree");
        std::fs::write(elsewhere.join("NetRuleRouter").join("t.token"), "nonce").expect("victim");
        let swapped = root.path().join("swapped");
        junction(&swapped, &elsewhere);

        let through_link = swapped.join("NetRuleRouter").join("t.token");
        assert!(
            take(&expected, &through_link).is_err(),
            "read from outside the trusted root"
        );
        assert!(
            elsewhere.join("NetRuleRouter").join("t.token").exists(),
            "deleted from outside the trusted root"
        );
        assert!(
            create_new(&expected, &swapped.join("NetRuleRouter").join("new.json")).is_err(),
            "created outside the trusted root"
        );
        // Positive control: the same path passes once the root does contain it,
        // so the refusals above are the root check and not a broken path.
        assert!(take(&elsewhere, &through_link).is_ok());
        let _ = std::fs::remove_dir(&swapped);
    }

    #[test]
    fn the_trusted_root_is_matched_by_component_not_by_prefix() {
        // `C:\Temp2` starts with `C:\Temp` as text and is a different directory.
        assert!(resolves_under(
            Path::new(r"\\?\C:\Users\u\AppData\Local\Temp\NetRuleRouter"),
            Path::new(r"C:\Users\u\AppData\Local\Temp")
        ));
        assert!(!resolves_under(
            Path::new(r"\\?\C:\Temp2\NetRuleRouter"),
            Path::new(r"C:\Temp")
        ));
        assert!(
            resolves_under(Path::new(r"\\?\C:\TEMP\x"), Path::new(r"C:\temp")),
            "the filesystem does not distinguish case here, and neither may we"
        );
    }

    #[test]
    fn a_trusted_root_given_in_short_form_still_contains_its_files() {
        let root = tempfile::tempdir().expect("temp dir");
        let long = root.path().join("a-directory-with-a-long-name");
        std::fs::create_dir(&long).expect("root");
        let short = short_form(&long);
        if short == long {
            return; // 8.3 names are disabled on this volume
        }
        let path = long.join("t.token");
        std::fs::write(&path, "nonce").expect("write");
        assert_eq!(take(&short, &path).expect("take"), "nonce");
    }

    fn short_form(path: &Path) -> PathBuf {
        use windows::Win32::Storage::FileSystem::GetShortPathNameW;
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut buf = vec![0u16; 1024];
        // SAFETY: `wide` is NUL-terminated; `buf` bounds the write.
        let len = unsafe { GetShortPathNameW(PCWSTR(wide.as_ptr()), Some(&mut buf)) } as usize;
        assert!(len > 0 && len < buf.len(), "short path");
        PathBuf::from(OsString::from_wide(&buf[..len]))
    }

    #[test]
    fn a_file_symlink_is_refused() {
        let root = tempfile::tempdir().expect("temp dir");
        let victim = root.path().join("victim.txt");
        std::fs::write(&victim, "nonce").expect("victim");
        let link = root.path().join("t.token");
        if std::os::windows::fs::symlink_file(&victim, &link).is_err() {
            return; // no symlink privilege on this host; the junction test stands
        }
        assert!(take(root.path(), &link).is_err(), "read through a symlink");
        assert!(victim.exists(), "deleted through a symlink");
    }
}
