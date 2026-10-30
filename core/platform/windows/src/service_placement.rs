//! The protected copy of the service binary — the mechanism behind
//! `nrr_platform_api::service_placement`.
//!
//! An install run from a folder ordinary accounts can change (an unpacked
//! portable copy) registers a copy kept under Program Files instead. Every step
//! here runs elevated and assumes the folder it reads from is hostile after the
//! moment of reading: the files are read once into memory, and what is written
//! and verified comes from those bytes, never from the source again. A source
//! file is read only through a handle that is no link and resolves to exactly
//! the expected name in the pinned source folder — otherwise a planted link
//! would have an administrator copy a file only administrators may read into a
//! folder every user can read. Writes go to a staging name in a folder that is
//! already locked down, are read back and compared, and only then renamed into
//! place.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nrr_platform_api::service_placement::CopyState;
use nrr_platform_api::third_party::WINTUN_COMPONENT;
use nrr_shared::product_identity::{BinaryRole, PRODUCT_NAME};
use sha2::{Digest, Sha256};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;

/// The C runtime the release build links dynamically. A clean Windows carries
/// no redistributable; the package ships these beside the binaries.
const C_RUNTIME: &[&str] = &["vcruntime140.dll", "vcruntime140_1.dll"];

/// How long a removal waits for a just-stopped service to let go of its image.
const REMOVE_BUDGET: Duration = Duration::from_secs(5);

/// The folder under Program Files the copy lives in. A sibling of the
/// installer's own product folder, never inside it, so neither install writes
/// into the other's files.
#[must_use]
pub fn installed_copy_dir_name() -> String {
    format!("{PRODUCT_NAME} Service")
}

/// Where the copy lives, from the shell's registration of Program Files — an
/// elevated install carries the user's environment, so never `%ProgramFiles%`.
pub fn installed_copy_dir() -> Result<PathBuf, String> {
    crate::system_shell::program_files_directory()
        .map(|dir| dir.join(installed_copy_dir_name()))
        .ok_or_else(|| "cannot resolve the Program Files folder".to_string())
}

/// The binary registered from the copy folder.
#[must_use]
pub fn installed_copy_binary(dir: &Path) -> PathBuf {
    dir.join(BinaryRole::Service.host_file_name())
}

/// Files the service loads from its own folder, besides itself: the TUN
/// driver, the C runtime, and its symbols where a developer build has them
/// (packages ship them in a separate archive).
fn companion_names() -> Vec<String> {
    let mut names = vec![WINTUN_COMPONENT.file_name.to_string()];
    names.extend(C_RUNTIME.iter().map(|name| (*name).to_string()));
    names.push(symbols_file_name());
    names
}

/// `nrr-service.exe` -> `nrr_service.pdb`, the name the linker gives it.
fn symbols_file_name() -> String {
    let exe = BinaryRole::Service.host_file_name();
    let stem = exe.strip_suffix(".exe").unwrap_or(exe);
    format!("{}.pdb", stem.replace('-', "_"))
}

struct PayloadFile {
    name: String,
    bytes: Vec<u8>,
    digest: [u8; 32],
}

impl PayloadFile {
    fn new(name: String, bytes: Vec<u8>) -> Self {
        let digest = Sha256::digest(&bytes).into();
        Self {
            name,
            bytes,
            digest,
        }
    }
}

/// The service binary and the companions found beside it, read once.
pub struct Payload {
    binary: PayloadFile,
    companions: Vec<PayloadFile>,
}

impl Payload {
    /// Reads `binary` and whichever companions sit beside it. The binary is
    /// stored under the service's own name whatever the source calls it. A
    /// companion that is present but fails the source checks is an error, never
    /// skipped and never followed.
    pub fn read(binary: &Path) -> Result<Self, String> {
        let source = SourceDir::pin(binary)?;
        let binary_name = binary
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| format!("{} names no file", binary.display()))?;
        let bytes = source
            .read(&binary_name)?
            .ok_or_else(|| format!("{} does not exist", binary.display()))?;
        let mut companions = Vec::new();
        for name in companion_names() {
            if let Some(bytes) = source.read(&name)? {
                companions.push(PayloadFile::new(name, bytes));
            }
        }
        Ok(Self {
            binary: PayloadFile::new(BinaryRole::Service.host_file_name().to_string(), bytes),
            companions,
        })
    }

    fn files(&self) -> impl Iterator<Item = &PayloadFile> {
        // Companions first: the binary is what the service manager starts, so
        // it lands last, once what it loads is already there.
        self.companions.iter().chain(std::iter::once(&self.binary))
    }

    fn carries(&self, name: &str) -> bool {
        self.files()
            .any(|file| file.name.eq_ignore_ascii_case(name))
    }

    /// The copy in `dir` compared with these files. A link at the folder is an
    /// error, not a state: nothing is read or written through one.
    pub fn state_in(&self, dir: &Path) -> Result<CopyState, String> {
        match std::fs::symlink_metadata(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CopyState::Missing),
            Err(e) => return Err(format!("inspect {}: {e}", dir.display())),
            Ok(meta) if is_reparse_point(&meta) => {
                return Err(format!("{} is a link to somewhere else", dir.display()))
            }
            Ok(meta) if !meta.is_dir() => return Ok(CopyState::Stale),
            Ok(_) => {}
        }
        for file in self.files() {
            match digest_of(&dir.join(&file.name)) {
                Ok(Some(digest)) if digest == file.digest => {}
                Ok(_) => return Ok(CopyState::Stale),
                Err(e) => return Err(e),
            }
        }
        let retired = companion_names()
            .into_iter()
            .filter(|name| !self.carries(name))
            .any(|name| std::fs::symlink_metadata(dir.join(name)).is_ok());
        Ok(if retired {
            CopyState::Stale
        } else {
            CopyState::Current
        })
    }

    /// Writes every file into `dir`, which [`prepare_copy_dir`] has locked
    /// down, and removes companions the source no longer ships.
    pub fn write_to(&self, dir: &Path) -> Result<(), String> {
        sweep_staging_leftovers(dir);
        for file in self.files() {
            place(dir, file)?;
        }
        for name in companion_names() {
            if !self.carries(&name) {
                retire(dir, &name);
            }
        }
        Ok(())
    }
}

/// The folder the install reads from, held open for the whole read so it cannot
/// be renamed or replaced underneath it, and the path Windows resolves it to.
struct SourceDir {
    path: PathBuf,
    _handle: File,
    resolved: PathBuf,
}

impl SourceDir {
    fn pin(binary: &Path) -> Result<Self, String> {
        let path = binary
            .parent()
            .ok_or_else(|| format!("{} has no folder", binary.display()))?
            .to_path_buf();
        // No FILE_SHARE_DELETE: while this is open the folder keeps its name.
        let handle = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        let meta = handle
            .metadata()
            .map_err(|e| format!("inspect {}: {e}", path.display()))?;
        if is_reparse_point(&meta) || !meta.is_dir() {
            return Err(format!("{} is a link, not a plain folder", path.display()));
        }
        let resolved = crate::pinned_file::final_path(&handle)
            .map_err(|e| format!("resolve {}: {e}", path.display()))?;
        Ok(Self {
            path,
            _handle: handle,
            resolved,
        })
    }

    /// The bytes of `name` in this folder, `None` when there is no such entry.
    /// Read only from a handle that is a plain file, not a link, and resolves
    /// to exactly `<this folder>\<name>`.
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        let path = self.path.join(name);
        let mut file = match OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("open {}: {e}", path.display())),
        };
        let meta = file
            .metadata()
            .map_err(|e| format!("inspect {}: {e}", path.display()))?;
        if is_reparse_point(&meta) || !meta.is_file() {
            return Err(format!(
                "{} is a link or not a plain file; refusing to copy it",
                path.display()
            ));
        }
        let resolved = crate::pinned_file::final_path(&file)
            .map_err(|e| format!("resolve {}: {e}", path.display()))?;
        if !resolves_to(&resolved, &self.resolved, name) {
            return Err(format!(
                "{} resolves to {}, not to a file in {}",
                path.display(),
                resolved.display(),
                self.resolved.display()
            ));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
        file.read_to_end(&mut bytes)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        Ok(Some(bytes))
    }
}

/// Whether a resolved file path is exactly `<dir>\<name>`, as the file system
/// compares: case-insensitively, whole components.
fn resolves_to(resolved: &Path, dir: &Path, name: &str) -> bool {
    let named = resolved
        .file_name()
        .is_some_and(|file| file.to_string_lossy().eq_ignore_ascii_case(name));
    let lower = |p: &Path| p.to_string_lossy().to_lowercase();
    named
        && resolved
            .parent()
            .is_some_and(|parent| lower(parent) == lower(dir))
}

/// Creates the copy folder, or takes over the one a previous install left, and
/// gives it its own protected ACL: SYSTEM and Administrators full control,
/// Users read and execute, nothing inherited.
pub fn prepare_copy_dir(dir: &Path) -> Result<(), String> {
    let parent = dir
        .parent()
        .ok_or_else(|| format!("{} has no parent folder", dir.display()))?;
    let parent_meta = std::fs::symlink_metadata(parent)
        .map_err(|e| format!("inspect {}: {e}", parent.display()))?;
    if is_reparse_point(&parent_meta) || !parent_meta.is_dir() {
        return Err(format!("{} is not a plain folder", parent.display()));
    }
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if is_reparse_point(&meta) => {
            return Err(format!("{} is a link to somewhere else", dir.display()))
        }
        Ok(meta) if !meta.is_dir() => {
            return Err(format!("{} exists and is not a folder", dir.display()))
        }
        // Program Files admits only administrators: a folder owned by anyone
        // else did not come from an install and is not adopted.
        Ok(_) => {
            if !crate::trusted_location::owner_is_trusted(dir)? {
                return Err(format!(
                    "{} is owned by an account other than SYSTEM or Administrators; \
                     remove it as an administrator and install again",
                    dir.display()
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
        Err(e) => return Err(format!("inspect {}: {e}", dir.display())),
    }
    crate::trusted_location::lock_down_program_tree(dir).map_err(|e| e.to_string())
}

/// What became of the copy folder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyRemoval {
    /// There was none.
    Absent,
    Removed,
    /// A file is still in use — the removal runs from the copy itself, or the
    /// stopped service has not let go of its image — so what is left goes at
    /// the next restart.
    AtRestart,
}

/// Removes the copy folder after the registration naming it is gone. Only this
/// folder, and refused outright if a link sits anywhere in it.
pub fn remove_copy_dir(dir: &Path) -> Result<CopyRemoval, String> {
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CopyRemoval::Absent),
        Err(e) => return Err(format!("inspect {}: {e}", dir.display())),
        Ok(meta) if is_reparse_point(&meta) => {
            return Err(format!("{} is a link to somewhere else", dir.display()))
        }
        Ok(_) => {}
    }
    if let Some(link) = crate::trusted_location::first_reparse_point(dir)? {
        return Err(format!("{} is a link out of the folder", link.display()));
    }
    // SERVICE_STOPPED is reported a moment before the process lets go of its
    // image, and the removal follows straight on from the stop.
    let deadline = Instant::now() + REMOVE_BUDGET;
    loop {
        match std::fs::remove_dir_all(dir) {
            Ok(()) => return Ok(CopyRemoval::Removed),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CopyRemoval::Removed),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(250)),
            Err(e) => {
                remove_at_restart(dir)
                    .map_err(|later| format!("remove {}: {e}; {later}", dir.display()))?;
                return Ok(CopyRemoval::AtRestart);
            }
        }
    }
}

/// Hands what is left of `dir` to the next restart. A file still in use is
/// first renamed to a staging name no copy is ever written under, so a reinstall
/// that reuses the folder before the restart keeps its new files; the folder
/// itself goes at the restart only if it is empty by then.
fn remove_at_restart(dir: &Path) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("list {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("list {}: {e}", dir.display()))?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("inspect {}: {e}", path.display()))?;
        if is_reparse_point(&meta) {
            return Err(format!("{} is a link", path.display()));
        }
        if meta.is_dir() {
            remove_at_restart(&path)?;
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let doomed = if name.to_ascii_lowercase().ends_with(".old") {
            path
        } else {
            let aside = dir.join(format!("{name}.{}.old", std::process::id()));
            std::fs::rename(&path, &aside)
                .map_err(|e| format!("move {} aside: {e}", path.display()))?;
            aside
        };
        delete_at_restart(&doomed)?;
    }
    delete_at_restart(dir)
}

#[allow(unsafe_code)]
fn delete_at_restart(path: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is NUL-terminated and outlives the call; a null new name
    // asks for deletion rather than a move.
    unsafe {
        MoveFileExW(
            PCWSTR(wide.as_ptr()),
            PCWSTR::null(),
            MOVEFILE_DELAY_UNTIL_REBOOT,
        )
    }
    .map_err(|e| format!("schedule removal of {}: {e}", path.display()))
}

/// Stage, verify, then rename into place. The file being replaced is renamed
/// aside first: a service image still mapped by a process that is exiting can
/// be renamed but not overwritten.
fn place(dir: &Path, file: &PayloadFile) -> Result<(), String> {
    let pid = std::process::id();
    let staged = dir.join(format!("{}.{pid}.new", file.name));
    let target = dir.join(&file.name);
    let aside = dir.join(format!("{}.{pid}.old", file.name));
    write_new(&staged, &file.bytes)?;
    // Read back what reached the disk, not what was handed to the write.
    match digest_of(&staged) {
        Ok(Some(digest)) if digest == file.digest => {}
        Ok(_) => {
            let _ = std::fs::remove_file(&staged);
            return Err(format!("{} did not read back as written", staged.display()));
        }
        Err(e) => {
            let _ = std::fs::remove_file(&staged);
            return Err(e);
        }
    }
    let had_target = std::fs::symlink_metadata(&target).is_ok();
    if had_target {
        std::fs::rename(&target, &aside).map_err(|e| {
            let _ = std::fs::remove_file(&staged);
            format!("move {} aside: {e}", target.display())
        })?;
    }
    if let Err(e) = std::fs::rename(&staged, &target) {
        if had_target {
            let _ = std::fs::rename(&aside, &target);
        }
        let _ = std::fs::remove_file(&staged);
        return Err(format!("put {} in place: {e}", target.display()));
    }
    if had_target {
        // Still mapped by an exiting process: the next install sweeps it.
        let _ = std::fs::remove_file(&aside);
    }
    Ok(())
}

/// A new file, never an existing one or a link at that name.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    out.write_all(bytes)
        .and_then(|()| out.sync_all())
        .map_err(|e| format!("write {}: {e}", path.display()))
}

/// SHA-256 of the file at `path`, `None` when there is no such file. A link is
/// an error: it is never opened through.
fn digest_of(path: &Path) -> Result<Option<[u8; 32]>, String> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("open {}: {e}", path.display())),
    };
    let meta = file
        .metadata()
        .map_err(|e| format!("inspect {}: {e}", path.display()))?;
    if is_reparse_point(&meta) || !meta.is_file() {
        return Err(format!("{} is not a plain file", path.display()));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(Some(Sha256::digest(&bytes).into()))
}

/// Staging and set-aside files an interrupted or locked earlier run left.
fn sweep_staging_leftovers(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut ours = companion_names();
    ours.push(BinaryRole::Service.host_file_name().to_string());
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_staging_leftover(&name, &ours) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// `<one of ours>.<pid>.new` or `.old`, and nothing else.
fn is_staging_leftover(name: &str, ours: &[String]) -> bool {
    let lower = name.to_ascii_lowercase();
    let Some(rest) = lower
        .strip_suffix(".new")
        .or_else(|| lower.strip_suffix(".old"))
    else {
        return false;
    };
    let Some((base, pid)) = rest.rsplit_once('.') else {
        return false;
    };
    !pid.is_empty()
        && pid.bytes().all(|b| b.is_ascii_digit())
        && ours.iter().any(|own| own.eq_ignore_ascii_case(base))
}

/// Removes a companion the source no longer ships. Best-effort: a DLL nothing
/// loads any more is harmless.
fn retire(dir: &Path, name: &str) {
    let path = dir.join(name);
    if std::fs::symlink_metadata(&path).is_err() {
        return;
    }
    if std::fs::remove_file(&path).is_err() {
        let aside = dir.join(format!("{name}.{}.old", std::process::id()));
        let _ = std::fs::rename(&path, aside);
    }
}

fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_with(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("source dir");
        for (name, bytes) in files {
            std::fs::write(dir.path().join(name), bytes).expect("source file");
        }
        dir
    }

    fn service_name() -> &'static str {
        BinaryRole::Service.host_file_name()
    }

    #[test]
    fn the_copy_folder_is_a_sibling_of_the_product_folder_not_inside_it() {
        let name = installed_copy_dir_name();
        assert_ne!(name, PRODUCT_NAME);
        assert!(!name.contains(['\\', '/']), "{name}");
        if let Ok(dir) = installed_copy_dir() {
            assert!(dir.is_absolute(), "{}", dir.display());
            assert_eq!(
                installed_copy_binary(&dir)
                    .file_name()
                    .and_then(|n| n.to_str()),
                Some(service_name())
            );
        }
    }

    #[test]
    fn symbols_carry_the_linker_spelling() {
        assert_eq!(symbols_file_name(), "nrr_service.pdb");
    }

    #[test]
    fn a_written_copy_is_current_and_a_changed_source_makes_it_stale() {
        let source = source_with(&[
            (service_name(), b"service v1"),
            ("wintun.dll", b"tun"),
            ("unrelated.txt", b"not ours"),
        ]);
        let target = tempfile::tempdir().expect("target dir");
        let copy = target.path().join("copy");
        let payload = Payload::read(&source.path().join(service_name())).expect("read");
        assert_eq!(payload.state_in(&copy), Ok(CopyState::Missing));

        std::fs::create_dir(&copy).expect("copy dir");
        payload.write_to(&copy).expect("write");
        assert_eq!(payload.state_in(&copy), Ok(CopyState::Current));
        assert_eq!(
            std::fs::read(copy.join(service_name())).expect("binary"),
            b"service v1"
        );
        assert!(copy.join("wintun.dll").is_file());
        assert!(
            !copy.join("unrelated.txt").exists(),
            "only the service and what it loads travel"
        );

        std::fs::write(source.path().join(service_name()), b"service v2").expect("update");
        let newer = Payload::read(&source.path().join(service_name())).expect("read v2");
        assert_eq!(newer.state_in(&copy), Ok(CopyState::Stale));
        newer.write_to(&copy).expect("rewrite");
        assert_eq!(newer.state_in(&copy), Ok(CopyState::Current));
        let leftovers: Vec<_> = std::fs::read_dir(&copy)
            .expect("list")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".new") || name.ends_with(".old"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn what_is_written_is_what_was_read_not_what_the_source_holds_later() {
        let source = source_with(&[(service_name(), b"genuine")]);
        let payload = Payload::read(&source.path().join(service_name())).expect("read");
        // Swapped after the read: the copy must not pick it up.
        std::fs::write(source.path().join(service_name()), b"swapped").expect("swap");
        let target = tempfile::tempdir().expect("target dir");
        payload.write_to(target.path()).expect("write");
        assert_eq!(
            std::fs::read(target.path().join(service_name())).expect("copy"),
            b"genuine"
        );
    }

    #[test]
    fn a_companion_the_source_dropped_is_retired_from_the_copy() {
        let target = tempfile::tempdir().expect("target dir");
        let with_dll = source_with(&[(service_name(), b"svc"), ("vcruntime140_1.dll", b"crt")]);
        Payload::read(&with_dll.path().join(service_name()))
            .expect("read")
            .write_to(target.path())
            .expect("write");
        let without = source_with(&[(service_name(), b"svc")]);
        let payload = Payload::read(&without.path().join(service_name())).expect("read");
        assert_eq!(payload.state_in(target.path()), Ok(CopyState::Stale));
        payload.write_to(target.path()).expect("rewrite");
        assert!(!target.path().join("vcruntime140_1.dll").exists());
        assert_eq!(payload.state_in(target.path()), Ok(CopyState::Current));
    }

    #[test]
    fn only_our_own_staging_names_are_swept() {
        let ours = vec![service_name().to_string(), "wintun.dll".to_string()];
        assert!(is_staging_leftover("nrr-service.exe.1234.new", &ours));
        assert!(is_staging_leftover("WINTUN.DLL.77.old", &ours));
        assert!(!is_staging_leftover("nrr-service.exe", &ours));
        assert!(!is_staging_leftover("nrr-service.exe.new", &ours));
        assert!(!is_staging_leftover("nrr-service.exe.abc.old", &ours));
        assert!(!is_staging_leftover("someone-else.dll.12.old", &ours));
    }

    /// `mklink /J` needs no privilege, which is exactly why it is the attack.
    fn junction(link: &Path, target: &Path) -> bool {
        std::process::Command::new(crate::system_shell::system32_exe("cmd.exe"))
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    #[test]
    fn a_junction_in_place_of_the_copy_folder_is_never_written_or_removed_through() {
        let root = tempfile::tempdir().expect("root");
        let victim = root.path().join("victim");
        std::fs::create_dir(&victim).expect("victim");
        std::fs::write(victim.join("keep.txt"), b"keep").expect("victim file");
        let link = root.path().join("copy");
        if !junction(&link, &victim) {
            return; // a locked-down host may refuse; the other refusals stand
        }
        let source = source_with(&[(service_name(), b"svc")]);
        let payload = Payload::read(&source.path().join(service_name())).expect("read");
        assert!(payload.state_in(&link).is_err());
        assert!(prepare_copy_dir(&link).is_err());
        assert!(remove_copy_dir(&link).is_err());
        assert!(
            victim.join("keep.txt").exists(),
            "removed through a junction"
        );
        assert!(
            !victim.join(service_name()).exists(),
            "written through a junction"
        );
        let _ = std::fs::remove_dir(&link);
    }

    #[test]
    fn a_link_inside_the_copy_folder_stops_its_removal() {
        let root = tempfile::tempdir().expect("root");
        let copy = root.path().join("copy");
        std::fs::create_dir(&copy).expect("copy");
        let victim = root.path().join("victim");
        std::fs::create_dir(&victim).expect("victim");
        std::fs::write(victim.join("keep.txt"), b"keep").expect("victim file");
        if !junction(&copy.join("logs"), &victim) {
            return;
        }
        assert!(remove_copy_dir(&copy).is_err());
        assert!(victim.join("keep.txt").exists());
        let _ = std::fs::remove_dir(copy.join("logs"));
    }

    #[test]
    fn a_companion_planted_as_a_link_is_refused_not_followed_or_skipped() {
        let source = source_with(&[(service_name(), b"svc")]);
        let secret = tempfile::tempdir().expect("secret dir");
        if !junction(&source.path().join("wintun.dll"), secret.path()) {
            return;
        }
        let refused = Payload::read(&source.path().join(service_name()));
        assert!(
            refused.is_err(),
            "a link at a companion name was read or skipped"
        );
        let _ = std::fs::remove_dir(source.path().join("wintun.dll"));
    }

    #[test]
    fn a_companion_symlinked_to_another_file_is_refused() {
        let source = source_with(&[(service_name(), b"svc")]);
        let secret = tempfile::tempdir().expect("secret dir");
        let target = secret.path().join("only-admins.bin");
        std::fs::write(&target, b"secret").expect("secret");
        let link = source.path().join(symbols_file_name());
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            return; // no symlink privilege on this host; the junction tests stand
        }
        assert!(Payload::read(&source.path().join(service_name())).is_err());
    }

    #[test]
    fn a_source_folder_reached_through_a_junction_is_refused() {
        let root = tempfile::tempdir().expect("root");
        let real = root.path().join("real");
        std::fs::create_dir(&real).expect("real");
        std::fs::write(real.join(service_name()), b"svc").expect("binary");
        let link = root.path().join("portable");
        if !junction(&link, &real) {
            return;
        }
        assert!(Payload::read(&link.join(service_name())).is_err());
        assert!(Payload::read(&real.join(service_name())).is_ok());
        let _ = std::fs::remove_dir(&link);
    }

    #[test]
    fn a_resolved_source_must_be_the_expected_name_in_the_pinned_folder() {
        let dir = Path::new(r"\\?\C:\Users\u\Desktop\NetRuleRouter");
        assert!(resolves_to(
            Path::new(r"\\?\C:\Users\u\Desktop\NetRuleRouter\WINTUN.DLL"),
            dir,
            "wintun.dll"
        ));
        assert!(!resolves_to(
            Path::new(r"\\?\C:\Windows\System32\config\SAM"),
            dir,
            "wintun.dll"
        ));
        assert!(!resolves_to(
            Path::new(r"\\?\C:\Users\u\Desktop\NetRuleRouter\other.dll"),
            dir,
            "wintun.dll"
        ));
        assert!(!resolves_to(
            Path::new(r"\\?\C:\Users\u\Desktop\NetRuleRouter\sub\wintun.dll"),
            dir,
            "wintun.dll"
        ));
    }

    #[test]
    fn removing_a_copy_folder_that_is_not_there_is_not_an_error() {
        let root = tempfile::tempdir().expect("root");
        assert_eq!(
            remove_copy_dir(&root.path().join("absent")),
            Ok(CopyRemoval::Absent)
        );
        let present = root.path().join("present");
        std::fs::create_dir(&present).expect("dir");
        std::fs::write(present.join(service_name()), b"svc").expect("file");
        assert_eq!(remove_copy_dir(&present), Ok(CopyRemoval::Removed));
        assert!(!present.exists());
    }

    #[test]
    fn a_link_planted_at_a_staging_name_is_not_written_through() {
        let target = tempfile::tempdir().expect("target");
        let victim = tempfile::tempdir().expect("victim");
        let staged = target
            .path()
            .join(format!("{}.{}.new", service_name(), std::process::id()));
        if !junction(&staged, victim.path()) {
            return;
        }
        let source = source_with(&[(service_name(), b"svc")]);
        let payload = Payload::read(&source.path().join(service_name())).expect("read");
        // The sweep removes the planted name first; if it could not, the
        // exclusive create refuses it. Either way nothing lands in the victim.
        let _ = payload.write_to(target.path());
        assert_eq!(
            std::fs::read_dir(victim.path()).expect("victim").count(),
            0,
            "written through a link at the staging name"
        );
        let _ = std::fs::remove_dir(&staged);
    }
}
