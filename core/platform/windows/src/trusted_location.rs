//! Whether a path a privileged process relies on is out of reach of ordinary
//! accounts, and making the service's own data tree so.
//!
//! The service runs as LocalSystem from the binary it was registered with, and
//! keeps its rules and audit trail in a tree under `%ProgramData%`, where any
//! user may create a directory first and stay its owner. Both are only as safe
//! as the permissions on disk, so both are checked against the DACL itself.
#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, BOOL, ERROR_SUCCESS, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, ProgressInvokeNever, TreeResetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetAce, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACCESS_ALLOWED_ACE, ACL,
    DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

const FILE_WRITE_DATA: u32 = 0x2; // FILE_ADD_FILE on a directory
const FILE_APPEND_DATA: u32 = 0x4; // FILE_ADD_SUBDIRECTORY on a directory
const FILE_DELETE_CHILD: u32 = 0x40;
const DELETE: u32 = 0x1_0000;
const WRITE_DAC: u32 = 0x4_0000;
const WRITE_OWNER: u32 = 0x8_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// Rights that let the holder replace the file's contents or the file itself.
const REPLACES_FILE: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_ALL
    | GENERIC_WRITE;
/// Rights on the containing directory that let the holder put a file beside it
/// (a DLL is found there first) or remove the binary.
const PLANTS_BESIDE: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_ALL
    | GENERIC_WRITE;
/// Rights on a directory further up that let the holder rename or replace the
/// subtree below it. Creating a new sibling is not one: `C:\` lets every user
/// do that, and it changes nothing under `Program Files`.
const REPLACES_SUBTREE: u32 = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;

/// SYSTEM, Administrators and TrustedInstaller — the accounts that already
/// hold every right the service has.
const TRUSTED_SIDS: &[&str] = &[
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// SYSTEM and Administrators own the tree and alone may touch it.
const SERVICE_TREE_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// As above, plus read and execute for Users (`0x1200a9`: FILE_GENERIC_READ |
/// FILE_GENERIC_EXECUTE): the application and the console compare their own
/// copy of the service binary with the one registered.
const PROGRAM_TREE_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

/// Who besides the trusted accounts could change `binary`, if anyone: an
/// account named in a description, or `None` when only trusted accounts can.
pub fn untrusted_writer(binary: &Path) -> Result<Option<String>, String> {
    if let Some(found) = untrusted_rights(binary, REPLACES_FILE)? {
        return Ok(Some(format!("{found} can change {}", binary.display())));
    }
    let Some(dir) = binary.parent() else {
        return Ok(None);
    };
    if let Some(found) = untrusted_rights(dir, PLANTS_BESIDE)? {
        return Ok(Some(format!("{found} can add files to {}", dir.display())));
    }
    for ancestor in dir.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        if let Some(found) = untrusted_rights(ancestor, REPLACES_SUBTREE)? {
            return Ok(Some(format!(
                "{found} can replace what is inside {}",
                ancestor.display()
            )));
        }
    }
    Ok(None)
}

/// Who besides the trusted accounts could have written `file` or swapped it,
/// if anyone. A reparse point at the file or its folder counts: what it points
/// at is not what an administrator placed. Adding new files to the folder does
/// not: ProgramData lets every user do that, and it changes no existing file.
pub fn untrusted_author(file: &Path) -> Result<Option<String>, String> {
    let dir = file.parent();
    for path in std::iter::once(file).chain(dir) {
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| format!("inspect {}: {e}", path.display()))?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Ok(Some(format!("{} is a link", path.display())));
        }
    }
    if !std::fs::symlink_metadata(file)
        .map_err(|e| format!("inspect {}: {e}", file.display()))?
        .is_file()
    {
        return Ok(Some(format!("{} is not a regular file", file.display())));
    }
    if let Some(found) = untrusted_rights(file, REPLACES_FILE)? {
        return Ok(Some(format!("{found} can change {}", file.display())));
    }
    for ancestor in dir.into_iter().flat_map(Path::ancestors) {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        if let Some(found) = untrusted_rights(ancestor, REPLACES_SUBTREE)? {
            return Ok(Some(format!(
                "{found} can replace what is inside {}",
                ancestor.display()
            )));
        }
    }
    Ok(None)
}

/// [`untrusted_author`] behind the neutral port.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsAdminAuthoredFiles;

impl nrr_platform_api::admin_authored::AdminAuthoredFiles for WindowsAdminAuthoredFiles {
    fn untrusted_because(&self, path: &Path) -> Option<String> {
        untrusted_author(path).unwrap_or_else(Some)
    }
}

/// Why the service tree could not be locked down.
#[derive(Debug, PartialEq, Eq)]
pub enum LockdownError {
    /// A reparse point sits in the tree: someone pointed part of it elsewhere,
    /// and anything written or reset through it would land there.
    Link(PathBuf),
    Failed(String),
}

impl std::fmt::Display for LockdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Link(path) => write!(f, "{} is a link out of the service tree", path.display()),
            Self::Failed(detail) => f.write_str(detail),
        }
    }
}

/// Make `root` and everything under it owned by Administrators and reachable
/// by SYSTEM and Administrators only: explicit entries anywhere below are
/// dropped, and children inherit the root's protected DACL. A reparse point
/// anywhere in the tree refuses the whole operation — the reset would follow
/// it out of the tree.
pub fn lock_down_service_tree(root: &Path) -> Result<(), LockdownError> {
    lock_down_tree(root, SERVICE_TREE_SDDL)
}

/// [`lock_down_service_tree`] for a folder of programs the service runs: the
/// same owner and protection, but Users may read and execute what is inside.
pub fn lock_down_program_tree(root: &Path) -> Result<(), LockdownError> {
    lock_down_tree(root, PROGRAM_TREE_SDDL)
}

fn lock_down_tree(root: &Path, sddl: &str) -> Result<(), LockdownError> {
    if let Some(link) = first_reparse_point(root).map_err(LockdownError::Failed)? {
        return Err(LockdownError::Link(link));
    }
    let descriptor = SecurityDescriptor::from_sddl(sddl).map_err(LockdownError::Failed)?;
    let (owner, dacl) = descriptor.owner_and_dacl().map_err(LockdownError::Failed)?;
    let wide = wide(root.as_os_str());
    // SAFETY: `wide` is a NUL-terminated path borrowed for the call; `owner`
    // and `dacl` point into `descriptor`, which outlives it. No progress callback.
    let status = unsafe {
        TreeResetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            PSID::default(),
            Some(dacl),
            None,
            BOOL(0),
            None,
            ProgressInvokeNever,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(LockdownError::Failed(format!(
            "reset permissions on {}: Win32 error {}",
            root.display(),
            status.0
        )));
    }
    Ok(())
}

/// Whether `path` is owned by SYSTEM, Administrators or TrustedInstaller.
pub fn owner_is_trusted(path: &Path) -> Result<bool, String> {
    let descriptor = SecurityDescriptor::of_file(path)?;
    let (owner, _) = descriptor.owner_and_dacl()?;
    Ok(is_trusted(&sid_string(owner)?))
}

/// Every path at or below `root`, and those owned outside
/// SYSTEM/Administrators/TrustedInstaller. Reparse points are listed but not
/// entered: [`lock_down_service_tree`] refuses them anyway.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TreeOwnership {
    pub entries: std::collections::BTreeSet<PathBuf>,
    pub foreign: std::collections::BTreeSet<PathBuf>,
}

/// Reads [`TreeOwnership`]. An entry whose owner cannot be read is an error,
/// never "trusted": an account can deny even administrators that read.
pub fn tree_ownership(root: &Path) -> Result<TreeOwnership, String> {
    let mut census = TreeOwnership::default();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("inspect {}: {e}", path.display()))?;
        if !owner_is_trusted(&path)? {
            census.foreign.insert(path.clone());
        }
        if meta.is_dir() && meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
            let entries =
                std::fs::read_dir(&path).map_err(|e| format!("list {}: {e}", path.display()))?;
            for entry in entries {
                let entry = entry.map_err(|e| format!("list {}: {e}", path.display()))?;
                pending.push(entry.path());
            }
        }
        census.entries.insert(path);
    }
    Ok(census)
}

/// The first path at or below `root` that is a reparse point, if any.
pub fn first_reparse_point(root: &Path) -> Result<Option<PathBuf>, String> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("inspect {}: {e}", path.display()))?;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Ok(Some(path));
        }
        if meta.is_dir() {
            let entries =
                std::fs::read_dir(&path).map_err(|e| format!("list {}: {e}", path.display()))?;
            for entry in entries {
                let entry = entry.map_err(|e| format!("list {}: {e}", path.display()))?;
                pending.push(entry.path());
            }
        }
    }
    Ok(None)
}

/// The first account outside [`TRUSTED_SIDS`] that owns `path` or is allowed
/// any of `rights` on it.
fn untrusted_rights(path: &Path, rights: u32) -> Result<Option<String>, String> {
    let descriptor = SecurityDescriptor::of_file(path)?;
    let (owner, dacl) = descriptor.owner_and_dacl()?;
    let owner_sid = sid_string(owner)?;
    if !is_trusted(&owner_sid) {
        return Ok(Some(format!("its owner {owner_sid}")));
    }
    if dacl.is_null() {
        return Ok(Some("everyone (no DACL)".to_string()));
    }
    // SAFETY: `dacl` points into `descriptor`, alive for the call.
    unsafe { first_allowed(dacl, rights, &|sid| !is_trusted(sid)) }
}

/// Groups every account that signs in belongs to: Everyone, Authenticated
/// Users, Users, Interactive, Guests, Anonymous.
const ANYONE_SIDS: &[&str] = &[
    "S-1-1-0",
    "S-1-5-11",
    "S-1-5-32-545",
    "S-1-5-4",
    "S-1-5-32-546",
    "S-1-5-7",
];

/// Rights on a folder that let the holder put a program into it.
const ADDS_PROGRAMS: u32 =
    FILE_WRITE_DATA | FILE_APPEND_DATA | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE;

/// Whether a group every account belongs to may add files or folders to
/// `dir`, as `C:\Users\Public` and most of `C:\ProgramData` let Users do.
pub fn open_to_everyone(dir: &Path) -> Result<bool, String> {
    let descriptor = SecurityDescriptor::of_file(dir)?;
    let (_, dacl) = descriptor.owner_and_dacl()?;
    if dacl.is_null() {
        return Ok(true);
    }
    let anyone = |sid: &str| ANYONE_SIDS.iter().any(|a| a.eq_ignore_ascii_case(sid));
    // SAFETY: `dacl` points into `descriptor`, alive for the call.
    Ok(unsafe { first_allowed(dacl, ADDS_PROGRAMS, &anyone) }?.is_some())
}

/// The first account `dacl` allows any of `rights` that `counts` picks.
///
/// # Safety
///
/// `dacl` must point at a valid ACL that outlives the call.
unsafe fn first_allowed(
    dacl: *const ACL,
    rights: u32,
    counts: &dyn Fn(&str) -> bool,
) -> Result<Option<String>, String> {
    // SAFETY: each ACE pointer `GetAce` returns stays inside the valid ACL,
    // and only allow-type ACEs — whose layout is `ACCESS_ALLOWED_ACE` with the
    // SID following the mask — are read.
    unsafe {
        for index in 0..u32::from((*dacl).AceCount) {
            let mut ace = std::ptr::null_mut();
            if GetAce(dacl, index, &mut ace).is_err() || ace.is_null() {
                continue;
            }
            let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
            if allowed.Header.AceType != ACCESS_ALLOWED_ACE_TYPE
                || u32::from(allowed.Header.AceFlags) & INHERIT_ONLY_ACE.0 != 0
                || allowed.Mask & rights == 0
            {
                continue;
            }
            let sid = PSID(std::ptr::addr_of!(allowed.SidStart) as *mut core::ffi::c_void);
            let sid = sid_string(sid)?;
            if counts(&sid) {
                return Ok(Some(sid));
            }
        }
    }
    Ok(None)
}

fn is_trusted(sid: &str) -> bool {
    TRUSTED_SIDS
        .iter()
        .any(|trusted| trusted.eq_ignore_ascii_case(sid))
}

fn sid_string(sid: PSID) -> Result<String, String> {
    let mut raw = PWSTR::null();
    // SAFETY: `sid` points at a valid SID inside a live descriptor; the
    // returned string is LocalAlloc'd and released right after it is copied.
    unsafe {
        ConvertSidToStringSidW(sid, &mut raw).map_err(|e| format!("read SID: {e}"))?;
        let text = raw.to_string().map_err(|e| format!("read SID: {e}"));
        let _ = LocalFree(HLOCAL(raw.0.cast()));
        text
    }
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

/// A LocalAlloc'd self-relative security descriptor, freed on drop.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, String> {
        let wide_sddl = wide(OsStr::new(sddl));
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: NUL-terminated input borrowed for the call; on success the
        // descriptor is LocalAlloc'd and owned by the returned value.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide_sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|e| format!("build descriptor: {e}"))?;
        Ok(Self(descriptor))
    }

    fn of_file(path: &Path) -> Result<Self, String> {
        let wide_path = wide(path.as_os_str());
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: NUL-terminated path borrowed for the call; the owner and
        // DACL are read later out of the returned descriptor, which is
        // LocalAlloc'd and owned by the returned value.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide_path.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!(
                "read permissions of {}: Win32 error {}",
                path.display(),
                status.0
            ));
        }
        Ok(Self(descriptor))
    }

    /// Owner and DACL, pointing into this descriptor.
    fn owner_and_dacl(&self) -> Result<(PSID, *const ACL), String> {
        let mut owner = PSID::default();
        let mut defaulted = BOOL(0);
        let mut present = BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `self.0` is a valid descriptor for the lifetime of `self`;
        // the out-pointers are fresh locals.
        unsafe {
            GetSecurityDescriptorOwner(self.0, &mut owner, &mut defaulted)
                .map_err(|e| format!("read owner: {e}"))?;
            GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted)
                .map_err(|e| format!("read DACL: {e}"))?;
        }
        if owner.0.is_null() {
            return Err("descriptor carries no owner".to_string());
        }
        Ok((
            owner,
            if present.as_bool() {
                dacl
            } else {
                std::ptr::null()
            },
        ))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor was LocalAlloc'd by the API that produced it.
        let _ = unsafe { LocalFree(HLOCAL(self.0 .0)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An elevated admin's new objects belong to Administrators (CI runners
    /// run so), which would make "a user's directory" trusted.
    fn own_by_this_user(root: &Path) {
        let sid = crate::win32_ffi::console_session::current_process_user_sid().expect("own SID");
        let done = std::process::Command::new(crate::system_shell::system32_exe("icacls.exe"))
            .arg(root)
            .args(["/setowner", &format!("*{sid}"), "/T", "/Q"])
            .output()
            .expect("run icacls");
        assert!(done.status.success(), "icacls /setowner: {done:?}");
    }

    #[test]
    fn a_system_tool_is_out_of_reach_of_ordinary_accounts() {
        let tool = crate::system_shell::system32_exe("icacls.exe");
        assert_eq!(untrusted_writer(&tool), Ok(None));
    }

    #[test]
    fn a_binary_in_a_user_created_directory_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = dir.path().join("service.exe");
        std::fs::write(&binary, b"placeholder").expect("write");
        let found = untrusted_writer(&binary).expect("readable");
        assert!(
            found.is_some(),
            "a directory the test user owns is not trusted"
        );
    }

    #[test]
    fn a_file_a_user_could_have_placed_has_an_untrusted_author_and_a_system_file_does_not() {
        assert_eq!(
            untrusted_author(&crate::system_shell::system32_exe("cmd.exe")),
            Ok(None)
        );
        let dir = tempfile::tempdir().expect("tempdir");
        let sheet = dir.path().join("first-run.json");
        std::fs::write(&sheet, b"{}").expect("write");
        own_by_this_user(dir.path());
        assert!(untrusted_author(&sheet).expect("readable").is_some());
    }

    #[test]
    fn a_link_inside_the_tree_is_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = tempfile::tempdir().expect("tempdir");
        let link = dir.path().join("logs");
        let made = std::process::Command::new(crate::system_shell::system32_exe("cmd.exe"))
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(target.path())
            .output()
            .expect("run mklink");
        if !made.status.success() {
            return; // Junctions need no privilege, but a locked-down host may refuse.
        }
        assert_eq!(first_reparse_point(dir.path()), Ok(Some(link.clone())));
        assert_eq!(
            lock_down_service_tree(dir.path()),
            Err(LockdownError::Link(link.clone()))
        );
        let _ = std::fs::remove_dir(&link);
    }

    #[test]
    fn a_system_directory_has_a_trusted_owner_and_a_user_directory_does_not() {
        let system32 = crate::system_shell::system32_exe("cmd.exe");
        let system32 = system32.parent().expect("System32");
        assert_eq!(owner_is_trusted(system32), Ok(true));
        let dir = tempfile::tempdir().expect("tempdir");
        own_by_this_user(dir.path());
        assert_eq!(owner_is_trusted(dir.path()), Ok(false));
    }

    #[test]
    fn a_tree_this_user_created_is_reported_as_foreign_with_every_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("logs").join("planted.db");
        std::fs::create_dir_all(file.parent().expect("parent")).expect("mkdir");
        std::fs::write(&file, b"x").expect("write");
        own_by_this_user(dir.path());
        let census = tree_ownership(dir.path()).expect("readable");
        assert_eq!(census.entries.len(), 3);
        assert_eq!(census.foreign, census.entries);
        assert!(census.entries.contains(&file));
    }

    #[test]
    fn a_program_tree_lets_users_read_but_change_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("service.exe");
        std::fs::write(&file, b"image").expect("write");
        if lock_down_program_tree(dir.path()).is_err() {
            return; // handing ownership to Administrators needs an elevated run
        }
        assert_eq!(untrusted_rights(dir.path(), PLANTS_BESIDE), Ok(None));
        assert_eq!(untrusted_rights(&file, REPLACES_FILE), Ok(None));
        assert_eq!(std::fs::read(&file).expect("readable"), b"image");
    }

    /// A folder Users may write into lets anyone put a program there; the
    /// system folder does not.
    #[test]
    fn a_folder_users_may_write_into_is_open_to_everyone() {
        let system = crate::system_shell::system32_exe("icacls.exe");
        let system_dir = system.parent().expect("System32");
        assert_eq!(open_to_everyone(system_dir), Ok(false));
        let dir = tempfile::tempdir().expect("tempdir");
        let done = std::process::Command::new(&system)
            .arg(dir.path())
            .args(["/grant", "*S-1-5-32-545:(OI)(CI)(W)", "/Q"])
            .output()
            .expect("run icacls");
        assert!(done.status.success(), "icacls /grant: {done:?}");
        assert_eq!(open_to_everyone(dir.path()), Ok(true));
    }

    #[test]
    fn a_plain_tree_has_no_link() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("logs").join("inner")).expect("mkdir");
        assert_eq!(first_reparse_point(dir.path()), Ok(None));
    }
}
