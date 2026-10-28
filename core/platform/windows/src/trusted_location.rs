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
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
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

/// [`open_admin_authored`] behind the neutral port.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsAdminAuthoredFiles;

impl nrr_platform_api::admin_authored::AdminAuthoredFiles for WindowsAdminAuthoredFiles {
    fn open_admin_authored(&self, path: &Path) -> nrr_platform_api::admin_authored::AdminAuthored {
        use nrr_platform_api::admin_authored::AdminAuthored;
        match open_admin_authored(path) {
            Ok(Some(file)) => AdminAuthored::Opened(file),
            Ok(None) => AdminAuthored::Missing,
            Err(why) => AdminAuthored::Refused(why),
        }
    }
}

/// `file` opened for reading when no ordinary account could have placed,
/// changed or swapped it, judged on the handle that is returned: opened as
/// the entry itself rather than a link's target, held without sharing write
/// or delete. Its folder and every folder above are judged on handles held
/// meanwhile: none may be a link, only trusted accounts may replace what is
/// inside, and nobody else may add files to the folder itself — one anyone
/// may add to is not an administrator's install folder, whoever wrote this
/// file. `Ok(None)` when absent, wherever it would have been: a copy of the
/// program in an open folder with no sheet beside it has nothing to report.
pub fn open_admin_authored(file: &Path) -> Result<Option<std::fs::File>, String> {
    open_trusting(file, &is_trusted).or_else(|why| match std::fs::symlink_metadata(file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        _ => Err(why),
    })
}

fn open_trusting(
    file: &Path,
    trusted: &dyn Fn(&str) -> bool,
) -> Result<Option<std::fs::File>, String> {
    let Some(held) = hold_chain(file)? else {
        return Ok(None);
    };
    match judge_held(&held, Beside::NotOpenToEveryone, trusted)? {
        Some(why) => Err(why),
        None => Ok(Some(held.file)),
    }
}

/// A file and every folder from the drive down to it, each opened as the
/// entry itself rather than a link's target and resolved to the place its
/// name says. The file is held without sharing write or delete, which on its
/// own keeps every folder above it from being renamed; each folder is held
/// without sharing delete too, unless another process already holds it so.
/// While this lives, the file's name leads to these same objects.
#[derive(Debug)]
pub(crate) struct HeldChain {
    /// The drive first, the file's own folder last.
    folders: Vec<(PathBuf, std::fs::File)>,
    path: PathBuf,
    file: std::fs::File,
}

impl HeldChain {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// `file` held as [`HeldChain`] says, judged for nothing but links and
/// location. `Ok(None)` when it or a folder above it is absent.
pub(crate) fn hold_chain(file: &Path) -> Result<Option<HeldChain>, String> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x1;
    let dir = file
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .ok_or_else(|| format!("{} has no folder", file.display()))?;
    let mut chain: Vec<&Path> = dir
        .ancestors()
        .take_while(|ancestor| !ancestor.as_os_str().is_empty())
        .collect();
    chain.reverse();
    let mut folders = Vec::with_capacity(chain.len());
    for folder in chain {
        let handle = match open_to_judge(folder) {
            Ok(handle) => handle,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("open {}: {e}", folder.display())),
        };
        judged_in_place(&handle, folder, false)?;
        folders.push((folder.to_path_buf(), handle));
    }
    let opened = match std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(file)
    {
        Ok(opened) => opened,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("open {}: {e}", file.display())),
    };
    judged_in_place(&opened, file, true)?;
    Ok(Some(HeldChain {
        folders,
        path: file.to_path_buf(),
        file: opened,
    }))
}

/// What the file's own folder must not let an ordinary account do.
#[derive(Clone, Copy)]
enum Beside {
    /// Add or remove anything: a program loads a library from beside itself
    /// before the system's.
    Nothing,
    /// Let every account add files: such a folder is nobody's install folder,
    /// whoever wrote the file in it.
    NotOpenToEveryone,
}

/// Who besides the trusted accounts could change the held program, add files
/// beside it or replace a folder above it, judged on the held handles; `None`
/// when nobody.
pub(crate) fn untrusted_writer_of(held: &HeldChain) -> Result<Option<String>, String> {
    judge_held(held, Beside::Nothing, &is_trusted)
}

fn judge_held(
    held: &HeldChain,
    beside: Beside,
    trusted: &dyn Fn(&str) -> bool,
) -> Result<Option<String>, String> {
    let own = held.folders.len().saturating_sub(1);
    for (index, (folder, handle)) in held.folders.iter().enumerate() {
        let descriptor = SecurityDescriptor::of_handle(handle)?;
        let (rights, verb) = match beside {
            Beside::Nothing if index == own => (PLANTS_BESIDE, "add files to"),
            _ => (REPLACES_SUBTREE, "replace what is inside"),
        };
        if let Some(found) = untrusted_rights_in(&descriptor, rights, trusted)? {
            return Ok(Some(format!("{found} can {verb} {}", folder.display())));
        }
        if matches!(beside, Beside::NotOpenToEveryone)
            && index == own
            && open_to_everyone_in(&descriptor)?
        {
            return Ok(Some(format!(
                "anyone can add files to {}",
                folder.display()
            )));
        }
    }
    let descriptor = SecurityDescriptor::of_handle(&held.file)?;
    Ok(untrusted_rights_in(&descriptor, REPLACES_FILE, trusted)?
        .map(|found| format!("{found} can change {}", held.path.display())))
}

const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// A folder opened to read its permissions, never through a link; held
/// without sharing delete, so it cannot be renamed while held. A folder some
/// process holds with delete access is opened without the pin: where each
/// handle resolves is still checked, and a file held below it still keeps it
/// from being renamed.
fn open_to_judge(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const READ_CONTROL: u32 = 0x2_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_SHARE_DELETE: u32 = 0x4;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    let open = |share: u32| {
        std::fs::OpenOptions::new()
            // Listing is data access: without it the share mode is not
            // enforced and the folder could be renamed while held.
            .access_mode(LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL)
            .share_mode(share)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    };
    match open(FILE_SHARE_READ | FILE_SHARE_WRITE) {
        Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => {
            open(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        }
        other => other,
    }
}

/// The handle holds what `path` names: not a link, of the expected kind, and
/// resolved to that same place, so no link higher up redirected the open.
fn judged_in_place(handle: &std::fs::File, path: &Path, is_file: bool) -> Result<(), String> {
    let meta = handle
        .metadata()
        .map_err(|e| format!("inspect {}: {e}", path.display()))?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!("{} is a link", path.display()));
    }
    if is_file != meta.is_file() || (!is_file && !meta.is_dir()) {
        return Err(format!(
            "{} is not a {}",
            path.display(),
            if is_file { "regular file" } else { "folder" }
        ));
    }
    let resolved = crate::pinned_file::final_path(handle)
        .map_err(|e| format!("resolve {}: {e}", path.display()))?;
    if !(crate::pinned_file::resolves_under(&resolved, path)
        && crate::pinned_file::resolves_under(path, &resolved))
    {
        return Err(format!("{} resolves elsewhere", path.display()));
    }
    Ok(())
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

/// An entry another account owned, moved out of the way, and where it went.
#[derive(Debug, PartialEq, Eq)]
pub struct SetAside {
    pub from: PathBuf,
    pub to: PathBuf,
}

/// Make `root` and everything under it owned by Administrators and reachable
/// by SYSTEM and Administrators only (`nrr_platform_api::data_tree_access`
/// decides, keeping an entry someone made stricter). A reparse point anywhere
/// in the tree, the root included, refuses the whole operation: a reset
/// through it would land outside the tree.
///
/// Entries owned by anyone else are taken over: the caller vetted the tree.
pub fn lock_down_service_tree(root: &Path) -> Result<(), LockdownError> {
    let options = Lockdown::production(TreeRule::Service);
    lock_down(root, &options).map(drop)
}

/// [`lock_down_service_tree`] for a tree nobody vetted, such as at every
/// service start: an entry owned outside SYSTEM and the administrators is
/// moved into `root\<aside>` first, so the reset that makes Administrators its
/// owner never passes it off as administrators' own work.
pub fn secure_service_tree(root: &Path, aside: &str) -> Result<Vec<SetAside>, LockdownError> {
    let mut options = Lockdown::production(TreeRule::Service);
    options.aside = Some(aside);
    lock_down(root, &options)
}

/// [`lock_down_service_tree`] for a folder of programs the service runs: the
/// same owner and protection, but Users may read and execute what is inside.
pub fn lock_down_program_tree(root: &Path) -> Result<(), LockdownError> {
    lock_down(root, &Lockdown::production(TreeRule::Program)).map(drop)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TreeRule {
    /// SYSTEM and Administrators, as `data_tree_access` plans it.
    Service,
    /// SYSTEM and Administrators, plus read and execute for Users.
    Program,
}

struct Lockdown<'a> {
    rule: TreeRule,
    /// Unset only in tests: handing ownership to Administrators needs elevation.
    set_owner: bool,
    aside: Option<&'a str>,
    trusted_owner: &'a dyn Fn(&str) -> bool,
    /// The SID written and read as Administrators; a test stands its own
    /// account in, since its unelevated token cannot use the group.
    administrators: &'a str,
}

const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

impl Lockdown<'static> {
    fn production(rule: TreeRule) -> Self {
        Self {
            rule,
            set_owner: true,
            aside: None,
            trusted_owner: &owner_counts_as_trusted,
            administrators: ADMINISTRATORS_SID,
        }
    }
}

/// SYSTEM, Administrators, TrustedInstaller, or an administrator's own
/// account: where a policy makes an administrator the owner of what they
/// create, a stop marker or a staged file is theirs.
fn owner_counts_as_trusted(sid: &str) -> bool {
    is_trusted(sid) || is_administrator(sid).unwrap_or(false)
}

/// The root is held open by handle from the start, without following a link
/// and without letting anyone rename it; every entry below is checked on its
/// own handle, link and location both, before its permissions are written.
/// The low-level write propagates nothing by name, so the tree is walked here.
fn lock_down(root: &Path, options: &Lockdown<'_>) -> Result<Vec<SetAside>, LockdownError> {
    // Before anything is written, so a tree with a link stays as found.
    if let Some(link) = first_reparse_point(root).map_err(LockdownError::Failed)? {
        return Err(LockdownError::Link(link));
    }
    let pinned = open_root(root, options.set_owner)?;
    let root_final = crate::pinned_file::final_path(&pinned)
        .map_err(|e| failed(root, "resolve", &e.to_string()))?;
    let passed = secure_root(&pinned, root, options)?;
    // From here on nobody else can add an entry to the root.
    if let Some(link) = first_reparse_point(root).map_err(LockdownError::Failed)? {
        return Err(LockdownError::Link(link));
    }
    let set_aside = match options.aside {
        Some(aside) => set_aside_foreign(root, &root_final, aside, options)?,
        None => Vec::new(),
    };
    let mut pending = children_of(root, &passed)?;
    while let Some((path, inherited)) = pending.pop() {
        let passed = secure_entry(&path, &root_final, &inherited, options)?;
        if let Some(passed) = passed {
            pending.extend(children_of(&path, &passed)?);
        }
    }
    // A link that appeared meanwhile is reported, so the caller does not take
    // the tree for clean.
    if let Some(link) = first_reparse_point(root).map_err(LockdownError::Failed)? {
        return Err(LockdownError::Link(link));
    }
    Ok(set_aside)
}

/// Pinned: open without `FILE_SHARE_DELETE`, so it cannot be renamed and
/// replaced while held. A handle someone else holds with delete access only
/// loses the pin; the walk below still checks where every entry resolves.
fn open_root(root: &Path, set_owner: bool) -> Result<std::fs::File, LockdownError> {
    const ERROR_SHARING_VIOLATION: i32 = 32;
    let opened = match open_entry(root, set_owner, false) {
        Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => {
            open_entry(root, set_owner, true)
        }
        other => other,
    }
    .map_err(|e| failed(root, "open", &e.to_string()))?;
    let meta = opened
        .metadata()
        .map_err(|e| failed(root, "inspect", &e.to_string()))?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(LockdownError::Link(root.to_path_buf()));
    }
    if !meta.is_dir() {
        return Err(failed(root, "inspect", "not a directory"));
    }
    Ok(opened)
}

/// Opens the entry itself, never what a link at it points to.
fn open_entry(path: &Path, set_owner: bool, share_delete: bool) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const READ_CONTROL: u32 = 0x2_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_SHARE_DELETE: u32 = 0x4;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let access =
        // LIST_DIRECTORY (read data on a file) is data access, without which
        // the share mode, and so the pin, is not enforced.
        LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | if set_owner { WRITE_OWNER } else { 0 };
    let share =
        FILE_SHARE_READ | FILE_SHARE_WRITE | if share_delete { FILE_SHARE_DELETE } else { 0 };
    std::fs::OpenOptions::new()
        .access_mode(access)
        .share_mode(share)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Writes the root's descriptor unless it is already strict enough; returns
/// what the root passes on to the entries below it.
fn secure_root(
    pinned: &std::fs::File,
    root: &Path,
    options: &Lockdown<'_>,
) -> Result<Vec<Ace>, LockdownError> {
    use nrr_platform_api::data_tree_access::{passed_on, plan_root, RootPlan};
    let aces = match options.rule {
        TreeRule::Program => program_aces(),
        TreeRule::Service => {
            let observed =
                observe(pinned, options).map_err(|e| failed(root, "read permissions of", &e))?;
            match plan_root(&observed) {
                RootPlan::Keep => return Ok(aces_of(&passed_on(&observed.grants))),
                RootPlan::Apply(grants) => aces_of(&grants),
            }
        }
    };
    let sddl = render(&aces, Rendered::Root, options);
    write_descriptor(
        pinned,
        &sddl,
        PROTECTED_DACL_SECURITY_INFORMATION.0,
        options.set_owner,
    )
    .map_err(|e| failed(root, "reset permissions on", &e))?;
    Ok(aces)
}

/// One entry below the root. `Some(passed on)` for a folder to walk into.
fn secure_entry(
    path: &Path,
    root_final: &Path,
    inherited: &[Ace],
    options: &Lockdown<'_>,
) -> Result<Option<Vec<Ace>>, LockdownError> {
    use nrr_platform_api::data_tree_access::{passed_on, plan_entry, EntryPlan};
    let entry = open_entry(path, options.set_owner, true)
        .map_err(|e| failed(path, "open", &e.to_string()))?;
    let meta = entry
        .metadata()
        .map_err(|e| failed(path, "inspect", &e.to_string()))?;
    let resolved = crate::pinned_file::final_path(&entry)
        .map_err(|e| failed(path, "resolve", &e.to_string()))?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !crate::pinned_file::resolves_under(&resolved, root_final)
    {
        return Err(LockdownError::Link(path.to_path_buf()));
    }
    if options.rule == TreeRule::Service {
        let observed =
            observe(&entry, options).map_err(|e| failed(path, "read permissions of", &e))?;
        if plan_entry(&observed, meta.is_dir()) == EntryPlan::Keep {
            return Ok(meta.is_dir().then(|| aces_of(&passed_on(&observed.grants))));
        }
    }
    let shape = if meta.is_dir() {
        Rendered::Folder
    } else {
        Rendered::File
    };
    let sddl = render(inherited, shape, options);
    write_descriptor(&entry, &sddl, UNPROTECTED_DACL_INFO, options.set_owner)
        .map_err(|e| failed(path, "reset permissions on", &e))?;
    Ok(meta.is_dir().then(|| inherited.to_vec()))
}

fn children_of(dir: &Path, passed: &[Ace]) -> Result<Vec<(PathBuf, Vec<Ace>)>, LockdownError> {
    let entries = std::fs::read_dir(dir).map_err(|e| failed(dir, "list", &e.to_string()))?;
    entries
        .map(|entry| {
            entry
                .map(|entry| (entry.path(), passed.to_vec()))
                .map_err(|e| failed(dir, "list", &e.to_string()))
        })
        .collect()
}

/// Moves every topmost entry below `root` that `trusted_owner` does not
/// accept into `root\<aside>`. Runs after the root is locked, so nothing new
/// can be planted meanwhile; the aside folder itself is never searched.
fn set_aside_foreign(
    root: &Path,
    root_final: &Path,
    aside: &str,
    options: &Lockdown<'_>,
) -> Result<Vec<SetAside>, LockdownError> {
    let aside_dir = root.join(aside);
    let mut foreign = Vec::new();
    let mut pending: Vec<PathBuf> = children_of(root, &[])?
        .into_iter()
        .map(|(path, _)| path)
        .filter(|path| *path != aside_dir)
        .collect();
    while let Some(path) = pending.pop() {
        let descriptor = SecurityDescriptor::of_file(&path).map_err(LockdownError::Failed)?;
        let (owner, _) = descriptor.owner_and_dacl().map_err(LockdownError::Failed)?;
        let owner = sid_string(owner).map_err(LockdownError::Failed)?;
        if !(options.trusted_owner)(&owner) {
            foreign.push(path);
        } else if std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()) {
            pending.extend(children_of(&path, &[])?.into_iter().map(|(path, _)| path));
        }
    }
    if foreign.is_empty() {
        return Ok(Vec::new());
    }
    match std::fs::create_dir(&aside_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(failed(&aside_dir, "create", &e.to_string())),
    }
    let held = open_entry(&aside_dir, false, true)
        .map_err(|e| failed(&aside_dir, "open", &e.to_string()))?;
    let resolved = crate::pinned_file::final_path(&held)
        .map_err(|e| failed(&aside_dir, "resolve", &e.to_string()))?;
    let is_link = held
        .metadata()
        .map(|meta| meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !meta.is_dir())
        .unwrap_or(true);
    if is_link || !crate::pinned_file::resolves_under(&resolved, root_final) {
        return Err(LockdownError::Link(aside_dir));
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis());
    foreign
        .into_iter()
        .enumerate()
        .map(|(index, from)| {
            let name = from.file_name().map_or_else(
                || "entry".to_string(),
                |name| name.to_string_lossy().into_owned(),
            );
            let to = aside_dir.join(format!("{stamp}-{index}-{name}"));
            std::fs::rename(&from, &to).map_err(|e| failed(&from, "set aside", &e.to_string()))?;
            Ok(SetAside { from, to })
        })
        .collect()
}

fn failed(path: &Path, what: &str, detail: &str) -> LockdownError {
    LockdownError::Failed(format!("{what} {}: {detail}", path.display()))
}

/// An allow entry as written: an SDDL account alias and its access mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ace {
    account: &'static str,
    mask: u32,
}

const FILE_ALL_ACCESS: u32 = 0x1F_01FF;
/// FILE_GENERIC_READ | FILE_GENERIC_EXECUTE.
const READ_AND_EXECUTE: u32 = 0x12_00A9;

/// Users may read and execute: the application and the console compare their
/// own copy of the service binary with the one registered.
fn program_aces() -> Vec<Ace> {
    vec![
        Ace {
            account: "SY",
            mask: FILE_ALL_ACCESS,
        },
        Ace {
            account: "BA",
            mask: FILE_ALL_ACCESS,
        },
        Ace {
            account: "BU",
            mask: READ_AND_EXECUTE,
        },
    ]
}

fn aces_of(grants: &[nrr_platform_api::data_tree_access::Grant]) -> Vec<Ace> {
    use nrr_platform_api::data_tree_access::Principal;
    grants
        .iter()
        .filter(|grant| !grant.deny)
        .filter_map(|grant| {
            let account = match grant.principal {
                Principal::Service => "SY",
                Principal::Administrators => "BA",
                Principal::Other => return None,
            };
            Some(Ace {
                account,
                mask: mask_of(grant.rights),
            })
        })
        .collect()
}

#[derive(Clone, Copy)]
enum Rendered {
    Root,
    Folder,
    File,
}

/// The descriptor as SDDL: the root protected and passing its entries on to
/// files and folders, an entry below holding them as inherited.
fn render(aces: &[Ace], shape: Rendered, options: &Lockdown<'_>) -> String {
    let (control, flags) = match shape {
        Rendered::Root => ("PAI", "OICI"),
        Rendered::Folder => ("AI", "OICIID"),
        Rendered::File => ("AI", "ID"),
    };
    let owner = if options.set_owner { "O:BA" } else { "" };
    let entries: String = aces
        .iter()
        .map(|ace| {
            let account = match ace.account {
                "BA" => options.administrators,
                other => other,
            };
            format!("(A;{flags};0x{:x};;;{account})", ace.mask)
        })
        .collect();
    format!("{owner}D:{control}{entries}")
}

const UNPROTECTED_DACL_INFO: u32 = 0x2000_0000;

/// `SetKernelObjectSecurity` on the open handle: it acts on that object alone
/// and walks nothing by name.
fn write_descriptor(
    file: &std::fs::File,
    sddl: &str,
    protection: u32,
    set_owner: bool,
) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{SetKernelObjectSecurity, OBJECT_SECURITY_INFORMATION};
    let descriptor = SecurityDescriptor::from_sddl(sddl)?;
    let owner = if set_owner {
        OWNER_SECURITY_INFORMATION.0
    } else {
        0
    };
    let info = OBJECT_SECURITY_INFORMATION(owner | DACL_SECURITY_INFORMATION.0 | protection);
    // SAFETY: the handle stays open for the borrow of `file`; the descriptor
    // is valid and outlives the call.
    unsafe { SetKernelObjectSecurity(HANDLE(file.as_raw_handle().cast()), info, descriptor.0) }
        .map_err(|e| e.to_string())
}

/// An entry's owner and DACL, read on its handle, in the neutral model.
fn observe(
    file: &std::fs::File,
    options: &Lockdown<'_>,
) -> Result<nrr_platform_api::data_tree_access::Observed, String> {
    use nrr_platform_api::data_tree_access::{Grant, Observed, Principal, Rights};
    use windows::Win32::Security::GetSecurityDescriptorControl;
    const SE_DACL_PROTECTED: u16 = 0x1000;

    let descriptor = SecurityDescriptor::of_handle(file)?;
    let (owner, dacl) = descriptor.owner_and_dacl()?;
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: a valid descriptor and two fresh out-locals.
    unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) }
        .map_err(|e| format!("read control: {e}"))?;
    let everyone_full = Grant {
        principal: Principal::Other,
        rights: Rights::FULL,
        deny: false,
        to_children: true,
    };
    let grants = if dacl.is_null() {
        vec![everyone_full]
    } else {
        // SAFETY: `dacl` points into `descriptor`, alive for the call.
        unsafe { grants_of(dacl, options.administrators) }?
    };
    Ok(Observed {
        protected: control & SE_DACL_PROTECTED != 0,
        owner_trusted: (options.trusted_owner)(&sid_string(owner)?),
        grants,
    })
}

/// Every entry of `dacl` in the neutral model. What the service and the
/// administrators are allowed counts only when every bit of a class is there;
/// what anyone else is allowed, and any denial, counts on a single bit. An
/// entry of a kind not read here counts as full access for someone else.
///
/// # Safety
///
/// `dacl` must point at a valid ACL that outlives the call.
unsafe fn grants_of(
    dacl: *const ACL,
    administrators: &str,
) -> Result<Vec<nrr_platform_api::data_tree_access::Grant>, String> {
    use nrr_platform_api::data_tree_access::{Grant, Principal, Rights};
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;
    const OBJECT_INHERIT: u8 = 0x1;
    const CONTAINER_INHERIT: u8 = 0x2;
    const NO_PROPAGATE: u8 = 0x4;
    let mut grants = Vec::new();
    // SAFETY: each ACE pointer `GetAce` returns stays inside the valid ACL;
    // allow and deny ACEs share the layout of `ACCESS_ALLOWED_ACE`.
    unsafe {
        for index in 0..u32::from((*dacl).AceCount) {
            let mut ace = std::ptr::null_mut();
            if GetAce(dacl, index, &mut ace).is_err() || ace.is_null() {
                return Err("read DACL entry".to_string());
            }
            let entry = &*(ace as *const ACCESS_ALLOWED_ACE);
            let kind = entry.Header.AceType;
            if kind != ACCESS_ALLOWED_ACE_TYPE && kind != ACCESS_DENIED_ACE_TYPE {
                grants.push(Grant {
                    principal: Principal::Other,
                    rights: Rights::FULL,
                    deny: false,
                    to_children: true,
                });
                continue;
            }
            let deny = kind == ACCESS_DENIED_ACE_TYPE;
            let flags = entry.Header.AceFlags;
            let sid = PSID(std::ptr::addr_of!(entry.SidStart) as *mut core::ffi::c_void);
            let account = sid_string(sid)?;
            let principal = if account.eq_ignore_ascii_case("S-1-5-18") {
                Principal::Service
            } else if account.eq_ignore_ascii_case(administrators) {
                Principal::Administrators
            } else {
                Principal::Other
            };
            let inherit_only = u32::from(flags) & INHERIT_ONLY_ACE.0 != 0;
            // An entry only passed on gives a trusted account nothing here.
            if inherit_only && !deny && principal != Principal::Other {
                continue;
            }
            let every_bit = !deny && principal != Principal::Other;
            grants.push(Grant {
                principal,
                rights: rights_of(entry.Mask, every_bit),
                deny,
                to_children: flags & OBJECT_INHERIT != 0
                    && flags & CONTAINER_INHERIT != 0
                    && flags & NO_PROPAGATE == 0,
            });
        }
    }
    Ok(grants)
}

const READ_CONTROL_RIGHT: u32 = 0x2_0000;
const READ_BITS: u32 = 0x1 | 0x8 | 0x80 | READ_CONTROL_RIGHT;
const EXECUTE_BIT: u32 = 0x20;
const CHANGE_BITS: u32 =
    FILE_WRITE_DATA | FILE_APPEND_DATA | 0x10 | FILE_DELETE_CHILD | 0x100 | DELETE;
const CONTROL_BITS: u32 = WRITE_DAC | WRITE_OWNER;
const SYNCHRONIZE: u32 = 0x10_0000;

fn rights_of(mask: u32, every_bit: bool) -> nrr_platform_api::data_tree_access::Rights {
    use nrr_platform_api::data_tree_access::Rights;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
    let mut bits = mask;
    if mask & (GENERIC_ALL | MAXIMUM_ALLOWED) != 0 {
        bits |= FILE_ALL_ACCESS;
    }
    if mask & GENERIC_READ != 0 {
        bits |= READ_BITS | SYNCHRONIZE;
    }
    if mask & GENERIC_WRITE != 0 {
        bits |= FILE_WRITE_DATA | FILE_APPEND_DATA | 0x10 | 0x100 | READ_CONTROL_RIGHT;
    }
    if mask & GENERIC_EXECUTE != 0 {
        bits |= EXECUTE_BIT | 0x80 | READ_CONTROL_RIGHT;
    }
    let class = |of: u32| {
        if every_bit {
            bits & of == of
        } else {
            bits & of != 0
        }
    };
    let mut rights = Rights::NONE;
    if class(READ_BITS) || (!every_bit && bits & EXECUTE_BIT != 0) {
        rights = rights.union(Rights::READ);
    }
    let unknown = bits
        & !(READ_BITS | EXECUTE_BIT | CHANGE_BITS | CONTROL_BITS | SYNCHRONIZE)
        & !(GENERIC_ALL | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | MAXIMUM_ALLOWED);
    if class(CHANGE_BITS) || (!every_bit && unknown != 0) {
        rights = rights.union(Rights::CHANGE);
    }
    if class(CONTROL_BITS) || (!every_bit && bits & ACCESS_SYSTEM_SECURITY != 0) {
        rights = rights.union(Rights::CONTROL);
    }
    rights
}

fn mask_of(rights: nrr_platform_api::data_tree_access::Rights) -> u32 {
    use nrr_platform_api::data_tree_access::Rights;
    if rights.contains(Rights::FULL) {
        return FILE_ALL_ACCESS;
    }
    let mut mask = 0;
    if rights.contains(Rights::READ) {
        mask |= READ_AND_EXECUTE;
    }
    if rights.contains(Rights::CHANGE) {
        mask |= CHANGE_BITS | SYNCHRONIZE | READ_CONTROL_RIGHT;
    }
    if rights.contains(Rights::CONTROL) {
        mask |= CONTROL_BITS | READ_CONTROL_RIGHT;
    }
    mask
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
    untrusted_rights_in(&SecurityDescriptor::of_file(path)?, rights, &is_trusted)
}

fn untrusted_rights_in(
    descriptor: &SecurityDescriptor,
    rights: u32,
    trusted: &dyn Fn(&str) -> bool,
) -> Result<Option<String>, String> {
    let (owner, dacl) = descriptor.owner_and_dacl()?;
    let owner_sid = sid_string(owner)?;
    if !trusted(&owner_sid) {
        return Ok(Some(format!("its owner {owner_sid}")));
    }
    if dacl.is_null() {
        return Ok(Some("everyone (no DACL)".to_string()));
    }
    // SAFETY: `dacl` points into `descriptor`, alive for the call.
    unsafe { first_allowed(dacl, rights, &|sid| !trusted(sid)) }
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
    open_to_everyone_in(&SecurityDescriptor::of_file(dir)?)
}

fn open_to_everyone_in(descriptor: &SecurityDescriptor) -> Result<bool, String> {
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

/// `FILE_LIST_DIRECTORY` on a folder, `FILE_READ_DATA` on a file.
const LIST_DIRECTORY: u32 = 0x1;

/// Whether the account `sid` may list `dir`, judged by the folder's own DACL
/// for that account and the groups the system resolves for it.
pub fn sid_may_list(dir: &Path, sid: &str) -> Result<bool, String> {
    use windows::Win32::Security::GROUP_SECURITY_INFORMATION;

    let wide_path = wide(dir.as_os_str());
    let mut raw = PSECURITY_DESCRIPTOR::default();
    // SAFETY: NUL-terminated path borrowed for the call; the descriptor is
    // LocalAlloc'd and owned by `descriptor` below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide_path.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut raw,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!("read permissions: Win32 error {}", status.0));
    }
    sid_granted(&SecurityDescriptor(raw), sid, LIST_DIRECTORY)
}

/// Whether the account `sid` belongs to Administrators, as the system resolves
/// its groups — not whether a process of it runs elevated.
pub fn is_administrator(sid: &str) -> Result<bool, String> {
    const PROBE: u32 = 0x1;
    let only_administrators = SecurityDescriptor::from_sddl("O:SYG:SYD:(A;;0x1;;;BA)")?;
    sid_granted(&only_administrators, sid, PROBE)
}

/// Whether `descriptor` grants the account `sid` every bit of `desired`.
fn sid_granted(descriptor: &SecurityDescriptor, sid: &str, desired: u32) -> Result<bool, String> {
    use windows::Win32::Foundation::LUID;
    use windows::Win32::Security::Authorization::{
        AuthzAccessCheck, AuthzFreeContext, AuthzFreeResourceManager,
        AuthzInitializeContextFromSid, AuthzInitializeResourceManager, ConvertStringSidToSidW,
        AUTHZ_ACCESS_CHECK_FLAGS, AUTHZ_ACCESS_REPLY, AUTHZ_ACCESS_REQUEST,
        AUTHZ_AUDIT_EVENT_HANDLE, AUTHZ_CLIENT_CONTEXT_HANDLE, AUTHZ_RESOURCE_MANAGER_HANDLE,
        AUTHZ_RM_FLAG_NO_AUDIT,
    };

    let wide_sid = wide(OsStr::new(sid));
    let mut account = PSID::default();
    // SAFETY: NUL-terminated input; the SID is LocalAlloc'd and freed below.
    unsafe { ConvertStringSidToSidW(PCWSTR(wide_sid.as_ptr()), &mut account) }
        .map_err(|e| format!("read SID: {e}"))?;
    let mut manager = AUTHZ_RESOURCE_MANAGER_HANDLE::default();
    let mut context = AUTHZ_CLIENT_CONTEXT_HANDLE::default();
    // SAFETY: every handle is initialised by the call that fills it and freed
    // once below; the request and reply point at locals alive for the check,
    // and the descriptor outlives it.
    let granted = unsafe {
        let checked = AuthzInitializeResourceManager(
            AUTHZ_RM_FLAG_NO_AUDIT.0,
            None,
            None,
            None,
            PCWSTR::null(),
            &mut manager,
        )
        .and_then(|()| {
            AuthzInitializeContextFromSid(
                0,
                account,
                manager,
                None,
                LUID::default(),
                None,
                &mut context,
            )
        })
        .and_then(|()| {
            let request = AUTHZ_ACCESS_REQUEST {
                DesiredAccess: desired,
                ..AUTHZ_ACCESS_REQUEST::default()
            };
            let mut mask = 0u32;
            let mut error = 0u32;
            let mut reply = AUTHZ_ACCESS_REPLY {
                ResultListLength: 1,
                GrantedAccessMask: &mut mask,
                Error: &mut error,
                ..AUTHZ_ACCESS_REPLY::default()
            };
            AuthzAccessCheck(
                AUTHZ_ACCESS_CHECK_FLAGS(0),
                context,
                &request,
                AUTHZ_AUDIT_EVENT_HANDLE::default(),
                descriptor.0,
                None,
                &mut reply,
                None,
            )
            .map(|()| error == 0 && mask & desired == desired)
        });
        if !context.is_invalid() {
            let _ = AuthzFreeContext(context);
        }
        if !manager.is_invalid() {
            let _ = AuthzFreeResourceManager(manager);
        }
        let _ = LocalFree(HLOCAL(account.0));
        checked
    };
    granted.map_err(|e| format!("access check: {e}"))
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

    /// The owner and DACL of the object an open handle holds.
    fn of_handle(file: &std::fs::File) -> Result<Self, String> {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::Authorization::GetSecurityInfo;
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the handle stays open for the borrow of `file`; the
        // descriptor is LocalAlloc'd and owned by the returned value.
        let status = unsafe {
            GetSecurityInfo(
                HANDLE(file.as_raw_handle().cast()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                Some(&mut descriptor),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("read permissions: Win32 error {}", status.0));
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

    /// A folder closed to everyone but SYSTEM is not listable for a person;
    /// the system folder is.
    #[test]
    fn only_a_folder_open_to_the_account_lists_for_it() {
        let me = crate::win32_ffi::console_session::current_process_user_sid().expect("own SID");
        let windows = crate::system_shell::system32_exe("cmd.exe");
        let system32 = windows.parent().expect("System32");
        assert_eq!(sid_may_list(system32, &me), Ok(true));

        let dir = tempfile::tempdir().expect("tempdir");
        let icacls = |args: &[&str]| {
            std::process::Command::new(crate::system_shell::system32_exe("icacls.exe"))
                .arg(dir.path())
                .args(args)
                .output()
                .expect("run icacls")
        };
        assert_eq!(sid_may_list(dir.path(), &me), Ok(true), "a folder it made");
        // CI runners give a new folder explicit entries, which `/inheritance:r`
        // leaves in place; planted here so every machine starts the same way.
        let planted = icacls(&[
            "/grant",
            &format!("*{me}:(OI)(CI)F"),
            "*S-1-5-32-544:(OI)(CI)F",
            "/Q",
        ]);
        assert!(planted.status.success(), "icacls: {planted:?}");
        let reset = icacls(&["/reset", "/Q"]);
        assert!(reset.status.success(), "icacls: {reset:?}");
        let closed = icacls(&["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/Q"]);
        assert!(closed.status.success(), "icacls: {closed:?}");
        let verdict = sid_may_list(dir.path(), &me);
        // What the check saw, for a machine where it differs from ours.
        let acl = String::from_utf8_lossy(&icacls(&[]).stdout).into_owned();
        let groups = std::process::Command::new(crate::system_shell::system32_exe("whoami.exe"))
            .args(["/user", "/groups", "/fo", "list"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        // The owner keeps the right to change the DACL, so it can open it
        // again for the temp folder to be removed.
        let _ = icacls(&["/reset", "/Q"]);
        assert_eq!(verdict, Ok(false), "acl:\n{acl}\naccount:\n{groups}");
    }

    #[test]
    fn a_system_tool_is_out_of_reach_of_ordinary_accounts() {
        let tool = crate::system_shell::system32_exe("icacls.exe");
        assert_eq!(untrusted_writer(&tool), Ok(None));
    }

    #[test]
    fn a_binary_in_a_user_created_directory_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Not `.exe`: the check reads rights, not the name, and an executable
        // dropped in a temp folder makes some antivirus hold the whole process.
        let binary = dir.path().join("service.bin");
        std::fs::write(&binary, b"placeholder").expect("write");
        let found = untrusted_writer(&binary).expect("readable");
        assert!(
            found.is_some(),
            "a directory the test user owns is not trusted"
        );
    }

    #[test]
    fn a_file_a_user_could_have_placed_is_refused_and_a_system_file_is_opened() {
        let system = crate::system_shell::system32_exe("icacls.exe");
        assert!(matches!(open_admin_authored(&system), Ok(Some(_))));
        let dir = tempfile::tempdir().expect("tempdir");
        let sheet = dir.path().join("first-run.json");
        std::fs::write(&sheet, b"{}").expect("write");
        own_by_this_user(dir.path());
        assert!(open_admin_authored(&sheet).is_err());
        assert!(matches!(
            open_admin_authored(&dir.path().join("absent.json")),
            Ok(None)
        ));
    }

    /// The folder reached through a junction is not the folder named: what
    /// was judged would not be what is read.
    #[test]
    fn a_sheet_reached_through_a_junction_is_refused() {
        let target = tempfile::tempdir().expect("tempdir");
        std::fs::write(target.path().join("first-run.json"), b"{}").expect("write");
        let holder = tempfile::tempdir().expect("tempdir");
        let link = holder.path().join("NetRuleRouter");
        let made = std::process::Command::new(crate::system_shell::system32_exe("cmd.exe"))
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(target.path())
            .output()
            .expect("run mklink");
        if !made.status.success() {
            return; // Junctions need no privilege, but a locked-down host may refuse.
        }
        // Only the groups everyone belongs to count as ordinary here, so the
        // chain through this account's profile passes and only the junction
        // is left to refuse.
        let trusted = |sid: &str| !ANYONE_SIDS.iter().any(|a| a.eq_ignore_ascii_case(sid));
        let through_link = open_trusting(&link.join("first-run.json"), &trusted);
        let direct = open_trusting(&target.path().join("first-run.json"), &trusted);
        let _ = std::fs::remove_dir(&link);
        let why = through_link.expect_err("refused");
        assert!(why.contains("is a link"), "{why}");
        assert!(matches!(direct, Ok(Some(_))), "{direct:?}");
    }

    /// A program the service would start in a user's name, in a folder that
    /// user owns, is reported from what the held handles say.
    #[test]
    fn a_program_in_a_folder_a_user_owns_is_reported_on_its_handles() {
        let dir = tempfile::tempdir().expect("tempdir");
        let program = dir.path().join("tray.bin");
        std::fs::write(&program, b"placeholder").expect("write");
        own_by_this_user(dir.path());
        let held = hold_chain(&program).expect("held").expect("present");
        let found = untrusted_writer_of(&held).expect("readable");
        assert!(found.is_some(), "a folder the test user owns is trusted");
    }

    /// A junction anywhere on the program's path would let what is judged
    /// and what is started be two different files: the hold refuses it.
    #[test]
    fn a_junction_in_a_programs_folder_chain_is_refused() {
        let target = tempfile::tempdir().expect("tempdir");
        std::fs::write(target.path().join("tray.bin"), b"placeholder").expect("write");
        let holder = tempfile::tempdir().expect("tempdir");
        let link = holder.path().join("NetRuleRouter");
        let made = std::process::Command::new(crate::system_shell::system32_exe("cmd.exe"))
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(target.path())
            .output()
            .expect("run mklink");
        if !made.status.success() {
            return; // Junctions need no privilege, but a locked-down host may refuse.
        }
        let through_link = hold_chain(&link.join("tray.bin"));
        let direct = hold_chain(&target.path().join("tray.bin"));
        let _ = std::fs::remove_dir(&link);
        let why = through_link.expect_err("held through a junction");
        assert!(why.contains(&link.display().to_string()), "{why}");
        assert!(matches!(direct, Ok(Some(_))), "{direct:?}");
    }

    /// While a folder is held nobody may rename it or remove it to put a
    /// junction in its place.
    #[test]
    fn a_held_folder_cannot_be_renamed_or_removed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let folder = dir.path().join("NetRuleRouter");
        std::fs::create_dir(&folder).expect("mkdir");
        let aside = dir.path().join("aside");
        let held = open_to_judge(&folder).expect("held");
        let renamed = std::fs::rename(&folder, &aside);
        let removed = std::fs::remove_dir(&folder);
        drop(held);
        assert!(renamed.is_err(), "renamed while held");
        assert!(removed.is_err(), "removed while held");
        std::fs::rename(&folder, &aside).expect("released");
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
        let file = dir.path().join("service.bin");
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

    const USERS: &str = "S-1-5-32-545";

    fn me() -> String {
        crate::win32_ffi::console_session::current_process_user_sid().expect("own SID")
    }

    /// Who owns a file this run just made: the account itself, or
    /// Administrators when the run is elevated.
    fn owner_of(path: &Path) -> String {
        let descriptor = SecurityDescriptor::of_file(path).expect("readable");
        let (owner, _) = descriptor.owner_and_dacl().expect("owner");
        sid_string(owner).expect("owner SID")
    }

    fn icacls(path: &Path, args: &[&str]) {
        let done = std::process::Command::new(crate::system_shell::system32_exe("icacls.exe"))
            .arg(path)
            .args(args)
            .output()
            .expect("run icacls");
        assert!(done.status.success(), "icacls {args:?}: {done:?}");
    }

    /// The lockdown as an unelevated run can carry it out: its own account
    /// stands in for Administrators, and owners stay as they are.
    fn lock_down_as_me(
        root: &Path,
        aside: Option<&str>,
        trusted_owner: &dyn Fn(&str) -> bool,
    ) -> Result<Vec<SetAside>, LockdownError> {
        let me = me();
        let options = Lockdown {
            rule: TreeRule::Service,
            set_owner: false,
            aside,
            trusted_owner,
            administrators: &me,
        };
        lock_down(root, &options)
    }

    /// Every account an allow entry on `path` names, inherited ones included.
    fn allowed_accounts(path: &Path) -> Vec<String> {
        let descriptor = SecurityDescriptor::of_file(path).expect("readable");
        let (_, dacl) = descriptor.owner_and_dacl().expect("DACL");
        let found = std::cell::RefCell::new(Vec::new());
        // SAFETY: `dacl` points into `descriptor`, alive for the call.
        let _ = unsafe {
            first_allowed(dacl, u32::MAX, &|sid| {
                found.borrow_mut().push(sid.to_ascii_uppercase());
                false
            })
        };
        found.into_inner()
    }

    fn is_protected(path: &Path) -> bool {
        use windows::Win32::Security::GetSecurityDescriptorControl;
        let descriptor = SecurityDescriptor::of_file(path).expect("readable");
        let (mut control, mut revision) = (0u16, 0u32);
        // SAFETY: a valid descriptor and two fresh out-locals.
        unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) }
            .expect("control");
        control & 0x1000 != 0
    }

    /// A data folder inherits from ProgramData the right of every user to
    /// create files in it; after the lockdown nobody but the service and the
    /// administrators has any entry anywhere in it, and it inherits nothing.
    #[test]
    fn a_folder_users_could_plant_files_in_is_closed_to_them_and_cut_from_its_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("NetRuleRouter");
        let state = root.join("nrr_service_state.db");
        let log = root.join("logs").join("service.log");
        std::fs::create_dir_all(log.parent().expect("parent")).expect("mkdir");
        std::fs::write(&state, b"rules").expect("write");
        std::fs::write(&log, b"line").expect("write");
        icacls(
            &root,
            &["/grant", &format!("*{USERS}:(OI)(CI)(WD,AD)"), "/Q"],
        );
        icacls(&state, &["/grant", &format!("*{USERS}:(M)"), "/Q"]);
        assert_eq!(open_to_everyone(&root), Ok(true), "users may plant files");

        lock_down_as_me(&root, None, &|_| true).expect("locked down");

        assert_eq!(open_to_everyone(&root), Ok(false));
        assert!(
            is_protected(&root),
            "the root still inherits from its parent"
        );
        for path in [&root, &state, &root.join("logs"), &log] {
            let accounts = allowed_accounts(path);
            assert!(
                !accounts.contains(&USERS.to_string()),
                "{path:?}: {accounts:?}"
            );
            assert!(
                accounts.contains(&"S-1-5-18".to_string()),
                "{path:?}: {accounts:?}"
            );
        }
        assert_eq!(std::fs::read(&state).expect("readable"), b"rules");
    }

    /// The lockdown runs at every start; a file narrowed to the service alone
    /// must not be opened back up to administrators by the next one.
    #[test]
    fn a_file_sealed_tighter_than_the_tree_keeps_its_seal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("NetRuleRouter");
        let sealed = root.join("sealed.bin");
        std::fs::create_dir_all(&root).expect("mkdir");
        std::fs::write(&sealed, b"secret").expect("write");
        // Administrators (this account, here) may read it and change its
        // permissions, never its contents.
        let me = me();
        // Explicit entries as a CI runner gives a new file; the seal replaces them.
        icacls(
            &sealed,
            &["/grant", &format!("*{me}:F"), "*S-1-5-32-544:F", "/Q"],
        );
        icacls(&sealed, &["/reset", "/Q"]);
        icacls(
            &sealed,
            &[
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:F",
                &format!("*{me}:(RX,WDAC)"),
                "/Q",
            ],
        );
        let before = dacl_sddl(&sealed);

        lock_down_as_me(&root, None, &|_| true).expect("locked down");

        assert_eq!(dacl_sddl(&sealed), before);
        assert!(before.starts_with("D:P"), "{before}");
    }

    fn dacl_sddl(path: &Path) -> String {
        use windows::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
        let descriptor = SecurityDescriptor::of_file(path).expect("readable");
        let mut raw = PWSTR::null();
        // SAFETY: a valid descriptor; the string is LocalAlloc'd and freed after
        // it is copied.
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut raw,
                None,
            )
            .expect("SDDL");
            let text = raw.to_string().expect("UTF-16");
            let _ = LocalFree(HLOCAL(raw.0.cast()));
            text
        }
    }

    /// A data root swapped for a junction would carry the reset to wherever it
    /// points; the target must come out exactly as it was.
    #[test]
    fn a_link_in_place_of_the_root_is_refused_and_its_target_left_alone() {
        let target = tempfile::tempdir().expect("tempdir");
        let file = target.path().join("other.txt");
        std::fs::write(&file, b"x").expect("write");
        icacls(
            target.path(),
            &["/grant", &format!("*{USERS}:(OI)(CI)(WD,AD)"), "/Q"],
        );
        let before = (allowed_accounts(target.path()), allowed_accounts(&file));
        let holder = tempfile::tempdir().expect("tempdir");
        let link = holder.path().join("NetRuleRouter");
        let made = std::process::Command::new(crate::system_shell::system32_exe("cmd.exe"))
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(target.path())
            .output()
            .expect("run mklink");
        if !made.status.success() {
            return; // Junctions need no privilege, but a locked-down host may refuse.
        }

        let outcome = lock_down_as_me(&link, Some("set-aside"), &|_| true);

        let after = (allowed_accounts(target.path()), allowed_accounts(&file));
        let _ = std::fs::remove_dir(&link);
        assert_eq!(outcome, Err(LockdownError::Link(link.clone())));
        assert_eq!(after, before);
    }

    /// Before the lockdown any account could put a file or folder into the
    /// tree; the reset makes Administrators the owner of everything, so a
    /// planted answer sheet or staged file would then pass for an
    /// administrator's. It is moved out of use first, and only once.
    #[test]
    fn what_another_account_planted_is_set_aside_not_adopted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("NetRuleRouter");
        let sheet = root.join("first-run.json");
        let staged = root.join("provision").join("rules_primary.txt");
        std::fs::create_dir_all(staged.parent().expect("parent")).expect("mkdir");
        std::fs::write(&sheet, b"{}").expect("write");
        std::fs::write(&staged, b"example.com").expect("write");
        let planter = owner_of(&sheet);
        let not_planter = |sid: &str| !sid.eq_ignore_ascii_case(&planter);

        let moved = lock_down_as_me(&root, Some("set-aside"), &not_planter).expect("locked down");

        let mut from: Vec<_> = moved.iter().map(|entry| entry.from.clone()).collect();
        from.sort();
        assert_eq!(from, vec![sheet.clone(), root.join("provision")]);
        assert!(!sheet.exists() && !staged.exists());
        for entry in &moved {
            assert!(entry.to.starts_with(root.join("set-aside")), "{entry:?}");
            assert!(entry.to.exists(), "{entry:?}");
        }
        assert_eq!(
            lock_down_as_me(&root, Some("set-aside"), &not_planter),
            Ok(Vec::new()),
            "what was set aside is not moved again"
        );
    }

    /// A copy of the program in a folder the user owns — a download, a desktop
    /// folder — must not seed the setup from a sheet left beside it.
    #[test]
    fn a_sheet_beside_a_program_in_a_users_own_folder_is_not_believed() {
        use nrr_platform_api::admin_authored::AdminAuthoredFiles;
        use nrr_shared::first_run_sheet::{search, PROVISIONING_FILE_NAME};
        let install = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            install.path().join(PROVISIONING_FILE_NAME),
            r#"{"leak-protection":"off","doh-lockdown":false,"fake-ip":false,"rule-set":"none"}"#,
        )
        .expect("write");
        own_by_this_user(install.path());
        let candidates = nrr_platform_api::paths::first_run_sheet_candidates(Some(install.path()));

        let outcome = search(&candidates, &|path| {
            WindowsAdminAuthoredFiles.open_admin_authored(path)
        });

        assert_eq!(outcome.found, None);
        assert_eq!(outcome.ignored.len(), 1, "{:?}", outcome.ignored);
    }

    #[test]
    fn an_administrator_account_is_told_apart_from_an_ordinary_one() {
        assert_eq!(is_administrator("S-1-5-18"), Ok(true));
        assert_eq!(is_administrator(USERS), Ok(false));
    }
}
