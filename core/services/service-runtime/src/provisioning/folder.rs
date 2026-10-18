//! The provisioning folder on disk: bounded reads that refuse a link or a
//! file another account could have written, staging the installer's files,
//! and marking them done.
//!
//! On Windows the folder sits in the service data tree, which every service
//! start locks to SYSTEM and Administrators before anything in it is opened.
//! Elsewhere it is under `/etc` and placed by root, so ownership and mode are
//! checked here.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use super::bundle::{BundleBytes, ProvisionPart, ProvisionRefusal};
use super::{
    OPTIONS_FILE, OPTIONS_MAX_BYTES, PRIMARY_FILE, RULES_MAX_BYTES, SECONDARY_FILE, SETTINGS_FILE,
    SETTINGS_MAX_BYTES,
};

const PARTS: [(ProvisionPart, &str, usize); 4] = [
    (ProvisionPart::Primary, PRIMARY_FILE, RULES_MAX_BYTES),
    (ProvisionPart::Secondary, SECONDARY_FILE, RULES_MAX_BYTES),
    (ProvisionPart::Settings, SETTINGS_FILE, SETTINGS_MAX_BYTES),
    (ProvisionPart::Options, OPTIONS_FILE, OPTIONS_MAX_BYTES),
];

/// What a processed file is renamed to: it stays for the administrator to
/// look at and is never read again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessedAs {
    Applied,
    Refused,
}

impl ProcessedAs {
    const fn suffix(self) -> &'static str {
        match self {
            Self::Applied => ".applied",
            Self::Refused => ".refused",
        }
    }
}

/// The account a staged entry must belong to off Windows: root.
pub(crate) const ROOT_UID: u32 = 0;

/// The staged files of `dir`, `None` when there are none (or no folder).
pub fn read_bundle(dir: &Path) -> Result<Option<BundleBytes>, ProvisionRefusal> {
    read_bundle_owned_by(dir, ROOT_UID)
}

/// [`read_bundle`] trusting `owner` instead of root: what a test running as
/// an ordinary user can stage.
pub(crate) fn read_bundle_owned_by(
    dir: &Path,
    owner: u32,
) -> Result<Option<BundleBytes>, ProvisionRefusal> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => trusted_entry(&meta, true, owner)
            .map_err(|why| ProvisionRefusal::new(ProvisionPart::Folder, "folder-untrusted", why))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(ProvisionRefusal::new(
                ProvisionPart::Folder,
                "folder-unreadable",
                e.to_string(),
            ))
        }
    }
    let mut bundle = BundleBytes::default();
    for (part, name, limit) in PARTS {
        let path = dir.join(name);
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(ProvisionRefusal::new(
                    part,
                    "file-unreadable",
                    e.to_string(),
                ))
            }
        };
        trusted_entry(&meta, false, owner)
            .map_err(|why| ProvisionRefusal::new(part, "file-untrusted", why))?;
        let bytes = read_bounded(&path, limit)
            .map_err(|(code, why)| ProvisionRefusal::new(part, code, why))?;
        *slot(&mut bundle, part) = Some(bytes);
    }
    Ok((!bundle.is_empty()).then_some(bundle))
}

/// A file named on the installer's command line, read once: what is checked
/// is what gets staged.
pub fn read_source_file(path: &Path, part: ProvisionPart) -> Result<Vec<u8>, ProvisionRefusal> {
    let limit = PARTS
        .iter()
        .find(|(p, _, _)| *p == part)
        .map_or(RULES_MAX_BYTES, |(_, _, limit)| *limit);
    let meta = fs::metadata(path).map_err(|e| {
        ProvisionRefusal::new(part, "file-unreadable", format!("{}: {e}", path.display()))
    })?;
    if !meta.is_file() {
        return Err(ProvisionRefusal::new(
            part,
            "not-a-file",
            format!("{} is not a regular file", path.display()),
        ));
    }
    read_bounded(path, limit).map_err(|(code, why)| ProvisionRefusal::new(part, code, why))
}

/// Write `bundle` into `dir`, replacing whatever an earlier install staged and
/// the service never applied. Each file lands whole or not at all.
pub fn stage_bundle(dir: &Path, bundle: &BundleBytes) -> std::io::Result<()> {
    stage_bundle_owned_by(dir, bundle, ROOT_UID)
}

pub(crate) fn stage_bundle_owned_by(
    dir: &Path,
    bundle: &BundleBytes,
    owner: u32,
) -> std::io::Result<()> {
    prepare_dir(dir, owner)?;
    for (part, name, _) in PARTS {
        let path = dir.join(name);
        match slot_ref(bundle, part) {
            Some(bytes) => write_whole(dir, name, bytes)?,
            None => match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            },
        }
    }
    Ok(())
}

/// Rename every staged file to its processed name. A failure is reported: a
/// file left under its own name would be applied again at the next start.
pub fn mark_processed(dir: &Path, outcome: ProcessedAs) -> std::io::Result<()> {
    let mut first_error = None;
    for (_, name, _) in PARTS {
        let from = dir.join(name);
        if fs::symlink_metadata(&from).is_err() {
            continue;
        }
        let to = dir.join(format!("{name}{}", outcome.suffix()));
        if let Err(e) = fs::rename(&from, &to) {
            // Not renamable: removing it still keeps it from a second apply.
            if let Err(e2) = fs::remove_file(&from) {
                first_error.get_or_insert(std::io::Error::new(e.kind(), format!("{e}; {e2}")));
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn slot(bundle: &mut BundleBytes, part: ProvisionPart) -> &mut Option<Vec<u8>> {
    match part {
        ProvisionPart::Primary => &mut bundle.primary,
        ProvisionPart::Secondary => &mut bundle.secondary,
        ProvisionPart::Settings => &mut bundle.settings,
        ProvisionPart::Options | ProvisionPart::Folder => &mut bundle.options,
    }
}

fn slot_ref(bundle: &BundleBytes, part: ProvisionPart) -> Option<&[u8]> {
    match part {
        ProvisionPart::Primary => bundle.primary.as_deref(),
        ProvisionPart::Secondary => bundle.secondary.as_deref(),
        ProvisionPart::Settings => bundle.settings.as_deref(),
        ProvisionPart::Options | ProvisionPart::Folder => bundle.options.as_deref(),
    }
}

/// Read at most `limit` bytes; one more is the refusal.
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, (&'static str, String)> {
    let file = fs::File::open(path)
        .map_err(|e| ("file-unreadable", format!("{}: {e}", path.display())))?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| ("file-unreadable", format!("{}: {e}", path.display())))?;
    if bytes.len() > limit {
        return Err((
            "file-too-large",
            format!("{} is larger than {limit} bytes", path.display()),
        ));
    }
    Ok(bytes)
}

/// A link is refused everywhere: what it points at is not what was staged.
/// Off Windows the entry must also belong to root and be writable by nobody
/// else.
fn trusted_entry(meta: &fs::Metadata, want_dir: bool, owner: u32) -> Result<(), String> {
    if meta.file_type().is_symlink() {
        return Err("is a link".to_owned());
    }
    if want_dir && !meta.is_dir() {
        return Err("is not a directory".to_owned());
    }
    if !want_dir && !meta.is_file() {
        return Err("is not a regular file".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != owner {
            return Err(format!("belongs to uid {}, not {owner}", meta.uid()));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(format!(
                "is writable by group or others (mode {:o})",
                meta.mode() & 0o777
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = owner;
    Ok(())
}

fn prepare_dir(dir: &Path, owner: u32) -> std::io::Result<()> {
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        match fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    #[cfg(not(unix))]
    fs::create_dir_all(dir)?;
    let meta = fs::symlink_metadata(dir)?;
    trusted_entry(&meta, true, owner).map_err(|why| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{}: {why}", dir.display()),
        )
    })
}

fn write_whole(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let staging = dir.join(format!("{name}.staging"));
    let _ = fs::remove_file(&staging);
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&staging)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    // Replaces an existing file on every OS (MoveFileEx with replace on Windows).
    fs::rename(&staging, dir.join(name))
}
