//! The `provision-check` and `provision-stage` verbs of the service binary,
//! neutral so both platforms run the same parsing and the same exit codes.
//!
//! `check` has no side effects. `stage` validates the very bytes it then
//! writes into the protected folder, so nothing can be swapped between the
//! two; the installers call it before the service is started.

use std::path::{Path, PathBuf};

use nrr_domain::rules_file::HostPlatform;
use nrr_storage::install_policy::SecondaryUnset;

use super::bundle::{check_bundle, options_file_text, BundleBytes, InstallOptions, ProvisionPart};
use super::exit;
use super::folder::{read_source_file, stage_bundle};

/// What the command line named. Empty values count as not given: an MSI
/// property left unset still arrives as `""`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProvisionArgs {
    pub primary: Option<PathBuf>,
    pub secondary: Option<PathBuf>,
    pub settings: Option<PathBuf>,
    pub secondary_unset: Option<String>,
}

impl ProvisionArgs {
    fn is_empty(&self) -> bool {
        self.primary.is_none()
            && self.secondary.is_none()
            && self.settings.is_none()
            && self.secondary_unset.is_none()
    }
}

/// Usage text, shared by both binaries.
pub const USAGE: &str = "provision-check | provision-stage \
[--primary <file>] [--secondary <file>] [--settings <file>] [--secondary-unset direct|block]";

/// `--name value` and `--name=value`, any number of leading dashes.
pub fn parse_args(args: &[String]) -> Result<ProvisionArgs, String> {
    let mut parsed = ProvisionArgs::default();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let bare = arg.trim_start_matches(['-', '/']);
        let (name, inline) = match bare.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (bare, None),
        };
        let value = match inline {
            Some(value) => value,
            None => rest
                .next()
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value"))?,
        };
        let value = value.trim().to_owned();
        let path = || (!value.is_empty()).then(|| PathBuf::from(&value));
        match name.to_ascii_lowercase().as_str() {
            "primary" => parsed.primary = path(),
            "secondary" => parsed.secondary = path(),
            "settings" => parsed.settings = path(),
            "secondary-unset" | "secondary_unset" => {
                parsed.secondary_unset = (!value.is_empty()).then(|| value.clone());
            }
            _ => return Err(format!("unknown option {arg}")),
        }
    }
    Ok(parsed)
}

/// Read and check everything named. `Err` carries the exit code and the line
/// for the administrator.
fn load(args: &[String]) -> Result<BundleBytes, (u8, String)> {
    let parsed = parse_args(args).map_err(|e| (exit::USAGE, format!("{e}\nusage: {USAGE}")))?;
    if parsed.is_empty() {
        return Err((exit::USAGE, format!("nothing to check\nusage: {USAGE}")));
    }
    let read = |path: &Option<PathBuf>, part| {
        path.as_deref()
            .map(|p| read_source_file(p, part))
            .transpose()
            .map_err(|refusal| (refusal.part.exit_code(), refusal.to_string()))
    };
    let mut bundle = BundleBytes {
        primary: read(&parsed.primary, ProvisionPart::Primary)?,
        secondary: read(&parsed.secondary, ProvisionPart::Secondary)?,
        settings: read(&parsed.settings, ProvisionPart::Settings)?,
        options: None,
    };
    if let Some(raw) = parsed.secondary_unset.as_deref() {
        let unset = SecondaryUnset::from_slug(&raw.to_ascii_lowercase()).ok_or_else(|| {
            (
                exit::OPTION_REFUSED,
                format!("secondary-unset {raw:?} refused: expected direct or block"),
            )
        })?;
        bundle.options = options_file_text(&InstallOptions {
            secondary_unset: Some(unset),
        })
        .map(String::into_bytes);
    }
    check_bundle(&bundle, HostPlatform::compiled())
        .map_err(|refusal| (refusal.part.exit_code(), refusal.to_string()))?;
    Ok(bundle)
}

/// `provision-check`: the exit code and what to print.
pub fn run_check(args: &[String]) -> (u8, String) {
    match load(args) {
        Ok(_) => (exit::OK, "the files can be provisioned".to_owned()),
        Err(failure) => failure,
    }
}

/// `provision-stage`: check, then write into `dir`.
pub fn run_stage(args: &[String], dir: &Path) -> (u8, String) {
    let bundle = match load(args) {
        Ok(bundle) => bundle,
        Err(failure) => return failure,
    };
    match stage_bundle(dir, &bundle) {
        Ok(()) => (
            exit::OK,
            format!(
                "staged in {}; the service applies them at its next start",
                dir.display()
            ),
        ),
        Err(e) => (
            exit::STAGE_FAILED,
            format!("could not write {}: {e}", dir.display()),
        ),
    }
}
