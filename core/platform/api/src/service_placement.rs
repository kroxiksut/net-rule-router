//! Where the service binary is registered from — the decision half.
//!
//! The service runs with full system rights from the file it is registered
//! with, so that file and its folder must be out of reach of ordinary accounts.
//! A copy unpacked anywhere — the desktop, a USB stick — is not. Rather than
//! refuse it, an install that finds its binary somewhere ordinary accounts can
//! change registers a copy kept in a folder only administrators can change.
//!
//! What that folder is, how it is protected and how files reach it is the OS
//! mechanism's business. What to do given what is there is decided here, once,
//! without an OS. A platform whose install already copies the binary into a
//! system location (Linux) never asks.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::service_control::ServiceStatusReport;

/// Whether this install registers a protected copy rather than the binary it
/// was given. A development build registers its build output in place: that is
/// where it lives by design, and the mechanism says so in a warning.
#[must_use]
pub const fn registers_protected_copy(source_protected: bool, development_build: bool) -> bool {
    !source_protected && !development_build
}

/// The protected copy, compared with the files the install was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyState {
    /// No copy yet.
    Missing,
    /// Every file holds the same bytes as the source.
    Current,
    /// A file is missing, differs, or is one the source no longer ships.
    Stale,
}

/// What the service manager has registered when the install starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisteredFrom {
    /// Nothing is registered.
    Nothing,
    /// The protected copy is registered; `running` while its process is up.
    TheCopy { running: bool },
    /// Some other binary is registered.
    Elsewhere,
}

/// What the install does about the protected copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyPlan {
    /// Write the copy, then register it.
    WriteAndRegister,
    /// The copy already holds these files: register it as it stands.
    Register,
    /// Registered from a current copy: nothing to change.
    Nothing,
    /// Registered from an out-of-date copy: stop the service, replace the
    /// files, and start it again if it was running.
    Update { restart: bool },
    /// Another binary is registered. Replacing that registration is what
    /// `reinstall` exists for; an install must not write files on its way to
    /// failing on the existing name.
    RefuseRegisteredElsewhere,
}

/// Decide what an install that registers a protected copy does.
#[must_use]
pub const fn plan_copy(copy: CopyState, registered: RegisteredFrom) -> CopyPlan {
    match (registered, copy) {
        (RegisteredFrom::Elsewhere, _) => CopyPlan::RefuseRegisteredElsewhere,
        (RegisteredFrom::Nothing, CopyState::Current) => CopyPlan::Register,
        (RegisteredFrom::Nothing, CopyState::Missing | CopyState::Stale) => {
            CopyPlan::WriteAndRegister
        }
        (RegisteredFrom::TheCopy { .. }, CopyState::Current) => CopyPlan::Nothing,
        (RegisteredFrom::TheCopy { running }, CopyState::Missing | CopyState::Stale) => {
            CopyPlan::Update { restart: running }
        }
    }
}

/// Whether two files hold the same bytes. Unreadable is "not the same", so a
/// caller asking "is that a copy of this one" never answers yes on a guess.
#[must_use]
pub fn same_contents(a: &Path, b: &Path) -> bool {
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(ma), Ok(mb)) if ma.len() == mb.len() => {}
        _ => return false,
    }
    let (Ok(fa), Ok(fb)) = (std::fs::File::open(a), std::fs::File::open(b)) else {
        return false;
    };
    same_stream(fa, fb).unwrap_or(false)
}

/// Chunk by chunk, stopping at the first difference: the binaries run to tens
/// of megabytes, and the callers include a check run on a struggling machine.
pub fn same_stream(mut a: impl Read, mut b: impl Read) -> std::io::Result<bool> {
    const CHUNK: usize = 64 * 1024;
    let (mut x, mut y) = (vec![0u8; CHUNK], vec![0u8; CHUNK]);
    loop {
        let n = read_full(&mut a, &mut x)?;
        if n != read_full(&mut b, &mut y)? || x[..n] != y[..n] {
            return Ok(false);
        }
        if n == 0 {
            return Ok(true);
        }
    }
}

/// How the registered service stands against the one shipped beside a client:
/// the window and the terminal tell the user the same thing from it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegistrationCheck {
    /// What the service manager starts, when it says.
    pub registered_path: Option<PathBuf>,
    /// The service binary shipped with this client, when it is there.
    pub expected_path: Option<PathBuf>,
    /// The manager starts another binary than the shipped one.
    pub registered_elsewhere: bool,
    /// The registered file was replaced after its process started, so the
    /// previous build is what runs.
    pub binary_replaced: bool,
}

impl RegistrationCheck {
    /// Unprivileged, and answerable with the service stopped.
    #[must_use]
    pub fn of(report: Option<&ServiceStatusReport>, expected: Option<&Path>) -> Self {
        let registered = report
            .and_then(|r| r.binary_path.clone())
            .filter(|p| !p.as_os_str().is_empty());
        let registered_elsewhere = match (registered.as_deref(), expected) {
            (Some(registered), Some(expected)) => registered_elsewhere(registered, expected),
            _ => false,
        };
        // An update written over the same folder changes neither the
        // registration nor the version string, yet the process still runs
        // the code it loaded before.
        let binary_replaced = report
            .and_then(binary_is_newer_than_process)
            .unwrap_or(false);
        Self {
            registered_path: registered,
            expected_path: expected.map(Path::to_path_buf),
            registered_elsewhere,
            binary_replaced,
        }
    }

    /// The registration is right and only a restart runs the update.
    #[must_use]
    pub fn restart_needed(&self) -> bool {
        self.binary_replaced && !self.registered_elsewhere
    }
}

/// Whether the registered binary on disk is newer than the process running
/// from it. `None` whenever that cannot be established (service stopped, no
/// start time from the OS, unreadable file): "unknown" must never become a
/// prompt telling the user their service is stale.
#[must_use]
pub fn binary_is_newer_than_process(report: &ServiceStatusReport) -> Option<bool> {
    let started = report.running_since?;
    let path = report.binary_path.as_ref()?;
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    // A second of slack: the file timestamp and the process clock come from
    // different sources, and a start that races its own binary's write would
    // otherwise report itself stale.
    Some(modified > started + std::time::Duration::from_secs(1))
}

/// Whether the service manager starts another binary than `expected`. A
/// byte-identical copy is this binary: an install from a folder ordinary
/// accounts can change registers exactly such a copy, and offering to
/// "update" it would only write the same copy again.
#[must_use]
pub fn registered_elsewhere(registered: &Path, expected: &Path) -> bool {
    !same_path(registered, expected) && !same_contents(registered, expected)
}

/// Case- and spelling-insensitive path comparison. Canonicalisation resolves
/// `\\?\` prefixes, 8.3 names and links; a path that cannot be canonicalised
/// falls back to a plain case-insensitive compare.
fn same_path(left: &Path, right: &Path) -> bool {
    match (
        std::fs::canonicalize(left).ok(),
        std::fs::canonicalize(right).ok(),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => left
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy()),
    }
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_release_binary_outside_protection_is_copied() {
        assert!(registers_protected_copy(false, false));
        assert!(!registers_protected_copy(true, false), "already protected");
        assert!(
            !registers_protected_copy(false, true),
            "a development build runs from its build output"
        );
        assert!(!registers_protected_copy(true, true));
    }

    #[test]
    fn a_fresh_install_writes_the_copy_unless_it_is_already_current() {
        assert_eq!(
            plan_copy(CopyState::Missing, RegisteredFrom::Nothing),
            CopyPlan::WriteAndRegister
        );
        assert_eq!(
            plan_copy(CopyState::Stale, RegisteredFrom::Nothing),
            CopyPlan::WriteAndRegister
        );
        assert_eq!(
            plan_copy(CopyState::Current, RegisteredFrom::Nothing),
            CopyPlan::Register
        );
    }

    #[test]
    fn a_registered_copy_is_updated_and_restarted_only_if_it_ran() {
        for copy in [CopyState::Missing, CopyState::Stale] {
            assert_eq!(
                plan_copy(copy, RegisteredFrom::TheCopy { running: true }),
                CopyPlan::Update { restart: true }
            );
            assert_eq!(
                plan_copy(copy, RegisteredFrom::TheCopy { running: false }),
                CopyPlan::Update { restart: false }
            );
        }
    }

    #[test]
    fn a_current_registered_copy_is_left_alone() {
        for running in [true, false] {
            assert_eq!(
                plan_copy(CopyState::Current, RegisteredFrom::TheCopy { running }),
                CopyPlan::Nothing
            );
        }
    }

    #[test]
    fn another_registration_is_refused_whatever_the_copy_holds() {
        for copy in [CopyState::Missing, CopyState::Current, CopyState::Stale] {
            assert_eq!(
                plan_copy(copy, RegisteredFrom::Elsewhere),
                CopyPlan::RefuseRegisteredElsewhere
            );
        }
    }

    #[test]
    fn streams_compare_chunk_by_chunk_to_the_last_byte() {
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let same = |a: &[u8], b: &[u8]| same_stream(a, b).expect("in memory");
        assert!(same(&big, &big));
        let mut last_differs = big.clone();
        *last_differs.last_mut().expect("bytes") ^= 1;
        assert!(!same(&big, &last_differs));
        assert!(!same(&big, &big[..big.len() - 1]));
        assert!(same(&[], &[]));
    }

    #[test]
    fn files_compare_by_content_and_a_missing_one_is_never_the_same() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (a, b, c) = (
            dir.path().join("a"),
            dir.path().join("b"),
            dir.path().join("c"),
        );
        std::fs::write(&a, b"service").expect("write a");
        std::fs::write(&b, b"service").expect("write b");
        std::fs::write(&c, b"servicf").expect("write c");
        assert!(same_contents(&a, &b));
        assert!(!same_contents(&a, &c));
        assert!(!same_contents(&a, &dir.path().join("missing")));
    }

    #[test]
    fn a_protected_copy_of_our_own_service_is_not_registered_elsewhere() {
        let shipped_dir = tempfile::tempdir().expect("shipped dir");
        let copy_dir = tempfile::tempdir().expect("copy dir");
        let shipped = shipped_dir.path().join("service.bin");
        let copy = copy_dir.path().join("service.bin");
        std::fs::write(&shipped, b"this build").expect("shipped");
        std::fs::write(&copy, b"this build").expect("copy");
        assert!(!registered_elsewhere(&copy, &shipped));
        assert!(!registered_elsewhere(&shipped, &shipped));

        std::fs::write(&copy, b"an older build").expect("older copy");
        assert!(registered_elsewhere(&copy, &shipped));
        assert!(
            registered_elsewhere(&copy_dir.path().join("gone.bin"), &shipped),
            "a registered binary that cannot be read is not taken for ours"
        );
    }

    fn report(path: &Path, running_since: Option<std::time::SystemTime>) -> ServiceStatusReport {
        ServiceStatusReport {
            run_state: crate::service_control::ServiceRunState::Running,
            start_mode: None,
            binary_path: Some(path.to_path_buf()),
            running_since,
        }
    }

    /// A file replaced after its process started asks for a restart; a
    /// stopped service or a file written before the start never does, and a
    /// registration elsewhere asks for re-registering instead.
    #[test]
    fn only_a_binary_replaced_under_a_running_process_asks_for_a_restart() {
        let dir = tempfile::tempdir().expect("temp dir");
        let registered = dir.path().join("service.bin");
        std::fs::write(&registered, b"new build").expect("binary");
        let long_ago = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1);
        let replaced = RegistrationCheck::of(Some(&report(&registered, Some(long_ago))), None);
        assert!(replaced.binary_replaced && replaced.restart_needed());

        let unknown = RegistrationCheck::of(Some(&report(&registered, None)), None);
        assert!(
            !unknown.binary_replaced,
            "no start time is not a stale service"
        );
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        let fresh = RegistrationCheck::of(Some(&report(&registered, Some(later))), None);
        assert!(!fresh.binary_replaced);

        let shipped = dir.path().join("shipped.bin");
        std::fs::write(&shipped, b"another build").expect("shipped");
        let elsewhere =
            RegistrationCheck::of(Some(&report(&registered, Some(long_ago))), Some(&shipped));
        assert!(elsewhere.registered_elsewhere && !elsewhere.restart_needed());
        assert_eq!(
            elsewhere.registered_path.as_deref(),
            Some(registered.as_path())
        );
        assert_eq!(elsewhere.expected_path.as_deref(), Some(shipped.as_path()));

        assert!(!RegistrationCheck::of(None, Some(&shipped)).registered_elsewhere);
    }
}
