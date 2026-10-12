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
use std::path::Path;

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
}
