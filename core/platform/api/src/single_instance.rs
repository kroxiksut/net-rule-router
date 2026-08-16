//! Neutral "only one of this surface may run per user session" port.
//!
//! The desktop surfaces used to decide this by creating a file in the runtime
//! directory: whoever managed `CREATE_NEW` was the primary. A file makes a poor
//! owner. Delete it — a user cleaning out `%TEMP%`, a disk cleaner, a support
//! script — and the next launch claims primacy while the first process is still
//! running, so the machine ends up with two trays and two GUIs. The same file
//! also has to be *reclaimed* after a crash, which needs a liveness probe on a
//! recorded PID, which Windows recycles.
//!
//! A kernel object has neither problem: it cannot be deleted from a file
//! manager, and the OS releases it when the owning process dies, however it
//! died. That is the mechanism this port exposes — existence of the claim is
//! the answer, and the OS maintains it.
//!
//! The claim is scoped to the user's session, not the machine: two users logged
//! in at once each get their own GUI.

use crate::error::PlatformError;

/// A held single-instance claim. Ownership ends when this is dropped — or when
/// the process dies, which is the property a lock file cannot offer.
pub trait SingleInstanceClaim: Send {}

/// Claims a session-scoped instance key.
pub trait SingleInstancePort {
    /// Claim `key` for this process.
    ///
    /// `Ok(Some(claim))` — this process now owns it. `Ok(None)` — another live
    /// process in this session owns it, so the caller is a duplicate launch.
    /// `Err` — the OS refused to answer; the caller decides what to fall back
    /// to rather than guessing an answer here.
    fn claim(&self, key: &str) -> Result<Option<Box<dyn SingleInstanceClaim>>, PlatformError>;
}
