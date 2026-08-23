//! Who the service should currently be enforcing policy FOR.
//!
//! Rules are stored per principal, and the service runs with no session of its
//! own, so "apply the rules" is only a well-formed instruction once someone
//! says whose. Each OS answers from a different authority: Windows watches for
//! a tray connection in the user's session, Linux asks `logind` which users
//! have a live login. The policy above this trait — when to recompute, what to
//! do when the answer is unavailable — is the same everywhere and is written
//! once.
//!
//! ## An error is NOT "nobody"
//!
//! The two are separate answers on purpose. "Nobody is logged in" legitimately
//! means enforce nothing. "I could not ask" must never be read that way:
//! dropping every user's policy because a query failed would silently remove
//! protection at the moment the system is least healthy.

use crate::enforcement::UserPrincipal;

/// Reads the set of principals whose policy is currently in force.
pub trait ActivePrincipalSource: Send + Sync {
    /// The active principals right now, or why the question could not be
    /// answered. An empty vector means "nobody", which is a real answer.
    fn active_principals(&self) -> Result<Vec<UserPrincipal>, ActivePrincipalError>;

    /// Short name of the authority consulted, for logs ("logind", "tray-ipc").
    /// An operator reading "no active users" needs to know who was asked.
    fn authority(&self) -> &'static str;
}

/// Why the active set could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivePrincipalError {
    /// Human-readable cause, already carrying the mechanism's own wording.
    pub reason: String,
}

impl ActivePrincipalError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for ActivePrincipalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for ActivePrincipalError {}

/// Source that reports a fixed set. For tests and for a host where the concept
/// does not apply.
pub struct FixedActivePrincipals(pub Vec<UserPrincipal>);

impl ActivePrincipalSource for FixedActivePrincipals {
    fn active_principals(&self) -> Result<Vec<UserPrincipal>, ActivePrincipalError> {
        Ok(self.0.clone())
    }

    fn authority(&self) -> &'static str {
        "fixed"
    }
}
