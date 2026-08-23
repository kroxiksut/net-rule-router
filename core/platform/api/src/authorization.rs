//! Asking whether a caller may perform a privileged operation.
//!
//! The service runs privileged and its clients do not. Some operations —
//! editing the shared baseline, controlling the service, recovering the network
//! — need more than "this client connected": they need an answer to "is THIS
//! user allowed to do THIS, right now".
//!
//! Windows answers it by having the caller elevate itself: the broker holds
//! admin rights and proxies the request, so by the time the service sees it the
//! question is already settled. On Linux the privileged process is the service
//! itself, always running, and the answer comes from polkit — which can also ask
//! the user for a password through their session's agent.
//!
//! The neutral half is the question and its possible answers; the mechanism is
//! per-OS. A platform with no authority of its own answers
//! [`AuthorizationDecision::Unavailable`], and the caller decides what that
//! means — never "allowed".

/// Who is asking.
///
/// Identified by pid AND the process's start time, because a pid alone is
/// reusable: between the check and the decision the original process can exit
/// and its number be handed to another. Every polkit-style authority takes the
/// pair for exactly this reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationSubject {
    pub pid: u32,
    pub uid: u32,
    /// Process start time in the platform's own units — the value that makes
    /// the pid unambiguous. `None` when it could not be read, which the
    /// mechanism must treat as "cannot identify the caller".
    pub start_time: Option<u64>,
}

/// What the authority said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationDecision {
    /// The caller may proceed.
    Allowed,
    /// The caller may not. A definite answer.
    Denied,
    /// The caller might be allowed, but nobody could ask: no authentication
    /// agent in their session, or interaction was not permitted for this call.
    /// Distinct from [`Self::Denied`] because the remedy differs — the user has
    /// to be somewhere they can be prompted.
    NeedsInteraction,
    /// The authority itself could not be consulted (not installed, failed,
    /// timed out). Never read as permission.
    Unavailable,
}

impl AuthorizationDecision {
    /// Whether the operation may go ahead. Only one variant says yes.
    #[must_use]
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Asks the platform's authority about one action.
///
/// `action` is the platform's action identifier — for polkit, the id declared
/// in the product's `.policy` file. `allow_interaction` says whether the user
/// may be prompted; a background pass sets it `false` so nothing pops a dialog
/// nobody asked for.
pub trait AuthorizationPort: Send + Sync {
    fn authorize(
        &self,
        subject: AuthorizationSubject,
        action: &str,
        allow_interaction: bool,
    ) -> AuthorizationDecision;
}

/// The answer on a platform with no authority wired: nothing is authorized
/// here, and the caller falls back to whatever it did before one existed.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoAuthority;

impl AuthorizationPort for NoAuthority {
    fn authorize(
        &self,
        _subject: AuthorizationSubject,
        _action: &str,
        _allow_interaction: bool,
    ) -> AuthorizationDecision {
        AuthorizationDecision::Unavailable
    }
}

/// Scripted authority for tests.
pub struct FixedAuthority(pub AuthorizationDecision);

impl AuthorizationPort for FixedAuthority {
    fn authorize(
        &self,
        _subject: AuthorizationSubject,
        _action: &str,
        _allow_interaction: bool,
    ) -> AuthorizationDecision {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The distinction the whole type exists for: only one answer is a yes, and
    /// "could not ask" is not it.
    #[test]
    fn only_allowed_permits_the_operation() {
        assert!(AuthorizationDecision::Allowed.is_allowed());
        assert!(!AuthorizationDecision::Denied.is_allowed());
        assert!(!AuthorizationDecision::NeedsInteraction.is_allowed());
        assert!(!AuthorizationDecision::Unavailable.is_allowed());
    }

    #[test]
    fn a_platform_without_an_authority_never_says_yes() {
        let subject = AuthorizationSubject {
            pid: 1234,
            uid: 1000,
            start_time: Some(99),
        };

        let decision = NoAuthority.authorize(subject, "com.example.act", true);

        assert_eq!(decision, AuthorizationDecision::Unavailable);
        assert!(!decision.is_allowed());
    }
}
