//! Cross-OS forward-compat principal abstraction.
//!
//! A *principal* partitions the per-user rule store: each OS user owns an
//! independent revision history, plus a reserved sentinel for the
//! admin-managed **baseline** that every user falls back to (via the
//! provider read-through). On disk the principal
//! lives in a single `TEXT` column (`revisions.principal` etc.); this
//! module is the typed view over that string and, crucially, **fixes the
//! on-disk format** so the schema survives a future Linux/macOS port
//! without a migration.
//!
//! ## Stored format (the invariant the whole partition scheme rests on)
//!
//! Every principal string is exactly one of:
//! - [`BASELINE_PRINCIPAL`] — the admin baseline sentinel.
//! - A **Windows** user SID: `S-1-5-21-…` (today's only real OS form).
//! - *(reserved, not yet wired)* a **Linux** user: [`LINUX_PRINCIPAL_SCHEME`]
//!   + numeric uid, e.g. `unix:uid:1000`.
//! - *(reserved, not yet wired)* a **macOS** user: [`MACOS_PRINCIPAL_SCHEME`]
//!   + numeric uid, e.g. `mac:uid:501`.
//!
//! The sentinel is chosen so it can NEVER collide with any of those: a
//! Windows SID always begins with `S-`, and the Unix forms are namespaced
//! with a scheme prefix. That non-collision is what lets the baseline
//! share the same column as real users (see the storage schema docs).

/// Reserved sentinel `principal` value for the admin-managed baseline
/// rule book. `nrr-storage` re-exports this as
/// `nrr_storage::BASELINE_PRINCIPAL`; the two are the same constant.
pub const BASELINE_PRINCIPAL: &str = "__baseline__";

/// Scheme prefix reserved for a future Linux principal: `unix:uid:<n>`.
/// Forward-compat only — not produced or consumed by any runtime path on
/// the Windows-first build.
pub const LINUX_PRINCIPAL_SCHEME: &str = "unix:uid:";

/// Scheme prefix reserved for a future macOS principal: `mac:uid:<n>`.
/// Forward-compat only — see [`LINUX_PRINCIPAL_SCHEME`].
pub const MACOS_PRINCIPAL_SCHEME: &str = "mac:uid:";

/// Typed view over a stored `principal` string. Construct it at the
/// boundary (where a SID is captured, or a stored row is read) and feed
/// [`Self::as_stored`] back into the `&str`-based storage / coordinator
/// APIs — the partition key stays a plain string everywhere downstream.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum UserPrincipal {
    /// The shared admin baseline ([`BASELINE_PRINCIPAL`]).
    Baseline,
    /// A concrete OS user in its platform-specific stored form.
    OsUser(String),
}

/// Why a candidate principal string was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrincipalError {
    /// The OS identity string was empty (e.g. a transport that could not
    /// determine the caller SID).
    Empty,
    /// A non-baseline identity equal to the reserved sentinel — refused so
    /// a real user can never masquerade as (or clobber) the baseline.
    ReservedSentinel,
}

impl UserPrincipal {
    /// The admin baseline principal.
    pub const fn baseline() -> Self {
        Self::Baseline
    }

    /// Interpret a value read from the `principal` column. The sentinel
    /// maps to [`Self::Baseline`]; any other non-empty string is an
    /// [`Self::OsUser`] verbatim (stored strings were validated on write).
    pub fn from_stored(s: &str) -> Result<Self, PrincipalError> {
        if s == BASELINE_PRINCIPAL {
            return Ok(Self::Baseline);
        }
        if s.is_empty() {
            return Err(PrincipalError::Empty);
        }
        Ok(Self::OsUser(s.to_string()))
    }

    /// Build a principal from a captured Windows user SID (`S-1-5-…`).
    /// Rejects an empty SID and the reserved sentinel.
    pub fn from_windows_sid(sid: &str) -> Result<Self, PrincipalError> {
        if sid.is_empty() {
            return Err(PrincipalError::Empty);
        }
        if sid == BASELINE_PRINCIPAL {
            return Err(PrincipalError::ReservedSentinel);
        }
        Ok(Self::OsUser(sid.to_string()))
    }

    /// Forward-compat (Р8): a future Linux port keys per principal off the
    /// numeric uid, stored as `unix:uid:<n>`. Reserved format — not wired
    /// into any runtime path yet.
    pub fn from_linux_uid(uid: u32) -> Self {
        Self::OsUser(format!("{LINUX_PRINCIPAL_SCHEME}{uid}"))
    }

    /// Forward-compat (Р8): macOS counterpart of [`Self::from_linux_uid`],
    /// stored as `mac:uid:<n>`. Reserved format — not wired yet.
    pub fn from_macos_uid(uid: u32) -> Self {
        Self::OsUser(format!("{MACOS_PRINCIPAL_SCHEME}{uid}"))
    }

    /// The on-disk string for this principal — the partition key the
    /// storage layer expects.
    pub fn as_stored(&self) -> &str {
        match self {
            Self::Baseline => BASELINE_PRINCIPAL,
            Self::OsUser(s) => s.as_str(),
        }
    }

    /// Whether this is the admin baseline.
    pub fn is_baseline(&self) -> bool {
        matches!(self, Self::Baseline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_round_trips_through_stored_form() {
        let p = UserPrincipal::baseline();
        assert!(p.is_baseline());
        assert_eq!(p.as_stored(), BASELINE_PRINCIPAL);
        assert_eq!(UserPrincipal::from_stored(BASELINE_PRINCIPAL).unwrap(), p);
    }

    #[test]
    fn windows_sid_round_trips_and_is_not_baseline() {
        let sid = "S-1-5-21-1111-2222-3333-1001";
        let p = UserPrincipal::from_windows_sid(sid).unwrap();
        assert!(!p.is_baseline());
        assert_eq!(p.as_stored(), sid);
        assert_eq!(UserPrincipal::from_stored(sid).unwrap(), p);
    }

    #[test]
    fn empty_identity_is_rejected() {
        assert_eq!(
            UserPrincipal::from_windows_sid(""),
            Err(PrincipalError::Empty)
        );
        assert_eq!(UserPrincipal::from_stored(""), Err(PrincipalError::Empty));
    }

    #[test]
    fn os_user_cannot_masquerade_as_the_sentinel() {
        assert_eq!(
            UserPrincipal::from_windows_sid(BASELINE_PRINCIPAL),
            Err(PrincipalError::ReservedSentinel)
        );
        // ...but reading the sentinel back from storage IS the baseline,
        // never an OsUser — the column can't be ambiguous.
        assert!(UserPrincipal::from_stored(BASELINE_PRINCIPAL)
            .unwrap()
            .is_baseline());
    }

    #[test]
    fn reserved_unix_forms_never_collide_with_sentinel_or_sid() {
        let linux = UserPrincipal::from_linux_uid(1000);
        let mac = UserPrincipal::from_macos_uid(501);
        assert_eq!(linux.as_stored(), "unix:uid:1000");
        assert_eq!(mac.as_stored(), "mac:uid:501");
        for p in [&linux, &mac] {
            assert!(!p.is_baseline());
            assert_ne!(p.as_stored(), BASELINE_PRINCIPAL);
            assert!(!p.as_stored().starts_with("S-"));
        }
    }
}
