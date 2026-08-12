//! Third-party binary components — the platform PORT.
//!
//! The descriptors, the reported status types and the verdict derivation are
//! wire-visible (the GUI renders them), so they live in the contracts crate as
//! [`nrr_shared::third_party`] and are re-exported here unchanged. What belongs
//! to the platform seam — and therefore lives here — is the port itself: the
//! MECHANISM of reading the file, hashing it and verifying its signature is
//! per-OS (Windows checks Authenticode; Linux and macOS ship no third-party
//! binary at all and report an empty list).

pub use nrr_shared::third_party::{
    IntegrityVerdict, SignatureStatus, ThirdPartyComponent, ThirdPartyComponentKind,
    ThirdPartyComponentStatus, TABLER_ICONS_COMPONENT, THIRD_PARTY_ASSET_COMPONENTS,
    THIRD_PARTY_BINARY_COMPONENTS, WINTUN_COMPONENT,
};

/// Inspect the third-party binaries on this machine. Never an error: a
/// component that cannot be read is reported as [`IntegrityVerdict::Missing`]
/// or [`IntegrityVerdict::Untrusted`], which is exactly what the user needs to
/// see.
pub trait ThirdPartyIntegrityPort: Send + Sync {
    fn inspect_components(&self) -> Vec<ThirdPartyComponentStatus>;
}

/// Platforms that ship no third-party binaries (Linux, macOS) — and the
/// off-platform default. The empty list is meaningful: the GUI hides the whole
/// surface rather than showing an empty "third-party components" block.
#[derive(Debug, Default)]
pub struct NoopThirdPartyIntegrity;

impl ThirdPartyIntegrityPort for NoopThirdPartyIntegrity {
    fn inspect_components(&self) -> Vec<ThirdPartyComponentStatus> {
        Vec::new()
    }
}

/// Test double. Always compiled, per the crate convention.
#[derive(Debug, Default, Clone)]
pub struct MockThirdPartyIntegrity {
    statuses: Vec<ThirdPartyComponentStatus>,
}

impl MockThirdPartyIntegrity {
    #[must_use]
    pub fn new(statuses: Vec<ThirdPartyComponentStatus>) -> Self {
        Self { statuses }
    }
}

impl ThirdPartyIntegrityPort for MockThirdPartyIntegrity {
    fn inspect_components(&self) -> Vec<ThirdPartyComponentStatus> {
        self.statuses.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platforms_without_third_party_binaries_report_an_empty_list() {
        assert!(NoopThirdPartyIntegrity.inspect_components().is_empty());
    }

    #[test]
    fn mock_returns_what_it_was_seeded_with() {
        let mock = MockThirdPartyIntegrity::new(vec![ThirdPartyComponentStatus::missing(
            &WINTUN_COMPONENT,
        )]);
        assert_eq!(mock.inspect_components().len(), 1);
        assert_eq!(mock.inspect_components()[0].key, "wintun");
    }
}
