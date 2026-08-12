//! Third-party binary components and their integrity — the wire contract.
//!
//! NetRuleRouter ships exactly one third-party BINARY: WireGuard LLC's signed
//! `wintun.dll`, needed on Windows because it is the only supported OS with no
//! usermode TUN of its own (Linux and macOS use their native kernel interfaces,
//! so they ship nothing extra). Two obligations follow, and this module serves
//! both from one place:
//!
//! - **Attribution** — the component's publisher, version and licence must be
//!   visible to the user, and its licence forbids stripping proprietary notices.
//! - **Provenance** — the user (and support) must be able to see that the DLL on
//!   disk is the genuine signed original, not something swapped in. A claim in
//!   an About box proves nothing; a live Authenticode check plus a hash pinned
//!   at build time does.
//!
//! This file holds the descriptor table (policy data), the reported status
//! types, and the verdict derivation — everything the GUI renders, hence its
//! place in the contracts crate. The PORT that produces the statuses lives in
//! `nrr_platform_api::third_party`, and the MECHANISM behind it (reading the
//! file, hashing it, verifying the signature) is per-OS. On Linux and macOS
//! there is no third-party binary at all, so the list comes back empty and the
//! GUI hides the surface entirely instead of showing an empty block.

use serde::{Deserialize, Serialize};

/// What kind of third-party material a component is — which decides what the
/// GUI can honestly say about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThirdPartyComponentKind {
    /// Executable code we ship (a driver, a library). Can be — and is —
    /// verified on disk: hash plus signature.
    Binary,
    /// Non-executable material compiled into the product (icons, fonts). There
    /// is no separate file on disk to point at, so there is nothing to verify;
    /// what matters is the attribution its licence requires.
    Asset,
}

/// A third-party component shipped with the product.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThirdPartyComponent {
    /// Binary (verifiable) or asset (attribution only).
    pub kind: ThirdPartyComponentKind,
    /// Stable slug used by the GUI for locale keys and by logs.
    pub key: &'static str,
    /// Product name as its publisher writes it.
    pub display_name: &'static str,
    /// Legal publisher — the entity that signs the binary.
    pub publisher: &'static str,
    /// Upstream release version we ship.
    pub version: &'static str,
    /// Human name of the licence the binary is distributed under.
    pub license_name: &'static str,
    /// Repository-relative path of the verbatim licence text we ship with it.
    pub license_path: &'static str,
    /// Upstream home page — where the same binary can be re-downloaded and
    /// checked against the hashes below.
    pub homepage: &'static str,
    /// File name of the binary as it is looked up at runtime.
    pub file_name: &'static str,
    /// SHA-256 of every architecture build we ship, lower-case hex. The
    /// inspector compares the file on disk against this set, so a substituted
    /// DLL fails even if it carries some other valid signature.
    pub known_sha256: &'static [&'static str],
    /// Subject common name expected in the Authenticode signature.
    pub expected_signer: &'static str,
    /// Which feature stops working when the component is absent — what the GUI
    /// tells the user is at stake. A slug; the GUI localizes it.
    pub required_for: &'static str,
}

/// Wintun 0.14.1, downloaded from `wintun.net/builds` and verified against the
/// SHA-256 published there before it entered the repository (see
/// `third_party/wintun/PROVENANCE.md`). Only the signed upstream binaries are
/// redistributable, and only alongside software that uses them through the
/// published API — which is exactly how the Windows backend consumes it.
pub const WINTUN_COMPONENT: ThirdPartyComponent = ThirdPartyComponent {
    kind: ThirdPartyComponentKind::Binary,
    key: "wintun",
    display_name: "Wintun",
    publisher: "WireGuard LLC",
    version: "0.14.1",
    license_name: "Wintun Prebuilt Binaries License",
    license_path: "third_party/wintun/LICENSE.txt",
    homepage: "https://www.wintun.net/",
    file_name: "wintun.dll",
    known_sha256: &[
        // bin/amd64/wintun.dll
        "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
        // bin/arm64/wintun.dll
        "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
        // bin/x86/wintun.dll — 32-bit Windows
        "d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931",
    ],
    expected_signer: "WireGuard LLC",
    required_for: "fake-ip",
};

/// Every third-party binary the product may ship, on any platform. The
/// per-OS inspector reports on the ones that apply to it.
pub const THIRD_PARTY_BINARY_COMPONENTS: &[ThirdPartyComponent] = &[WINTUN_COMPONENT];

/// Tabler Icons — the outline icon set used for the UI, status and tray
/// artwork. MIT, so the only obligation is to carry the attribution; there is
/// no separate file on disk to verify, hence [`ThirdPartyComponentKind::Asset`].
/// The application's own logo is in-house and is not part of this set.
pub const TABLER_ICONS_COMPONENT: ThirdPartyComponent = ThirdPartyComponent {
    kind: ThirdPartyComponentKind::Asset,
    key: "tabler-icons",
    display_name: "Tabler Icons",
    publisher: "Tabler",
    version: "outline set",
    license_name: "MIT",
    license_path: "assets/icons/THIRD_PARTY.md",
    homepage: "https://tabler.io/icons",
    file_name: "",
    known_sha256: &[],
    expected_signer: "",
    required_for: "user-interface",
};

/// Third-party material that is shipped but has nothing to verify — attribution
/// only. Reported on EVERY platform, unlike the binaries: the icons are part of
/// every build.
pub const THIRD_PARTY_ASSET_COMPONENTS: &[ThirdPartyComponent] = &[TABLER_ICONS_COMPONENT];

/// Result of the Authenticode (or platform-equivalent) signature check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "status", content = "detail")]
pub enum SignatureStatus {
    /// Signed, valid, and by the expected publisher — the name is carried so
    /// the GUI can show WHO signed it rather than just a green tick.
    Valid(String),
    /// Signature is valid but belongs to someone else.
    SignerMismatch(String),
    /// Present but invalid (broken chain, revoked, modified file).
    Invalid(String),
    /// No signature at all.
    Unsigned,
    /// The platform cannot check signatures — never reported as genuine.
    NotChecked,
}

/// One-line answer the GUI colours, derived from the full status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrityVerdict {
    /// On disk, hash matches a shipped build, signed by the expected publisher.
    Genuine,
    /// On disk, but the hash or the signature does not match what we ship.
    Untrusted,
    /// Not installed — the dependent feature is unavailable, not compromised.
    Missing,
    /// Nothing to verify: an [`ThirdPartyComponentKind::Asset`] compiled into
    /// the product. Deliberately distinct from `Genuine` — claiming a verified
    /// state for something never verified is exactly the lie this type exists
    /// to prevent.
    NotApplicable,
}

/// What the GUI shows for one component.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThirdPartyComponentStatus {
    /// Binary or asset — the GUI shows the integrity block only for binaries.
    pub kind: ThirdPartyComponentKind,
    pub key: String,
    pub display_name: String,
    pub publisher: String,
    pub version: String,
    pub license_name: String,
    pub license_path: String,
    pub homepage: String,
    /// Feature slug that depends on this component.
    pub required_for: String,
    /// Absolute path of the file that was inspected, when it was found.
    pub path: Option<String>,
    /// SHA-256 of the file on disk, lower-case hex.
    pub sha256: Option<String>,
    /// Whether that hash is one of the builds we ship.
    pub sha256_matches_shipped: bool,
    pub signature: SignatureStatus,
    pub verdict: IntegrityVerdict,
}

impl ThirdPartyComponentStatus {
    /// Status for a component that is not installed on this machine.
    #[must_use]
    pub fn missing(component: &ThirdPartyComponent) -> Self {
        Self::from_parts(component, None, None, SignatureStatus::NotChecked)
    }

    /// Status for an attribution-only component (icons, fonts): the licence and
    /// credits are shown, and no integrity claim is made at all.
    #[must_use]
    pub fn attribution_only(component: &ThirdPartyComponent) -> Self {
        let mut status = Self::from_parts(component, None, None, SignatureStatus::NotChecked);
        status.verdict = IntegrityVerdict::NotApplicable;
        status
    }

    /// Every component the product ships that has nothing to verify. Platform
    /// independent — the icons are in every build.
    #[must_use]
    pub fn asset_components() -> Vec<Self> {
        THIRD_PARTY_ASSET_COMPONENTS
            .iter()
            .map(Self::attribution_only)
            .collect()
    }

    /// Build a status from what the backend actually measured, deriving the
    /// verdict here so every OS answers the question the same way.
    #[must_use]
    pub fn from_parts(
        component: &ThirdPartyComponent,
        path: Option<String>,
        sha256: Option<String>,
        signature: SignatureStatus,
    ) -> Self {
        let sha256 = sha256.map(|h| h.to_ascii_lowercase());
        let sha256_matches_shipped = sha256
            .as_deref()
            .is_some_and(|h| component.known_sha256.contains(&h));
        let signature_is_expected = match &signature {
            SignatureStatus::Valid(signer) => signer == component.expected_signer,
            _ => false,
        };
        let verdict = if component.kind == ThirdPartyComponentKind::Asset {
            IntegrityVerdict::NotApplicable
        } else if path.is_none() {
            IntegrityVerdict::Missing
        } else if sha256_matches_shipped && signature_is_expected {
            IntegrityVerdict::Genuine
        } else {
            IntegrityVerdict::Untrusted
        };
        Self {
            kind: component.kind,
            key: component.key.to_string(),
            display_name: component.display_name.to_string(),
            publisher: component.publisher.to_string(),
            version: component.version.to_string(),
            license_name: component.license_name.to_string(),
            license_path: component.license_path.to_string(),
            homepage: component.homepage.to_string(),
            required_for: component.required_for.to_string(),
            path,
            sha256,
            sha256_matches_shipped,
            signature,
            verdict,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHIPPED: &str = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

    #[test]
    fn matching_hash_and_expected_signer_is_genuine() {
        let status = ThirdPartyComponentStatus::from_parts(
            &WINTUN_COMPONENT,
            Some(r"C:\Program Files\NetRuleRouter\wintun.dll".to_string()),
            Some(SHIPPED.to_ascii_uppercase()),
            SignatureStatus::Valid("WireGuard LLC".to_string()),
        );
        assert!(status.sha256_matches_shipped, "hash compare is case-blind");
        assert_eq!(status.verdict, IntegrityVerdict::Genuine);
    }

    #[test]
    fn a_valid_signature_from_someone_else_is_not_genuine() {
        let status = ThirdPartyComponentStatus::from_parts(
            &WINTUN_COMPONENT,
            Some("wintun.dll".to_string()),
            Some(SHIPPED.to_string()),
            SignatureStatus::Valid("Someone Else Inc".to_string()),
        );
        assert_eq!(status.verdict, IntegrityVerdict::Untrusted);
    }

    #[test]
    fn a_signed_but_substituted_binary_is_not_genuine() {
        let status = ThirdPartyComponentStatus::from_parts(
            &WINTUN_COMPONENT,
            Some("wintun.dll".to_string()),
            Some("00".repeat(32)),
            SignatureStatus::Valid("WireGuard LLC".to_string()),
        );
        assert!(!status.sha256_matches_shipped);
        assert_eq!(status.verdict, IntegrityVerdict::Untrusted);
    }

    #[test]
    fn platforms_that_cannot_check_signatures_never_report_genuine() {
        let status = ThirdPartyComponentStatus::from_parts(
            &WINTUN_COMPONENT,
            Some("wintun.dll".to_string()),
            Some(SHIPPED.to_string()),
            SignatureStatus::NotChecked,
        );
        assert_eq!(status.verdict, IntegrityVerdict::Untrusted);
    }

    #[test]
    fn absent_component_is_missing_not_untrusted() {
        let status = ThirdPartyComponentStatus::missing(&WINTUN_COMPONENT);
        assert_eq!(status.verdict, IntegrityVerdict::Missing);
        assert_eq!(status.required_for, "fake-ip");
        assert_eq!(status.publisher, "WireGuard LLC");
    }

    #[test]
    fn assets_are_attribution_only_and_never_claim_verification() {
        let status = ThirdPartyComponentStatus::attribution_only(&TABLER_ICONS_COMPONENT);
        assert_eq!(status.kind, ThirdPartyComponentKind::Asset);
        assert_eq!(status.verdict, IntegrityVerdict::NotApplicable);
        assert_eq!(status.license_name, "MIT");
        assert_eq!(status.path, None);
        assert_eq!(status.sha256, None);
        // Even if something measured a hash for an asset, it stays unverifiable.
        let forced = ThirdPartyComponentStatus::from_parts(
            &TABLER_ICONS_COMPONENT,
            Some("icons".to_string()),
            Some(SHIPPED.to_string()),
            SignatureStatus::Valid("Tabler".to_string()),
        );
        assert_eq!(forced.verdict, IntegrityVerdict::NotApplicable);
    }

    #[test]
    fn every_build_reports_the_icon_attribution() {
        let assets = ThirdPartyComponentStatus::asset_components();
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].key, "tabler-icons");
    }

    #[test]
    fn status_serializes_in_the_shape_the_gui_reads() {
        let status = ThirdPartyComponentStatus::from_parts(
            &WINTUN_COMPONENT,
            Some("wintun.dll".to_string()),
            Some(SHIPPED.to_string()),
            SignatureStatus::Valid("WireGuard LLC".to_string()),
        );
        let json = serde_json::to_value(&status).expect("serialize status");
        assert_eq!(json["displayName"], "Wintun");
        assert_eq!(json["verdict"], "genuine");
        assert_eq!(json["signature"]["status"], "valid");
        assert_eq!(json["signature"]["detail"], "WireGuard LLC");
        assert_eq!(json["sha256MatchesShipped"], true);
    }
}
