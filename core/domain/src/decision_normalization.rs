//! Runtime normalization contracts for the routing decision pipeline.
//!
//! This module formalises the **normalization stage**: the first step of the
//! routing decision pipeline that converts a raw [`RuntimeInput`] into a
//! [`NormalizedDecisionInput`] ready for downstream stages (lookup → rule
//! matching → availability check → …).
//!
//! # What normalization does
//!
//! | Input field          | Normalization applied                                        |
//! |----------------------|--------------------------------------------------------------|
//! | `destination_hostname` | lowercase, trailing dot removal, IDNA2008/punycode         |
//! | `destination_ip`     | IPv4 → pass through; IPv4-mapped IPv6 → IPv4 + warning;     |
//! |                      | native IPv6 → `ProOnlyNativeIpv6` (blocks `ExactIp` only)   |
//! | `process_context`    | lowercase basename, path stripped, `.exe` suffix ensured     |
//! | zone name (rule-side)| lowercase, leading dot stripped; empty/whitespace → error    |
//!
//! # Normalization errors are match-class–scoped, not pipeline-fatal
//!
//! A normalization error blocks the **match class** it affects, not the entire
//! pipeline.  For example, a native IPv6 destination blocks `ExactIp` matching
//! but hostname and application matching continue normally.  All errors are
//! recorded in [`MatchClassAvailability`] and surfaced in explain output.
//!
//! When all address-based match classes are blocked **and** no app identity is
//! available, the pipeline falls through to the default route.
//!
//! # Same rules as canonicalization
//!
//! Runtime normalization applies the same rules as the rule-book
//! canonicalization pass — lowercase, trailing dot removal, IDNA2008 encoding
//! for domains; lowercase, `.exe` suffix, path stripping for app names.  The
//! difference is that runtime normalization handles partial/missing inputs
//! gracefully; canonicalization always has complete data.
//!
//! # Ownership boundary
//!
//! The normalization stage reads only `RuntimeInput` and produces
//! `NormalizedDecisionInput`.  It must not access the active rule book,
//! adapter state, or UI preferences.
//!
//! # `AddressMatch::ExactIp(IpAddr::V6)` in saved rules
//!
//! If the active rule book contains a rule with `AddressMatch::ExactIp(V6)`,
//! that rule is treated as Pro-only unsupported in Free edition:
//! - The rule is preserved in storage and exported unchanged.
//! - The GUI marks it with the `pro.svg` badge.
//! - The rule does **not** participate in `ExactIp` matching.
//!
//! This check is performed at rule-matching time rather than during
//! `RuntimeInput` normalization.  It is documented here because it follows
//! from the same "IPv6 = Pro-only" invariant.

use std::net::{Ipv4Addr, Ipv6Addr};

// ── NormalizationWarning ──────────────────────────────────────────────────────

/// Non-fatal diagnostic produced during normalization.
///
/// Warnings do not block a match class.  They are recorded in
/// [`NormalizedDecisionInput::warnings`] and propagated into explain output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NormalizationWarning {
    /// An IPv4-mapped IPv6 address (e.g. `::ffff:192.168.1.1`) was converted
    /// to its IPv4 equivalent.  The original address is preserved for explain.
    Ipv4MappedIpv6NormalizedToIpv4 {
        original: Ipv6Addr,
        normalized: Ipv4Addr,
    },
    /// The process name alone (without a full path) is a weak identity signal
    /// on Windows — any process can choose any name.
    ApplicationBareProcessNameWeakIdentity { process_name: String },
    /// The full executable path was stripped to produce the match filename.
    ApplicationPathStripped {
        original_path: String,
        normalized_name: String,
    },
    /// The `.exe` suffix was appended to the process name during normalization.
    ApplicationExeSuffixAdded { original: String },
    /// A trailing dot was removed from the hostname before matching.
    DomainTrailingDotRemoved,
    /// The hostname was IDNA-encoded from Unicode to its punycode form.
    DomainPunycodeEncoded { original: String, punycode: String },
    /// A leading dot was removed from a zone name during normalization.
    ZoneLeadingDotRemoved { original: String },
}

// ── NormalizationError ────────────────────────────────────────────────────────

/// Error that blocks a specific match class.
///
/// These are **not** pipeline-fatal: each error is scoped to the match class
/// it affects (see [`MatchClassAvailability`]).  The pipeline continues with
/// remaining match classes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NormalizationError {
    // ── Hostname errors — block ExactFqdn, SuffixDomain, Zone ─────────────────
    /// The hostname was empty (or whitespace-only) after trimming.
    DomainEmpty,
    /// The hostname contained characters that are not valid in a DNS label.
    DomainInvalidCharacters { raw: String },
    /// IDNA2008 encoding of a Unicode hostname failed.
    DomainIdnaFailed { raw: String },

    // ── IP errors — block ExactIp ─────────────────────────────────────────────
    /// A native IPv6 address was observed.  Free edition does not support
    /// `ExactIp` matching for IPv6.  Hostname and application matching continue.
    IpNativeIpv6ProOnly { addr: Ipv6Addr },

    // ── Zone name errors — block Zone matching for that specific rule ──────────
    /// A zone name from a saved rule was empty after trimming.
    ZoneNameEmpty,
    /// A zone name from a saved rule contained whitespace.
    ZoneNameContainsWhitespace { raw: String },
    /// A zone name from a saved rule contained characters not valid in a DNS label.
    ZoneNameInvalidCharacters { raw: String },

    // ── Application identity errors — block Application ───────────────────────
    /// The process name resolved to an empty string after stripping path and
    /// normalizing — application matching cannot proceed.
    ApplicationNameEmpty,
}

// ── NormalizedHostname ────────────────────────────────────────────────────────

/// Result of normalizing the destination hostname from `RuntimeInput`.
///
/// **Explain signals:**
/// - `Valid` → hostname used for `ExactFqdn`, `SuffixDomain`, and `Zone` matching.
/// - `Unavailable` → explain signal `hostname_unavailable`; pipeline skips all
///   hostname-based match classes and proceeds to `ExactIp` / `Application`.
/// - `Invalid` → explain signal `hostname_invalid`; treated as `Unavailable`
///   for matching; raw value and error preserved for diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NormalizedHostname {
    /// Normalized and ready for matching (lowercase, no trailing dot, IDNA-encoded).
    Valid(String),
    /// No hostname was provided — direct-IP connection or DNS layer bypassed.
    Unavailable,
    /// A hostname was provided but failed normalization.
    Invalid {
        raw: String,
        error: NormalizationError,
    },
}

impl NormalizedHostname {
    /// Returns `true` if a valid hostname is available for matching.
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Valid(_))
    }
}

// ── NormalizedIp ──────────────────────────────────────────────────────────────

/// Result of normalizing the destination IP from `RuntimeInput`.
///
/// IPv4-mapped IPv6 addresses are converted to IPv4 before this type is
/// constructed; the conversion is recorded in [`NormalizedDecisionInput::warnings`].
///
/// **Explain signals:**
/// - `ValidIpv4` → used for `ExactIp` matching.
/// - `Unavailable` → explain signal `ip_unavailable`; `ExactIp` skipped.  The
///   lookup stage may attempt DNS resolution from the hostname.
/// - `ProOnlyNativeIpv6` → explain signal `ip_native_ipv6_pro_only`; `ExactIp`
///   skipped in Free.  All hostname and application matching continues normally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NormalizedIp {
    /// IPv4 address ready for `ExactIp` matching.
    ValidIpv4(Ipv4Addr),
    /// No IP was present in `RuntimeInput`.
    Unavailable,
    /// A native IPv6 address was observed — not used for matching in Free edition.
    ProOnlyNativeIpv6 { addr: Ipv6Addr },
}

impl NormalizedIp {
    /// Returns `true` if a valid IPv4 address is available for `ExactIp` matching.
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::ValidIpv4(_))
    }
}

// ── NormalizedAppIdentity ─────────────────────────────────────────────────────

/// Result of normalizing the process identity from `RuntimeInput::process_context`.
///
/// `process_name` is the primary matching key: lowercase basename with `.exe`
/// suffix, path stripped.  See [`NormalizationWarning`] variants for the
/// transformations that may have been applied.
///
/// If `process_context.process_name` was `None`, app-identity normalization
/// is skipped entirely and `NormalizedDecisionInput::app_identity` is `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedAppIdentity {
    /// Lowercase `.exe`-suffixed filename with path stripped.  Primary match key.
    pub process_name: String,
    /// Original process path before stripping, if available.
    /// Not used for matching; preserved for explain/diagnostics.
    pub original_path: Option<String>,
    /// Per-identity normalization warnings (weak identity, path stripped, etc.).
    pub warnings: Vec<NormalizationWarning>,
}

// ── InputAvailabilitySignal ───────────────────────────────────────────────────

/// Signal emitted when a `RuntimeInput` field is absent or unusable.
///
/// Signals are inserted into [`NormalizedDecisionInput::availability_signals`]
/// and propagated verbatim to the explain output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputAvailabilitySignal {
    /// `RuntimeInput::destination_hostname` was `None`.
    /// Pipeline proceeds with IP and application matching only.
    HostnameUnavailable,
    /// `RuntimeInput::destination_ip` was `None`.
    /// Lookup stage may attempt DNS resolution from the hostname.
    IpUnavailable,
    /// `RuntimeInput::process_context.process_name` was `None`.
    /// Application match classes are skipped; address-based matching still applies.
    AppContextUnavailable,
}

// ── MatchClassAvailability ────────────────────────────────────────────────────

/// Which match classes are available for the current decision, based on
/// normalization outcomes.
///
/// `None` in a field means the class is **available**.
/// `Some(error)` means the class is **blocked** for the stated reason.
///
/// ## Blocking rules
///
/// | Match class    | Blocked when                                              |
/// |----------------|-----------------------------------------------------------|
/// | `ExactFqdn`    | hostname unavailable or invalid                           |
/// | `SuffixDomain` | hostname unavailable or invalid                           |
/// | `Zone`         | hostname unavailable or invalid                           |
/// | `ExactIp`      | IP unavailable, or native IPv6 (`IpNativeIpv6ProOnly`)    |
/// | `Application`  | process name absent or empty (`ApplicationNameEmpty`)     |
///
/// The `Default` route is never blocked — it is the guaranteed final fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchClassAvailability {
    /// `ExactFqdn` match class.  `None` = available.
    pub exact_fqdn: Option<NormalizationError>,
    /// `SuffixDomain` match class.  `None` = available.
    pub suffix_domain: Option<NormalizationError>,
    /// `Zone` match class.  `None` = available.
    pub zone: Option<NormalizationError>,
    /// `ExactIp` match class.  `None` = available.
    pub exact_ip: Option<NormalizationError>,
    /// `Application` match class.  `None` = available.
    pub application: Option<NormalizationError>,
}

impl MatchClassAvailability {
    /// Returns `true` if every match class is available (no normalization errors).
    pub fn all_available(&self) -> bool {
        self.exact_fqdn.is_none()
            && self.suffix_domain.is_none()
            && self.zone.is_none()
            && self.exact_ip.is_none()
            && self.application.is_none()
    }

    /// Returns `true` if all address-based match classes are blocked.
    ///
    /// When this is true, only `Application` and the final `Default` fallback
    /// remain as candidates for routing.
    pub fn all_address_classes_blocked(&self) -> bool {
        self.exact_fqdn.is_some()
            && self.suffix_domain.is_some()
            && self.zone.is_some()
            && self.exact_ip.is_some()
    }

    /// Returns `true` if the pipeline has no usable input for any match class.
    ///
    /// When this returns `true`, the decision falls through to the `Default`
    /// route regardless of the active rule book.
    pub fn nothing_available(&self) -> bool {
        self.all_address_classes_blocked() && self.application.is_some()
    }
}

// ── NormalizedDecisionInput ───────────────────────────────────────────────────

/// Output of the normalization stage — canonical form of a `RuntimeInput`,
/// ready for the FQDN/IP lookup stage.
///
/// All downstream pipeline stages consume `NormalizedDecisionInput`, never the
/// raw `RuntimeInput`.
///
/// # Invariants
///
/// - If `match_class_availability.nothing_available()` is `true`, the pipeline
///   falls through to the default route and the explain output records
///   `all_inputs_unavailable`.
/// - `match_class_availability` is derived from `hostname`, `ip`, and
///   `app_identity`.  These fields are the source of truth; consumers must not
///   treat `match_class_availability` as independent state.
/// - `availability_signals` contains exactly one signal per absent input field;
///   there are no duplicate entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedDecisionInput {
    /// Normalized destination hostname.
    pub hostname: NormalizedHostname,
    /// Normalized destination IP address.
    pub ip: NormalizedIp,
    /// Normalized process identity.  `None` when `process_name` was absent.
    pub app_identity: Option<NormalizedAppIdentity>,
    /// Per-match-class availability derived from normalization outcomes.
    pub match_class_availability: MatchClassAvailability,
    /// Signals for absent input fields — propagated to explain output.
    pub availability_signals: Vec<InputAvailabilitySignal>,
    /// Non-fatal normalization warnings — propagated to explain output.
    pub warnings: Vec<NormalizationWarning>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── NormalizedHostname ────────────────────────────────────────────────────

    #[test]
    fn normalized_hostname_valid_is_usable() {
        let h = NormalizedHostname::Valid("example.com".to_owned());
        assert!(h.is_usable());
    }

    #[test]
    fn normalized_hostname_unavailable_is_not_usable() {
        assert!(!NormalizedHostname::Unavailable.is_usable());
    }

    #[test]
    fn normalized_hostname_invalid_is_not_usable() {
        let h = NormalizedHostname::Invalid {
            raw: "bad!host".to_owned(),
            error: NormalizationError::DomainInvalidCharacters {
                raw: "bad!host".to_owned(),
            },
        };
        assert!(!h.is_usable());
    }

    // ── NormalizedIp ──────────────────────────────────────────────────────────

    #[test]
    fn normalized_ip_valid_ipv4_is_usable() {
        let ip = NormalizedIp::ValidIpv4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(ip.is_usable());
    }

    #[test]
    fn normalized_ip_unavailable_is_not_usable() {
        assert!(!NormalizedIp::Unavailable.is_usable());
    }

    #[test]
    fn normalized_ip_pro_only_native_ipv6_is_not_usable() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let ip = NormalizedIp::ProOnlyNativeIpv6 { addr };
        assert!(!ip.is_usable());
    }

    #[test]
    fn ipv4_mapped_ipv6_warning_carries_original_and_normalized() {
        let original: Ipv6Addr = "::ffff:203.0.113.7".parse().unwrap();
        let normalized = Ipv4Addr::new(203, 0, 113, 7);
        let w = NormalizationWarning::Ipv4MappedIpv6NormalizedToIpv4 {
            original,
            normalized,
        };
        assert_eq!(
            w,
            NormalizationWarning::Ipv4MappedIpv6NormalizedToIpv4 {
                original: "::ffff:203.0.113.7".parse().unwrap(),
                normalized: Ipv4Addr::new(203, 0, 113, 7),
            }
        );
    }

    // ── MatchClassAvailability ────────────────────────────────────────────────

    fn all_available() -> MatchClassAvailability {
        MatchClassAvailability {
            exact_fqdn: None,
            suffix_domain: None,
            zone: None,
            exact_ip: None,
            application: None,
        }
    }

    fn hostname_blocked() -> MatchClassAvailability {
        MatchClassAvailability {
            exact_fqdn: Some(NormalizationError::DomainEmpty),
            suffix_domain: Some(NormalizationError::DomainEmpty),
            zone: Some(NormalizationError::DomainEmpty),
            exact_ip: None,
            application: None,
        }
    }

    fn all_blocked() -> MatchClassAvailability {
        MatchClassAvailability {
            exact_fqdn: Some(NormalizationError::DomainEmpty),
            suffix_domain: Some(NormalizationError::DomainEmpty),
            zone: Some(NormalizationError::DomainEmpty),
            exact_ip: Some(NormalizationError::IpNativeIpv6ProOnly {
                addr: "2001:db8::1".parse().unwrap(),
            }),
            application: Some(NormalizationError::ApplicationNameEmpty),
        }
    }

    #[test]
    fn match_class_availability_all_available_when_no_errors() {
        assert!(all_available().all_available());
    }

    #[test]
    fn match_class_availability_not_all_available_when_one_blocked() {
        assert!(!hostname_blocked().all_available());
    }

    #[test]
    fn match_class_all_address_blocked_when_hostname_and_ip_blocked() {
        let mca = MatchClassAvailability {
            exact_fqdn: Some(NormalizationError::DomainEmpty),
            suffix_domain: Some(NormalizationError::DomainEmpty),
            zone: Some(NormalizationError::DomainEmpty),
            exact_ip: Some(NormalizationError::IpNativeIpv6ProOnly {
                addr: "2001:db8::1".parse().unwrap(),
            }),
            application: None,
        };
        assert!(mca.all_address_classes_blocked());
        // Application is still available
        assert!(!mca.nothing_available());
    }

    #[test]
    fn match_class_nothing_available_when_all_blocked() {
        assert!(all_blocked().nothing_available());
    }

    #[test]
    fn match_class_hostname_only_blocked_does_not_mean_all_address_blocked() {
        // ExactIp is still available, so not all address classes are blocked
        assert!(!hostname_blocked().all_address_classes_blocked());
    }

    // ── NormalizedDecisionInput ───────────────────────────────────────────────

    #[test]
    fn normalized_decision_input_ip_only_connection_structure() {
        // Simulates a direct-IP connection (no hostname, IPv4, no process context)
        let input = NormalizedDecisionInput {
            hostname: NormalizedHostname::Unavailable,
            ip: NormalizedIp::ValidIpv4(Ipv4Addr::new(8, 8, 8, 8)),
            app_identity: None,
            match_class_availability: MatchClassAvailability {
                exact_fqdn: Some(NormalizationError::DomainEmpty),
                suffix_domain: Some(NormalizationError::DomainEmpty),
                zone: Some(NormalizationError::DomainEmpty),
                exact_ip: None,
                application: Some(NormalizationError::ApplicationNameEmpty),
            },
            availability_signals: vec![
                InputAvailabilitySignal::HostnameUnavailable,
                InputAvailabilitySignal::AppContextUnavailable,
            ],
            warnings: vec![],
        };
        assert!(!input.match_class_availability.all_address_classes_blocked());
        assert!(input.ip.is_usable()); // ip IS usable
        assert!(input.hostname == NormalizedHostname::Unavailable);
        assert!(input
            .availability_signals
            .contains(&InputAvailabilitySignal::HostnameUnavailable));
    }

    #[test]
    fn normalized_decision_input_full_connection_structure() {
        // Simulates a full connection: hostname + IPv4 + process context
        let input = NormalizedDecisionInput {
            hostname: NormalizedHostname::Valid("example.com".to_owned()),
            ip: NormalizedIp::ValidIpv4(Ipv4Addr::new(93, 184, 216, 34)),
            app_identity: Some(NormalizedAppIdentity {
                process_name: "firefox.exe".to_owned(),
                original_path: Some(r"C:\Program Files\Mozilla Firefox\firefox.exe".to_owned()),
                warnings: vec![NormalizationWarning::ApplicationPathStripped {
                    original_path: r"C:\Program Files\Mozilla Firefox\firefox.exe".to_owned(),
                    normalized_name: "firefox.exe".to_owned(),
                }],
            }),
            match_class_availability: all_available(),
            availability_signals: vec![],
            warnings: vec![],
        };
        assert!(input.match_class_availability.all_available());
        assert!(input.hostname.is_usable());
        assert!(input.ip.is_usable());
        assert!(input.app_identity.is_some());
    }

    #[test]
    fn normalized_decision_input_native_ipv6_blocks_exact_ip_only() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let input = NormalizedDecisionInput {
            hostname: NormalizedHostname::Valid("ipv6host.example.com".to_owned()),
            ip: NormalizedIp::ProOnlyNativeIpv6 { addr },
            app_identity: None,
            match_class_availability: MatchClassAvailability {
                exact_fqdn: None,
                suffix_domain: None,
                zone: None,
                exact_ip: Some(NormalizationError::IpNativeIpv6ProOnly { addr }),
                application: Some(NormalizationError::ApplicationNameEmpty),
            },
            availability_signals: vec![InputAvailabilitySignal::AppContextUnavailable],
            warnings: vec![],
        };
        // ExactIp is blocked but hostname classes are still available
        assert!(input.match_class_availability.exact_ip.is_some());
        assert!(input.match_class_availability.exact_fqdn.is_none());
        assert!(input.match_class_availability.suffix_domain.is_none());
        assert!(input.match_class_availability.zone.is_none());
        // Not all address classes blocked (hostname classes are still open)
        assert!(!input.match_class_availability.all_address_classes_blocked());
    }

    // ── Zone name errors ──────────────────────────────────────────────────────

    #[test]
    fn zone_name_empty_error_variant_constructible() {
        let e = NormalizationError::ZoneNameEmpty;
        assert_eq!(e, NormalizationError::ZoneNameEmpty);
    }

    #[test]
    fn zone_name_whitespace_error_carries_raw_name() {
        let e = NormalizationError::ZoneNameContainsWhitespace {
            raw: "my zone".to_owned(),
        };
        assert!(matches!(
            e,
            NormalizationError::ZoneNameContainsWhitespace { .. }
        ));
    }

    #[test]
    fn zone_leading_dot_warning_carries_original() {
        let w = NormalizationWarning::ZoneLeadingDotRemoved {
            original: ".intra".to_owned(),
        };
        assert!(matches!(
            w,
            NormalizationWarning::ZoneLeadingDotRemoved { .. }
        ));
    }
}
