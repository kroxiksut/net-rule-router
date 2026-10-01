//! Codec between the canonical wire schema in
//! [`nrr_shared::rules_json`] and the domain
//! [`RulesRevisionContent`].
//!
//! [`RulesRevisionContent`]: crate::rules_revision::RulesRevisionContent
//!
//! ## Scope
//!
//! - [`encode`] takes a `&RulesRevisionContent` and produces a
//!   [`CanonicalRulesJsonV1`] in canonical order. The encoder is
//!   infallible — it only re-shapes existing canonical types.
//! - [`decode`] takes a [`CanonicalRulesJsonV1`] and reconstructs a
//!   `RulesRevisionContent`. It rejects unknown schema versions, rules that
//!   carry neither `address_match` nor `app_match`, and any address or
//!   application value the rule pipeline refuses.
//!
//! The codec does not re-run the validation pipeline's acceptance, but it does
//! not trust the wire's SPELLING either: the GUI sends names as the user typed
//! them (`.ru`, `example.com.`, `Cloud.exe`), so names are re-spelled the way
//! [`crate::validation`] spells them, and a host name the pipeline refuses is
//! kept as it came: a stored revision must keep decoding, so refusing a new one
//! is the service's acceptance gate
//! ([`crate::rule_value_validation::rules_with_refused_values`]).
//! Addresses and applications are read by the pipeline's own readers, refusals
//! included: a stored book is read through
//! [`crate::rule_value_validation::drop_rules_refused_outright`] first, so only
//! a new submission can still carry such a value.
//!
//! ## Schema-version vs format-version
//!
//! Two related but distinct version numbers live in different crates:
//!
//! - [`crate::rules_revision::RULES_REVISION_FORMAT_VERSION`] —
//!   domain-side format version for `RulesRevisionContent`.
//! - [`nrr_shared::rules_json::RULES_JSON_SCHEMA_VERSION`] — wire
//!   schema version for the canonical JSON envelope.
//!
//! Both start at `1` and are pinned independently. A change to the
//! domain types may or may not require a wire schema bump — they
//! evolve as two separate releases.

use std::net::IpAddr;

use nrr_shared::rules_json::{
    AddressMatchDto, AppMatchDto, AppPatternDto, CanonicalRulesJsonV1,
    RuleAction as WireRuleAction, RuleDto, RULES_JSON_SCHEMA_VERSION,
};

use crate::canonical::{
    CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalRule,
    CanonicalRuleBook, CanonicalRuleSet,
};
use crate::rules_file::HostPlatform;
use crate::rules_revision::{RulesRevisionContent, RULES_REVISION_FORMAT_VERSION};
use crate::validation::{
    canonical_app_pattern, canonical_host_name, canonical_ip_address, HostNameKind, ValidationError,
};
use crate::RuleId;
use nrr_shared::app_identity::ExecutableNaming;

// ── Error type ──────────────────────────────────────────────────────────────

/// Reasons the canonical-wire decoder can reject input.
///
/// All variants are recoverable from the caller's perspective: the
/// service layer maps them to `IpcErrorCode::MalformedRequest` and
/// surfaces them to the GUI as a structured error. None of them
/// indicate platform-level corruption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RulesJsonCodecError {
    /// Wire schema version is not supported by this build.
    UnsupportedSchemaVersion {
        /// Version the wire carried.
        got: u16,
        /// Version this build expects.
        expected: u16,
    },
    /// `AddressMatchDto::ExactIpv4.address` is not an address the rule
    /// pipeline reads.
    InvalidIpv4 {
        /// The offending rule's id, for error context.
        rule_id: String,
        /// The raw string the decoder failed to parse.
        raw: String,
    },
    /// `AddressMatchDto::ExactIpv6.address` is not an address the rule
    /// pipeline reads.
    InvalidIpv6 { rule_id: String, raw: String },
    /// A rule carries neither `address_match` nor `app_match`. The
    /// domain invariant requires at least one.
    EmptyMatch {
        /// The offending rule's id, for error context.
        rule_id: String,
    },
    /// An application pattern that matches every running process: `*`, or one
    /// reducing to it such as `*.exe`.
    AppGlobTooWide {
        /// The offending rule's id, for error context.
        rule_id: String,
    },
    /// An application value the rule pipeline refuses (too long, a control
    /// character).
    AppNameInvalid { rule_id: String, raw: String },
}

impl core::fmt::Display for RulesJsonCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion { got, expected } => write!(
                f,
                "unsupported rules-json schema version: got {got}, expected {expected}"
            ),
            Self::InvalidIpv4 { rule_id, raw } => {
                write!(f, "rule {rule_id:?}: invalid IPv4 address {raw:?}")
            }
            Self::InvalidIpv6 { rule_id, raw } => {
                write!(f, "rule {rule_id:?}: invalid IPv6 address {raw:?}")
            }
            Self::EmptyMatch { rule_id } => write!(
                f,
                "rule {rule_id:?}: must carry at least one of address-match / app-match"
            ),
            Self::AppGlobTooWide { rule_id } => write!(
                f,
                "rule {rule_id:?}: application pattern matches every process"
            ),
            Self::AppNameInvalid { rule_id, raw } => {
                write!(f, "rule {rule_id:?}: invalid application name {raw:?}")
            }
        }
    }
}

impl std::error::Error for RulesJsonCodecError {}

// ── Encode (domain → wire DTO) ──────────────────────────────────────────────

/// Project a [`RulesRevisionContent`] into the canonical wire DTO.
///
/// Output preserves the canonical rule order produced by
/// [`CanonicalRuleSet`] — `primary` and `secondary` rules are emitted
/// in the same sequence the domain layer iterates them.
pub fn encode(content: &RulesRevisionContent) -> CanonicalRulesJsonV1 {
    CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary: content
            .rule_book
            .primary
            .rules()
            .iter()
            .map(encode_rule)
            .collect(),
        secondary: content
            .rule_book
            .secondary
            .rules()
            .iter()
            .map(encode_rule)
            .collect(),
    }
}

fn encode_rule(rule: &CanonicalRule) -> RuleDto {
    RuleDto {
        id: rule.id.as_str().to_string(),
        enabled: rule.enabled,
        address_match: rule.address_match.as_ref().map(encode_address_match),
        app_match: rule.app_match.as_ref().map(encode_app_match),
        comment: rule.comment.clone(),
        action: encode_action(rule.action),
        // Provenance is the same type on both sides (see
        // `nrr_shared::auto_rule`), so there is nothing to map — and nothing
        // to emit at all for the user-authored majority, which keeps their
        // canonical bytes and content hashes untouched.
        origin: rule.origin.clone(),
    }
}

fn encode_action(action: crate::canonical::RuleAction) -> WireRuleAction {
    match action {
        crate::canonical::RuleAction::Route => WireRuleAction::Route,
        crate::canonical::RuleAction::Block => WireRuleAction::Block,
    }
}

fn decode_action(action: WireRuleAction) -> crate::canonical::RuleAction {
    match action {
        WireRuleAction::Route => crate::canonical::RuleAction::Route,
        WireRuleAction::Block => crate::canonical::RuleAction::Block,
    }
}

fn encode_address_match(m: &CanonicalAddressMatch) -> AddressMatchDto {
    match m {
        CanonicalAddressMatch::ExactFqdn(value) => AddressMatchDto::ExactFqdn {
            value: value.clone(),
        },
        CanonicalAddressMatch::SuffixDomain(suffix) => AddressMatchDto::SuffixDomain {
            suffix: suffix.clone(),
        },
        CanonicalAddressMatch::Zone(name) => AddressMatchDto::Zone { name: name.clone() },
        CanonicalAddressMatch::ExactIp(IpAddr::V4(addr)) => AddressMatchDto::ExactIpv4 {
            address: addr.to_string(),
        },
        CanonicalAddressMatch::ExactIp(IpAddr::V6(addr)) => AddressMatchDto::ExactIpv6 {
            address: addr.to_string(),
        },
    }
}

fn encode_app_match(m: &CanonicalAppMatch) -> AppMatchDto {
    AppMatchDto {
        pattern: match &m.pattern {
            CanonicalAppPattern::Exact(v) => AppPatternDto::Exact { value: v.clone() },
            CanonicalAppPattern::Glob(v) => AppPatternDto::Glob { value: v.clone() },
        },
        include_child_processes: m.include_child_processes,
    }
}

// ── Decode (wire DTO → domain) ──────────────────────────────────────────────

/// Reconstruct a [`RulesRevisionContent`] from the canonical wire DTO.
///
/// Rejects unknown schema versions, addresses and application values the rule
/// pipeline refuses, and rules that carry no match. [`CanonicalRuleSet::from_rules`]
/// re-sorts each route, so a wire arriving out of order decodes canonically.
///
/// `platform` is the one the revision's application rules are for — on the
/// service, the host it runs on — and decides how their names are spelled.
pub fn decode(
    dto: CanonicalRulesJsonV1,
    platform: HostPlatform,
) -> Result<RulesRevisionContent, RulesJsonCodecError> {
    let naming = platform.executable_naming();
    if dto.schema_version != RULES_JSON_SCHEMA_VERSION {
        return Err(RulesJsonCodecError::UnsupportedSchemaVersion {
            got: dto.schema_version,
            expected: RULES_JSON_SCHEMA_VERSION,
        });
    }

    let primary = dto
        .primary
        .into_iter()
        .map(|rule| decode_rule(rule, naming))
        .collect::<Result<Vec<_>, _>>()?;
    let secondary = dto
        .secondary
        .into_iter()
        .map(|rule| decode_rule(rule, naming))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(RulesRevisionContent {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(primary),
            secondary: CanonicalRuleSet::from_rules(secondary),
        },
        format_version: RULES_REVISION_FORMAT_VERSION,
    })
}

fn decode_rule(
    dto: RuleDto,
    naming: ExecutableNaming,
) -> Result<CanonicalRule, RulesJsonCodecError> {
    let address_match = dto
        .address_match
        .map(|m| decode_address_match(&dto.id, m))
        .transpose()?;
    let app_match = dto
        .app_match
        .map(|m| decode_app_match(&dto.id, m, naming))
        .transpose()?;
    if address_match.is_none() && app_match.is_none() {
        return Err(RulesJsonCodecError::EmptyMatch { rule_id: dto.id });
    }
    Ok(CanonicalRule {
        id: RuleId(dto.id),
        enabled: dto.enabled,
        address_match,
        app_match,
        comment: dto.comment,
        action: decode_action(dto.action),
        origin: dto.origin,
    })
}

fn decode_address_match(
    rule_id: &str,
    m: AddressMatchDto,
) -> Result<CanonicalAddressMatch, RulesJsonCodecError> {
    Ok(match m {
        AddressMatchDto::ExactFqdn { value } => {
            CanonicalAddressMatch::ExactFqdn(respelled(HostNameKind::Domain, value))
        }
        AddressMatchDto::SuffixDomain { suffix } => {
            CanonicalAddressMatch::SuffixDomain(respelled(HostNameKind::Domain, suffix))
        }
        AddressMatchDto::Zone { name } => {
            CanonicalAddressMatch::Zone(respelled(HostNameKind::Zone, name))
        }
        AddressMatchDto::ExactIpv4 { address } => {
            CanonicalAddressMatch::ExactIp(exact_ip(rule_id, address, false)?)
        }
        AddressMatchDto::ExactIpv6 { address } => {
            CanonicalAddressMatch::ExactIp(exact_ip(rule_id, address, true)?)
        }
    })
}

/// The address the rule pipeline reads from `raw`. The wire kind only names
/// the error: the value decides the family, as it does everywhere else.
fn exact_ip(rule_id: &str, raw: String, v6: bool) -> Result<IpAddr, RulesJsonCodecError> {
    canonical_ip_address(&raw, &RuleId(rule_id.to_string()), &mut Vec::new()).map_err(|_| {
        let rule_id = rule_id.to_string();
        if v6 {
            RulesJsonCodecError::InvalidIpv6 { rule_id, raw }
        } else {
            RulesJsonCodecError::InvalidIpv4 { rule_id, raw }
        }
    })
}

/// The pipeline's spelling of a name it accepts; any other name unchanged.
/// Without it `.ru` or `example.com.` from the GUI would be stored as typed and
/// never match: `match_zone` looks for `..ru`, a query name has no final dot.
fn respelled(kind: HostNameKind, raw: String) -> String {
    canonical_host_name(kind, &raw, &RuleId(String::new()), &mut Vec::new()).unwrap_or(raw)
}

/// The pipeline's reading of a wire application pattern: canonical spelling (a
/// client may never have run validation, and two spellings of one rule would
/// make the set unequal to itself) or the pipeline's refusal.
pub(crate) fn wire_app_pattern(
    pattern: &AppPatternDto,
    naming: ExecutableNaming,
    rule_id: &RuleId,
) -> Result<CanonicalAppPattern, ValidationError> {
    let (value, glob) = match pattern {
        // No process can carry a `*` in its name: an "exact" value holding one
        // is a mislabelled pattern.
        AppPatternDto::Exact { value } => (value, value.contains('*')),
        AppPatternDto::Glob { value } => (value, true),
    };
    canonical_app_pattern(value, glob, naming, rule_id, &mut Vec::new())
}

fn decode_app_match(
    rule_id: &str,
    m: AppMatchDto,
    naming: ExecutableNaming,
) -> Result<CanonicalAppMatch, RulesJsonCodecError> {
    let pattern =
        wire_app_pattern(&m.pattern, naming, &RuleId(rule_id.to_string())).map_err(|refusal| {
            let rule_id = rule_id.to_string();
            match refusal {
                ValidationError::AppGlobTooWide { .. } => {
                    RulesJsonCodecError::AppGlobTooWide { rule_id }
                }
                _ => RulesJsonCodecError::AppNameInvalid {
                    rule_id,
                    raw: match &m.pattern {
                        AppPatternDto::Exact { value } | AppPatternDto::Glob { value } => {
                            value.clone()
                        }
                    },
                },
            }
        })?;
    Ok(CanonicalAppMatch {
        pattern,
        include_child_processes: m.include_child_processes,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::rules_json::{from_canonical_string, to_canonical_string};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn exact_fqdn(id: &str, value: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn(value.into())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn suffix(id: &str, suffix_val: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::SuffixDomain(suffix_val.into())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn zone(id: &str, name: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::Zone(name.into())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn ip(id: &str, addr: Ipv4Addr) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(addr))),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn app_exact(id: &str, process: &str, include_children: bool) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: None,
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact(process.into()),
                include_child_processes: include_children,
            }),
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn app_glob(id: &str, pattern: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: None,
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Glob(pattern.into()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
        CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(primary),
            secondary: CanonicalRuleSet::from_rules(secondary),
        }
    }

    #[test]
    fn an_exact_pattern_carrying_a_star_decodes_as_a_glob() {
        // What the GUI used to send for `disko*.exe`: no process can be named
        // that, so keeping it exact stored a rule that matched nothing.
        let dto = CanonicalRulesJsonV1 {
            schema_version: 1,
            primary: vec![RuleDto {
                id: "r-app".into(),
                enabled: true,
                address_match: None,
                app_match: Some(AppMatchDto {
                    pattern: AppPatternDto::Exact {
                        value: "DiskO*.exe".into(),
                    },
                    include_child_processes: false,
                }),
                comment: String::new(),
                action: WireRuleAction::default(),
                origin: None,
            }],
            secondary: vec![],
        };
        let decoded = decode(dto, HostPlatform::Windows).expect("decode");
        assert_eq!(
            decoded.rule_book.primary.rules()[0]
                .app_match
                .as_ref()
                .expect("app match")
                .pattern,
            CanonicalAppPattern::Glob("disko*.exe".into())
        );
    }

    /// The pipeline blocks a bare `*` (`ValidationError::AppGlobTooWide`), but
    /// a revision can reach enforcement from storage or the wire WITHOUT
    /// passing through it — this decoder is the only gate on that path, and it
    /// used to wave the pattern through as a rule matching every process.
    #[test]
    fn a_bare_star_app_pattern_is_refused_on_the_storage_and_wire_path() {
        let dto = |pattern: AppPatternDto| CanonicalRulesJsonV1 {
            schema_version: 1,
            primary: vec![RuleDto {
                id: "r-app".into(),
                enabled: true,
                address_match: None,
                app_match: Some(AppMatchDto {
                    pattern,
                    include_child_processes: false,
                }),
                comment: String::new(),
                action: WireRuleAction::default(),
                origin: None,
            }],
            secondary: vec![],
        };
        // Both spellings a producer can use for "everything".
        for pattern in [
            AppPatternDto::Glob { value: "*".into() },
            AppPatternDto::Exact { value: "*".into() },
        ] {
            assert_eq!(
                decode(dto(pattern), HostPlatform::Windows),
                Err(RulesJsonCodecError::AppGlobTooWide {
                    rule_id: "r-app".into()
                })
            );
        }
        // A narrower glob is still perfectly legal.
        assert!(decode(
            dto(AppPatternDto::Glob {
                value: "chrome*.exe".into()
            }),
            HostPlatform::Windows
        )
        .is_ok());
    }

    /// Decode reads an application value by the pipeline's verdict alone: it
    /// accepts exactly what the per-row verdict accepts, and keeps no reader
    /// of its own.
    #[test]
    fn decode_reads_applications_by_the_pipeline_verdict_only() {
        let dto = |value: &str| CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![RuleDto {
                id: "r-app".into(),
                enabled: true,
                address_match: None,
                app_match: Some(AppMatchDto {
                    pattern: AppPatternDto::Exact {
                        value: value.into(),
                    },
                    include_child_processes: false,
                }),
                comment: String::new(),
                action: WireRuleAction::default(),
                origin: None,
            }],
            secondary: vec![],
        };
        let long = "a".repeat(crate::preset_validation::MAX_MATCH_VALUE_LEN + 1);
        for value in [
            "chrome.exe",
            "chrome*.exe",
            "tab\tname.exe",
            "*",
            "bell\u{7}.exe",
            "line\nbreak.exe",
            long.as_str(),
        ] {
            let verdict = crate::rule_value_validation::validate_rule_value("application", value);
            assert_eq!(
                decode(dto(value), HostPlatform::Windows).is_ok(),
                !verdict.is_error(),
                "{value:?}"
            );
        }
        assert_eq!(
            decode(dto(&long), HostPlatform::Windows),
            Err(RulesJsonCodecError::AppNameInvalid {
                rule_id: "r-app".into(),
                raw: long.clone(),
            })
        );
        let source = include_str!("rules_json_codec.rs");
        let (code, _) = source.split_once("#[cfg(test)]").expect("test module");
        for own_reader in [
            concat!("canonical_exact_", "process_name"),
            concat!("canonical_glob_", "process_pattern"),
        ] {
            assert!(!code.contains(own_reader), "{own_reader}");
        }
    }

    /// A submission a Linux service re-spells must come out as the name the
    /// process has, not the Windows spelling of it.
    #[test]
    fn a_linux_revision_keeps_bare_names_while_windows_gains_the_suffix() {
        let dto = || CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![RuleDto {
                id: "r-app".into(),
                enabled: true,
                address_match: None,
                app_match: Some(AppMatchDto {
                    pattern: AppPatternDto::Exact {
                        value: "Messenger-Desktop".into(),
                    },
                    include_child_processes: false,
                }),
                comment: String::new(),
                action: WireRuleAction::default(),
                origin: None,
            }],
            secondary: vec![],
        };
        let name = |platform| {
            decode(dto(), platform)
                .expect("decode")
                .rule_book
                .primary
                .rules()[0]
                .app_match
                .as_ref()
                .expect("app match")
                .pattern
                .as_str()
                .to_string()
        };
        assert_eq!(name(HostPlatform::Linux), "messenger-desktop");
        assert_eq!(name(HostPlatform::MacOS), "messenger-desktop");
        assert_eq!(name(HostPlatform::Windows), "messenger-desktop.exe");
    }

    #[test]
    fn round_trip_exact_fqdn() {
        let content =
            RulesRevisionContent::new(book(vec![exact_fqdn("r-1", "api.example.com")], vec![]));
        let dto = encode(&content);
        let back = decode(dto, HostPlatform::Windows).expect("decode");
        assert_eq!(content, back);
    }

    #[test]
    fn round_trip_all_address_kinds_and_app_match() {
        let content = RulesRevisionContent::new(book(
            vec![
                exact_fqdn("r-fqdn", "api.example.com"),
                suffix("r-suffix", "example.com"),
                zone("r-zone", "ru"),
                ip("r-ip", Ipv4Addr::new(203, 0, 113, 5)),
                app_exact("r-app", "chrome.exe", true),
                app_glob("r-glob", "*vpn*.exe"),
            ],
            vec![],
        ));
        let dto = encode(&content);
        let back = decode(dto, HostPlatform::Windows).expect("decode");
        assert_eq!(content, back);
    }

    #[test]
    fn an_ipv6_rule_round_trips_as_its_own_kind() {
        let mut v6 = ip("r-v6", Ipv4Addr::new(203, 0, 113, 5));
        v6.address_match = Some(CanonicalAddressMatch::ExactIp(
            "2001:db8::7".parse().expect("v6"),
        ));
        let content = RulesRevisionContent::new(book(vec![v6], vec![]));
        let dto = encode(&content);
        assert!(matches!(
            dto.primary[0].address_match,
            Some(AddressMatchDto::ExactIpv6 { .. })
        ));
        assert_eq!(decode(dto, HostPlatform::Windows).expect("decode"), content);
    }

    #[test]
    fn block_action_round_trips_through_canonical_string() {
        let mut blocked = exact_fqdn("r-block", "ads.example.com");
        blocked.action = crate::canonical::RuleAction::Block;
        let content = RulesRevisionContent::new(book(vec![blocked], vec![]));
        let dto = encode(&content);
        let s = to_canonical_string(&dto).expect("serialize");
        assert!(
            s.contains("\"action\":\"block\""),
            "block action must serialize with the kebab slug, got: {s}"
        );
        let back = decode(
            from_canonical_string(&s).expect("deserialize"),
            HostPlatform::Windows,
        )
        .expect("decode");
        assert_eq!(content, back);
        assert_eq!(
            back.rule_book.primary.rules()[0].action,
            crate::canonical::RuleAction::Block
        );
    }

    #[test]
    fn route_rule_canonical_bytes_stay_stable_and_hash_guard() {
        // A default Route rule must serialize byte-identically to the
        // pre-block format: the `action` field is skipped when default, so
        // existing revisions decode to Route and content hashes never churn.
        let content =
            RulesRevisionContent::new(book(vec![exact_fqdn("r-1", "api.example.com")], vec![]));
        let s = to_canonical_string(&encode(&content)).expect("serialize");
        assert!(
            !s.contains("action"),
            "route rules must not emit the action field (hash-stability guard), got: {s}"
        );
        // A missing action field decodes back to Route.
        let back = decode(
            from_canonical_string(&s).expect("deserialize"),
            HostPlatform::Windows,
        )
        .expect("decode");
        assert_eq!(
            back.rule_book.primary.rules()[0].action,
            crate::canonical::RuleAction::Route
        );
    }

    #[test]
    fn round_trip_through_canonical_string() {
        let content = RulesRevisionContent::new(book(
            vec![
                exact_fqdn("r-2", "b.example.com"),
                exact_fqdn("r-1", "a.example.com"),
            ],
            vec![app_exact("r-3", "chrome.exe", false)],
        ));
        let dto = encode(&content);
        let s = to_canonical_string(&dto).expect("serialize");
        let parsed = from_canonical_string(&s).expect("deserialize");
        let back = decode(parsed, HostPlatform::Windows).expect("decode");
        assert_eq!(content, back);
    }

    #[test]
    fn encode_emits_canonical_order_across_address_kinds() {
        // Insertion order shuffled — encode should still produce
        // canonical order (ExactFqdn → Suffix → Zone → ExactIp → App).
        let content = RulesRevisionContent::new(book(
            vec![
                ip("r-ip", Ipv4Addr::new(10, 0, 0, 1)),
                zone("r-zone", "intra"),
                suffix("r-suffix", "example.com"),
                exact_fqdn("r-fqdn", "example.com"),
                app_exact("r-app", "chrome.exe", false),
            ],
            vec![],
        ));
        let dto = encode(&content);
        let ids: Vec<&str> = dto.primary.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["r-fqdn", "r-suffix", "r-zone", "r-ip", "r-app"],
            "encoder must emit canonical order"
        );
    }

    #[test]
    fn decode_re_sorts_wire_rules_into_canonical_order() {
        // Wire arrives out of order; decoder must sort.
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![
                RuleDto {
                    id: "r-ip".into(),
                    enabled: true,
                    address_match: Some(AddressMatchDto::ExactIpv4 {
                        address: "10.0.0.1".into(),
                    }),
                    app_match: None,
                    comment: String::new(),
                    action: nrr_shared::rules_json::RuleAction::Route,
                    origin: None,
                },
                RuleDto {
                    id: "r-fqdn".into(),
                    enabled: true,
                    address_match: Some(AddressMatchDto::ExactFqdn {
                        value: "example.com".into(),
                    }),
                    app_match: None,
                    comment: String::new(),
                    action: nrr_shared::rules_json::RuleAction::Route,
                    origin: None,
                },
            ],
            secondary: vec![],
        };
        let content = decode(dto, HostPlatform::Windows).expect("decode");
        let ids: Vec<&str> = content
            .rule_book
            .primary
            .rules()
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(ids, vec!["r-fqdn", "r-ip"]);
    }

    #[test]
    fn decode_rejects_unsupported_schema_version() {
        let dto = CanonicalRulesJsonV1 {
            schema_version: 999,
            primary: vec![],
            secondary: vec![],
        };
        let err = decode(dto, HostPlatform::Windows).expect_err("must reject");
        match err {
            RulesJsonCodecError::UnsupportedSchemaVersion { got, expected } => {
                assert_eq!(got, 999);
                assert_eq!(expected, RULES_JSON_SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedSchemaVersion, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_invalid_ipv4() {
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![RuleDto {
                id: "r-bad".into(),
                enabled: true,
                address_match: Some(AddressMatchDto::ExactIpv4 {
                    address: "not.an.ipv4".into(),
                }),
                app_match: None,
                comment: String::new(),
                action: nrr_shared::rules_json::RuleAction::Route,
                origin: None,
            }],
            secondary: vec![],
        };
        let err = decode(dto, HostPlatform::Windows).expect_err("must reject");
        match err {
            RulesJsonCodecError::InvalidIpv4 { rule_id, raw } => {
                assert_eq!(rule_id, "r-bad");
                assert_eq!(raw, "not.an.ipv4");
            }
            other => panic!("expected InvalidIpv4, got {other:?}"),
        }
    }

    /// Stored revisions keep loading: every address the decoder read before
    /// it went through the pipeline's reader comes out as the same address.
    #[test]
    fn every_address_the_former_decoder_read_decodes_unchanged() {
        let former = |address: &AddressMatchDto| match address {
            AddressMatchDto::ExactIpv4 { address } => {
                address.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
            }
            AddressMatchDto::ExactIpv6 { address } => address
                .parse::<Ipv6Addr>()
                .ok()
                .map(|a| crate::address_class::canonical_ip(IpAddr::V6(a))),
            _ => None,
        };
        // "This host" and the broadcast are left out: a stored book drops
        // them before decoding.
        let values = [
            "203.0.113.5",
            "10.0.0.1",
            "::1",
            "2001:DB8::7",
            "2001:db8:0:0:0:0:0:7",
            "::ffff:203.0.113.7",
            "fe80::1",
            "01.0.2.4",
            " 203.0.113.5",
            "203.0.113.5/32",
            "203.0.113.1-203.0.113.9",
            "fe80::1%3",
            "example.com",
            "",
        ];
        for value in values {
            for address in [
                AddressMatchDto::ExactIpv4 {
                    address: value.into(),
                },
                AddressMatchDto::ExactIpv6 {
                    address: value.into(),
                },
            ] {
                let Some(expected) = former(&address) else {
                    continue;
                };
                let decoded = decode_address_match("r-ip", address.clone())
                    .unwrap_or_else(|e| panic!("{address:?} stopped decoding: {e}"));
                assert_eq!(
                    decoded,
                    CanonicalAddressMatch::ExactIp(expected),
                    "{address:?}"
                );
            }
        }
    }

    #[test]
    fn decode_rejects_rule_without_any_match() {
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![RuleDto {
                id: "r-empty".into(),
                enabled: true,
                address_match: None,
                app_match: None,
                comment: String::new(),
                action: nrr_shared::rules_json::RuleAction::Route,
                origin: None,
            }],
            secondary: vec![],
        };
        let err = decode(dto, HostPlatform::Windows).expect_err("must reject");
        match err {
            RulesJsonCodecError::EmptyMatch { rule_id } => {
                assert_eq!(rule_id, "r-empty");
            }
            other => panic!("expected EmptyMatch, got {other:?}"),
        }
    }

    #[test]
    fn names_are_spelled_the_pipeline_way_and_refused_ones_kept_as_they_came() {
        let rule = |id: &str, address_match: AddressMatchDto| RuleDto {
            id: id.into(),
            enabled: true,
            address_match: Some(address_match),
            app_match: None,
            comment: String::new(),
            action: nrr_shared::rules_json::RuleAction::Route,
            origin: None,
        };
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![
                rule("z1", AddressMatchDto::Zone { name: ".RU".into() }),
                rule(
                    "z2",
                    AddressMatchDto::Zone {
                        name: "*.org.".into(),
                    },
                ),
                rule(
                    "z3",
                    AddressMatchDto::Zone {
                        name: "рф".into()
                    },
                ),
                rule(
                    "f1",
                    AddressMatchDto::ExactFqdn {
                        value: "Example.COM.".into(),
                    },
                ),
                rule(
                    "s1",
                    AddressMatchDto::SuffixDomain {
                        suffix: "cdn.example.".into(),
                    },
                ),
                rule(
                    "bad",
                    AddressMatchDto::ExactFqdn {
                        value: "192.168.1.1".into(),
                    },
                ),
            ],
            secondary: vec![],
        };
        let content = decode(dto, HostPlatform::Windows).expect("decode");
        let spelled: std::collections::BTreeMap<&str, String> = content
            .rule_book
            .primary
            .rules()
            .iter()
            .map(|r| {
                let value = match r.address_match.as_ref().expect("address") {
                    CanonicalAddressMatch::Zone(v)
                    | CanonicalAddressMatch::ExactFqdn(v)
                    | CanonicalAddressMatch::SuffixDomain(v) => v.clone(),
                    CanonicalAddressMatch::ExactIp(ip) => ip.to_string(),
                };
                (r.id.as_str(), value)
            })
            .collect();
        assert_eq!(spelled["z1"], "ru");
        assert_eq!(spelled["z2"], "org");
        assert_eq!(spelled["z3"], "xn--p1ai");
        assert_eq!(spelled["f1"], "example.com");
        assert_eq!(spelled["s1"], "cdn.example");
        assert_eq!(spelled["bad"], "192.168.1.1");
    }

    #[test]
    fn decode_preserves_disabled_flag_and_comment() {
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![RuleDto {
                id: "r-x".into(),
                enabled: false,
                address_match: Some(AddressMatchDto::ExactFqdn {
                    value: "x.test".into(),
                }),
                app_match: None,
                comment: "muted by user".into(),
                action: nrr_shared::rules_json::RuleAction::Route,
                origin: None,
            }],
            secondary: vec![],
        };
        let content = decode(dto, HostPlatform::Windows).expect("decode");
        let rule = &content.rule_book.primary.rules()[0];
        assert!(!rule.enabled);
        assert_eq!(rule.comment, "muted by user");
    }

    #[test]
    fn encode_uses_wire_schema_version_constant() {
        let content = RulesRevisionContent::new(book(vec![exact_fqdn("r-1", "x.test")], vec![]));
        let dto = encode(&content);
        assert_eq!(dto.schema_version, RULES_JSON_SCHEMA_VERSION);
    }

    #[test]
    fn decode_returns_current_format_version() {
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![],
            secondary: vec![],
        };
        let content = decode(dto, HostPlatform::Windows).expect("decode");
        assert_eq!(content.format_version, RULES_REVISION_FORMAT_VERSION);
    }

    #[test]
    fn empty_book_round_trips() {
        let content = RulesRevisionContent::new(book(vec![], vec![]));
        let dto = encode(&content);
        let back = decode(dto, HostPlatform::Windows).expect("decode");
        assert_eq!(content, back);
    }

    /// Repeated encode → canonical-string must be byte-identical for
    /// the same input. This is the load-bearing property for
    /// content-hash idempotency.
    #[test]
    fn encode_to_canonical_string_is_deterministic() {
        let content = RulesRevisionContent::new(book(
            vec![
                exact_fqdn("r-2", "b.test"),
                exact_fqdn("r-1", "a.test"),
                ip("r-ip", Ipv4Addr::new(192, 0, 2, 1)),
            ],
            vec![app_glob("r-app", "*proxy*.exe")],
        ));
        let s1 = to_canonical_string(&encode(&content)).expect("serialize 1");
        let s2 = to_canonical_string(&encode(&content)).expect("serialize 2");
        let s3 = to_canonical_string(&encode(&content)).expect("serialize 3");
        assert_eq!(s1, s2);
        assert_eq!(s2, s3);
    }
}
