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
//!   `RulesRevisionContent`. It rejects unknown schema versions,
//!   malformed IPv4 strings, and rules that carry neither
//!   `address_match` nor `app_match`.
//!
//! The codec is **trust-the-wire**: it does NOT run the full
//! validation pipeline (lowercase, IDNA, glob syntax, …). Wire bytes
//! are expected to be canonical. The validation pipeline in
//! [`crate::validation`] is the upstream gate.
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

use std::net::Ipv4Addr;

use nrr_shared::rules_json::{
    AddressMatchDto, AppMatchDto, AppPatternDto, CanonicalRulesJsonV1,
    RuleAction as WireRuleAction, RuleDto, RULES_JSON_SCHEMA_VERSION,
};

use crate::canonical::{
    CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalRule,
    CanonicalRuleBook, CanonicalRuleSet,
};
use crate::rules_revision::{RulesRevisionContent, RULES_REVISION_FORMAT_VERSION};
use crate::RuleId;

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
    /// `AddressMatchDto::ExactIpv4.address` did not parse as a
    /// dotted-quad IPv4 string.
    InvalidIpv4 {
        /// The offending rule's id, for error context.
        rule_id: String,
        /// The raw string the decoder failed to parse.
        raw: String,
    },
    /// A rule carries neither `address_match` nor `app_match`. The
    /// domain invariant requires at least one.
    EmptyMatch {
        /// The offending rule's id, for error context.
        rule_id: String,
    },
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
            Self::EmptyMatch { rule_id } => write!(
                f,
                "rule {rule_id:?}: must carry at least one of address-match / app-match"
            ),
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
        CanonicalAddressMatch::ExactIp(addr) => AddressMatchDto::ExactIpv4 {
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
/// Rejects unknown schema versions, malformed IPv4 strings, and rules
/// that carry no match. Per-route rules are passed through
/// [`CanonicalRuleSet::from_rules`] which re-applies the canonical
/// sort — so even if the wire arrives out of order, the decoded book
/// is canonically ordered.
pub fn decode(dto: CanonicalRulesJsonV1) -> Result<RulesRevisionContent, RulesJsonCodecError> {
    if dto.schema_version != RULES_JSON_SCHEMA_VERSION {
        return Err(RulesJsonCodecError::UnsupportedSchemaVersion {
            got: dto.schema_version,
            expected: RULES_JSON_SCHEMA_VERSION,
        });
    }

    let primary = dto
        .primary
        .into_iter()
        .map(decode_rule)
        .collect::<Result<Vec<_>, _>>()?;
    let secondary = dto
        .secondary
        .into_iter()
        .map(decode_rule)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(RulesRevisionContent {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(primary),
            secondary: CanonicalRuleSet::from_rules(secondary),
        },
        format_version: RULES_REVISION_FORMAT_VERSION,
    })
}

fn decode_rule(dto: RuleDto) -> Result<CanonicalRule, RulesJsonCodecError> {
    let address_match = dto
        .address_match
        .map(|m| decode_address_match(&dto.id, m))
        .transpose()?;
    let app_match = dto.app_match.map(decode_app_match);
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
        AddressMatchDto::ExactFqdn { value } => CanonicalAddressMatch::ExactFqdn(value),
        AddressMatchDto::SuffixDomain { suffix } => CanonicalAddressMatch::SuffixDomain(suffix),
        AddressMatchDto::Zone { name } => CanonicalAddressMatch::Zone(name),
        AddressMatchDto::ExactIpv4 { address } => {
            let parsed =
                address
                    .parse::<Ipv4Addr>()
                    .map_err(|_| RulesJsonCodecError::InvalidIpv4 {
                        rule_id: rule_id.to_string(),
                        raw: address.clone(),
                    })?;
            CanonicalAddressMatch::ExactIp(parsed)
        }
    })
}

fn decode_app_match(m: AppMatchDto) -> CanonicalAppMatch {
    CanonicalAppMatch {
        pattern: match m.pattern {
            AppPatternDto::Exact { value } => CanonicalAppPattern::Exact(value),
            AppPatternDto::Glob { value } => CanonicalAppPattern::Glob(value),
        },
        include_child_processes: m.include_child_processes,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::rules_json::{from_canonical_string, to_canonical_string};

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
            address_match: Some(CanonicalAddressMatch::ExactIp(addr)),
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
    fn round_trip_exact_fqdn() {
        let content =
            RulesRevisionContent::new(book(vec![exact_fqdn("r-1", "api.example.com")], vec![]));
        let dto = encode(&content);
        let back = decode(dto).expect("decode");
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
        let back = decode(dto).expect("decode");
        assert_eq!(content, back);
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
        let back = decode(from_canonical_string(&s).expect("deserialize")).expect("decode");
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
        let back = decode(from_canonical_string(&s).expect("deserialize")).expect("decode");
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
        let back = decode(parsed).expect("decode");
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
        let content = decode(dto).expect("decode");
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
        let err = decode(dto).expect_err("must reject");
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
        let err = decode(dto).expect_err("must reject");
        match err {
            RulesJsonCodecError::InvalidIpv4 { rule_id, raw } => {
                assert_eq!(rule_id, "r-bad");
                assert_eq!(raw, "not.an.ipv4");
            }
            other => panic!("expected InvalidIpv4, got {other:?}"),
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
        let err = decode(dto).expect_err("must reject");
        match err {
            RulesJsonCodecError::EmptyMatch { rule_id } => {
                assert_eq!(rule_id, "r-empty");
            }
            other => panic!("expected EmptyMatch, got {other:?}"),
        }
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
        let content = decode(dto).expect("decode");
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
        let content = decode(dto).expect("decode");
        assert_eq!(content.format_version, RULES_REVISION_FORMAT_VERSION);
    }

    #[test]
    fn empty_book_round_trips() {
        let content = RulesRevisionContent::new(book(vec![], vec![]));
        let dto = encode(&content);
        let back = decode(dto).expect("decode");
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
                ip("r-ip", Ipv4Addr::new(1, 1, 1, 1)),
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
