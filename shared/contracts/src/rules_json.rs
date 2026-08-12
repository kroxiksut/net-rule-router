//! Canonical rules-json wire schema.
//!
//! This module defines the **on-the-wire** form of a rules revision —
//! the schema the GUI submits as `RulesUpdatePayload.rules_json`, the
//! service persists in `revisions.content_json`, and the apply layer
//! decodes back into [`RulesRevisionContent`].
//!
//! [`RulesRevisionContent`]: nrr_domain::rules_revision::RulesRevisionContent
//!
//! ## Why a separate DTO layer
//!
//! The domain crate ([`nrr-domain`]) is pure — no serde, no I/O. The
//! [`CanonicalRuleBook`] struct it owns has no `Serialize` derives, so
//! the bytes that flow across IPC need their own typed shape. This
//! module provides that shape, plus a deterministic serializer
//! ([`to_canonical_string`]) suitable for content-hashing.
//!
//! [`CanonicalRuleBook`]: nrr_domain::canonical::CanonicalRuleBook
//! [`nrr-domain`]: nrr_domain
//!
//! ## Wire format (`schema_version = 1`)
//!
//! ```json
//! {
//!   "schema-version": 1,
//!   "primary": [
//!     {
//!       "id": "r-001",
//!       "enabled": true,
//!       "address-match": { "kind": "exact-fqdn", "value": "api.example.com" }
//!     }
//!   ],
//!   "secondary": [
//!     {
//!       "id": "r-002",
//!       "enabled": true,
//!       "app-match": {
//!         "pattern": { "kind": "exact", "value": "chrome.exe" },
//!         "include-child-processes": true
//!       },
//!       "comment": "browser pinned to secondary"
//!     }
//!   ]
//! }
//! ```
//!
//! Tagged enums for [`AddressMatchDto`] and [`AppPatternDto`] use
//! `"kind"` as the discriminator and kebab-case slugs. Fields use
//! kebab-case at the JSON layer.
//!
//! ## Determinism guarantees
//!
//! [`to_canonical_string`] produces byte-identical output for two
//! semantically equal DTOs. This is what makes content-hashing
//! idempotent — callers SHA-256 the canonical string and rely on
//! collisions only when rule content actually changes. Guarantees:
//!
//! - **Field order** is the declaration order of the structs in this
//!   module. `serde_json` walks fields in declaration order; we use
//!   no [`HashMap`] in the DTO surface.
//! - **No floats** — IPv4 is a `String` (canonical dotted-quad), TTL
//!   counts are `u16`/`u32`. No `f32`/`f64` anywhere.
//! - **No whitespace** between tokens — `serde_json::to_string` (NOT
//!   `to_string_pretty`).
//! - **Optional fields elided** when `None` / empty — `address_match`,
//!   `app_match`, `comment`, `action`, `origin`. The same input must
//!   always serialise to the same byte string; if one rule has
//!   `comment: ""` and another omits it entirely, both produce the
//!   SAME JSON. This is also what lets an optional field be *added*
//!   without disturbing the content hash of any rule that does not
//!   use it.
//! - **Multi-byte UTF-8** passes through as-is. Both sides of the IPC
//!   speak UTF-8; ascii-only escaping would only matter for
//!   third-party tools.
//!
//! Content-hash computation lives **outside** this module: the
//! consumer of [`to_canonical_string`] hashes the returned bytes with
//! SHA-256 (storage / service-runtime crates already pull in `sha2`).
//! Keeping the hash out of `nrr-shared` avoids dragging the crypto
//! dependency through every consumer of the contracts crate.

use serde::{Deserialize, Serialize};

/// Rule provenance on the wire. Declared once in [`crate::auto_rule`] — the
/// same type the rules-file parser and the GUI preset parser use — so the
/// reason slug cannot drift between the file syntax, the JSON payload, and the
/// locale key. See that module for why this one is not mirrored into a
/// separate DTO the way [`RuleAction`] is.
pub use crate::auto_rule::RuleOrigin as RuleOriginDto;

/// Current canonical schema version. Bumped when the wire shape of
/// any struct in this module changes in a way that could break
/// content-hash idempotency or codec round-trips.
pub const RULES_JSON_SCHEMA_VERSION: u16 = 1;

/// Versioned canonical envelope for the rules of a single revision.
///
/// `primary` / `secondary` are emitted in the **canonical order**
/// defined by [`nrr_domain::canonical::CanonicalRuleSet`] — the
/// encoder in `nrr-domain` is the single source of truth for that
/// ordering. Callers must not re-sort the vectors before serializing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CanonicalRulesJsonV1 {
    /// Wire-schema version. Must equal
    /// [`RULES_JSON_SCHEMA_VERSION`] for the codec to accept it.
    pub schema_version: u16,
    /// Primary-route rules in canonical order.
    pub primary: Vec<RuleDto>,
    /// Secondary-route rules in canonical order.
    pub secondary: Vec<RuleDto>,
}

/// One rule in the canonical wire form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleDto {
    /// Stable rule identifier (mirrors `nrr_domain::RuleId`).
    pub id: String,
    /// Whether the rule participates in route evaluation.
    pub enabled: bool,
    /// Address-side match condition. Optional — a rule may carry
    /// only an `app_match`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_match: Option<AddressMatchDto>,
    /// Application-side match condition. Optional — a rule may carry
    /// only an `address_match`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_match: Option<AppMatchDto>,
    /// User comment. Serialised as the empty string when omitted on
    /// the domain side; the `skip_serializing_if` clause normalises
    /// `""` to "field absent" so two inputs that differ only by
    /// whether the comment was explicitly empty produce the same
    /// canonical bytes.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
    /// Per-rule enforcement action. Defaults to [`RuleAction::Route`] and is
    /// skipped when serialising a route rule, so existing revisions decode to
    /// `Route` and a route rule's canonical bytes (and content hash) stay
    /// identical to the pre-block format — no schema bump, no revision churn.
    #[serde(default, skip_serializing_if = "RuleAction::is_route")]
    pub action: RuleAction,
    /// Who authored the rule. `None` — the overwhelmingly common case — means
    /// the user wrote it; the field is then absent from the canonical bytes.
    ///
    /// The `skip_serializing_if` clause is load-bearing, not cosmetic: every
    /// user-authored rule must keep hashing to exactly the bytes it hashed to
    /// before this field existed. Emitting `"origin":null` would change every
    /// content hash at once and make the whole rule set look modified to
    /// revision dedup.
    ///
    /// [`RULES_JSON_SCHEMA_VERSION`] therefore stays at 1: the addition is
    /// optional on read (`serde(default)`) and invisible on write when unset,
    /// so old readers and new readers agree on every pre-existing payload. A
    /// bump would force the codec to reject revisions that are still perfectly
    /// decodable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<RuleOriginDto>,
}

/// Per-rule enforcement action on the wire.
///
/// `Route` (default) routes matching traffic via the rule's bucket
/// (primary/secondary adapter). `Block` drops matching traffic entirely.
/// Kept distinct from `nrr_domain::RuleAction`; the codec maps between them.
/// The wire slug is kebab-case `"route"` / `"block"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleAction {
    /// Route matching traffic via the rule's bucket. Default action.
    #[default]
    Route,
    /// Drop matching traffic (hard WFP block); install no route.
    Block,
}

impl RuleAction {
    /// Returns `true` for the default [`RuleAction::Route`] action.
    ///
    /// Used by serde `skip_serializing_if` so route rules serialize
    /// byte-identically to the pre-block format.
    pub fn is_route(&self) -> bool {
        matches!(self, Self::Route)
    }
}

/// Address-side match condition. Tagged enum with kebab-case slug in
/// the `"kind"` field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AddressMatchDto {
    /// Exact FQDN, e.g. `"api.example.com"`. Always lowercase, no
    /// trailing dot, punycode for IDN labels.
    ExactFqdn {
        /// The FQDN.
        value: String,
    },
    /// Subdomain suffix, e.g. `"example.com"` (renders as
    /// `*.example.com` in the GUI). Always lowercase, no leading `*.`.
    SuffixDomain {
        /// The suffix without the `*.` prefix.
        suffix: String,
    },
    /// Zone (TLD or internal domain suffix), e.g. `"ru"`, `"intra"`.
    /// Always lowercase, leading dot stripped.
    Zone {
        /// The zone label.
        name: String,
    },
    /// Single IPv4 address in canonical dotted-quad form.
    #[serde(rename = "exact-ipv4")]
    ExactIpv4 {
        /// IPv4 address as `"a.b.c.d"`.
        address: String,
    },
}

/// Application-side match condition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AppMatchDto {
    /// Match pattern (exact filename or glob).
    pub pattern: AppPatternDto,
    /// When `true`, direct child processes are also matched.
    pub include_child_processes: bool,
}

/// Tagged enum: how an application is matched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AppPatternDto {
    /// Exact filename, e.g. `"chrome.exe"`. Always lowercase, `.exe`
    /// suffix guaranteed on the domain side.
    Exact {
        /// The filename.
        value: String,
    },
    /// Glob, e.g. `"*vpn*.exe"`. Always lowercase.
    Glob {
        /// The glob pattern.
        value: String,
    },
}

/// Errors produced by the canonical-string codec helpers.
#[derive(Debug)]
pub enum RulesJsonCodecError {
    /// `serde_json` failed to (de)serialise the canonical bytes.
    Serde(serde_json::Error),
}

impl core::fmt::Display for RulesJsonCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Serde(e) => write!(f, "rules-json (de)serialise failed: {e}"),
        }
    }
}

impl std::error::Error for RulesJsonCodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serde(e) => Some(e),
        }
    }
}

impl From<serde_json::Error> for RulesJsonCodecError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e)
    }
}

// ── Canonical (de)serialisation ─────────────────────────────────────────────

/// Serialise a [`CanonicalRulesJsonV1`] to its canonical UTF-8 JSON
/// string.
///
/// Output guarantees (see the module-level doc-comment for the full
/// list): stable field order, no whitespace, optional fields elided.
/// Two equal DTOs produce byte-identical strings — the caller can
/// SHA-256 the bytes for content-hash idempotency.
pub fn to_canonical_string(dto: &CanonicalRulesJsonV1) -> Result<String, RulesJsonCodecError> {
    Ok(serde_json::to_string(dto)?)
}

/// Parse a canonical JSON string back into a [`CanonicalRulesJsonV1`].
///
/// This deliberately does not validate `schema_version` — the codec
/// in `nrr-domain` checks that against
/// [`RULES_JSON_SCHEMA_VERSION`] before reconstructing the domain
/// types. Keeping the version check out of the wire layer lets older
/// schemas survive round-trips through the wire DTO even when the
/// upper codec rejects them with a localised error.
pub fn from_canonical_string(s: &str) -> Result<CanonicalRulesJsonV1, RulesJsonCodecError> {
    Ok(serde_json::from_str(s)?)
}

// ── Free-tier rule cap ──────────────────────────────────────────────────────

/// Free-edition maximum USER-authored rule count (primary + secondary) in a
/// single revision — see [`user_rule_count`] for what does not count. The GUI
/// mirrors this as `freeRulesMaxCount` and refuses to add a
/// rule past it; the service enforces the SAME cap authoritatively so a
/// hand-edited preset file or a crafted IPC payload cannot slip past the
/// client-side limit (defense-in-depth — not a hard licence gate, but it raises
/// the bar past editing QML). Tied to the R-ID width (`R-0001`…`R-9999`,
/// zero-padded to 4 digits).
pub const FREE_MAX_RULES: usize = 9999;

/// Total rule count (primary + secondary) of a canonical rules-json string.
///
/// Returns `0` when the string does not decode. That is safe for the cap check:
/// this counts with the SAME [`from_canonical_string`] decoder the apply layer
/// uses, so any payload the apply layer accepts is decoded (and counted)
/// identically here — a malformed string that counts as `0` is also rejected
/// downstream by the codec / apply layer, never applied.
pub fn rule_count(rules_json: &str) -> usize {
    from_canonical_string(rules_json)
        .map(|dto| dto.primary.len() + dto.secondary.len())
        .unwrap_or(0)
}

/// Rules the USER authored — the count the cap is about.
///
/// App-authored rules (`origin: auto`) are excluded. The user did not write the
/// service companions a routed site needs, and hitting the ceiling because the
/// app added them for them is the app taking the user's allowance. The cap's
/// own rationale agrees: it is tied to the `R-0001`…`R-9999` id width, and an
/// authored rule carries an `auto-…` id that consumes no R-number.
pub fn user_rule_count(rules_json: &str) -> usize {
    from_canonical_string(rules_json)
        .map(|dto| {
            dto.primary
                .iter()
                .chain(dto.secondary.iter())
                .filter(|rule| rule.origin.is_none())
                .count()
        })
        .unwrap_or(0)
}

/// `true` when a canonical rules-json string carries more than
/// [`FREE_MAX_RULES`] USER-authored rules across both routes.
pub fn exceeds_free_rule_cap(rules_json: &str) -> bool {
    user_rule_count(rules_json) > FREE_MAX_RULES
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_exact_fqdn(id: &str, value: &str) -> RuleDto {
        RuleDto {
            id: id.into(),
            enabled: true,
            address_match: Some(AddressMatchDto::ExactFqdn {
                value: value.into(),
            }),
            app_match: None,
            comment: String::new(),
            action: crate::rules_json::RuleAction::Route,
            origin: None,
        }
    }

    fn sample_app_rule(id: &str, process: &str, include_children: bool) -> RuleDto {
        RuleDto {
            id: id.into(),
            enabled: true,
            address_match: None,
            app_match: Some(AppMatchDto {
                pattern: AppPatternDto::Exact {
                    value: process.into(),
                },
                include_child_processes: include_children,
            }),
            comment: String::new(),
            action: crate::rules_json::RuleAction::Route,
            origin: None,
        }
    }

    #[test]
    fn schema_version_is_one() {
        assert_eq!(RULES_JSON_SCHEMA_VERSION, 1);
    }

    #[test]
    fn round_trip_preserves_exact_fqdn_rule() {
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![sample_exact_fqdn("r-001", "api.example.com")],
            secondary: vec![],
        };
        let s = to_canonical_string(&dto).expect("serialize");
        let back = from_canonical_string(&s).expect("deserialize");
        assert_eq!(dto, back);
    }

    #[test]
    fn round_trip_preserves_all_address_kinds() {
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![
                RuleDto {
                    id: "r-fqdn".into(),
                    enabled: true,
                    address_match: Some(AddressMatchDto::ExactFqdn {
                        value: "api.example.com".into(),
                    }),
                    app_match: None,
                    comment: String::new(),
                    action: crate::rules_json::RuleAction::Route,
                    origin: None,
                },
                RuleDto {
                    id: "r-suffix".into(),
                    enabled: true,
                    address_match: Some(AddressMatchDto::SuffixDomain {
                        suffix: "example.com".into(),
                    }),
                    app_match: None,
                    comment: String::new(),
                    action: crate::rules_json::RuleAction::Route,
                    origin: None,
                },
                RuleDto {
                    id: "r-zone".into(),
                    enabled: true,
                    address_match: Some(AddressMatchDto::Zone { name: "ru".into() }),
                    app_match: None,
                    comment: String::new(),
                    action: crate::rules_json::RuleAction::Route,
                    origin: None,
                },
                RuleDto {
                    id: "r-ipv4".into(),
                    enabled: true,
                    address_match: Some(AddressMatchDto::ExactIpv4 {
                        address: "203.0.113.5".into(),
                    }),
                    app_match: None,
                    comment: String::new(),
                    action: crate::rules_json::RuleAction::Route,
                    origin: None,
                },
            ],
            secondary: vec![],
        };
        let s = to_canonical_string(&dto).expect("serialize");
        let back = from_canonical_string(&s).expect("deserialize");
        assert_eq!(dto, back);
    }

    #[test]
    fn round_trip_preserves_app_match_with_glob() {
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![],
            secondary: vec![RuleDto {
                id: "r-app".into(),
                enabled: true,
                address_match: None,
                app_match: Some(AppMatchDto {
                    pattern: AppPatternDto::Glob {
                        value: "*vpn*.exe".into(),
                    },
                    include_child_processes: true,
                }),
                comment: "vpn-related processes".into(),
                action: crate::rules_json::RuleAction::Route,
                origin: None,
            }],
        };
        let s = to_canonical_string(&dto).expect("serialize");
        let back = from_canonical_string(&s).expect("deserialize");
        assert_eq!(dto, back);
    }

    #[test]
    fn empty_rule_book_serialises_to_minimal_json() {
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![],
            secondary: vec![],
        };
        let s = to_canonical_string(&dto).expect("serialize");
        assert_eq!(s, r#"{"schema-version":1,"primary":[],"secondary":[]}"#);
    }

    #[test]
    fn repeated_serialisation_is_byte_identical() {
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![
                sample_exact_fqdn("r-002", "b.example.com"),
                sample_exact_fqdn("r-001", "a.example.com"),
            ],
            secondary: vec![sample_app_rule("r-003", "chrome.exe", false)],
        };
        let s1 = to_canonical_string(&dto).expect("serialize 1");
        let s2 = to_canonical_string(&dto).expect("serialize 2");
        let s3 = to_canonical_string(&dto).expect("serialize 3");
        assert_eq!(s1, s2);
        assert_eq!(s2, s3);
    }

    /// `comment: ""` and `comment: <omitted>` MUST produce the same
    /// canonical bytes — `skip_serializing_if = "String::is_empty"`
    /// is what guarantees that.
    #[test]
    fn empty_comment_is_elided_from_canonical_bytes() {
        let with_empty = RuleDto {
            id: "r-x".into(),
            enabled: true,
            address_match: Some(AddressMatchDto::ExactFqdn {
                value: "x.test".into(),
            }),
            app_match: None,
            comment: String::new(),
            action: crate::rules_json::RuleAction::Route,
            origin: None,
        };
        let with_filled = RuleDto {
            comment: "hello".into(),
            ..with_empty.clone()
        };

        let s_empty = to_canonical_string(&CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![with_empty],
            secondary: vec![],
        })
        .expect("serialize empty");
        assert!(
            !s_empty.contains("\"comment\""),
            "empty comment must be elided from the canonical bytes; got {s_empty}"
        );

        let s_filled = to_canonical_string(&CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![with_filled],
            secondary: vec![],
        })
        .expect("serialize filled");
        assert!(s_filled.contains("\"comment\":\"hello\""));
    }

    #[test]
    fn address_match_kind_uses_kebab_case_slugs() {
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![RuleDto {
                id: "r-1".into(),
                enabled: true,
                address_match: Some(AddressMatchDto::SuffixDomain {
                    suffix: "example.com".into(),
                }),
                app_match: None,
                comment: String::new(),
                action: crate::rules_json::RuleAction::Route,
                origin: None,
            }],
            secondary: vec![],
        };
        let s = to_canonical_string(&dto).expect("serialize");
        assert!(
            s.contains(r#""kind":"suffix-domain""#),
            "suffix-domain slug must be kebab-case in canonical bytes; got {s}"
        );
    }

    #[test]
    fn exact_ipv4_kind_slug_is_exact_ipv4() {
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![RuleDto {
                id: "r-ip".into(),
                enabled: true,
                address_match: Some(AddressMatchDto::ExactIpv4 {
                    address: "1.2.3.4".into(),
                }),
                app_match: None,
                comment: String::new(),
                action: crate::rules_json::RuleAction::Route,
                origin: None,
            }],
            secondary: vec![],
        };
        let s = to_canonical_string(&dto).expect("serialize");
        assert!(
            s.contains(r#""kind":"exact-ipv4""#),
            "exact-ipv4 slug must be present in canonical bytes; got {s}"
        );
    }

    #[test]
    fn app_pattern_kind_slugs_are_exact_and_glob() {
        let s_exact = to_canonical_string(&CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![sample_app_rule("r-1", "chrome.exe", false)],
            secondary: vec![],
        })
        .expect("serialize exact");
        assert!(s_exact.contains(r#""kind":"exact""#), "got {s_exact}");

        let s_glob = to_canonical_string(&CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![RuleDto {
                id: "r-g".into(),
                enabled: true,
                address_match: None,
                app_match: Some(AppMatchDto {
                    pattern: AppPatternDto::Glob {
                        value: "*vpn*.exe".into(),
                    },
                    include_child_processes: false,
                }),
                comment: String::new(),
                action: crate::rules_json::RuleAction::Route,
                origin: None,
            }],
            secondary: vec![],
        })
        .expect("serialize glob");
        assert!(s_glob.contains(r#""kind":"glob""#), "got {s_glob}");
    }

    /// Unknown schema_version round-trips at the wire layer — the
    /// upper codec in `nrr-domain` is what rejects it.
    #[test]
    fn from_canonical_string_accepts_unknown_schema_version() {
        let s = r#"{"schema-version":999,"primary":[],"secondary":[]}"#;
        let dto = from_canonical_string(s).expect("decode must accept future version");
        assert_eq!(dto.schema_version, 999);
    }

    #[test]
    fn malformed_json_surfaces_as_serde_error() {
        let err = from_canonical_string("{not json").expect_err("malformed must fail");
        match err {
            RulesJsonCodecError::Serde(_) => {}
        }
    }

    // ── Origin wire pins ────────────────────────────────────────────────────

    /// The origin field name and every reason slug are a published contract
    /// with three consumers that cannot be type-checked against this module:
    ///
    /// - the rules-file `--- Auto` section syntax (`auto:<slug>` token) —
    ///   `nrr_domain::rules_file`, and any file a user hand-edits;
    /// - the locale entries `rules.auto-origin.<slug>` in `locales/en.json`
    ///   and `locales/ru.json`, which the QML rules list renders through
    ///   `tr()`;
    /// - persisted revision blobs, which are decoded by builds older and newer
    ///   than this one.
    ///
    /// Renaming a slug silently breaks all three at once, so they are pinned
    /// here as literals rather than derived from the enum.
    #[test]
    fn origin_wire_strings_are_pinned() {
        use crate::auto_rule::{AutoRuleReason, RuleOrigin, REASON_LOCALE_KEY_PREFIX};

        let expected = [
            (AutoRuleReason::SiteCompanion, "site-companion"),
            (AutoRuleReason::VpnClientBootstrap, "vpn-client-bootstrap"),
            (AutoRuleReason::UserConfirmed, "user-confirmed"),
            (AutoRuleReason::BlockNoticeRouted, "block-notice-routed"),
        ];
        assert_eq!(
            expected.len(),
            AutoRuleReason::KNOWN.len(),
            "a reason variant was added without pinning its slug (and its \
             locale entry in BOTH locales/en.json and locales/ru.json)"
        );

        for (reason, slug) in expected {
            assert_eq!(reason.as_slug(), slug);
            assert_eq!(
                reason.locale_key(),
                format!("{REASON_LOCALE_KEY_PREFIX}{slug}"),
                "locale key must stay <prefix><slug>"
            );

            let dto = CanonicalRulesJsonV1 {
                schema_version: RULES_JSON_SCHEMA_VERSION,
                primary: vec![RuleDto {
                    origin: Some(RuleOrigin::auto(
                        reason.clone(),
                        "anchor.test",
                        "2026-07-31",
                    )),
                    ..sample_exact_fqdn("r-1", "companion.test")
                }],
                secondary: vec![],
            };
            let s = to_canonical_string(&dto).expect("serialize");
            assert!(
                s.contains(&format!(
                    r#""origin":{{"kind":"auto","reason":"{slug}","anchor":"anchor.test","added":"2026-07-31"}}"#
                )),
                "origin wire shape drifted for {slug}; got {s}"
            );
            assert_eq!(from_canonical_string(&s).expect("deserialize"), dto);
        }
    }

    /// The hash-stability guard: a rule with no origin must serialise to
    /// exactly the bytes it did before the field existed.
    #[test]
    fn absent_origin_is_elided_from_canonical_bytes() {
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![sample_exact_fqdn("r-1", "api.example.com")],
            secondary: vec![],
        };
        let s = to_canonical_string(&dto).expect("serialize");
        assert_eq!(
            s,
            r#"{"schema-version":1,"primary":[{"id":"r-1","enabled":true,"address-match":{"kind":"exact-fqdn","value":"api.example.com"}}],"secondary":[]}"#
        );
    }

    /// A payload written before the field existed still decodes.
    #[test]
    fn payload_without_origin_field_decodes_to_none() {
        let s = r#"{"schema-version":1,"primary":[{"id":"r-1","enabled":true,"address-match":{"kind":"exact-fqdn","value":"a.test"}}],"secondary":[]}"#;
        let dto = from_canonical_string(s).expect("decode");
        assert_eq!(dto.primary[0].origin, None);
    }

    #[test]
    fn rule_count_sums_both_routes_and_zero_on_malformed() {
        assert_eq!(FREE_MAX_RULES, 9999);
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![sample_exact_fqdn("r-1", "a.test")],
            secondary: vec![sample_app_rule("r-2", "b.exe", false)],
        };
        let s = to_canonical_string(&dto).expect("serialize");
        assert_eq!(rule_count(&s), 2);
        assert!(!exceeds_free_rule_cap(&s));
        // Malformed decodes to 0 (rejected downstream by the same codec).
        assert_eq!(rule_count("{not json"), 0);
        assert!(!exceeds_free_rule_cap("{not json"));
    }

    #[test]
    fn exceeds_free_rule_cap_fires_one_past_the_limit() {
        // FREE_MAX_RULES rules is allowed; FREE_MAX_RULES + 1 is not.
        let at_cap: Vec<RuleDto> = (0..FREE_MAX_RULES)
            .map(|i| sample_exact_fqdn(&format!("r-{i}"), &format!("h{i}.test")))
            .collect();
        let s_at = to_canonical_string(&CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: at_cap,
            secondary: vec![],
        })
        .expect("serialize at cap");
        assert_eq!(rule_count(&s_at), FREE_MAX_RULES);
        assert!(
            !exceeds_free_rule_cap(&s_at),
            "exactly at the cap is allowed"
        );

        // One more, split across both routes to prove the total (not per-route)
        // is what counts.
        let s_over = to_canonical_string(&CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: (0..FREE_MAX_RULES)
                .map(|i| sample_exact_fqdn(&format!("r-{i}"), &format!("h{i}.test")))
                .collect(),
            secondary: vec![sample_app_rule("r-extra", "x.exe", false)],
        })
        .expect("serialize over cap");
        assert_eq!(rule_count(&s_over), FREE_MAX_RULES + 1);
        assert!(
            exceeds_free_rule_cap(&s_over),
            "one past the cap is rejected"
        );
    }

    /// The rules the app authored on the user's behalf are not the user's
    /// allowance: a browsing session's worth of site companions must not be
    /// what stops them writing their next rule.
    #[test]
    fn app_authored_rules_do_not_spend_the_free_cap() {
        let authored = |i: usize| RuleDto {
            origin: Some(RuleOriginDto::auto(
                crate::AutoRuleReason::SiteCompanion,
                "example.com",
                "2026-08-04",
            )),
            ..sample_exact_fqdn(&format!("auto-{i}"), &format!("cdn{i}.test"))
        };
        let mut rules: Vec<RuleDto> = (0..FREE_MAX_RULES)
            .map(|i| sample_exact_fqdn(&format!("r-{i}"), &format!("h{i}.test")))
            .collect();
        rules.extend((0..50).map(authored));
        let s = to_canonical_string(&CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: rules,
            secondary: vec![],
        })
        .expect("serialize");

        assert_eq!(
            rule_count(&s),
            FREE_MAX_RULES + 50,
            "the total is unchanged"
        );
        assert_eq!(
            user_rule_count(&s),
            FREE_MAX_RULES,
            "but only what the user wrote is counted against the cap"
        );
        assert!(!exceeds_free_rule_cap(&s));

        // One more USER rule on top is what actually trips it.
        let s_over = to_canonical_string(&CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: (0..=FREE_MAX_RULES)
                .map(|i| sample_exact_fqdn(&format!("r-{i}"), &format!("h{i}.test")))
                .collect(),
            secondary: (0..50).map(authored).collect(),
        })
        .expect("serialize");
        assert!(exceeds_free_rule_cap(&s_over));
    }
}
