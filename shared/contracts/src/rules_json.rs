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
///
/// Cumulative: 2 added subnets and ranges, 3 the `verify-primary` action. A
/// book is written at the lowest version its content needs, so its bytes and
/// content hash stay what they were; a reader accepts any version and keeps
/// the kinds it does not know.
pub const RULES_JSON_SCHEMA_VERSION: u16 = 3;

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

impl RuleDto {
    /// A rule of a kind or action this build does not know (a newer build
    /// wrote it, or the payload is broken). It is kept aside: never applied,
    /// never shown to a client.
    pub fn is_unrecognized(&self) -> bool {
        matches!(self.address_match, Some(AddressMatchDto::Unrecognized(_)))
            || matches!(self.action, RuleAction::Unrecognized(_))
    }
}

/// Per-rule enforcement action on the wire.
///
/// `Route` (default) routes matching traffic via the rule's bucket
/// (primary/secondary adapter). `Block` drops matching traffic entirely.
/// Kept distinct from `nrr_domain::RuleAction`; the codec maps between them.
/// The wire slug is kebab-case `"route"` / `"block"`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleAction {
    /// Route matching traffic via the rule's bucket. Default action.
    #[default]
    Route,
    /// Drop matching traffic (hard WFP block); install no route.
    Block,
    /// `?value` in either set: a route of its own set that the service checks.
    /// The slug predates checking in both directions and stays for stored
    /// revisions.
    VerifyPrimary,
    /// An action this build does not know, kept verbatim. A newer build may
    /// have written it; the rule is stored and re-sent unchanged, never applied.
    #[serde(untagged)]
    Unrecognized(String),
}

impl RuleAction {
    /// Returns `true` for the default [`RuleAction::Route`] action.
    ///
    /// Used by serde `skip_serializing_if` so route rules serialize
    /// byte-identically to the pre-block format.
    pub fn is_route(&self) -> bool {
        matches!(self, Self::Route)
    }

    /// An unknown action that is not even a slug: a broken payload rather
    /// than a newer one.
    pub fn is_malformed(&self) -> bool {
        matches!(self, Self::Unrecognized(slug) if !is_slug(slug))
    }
}

/// A kind or action name as a newer build would write it.
fn is_slug(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
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
    /// Single IPv6 address in its RFC 5952 text form.
    #[serde(rename = "exact-ipv6")]
    ExactIpv6 {
        /// IPv6 address, e.g. `"2001:db8::7"`.
        address: String,
    },
    /// A network of either family, `"10.0.0.0/8"` — canonical, host bits clear.
    Subnet { network: String },
    /// An inclusive address range of one family.
    IpRange { first: String, last: String },
    /// A kind this build does not know, kept verbatim. A newer build may have
    /// written it; the rule is stored and re-sent unchanged, never applied.
    #[serde(untagged)]
    Unrecognized(serde_json::Value),
}

impl AddressMatchDto {
    /// The `kind` slug, also for a kind this build does not know.
    pub fn kind(&self) -> &str {
        match self {
            Self::ExactFqdn { .. } => "exact-fqdn",
            Self::SuffixDomain { .. } => "suffix-domain",
            Self::Zone { .. } => "zone",
            Self::ExactIpv4 { .. } => "exact-ipv4",
            Self::ExactIpv6 { .. } => "exact-ipv6",
            Self::Subnet { .. } => "subnet",
            Self::IpRange { .. } => "ip-range",
            Self::Unrecognized(value) => value
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
        }
    }

    /// The value as one text: a range as `first-last`, an unknown kind as its
    /// JSON.
    pub fn value_text(&self) -> std::borrow::Cow<'_, str> {
        use std::borrow::Cow;
        match self {
            Self::ExactFqdn { value } => Cow::Borrowed(value),
            Self::SuffixDomain { suffix } => Cow::Borrowed(suffix),
            Self::Zone { name } => Cow::Borrowed(name),
            Self::ExactIpv4 { address } | Self::ExactIpv6 { address } => Cow::Borrowed(address),
            Self::Subnet { network } => Cow::Borrowed(network),
            Self::IpRange { first, last } => Cow::Owned(format!("{first}-{last}")),
            Self::Unrecognized(value) => Cow::Owned(value.to_string()),
        }
    }

    /// A kind this build knows that still fell through to the catch-all (its
    /// fields are wrong), or no kind slug at all: a broken payload rather than
    /// a newer one.
    pub fn is_malformed(&self) -> bool {
        const KNOWN: [&str; 7] = [
            "exact-fqdn",
            "suffix-domain",
            "zone",
            "exact-ipv4",
            "exact-ipv6",
            "subnet",
            "ip-range",
        ];
        matches!(self, Self::Unrecognized(_))
            && (KNOWN.contains(&self.kind()) || !is_slug(self.kind()))
    }

    /// The kinds the subnet-and-range format added; a book without them is
    /// written at schema 1, byte for byte as before.
    pub fn needs_schema_2(&self) -> bool {
        matches!(self, Self::Subnet { .. } | Self::IpRange { .. })
    }
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

/// The schema a book needs: 1 unless it holds a kind or action a later schema
/// added, or one this build does not know. Written by the encoder and settled by the
/// comparison fold, so a GUI that still sends 1 never reads as diverged.
pub fn required_schema_version(dto: &CanonicalRulesJsonV1) -> u16 {
    let mut needed = 1;
    for rule in dto.primary.iter().chain(&dto.secondary) {
        match &rule.address_match {
            Some(AddressMatchDto::Unrecognized(_)) => {
                return RULES_JSON_SCHEMA_VERSION.max(dto.schema_version)
            }
            Some(m) if m.needs_schema_2() => needed = needed.max(2),
            _ => {}
        }
        match rule.action {
            RuleAction::Unrecognized(_) => {
                return RULES_JSON_SCHEMA_VERSION.max(dto.schema_version)
            }
            RuleAction::VerifyPrimary => needed = needed.max(3),
            RuleAction::Route | RuleAction::Block => {}
        }
    }
    needed
}

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

// ── Field text ──────────────────────────────────────────────────────────────

/// A rule field holding a character the rules file cannot carry — see
/// [`crate::preset_parser::is_forbidden_field_char`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForbiddenFieldText {
    /// Id of the offending rule.
    pub rule_id: String,
    /// Which field: `address-match`, `app-match`, `comment` or `origin`.
    pub field: &'static str,
}

/// The first rule whose text would not survive the rules file intact.
///
/// Every field checked here is written into that file on export, where a line
/// break inside a note becomes a rule of its own. Refusing it on the way in is
/// what keeps one principal's text from turning into another's routing.
pub fn first_forbidden_field_text(dto: &CanonicalRulesJsonV1) -> Option<ForbiddenFieldText> {
    use crate::auto_rule::RuleOrigin;
    use crate::preset_parser::first_forbidden_field_char;

    let bad = |s: &str| first_forbidden_field_char(s).is_some();
    dto.primary.iter().chain(&dto.secondary).find_map(|rule| {
        let address = rule.address_match.as_ref().is_some_and(|m| match m {
            AddressMatchDto::ExactFqdn { value } => bad(value),
            AddressMatchDto::SuffixDomain { suffix } => bad(suffix),
            AddressMatchDto::Zone { name } => bad(name),
            AddressMatchDto::ExactIpv4 { address } | AddressMatchDto::ExactIpv6 { address } => {
                bad(address)
            }
            AddressMatchDto::Subnet { network } => bad(network),
            AddressMatchDto::IpRange { first, last } => bad(first) || bad(last),
            // Never written into the rules file: it carries no kind the file has.
            AddressMatchDto::Unrecognized(_) => false,
        });
        let app = rule.app_match.as_ref().is_some_and(|m| match &m.pattern {
            AppPatternDto::Exact { value } | AppPatternDto::Glob { value } => bad(value),
        });
        let origin = rule.origin.as_ref().is_some_and(|o| match o {
            RuleOrigin::Auto { anchor, added, .. } => bad(anchor) || bad(added),
        });
        let field = if address {
            "address-match"
        } else if app {
            "app-match"
        } else if bad(&rule.comment) {
            "comment"
        } else if origin {
            "origin"
        } else {
            return None;
        };
        Some(ForbiddenFieldText {
            rule_id: rule.id.clone(),
            field,
        })
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────

// ── Comparison folding ──────────────────────────────────────────────────────

/// Fold a rules-json DTO into the form a COMPARISON should see, then hash or
/// diff that instead of the raw payload.
///
/// [`to_canonical_string`] answers "were these two payloads written the same
/// way"; comparing rule sets needs "do they describe the same routing". The two
/// differ because the service normalises on validation — application names are
/// lower-cased, hostnames lose their trailing dot, a suffix loses its `*.` —
/// while a set typed in the window or read back from a `.txt` keeps whatever
/// the user wrote. A rule spelled `Cloud.exe` therefore hashed differently from
/// the identical `cloud.exe` the service had applied, and the amber
/// "the app and the service disagree" banner could never be cleared: the diff
/// the service computed alongside it was empty, because by then both sides were
/// folded.
///
/// Identity that carries no routing (`id`, `comment`, `origin`) is dropped, and
/// both buckets are ordered, so the result depends on the rules alone and not
/// on the order they arrived in. `origin` belongs in that list even though it
/// is not user-typed: an auto-rule's reason, anchor host and discovery date say
/// where a rule came from, not where the traffic goes, and two sides that
/// learned the same host on different days were reported as diverged.
pub fn fold_for_comparison(dto: &mut CanonicalRulesJsonV1) {
    for rule in dto.primary.iter_mut().chain(dto.secondary.iter_mut()) {
        fold_rule(rule);
    }
    dto.schema_version = required_schema_version(dto);
    // `sort_by_cached_key`, not `sort_by_key`: the key is an owned String and
    // this runs on every edit and every 30 s poll.
    dto.primary.sort_by_cached_key(comparison_key);
    dto.secondary.sort_by_cached_key(comparison_key);
}

fn fold_rule(rule: &mut RuleDto) {
    rule.id.clear();
    rule.comment.clear();
    rule.origin = None;
    if let Some(address) = rule.address_match.as_mut() {
        fold_address_match(address);
    }
    if let Some(app) = rule.app_match.as_mut() {
        match &mut app.pattern {
            // A comparison needs one representative per match class, not the
            // stored spelling: every matcher treats `x` and `x.exe` alike, so
            // folding to the suffixed form is exact on every platform.
            AppPatternDto::Exact { value } => {
                *value = crate::app_identity::canonical_exact_process_name(
                    value,
                    crate::app_identity::ExecutableNaming::WindowsExe,
                )
                .0
            }
            AppPatternDto::Glob { value } => {
                *value = crate::app_identity::canonical_glob_process_pattern(value)
            }
        }
    }
}

/// An address the way the service stores it: IPv4-mapped forms are their IPv4
/// address or network ([`crate::ip_block::canonical_ip`], the service's own
/// reading), under the kind of their family. A value that does not parse is
/// only trimmed: the validator refuses rather than folds it (leading zeros),
/// and a comparison must not invent a difference of its own.
fn fold_address_match(address: &mut AddressMatchDto) {
    use crate::ip_block::{canonical_block, canonical_ip, IpBlock};
    use std::net::IpAddr;

    if let Some(name) = folded_rule_name(address) {
        if let AddressMatchDto::ExactFqdn { value: written }
        | AddressMatchDto::SuffixDomain { suffix: written }
        | AddressMatchDto::Zone { name: written } = address
        {
            *written = name;
        }
        return;
    }
    let fold_bound = |bound: &mut String| {
        let trimmed = bound.trim();
        *bound = trimmed
            .parse::<IpAddr>()
            .map_or_else(|_| trimmed.to_string(), |ip| canonical_ip(ip).to_string());
    };
    let exact = match address {
        AddressMatchDto::ExactIpv4 { address: text }
        | AddressMatchDto::ExactIpv6 { address: text } => {
            *text = text.trim().to_string();
            text.parse::<IpAddr>().ok().map(canonical_ip)
        }
        AddressMatchDto::Subnet { network } => {
            if let Some(block) = IpBlock::parse(network) {
                *network = canonical_block(block).to_string();
            }
            None
        }
        AddressMatchDto::IpRange { first, last } => {
            fold_bound(first);
            fold_bound(last);
            None
        }
        _ => None,
    };
    match exact {
        Some(IpAddr::V4(v4)) => {
            *address = AddressMatchDto::ExactIpv4 {
                address: v4.to_string(),
            }
        }
        Some(IpAddr::V6(v6)) => {
            *address = AddressMatchDto::ExactIpv6 {
                address: v6.to_string(),
            }
        }
        None => {}
    }
}

/// The name a host rule is compared under, `None` for an address rule.
///
/// The one folding every rule-book comparison in this crate uses — the drift
/// hash and both overlap passes — so two surfaces never disagree about whether
/// two rules name the same host. It is the matcher's canonical spelling
/// (`nrr_domain`'s `canonical_host_name`) short of IDNA and validation: on
/// every value the service accepts the two agree, and a stored rule is already
/// in that spelling, so folding it changes nothing.
pub fn folded_rule_name(address: &AddressMatchDto) -> Option<String> {
    match address {
        AddressMatchDto::ExactFqdn { value } => Some(fold_host(value)),
        AddressMatchDto::SuffixDomain { suffix } => Some(fold_suffix(suffix)),
        AddressMatchDto::Zone { name } => Some(fold_suffix(name)),
        AddressMatchDto::ExactIpv4 { .. }
        | AddressMatchDto::ExactIpv6 { .. }
        | AddressMatchDto::Subnet { .. }
        | AddressMatchDto::IpRange { .. }
        | AddressMatchDto::Unrecognized(_) => None,
    }
}

/// Case and trailing-dot folding for a hostname. IDN encoding is NOT done here
/// — the producers punycode before they get this far, and pulling an IDNA
/// implementation into the contracts crate to re-do it would be a second
/// spelling of a decision made upstream.
fn fold_host(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_lowercase()
}

/// [`fold_host`] plus the `*.` / leading-dot spellings of a suffix or zone.
fn fold_suffix(raw: &str) -> String {
    let host = fold_host(raw);
    let stripped = host.strip_prefix("*.").unwrap_or(&host);
    stripped.strip_prefix('.').unwrap_or(stripped).to_string()
}

/// Order key for a folded rule: the routing it describes, nothing else. NUL
/// separates the parts because an application pattern may contain spaces.
///
/// EVERY field that distinguishes two rules has to be in here. The sort is
/// stable, so two rules the key cannot tell apart keep the order they arrived
/// in — and two sides holding the same set in a different order then produce
/// different canonical bytes, which is the permanent amber divergence banner
/// this folding exists to prevent.
fn comparison_key(rule: &RuleDto) -> String {
    let (kind, value) = match &rule.address_match {
        Some(m) => (m.kind(), m.value_text()),
        None => ("", std::borrow::Cow::Borrowed("")),
    };
    let value = value.as_ref();
    // The app side keeps its own discriminator: an `Exact` and a `Glob` of the
    // same text are different rules, and folding them into one slot left input
    // order to decide which came first.
    let (app_kind, app_value, app_children) = match &rule.app_match {
        Some(app) => {
            let (k, v) = match &app.pattern {
                AppPatternDto::Exact { value } => ("app:exact", value.as_str()),
                AppPatternDto::Glob { value } => ("app:glob", value.as_str()),
            };
            (k, v, app.include_child_processes)
        }
        None => ("", "", false),
    };
    let mut key =
        String::with_capacity(kind.len() + value.len() + app_kind.len() + app_value.len() + 12);
    for part in [kind, value, app_kind, app_value] {
        key.push_str(part);
        key.push('\0');
    }
    for flag in [app_children, rule.enabled] {
        key.push(if flag { '1' } else { '0' });
        key.push('\0');
    }
    key.push_str(match &rule.action {
        RuleAction::Route => "route",
        RuleAction::Block => "block",
        RuleAction::VerifyPrimary => "verify-primary",
        RuleAction::Unrecognized(slug) => slug,
    });
    key
}

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

    /// A rule set typed by the user and the same set after the service
    /// validated it must fold to the same bytes — this is what the drift
    /// comparison hashes.
    #[test]
    fn spelling_does_not_survive_folding() {
        let mut typed = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![
                sample_app_rule("r-001", r"C:\Program Files\Cloud\Cloud.exe", false),
                sample_exact_fqdn("r-002", "API.Example.COM."),
            ],
            secondary: vec![],
        };
        let mut validated = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![
                sample_exact_fqdn("r-777", "api.example.com"),
                sample_app_rule("r-999", "cloud.exe", false),
            ],
            secondary: vec![],
        };
        fold_for_comparison(&mut typed);
        fold_for_comparison(&mut validated);
        assert_eq!(
            to_canonical_string(&typed).expect("typed"),
            to_canonical_string(&validated).expect("validated")
        );
    }

    /// Each pair: as a client may send it, as the service stores it.
    #[test]
    fn address_spellings_fold_to_the_stored_form() {
        let folded = |address: AddressMatchDto| {
            let mut dto = CanonicalRulesJsonV1 {
                schema_version: RULES_JSON_SCHEMA_VERSION,
                primary: vec![RuleDto {
                    address_match: Some(address),
                    ..sample_exact_fqdn("r-1", "unused.example")
                }],
                secondary: vec![],
            };
            fold_for_comparison(&mut dto);
            to_canonical_string(&dto).expect("canonical")
        };
        let range = |first: &str, last: &str| AddressMatchDto::IpRange {
            first: first.into(),
            last: last.into(),
        };
        let subnet = |network: &str| AddressMatchDto::Subnet {
            network: network.into(),
        };
        let pairs = [
            (
                range("2001:DB8::1", "2001:DB8:0::FF"),
                range("2001:db8::1", "2001:db8::ff"),
            ),
            (
                range("::ffff:10.0.0.1", " ::ffff:10.0.0.9"),
                range("10.0.0.1", "10.0.0.9"),
            ),
            (subnet("::ffff:10.0.0.0/104"), subnet("10.0.0.0/8")),
            (
                AddressMatchDto::ExactIpv6 {
                    address: "::ffff:192.0.2.7".into(),
                },
                AddressMatchDto::ExactIpv4 {
                    address: "192.0.2.7".into(),
                },
            ),
            (
                AddressMatchDto::ExactIpv6 {
                    address: "2001:DB8::7".into(),
                },
                AddressMatchDto::ExactIpv6 {
                    address: "2001:db8::7".into(),
                },
            ),
        ];
        for (sent, stored) in pairs {
            assert_eq!(folded(sent.clone()), folded(stored), "{sent:?}");
        }
        // Positive control: different networks stay different.
        assert_ne!(
            folded(range("10.0.0.1", "10.0.0.9")),
            folded(range("10.0.0.1", "10.0.0.8"))
        );
        // A value the validator refuses is not repaired into another one.
        assert_ne!(
            folded(AddressMatchDto::ExactIpv4 {
                address: "010.0.0.1".into()
            }),
            folded(AddressMatchDto::ExactIpv4 {
                address: "10.0.0.1".into()
            })
        );
    }

    #[test]
    fn glob_case_and_suffix_spellings_fold_together() {
        let fold_one = |rule: RuleDto| {
            let mut dto = CanonicalRulesJsonV1 {
                schema_version: RULES_JSON_SCHEMA_VERSION,
                primary: vec![rule],
                secondary: vec![],
            };
            fold_for_comparison(&mut dto);
            to_canonical_string(&dto).expect("canonical")
        };
        let glob = |value: &str| RuleDto {
            id: "r-001".into(),
            enabled: true,
            address_match: None,
            app_match: Some(AppMatchDto {
                pattern: AppPatternDto::Glob {
                    value: value.into(),
                },
                include_child_processes: false,
            }),
            comment: String::new(),
            action: crate::rules_json::RuleAction::Route,
            origin: None,
        };
        assert_eq!(fold_one(glob("DiskO*.exe")), fold_one(glob("disko*.exe")));

        let zone = |name: &str| RuleDto {
            id: "r-002".into(),
            enabled: true,
            address_match: Some(AddressMatchDto::Zone { name: name.into() }),
            app_match: None,
            comment: String::new(),
            action: crate::rules_json::RuleAction::Route,
            origin: None,
        };
        assert_eq!(fold_one(zone("*.RU")), fold_one(zone("ru")));
    }

    /// Folding must not make two different rules look alike.
    #[test]
    fn folding_keeps_genuinely_different_rules_apart() {
        let fold_one = |value: &str| {
            let mut dto = CanonicalRulesJsonV1 {
                schema_version: RULES_JSON_SCHEMA_VERSION,
                primary: vec![sample_exact_fqdn("r-001", value)],
                secondary: vec![],
            };
            fold_for_comparison(&mut dto);
            to_canonical_string(&dto).expect("canonical")
        };
        assert_ne!(fold_one("api.example.com"), fold_one("api.example.org"));
    }

    /// The whole point of ordering before hashing is that arrival order stops
    /// mattering. A key that cannot tell two rules apart hands that decision
    /// back to the stable sort, and the two sides diverge forever over nothing.
    #[test]
    fn the_same_rules_in_a_different_order_fold_to_the_same_bytes() {
        let fold = |rules: Vec<RuleDto>| {
            let mut dto = CanonicalRulesJsonV1 {
                schema_version: RULES_JSON_SCHEMA_VERSION,
                primary: rules,
                secondary: vec![],
            };
            fold_for_comparison(&mut dto);
            to_canonical_string(&dto).expect("canonical")
        };
        // Pairs the key used to collapse: same text, different pattern kind;
        // same process, different child-process flag.
        let glob = RuleDto {
            app_match: Some(AppMatchDto {
                pattern: AppPatternDto::Glob {
                    value: "chrome.exe".into(),
                },
                include_child_processes: false,
            }),
            ..sample_app_rule("r-001", "chrome.exe", false)
        };
        let exact = sample_app_rule("r-002", "chrome.exe", false);
        let with_children = sample_app_rule("r-003", "chrome.exe", true);

        let forward = vec![glob.clone(), exact.clone(), with_children.clone()];
        let reversed = vec![with_children, exact, glob];
        assert_eq!(fold(forward), fold(reversed));
    }

    /// Provenance is not routing: the same host learned on two different days
    /// must not read as a difference between the app and the service.
    #[test]
    fn provenance_does_not_survive_folding() {
        let fold = |origin: Option<RuleOriginDto>| {
            let mut rule = sample_exact_fqdn("r-001", "cdn.example.com");
            rule.origin = origin;
            let mut dto = CanonicalRulesJsonV1 {
                schema_version: RULES_JSON_SCHEMA_VERSION,
                primary: vec![rule],
                secondary: vec![],
            };
            fold_for_comparison(&mut dto);
            to_canonical_string(&dto).expect("canonical")
        };
        use crate::auto_rule::AutoRuleReason;
        let authored = RuleOriginDto::auto(
            AutoRuleReason::SiteCompanion,
            "anchor.example.com",
            "2026-08-30",
        );
        let later = RuleOriginDto::auto(
            AutoRuleReason::SiteCompanion,
            "anchor.example.com",
            "2026-09-01",
        );
        assert_eq!(fold(Some(authored)), fold(Some(later.clone())));
        assert_eq!(fold(None), fold(Some(later)));
    }

    #[test]
    fn a_book_of_the_older_kinds_needs_schema_one_only() {
        assert_eq!(RULES_JSON_SCHEMA_VERSION, 3);
        let mut dto = CanonicalRulesJsonV1 {
            schema_version: 2,
            primary: vec![sample_exact_fqdn("r-1", "api.example.com")],
            secondary: vec![],
        };
        assert_eq!(required_schema_version(&dto), 1);
        dto.primary[0].address_match = Some(AddressMatchDto::Subnet {
            network: "10.0.0.0/8".into(),
        });
        assert_eq!(required_schema_version(&dto), 2);
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
            schema_version: 1,
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
                    address: "192.0.2.4".into(),
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
            schema_version: 1,
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

    /// A note carrying a line break is a second rule once exported; the check
    /// names the rule and the field, and leaves tabs and plain text alone.
    #[test]
    fn a_line_break_in_rule_text_is_found_and_plain_text_is_not() {
        let dto = |rule: RuleDto| CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![sample_exact_fqdn("r-1", "a.test")],
            secondary: vec![rule],
        };
        let injected = RuleDto {
            comment: "note\n--- IP\n192.0.2.9".into(),
            ..sample_exact_fqdn("r-2", "b.test")
        };
        assert_eq!(
            first_forbidden_field_text(&dto(injected)),
            Some(ForbiddenFieldText {
                rule_id: "r-2".into(),
                field: "comment",
            })
        );
        let carriage_return = sample_exact_fqdn("r-3", "c.test\rd.test");
        assert_eq!(
            first_forbidden_field_text(&dto(carriage_return)).map(|hit| hit.field),
            Some("address-match")
        );
        let app = sample_app_rule("r-4", "a\u{0}b.exe", false);
        assert_eq!(
            first_forbidden_field_text(&dto(app)).map(|hit| hit.field),
            Some("app-match")
        );
        let origin = RuleDto {
            origin: Some(RuleOriginDto::auto(
                crate::AutoRuleReason::SiteCompanion,
                "anchor.test\n--- IP",
                "2026-09-01",
            )),
            ..sample_exact_fqdn("r-5", "e.test")
        };
        assert_eq!(
            first_forbidden_field_text(&dto(origin)).map(|hit| hit.field),
            Some("origin")
        );
        let plain = RuleDto {
            comment: "tabbed\tnote, пример".into(),
            ..sample_exact_fqdn("r-6", "f.test")
        };
        assert_eq!(first_forbidden_field_text(&dto(plain)), None);
    }
}

#[cfg(test)]
mod unrecognized_kind_tests {
    use super::*;

    #[test]
    fn an_unknown_kind_round_trips_verbatim() {
        let wire = r#"{"schema-version":2,"primary":[{"id":"r-1","enabled":true,"address-match":{"kind":"port-range","from":80,"to":90}}],"secondary":[]}"#;
        let dto = from_canonical_string(wire).expect("decodes");
        let m = dto.primary[0].address_match.as_ref().expect("match");
        assert!(matches!(m, AddressMatchDto::Unrecognized(_)));
        assert_eq!(m.kind(), "port-range");
        // Keys of an unknown object come back sorted: stable, though not the
        // writer's byte order.
        let again = to_canonical_string(&dto).expect("encodes");
        let reread = from_canonical_string(&again).expect("decodes");
        assert_eq!(reread, dto);
        assert_eq!(to_canonical_string(&reread).expect("encodes"), again);
    }

    #[test]
    fn known_kinds_still_decode_as_themselves() {
        let wire = r#"{"schema-version":2,"primary":[{"id":"r-1","enabled":true,"address-match":{"kind":"subnet","network":"10.0.0.0/8"}},{"id":"r-2","enabled":true,"address-match":{"kind":"ip-range","first":"10.0.0.1","last":"10.0.0.9"}}],"secondary":[]}"#;
        let dto = from_canonical_string(wire).expect("decodes");
        assert_eq!(
            dto.primary[0].address_match,
            Some(AddressMatchDto::Subnet {
                network: "10.0.0.0/8".into()
            })
        );
        assert!(matches!(
            dto.primary[1].address_match,
            Some(AddressMatchDto::IpRange { .. })
        ));
        assert_eq!(to_canonical_string(&dto).expect("encodes"), wire);
    }

    #[test]
    fn an_unknown_action_round_trips_verbatim_and_asks_for_the_newest_schema() {
        let wire = r#"{"schema-version":9,"primary":[{"action":"throttle","address-match":{"kind":"zone","name":"example"},"enabled":true,"id":"r-1"}],"secondary":[]}"#;
        let dto = from_canonical_string(wire).expect("decodes");
        assert_eq!(
            dto.primary[0].action,
            RuleAction::Unrecognized("throttle".into())
        );
        assert!(!dto.primary[0].action.is_malformed());
        assert_eq!(required_schema_version(&dto), 9);
        let again =
            from_canonical_string(&to_canonical_string(&dto).expect("encodes")).expect("decodes");
        assert_eq!(again, dto);
    }

    #[test]
    fn a_kind_or_action_that_is_no_slug_is_a_broken_payload() {
        for address in [
            r#"{}"#,
            r#"{"kind":""}"#,
            r#"{"kind":"Exact FQDN","value":"a"}"#,
        ] {
            let m: AddressMatchDto = serde_json::from_str(address).expect("catch-all");
            assert!(m.is_malformed(), "{address}");
        }
        let newer: AddressMatchDto =
            serde_json::from_str(r#"{"kind":"port-range","from":1}"#).expect("catch-all");
        assert!(!newer.is_malformed());
        for action in ["", "Route", "via primary"] {
            assert!(
                RuleAction::Unrecognized(action.into()).is_malformed(),
                "{action:?}"
            );
        }
    }
}
