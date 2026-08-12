//! Provenance of app-authored rules — the `--- Auto` rules-file section.
//!
//! A rule the application authored on the user's behalf must be visibly
//! distinguishable from a rule the user typed, and must carry a
//! human-readable reason. This module is the **single declaration** of that
//! provenance: the reason slugs, the inline-comment token syntax used in the
//! rules file, and the wire shape carried by
//! [`RuleDto::origin`](crate::rules_json::RuleDto::origin).
//!
//! ## Why one type instead of a wire DTO plus a mirrored domain type
//!
//! Elsewhere in this crate the wire form and the domain form are separate
//! types bridged by a codec (`rules_json::RuleAction` vs
//! `nrr_domain::canonical::RuleAction`). That split earns its keep when the
//! two sides carry different *semantics* — the enforcement layer branches on
//! the action, so the domain owns its own meaning of it.
//!
//! Origin is inert: nothing in the decision engine or the enforcement planner
//! branches on it, it only travels from the file to the GUI. Mirroring it
//! would create three places for the same slug to live (file syntax, wire
//! JSON, locale key) and therefore three ways for them to drift. One
//! declaration, consumed directly by both `nrr-domain` and the wire DTO,
//! removes that drift surface entirely.
//!
//! ## Inline-comment syntax
//!
//! Every entry in the `--- Auto` section carries its provenance as a
//! structured inline comment:
//!
//! ```text
//! rr3---sn-4g5e6nez.googlevideo.com  # auto:site-companion anchor:youtube.com added:
//! ```
//!
//! The three tokens may appear in any order and are followed by optional free
//! text, which becomes the rule's ordinary comment (its GUI label).

use serde::{Deserialize, Serialize};

// ── File-format constants ────────────────────────────────────────────────────

/// Canonical name of the rules-file section holding app-authored rules.
///
/// Technical keyword — never localized, never translated (docs/en/rules-file-format.md Section names are not localized).
pub const AUTO_SECTION_NAME: &str = "Auto";

/// Inline-comment token naming why the rule was authored. Its presence is what
/// marks a line as app-authored.
pub const AUTO_REASON_TOKEN: &str = "auto:";

/// Inline-comment token naming the host the rule was authored for.
pub const AUTO_ANCHOR_TOKEN: &str = "anchor:";

/// Inline-comment token carrying the calendar date the rule was added,
/// `YYYY-MM-DD`.
pub const AUTO_ADDED_TOKEN: &str = "added:";

// ── Reason slugs ─────────────────────────────────────────────────────────────

/// Slug for [`AutoRuleReason::SiteCompanion`].
pub const REASON_SLUG_SITE_COMPANION: &str = "site-companion";

/// Slug for [`AutoRuleReason::VpnClientBootstrap`].
pub const REASON_SLUG_VPN_CLIENT_BOOTSTRAP: &str = "vpn-client-bootstrap";

/// Slug for [`AutoRuleReason::UserConfirmed`].
pub const REASON_SLUG_USER_CONFIRMED: &str = "user-confirmed";

/// Slug for [`AutoRuleReason::BlockNoticeRouted`].
pub const REASON_SLUG_BLOCK_NOTICE_ROUTED: &str = "block-notice-routed";

/// Locale-key prefix for the human-readable reason text.
///
/// The full key is this prefix plus the slug, e.g.
/// `rules.auto-origin.site-companion`. Both `locales/en.json` and
/// `locales/ru.json` carry an entry for each slug below.
pub const REASON_LOCALE_KEY_PREFIX: &str = "rules.auto-origin.";

// ── AutoRuleReason ───────────────────────────────────────────────────────────

/// Why the application authored a rule.
///
/// The slug is the on-disk and on-the-wire identity of the variant; it is also
/// the tail of the locale key that renders the reason to the user. Adding a
/// variant therefore means adding a locale entry in the same change set.
///
/// [`AutoRuleReason::Other`] is the forward-compatibility escape hatch: a file
/// or a payload written by a newer build may carry a slug this build has never
/// heard of, and it must survive a round-trip unchanged rather than being
/// dropped or rejected.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum AutoRuleReason {
    /// A domain a site needs in order to work (media, assets, API hosts).
    SiteCompanion,
    /// Addresses a VPN client needs in order to re-establish its tunnel.
    VpnClientBootstrap,
    /// The user accepted a rule the application suggested.
    UserConfirmed,
    /// The user turned a block notice into a rule, routing the blocked host
    /// over the additional link.
    BlockNoticeRouted,
    /// A slug produced by a newer build, preserved verbatim.
    Other(String),
}

impl AutoRuleReason {
    /// Every reason this build knows by name, in declaration order.
    ///
    /// [`AutoRuleReason::Other`] is deliberately absent — it has no fixed slug.
    pub const KNOWN: [Self; 4] = [
        Self::SiteCompanion,
        Self::VpnClientBootstrap,
        Self::UserConfirmed,
        Self::BlockNoticeRouted,
    ];

    /// The slug written to the rules file and to the canonical JSON.
    pub fn as_slug(&self) -> &str {
        match self {
            Self::SiteCompanion => REASON_SLUG_SITE_COMPANION,
            Self::VpnClientBootstrap => REASON_SLUG_VPN_CLIENT_BOOTSTRAP,
            Self::UserConfirmed => REASON_SLUG_USER_CONFIRMED,
            Self::BlockNoticeRouted => REASON_SLUG_BLOCK_NOTICE_ROUTED,
            Self::Other(slug) => slug.as_str(),
        }
    }

    /// Parses a slug. Never fails — an unrecognised slug becomes
    /// [`AutoRuleReason::Other`] so a file from a newer build round-trips.
    ///
    /// Whitespace is collapsed to `-`: a slug occupies exactly one
    /// whitespace-separated token in the rules file, so a value that could not
    /// be written back is normalised on the way in rather than corrupting the
    /// line on the way out.
    pub fn from_slug(slug: &str) -> Self {
        match slug {
            REASON_SLUG_SITE_COMPANION => Self::SiteCompanion,
            REASON_SLUG_VPN_CLIENT_BOOTSTRAP => Self::VpnClientBootstrap,
            REASON_SLUG_USER_CONFIRMED => Self::UserConfirmed,
            REASON_SLUG_BLOCK_NOTICE_ROUTED => Self::BlockNoticeRouted,
            other => Self::Other(sanitize_token(other)),
        }
    }

    /// `true` when this build knows the variant by name.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Other(_))
    }

    /// Locale key for the user-facing reason text, e.g.
    /// `"rules.auto-origin.site-companion"`.
    ///
    /// Unknown slugs produce a key that is simply absent from the locale files;
    /// the `tr(key, fallback)` fallback then renders whatever the caller passes.
    pub fn locale_key(&self) -> String {
        format!("{REASON_LOCALE_KEY_PREFIX}{}", self.as_slug())
    }
}

impl From<String> for AutoRuleReason {
    fn from(slug: String) -> Self {
        Self::from_slug(&slug)
    }
}

impl From<AutoRuleReason> for String {
    fn from(reason: AutoRuleReason) -> Self {
        match reason {
            AutoRuleReason::Other(slug) => slug,
            known => known.as_slug().to_string(),
        }
    }
}

impl core::fmt::Display for AutoRuleReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_slug())
    }
}

// ── RuleOrigin ───────────────────────────────────────────────────────────────

/// Who authored a rule.
///
/// A rule with no origin (`Option::None` at every call site) is user-authored —
/// that is the overwhelmingly common case, which is why the field is optional
/// and elided from the canonical bytes when absent.
///
/// The enum is tagged rather than a bare struct because authorship is expected
/// to grow further categories (an imported vendor list, an administrator
/// baseline) that carry different payloads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RuleOrigin {
    /// Authored by the application itself, on the user's behalf.
    Auto {
        /// Why the rule was authored.
        reason: AutoRuleReason,
        /// The host the rule was authored for — the site or client whose
        /// behaviour prompted it. Never empty in rules this build authors;
        /// may be empty when read from a file whose provenance comment was
        /// hand-edited.
        anchor: String,
        /// Calendar date the rule was added, `YYYY-MM-DD`.
        added: String,
    },
}

impl RuleOrigin {
    /// Constructs an [`RuleOrigin::Auto`] origin.
    pub fn auto(
        reason: AutoRuleReason,
        anchor: impl Into<String>,
        added: impl Into<String>,
    ) -> Self {
        Self::Auto {
            reason,
            anchor: anchor.into(),
            added: added.into(),
        }
    }

    /// The reason, for every origin kind that has one.
    pub fn reason(&self) -> &AutoRuleReason {
        match self {
            Self::Auto { reason, .. } => reason,
        }
    }

    /// The anchor host.
    pub fn anchor(&self) -> &str {
        match self {
            Self::Auto { anchor, .. } => anchor.as_str(),
        }
    }

    /// The `YYYY-MM-DD` date the rule was added.
    pub fn added(&self) -> &str {
        match self {
            Self::Auto { added, .. } => added.as_str(),
        }
    }

    /// Renders the structured inline comment for a rules-file line, without
    /// the leading `#`.
    ///
    /// Tokens are emitted from the typed fields, never echoed from parsed text,
    /// so a hand-edited file is normalised to canonical token order on export.
    /// Whitespace inside a field is collapsed defensively — a token that could
    /// not be re-parsed would silently break the round-trip invariant.
    pub fn to_provenance_comment(&self) -> String {
        match self {
            Self::Auto {
                reason,
                anchor,
                added,
            } => {
                let mut out = String::with_capacity(64);
                out.push_str(AUTO_REASON_TOKEN);
                out.push_str(&sanitize_token(reason.as_slug()));
                if !anchor.trim().is_empty() {
                    out.push(' ');
                    out.push_str(AUTO_ANCHOR_TOKEN);
                    out.push_str(&sanitize_token(anchor));
                }
                if !added.trim().is_empty() {
                    out.push(' ');
                    out.push_str(AUTO_ADDED_TOKEN);
                    out.push_str(&sanitize_token(added));
                }
                out
            }
        }
    }
}

// ── Provenance comment parsing ───────────────────────────────────────────────

/// Outcome of [`parse_provenance_comment`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceComment {
    /// The typed provenance recovered from the token prefix.
    pub origin: RuleOrigin,
    /// Free text following the tokens — the rule's ordinary comment / GUI
    /// label. `None` when the comment was tokens only.
    pub note: Option<String>,
    /// `false` when the `anchor:` or `added:` token was missing. The origin is
    /// still returned (with the missing field empty) so nothing is lost; the
    /// caller decides whether to warn.
    pub complete: bool,
}

/// Parses the structured provenance prefix of a rules-file inline comment.
///
/// Returns `None` when the comment carries no [`AUTO_REASON_TOKEN`] — such a
/// line is an ordinary rule that happens to live in the `--- Auto` section, and
/// the caller keeps the comment verbatim.
///
/// Tokens may appear in any order; the first token that is not one of the three
/// recognised prefixes ends the structured part and begins the free-text note.
pub fn parse_provenance_comment(comment: &str) -> Option<ProvenanceComment> {
    let mut reason_slug: Option<&str> = None;
    let mut anchor: Option<&str> = None;
    let mut added: Option<&str> = None;

    let mut rest = comment.trim();
    while !rest.is_empty() {
        let token_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let token = &rest[..token_end];
        if let Some(value) = token.strip_prefix(AUTO_REASON_TOKEN) {
            reason_slug = Some(value);
        } else if let Some(value) = token.strip_prefix(AUTO_ANCHOR_TOKEN) {
            anchor = Some(value);
        } else if let Some(value) = token.strip_prefix(AUTO_ADDED_TOKEN) {
            added = Some(value);
        } else {
            break;
        }
        rest = rest[token_end..].trim_start();
    }

    // An `auto:` token with an empty value carries no reason — treat the whole
    // comment as free text rather than inventing an empty `Other("")` slug.
    let reason_slug = reason_slug.filter(|s| !s.is_empty())?;

    let note = if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    };

    Some(ProvenanceComment {
        origin: RuleOrigin::Auto {
            reason: AutoRuleReason::from_slug(reason_slug),
            anchor: anchor.unwrap_or_default().to_string(),
            added: added.unwrap_or_default().to_string(),
        },
        note,
        complete: anchor.is_some() && added.is_some(),
    })
}

/// Collapses internal whitespace so the value occupies exactly one
/// whitespace-separated token in the rules file.
fn sanitize_token(value: &str) -> String {
    let trimmed = value.trim();
    if !trimmed.contains(char::is_whitespace) {
        return trimmed.to_string();
    }
    trimmed.split_whitespace().collect::<Vec<_>>().join("-")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_reason_slugs_are_stable() {
        assert_eq!(AutoRuleReason::SiteCompanion.as_slug(), "site-companion");
        assert_eq!(
            AutoRuleReason::VpnClientBootstrap.as_slug(),
            "vpn-client-bootstrap"
        );
        assert_eq!(AutoRuleReason::UserConfirmed.as_slug(), "user-confirmed");
        assert_eq!(
            AutoRuleReason::BlockNoticeRouted.as_slug(),
            "block-notice-routed"
        );
    }

    #[test]
    fn every_known_reason_round_trips_through_its_slug() {
        for reason in AutoRuleReason::KNOWN {
            let slug = reason.as_slug().to_string();
            assert_eq!(AutoRuleReason::from_slug(&slug), reason);
            assert!(reason.is_known());
        }
    }

    #[test]
    fn unknown_slug_becomes_other_and_survives_round_trip() {
        let reason = AutoRuleReason::from_slug("future-reason");
        assert_eq!(reason, AutoRuleReason::Other("future-reason".to_string()));
        assert!(!reason.is_known());
        assert_eq!(reason.as_slug(), "future-reason");
    }

    #[test]
    fn slug_with_whitespace_is_collapsed_to_one_token() {
        let reason = AutoRuleReason::from_slug("two words");
        assert_eq!(reason.as_slug(), "two-words");
    }

    #[test]
    fn locale_key_is_prefix_plus_slug() {
        assert_eq!(
            AutoRuleReason::SiteCompanion.locale_key(),
            "rules.auto-origin.site-companion"
        );
    }

    #[test]
    fn provenance_comment_renders_all_three_tokens() {
        let origin = RuleOrigin::auto(AutoRuleReason::SiteCompanion, "youtube.com", "2026-07-31");
        assert_eq!(
            origin.to_provenance_comment(),
            "auto:site-companion anchor:youtube.com added:2026-07-31"
        );
    }

    #[test]
    fn provenance_comment_round_trips_without_note() {
        let origin = RuleOrigin::auto(
            AutoRuleReason::VpnClientBootstrap,
            "vpn.example.net",
            "2026-01-02",
        );
        let text = origin.to_provenance_comment();
        let parsed = parse_provenance_comment(&text).expect("provenance");
        assert_eq!(parsed.origin, origin);
        assert_eq!(parsed.note, None);
        assert!(parsed.complete);
    }

    #[test]
    fn provenance_comment_keeps_trailing_free_text_as_note() {
        let parsed = parse_provenance_comment(
            "auto:site-companion anchor:youtube.com added:2026-07-31 video CDN",
        )
        .expect("provenance");
        assert_eq!(parsed.note.as_deref(), Some("video CDN"));
        assert!(parsed.complete);
    }

    #[test]
    fn provenance_tokens_may_appear_in_any_order() {
        let parsed =
            parse_provenance_comment("added:2026-07-31 anchor:youtube.com auto:user-confirmed")
                .expect("provenance");
        assert_eq!(parsed.origin.reason(), &AutoRuleReason::UserConfirmed);
        assert_eq!(parsed.origin.anchor(), "youtube.com");
        assert_eq!(parsed.origin.added(), "2026-07-31");
    }

    #[test]
    fn comment_without_auto_token_is_not_provenance() {
        assert!(parse_provenance_comment("vendor updates").is_none());
        assert!(parse_provenance_comment("anchor:youtube.com").is_none());
        assert!(parse_provenance_comment("").is_none());
        // A bare `auto:` with no slug is free text, not an empty reason.
        assert!(parse_provenance_comment("auto:").is_none());
    }

    #[test]
    fn missing_anchor_or_added_is_reported_incomplete_but_not_dropped() {
        let parsed = parse_provenance_comment("auto:site-companion added:2026-07-31 note")
            .expect("provenance");
        assert!(!parsed.complete);
        assert_eq!(parsed.origin.anchor(), "");
        assert_eq!(parsed.origin.added(), "2026-07-31");
        assert_eq!(parsed.note.as_deref(), Some("note"));
    }

    #[test]
    fn empty_anchor_and_added_are_omitted_from_the_rendered_comment() {
        let origin = RuleOrigin::auto(AutoRuleReason::UserConfirmed, "", "");
        assert_eq!(origin.to_provenance_comment(), "auto:user-confirmed");
        let parsed = parse_provenance_comment(&origin.to_provenance_comment()).expect("provenance");
        assert_eq!(parsed.origin, origin);
        assert!(!parsed.complete);
    }

    #[test]
    fn origin_serialises_with_kebab_case_kind_and_plain_slug() {
        let origin = RuleOrigin::auto(AutoRuleReason::SiteCompanion, "youtube.com", "2026-07-31");
        let json = serde_json::to_string(&origin).expect("serialize");
        assert_eq!(
            json,
            r#"{"kind":"auto","reason":"site-companion","anchor":"youtube.com","added":"2026-07-31"}"#
        );
        let back: RuleOrigin = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, origin);
    }

    #[test]
    fn unknown_reason_slug_survives_the_json_round_trip() {
        let json =
            r#"{"kind":"auto","reason":"from-the-future","anchor":"x.test","added":"2030-01-01"}"#;
        let origin: RuleOrigin = serde_json::from_str(json).expect("deserialize");
        assert_eq!(
            origin.reason(),
            &AutoRuleReason::Other("from-the-future".to_string())
        );
        assert_eq!(serde_json::to_string(&origin).expect("serialize"), json);
    }
}
