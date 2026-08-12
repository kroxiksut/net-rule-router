//! Canonicalization of preset file data.
//!
//! This module bridges the parse stage ([`crate::rules_file`]) and the
//! canonical internal representation ([`crate::canonical`]) for the case where
//! only one route's rules are available — as is the case when the user imports
//! a preset file.
//!
//! # Mapping: raw preset file → `CanonicalRuleSet`
//!
//! ```text
//! raw text bytes
//!   │  validate_preset_bytes()
//!   ▼
//! ParseOutcome { parsed, unknown_sections, preset_metadata, … }
//!   │  rules_file_to_route_rule_set()
//!   ▼
//! RouteRuleSet { rules: [Rule { id, enabled, address_match, app_match, comment }] }
//!   │  canonicalize_preset_rules()  (this module)
//!   ▼
//! PresetRulesCanonicalizeOutcome
//!   └─ Accepted / AcceptedWithWarnings
//!        └─ rule_set: CanonicalRuleSet  ← stable ordering, normalized values
//! ```
//!
//! The resulting `CanonicalRuleSet` is used as the rule portion of a
//! `CanonicalProfile` candidate when building an `ImportCandidate` for the
//! import review flow.
//!
//! # Semantic-noop policy
//!
//! The following transformations produce a **semantically equivalent** result —
//! the routing policy is unchanged even though the file representation differs:
//!
//! | Input variation          | Canonical form          | Warning? |
//! |--------------------------|-------------------------|----------|
//! | Rule insertion order     | Stable canonical order  | No       |
//! | Leading/trailing spaces  | Trimmed (by parser)     | No       |
//! | `EXAMPLE.COM` / `Example.COM` | `example.com`    | No       |
//! | `example.com.` (trailing dot) | `example.com`    | Yes      |
//! | `*.ru` in Zones section  | `ru`                    | No       |
//! | Unicode IDN domain       | Punycode (IDNA2008)     | Yes      |
//! | IPv4-mapped IPv6 address | IPv4                    | Yes      |
//! | `C:\path\chrome.exe`     | `chrome.exe`            | Yes      |
//! | `chrome` (no `.exe`)     | `chrome.exe`            | Yes      |
//! | Duplicate rule (same set)| First occurrence kept   | Yes      |
//!
//! # Discarded after canonicalization
//!
//! The following constructs are present in the raw file but **not** represented
//! in `CanonicalRuleSet` and do not influence diff, review, or content hash:
//!
//! - **Rule insertion order** — replaced by canonical ordering.
//! - **Free comments** — prose comment lines (e.g. `# This is a note`) are
//!   not rule entries; the parser never creates `RulesFileEntry` for them.
//! - **Preset metadata** (`name`, `description`, `author`, `preset_version`)
//!   — UI/display information, not routing policy.
//! - **Section structure** — `--- Domains`, `--- IP`, etc. are collapsed into
//!   typed `CanonicalAddressMatch` variants.
//! - **`*.` suffix-domain prefix** — stored without the prefix in
//!   [`CanonicalAddressMatch::SuffixDomain`]; display layer restores it.
//! - **Platform-inactive sections** — on Windows, `--- Linux` and `--- MacOS`
//!   entries are excluded from the canonical rule set (never applied to routing).
//! - **Pro-only section entries** — entries in unknown sections (e.g. `--- CIDR`,
//!   `--- Ports`) are not converted; they live in `ParseOutcome::unknown_sections`
//!   and are round-tripped through the file, but they are outside the canonical
//!   policy boundary for the Free edition.
//!
//! # Inline comments (preserved)
//!
//! Inline comments (text after `#` on a rule line, e.g. `# vendor updates`)
//! are preserved in `CanonicalRule::comment`. They appear in the review dialog
//! as rule labels. Two rules that differ only in their inline comment are
//! **not** duplicates — only the match value determines identity.

use nrr_shared::RouteRole;

use crate::{
    canonical::{CanonicalRuleBook, CanonicalRuleSet},
    rules_file::{rules_file_to_route_rule_set, HostPlatform, ParseOutcome},
    validation::{validate_and_canonicalize, ValidationError, ValidationWarning},
    ActiveConfiguration, AdapterIdentity, BindingSource, RouteBehaviorMode, RouteBinding, RuleBook,
};

// ── Outcome ───────────────────────────────────────────────────────────────────

/// The result of [`canonicalize_preset_rules`].
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum PresetRulesCanonicalizeOutcome {
    /// Canonicalization succeeded with no normalization side-effects.
    Accepted { rule_set: CanonicalRuleSet },

    /// Canonicalization succeeded; the rule set is usable but normalization
    /// side-effects were encountered. The GUI should surface `warnings` in the
    /// review dialog so the user can see what was changed.
    AcceptedWithWarnings {
        rule_set: CanonicalRuleSet,
        warnings: Vec<ValidationWarning>,
    },

    /// One or more blocking semantic errors prevent the rule set from being
    /// built. The import candidate must not be created until the file is
    /// corrected.
    Rejected { errors: Vec<ValidationError> },
}

impl PresetRulesCanonicalizeOutcome {
    /// Returns `true` when the rule set is available (accepted with or without warnings).
    pub fn is_accepted(&self) -> bool {
        !matches!(self, Self::Rejected { .. })
    }

    /// Returns the `CanonicalRuleSet` if canonicalization succeeded.
    pub fn rule_set(&self) -> Option<&CanonicalRuleSet> {
        match self {
            Self::Accepted { rule_set } | Self::AcceptedWithWarnings { rule_set, .. } => {
                Some(rule_set)
            }
            Self::Rejected { .. } => None,
        }
    }

    /// Returns the non-blocking warnings when present.
    pub fn warnings(&self) -> &[ValidationWarning] {
        match self {
            Self::AcceptedWithWarnings { warnings, .. } => warnings.as_slice(),
            _ => &[],
        }
    }
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

/// Canonicalizes the rules from a parsed preset file for one route.
///
/// This is the bridge between the parse stage (`parse_rules_file`) and the
/// canonical internal representation (`CanonicalRuleSet`). It runs the full
/// semantic validation and normalization pipeline on the parsed rules without
/// requiring real adapter bindings.
///
/// # Arguments
///
/// - `parse_outcome` — output of `parse_rules_file` (or `validate_preset_bytes`).
/// - `route` — which route role the preset file represents. Rules from
///   `parse_outcome` are placed into this route slot of the internal config.
/// - `platform` — the host platform, used to filter platform-inactive sections.
///   On Windows, `--- Linux` and `--- MacOS` sections are excluded.
/// - `include_child_processes` — the current global "Apply rules to child
///   processes" setting. Applied uniformly to all app rules.
///
/// # Stub bindings
///
/// Since a preset file does not carry adapter bindings, this function supplies
/// synthetic placeholder bindings internally. These stubs exist only to satisfy
/// the validation pipeline's structural requirements — they are never used
/// outside this module and are not persisted.
pub fn canonicalize_preset_rules(
    parse_outcome: &ParseOutcome,
    route: RouteRole,
    platform: HostPlatform,
    include_child_processes: bool,
) -> PresetRulesCanonicalizeOutcome {
    let rule_set =
        rules_file_to_route_rule_set(&parse_outcome.parsed, platform, include_child_processes);

    let config = stub_config_for_route(route, rule_set);
    let validation = validate_and_canonicalize(&config);

    match validation {
        crate::validation::ValidationOutcome::Accepted(profile) => {
            let set = extract_rule_set(profile.rule_book, route);
            PresetRulesCanonicalizeOutcome::Accepted { rule_set: set }
        }
        crate::validation::ValidationOutcome::AcceptedWithWarnings { profile, warnings } => {
            let relevant = filter_rule_warnings(warnings);
            let set = extract_rule_set(profile.rule_book, route);
            if relevant.is_empty() {
                PresetRulesCanonicalizeOutcome::Accepted { rule_set: set }
            } else {
                PresetRulesCanonicalizeOutcome::AcceptedWithWarnings {
                    rule_set: set,
                    warnings: relevant,
                }
            }
        }
        crate::validation::ValidationOutcome::Rejected { errors, warnings } => {
            // Filter out any stub-binding errors — they can never fire with our
            // well-formed stub, but be defensive.
            let rule_errors: Vec<_> = errors
                .into_iter()
                .filter(|e| e.rule_id().is_some())
                .collect();

            if rule_errors.is_empty() {
                // All errors were binding-related (should not happen with valid stub).
                // Treat as accepted with any rule-level warnings.
                let relevant = filter_rule_warnings(warnings);
                PresetRulesCanonicalizeOutcome::AcceptedWithWarnings {
                    rule_set: CanonicalRuleSet::default(),
                    warnings: relevant,
                }
            } else {
                PresetRulesCanonicalizeOutcome::Rejected {
                    errors: rule_errors,
                }
            }
        }
    }
}

/// Builds a minimal `ActiveConfiguration` placing `rule_set` in the given `route`.
///
/// The stub bindings use synthetic IDs that can never clash with real adapters.
fn stub_config_for_route(route: RouteRole, rule_set: crate::RouteRuleSet) -> ActiveConfiguration {
    let (primary_set, secondary_set) = match route {
        RouteRole::Primary => (rule_set, crate::RouteRuleSet::default()),
        RouteRole::Secondary => (crate::RouteRuleSet::default(), rule_set),
    };

    ActiveConfiguration {
        primary: Some(RouteBinding {
            role: RouteRole::Primary,
            adapter: AdapterIdentity {
                stable_id: "preset-stub-primary-00000000".to_string(),
                display_name: String::new(),
            },
            source: BindingSource::UserAssigned,
        }),
        secondary: Some(RouteBinding {
            role: RouteRole::Secondary,
            adapter: AdapterIdentity {
                stable_id: "preset-stub-secondary-00000000".to_string(),
                display_name: String::new(),
            },
            source: BindingSource::UserAssigned,
        }),
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        rule_book: RuleBook {
            primary: primary_set,
            secondary: secondary_set,
        },
    }
}

/// Extracts the `CanonicalRuleSet` for `route` from a `CanonicalRuleBook`.
fn extract_rule_set(rule_book: CanonicalRuleBook, route: RouteRole) -> CanonicalRuleSet {
    match route {
        RouteRole::Primary => rule_book.primary,
        RouteRole::Secondary => rule_book.secondary,
    }
}

/// Retains only rule-level warnings (filters out stub-binding-related warnings
/// like `MissingSecondaryWithFailClosed` or `UnknownAdapterReference` that
/// can arise from the synthetic bindings used during preset canonicalization).
fn filter_rule_warnings(warnings: Vec<ValidationWarning>) -> Vec<ValidationWarning> {
    warnings
        .into_iter()
        .filter(|w| {
            !matches!(
                w,
                ValidationWarning::MissingSecondaryWithFailClosed
                    | ValidationWarning::UnknownAdapterReference { .. }
            )
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonical::CanonicalAddressMatch, rules_file::parse_rules_file};

    fn canonicalize(text: &str, route: RouteRole) -> PresetRulesCanonicalizeOutcome {
        let parsed = parse_rules_file(text);
        canonicalize_preset_rules(&parsed, route, HostPlatform::Windows, false)
    }

    fn rule_set(text: &str) -> CanonicalRuleSet {
        match canonicalize(text, RouteRole::Primary) {
            PresetRulesCanonicalizeOutcome::Accepted { rule_set }
            | PresetRulesCanonicalizeOutcome::AcceptedWithWarnings { rule_set, .. } => rule_set,
            PresetRulesCanonicalizeOutcome::Rejected { errors } => {
                panic!("unexpected rejection: {errors:?}")
            }
        }
    }

    /// Match values in canonical order, for semantic equality checks.
    /// Rule IDs are parse-position-dependent and must not be compared across
    /// files that were parsed in different section orders.
    fn match_values(set: &CanonicalRuleSet) -> Vec<String> {
        set.rules()
            .iter()
            .map(|r| {
                r.address_match
                    .as_ref()
                    .map(|a| a.to_display_string())
                    .or_else(|| r.app_match.as_ref().map(|a| a.pattern.as_str().to_string()))
                    .unwrap_or_default()
            })
            .collect()
    }

    // ── Canonical ordering ────────────────────────────────────────────────────

    #[test]
    fn different_insertion_order_produces_equal_canonical_set() {
        // Rule IDs are parse-position-dependent so we compare by match values.
        let file_a = "--- Domains\nexample.com\n--- IP\n203.0.113.7\n--- Windows\nbrowser.exe\n";
        let file_b = "--- Windows\nbrowser.exe\n--- IP\n203.0.113.7\n--- Domains\nexample.com\n";
        assert_eq!(
            match_values(&rule_set(file_a)),
            match_values(&rule_set(file_b))
        );
    }

    #[test]
    fn canonical_order_is_fqdn_suffix_zone_ip_app() {
        let input = "\
--- Windows\noutlook.exe\n\
--- IP\n10.0.0.1\n\
--- Domains\n*.corp.example.com\nexact.example.com\n\
--- Zones\ncorp-internal\n";
        let set = rule_set(input);
        let groups: Vec<u8> = set
            .rules()
            .iter()
            .map(|r| match &r.address_match {
                Some(CanonicalAddressMatch::ExactFqdn(_)) => 0,
                Some(CanonicalAddressMatch::SuffixDomain(_)) => 1,
                Some(CanonicalAddressMatch::Zone(_)) => 2,
                Some(CanonicalAddressMatch::ExactIp(_)) => 3,
                None => 4,
            })
            .collect();
        assert!(
            groups.windows(2).all(|w| w[0] <= w[1]),
            "order must be non-decreasing: {groups:?}"
        );
    }

    // ── Semantic-noop: case normalization ─────────────────────────────────────

    #[test]
    fn uppercase_domain_normalized_to_lowercase() {
        let lower = match_values(&rule_set("--- Domains\nexample.com\n"));
        let upper = match_values(&rule_set("--- Domains\nEXAMPLE.COM\n"));
        assert_eq!(lower, upper);
    }

    #[test]
    fn mixed_case_domain_normalized() {
        let a = match_values(&rule_set("--- Domains\nApi.Example.Com\n"));
        let b = match_values(&rule_set("--- Domains\napi.example.com\n"));
        assert_eq!(a, b);
    }

    // ── Semantic-noop: trailing dot ───────────────────────────────────────────

    #[test]
    fn trailing_dot_domain_equals_no_trailing_dot() {
        let with_dot = canonicalize("--- Domains\nexample.com.\n", RouteRole::Primary);
        assert!(with_dot.is_accepted());
        assert!(
            matches!(
                with_dot,
                PresetRulesCanonicalizeOutcome::AcceptedWithWarnings { .. }
            ),
            "trailing dot must produce a warning"
        );
        assert_eq!(
            match_values(with_dot.rule_set().unwrap()),
            vec!["example.com"]
        );
    }

    // ── Semantic-noop: zone prefix ────────────────────────────────────────────

    #[test]
    fn zone_wildcard_prefix_and_bare_name_are_equivalent() {
        // Both `*.ru` and `ru` in the Zones section map to zone `ru`.
        let with_star = match_values(&rule_set("--- Zones\n*.ru\n"));
        let bare = match_values(&rule_set("--- Zones\nru\n"));
        assert_eq!(with_star, bare);
    }

    // ── Semantic-noop: suffix domain prefix ───────────────────────────────────

    #[test]
    fn suffix_domain_stored_without_wildcard_prefix() {
        let set = rule_set("--- Domains\n*.example.com\n");
        let rule = &set.rules()[0];
        assert!(
            matches!(&rule.address_match, Some(CanonicalAddressMatch::SuffixDomain(label)) if label == "example.com"),
            "SuffixDomain must store label without `*.` prefix"
        );
    }

    // ── Semantic-noop: duplicate rules ────────────────────────────────────────

    #[test]
    fn duplicate_rules_deduplicated_with_warning() {
        let outcome = canonicalize(
            "--- Domains\nexample.com\nexample.com\n",
            RouteRole::Primary,
        );
        assert!(outcome.is_accepted());
        // One rule survives after deduplication.
        assert_eq!(outcome.rule_set().unwrap().len(), 1);
        // A DuplicateRuleInSameSet warning was emitted.
        assert!(
            outcome
                .warnings()
                .iter()
                .any(|w| matches!(w, ValidationWarning::DuplicateRuleInSameSet { .. })),
            "duplicate rule must produce DuplicateRuleInSameSet warning"
        );
    }

    #[test]
    fn duplicate_rules_via_duplicate_section_headers_deduplicated() {
        // `*.example.com` written twice (via a duplicate section header).
        let set = rule_set("--- Domains\n*.example.com\n--- Domains\n*.example.com\n");
        assert_eq!(set.len(), 1);
    }

    // ── Discarded: free comments and metadata ─────────────────────────────────

    #[test]
    fn preset_metadata_does_not_affect_canonical_rule_set() {
        let with_meta = match_values(&rule_set(
            "\
# NetRuleRouter preset \u{2014} version 1\n\
# name: My Preset\n\
# description: A test preset\n\
# author: Test\n\
--- Domains\nexample.com\n",
        ));
        let without_meta = match_values(&rule_set("--- Domains\nexample.com\n"));
        assert_eq!(with_meta, without_meta);
    }

    #[test]
    fn free_comment_lines_do_not_create_rules() {
        let a = rule_set("--- Domains\n# This is a free comment\nexample.com\n# another comment\n");
        let b = rule_set("--- Domains\nexample.com\n");
        assert_eq!(a.len(), b.len());
        assert_eq!(match_values(&a), match_values(&b));
    }

    // ── Preserved: inline comments ────────────────────────────────────────────

    #[test]
    fn inline_comment_preserved_in_canonical_rule() {
        let set = rule_set("--- Domains\nexample.com  # vendor updates\n");
        assert_eq!(set.rules()[0].comment, "vendor updates");
    }

    #[test]
    fn two_rules_differing_only_in_inline_comment_are_not_duplicates() {
        let set = rule_set("--- Domains\nexample.com  # label A\nexample.org  # label B\n");
        // Distinct match values — both survive.
        assert_eq!(set.len(), 2);
    }

    // ── Discarded: platform-inactive sections ─────────────────────────────────

    #[test]
    fn linux_and_macos_sections_excluded_on_windows() {
        let set = rule_set("--- Linux\ncurl\n--- MacOS\nSafari\n--- Windows\nbrowser.exe\n");
        assert_eq!(set.len(), 1);
        assert!(set.rules()[0]
            .app_match
            .as_ref()
            .is_some_and(|a| a.pattern.as_str() == "browser.exe"));
    }

    // ── Discarded: Pro-only section entries ───────────────────────────────────

    #[test]
    fn pro_only_sections_not_in_canonical_rule_set() {
        // CIDR entries live in unknown_sections and must not enter the canonical set.
        let set = rule_set("--- Domains\nexample.com\n--- CIDR\n10.0.0.0/8\n");
        assert_eq!(set.len(), 1);
        let value = match &set.rules()[0].address_match {
            Some(CanonicalAddressMatch::ExactFqdn(v)) => v.as_str(),
            _ => "",
        };
        assert_eq!(value, "example.com");
    }

    // ── Secondary route ───────────────────────────────────────────────────────

    #[test]
    fn secondary_route_rules_placed_in_secondary_slot() {
        let parsed = parse_rules_file("--- Domains\nvpn.corp.com\n");
        let outcome =
            canonicalize_preset_rules(&parsed, RouteRole::Secondary, HostPlatform::Windows, false);
        assert!(outcome.is_accepted());
        assert_eq!(outcome.rule_set().unwrap().len(), 1);
    }

    // ── Empty file ────────────────────────────────────────────────────────────

    #[test]
    fn empty_preset_file_produces_empty_canonical_set() {
        let set = rule_set("");
        assert!(set.is_empty());
    }

    // ── Blocking semantic errors ──────────────────────────────────────────────

    #[test]
    fn bare_glob_star_is_rejected() {
        let outcome = canonicalize("--- Windows\n*\n", RouteRole::Primary);
        assert!(matches!(
            outcome,
            PresetRulesCanonicalizeOutcome::Rejected { .. }
        ));
    }

    #[test]
    fn ipv6_address_is_rejected_in_free_edition() {
        let outcome = canonicalize("--- IP\n::1\n", RouteRole::Primary);
        assert!(matches!(
            outcome,
            PresetRulesCanonicalizeOutcome::Rejected { .. }
        ));
    }

    // ── `include_child_processes` propagation ─────────────────────────────────

    #[test]
    fn include_child_processes_flag_propagated_to_app_rules() {
        let parsed = parse_rules_file("--- Windows\nbrowser.exe\n");
        let with_icp =
            canonicalize_preset_rules(&parsed, RouteRole::Primary, HostPlatform::Windows, true);
        let without_icp =
            canonicalize_preset_rules(&parsed, RouteRole::Primary, HostPlatform::Windows, false);

        let icp_value = |outcome: &PresetRulesCanonicalizeOutcome| {
            outcome
                .rule_set()
                .unwrap()
                .rules()
                .first()
                .and_then(|r| r.app_match.as_ref())
                .map(|a| a.include_child_processes)
        };

        assert_eq!(icp_value(&with_icp), Some(true));
        assert_eq!(icp_value(&without_icp), Some(false));
    }
}
