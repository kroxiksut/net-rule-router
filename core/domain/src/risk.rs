//! Risk scoring for candidate policy revisions.
//!
//! Risk scoring is pure domain logic: no I/O, no OS API, no side effects.
//! The service layer calls these same functions.
//!
//! # Data flow
//!
//! `compute_diff(prev, candidate)` → `StructuralDiff`
//! → `score_candidate(diff, source)` → `RiskAssessment`
//! → stored in `PolicyRevision::risk_level`
//! → used to decide: mandatory review, persistent alert, block silent activation.
//!
//! # Signal catalogue and thresholds
//!
//! | Signal                   | Condition                                                       | Level    |
//! |--------------------------|-----------------------------------------------------------------|----------|
//! | `BroadSuffixScope`       | SuffixDomain on TLD or ccTLD (`*.com`, `*.ru`)                  | High     |
//! | `ModerateSuffixScope`    | SuffixDomain on 2nd-level (`*.example.com`)                     | Medium   |
//! | `DefaultBehaviorChanged` | `behavior_mode` changed between revisions                       | Medium   |
//! | `MassChangeCount`        | ≥ 20 rule changes across both sets                              | High     |
//! | `SecondaryReroute`       | ≥ 1 rule added or retargeted to secondary                       | Medium   |
//! | `UnstableInterfaceBinding`| Adapter binding changed                                        | High     |
//! | `UnknownSource`          | Reserved; cannot occur with current types                       | Medium   |
//! | `LinkedSuspiciousDelta`  | Reserved; requires linked import support                        | High     |
//! | `RuleSetEmptied`         | Prev had rules, next has zero                                   | High     |
//! | `HighRemovalRatio`       | ≥ 50 % of prev rules removed in this revision                   | High     |
//! | `OverlappingRules`       | ExactFqdn `host.apex` + SuffixDomain `apex` in same set          | Medium   |
//! | `FailClosedActivation`   | `behavior_mode` newly set to `StrictSecondaryFailClosed`        | High     |
//!
//! # Threshold rationale
//!
//! - **`MassChangeCount` ≥ 20**: In the Free edition the rule set is small
//!   (≤ 50 rules typical). Twenty simultaneous changes is already a significant
//!   structural shift — enough to require mandatory review.
//! - **`BroadSuffixScope` on TLD**: Routing all traffic matching `*.com` or
//!   `*.ru` is almost certainly unintentional or malicious. No legitimate use
//!   case in the Free edition routes entire TLDs to secondary.
//! - **`UnstableInterfaceBinding`**: Adapter identity changes can silently
//!   redirect all traffic. The user must confirm the new binding is intentional.
//! - **`RuleSetEmptied`**: Going from non-empty rules → empty in one step
//!   removes all per-rule routing decisions. Under `PreferPrimary` mode the
//!   user just falls back to the OS default route (recoverable); under
//!   `StrictSecondaryFailClosed` it disables all traffic until the user
//!   restores rules.
//! - **`HighRemovalRatio` ≥ 50 %**: Distinct from `RuleSetEmptied` —
//!   removing half-or-more of an active rule set is rarely intentional in
//!   the Free edition (typical edit is "add one rule" or "modify one
//!   rule"). Catches accidental bulk-delete in the GUI.
//! - **`OverlappingRules`**: When `api.example.com` (ExactFqdn) and
//!   `example.com` (SuffixDomain) coexist in the same route set, the
//!   ExactFqdn rule technically wins at decision time (tier 1 vs tier 2),
//!   but the user may not realise they've created a redundant entry — or
//!   worse, the two rules sit in DIFFERENT route sets (primary vs secondary)
//!   and produce surprising routing.
//! - **`FailClosedActivation`**: Turning on `StrictSecondaryFailClosed`
//!   changes the default behaviour from "permit unmatched" to "block
//!   unmatched". Important enough to flag even when the rules diff is
//!   trivial.

use crate::{
    canonical::CanonicalAddressMatch,
    review::{RuleChange, StructuralDiff},
    revision::{RevisionSource, RiskLevel},
    RouteBehaviorMode, RouteRole,
};

/// Minimum number of rule changes that triggers [`RiskSignal::MassChangeCount`].
pub const MASS_CHANGE_THRESHOLD: u32 = 20;

/// Removal-ratio (% of previous rules removed) at or above which
/// [`RiskSignal::HighRemovalRatio`] fires. 50 % is the design value —
/// anything from the "I deleted half my rules by accident" bracket and worse.
pub const HIGH_REMOVAL_RATIO_THRESHOLD_PCT: u8 = 50;

// ── RiskSignal ────────────────────────────────────────────────────────────────

/// A single reason contributing to a [`RiskAssessment`].
///
/// Multiple signals can be present simultaneously. The final risk level is the
/// maximum of all individual signal levels.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RiskSignal {
    /// A `SuffixDomain` rule was added that matches a top-level domain or
    /// country-code TLD (e.g., `*.com`, `*.ru`, `*.net`). The `label` field
    /// is the raw stored label without `*.` (e.g., `"com"`, `"ru"`).
    ///
    /// Level: **High** — routing an entire TLD to secondary is almost always
    /// unintentional. Mandatory review required.
    BroadSuffixScope { label: String },

    /// A `SuffixDomain` rule was added that matches a second-level domain
    /// (e.g., `*.example.com`). The `label` field includes the apex domain.
    ///
    /// Level: **Medium** — broader than an exact FQDN but less extreme than a TLD.
    ModerateSuffixScope { label: String },

    /// The default routing behavior mode changed between the previous active
    /// revision and the candidate. Any behavior change requires review.
    ///
    /// Level: **Medium**.
    DefaultBehaviorChanged,

    /// The total number of rule changes (Added + Removed + Modified + Retargeted)
    /// is at or above [`MASS_CHANGE_THRESHOLD`].
    ///
    /// Level: **High** — large structural changes need explicit user confirmation.
    MassChangeCount { count: u32 },

    /// At least one rule was added or retargeted to the secondary route. Routing
    /// previously-primary traffic to secondary can redirect sensitive connections.
    ///
    /// Level: **Medium**. `rule_count` is the number of such rules.
    SecondaryReroute { rule_count: u32 },

    /// At least one network adapter binding (primary or secondary) changed.
    /// An unexpected binding change can silently redirect all unmatched traffic.
    ///
    /// Level: **High**.
    UnstableInterfaceBinding,

    /// The revision source cannot be verified. Reserved for future use — with the
    /// current strongly-typed [`RevisionSource`] this signal is never produced.
    ///
    /// Level: **Medium**.
    UnknownSource,

    /// A linked-import update showed a suspiciously large diff compared to previous
    /// check cycles. Reserved; requires linked import support.
    ///
    /// Level: **High**.
    LinkedSuspiciousDelta,

    /// Fires when the previous active revision had non-zero
    /// rules and the candidate has zero. Catches "I just deleted all
    /// my rules" in a single review pass.
    ///
    /// Level: **High**.
    RuleSetEmptied {
        /// How many rules the previous revision carried (informational
        /// — surfaces in the review UI so the user sees "you are about
        /// to delete N rules").
        prev_total: u32,
    },

    /// Fires when at least
    /// [`HIGH_REMOVAL_RATIO_THRESHOLD_PCT`] % of the previous revision's
    /// rules are being removed by this candidate. Distinct from
    /// [`RuleSetEmptied`](RiskSignal::RuleSetEmptied), which is the
    /// 100 % case. `removed_pct` is the actual percentage rounded down.
    ///
    /// Level: **High**.
    HighRemovalRatio { removed_pct: u8 },

    /// Fires when the candidate contains an `ExactFqdn` rule
    /// and a `SuffixDomain` rule whose suffix is the apex of the
    /// ExactFqdn. Example: `api.example.com` (ExactFqdn) and
    /// `example.com` (SuffixDomain) both present. The ExactFqdn
    /// technically wins at decision time, but the redundancy hints at
    /// a user authoring mistake — or if the two rules sit in different
    /// route sets the routing is surprising.
    ///
    /// Level: **Medium**. `apex` is the suffix label without the `*.`
    /// prefix (e.g. `"example.com"`).
    OverlappingRules { apex: String },

    /// Fires when `behavior_mode` is being set to
    /// `StrictSecondaryFailClosed` in this revision and was not in the
    /// previous one (or there was no previous revision). The mode
    /// change flips the default behaviour from "permit unmatched" to
    /// "block unmatched"; even a trivial-looking rules diff deserves
    /// review when fail-closed is activated.
    ///
    /// Level: **High**.
    FailClosedActivation,
}

// Cross-crate projection: domain `RiskSignal` → wire
// `nrr_shared::ipc_payloads::RiskSignalDto`. Lives in domain because
// the dep direction is `domain → shared`; service-runtime calls
// `Into::into` on each signal when assembling
// `ReviewSummaryResponse.risk_signals`. The mapping is 1:1 today —
// all 12 wire variants have domain counterparts.
impl From<&RiskSignal> for nrr_shared::ipc_payloads::RiskSignalDto {
    fn from(s: &RiskSignal) -> Self {
        use nrr_shared::ipc_payloads::RiskSignalDto as W;
        match s {
            RiskSignal::BroadSuffixScope { label } => W::BroadSuffixScope {
                label: label.clone(),
            },
            RiskSignal::ModerateSuffixScope { label } => W::ModerateSuffixScope {
                label: label.clone(),
            },
            RiskSignal::DefaultBehaviorChanged => W::DefaultBehaviorChanged,
            RiskSignal::MassChangeCount { count } => W::MassChangeCount { count: *count },
            RiskSignal::SecondaryReroute { rule_count } => W::SecondaryReroute {
                rule_count: *rule_count,
            },
            RiskSignal::UnstableInterfaceBinding => W::UnstableInterfaceBinding,
            RiskSignal::UnknownSource => W::UnknownSource,
            RiskSignal::LinkedSuspiciousDelta => W::LinkedSuspiciousDelta,
            RiskSignal::RuleSetEmptied { prev_total } => W::RuleSetEmptied {
                prev_total: *prev_total,
            },
            RiskSignal::HighRemovalRatio { removed_pct } => W::HighRemovalRatio {
                removed_pct: *removed_pct,
            },
            RiskSignal::OverlappingRules { apex } => W::OverlappingRules { apex: apex.clone() },
            RiskSignal::FailClosedActivation => W::FailClosedActivation,
        }
    }
}

impl RiskSignal {
    /// Returns the [`RiskLevel`] this signal contributes to the overall assessment.
    pub fn level(&self) -> RiskLevel {
        match self {
            Self::BroadSuffixScope { .. }
            | Self::MassChangeCount { .. }
            | Self::UnstableInterfaceBinding
            | Self::LinkedSuspiciousDelta
            | Self::RuleSetEmptied { .. }
            | Self::HighRemovalRatio { .. }
            | Self::FailClosedActivation => RiskLevel::High,

            Self::ModerateSuffixScope { .. }
            | Self::DefaultBehaviorChanged
            | Self::SecondaryReroute { .. }
            | Self::OverlappingRules { .. }
            | Self::UnknownSource => RiskLevel::Medium,
        }
    }
}

// ── RiskAssessment ────────────────────────────────────────────────────────────

/// The risk classification assigned to a candidate revision before review.
///
/// `level` is the overall verdict (maximum of all signal levels). `signals`
/// lists every contributing reason so the review UI and audit log can show
/// specific explanations rather than just a bare risk number.
///
/// An empty `signals` vec always corresponds to [`RiskLevel::Low`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiskAssessment {
    /// Overall risk level: the highest level across all signals, or `Low`
    /// when no signals are present.
    pub level: RiskLevel,
    /// All contributing signals, in the order they were detected.
    pub signals: Vec<RiskSignal>,
}

impl RiskAssessment {
    /// Returns `true` when no risk signals were detected (level is `Low`).
    pub fn is_low_risk(&self) -> bool {
        self.signals.is_empty()
    }

    /// Returns `true` when the level is `High`.
    ///
    /// High-risk candidates require mandatory user review and a persistent alert.
    /// Silent activation must be blocked.
    pub fn requires_mandatory_review(&self) -> bool {
        self.level == RiskLevel::High
    }
}

// ── score_candidate ───────────────────────────────────────────────────────────

/// Scores the risk of a candidate revision given its structural diff and source.
///
/// Collects [`RiskSignal`]s from three categories:
/// 1. **Content signals** — derived from `diff`: suffix scope, mass change count,
///    secondary reroute, behavior mode change, interface binding change.
/// 2. **Source signals** — derived from `source`: `UnknownSource` is reserved for
///    future use; with current strongly-typed sources it is never produced.
/// 3. **Linked-delta signals** — `LinkedSuspiciousDelta` is reserved for
///    linked import support and is never produced by this function in the current scope.
///
/// The final [`RiskLevel`] is the maximum of all individual signal levels, or
/// [`RiskLevel::Low`] when no signals are present.
pub fn score_candidate(diff: &StructuralDiff, source: &RevisionSource) -> RiskAssessment {
    let mut signals: Vec<RiskSignal> = Vec::new();

    collect_content_signals(diff, &mut signals);
    collect_block_16_12_signals(diff, &mut signals);
    collect_source_signals(source, &mut signals);

    let level = signals
        .iter()
        .map(RiskSignal::level)
        .max()
        .unwrap_or(RiskLevel::Low);

    RiskAssessment { level, signals }
}

/// Detects `FailClosedActivation`, `RuleSetEmptied`, `HighRemovalRatio`,
/// and `OverlappingRules`.
///
/// All four signals rely on fields on [`StructuralDiff`]
/// (`prev_total_rules`, `next_total_rules`,
/// `overlapping_apexes`, `prev_behavior_mode`, `next_behavior_mode`).
/// They are emitted in this order: `FailClosedActivation`,
/// `RuleSetEmptied`, `HighRemovalRatio`, `OverlappingRules` — matching
/// severity-then-specificity for the review UI's rendering.
fn collect_block_16_12_signals(diff: &StructuralDiff, signals: &mut Vec<RiskSignal>) {
    // Fail-closed activation: next mode is StrictSecondaryFailClosed
    // AND prev mode wasn't (or there was no prev — first revision
    // activating fail-closed is still High risk).
    if diff.next_behavior_mode == RouteBehaviorMode::StrictSecondaryFailClosed
        && diff.prev_behavior_mode != Some(RouteBehaviorMode::StrictSecondaryFailClosed)
    {
        signals.push(RiskSignal::FailClosedActivation);
    }

    // Rule-set emptied: prev had rules, next has zero.
    if diff.prev_total_rules > 0 && diff.next_total_rules == 0 {
        signals.push(RiskSignal::RuleSetEmptied {
            prev_total: diff.prev_total_rules,
        });
    } else if diff.prev_total_rules > 0 {
        // High-removal-ratio: ≥ threshold % of prev rules removed.
        // Computed from rule_changes (the diff already partitioned
        // them) rather than `prev - next` because Modified /
        // Retargeted entries don't reduce next_total but still
        // require the user's attention; we count only literal
        // Removed entries here.
        let removed_count = diff
            .rule_changes
            .iter()
            .filter(|c| matches!(c, RuleChange::Removed { .. }))
            .count() as u64;
        let pct = (removed_count * 100 / diff.prev_total_rules as u64) as u8;
        if pct >= HIGH_REMOVAL_RATIO_THRESHOLD_PCT {
            signals.push(RiskSignal::HighRemovalRatio { removed_pct: pct });
        }
    }

    // Overlapping rules: every apex with both an ExactFqdn and a
    // SuffixDomain in the candidate. compute_diff produced the list
    // in lexicographic order, so the emitted signals follow.
    for apex in &diff.overlapping_apexes {
        signals.push(RiskSignal::OverlappingRules { apex: apex.clone() });
    }
}

fn collect_content_signals(diff: &StructuralDiff, signals: &mut Vec<RiskSignal>) {
    if diff.behavior_mode_changed {
        signals.push(RiskSignal::DefaultBehaviorChanged);
    }

    if diff.binding_changed {
        signals.push(RiskSignal::UnstableInterfaceBinding);
    }

    let total_changes = diff.rule_changes.len() as u32;
    if total_changes >= MASS_CHANGE_THRESHOLD {
        signals.push(RiskSignal::MassChangeCount {
            count: total_changes,
        });
    }

    let mut secondary_reroute_count: u32 = 0;

    for change in &diff.rule_changes {
        match change {
            RuleChange::Added { rule, route } => {
                if *route == RouteRole::Secondary {
                    secondary_reroute_count += 1;
                }
                if let Some(CanonicalAddressMatch::SuffixDomain(label)) = &rule.address_match {
                    classify_suffix(label, signals);
                }
            }
            RuleChange::Retargeted {
                to: RouteRole::Secondary,
                ..
            } => {
                secondary_reroute_count += 1;
            }
            _ => {}
        }
    }

    if secondary_reroute_count > 0 {
        signals.push(RiskSignal::SecondaryReroute {
            rule_count: secondary_reroute_count,
        });
    }
}

fn classify_suffix(label: &str, signals: &mut Vec<RiskSignal>) {
    let dot_count = label.chars().filter(|c| *c == '.').count();
    if dot_count == 0 {
        // No dots → TLD-level (`com`, `ru`, `net`) → High
        signals.push(RiskSignal::BroadSuffixScope {
            label: label.to_string(),
        });
    } else if dot_count == 1 {
        // One dot → second-level (`example.com`) → Medium
        signals.push(RiskSignal::ModerateSuffixScope {
            label: label.to_string(),
        });
    }
    // Deeper suffixes (`api.example.com`) — no signal
}

fn collect_source_signals(source: &RevisionSource, _signals: &mut Vec<RiskSignal>) {
    // With current strongly-typed RevisionSource all variants have known
    // provenance. UnknownSource is reserved for future use.
    match source {
        RevisionSource::DirectEdit | RevisionSource::FileSync | RevisionSource::Import(_) => {}
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{
        canonical::{CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet},
        review::compute_diff,
        revision::{ContentHash, ImportChannel, ImportedArtifact, RevisionSource, UnixTimestamp},
        AdapterIdentity, BindingSource, RouteBinding, RuleId,
    };

    fn fqdn_rule(id: &str, fqdn: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_string()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn(fqdn.to_string())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn suffix_rule(id: &str, label: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_string()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::SuffixDomain(label.to_string())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn make_profile(
        primary_rules: Vec<CanonicalRule>,
        secondary_rules: Vec<CanonicalRule>,
    ) -> crate::canonical::CanonicalProfile {
        crate::canonical::CanonicalProfile {
            primary: RouteBinding {
                role: RouteRole::Primary,
                adapter: AdapterIdentity {
                    stable_id: "adapter-primary".to_string(),
                    display_name: "Primary".to_string(),
                },
                source: BindingSource::UserAssigned,
            },
            secondary: Some(RouteBinding {
                role: RouteRole::Secondary,
                adapter: AdapterIdentity {
                    stable_id: "adapter-secondary".to_string(),
                    display_name: "Secondary".to_string(),
                },
                source: BindingSource::UserAssigned,
            }),
            behavior_mode: crate::RouteBehaviorMode::StrictSecondaryFailClosed,
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(primary_rules),
                secondary: CanonicalRuleSet::from_rules(secondary_rules),
            },
        }
    }

    fn import_source() -> RevisionSource {
        RevisionSource::Import(ImportedArtifact {
            source_path: "/rules.txt".to_string(),
            file_hash: ContentHash::from_bytes([0xAA; 32]),
            imported_at: UnixTimestamp::from_secs(1_700_000_000),
            channel: ImportChannel::Snapshot,
        })
    }

    #[test]
    fn low_risk_for_small_exact_fqdn_addition() {
        let prev = make_profile(vec![], vec![]);
        let next = make_profile(vec![fqdn_rule("r-1", "corp.example.com")], vec![]);
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        assert_eq!(assessment.level, RiskLevel::Low);
        assert!(assessment.signals.is_empty());
        assert!(assessment.is_low_risk());
    }

    #[test]
    fn high_risk_for_tld_suffix_scope() {
        let prev = make_profile(vec![], vec![]);
        let next = make_profile(vec![suffix_rule("r-1", "com")], vec![]);
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        assert_eq!(assessment.level, RiskLevel::High);
        assert!(assessment.requires_mandatory_review());
        assert!(assessment
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::BroadSuffixScope { label } if label == "com")));
    }

    #[test]
    fn high_risk_for_cctld_suffix_scope() {
        let prev = make_profile(vec![], vec![]);
        let next = make_profile(vec![suffix_rule("r-1", "ru")], vec![]);
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        assert!(assessment
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::BroadSuffixScope { .. })));
    }

    #[test]
    fn medium_risk_for_second_level_suffix_scope() {
        let prev = make_profile(vec![], vec![]);
        let next = make_profile(vec![suffix_rule("r-1", "example.com")], vec![]);
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        assert_eq!(assessment.level, RiskLevel::Medium);
        assert!(assessment
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::ModerateSuffixScope { .. })));
    }

    #[test]
    fn no_signal_for_deep_suffix_scope() {
        let prev = make_profile(vec![], vec![]);
        let next = make_profile(vec![suffix_rule("r-1", "api.example.com")], vec![]);
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        assert!(assessment.is_low_risk());
    }

    #[test]
    fn medium_risk_for_default_behavior_changed() {
        let prev = make_profile(vec![], vec![]);
        let mut next = make_profile(vec![], vec![]);
        next.behavior_mode = crate::RouteBehaviorMode::PreferPrimary;
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        assert_eq!(assessment.level, RiskLevel::Medium);
        assert!(assessment
            .signals
            .contains(&RiskSignal::DefaultBehaviorChanged));
    }

    #[test]
    fn high_risk_for_mass_change_at_threshold() {
        let prev = make_profile(vec![], vec![]);
        let rules: Vec<CanonicalRule> = (0..20)
            .map(|i| fqdn_rule(&format!("r-{i}"), &format!("host{i}.example.com")))
            .collect();
        let next = make_profile(rules, vec![]);
        let diff = compute_diff(Some(&prev), &next);
        assert_eq!(diff.rule_changes.len(), 20);
        let assessment = score_candidate(&diff, &import_source());
        assert_eq!(assessment.level, RiskLevel::High);
        assert!(assessment
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::MassChangeCount { count: 20 })));
    }

    #[test]
    fn no_mass_change_signal_below_threshold() {
        let prev = make_profile(vec![], vec![]);
        let rules: Vec<CanonicalRule> = (0..19)
            .map(|i| fqdn_rule(&format!("r-{i}"), &format!("host{i}.example.com")))
            .collect();
        let next = make_profile(rules, vec![]);
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        assert!(!assessment
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::MassChangeCount { .. })));
    }

    #[test]
    fn medium_risk_for_secondary_reroute() {
        let prev = make_profile(vec![fqdn_rule("r-1", "corp.net")], vec![]);
        let next = make_profile(vec![], vec![fqdn_rule("r-1", "corp.net")]); // retargeted to secondary
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        assert!(assessment
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::SecondaryReroute { rule_count: 1 })));
    }

    #[test]
    fn high_risk_for_interface_binding_change() {
        let prev = make_profile(vec![], vec![]);
        let mut next = make_profile(vec![], vec![]);
        next.primary.adapter.stable_id = "adapter-different".to_string();
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        assert_eq!(assessment.level, RiskLevel::High);
        assert!(assessment
            .signals
            .contains(&RiskSignal::UnstableInterfaceBinding));
    }

    #[test]
    fn multiple_signals_level_is_maximum() {
        let prev = make_profile(vec![], vec![]);
        // suffix (medium) + secondary reroute (medium) → still Medium overall
        let next = make_profile(
            vec![],
            vec![suffix_rule("r-1", "example.com")], // secondary + 2nd-level suffix
        );
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        // ModerateSuffix (medium) + SecondaryReroute (medium) → Medium
        assert_eq!(assessment.level, RiskLevel::Medium);
        assert!(assessment.signals.len() >= 2);
    }

    #[test]
    fn direct_edit_source_does_not_add_unknown_source_signal() {
        let prev = make_profile(vec![], vec![]);
        let next = make_profile(vec![fqdn_rule("r-1", "a.com")], vec![]);
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &RevisionSource::DirectEdit);
        assert!(!assessment
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::UnknownSource)));
    }

    #[test]
    fn repeated_safe_import_stays_low_risk() {
        let profile = make_profile(vec![fqdn_rule("r-1", "corp.example.com")], vec![]);
        // Import same content → no diff changes, no risk signals
        let diff = compute_diff(Some(&profile), &profile);
        let assessment = score_candidate(&diff, &import_source());
        assert!(assessment.is_low_risk());
    }

    #[test]
    fn risk_signal_levels_are_correct() {
        assert_eq!(
            RiskSignal::BroadSuffixScope {
                label: "com".into()
            }
            .level(),
            RiskLevel::High
        );
        assert_eq!(
            RiskSignal::ModerateSuffixScope {
                label: "example.com".into()
            }
            .level(),
            RiskLevel::Medium
        );
        assert_eq!(
            RiskSignal::DefaultBehaviorChanged.level(),
            RiskLevel::Medium
        );
        assert_eq!(
            RiskSignal::MassChangeCount { count: 20 }.level(),
            RiskLevel::High
        );
        assert_eq!(
            RiskSignal::SecondaryReroute { rule_count: 1 }.level(),
            RiskLevel::Medium
        );
        assert_eq!(
            RiskSignal::UnstableInterfaceBinding.level(),
            RiskLevel::High
        );
        assert_eq!(RiskSignal::UnknownSource.level(), RiskLevel::Medium);
        assert_eq!(RiskSignal::LinkedSuspiciousDelta.level(), RiskLevel::High);
        assert_eq!(
            RiskSignal::RuleSetEmptied { prev_total: 10 }.level(),
            RiskLevel::High
        );
        assert_eq!(
            RiskSignal::HighRemovalRatio { removed_pct: 50 }.level(),
            RiskLevel::High
        );
        assert_eq!(
            RiskSignal::OverlappingRules {
                apex: "example.com".into()
            }
            .level(),
            RiskLevel::Medium
        );
        assert_eq!(RiskSignal::FailClosedActivation.level(), RiskLevel::High);
    }

    // ── New signal detection tests ────────────────────────────────────────────

    #[test]
    fn rule_set_emptied_fires_when_prev_had_rules_and_next_has_zero() {
        let prev = make_profile(
            vec![
                fqdn_rule("r-1", "a.example.com"),
                fqdn_rule("r-2", "b.example.com"),
            ],
            vec![],
        );
        let next = make_profile(vec![], vec![]);
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        assert!(assessment
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::RuleSetEmptied { prev_total: 2 })));
        assert_eq!(assessment.level, RiskLevel::High);
    }

    #[test]
    fn rule_set_emptied_does_not_fire_for_empty_to_empty() {
        let prev = make_profile(vec![], vec![]);
        let next = make_profile(vec![], vec![]);
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        assert!(!assessment
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::RuleSetEmptied { .. })));
    }

    #[test]
    fn high_removal_ratio_fires_at_threshold() {
        // 4 rules → remove 2 → 50 % removed
        let prev = make_profile(
            vec![
                fqdn_rule("r-1", "a.example.com"),
                fqdn_rule("r-2", "b.example.com"),
                fqdn_rule("r-3", "c.example.com"),
                fqdn_rule("r-4", "d.example.com"),
            ],
            vec![],
        );
        let next = make_profile(
            vec![
                fqdn_rule("r-1", "a.example.com"),
                fqdn_rule("r-2", "b.example.com"),
            ],
            vec![],
        );
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        assert!(assessment.signals.iter().any(
            |s| matches!(s, RiskSignal::HighRemovalRatio { removed_pct } if *removed_pct == 50)
        ));
    }

    #[test]
    fn high_removal_ratio_does_not_fire_below_threshold() {
        // 5 rules → remove 2 → 40 % removed (below 50 %)
        let prev = make_profile(
            vec![
                fqdn_rule("r-1", "a.example.com"),
                fqdn_rule("r-2", "b.example.com"),
                fqdn_rule("r-3", "c.example.com"),
                fqdn_rule("r-4", "d.example.com"),
                fqdn_rule("r-5", "e.example.com"),
            ],
            vec![],
        );
        let next = make_profile(
            vec![
                fqdn_rule("r-1", "a.example.com"),
                fqdn_rule("r-2", "b.example.com"),
                fqdn_rule("r-3", "c.example.com"),
            ],
            vec![],
        );
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        assert!(!assessment
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::HighRemovalRatio { .. })));
    }

    #[test]
    fn overlapping_rules_fires_when_exact_fqdn_overlaps_suffix_apex() {
        let prev = make_profile(vec![], vec![]);
        let next = make_profile(
            vec![
                fqdn_rule("r-fqdn", "api.example.com"),
                suffix_rule("r-suffix", "example.com"),
            ],
            vec![],
        );
        let diff = compute_diff(Some(&prev), &next);
        assert_eq!(diff.overlapping_apexes, vec!["example.com".to_string()]);
        let assessment = score_candidate(&diff, &import_source());
        assert!(assessment
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::OverlappingRules { apex } if apex == "example.com")));
    }

    #[test]
    fn overlapping_rules_does_not_fire_for_unrelated_apexes() {
        let prev = make_profile(vec![], vec![]);
        let next = make_profile(
            vec![
                fqdn_rule("r-fqdn", "api.foo.com"),
                suffix_rule("r-suffix", "bar.com"),
            ],
            vec![],
        );
        let diff = compute_diff(Some(&prev), &next);
        assert!(diff.overlapping_apexes.is_empty());
        let assessment = score_candidate(&diff, &import_source());
        assert!(!assessment
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::OverlappingRules { .. })));
    }

    #[test]
    fn overlapping_rules_detects_exact_match_at_apex() {
        // ExactFqdn === apex (e.g. user has rule for "example.com" itself
        // plus a SuffixDomain "example.com" → overlap)
        let prev = make_profile(vec![], vec![]);
        let next = make_profile(
            vec![
                fqdn_rule("r-apex", "example.com"),
                suffix_rule("r-suffix", "example.com"),
            ],
            vec![],
        );
        let diff = compute_diff(Some(&prev), &next);
        assert_eq!(diff.overlapping_apexes, vec!["example.com".to_string()]);
    }

    #[test]
    fn fail_closed_activation_fires_when_mode_transitions_to_strict() {
        let mut prev = make_profile(vec![], vec![]);
        prev.behavior_mode = crate::RouteBehaviorMode::PreferPrimary;
        let mut next = make_profile(vec![], vec![]);
        next.behavior_mode = crate::RouteBehaviorMode::StrictSecondaryFailClosed;
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        assert!(assessment
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::FailClosedActivation)));
        assert_eq!(assessment.level, RiskLevel::High);
    }

    #[test]
    fn fail_closed_activation_does_not_fire_when_already_strict() {
        // Both prev and next are StrictSecondaryFailClosed → no new
        // activation signal (the mode was already strict).
        let mut prev = make_profile(vec![], vec![]);
        prev.behavior_mode = crate::RouteBehaviorMode::StrictSecondaryFailClosed;
        let mut next = make_profile(vec![], vec![]);
        next.behavior_mode = crate::RouteBehaviorMode::StrictSecondaryFailClosed;
        let diff = compute_diff(Some(&prev), &next);
        let assessment = score_candidate(&diff, &import_source());
        assert!(!assessment
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::FailClosedActivation)));
    }

    #[test]
    fn fail_closed_activation_fires_on_first_revision_if_strict() {
        // No prev revision; first activation is StrictSecondaryFailClosed.
        let next = make_profile(vec![], vec![]);
        // `make_profile` default is `StrictSecondaryFailClosed`; the
        // helper test path already covers this. Confirm the signal
        // fires when prev is None.
        let diff = compute_diff(None, &next);
        let assessment = score_candidate(&diff, &import_source());
        assert!(assessment
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignal::FailClosedActivation)));
    }
}
