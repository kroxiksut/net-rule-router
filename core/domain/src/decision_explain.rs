//! Identifiers and the detail level for explain output.
//!
//! # Decision ID format
//!
//! `DecisionId` uses the format `"d-{uuid_v4}"` — the `d-` prefix distinguishes
//! decision IDs from rule IDs (`r-`) and event IDs (`evt-`) in logs and audit.
//!
//! # Privacy filtering
//!
//! `ExplainDetailLevel` is what the diagnostics layer gates redaction on: the
//! compact level must not expose the full executable path, the resolved IP
//! list, exact resolution timestamps, or reverse hostnames. Those are reached
//! only by an explicit user action.
//!
//! This module used to also carry the assembled `DecisionExplain` and its
//! builder. Both existed for `decide_route`, which never ran in production;
//! they were removed with it rather than left as a second, untested
//! description of what the service does.

// ── DecisionId ────────────────────────────────────────────────────────────────

/// Stable, unique identifier for a single routing decision.
///
/// Format: `"d-{uuid_v4}"` — the `d-` prefix distinguishes decision IDs from
/// rule IDs (`r-`), event IDs (`evt-`), and revision IDs in logs and audit.
///
/// Generated fresh for every decision invocation; never reused.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DecisionId(pub String);

impl DecisionId {
    /// Returns the ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DecisionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ── ExplainDetailLevel ────────────────────────────────────────────────────────

/// Level of detail requested when rendering explain output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExplainDetailLevel {
    /// Compact, privacy-safe summary for the end-user explain panel.
    CompactUi,
    /// Extended diagnostics for power users or support — includes normalized
    /// inputs, cache state, and non-sensitive warnings.
    Diagnostics,
    /// Full trace for developer and integration-test use — includes all stage
    /// outputs, timestamps, and internal IDs.
    DeveloperTrace,
}

#[cfg(test)]
mod tests {
    use super::{DecisionId, ExplainDetailLevel};

    #[test]
    fn a_decision_id_prints_as_the_string_it_carries() {
        let id = DecisionId("d-0000".to_owned());
        assert_eq!(id.as_str(), "d-0000");
        assert_eq!(id.to_string(), "d-0000");
    }

    /// Redaction widens with the level, and the diagnostics layer relies on
    /// that order rather than matching every variant.
    #[test]
    fn detail_levels_order_from_the_most_redacted_to_the_least() {
        assert!(ExplainDetailLevel::CompactUi < ExplainDetailLevel::Diagnostics);
        assert!(ExplainDetailLevel::Diagnostics < ExplainDetailLevel::DeveloperTrace);
    }
}
