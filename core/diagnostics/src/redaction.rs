//! Privacy redaction level mapping.
//!
//! # Two distinct concepts
//!
//! | Type                    | Crate         | Controls                                              |
//! |-------------------------|---------------|-------------------------------------------------------|
//! | [`ExplainDetailLevel`]  | `nrr-domain`  | How much data the rule engine puts into `DecisionExplain` |
//! | [`DiagnosticRedactionLevel`] | `nrr-storage` | How much of that data is revealed to the caller     |
//!
//! The mapping [`explain_to_redaction`] translates between them so that
//! callers who work with the storage/display layer do not need to import
//! `nrr-domain` directly.
//!
//! # Privacy ordering invariant
//!
//! Redaction is monotone: a higher `ExplainDetailLevel` maps to an equal or
//! higher `DiagnosticRedactionLevel`.  The function below preserves this.

pub use nrr_domain::decision_explain::ExplainDetailLevel;
pub use nrr_storage::DiagnosticRedactionLevel;

/// Translate a rule-engine detail level to the corresponding display
/// redaction level.
///
/// The rule-engine level controls what data was *collected*; the redaction
/// level controls what is *shown*.  Both must agree before sensitive fields
/// are surfaced.
///
/// # Mapping table
///
/// | `ExplainDetailLevel` | `DiagnosticRedactionLevel` |
/// |----------------------|----------------------------|
/// | `CompactUi`          | `Compact`                  |
/// | `Diagnostics`        | `Diagnostics`              |
/// | `DeveloperTrace`     | `Diagnostics`              |
///
/// `DeveloperTrace` maps to `Diagnostics` (the maximum reveal level) because
/// the redaction type has no developer-only variant — full reveal is already
/// the maximum.  Further gating in dev/test profiles is done by the caller.
#[must_use]
pub fn explain_to_redaction(level: ExplainDetailLevel) -> DiagnosticRedactionLevel {
    match level {
        ExplainDetailLevel::CompactUi => DiagnosticRedactionLevel::Compact,
        ExplainDetailLevel::Diagnostics => DiagnosticRedactionLevel::Diagnostics,
        ExplainDetailLevel::DeveloperTrace => DiagnosticRedactionLevel::Diagnostics,
    }
}

/// Translate a display redaction level back to the most permissive explain
/// detail level that is consistent with showing that much data.
///
/// Used when the caller has a redaction level and needs to request an
/// appropriate `DecisionExplain` from the rule engine.
#[must_use]
pub fn redaction_to_explain(level: DiagnosticRedactionLevel) -> ExplainDetailLevel {
    match level {
        DiagnosticRedactionLevel::Compact => ExplainDetailLevel::CompactUi,
        DiagnosticRedactionLevel::Standard => ExplainDetailLevel::Diagnostics,
        DiagnosticRedactionLevel::Diagnostics => ExplainDetailLevel::Diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_ui_maps_to_compact() {
        assert_eq!(
            explain_to_redaction(ExplainDetailLevel::CompactUi),
            DiagnosticRedactionLevel::Compact,
        );
    }

    #[test]
    fn diagnostics_maps_to_diagnostics() {
        assert_eq!(
            explain_to_redaction(ExplainDetailLevel::Diagnostics),
            DiagnosticRedactionLevel::Diagnostics,
        );
    }

    #[test]
    fn developer_trace_maps_to_diagnostics() {
        assert_eq!(
            explain_to_redaction(ExplainDetailLevel::DeveloperTrace),
            DiagnosticRedactionLevel::Diagnostics,
        );
    }

    #[test]
    fn mapping_is_monotone() {
        // Higher explain level must map to >= redaction level.
        let compact = explain_to_redaction(ExplainDetailLevel::CompactUi);
        let diag = explain_to_redaction(ExplainDetailLevel::Diagnostics);
        let dev = explain_to_redaction(ExplainDetailLevel::DeveloperTrace);
        assert!(compact <= diag);
        assert!(diag <= dev);
    }

    #[test]
    fn redaction_to_explain_compact() {
        assert_eq!(
            redaction_to_explain(DiagnosticRedactionLevel::Compact),
            ExplainDetailLevel::CompactUi,
        );
    }

    #[test]
    fn redaction_to_explain_standard_gives_diagnostics() {
        assert_eq!(
            redaction_to_explain(DiagnosticRedactionLevel::Standard),
            ExplainDetailLevel::Diagnostics,
        );
    }

    #[test]
    fn round_trip_compact() {
        let level = ExplainDetailLevel::CompactUi;
        let redacted = explain_to_redaction(level);
        let back = redaction_to_explain(redacted);
        assert_eq!(back, level);
    }
}
