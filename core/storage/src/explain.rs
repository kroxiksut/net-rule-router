//! Privacy-tiered redaction level for cache-lookup explain detail.
//!
//! # Privacy model
//!
//! Three redaction levels control what explain detail is surfaced to callers:
//!
//! | Level        | What is revealed                                                 |
//! |--------------|------------------------------------------------------------------|
//! | `Compact`    | Cache hit/miss, freshness label, source label, error presence    |
//! | `Standard`   | + selected IP, ambiguity/conflict flags, TTL                     |
//! | `Diagnostics`| + all resolved IPs, reverse hostnames, resolution timestamps     |
//!
//! `Compact` is safe for the normal explain panel shown to all users.
//! `Standard` is the default for the diagnostics drawer / explain detail view.
//! `Diagnostics` requires explicit developer/diagnostics mode opt-in.

// ── DiagnosticRedactionLevel ──────────────────────────────────────────────────

/// How much explain detail is revealed in a given display context.
///
/// The levels are ordered from least to most revealing; `>=` comparisons
/// can be used to check whether a level includes a feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum DiagnosticRedactionLevel {
    /// Safe for the normal explain panel: only categorical labels, no addresses.
    Compact,
    /// Extended explain / diagnostics drawer: adds selected IP, ambiguity flags.
    #[default]
    Standard,
    /// Developer / full diagnostics mode: reveals all IPs, hostnames, timestamps.
    Diagnostics,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_levels_are_ordered_compact_lt_standard_lt_diagnostics() {
        assert!(DiagnosticRedactionLevel::Compact < DiagnosticRedactionLevel::Standard);
        assert!(DiagnosticRedactionLevel::Standard < DiagnosticRedactionLevel::Diagnostics);
    }
}
