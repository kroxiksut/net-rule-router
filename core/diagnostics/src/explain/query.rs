//! Explain mode query types.

use nrr_domain::decision_explain::DecisionId;

// ── ExplainQueryKind ──────────────────────────────────────────────────────────

/// Distinguishes the two explain scenarios at the DTO level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplainQueryKind {
    /// Explain a real decision that was applied by the service.
    Historical,
    /// Explain a synthetic input sample for diagnostic purposes.
    /// The result is **not** an applied routing decision.
    Synthetic,
}

impl ExplainQueryKind {
    #[must_use]
    pub fn is_simulation(self) -> bool {
        self == Self::Synthetic
    }
}

// ── RuntimeInputSample ────────────────────────────────────────────────────────

/// Minimal input sample for `ExplainQuery::Synthetic`.
///
/// Provides the key fields that would be fed to the rule engine.
/// Does not include full process path or resolved IPs — those come from
/// the cache/resolver at evaluation time.
#[derive(Clone, Debug)]
pub struct RuntimeInputSample {
    /// Destination hostname to evaluate (optional).
    pub hostname: Option<String>,
    /// Observed destination IPv4 address (dotted decimal, optional).
    pub observed_ip: Option<String>,
    /// Process filename only (no path, optional).
    pub process_name: Option<String>,
}

impl RuntimeInputSample {
    pub fn new() -> Self {
        Self {
            hostname: None,
            observed_ip: None,
            process_name: None,
        }
    }

    pub fn with_hostname(mut self, h: impl Into<String>) -> Self {
        self.hostname = Some(h.into());
        self
    }
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.observed_ip = Some(ip.into());
        self
    }
    pub fn with_process(mut self, p: impl Into<String>) -> Self {
        self.process_name = Some(p.into());
        self
    }
}

impl Default for RuntimeInputSample {
    fn default() -> Self {
        Self::new()
    }
}

// ── ExplainQuery ──────────────────────────────────────────────────────────────

/// The two explain scenarios supported by explain mode.
///
/// # `HistoricalDecision`
///
/// The caller passes a `DecisionExplain` snapshot (already computed by the
/// rule engine).  The response reflects exactly the decision that was applied.
///
/// # `Synthetic`
///
/// The caller passes a `RuntimeInputSample`.  The service re-runs the explain
/// pipeline with current rule state and marks the result as a diagnostic
/// simulation — not an applied routing decision.  Synthetic explains must not
/// be written to the audit trail.
#[derive(Clone, Debug)]
pub enum ExplainQuery {
    /// Explain a historical routing decision identified by its snapshot.
    HistoricalDecision { decision_id: DecisionId },
    /// Explain a synthetic input sample as a diagnostic simulation.
    Synthetic { input_sample: RuntimeInputSample },
}

impl ExplainQuery {
    pub fn kind(&self) -> ExplainQueryKind {
        match self {
            Self::HistoricalDecision { .. } => ExplainQueryKind::Historical,
            Self::Synthetic { .. } => ExplainQueryKind::Synthetic,
        }
    }
}

// ── ExplainDataAvailability ───────────────────────────────────────────────────

/// Availability of explain data for the requested query.
///
/// Determines which sections of [`super::response::ExplainResponse`] are populated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplainDataAvailability {
    /// Full explain data is available for the requested detail level.
    Available,
    /// The requested decision id was not found (may have expired or never existed).
    DecisionNotFound,
    /// The requested detail level requires diagnostic mode to be enabled.
    DiagnosticModeRequired,
    /// Cache/lookup metadata is unavailable for the lookup section.
    LookupUnavailable,
    /// The service is not running; explain is not available.
    ServiceUnavailable,
}

impl ExplainDataAvailability {
    /// Localization key for user-facing unavailability message.
    #[must_use]
    pub fn ui_key(self) -> &'static str {
        // Locale schema enforces kebab-case key segments; underscores
        // are rejected during locale validation and would silently
        // discard the entire locale file. See LESSONS_LEARNED.md.
        // Keys MUST start with `diag.` to match the nested locale
        // tree (`locales/{en,ru}.json` puts `explain.*` under `diag`).
        match self {
            Self::Available => "diag.explain.availability.available",
            Self::DecisionNotFound => "diag.explain.availability.decision-not-found",
            Self::DiagnosticModeRequired => "diag.explain.availability.diagnostic-mode-required",
            Self::LookupUnavailable => "diag.explain.availability.lookup-unavailable",
            Self::ServiceUnavailable => "diag.explain.availability.service-unavailable",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_query_kind_is_simulation() {
        assert!(!ExplainQueryKind::Historical.is_simulation());
        assert!(ExplainQueryKind::Synthetic.is_simulation());
    }

    #[test]
    fn explain_query_kind_from_query() {
        let q = ExplainQuery::HistoricalDecision {
            decision_id: DecisionId("d-001".into()),
        };
        assert_eq!(q.kind(), ExplainQueryKind::Historical);

        let q = ExplainQuery::Synthetic {
            input_sample: RuntimeInputSample::new(),
        };
        assert_eq!(q.kind(), ExplainQueryKind::Synthetic);
    }

    #[test]
    fn runtime_input_sample_builder() {
        let s = RuntimeInputSample::new()
            .with_hostname("example.com")
            .with_ip("1.2.3.4")
            .with_process("chrome.exe");
        assert_eq!(s.hostname.as_deref(), Some("example.com"));
        assert_eq!(s.observed_ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(s.process_name.as_deref(), Some("chrome.exe"));
    }

    #[test]
    fn availability_ui_keys_stable() {
        // Locale schema enforces kebab-case key segments AND nests
        // `explain.*` under `diag.*` in `locales/{en,ru}.json` — keys
        // must therefore start with `diag.` to resolve. Lock in the
        // current shape so a drift back to bare `explain.*` (which
        // surfaces raw slugs in the GUI) fails fast.
        assert_eq!(
            ExplainDataAvailability::Available.ui_key(),
            "diag.explain.availability.available"
        );
        assert_eq!(
            ExplainDataAvailability::DecisionNotFound.ui_key(),
            "diag.explain.availability.decision-not-found"
        );
        assert_eq!(
            ExplainDataAvailability::DiagnosticModeRequired.ui_key(),
            "diag.explain.availability.diagnostic-mode-required"
        );
        assert_eq!(
            ExplainDataAvailability::LookupUnavailable.ui_key(),
            "diag.explain.availability.lookup-unavailable"
        );
        assert_eq!(
            ExplainDataAvailability::ServiceUnavailable.ui_key(),
            "diag.explain.availability.service-unavailable"
        );
    }
}
