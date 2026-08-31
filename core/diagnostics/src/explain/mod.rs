//! Explain mode presentation layer: the [`ExplainResponse`] DTO the routing
//! check answers with.
//!
//! It used to also carry a mapper from `DecisionExplain` (the rule engine's
//! trace) plus its own key namespace. Both were unreachable — the engine entry
//! point that produces `DecisionExplain` is not called in production, the
//! historical-decision query has no snapshot store to read, and the synthetic
//! query builds its response directly — and the keys did not match the locale
//! files anyway, so wiring them up would have shown untranslated text.
//!
//! # Two explain scenarios
//!
//! | `ExplainQuery` variant      | Source of truth                  | Audit? |
//! |-----------------------------|----------------------------------|--------|
//! | `HistoricalDecision`        | Stored `DecisionExplain` snapshot| No     |
//! | `Synthetic`                 | Re-run with current rule state   | No     |
//!
//! Neither scenario modifies routing policy or creates an audit event.
//!
//! # Detail levels
//!
//! | Level          | Audience         | Available                                  |
//! |----------------|------------------|--------------------------------------------|
//! | `CompactUi`    | All users        | Summary, match result, final action        |
//! | `Diagnostics`  | Diagnostic mode  | + IP, TTL, warnings, uncertainty markers   |
//! | `DeveloperTrace`| Dev/test only   | + full process path, correlation details   |

pub mod query;
pub mod response;

pub use query::{ExplainDataAvailability, ExplainQuery, ExplainQueryKind, RuntimeInputSample};
pub use response::{
    ExplainAvailabilitySection, ExplainCorrelationSection, ExplainFinalActionSection,
    ExplainInputSection, ExplainLookupSection, ExplainMatchSection, ExplainResponse,
    ExplainSummarySection, ExplainWarningEntry,
};
