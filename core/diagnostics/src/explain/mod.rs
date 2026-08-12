//! Explain mode presentation layer.
//!
//! Converts `DecisionExplain` (from the rule engine) and
//! `LookupExplainSummary` (from the cache layer) into a
//! GUI-ready [`ExplainResponse`] DTO.
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

pub mod keys;
pub mod mapper;
pub mod query;
pub mod response;

pub use keys::*;
pub use mapper::map_explain;
pub use query::{ExplainDataAvailability, ExplainQuery, ExplainQueryKind, RuntimeInputSample};
pub use response::{
    ExplainAvailabilitySection, ExplainCorrelationSection, ExplainFinalActionSection,
    ExplainInputSection, ExplainLookupSection, ExplainMatchSection, ExplainResponse,
    ExplainSummarySection, ExplainWarningEntry,
};
