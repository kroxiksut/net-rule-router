//! What a rules change previewed and how it ended (`pure.js`): whether a
//! preview has anything to apply, whether the service refused it, which named
//! text a refusal has, and what the operation record says once confirmed.

use std::collections::BTreeMap;

use nrr_shared::ipc_payloads::{OperationStatusResponse, ReviewSummaryResponse, RiskSignalDto};

/// The service's refusal of a previewed change (`previewRefusal`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreviewRefusal {
    /// The error code the confirm would fail with.
    pub code: String,
    /// The refused rule values, `", "`-joined; empty unless the refusal names them.
    pub values: String,
    /// Placeholder values for the code's localized text.
    pub args: BTreeMap<String, String>,
}

/// The named text of a refusal (`refusalDetail`): a locale key and its
/// placeholder values, in fill order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusalDetail {
    pub key: String,
    pub values: Vec<(String, String)>,
}

/// How a confirmed operation ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    /// The failure code; never empty.
    Failed(String),
}

/// No rule changes and no changed fields (`reviewSummaryIsEmpty`). A refused
/// preview is empty too: ask [`preview_refusal`] first.
pub fn review_summary_is_empty(summary: &ReviewSummaryResponse) -> bool {
    summary.rules_added.is_empty()
        && summary.rules_removed.is_empty()
        && summary.rules_modified.is_empty()
        && summary.rules_retargeted.is_empty()
        && summary.changed_fields.is_empty()
}

fn non_empty_or_unknown(code: &str) -> String {
    if code.is_empty() {
        "unknown".to_owned()
    } else {
        code.to_owned()
    }
}

/// The first refusal among the preview's signals (`previewRefusal`).
pub fn preview_refusal(summary: &ReviewSummaryResponse) -> Option<PreviewRefusal> {
    summary.risk_signals.iter().find_map(|signal| match signal {
        RiskSignalDto::InvalidRuleValue { .. } => Some(PreviewRefusal {
            code: "invalid-rule-value".to_owned(),
            values: refused_rule_values_text(summary),
            args: BTreeMap::new(),
        }),
        RiskSignalDto::ChangeRefused { code, args } => Some(PreviewRefusal {
            code: non_empty_or_unknown(code),
            values: String::new(),
            args: args.clone(),
        }),
        _ => None,
    })
}

/// The values of the first `invalid-rule-value` signal (`refusedRuleValuesText`).
fn refused_rule_values_text(summary: &ReviewSummaryResponse) -> String {
    summary
        .risk_signals
        .iter()
        .find_map(|signal| match signal {
            RiskSignalDto::InvalidRuleValue { rules } => Some(rules.join(", ")),
            _ => None,
        })
        .unwrap_or_default()
}

/// The sentence that names what a refused network covers, when the refusal
/// carries it (`refusalDetail`); `None` sends the caller to the code's own text.
pub fn refusal_detail(code: &str, args: &BTreeMap<String, String>) -> Option<RefusalDetail> {
    let field = |name: &str| args.get(name).cloned().unwrap_or_default();
    let network = field("network");
    if network.is_empty() {
        return None;
    }
    let kind = field("covers-kind");
    let covers = field("covers");
    if code == "network-covers-link"
        && !covers.is_empty()
        && (kind == "tunnel-server" || kind == "local-network")
    {
        return Some(RefusalDetail {
            key: format!("errors.network-covers-link-{kind}"),
            values: vec![
                ("network".to_owned(), network),
                ("covers".to_owned(), covers),
            ],
        });
    }
    if code == "network-covers-fake-ip-pool" {
        return Some(RefusalDetail {
            key: "errors.network-covers-fake-ip-pool-named".to_owned(),
            values: vec![("network".to_owned(), network)],
        });
    }
    if code == "network-on-both-routes" {
        return Some(RefusalDetail {
            key: "errors.network-on-both-routes-named".to_owned(),
            values: vec![("network".to_owned(), network)],
        });
    }
    None
}

/// What an `operation.status.get` answer settles (`operationOutcome`); `None`
/// while the record does not say, and the caller settles by preview instead.
pub fn operation_outcome(status: Option<&OperationStatusResponse>) -> Option<Outcome> {
    let status = status?;
    match status.state.as_str() {
        "completed" => Some(Outcome::Applied),
        "failed" => Some(Outcome::Failed(non_empty_or_unknown(
            status.error.as_ref().map_or("", |e| e.code.as_str()),
        ))),
        _ => None,
    }
}

/// A preview of the confirmed payload, read as its outcome (`previewOutcome`):
/// the change took effect exactly when it now previews as `unchanged`.
pub fn preview_outcome(
    summary: &ReviewSummaryResponse,
    unchanged: impl Fn(&ReviewSummaryResponse) -> bool,
) -> Outcome {
    if let Some(refusal) = preview_refusal(summary) {
        return Outcome::Failed(refusal.code);
    }
    if unchanged(summary) {
        Outcome::Applied
    } else {
        Outcome::Failed("unknown".to_owned())
    }
}
