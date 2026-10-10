//! Reading and applying the rules, the GUI's review flow: `rules.list`, then
//! `mutation.submit` dry-run → review → confirm with the token, and the
//! operation record (or a second preview) for how the confirm ended.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use nrr_client_logic::placeholders::fill_placeholders;
use nrr_client_logic::review::{
    operation_outcome, preview_outcome, preview_refusal, refusal_detail, review_summary_is_empty,
    Outcome,
};
use nrr_client_logic::rules_table::{rule_row_to_wire_dto, RuleRow, WireDtoOptions};
use nrr_client_logic::Route;
use nrr_ipc_client::{ipc_error_to_wire, ipc_operation_timeout, IpcClient, IpcClientError};
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    OperationStatusResponse, ReviewRiskLevel, ReviewSummaryResponse, RulesListResponse,
};
use nrr_shared::rules_json::{
    to_canonical_string, CanonicalRulesJsonV1, RULES_JSON_SCHEMA_VERSION,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::table::Table;
use super::{ace, text};
use crate::backend::{Job, Reply};
use crate::i18n::Texts;

const KIND: &str = "rules-update";

/// Why something did not happen, in the service's terms; worded on screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    Code {
        code: String,
        args: BTreeMap<String, String>,
    },
    /// The values the service refused, `", "`-joined.
    Values(String),
}

impl Failure {
    pub fn code(code: &str) -> Self {
        Self::Code {
            code: code.to_owned(),
            args: BTreeMap::new(),
        }
    }

    pub(super) fn of(error: &IpcClientError) -> Self {
        Self::code(ipc_error_to_wire(error).0)
    }

    pub fn text(&self, texts: &Texts) -> String {
        match self {
            Self::Values(values) => texts.fill(text::INVALID_VALUES, &[("rules", values)]),
            Self::Code { code, args } => error_label(code, args, texts),
        }
    }
}

/// An error code in words (`ipcErrorLabel`): the named sentence when the
/// refusal carries one, else `errors.<code>`, else the code itself, so a code
/// newer than this build still says something.
pub fn error_label(code: &str, args: &BTreeMap<String, String>, texts: &Texts) -> String {
    let slug = code.to_lowercase().replace('_', "-");
    if slug.is_empty() {
        return texts.get(text::ERROR_UNKNOWN);
    }
    if let Some(detail) = refusal_detail(&slug, args) {
        let sentence = texts.dynamic(&detail.key, "");
        if !sentence.is_empty() {
            return fill_placeholders(&sentence, detail.values);
        }
    }
    let localised = texts.dynamic(&format!("errors.{slug}"), "");
    if localised.is_empty() {
        slug
    } else {
        localised
    }
}

/// One rules payload: what the review previews and the confirm applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub rules_json: String,
    pub content_hash: String,
    pub correlation_id: String,
    /// Committed to the administrator's baseline (`admin-baseline`), which
    /// the service accepts only from an elevated caller.
    pub admin_baseline: bool,
}

/// Rules as the canonical rules-json (`_buildRulesJsonFromModel`): a rule
/// rides in its route's bucket, a pseudo-route in the secondary one.
pub fn book_of<'a>(rules: impl IntoIterator<Item = &'a RuleRow>) -> CanonicalRulesJsonV1 {
    let encode: &dyn Fn(&str) -> String = &ace::encode;
    let mut book = CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary: Vec::new(),
        secondary: Vec::new(),
    };
    for rule in rules {
        let dto = rule_row_to_wire_dto(rule, Some(encode), WireDtoOptions::FULL);
        if rule.target_route.bucket() == Some(Route::Secondary) {
            book.secondary.push(dto);
        } else {
            book.primary.push(dto);
        }
    }
    book
}

/// The rows on screen as one rules payload.
pub fn pending_from(table: &Table, admin_baseline: bool) -> Option<Pending> {
    let rules_json = to_canonical_string(&book_of(table.rules())).ok()?;
    let content_hash = format!("{:x}", Sha256::digest(rules_json.as_bytes()));
    Some(Pending {
        rules_json,
        content_hash,
        correlation_id: correlation_id("tui-apply"),
        admin_baseline,
    })
}

/// `rules-update-<origin>-<ms>-<n>`: the origin reaches the service log, so a
/// stray cycle names its caller (`newCorrelationId`).
fn correlation_id(origin: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("{KIND}-{origin}-{ms}-{n}")
}

fn submit(
    client: &dyn IpcClient,
    pending: &Pending,
    dry_run: bool,
    token: Option<&str>,
) -> Result<Value, IpcClientError> {
    let mut request = json!({
        "mutation-kind": KIND,
        "payload": {
            "rules-json": pending.rules_json,
            "content-hash": pending.content_hash,
            "correlation-id": pending.correlation_id,
        },
        "dry-run": dry_run,
    });
    if pending.admin_baseline {
        request["payload"]["admin-baseline"] = Value::Bool(true);
    }
    // The client lifts this to the envelope, where the dispatcher reads it.
    if let Some(token) = token {
        request["_envelope_confirmation_token"] = Value::from(token);
    }
    let op = IpcOperationName::MutationSubmit;
    client.call(op, request, ipc_operation_timeout(op))
}

/// A dry-run answer: the summary (under `review-summary`, or the answer
/// itself) and the confirmation token.
fn read_preview(answer: Value) -> Result<(ReviewSummaryResponse, String), Failure> {
    let token = answer
        .get("confirmation-token")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let summary = answer.get("review-summary").cloned().unwrap_or(answer);
    serde_json::from_value(summary)
        .map(|s| (s, token))
        .map_err(|_| Failure::code("bad-response"))
}

/// What the screen shows of a finished review.
#[derive(Clone, Debug)]
pub struct Review {
    pub summary: ReviewSummaryResponse,
    pub token: String,
    pub pending: Pending,
    /// The critical-risk acknowledgement.
    pub understood: bool,
    /// Entries scrolled off the top.
    pub scroll: usize,
}

impl Review {
    pub fn is_critical(&self) -> bool {
        self.summary.risk_level == ReviewRiskLevel::Critical
    }

    pub fn may_apply(&self) -> bool {
        !self.is_critical() || self.understood
    }
}

/// How a preview came back.
#[derive(Debug)]
pub enum Previewed {
    Review(Box<Review>),
    NothingToApply,
    Refused(Failure),
}

/// How an apply ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finished {
    Applied,
    /// The token died before the confirm: the review is out of date.
    Expired,
    UacDeclined,
    Failed(Failure),
}

pub fn load_job() -> Job {
    Box::new(|client: &dyn IpcClient| {
        let op = IpcOperationName::RulesList;
        let result = client
            .call(op, json!({}), ipc_operation_timeout(op))
            .map_err(|e| Failure::of(&e))
            .and_then(|v| {
                serde_json::from_value::<RulesListResponse>(v)
                    .map_err(|_| Failure::code("bad-response"))
            });
        Reply::new(move |app| super::loaded(app, result))
    })
}

pub fn preview_job(pending: Pending) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let previewed = match submit(client, &pending, true, None) {
            Err(error) => Previewed::Refused(Failure::of(&error)),
            Ok(answer) => match read_preview(answer) {
                Err(failure) => Previewed::Refused(failure),
                Ok((summary, token)) => classify(summary, token, pending),
            },
        };
        Reply::new(move |app| super::previewed(app, previewed))
    })
}

/// A refused preview has an empty diff: say why, or it reads as "nothing to
/// apply".
fn classify(summary: ReviewSummaryResponse, token: String, pending: Pending) -> Previewed {
    if let Some(refusal) = preview_refusal(&summary) {
        return Previewed::Refused(if refusal.values.is_empty() {
            Failure::Code {
                code: refusal.code,
                args: refusal.args,
            }
        } else {
            Failure::Values(refusal.values)
        });
    }
    if review_summary_is_empty(&summary) {
        return Previewed::NothingToApply;
    }
    Previewed::Review(Box::new(Review {
        summary,
        token,
        pending,
        understood: false,
        scroll: 0,
    }))
}

pub fn confirm_job(pending: Pending, token: String) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let finished = confirm(client, &pending, &token);
        Reply::new(move |app| super::finished(app, finished))
    })
}

fn confirm(client: &dyn IpcClient, pending: &Pending, token: &str) -> Finished {
    let answer = match submit(client, pending, false, Some(token)) {
        Ok(answer) => answer,
        Err(error) => {
            return match ipc_error_to_wire(&error).0 {
                "confirmation-expired" => Finished::Expired,
                "uac-declined" => Finished::UacDeclined,
                code => Finished::Failed(Failure::code(code)),
            }
        }
    };
    // The confirm only accepts the change; its verdict is on the record.
    let operation_id = answer
        .get("operation-id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let status = (!operation_id.is_empty())
        .then(|| {
            let op = IpcOperationName::OperationStatusGet;
            client
                .call(
                    op,
                    json!({ "operation-id": operation_id }),
                    ipc_operation_timeout(op),
                )
                .ok()
                .and_then(|v| serde_json::from_value::<OperationStatusResponse>(v).ok())
        })
        .flatten();
    match operation_outcome(status.as_ref()) {
        Some(Outcome::Applied) => Finished::Applied,
        Some(Outcome::Failed(code)) => Finished::Failed(Failure::Code {
            code,
            args: status
                .and_then(|s| s.error)
                .map(|e| e.args)
                .unwrap_or_default(),
        }),
        None => settle_by_preview(client, pending),
    }
}

/// The change took effect exactly when the same payload now previews as
/// unchanged (`settleByPreview`).
fn settle_by_preview(client: &dyn IpcClient, pending: &Pending) -> Finished {
    let again = Pending {
        correlation_id: correlation_id("outcome"),
        ..pending.clone()
    };
    let summary = match submit(client, &again, true, None) {
        Ok(answer) => read_preview(answer),
        Err(error) => Err(Failure::of(&error)),
    };
    match summary {
        Err(failure) => Finished::Failed(failure),
        Ok((summary, _)) => match preview_outcome(&summary, review_summary_is_empty) {
            Outcome::Applied => Finished::Applied,
            Outcome::Failed(code) => Finished::Failed(Failure::code(&code)),
        },
    }
}
