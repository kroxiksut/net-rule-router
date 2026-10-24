//! Restarting the audit chain, as the window's dialog does it: the service's
//! dry-run lists the breaks the restart covers, the user confirms that list,
//! and the confirm re-runs the dry-run with the shown digest, so a trail that
//! changed meanwhile is shown again rather than restarted blind.

use nrr_client_logic::review::{operation_outcome, Outcome};
use nrr_ipc_client::IpcClient;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    AuditChainBreakDto, AuditChainRestartPreviewDto, MutationConfirmResponse,
    MutationDryRunResponse, MutationKind, OperationStatusRequest, OperationStatusResponse,
};
use serde_json::{json, Value};

use super::diagnostics::submit_kind;
use super::{bad_response, call, error_text, keys, queue};
use crate::backend::Reply;
use crate::i18n::Texts;
use crate::state::AppState;
use crate::view::{Segment, ViewLine};

#[derive(Debug, Default)]
pub enum Restart {
    #[default]
    Idle,
    Working,
    /// The breaks the restart would cover, waiting for a yes or a no.
    Review {
        preview: AuditChainRestartPreviewDto,
        changed: bool,
    },
    Done(Result<(), String>),
}

impl Restart {
    pub fn reviewing(&self) -> bool {
        matches!(self, Self::Review { .. })
    }
}

/// What a preview comes to: nothing to restart, or a list to show.
enum Preview {
    Intact,
    Breaks(AuditChainRestartPreviewDto),
}

fn preview(client: &dyn IpcClient, payload: Value) -> Result<(Preview, String), String> {
    let answer = submit_kind(client, MutationKind::AuditChainRestart, payload, true, None)?;
    let dry: MutationDryRunResponse = serde_json::from_value(answer).map_err(bad_response)?;
    let shown = dry
        .audit_chain
        .ok_or_else(|| "audit-unavailable".to_owned())?;
    let verdict = if shown.break_count == 0 || shown.breaks_digest.is_empty() {
        Preview::Intact
    } else {
        Preview::Breaks(shown)
    };
    Ok((verdict, dry.confirmation_token))
}

fn settle(app: &mut AppState, outcome: Result<Preview, String>, changed: bool) {
    app.inspect.diag.restart = match outcome {
        Ok(Preview::Intact) => Restart::Done(Err("audit-chain-intact".to_owned())),
        Ok(Preview::Breaks(preview)) => Restart::Review { preview, changed },
        Err(slug) => Restart::Done(Err(slug)),
    };
}

/// `k`: ask the service what a restart would cover.
pub fn start(app: &mut AppState) {
    if matches!(app.inspect.diag.restart, Restart::Working) || !app.link.is_connected() {
        return;
    }
    app.inspect.diag.restart = Restart::Working;
    queue(app, |client| {
        let outcome = preview(client, json!({})).map(|(verdict, _)| verdict);
        Reply::new(move |app| settle(app, outcome, false))
    });
}

/// The answer to the shown list.
pub fn answer(app: &mut AppState, yes: bool) {
    let Restart::Review { preview: shown, .. } = std::mem::take(&mut app.inspect.diag.restart)
    else {
        return;
    };
    if !yes {
        return;
    }
    app.inspect.diag.restart = Restart::Working;
    let digest = shown.breaks_digest;
    queue(app, move |client| {
        let result = confirm(client, &digest);
        Reply::new(move |app| match result {
            Confirmed::Done => app.inspect.diag.restart = Restart::Done(Ok(())),
            Confirmed::Changed(outcome) => settle(app, outcome, true),
            Confirmed::Failed(slug) => app.inspect.diag.restart = Restart::Done(Err(slug)),
        })
    });
}

enum Confirmed {
    Done,
    /// The trail moved since the list was shown: the new list, to confirm again.
    Changed(Result<Preview, String>),
    Failed(String),
}

fn confirm(client: &dyn IpcClient, digest: &str) -> Confirmed {
    let payload = json!({ "breaks-digest": digest });
    // The token is minted for this exact payload; a fresh preview catches a
    // change before anything is sent.
    let token = match preview(client, payload.clone()) {
        Err(slug) => return Confirmed::Failed(slug),
        Ok((Preview::Intact, _)) => return Confirmed::Failed("audit-chain-intact".to_owned()),
        Ok((Preview::Breaks(now), _)) if now.breaks_digest != digest => {
            return Confirmed::Changed(Ok(Preview::Breaks(now)))
        }
        Ok((Preview::Breaks(_), token)) => token,
    };
    let recorded = submit_kind(
        client,
        MutationKind::AuditChainRestart,
        payload,
        false,
        Some(&token),
    )
    .and_then(|answer| {
        serde_json::from_value::<MutationConfirmResponse>(answer).map_err(bad_response)
    })
    .map(|confirmed| {
        let request = OperationStatusRequest {
            operation_id: confirmed.operation_id,
        };
        let record = serde_json::to_value(&request)
            .ok()
            .and_then(|p| call(client, IpcOperationName::OperationStatusGet, p).ok())
            .and_then(|v| serde_json::from_value::<OperationStatusResponse>(v).ok());
        operation_outcome(record.as_ref())
    });
    match recorded {
        Err(slug) => Confirmed::Failed(slug),
        Ok(Some(Outcome::Applied)) => Confirmed::Done,
        Ok(Some(Outcome::Failed(code))) if code == "audit-chain-changed" => {
            Confirmed::Changed(preview(client, json!({})).map(|(verdict, _)| verdict))
        }
        Ok(Some(Outcome::Failed(code))) => Confirmed::Failed(code),
        // A record this account cannot read: judge by what the chain says now.
        Ok(None) => match preview(client, json!({})) {
            Ok((Preview::Intact, _)) => Confirmed::Done,
            Ok((Preview::Breaks(now), _)) if now.breaks_digest != digest => {
                Confirmed::Changed(Ok(Preview::Breaks(now)))
            }
            Ok(_) => Confirmed::Failed("unknown".to_owned()),
            Err(slug) => Confirmed::Failed(slug),
        },
    }
}

fn break_line(texts: &Texts, row: &AuditChainBreakDto) -> String {
    let kind = texts.dynamic(&format!("diag.audit.break-kind.{}", row.kind), &row.kind);
    if row.line > 0 {
        texts.fill(
            keys::AUDIT_RESTART_ROW_LINE,
            &[
                ("file", row.file.clone()),
                ("line", row.line.to_string()),
                ("kind", kind),
            ],
        )
    } else {
        texts.fill(
            keys::AUDIT_RESTART_ROW_FILE,
            &[("file", row.file.clone()), ("kind", kind)],
        )
    }
}

/// The restart's lines under the audit state; `offered` adds the key hint.
pub fn lines(restart: &Restart, offered: bool, texts: &Texts) -> Vec<ViewLine> {
    match restart {
        Restart::Idle if offered => vec![ViewLine::text(format!(
            "k: {}",
            texts.get(keys::AUDIT_RESTART_OPEN)
        ))],
        Restart::Idle => Vec::new(),
        Restart::Working => vec![ViewLine::text(texts.get(keys::AUDIT_RESTART_LOADING))],
        Restart::Done(Ok(())) => vec![ViewLine::text(texts.get(keys::AUDIT_RESTART_COMPLETED))],
        Restart::Done(Err(slug)) if slug == "audit-chain-intact" => {
            vec![ViewLine::text(error_text(texts, slug))]
        }
        Restart::Done(Err(slug)) => vec![ViewLine::text(format!(
            "{}{}",
            texts.get(keys::AUDIT_RESTART_FAILED),
            error_text(texts, slug)
        ))],
        Restart::Review { preview, changed } => {
            let mut lines = vec![ViewLine::new(vec![Segment::strong(
                texts.get(keys::AUDIT_RESTART_TITLE),
            )])];
            if *changed {
                lines.push(ViewLine::text(texts.get(keys::AUDIT_RESTART_CHANGED)));
            }
            let count = usize::try_from(preview.break_count).unwrap_or(usize::MAX);
            lines.push(ViewLine::text(
                texts.counted(keys::AUDIT_RESTART_SUMMARY, count),
            ));
            lines.extend(
                preview
                    .breaks
                    .iter()
                    .map(|row| ViewLine::text(format!("- {}", break_line(texts, row)))),
            );
            if count > preview.breaks.len() {
                lines.push(ViewLine::text(texts.fill(
                    keys::AUDIT_RESTART_TRUNCATED,
                    &[("shown", preview.breaks.len().to_string())],
                )));
            }
            lines.push(ViewLine::text(texts.get(keys::AUDIT_RESTART_EXPLAIN)));
            lines.push(ViewLine::text(texts.get(keys::YES_NO)));
            lines
        }
    }
}
