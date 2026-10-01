//! What acknowledging a blocking integrity alert adopts.
//!
//! The answer always comes from the service's own scan, never from
//! `security_alerts`: that table is unsigned. The alert row decides only which
//! scanned rows are in question, and an alert id that names a row's content is
//! all it ever narrows by — it cannot widen what a key reset adopts, which only
//! the re-sign marker beside the key can.

use nrr_diagnostics::audit::alert::{SecurityAlert, SecurityAlertState};
use nrr_diagnostics::audit::kind::AuditEventKind;
use nrr_shared::ipc_payloads::{IntegrityRowKind, IntegrityRowRef, UnverifiedRowDto};
use nrr_storage::revision_hmac::HmacVerification;
use nrr_storage::revisions::{self, AdoptionRequest, ScannedContent, ScannedRow};

const TAMPER_ALERT_PREFIX: &str = "alt-dbtamper-";
const UNTRUSTED_REVISION_ALERT_PREFIX: &str = "alt-revintegrity-";
const POINTER_LABEL_PREFIX: &str = "pointer:";

/// One tamper alert per row AND content: the same edit seen on every restart is
/// one incident, a later edit of the same row is a new one.
#[must_use]
pub fn tamper_alert_id(row: &ScannedRow) -> String {
    format!(
        "{TAMPER_ALERT_PREFIX}{}@{}",
        row_label(row),
        row.fingerprint
    )
}

/// One alert per revision the activation gate refused.
#[must_use]
pub fn untrusted_revision_alert_id(revision_id: &str) -> String {
    format!("{UNTRUSTED_REVISION_ALERT_PREFIX}{revision_id}")
}

/// How logs and the bootstrap outcome name a row.
#[must_use]
pub fn row_label(row: &ScannedRow) -> String {
    match row.content {
        ScannedContent::Revision(_) => row.revision_id().to_string(),
        ScannedContent::Pointer(_) => format!("{POINTER_LABEL_PREFIX}{}", row.principal),
    }
}

/// The stored row an alert is about, read back from its id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertRow<'a> {
    /// A principal's active-revision pointer; carries the principal.
    Pointer(&'a str),
    Revision(&'a str),
}

/// `None` for an alert about no one row — the key, the audit trail, the check.
#[must_use]
pub fn alert_row(alert: &SecurityAlert) -> Option<AlertRow<'_>> {
    let id = alert.alert_id.as_str();
    if alert.kind == AuditEventKind::DbTamperDetected.as_str() {
        let (label, _fingerprint) = id.strip_prefix(TAMPER_ALERT_PREFIX)?.rsplit_once('@')?;
        Some(match label.strip_prefix(POINTER_LABEL_PREFIX) {
            Some(principal) => AlertRow::Pointer(principal),
            None => AlertRow::Revision(label),
        })
    } else if alert.kind == AuditEventKind::UntrustedRevisionRejected.as_str() {
        id.strip_prefix(UNTRUSTED_REVISION_ALERT_PREFIX)
            .map(AlertRow::Revision)
    } else {
        None
    }
}

/// The rows acknowledging `alert` adopts.
///
/// A tamper alert covers the one row whose current content it was raised for.
/// A key reset covers every row the lost key signed, but only while the re-sign
/// marker says a reset is pending, and never a row under an active tamper
/// alert for its current content: that one is evidence, not an orphan of the
/// old key.
#[must_use]
pub fn alert_scope<'s>(
    alert: &SecurityAlert,
    scan: &'s [ScannedRow],
    key_reset_pending: bool,
    open_alerts: &[SecurityAlert],
) -> Vec<&'s ScannedRow> {
    let tampered = scan
        .iter()
        .filter(|r| r.verification == HmacVerification::Tampered);
    if alert.kind == AuditEventKind::DbTamperDetected.as_str() {
        return tampered
            .filter(|r| tamper_alert_id(r) == alert.alert_id)
            .collect();
    }
    if alert.kind != AuditEventKind::KeyResetWithExistingData.as_str() || !key_reset_pending {
        return Vec::new();
    }
    tampered
        .filter(|r| {
            let id = tamper_alert_id(r);
            !open_alerts.iter().any(|a| {
                a.state == SecurityAlertState::Active
                    && a.kind == AuditEventKind::DbTamperDetected.as_str()
                    && a.alert_id == id
            })
        })
        .collect()
}

#[must_use]
pub fn row_ref(row: &ScannedRow) -> IntegrityRowRef {
    IntegrityRowRef {
        row_kind: match row.kind() {
            revisions::IntegrityRowKind::Revision => IntegrityRowKind::Revision,
            revisions::IntegrityRowKind::ActivePointer => IntegrityRowKind::ActivePointer,
        },
        principal: row.principal.clone(),
        revision_id: row.revision_id().to_string(),
        content_hash: row.fingerprint.clone(),
    }
}

/// The same row whatever it holds now: a pointer is identified by its
/// principal alone, a revision by its id under its principal.
#[must_use]
pub fn same_row(a: &IntegrityRowRef, b: &IntegrityRowRef) -> bool {
    a.row_kind == b.row_kind
        && a.principal == b.principal
        && (a.row_kind == IntegrityRowKind::ActivePointer || a.revision_id == b.revision_id)
}

#[must_use]
pub fn row_dto(row: &ScannedRow) -> UnverifiedRowDto {
    let (created_at, source, status, rule_count) = match &row.content {
        ScannedContent::Revision(r) => (
            r.created_at,
            Some(r.source.as_slug().to_string()),
            Some(r.status.as_slug().to_string()),
            // Unparseable content is shown without a count rather than as zero.
            nrr_shared::rules_json::from_canonical_string(&r.rules_json)
                .is_ok()
                .then(|| {
                    let n = nrr_shared::rules_json::user_rule_count(&r.rules_json);
                    u32::try_from(n).unwrap_or(u32::MAX)
                }),
        ),
        ScannedContent::Pointer(p) => (p.activated_at, None, None, None),
    };
    UnverifiedRowDto {
        row: row_ref(row),
        baseline: row.principal == nrr_storage::BASELINE_PRINCIPAL,
        created_at,
        source,
        status,
        rule_count,
    }
}

/// The storage request for a scoped row, carrying the content it was shown with.
#[must_use]
pub fn adoption_request(row: &ScannedRow) -> AdoptionRequest<'_> {
    AdoptionRequest {
        kind: row.kind(),
        principal: &row.principal,
        revision_id: row.revision_id(),
        fingerprint: &row.fingerprint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(id: String, kind: AuditEventKind) -> SecurityAlert {
        SecurityAlert {
            alert_id: id,
            kind: kind.as_str().to_owned(),
            state: SecurityAlertState::Active,
            raised_event_seq: 0,
            raised_file: String::new(),
            ack_event_seq: None,
            ack_file: None,
            resolved_event_seq: None,
            resolved_file: None,
            created_at: 0,
            updated_at: 0,
            reason_code: String::new(),
        }
    }

    #[test]
    fn an_alert_names_the_row_its_id_was_made_from() {
        let refused = alert(
            untrusted_revision_alert_id("rev-7"),
            AuditEventKind::UntrustedRevisionRejected,
        );
        assert_eq!(alert_row(&refused), Some(AlertRow::Revision("rev-7")));
        let pointer = alert(
            format!("{TAMPER_ALERT_PREFIX}{POINTER_LABEL_PREFIX}unix:uid:1000@ab12"),
            AuditEventKind::DbTamperDetected,
        );
        assert_eq!(
            alert_row(&pointer),
            Some(AlertRow::Pointer("unix:uid:1000"))
        );
        let revision = alert(
            format!("{TAMPER_ALERT_PREFIX}rev-9@ab12"),
            AuditEventKind::DbTamperDetected,
        );
        assert_eq!(alert_row(&revision), Some(AlertRow::Revision("rev-9")));
        let key_reset = alert(
            "alt-keyreset-1".into(),
            AuditEventKind::KeyResetWithExistingData,
        );
        assert_eq!(alert_row(&key_reset), None);
    }
}
