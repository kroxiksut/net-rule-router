//! Who may read a security alert.
//!
//! An alert about the key, the audit trail or the check itself concerns the
//! whole machine. One about a principal's stored rules is that principal's and
//! an administrator's: its id can carry the SID, and even without one it tells
//! another user what someone else's rules went through. The edit gate it
//! trips stays machine-wide — rewriting the service database takes
//! administrator rights — so another user is still told an alert holds their
//! edits, through one entry that names nobody.

use nrr_diagnostics::audit::alert::{SecurityAlert, SecurityAlertState};
use nrr_diagnostics::facade::dto::DiagnosticsAudience;

use crate::integrity_review::{alert_row, AlertRow};

pub use nrr_shared::diagnostics_dto::OTHER_PRINCIPAL_ALERT_ID;

/// Kind of the [`OTHER_PRINCIPAL_ALERT_ID`] entry; the GUI names it through
/// `diag.alert.kind.*`.
pub const OTHER_PRINCIPAL_ALERT_KIND: &str = "integrity_alert_other_principal";

/// The principal whose rules `alert` is about; `None` for a machine alert and
/// for the shared baseline, which every user reads through.
///
/// A revision whose owner cannot be read back — its row gone — is treated as
/// the machine's: its id names no one, and hiding it could leave a user unable
/// to see what holds their edits.
pub fn alert_principal(
    alert: &SecurityAlert,
    principal_of_revision: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    let principal = match alert_row(alert)? {
        AlertRow::Pointer(principal) => principal.to_owned(),
        AlertRow::Revision(revision_id) => principal_of_revision(revision_id)?,
    };
    (principal != nrr_storage::BASELINE_PRINCIPAL).then_some(principal)
}

/// `alerts` as `audience` may see them, order kept. Another principal's open
/// alerts collapse into one [`OTHER_PRINCIPAL_ALERT_ID`] entry where the first
/// of them stood; their closed ones are dropped.
pub fn scope_alerts(
    alerts: Vec<SecurityAlert>,
    audience: &DiagnosticsAudience,
    principal_of_revision: &dyn Fn(&str) -> Option<String>,
) -> Vec<SecurityAlert> {
    let Some(caller) = audience.principal() else {
        return alerts;
    };
    let mut visible = Vec::with_capacity(alerts.len());
    let mut stand_in: Option<(usize, SecurityAlert)> = None;
    for alert in alerts {
        match alert_principal(&alert, principal_of_revision) {
            Some(owner) if owner != caller => {
                if !alert.state.is_open() {
                    continue;
                }
                match stand_in.as_mut() {
                    Some((_, merged)) => absorb(merged, &alert),
                    None => stand_in = Some((visible.len(), stand_in_for(&alert))),
                }
            }
            _ => visible.push(alert),
        }
    }
    if let Some((at, merged)) = stand_in {
        visible.insert(at, merged);
    }
    visible
}

fn stand_in_for(alert: &SecurityAlert) -> SecurityAlert {
    SecurityAlert {
        alert_id: OTHER_PRINCIPAL_ALERT_ID.to_owned(),
        kind: OTHER_PRINCIPAL_ALERT_KIND.to_owned(),
        state: alert.state,
        raised_event_seq: 0,
        raised_file: String::new(),
        ack_event_seq: None,
        ack_file: None,
        resolved_event_seq: None,
        resolved_file: None,
        created_at: alert.created_at,
        updated_at: alert.updated_at,
        reason_code: alert.reason_code.clone(),
    }
}

/// Active wins: one unacknowledged alert is what holds the edits.
fn absorb(merged: &mut SecurityAlert, alert: &SecurityAlert) {
    if alert.state == SecurityAlertState::Active && merged.state != SecurityAlertState::Active {
        merged.state = SecurityAlertState::Active;
        merged.reason_code.clone_from(&alert.reason_code);
    }
    merged.created_at = merged.created_at.min(alert.created_at);
    merged.updated_at = merged.updated_at.max(alert.updated_at);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const ALICE: &str = "S-1-5-21-1000-1000-1000-1001";
    const BOB: &str = "S-1-5-21-1000-1000-1000-1002";

    fn alert(id: &str, kind: &str, state: SecurityAlertState, at: i64) -> SecurityAlert {
        SecurityAlert {
            alert_id: id.into(),
            kind: kind.into(),
            state,
            raised_event_seq: 0,
            raised_file: "bootstrap".into(),
            ack_event_seq: None,
            ack_file: None,
            resolved_event_seq: None,
            resolved_file: None,
            created_at: at,
            updated_at: at,
            reason_code: "integrity.db_row_hmac_mismatch".into(),
        }
    }

    fn pointer(principal: &str, state: SecurityAlertState, at: i64) -> SecurityAlert {
        alert(
            &format!("alt-dbtamper-pointer:{principal}@abc123"),
            "db_tamper_detected",
            state,
            at,
        )
    }

    fn owners(revision_id: &str) -> Option<String> {
        match revision_id {
            "rev-alice" => Some(ALICE.into()),
            "rev-bob" => Some(BOB.into()),
            "rev-base" => Some(nrr_storage::BASELINE_PRINCIPAL.into()),
            _ => None,
        }
    }

    fn book() -> Vec<SecurityAlert> {
        vec![
            alert(
                "alt-keyreset-1",
                "key_reset_with_existing_data",
                SecurityAlertState::Active,
                10,
            ),
            pointer(BOB, SecurityAlertState::Acknowledged, 20),
            alert(
                "alt-dbtamper-rev-alice@f1",
                "db_tamper_detected",
                SecurityAlertState::Active,
                30,
            ),
            alert(
                "alt-revintegrity-rev-bob",
                "untrusted_revision_rejected",
                SecurityAlertState::Active,
                40,
            ),
            pointer(ALICE, SecurityAlertState::Active, 50),
            alert(
                "alt-dbtamper-rev-base@f2",
                "db_tamper_detected",
                SecurityAlertState::Active,
                60,
            ),
        ]
    }

    fn ids(alerts: &[SecurityAlert]) -> Vec<&str> {
        alerts.iter().map(|a| a.alert_id.as_str()).collect()
    }

    #[test]
    fn an_administrator_sees_every_alert_as_stored() {
        let all = scope_alerts(book(), &DiagnosticsAudience::Machine, &owners);
        assert_eq!(ids(&all), ids(&book()));
    }

    #[test]
    fn a_user_sees_machine_alerts_their_own_and_one_entry_for_the_rest() {
        let seen = scope_alerts(
            book(),
            &DiagnosticsAudience::Principal(ALICE.into()),
            &owners,
        );
        assert_eq!(
            ids(&seen),
            [
                "alt-keyreset-1",
                OTHER_PRINCIPAL_ALERT_ID,
                "alt-dbtamper-rev-alice@f1",
                &format!("alt-dbtamper-pointer:{ALICE}@abc123"),
                "alt-dbtamper-rev-base@f2",
            ]
        );
        let stand_in = &seen[1];
        assert_eq!(stand_in.kind, OTHER_PRINCIPAL_ALERT_KIND);
        assert_eq!(
            stand_in.state,
            SecurityAlertState::Active,
            "one unacknowledged alert of Bob's holds Alice's edits too"
        );
        assert_eq!((stand_in.created_at, stand_in.updated_at), (20, 40));
        let wire = serde_json::to_string(&seen).unwrap();
        assert!(!wire.contains(BOB), "{wire}");
        assert!(!wire.contains("rev-bob"), "{wire}");
    }

    #[test]
    fn another_users_closed_alerts_are_not_shown_at_all() {
        let resolved = vec![
            pointer(BOB, SecurityAlertState::Resolved, 1),
            pointer(BOB, SecurityAlertState::Superseded, 2),
        ];
        assert!(scope_alerts(
            resolved,
            &DiagnosticsAudience::Principal(ALICE.into()),
            &owners
        )
        .is_empty());
        let acknowledged = scope_alerts(
            vec![pointer(BOB, SecurityAlertState::Acknowledged, 1)],
            &DiagnosticsAudience::Principal(ALICE.into()),
            &owners,
        );
        assert_eq!(ids(&acknowledged), [OTHER_PRINCIPAL_ALERT_ID]);
        assert_eq!(acknowledged[0].state, SecurityAlertState::Acknowledged);
    }

    #[test]
    fn the_owner_sees_their_own_alert_with_its_id() {
        let seen = scope_alerts(book(), &DiagnosticsAudience::Principal(BOB.into()), &owners);
        assert!(ids(&seen).contains(&"alt-revintegrity-rev-bob"));
        assert!(ids(&seen).contains(&format!("alt-dbtamper-pointer:{BOB}@abc123").as_str()));
        assert!(
            ids(&seen).contains(&OTHER_PRINCIPAL_ALERT_ID),
            "Alice's two"
        );
    }

    #[test]
    fn an_alert_whose_revision_is_gone_names_no_one_and_stays_visible() {
        let orphan = alert(
            "alt-dbtamper-rev-gone@f9",
            "db_tamper_detected",
            SecurityAlertState::Active,
            1,
        );
        assert_eq!(alert_principal(&orphan, &owners), None);
        let seen = scope_alerts(
            vec![orphan],
            &DiagnosticsAudience::Principal(ALICE.into()),
            &owners,
        );
        assert_eq!(ids(&seen), ["alt-dbtamper-rev-gone@f9"]);
    }
}
