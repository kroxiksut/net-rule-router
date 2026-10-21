//! How the diagnostics page reads the service's answers: whether a
//! `snapshot.diagnostics.get` status carries a usable alert list, whether an
//! acknowledgement took, and when the user hears their saved rules do not
//! read.

use serde_json::Value;

use crate::js;

/// One security alert as the diagnostics page lists it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AlertItem {
    pub alert_id: String,
    pub kind: String,
    pub state: String,
    pub reason_code: String,
    pub raised_file: String,
    pub requires_action: bool,
}

/// `String(value[key] || "")`.
fn member_text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .filter(|v| js::is_truthy(v))
        .map(js::to_display_string)
        .unwrap_or_default()
}

fn is_true(value: &Value, key: &str) -> bool {
    value.get(key) == Some(&Value::Bool(true))
}

/// What the service's `policy` health message opens with while a stored rule
/// book cannot be read (`RULES_BOOK_UNREADABLE` in `nrr-shared`).
pub const RULES_BOOK_UNREADABLE: &str = nrr_shared::ipc_payloads::RULES_BOOK_UNREADABLE;

/// Whether a health answer says a stored rule book could not be read, so the
/// last applied rules stay in force (`rulesBookUnreadable`).
pub fn rules_book_unreadable(health: &Value) -> bool {
    let Some(Value::Array(components)) = health.get("components") else {
        return false;
    };
    components.iter().any(|component| {
        component.get("component") == Some(&Value::String("policy".to_owned()))
            && component
                .get("message")
                .filter(|m| js::is_truthy(m))
                .is_some_and(|m| js::to_display_string(m).starts_with(RULES_BOOK_UNREADABLE))
    })
}

/// One reading of whether the user's own stored rule book cannot be read,
/// from its push or the snapshot: raise the notice when the state appears;
/// while it lasts, a dismissed notice stays down; once the book reads again,
/// the next occurrence is news (`rulesBookNoticeStep`).
pub fn rules_book_notice_step(was_raised: bool, unreadable: bool) -> crate::system_dns::NoticeStep {
    crate::system_dns::notice_step(was_raised, unreadable)
}

/// Whether the status is the service saying it could not read its alert store
/// (`securityAlertsUnreadable`), as opposed to no answer at all.
pub fn security_alerts_unreadable(status: &Value) -> bool {
    if !js::is_truthy(status) || is_true(status, "stale") {
        return false;
    }
    match status.get("security_status") {
        Some(security) if js::is_truthy(security) => !is_true(security, "alerts_readable"),
        _ => true,
    }
}

/// The alert list of a status (`securityAlertItemsFromStatus`); `None` when
/// the status is no answer, or the store was unreadable: an empty list from a
/// failed read must not clear the alerts shown.
pub fn security_alert_items(status: &Value) -> Option<Vec<AlertItem>> {
    if !js::is_truthy(status) || is_true(status, "stale") || security_alerts_unreadable(status) {
        return None;
    }
    let alerts = status.get("active_alerts").filter(|a| js::is_truthy(a))?;
    let entries: Vec<Value> = match alerts {
        Value::Array(items) => items.clone(),
        // A string has a length: each of its UTF-16 units is a truthy entry.
        Value::String(s) => vec![Value::String("x".to_owned()); s.encode_utf16().count()],
        Value::Object(map) => {
            let Some(Value::Number(length)) = map.get("length") else {
                return None;
            };
            let length = length.as_f64().unwrap_or(f64::NAN);
            let mut indexed: Vec<(u64, Value)> = map
                .iter()
                .filter_map(|(key, value)| {
                    let canonical = key == "0" || (!key.starts_with('0') && !key.is_empty());
                    let index = key.parse::<u64>().ok().filter(|_| canonical)?;
                    ((index as f64) < length).then(|| (index, value.clone()))
                })
                .collect();
            indexed.sort_by_key(|(index, _)| *index);
            indexed.into_iter().map(|(_, value)| value).collect()
        }
        _ => return None,
    };
    Some(
        entries
            .iter()
            .filter(|a| js::is_truthy(a))
            .map(|a| AlertItem {
                alert_id: member_text(a, "alert_id"),
                kind: member_text(a, "kind"),
                state: member_text(a, "state"),
                reason_code: member_text(a, "reason_code"),
                raised_file: member_text(a, "raised_file"),
                requires_action: is_true(a, "requires_action"),
            })
            .collect(),
    )
}

/// Verdict on an acknowledgement from a fresh status (`alertAckOutcome`): ""
/// once `alert_id` is no longer active, "unknown" while it still is, and
/// `failure_code` (or "unknown") when the answer holds no readable list.
pub fn alert_ack_outcome(status: &Value, alert_id: &str, failure_code: &str) -> String {
    let Some(alerts) = security_alert_items(status) else {
        return if failure_code.is_empty() {
            "unknown".to_owned()
        } else {
            failure_code.to_owned()
        };
    };
    if alerts
        .iter()
        .any(|a| a.alert_id == alert_id && a.state == "active")
    {
        "unknown".to_owned()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_unreadable_store_is_not_an_empty_list() {
        let status = json!({ "stale": false, "security_status": { "alerts_readable": false },
            "active_alerts": [] });
        assert!(security_alerts_unreadable(&status));
        assert_eq!(security_alert_items(&status), None);
        assert_eq!(alert_ack_outcome(&status, "a", ""), "unknown");
    }
}
