//! What a safe-rollback dry run answered (`rollbackDryRunVerdict` in `pure.js`).

use nrr_shared::ipc_payloads::RollbackTargetDto;
use serde_json::Value;

/// Where the rollback dialog or row stands after the dry run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RollbackPhase {
    /// A target and the token that restores it.
    Ready,
    /// Nothing earlier to go back to.
    None,
    /// `code` says why not.
    Error,
}

impl RollbackPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::None => "none",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackVerdict {
    pub phase: RollbackPhase,
    pub token: String,
    pub target: Option<RollbackTargetDto>,
    /// The error code of an `Error` phase; empty otherwise.
    pub code: String,
}

impl RollbackVerdict {
    fn error(code: &str) -> Self {
        Self {
            phase: RollbackPhase::Error,
            token: String::new(),
            target: None,
            code: code.to_owned(),
        }
    }
}

fn text_or_unknown(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => "unknown".to_owned(),
    }
}

/// The verdict on a dry-run call: `ok` is whether the call went through,
/// `answer` its payload, `code` the failure code when it did not.
pub fn rollback_verdict(ok: bool, answer: &Value, code: Option<&str>) -> RollbackVerdict {
    if !ok {
        return RollbackVerdict::error(code.filter(|c| !c.is_empty()).unwrap_or("unknown"));
    }
    if let Some(error) = answer.get("error").filter(|e| !e.is_null()) {
        return RollbackVerdict::error(&text_or_unknown(error.get("code")));
    }
    let token = answer
        .get("confirmation-token")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let target = answer.get("target").filter(|t| !t.is_null());
    match (token.is_empty(), target) {
        (false, Some(target)) => {
            match serde_json::from_value::<RollbackTargetDto>(target.clone()) {
                Ok(target) => RollbackVerdict {
                    phase: RollbackPhase::Ready,
                    token: token.to_owned(),
                    target: Some(target),
                    code: String::new(),
                },
                Err(_) => RollbackVerdict::error("bad-response"),
            }
        }
        (true, None) => RollbackVerdict {
            phase: RollbackPhase::None,
            token: String::new(),
            target: None,
            code: String::new(),
        },
        _ => RollbackVerdict::error("bad-response"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_target_with_its_token_is_ready() {
        let v = rollback_verdict(
            true,
            &json!({"confirmation-token": "t", "target": {"revision-id": "r", "activated-at": 5, "rule-count": 3}}),
            None,
        );
        assert_eq!(v.phase, RollbackPhase::Ready);
        assert_eq!(v.token, "t");
        assert_eq!(v.target.map(|t| t.rule_count), Some(3));
    }

    #[test]
    fn neither_token_nor_target_is_nothing_to_roll_back_to() {
        let v = rollback_verdict(true, &json!({}), None);
        assert_eq!(v.phase, RollbackPhase::None);
    }

    #[test]
    fn a_token_without_a_target_is_a_bad_response() {
        let v = rollback_verdict(true, &json!({"confirmation-token": "t"}), None);
        assert_eq!(
            (v.phase, v.code.as_str()),
            (RollbackPhase::Error, "bad-response")
        );
    }

    #[test]
    fn a_failed_call_keeps_its_code() {
        assert_eq!(
            rollback_verdict(false, &Value::Null, Some("forbidden")).code,
            "forbidden"
        );
        assert_eq!(rollback_verdict(false, &Value::Null, None).code, "unknown");
    }
}
