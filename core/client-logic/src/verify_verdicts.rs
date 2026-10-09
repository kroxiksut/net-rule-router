//! The one notice for the user's `?` rules that work only on the other route
//! (`verifyVerdictNotice` in `pure.js`).

use nrr_shared::ipc_payloads::VerifyVerdictDto;

/// How many values the notice names before "and N more".
pub const SHOWN: usize = 5;

/// What the notice says and what its buttons act on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerdictNotice {
    /// Every verdict still waiting for an answer: what "Move" and "Not now"
    /// act on.
    pub rule_ids: Vec<String>,
    /// The first [`SHOWN`] of them as (value, route it would move to).
    pub shown: Vec<(String, String)>,
    /// How many are not named.
    pub more: usize,
}

/// The notice for `verdicts`, in the service's order; `None` when nothing
/// waits — a set-aside verdict is answered.
pub fn verdict_notice(verdicts: &[VerifyVerdictDto]) -> Option<VerdictNotice> {
    let pending: Vec<&VerifyVerdictDto> = verdicts.iter().filter(|v| !v.dismissed).collect();
    if pending.is_empty() {
        return None;
    }
    Some(VerdictNotice {
        rule_ids: pending.iter().map(|v| v.rule_id.clone()).collect(),
        shown: pending
            .iter()
            .take(SHOWN)
            .map(|v| (v.value.clone(), v.to_route.clone()))
            .collect(),
        more: pending.len().saturating_sub(SHOWN),
    })
}
