//! "Don't show" for the application-rule notice, remembered per program and
//! per problem: a program that was not found and later is found but routes
//! nothing has a new problem, which is told once anew.
//!
//! The acknowledgement is one `|`-joined line of entries `<state>:<program>`.
//! An entry without a known state was written before states existed, when the
//! only problem the notice told was a program that was not found.

/// The program was not found, so its rule is not applied.
pub const NOT_FOUND: &str = "not-found";
/// The program was found, but its rule routes none of its traffic.
pub const UNROUTED: &str = "unrouted";

/// One acknowledged `(state, program)`, legacy entries read as not found.
fn entry_of(token: &str) -> String {
    for state in [NOT_FOUND, UNROUTED] {
        if token
            .strip_prefix(state)
            .is_some_and(|rest| rest.starts_with(':'))
        {
            return token.to_owned();
        }
    }
    format!("{NOT_FOUND}:{token}")
}

fn acknowledged(ack: &str) -> Vec<String> {
    ack.split('|')
        .filter(|token| !token.is_empty())
        .map(entry_of)
        .collect()
}

/// The notice's current problems as acknowledgement entries.
fn current(not_found: &[String], unrouted: &[String]) -> Vec<String> {
    not_found
        .iter()
        .map(|app| format!("{NOT_FOUND}:{app}"))
        .chain(unrouted.iter().map(|app| format!("{UNROUTED}:{app}")))
        .collect()
}

/// Whether every current problem was acknowledged before
/// (`appNoticeCoveredByAck`). Nothing acknowledged covers nothing.
#[must_use]
pub fn app_notice_covered_by_ack(ack: &str, not_found: &[String], unrouted: &[String]) -> bool {
    let acked = acknowledged(ack);
    if acked.is_empty() {
        return false;
    }
    current(not_found, unrouted)
        .iter()
        .all(|entry| acked.contains(entry))
}

/// The acknowledgement after "Don't show": what was acknowledged before, in
/// the current spelling, and every current problem, sorted
/// (`appNoticeAckUnion`). A program that comes and goes stays acknowledged
/// for the problem it was acknowledged for.
#[must_use]
pub fn app_notice_ack_union(ack: &str, not_found: &[String], unrouted: &[String]) -> String {
    let mut all = acknowledged(ack);
    all.extend(current(not_found, unrouted));
    all.sort();
    all.dedup();
    all.join("|")
}
