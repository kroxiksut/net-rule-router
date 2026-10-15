//! The one summary of blocks the service kept while no NetRuleRouter surface
//! was open (`blockNoticeBacklog` in `pure.js`).

use nrr_shared::ipc_payloads::BlockNoticeJournalEntryDto;

/// How many destinations the summary names before "and N more".
pub const SHOWN: usize = 5;

/// What the summary says and how far the backlog is acknowledged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BacklogSummary {
    /// Every backlog entry, repeats of one destination included.
    pub count: usize,
    /// The largest id read: the acknowledgement covers exactly these, so an
    /// entry raised while the list was in flight is kept for next time.
    pub through_id: i64,
    /// The first [`SHOWN`] distinct destinations, oldest first.
    pub shown: Vec<String>,
    /// Distinct destinations not named.
    pub more: usize,
}

/// The summary for `entries` in the service's order; `None` when there are
/// none.
pub fn backlog_summary(entries: &[BlockNoticeJournalEntryDto]) -> Option<BacklogSummary> {
    if entries.is_empty() {
        return None;
    }
    let mut destinations: Vec<&str> = Vec::new();
    for entry in entries {
        let destination = entry.destination.as_str();
        if !destination.is_empty() && !destinations.contains(&destination) {
            destinations.push(destination);
        }
    }
    Some(BacklogSummary {
        count: entries.len(),
        through_id: entries.iter().map(|e| e.id).fold(0, i64::max),
        shown: destinations
            .iter()
            .take(SHOWN)
            .map(|d| (*d).to_owned())
            .collect(),
        more: destinations.len().saturating_sub(SHOWN),
    })
}
