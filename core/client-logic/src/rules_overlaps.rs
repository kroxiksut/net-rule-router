//! Overlaps the user made on purpose (`overlapsConfirmedByOwnEdit` in
//! `pure.js`).

use nrr_shared::rules_overlap::{RouteOverlap, RouteOverlapKind};

/// Keys of the pairs that a rule saved from the rule form settles by itself:
/// the saved rule sits inside a wider rule of the other route and wins. That
/// is how an exception is written, so asking "is this right?" again is noise.
///
/// Everything else still asks: a tie, a partial intersection, a block winning
/// a tie, and a new wide rule that swallows an older narrow one the user may
/// have forgotten.
pub fn confirmed_by_own_edit(overlaps: &[RouteOverlap], edited_rule_ids: &[&str]) -> Vec<String> {
    overlaps
        .iter()
        .filter(|o| {
            o.kind == RouteOverlapKind::Nested
                && !o.block_wins_tie
                && edited_rule_ids.contains(&o.winner.rule_id.as_str())
        })
        .map(|o| o.key.clone())
        .collect()
}

/// The pairs one rule takes part in, on either side.
pub fn overlaps_of_rule<'a>(
    overlaps: &'a [RouteOverlap],
    rule_id: &'a str,
) -> impl Iterator<Item = &'a RouteOverlap> + 'a {
    overlaps
        .iter()
        .filter(move |o| o.winner.rule_id == rule_id || o.loser.rule_id == rule_id)
}
