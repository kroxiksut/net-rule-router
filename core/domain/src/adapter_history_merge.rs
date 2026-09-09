//! When one connection's traffic history should continue as another's.
//!
//! A connection the user renames, or a client that recreates its adapter on
//! update, arrives in the ledger as a NEW key while the old one goes quiet. The
//! per-day totals then split: yesterday under one key, today under another,
//! with nothing on screen saying why.
//!
//! Merging them automatically is not available, and a setting is worse than
//! either. A setting has to be turned on BEFORE the event, by someone who knows
//! it is coming; left on, it would eventually join two connections that have
//! nothing to do with each other — "swiftvpn v2 became v3" and "I replaced
//! swiftvpn with amnezia" look identical from inside the ledger. So this
//! module produces a QUESTION, once, at the moment there is evidence for it,
//! and nothing is joined until the user answers.
//!
//! What counts as evidence is deliberately narrow:
//!
//! - a key appeared, and another stopped being seen, close enough together to
//!   read as a handover rather than a coincidence;
//! - the one that stopped has been quiet long enough to be gone rather than
//!   briefly down;
//! - the two names share a word that means something.
//!
//! The names RANK the offer, they do not decide it. Two connections with
//! nothing in common produce no question at all — an unprompted "are these the
//! same adapter?" about two unrelated links is noise, and answering it wrong is
//! worse than the split it was trying to fix.
//!
//! Pure and I/O-free: the caller supplies the sightings, the decisions already
//! made and the clock.

use std::collections::HashSet;

/// How far apart "the old one went quiet" and "the new one appeared" may be and
/// still read as one handover.
///
/// Generous on purpose: the ledger is flushed on an interval measured in tens
/// of seconds, so the two events are already coarse when they arrive here.
pub const DEFAULT_HANDOVER_MS: u64 = 10 * 60 * 1000;

/// How long the old key must have been silent before it is treated as gone.
///
/// An adapter that drops for a minute and returns is not a handover, and asking
/// about one would train the user to dismiss the question.
pub const DEFAULT_SILENT_FOR_MS: u64 = 60 * 60 * 1000;

/// Shortest word that can carry a connection's identity. Below this, a shared
/// token is a coincidence between two abbreviations.
const MIN_TOKEN_LEN: usize = 3;

/// Words that appear in connection names without saying WHICH connection it is.
///
/// Deliberately a short, human-auditable list: every entry here is a word two
/// unrelated adapters routinely share, and a missing entry costs at most one
/// question the user declines. An over-long list costs the opposite — a real
/// handover that never gets offered.
const GENERIC_TOKENS: &[&str] = &[
    "adapter",
    "area",
    "bridge",
    "client",
    "connection",
    "default",
    "ethernet",
    "interface",
    "ipv4",
    "ipv6",
    "lan",
    "link",
    "local",
    "miniport",
    "net",
    "network",
    "switch",
    "tap",
    "tun",
    "tunnel",
    "virtual",
    "vpn",
    "wan",
    "wifi",
    "windows",
    "wireless",
];

/// One key the traffic ledger holds, with when it was seen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerKeySighting {
    /// The ledger's own key — whatever identity the ledger is keyed on. This
    /// module never interprets it.
    pub key: String,
    /// The name a person would recognise, used only for ranking.
    pub display_name: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

/// The one question worth asking right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeProposal {
    /// The key that went quiet — the history that would be continued.
    pub old_key: String,
    /// The key that appeared — where the history would continue.
    pub new_key: String,
    /// The word the two names share, so the question can say WHY it is being
    /// asked rather than presenting a bare pair of names.
    pub shared_token: String,
}

/// Timing bounds, injectable so a test can cross them without sleeping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeTiming {
    pub handover_ms: u64,
    pub silent_for_ms: u64,
}

impl Default for MergeTiming {
    fn default() -> Self {
        Self {
            handover_ms: DEFAULT_HANDOVER_MS,
            silent_for_ms: DEFAULT_SILENT_FOR_MS,
        }
    }
}

/// Propose at most ONE merge, or nothing.
///
/// One rather than a list: a question the user has to work through as a queue
/// stops being a question and becomes a chore, and the answer to the first one
/// changes what the ledger looks like for the rest.
///
/// `decided` holds the pairs already answered — either way. A pair the user
/// refused must never come back; a pair they accepted has already been joined.
#[must_use]
pub fn propose_merge(
    sightings: &[LedgerKeySighting],
    decided: &[(String, String)],
    now_ms: u64,
    timing: MergeTiming,
) -> Option<MergeProposal> {
    let mut best: Option<(MergeProposal, usize, u64)> = None;
    for new in sightings {
        // The successor has to still be here. A key that appeared and also went
        // quiet is not where anything should be continued.
        if now_ms.saturating_sub(new.last_seen_ms) > timing.silent_for_ms {
            continue;
        }
        for old in sightings {
            if old.key == new.key {
                continue;
            }
            // The predecessor has to be gone, and gone since before the
            // successor arrived — otherwise the two simply coexist.
            if now_ms.saturating_sub(old.last_seen_ms) < timing.silent_for_ms {
                continue;
            }
            if old.last_seen_ms > new.first_seen_ms {
                continue;
            }
            if new.first_seen_ms.saturating_sub(old.last_seen_ms) > timing.handover_ms {
                continue;
            }
            if is_decided(decided, &old.key, &new.key) {
                continue;
            }
            let Some(token) = shared_token(&old.display_name, &new.display_name) else {
                continue;
            };
            let gap = new.first_seen_ms.saturating_sub(old.last_seen_ms);
            let strength = token.len();
            let better = match &best {
                // A longer shared word is stronger evidence than a closer
                // handover: two adapters can go quiet and appear within the same
                // minute by accident, but they do not share a long word by
                // accident.
                Some((_, best_strength, best_gap)) => {
                    strength > *best_strength || (strength == *best_strength && gap < *best_gap)
                }
                None => true,
            };
            if better {
                best = Some((
                    MergeProposal {
                        old_key: old.key.clone(),
                        new_key: new.key.clone(),
                        shared_token: token,
                    },
                    strength,
                    gap,
                ));
            }
        }
    }
    best.map(|(proposal, _, _)| proposal)
}

/// Whether this pair has already been put to the user, in either direction.
fn is_decided(decided: &[(String, String)], old_key: &str, new_key: &str) -> bool {
    decided
        .iter()
        .any(|(a, b)| (a == old_key && b == new_key) || (a == new_key && b == old_key))
}

/// The longest meaningful word two connection names share, or `None`.
///
/// `None` is the answer that matters most: it is what stops the app asking
/// whether an unrelated pair of connections is the same thing.
#[must_use]
pub fn shared_token(left: &str, right: &str) -> Option<String> {
    let right_tokens: HashSet<String> = meaningful_tokens(right).into_iter().collect();
    meaningful_tokens(left)
        .into_iter()
        .filter(|t| right_tokens.contains(t))
        .max_by_key(String::len)
}

/// Words in a connection name that could identify it.
fn meaningful_tokens(name: &str) -> Vec<String> {
    name.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= MIN_TOKEN_LEN)
        // A version number is the very thing that CHANGES between the two names
        // ("client v2" / "client v3"), so it can never be the word that ties
        // them together.
        .filter(|t| t.chars().any(|c| c.is_ascii_alphabetic()))
        .filter(|t| !t.chars().all(|c| c.is_ascii_digit()))
        .filter(|t| !GENERIC_TOKENS.contains(t))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 60 * 60 * 1000;

    fn sighting(key: &str, name: &str, first: u64, last: u64) -> LedgerKeySighting {
        LedgerKeySighting {
            key: key.to_string(),
            display_name: name.to_string(),
            first_seen_ms: first,
            last_seen_ms: last,
        }
    }

    /// The case the whole module exists for, in the owner's words: v2 became
    /// v3, and it is the same channel.
    #[test]
    fn a_version_bump_of_the_same_client_is_offered() {
        let now = 10 * HOUR;
        let keys = vec![
            sighting("old", "swiftvpn v2", 0, 5 * HOUR),
            sighting("new", "swiftvpn v3", 5 * HOUR + 1000, now),
        ];
        let proposal = propose_merge(&keys, &[], now, MergeTiming::default())
            .expect("a handover between two names sharing a word must be offered");
        assert_eq!(proposal.old_key, "old");
        assert_eq!(proposal.new_key, "new");
        assert_eq!(proposal.shared_token, "swiftvpn");
    }

    /// The other half of the same sentence: a different product is not the same
    /// channel, and must not even be asked about.
    #[test]
    fn a_replacement_by_a_different_product_is_never_offered() {
        let now = 10 * HOUR;
        let keys = vec![
            sighting("old", "swiftvpn", 0, 5 * HOUR),
            sighting("new", "amnezia", 5 * HOUR + 1000, now),
        ];
        assert_eq!(propose_merge(&keys, &[], now, MergeTiming::default()), None);
    }

    #[test]
    fn a_generic_word_is_not_a_shared_name() {
        // Two unrelated links both called "… VPN Tunnel" share only words that
        // say nothing about WHICH connection either is.
        let now = 10 * HOUR;
        let keys = vec![
            sighting("old", "Work VPN Tunnel", 0, 5 * HOUR),
            sighting("new", "Home VPN Tunnel", 5 * HOUR + 1000, now),
        ];
        assert_eq!(propose_merge(&keys, &[], now, MergeTiming::default()), None);
    }

    #[test]
    fn a_connection_that_is_still_live_is_not_a_predecessor() {
        // Both seen up to now: they coexist, nothing was handed over.
        let now = 10 * HOUR;
        let keys = vec![
            sighting("old", "swiftvpn v2", 0, now),
            sighting("new", "swiftvpn v3", 5 * HOUR, now),
        ];
        assert_eq!(propose_merge(&keys, &[], now, MergeTiming::default()), None);
    }

    #[test]
    fn a_brief_outage_is_not_a_handover() {
        // The old key went quiet ten minutes ago — that is an adapter bouncing,
        // not one being replaced.
        let now = 10 * HOUR;
        let keys = vec![
            sighting("old", "swiftvpn v2", 0, now - 10 * 60 * 1000),
            sighting("new", "swiftvpn v3", now - 9 * 60 * 1000, now),
        ];
        assert_eq!(propose_merge(&keys, &[], now, MergeTiming::default()), None);
    }

    #[test]
    fn an_appearance_long_after_the_disappearance_is_not_a_handover() {
        let now = 10 * HOUR;
        let keys = vec![
            sighting("old", "swiftvpn v2", 0, HOUR),
            sighting("new", "swiftvpn v3", 5 * HOUR, now),
        ];
        assert_eq!(propose_merge(&keys, &[], now, MergeTiming::default()), None);
    }

    #[test]
    fn a_pair_already_answered_never_comes_back() {
        let now = 10 * HOUR;
        let keys = vec![
            sighting("old", "swiftvpn v2", 0, 5 * HOUR),
            sighting("new", "swiftvpn v3", 5 * HOUR + 1000, now),
        ];
        let decided = vec![("new".to_string(), "old".to_string())];
        assert_eq!(
            propose_merge(&keys, &decided, now, MergeTiming::default()),
            None,
            "the pair was answered in the other order and must still count as answered"
        );
    }

    #[test]
    fn the_longer_shared_word_wins_over_the_closer_handover() {
        let now = 10 * HOUR;
        let keys = vec![
            // Closer in time, but the shared word is short.
            sighting("near", "acme link", 0, 5 * HOUR),
            // Further away, but unmistakably the same product.
            sighting("far", "swiftvpn v2", 0, 5 * HOUR - 60_000),
            sighting("new", "swiftvpn v3 acme", 5 * HOUR + 1000, now),
        ];
        let proposal = propose_merge(&keys, &[], now, MergeTiming::default()).expect("a proposal");
        assert_eq!(proposal.old_key, "far");
        assert_eq!(proposal.shared_token, "swiftvpn");
    }

    #[test]
    fn a_version_number_is_never_the_shared_word() {
        // `v2`/`v3` is what CHANGED; if a number could tie two names together,
        // every "Ethernet 2" would be kin to every other.
        assert_eq!(shared_token("client 2", "server 2"), None);
    }

    #[test]
    fn only_one_question_is_produced_at_a_time() {
        let now = 10 * HOUR;
        let keys = vec![
            sighting("old-a", "alpha link", 0, 5 * HOUR),
            sighting("new-a", "alpha link v2", 5 * HOUR + 1000, now),
            sighting("old-b", "bravo link", 0, 5 * HOUR),
            sighting("new-b", "bravo link v2", 5 * HOUR + 1000, now),
        ];
        let proposal = propose_merge(&keys, &[], now, MergeTiming::default());
        assert!(proposal.is_some(), "one of the two must be offered");
    }
}
