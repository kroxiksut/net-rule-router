//! Bounded, owner-scoped evidence for why a site did or did not earn an offer.

use std::collections::VecDeque;

pub const EPISODE_TTL_MS: i64 = 60 * 60 * 1_000;
pub const MAX_PRINCIPALS: usize = 8;
pub const MAX_EPISODES: usize = 128;
pub const MAX_STEPS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveryDecision {
    pub stage: &'static str,
    pub state: &'static str,
    pub reason: &'static str,
}

impl DiscoveryDecision {
    pub const fn new(stage: &'static str, state: &'static str, reason: &'static str) -> Self {
        Self {
            stage,
            state,
            reason,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryStep {
    pub decision: DiscoveryDecision,
    pub at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryEpisode {
    pub id: u64,
    pub host: Option<String>,
    pub destination: Option<String>,
    pub candidate_id: Option<String>,
    pub first_ms: i64,
    pub last_ms: i64,
    pub history: VecDeque<DiscoveryStep>,
}

#[derive(Default)]
struct PrincipalEpisodes {
    owner: String,
    episodes: VecDeque<DiscoveryEpisode>,
    omitted: u64,
    last_ms: i64,
    log_window_ms: i64,
    log_count: u32,
}

#[derive(Default)]
pub struct DiscoveryLedger {
    principals: Vec<PrincipalEpisodes>,
    sequence: u64,
}

impl DiscoveryLedger {
    pub fn record(
        &mut self,
        owner: &str,
        host: Option<&str>,
        destination: Option<&str>,
        decision: DiscoveryDecision,
        at_ms: i64,
    ) -> Option<u64> {
        if owner.is_empty() || owner.len() > 256 {
            return None;
        }
        let host = host.and_then(normalized_host);
        let destination = destination
            .filter(|value| {
                !value.is_empty() && value.len() <= 192 && !value.chars().any(char::is_control)
            })
            .map(str::to_owned);
        if host.is_none() && destination.is_none() {
            return None;
        }
        let at_ms = at_ms.max(0);
        self.sweep(at_ms);
        if !self.principals.iter().any(|p| p.owner == owner) {
            if self.principals.len() >= MAX_PRINCIPALS {
                if let Some(index) = self
                    .principals
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, p)| p.last_ms)
                    .map(|(index, _)| index)
                {
                    self.principals.remove(index);
                }
            }
            self.principals.push(PrincipalEpisodes {
                owner: owner.to_owned(),
                ..Default::default()
            });
        }
        let principal = self.principals.iter_mut().find(|p| p.owner == owner)?;
        principal.last_ms = at_ms;
        let existing = principal.episodes.iter().position(|episode| {
            if let Some(host) = host.as_ref() {
                episode.host.as_ref() == Some(host)
            } else {
                episode.host.is_none() && episode.destination == destination
            }
        });
        let mut episode = if let Some(index) = existing {
            principal.episodes.remove(index)?
        } else {
            let next_id = self.sequence.checked_add(1)?;
            if principal.episodes.len() >= MAX_EPISODES {
                principal.episodes.pop_front();
                principal.omitted = principal.omitted.saturating_add(1);
            }
            self.sequence = next_id;
            DiscoveryEpisode {
                id: self.sequence,
                host,
                destination: destination.clone(),
                candidate_id: None,
                first_ms: at_ms,
                last_ms: at_ms,
                history: VecDeque::new(),
            }
        };
        episode.last_ms = at_ms;
        if destination.is_some() {
            episode.destination = destination;
        }
        let changed = episode
            .history
            .back()
            .is_none_or(|step| step.decision != decision);
        if changed {
            if episode.history.len() >= MAX_STEPS {
                episode.history.pop_front();
            }
            episode.history.push_back(DiscoveryStep { decision, at_ms });
        }
        let id = episode.id;
        principal.episodes.push_back(episode);
        if at_ms < principal.log_window_ms
            || at_ms.saturating_sub(principal.log_window_ms) >= 60_000
        {
            principal.log_window_ms = at_ms;
            principal.log_count = 0;
        }
        // The in-memory history survives even when the operational log is busy.
        if changed && principal.log_count < 32 {
            principal.log_count += 1;
            Some(id)
        } else {
            None
        }
    }

    pub fn link_candidate(&mut self, owner: &str, host: &str, candidate_id: &str) {
        if candidate_id.len() > 128 {
            return;
        }
        let Some(host) = normalized_host(host) else {
            return;
        };
        if let Some(episode) = self
            .principals
            .iter_mut()
            .find(|p| p.owner == owner)
            .and_then(|p| {
                p.episodes
                    .iter_mut()
                    .find(|e| e.host.as_ref() == Some(&host))
            })
        {
            episode.candidate_id = Some(candidate_id.to_owned());
        }
    }

    pub fn forget_principal(&mut self, owner: &str) {
        self.principals.retain(|principal| principal.owner != owner);
    }

    pub fn forget_everyone(&mut self) {
        self.principals.clear();
    }

    pub fn forget_candidates(&mut self, owner: &str, mut matches: impl FnMut(&str) -> bool) {
        if let Some(principal) = self
            .principals
            .iter_mut()
            .find(|principal| principal.owner == owner)
        {
            principal
                .episodes
                .retain(|episode| episode.candidate_id.as_ref().is_none_or(|id| !matches(id)));
        }
        self.principals
            .retain(|principal| !principal.episodes.is_empty());
    }

    pub fn snapshot(
        &mut self,
        owner: &str,
        at_ms: i64,
        limit: usize,
    ) -> (Vec<DiscoveryEpisode>, u64) {
        self.sweep(at_ms.max(0));
        let Some(principal) = self.principals.iter().find(|p| p.owner == owner) else {
            return (Vec::new(), 0);
        };
        let count = principal.episodes.len().min(limit.min(MAX_EPISODES));
        (
            principal
                .episodes
                .iter()
                .rev()
                .take(count)
                .cloned()
                .collect(),
            principal
                .omitted
                .saturating_add(principal.episodes.len().saturating_sub(count) as u64),
        )
    }

    fn sweep(&mut self, now: i64) {
        for principal in &mut self.principals {
            principal.episodes.retain(|episode| {
                now >= episode.last_ms && now.saturating_sub(episode.last_ms) < EPISODE_TTL_MS
            });
        }
        self.principals.retain(|p| !p.episodes.is_empty());
    }
}

fn normalized_host(value: &str) -> Option<String> {
    if value.len() > 253 {
        return None;
    }
    let value = value.trim().trim_end_matches('.');
    (!value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')))
    .then(|| value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    const UNKNOWN: DiscoveryDecision =
        DiscoveryDecision::new("name", "not-created", "name-unknown");

    #[test]
    fn interleaved_users_and_unidentified_flows_never_share_an_episode() {
        let mut ledger = DiscoveryLedger::default();
        for user in ["one", "two"] {
            let _ = ledger.record(
                user,
                None,
                Some("10.0.0.1:5000 -> 192.0.2.1:443"),
                UNKNOWN,
                1,
            );
        }
        let _ = ledger.record(
            "one",
            None,
            Some("10.0.0.1:5001 -> 192.0.2.1:443"),
            UNKNOWN,
            2,
        );
        let (one, _) = ledger.snapshot("one", 2, 128);
        let (two, _) = ledger.snapshot("two", 2, 128);
        assert_eq!(one.len(), 2);
        assert_eq!(two.len(), 1);
        assert!(one.iter().all(|a| two.iter().all(|b| a.id != b.id)));
        assert!(ledger.snapshot("stranger", 2, 128).0.is_empty());
    }

    #[test]
    fn clock_rollback_and_expiry_do_not_keep_old_failures_alive() {
        let mut ledger = DiscoveryLedger::default();
        let _ = ledger.record("one", Some("Site.Example."), None, UNKNOWN, 1_000);
        assert!(ledger.snapshot("one", 999, 10).0.is_empty());
        let _ = ledger.record("one", Some("site.example"), None, UNKNOWN, 1_000);
        assert!(ledger
            .snapshot("one", 1_000 + EPISODE_TTL_MS, 10)
            .0
            .is_empty());
    }

    #[test]
    fn a_flood_is_bounded_and_oldest_records_are_reported_as_omitted() {
        let mut ledger = DiscoveryLedger::default();
        for index in 0..500 {
            let _ = ledger.record(
                "one",
                Some(&format!("site{index}.example")),
                None,
                UNKNOWN,
                index,
            );
        }
        let (episodes, omitted) = ledger.snapshot("one", 500, usize::MAX);
        assert_eq!(episodes.len(), MAX_EPISODES);
        assert_eq!(omitted, 500 - MAX_EPISODES as u64);
        assert_eq!(episodes[0].host.as_deref(), Some("site499.example"));
        for index in 0..1_000 {
            let _ = ledger.record(
                "one",
                Some("site499.example"),
                None,
                DiscoveryDecision::new(
                    "health",
                    "deferred",
                    if index % 2 == 0 {
                        "probe-pending"
                    } else {
                        "probe-inconclusive"
                    },
                ),
                500 + index,
            );
        }
        assert_eq!(
            ledger.snapshot("one", 1_500, 1).0[0].history.len(),
            MAX_STEPS
        );
    }

    #[test]
    fn an_exhausted_sequence_never_reuses_the_last_episode_identity() {
        let mut ledger = DiscoveryLedger {
            sequence: u64::MAX,
            ..Default::default()
        };
        assert!(ledger
            .record("one", Some("site.example"), None, UNKNOWN, 1)
            .is_none());
        assert!(ledger.snapshot("one", 1, 128).0.is_empty());
    }
}
