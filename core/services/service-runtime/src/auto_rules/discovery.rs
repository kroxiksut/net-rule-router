//! Evidence shared by the inbox, the notice acknowledgement, and an export.

use super::*;
pub use nrr_domain::suggestion_discovery::DiscoveryDecision;
use nrr_domain::suggestion_discovery::DiscoveryEpisode;
use nrr_shared::ipc_payloads::{
    DiscoveryEpisodeDto, DiscoveryEpisodesSnapshotDto, DiscoveryStepDto,
};

const DISCOVERY_ROWS_PER_GROUP: usize = 64;

impl AutoRulesEngine {
    pub(crate) fn set_discovery_queue_source(&self, source: super::DiscoveryQueueSource) {
        *self
            .discovery_queue
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(source);
    }

    pub fn note_discovery(
        &self,
        sid: &str,
        host: Option<&str>,
        destination: Option<&str>,
        decision: DiscoveryDecision,
        now: SystemTime,
    ) {
        if self.discovery_namespace.is_none() {
            return;
        }
        let id = self
            .discovery
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .record(sid, host, destination, decision, unix_ms(now));
        self.emit_discovery(sid, id, decision);
    }

    fn emit_discovery(&self, sid: &str, id: Option<u64>, decision: DiscoveryDecision) {
        if let (Some(namespace), Some(id)) = (self.discovery_namespace.as_deref(), id) {
            tracing::info!(target: "nrr::discovery", sid,
                discovery_id = %format!("discovery-{namespace}-{id}"), stage = decision.stage,
                state = decision.state, reason = decision.reason,
                "site suggestion decision");
        }
    }

    pub fn set_discovery_limitations(&self, limitations: &[&str]) {
        let mut current = self
            .discovery_limitations
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        for &limitation in limitations.iter().take(4) {
            if matches!(
                limitation,
                "os-dns-cache-unavailable"
                    | "passive-reset-unavailable"
                    | "discovery-identity-unavailable"
            ) && !current.iter().any(|item| item == limitation)
            {
                current.push(limitation.to_owned());
            }
        }
    }

    pub fn note_discovery_limitation(&self, _sid: &str, limitation: &str) {
        self.set_discovery_limitations(&[limitation]);
    }

    pub fn discovery_limitations(&self) -> Vec<String> {
        self.discovery_limitations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn discovery_snapshot(&self, sid: &str, now: SystemTime) -> DiscoveryEpisodesSnapshotDto {
        let Some(namespace) = self.discovery_namespace.as_deref() else {
            return DiscoveryEpisodesSnapshotDto {
                limitations: self.discovery_limitations(),
                ..Default::default()
            };
        };
        let pending = self.pending_snapshot(sid);
        let queue_source = self
            .discovery_queue
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let mut queued = queue_source.map_or_else(HashMap::new, |source| source(sid));
        let snapshot = self.rules.active_rules_for(sid);
        let secondary_ready = self.secondary_ready.as_ref().is_none_or(|ready| ready(sid));
        let pass_enabled = self
            .main_link_pass_enabled
            .as_ref()
            .is_some_and(|enabled| enabled(sid));
        let (episodes, mut omitted) = self
            .discovery
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .snapshot(
                sid,
                unix_ms(now),
                nrr_domain::suggestion_discovery::MAX_EPISODES,
            );
        let queued_order: HashMap<_, _> = queued
            .iter()
            .map(|(host, entry)| (host.clone(), entry.sequence))
            .collect();
        let mut episodes: Vec<_> = episodes
            .into_iter()
            .map(|episode| {
                let mut episode = to_dto(namespace, episode);
                if let Some(host) = episode.host.as_deref() {
                    episode.probe_queue = queued.remove(host).map(|entry| entry.status);
                }
                if episode.probe_queue.as_ref().is_some_and(|queue| {
                    queue.wait_kind == nrr_shared::ipc_payloads::ProbeQueueWaitKindDto::Rules
                }) {
                    episode.stage = "probe".to_owned();
                    episode.state = "deferred".to_owned();
                    episode.reason = "rules-unavailable".to_owned();
                    return episode;
                }
                if episode.probe_queue.is_some() && episode.reason == "rules-unavailable" {
                    episode.stage = "probe".to_owned();
                    episode.state = "deferred".to_owned();
                    episode.reason = "probe-queued".to_owned();
                }
                if episode.state == "delivered" {
                    return episode;
                }
                let Some(offer) = pending
                    .iter()
                    .map(|candidate| &candidate.dto)
                    .find(|dto| episode.candidate_id.as_deref() == Some(dto.id.as_str()))
                else {
                    return episode;
                };
                let waiting = !is_app_offer(offer)
                    && (awaiting_the_main_link(offer, pass_enabled)
                        || (pass_enabled
                            && offer.signal == AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED
                            && offer.secondary_reach.is_none()));
                // Current gates change the view, never the observed history or its lifetime.
                let decision = if is_own_application_offer(offer) {
                    Some(DiscoveryDecision::new("candidate", "hidden", "own-process"))
                } else if unconfirmed_scope(offer) {
                    Some(DiscoveryDecision::new(
                        "candidate",
                        "deferred",
                        "scope-unconfirmed",
                    ))
                } else if offer_covered(snapshot.as_ref(), offer) {
                    Some(DiscoveryDecision::new(
                        "candidate",
                        "hidden",
                        "already-covered",
                    ))
                } else if settled_self_signed(offer) || offer.served_by_main_link {
                    Some(DiscoveryDecision::new(
                        "health",
                        "hidden",
                        "primary-responds",
                    ))
                } else if offer.secondary_reach == Some(false) {
                    Some(DiscoveryDecision::new(
                        "probe",
                        "hidden",
                        "secondary-failed",
                    ))
                } else if !secondary_ready {
                    Some(DiscoveryDecision::new(
                        "probe",
                        "deferred",
                        "secondary-unavailable",
                    ))
                } else if waiting && waiting_can_replace(&episode.reason) {
                    Some(DiscoveryDecision::new("probe", "deferred", "probe-pending"))
                } else if !waiting
                    && matches!(
                        episode.reason.as_str(),
                        "secondary-failed"
                            | "secondary-unavailable"
                            | "probe-pending"
                            | "already-covered"
                            | "primary-responds"
                            | "insufficient-evidence"
                            | "close-unknown"
                            | "connection-reset"
                            | "probe-queued"
                            | "https-unconfirmed"
                            | "http-answered"
                    )
                {
                    Some(DiscoveryDecision::new("candidate", "ready", "offer-ready"))
                } else {
                    None
                };
                if let Some(decision) = decision {
                    episode.stage = decision.stage.to_owned();
                    episode.state = decision.state.to_owned();
                    episode.reason = decision.reason.to_owned();
                }
                episode
            })
            .collect();
        for (host, entry) in queued {
            let digest = Sha256::digest(format!("{sid}\0{host}").as_bytes());
            let reason = if entry.status.wait_kind
                == nrr_shared::ipc_payloads::ProbeQueueWaitKindDto::Rules
            {
                "rules-unavailable"
            } else {
                "probe-queued"
            };
            episodes.push(DiscoveryEpisodeDto {
                id: format!("discovery-{namespace}-queued-{digest:x}"),
                host: Some(host),
                destination: Some(entry.destination),
                state: "deferred".to_owned(),
                stage: "probe".to_owned(),
                reason: reason.to_owned(),
                first_seen_unix_ms: entry.first_seen_unix_ms,
                last_seen_unix_ms: entry.last_seen_unix_ms,
                probe_queue: Some(entry.status),
                ..Default::default()
            });
        }
        let (mut active, mut history): (Vec<_>, Vec<_>) = episodes
            .into_iter()
            .partition(|episode| episode.probe_queue.is_some());
        active.sort_by_key(|episode| {
            episode
                .host
                .as_ref()
                .and_then(|host| queued_order.get(host))
                .copied()
                .unwrap_or(0)
        });
        omitted = omitted.saturating_add(
            active.len().saturating_sub(DISCOVERY_ROWS_PER_GROUP) as u64
                + history.len().saturating_sub(DISCOVERY_ROWS_PER_GROUP) as u64,
        );
        active.truncate(DISCOVERY_ROWS_PER_GROUP);
        history.truncate(DISCOVERY_ROWS_PER_GROUP);
        active.extend(history);
        let episodes = active;
        DiscoveryEpisodesSnapshotDto {
            episodes,
            omitted,
            limitations: self.discovery_limitations(),
        }
    }

    pub fn discovery_episodes(&self, sid: &str) -> Vec<DiscoveryEpisodeDto> {
        self.discovery_snapshot(sid, SystemTime::now()).episodes
    }

    pub fn record_discovery_feedback(
        &self,
        sid: &str,
        ids: &[String],
        state: &str,
        reason: &str,
        now: SystemTime,
    ) -> u32 {
        let decision = match (state, reason) {
            ("delivered", "shown") => DiscoveryDecision::new("notice", "delivered", "shown"),
            ("deferred", "notification-pacing") => {
                DiscoveryDecision::new("notice", "deferred", "notification-pacing")
            }
            ("deferred", "client-busy") => {
                DiscoveryDecision::new("notice", "deferred", "client-busy")
            }
            ("hidden", "notifications-muted") => {
                DiscoveryDecision::new("notice", "hidden", "notifications-muted")
            }
            ("hidden", "client-filter") => {
                DiscoveryDecision::new("notice", "hidden", "client-filter")
            }
            _ => return 0,
        };
        let mut states = self.publish_state.lock().unwrap_or_else(|p| p.into_inner());
        let owned: Vec<_> = self
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .map(|offers| {
                offers
                    .iter()
                    .filter(|offer| ids.iter().take(50).any(|id| id == &offer.dto.id))
                    .map(|offer| (offer.dto.id.clone(), offer.dto.proposed_match.clone()))
                    .collect()
            })
            .unwrap_or_default();
        if owned.is_empty() {
            return 0;
        }
        cap_publish_states(&mut states, sid);
        let publish = states.entry(sid.to_owned()).or_default();
        let mut ledger = self.discovery.lock().unwrap_or_else(|p| p.into_inner());
        let mut logs = Vec::new();
        let mut recorded = 0;
        for (id, host) in &owned {
            if state != "delivered" && publish.delivered.contains(id) {
                continue;
            }
            if state == "delivered" {
                publish.delivered.insert(id.clone());
            }
            if self.discovery_namespace.is_some() {
                logs.push(ledger.record(sid, Some(host), None, decision, unix_ms(now)));
                ledger.link_candidate(sid, host, id);
            }
            recorded += 1;
        }
        drop(ledger);
        drop(states);
        for id in logs {
            self.emit_discovery(sid, id, decision);
        }
        recorded
    }

    pub(super) fn record_candidate_discovery(
        &self,
        sid: &str,
        candidate: &AutoRuleCandidateDto,
        decision: DiscoveryDecision,
        now: SystemTime,
    ) {
        let mut states = self.publish_state.lock().unwrap_or_else(|p| p.into_inner());
        if matches!(
            decision.reason,
            "offer-ready" | "awaiting-client" | "notification-pacing" | "no-subscriber"
        ) && states
            .get(sid)
            .is_some_and(|state| state.delivered.contains(&candidate.id))
        {
            return;
        }
        if (decision.state == "ready" || matches!(decision.stage, "probe" | "notice"))
            && !self
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(sid)
                .is_some_and(|offers| offers.iter().any(|offer| offer.dto.id == candidate.id))
        {
            return;
        }
        if matches!(
            decision.reason,
            "already-covered" | "user-dismissed" | "primary-responds"
        ) {
            if let Some(state) = states.get_mut(sid) {
                discard_delivery(state, &candidate.id);
            }
        }
        let id = if self.discovery_namespace.is_some() {
            let mut ledger = self.discovery.lock().unwrap_or_else(|p| p.into_inner());
            let id = ledger.record(
                sid,
                Some(&candidate.proposed_match),
                None,
                decision,
                unix_ms(now),
            );
            ledger.link_candidate(sid, &candidate.proposed_match, &candidate.id);
            id
        } else {
            None
        };
        drop(states);
        self.emit_discovery(sid, id, decision);
    }

    pub(super) fn forget_discovery_candidates(&self, sid: &str, wanted: &HashSet<&str>) {
        let mut states = self.publish_state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(state) = states.get_mut(sid) {
            for id in wanted {
                discard_delivery(state, id);
            }
        }
        self.discovery
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .forget_candidates(sid, |id| wanted.contains(id));
    }

    /// Failed secondary measurements remain eligible for another measurement.
    pub fn candidates_for_probe(&self, sid: &str) -> Vec<AutoRuleCandidateDto> {
        let snapshot = self.rules.active_rules_for(sid);
        self.pending_snapshot(sid)
            .into_iter()
            .map(|candidate| candidate.dto)
            .filter(|dto| !is_app_offer(dto) && !unconfirmed_scope(dto))
            .filter(|dto| !offer_covered(snapshot.as_ref(), dto) && !settled_self_signed(dto))
            .collect()
    }
}

fn waiting_can_replace(reason: &str) -> bool {
    matches!(
        reason,
        "offer-ready"
            | "awaiting-client"
            | "no-subscriber"
            | "notification-pacing"
            | "probe-pending"
            | "secondary-unavailable"
    )
}

fn discard_delivery(state: &mut PublishState, id: &str) {
    state.announced.remove(id);
    state.delivered.remove(id);
    state.in_flight.remove(id);
}

pub(super) fn new_namespace() -> Option<String> {
    let mut bytes = [0_u8; 16];
    if let Err(error) = getrandom::fill(&mut bytes) {
        tracing::warn!(target: "nrr::discovery", %error, "discovery history unavailable: a private session identity could not be created");
        return None;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(32);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 15)]));
    }
    Some(value)
}

pub(super) fn cap_publish_states(states: &mut HashMap<String, PublishState>, sid: &str) {
    if states.len() >= MAX_TRACKED_PRINCIPALS && !states.contains_key(sid) {
        if let Some(oldest) = states
            .iter()
            .min_by_key(|(_, state)| state.announced_at)
            .map(|(sid, _)| sid.clone())
        {
            states.remove(&oldest);
        }
    }
}

fn to_dto(namespace: &str, episode: DiscoveryEpisode) -> DiscoveryEpisodeDto {
    let decision =
        episode
            .history
            .back()
            .map(|step| step.decision)
            .unwrap_or(DiscoveryDecision::new(
                "observation",
                "not-created",
                "insufficient-evidence",
            ));
    DiscoveryEpisodeDto {
        id: format!("discovery-{namespace}-{}", episode.id),
        host: episode.host,
        destination: episode.destination,
        candidate_id: episode.candidate_id,
        platform_limitation: None,
        probe_queue: None,
        state: decision.state.to_owned(),
        stage: decision.stage.to_owned(),
        reason: decision.reason.to_owned(),
        first_seen_unix_ms: episode.first_ms,
        last_seen_unix_ms: episode.last_ms,
        history: episode
            .history
            .into_iter()
            .map(|step| DiscoveryStepDto {
                stage: step.decision.stage.to_owned(),
                state: step.decision.state.to_owned(),
                reason: step.decision.reason.to_owned(),
                at_unix_ms: step.at_ms,
            })
            .collect(),
    }
}
