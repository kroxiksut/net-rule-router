//! The local networks a principal may keep reachable while the kill-switch
//! blocks everything else.
//!
//! Two halves meet here. What the service can see for itself — the main link's
//! own subnets and the host side of hypervisor adapters — and what only the
//! user knows: a network no interface on this machine reveals (a hypervisor in
//! NAT mode creates none), or a discovered one they would rather keep blocked.
//!
//! The discovery half must never mistake a tunnel for a hypervisor: both live
//! in RFC1918 space, and exempting a VPN's own range would open exactly the
//! hole the kill-switch exists to close. That decision lives in
//! `nrr_platform_api::adapters::is_virtual_machine_adapter`; this module only
//! joins its answer to the stored one.

use std::sync::{Arc, Mutex};

use nrr_domain::ipv4_network::Ipv4Network;
use nrr_shared::ipc_payloads::{
    LocalNetworkDto, LocalNetworkRejectionDto, LocalNetworksGetResponse, LocalNetworksSetRequest,
    LocalNetworksSetResponse, LOCAL_NETWORK_KIND_MAIN_LINK, LOCAL_NETWORK_KIND_MANUAL,
    LOCAL_NETWORK_KIND_VIRTUAL_MACHINE,
};
use nrr_storage::local_network_rules::{
    LocalNetworkOrigin, LocalNetworkRule, LocalNetworkRulesRepository,
};
use rusqlite::Connection;

use crate::ipc_handlers::providers::LocalNetworksProvider;
use crate::route_coordinator::SecondaryRouteCoordinator;

/// Reason slugs returned for entries the service declined to store.
const REJECT_MALFORMED: &str = "malformed-cidr";
const REJECT_NOT_PRIVATE: &str = "not-private";

pub struct ProductionLocalNetworks {
    coordinator: Arc<SecondaryRouteCoordinator>,
    state_conn: Arc<Mutex<Connection>>,
}

impl ProductionLocalNetworks {
    pub fn new(
        coordinator: Arc<SecondaryRouteCoordinator>,
        state_conn: Arc<Mutex<Connection>>,
    ) -> Self {
        Self {
            coordinator,
            state_conn,
        }
    }

    fn stored(&self, sid: &str) -> Vec<LocalNetworkRule> {
        let guard = self
            .state_conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        LocalNetworkRulesRepository::new(&guard)
            .list_for_sid(sid)
            .unwrap_or_default()
    }

    fn compose(&self, sid: &str) -> Vec<LocalNetworkDto> {
        let discovered = self.coordinator.discovered_local_networks(sid);
        let stored = self.stored(sid);
        let decision_for = |network: Ipv4Network| {
            stored
                .iter()
                .find(|rule| Ipv4Network::parse(&rule.cidr) == Some(network))
                .map(|rule| rule.allow)
        };

        let mut out: Vec<LocalNetworkDto> = discovered
            .iter()
            .map(|(network, adapter, from_main_link)| {
                let decided = decision_for(*network);
                LocalNetworkDto {
                    cidr: network.to_cidr_string(),
                    kind: if *from_main_link {
                        LOCAL_NETWORK_KIND_MAIN_LINK.to_string()
                    } else {
                        LOCAL_NETWORK_KIND_VIRTUAL_MACHINE.to_string()
                    },
                    adapter: adapter.clone(),
                    // Discovered networks are exempt unless the user said no.
                    allowed: decided.unwrap_or(true),
                    decided_by_user: decided.is_some(),
                }
            })
            .collect();

        // The user's own entries, minus the ones that also turned up in
        // discovery — those are already listed above with their real adapter.
        for rule in &stored {
            let Some(network) = Ipv4Network::parse(&rule.cidr) else {
                continue;
            };
            if discovered.iter().any(|(found, _, _)| *found == network) {
                continue;
            }
            out.push(LocalNetworkDto {
                cidr: network.to_cidr_string(),
                kind: LOCAL_NETWORK_KIND_MANUAL.to_string(),
                adapter: String::new(),
                allowed: rule.allow,
                decided_by_user: true,
            });
        }
        out
    }
}

impl LocalNetworksProvider for ProductionLocalNetworks {
    fn list(&self, sid: &str) -> LocalNetworksGetResponse {
        LocalNetworksGetResponse {
            networks: self.compose(sid),
        }
    }

    fn set(&self, sid: &str, request: &LocalNetworksSetRequest) -> LocalNetworksSetResponse {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let discovered = self.coordinator.discovered_local_networks(sid);
        let mut rejected: Vec<LocalNetworkRejectionDto> = Vec::new();
        {
            let guard = self
                .state_conn
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let repo = LocalNetworkRulesRepository::new(&guard);
            for decision in &request.decisions {
                let Some(network) = Ipv4Network::parse(&decision.cidr) else {
                    rejected.push(LocalNetworkRejectionDto {
                        cidr: decision.cidr.clone(),
                        reason: REJECT_MALFORMED.to_string(),
                    });
                    continue;
                };
                // A public range is not a local segment, and exempting one
                // would be a hole rather than a convenience. Discovered
                // networks are already filtered this way; a typed one is not.
                if !is_private(network) {
                    rejected.push(LocalNetworkRejectionDto {
                        cidr: network.to_cidr_string(),
                        reason: REJECT_NOT_PRIVATE.to_string(),
                    });
                    continue;
                }
                let was_discovered = discovered.iter().any(|(found, _, _)| *found == network);
                let rule = LocalNetworkRule {
                    cidr: network.to_cidr_string(),
                    allow: decision.allowed,
                    origin: if was_discovered {
                        LocalNetworkOrigin::Discovered
                    } else {
                        LocalNetworkOrigin::Manual
                    },
                };
                // A confirmed "yes" is stored even though discovery already
                // answers yes: `decided_by_user` is what tells the surfaces a
                // network is still WAITING for an answer, and a confirmation
                // that leaves no trace would make the offer reappear forever.
                if let Err(e) = repo.upsert(sid, &rule, now) {
                    tracing::warn!(
                        target: "nrr::local-networks",
                        sid = %sid,
                        cidr = %rule.cidr,
                        "could not store the local-network decision: {e}",
                    );
                }
            }
            for cidr in &request.forget {
                let canonical = Ipv4Network::parse(cidr)
                    .map(|n| n.to_cidr_string())
                    .unwrap_or_else(|| cidr.clone());
                let _ = repo.remove(sid, &canonical);
            }
        }
        LocalNetworksSetResponse {
            networks: self.compose(sid),
            rejected,
        }
    }
}

/// RFC1918 only — the ranges a local segment may claim.
fn is_private(network: Ipv4Network) -> bool {
    let o = network.network().octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

// ── Sites that refuse main-link addresses ────────────────────────────────────

/// Records the sites a principal says answer the MAIN link with a refusal.
///
/// Shares this module because it shares its shape: a small per-SID table whose
/// only job is to correct what the service can measure with something only the
/// user knows.
pub struct ProductionRefusingAnchors {
    state_conn: Arc<Mutex<Connection>>,
}

impl ProductionRefusingAnchors {
    pub fn new(state_conn: Arc<Mutex<Connection>>) -> Self {
        Self { state_conn }
    }
}

impl crate::ipc_handlers::providers::RefusingAnchorsWriter for ProductionRefusingAnchors {
    fn set(
        &self,
        sid: &str,
        hostname: &str,
        refusing: bool,
    ) -> nrr_shared::ipc_payloads::RefusingAnchorSetResponse {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let guard = self
            .state_conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let repo = nrr_storage::refusing_anchors::RefusingAnchorsRepository::new(&guard);
        if let Err(e) = repo.set(sid, hostname, refusing, now) {
            tracing::warn!(
                target: "nrr::auto-rules",
                sid = %sid,
                "could not record that a site refuses main-link addresses: {e}",
            );
        }
        nrr_shared::ipc_payloads::RefusingAnchorSetResponse {
            refusing: repo.list_for_sid(sid).unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_rfc1918_counts_as_a_local_segment() {
        for good in ["10.0.2.0/24", "172.20.0.0/16", "192.168.56.0/24"] {
            assert!(
                is_private(Ipv4Network::parse(good).expect("parse")),
                "{good}"
            );
        }
        for bad in ["203.0.113.0/24", "8.8.8.0/24", "172.32.0.0/16"] {
            assert!(
                !is_private(Ipv4Network::parse(bad).expect("parse")),
                "{bad}"
            );
        }
    }
}
