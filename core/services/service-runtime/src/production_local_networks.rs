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

    /// Has this principal asked not to be questioned about networks it has not
    /// seen before?
    ///
    /// Read from the stored policy rather than cached: the answer is a setting
    /// the user can flip while the service runs, and the next read is the next
    /// question.
    fn auto_accept(&self, sid: &str) -> bool {
        let guard = self
            .state_conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        nrr_storage::route_bindings::RouteBindingsRepository::new(&guard)
            .load_for_sid(sid)
            .map(|policy| policy.local_networks_auto_accept)
            .unwrap_or(false)
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
        // "Stop asking about networks I have not seen yet." Nothing is written:
        // the setting suppresses the QUESTION, and turning it back off asks
        // again - which is the honest behaviour for a switch that decides on
        // the user's behalf.
        let auto_accept = self.auto_accept(sid);
        let decision_for = |network: Ipv4Network, adapter: &str| {
            stored
                .iter()
                .find(|rule| Ipv4Network::parse(&rule.cidr) == Some(network))
                .map(|rule| rule.allow)
                .or_else(|| inherited_from_adapter(&stored, adapter))
        };

        let mut out: Vec<LocalNetworkDto> = discovered
            .iter()
            .map(|(network, adapter, from_main_link)| {
                let decided = decision_for(*network, adapter);
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
                    decided_by_user: decided.is_some() || auto_accept,
                }
            })
            .collect();

        // The user's own entries, minus the ones that also turned up in
        // discovery — those are already listed above with their real adapter.
        // An answer whose adapter is still here is listed there too, under the
        // number that adapter carries today; showing its old number as well
        // would present one decision as two, the second of them nameless.
        for rule in &stored {
            let Some(network) = Ipv4Network::parse(&rule.cidr) else {
                continue;
            };
            if discovered
                .iter()
                .any(|(found, adapter, _)| *found == network || is_same_adapter(adapter, rule))
            {
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

/// The answer this adapter already carries, for a segment number it did not
/// have when the answer was given — the user's LATEST word on that adapter.
///
/// A refusal used to outrank every confirmation regardless of age, on the
/// reasoning that the other direction reopens a segment the user closed. It
/// does not survive the case the feature exists for: the adapter renumbers,
/// the refused network number is gone, the user explicitly allows the new one,
/// it renumbers again — and the dead refusal was inherited over the live
/// approval. Worse, the row doing it is invisible in the UI (`compose` hides
/// stored rows whose adapter discovery still reports), so only a full reset
/// cleared it. Ordering by recency keeps both directions honest and forgets
/// nothing; a tie still favours the refusal, which is the conservative read.
fn inherited_from_adapter(stored: &[LocalNetworkRule], adapter: &str) -> Option<bool> {
    if adapter.is_empty() {
        return None;
    }
    stored
        .iter()
        .filter(|rule| is_same_adapter(adapter, rule))
        // Newest wins; on an equal timestamp the refusal does.
        .max_by_key(|rule| (rule.updated_at, u8::from(!rule.allow)))
        .map(|rule| rule.allow)
}

/// A stored answer belongs to `adapter` only if discovery named one when it was
/// given; a network the user typed in names none and inherits nothing.
fn is_same_adapter(adapter: &str, rule: &LocalNetworkRule) -> bool {
    rule.origin == LocalNetworkOrigin::Discovered
        && !rule.adapter.is_empty()
        && rule.adapter == adapter
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
                let adapter = discovered
                    .iter()
                    .find(|(found, _, _)| *found == network)
                    .map(|(_, adapter, _)| adapter.clone());
                let rule = LocalNetworkRule {
                    cidr: network.to_cidr_string(),
                    allow: decision.allowed,
                    origin: if adapter.is_some() {
                        LocalNetworkOrigin::Discovered
                    } else {
                        LocalNetworkOrigin::Manual
                    },
                    adapter: adapter.unwrap_or_default(),
                    // The store stamps the write time itself; this value is
                    // read back from the row, never taken from here.
                    updated_at: 0,
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
                    continue;
                }
                // This answer now speaks for the adapter, so the numbers it
                // used to carry have nothing left to say. Without this a
                // switch that renumbers on every reboot leaves a row per boot.
                if let Err(e) = repo.forget_superseded_confirmations(sid, &rule.adapter, &rule.cidr)
                {
                    tracing::warn!(
                        target: "nrr::local-networks",
                        sid = %sid,
                        adapter = %rule.adapter,
                        "could not prune superseded local-network answers: {e}",
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

    fn rule(
        cidr: &str,
        adapter: &str,
        allow: bool,
        origin: LocalNetworkOrigin,
    ) -> LocalNetworkRule {
        rule_at(cidr, adapter, allow, origin, 0)
    }

    /// Same, with an explicit write time — inheritance across a renumbered
    /// adapter follows the most recent answer, so its tests need to order them.
    fn rule_at(
        cidr: &str,
        adapter: &str,
        allow: bool,
        origin: LocalNetworkOrigin,
        updated_at: i64,
    ) -> LocalNetworkRule {
        LocalNetworkRule {
            cidr: cidr.into(),
            allow,
            origin,
            adapter: adapter.into(),
            updated_at,
        }
    }

    #[test]
    fn an_answer_follows_its_adapter_through_a_renumbering() {
        let switch = "Ethernet (Default Switch)";
        let stored = vec![rule(
            "172.23.208.0/20",
            switch,
            true,
            LocalNetworkOrigin::Discovered,
        )];
        assert_eq!(inherited_from_adapter(&stored, switch), Some(true));
        assert_eq!(
            inherited_from_adapter(&stored, "VirtualBox Host-Only"),
            None
        );
        assert_eq!(inherited_from_adapter(&stored, ""), None);
    }

    #[test]
    fn a_refusal_outranks_a_confirmation_on_the_same_adapter() {
        let switch = "Ethernet (Default Switch)";
        let stored = vec![
            rule(
                "172.23.208.0/20",
                switch,
                true,
                LocalNetworkOrigin::Discovered,
            ),
            rule(
                "172.28.176.0/20",
                switch,
                false,
                LocalNetworkOrigin::Discovered,
            ),
        ];
        assert_eq!(inherited_from_adapter(&stored, switch), Some(false));
    }

    /// The scenario the feature exists for: a hypervisor switch renumbers, the
    /// user refuses one number, later ALLOWS the new one, it renumbers again.
    /// The dead refusal used to outrank the live approval forever, and the row
    /// doing it is not even visible in the UI.
    #[test]
    fn a_newer_approval_outranks_an_older_refusal_on_the_same_adapter() {
        let switch = "Ethernet (Default Switch)";
        let stored = vec![
            rule_at(
                "172.23.208.0/20",
                switch,
                false,
                LocalNetworkOrigin::Discovered,
                1_000,
            ),
            rule_at(
                "172.28.176.0/20",
                switch,
                true,
                LocalNetworkOrigin::Discovered,
                2_000,
            ),
        ];
        assert_eq!(inherited_from_adapter(&stored, switch), Some(true));

        // And the other direction still holds: a refusal given AFTER an
        // approval closes the segment again.
        let reversed = vec![
            rule_at(
                "172.23.208.0/20",
                switch,
                true,
                LocalNetworkOrigin::Discovered,
                1_000,
            ),
            rule_at(
                "172.28.176.0/20",
                switch,
                false,
                LocalNetworkOrigin::Discovered,
                2_000,
            ),
        ];
        assert_eq!(inherited_from_adapter(&reversed, switch), Some(false));
    }

    #[test]
    fn a_typed_in_network_inherits_nothing() {
        // Manual rows carry no adapter, and one that somehow did must still not
        // speak for an interface the user never pointed at.
        let stored = vec![rule(
            "10.9.0.0/16",
            "Ethernet",
            true,
            LocalNetworkOrigin::Manual,
        )];
        assert_eq!(inherited_from_adapter(&stored, "Ethernet"), None);
    }

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
