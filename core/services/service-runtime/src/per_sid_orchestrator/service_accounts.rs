//! The service accounts' share of the route-table owners' guards: who gets it,
//! and moving it when the owners change.
//!
//! Every served user is an owner: the table carries all of their routes. Each
//! one's share keeps only the destinations the table sends through that user's
//! own link, so system traffic is pinned where it actually goes.

use std::net::IpAddr;

use nrr_shared::ip_block::IpBlock;

use crate::enforcement_planner::{
    service_account_guard, NetworkHolds, ServiceAccountInput, ServiceAccountPosture,
};
use crate::killswitch_codegen::KillSwitchProtocols;

use super::*;

/// What the owner's pass decided, as the service-account twin reads it.
pub(super) struct OwnerGuard<'a> {
    pub posture: ServiceAccountPosture,
    pub destinations: &'a [IpAddr],
    pub holds: &'a NetworkHolds,
    pub tunnel_servers: Vec<IpAddr>,
    pub local_subnets: Vec<IpBlock>,
    /// `0` unless the tunnel resolves; a pin without it fails open.
    pub secondary_luid: u64,
    pub protocols: KillSwitchProtocols,
    /// The owner keeps forwarded traffic (WSL) under the guard too.
    pub guard_forwarded: bool,
    /// Networks of somebody else's tunnels, which service accounts and
    /// forwarded traffic reach as the owner does.
    pub foreign_networks: &'a [crate::killswitch_codegen::ForeignTunnelNetwork],
    /// The owner's blanket block with the tunnel gone, and what it leaves open.
    pub block_all: Option<&'a crate::killswitch_codegen::FailClosedExemptions>,
    /// The networks the owner's main-link rules route, which that blanket
    /// leaves open as the owner's rule filters do.
    pub main_networks: &'a [IpBlock],
}

/// What the owner's guard hands out beyond the owner.
#[derive(Default)]
pub(super) struct OwnerShares {
    /// Scoped to the service accounts.
    pub service: Vec<WfpFilterSpec>,
    /// On the forwarding path; no account to scope to.
    pub forwarded: Vec<WfpFilterSpec>,
}

impl OwnerGuard<'_> {
    pub(super) fn servers_of(v4: &[std::net::Ipv4Addr], v6: &[std::net::Ipv6Addr]) -> Vec<IpAddr> {
        v4.iter()
            .copied()
            .map(IpAddr::V4)
            .chain(v6.iter().copied().map(IpAddr::V6))
            .collect()
    }

    pub(super) fn subnets_of(
        v4: &[(std::net::Ipv4Addr, u8)],
        v6: &[(std::net::Ipv6Addr, u8)],
    ) -> Vec<IpBlock> {
        v4.iter()
            .filter_map(|(net, len)| IpBlock::new(IpAddr::V4(*net), *len))
            .chain(
                v6.iter()
                    .filter_map(|(net, len)| IpBlock::new(IpAddr::V6(*net), *len)),
            )
            .collect()
    }
}

impl PerSidApplyOrchestrator {
    /// The main link's resolvers, both families, the only hosts the DNS permit
    /// under a block-all may name. Empty without the wiring, which permits
    /// nothing.
    pub(super) fn primary_dns(&self) -> Vec<IpAddr> {
        self.service_accounts
            .as_ref()
            .map(|wiring| (wiring.primary_dns)())
            .unwrap_or_default()
    }

    /// The service accounts' and the forwarded traffic's filters for `sid`'s
    /// guard — empty unless the route table serves `sid`, and without the
    /// destinations it sends through another user's link. `tunnel_clients` must
    /// reach their servers whatever account runs them, so they are exempt with
    /// every set, not only a block.
    pub(super) fn owner_shares(
        &self,
        sid: &str,
        intent: ComputeIntent,
        owner: OwnerGuard<'_>,
        tunnel_clients: &[String],
    ) -> OwnerShares {
        let Some(wiring) = self.service_accounts.as_ref() else {
            return OwnerShares::default();
        };
        let is_route_table_owner = (wiring.routing_owners)().iter().any(|s| s == sid);
        if !is_route_table_owner {
            return OwnerShares::default();
        }
        let elsewhere = |block: Option<IpBlock>| {
            block.is_some_and(|block| (wiring.routed_elsewhere)(sid, block))
        };
        let destinations: Vec<IpAddr> = owner
            .destinations
            .iter()
            .copied()
            .filter(|ip| !elsewhere(IpBlock::new(*ip, if ip.is_ipv4() { 32 } else { 128 })))
            .collect();
        let narrowed;
        let holds = if owner.holds.held.iter().any(|net| elsewhere(Some(*net))) {
            let mut kept = owner.holds.clone();
            kept.held.retain(|net| !elsewhere(Some(*net)));
            narrowed = kept;
            &narrowed
        } else {
            owner.holds
        };
        let primary_dns = (wiring.primary_dns)();
        // Forwarded traffic follows the owner's blanket even with no address to
        // name: what the tunnel would have carried goes nowhere else.
        let forwarded_block_all = match owner.block_all {
            Some(exemptions) if owner.guard_forwarded => {
                crate::killswitch_codegen::forwarded_block_all_filters(
                    sid,
                    exemptions,
                    &primary_dns,
                    owner.main_networks,
                )
            }
            _ => Vec::new(),
        };
        let guard = service_account_guard(&ServiceAccountInput {
            is_route_table_owner,
            posture: Some(owner.posture),
            destinations: &destinations,
            holds,
            tunnel_servers: &owner.tunnel_servers,
            local_subnets: &owner.local_subnets,
            primary_dns: &primary_dns,
        });
        let only_block_all = || OwnerShares {
            service: Vec::new(),
            forwarded: forwarded_block_all.clone(),
        };
        let Some(guard) = guard else {
            return only_block_all();
        };
        if intent.publishes() {
            self.service_account_dns_log.note(&guard.dns_spared);
        }
        if guard.destinations.is_empty() && guard.holds.is_empty() {
            return only_block_all();
        }
        let mut forwarded = if owner.guard_forwarded {
            crate::killswitch_codegen::forwarded_guard_filters(
                sid,
                &guard,
                owner.secondary_luid,
                owner.foreign_networks,
            )
        } else {
            Vec::new()
        };
        let mut seen: HashSet<_> = forwarded.iter().map(|spec| spec.id).collect();
        forwarded.extend(
            forwarded_block_all
                .iter()
                .filter(|spec| seen.insert(spec.id))
                .cloned(),
        );
        let exempt: Vec<String> = {
            let mut seen = HashSet::new();
            wiring
                .own_executable
                .iter()
                .chain(tunnel_clients)
                .filter(|path| seen.insert(path.to_ascii_lowercase()))
                .cloned()
                .collect()
        };
        let mut service = crate::killswitch_codegen::service_account_filters(
            sid,
            &guard,
            owner.secondary_luid,
            owner.protocols,
            &exempt,
            owner.foreign_networks,
        );
        let ike =
            crate::killswitch_codegen::ike_service_filters(sid, &service, &self.ike_service_images);
        service.extend(ike);
        OwnerShares { service, forwarded }
    }

    /// Re-derive the owners who left and those who arrived, so each one's
    /// service-account set leaves or arrives without waiting for the next tick.
    /// An owner present before and after is left alone. `fresh` were installed
    /// by this very reconcile and already carry the answer.
    pub(super) fn follow_route_table_owner(
        &self,
        fresh: &std::collections::BTreeSet<String>,
    ) -> Result<(), OrchestratorError> {
        let Some(wiring) = self.service_accounts.as_ref() else {
            return Ok(());
        };
        let mut owners = (wiring.routing_owners)();
        owners.sort_unstable();
        owners.dedup();
        let previous = {
            let mut last = self
                .service_account_owner
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if *last == owners {
                return Ok(());
            }
            std::mem::replace(&mut *last, owners.clone())
        };
        let list = |sids: &[String]| match sids {
            [] => "-".to_string(),
            sids => sids.join(", "),
        };
        tracing::info!(
            target: "nrr::per_sid_orchestrator",
            msg_key = "persid-service-accounts-owner-changed",
            previous = %list(&previous),
            owner = %list(&owners),
            "route-table owners changed: system services now follow their address pins",
        );
        let changed = previous
            .iter()
            .filter(|sid| !owners.contains(sid))
            .chain(owners.iter().filter(|sid| !previous.contains(sid)));
        for sid in changed {
            if fresh.contains(sid) {
                continue;
            }
            self.reconcile_secondary_coverage(sid)?;
        }
        Ok(())
    }
}
