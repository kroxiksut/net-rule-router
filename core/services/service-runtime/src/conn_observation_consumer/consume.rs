//! One batch of observations.
//!
//! The loop the rest of this module exists for: classify each observation,
//! feed the learners, report the drops. It is long because a batch is where
//! every collaborator is finally called, and short-circuiting any of them
//! early is how an observation stops reaching one of them.
//!
//! Same inherent impl, split across files. Behaviour is unchanged.

use super::*;

impl ConnectionObservationConsumer {
    /// Consume a batch: derive each connection's egress interface and emit a
    /// per-connection trace line on `nrr::conn-trace`. Returns counts by role.
    pub fn consume(&self, batch: &[ConnectionObservation], now: SystemTime) -> ConnConsumeSummary {
        let mut summary = ConnConsumeSummary::default();
        if batch.is_empty() {
            return summary;
        }
        let now_ms = now
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let paired;
        let batch: &[ConnectionObservation] = match self.drop_pairing.as_ref() {
            Some(pairing) => {
                paired = pairing
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .pair(batch, now_ms);
                &paired
            }
            None => batch,
        };

        // Live context, read once per batch. Prefer the full unicast table
        // (IPv4 + IPv6 → ifindex) so v6 egress is labelled; fall back to the
        // IPv4-only adapter table if that query is unavailable.
        let mut unicast = self.api.unicast_ip_addresses().unwrap_or_default();
        if unicast.is_empty() {
            unicast = build_unicast_table(&self.api.get_adapter_infos().unwrap_or_default());
        }
        let active_sid_now = (self.active_sid)();
        let log_ndjson = self.log_ndjson.load(Ordering::Relaxed);
        // Once per batch: the collateral check consults it for every observation
        // and a rule edit must land without a restart.
        let routed_apps: Vec<String> = self
            .routed_apps
            .as_ref()
            .map(|read| read())
            .unwrap_or_default();
        // Owner-scoped, each connection is resolved against its own user's
        // links below instead.
        let (active_primary, active_secondary) = match active_sid_now.as_deref() {
            Some(sid) if !self.owner_scoped || self.machine_accounts_follow_active => {
                (self.egress_of)(sid)
            }
            _ => (None, None),
        };
        let mut owner_links: std::collections::HashMap<String, (Option<u32>, Option<u32>)> =
            std::collections::HashMap::new();
        // The active user's additional route is usable again, so their outage
        // is over — also when no status change said so (a tunnel the liveness
        // probe had declared dead).
        if let (Some(ring), Some(sid), Some(_)) = (
            self.trace_ring.as_ref(),
            active_sid_now.as_deref(),
            active_secondary,
        ) {
            ring.outage_blocks().outage_ended(sid, now_ms);
        }
        // Per-batch dedup for the FCrDNS learner.
        let mut reverse_learned_this_batch: std::collections::HashSet<std::net::Ipv4Addr> =
            std::collections::HashSet::new();
        // Per-batch dedup for the client-app learner: one call per
        // process path per batch, no matter how many endpoints its checks hit.
        let mut app_learned_this_batch: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        // First destination-scoped offender of the batch, so the
        // scope-bug WARN can name the filter and one concrete victim instead
        // of only a count. One `Option` write per batch, no allocation beyond
        // the sampled process path.
        let mut dest_scope_sample: Option<DropSample> = None;
        // Destinations whose pin caught a socket on the wrong link this batch.
        // Deduped (a stalled flow is re-observed every tick) and capped.
        let mut stale_flow_victims: std::collections::BTreeMap<
            std::net::IpAddr,
            drop_reporter::PinDropVictims,
        > = std::collections::BTreeMap::new();
        // A process connects many times a batch; its command line is asked
        // about once.
        let mut scripts_this_batch: std::collections::HashMap<u32, Vec<String>> =
            std::collections::HashMap::new();
        // Each costs a read of the connection table: a few per batch.
        let mut flow_pid_lookups_left: u32 = 8;

        for obs in batch {
            // Asked of EVERY observation, before the filter below keeps only
            // established connections. A host a provider censors is one whose
            // connection never comes up, so waiting for an establishment to
            // confirm that somebody went there waits forever — the whole point
            // is that they went and it did not work.
            self.confirm_placeholder_use(
                obs.remote.ip(),
                obs.observed_unix_ms.unwrap_or(now_ms),
                obs.user_sid.as_deref(),
            );
            let on_active_links = self.machine_accounts_follow_active
                && obs.user_sid.as_deref().is_none_or(|o| {
                    o.is_empty() || nrr_platform_api::types::is_service_account_sid(o)
                });
            let (primary_ifindex, secondary_ifindex) = if self.owner_scoped && !on_active_links {
                self.owner_links(&mut owner_links, obs.user_sid.as_deref(), now_ms)
            } else {
                (active_primary, active_secondary)
            };
            let mut rec = classify_connection(obs, &unicast, primary_ifindex, secondary_ifindex);
            self.note_unanswered(obs, &rec, now_ms);
            // A resend or an orderly close is evidence about a peer, not a
            // connection of its own: it must never become a trace row, an
            // NDJSON line, an app→IP fact or a drop statistic. Only the primary
            // link is asked about — the offer is "move this into the tunnel",
            // and how a host behaves once already inside it answers nothing.
            // The stack's own connect event marks the connection established,
            // and only an established connection's close counts as "it works".
            // A filter classify is not one: it fires before the handshake.
            let establishes = obs.progress == ConnectionProgress::Attempt
                && obs.verdict == ConnectionVerdict::Unknown;
            if rec.egress.role == EgressRole::Primary
                && (establishes || obs.progress != ConnectionProgress::Attempt)
            {
                self.note_companion_primary_health(obs, now_ms);
            }
            if obs.progress != ConnectionProgress::Attempt {
                continue;
            }
            // Our own filter dropped it, and the stack now resends into that
            // filter: those resends must not read as the main link not answering.
            if obs.blocked_by_nrr == Some(true) {
                let at_ms = obs.observed_unix_ms.unwrap_or(now_ms);
                self.primary_stall_evidence
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .exclude(obs.local, obs.remote, at_ms);
                self.unanswered
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .exclude(obs.local, obs.remote, at_ms);
            }
            summary.total += 1;
            // Role verification, shared by the VPN-endpoint learner and the
            // live-secondary drop counter below: the dropping filter's spec id
            // must be a member of the live kill-switch/fail-closed Block
            // registry — `blocked_by_nrr` alone cannot tell a leak-guard drop
            // from the user's own Block rule.
            let killswitch_verified = rec
                .nrr_drop_spec_id
                .zip(self.killswitch_drop_check.as_ref())
                .is_some_and(|(spec_id, check)| check(spec_id));
            // Was the dropping filter the APP-SCOPED block? Read once here
            // because the FCrDNS gate below needs it outside the live-secondary
            // scope-bug branch that also consults it.
            let killswitch_app_scoped = rec
                .nrr_drop_spec_id
                .zip(self.killswitch_app_scope_check.as_ref())
                .is_some_and(|(spec_id, check)| check(spec_id));
            // System traffic the owner's guard dropped. Only the tunnel
            // learners below may read it: it is nobody's notice, outage or name.
            let service_account_drop = rec.blocked_by_nrr == Some(true)
                && rec
                    .nrr_drop_spec_id
                    .zip(self.service_account_drop_check.as_ref())
                    .is_some_and(|(spec_id, check)| check(spec_id));
            let mut drop_reason = None;
            if rec.blocked_by_nrr == Some(true) {
                let reason = self.reason_for_drop(&rec, killswitch_verified);
                rec.nrr_block_reason = Some(reason.slug());
                drop_reason = Some(reason);
            }
            // Joins its owner's outage list only on the terms the outage
            // notice is raised on.
            let mut outage_drop = false;
            // Surface every attributed drop in the NDJSON
            // (once per app/destination; see `log_drop_once`) and count it in
            // the tick summary so "N connections were being blocked right
            // then" is visible even with detail lines deduped away.
            if rec.verdict == ConnectionVerdict::Block {
                match rec.blocked_by_nrr {
                    Some(true) => summary.blocked_nrr += 1,
                    Some(false) => summary.blocked_foreign += 1,
                    None => {}
                }
                // Not an outage: the pinned link is up and both branches below
                // heal themselves, so this class is repaired, never announced —
                // a notice here would call a working route unavailable.
                let pinned_while_secondary_live =
                    killswitch_verified && secondary_ifindex.is_some();
                // Block-notice reporting: a foreign filter (`Some(false)`) is
                // never ours to explain, so only OUR drops reach the sink.
                if rec.blocked_by_nrr == Some(true)
                    && !pinned_while_secondary_live
                    && !service_account_drop
                {
                    self.note_block_attempt(&rec, killswitch_verified);
                    outage_drop = drop_reason
                        == Some(nrr_domain::block_notice::BlockReason::RouteUnavailable)
                        && !nrr_domain::address_class::is_local_housekeeping_endpoint(
                            rec.remote.ip(),
                            rec.remote.port(),
                        );
                }
                // Scope-bug detector: a kill-switch drop while
                // the secondary is resolved and USABLE should be impossible
                // (the block-all is only for outage windows). See the summary
                // field doc for the tolerated edge-of-window races.
                // A service bound to the main link is what the service-account
                // pin exists to catch, not a pin that outran its route.
                if rec.blocked_by_nrr == Some(true)
                    && pinned_while_secondary_live
                    && !service_account_drop
                {
                    summary.killswitch_drops_live_secondary += 1;
                    // Split by blocking scope. An app-scoped block
                    // covers destinations the routing layer has never seen, so
                    // its first-contact drop is expected and self-healing; only
                    // the destination-scoped remainder can be a scope bug, and
                    // that is the half worth naming in the WARN.
                    if killswitch_app_scoped {
                        summary.killswitch_drops_live_secondary_app_scope += 1;
                    } else {
                        // Routed through the tunnel, yet this socket is on the
                        // other link — a teardown candidate.
                        let rip = rec.remote.ip();
                        if stale_flow_victims.len() < MAX_STALE_FLOW_RESETS_PER_BATCH
                            || stale_flow_victims.contains_key(&rip)
                        {
                            stale_flow_victims
                                .entry(rip)
                                .or_default()
                                .note(rec.local, rec.user_sid.as_deref());
                        }
                        if dest_scope_sample.is_none() {
                            dest_scope_sample = Some(DropSample {
                                filter_id: obs.drop_filter_id.unwrap_or(0),
                                spec_id: rec.nrr_drop_spec_id.unwrap_or(0),
                                process: rec.process_path.clone().unwrap_or_default(),
                                remote: rec.remote,
                            });
                        }
                    }
                }
                self.log_drop_once(&rec, obs.drop_filter_id);
            }
            // Gate for the client-app learner: OUR drop, by a filter whose spec
            // id passes the wired role verification, from a VPN-named process.
            // `blocked_by_nrr` alone cannot tell a leak-guard drop from the
            // user's own Block rule.
            let role_verified_vpn_drop = rec.verdict == ConnectionVerdict::Block
                && rec.blocked_by_nrr == Some(true)
                && killswitch_verified
                && process_name_matches_vpn(rec.process_path.as_deref());
            // Proactive VPN-client learning: the same role-verified
            // drop also identifies the CLIENT PROCESS itself. Register it for an
            // app-scoped exemption so the next block-all arming permits the
            // whole process up front — its egress IS the tunnel's transport —
            // rather than any address it dialled: a CDN front a rule host
            // shares would become a hole. The client's role is proven by the
            // drop whichever address the check targeted.
            if let Some(learner) = self.vpn_client_app_learner.as_ref() {
                if role_verified_vpn_drop {
                    if let Some(path) = rec.process_path.as_deref() {
                        if app_learned_this_batch.insert(path.to_ascii_lowercase()) && learner(path)
                        {
                            summary.vpn_client_apps_learned += 1;
                        }
                    }
                }
            }
            // Another VPN's handshake the guard dropped, from nothing the
            // client learner above can name: a question for its owner. The
            // IPv6 cut counts here: it proves nothing about our tunnel, but a
            // handshake it stopped is the same question about a gateway.
            let ipv6_cut_drop = rec
                .nrr_drop_spec_id
                .zip(self.ipv6_cut_drop_check.as_ref())
                .is_some_and(|(spec_id, check)| check(spec_id));
            if let (Some(sink), Some(owner)) = (
                self.vpn_gateway_drop.as_ref(),
                rec.user_sid.as_deref().filter(|s| !s.is_empty()),
            ) {
                if rec.verdict == ConnectionVerdict::Block
                    && rec.blocked_by_nrr == Some(true)
                    && (killswitch_verified || ipv6_cut_drop)
                    && !service_account_drop
                    && !process_name_matches_vpn(rec.process_path.as_deref())
                    && crate::vpn_gateway_confirm::handshake_shaped(rec.protocol, rec.remote.port())
                {
                    let program = crate::vpn_gateway_confirm::handshake_program(
                        rec.protocol,
                        rec.local.port(),
                        rec.remote.port(),
                        rec.process_path.as_deref(),
                    );
                    sink(owner, rec.remote.ip(), program);
                }
            }
            // FCrDNS reverse-learning: our block of a routable V4 no rule
            // permitted (the browser-cache/DoH blind spot under block-all) is
            // named by the learner; a match caches it for the rule, a confirmed
            // name no rule matches is only reported. A user's own Block rule
            // still blocks. De-duped per batch.
            if let Some(learner) = self.reverse_dns_learner.as_ref() {
                if rec.verdict == ConnectionVerdict::Block
                    && rec.blocked_by_nrr == Some(true)
                    && !service_account_drop
                    // Never learn from a P2P process's dropped peers:
                    // their ISP-pool PTRs forward-confirm and match broad zone
                    // rules, flooding the zone permit cap with junk.
                    && !process_is_p2p_fcrdns_suppressed(rec.process_path.as_deref())
                    // A DoH/DoT lockdown drop is an app reaching for a resolver
                    // of its own. Naming it registers that resolver as a DIRECT
                    // host, and the exemption compiled for one outranks the
                    // lockdown block — the leak guard would undo itself.
                    && !self.is_dns_lockdown_drop(&rec)
                    // A deny names its destination already: asking the user's
                    // resolver about it again only sends the denied site out.
                    && !self.is_rule_block_drop(&rec)
                {
                    if let IpAddr::V4(rip) = rec.remote.ip() {
                        if is_learnable_endpoint(rip) && reverse_learned_this_batch.insert(rip) {
                            // An app-scoped kill-switch drop is the routed app
                            // waiting for its tunnel, not a name we failed to
                            // see. Naming it is still useful; calling it DIRECT
                            // would punch that app's destination out of the
                            // block-all.
                            learner(
                                rip,
                                !(killswitch_verified && killswitch_app_scoped),
                                crate::conn_observation_consumer::ReverseLearnOrigin::EnforcementDrop,
                                rec.user_sid.as_deref(),
                            );
                        }
                    }
                }
            }
            // App-routing via observation: record (app → remote IP)
            // so the codegen routes this app's destinations via the secondary on
            // the next apply. The store ignores unroutable IPs itself.
            //
            // Before recording, the reverse question: is this flow somebody
            // ELSE riding a route an application rule installed? A host route
            // cannot be scoped to a process, so an address learned for one
            // application moves every process that talks to it — which is how a
            // site the user put on the main link ended up inside the tunnel.
            // A foreign process EGRESSING THE SECONDARY on such an address is
            // that collateral, in the act; nothing else needs to go wrong first,
            // and waiting for a failure would mean waiting for a timeout that
            // may never come. The pin comes off and the owner does not relearn
            // it this session.
            // Kept per user where routes are: the owner's own store.
            if let Some(store) = self
                .app_observations
                .as_ref()
                .and_then(|store| store.scope_for(rec.user_sid.as_deref()))
            {
                if let (Some(path), IpAddr::V4(rip)) =
                    (rec.process_path.as_deref(), rec.remote.ip())
                {
                    let this_app = crate::app_observation_lookup::app_key(path);
                    // Who the remembered rows of this store belong to.
                    let per_user = self
                        .app_observations
                        .as_ref()
                        .is_some_and(|root| root.keeps_per_principal());
                    let persisted_owner = if per_user {
                        rec.user_sid.as_deref()
                    } else {
                        None
                    };
                    let pid = self.pid_of(obs, &store, &mut flow_pid_lookups_left);
                    let script_rules = self.script_rule_paths(
                        &store,
                        pid,
                        path,
                        ScriptOwner {
                            per_user,
                            owner: rec.user_sid.as_deref(),
                            active: active_sid_now.as_deref(),
                        },
                        &mut scripts_this_batch,
                    );
                    for owner in collateral_pin_owners(
                        &store,
                        path,
                        &script_rules,
                        crate::app_observation_lookup::own_process_key(),
                        &routed_apps,
                        rec.egress.role,
                        rip,
                    ) {
                        if store.retract(&owner, rip) {
                            summary.app_ips_retracted += 1;
                            if let Some(forget) = self.app_destination_forget.as_ref() {
                                forget(persisted_owner, &owner, rip);
                            }
                            tracing::info!(
                                target: "nrr::conn-trace",
                                msg_key = "connobs-app-pin-withdrawn",
                                owner = %owner,
                                intruder = %this_app,
                                destination = %rip,
                                "withdrew a destination an application rule had pinned: another process was travelling the additional link on it, and a host route cannot tell the two apart. That address goes back to the main link for everyone, this application included",
                            );
                        }
                    }
                    // Evidence first, claim second: the census must see this
                    // process before the rule set is compiled against it, or a
                    // destination could be pinned in the same tick that proved
                    // somebody else was already using it.
                    // Learnt whatever link the flow left on: "other" is also an
                    // unresolved main link or a second uplink. What a corporate
                    // tunnel owns, and private space, the store refuses by
                    // address.
                    store.note_process_destination_running(path, obs.pid, &script_rules, rip);
                    if store.record(path, rip) {
                        summary.app_ips_added += 1;
                    }
                    if store.record_for_rule_paths(&script_rules, rip) {
                        summary.app_ips_added += 1;
                    }
                }
            }
            // A flow leaving over the primary while the user is on a routed
            // site IS the half-broken page. The ledger decides whether it means
            // anything — it only counts inside an open anchor window — so the
            // observer stays a reporter of facts.
            if rec.egress.role == EgressRole::Secondary {
                self.note_owner_on_secondary(rec.user_sid.as_deref());
                // Same outcome filter as the main-link half: only what the stack
                // established went over the link.
                if establishes {
                    self.note_app_additional_link(&rec);
                }
            }
            if rec.egress.role == EgressRole::Primary {
                self.note_companion_in_use(rec.remote.ip(), rec.user_sid.as_deref());
                self.remember_program(&rec, rec.observed_unix_ms.unwrap_or(now_ms));
            }
            // Did the user go there, or did a page take them there? Measured
            // on the event's OWN timestamp: the batch is drained on a timer,
            // and the drain time would collapse a whole interval onto one
            // instant. A backend that stamps nothing degrades to exactly that,
            // which is why the fallback is last, not first.
            self.note_navigation_attempt(
                rec.user_sid.as_deref(),
                rec.process_path.as_deref(),
                rec.remote.ip(),
                rec.observed_unix_ms.unwrap_or_else(now_unix_ms),
            );
            match rec.egress.role {
                EgressRole::Primary => summary.primary += 1,
                EgressRole::Secondary => summary.secondary += 1,
                EgressRole::Loopback => summary.loopback += 1,
                EgressRole::Other => summary.other += 1,
                EgressRole::Unknown => summary.unknown += 1,
            }
            if log_ndjson {
                log_observed_connection(&rec);
            }
            // Retain for the Diagnostics panel (last use of `rec`).
            if let Some(ring) = self.trace_ring.as_ref() {
                let outage_at_ms = outage_drop.then(|| rec.observed_unix_ms.unwrap_or(now_ms));
                ring.push_noting_outage(rec, outage_at_ms);
            }
        }
        // The scope-bug indicator must be loud: this count is
        // supposed to be zero (see the summary field doc), so any nonzero
        // batch gets one WARN (bounded by the ~5 s drain cadence, and only
        // while the condition actually occurs).
        //
        // WARN only on the DESTINATION-scoped half. An app pin
        // covers every destination its process talks to, including addresses
        // routing has never seen, so its first-contact drop is expected and
        // self-healing (the drop is the observation that creates the route);
        // it gets an INFO line naming the volume instead of a WARN that cries
        // wolf. The destination-scoped half keeps the WARN and names the
        // dropping filter, its spec id, the process and one victim address,
        // so a diagnosis does not depend on cross-referencing a bare count
        // against the per-drop lines.
        let dest_scope = summary.killswitch_drops_live_secondary_dest_scope();
        if dest_scope > 0 {
            let sample = dest_scope_sample.unwrap_or_default();
            // Two different faults produce this same count, and saying only the
            // first one sent a live diagnosis down the wrong path: a socket
            // OLDER than the pin (torn down below, gone next batch) versus an
            // application that keeps dialling the pinned address because it
            // still holds the pre-rule DNS answer — that one survives the
            // teardown and needs a re-query, not a reset. Which one it is shows
            // in whether we already tore this destination down.
            let repeat = stale_flow_victims
                .keys()
                .any(|ip| self.was_torn_down_before(*ip));
            if repeat {
                tracing::warn!(
                    target: "nrr::conn-trace",
                    msg_key = "connobs-stale-pin-repeat-drop",
                    count = dest_scope,
                    filter_id = sample.filter_id,
                    spec_id = sample.spec_id,
                    process = sample.process.as_str(),
                    remote = %sample.remote,
                    "a destination pin is still dropping connections we already tore down — the application is dialling the address it was answered with BEFORE the rule existed, so no reset can fix it; it needs a fresh lookup (the OS resolver cache is flushed on a rule change) or the pin has no working path at all",
                );
            } else {
                tracing::warn!(
                    target: "nrr::conn-trace",
                    msg_key = "connobs-stale-pin-live-secondary-drop",
                    count = dest_scope,
                    app_scoped = summary.killswitch_drops_live_secondary_app_scope,
                    filter_id = sample.filter_id,
                    spec_id = sample.spec_id,
                    process = sample.process.as_str(),
                    remote = %sample.remote,
                    "a destination pin dropped connections while the secondary was resolved and USABLE — a socket older than the pin, kept on the wrong interface for life, which the teardown below repairs. The sampled filter/spec/process/remote is one concrete victim of this batch",
                );
            }
        }
        // The socket predates the pin and can never reach the tunnel; tearing it
        // down is what makes the application reconnect onto the route.
        // Only the dropped sockets and their owners' siblings: the pin is one
        // user's, and another user's connection to the address is not behind it.
        if let Some(reset) = self
            .stale_flow_reset
            .as_ref()
            .filter(|_| !stale_flow_victims.is_empty())
        {
            let addresses: Vec<std::net::IpAddr> = stale_flow_victims.keys().copied().collect();
            let shared_direct = self
                .flow_reset_census
                .as_ref()
                .map(|census| census.shared_direct_ips())
                .unwrap_or_default();
            let flows = drop_reporter::pin_drop_resets(
                reset.established_flows_to(&addresses),
                &stale_flow_victims,
                &shared_direct,
                |owner| {
                    let (primary, secondary) = (self.egress_of)(owner);
                    nrr_platform_api::fake_ip::stale_flows::FlowLinks::new(
                        unicast.clone(),
                        primary,
                        secondary,
                    )
                },
            );
            let torn_down = self.own_flow_resets.reset(reset.as_ref(), &flows);
            for ip in flows
                .iter()
                .map(|flow| flow.remote.ip())
                .collect::<std::collections::BTreeSet<_>>()
            {
                self.note_torn_down(ip);
            }
            if torn_down > 0 {
                crate::flow_reset_log::log_reset_flows(None, &flows, |_| {
                    (None, crate::flow_reset_log::ResetCause::PinDrop)
                });
                tracing::info!(
                    target: "nrr::conn-trace",
                    msg_key = "connobs-stale-flows-torn-down",
                    torn_down,
                    destinations = stale_flow_victims.len(),
                    "tore down connections a destination pin caught on the wrong link — the application reconnects over the additional route",
                );
            }
        }
        if summary.killswitch_drops_live_secondary_app_scope > 0 {
            tracing::info!(
                target: "nrr::conn-trace",
                msg_key = "connobs-app-pin-first-contact-drop",
                count = summary.killswitch_drops_live_secondary_app_scope,
                "app-pinned processes hit the kill-switch on destinations that are not routed through the additional link yet — expected first contact: the drop is what teaches the destination, and the route plus its own pin follow on the next reconcile",
            );
        }
        summary
    }

    /// `owner`'s links, asked once per batch. An owner whose additional route
    /// is usable has no outage, whatever the status said last.
    fn owner_links(
        &self,
        seen: &mut std::collections::HashMap<String, (Option<u32>, Option<u32>)>,
        owner: Option<&str>,
        now_ms: u64,
    ) -> (Option<u32>, Option<u32>) {
        let Some(owner) = owner.filter(|o| !o.is_empty()) else {
            return (None, None);
        };
        if let Some(links) = seen.get(owner) {
            return *links;
        }
        let links = (self.egress_of)(owner);
        if let (Some(ring), Some(_)) = (self.trace_ring.as_ref(), links.1) {
            ring.outage_blocks().outage_ended(owner, now_ms);
        }
        seen.insert(owner.to_owned(), links);
        links
    }

    /// `obs.pid`, or for a TCP connection reported without one, the process
    /// still holding the flow — asked only while a rule names a path, within
    /// `left` lookups.
    fn pid_of(
        &self,
        obs: &ConnectionObservation,
        store: &AppObservationStore,
        left: &mut u32,
    ) -> u32 {
        if obs.pid != 0 || *left == 0 || !matches!(obs.protocol, TransportProtocol::Tcp) {
            return obs.pid;
        }
        let Some(lookup) = self.flow_pid.as_ref() else {
            return 0;
        };
        if self.script_launches.is_none() || !store.watches_paths() {
            return 0;
        }
        *left -= 1;
        lookup(obs.local, obs.remote).unwrap_or(0)
    }

    /// The rule paths whose script the process `pid` runs, for its own
    /// observations only.
    fn script_rule_paths(
        &self,
        store: &AppObservationStore,
        pid: u32,
        image: &str,
        whose: ScriptOwner<'_>,
        memo: &mut std::collections::HashMap<u32, Vec<String>>,
    ) -> Vec<String> {
        let Some(launches) = self.script_launches.as_ref() else {
            return Vec::new();
        };
        // One store serves the routing user's plan here. Machine accounts
        // follow that user's rules, as their programs do; another person's
        // script in that user's folder must not move the user's routes.
        let credited = whose.per_user
            || whose.owner.is_some_and(|owner| {
                whose.active == Some(owner)
                    || nrr_platform_api::types::is_service_account_sid(owner)
            });
        if !credited {
            return Vec::new();
        }
        memo.entry(pid)
            .or_insert_with(|| launches.rule_paths_run_by(store, pid, image))
            .clone()
    }
}

/// Whose observations a connection teaches.
struct ScriptOwner<'a> {
    /// The store is the connection owner's own.
    per_user: bool,
    owner: Option<&'a str>,
    active: Option<&'a str>,
}
