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
    pub fn consume(&self, batch: &[ConnectionObservation], _now: SystemTime) -> ConnConsumeSummary {
        let mut summary = ConnConsumeSummary::default();
        if batch.is_empty() {
            return summary;
        }

        // Live context, read once per batch. Prefer the full unicast table
        // (IPv4 + IPv6 → ifindex) so v6 egress is labelled; fall back to the
        // IPv4-only adapter table if that query is unavailable.
        let mut unicast = self.api.unicast_ip_addresses().unwrap_or_default();
        if unicast.is_empty() {
            unicast = build_unicast_table(&self.api.get_adapter_infos().unwrap_or_default());
        }
        let active_sid_now = (self.active_sid)();
        // Once per batch: the collateral check consults it for every observation
        // and a rule edit must land without a restart.
        let routed_apps: Vec<String> = self
            .routed_apps
            .as_ref()
            .map(|read| read())
            .unwrap_or_default();
        let (primary_ifindex, secondary_ifindex) = match active_sid_now.as_deref() {
            Some(sid) => self.coordinator.resolve_egress_ifindexes(sid),
            None => (None, None),
        };
        // The "no rule covers this host" catch-all's id is deterministic
        // (same hash the codegen used to mint it) — computed once per batch,
        // only when a sink is actually wired, so an idle observer never pays
        // for it.
        let default_block_id: Option<u64> = self.block_notice_sink.as_ref().and_then(|_| {
            active_sid_now.as_deref().map(|sid| {
                crate::wfp_codegen::filter_id_for(sid, "default", "", "default", "block-all").raw
            })
        });

        // De-dup learned endpoints within the batch
        // so a burst of drops to one server calls the learner once.
        let mut learned_this_batch: std::collections::HashSet<std::net::Ipv4Addr> =
            std::collections::HashSet::new();
        // Separate per-batch dedup for the FCrDNS learner so it
        // never couples with the VPN learner's dedup above (different concerns,
        // same IP could matter to both).
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
        let mut stale_flow_victims: std::collections::BTreeSet<std::net::Ipv4Addr> =
            std::collections::BTreeSet::new();

        for obs in batch {
            let rec = classify_connection(obs, &unicast, primary_ifindex, secondary_ifindex);
            // A resend or an orderly close is evidence about a peer, not a
            // connection of its own: it must never become a trace row, an
            // NDJSON line, an app→IP fact or a drop statistic. Only the primary
            // link is asked about — the offer is "move this into the tunnel",
            // and how a host behaves once already inside it answers nothing.
            if obs.progress != ConnectionProgress::Attempt {
                if rec.egress.role == EgressRole::Primary {
                    self.note_companion_primary_health(
                        rec.remote.ip(),
                        obs.progress == ConnectionProgress::Retransmit,
                    );
                }
                continue;
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
                if rec.blocked_by_nrr == Some(true) && !pinned_while_secondary_live {
                    self.note_block_attempt(&rec, killswitch_verified, default_block_id);
                }
                // Scope-bug detector: a kill-switch drop while
                // the secondary is resolved and USABLE should be impossible
                // (the block-all is only for outage windows). See the summary
                // field doc for the tolerated edge-of-window races.
                if rec.blocked_by_nrr == Some(true) && pinned_while_secondary_live {
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
                        if let IpAddr::V4(rip) = rec.remote.ip() {
                            if stale_flow_victims.len() < MAX_STALE_FLOW_RESETS_PER_BATCH {
                                stale_flow_victims.insert(rip);
                            }
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
            // Reactive self-learning: a flow that OUR kill-switch/fail-closed
            // Block dropped, from a process whose name matches a VPN-client
            // pattern, teaches the exemption set the tunnel's server IP, so the
            // client's own retry (VPN clients retry) is permitted and the
            // tunnel comes up — no user action, no first-connect deadlock.
            // Requires ALL of: our drop, a VPN-named process, a routable V4
            // remote, AND the dropping filter's spec id passing the wired
            // role-verification check — `blocked_by_nrr` alone cannot tell a
            // leak-guard drop from the user's own Block rule, so without a
            // verified spec id membership in the kill-switch registry the
            // learner never fires.
            // Shared gate for both VPN learners: OUR drop, whose filter's spec
            // id passes the wired role-verification check, from a VPN-named
            // process. Absence of a wired check keeps both learners inert.
            let role_verified_vpn_drop = rec.verdict == ConnectionVerdict::Block
                && rec.blocked_by_nrr == Some(true)
                && killswitch_verified
                && process_name_matches_vpn(rec.process_path.as_deref());
            if let Some(learner) = self.vpn_endpoint_learner.as_ref() {
                if role_verified_vpn_drop {
                    if let IpAddr::V4(rip) = rec.remote.ip() {
                        if is_learnable_endpoint(rip) && learned_this_batch.insert(rip) {
                            learner(rip);
                            summary.vpn_endpoints_learned += 1;
                            tracing::info!(
                                target: "nrr::vpn-learn",
                                server = %rip,
                                process = rec.process_path.as_deref().unwrap_or("?"),
                                "learned VPN bootstrap endpoint from a role-verified kill-switch drop — exempting so the tunnel can reconnect",
                            );
                        }
                    }
                }
            }
            // Proactive VPN-client learning: the same role-verified
            // drop also identifies the CLIENT PROCESS itself. Register it for an
            // app-scoped exemption so the next block-all arming permits the
            // whole process up front — its egress IS the tunnel's transport —
            // instead of chasing one rotated endpoint IP per drop (the
            // hidemy.name-over-rotating-Google-IPs failure mode). Not gated on
            // the remote IP being a learnable endpoint: the client's role is
            // proven by the drop regardless of which address the check targeted.
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
            // FCrDNS reverse-learning: OUR block
            // of a routable V4 that no rule permitted (the browser-cache/DoH blind
            // spot under block-all) is handed to the learner, which names the IP
            // (PTR + forward-confirm) and caches it iff it matches a rule. NOT
            // gated on the process name and safe even if `blocked_by_nrr` over-
            // attributes (it grants no exemption — only the rule-gated cache; a
            // user's own Block rule still blocks). De-duped per batch.
            if let Some(learner) = self.reverse_dns_learner.as_ref() {
                if rec.verdict == ConnectionVerdict::Block
                    && rec.blocked_by_nrr == Some(true)
                    // Never learn from a P2P process's dropped peers:
                    // their ISP-pool PTRs forward-confirm and match broad zone
                    // rules, flooding the zone permit cap with junk.
                    && !process_is_p2p_fcrdns_suppressed(rec.process_path.as_deref())
                    // A DoH/DoT lockdown drop is an app reaching for a resolver
                    // of its own. Naming it registers that resolver as a DIRECT
                    // host, and the exemption compiled for one outranks the
                    // lockdown block — the leak guard would undo itself.
                    && !self.is_dns_lockdown_drop(&rec)
                {
                    if let IpAddr::V4(rip) = rec.remote.ip() {
                        if is_learnable_endpoint(rip) && reverse_learned_this_batch.insert(rip) {
                            // An app-scoped kill-switch drop is the routed app
                            // waiting for its tunnel, not a name we failed to
                            // see. Naming it is still useful; calling it DIRECT
                            // would punch that app's destination out of the
                            // block-all.
                            learner(rip, !(killswitch_verified && killswitch_app_scoped));
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
            if let Some(store) = self.app_observations.as_ref() {
                if let (Some(path), IpAddr::V4(rip)) =
                    (rec.process_path.as_deref(), rec.remote.ip())
                {
                    let this_app = crate::app_observation_lookup::app_key(path);
                    for owner in collateral_pin_owners(
                        store,
                        &this_app,
                        crate::app_observation_lookup::own_process_key(),
                        &routed_apps,
                        rec.egress.role,
                        rip,
                    ) {
                        if store.retract(&owner, rip) {
                            summary.app_ips_retracted += 1;
                            if let Some(forget) = self.app_destination_forget.as_ref() {
                                forget(&owner, rip);
                            }
                            tracing::info!(
                                target: "nrr::conn-trace",
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
                    store.note_process_destination(path, rip);
                    if store.record(path, rip) {
                        summary.app_ips_added += 1;
                    }
                }
            }
            // A flow leaving over the primary while the user is on a routed
            // site IS the half-broken page. The ledger decides whether it means
            // anything — it only counts inside an open anchor window — so the
            // observer stays a reporter of facts.
            if rec.egress.role == EgressRole::Secondary {
                *self
                    .last_secondary_at
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
            }
            if rec.egress.role == EgressRole::Primary {
                self.note_companion_in_use(rec.remote.ip());
            }
            match rec.egress.role {
                EgressRole::Primary => summary.primary += 1,
                EgressRole::Secondary => summary.secondary += 1,
                EgressRole::Loopback => summary.loopback += 1,
                EgressRole::Other => summary.other += 1,
                EgressRole::Unknown => summary.unknown += 1,
            }
            if self.log_ndjson {
                tracing::info!(
                    target: "nrr::conn-trace",
                    process = rec.process_path.as_deref().unwrap_or("?"),
                    sid = rec.user_sid.as_deref().unwrap_or("?"),
                    proto = proto_str(rec.protocol),
                    remote = %rec.remote,
                    local = %rec.local,
                    egress_ifindex = rec.egress.ifindex,
                    egress = role_str(rec.egress.role),
                    verdict = verdict_str(rec.verdict),
                    "observed outbound connection",
                );
            }
            // Retain for the Diagnostics panel (last use of `rec`).
            if let Some(ring) = self.trace_ring.as_ref() {
                ring.push(rec);
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
                .iter()
                .any(|ip| self.was_torn_down_before(*ip));
            if repeat {
                tracing::warn!(
                    target: "nrr::conn-trace",
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
        if let Some(reset) = self.stale_flow_reset.as_ref() {
            let mut torn_down = 0usize;
            for ip in &stale_flow_victims {
                torn_down = torn_down.saturating_add(reset.reset_flows_to(*ip, 32).torn_down);
                self.note_torn_down(*ip);
            }
            if torn_down > 0 {
                tracing::info!(
                    target: "nrr::conn-trace",
                    torn_down,
                    destinations = stale_flow_victims.len(),
                    "tore down connections a destination pin caught on the wrong link — the application reconnects over the additional route",
                );
            }
        }
        if summary.killswitch_drops_live_secondary_app_scope > 0 {
            tracing::info!(
                target: "nrr::conn-trace",
                count = summary.killswitch_drops_live_secondary_app_scope,
                "app-pinned processes hit the kill-switch on destinations that are not routed through the additional link yet — expected first contact: the drop is what teaches the destination, and the route plus its own pin follow on the next reconcile",
            );
        }
        summary
    }
}
