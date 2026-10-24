//! Posture bookkeeping: the rate-limited posture-log latch, the per-SID
//! notification helpers (block-all / fail-closed / machine-wide-cut / new
//! app rules / cross-set duplicates), and the fail-closed filter builder
//! those notifications key off.

use super::*;

/// Outcome of the posture rate-limiter for one log call: whether it should
/// log at full level because the posture just changed, at full level again
/// because the (unchanged) posture has persisted long enough to earn a
/// heartbeat, or be suppressed to `debug` as steady-state repetition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PostureLogEvent {
    /// The posture differs from the last one latched for this SID (or
    /// nothing was latched yet).
    Transition,
    /// The posture is unchanged, but at least the heartbeat interval has
    /// elapsed since the last full-level line for it. Carries the time
    /// since the posture was first entered.
    Heartbeat { elapsed: Duration },
    /// The posture is unchanged and the heartbeat interval has not yet
    /// elapsed.
    Steady,
}

/// Latch recorded per SID behind the posture rate-limiter: which posture is
/// current, when it was entered, and when it last logged at full level.
#[derive(Debug, Clone, Copy)]
pub(super) struct PostureLogLatch {
    pub(super) posture: &'static str,
    entered_at: Instant,
    last_logged_at: Instant,
}

/// `(kept, dropped, app_covered)` of one pin-set trim.
pub(super) type PinTrimCounts = (usize, usize, usize);

/// How often an unchanged, persisting posture re-announces itself at full
/// level (see [`PostureLogEvent::Heartbeat`]). A long block-all session that
/// never changes state would otherwise go from two WARN lines straight to
/// silence for its entire duration — this keeps a periodic "still here"
/// trail without flooding steady-state ticks.
pub(super) const POSTURE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Pure decision core behind the posture rate-limiter: given the latch
/// previously recorded for a SID (if any), the posture this compute just
/// derived, and the current time, decide whether this call is a state
/// transition, a periodic heartbeat, or steady-state repetition — and the
/// latch to store afterwards. Free of locks/HashMaps so it is unit-testable
/// without a live orchestrator or a real clock (callers can synthesize
/// future `Instant`s via `Instant::now() + Duration::from_secs(n)`).
pub(super) fn evaluate_posture_log(
    prior: Option<PostureLogLatch>,
    posture: &'static str,
    now: Instant,
    heartbeat_interval: Duration,
) -> (PostureLogEvent, PostureLogLatch) {
    if let Some(latch) = prior {
        if latch.posture == posture {
            return if now.duration_since(latch.last_logged_at) >= heartbeat_interval {
                (
                    PostureLogEvent::Heartbeat {
                        elapsed: now.duration_since(latch.entered_at),
                    },
                    PostureLogLatch {
                        last_logged_at: now,
                        ..latch
                    },
                )
            } else {
                (PostureLogEvent::Steady, latch)
            };
        }
    }
    (
        PostureLogEvent::Transition,
        PostureLogLatch {
            posture,
            entered_at: now,
            last_logged_at: now,
        },
    )
}

/// The protected set minus the tunnel's own endpoints, in either family.
///
/// Blocking the address the tunnel dials is how an outage becomes permanent:
/// the guard arms because the link is gone, and the handshake that would bring
/// it back is the first thing the guard drops.
fn exempt_tunnel_servers(
    protected: &[std::net::IpAddr],
    exemptions: &FailClosedExemptions,
) -> Vec<std::net::IpAddr> {
    protected
        .iter()
        .copied()
        .filter(|ip| match ip {
            std::net::IpAddr::V4(v4) => !exemptions.bootstrap_server_ips.contains(v4),
            std::net::IpAddr::V6(v6) => !exemptions.bootstrap_server_ips_v6.contains(v6),
        })
        .collect()
}

/// The tunnel's own destinations — addresses and networks — blocked by name
/// on top of a blanket block.
///
/// The blanket sits below the main-link rule band, so a program the user
/// routes to the main link passes it — and would reach a host or a network
/// the tunnel owns over the main link while the tunnel is down. The pins and
/// the holds sit above that band: an address a rule names belongs to that
/// rule, whatever program dials it. ALE only — the blanket already covers the
/// packet layer, and the per-chunk packet blocks would share its weights.
fn named_destination_blocks_under_block_all(
    sid: &str,
    protected_secondary_ips: &[std::net::IpAddr],
    holds: &crate::enforcement_planner::NetworkHolds,
    exemptions: &FailClosedExemptions,
    protocols: crate::killswitch_codegen::KillSwitchProtocols,
) -> Vec<WfpFilterSpec> {
    let ale_only = crate::killswitch_codegen::KillSwitchProtocols {
        icmp: false,
        igmp: false,
        gre: false,
        esp: false,
        other: false,
        ..protocols
    };
    let protected = exempt_tunnel_servers(protected_secondary_ips, exemptions);
    let mut out =
        crate::killswitch_codegen::fail_closed_block_destinations(sid, &protected, ale_only);
    out.extend(crate::killswitch_codegen::fail_closed_network_filters(
        sid, holds, ale_only,
    ));
    out
}

impl PerSidApplyOrchestrator {
    /// Executables recognised as VPN clients by name but not yet trusted by
    /// place are listed per principal; a principal whose enforcement is gone
    /// has none to ask about.
    pub(super) fn clear_pending_vpn_clients(&self, sid: &str) {
        crate::vpn_client_trust::global_pending_vpn_clients().publish(sid, &[]);
    }

    /// Record whether the latest compute for `sid` produced a fail-closed
    /// block-all set and flush the OS resolver cache on the transition
    /// EDGE (both directions):
    ///
    /// - disarmed → armed: everything the user resolved *before* the block
    ///   must re-query on the wire so the DNS observer sees it and the next
    ///   reconcile builds its permit (otherwise a `zone → primary` host the
    ///   OS already cached stays blocked with no diagnostic trail);
    /// - armed → disarmed: negative/blocked-era entries must not linger.
    ///
    /// Steady states never flush — the leak-guard reconcile recomputes every
    /// few seconds and a per-tick flush would defeat the OS cache entirely.
    /// `true` when it flushed, so the fail-closed edge of the same compute
    /// need not flush again; a failed flush leaves that edge its own try.
    /// Publish whether anyone's traffic waits for their additional link.
    pub(super) fn note_outage_hold(&self, sid: &str, holding: bool) {
        let any = {
            let mut g = self
                .outage_hold_state
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if holding {
                g.insert(sid.to_owned());
            } else {
                g.remove(sid);
            }
            !g.is_empty()
        };
        if let Some(status) = self.block_all_posture_status.as_ref() {
            status.set_outage(any);
        }
    }

    pub(super) fn note_block_all_state(&self, sid: &str, armed: bool) -> bool {
        let transitioned = {
            let mut g = self
                .block_all_flush_state
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let prior = g.get(sid).copied().unwrap_or(false);
            if prior != armed {
                g.insert(sid.to_string(), armed);
                true
            } else {
                false
            }
        };
        if !transitioned {
            return false;
        }
        // publish the new "any SID armed?" posture for the GUI
        // banner. On the transition edge only (same throttle as the flush).
        if let Some(status) = self.block_all_posture_status.as_ref() {
            status.set(self.any_block_all_armed());
        }
        // Another armed user's plan decides its machine-wide IPv6 packet cut by
        // who else blocks, so this edge changes their plan too.
        if self.other_principals_hold_block_all(sid) {
            if let Some(request) = self.peer_replan.as_ref() {
                request();
            }
        }
        match self.dns_cache_control.flush_resolver_cache() {
            Ok(()) => {
                tracing::info!(
                    target: "nrr::per_sid_orchestrator",
                    msg_key = "persid-posture-dns-flush-ok",
                    sid,
                    block_all_armed = armed,
                    "flushed OS DNS resolver cache on kill-switch block-all transition — pre-transition cached names will re-query and become observable",
                );
                true
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::per_sid_orchestrator",
                    msg_key = "persid-posture-dns-flush-failed",
                    sid,
                    block_all_armed = armed,
                    error = %e,
                    "OS DNS resolver cache flush failed on kill-switch block-all transition — names the OS already cached stay invisible to the DNS observer until their TTL expires",
                );
                false
            }
        }
    }

    /// Record whether the latest compute for `sid` left the guard BLOCKING with
    /// the additional link unresolved, and publish the "any SID armed?" answer
    /// on the transition edge.
    ///
    /// The OS cache is flushed once on each edge: when the guard takes hold, an
    /// address cached while the tunnel was up would otherwise carry a rule
    /// host over the main link (one the census spared is not blocked); when
    /// it lets go, the failures it caused would otherwise outlive it.
    pub(super) fn note_fail_closed_state(&self, sid: &str, armed: bool, cache_flushed: bool) {
        let transitioned = {
            let mut g = self
                .fail_closed_state
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let prior = g.get(sid).copied().unwrap_or(false);
            if prior != armed {
                g.insert(sid.to_string(), armed);
                true
            } else {
                false
            }
        };
        if !transitioned {
            return;
        }
        if let Some(status) = self.fail_closed_posture_status.as_ref() {
            status.set(self.any_fail_closed_armed());
        }
        if !cache_flushed {
            if let Err(e) = self.dns_cache_control.flush_resolver_cache() {
                tracing::warn!(
                    target: "nrr::per_sid_orchestrator",
                    msg_key = "persid-posture-dns-flush-link-edge-failed",
                    sid,
                    error = %e,
                    "OS DNS resolver cache flush failed as the additional link went down or came back — cached answers outlive the change until their TTL expires",
                );
            }
        }
    }

    /// Drop every per-SID record describing an enforcement that is gone: the
    /// installed-filter set, both posture latches, the kill-switch block-id
    /// registry and the posture-log throttle (so a later re-arm logs as the
    /// transition it is, not as a steady state).
    pub(super) fn forget_sid_state(&self, sid: &str) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
        crate::enforced_addresses::global_enforced_addresses().forget(sid);
        crate::ipv6_disposition::global_ipv6_dispositions().forget(sid);
        super::plan::note_machine_volume(crate::standing_volume::global_standing_volume().forget(
            sid,
            nrr_platform_api::enforcement::EnforcementCapabilities::current().standing_filter_alarm,
        ));
        let flushed = self.note_block_all_state(sid, false);
        self.note_outage_hold(sid, false);
        self.note_fail_closed_state(sid, false, flushed);
        self.update_killswitch_registry(sid, KillswitchBlockIds::default());
        self.clear_pending_vpn_clients(sid);
        // A cut asked for by someone gone must not be blamed on them later.
        self.machine_wide_cut_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
        self.posture_log_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
        self.pin_trim_log_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
        self.network_hold_log.forget(sid);
    }

    /// Whether this trim differs from the last one logged for `sid`; `None`
    /// (nothing trimmed) re-arms it.
    pub(super) fn pin_trim_changed(&self, sid: &str, counts: Option<PinTrimCounts>) -> bool {
        let mut g = self
            .pin_trim_log_state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match counts {
            None => {
                g.remove(sid);
                false
            }
            Some(counts) if g.get(sid) == Some(&counts) => false,
            Some(counts) => {
                g.insert(sid.to_string(), counts);
                true
            }
        }
    }

    /// Tell everyone else when somebody arms a cut that reaches them.
    ///
    /// Published on the CHANGE only, and only to principals whose own plan asks
    /// for no such cut: a notice repeated on every recompute is one the user
    /// learns to dismiss without reading. The Linux side does the same from
    /// `PrincipalEnforcementCycle` — same event, same slug, because the
    /// limitation is the packet layer's on both systems, not this backend's.
    pub(super) fn note_machine_wide_cut(&self, sid: &str, wants: bool) {
        let (changed, bystanders) = {
            let mut g = self
                .machine_wide_cut_state
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let prior = g.insert(sid.to_string(), wants);
            let changed = prior != Some(wants);
            // Where a cut is limited to one account nobody else is affected.
            let anybody_cuts = !nrr_platform_api::enforcement::EnforcementCapabilities::current()
                .per_user_all_protocol_scoping
                && g.values().any(|v| *v);
            let bystanders: Vec<String> = if anybody_cuts {
                g.iter()
                    .filter(|(_, cuts)| !**cuts)
                    .map(|(other, _)| other.clone())
                    .collect()
            } else {
                Vec::new()
            };
            (changed, bystanders)
        };
        if !changed || bystanders.is_empty() {
            return;
        }
        let Some(bus) = self.events.as_ref() else {
            return;
        };
        for other in bystanders {
            bus.publish_for(
                other,
                nrr_shared::ipc_payloads::StatusUpdateEvent::ProtectionCoverageChanged {
                    reason: "machine-wide-cut-by-another-user".to_string(),
                },
            );
        }
    }

    /// Tell the user when an application rule is delivered for the first time.
    ///
    /// Its route exists only for addresses the service has already seen the
    /// program use, so the first contact with each new one is refused while it
    /// is learnt. A program that gives up on that refusal looks broken until it
    /// is restarted, and nothing on screen would explain why.
    pub(super) fn note_new_app_rules(&self, sid: &str, secondary_apps: &[String]) {
        let current: std::collections::BTreeSet<String> = secondary_apps.iter().cloned().collect();
        let fresh: Vec<String> = {
            let mut announced = self
                .announced_app_rules
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let known = announced.entry(sid.to_string()).or_default();
            let fresh: Vec<String> = current.difference(known).cloned().collect();
            // Replaced wholesale: a rule the user removed and adds again is news
            // for the same reason it was the first time.
            *known = current;
            fresh
        };
        if fresh.is_empty() {
            return;
        }
        tracing::info!(
            target: "nrr::per_sid_orchestrator",
            msg_key = "persid-posture-app-rules-learning",
            sid,
            apps = %fresh.join(", "),
            "application rules delivered for the first time — their destinations are still being learnt",
        );
        if let Some(bus) = self.events.as_ref() {
            bus.publish_for(
                sid,
                nrr_shared::ipc_payloads::StatusUpdateEvent::AppRuleLearningDestinations {
                    sid: sid.to_string(),
                    apps: fresh,
                },
            );
        }
    }

    /// Say when this SID's active rules name the same traffic on both routes
    /// with both copies enabled.
    ///
    /// Nothing in the running policy shows this: the rules are valid, they
    /// simply disagree about where the traffic goes, and evaluation order
    /// settles it instead of the user. Reported on apply and only when the set
    /// changes — the condition lasts until they resolve it.
    pub(super) fn note_cross_set_duplicates(
        &self,
        sid: &str,
        book: &nrr_domain::canonical::CanonicalRuleBook,
    ) {
        let found = nrr_domain::validation::enabled_duplicates_across_sets(book);
        let fingerprint = found
            .iter()
            .map(|pair| pair.match_summary.as_str())
            .collect::<Vec<_>>()
            .join("|");
        {
            let mut seen = self
                .cross_set_duplicate_state
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if seen.get(sid).map(String::as_str) == Some(fingerprint.as_str()) {
                return;
            }
            seen.insert(sid.to_string(), fingerprint);
        }
        let Some(first) = found.first() else {
            return; // resolved — nothing to announce, the state was recorded
        };
        tracing::info!(
            target: "nrr::per_sid_orchestrator",
            msg_key = "persid-posture-cross-set-duplicates",
            sid,
            count = found.len(),
            sample = %first.match_summary,
            "active rules name the same traffic on both routes",
        );
        if let Some(bus) = self.events.as_ref() {
            bus.publish_for(
                sid,
                nrr_shared::ipc_payloads::StatusUpdateEvent::RuleDuplicatesDetected {
                    sid: sid.to_string(),
                    count: found.len() as u64,
                    sample: first.match_summary.clone(),
                },
            );
        }
    }

    /// The tunnel-down filter set: with `block_all`, everything except the safe
    /// exemptions plus the tunnel's own destinations by name; otherwise only
    /// the protected destinations and the held networks. Pure projection over
    /// the codegen primitives.
    pub(super) fn fail_closed_filters(
        &self,
        sid: &str,
        protected_secondary_ips: &[std::net::IpAddr],
        holds: &crate::enforcement_planner::NetworkHolds,
        exemptions: &FailClosedExemptions,
        protocols: crate::killswitch_codegen::KillSwitchProtocols,
        posture: FailClosedPosture,
    ) -> Vec<WfpFilterSpec> {
        let FailClosedPosture {
            block_all,
            machine_has_other_principals,
        } = posture;
        if block_all {
            let mut out = crate::killswitch_codegen::fail_closed_block_all_filters_for(
                sid,
                exemptions,
                protocols,
                machine_has_other_principals,
            );
            out.extend(named_destination_blocks_under_block_all(
                sid,
                protected_secondary_ips,
                holds,
                exemptions,
                protocols,
            ));
            return out;
        }
        // The tunnel's own server is never blocked by name, even if a rule
        // resolved to it: the handshake to it is how the tunnel comes back.
        let protected = exempt_tunnel_servers(protected_secondary_ips, exemptions);
        let mut out =
            crate::killswitch_codegen::fail_closed_block_destinations(sid, &protected, protocols);
        out.extend(crate::killswitch_codegen::fail_closed_network_filters(
            sid, holds, protocols,
        ));
        out
    }

    /// Reset `sid`'s unresolved-app set and rule conflicts so the
    /// GUI does not keep listing them for a SID that no longer has any
    /// (enforceable) rules. No-op when the status is unwired.
    pub(super) fn clear_app_enforcement_status(&self, sid: &str) {
        if let Some(status) = self.app_enforcement_status.as_ref() {
            status.set_unresolved(sid, Vec::new());
            status.set_rule_conflicts(sid, Vec::new());
        }
    }
}
