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

impl PerSidApplyOrchestrator {
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
    pub(super) fn note_block_all_state(&self, sid: &str, armed: bool) {
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
            return;
        }
        // publish the new "any SID armed?" posture for the GUI
        // banner. On the transition edge only (same throttle as the flush).
        if let Some(status) = self.block_all_posture_status.as_ref() {
            status.set(self.any_block_all_armed());
        }
        match self.dns_cache_control.flush_resolver_cache() {
            Ok(()) => tracing::info!(
                target: "nrr::per_sid_orchestrator",
                sid,
                block_all_armed = armed,
                "flushed OS DNS resolver cache on kill-switch block-all transition — pre-transition cached names will re-query and become observable",
            ),
            Err(e) => tracing::warn!(
                target: "nrr::per_sid_orchestrator",
                sid,
                block_all_armed = armed,
                error = ?e,
                "OS DNS resolver cache flush failed on kill-switch block-all transition — names the OS already cached stay invisible to the DNS observer until their TTL expires",
            ),
        }
    }

    /// Record whether the latest compute for `sid` left the guard BLOCKING with
    /// the additional link unresolved, and publish the "any SID armed?" answer
    /// on the transition edge.
    ///
    /// No cache flush and no logging of its own: the posture it mirrors is
    /// already logged where it is decided, and this latch exists for readers
    /// that must not treat a rule host as covered while the guard has nothing
    /// but its known addresses to block with.
    pub(super) fn note_fail_closed_state(&self, sid: &str, armed: bool) {
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
        self.note_block_all_state(sid, false);
        self.note_fail_closed_state(sid, false);
        self.update_killswitch_registry(sid, KillswitchBlockIds::default());
        self.posture_log_state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
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
            let anybody_cuts = g.values().any(|v| *v);
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

    /// Build the fail-closed filter set for the failure posture. Mode A
    /// (selective) blocks only the protected secondary destinations; modes B
    /// (everything-via-secondary) block all egress except the safe
    /// exemptions. Pure projection over the codegen primitives.
    pub(super) fn fail_closed_filters(
        &self,
        sid: &str,
        mode: RouteBehaviorMode,
        protected_secondary_ips: &[std::net::IpAddr],
        exemptions: &FailClosedExemptions,
        protocols: crate::killswitch_codegen::KillSwitchProtocols,
        posture: FailClosedPosture,
    ) -> Vec<WfpFilterSpec> {
        let FailClosedPosture { block_all } = posture;
        match mode {
            RouteBehaviorMode::PreferPrimary => {
                // with `kill_switch_block_all` the split-mode
                // emergency block covers ALL egress (catch-all) so ICMP/ping and
                // rotating/un-cached secondary-rule IPs can't leak to the primary
                // while the secondary adapter is down; otherwise it blocks only the enumerated
                // secondary destinations (the historic per-IP behaviour).
                if block_all {
                    crate::killswitch_codegen::fail_closed_block_all_filters(
                        sid, exemptions, protocols,
                    )
                } else {
                    // honour the VPN-server (bootstrap) exemption on
                    // the mode-A per-IP path too: subtract the exempted server IPs
                    // from the per-destination block set so, if a secondary rule
                    // ever resolved to the tunnel's own server IP, the handshake to
                    // it is never blocked. Mirrors the block-all path's
                    // bootstrap_server_ips exemption, closing the IP-overlap corner
                    // case as defence-in-depth alongside the per-app primary
                    // exemption above.
                    // The protected set carries both families, so a rule host's
                    // v6 addresses are blocked here by name instead of cutting the
                    // whole v6 family.
                    let protected: Vec<std::net::IpAddr> =
                        exempt_tunnel_servers(protected_secondary_ips, exemptions);
                    crate::killswitch_codegen::fail_closed_block_destinations(
                        sid, &protected, protocols,
                    )
                }
            }
            RouteBehaviorMode::PreferSecondaryWhenAvailable
            | RouteBehaviorMode::StrictSecondaryFailClosed => {
                // `block_all` must be honoured here: the caller that arms the
                // guard while the tunnel is HEALTHY (empty pin set on a cold
                // FQDN cache) states in its own comment that it must not
                // escalate. Ignoring `block_all` would force a catch-all
                // anyway, cutting every egress on a live tunnel and
                // deadlocking the very cache warm-up that would lift it.
                if block_all {
                    crate::killswitch_codegen::fail_closed_block_all_filters(
                        sid, exemptions, protocols,
                    )
                } else {
                    let protected: Vec<std::net::IpAddr> =
                        exempt_tunnel_servers(protected_secondary_ips, exemptions);
                    crate::killswitch_codegen::fail_closed_block_destinations(
                        sid, &protected, protocols,
                    )
                }
            }
        }
    }

    /// Reset the shared unresolved-app set to empty so the GUI banner does
    /// not keep listing apps for a SID that no longer has any (enforceable)
    /// rules. No-op when the status is unwired.
    pub(super) fn clear_app_enforcement_status(&self) {
        if let Some(status) = self.app_enforcement_status.as_ref() {
            status.set_unresolved(Vec::new());
        }
    }
}
