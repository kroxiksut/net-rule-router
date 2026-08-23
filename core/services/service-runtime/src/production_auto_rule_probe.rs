//! Runs the "does it answer on the main link?" pass for a principal's pending
//! suggestions.
//!
//! Joins four things that already exist: the pending suggestions (auto-rules
//! engine), the addresses behind their hostnames (FQDN cache), the main link's
//! own source address (route coordinator) and the bounded probe itself. The
//! verdict goes back through `note_primary_health` — the same channel observed
//! traffic uses — so the GUI has one story to tell regardless of how the
//! evidence was obtained.
//!
//! The pass runs on its own thread and answers the IPC request immediately:
//! eight addresses at a second and a half each is not something an IPC reply
//! may sit on, and the GUI already learns the outcome from the
//! suggestion-changed push.

use std::sync::Arc;

use nrr_shared::ipc_payloads::AutoRuleCandidatesProbeResponse;

use crate::auto_rules::AutoRulesEngine;
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::ipc_handlers::providers::AutoRuleProbeRunner;
use crate::main_route_verdicts::{MainRouteVerdict, MainRouteVerdicts};
use crate::primary_path_probe::{PrimaryPathProber, ProbeLimits, ProbeTarget};
use crate::route_coordinator::SecondaryRouteCoordinator;

/// Port 443 is where a companion host lives in practice — these are CDN, media
/// and API endpoints. Probing the port the browser would use is the only answer
/// worth having; a reachable ICMP or port 80 would say something else.
const PROBE_PORT: u16 = 443;

pub struct ProductionAutoRuleProbe {
    engine: Arc<AutoRulesEngine>,
    cache: Arc<dyn FqdnCacheLookup>,
    coordinator: Arc<SecondaryRouteCoordinator>,
    prober: Arc<PrimaryPathProber>,
    limits_for: Arc<dyn Fn(&str) -> ProbeLimits + Send + Sync>,
    /// Where a rule-host pass leaves its answers. `None` keeps the runner
    /// suggestion-only, exactly as before.
    verdicts: Option<Arc<MainRouteVerdicts>>,
}

impl ProductionAutoRuleProbe {
    pub fn new(
        engine: Arc<AutoRulesEngine>,
        cache: Arc<dyn FqdnCacheLookup>,
        coordinator: Arc<SecondaryRouteCoordinator>,
        prober: Arc<PrimaryPathProber>,
        limits_for: Arc<dyn Fn(&str) -> ProbeLimits + Send + Sync>,
    ) -> Self {
        Self {
            engine,
            cache,
            coordinator,
            prober,
            limits_for,
            verdicts: None,
        }
    }

    /// Wire the store a rule-host pass writes its verdicts into; the rules list
    /// reads them back so the user sees what the check found.
    #[must_use]
    pub fn with_verdicts(mut self, verdicts: Arc<MainRouteVerdicts>) -> Self {
        self.verdicts = Some(verdicts);
        self
    }

    /// Probe targets for hosts the caller's rules already name.
    ///
    /// Same rule as for suggestions: a host with nothing cached is skipped
    /// rather than resolved here — resolving would send a query the user did
    /// not ask for, and the answer would arrive after this pass.
    fn rule_targets(&self, hostnames: &[String]) -> Vec<ProbeTarget> {
        hostnames
            .iter()
            .map(|h| h.trim().trim_start_matches("*.").to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .filter_map(|hostname| {
                let addresses = self.cache.ips_for_hostname(&hostname);
                (!addresses.is_empty()).then_some(ProbeTarget {
                    hostname,
                    addresses,
                })
            })
            .collect()
    }

    /// The hosts to examine: the named suggestions, or every pending one.
    ///
    /// A suggestion whose addresses nothing has cached is skipped rather than
    /// resolved here: resolving would send a query the user did not ask for, and
    /// the answer would arrive too late for this pass anyway.
    fn targets(&self, sid: &str, ids: &[String]) -> Vec<ProbeTarget> {
        self.engine
            .candidates(sid)
            .into_iter()
            .filter(|c| ids.is_empty() || ids.contains(&c.id))
            .filter_map(|c| {
                let hostname = c.proposed_match.trim_start_matches("*.").to_string();
                let addresses = self.cache.ips_for_hostname(&hostname);
                (!addresses.is_empty()).then_some(ProbeTarget {
                    hostname,
                    addresses,
                })
            })
            .collect()
    }
}

impl AutoRuleProbeRunner for ProductionAutoRuleProbe {
    fn probe(
        &self,
        sid: &str,
        ids: &[String],
        rule_hostnames: &[String],
    ) -> AutoRuleCandidatesProbeResponse {
        let limits = (self.limits_for)(sid);
        // Rule hosts and suggestions are the same question over the same
        // mechanism; only where the verdict is filed differs.
        let rules_pass = !rule_hostnames.is_empty();
        let targets = if rules_pass {
            self.rule_targets(rule_hostnames)
        } else {
            self.targets(sid, ids)
        };
        if targets.is_empty() {
            return AutoRuleCandidatesProbeResponse::default();
        }
        let over_limit = targets.len().saturating_sub(limits.max_targets) as u32;
        let accepted = targets.len().min(limits.max_targets) as u32;
        // The main link's own address — without it the OS would route by the
        // pin, which points at the tunnel and would answer a different question.
        let source = self.coordinator.resolve_egress_source_ips(sid).0;
        let engine = Arc::clone(&self.engine);
        let prober = Arc::clone(&self.prober);
        let sid_owned = sid.to_string();
        let verdicts = self.verdicts.clone();
        let spawned = std::thread::Builder::new()
            .name("nrr-main-link-probe".into())
            .spawn(move || {
                use nrr_domain::companion_affinity::PrimaryHealthEvent;
                let report = move |hostname: &str, answered: bool| {
                    if rules_pass {
                        // A rule's own address: the answer belongs beside the
                        // rule, not in the suggestion engine's health signal —
                        // feeding it there would let a check the user ran on
                        // their own rules reshape what gets suggested.
                        if let Some(store) = verdicts.as_ref() {
                            store.record(
                                &sid_owned,
                                hostname,
                                if answered {
                                    MainRouteVerdict::Answered
                                } else {
                                    MainRouteVerdict::Silent
                                },
                                std::time::Instant::now(),
                            );
                        }
                        return;
                    }
                    engine.note_primary_health(
                        &sid_owned,
                        hostname,
                        if answered {
                            PrimaryHealthEvent::Completed
                        } else {
                            PrimaryHealthEvent::Stalled
                        },
                    );
                };
                let summary = prober.run_pass(
                    &targets,
                    PROBE_PORT,
                    source,
                    limits,
                    std::time::Instant::now(),
                    &report,
                );
                tracing::info!(
                    target: "nrr::auto-rules",
                    answered = summary.answered,
                    silent = summary.silent,
                    indeterminate = summary.indeterminate,
                    skipped_recent = summary.skipped_recent,
                    skipped_over_limit = summary.skipped_over_limit,
                    source = ?source,
                    "checked whether the suggested addresses answer on the main link (requested by the user)",
                );
            });
        if let Err(e) = spawned {
            tracing::warn!(
                target: "nrr::auto-rules",
                "could not start the main-link probe pass: {e}",
            );
            return AutoRuleCandidatesProbeResponse::default();
        }
        AutoRuleCandidatesProbeResponse {
            accepted,
            over_limit,
        }
    }
}
