//! Stage 0 of "the site does not open on the main link": the observer names
//! the hosts whose connections stall there and files them in the stall
//! register, whether or not the suggestions engine runs. Names come from what
//! the service already remembers (recent rule-host resolutions, observed
//! names); nothing is looked up for it.

use std::sync::Arc;

use nrr_domain::companion_affinity::PrimaryHealthEvent;

use crate::dns_observation_consumer::ActiveSidFn;
use crate::primary_stall_registry::{PrimaryStallRegistry, StallReport};

use super::{NameForAddressFn, SeveralServedFn};

/// One main-link outcome as the register filed it, for the suggestions engine.
#[derive(Debug, Clone, Copy)]
pub struct MainLinkHealth<'a> {
    /// The connection's own user, when known.
    pub owner: Option<&'a str>,
    /// Whose register entry it went to.
    pub sid: &'a str,
    pub hostname: &'a str,
    pub event: PrimaryHealthEvent,
    /// The register's verdict when this outcome changed it.
    pub report: Option<&'a StallReport>,
}

/// The suggestions engine's reading of each outcome.
pub type MainLinkHealthHook = Arc<dyn Fn(MainLinkHealth<'_>) + Send + Sync>;

/// What stage 0 needs wired.
pub struct MainLinkDiagnostics {
    /// Names of rule hosts by address.
    pub rule_host_names: NameForAddressFn,
    /// Names of the other hosts the service saw resolve.
    pub observed_names: NameForAddressFn,
    pub routing: ActiveSidFn,
    pub several_served: SeveralServedFn,
    pub stalls: Arc<PrimaryStallRegistry>,
    /// Set while the suggestions engine runs; the register is fed either way.
    pub engine: Option<MainLinkHealthHook>,
}

impl super::ConnectionObservationConsumer {
    /// Wire stage 0. Replaces any name source and main-link sink set before.
    #[must_use]
    pub fn with_main_link_diagnostics(mut self, diagnostics: MainLinkDiagnostics) -> Self {
        let MainLinkDiagnostics {
            rule_host_names,
            observed_names,
            routing,
            several_served,
            stalls,
            engine,
        } = diagnostics;
        self.name_for_address = Some(rule_host_names);
        self.health_name_fallback = Some(observed_names);
        self.companion_primary_health = Some(Arc::new(move |owner, hostname, stalled| {
            let event = if stalled {
                PrimaryHealthEvent::Stalled
            } else {
                PrimaryHealthEvent::Completed
            };
            let Some(sid) = super::suggestion_owner(owner, &routing, &several_served) else {
                return;
            };
            let report = stalls.note(&sid, hostname, event);
            if let Some(report) = report.as_ref() {
                crate::primary_stall_registry::log_report(report);
            }
            if let Some(engine) = engine.as_ref() {
                engine(MainLinkHealth {
                    owner,
                    sid: &sid,
                    hostname,
                    event,
                    report: report.as_ref(),
                });
            }
        }));
        self
    }
}
