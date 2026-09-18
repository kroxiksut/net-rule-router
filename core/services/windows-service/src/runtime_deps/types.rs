//! Small boot-time types and helpers shared across the runtime-deps
//! submodules: adapter debounce, epoch-millis clock, per-SID route bundle.

use super::*;

/// Adapter-monitor debounce, in milliseconds. Matches block-15.x default;
/// short enough that a Wi-Fi flicker resolves before the GUI render
/// settles, long enough to avoid double-firing on a normal cable plug.
pub(crate) const ADAPTER_DEBOUNCE_MS: u64 = 500;

/// UTC Unix milliseconds, the timestamp unit every state-DB table stores.
/// A pre-epoch clock reads as `0` — a stamp that is merely very old, which the
/// freshness windows already handle, rather than a panic on a machine whose RTC
/// has not been set yet.
pub(super) fn unix_millis(at: std::time::SystemTime) -> i64 {
    at.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The per-SID WFP orchestrator plus the route-table coordinator,
/// rule-hostname seeder, and DNS-observation consumer — all `Some`
/// together (built from the same providers when WFP is available) or all
/// `None`.
pub(super) type RoutePathBundle = (
    Option<Arc<PerSidApplyOrchestrator>>,
    Option<Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>>,
    Option<Arc<nrr_service_runtime::rule_hostname_seeder::RuleHostnameSeeder>>,
    Option<Arc<nrr_service_runtime::dns_observation_consumer::DnsObservationConsumer>>,
    // Session known-direct registry shared by the orchestrator (block-all
    // exemptions), the FCrDNS direct-learning sink, and the Mode-B
    // direct-answer gate.
    Option<Arc<nrr_service_runtime::known_direct::KnownDirectRegistry>>,
    // Companion-domain discovery engine, fed by the DNS-observation
    // consumer above and read by the tray through the `autorules.candidates.*`
    // ops. Same `Arc` in both places, so the tick and the tray see one state.
    Option<Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>>,
    // Cross-session memory of the destinations application rules route
    // over the additional link, so those routes exist before the app's
    // first connection instead of being learned from its refusal.
    Option<Arc<nrr_service_runtime::app_destination_memory::AppDestinationMemory>>,
);
