use super::test_support::{page_load, StaticExclusions};
use super::*;

const SECONDARY: RouteRole = RouteRole::Secondary;
const PRIMARY: RouteRole = RouteRole::Primary;

fn defaults() -> CompanionAffinityLedger {
    CompanionAffinityLedger::with_defaults()
}

/// Two page loads far enough apart to land in distinct windows.
fn two_visits(ledger: &mut CompanionAffinityLedger, anchor: &str, candidates: &[&str]) {
    page_load(ledger, 0, anchor, SECONDARY, candidates);
    page_load(ledger, 100_000, anchor, SECONDARY, candidates);
}

// ── Fixtures shared by more than one theme ───────────────────────────────

fn health(ledger: &mut CompanionAffinityLedger, host: &str, event: PrimaryHealthEvent, times: u32) {
    for _ in 0..times {
        ledger.observe(0, host, CoActivityKind::PrimaryHealth(event));
    }
}

mod bounds_and_order;
mod delivery_names;
mod lifecycle;
mod proposal;
mod windows_and_suffixes;
