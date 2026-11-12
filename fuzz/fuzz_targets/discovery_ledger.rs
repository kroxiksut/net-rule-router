#![no_main]
use libfuzzer_sys::fuzz_target;
use nrr_domain::suggestion_discovery::{DiscoveryDecision, DiscoveryLedger};
fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let mut fields = text.split('\n');
    let owner = fields.next().unwrap_or_default();
    let host = fields.next();
    let destination = fields.next();
    let mut ledger = DiscoveryLedger::default();
    let _ = ledger.record(
        owner,
        host,
        destination,
        DiscoveryDecision::new("name", "not-created", "name-unknown"),
        1000,
    );
    let _ = ledger.record(
        owner,
        host,
        destination,
        DiscoveryDecision::new("probe", "deferred", "probe-pending"),
        999,
    );
    assert!(ledger.snapshot(owner, 1000, usize::MAX).0.len() <= 128);
});
