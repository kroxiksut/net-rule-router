//! One test against the LIVE mechanism, per the rule every platform port here
//! follows: fixtures prove the shape, but only the kernel proves the mechanism.
//!
//! It applies a real ruleset through `nft`, reads it back, and tears it down.
//! Everything else about the Linux enforcement path is pure and covered by unit
//! tests on any host; this covers the one thing they cannot — that what we
//! generate is something `nft` and the kernel actually accept.
//!
//! Ignored by default: it needs root, `nft` and nf_tables. Run it with
//! `--ignored`; it then fails, rather than passes, on a host that lacks them —
//! a silent pass on an unequipped machine reads as coverage.
//!
//! The table name carries the pid, so a run cannot collide with the product's
//! own `nrr` table or with a parallel run.

#![cfg(target_os = "linux")]
// Same convention as the other integration tests here: a failed setup step in a
// test is a panic with a message, not an error to propagate.
#![allow(clippy::expect_used)]

use std::process::Command;

use nrr_platform_linux::nft_apply::{render_batch, NftApplyError, NftCliEnforcement};
use nrr_platform_linux::nft_ir::{NftFamily, NftMatch, NftRule, NftRuleset, NftVerdict};

/// Panics with the reason when the host cannot run this.
fn require_environment() {
    assert!(
        nix_is_root(),
        "needs root: nf_tables refuses an unprivileged caller"
    );
    match NftCliEnforcement::new().probe() {
        Ok(()) => {}
        Err(NftApplyError::NftUnavailable { detail }) => {
            panic!("nft is unavailable ({detail})")
        }
        Err(other) => panic!("nft answered an error: {other}"),
    }
}

/// Deletes the test table on every exit, a failed assert included.
struct TableGuard(String);

impl Drop for TableGuard {
    fn drop(&mut self) {
        let _ = NftCliEnforcement::new().teardown(&self.0);
    }
}

fn nix_is_root() -> bool {
    // No libc dependency needed for one number that the kernel already exposes.
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_owned))
        })
        .is_some_and(|uid| uid == "0")
}

fn live_ruleset(table: &str) -> NftRuleset {
    NftRuleset {
        family: NftFamily::Inet,
        table: table.to_owned(),
        chain: "output".to_owned(),
        rules: vec![
            // A host pinned to an interface — the shape an egress pin lowers to.
            NftRule {
                matches: vec![
                    NftMatch::DstV4 {
                        net: "198.51.100.7".parse().expect("test address"),
                        prefix: 32,
                    },
                    NftMatch::OutInterface("lo".to_owned()),
                ],
                verdict: NftVerdict::Accept,
                comment: "route-secondary#0 via".to_owned(),
            },
            // The scoped drop that makes the pin leak-proof.
            NftRule {
                matches: vec![NftMatch::DstV4 {
                    net: "198.51.100.7".parse().expect("test address"),
                    prefix: 32,
                }],
                verdict: NftVerdict::Drop,
                comment: "route-secondary#0 leak-guard".to_owned(),
            },
            // A subnet, a protocol and a port — the remaining condition kinds.
            NftRule {
                matches: vec![
                    NftMatch::DstV4 {
                        net: "203.0.113.0".parse().expect("test address"),
                        prefix: 24,
                    },
                    NftMatch::Protocol(17),
                    NftMatch::DstPort(53),
                ],
                verdict: NftVerdict::Accept,
                comment: "catch-all-exempt#0".to_owned(),
            },
            // The v6 half of a block-all: `inet` carries both families.
            NftRule {
                matches: vec![NftMatch::DstV6 {
                    net: "2001:db8::7".parse().expect("test address"),
                    prefix: 128,
                }],
                verdict: NftVerdict::Drop,
                comment: "block-all#0 v6".to_owned(),
            },
        ],
    }
}

fn list_table(table: &str) -> String {
    let output = Command::new("nft")
        .args(["list", "table", "inet", table])
        .output()
        .expect("nft must be runnable");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn table_exists(table: &str) -> bool {
    let output = Command::new("nft")
        .args(["list", "tables"])
        .output()
        .expect("nft must be runnable");
    String::from_utf8_lossy(&output.stdout).contains(&format!("table inet {table}"))
}

#[test]
#[ignore = "needs root, nft and nf_tables; run with --ignored"]
fn the_kernel_accepts_what_we_generate_and_teardown_removes_it() {
    require_environment();

    let table = format!("nrr_live_{}", std::process::id());
    let _guard = TableGuard(table.clone());
    let enforcement = NftCliEnforcement::new();
    let ruleset = live_ruleset(&table);

    // The batch has to be valid before anything is applied; a serialisation
    // failure here would otherwise surface as an opaque `nft` error.
    let batch = render_batch(&ruleset);
    assert!(!serde_json::to_string(&batch)
        .expect("the batch must serialise")
        .is_empty(),);

    enforcement
        .apply(&ruleset)
        .unwrap_or_else(|e| panic!("the kernel rejected our ruleset: {e}"));

    let listed = list_table(&table);
    assert!(
        listed.contains("hook output"),
        "the base chain must exist: {listed}"
    );
    assert!(
        listed.contains("198.51.100.7"),
        "the pinned host rule must be present: {listed}"
    );
    assert!(
        listed.contains("203.0.113.0/24"),
        "the subnet rule must keep its prefix: {listed}"
    );
    assert!(
        listed.contains("ip6 daddr 2001:db8::7"),
        "the v6 host rule must be present: {listed}"
    );
    assert!(
        listed.contains("route-secondary#0 leak-guard"),
        "rule comments carry the provenance we read a live ruleset back with: {listed}"
    );
    assert!(
        listed.contains("policy accept"),
        "the chain must not default to dropping: {listed}"
    );

    // Re-apply must be a no-op rather than an append — the property the
    // create-then-flush batch exists for.
    enforcement
        .apply(&ruleset)
        .expect("re-applying an identical ruleset must succeed");
    let after_reapply = list_table(&table);
    assert_eq!(
        listed.matches("198.51.100.7").count(),
        after_reapply.matches("198.51.100.7").count(),
        "re-apply duplicated rules instead of replacing the table:\n{after_reapply}"
    );

    enforcement
        .teardown(&table)
        .unwrap_or_else(|e| panic!("teardown failed, leaving state behind: {e}"));
    assert!(
        !table_exists(&table),
        "teardown must remove our table completely"
    );
}
