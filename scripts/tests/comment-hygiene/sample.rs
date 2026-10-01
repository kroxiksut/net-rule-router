// Positive control for the comment-hygiene gate. Every line listed in
// expected.txt must be reported; every other line must not be.
// A 16-byte block and RFC 1035 section 4 are ordinary prose.
// Block 16.2 keeps a tracking tag.
// lowercase block 16.18.vpn keeps one too.
const NOTE: &str = "deferred to block 14.5";
fn block16_catalog() {}
const STAMP: &str = "2026-06-27T00:00:00Z"; // test data, not a stamp
// Removed on 2026-06-27 after review.
// Epoch arithmetic: 2026-01-01 is 20454 days after the epoch.
// Two-phase commit: Phase 1 is the dry run.
// See TASKS_RU for the status.
// The tag below is split across a line break: see the tracking
// block
// 7 of the plan.
const UNBLOCKED: u8 = 3; // unblock 3 peers
/*
   Released 2026-06-27 inside a block comment.
*/
const NET: &str = "10.0.0.0/8"; // 10.0.0.0/8 is private
// Phase B lands later.
// Seen during the HW-0717 run.
// Ubuntu 24.04.1 LTS reports its name.
const VERSION: &str = "16.18.vpn"; // string data only
// Fixed in 16.18.vpn slice D.
// Block T keeps the traffic counter.
// block D of the spec needs no changes.
// a block of code is not a marker, nor is block all traffic.
// Direct-answer steering (П0-D).

// Lost `\` continuation, collapsed onto one line by the cleanup pass that
// dropped it: a wide gap flanked by text on both sides is reported.
const GAP: &str = "one line ends here                              and continues where a backslash used to be";
// A gap under the threshold must not be reported.
const SHORT_GAP: &str = "one line ends here     and a short gap stays under the threshold";
// A raw string keeps its own formatting and is exempt even with the same gap.
const RAW_OK: &str = r"one line ends here                              and continues, but raw strings are exempt";
// A genuine multi-line literal (this codebase's SQL text uses exactly this
// shape) is not reported: the check only looks inside one physical line, and
// a continuation line's leading indentation has no string content before it.
const SQL_OK: &str = "SELECT * FROM t WHERE a = 1
              AND b = 2";
