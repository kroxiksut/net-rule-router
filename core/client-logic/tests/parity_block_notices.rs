#![allow(clippy::expect_used)]

//! The summary of blocks kept while no surface was open — the same answer
//! from `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, JsLib};
use nrr_client_logic::block_notices::backlog_summary;
use nrr_shared::ipc_payloads::BlockNoticeJournalEntryDto;
use serde_json::{json, Value};

#[test]
fn block_notice_backlog_matches_js() {
    check(
        "block_notice_backlog",
        &mut JsLib::pure(),
        |input| format!("blockNoticeBacklog({})", arg(input, "entries")),
        |input| {
            let entries: Vec<BlockNoticeJournalEntryDto> =
                serde_json::from_value(input["entries"].clone()).expect("entries decode");
            backlog_summary(&entries).map_or(Value::Null, |summary| {
                json!({
                    "count": summary.count,
                    "throughId": summary.through_id,
                    "shown": summary.shown,
                    "more": summary.more,
                })
            })
        },
    );
}
