#![no_main]
//! Text pasted into the Add form's "several rules" field: whatever the bytes,
//! planning never panics, never reads past its bounds, and what the field keeps
//! after an apply plans again without a panic.

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use nrr_client_logic::bulk_rules::{
    plan_bulk_rules, BulkInput, LineChoice, LineVerdict, RowStatus, VerdictLevel, MAX_LINES,
};

/// Past the planner's own size bound, so the cut is exercised too.
const MAX_INPUT: usize = 1024 * 1024;

const ROUTES: [&str; 3] = ["primary", "secondary", "block"];
const OSES: [&str; 3] = ["windows", "linux", "macos"];

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let (head, body) = data.split_first().map_or((0, data), |(h, b)| (*h, b));
    let text = String::from_utf8_lossy(body);
    let route = ROUTES[usize::from(head) % ROUTES.len()];
    let os = OSES[usize::from(head >> 2) % OSES.len()];
    let apps = head & 0x40 == 0;
    let choices = HashMap::new();
    let none = HashMap::new();
    let plan = |verdicts: &HashMap<String, LineVerdict>,
                choices: &HashMap<usize, LineChoice>,
                text: &str| {
        plan_bulk_rules(&BulkInput {
            text,
            route,
            os,
            apps,
            existing: &[],
            choices,
            verdicts,
            room: (head & 0x80 != 0).then_some(3),
        })
    };
    let first = plan(&none, &choices, &text);
    assert!(first.lines <= MAX_LINES);
    assert!(first.rows.len() <= first.lines);
    assert!(first
        .rows
        .iter()
        .all(|r| r.line >= 1 && r.line <= first.lines));

    // Every verdict in and every one-word row given its first offer: the rows
    // then reach the duplicate and move checks.
    let verdicts: HashMap<String, LineVerdict> = first
        .rows
        .iter()
        .filter(|r| r.status == RowStatus::Pending)
        .map(|r| {
            let verdict = LineVerdict {
                level: VerdictLevel::Valid,
                message_key: String::new(),
                args: Default::default(),
            };
            (r.verdict_key.clone(), verdict)
        })
        .collect();
    let picked: HashMap<usize, LineChoice> = first
        .rows
        .iter()
        .filter_map(|r| {
            let choice = LineChoice {
                rule_type: Some((*r.options.first()?).to_owned()),
                move_elsewhere: true,
            };
            Some((r.line, choice))
        })
        .collect();
    let second = plan(&verdicts, &picked, &text);
    assert_eq!(second.lines, first.lines);
    let _ = plan(&verdicts, &picked, &second.remaining);
});
