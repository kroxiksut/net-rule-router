#![no_main]
//! Program paths the OS reports for other users' processes, grouped as the
//! connection trace groups them: whatever the bytes, nothing panics and every
//! row lands in exactly one group.

use libfuzzer_sys::fuzz_target;
use nrr_client_logic::conn_trace::{group_trace_rows, TraceGroupKind, TraceGrouping, TraceRowRef};
use nrr_shared::app_path::PathStyle;

/// The trace keeps at most a few thousand rows; one line is one row.
const MAX_INPUT: usize = 256 * 1024;
const MAX_ROWS: usize = 4096;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let text = String::from_utf8_lossy(data);
    // `name<TAB>path` per line; a line without a tab is a path alone.
    let rows: Vec<TraceRowRef<'_>> = text
        .split('\n')
        .take(MAX_ROWS)
        .map(|line| match line.split_once('\t') {
            Some((process, process_path)) => TraceRowRef {
                process,
                process_path,
            },
            None => TraceRowRef {
                process: "",
                process_path: line,
            },
        })
        .collect();
    for style in [PathStyle::Windows, PathStyle::Linux, PathStyle::MacOS] {
        for grouping in TraceGrouping::ALL {
            let groups = group_trace_rows(&rows, grouping, style);
            if grouping == TraceGrouping::None {
                assert!(groups.is_empty());
                continue;
            }
            let mut seen = vec![false; rows.len()];
            for group in &groups {
                for &row in &group.rows {
                    assert!(!seen[row], "row {row} in two groups");
                    seen[row] = true;
                }
                assert!(group.programs >= 1 && group.programs <= group.rows.len());
                if let Some(value) = &group.rule_value {
                    assert_eq!(group.kind, TraceGroupKind::Folder);
                    assert!(value.ends_with('*'));
                }
            }
            assert!(seen.iter().all(|s| *s), "a row in no group");
            let no_path = groups
                .iter()
                .position(|g| g.kind == TraceGroupKind::NoPath);
            assert!(no_path.is_none_or(|at| at + 1 == groups.len()));
        }
    }
});
