//! Which traffic rows a view shows (`visibleTrafficRows` in `pure.js`).

use nrr_shared::ipc_payloads::TrafficRowDto;

/// The rows worth showing and summing: virtual-adapter rows recorded while
/// the count was on stay in history, but are hidden while it is off.
pub fn visible_traffic_rows(rows: &[TrafficRowDto], count_virtual: bool) -> Vec<TrafficRowDto> {
    rows.iter()
        .filter(|row| count_virtual || row.role != "virtual")
        .cloned()
        .collect()
}
