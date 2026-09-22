// Asking each adapter what the outside world sees behind it.

use super::*;

/// Ask every probe-worthy adapter for its external address, in parallel, and
/// record the answer on its row.
///
/// Adapters that are not worth probing are marked as skipped rather than left
/// at their default: when the user asked for the check, every row should say
/// what happened to it — including "nothing, and here is why".
///
/// Neutral: binding a UDP socket to a local source address is the same act on
/// every OS, and both live enumerations call this one copy so a row cannot mean
/// one thing on Windows and another on Linux.
pub fn apply_external_ip_probes(rows: &mut [InterfaceRouteRow]) {
    let targets = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| {
            external_probe_target(row.availability_status, &row.local_ip)
                .map(|source| (index, source))
        })
        .collect::<Vec<_>>();

    for row in rows.iter_mut() {
        apply_external_probe(&mut row.observed_facts, ExternalIpProbeOutcome::Skipped);
    }
    if targets.is_empty() {
        return;
    }

    let sources = targets
        .iter()
        .map(|(_, source)| *source)
        .collect::<Vec<_>>();
    let outcomes = crate::external_ip::probe_external_ipv4_batch(&sources);

    for ((index, _), outcome) in targets.iter().zip(outcomes) {
        let Some(row) = rows.get_mut(*index) else {
            continue;
        };
        apply_external_probe(&mut row.observed_facts, outcome);
        // The observed address itself is deliberately absent from the log: it
        // identifies the user's connection and the status is what diagnostics
        // need to see.
        tracing::debug!(
            target: "nrr::interfaces",
            adapter = %row.adapter_name,
            status = row.observed_facts.external_ip_status.title(),
            "external-address probe finished",
        );
    }
}
