use super::*;
use crate::path_probe::{http_probe, HttpProbeVerdict};

impl DiscoveryObservationPipeline {
    pub(super) fn confirm_http(
        wiring: &DiscoveryObservationWiring,
        confirmation: Confirmation,
        https: &dyn crate::site_check::HttpsHead,
        start: impl FnOnce(),
    ) -> ConfirmationOutcome {
        let Confirmation {
            owner,
            host,
            destination,
            target,
            source,
            secondary,
            timeout,
            process,
            ..
        } = confirmation;
        let note = |state, reason| {
            wiring.engine.note_discovery(
                &owner,
                Some(&host),
                Some(&destination),
                DiscoveryDecision::new("probe", state, reason),
                SystemTime::now(),
            )
        };
        let refusal = || {
            (!(wiring.cadence)(&owner).enabled)
                .then_some("auto-probe-disabled")
                .or_else(|| {
                    Self::confirmation_refusal(
                        wiring,
                        &owner,
                        &host,
                        target.into(),
                        process.as_deref(),
                    )
                })
                .or_else(|| {
                    (wiring.egress.egress_source_ips(&owner) != (Some(source), secondary)
                        || !wiring.names.probe_names_for(&owner, target).contains(&host))
                    .then_some("probe-inconclusive")
                })
        };
        let Some(secondary) = secondary.filter(|secondary| *secondary != source) else {
            note("deferred", "secondary-unavailable");
            return ConfirmationOutcome::Finished;
        };
        let mut start = Some(start);
        for _ in 0..3 {
            if let Some(reason) = refusal() {
                note(Self::refusal_state(reason), reason);
                return ConfirmationOutcome::refused(reason);
            }
            if let Some(start) = start.take() {
                start();
            }
            let answer = http_probe(https, target, &host, Some(source), timeout);
            if let Some(reason) = refusal() {
                note(Self::refusal_state(reason), reason);
                return ConfirmationOutcome::refused(reason);
            }
            tracing::debug!(target:"nrr::discovery", sid=%owner, host=%host, route="primary", outcome=?answer, "automatic HTTP path measurement");
            note("deferred", answer.reason());
            match answer {
                HttpProbeVerdict::NoAnswer => {}
                HttpProbeVerdict::Answered(_)
                | HttpProbeVerdict::ClientError(_)
                | HttpProbeVerdict::ServerError(_)
                | HttpProbeVerdict::Untrusted => {
                    wiring
                        .engine
                        .withdraw_http_path_reachability(&owner, &host, SystemTime::now());
                    return ConfirmationOutcome::Finished;
                }
                HttpProbeVerdict::Unconfirmed | HttpProbeVerdict::Unavailable => {
                    return ConfirmationOutcome::Finished
                }
            }
        }
        if let Some(reason) = refusal() {
            note(Self::refusal_state(reason), reason);
            return ConfirmationOutcome::refused(reason);
        }
        let answer = http_probe(https, target, &host, Some(secondary), timeout);
        if let Some(reason) = refusal() {
            note(Self::refusal_state(reason), reason);
            return ConfirmationOutcome::refused(reason);
        }
        tracing::debug!(target:"nrr::discovery", sid=%owner, host=%host, route="secondary", outcome=?answer, "automatic HTTP path measurement");
        note("deferred", answer.reason());
        if matches!(answer, HttpProbeVerdict::Answered(_)) {
            wiring
                .engine
                .note_http_path_reachability(&owner, &host, SystemTime::now());
        } else if !matches!(
            answer,
            HttpProbeVerdict::Unavailable | HttpProbeVerdict::Unconfirmed
        ) {
            wiring
                .engine
                .withdraw_http_path_reachability(&owner, &host, SystemTime::now());
        }
        ConfirmationOutcome::Finished
    }
}
