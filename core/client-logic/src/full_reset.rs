//! The order of a full reset and what each step's result decides
//! (`fullResetNext` in `pure.js`).
//!
//! The service is restarted last because every earlier step needs it
//! answering, and a reset ends as a fresh install does: with the service
//! running on the cleared state, not stopped. A step that fails does not abort
//! the ones after it, except when the client cannot gain the rights the step
//! asked for: then the flow stops and says so, before the service is touched.

/// One step of the reset, in the order they run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    ClearLogs,
    ResetSidecar,
    PurgePrincipalData,
    RestartService,
}

/// The order the steps run in.
pub const ORDER: [Step; 4] = [
    Step::ClearLogs,
    Step::ResetSidecar,
    Step::PurgePrincipalData,
    Step::RestartService,
];

impl Step {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClearLogs => "clear-logs",
            Self::ResetSidecar => "reset-sidecar",
            Self::PurgePrincipalData => "purge-principal-data",
            Self::RestartService => "restart-service",
        }
    }

    pub fn parse(slug: &str) -> Option<Self> {
        ORDER.into_iter().find(|s| s.as_str() == slug)
    }
}

/// How a step ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Failed,
    /// Refused for want of administrator rights.
    Forbidden,
    /// Nothing to do on this client.
    Skipped,
}

impl Outcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Forbidden => "forbidden",
            Self::Skipped => "skipped",
        }
    }

    /// An unknown word counts as a failure, never as success.
    pub fn parse(slug: &str) -> Self {
        match slug {
            "ok" => Self::Ok,
            "forbidden" => Self::Forbidden,
            "skipped" => Self::Skipped,
            _ => Self::Failed,
        }
    }
}

/// What to do after the steps done so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    Run(Step),
    /// All steps ran. `cleared`: the service-side state is gone; `restarted`:
    /// the service is running again on it.
    Finish {
        cleared: bool,
        restarted: bool,
    },
    /// The flow ends here: `step` was refused and this client cannot elevate.
    NeedsElevation {
        step: Step,
    },
}

/// The next move (`fullResetNext`). `done` is the steps already run, in order,
/// with their outcomes; `can_elevate` says the client asks for administrator
/// approval by itself when a step is refused (the window does, the terminal
/// does not).
pub fn next(can_elevate: bool, done: &[(Step, Outcome)]) -> Next {
    if let Some(&(step, Outcome::Forbidden)) = done.last() {
        if step == Step::PurgePrincipalData && !can_elevate {
            return Next::NeedsElevation { step };
        }
    }
    match ORDER.get(done.len()) {
        Some(step) => Next::Run(*step),
        None => {
            let ok = |wanted: Step| done.iter().any(|&(s, o)| s == wanted && o == Outcome::Ok);
            Next::Finish {
                cleared: ok(Step::PurgePrincipalData),
                restarted: ok(Step::RestartService),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Outcome::{Failed, Forbidden, Ok as Good, Skipped};

    fn run(results: &[Outcome]) -> Vec<(Step, Outcome)> {
        ORDER.into_iter().zip(results.iter().copied()).collect()
    }

    #[test]
    fn steps_run_in_the_documented_order() {
        let mut done = Vec::new();
        for expected in ORDER {
            assert_eq!(next(false, &done), Next::Run(expected));
            done.push((expected, Good));
        }
        assert_eq!(
            next(false, &done),
            Next::Finish {
                cleared: true,
                restarted: true
            }
        );
    }

    /// After a full reset the user reads the shared baseline like a new one.
    /// A step writing a rule book into their own partition (even an empty
    /// one) after the purge left them diverged: no rules, and no baseline edit
    /// ever reached them again.
    #[test]
    fn a_full_reset_writes_no_rule_book_of_its_own() {
        let mut done = Vec::new();
        let mut ran = Vec::new();
        while let Next::Run(step) = next(false, &done) {
            ran.push(step.as_str());
            done.push((step, Good));
        }
        assert_eq!(
            ran,
            [
                "clear-logs",
                "reset-sidecar",
                "purge-principal-data",
                "restart-service"
            ]
        );
    }

    /// A reset that ended on a stopped service left the user with no routing
    /// and no protection until they found the service controls.
    #[test]
    fn the_reset_ends_with_the_service_restarted_not_stopped() {
        assert_eq!(ORDER[ORDER.len() - 1], Step::RestartService);
        assert!(Step::parse("stop-service").is_none());
    }

    #[test]
    fn a_failed_best_effort_step_does_not_abort() {
        assert_eq!(next(false, &run(&[Failed])), Next::Run(Step::ResetSidecar));
        let done = run(&[Failed, Skipped, Good, Good]);
        assert_eq!(
            next(false, &done),
            Next::Finish {
                cleared: true,
                restarted: true
            }
        );
    }

    #[test]
    fn a_refused_purge_stops_the_flow_without_elevation() {
        let done = run(&[Good, Skipped, Forbidden]);
        assert_eq!(
            next(false, &done),
            Next::NeedsElevation {
                step: Step::PurgePrincipalData
            }
        );
        assert_eq!(next(true, &done), Next::Run(Step::RestartService));
    }

    #[test]
    fn a_refused_log_clear_is_not_a_reason_to_stop() {
        assert_eq!(
            next(false, &run(&[Forbidden])),
            Next::Run(Step::ResetSidecar)
        );
    }

    /// The data is gone either way; what the user must hear is that the
    /// service did not come back, so they can start it.
    #[test]
    fn a_failed_restart_is_told_apart_from_uncleared_data() {
        let done = run(&[Good, Good, Good, Failed]);
        assert_eq!(
            next(false, &done),
            Next::Finish {
                cleared: true,
                restarted: false
            }
        );
    }
}
