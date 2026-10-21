//! When a client that watched the service run should tell the user it is gone,
//! and which recoveries to offer.
//!
//! Only a stop nobody asked for counts: a stop the user made from any surface
//! stays silent. The inputs are what the client already holds (the service
//! manager's state and its own memory), so nothing here touches the traffic path.

/// Offer to start the service again.
pub const ACTION_START: &str = "start-service";
/// Offer to remove what the service left applied.
pub const ACTION_RESTORE: &str = "restore-network";

/// What to do after one reading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LossStep {
    /// Raise the notice now.
    pub raise: bool,
    /// What to remember for the next reading.
    pub raised: bool,
    /// Recovery actions to offer, in order; empty while there is nothing to say.
    pub actions: Vec<&'static str>,
}

/// One reading (`serviceLossStep`). `status` is the service manager's slug
/// (`running`, `stopped`, `pending`, `not-installed`, `unknown`); `was_running`
/// says this client has seen the service run; `stop_expected` says a user asked
/// for the stop; `can_restore` says the platform has anything to restore.
/// A notice that was raised stays down for as long as the loss lasts.
pub fn step(
    was_raised: bool,
    status: &str,
    was_running: bool,
    stop_expected: bool,
    can_restore: bool,
) -> LossStep {
    let lost = status == "stopped" && was_running && !stop_expected;
    let mut actions = Vec::new();
    if lost {
        actions.push(ACTION_START);
        if can_restore {
            actions.push(ACTION_RESTORE);
        }
    }
    LossStep {
        raise: lost && !was_raised,
        raised: lost,
        actions,
    }
}
