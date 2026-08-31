//! Writing a machine-wide setting from a user-scoped operation.
//!
//! Six operations change state that belongs to the MACHINE, not to the caller:
//! the shared DoH resolver list, retention and log-retention policy, the
//! apply-failure policy, the service-stability row, and the traffic ledger.
//! They travel under a class that does not require elevation, and their
//! handlers never asked about it - so any authenticated local user could
//! rewrite what every other user on the machine is subject to.
//!
//! The obvious fix - demand elevation for the whole operation - is wrong here,
//! and the reasoning already exists in `service_stability_handlers` for the
//! rules lock: clients read-modify-write the whole row, so refusing every save
//! that merely echoes the current value would turn ordinary settings into a UAC
//! prompt for exactly the users the restriction applies to.
//!
//! So the check is on the VALUE, not on the operation: a non-elevated caller
//! may save anything as long as the machine-wide part comes back unchanged.

use crate::ipc::{IpcError, IpcErrorCode};

/// Whether this write may proceed.
///
/// `true` when the caller is elevated, or when the machine-wide value is not
/// actually changing.
#[must_use]
pub fn machine_scoped_write_allowed<T: PartialEq>(
    requested: &T,
    current: &T,
    caller_is_elevated: bool,
) -> bool {
    caller_is_elevated || requested == current
}

/// The refusal, worded so the GUI can explain what to do.
#[must_use]
pub fn machine_scoped_refusal(setting: &str) -> IpcError {
    IpcError {
        code: IpcErrorCode::Forbidden,
        message: format!(
            "{setting} is shared by every user of this machine; changing it needs an \
             administrator. Saving it unchanged is always allowed."
        ),
        diagnostics_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unchanged_value_saves_without_elevation() {
        // The read-modify-write case: the client sends the whole row back,
        // machine-wide fields included, without meaning to change them.
        assert!(machine_scoped_write_allowed(&7, &7, false));
    }

    #[test]
    fn a_changed_value_needs_elevation() {
        assert!(!machine_scoped_write_allowed(&8, &7, false));
        assert!(machine_scoped_write_allowed(&8, &7, true));
    }

    #[test]
    fn the_refusal_names_the_setting_and_the_way_out() {
        let e = machine_scoped_refusal("The DoH resolver list");
        assert_eq!(e.code, IpcErrorCode::Forbidden);
        assert!(e.message.contains("DoH resolver list"));
        assert!(e.message.contains("administrator"));
    }
}
