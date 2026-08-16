//! Exit codes — one table, identical on every operating system.
//!
//! A console's exit code is the one part of its output that scripts are
//! entitled to depend on, so it is defined here as a closed set and mapped from
//! the port's error taxonomy rather than from OS error strings.

use nrr_platform_api::service_control::ServiceControlError;

/// The operation completed.
pub const SUCCESS: u8 = 0;
/// The operation was understood but did not succeed.
pub const FAILED: u8 = 1;
/// The command line was not valid.
pub const USAGE: u8 = 2;
/// The operation requires an elevated console.
pub const NEEDS_PRIVILEGE: u8 = 3;
/// The service is not installed.
pub const NOT_INSTALLED: u8 = 4;
/// The service is installed but not answering.
pub const NOT_RESPONDING: u8 = 5;
/// The operation has no meaning on this platform.
pub const UNSUPPORTED: u8 = 6;
/// The operation was refused because it was not confirmed. Distinct from
/// USAGE: the command was spelled correctly and would have run.
pub const NOT_CONFIRMED: u8 = 7;

/// Map a control-port failure onto its exit code.
pub fn for_error(err: &ServiceControlError) -> u8 {
    match err {
        ServiceControlError::NotInstalled => NOT_INSTALLED,
        ServiceControlError::AccessDenied => NEEDS_PRIVILEGE,
        ServiceControlError::Timeout { .. } => NOT_RESPONDING,
        ServiceControlError::Unsupported { .. } => UNSUPPORTED,
        ServiceControlError::InvalidState { .. } | ServiceControlError::Mechanism { .. } => FAILED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_is_distinct() {
        let codes = [
            SUCCESS,
            FAILED,
            USAGE,
            NEEDS_PRIVILEGE,
            NOT_INSTALLED,
            NOT_RESPONDING,
            UNSUPPORTED,
            NOT_CONFIRMED,
        ];
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
    }

    #[test]
    fn actionable_failures_do_not_collapse_into_the_generic_code() {
        // These three are the ones a user (or a script) acts on differently:
        // elevate, install, or wait/investigate. Folding any of them into
        // FAILED would make the console useless in a script.
        assert_eq!(
            for_error(&ServiceControlError::AccessDenied),
            NEEDS_PRIVILEGE
        );
        assert_eq!(for_error(&ServiceControlError::NotInstalled), NOT_INSTALLED);
        assert_eq!(
            for_error(&ServiceControlError::Timeout {
                operation: "start",
                seconds: 15
            }),
            NOT_RESPONDING
        );
    }

    #[test]
    fn refusing_an_unconfirmed_command_is_not_a_usage_error() {
        // The command was spelled correctly; a script must be able to tell
        // "you meant this but did not confirm" from "you typed it wrong".
        assert_ne!(NOT_CONFIRMED, USAGE);
        assert_ne!(NOT_CONFIRMED, FAILED);
    }

    #[test]
    fn an_unimplemented_platform_is_not_a_usage_error() {
        // "This OS cannot do that" must not read as "you typed it wrong".
        assert_eq!(
            for_error(&ServiceControlError::Unsupported {
                operation: "install"
            }),
            UNSUPPORTED
        );
        assert_ne!(
            for_error(&ServiceControlError::Unsupported {
                operation: "install"
            }),
            USAGE
        );
    }
}
