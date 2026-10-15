//! Whether the DoH/DoT lockdown applies to one user right now.
//!
//! A browser that resolves names over encrypted DNS resolves the user's
//! routed sites past the resolver, and their traffic takes the main link with
//! nobody the wiser. So by default the lockdown decides itself: on while the
//! user has rules for the additional route, in every mode and whether or not
//! leak protection is armed. A user who sets the toggle by hand gets what
//! they set, with the scope they chose.

use nrr_storage::doh_lockdown::DohLockdownScope;

/// The one decision both planners and the settings read-back share.
#[must_use]
pub fn doh_lockdown_active(
    auto: bool,
    enabled: bool,
    scope: DohLockdownScope,
    kill_switch_enabled: bool,
    has_secondary_rules: bool,
) -> bool {
    if auto {
        return has_secondary_rules;
    }
    enabled && (scope == DohLockdownScope::Always || kill_switch_enabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The automatic posture follows the rules alone.
    #[test]
    fn automatic_follows_the_secondary_rules_whatever_else_is_set() {
        for enabled in [false, true] {
            for scope in [
                DohLockdownScope::LeakProtectionOnly,
                DohLockdownScope::Always,
            ] {
                for kill_switch in [false, true] {
                    assert!(doh_lockdown_active(true, enabled, scope, kill_switch, true));
                    assert!(!doh_lockdown_active(
                        true,
                        enabled,
                        scope,
                        kill_switch,
                        false
                    ));
                }
            }
        }
    }

    /// A hand-set toggle keeps its old meaning: on, within its scope.
    #[test]
    fn a_hand_set_toggle_keeps_its_scope() {
        let leak_only = DohLockdownScope::LeakProtectionOnly;
        assert!(!doh_lockdown_active(false, false, leak_only, true, true));
        assert!(!doh_lockdown_active(false, true, leak_only, false, true));
        assert!(doh_lockdown_active(false, true, leak_only, true, false));
        assert!(doh_lockdown_active(
            false,
            true,
            DohLockdownScope::Always,
            false,
            false
        ));
    }
}
