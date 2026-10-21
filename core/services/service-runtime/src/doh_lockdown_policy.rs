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
/// `leak_protection_on` is `LeakProtection::is_on`: the `leak-protection-only`
/// scope applies under `sites` and `everything` alike.
#[must_use]
pub fn doh_lockdown_active(
    auto: bool,
    enabled: bool,
    scope: DohLockdownScope,
    leak_protection_on: bool,
    has_secondary_rules: bool,
) -> bool {
    if auto {
        return has_secondary_rules;
    }
    enabled && (scope == DohLockdownScope::Always || leak_protection_on)
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
                for protection in [
                    nrr_domain::LeakProtection::Off,
                    nrr_domain::LeakProtection::Sites,
                    nrr_domain::LeakProtection::Everything,
                ] {
                    let on = protection.is_on();
                    assert!(doh_lockdown_active(true, enabled, scope, on, true));
                    assert!(!doh_lockdown_active(true, enabled, scope, on, false));
                }
            }
        }
    }

    /// A hand-set toggle applies within its scope; `leak-protection-only`
    /// follows any protection other than `off`.
    #[test]
    fn a_hand_set_toggle_keeps_its_scope() {
        use nrr_domain::LeakProtection;
        let leak_only = DohLockdownScope::LeakProtectionOnly;
        assert!(!doh_lockdown_active(false, false, leak_only, true, true));
        assert!(!doh_lockdown_active(
            false,
            true,
            leak_only,
            LeakProtection::Off.is_on(),
            true
        ));
        for protection in [LeakProtection::Sites, LeakProtection::Everything] {
            assert!(doh_lockdown_active(
                false,
                true,
                leak_only,
                protection.is_on(),
                false
            ));
        }
        assert!(doh_lockdown_active(
            false,
            true,
            DohLockdownScope::Always,
            false,
            false
        ));
    }
}
