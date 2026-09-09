//! Is a network adapter ABSENT, or present but refusing to start?
//!
//! The ordinary adapter enumeration answers neither question: an adapter whose
//! driver failed to start is not returned at all, so "the vendor removed it",
//! "the user deleted the connection" and "a second driver broke this one" all
//! arrive as the same silence.
//!
//! Field case that motivated the port: a second VPN client installed an older
//! copy of the same TAP driver, the first vendor's adapter went to
//! `CM_PROB_FAILED_START`, and the vendor's client quietly moved to a different
//! transport. The product could say only "the saved connection is gone", which
//! sends the user looking for a connection to pick instead of telling them a
//! driver needs attention.
//!
//! **Policy / mechanism seam.** The decision — what to tell the user, and
//! whether to keep failing closed — stays neutral. The mechanism is per-OS and
//! genuinely different in kind: Windows asks the configuration manager about a
//! devnode, Linux reads the device's operational state, macOS has no analogue
//! for a driver that failed to start. A backend that cannot answer says so
//! rather than guessing, and the caller keeps the wording it had.

/// What the OS says about one network device the adapter list did not return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceState {
    /// Present and started. Being here at all is unusual — an adapter in this
    /// state normally appears in the ordinary enumeration.
    Started,
    /// Present, but its driver did not start. The connection cannot be used and
    /// will not come back on its own: something has to be repaired.
    FailedToStart,
    /// Present and deliberately switched off by a user or an administrator.
    Disabled,
    /// No such device on this machine.
    Absent,
}

impl DeviceState {
    /// Stable slug for logs and for the wire. The GUI maps these to sentences,
    /// so they are a cross-process contract like every other slug.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::FailedToStart => "failed-to-start",
            Self::Disabled => "disabled",
            Self::Absent => "absent",
        }
    }

    /// Does this state mean the device is on the machine but unusable?
    ///
    /// The distinction the caller acts on: an adapter that is here and broken
    /// asks for repair, one that is absent asks the user to pick another.
    #[must_use]
    pub fn is_present_but_unusable(self) -> bool {
        matches!(self, Self::FailedToStart | Self::Disabled)
    }
}

/// Asks the OS about a network device the adapter enumeration did not return.
pub trait NetworkDeviceStatusPort: Send + Sync {
    /// State of the network device behind `adapter_guid` — the adapter's own
    /// identifier as the binding stores it, braces and case as they come.
    ///
    /// `None` means the question could not be asked on this platform or this
    /// build: not "absent", which is a real answer with real consequences for
    /// what the user is told. A caller must keep its previous wording when it
    /// gets `None`.
    fn device_state(&self, adapter_guid: &str) -> Option<DeviceState>;
}

/// Answers `None` to everything: the platform has no mechanism wired, or the
/// composition root chose not to wire one. Callers keep their prior behaviour.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnknownDeviceStatus;

impl NetworkDeviceStatusPort for UnknownDeviceStatus {
    fn device_state(&self, _adapter_guid: &str) -> Option<DeviceState> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_are_pinned_because_the_gui_maps_them_to_sentences() {
        assert_eq!(DeviceState::Started.as_str(), "started");
        assert_eq!(DeviceState::FailedToStart.as_str(), "failed-to-start");
        assert_eq!(DeviceState::Disabled.as_str(), "disabled");
        assert_eq!(DeviceState::Absent.as_str(), "absent");
    }

    /// The whole point of the port: two states mean "here but unusable" and
    /// lead to a different sentence than the two that do not.
    #[test]
    fn only_a_present_device_asks_the_user_to_repair_rather_than_choose() {
        assert!(DeviceState::FailedToStart.is_present_but_unusable());
        assert!(DeviceState::Disabled.is_present_but_unusable());
        assert!(!DeviceState::Absent.is_present_but_unusable());
        assert!(!DeviceState::Started.is_present_but_unusable());
    }

    /// An unwired platform must not be mistaken for "no such device": the two
    /// send the user to opposite places.
    #[test]
    fn an_unwired_platform_answers_nothing_rather_than_absent() {
        assert_eq!(UnknownDeviceStatus.device_state("{whatever}"), None);
    }
}
