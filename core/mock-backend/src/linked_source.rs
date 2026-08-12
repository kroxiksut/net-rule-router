//! Mock linked source data for the scaffold phase.
//!
//! Returns a pre-built [`LinkedSourceRegistration`] representing a source in
//! the `Active` / `ManualRefresh` state with a known-good file hash. This is
//! sufficient to exercise the review flow without real file I/O.
//!
//! # preview-only — production goes through the service-owned linked source
//! store (alongside the AutoPoll watcher).

use nrr_domain::linked_source::{
    LinkedSourceId, LinkedSourceLocator, LinkedSourceRegistration, LinkedWatchMode,
    LinkedWatchStatus,
};
use nrr_domain::revision::{ContentHash, UnixTimestamp};

/// Returns a mock `LinkedSourceRegistration` for UI preview and tests.
pub fn mock_linked_registration() -> LinkedSourceRegistration {
    LinkedSourceRegistration {
        id: LinkedSourceId::from_prefixed_string("lsrc-mock-preview-001".to_string())
            .unwrap_or_else(|e| panic!("invalid mock linked source id: {e}")),
        locator: LinkedSourceLocator::from_path(
            "C:\\Users\\user\\Documents\\NetRuleRouter\\rules_primary.txt",
        ),
        watch_mode: LinkedWatchMode::ManualRefresh,
        status: LinkedWatchStatus::Active,
        registered_at: UnixTimestamp::from_secs(1_700_000_000),
        last_successful_check_at: Some(UnixTimestamp::from_secs(1_700_003_600)),
        last_known_file_hash: Some(ContentHash::from_bytes([0xAB; 32])),
        pending_revision_id: None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use nrr_domain::linked_source::LinkedWatchStatus;

    #[test]
    fn mock_linked_registration_is_active_and_manual_refresh() {
        let reg = mock_linked_registration();
        assert_eq!(reg.status, LinkedWatchStatus::Active);
        assert_eq!(reg.watch_mode, LinkedWatchMode::ManualRefresh);
        assert!(reg.pending_revision_id.is_none());
        assert!(reg.last_known_file_hash.is_some());
    }
}
