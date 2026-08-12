use nrr_ui_support::tray::TrayStatusKind;
use std::env;

pub mod diagnostics {
    pub use nrr_mock_backend::diagnostics::*;
}

pub mod logs {
    pub use nrr_mock_backend::logs::*;
}

pub mod network_interfaces {
    pub use nrr_mock_backend::network_interfaces::*;
}

pub mod rules {
    pub use nrr_mock_backend::rules::*;
}

pub mod security_status {
    pub use nrr_mock_backend::security_status::*;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MockScenarioId {
    ServiceOnline,
    ServiceOffline,
    PendingChanges,
    TamperVisibleStatus,
    OperationSuccess,
    OperationFailure,
}

impl MockScenarioId {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::ServiceOnline => "service-online",
            Self::ServiceOffline => "service-offline",
            Self::PendingChanges => "pending-changes",
            Self::TamperVisibleStatus => "tamper-visible-status",
            Self::OperationSuccess => "operation-success",
            Self::OperationFailure => "operation-failure",
        }
    }
}

pub const MOCK_REQUIRED_SCENARIOS_6_6: [MockScenarioId; 6] = [
    MockScenarioId::ServiceOnline,
    MockScenarioId::ServiceOffline,
    MockScenarioId::PendingChanges,
    MockScenarioId::TamperVisibleStatus,
    MockScenarioId::OperationSuccess,
    MockScenarioId::OperationFailure,
];

pub fn mock_required_scenarios_6_6() -> &'static [MockScenarioId] {
    &MOCK_REQUIRED_SCENARIOS_6_6
}

pub fn mock_scenario_from_env() -> Option<MockScenarioId> {
    let raw = env::var("NRR_MOCK_SCENARIO").ok()?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "service-online" | "online" => Some(MockScenarioId::ServiceOnline),
        "service-offline" | "offline" => Some(MockScenarioId::ServiceOffline),
        "pending-changes" | "pending" => Some(MockScenarioId::PendingChanges),
        "tamper-visible-status" | "tamper" => Some(MockScenarioId::TamperVisibleStatus),
        "operation-success" | "op-success" => Some(MockScenarioId::OperationSuccess),
        "operation-failure" | "op-failure" => Some(MockScenarioId::OperationFailure),
        _ => None,
    }
}

pub fn tray_status_for_mock_scenario(scenario: MockScenarioId) -> Option<TrayStatusKind> {
    match scenario {
        MockScenarioId::ServiceOnline | MockScenarioId::OperationSuccess => None,
        MockScenarioId::ServiceOffline | MockScenarioId::OperationFailure => {
            Some(TrayStatusKind::ServiceUnavailable)
        }
        MockScenarioId::PendingChanges | MockScenarioId::TamperVisibleStatus => {
            Some(TrayStatusKind::PreviewMode)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        mock_required_scenarios_6_6, tray_status_for_mock_scenario, MockScenarioId,
        MOCK_REQUIRED_SCENARIOS_6_6,
    };
    use nrr_ui_support::tray::TrayStatusKind;

    #[test]
    fn required_mock_scenarios_cover_subblock_6_6_baseline() {
        let scenarios = mock_required_scenarios_6_6();
        assert_eq!(scenarios.len(), 6);
        assert!(scenarios.contains(&MockScenarioId::ServiceOnline));
        assert!(scenarios.contains(&MockScenarioId::ServiceOffline));
        assert!(scenarios.contains(&MockScenarioId::PendingChanges));
        assert!(scenarios.contains(&MockScenarioId::TamperVisibleStatus));
        assert!(scenarios.contains(&MockScenarioId::OperationSuccess));
        assert!(scenarios.contains(&MockScenarioId::OperationFailure));
        assert_eq!(scenarios, &MOCK_REQUIRED_SCENARIOS_6_6);
    }

    #[test]
    fn tray_status_mapping_reuses_mock_status_contracts() {
        assert_eq!(
            tray_status_for_mock_scenario(MockScenarioId::ServiceOffline),
            Some(TrayStatusKind::ServiceUnavailable)
        );
        assert_eq!(
            tray_status_for_mock_scenario(MockScenarioId::TamperVisibleStatus),
            Some(TrayStatusKind::PreviewMode)
        );
        assert_eq!(
            tray_status_for_mock_scenario(MockScenarioId::ServiceOnline),
            None
        );
    }
}
