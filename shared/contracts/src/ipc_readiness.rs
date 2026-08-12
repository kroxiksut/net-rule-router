#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Block6CrossBlockAlignment {
    pub block4_security_alignment_note: &'static str,
    pub block5_interfaces_alignment_note: &'static str,
}

pub const BLOCK_6_8_CROSS_BLOCK_ALIGNMENT: Block6CrossBlockAlignment = Block6CrossBlockAlignment {
    block4_security_alignment_note:
        "Block 6 IPC contracts keep block 4 trust-significant indicators explicit: active revision, pending changes, tamper alerts, rollback state, and service status.",
    block5_interfaces_alignment_note:
        "Block 6 DTO and operation contracts keep block 5 interface model explicit: observed facts vs derived assessments, advisory recommendations, and role confirmation constraints.",
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Block16BoundaryScope {
    pub block6_scope: &'static str,
    pub block16_scope: &'static str,
}

pub const BLOCK_6_8_BLOCK16_BOUNDARY: Block16BoundaryScope = Block16BoundaryScope {
    block6_scope:
        "Stabilize transport, security boundary, DTO contracts, and backend facade contract for GUI/tray.",
    block16_scope:
        "Complete migration of GUI flows to real service-owned policy apply and full production behavior.",
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Block6ReadinessChecklist {
    pub completion_criteria: &'static [&'static str],
    pub downstream_blocks_unblocked: &'static [u8],
}

const BLOCK_6_8_COMPLETION_CRITERIA: [&str; 5] = [
    "transport-selected",
    "security-boundary-defined",
    "dto-contracts-defined",
    "mock-backend-connected",
    "facade-hides-backend-source-from-ui",
];

const BLOCK_6_8_DOWNSTREAM_BLOCKS: [u8; 4] = [7, 13, 14, 16];

pub const BLOCK_6_8_READINESS_CHECKLIST: Block6ReadinessChecklist = Block6ReadinessChecklist {
    completion_criteria: &BLOCK_6_8_COMPLETION_CRITERIA,
    downstream_blocks_unblocked: &BLOCK_6_8_DOWNSTREAM_BLOCKS,
};

pub fn block6_downstream_input_blocks() -> &'static [u8] {
    &BLOCK_6_8_DOWNSTREAM_BLOCKS
}

#[cfg(test)]
mod tests {
    use super::{
        block6_downstream_input_blocks, BLOCK_6_8_BLOCK16_BOUNDARY,
        BLOCK_6_8_CROSS_BLOCK_ALIGNMENT, BLOCK_6_8_READINESS_CHECKLIST,
    };
    use crate::{
        gui_shell_v1, ipc_endpoint_security_specs, DtoGroup, IpcEndpointAccessClass,
        IpcTransportKind, SecurityIndicatorId, DTO_GROUPS_6_5, IPC_TRANSPORT_KIND,
    };

    #[test]
    fn block6_alignment_keeps_block4_security_indicators_explicit() {
        let shell = gui_shell_v1();
        let rules = shell.security_visibility.rules;
        assert!(rules
            .iter()
            .any(|item| item.indicator == SecurityIndicatorId::ActiveRevision));
        assert!(rules
            .iter()
            .any(|item| item.indicator == SecurityIndicatorId::PendingChanges));
        assert!(rules
            .iter()
            .any(|item| item.indicator == SecurityIndicatorId::TamperAlerts));
        assert!(rules
            .iter()
            .any(|item| item.indicator == SecurityIndicatorId::RollbackState));
        assert!(rules
            .iter()
            .any(|item| item.indicator == SecurityIndicatorId::ServiceStatus));
        assert!(BLOCK_6_8_CROSS_BLOCK_ALIGNMENT
            .block4_security_alignment_note
            .contains("block 4"));
    }

    #[test]
    fn block6_alignment_keeps_block5_interfaces_model_visible() {
        let shell = gui_shell_v1();
        assert!(shell.interfaces_routes.manual_role_confirmation_required);
        assert!(shell
            .interfaces_routes
            .observed_vs_derived_boundary
            .contains("observed_facts"));
        assert!(DTO_GROUPS_6_5.contains(&DtoGroup::Interface));
        assert!(BLOCK_6_8_CROSS_BLOCK_ALIGNMENT
            .block5_interfaces_alignment_note
            .contains("block 5"));
    }

    #[test]
    fn block6_readiness_criteria_and_boundary_are_fixed() {
        // Transport mechanism is selected per-OS.
        #[cfg(windows)]
        assert_eq!(IPC_TRANSPORT_KIND, IpcTransportKind::WindowsNamedPipes);
        #[cfg(unix)]
        assert_eq!(IPC_TRANSPORT_KIND, IpcTransportKind::UnixDomainSocket);
        let endpoint_specs = ipc_endpoint_security_specs();
        assert!(endpoint_specs
            .iter()
            .any(|item| item.access_class == IpcEndpointAccessClass::ReadOnly));
        assert!(endpoint_specs
            .iter()
            .any(|item| item.access_class == IpcEndpointAccessClass::PrivilegedMutation));
        assert_eq!(BLOCK_6_8_READINESS_CHECKLIST.completion_criteria.len(), 5);
        assert!(BLOCK_6_8_READINESS_CHECKLIST
            .completion_criteria
            .contains(&"facade-hides-backend-source-from-ui"));
        assert!(BLOCK_6_8_BLOCK16_BOUNDARY
            .block6_scope
            .contains("Stabilize"));
        assert!(BLOCK_6_8_BLOCK16_BOUNDARY
            .block16_scope
            .contains("Complete migration"));
    }

    #[test]
    fn block6_outputs_are_ready_for_next_blocks() {
        let downstream = block6_downstream_input_blocks();
        assert_eq!(downstream, [7, 13, 14, 16]);
        assert_eq!(
            BLOCK_6_8_READINESS_CHECKLIST.downstream_blocks_unblocked,
            downstream
        );
    }
}
