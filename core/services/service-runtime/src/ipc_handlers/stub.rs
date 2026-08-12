//! Placeholder handler used by [`super::register_production_handlers`]
//! for operations whose real implementation has not yet landed.
//!
//! `RecoveryRequired` (not `Internal`) is intentional:
//! - the response envelope's `user_action_required` flag flips on for
//!   `RecoveryRequired`, prompting the GUI to render the "service
//!   action needed" surface;
//! - the diagnostics id stays empty because there's nothing to
//!   correlate yet — the audit/log subsystem isn't wired here.

use nrr_shared::ipc::IpcOperationName;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};

pub struct UnimplementedHandler {
    op: IpcOperationName,
}

impl UnimplementedHandler {
    pub fn new(op: IpcOperationName) -> Self {
        Self { op }
    }
}

impl IpcHandler for UnimplementedHandler {
    fn handle(&self, _request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        Err(IpcError {
            code: IpcErrorCode::RecoveryRequired,
            message: format!(
                "operation {} not yet implemented (block 16.3 phase A stub)",
                self.op.slug()
            ),
            diagnostics_id: None,
        })
    }
}
