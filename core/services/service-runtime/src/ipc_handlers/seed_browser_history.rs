//! `diagnostics.seed-from-browser-history` handler.
//!
//! Opt-in: reads the user's browser history, resolves the rule-matching
//! hostnames, and caches them. Runs on a detached worker thread (the read +
//! resolve can take seconds) and returns immediately with `started: true`; the
//! per-host counts are logged. When no seeder is wired (feature unavailable on
//! this build/platform) it returns `started: false`.

use std::sync::Arc;

use crate::browser_history_seeder::BrowserHistorySeeder;
use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::SeedFromBrowserHistoryResponse;

pub struct SeedFromBrowserHistoryHandler {
    seeder: Arc<BrowserHistorySeeder>,
}

impl SeedFromBrowserHistoryHandler {
    pub fn new(seeder: Arc<BrowserHistorySeeder>) -> Self {
        Self { seeder }
    }
}

impl IpcHandler for SeedFromBrowserHistoryHandler {
    fn handle(&self, _request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let seeder = Arc::clone(&self.seeder);
        // Detach: the read + per-host resolve outlives this reply. The seeder
        // logs its summary and fires the recompute hook when it caches anything.
        let spawned = std::thread::Builder::new()
            .name("nrr-bh-seed".into())
            .spawn(move || {
                let _ = seeder.seed(std::time::SystemTime::now());
            });
        let started = spawned.is_ok();
        if let Err(e) = &spawned {
            tracing::warn!(target: "nrr::browser-history", error = %e, "could not spawn browser-history seed worker");
        }
        serde_json::to_value(SeedFromBrowserHistoryResponse { started }).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("seed-from-browser-history response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}
