#![no_main]

use libfuzzer_sys::fuzz_target;
use nrr_client_logic::discovery_probe::{discovery_previous_probe, discovery_probe_queue};

fuzz_target!(|data: &[u8]| {
    if data.len() > nrr_shared::ipc_transport::IPC_MAX_MESSAGE_BYTES {
        return;
    }
    // Keep serde's default recursion bound, matching the production IPC ingress.
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = discovery_probe_queue(&value["probe-queue"]);
        let _ = discovery_previous_probe(&value["history"]);
    }
});
