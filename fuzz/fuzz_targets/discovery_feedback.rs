#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() > nrr_shared::ipc_transport::IPC_MAX_MESSAGE_BYTES {
        return;
    }
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        if let Ok(feedback) =
            nrr_shared::ipc_payloads::DiscoveryFeedbackRequest::checked_from_payload(&value)
        {
            assert!(feedback.ids.len() <= 50);
            assert!(feedback.ids.iter().all(|id| id.len() <= 128));
        }
    }
});
