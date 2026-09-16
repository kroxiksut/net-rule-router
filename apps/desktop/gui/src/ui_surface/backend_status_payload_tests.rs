use super::*;

#[test]
fn connected_payload_has_kind_only() {
    let payload = backend_connection_status_to_payload(&BackendConnectionStatus::Connected);
    assert_eq!(payload, json!({"kind": "connected"}));
}

#[test]
fn disconnected_payload_carries_last_error() {
    let payload = backend_connection_status_to_payload(&BackendConnectionStatus::Disconnected {
        last_error: "pipe broken".into(),
    });
    assert_eq!(
        payload,
        json!({"kind": "disconnected", "lastError": "pipe broken"})
    );
}

#[test]
fn protocol_mismatch_payload_carries_versions() {
    let payload =
        backend_connection_status_to_payload(&BackendConnectionStatus::ProtocolMismatch {
            server_version: 3,
            client_version: 1,
        });
    assert_eq!(
        payload,
        json!({
            "kind": "protocol-mismatch",
            "serverVersion": 3,
            "clientVersion": 1,
        })
    );
}
