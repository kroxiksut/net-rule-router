use super::{serve, with_deadline, MAX_FRAME};
use std::io::Cursor;
use std::time::Duration;

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = (payload.len() as u32).to_ne_bytes().to_vec();
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn a_browser_handshake_reports_only_an_unverified_host_and_unknown_service() {
    let input = frame(br#"{"type":"hello","protocol":1,"requestId":"test-7"}"#);
    let mut output = Vec::new();
    assert!(serve(&mut Cursor::new(input), &mut output).is_ok());
    assert!(output.len() >= 4);
    let response: serde_json::Value = match serde_json::from_slice(&output[4..]) {
        Ok(value) => value,
        Err(error) => panic!("invalid response: {error}"),
    };
    assert_eq!(response["type"], "hello");
    assert_eq!(response["protocol"], 1);
    assert_eq!(response["requestId"], "test-7");
    assert_eq!(
        response["product"],
        nrr_shared::product_identity::PRODUCT_NAME
    );
    assert_eq!(response["service"], "unknown");
}

#[test]
fn hostile_or_truncated_frames_never_get_a_success_response() {
    let mut oversized = ((MAX_FRAME + 1) as u32).to_ne_bytes().to_vec();
    oversized.extend_from_slice(b"{}");
    for input in [
        oversized,
        vec![42, 0],
        frame(br#"{"type":"hello","protocol":2,"requestId":"x"}"#),
        frame(br#"{"type":"hello","protocol":1,"requestId":"../../other"}"#),
        frame(br#"{"type":"hello","protocol":1,"requestId":"x","site":"private"}"#),
        frame(b"{not-json}"),
    ] {
        let mut output = Vec::new();
        let result = serve(&mut Cursor::new(input), &mut output);
        assert!(result.is_err());
        assert!(output.is_empty());
    }
}

#[test]
fn a_peer_stalling_mid_frame_cannot_keep_the_host_alive_indefinitely() {
    let result = with_deadline(
        || {
            std::thread::sleep(Duration::from_millis(100));
            Ok(())
        },
        Duration::from_millis(1),
    );
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(std::io::ErrorKind::TimedOut)
    );
}
