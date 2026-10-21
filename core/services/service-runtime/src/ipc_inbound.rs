//! Reading one request frame off a connection.
//!
//! A request naming an operation this service does not know (a newer client,
//! or a service older than the binaries around it) is answered with a typed
//! error and the connection stays open. Any other undecodable frame is still
//! the peer's protocol error and ends the connection.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_wire::{read_frame_bytes, write_frame, WireError};

use crate::ipc::{IpcError, IpcErrorCode, IpcRequestEnvelope, IpcResponseEnvelope};

/// Longest identifier echoed back from a request we could not route.
const MAX_ECHOED_LEN: usize = 64;

/// One frame, classified.
#[derive(Debug)]
pub enum InboundFrame {
    Request(IpcRequestEnvelope),
    /// Ready to write back; the connection carries on.
    UnsupportedOperation(Box<IpcResponseEnvelope>),
}

/// How long a frame may take from its first byte to its last. A sender that
/// trickles bytes would otherwise hold one of the connection slots for good.
pub const FRAME_READ_DEADLINE: Duration = Duration::from_secs(10);

/// Read and classify one request frame, with no wait on the first byte.
pub fn read_request<R: Read>(r: &mut R) -> Result<InboundFrame, WireError> {
    read_request_within(r, None, FRAME_READ_DEADLINE, |_, _| {})
}

/// Like [`read_request`], waiting `idle` for the first byte and then at most
/// `frame_deadline` for the rest. `set_timeout` applies a per-read wait to the
/// transport; an overdue frame ends as a timed-out I/O error.
pub fn read_request_within<R: Read>(
    r: &mut R,
    idle: Option<Duration>,
    frame_deadline: Duration,
    set_timeout: impl FnMut(&mut R, Option<Duration>),
) -> Result<InboundFrame, WireError> {
    let bytes = {
        let mut reader = DeadlineReader {
            inner: r,
            set_timeout,
            idle,
            frame_deadline,
            started: None,
        };
        reader.arm();
        let bytes = read_frame_bytes(&mut reader);
        reader.disarm();
        bytes?
    };
    match serde_json::from_slice::<IpcRequestEnvelope>(&bytes) {
        Ok(request) => Ok(InboundFrame::Request(request)),
        Err(e) => match unsupported_operation_answer(&bytes) {
            Some(answer) => Ok(InboundFrame::UnsupportedOperation(Box::new(answer))),
            None => Err(WireError::Decode(e.to_string())),
        },
    }
}

struct DeadlineReader<'a, R, F> {
    inner: &'a mut R,
    set_timeout: F,
    idle: Option<Duration>,
    frame_deadline: Duration,
    started: Option<Instant>,
}

impl<R, F: FnMut(&mut R, Option<Duration>)> DeadlineReader<'_, R, F> {
    fn arm(&mut self) {
        (self.set_timeout)(self.inner, self.idle);
    }

    fn disarm(&mut self) {
        (self.set_timeout)(self.inner, None);
    }
}

impl<R: Read, F: FnMut(&mut R, Option<Duration>)> Read for DeadlineReader<'_, R, F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(started) = self.started {
            let left = self
                .frame_deadline
                .checked_sub(started.elapsed())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::TimedOut))?;
            (self.set_timeout)(self.inner, Some(left));
        }
        let n = self.inner.read(buf)?;
        if n > 0 && self.started.is_none() {
            self.started = Some(Instant::now());
        }
        Ok(n)
    }
}

/// Write one response. An answer too large for a frame is replaced by a typed
/// error for the same request, so the client hears why instead of losing the
/// connection.
pub fn write_response<W: Write>(
    w: &mut W,
    response: &IpcResponseEnvelope,
) -> Result<(), WireError> {
    match write_frame(w, response) {
        Err(WireError::PayloadTooLarge { actual, limit }) => {
            tracing::warn!(
                target: "nrr::ipc",
                actual,
                limit,
                "response does not fit one frame, answering with an error"
            );
            write_frame(w, &response_too_large(response))
        }
        other => other,
    }
}

fn response_too_large(response: &IpcResponseEnvelope) -> IpcResponseEnvelope {
    IpcResponseEnvelope {
        request_id: response.request_id.clone(),
        correlation_id: response.correlation_id.clone(),
        operation_id: None,
        ok: false,
        stale: false,
        diagnostics_id: None,
        user_action_required: false,
        payload: None,
        error: Some(IpcError {
            code: IpcErrorCode::ResponseTooLarge,
            message: "the answer does not fit one IPC frame".into(),
            diagnostics_id: None,
        }),
    }
}

/// The answer to a frame whose only fault is an unknown operation slug.
fn unsupported_operation_answer(bytes: &[u8]) -> Option<IpcResponseEnvelope> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let operation = value.get("operation")?.as_str()?;
    if IpcOperationName::from_slug(operation).is_some() {
        return None;
    }
    let request_id = echoable(value.get("request-id")).unwrap_or_default();
    let correlation_id =
        echoable(value.get("correlation-id")).unwrap_or_else(|| request_id.clone());
    let named = echoable_str(operation)
        .map(|op| format!(" `{op}`"))
        .unwrap_or_default();
    Some(IpcResponseEnvelope {
        request_id,
        correlation_id,
        operation_id: None,
        ok: false,
        stale: false,
        diagnostics_id: None,
        user_action_required: false,
        payload: None,
        error: Some(IpcError {
            code: IpcErrorCode::UnsupportedOperation,
            message: format!("operation{named} is not supported by this service version"),
            diagnostics_id: None,
        }),
    })
}

fn echoable(value: Option<&serde_json::Value>) -> Option<String> {
    echoable_str(value?.as_str()?)
}

/// Short and plain, so an echoed identifier cannot carry anything into a log
/// line or a message.
fn echoable_str(s: &str) -> Option<String> {
    let plain = !s.is_empty()
        && s.len() <= MAX_ECHOED_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'));
    plain.then(|| s.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::ipc_wire::write_frame;
    use std::io::Cursor;

    fn framed(value: &serde_json::Value) -> Cursor<Vec<u8>> {
        let mut buf = Vec::new();
        write_frame(&mut buf, value).expect("frame");
        Cursor::new(buf)
    }

    fn request(operation: &str) -> serde_json::Value {
        serde_json::json!({
            "protocol-version": 1,
            "request-id": "r-1",
            "correlation-id": "c-1",
            "operation": operation,
            "operation-class": "read-snapshot",
            "payload": {},
        })
    }

    #[test]
    fn a_known_operation_is_a_request() {
        let got = read_request(&mut framed(&request("rules.list"))).expect("read");
        assert!(matches!(got, InboundFrame::Request(r) if r.request_id == "r-1"));
    }

    #[test]
    fn an_unknown_operation_gets_a_typed_answer_naming_the_request() {
        let got = read_request(&mut framed(&request("rules.from-the-future"))).expect("read");
        let InboundFrame::UnsupportedOperation(answer) = got else {
            panic!("expected a typed answer");
        };
        assert!(!answer.ok);
        assert_eq!(answer.request_id, "r-1");
        assert_eq!(answer.correlation_id, "c-1");
        let error = answer.error.expect("error");
        assert_eq!(error.code, IpcErrorCode::UnsupportedOperation);
        assert!(error.message.contains("rules.from-the-future"));
    }

    #[test]
    fn the_removed_autostart_toggle_is_unsupported() {
        let got = read_request(&mut framed(&request("autostart.toggle"))).expect("read");
        assert!(matches!(got, InboundFrame::UnsupportedOperation(_)));
    }

    #[test]
    fn the_connection_serves_the_next_frame_after_an_unsupported_one() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &request("rules.from-the-future")).expect("frame");
        write_frame(&mut buf, &request("rules.list")).expect("frame");
        let mut cursor = Cursor::new(buf);
        assert!(matches!(
            read_request(&mut cursor),
            Ok(InboundFrame::UnsupportedOperation(_))
        ));
        assert!(matches!(
            read_request(&mut cursor),
            Ok(InboundFrame::Request(_))
        ));
    }

    #[test]
    fn hostile_identifiers_are_not_echoed() {
        let mut value = request("evil\nop \u{1b}[31m");
        value["request-id"] = serde_json::json!("x".repeat(500));
        let got = read_request(&mut framed(&value)).expect("read");
        let InboundFrame::UnsupportedOperation(answer) = got else {
            panic!("expected a typed answer");
        };
        assert_eq!(answer.request_id, "");
        let message = answer.error.expect("error").message;
        assert!(!message.contains('\n') && !message.contains('\u{1b}'));
    }

    #[test]
    fn an_answer_too_large_for_a_frame_becomes_a_typed_error() {
        let big = IpcResponseEnvelope {
            request_id: "r-9".into(),
            correlation_id: "c-9".into(),
            operation_id: None,
            ok: true,
            stale: false,
            diagnostics_id: None,
            user_action_required: false,
            payload: Some(serde_json::json!({
                "rows": "x".repeat(nrr_shared::ipc_transport::IPC_MAX_MESSAGE_BYTES)
            })),
            error: None,
        };
        let mut wire = Vec::new();
        write_response(&mut wire, &big).expect("substitute written");
        let got: IpcResponseEnvelope =
            nrr_shared::ipc_wire::read_frame(&mut Cursor::new(wire)).expect("one frame");
        assert!(!got.ok);
        assert_eq!(got.request_id, "r-9");
        assert_eq!(
            got.error.map(|e| e.code),
            Some(IpcErrorCode::ResponseTooLarge)
        );
    }

    #[test]
    fn a_trickling_sender_is_cut_off_at_the_frame_deadline() {
        struct Trickle {
            data: Cursor<Vec<u8>>,
        }
        impl Read for Trickle {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                std::thread::sleep(Duration::from_millis(20));
                let n = buf.len().min(1);
                self.data.read(&mut buf[..n])
            }
        }
        let mut wire = 1000u32.to_be_bytes().to_vec();
        wire.resize(4 + 1000, b' ');
        let mut r = Trickle {
            data: Cursor::new(wire),
        };
        let started = Instant::now();
        let got = read_request_within(&mut r, None, Duration::from_millis(150), |_, _| {});
        match got {
            Err(WireError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::TimedOut),
            other => panic!("expected a timeout, got {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn the_transport_wait_is_the_idle_one_until_a_byte_arrives_then_the_remainder() {
        let mut seen: Vec<Option<Duration>> = Vec::new();
        let mut cursor = framed(&request("rules.list"));
        let idle = Some(Duration::from_secs(20));
        let got = read_request_within(&mut cursor, idle, FRAME_READ_DEADLINE, |_, t| seen.push(t));
        assert!(matches!(got, Ok(InboundFrame::Request(_))));
        assert_eq!(seen.first(), Some(&idle));
        assert!(seen[1..seen.len() - 1]
            .iter()
            .all(|t| t.is_some_and(|d| d <= FRAME_READ_DEADLINE)));
        assert_eq!(seen.last(), Some(&None), "the wait is lifted afterwards");
    }

    #[test]
    fn other_faults_stay_decode_errors() {
        // Known operation, broken envelope.
        let mut value = request("rules.list");
        value["operation-class"] = serde_json::json!("no-such-class");
        assert!(matches!(
            read_request(&mut framed(&value)),
            Err(WireError::Decode(_))
        ));
        // Not an object, no operation, operation of the wrong type.
        for junk in [
            serde_json::json!([1, 2]),
            serde_json::json!({"request-id": "r"}),
            serde_json::json!({"operation": 7}),
        ] {
            assert!(matches!(
                read_request(&mut framed(&junk)),
                Err(WireError::Decode(_))
            ));
        }
    }
}
