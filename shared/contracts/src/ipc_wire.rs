//! Wire-format codec for the IPC named pipe.
//!
//! ## Frame format
//!
//! ```text
//! +-----------+------------------------------+
//! | u32 BE    | UTF-8 JSON payload (N bytes) |
//! +-----------+------------------------------+
//! ```
//!
//! - Header: 4 bytes big-endian `u32` payload length
//! - Payload: UTF-8 encoded JSON (`IpcRequestEnvelope` /
//!   `IpcResponseEnvelope`)
//! - Max payload: `IPC_MAX_MESSAGE_BYTES` (`nrr-shared::ipc_transport`)
//!
//! Single source of truth for the codec. Both client (`nrr-ipc-client`)
//! and server (`nrr-windows-service`, `nrr-serviced`) consume this module, so
//! any change to the framing rules lands in one place.
//!
//! It lives in the contracts crate for the reason that sentence implies: a
//! frame format is a fact shared by both ends. While it sat in the CLIENT
//! crate, every server had to depend on the client to speak its own protocol —
//! and that edge carried `nrr-application` and, behind it, the UI and preview
//! crates into a service running as LocalSystem.
//!
//! Cross-platform: takes `Read` / `Write` so the same codec drives both
//! real Windows pipes and the in-memory test transport.

use std::io::{Read, Write};

use serde::{de::DeserializeOwned, Serialize};

use crate::ipc_transport::IPC_MAX_MESSAGE_BYTES;

const INITIAL_FRAME_CAPACITY: usize = 64 * 1024;

/// Read one length-prefixed frame from `r` and return its payload bytes,
/// undecoded.
pub fn read_frame_bytes<R: Read>(r: &mut R) -> Result<Vec<u8>, WireError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).map_err(WireError::Io)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(WireError::ZeroLengthFrame);
    }
    if len > IPC_MAX_MESSAGE_BYTES {
        return Err(WireError::PayloadTooLarge {
            actual: len,
            limit: IPC_MAX_MESSAGE_BYTES,
        });
    }
    // The first chunk is read before reserving the rest: a header alone,
    // claiming the cap, reserves little. Past it the remainder is reserved
    // once, so growth never doubles past the declared length.
    let first = len.min(INITIAL_FRAME_CAPACITY);
    let mut payload = Vec::with_capacity(first);
    read_exactly(r, &mut payload, first)?;
    if len > first {
        payload.reserve_exact(len - first);
        read_exactly(r, &mut payload, len - first)?;
    }
    Ok(payload)
}

fn read_exactly<R: Read>(r: &mut R, out: &mut Vec<u8>, n: usize) -> Result<(), WireError> {
    let before = out.len();
    r.by_ref()
        .take(n as u64)
        .read_to_end(out)
        .map_err(WireError::Io)?;
    if out.len() - before != n {
        return Err(WireError::Io(std::io::ErrorKind::UnexpectedEof.into()));
    }
    Ok(())
}

/// Read one length-prefixed JSON frame from `r` and decode into `T`.
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T, WireError> {
    let payload = read_frame_bytes(r)?;
    serde_json::from_slice(&payload).map_err(|e| WireError::Decode(e.to_string()))
}

/// Encode `value` and write one length-prefixed JSON frame to `w`.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, value: &T) -> Result<(), WireError> {
    let payload = serde_json::to_vec(value).map_err(|e| WireError::Encode(e.to_string()))?;
    if payload.len() > IPC_MAX_MESSAGE_BYTES {
        return Err(WireError::PayloadTooLarge {
            actual: payload.len(),
            limit: IPC_MAX_MESSAGE_BYTES,
        });
    }
    let len = (payload.len() as u32).to_be_bytes();
    w.write_all(&len).map_err(WireError::Io)?;
    w.write_all(&payload).map_err(WireError::Io)?;
    // `flush` stays. It is load-bearing on a Windows named pipe: the
    // request/response paths write a frame and close the handle right after,
    // and without `FlushFileBuffers` the peer can be left reading a pipe whose
    // both ends are gone (os error 233 - the broker's round-trip test fails on
    // exactly that). The parked-worker problem it causes on the PUSH path is
    // real but is a different fix: a write deadline for push frames, not a
    // codec that stops delivering.
    w.flush().map_err(WireError::Io)?;
    Ok(())
}

/// Errors returned by the wire codec.
#[derive(Debug)]
pub enum WireError {
    /// Underlying I/O error (pipe closed, broken pipe, etc).
    Io(std::io::Error),
    /// Frame announces zero-length payload.
    ZeroLengthFrame,
    /// Frame size exceeds `IPC_MAX_MESSAGE_BYTES`.
    PayloadTooLarge { actual: usize, limit: usize },
    /// JSON decode failed.
    Decode(String),
    /// JSON encode failed (almost never — only if the value contains
    /// non-string keys or similar serde violations).
    Encode(String),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "wire I/O error: {e}"),
            Self::ZeroLengthFrame => write!(f, "wire frame has zero-length payload"),
            Self::PayloadTooLarge { actual, limit } => {
                write!(f, "wire payload {actual} bytes exceeds limit of {limit}")
            }
            Self::Decode(s) => write!(f, "wire decode failed: {s}"),
            Self::Encode(s) => write!(f, "wire encode failed: {s}"),
        }
    }
}

impl std::error::Error for WireError {}

impl WireError {
    /// True for errors that mean the pipe is dead and we should close /
    /// reconnect. False for errors where the frame was bad but the
    /// transport is alive (we still close by policy, but this lets the
    /// caller distinguish "buggy peer" from "transport gone").
    pub fn is_transport_dead(&self) -> bool {
        matches!(self, Self::Io(_))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {

    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Sample {
        kind: String,
        value: u32,
    }

    fn sample() -> Sample {
        Sample {
            kind: "hello".into(),
            value: 42,
        }
    }

    /// `flush` is part of the contract, not an accident: the request/response
    /// paths close the pipe handle immediately after writing, and on Windows a
    /// frame that was not flushed can leave the peer reading a pipe with no
    /// process on either end (os error 233).
    #[test]
    fn a_frame_is_flushed_before_the_writer_is_let_go() {
        struct CountingFlush {
            written: Vec<u8>,
            flushes: usize,
        }
        impl std::io::Write for CountingFlush {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.written.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.flushes += 1;
                Ok(())
            }
        }

        let mut w = CountingFlush {
            written: Vec::new(),
            flushes: 0,
        };
        write_frame(&mut w, &sample()).expect("write");
        assert_eq!(w.flushes, 1, "the frame must be flushed exactly once");
        let mut read = std::io::Cursor::new(w.written);
        let got: Sample = read_frame(&mut read).expect("read");
        assert_eq!(got, sample());
    }

    use super::*;
    use std::io::Cursor;

    #[test]
    fn write_then_read_roundtrip() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &sample()).unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded: Sample = read_frame(&mut cursor).unwrap();
        assert_eq!(decoded, sample());
    }

    #[test]
    fn frame_starts_with_big_endian_length_prefix() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &sample()).unwrap();
        let payload_len = serde_json::to_vec(&sample()).unwrap().len();
        let header = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(header as usize, payload_len);
    }

    #[test]
    fn read_oversized_frame_rejected() {
        let mut buf: Vec<u8> = Vec::new();
        let oversized = (IPC_MAX_MESSAGE_BYTES as u32 + 1).to_be_bytes();
        buf.extend_from_slice(&oversized);
        let mut cursor = Cursor::new(buf);
        let result: Result<Sample, _> = read_frame(&mut cursor);
        assert!(matches!(result, Err(WireError::PayloadTooLarge { .. })));
    }

    #[test]
    fn a_header_claiming_the_cap_with_no_body_is_a_short_read() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&(IPC_MAX_MESSAGE_BYTES as u32).to_be_bytes());
        buf.extend_from_slice(b"{}");
        let mut cursor = Cursor::new(buf);
        let result: Result<Sample, _> = read_frame(&mut cursor);
        assert!(matches!(result, Err(WireError::Io(_))));
    }

    #[test]
    fn a_frame_at_the_cap_roundtrips() {
        let body =
            serde_json::json!({ "kind": "x".repeat(IPC_MAX_MESSAGE_BYTES - 32), "value": 1 });
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &body).unwrap();
        assert!(buf.len() - 4 <= IPC_MAX_MESSAGE_BYTES);
        let got: serde_json::Value = read_frame(&mut Cursor::new(buf)).unwrap();
        assert_eq!(got["value"], 1);
    }

    #[test]
    fn a_large_frame_reserves_its_declared_length_once() {
        let len = 3 * 1024 * 1024;
        let mut buf = (len as u32).to_be_bytes().to_vec();
        buf.resize(4 + len, b' ');
        let payload = read_frame_bytes(&mut Cursor::new(buf)).unwrap();
        assert_eq!(payload.len(), len);
        assert!(payload.capacity() < len + len / 4, "no doubling slack");
    }

    #[test]
    fn read_zero_length_rejected() {
        let buf: Vec<u8> = vec![0, 0, 0, 0];
        let mut cursor = Cursor::new(buf);
        let result: Result<Sample, _> = read_frame(&mut cursor);
        assert!(matches!(result, Err(WireError::ZeroLengthFrame)));
    }

    #[test]
    fn read_truncated_header_returns_io_error() {
        let buf: Vec<u8> = vec![0, 0];
        let mut cursor = Cursor::new(buf);
        let result: Result<Sample, _> = read_frame(&mut cursor);
        assert!(matches!(result, Err(WireError::Io(_))));
    }

    #[test]
    fn read_truncated_payload_returns_io_error() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&100u32.to_be_bytes());
        buf.extend_from_slice(b"only-five");
        let mut cursor = Cursor::new(buf);
        let result: Result<Sample, _> = read_frame(&mut cursor);
        assert!(matches!(result, Err(WireError::Io(_))));
    }

    #[test]
    fn read_malformed_json_returns_decode_error() {
        let payload = b"this is not json";
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        let mut cursor = Cursor::new(buf);
        let result: Result<Sample, _> = read_frame(&mut cursor);
        assert!(matches!(result, Err(WireError::Decode(_))));
    }

    #[test]
    fn write_oversized_value_rejected() {
        let big = Sample {
            kind: "x".repeat(IPC_MAX_MESSAGE_BYTES + 1),
            value: 0,
        };
        let mut buf: Vec<u8> = Vec::new();
        let result = write_frame(&mut buf, &big);
        assert!(matches!(result, Err(WireError::PayloadTooLarge { .. })));
        assert!(buf.is_empty());
    }

    #[test]
    fn is_transport_dead_only_for_io() {
        let io_err = WireError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "x"));
        assert!(io_err.is_transport_dead());
        assert!(!WireError::ZeroLengthFrame.is_transport_dead());
        assert!(!WireError::PayloadTooLarge {
            actual: 1,
            limit: 0
        }
        .is_transport_dead());
        assert!(!WireError::Decode("x".into()).is_transport_dead());
    }
}
