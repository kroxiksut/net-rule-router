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
//! and server (`nrr-windows-service`) consume this module, so any change
//! to the framing rules lands in one place.
//!
//! Cross-platform: takes `Read` / `Write` so the same codec drives both
//! real Windows pipes and the in-memory test transport.

use std::io::{Read, Write};

use serde::{de::DeserializeOwned, Serialize};

use nrr_shared::ipc_transport::IPC_MAX_MESSAGE_BYTES;

/// Read one length-prefixed JSON frame from `r` and decode into `T`.
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T, WireError> {
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
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).map_err(WireError::Io)?;
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
    use super::*;
    use std::io::Cursor;

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
