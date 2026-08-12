// In-memory test-support transport: much of the surface is exercised only by
// some platforms' tests, so dead-code / test-idiom lints are expected here.
#![allow(
    dead_code,
    clippy::needless_range_loop,
    clippy::default_constructed_unit_structs
)]
//! In-memory transport for cross-platform unit tests.
//!
//! Mirrors the accept-loop / per-connection-worker shape of the real
//! Windows pipe server but uses paired `mpsc::sync_channel` queues
//! instead of named pipes. Allows running the wire codec, identity
//! whitelist, and router dispatch end-to-end on Linux/macOS CI.

use std::io::{self, Read, Write};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};

/// One direction of an in-memory pipe (`SyncSender` writer + `Receiver`
/// reader on the other end).
pub struct InMemPipeEnd {
    rx: Receiver<Vec<u8>>,
    tx: SyncSender<Vec<u8>>,
    /// Held-over read buffer for `Read::read` calls smaller than the
    /// most recent message.
    pending: Vec<u8>,
}

impl InMemPipeEnd {
    fn new(rx: Receiver<Vec<u8>>, tx: SyncSender<Vec<u8>>) -> Self {
        Self {
            rx,
            tx,
            pending: Vec::new(),
        }
    }
}

impl Read for InMemPipeEnd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pending.is_empty() {
            match self.rx.recv() {
                Ok(msg) => self.pending = msg,
                Err(_) => return Ok(0), // peer dropped → EOF
            }
        }
        let n = buf.len().min(self.pending.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
}

impl Write for InMemPipeEnd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx
            .send(buf.to_vec())
            .map(|()| buf.len())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer dropped"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Construct a paired `(server_end, client_end)` of an in-memory pipe.
pub fn pipe_pair() -> (InMemPipeEnd, InMemPipeEnd) {
    let (a_tx, b_rx) = sync_channel::<Vec<u8>>(16);
    let (b_tx, a_rx) = sync_channel::<Vec<u8>>(16);
    (InMemPipeEnd::new(a_rx, a_tx), InMemPipeEnd::new(b_rx, b_tx))
}

/// Test fixture: an in-memory IPC accept queue. The server pushes
/// connection ends here; the test pulls them out, attaches a worker
/// thread, and drives the protocol.
pub struct InMemoryAcceptQueue {
    inner: Arc<Mutex<Vec<InMemPipeEnd>>>,
}

impl Default for InMemoryAcceptQueue {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl InMemoryAcceptQueue {
    pub fn push(&self, end: InMemPipeEnd) {
        if let Ok(mut g) = self.inner.lock() {
            g.push(end);
        }
    }

    pub fn pop(&self) -> Option<InMemPipeEnd> {
        self.inner.lock().ok().and_then(|mut g| g.pop())
    }
}

/// Simulate the server-side per-connection loop using an in-memory pipe end.
///
/// Mirrors `named_pipe_server::handle_connection` but is cross-platform:
/// reads frames from `server_end`, dispatches them through the router,
/// writes responses back. Returns when the read side returns EOF.
///
/// `client_profile` and `caller_is_elevated` synthesise the identity
/// that the real Windows transport extracts from the pipe handle.
#[cfg(test)]
pub fn run_server_loop_for_test(
    mut server_end: InMemPipeEnd,
    router: &nrr_service_runtime::IpcRouter,
    client_profile: nrr_shared::ipc::IpcClientProfile,
    caller_is_elevated: bool,
) {
    use nrr_ipc_client::wire::{read_frame, write_frame};
    use nrr_service_runtime::{IpcRequestContext, IpcRequestEnvelope};

    while let Ok(request) = read_frame::<_, IpcRequestEnvelope>(&mut server_end) {
        let ctx = IpcRequestContext {
            client_profile,
            caller_is_elevated,
            caller_principal: None,
        };
        let response = router.dispatch(request, ctx);
        if write_frame(&mut server_end, &response).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn pair_passes_message_in_each_direction() {
        let (mut a, mut b) = pipe_pair();
        a.write_all(b"hello").unwrap();
        b.write_all(b"world").unwrap();

        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");

        a.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"world");
    }

    #[test]
    fn dropping_peer_returns_eof_on_read() {
        let (mut a, b) = pipe_pair();
        drop(b);
        let mut buf = [0u8; 4];
        let n = a.read(&mut buf).unwrap();
        assert_eq!(n, 0, "EOF when peer dropped");
    }

    #[test]
    fn read_smaller_than_message_returns_partial() {
        let (mut a, mut b) = pipe_pair();
        a.write_all(b"abcdefgh").unwrap();
        let mut buf = [0u8; 4];
        b.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"abcd");
        b.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"efgh");
    }

    #[test]
    fn concurrent_send_recv_serializes_correctly() {
        let (mut a, mut b) = pipe_pair();
        let producer = thread::spawn(move || {
            for i in 0..10u8 {
                a.write_all(&[i]).unwrap();
            }
        });
        let mut received = Vec::new();
        for _ in 0..10 {
            let mut buf = [0u8; 1];
            b.read_exact(&mut buf).unwrap();
            received.push(buf[0]);
        }
        producer.join().unwrap();
        assert_eq!(received, (0..10u8).collect::<Vec<_>>());
    }

    #[test]
    fn accept_queue_pops_in_lifo_order() {
        let queue = InMemoryAcceptQueue::default();
        let (a, _b) = pipe_pair();
        let (c, _d) = pipe_pair();
        queue.push(a);
        queue.push(c);
        assert!(queue.pop().is_some());
        assert!(queue.pop().is_some());
        assert!(queue.pop().is_none());
    }

    // ── End-to-end: client → wire → router → wire → client ────────────────

    use nrr_ipc_client::wire::{read_frame, write_frame};
    use nrr_service_runtime::{
        HandlerOutcome, IpcAuditEmitter, IpcHandler, IpcHandlerRegistry, IpcOperationClass,
        IpcRequestContext, IpcRequestEnvelope, IpcResponseEnvelope, IpcRouter, NoopIpcAuditEmitter,
        IPC_PROTOCOL_VERSION,
    };
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use std::sync::Arc;

    struct EchoHandler;
    impl IpcHandler for EchoHandler {
        fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
            Ok(serde_json::json!({ "echoed": request.operation.slug() }))
        }
    }

    fn make_router_with_echo() -> IpcRouter {
        let mut reg = IpcHandlerRegistry::new();
        reg.register(IpcOperationName::ServiceHealthGet, EchoHandler);
        let audit: Arc<dyn IpcAuditEmitter> = Arc::new(NoopIpcAuditEmitter::default());
        IpcRouter::new(reg, audit, 1)
    }

    fn read_request(req_id: &str) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: req_id.into(),
            correlation_id: None,
            operation: IpcOperationName::ServiceHealthGet,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload: serde_json::json!({}),
        }
    }

    #[test]
    fn end_to_end_request_response_through_in_memory_pipe() {
        let router = Arc::new(make_router_with_echo());
        let (server_end, mut client_end) = pipe_pair();

        // Spawn server loop on a worker thread.
        let router_clone = Arc::clone(&router);
        let server = thread::spawn(move || {
            run_server_loop_for_test(
                server_end,
                &router_clone,
                IpcClientProfile::GuiInteractive,
                true,
            );
        });

        // Client: send one request, read one response.
        let request = read_request("req-1");
        write_frame(&mut client_end, &request).unwrap();
        let response: IpcResponseEnvelope = read_frame(&mut client_end).unwrap();

        assert!(response.ok);
        assert_eq!(response.request_id, "req-1");
        assert_eq!(
            response.payload.unwrap()["echoed"],
            serde_json::json!("service.health.get")
        );

        // Drop client → server loop sees EOF → exits.
        drop(client_end);
        server.join().expect("server thread");
    }

    #[test]
    fn end_to_end_invalid_protocol_version_rejected() {
        let router = Arc::new(make_router_with_echo());
        let (server_end, mut client_end) = pipe_pair();

        let router_clone = Arc::clone(&router);
        let server = thread::spawn(move || {
            run_server_loop_for_test(
                server_end,
                &router_clone,
                IpcClientProfile::GuiInteractive,
                true,
            );
        });

        let mut bad = read_request("req-bad");
        bad.protocol_version = 999;
        write_frame(&mut client_end, &bad).unwrap();
        let response: IpcResponseEnvelope = read_frame(&mut client_end).unwrap();
        assert!(!response.ok);
        let err = response.error.unwrap();
        assert_eq!(err.code, nrr_service_runtime::IpcErrorCode::InvalidVersion);

        drop(client_end);
        server.join().unwrap();
    }

    #[test]
    fn end_to_end_multiple_requests_serialised_correctly() {
        let router = Arc::new(make_router_with_echo());
        let (server_end, mut client_end) = pipe_pair();

        let router_clone = Arc::clone(&router);
        let server = thread::spawn(move || {
            run_server_loop_for_test(
                server_end,
                &router_clone,
                IpcClientProfile::GuiInteractive,
                true,
            );
        });

        for i in 0..5 {
            let req = read_request(&format!("req-{i}"));
            write_frame(&mut client_end, &req).unwrap();
            let resp: IpcResponseEnvelope = read_frame(&mut client_end).unwrap();
            assert_eq!(resp.request_id, format!("req-{i}"));
            assert!(resp.ok);
        }

        drop(client_end);
        server.join().unwrap();
    }
}
