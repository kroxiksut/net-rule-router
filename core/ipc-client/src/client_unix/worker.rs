//! The owned worker thread: one connection at a time, one request in flight,
//! reconnect with backoff when the socket goes.
//!
//! Split out of `client_unix`; the code is unchanged.

use super::frames::*;
use super::*;

// ── Worker loop ──────────────────────────────────────────────────────────────

pub(super) fn worker_loop(inner: Arc<ClientInner>) {
    let request_rx = match inner.request_rx.lock() {
        Ok(mut g) => match g.take() {
            Some(r) => r,
            None => return,
        },
        Err(_) => return,
    };

    let mut backoff = ReconnectBackoff::fast();

    while !inner.shutdown.load(Ordering::SeqCst) {
        inner.set_status(ConnectionStatus::Connecting);
        let stream = match transport_unix::connect_to(&inner.endpoint) {
            Ok(s) => s,
            Err(e) => {
                // No SCM probe on Linux — the service is a systemd unit. Just
                // back off and retry; systemd owns start/stop.
                inner.set_status(ConnectionStatus::Disconnected {
                    last_error: format!("connect failed: {e}"),
                });
                let delay = backoff.next_delay();
                sleep_observing_shutdown(&inner, delay);
                continue;
            }
        };

        // A read must not wait forever: a service that accepts the connection
        // and then answers nothing would otherwise park this worker for the
        // life of the process, with the status still reading `Connected`.
        let mut stream = match transport_unix::TimedStream::new(
            stream,
            Arc::clone(&inner.shutdown),
            RESPONSE_READ_TIMEOUT,
        ) {
            Ok(s) => s,
            Err(e) => {
                inner.set_status(ConnectionStatus::Disconnected {
                    last_error: format!("set read timeout: {e}"),
                });
                let delay = backoff.next_delay();
                sleep_observing_shutdown(&inner, delay);
                continue;
            }
        };

        // Handshake: ContractNegotiate. Interpretation is neutral (protocol).
        let parsed = match negotiate_over(&mut stream) {
            Ok(p) => p,
            Err(e) => {
                inner.set_status(ConnectionStatus::Disconnected {
                    last_error: format!("handshake failed: {e}"),
                });
                let delay = backoff.next_delay();
                sleep_observing_shutdown(&inner, delay);
                continue;
            }
        };
        match parsed {
            NegotiateParse::Ok(info) => {
                if let Ok(mut g) = inner.negotiate_info.write() {
                    *g = Some(info);
                }
                inner.set_status(ConnectionStatus::Connected);
                backoff.reset();
            }
            NegotiateParse::ProtocolMismatch { server_version } => {
                inner.set_status(ConnectionStatus::ProtocolMismatch {
                    server_version,
                    client_version: CLIENT_PROTOCOL_VERSION,
                });
                // Terminal: stop reconnecting until shutdown / force-reconnect.
                wait_for_shutdown_or_force_reconnect(&inner, &request_rx);
                continue;
            }
            NegotiateParse::Unexpected(msg) => {
                inner.set_status(ConnectionStatus::Disconnected {
                    last_error: format!("handshake rejected: {msg}"),
                });
                let delay = backoff.next_delay();
                sleep_observing_shutdown(&inner, delay);
                continue;
            }
        }

        serve_requests(&inner, &request_rx, &mut stream);
    }

    // Drain any remaining pending requests on shutdown.
    while let Ok(p) = request_rx.try_recv() {
        let _ = p.response_tx.send(RequestResponse::Disconnected);
    }
}

pub(super) fn serve_requests<S: Read + Write + IdleDrain>(
    inner: &Arc<ClientInner>,
    request_rx: &Receiver<PendingRequest>,
    stream: &mut S,
) {
    // A subscription lives and dies with the socket connection, so the side
    // that owns reconnect owns restoring it — callers subscribe once.
    if !replay_subscription(inner, stream) {
        return;
    }

    loop {
        if inner.shutdown.load(Ordering::SeqCst) {
            break;
        }
        if inner.force_reconnect.swap(false, Ordering::SeqCst) {
            break;
        }

        // Pull the next request with a small timeout so we re-check shutdown /
        // force-reconnect while idle.
        let pending = match request_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(p) => p,
            Err(RecvTimeoutError::Timeout) => {
                // Idle tick: a subscriber's push frames arrive whenever the
                // service decides, not when we happen to be mid-request. The
                // Windows client has always drained them here; on Linux they
                // sat unread until the next call, so a client that subscribed
                // and went quiet (the tray does exactly that) saw nothing.
                if !stream.drain_idle(inner) {
                    break;
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };

        let request_id = pending
            .envelope
            .get("request-id")
            .or_else(|| pending.envelope.get("request_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // The caller may have given up while this sat in the queue; sending it
        // now would apply a change nobody is waiting for.
        if pending.abandoned.load(Ordering::SeqCst) {
            continue;
        }

        let push = |frame: &Value| route_push_frame(inner, frame, "inline");

        match exchange(stream, &pending.envelope, &request_id, &push) {
            Ok(resp) => {
                if let RequestResponse::Ok(ref payload) = resp {
                    remember_subscription(inner, &pending.envelope);
                    if is_subscribe_envelope(&pending.envelope) {
                        remember_subscription_id(inner, &serde_json::json!({ "payload": payload }));
                    }
                }
                let _ = pending.response_tx.send(resp);
            }
            Err(e) if !e.is_transport_dead() => {
                // The codec refused the request (oversized payload, say); it
                // never reached the socket, so the connection is fine and the
                // caller must hear what actually happened.
                let _ = pending
                    .response_tx
                    .send(RequestResponse::BadResponse(format!(
                        "request rejected: {e}"
                    )));
            }
            Err(e) => {
                // Transport dead — fail this request and break to reconnect.
                let _ = pending.response_tx.send(RequestResponse::Disconnected);
                inner.set_status(ConnectionStatus::Disconnected {
                    last_error: format!("exchange failed: {e}"),
                });
                break;
            }
        }
    }
}

/// Draining server-initiated frames while idle.
///
/// Only the timed stream can do this without blocking, and only it is used in
/// production; the plain `UnixStream` the unit tests drive has nothing to
/// drain, so it answers "still alive" and moves on.
pub(super) trait IdleDrain {
    fn drain_idle(&mut self, inner: &Arc<ClientInner>) -> bool;
}

impl IdleDrain for transport_unix::TimedStream {
    fn drain_idle(&mut self, inner: &Arc<ClientInner>) -> bool {
        drain_push_frames(inner, self)
    }
}

#[cfg(test)]
impl IdleDrain for std::os::unix::net::UnixStream {
    fn drain_idle(&mut self, _inner: &Arc<ClientInner>) -> bool {
        true
    }
}

/// Read whatever server-initiated frames are already waiting, without
/// committing to a long block. Returns `false` when the transport died and the
/// caller must reconnect.
///
/// The probe window bounds only the wait for the first byte — see
/// [`TimedStream::begin_probe`]. Anything with a `request-id` here belongs to
/// no in-flight request, so it is logged and dropped.
pub(super) fn drain_push_frames(
    inner: &Arc<ClientInner>,
    stream: &mut transport_unix::TimedStream,
) -> bool {
    stream.begin_probe(PUSH_PROBE_WINDOW);
    let alive = loop {
        match read_frame::<_, Value>(stream) {
            Ok(frame) => {
                let has_id = frame
                    .get("request-id")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.is_empty());
                if has_id {
                    eprintln!("nrr-ipc-client(unix): discarding idle frame with a request_id");
                } else if crate::protocol::is_server_refusal(&frame) {
                    eprintln!("nrr-ipc-client(unix): service refused while idle");
                    break false;
                } else {
                    route_push_frame(inner, &frame, "idle");
                }
                stream.begin_probe(PUSH_PROBE_WINDOW);
            }
            Err(WireError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => break true,
            Err(_) => break false,
        }
    };
    stream.end_probe();
    alive
}

/// How long an idle tick waits for a push frame to start arriving. Short: the
/// tick repeats every 200 ms anyway, and a longer wait would delay the next
/// outgoing request by exactly that much.
const PUSH_PROBE_WINDOW: Duration = Duration::from_millis(20);
