use super::*;
// Both halves of the split are private to the module; their tests live here.
use super::frames::*;
use super::worker::*;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::AtomicU32;

// ── Transport-generic helpers over a socketpair ──────────────────────────

#[test]
fn negotiate_over_socketpair_parses_ok() {
    let (mut client, mut server) = UnixStream::pair().expect("socketpair");
    let server_thread = thread::spawn(move || {
        let req: Value = read_frame(&mut server).expect("server read");
        assert_eq!(req["operation"], "contract.negotiate");
        let resp = serde_json::json!({
            "ok": true,
            "payload": {
                "server-version": 1,
                "negotiated-protocol": CLIENT_PROTOCOL_VERSION,
                "service-version": "test-1.0",
                "session-id": "sess-1",
            }
        });
        write_frame(&mut server, &resp).expect("server write");
    });

    match negotiate_over(&mut client).expect("negotiate") {
        NegotiateParse::Ok(info) => {
            assert_eq!(info.server_protocol, 1);
            assert_eq!(info.service_version, "test-1.0");
        }
        _ => panic!("expected Ok"),
    }
    server_thread.join().expect("server thread");
}

#[test]
fn exchange_socketpair_round_trips_and_routes_push() {
    let (mut client, mut server) = UnixStream::pair().expect("socketpair");
    let server_thread = thread::spawn(move || {
        let req: Value = read_frame(&mut server).expect("server read");
        let rid = req["request-id"].as_str().unwrap_or("").to_string();
        // Emit an unsolicited push frame first (empty request-id), then the
        // real response — the client must route the push and match the reply.
        let push = serde_json::json!({ "request-id": "", "payload": { "evt": "hi" } });
        write_frame(&mut server, &push).expect("server push");
        let resp = serde_json::json!({ "ok": true, "request-id": rid, "payload": { "n": 5 } });
        write_frame(&mut server, &resp).expect("server resp");
    });

    let envelope = serde_json::json!({ "request-id": "req-7", "operation": "x" });
    let pushed = Arc::new(Mutex::new(Vec::<Value>::new()));
    let pushed_c = Arc::clone(&pushed);
    let sink = move |v: &Value| pushed_c.lock().expect("lock").push(v.clone());

    let resp = exchange(&mut client, &envelope, "req-7", &sink).expect("exchange");
    match resp {
        RequestResponse::Ok(p) => assert_eq!(p["n"], 5),
        _ => panic!("expected Ok"),
    }
    assert_eq!(pushed.lock().expect("lock").len(), 1);
    server_thread.join().expect("server thread");
}

#[test]
fn dropping_the_last_handle_stops_the_worker() {
    // The old `Arc::strong_count(&inner) == 1` test could never be true —
    // the worker holds an `inner` of its own — so the client leaked a
    // thread and a socket per `start()`. Watch `inner` directly.
    let sock = temp_sock_path();
    let client = UnixIpcClient::start_at(sock.0.clone());
    let inner = Arc::clone(&client.inner);
    let second = client.clone();
    drop(client);
    assert!(
        !inner.shutdown.load(Ordering::SeqCst),
        "a surviving handle must keep the worker running"
    );
    drop(second);
    assert!(
        inner.shutdown.load(Ordering::SeqCst),
        "worker was told to stop"
    );
    assert!(
        inner
            .worker_handle
            .lock()
            .expect("worker handle lock")
            .is_none(),
        "the worker thread was joined"
    );
}

#[test]
fn an_id_less_refusal_answers_the_caller_instead_of_going_to_push() {
    // What the server sends when it refuses before reading the request:
    // no request-id, ok=false, a typed error. The caller must get it.
    let (mut client, mut server) = UnixStream::pair().expect("socketpair");
    let server_thread = thread::spawn(move || {
        let _req: Value = read_frame(&mut server).expect("server read");
        let refusal = serde_json::json!({
            "request-id": "",
            "ok": false,
            "error": { "code": "forbidden", "message": "client rejected" }
        });
        write_frame(&mut server, &refusal).expect("server refusal");
    });

    let envelope = serde_json::json!({ "request-id": "req-9", "operation": "x" });
    let pushed = Arc::new(Mutex::new(Vec::<Value>::new()));
    let pushed_c = Arc::clone(&pushed);
    let sink = move |v: &Value| pushed_c.lock().expect("lock").push(v.clone());

    let resp = exchange(&mut client, &envelope, "req-9", &sink).expect("exchange");
    match resp {
        RequestResponse::ServerError { code, .. } => {
            assert_eq!(code, nrr_shared::ipc_transport::IpcErrorCode::Forbidden);
        }
        _ => panic!("expected ServerError"),
    }
    assert!(
        pushed.lock().expect("lock").is_empty(),
        "a refusal must not reach the push channel"
    );
    server_thread.join().expect("server thread");
}

#[test]
fn the_subscription_id_follows_the_service_across_a_reconnect() {
    // Windows tracked this; on Linux the launcher stamped every forwarded
    // frame with the id captured when the forwarder started, which the
    // service stops recognising after a reconnect.
    let sock = temp_sock_path();
    let listener = UnixListener::bind(&sock.0).expect("bind");
    let stop = Arc::new(AtomicBool::new(false));
    let server = spawn_stub_server(listener, Arc::clone(&stop));

    let client = UnixIpcClient::start_at(sock.0.clone());
    // Prepare and put in force, the way the RPC dispatcher does once the
    // subscribe has been answered.
    let _rx = client.subscribe_push();
    client.commit_push();
    assert!(
        wait_until(Duration::from_secs(3), || client
            .connection_status()
            .is_connected()),
        "client never reached Connected"
    );
    let resp = client.call(
        IpcOperationName::StatusUpdatesSubscribe,
        serde_json::json!({}),
        Duration::from_secs(2),
    );
    assert!(resp.is_ok(), "stub answers subscribe");
    assert_eq!(
        crate::connection::IpcClient::active_subscription_id(&client),
        Some("stub-subscription".to_string())
    );

    stop.store(true, Ordering::SeqCst);
    client.shutdown();
    drop(client);
    let _ = server.join();
}

#[test]
fn a_dropped_push_is_announced_as_a_gap() {
    // A hole in the event stream the subscriber cannot see is worse than a
    // late refresh: the GUI keeps rendering from state that stopped being
    // updated.
    let inner = Arc::new(ClientInner::new(PathBuf::from("/nonexistent.sock")));
    let (push_tx, push_rx) = sync_channel::<Value>(2);
    *inner.push_tx.lock().expect("push lock") = Some(push_tx);

    let frame = |t: &str| {
        serde_json::json!({
            "request-id": "",
            "ok": true,
            "payload": { "event": { "type": t } }
        })
    };
    route_push_frame(&inner, &frame("first"), "test");
    route_push_frame(&inner, &frame("second"), "test");
    // Third one has nowhere to go.
    route_push_frame(&inner, &frame("third"), "test");
    assert!(
        inner.push_gap.load(Ordering::SeqCst),
        "the drop is remembered"
    );

    // Drain, then deliver again: the gap is announced ahead of the frame.
    assert_eq!(
        push_rx.recv().expect("first push")["event"]["type"],
        "first"
    );
    assert_eq!(
        push_rx.recv().expect("second push")["event"]["type"],
        "second"
    );
    route_push_frame(&inner, &frame("fourth"), "test");
    let gap = push_rx.recv().expect("gap announcement");
    assert_eq!(gap["event"]["type"], "push-gap");
    assert_eq!(
        push_rx.recv().expect("fourth push")["event"]["type"],
        "fourth"
    );
    assert!(
        !inner.push_gap.load(Ordering::SeqCst),
        "the debt is settled"
    );
}

#[test]
fn push_frames_are_drained_while_the_client_is_idle() {
    // The Windows client always did this; on Linux a subscriber that went
    // quiet received nothing until its next call.
    let inner = Arc::new(ClientInner::new(PathBuf::from("/nonexistent.sock")));
    let (push_tx, push_rx) = sync_channel::<Value>(4);
    *inner.push_tx.lock().expect("push lock") = Some(push_tx);

    let (client_side, mut server_side) = UnixStream::pair().expect("socketpair");
    let mut timed = transport_unix::TimedStream::new(
        client_side,
        Arc::clone(&inner.shutdown),
        Duration::from_secs(5),
    )
    .expect("wrap stream");

    let push = serde_json::json!({
        "request-id": "",
        "ok": true,
        "payload": { "event": { "type": "adapters-changed" } }
    });
    write_frame(&mut server_side, &push).expect("server push");

    assert!(
        drain_push_frames(&inner, &mut timed),
        "transport stays alive"
    );
    let delivered = push_rx
        .recv_timeout(Duration::from_millis(200))
        .expect("push delivered");
    assert_eq!(delivered["event"]["type"], "adapters-changed");

    // A second drain with nothing waiting must return promptly and keep
    // the connection.
    assert!(drain_push_frames(&inner, &mut timed));
}

#[test]
fn a_request_abandoned_while_queued_is_never_sent() {
    // The caller timed out while this sat behind a slow one. Writing it now
    // would apply a change nobody is waiting for — and for a mutation that
    // is the same policy applied twice.
    let inner = Arc::new(ClientInner::new(PathBuf::from("/nonexistent.sock")));
    let request_rx = inner
        .request_rx
        .lock()
        .expect("rx lock")
        .take()
        .expect("receiver");

    let (client_side, mut server_side) = UnixStream::pair().expect("socketpair");
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen_c = Arc::clone(&seen);
    let server = thread::spawn(move || {
        while let Ok(frame) = read_frame::<_, Value>(&mut server_side) {
            let rid = frame["request-id"].as_str().unwrap_or("").to_string();
            seen_c.lock().expect("lock").push(rid.clone());
            let resp = serde_json::json!({ "ok": true, "request-id": rid, "payload": {} });
            if write_frame(&mut server_side, &resp).is_err() {
                break;
            }
        }
    });

    let queue = |rid: &str, abandoned: bool| {
        let (tx, _rx) = sync_channel::<RequestResponse>(1);
        inner
            .request_tx
            .send(PendingRequest {
                envelope: serde_json::json!({ "request-id": rid, "operation": "x" }),
                response_tx: tx,
                abandoned: Arc::new(AtomicBool::new(abandoned)),
            })
            .expect("queue request");
    };
    queue("req-abandoned", true);
    queue("req-live", false);
    // `inner` owns the sender, so the queue never closes on its own — stop
    // the loop the way the client does.
    let stop = Arc::clone(&inner.shutdown);
    let stopper = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        stop.store(true, Ordering::SeqCst);
    });

    let mut stream = client_side;
    serve_requests(&inner, &request_rx, &mut stream);
    stopper.join().expect("stopper thread");
    drop(stream);
    server.join().expect("server thread");

    let seen = seen.lock().expect("lock").clone();
    assert_eq!(seen, vec!["req-live".to_string()]);
}

#[test]
fn an_oversized_request_is_refused_without_killing_the_connection() {
    // The codec rejects it before a byte reaches the socket, so the pipe is
    // fine — reporting `Disconnected` and reconnecting fixed nothing and
    // hid the real reason from the caller.
    let inner = Arc::new(ClientInner::new(PathBuf::from("/nonexistent.sock")));
    let request_rx = inner
        .request_rx
        .lock()
        .expect("rx lock")
        .take()
        .expect("receiver");

    let (client_side, mut server_side) = UnixStream::pair().expect("socketpair");
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen_c = Arc::clone(&seen);
    let server = thread::spawn(move || {
        while let Ok(frame) = read_frame::<_, Value>(&mut server_side) {
            let rid = frame["request-id"].as_str().unwrap_or("").to_string();
            seen_c.lock().expect("lock").push(rid.clone());
            let resp = serde_json::json!({ "ok": true, "request-id": rid, "payload": {} });
            if write_frame(&mut server_side, &resp).is_err() {
                break;
            }
        }
    });

    let (big_tx, big_rx) = sync_channel::<RequestResponse>(1);
    inner
        .request_tx
        .send(PendingRequest {
            envelope: serde_json::json!({
                "request-id": "req-big",
                "operation": "x",
                "payload": { "blob": "x".repeat(2 * 1024 * 1024) },
            }),
            response_tx: big_tx,
            abandoned: Arc::new(AtomicBool::new(false)),
        })
        .expect("queue big");
    let (small_tx, small_rx) = sync_channel::<RequestResponse>(1);
    inner
        .request_tx
        .send(PendingRequest {
            envelope: serde_json::json!({ "request-id": "req-small", "operation": "x" }),
            response_tx: small_tx,
            abandoned: Arc::new(AtomicBool::new(false)),
        })
        .expect("queue small");

    let stop = Arc::clone(&inner.shutdown);
    let stopper = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        stop.store(true, Ordering::SeqCst);
    });

    let mut stream = client_side;
    serve_requests(&inner, &request_rx, &mut stream);
    stopper.join().expect("stopper thread");
    drop(stream);
    server.join().expect("server thread");

    assert!(
        matches!(
            big_rx.recv_timeout(Duration::from_millis(100)),
            Ok(RequestResponse::BadResponse(_))
        ),
        "the caller must learn the request was rejected, not that the link died"
    );
    assert!(
        matches!(
            small_rx.recv_timeout(Duration::from_millis(100)),
            Ok(RequestResponse::Ok(_))
        ),
        "the connection must survive and serve the next request"
    );
    assert_eq!(
        seen.lock().expect("lock").clone(),
        vec!["req-small".to_string()]
    );
}

// ── End-to-end client against a stub listener ────────────────────────────

struct TempSock(PathBuf);
impl Drop for TempSock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn temp_sock_path() -> TempSock {
    static N: AtomicU32 = AtomicU32::new(0);
    let mut p = std::env::temp_dir();
    p.push(format!(
        "nrr-unix-client-test-{}-{}.sock",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&p);
    TempSock(p)
}

/// Minimal service stand-in: accept connections until `stop` is set; per
/// connection, answer `contract.negotiate` with an ok handshake and echo
/// every other request back with its `request-id`. The listener is
/// non-blocking so `accept` never wedges the thread — it polls `stop`
/// between attempts, so `join()` always returns once the test sets `stop`
/// (no dependency on a fixed connection count, which is what would deadlock
/// when a reconnect races the accept loop).
fn spawn_stub_server(listener: UnixListener, stop: Arc<AtomicBool>) -> thread::JoinHandle<()> {
    spawn_stub_server_counting(listener, stop, Arc::new(AtomicU32::new(0)))
}

/// Same stand-in, plus a counter of `status.updates.subscribe` requests
/// seen across *all* connections, and one push frame emitted ahead of every
/// subscribe reply — the frame ordering a replayed subscription has to
/// survive (push queued before the response it is waiting for).
fn spawn_stub_server_counting(
    listener: UnixListener,
    stop: Arc<AtomicBool>,
    subscribes: Arc<AtomicU32>,
) -> thread::JoinHandle<()> {
    let _ = listener.set_nonblocking(true);
    thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            let mut conn = match listener.accept() {
                Ok((c, _)) => {
                    let _ = c.set_nonblocking(false); // blocking per-conn I/O
                    c
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => return,
            };
            // Serve this connection until the client drops it (read error).
            while let Ok(frame) = read_frame::<_, Value>(&mut conn) {
                let op = frame
                    .get("operation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let rid = frame
                    .get("request-id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if op == IpcOperationName::StatusUpdatesSubscribe.slug() {
                    subscribes.fetch_add(1, Ordering::SeqCst);
                    let push = serde_json::json!({
                        "request-id": "",
                        "ok": true,
                        "payload": { "event": { "type": "stub-status-update" } }
                    });
                    if write_frame(&mut conn, &push).is_err() {
                        break;
                    }
                }
                let resp = if op == "contract.negotiate" {
                    serde_json::json!({
                            "ok": true,
                            "request-id": rid,
                            "payload": {
                                "server-version": 1,
                    "negotiated-protocol": CLIENT_PROTOCOL_VERSION,
                                "service-version": "stub",
                                "session-id": "stub-session",
                            }
                        })
                } else if op == IpcOperationName::StatusUpdatesSubscribe.slug() {
                    // Answer like the service does: the ack carries the id
                    // the subscription is known by from now on.
                    serde_json::json!({
                        "ok": true,
                        "request-id": rid,
                        "payload": {
                            "subscription-id": "stub-subscription",
                            "current-event-id": 0,
                            "gap-detected": false,
                        }
                    })
                } else {
                    serde_json::json!({
                        "ok": true,
                        "request-id": rid,
                        "payload": { "echoed-op": op }
                    })
                };
                if write_frame(&mut conn, &resp).is_err() || stop.load(Ordering::SeqCst) {
                    break;
                }
            }
        }
    })
}

/// Poll `predicate` until true or `timeout` elapses. Returns whether it
/// became true (avoids sleeping on a fixed delay — no `Date::now` needed).
fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    predicate()
}

#[test]
fn connects_and_handshakes_against_stub() {
    let sock = temp_sock_path();
    let listener = UnixListener::bind(&sock.0).expect("bind");
    let stop = Arc::new(AtomicBool::new(false));
    let server = spawn_stub_server(listener, Arc::clone(&stop));

    let client = UnixIpcClient::start_at(sock.0.clone());
    assert!(
        wait_until(Duration::from_secs(3), || client
            .connection_status()
            .is_connected()),
        "client never reached Connected: {:?}",
        client.connection_status()
    );
    let info = client.negotiate_info().expect("negotiate info");
    assert_eq!(info.server_protocol, 1);
    assert_eq!(info.service_version, "stub");

    stop.store(true, Ordering::SeqCst);
    client.shutdown();
    drop(client);
    let _ = server.join();
}

#[test]
fn round_trips_a_call_against_stub() {
    let sock = temp_sock_path();
    let listener = UnixListener::bind(&sock.0).expect("bind");
    let stop = Arc::new(AtomicBool::new(false));
    let server = spawn_stub_server(listener, Arc::clone(&stop));

    let client = UnixIpcClient::start_at(sock.0.clone());
    assert!(wait_until(Duration::from_secs(3), || client
        .connection_status()
        .is_connected()));

    let resp = client
        .call(
            IpcOperationName::ServiceHealthGet,
            serde_json::json!({}),
            Duration::from_secs(2),
        )
        .expect("call ok");
    assert_eq!(resp["echoed-op"], "service.health.get");

    stop.store(true, Ordering::SeqCst);
    client.shutdown();
    drop(client);
    let _ = server.join();
}

#[test]
fn reconnects_after_forced_reconnect() {
    let sock = temp_sock_path();
    let listener = UnixListener::bind(&sock.0).expect("bind");
    let stop = Arc::new(AtomicBool::new(false));
    // Unbounded accept loop: the client reconnects onto a fresh connection,
    // and the server keeps accepting until `stop`.
    let server = spawn_stub_server(listener, Arc::clone(&stop));

    let client = UnixIpcClient::start_at(sock.0.clone());
    assert!(wait_until(Duration::from_secs(3), || client
        .connection_status()
        .is_connected()));
    // A call works on the first connection.
    assert!(client
        .call(
            IpcOperationName::ServiceHealthGet,
            serde_json::json!({}),
            Duration::from_secs(2),
        )
        .is_ok());

    // Force the worker to drop the connection and reconnect. Prove recovery
    // by polling `call()` until it succeeds again — this depends only on
    // the client actually re-establishing a working connection, not on
    // status-flag or connection-count timing (which is what deadlocked the
    // earlier count-based version).
    client.force_reconnect();
    let recovered = wait_until(Duration::from_secs(5), || {
        client
            .call(
                IpcOperationName::ServiceHealthGet,
                serde_json::json!({}),
                Duration::from_millis(500),
            )
            .is_ok()
    });
    assert!(recovered, "client did not recover after forced reconnect");

    stop.store(true, Ordering::SeqCst);
    client.shutdown();
    drop(client);
    let _ = server.join();
}

// A subscription is a property of the connection: after a reconnect the
// server knows nothing about the subscriber, and a caller that subscribed
// once and went quiet (the tray does exactly that) would never see another
// event for the rest of its life. The client owns reconnect, so the client
// must re-issue the subscription — without any caller involvement, which is
// what this test asserts by never calling `subscribe` a second time.
#[test]
fn resubscribes_after_reconnect_without_caller_help() {
    let sock = temp_sock_path();
    let listener = UnixListener::bind(&sock.0).expect("bind");
    let stop = Arc::new(AtomicBool::new(false));
    let subscribes = Arc::new(AtomicU32::new(0));
    let server = spawn_stub_server_counting(listener, Arc::clone(&stop), Arc::clone(&subscribes));

    let client = UnixIpcClient::start_at(sock.0.clone());
    assert!(wait_until(Duration::from_secs(3), || client
        .connection_status()
        .is_connected()));

    let pushes = client.subscribe_push();
    client.commit_push();
    client
        .call(
            IpcOperationName::StatusUpdatesSubscribe,
            serde_json::json!({}),
            Duration::from_secs(2),
        )
        .expect("subscribe accepted");
    assert_eq!(subscribes.load(Ordering::SeqCst), 1);
    assert!(
        pushes.recv_timeout(Duration::from_secs(2)).is_ok(),
        "push on the first connection never reached the subscriber"
    );

    // Drop the connection the way a service restart does.
    client.force_reconnect();

    assert!(
        wait_until(Duration::from_secs(5), || subscribes.load(Ordering::SeqCst)
            >= 2),
        "client never replayed the subscription after reconnect"
    );
    assert!(
        pushes.recv_timeout(Duration::from_secs(2)).is_ok(),
        "push after the replayed subscription never reached the subscriber"
    );

    stop.store(true, Ordering::SeqCst);
    client.shutdown();
    drop(client);
    let _ = server.join();
}

// Nothing to replay must stay a no-op: a client that never subscribed keeps
// reconnecting normally instead of writing a bogus frame on every connect.
#[test]
fn replay_is_a_no_op_without_a_remembered_subscription() {
    let (mut client, mut server) = UnixStream::pair().expect("socketpair");
    let inner = Arc::new(ClientInner::new(PathBuf::from("/nonexistent")));
    assert!(replay_subscription(&inner, &mut client));
    // Nothing was written, so the peer sees an empty (would-block) socket.
    server
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("read timeout");
    let mut buf = [0u8; 1];
    assert!(server.read(&mut buf).is_err(), "replay wrote a frame");
}

#[test]
fn call_returns_disconnected_before_connected() {
    // Point at a path with no listener → never connects. Immediate call
    // returns Disconnected rather than hanging.
    let sock = temp_sock_path(); // nothing bound here
    let client = UnixIpcClient::start_at(sock.0.clone());
    let result = client.call(
        IpcOperationName::ServiceHealthGet,
        serde_json::json!({}),
        Duration::from_millis(50),
    );
    assert!(matches!(result, Err(IpcClientError::Disconnected)));
    client.shutdown();
}

#[test]
fn shutdown_is_idempotent() {
    let sock = temp_sock_path();
    let client = UnixIpcClient::start_at(sock.0.clone());
    client.shutdown();
    client.shutdown(); // no panic
}

// Regression (mirrors the equivalent test in `client.rs` for the Windows
// client): a `force_reconnect()` nudge fired while the worker is backing
// off must not survive the early wake-up it causes, or the next
// successful `serve_requests()` tears itself down before serving a
// request, because its own top-of-loop check would still see the flag
// `true`.
#[test]
fn sleep_observing_shutdown_consumes_force_reconnect_flag() {
    let inner = Arc::new(ClientInner::new(PathBuf::from("/nonexistent")));
    inner.force_reconnect.store(true, Ordering::SeqCst);

    let started = Instant::now();
    sleep_observing_shutdown(&inner, Duration::from_secs(10));

    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(!inner.force_reconnect.load(Ordering::SeqCst));
}
