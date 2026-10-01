//! `replay_subscription` exercised over a scripted loopback TCP pair standing
//! in for the named pipe — `replay_subscription` is generic over `Read +
//! Write`, so a real transport is not needed to drive its wire behaviour.
//!
//! 39.5.6: a resubscribe the server refuses (subscription slots exhausted,
//! identity mismatch, …) is an application-level outcome on a connection that
//! just negotiated fine — not a dead transport. Reporting it as one forced a
//! reconnect that hit the exact same refusal forever.

use super::*;
use std::net::{TcpListener, TcpStream};

fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let client = TcpStream::connect(addr).expect("connect loopback");
    let (server, _) = listener.accept().expect("accept loopback");
    (client, server)
}

fn inner_with_remembered_subscription() -> Arc<ClientInner> {
    let inner = Arc::new(ClientInner::new());
    *inner.last_subscribe.lock().expect("lock") = Some(serde_json::json!({
        "operation": "status.subscribe",
        "request-id": "original-sub",
    }));
    inner
}

#[test]
fn a_refused_resubscribe_does_not_kill_the_transport() {
    let inner = inner_with_remembered_subscription();
    let (mut client_io, mut server_io) = loopback_pair();
    let server = thread::spawn(move || {
        let req: Value = read_frame(&mut server_io).expect("server read");
        let request_id = req
            .get("request-id")
            .and_then(|v| v.as_str())
            .expect("request-id")
            .to_string();
        let resp = serde_json::json!({
            "ok": false,
            "request-id": request_id,
            "error": "subscription-limit-exhausted",
        });
        write_frame(&mut server_io, &resp).expect("server write");
    });

    let alive = replay_subscription(&inner, &mut client_io);
    server.join().expect("server thread");

    assert!(
        alive,
        "a server-side refusal of the resubscribe must not be reported as a dead transport"
    );
}

/// An accepted resubscribe replaces the subscription id, so later push frames
/// are labelled with the connection's NEW subscription, not the caller's
/// original one (the server allocates a fresh id per connection).
#[test]
fn an_accepted_resubscribe_remembers_the_new_subscription_id() {
    let inner = inner_with_remembered_subscription();
    let (mut client_io, mut server_io) = loopback_pair();
    let server = thread::spawn(move || {
        let req: Value = read_frame(&mut server_io).expect("server read");
        let request_id = req
            .get("request-id")
            .and_then(|v| v.as_str())
            .expect("request-id")
            .to_string();
        let resp = serde_json::json!({
            "ok": true,
            "request-id": request_id,
            "payload": {"subscription-id": "new-sub-42"},
        });
        write_frame(&mut server_io, &resp).expect("server write");
    });

    let alive = replay_subscription(&inner, &mut client_io);
    server.join().expect("server thread");

    assert!(alive);
    assert_eq!(
        inner.subscription_id.lock().expect("lock").as_deref(),
        Some("new-sub-42")
    );
}

/// A transport that dies mid-resubscribe (the read never returns a frame) is
/// the one case that must still force a reconnect.
#[test]
fn a_dropped_connection_during_resubscribe_is_reported_dead() {
    let inner = inner_with_remembered_subscription();
    let (mut client_io, server_io) = loopback_pair();
    // Drop the server end immediately: the write may succeed (buffered), but
    // the read that follows sees EOF rather than a matching response.
    drop(server_io);

    let alive = replay_subscription(&inner, &mut client_io);
    assert!(
        !alive,
        "a transport that never answers must still be treated as dead"
    );
}
