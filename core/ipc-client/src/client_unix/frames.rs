//! Frames on the wire: the handshake, one request/response exchange, the push
//! stream, and what has to be replayed after a reconnect.
//!
//! Split out of `client_unix`; the code is unchanged.

use super::*;

// ── Transport-generic frame exchanges ────────────────────────────────────────
//
// Generic over `Read + Write` so the identical framing / push-routing logic
// runs over a real `UnixStream` and a test `socketpair`. Written generically so
// a future migration of the Windows client onto this shared path (under
// HW-verify) can lift these as-is; today only the Unix client consumes them.

/// Perform the `ContractNegotiate` handshake over `stream`: write the request,
/// read the response, interpret it (neutral). `Err` on transport failure.
pub(super) fn negotiate_over<S: Read + Write>(stream: &mut S) -> Result<NegotiateParse, WireError> {
    let request = build_contract_negotiate(CLIENT_PROTOCOL_VERSION);
    write_frame(stream, &request)?;
    let response: Value = read_frame(stream)?;
    Ok(interpret_negotiate_response(&response))
}

/// Write one request envelope and read frames until the matching response
/// arrives, handing push frames (empty `request-id`) to `push`. `Err` means the
/// transport died and the caller should reconnect.
pub(super) fn exchange<S: Read + Write>(
    stream: &mut S,
    envelope: &Value,
    request_id: &str,
    push: &dyn Fn(&Value),
) -> Result<RequestResponse, WireError> {
    let op = crate::protocol::envelope_operation(envelope);
    write_frame(stream, envelope)?;
    loop {
        let frame: Value = read_frame(stream)?;
        let frame_request_id = frame
            .get("request-id")
            .or_else(|| frame.get("request_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if frame_request_id.is_empty() {
            // A refusal the server issues before it knows our request id is
            // this call's answer — see `is_server_refusal`.
            if crate::protocol::is_server_refusal(&frame) {
                return Ok(parse_response(&frame, op));
            }
            // Server-initiated frame; the whole frame goes to the router so a
            // payload-less one is reported rather than vanishing here.
            push(&frame);
            continue;
        }
        if frame_request_id == request_id {
            return Ok(parse_response(&frame, op));
        }
        // Mismatched request_id on a single-in-flight socket — log and skip.
        eprintln!(
            "nrr-ipc-client(unix): discarding frame with unexpected request_id={frame_request_id}"
        );
    }
}

// ── Subscription survival across reconnects ──────────────────────────────────

/// Remember an accepted subscription request so it can be replayed on the next
/// connection. Only the subscribe operation is remembered; every other accepted
/// request is stateless from the connection's point of view.
pub(super) fn is_subscribe_envelope(envelope: &Value) -> bool {
    envelope
        .get("operation")
        .and_then(|v| v.as_str())
        .map(|op| op == IpcOperationName::StatusUpdatesSubscribe.slug())
        .unwrap_or(false)
}

pub(super) fn remember_subscription(inner: &Arc<ClientInner>, envelope: &Value) {
    if !is_subscribe_envelope(envelope) {
        return;
    }
    if let Ok(mut g) = inner.last_subscribe.lock() {
        *g = Some(envelope.clone());
    }
}

/// Record the id the service handed back for a subscribe. The Windows twin
/// does the same; both re-read it after every reconnect rather than caching
/// the first one.
pub(super) fn remember_subscription_id(inner: &Arc<ClientInner>, frame: &Value) {
    let id = frame
        .get("payload")
        .and_then(|p| {
            p.get("subscription-id")
                .or_else(|| p.get("subscription_id"))
        })
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if id.is_none() {
        return;
    }
    if let Ok(mut g) = inner.subscription_id.lock() {
        *g = id;
    }
}

/// Re-issue the remembered subscription on a freshly connected socket. Runs
/// before the dispatch loop so events emitted right after reconnect are not
/// missed. Returns `false` when the transport died and the caller must
/// reconnect.
pub(super) fn replay_subscription<S: Read + Write>(
    inner: &Arc<ClientInner>,
    stream: &mut S,
) -> bool {
    let remembered = match inner.last_subscribe.lock() {
        Ok(g) => g.clone(),
        Err(_) => {
            eprintln!("nrr-ipc-client(unix): resubscribe skipped — subscription lock poisoned");
            return true;
        }
    };
    let Some(mut replay) = remembered else {
        // Nobody ever subscribed on this client — nothing to restore.
        return true;
    };

    let seq = inner.replay_seq.fetch_add(1, Ordering::SeqCst);
    let request_id = format!("resubscribe-{seq}");
    match replay.as_object_mut() {
        Some(obj) => {
            obj.insert("request-id".into(), Value::String(request_id.clone()));
        }
        None => {
            eprintln!(
                "nrr-ipc-client(unix): resubscribe skipped — remembered envelope not an object"
            );
            return true;
        }
    }

    // Push frames queued ahead of the reply are routed, not discarded — that is
    // exactly what `exchange` already does for a caller request.
    let push = |frame: &Value| route_push_frame(inner, frame, "resubscribe");
    match exchange(stream, &replay, &request_id, &push) {
        Ok(RequestResponse::Ok(payload)) => {
            // The service allocated a NEW subscription for this connection;
            // the id from the caller's original subscribe is dead.
            remember_subscription_id(inner, &serde_json::json!({ "payload": payload }));
            eprintln!("nrr-ipc-client(unix): resubscribed after reconnect (id={request_id})");
            true
        }
        Ok(RequestResponse::ServerError { code, message, .. }) => {
            eprintln!("nrr-ipc-client(unix): resubscribe rejected by server: {code:?} {message}");
            true
        }
        Ok(RequestResponse::BadResponse(reason)) => {
            eprintln!("nrr-ipc-client(unix): resubscribe got a malformed reply: {reason}");
            true
        }
        Ok(RequestResponse::Disconnected) => false,
        Err(e) => {
            inner.set_status(ConnectionStatus::Disconnected {
                last_error: format!("resubscribe failed: {e}"),
            });
            eprintln!("nrr-ipc-client(unix): resubscribe transport failure: {e}");
            false
        }
    }
}

/// Hand a server-initiated frame to the subscriber. Every outcome is reported:
/// a silently dropped push is indistinguishable from one that never arrived,
/// and that ambiguity costs whole test runs to diagnose.
pub(super) fn route_push_frame(inner: &Arc<ClientInner>, frame: &Value, source: &str) {
    let Some(payload) = frame.get("payload").cloned() else {
        eprintln!("nrr-ipc-client(unix): push frame without payload (source={source})");
        return;
    };
    let event_type = payload
        .get("event")
        .and_then(|e| e.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let Ok(guard) = inner.push_tx.lock() else {
        eprintln!("nrr-ipc-client(unix): push {event_type} lost — subscriber lock poisoned");
        return;
    };
    let Some(tx) = guard.as_ref() else {
        eprintln!("nrr-ipc-client(unix): push {event_type} discarded — nobody subscribed");
        return;
    };
    // A dropped frame is a hole in the event stream, and the subscriber has no
    // way of knowing it. Announce the hole once, so the GUI can re-read the
    // snapshots it would otherwise keep rendering from stale pushes.
    if inner.push_gap.swap(false, Ordering::SeqCst) {
        let gap = serde_json::json!({ "event": { "type": "push-gap" } });
        if tx.try_send(gap).is_err() {
            // Still full — keep the debt and try again with the next frame.
            inner.push_gap.store(true, Ordering::SeqCst);
        }
    }
    match tx.try_send(payload) {
        Ok(()) => eprintln!("nrr-ipc-client(unix): push {event_type} delivered (source={source})"),
        Err(e) => {
            eprintln!("nrr-ipc-client(unix): push {event_type} dropped — channel full ({e})");
            inner.push_gap.store(true, Ordering::SeqCst);
        }
    }
}

// ── Shutdown / backoff helpers ───────────────────────────────────────────────

pub(super) fn wait_for_shutdown_or_force_reconnect(
    inner: &Arc<ClientInner>,
    request_rx: &Receiver<PendingRequest>,
) {
    while !inner.shutdown.load(Ordering::SeqCst) {
        if inner.force_reconnect.swap(false, Ordering::SeqCst) {
            break;
        }
        // Drain pending requests so callers don't hang while terminal.
        match request_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(p) => {
                let _ = p.response_tx.send(RequestResponse::Disconnected);
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

pub(super) fn sleep_observing_shutdown(inner: &Arc<ClientInner>, total: Duration) {
    let granularity = Duration::from_millis(50);
    let deadline = Instant::now() + total;
    while Instant::now() < deadline {
        if inner.shutdown.load(Ordering::SeqCst) {
            return;
        }
        // Consume (swap), not just observe: see the matching comment in
        // `client.rs::sleep_observing_shutdown` — a `force_reconnect()` nudge
        // that fires during backoff must not survive past the wake-up it
        // causes, or the NEXT successful connect gets torn down by
        // `serve_requests`' own top-of-loop check before serving a request,
        // and the worker livelocks between "reconnect" and "instant
        // disconnect" for as long as callers keep nudging on failure.
        if inner.force_reconnect.swap(false, Ordering::SeqCst) {
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        thread::sleep(remaining.min(granularity));
    }
}
