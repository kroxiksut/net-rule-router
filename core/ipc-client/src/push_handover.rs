//! Who delivers server-pushed frames, and when that changes hands.
//!
//! A subscribe prepares a channel and only PUTS IT IN FORCE once the call has
//! been answered. The single-phase version registered the new sender up front,
//! so a subscribe that then failed destroyed the live channel and left the
//! client with none at all — events stopped arriving until some later subscribe
//! happened to work. While the service is unreachable that costs nothing; the
//! case it breaks is a working subscription and a retry that times out.
//!
//! Shared by both OS clients: the rule is about ordering, not about pipes.

use std::sync::mpsc::SyncSender;
use std::sync::Mutex;

use serde_json::Value;

/// Move the prepared sender into the slot that delivers.
pub(crate) fn commit_pending_push(
    pending: &Mutex<Option<SyncSender<Value>>>,
    live: &Mutex<Option<SyncSender<Value>>>,
) {
    let Ok(mut pending) = pending.lock() else {
        return;
    };
    let Some(tx) = pending.take() else {
        return;
    };
    if let Ok(mut live) = live.lock() {
        *live = Some(tx);
    }
}

/// Drop the prepared sender, leaving the delivering one untouched.
pub(crate) fn abandon_pending_push(pending: &Mutex<Option<SyncSender<Value>>>) {
    if let Ok(mut pending) = pending.lock() {
        *pending = None;
    }
}

#[cfg(test)]
mod push_handover_tests {
    use super::*;
    use std::sync::mpsc::sync_channel;

    fn slot() -> Mutex<Option<SyncSender<Value>>> {
        Mutex::new(None)
    }

    fn send_through(live: &Mutex<Option<SyncSender<Value>>>, marker: &str) -> bool {
        let guard = live.lock().expect("slot");
        let Some(tx) = guard.as_ref() else {
            return false;
        };
        tx.try_send(serde_json::json!({ "marker": marker })).is_ok()
    }

    /// A subscribe that does not go through must leave the channel that was
    /// already delivering exactly where it was.
    ///
    /// The single-phase version registered the new sender before the call, so a
    /// failed call left the client with no channel at all and events stopped
    /// arriving until some later subscribe happened to work.
    #[test]
    fn an_abandoned_subscribe_leaves_the_live_channel_delivering() {
        let (live_tx, live_rx) = sync_channel::<Value>(4);
        let live = Mutex::new(Some(live_tx));
        let pending = slot();

        // A second subscribe prepares its own channel, then fails.
        let (_new_tx, new_rx) = sync_channel::<Value>(4);
        *pending.lock().expect("slot") = Some(_new_tx);
        abandon_pending_push(&pending);

        assert!(
            send_through(&live, "still-here"),
            "the live channel is gone"
        );
        assert!(
            live_rx.try_recv().is_ok(),
            "the original subscriber lost its frame"
        );
        assert!(
            new_rx.try_recv().is_err(),
            "an abandoned channel must carry nothing",
        );
        assert!(pending.lock().expect("slot").is_none());
    }

    /// And when it does go through, the prepared channel takes over.
    #[test]
    fn a_committed_subscribe_takes_over_delivery() {
        let (old_tx, old_rx) = sync_channel::<Value>(4);
        let live = Mutex::new(Some(old_tx));
        let pending = slot();
        let (new_tx, new_rx) = sync_channel::<Value>(4);
        *pending.lock().expect("slot") = Some(new_tx);

        commit_pending_push(&pending, &live);

        assert!(send_through(&live, "after-commit"));
        assert!(
            new_rx.try_recv().is_ok(),
            "the new subscriber gets the frame"
        );
        assert!(
            old_rx.try_recv().is_err(),
            "the old channel is no longer fed"
        );
        assert!(
            pending.lock().expect("slot").is_none(),
            "a committed channel is no longer pending",
        );
    }
}
