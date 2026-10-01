//! Reader-thread → poll-loop hand-off for TUN packets over a fixed pool of
//! reusable buffers. Both queues are bounded array channels, so the steady
//! state allocates nothing per packet, and a stalled consumer holds the
//! producer back instead of growing a queue: the driver ring then overflows
//! and drops, exactly as it would with no reader at all.

use std::sync::mpsc::{self, Receiver, RecvError, SyncSender, TryRecvError};

/// Producer half, owned by the reader thread.
pub(crate) struct PacketFeeder {
    filled: SyncSender<Vec<u8>>,
    free: Receiver<Vec<u8>>,
    allocated: usize,
    depth: usize,
    slot_capacity: usize,
}

/// Consumer half, owned by the device.
pub(crate) struct PacketDrain {
    filled: Receiver<Vec<u8>>,
    free: SyncSender<Vec<u8>>,
}

/// Outcome of [`PacketDrain::drain_into`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Drained {
    Packet(usize),
    /// The packet did not fit the caller's buffer and was dropped.
    TooLarge {
        packet_len: usize,
    },
    Empty,
    Disconnected,
}

/// `depth` bounds the packets in flight; `slot_capacity` sizes a buffer when
/// it is first minted (a larger packet grows that one buffer once).
pub(crate) fn packet_relay(depth: usize, slot_capacity: usize) -> (PacketFeeder, PacketDrain) {
    let depth = depth.max(1);
    let (filled_tx, filled_rx) = mpsc::sync_channel(depth);
    let (free_tx, free_rx) = mpsc::sync_channel(depth);
    (
        PacketFeeder {
            filled: filled_tx,
            free: free_rx,
            allocated: 0,
            depth,
            slot_capacity,
        },
        PacketDrain {
            filled: filled_rx,
            free: free_tx,
        },
    )
}

impl PacketFeeder {
    /// Copies `packet` into a pooled buffer and queues it. Blocks while every
    /// buffer is in flight; `Err` means the drain is gone.
    pub(crate) fn push(&mut self, packet: &[u8]) -> Result<(), RecvError> {
        let mut slot = self.take_slot()?;
        slot.clear();
        slot.extend_from_slice(packet);
        self.filled.send(slot).map_err(|_| RecvError)
    }

    fn take_slot(&mut self) -> Result<Vec<u8>, RecvError> {
        match self.free.try_recv() {
            Ok(slot) => Ok(slot),
            Err(TryRecvError::Empty) if self.allocated < self.depth => {
                self.allocated += 1;
                Ok(Vec::with_capacity(self.slot_capacity))
            }
            Err(TryRecvError::Empty) => self.free.recv(),
            Err(TryRecvError::Disconnected) => Err(RecvError),
        }
    }
}

impl PacketDrain {
    /// Moves the oldest queued packet into `buf` without blocking and returns
    /// its buffer to the pool.
    pub(crate) fn drain_into(&self, buf: &mut [u8]) -> Drained {
        let slot = match self.filled.try_recv() {
            Ok(slot) => slot,
            Err(TryRecvError::Empty) => return Drained::Empty,
            Err(TryRecvError::Disconnected) => return Drained::Disconnected,
        };
        let len = slot.len();
        let outcome = match buf.get_mut(..len) {
            Some(dst) => {
                dst.copy_from_slice(&slot);
                Drained::Packet(len)
            }
            None => Drained::TooLarge { packet_len: len },
        };
        // At most `depth` buffers exist, so this never blocks; a failure only
        // means the feeder is gone.
        let _ = self.free.try_send(slot);
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alloc_count::allocations_during;

    #[test]
    fn steady_state_relays_packets_without_allocating() {
        // Positive control: the counter does see an allocation.
        assert!(allocations_during(|| drop(std::hint::black_box(vec![0u8; 64]))) > 0);
        let (mut feeder, drain) = packet_relay(4, 1500);
        let packet = [0xABu8; 1400];
        let mut buf = [0u8; 2048];
        // Warm the pool up to its full depth.
        for _ in 0..4 {
            assert!(feeder.push(&packet).is_ok());
        }
        for _ in 0..4 {
            assert_eq!(drain.drain_into(&mut buf), Drained::Packet(packet.len()));
        }
        let allocations = allocations_during(|| {
            for round in 0..1000 {
                let len = 20 + round % 1300;
                assert!(feeder.push(&packet[..len]).is_ok());
                assert_eq!(drain.drain_into(&mut buf), Drained::Packet(len));
            }
        });
        assert_eq!(allocations, 0);
    }

    #[test]
    fn packets_arrive_intact_and_in_order() {
        let (mut feeder, drain) = packet_relay(8, 16);
        for n in 1..=3u8 {
            assert!(feeder.push(&vec![n; usize::from(n) * 10]).is_ok());
        }
        let mut buf = [0u8; 64];
        for n in 1..=3u8 {
            let len = usize::from(n) * 10;
            assert_eq!(drain.drain_into(&mut buf), Drained::Packet(len));
            assert!(buf[..len].iter().all(|b| *b == n));
        }
        assert_eq!(drain.drain_into(&mut buf), Drained::Empty);
    }

    #[test]
    fn an_oversized_packet_is_dropped_and_its_buffer_reused() {
        let (mut feeder, drain) = packet_relay(1, 16);
        assert!(feeder.push(&[1u8; 32]).is_ok());
        let mut buf = [0u8; 16];
        assert_eq!(
            drain.drain_into(&mut buf),
            Drained::TooLarge { packet_len: 32 }
        );
        // The single buffer came back, so a depth-1 relay does not block.
        assert!(feeder.push(&[2u8; 8]).is_ok());
        assert_eq!(drain.drain_into(&mut buf), Drained::Packet(8));
    }

    #[test]
    fn a_full_relay_holds_the_producer_back() {
        let (mut feeder, drain) = packet_relay(2, 8);
        assert!(feeder.push(&[1]).is_ok());
        assert!(feeder.push(&[2]).is_ok());
        let producer = std::thread::spawn(move || feeder.push(&[3]).is_ok());
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!producer.is_finished());
        let mut buf = [0u8; 8];
        assert_eq!(drain.drain_into(&mut buf), Drained::Packet(1));
        assert_eq!(producer.join().ok(), Some(true));
    }

    #[test]
    fn either_half_dropping_is_observed_by_the_other() {
        let (mut feeder, drain) = packet_relay(1, 8);
        assert!(feeder.push(&[1]).is_ok());
        drop(drain);
        // Pool exhausted and the drain gone: the blocked wait ends in an error.
        assert!(feeder.push(&[2]).is_err());

        let (feeder, drain) = packet_relay(1, 8);
        drop(feeder);
        assert_eq!(drain.drain_into(&mut [0u8; 8]), Drained::Disconnected);
    }
}
