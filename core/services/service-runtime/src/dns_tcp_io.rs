//! DNS framing over a stream with configurable I/O timeouts.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::dns_wire::{read_tcp_message, write_tcp_message, DNS_TCP_MAX_MESSAGE};

pub(super) trait TimeoutIo: Read + Write {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl TimeoutIo for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }
}

/// Enforce one deadline across a stream's reads and writes, with an optional
/// shorter idle interval for each operation.
pub(super) struct DeadlineStream<'a, S, F> {
    stream: &'a mut S,
    deadline: Instant,
    idle: Duration,
    now: F,
}

impl<'a> DeadlineStream<'a, TcpStream, fn() -> Instant> {
    pub(super) fn new(stream: &'a mut TcpStream, within: Duration, idle: Duration) -> Self {
        let now = Instant::now();
        Self {
            stream,
            deadline: now.checked_add(within).unwrap_or(now),
            idle,
            now: Instant::now,
        }
    }
}

impl<S, F: Fn() -> Instant> DeadlineStream<'_, S, F> {
    fn window(&self) -> io::Result<Duration> {
        let left = self.deadline.saturating_duration_since((self.now)());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(left.min(self.idle))
    }
}

impl<S: TimeoutIo, F: Fn() -> Instant> Read for DeadlineStream<'_, S, F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.window()?))?;
        self.stream.read(buf)
    }
}

impl<S: TimeoutIo, F: Fn() -> Instant> Write for DeadlineStream<'_, S, F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.window()?))?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

pub(super) fn exchange_tcp_frame(
    stream: &mut impl TimeoutIo,
    query: &[u8],
    deadline: Instant,
    now: impl Fn() -> Instant,
) -> Result<Option<Vec<u8>>, (Option<&'static str>, io::Error)> {
    let remaining = deadline.saturating_duration_since(now());
    if remaining.is_zero() {
        return Err((None, io::ErrorKind::TimedOut.into()));
    }
    stream
        .set_read_timeout(Some(remaining))
        .and_then(|()| stream.set_write_timeout(Some(remaining)))
        .map_err(|error| (Some("timeout cfg"), error))?;
    let mut stream = DeadlineStream {
        stream,
        deadline,
        idle: remaining,
        now,
    };
    write_tcp_message(&mut stream, query).map_err(|error| (Some("send"), error))?;
    let reply = read_tcp_message(&mut stream, DNS_TCP_MAX_MESSAGE)
        .map_err(|error| (Some("recv"), error))?;
    stream.window().map_err(|error| (Some("recv"), error))?;
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_wire::{build_a_response, build_address_query, QTYPE_A};
    use std::cell::Cell;
    use std::io::Cursor;
    use std::net::Ipv4Addr;

    struct MemoryFrame<'a> {
        now: &'a Cell<Instant>,
        reply: Cursor<Vec<u8>>,
        read_timeout: Cell<Option<Duration>>,
        write_timeout: Cell<Option<Duration>>,
    }

    impl MemoryFrame<'_> {
        fn advance(&self, time: Duration, timeout: Option<Duration>) -> io::Result<()> {
            let allowed = timeout.unwrap_or(time);
            self.now.set(self.now.get() + time.min(allowed));
            if time >= allowed && timeout.is_some() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            Ok(())
        }
    }

    impl Read for MemoryFrame<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.advance(Duration::from_millis(10), self.read_timeout.get())?;
            let chunk = buf.len().min(5);
            self.reply.read(&mut buf[..chunk])
        }
    }

    impl Write for MemoryFrame<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.advance(Duration::from_millis(1), self.write_timeout.get())?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl TimeoutIo for MemoryFrame<'_> {
        fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.read_timeout.set(timeout);
            Ok(())
        }

        fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.write_timeout.set(timeout);
            Ok(())
        }
    }

    #[test]
    fn partial_frame_progress_cannot_extend_the_exchange_budget() {
        let query = build_address_query(7, "budget.example", QTYPE_A).expect("query");
        let reply = build_a_response(&query, &[Ipv4Addr::new(192, 0, 2, 1)], 60).expect("reply");
        let mut frame = Vec::new();
        write_tcp_message(&mut frame, &reply).expect("in-memory frame");

        let started = Instant::now();
        let now = Cell::new(started);
        let budget = Duration::from_millis(45);
        let mut stream = MemoryFrame {
            now: &now,
            reply: Cursor::new(frame.clone()),
            read_timeout: Cell::new(None),
            write_timeout: Cell::new(None),
        };

        let outcome = exchange_tcp_frame(&mut stream, &query, started + budget, || now.get());
        let elapsed = now.get().duration_since(started);
        assert!(
            matches!(&outcome, Err((_, error)) if error.kind() == io::ErrorKind::TimedOut)
                && elapsed <= budget,
            "expected timeout within {budget:?}, got {outcome:?} after {elapsed:?}"
        );

        now.set(started);
        stream.reply = Cursor::new(frame);
        let budget = Duration::from_millis(200);
        let outcome = exchange_tcp_frame(&mut stream, &query, started + budget, || now.get());
        assert_eq!(outcome.expect("in-budget frame"), Some(reply));
        assert!(now.get().duration_since(started) < budget);
    }
}
