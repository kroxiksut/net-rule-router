//! Linux mechanism behind
//! [`nrr_platform_api::network_change::NetworkChangeObserver`].
//!
//! An `AF_NETLINK`/`NETLINK_ROUTE` socket subscribed to the link, address and
//! route multicast groups — the kernel's own change feed, so a tunnel coming up
//! is known the moment it happens rather than at the next poll. Listening needs
//! no privilege: these groups are readable by any process.
//!
//! The reader thread does the minimum the port asks for — call `on_change` and
//! go back to waiting. Coalescing lives in the neutral layer, so a burst of
//! kernel messages costs no more than the callback the caller debounces.
//!
//! Cancellation is a self-pipe rather than a timeout: the thread parks in
//! `poll` with no periodic wakeups, and dropping the subscription writes one
//! byte to retire it immediately.

#![allow(unsafe_code)]
// The socket half has no caller off Linux; the message parser below still
// compiles and is still tested there.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::network_change::{
    NetworkChangeCallback, NetworkChangeObserver, NetworkChangeSubscription,
};

/// Production observer over the kernel's rtnetlink change feed.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxNetworkChangeObserver;

impl NetworkChangeObserver for LinuxNetworkChangeObserver {
    #[cfg(target_os = "linux")]
    fn subscribe(
        &self,
        on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        let watcher = NetlinkWatcher::start(on_change)?;
        Ok(NetworkChangeSubscription::new(Box::new(watcher)))
    }

    #[cfg(not(target_os = "linux"))]
    fn subscribe(
        &self,
        _on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        Err(PlatformError::NotSupported {
            reason: "rtnetlink change notification has no implementation on this host",
        })
    }
}

// ── Message parsing (pure; tested on every host) ─────────────────────────────

/// `struct nlmsghdr`: length, type, flags, sequence, port id.
const NLMSG_HEADER_LEN: usize = 16;
/// Netlink pads every message to a 4-byte boundary.
const NLMSG_ALIGNMENT: usize = 4;

/// Message types that mean the network topology moved under us.
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;

/// Does this message type mean the topology changed?
///
/// The control types (`NLMSG_NOOP`, `NLMSG_ERROR`, `NLMSG_DONE`) share the
/// stream and must not fire the callback: treating an error frame as a change
/// would re-drive routing every time the kernel refuses something.
fn is_topology_change(message_type: u16) -> bool {
    matches!(
        message_type,
        RTM_NEWLINK | RTM_DELLINK | RTM_NEWADDR | RTM_DELADDR | RTM_NEWROUTE | RTM_DELROUTE
    )
}

/// Does a received datagram carry at least one topology change?
///
/// One `recv` can hold several messages back to back, each padded to a 4-byte
/// boundary — walking by the declared length is the only way to reach the
/// second one. A malformed or truncated length ends the walk rather than
/// looping: a bad frame must cost the rest of that datagram, not the thread.
fn carries_topology_change(datagram: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset + NLMSG_HEADER_LEN <= datagram.len() {
        let length = u32::from_ne_bytes([
            datagram[offset],
            datagram[offset + 1],
            datagram[offset + 2],
            datagram[offset + 3],
        ]) as usize;
        if length < NLMSG_HEADER_LEN || offset + length > datagram.len() {
            return false;
        }
        let message_type = u16::from_ne_bytes([datagram[offset + 4], datagram[offset + 5]]);
        if is_topology_change(message_type) {
            return true;
        }
        // Round up to the alignment; a length that is already aligned stays put.
        offset += length.div_ceil(NLMSG_ALIGNMENT) * NLMSG_ALIGNMENT;
    }
    false
}

// ── Socket mechanism (Linux only) ────────────────────────────────────────────

/// Owns the reader thread and the pipe that retires it.
#[cfg(target_os = "linux")]
struct NetlinkWatcher {
    wake_writer: libc::c_int,
    reader: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl NetlinkWatcher {
    fn start(on_change: NetworkChangeCallback) -> Result<Self, PlatformError> {
        let netlink = open_netlink_socket()?;
        let (wake_reader, wake_writer) = match open_wake_pipe() {
            Ok(pair) => pair,
            Err(e) => {
                close_fd(netlink);
                return Err(e);
            }
        };

        let reader = std::thread::Builder::new()
            .name("nrr-netlink-watch".to_string())
            .spawn(move || {
                read_until_woken(netlink, wake_reader, on_change);
                close_fd(netlink);
                close_fd(wake_reader);
            })
            .map_err(|e| {
                close_fd(netlink);
                close_fd(wake_reader);
                close_fd(wake_writer);
                PlatformError::Transient {
                    operation: "spawn rtnetlink watch thread",
                    detail: e.to_string(),
                }
            })?;

        Ok(Self {
            wake_writer,
            reader: Some(reader),
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for NetlinkWatcher {
    fn drop(&mut self) {
        // One byte is enough to break the `poll`; the thread then closes the
        // descriptors it owns.
        let byte = 1u8;
        // SAFETY: `wake_writer` is owned by this value and still open; the
        // buffer is live for the call.
        unsafe {
            libc::write(
                self.wake_writer,
                std::ptr::addr_of!(byte).cast::<libc::c_void>(),
                1,
            );
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        close_fd(self.wake_writer);
    }
}

/// `AF_NETLINK` socket bound to the link / IPv4-address / IPv4-route groups.
/// IPv6 is deliberately absent: the product routes IPv4, and a v6 address
/// churn would only re-drive the same decision.
#[cfg(target_os = "linux")]
fn open_netlink_socket() -> Result<libc::c_int, PlatformError> {
    // SAFETY: three integers in, a descriptor out.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(PlatformError::Transient {
            operation: "open rtnetlink socket",
            detail: std::io::Error::last_os_error().to_string(),
        });
    }
    // SAFETY: `sockaddr_nl` is plain data; zeroed is a valid starting value.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_groups =
        (libc::RTMGRP_LINK | libc::RTMGRP_IPV4_IFADDR | libc::RTMGRP_IPV4_ROUTE) as u32;
    // SAFETY: the address is live for the call and its declared length matches
    // the struct actually passed.
    let rc = unsafe {
        libc::bind(
            fd,
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let detail = std::io::Error::last_os_error().to_string();
        close_fd(fd);
        return Err(PlatformError::Transient {
            operation: "bind rtnetlink groups",
            detail,
        });
    }
    Ok(fd)
}

/// Self-pipe used to retire the reader thread.
#[cfg(target_os = "linux")]
fn open_wake_pipe() -> Result<(libc::c_int, libc::c_int), PlatformError> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a live two-element array, which is what `pipe2` writes.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc < 0 {
        return Err(PlatformError::Transient {
            operation: "open netlink wake pipe",
            detail: std::io::Error::last_os_error().to_string(),
        });
    }
    Ok((fds[0], fds[1]))
}

/// Park in `poll` until either the kernel reports a change or the wake pipe
/// says to stop.
#[cfg(target_os = "linux")]
fn read_until_woken(
    netlink: libc::c_int,
    wake_reader: libc::c_int,
    on_change: NetworkChangeCallback,
) {
    let mut buffer = [0u8; 8192];
    loop {
        let mut fds = [
            libc::pollfd {
                fd: netlink,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_reader,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: `fds` is a live two-element array for the duration of the
        // call; a negative timeout means "block until something happens".
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        // Retirement wins over a pending change: the caller is going away and
        // has nothing left to do with the notification.
        if fds[1].revents != 0 {
            return;
        }
        if fds[0].revents & libc::POLLIN == 0 {
            continue;
        }
        // SAFETY: `buffer` is live and writable for its own length.
        let read = unsafe {
            libc::recv(
                netlink,
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
                0,
            )
        };
        if read < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if carries_topology_change(&buffer[..read as usize]) {
            on_change();
        }
    }
}

#[cfg(target_os = "linux")]
fn close_fd(fd: libc::c_int) {
    // SAFETY: every caller passes a descriptor it owns and does not reuse.
    unsafe {
        libc::close(fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one netlink message: header (native-endian length and type) plus
    /// `payload`, exactly as the kernel frames it.
    fn message(message_type: u16, payload: &[u8]) -> Vec<u8> {
        let length = (NLMSG_HEADER_LEN + payload.len()) as u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&length.to_ne_bytes());
        bytes.extend_from_slice(&message_type.to_ne_bytes());
        bytes.extend_from_slice(&0u16.to_ne_bytes()); // flags
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // sequence
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // port id
        bytes.extend_from_slice(payload);
        while bytes.len() % NLMSG_ALIGNMENT != 0 {
            bytes.push(0);
        }
        bytes
    }

    #[test]
    fn a_link_change_is_a_topology_change() {
        assert!(carries_topology_change(&message(RTM_NEWLINK, b"payload")));
        assert!(carries_topology_change(&message(RTM_DELROUTE, b"x")));
    }

    #[test]
    fn control_messages_do_not_fire_the_callback() {
        // NLMSG_NOOP / NLMSG_ERROR / NLMSG_DONE share the stream. Treating an
        // error frame as a change would re-drive routing every time the kernel
        // refuses something.
        for control in [1u16, 2, 3] {
            assert!(
                !carries_topology_change(&message(control, b"payload")),
                "type {control} must not count as a change"
            );
        }
    }

    #[test]
    fn a_change_behind_a_control_message_is_still_found() {
        // The interesting one is rarely first: the walk has to step over the
        // leading message by its declared length, aligned up.
        let mut datagram = message(3, b"done");
        datagram.extend_from_slice(&message(RTM_NEWADDR, b"addr"));
        assert!(carries_topology_change(&datagram));
    }

    #[test]
    fn an_unaligned_payload_does_not_desynchronise_the_walk() {
        // A 5-byte payload makes the message 21 bytes, padded to 24. Stepping
        // by the raw length would land mid-header and read garbage as a type.
        let mut datagram = message(3, b"12345");
        datagram.extend_from_slice(&message(RTM_NEWLINK, b"1"));
        assert!(carries_topology_change(&datagram));
    }

    #[test]
    fn a_truncated_or_lying_frame_ends_the_walk_instead_of_looping() {
        assert!(!carries_topology_change(&[]));
        assert!(!carries_topology_change(&[0u8; 8]));
        // Length field smaller than a header: stepping by it would never
        // advance past this message.
        let mut liar = message(RTM_NEWLINK, b"x");
        liar[0..4].copy_from_slice(&4u32.to_ne_bytes());
        assert!(!carries_topology_change(&liar));
        // Length longer than the datagram actually is.
        let mut overrun = message(RTM_NEWLINK, b"x");
        overrun[0..4].copy_from_slice(&9999u32.to_ne_bytes());
        assert!(!carries_topology_change(&overrun));
    }

    /// The live half: subscribing must succeed on any Linux host (the groups
    /// need no privilege) and dropping the subscription must return promptly —
    /// a reader thread that only woke on a timeout would make this hang.
    #[cfg(target_os = "linux")]
    #[test]
    fn subscribing_and_dropping_completes_without_a_change_ever_arriving() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let subscription = LinuxNetworkChangeObserver
            .subscribe(Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }))
            .expect("rtnetlink groups need no privilege");
        drop(subscription);
        // Nothing is asserted about the count: a quiet host reports nothing and
        // a busy one may legitimately report several. What matters is that the
        // subscription came up and went away.
        let _ = hits.load(Ordering::SeqCst);
    }

    /// The assertion the port exists for: a real change reaches the callback.
    ///
    /// Needs `CAP_NET_ADMIN` to cause one, so it runs only as root and skips
    /// otherwise — an observer that silently never fires would degrade to the
    /// polling fallback, which is exactly the failure a quiet green test hides.
    /// The trigger is an extra loopback address, added and removed: it emits
    /// `RTM_NEWADDR`/`RTM_DELADDR` without touching any link's state.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_address_change_reaches_the_callback() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        // SAFETY: `geteuid` reads process state and takes no pointer.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        const PROBE_ADDRESS: &str = "127.0.0.9/32";
        let ip = |args: &[&str]| std::process::Command::new("ip").args(args).status();

        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let subscription = LinuxNetworkChangeObserver
            .subscribe(Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }))
            .expect("subscribe");

        let added = ip(&["addr", "add", PROBE_ADDRESS, "dev", "lo"]);
        let deadline = Instant::now() + Duration::from_secs(2);
        while hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        // Put the host back the way it was before asserting, so a failure does
        // not leave a stray address behind.
        let _ = ip(&["addr", "del", PROBE_ADDRESS, "dev", "lo"]);
        drop(subscription);

        assert!(
            added.is_ok_and(|s| s.success()),
            "could not add the probe address; nothing was triggered to observe"
        );
        assert!(
            hits.load(Ordering::SeqCst) > 0,
            "an address change produced no notification"
        );
    }
}
