//! Linux mechanism behind
//! [`nrr_platform_api::dns_config_change::DnsConfigChangeObserver`].
//!
//! A link's DNS servers and domains reach the DNS manager over D-Bus or a hook
//! script, with no rtnetlink message of their own — a VPN client typically
//! pushes its domain after the tunnel's addresses and routes are already up.
//! Every manager the product captures through writes the result to a file:
//! systemd-resolved and NetworkManager rewrite their `resolv.conf`, resolvconf
//! keeps one record per interface. inotify on those directories is the change
//! feed; a manager that is not installed has no directory and costs nothing.
//!
//! Same thread shape as the rtnetlink watcher: `poll` with no timeout, retired
//! through a self-pipe.

#![allow(unsafe_code)]
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::PathBuf;

use nrr_platform_api::dns_config_change::DnsConfigChangeObserver;
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::network_change::{NetworkChangeCallback, NetworkChangeSubscription};

/// A directory to watch, and which of its entries matter (`None`: any).
#[derive(Clone, Debug)]
pub struct WatchedDir {
    pub path: PathBuf,
    pub names: Option<&'static [&'static str]>,
}

/// Production observer over [`system_dirs`].
#[derive(Clone, Debug)]
pub struct LinuxDnsConfigChangeObserver {
    dirs: Vec<WatchedDir>,
}

impl Default for LinuxDnsConfigChangeObserver {
    fn default() -> Self {
        Self::watching(system_dirs())
    }
}

impl LinuxDnsConfigChangeObserver {
    pub fn watching(dirs: Vec<WatchedDir>) -> Self {
        Self { dirs }
    }
}

/// Where the DNS managers leave the configuration they apply.
pub fn system_dirs() -> Vec<WatchedDir> {
    const RESOLV_FILES: &[&str] = &["resolv.conf", "stub-resolv.conf", "no-stub-resolv.conf"];
    vec![
        WatchedDir {
            path: PathBuf::from("/run/systemd/resolve"),
            names: Some(RESOLV_FILES),
        },
        WatchedDir {
            path: PathBuf::from("/run/NetworkManager"),
            names: Some(RESOLV_FILES),
        },
        WatchedDir {
            path: PathBuf::from("/run/resolvconf/interface"),
            names: None,
        },
        WatchedDir {
            path: PathBuf::from("/run/resolvconf/interfaces"),
            names: None,
        },
    ]
}

impl DnsConfigChangeObserver for LinuxDnsConfigChangeObserver {
    #[cfg(target_os = "linux")]
    fn subscribe(
        &self,
        on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        match InotifyWatcher::start(&self.dirs, on_change)? {
            Some(watcher) => Ok(NetworkChangeSubscription::new(Box::new(watcher))),
            // No manager's directory: the configuration is a plain file only
            // this product and the network-change feed's links touch.
            None => Ok(NetworkChangeSubscription::inert()),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn subscribe(
        &self,
        _on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        Err(PlatformError::NotSupported {
            reason: "inotify has no implementation on this host",
        })
    }
}

// ── Event parsing (pure; tested on every host) ───────────────────────────────

/// `struct inotify_event` without its name: wd, mask, cookie, len.
const EVENT_HEADER_LEN: usize = 16;
/// The kernel dropped events; something changed, we do not know what.
const IN_Q_OVERFLOW: u32 = 0x4000;

/// One event: the watch it came from, its mask and the entry name.
#[derive(Debug, PartialEq, Eq)]
struct InotifyEvent<'a> {
    wd: i32,
    mask: u32,
    name: &'a str,
}

/// Walk a read buffer. A length running past the buffer ends the walk rather
/// than reading garbage as the next header.
fn events(buffer: &[u8]) -> Vec<InotifyEvent<'_>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + EVENT_HEADER_LEN <= buffer.len() {
        let word = |at: usize| {
            let b = &buffer[offset + at..offset + at + 4];
            [b[0], b[1], b[2], b[3]]
        };
        let wd = i32::from_ne_bytes(word(0));
        let mask = u32::from_ne_bytes(word(4));
        let len = u32::from_ne_bytes(word(12)) as usize;
        let start = offset + EVENT_HEADER_LEN;
        let Some(raw) = buffer.get(start..start + len) else {
            break;
        };
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        out.push(InotifyEvent {
            wd,
            mask,
            name: std::str::from_utf8(&raw[..end]).unwrap_or(""),
        });
        offset = start + len;
    }
    out
}

/// Does any event touch an entry the watch cares about?
fn is_relevant(events: &[InotifyEvent<'_>], filter_of: impl Fn(i32) -> Option<Filter>) -> bool {
    events.iter().any(|e| {
        e.mask & IN_Q_OVERFLOW != 0
            || match filter_of(e.wd) {
                Some(Filter::Any) => true,
                Some(Filter::Named(names)) => names.contains(&e.name),
                None => false,
            }
    })
}

#[derive(Clone, Copy, Debug)]
enum Filter {
    Any,
    Named(&'static [&'static str]),
}

impl From<Option<&'static [&'static str]>> for Filter {
    fn from(names: Option<&'static [&'static str]>) -> Self {
        names.map_or(Self::Any, Self::Named)
    }
}

// ── inotify mechanism (Linux only) ───────────────────────────────────────────

#[cfg(target_os = "linux")]
struct InotifyWatcher {
    wake_writer: libc::c_int,
    reader: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl InotifyWatcher {
    /// `Ok(None)` when none of `dirs` exists.
    fn start(
        dirs: &[WatchedDir],
        on_change: NetworkChangeCallback,
    ) -> Result<Option<Self>, PlatformError> {
        use std::os::unix::ffi::OsStrExt;

        // SAFETY: flags in, a descriptor out.
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(PlatformError::Transient {
                operation: "inotify_init1",
                detail: std::io::Error::last_os_error().to_string(),
            });
        }
        let mask = libc::IN_CLOSE_WRITE
            | libc::IN_MOVED_TO
            | libc::IN_MOVED_FROM
            | libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_ONLYDIR;
        let mut filters: Vec<(i32, Filter)> = Vec::new();
        for dir in dirs {
            let Ok(path) = std::ffi::CString::new(dir.path.as_os_str().as_bytes()) else {
                continue;
            };
            // SAFETY: `path` is NUL-terminated and outlives the call.
            let wd = unsafe { libc::inotify_add_watch(fd, path.as_ptr(), mask) };
            // A directory that is absent belongs to a manager not in use.
            if wd >= 0 {
                filters.push((wd, dir.names.into()));
            }
        }
        if filters.is_empty() {
            close_fd(fd);
            return Ok(None);
        }
        let (wake_reader, wake_writer) = match open_wake_pipe() {
            Ok(pair) => pair,
            Err(e) => {
                close_fd(fd);
                return Err(e);
            }
        };
        let reader = std::thread::Builder::new()
            .name("nrr-dns-config-watch".to_string())
            .spawn(move || {
                read_until_woken(fd, wake_reader, &filters, on_change);
                close_fd(fd);
                close_fd(wake_reader);
            })
            .map_err(|e| {
                close_fd(fd);
                close_fd(wake_reader);
                close_fd(wake_writer);
                PlatformError::Transient {
                    operation: "spawn inotify watch thread",
                    detail: e.to_string(),
                }
            })?;
        Ok(Some(Self {
            wake_writer,
            reader: Some(reader),
        }))
    }
}

#[cfg(target_os = "linux")]
impl Drop for InotifyWatcher {
    fn drop(&mut self) {
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

#[cfg(target_os = "linux")]
fn open_wake_pipe() -> Result<(libc::c_int, libc::c_int), PlatformError> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a live two-element array, which is what `pipe2` writes.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc < 0 {
        return Err(PlatformError::Transient {
            operation: "open inotify wake pipe",
            detail: std::io::Error::last_os_error().to_string(),
        });
    }
    Ok((fds[0], fds[1]))
}

#[cfg(target_os = "linux")]
fn read_until_woken(
    fd: libc::c_int,
    wake_reader: libc::c_int,
    filters: &[(i32, Filter)],
    on_change: NetworkChangeCallback,
) {
    let filter_of = |wd: i32| filters.iter().find(|(w, _)| *w == wd).map(|(_, f)| *f);
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let mut fds = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_reader,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: `fds` is a live two-element array; no timeout.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if rc < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if fds[1].revents != 0 {
            return;
        }
        if fds[0].revents & libc::POLLIN == 0 {
            continue;
        }
        // SAFETY: `buffer` is live and writable for its own length.
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            tracing::warn!(
                target: "nrr::dns-redirect",
                msg_key = "dns-config-watch-stopped",
                error = %error,
                "the DNS settings watch stopped; changes are noticed only by the periodic check",
            );
            return;
        }
        if is_relevant(&events(&buffer[..read as usize]), filter_of) {
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

    fn event(wd: i32, mask: u32, name: &str) -> Vec<u8> {
        // The kernel pads the name with NULs to an aligned length.
        let padded = (name.len() + 1).div_ceil(4) * 4;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&wd.to_ne_bytes());
        bytes.extend_from_slice(&mask.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(&(padded as u32).to_ne_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.resize(bytes.len() + padded - name.len(), 0);
        bytes
    }

    const RESOLV: &[&str] = &["resolv.conf"];

    fn filters(wd: i32) -> Option<Filter> {
        match wd {
            1 => Some(Filter::Named(RESOLV)),
            2 => Some(Filter::Any),
            _ => None,
        }
    }

    #[test]
    fn several_events_in_one_read_are_all_found() {
        let mut buffer = event(1, 0x80, "netif");
        buffer.extend(event(1, 0x80, "resolv.conf"));
        let parsed = events(&buffer);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].name, "resolv.conf");
        assert!(is_relevant(&parsed, filters));
    }

    /// resolved keeps per-link state files beside the one that matters; a
    /// write to those alone is not a configuration change.
    #[test]
    fn an_unwatched_name_in_a_filtered_directory_is_ignored() {
        assert!(!is_relevant(&events(&event(1, 0x80, "netif")), filters));
        assert!(!is_relevant(
            &events(&event(9, 0x80, "resolv.conf")),
            filters
        ));
    }

    #[test]
    fn any_record_of_an_unfiltered_directory_counts() {
        assert!(is_relevant(&events(&event(2, 0x100, "tun0.inet")), filters));
    }

    #[test]
    fn an_overflow_counts_as_a_change() {
        assert!(is_relevant(&events(&event(-1, IN_Q_OVERFLOW, "")), filters));
    }

    #[test]
    fn a_truncated_event_ends_the_walk() {
        let mut buffer = event(1, 0x80, "resolv.conf");
        buffer.truncate(buffer.len() - 2);
        assert!(events(&buffer).is_empty());
        assert!(events(&[0u8; 8]).is_empty());
    }

    #[cfg(target_os = "linux")]
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nrr-dns-watch-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[cfg(target_os = "linux")]
    fn counting() -> (
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        NetworkChangeCallback,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        (
            hits,
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        )
    }

    /// The live half: a file replaced the way the managers do it (write a
    /// temporary, rename over) reaches the callback; a neighbour does not.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_rewritten_resolv_conf_reaches_the_callback() {
        use std::sync::atomic::Ordering;
        use std::time::{Duration, Instant};

        let dir = scratch("rewrite");
        let (hits, callback) = counting();
        let subscription = LinuxDnsConfigChangeObserver::watching(vec![WatchedDir {
            path: dir.clone(),
            names: Some(RESOLV),
        }])
        .subscribe(callback)
        .expect("subscribe");

        std::fs::write(dir.join("netif"), "x").expect("neighbour");
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "a neighbour is not a change"
        );

        std::fs::write(dir.join(".resolv.conf.tmp"), "search corp.example\n").expect("tmp");
        std::fs::rename(dir.join(".resolv.conf.tmp"), dir.join("resolv.conf")).expect("rename");
        let deadline = Instant::now() + Duration::from_secs(2);
        while hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let started = Instant::now();
        drop(subscription);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "retired at once"
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(hits.load(Ordering::SeqCst) > 0, "the rename was reported");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn no_manager_directory_means_an_inert_subscription() {
        let (_hits, callback) = counting();
        LinuxDnsConfigChangeObserver::watching(vec![WatchedDir {
            path: PathBuf::from("/nonexistent/nrr-dns-watch"),
            names: None,
        }])
        .subscribe(callback)
        .expect("nothing to watch is not an error");
    }
}
