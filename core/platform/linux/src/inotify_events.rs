//! The records an inotify descriptor reads back (`struct inotify_event`),
//! walked without the kernel, and the descriptor plumbing every inotify watch
//! here shares.
//!
//! The names inside are whatever any user who can write into a watched
//! directory chose to call a file, so the walk is bounded, never panics and
//! has a fuzz target.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

/// `struct inotify_event` without its name: wd, mask, cookie, len.
pub(crate) const EVENT_HEADER_LEN: usize = 16;
/// The kernel dropped events; something changed, we do not know what.
pub(crate) const IN_Q_OVERFLOW: u32 = 0x4000;
/// The event's subject is a directory.
pub(crate) const IN_ISDIR: u32 = 0x4000_0000;
/// Events read from one buffer; the rest is ignored.
pub(crate) const MAX_EVENTS: usize = 4096;

/// One event: the watch it came from, its mask and the entry name.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InotifyEvent<'a> {
    pub(crate) wd: i32,
    pub(crate) mask: u32,
    pub(crate) name: &'a str,
}

/// Walk a read buffer. A length running past the buffer ends the walk rather
/// than reading garbage as the next header.
pub(crate) fn events(buffer: &[u8]) -> Vec<InotifyEvent<'_>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while out.len() < MAX_EVENTS {
        let Some(start) = offset.checked_add(EVENT_HEADER_LEN) else {
            break;
        };
        let Some(header) = buffer.get(offset..start) else {
            break;
        };
        let wd = i32::from_ne_bytes(word(header, 0));
        let mask = u32::from_ne_bytes(word(header, 4));
        let len = u32::from_ne_bytes(word(header, 12)) as usize;
        let Some(raw) = start
            .checked_add(len)
            .and_then(|end| buffer.get(start..end))
        else {
            break;
        };
        let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        out.push(InotifyEvent {
            wd,
            mask,
            name: std::str::from_utf8(raw.get(..end).unwrap_or_default()).unwrap_or(""),
        });
        offset = start + len;
    }
    out
}

fn word(header: &[u8], at: usize) -> [u8; 4] {
    header
        .get(at..at + 4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .unwrap_or([0; 4])
}

/// The walk the fuzz targets reach, with the folder watch's verdict on it.
#[cfg(feature = "fuzzing")]
pub fn fuzz_events(buffer: &[u8]) -> (usize, bool) {
    let parsed = events(buffer);
    (
        parsed.len(),
        crate::app_folders::events_may_change_programs(&parsed),
    )
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub(crate) mod fd {
    use nrr_platform_api::error::PlatformError;

    /// A pipe whose write end retires a watch thread parked in `poll`.
    pub(crate) fn open_wake_pipe() -> Result<(libc::c_int, libc::c_int), PlatformError> {
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

    /// Wake the thread parked on the read end of `wake_writer`'s pipe.
    pub(crate) fn wake(wake_writer: libc::c_int) {
        let byte = 1u8;
        // SAFETY: `wake_writer` is owned by the caller and still open; the
        // buffer is live for the call.
        unsafe {
            libc::write(
                wake_writer,
                std::ptr::addr_of!(byte).cast::<libc::c_void>(),
                1,
            );
        }
    }

    pub(crate) fn close_fd(fd: libc::c_int) {
        // SAFETY: every caller passes a descriptor it owns and does not reuse.
        unsafe {
            libc::close(fd);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn event(wd: i32, mask: u32, name: &str) -> Vec<u8> {
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

    #[test]
    fn several_events_in_one_read_are_all_found() {
        let mut buffer = event(1, 0x100, "app-2");
        buffer.extend(event(2, 0x100 | IN_ISDIR, "bin"));
        let parsed = events(&buffer);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].name, "bin");
        assert_eq!(parsed[1].mask & IN_ISDIR, IN_ISDIR);
    }

    #[test]
    fn a_truncated_or_lying_event_ends_the_walk() {
        let mut buffer = event(1, 0x100, "tool");
        buffer.truncate(buffer.len() - 2);
        assert!(events(&buffer).is_empty());
        assert!(events(&[0u8; 8]).is_empty());
        let mut lying = event(1, 0x100, "tool");
        lying[12..16].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(events(&lying).is_empty());
    }

    #[test]
    fn a_name_that_is_not_text_reads_as_empty() {
        let mut buffer = event(1, 0x100, "ab");
        buffer[16] = 0xff;
        assert_eq!(events(&buffer)[0].name, "");
    }

    #[test]
    fn a_hostile_buffer_never_panics_and_stays_bounded() {
        let mut buffer = Vec::new();
        for i in 0..80u8 {
            buffer.push(i.wrapping_mul(53));
            let _ = events(&buffer);
        }
        let empty_names: Vec<u8> = (0..MAX_EVENTS + 10)
            .flat_map(|_| {
                let mut header = vec![0u8; EVENT_HEADER_LEN];
                header[4] = 1;
                header
            })
            .collect();
        assert_eq!(events(&empty_names).len(), MAX_EVENTS);
    }
}
