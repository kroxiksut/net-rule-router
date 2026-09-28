//! Is the process serving the service pipe the service itself?
//!
//! The service detects a squatted pipe name at startup, but by then a client
//! may already be talking to the squatter. The client closes that gap by
//! comparing the pipe server's process id with the one the service manager
//! reports, before it sends anything.

/// Why the pipe server is not the service, or `None` when it is.
///
/// `service` is the service manager's answer: its process id, `None` when it
/// has no process, or the error code when it could not be asked. A dev build
/// accepts a server with no managed service behind it, which is how a service
/// started from a console runs.
pub(crate) fn impostor_reason(
    server_pid: u32,
    service: Result<Option<u32>, u32>,
    dev_build: bool,
) -> Option<String> {
    match service {
        Ok(Some(pid)) if pid == server_pid => None,
        Ok(Some(pid)) => Some(format!(
            "the service pipe is served by process {server_pid}, but the service is process {pid}"
        )),
        Ok(None) | Err(_) if dev_build => None,
        Ok(None) => Some(format!(
            "the service pipe is served by process {server_pid} while the service is not running"
        )),
        Err(code) => Some(format!(
            "could not ask the service manager who owns the service pipe (Win32 0x{code:08X})"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_service_itself_is_accepted() {
        assert_eq!(impostor_reason(42, Ok(Some(42)), false), None);
    }

    #[test]
    fn another_process_is_refused_even_in_a_dev_build() {
        assert!(impostor_reason(7, Ok(Some(42)), false).is_some());
        assert!(impostor_reason(7, Ok(Some(42)), true).is_some());
    }

    #[test]
    fn a_server_with_no_running_service_is_refused_outside_dev_builds() {
        assert!(impostor_reason(7, Ok(None), false).is_some());
        assert_eq!(impostor_reason(7, Ok(None), true), None);
    }

    #[test]
    fn an_unanswerable_service_manager_fails_closed_outside_dev_builds() {
        assert!(impostor_reason(7, Err(5), false).is_some());
        assert_eq!(impostor_reason(7, Err(5), true), None);
    }
}
