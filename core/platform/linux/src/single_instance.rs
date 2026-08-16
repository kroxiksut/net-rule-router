//! Linux mechanism behind the single-instance port: a bound abstract socket.
//!
//! An abstract-namespace socket lives in the kernel, not the filesystem: no
//! file to delete, no directory to clean, and the name is released the moment
//! the owning process dies — including a kill -9. `flock` on a file would be
//! the more obvious choice and is the wrong one here, because deleting the file
//! (exactly the incident this port exists for) lets the next process create a
//! new one and lock that instead.
//!
//! The name is scoped per user: the abstract namespace is machine-wide, so two
//! users' sessions would otherwise fight over one claim.

#![cfg(target_os = "linux")]

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener};

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::single_instance::{SingleInstanceClaim, SingleInstancePort};

/// Binds `\0netrulerouter.<uid>.<key>`.
#[derive(Debug, Default)]
pub struct LinuxSingleInstance;

impl SingleInstancePort for LinuxSingleInstance {
    fn claim(&self, key: &str) -> Result<Option<Box<dyn SingleInstanceClaim>>, PlatformError> {
        let name = format!("netrulerouter.{}.{key}", current_uid());
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).map_err(|e| {
            PlatformError::Transient {
                operation: "single-instance abstract name",
                detail: format!("{name}: {e}"),
            }
        })?;
        match UnixListener::bind_addr(&addr) {
            Ok(listener) => Ok(Some(Box::new(SocketClaim {
                _listener: listener,
            }))),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Ok(None),
            Err(e) => Err(PlatformError::Transient {
                operation: "single-instance bind",
                detail: format!("{name}: {e}"),
            }),
        }
    }
}

/// Holding the listener IS the claim: the abstract name stays taken for exactly
/// as long as this socket is open, and the kernel frees it when the process
/// dies. Nothing ever reads the field — dropping it is the whole behaviour.
struct SocketClaim {
    _listener: UnixListener,
}

impl SingleInstanceClaim for SocketClaim {}

#[allow(unsafe_code)]
fn current_uid() -> u32 {
    // SAFETY: `getuid` takes no arguments, cannot fail, and touches no memory.
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_claim_of_the_same_key_is_refused_while_the_first_is_held() {
        let port = LinuxSingleInstance;
        let key = format!("test-{}-{}", std::process::id(), line!());
        let first = port.claim(&key).expect("claim succeeds");
        assert!(first.is_some(), "an unclaimed key must be claimable");
        let second = port.claim(&key).expect("claim succeeds");
        assert!(second.is_none(), "a held key must refuse a second claim");
        drop(first);
        let third = port.claim(&key).expect("claim succeeds");
        assert!(third.is_some(), "releasing the claim must free the key");
    }
}
