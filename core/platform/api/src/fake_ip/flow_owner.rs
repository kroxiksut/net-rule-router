//! Fake-IP — the neutral "who owns this flow" contract (VPN self-heal).
//!
//! When the fake-IP relay accepts a TCP flow it knows the four-tuple (the
//! client's own local endpoint and the fake destination) and the hostname the
//! fake address stands for, but not WHICH process opened the socket. That last
//! fact is the one genuinely OS-specific piece needed to notice that a VPN
//! client is talking to its own server through the relay — an extra hop that
//! also hides the VPN's real remote address from the user.
//!
//! Per the policy/mechanism seam this trait is the mechanism half: an
//! implementation reads the OS connection table and returns the owning
//! process's image name. The POLICY (is that image a VPN client? →
//! [`crate::vpn_discovery::looks_like_vpn`]) and the reaction (exclude the
//! hostname from fake-IP, flush DNS) stay neutral in `service-runtime`.
//!
//! The lookup is best-effort by construction: the socket may already be gone,
//! the caller may lack the rights to read another process's image path, or the
//! platform may have no such table. Every failure returns `None` and the relay
//! simply keeps serving the flow — self-heal is an optimisation, never a
//! correctness dependency.

use std::net::SocketAddr;
use std::sync::Mutex;

/// Resolve the process that owns the local end of a TCP connection.
pub trait FlowOwnerLookup: Send + Sync {
    /// The image name (lower-cased file basename, e.g. `"wireguard.exe"`) of the
    /// process that owns the TCP socket whose local endpoint is `local` and
    /// whose remote endpoint is `remote`, or `None` when it cannot be
    /// determined. Must not block for more than a moment — callers may invoke it
    /// off the hot path, but it should never hang.
    fn owner_image_name(&self, local: SocketAddr, remote: SocketAddr) -> Option<String>;
}

/// The default lookup: never resolves an owner. Used on platforms with no
/// connection-table mechanism wired and as the inert default so the relay works
/// unchanged when self-heal is not configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopFlowOwnerLookup;

impl FlowOwnerLookup for NoopFlowOwnerLookup {
    fn owner_image_name(&self, _local: SocketAddr, _remote: SocketAddr) -> Option<String> {
        None
    }
}

/// Test double: answers from a fixed `(local, remote) -> image name` table and
/// counts how many lookups it served, so a test can prove the relay consulted
/// it exactly when expected.
#[derive(Debug, Default)]
pub struct MockFlowOwnerLookup {
    inner: Mutex<MockInner>,
}

#[derive(Debug, Default)]
struct MockInner {
    entries: Vec<(SocketAddr, SocketAddr, String)>,
    calls: u32,
}

impl MockFlowOwnerLookup {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the owner reported for one `(local, remote)` pair.
    pub fn set_owner(&self, local: SocketAddr, remote: SocketAddr, image: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.entries.push((local, remote, image.to_string()));
    }

    /// Number of `owner_image_name` calls served so far.
    #[must_use]
    pub fn call_count(&self) -> u32 {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).calls
    }
}

impl FlowOwnerLookup for MockFlowOwnerLookup {
    fn owner_image_name(&self, local: SocketAddr, remote: SocketAddr) -> Option<String> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.calls += 1;
        inner
            .entries
            .iter()
            .find(|(l, r, _)| *l == local && *r == remote)
            .map(|(_, _, image)| image.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("addr")
    }

    #[test]
    fn noop_never_resolves() {
        let noop = NoopFlowOwnerLookup;
        assert_eq!(
            noop.owner_image_name(addr("10.0.0.2:51000"), addr("198.18.0.7:443")),
            None
        );
    }

    #[test]
    fn mock_answers_registered_pairs_and_counts_calls() {
        let mock = MockFlowOwnerLookup::new();
        let local = addr("10.0.0.2:51000");
        let remote = addr("198.18.0.7:443");
        mock.set_owner(local, remote, "wireguard.exe");
        assert_eq!(
            mock.owner_image_name(local, remote).as_deref(),
            Some("wireguard.exe")
        );
        // An unregistered pair resolves to None.
        assert_eq!(mock.owner_image_name(addr("10.0.0.2:51001"), remote), None);
        assert_eq!(mock.call_count(), 2);
    }
}
