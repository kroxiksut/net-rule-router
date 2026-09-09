//! System DNS redirect — the neutral port.
//!
//! Points the OS resolver at NetRuleRouter's loopback DNS listener so rule-host
//! queries transit our resolver (`EnforcementMode::Resolver`), and restores the
//! prior configuration cleanly on stop / crash. This is the genuinely OS-specific
//! half of resolver-mode enforcement — the listener and the rule-host policy are
//! neutral. Per the policy/mechanism seam only the PORT lives here; each backend
//! impls it:
//!
//! - **Windows** — NRPT (Name Resolution Policy Table), a rule written into
//!   the registry in one transaction (in `nrr-platform-windows`).
//! - **Linux / macOS** — systemd-resolved / `resolv.conf`, `scutil` (future).

use std::net::{Ipv4Addr, SocketAddr};

use crate::error::PlatformError;

/// A namespace the product steps out of, and who answers for it instead.
///
/// A catch-all redirect captures names the machine's OTHER resolvers own —
/// a corporate VPN's internal domain being the case that matters. Asking a
/// public resolver for such a name yields "no such name", and the product
/// becomes the reason a working VPN cannot reach its own hosts.
///
/// An exemption says: these names are not ours. The OS resolves them the way
/// it would if the product were not installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsNamespaceExemption {
    /// Lower-cased namespace with no leading or trailing dot.
    pub suffix: String,
    /// Servers that answer for it, in the order the OS listed them.
    pub servers: Vec<Ipv4Addr>,
}

/// Opaque, persistable handle to an active redirect. Persist it so a restart —
/// even after a crash — can `restore` the OS to its prior DNS configuration and
/// never leave it pointed at a dead listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedirectHandle {
    /// Marker identifying our redirect among any others.
    pub marker: String,
    /// The listener the OS was pointed at (for `verify` / diagnostics).
    pub listener: SocketAddr,
}

/// Observed state of our system-DNS redirect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedirectState {
    /// The OS is currently pointed at our listener.
    Active,
    /// No redirect of ours is present.
    Inactive,
}

/// Point the OS resolver at (and restore it from) NetRuleRouter's loopback DNS
/// listener. One implementation per OS; the mechanism is entirely behind this
/// trait so the neutral resolver core never learns about NRPT / resolv.conf.
pub trait SystemDnsRedirectPort: Send + Sync {
    /// Point the OS resolver at `listener`. Idempotent: re-calling replaces any
    /// prior redirect of ours. Returns a handle to persist and later `restore`.
    fn redirect_to(&self, listener: SocketAddr) -> Result<RedirectHandle, PlatformError>;
    /// Undo the redirect identified by `handle`, restoring the prior config.
    /// Idempotent: restoring an already-restored handle succeeds (no-op).
    fn restore(&self, handle: &RedirectHandle) -> Result<(), PlatformError>;
    /// Report whether our redirect is currently active — read from the
    /// configuration the OS is actually using, which can cost a process.
    fn verify(&self, handle: &RedirectHandle) -> Result<RedirectState, PlatformError>;
    /// Cheap self-check of what we CONFIGURED: our redirect is present and
    /// intact, and nothing sits beside it that makes the OS reject the whole
    /// configuration. Meant for a periodic guard, where `verify`'s cost is not.
    /// Default: `Active` (platforms whose redirect cannot be damaged from
    /// outside).
    fn inspect(&self, handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
        let _ = handle;
        Ok(RedirectState::Active)
    }
    /// Flush the OS DNS resolver cache so already-cached names re-query through
    /// our listener the instant the redirect activates (and re-query the real
    /// servers again once it is restored). Best-effort — a failure is not fatal.
    /// Default: no-op (platforms without a flushable client cache). Without this,
    /// a warm cache silently bypasses the resolver on activation.
    fn flush_cache(&self) -> Result<(), PlatformError> {
        Ok(())
    }

    /// Step out of the way for `exemptions`, replacing any previous set.
    ///
    /// Called whenever the machine's connections change, with the CURRENT
    /// full set — an empty slice therefore means "claim everything again",
    /// which is what a disconnected VPN must produce. Returns how many are
    /// in force, so the caller can log a change rather than a state.
    ///
    /// Default: none, and none in force. A platform whose redirect cannot be
    /// narrowed keeps the behaviour it had.
    fn exempt_namespaces(
        &self,
        exemptions: &[DnsNamespaceExemption],
    ) -> Result<usize, PlatformError> {
        let _ = exemptions;
        Ok(0)
    }
}
