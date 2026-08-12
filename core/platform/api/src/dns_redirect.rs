//! System DNS redirect — the neutral port.
//!
//! Points the OS resolver at NetRuleRouter's loopback DNS listener so rule-host
//! queries transit our resolver (`EnforcementMode::Resolver`), and restores the
//! prior configuration cleanly on stop / crash. This is the genuinely OS-specific
//! half of resolver-mode enforcement — the listener and the rule-host policy are
//! neutral. Per the policy/mechanism seam only the PORT lives here; each backend
//! impls it:
//!
//! - **Windows** — NRPT (Name Resolution Policy Table) via the
//!   `*-DnsClientNrptRule` cmdlets (in `nrr-platform-windows`).
//! - **Linux / macOS** — systemd-resolved / `resolv.conf`, `scutil` (future).

use std::net::SocketAddr;

use crate::error::PlatformError;

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
    /// Report whether our redirect is currently active.
    fn verify(&self, handle: &RedirectHandle) -> Result<RedirectState, PlatformError>;
    /// Flush the OS DNS resolver cache so already-cached names re-query through
    /// our listener the instant the redirect activates (and re-query the real
    /// servers again once it is restored). Best-effort — a failure is not fatal.
    /// Default: no-op (platforms without a flushable client cache). Without this,
    /// a warm cache silently bypasses the resolver on activation.
    fn flush_cache(&self) -> Result<(), PlatformError> {
        Ok(())
    }
}
