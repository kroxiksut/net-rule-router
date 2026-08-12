//! The Linux TUN mechanism seam for fake-IP.
//!
//! The interesting fact about fake-IP on Linux is what is NOT here: no
//! third-party driver, no vendored binary, no signature to verify. Linux has a
//! usermode TUN interface in the kernel (`/dev/net/tun`, `IFF_TUN | IFF_NO_PI`),
//! so the adapter is opened directly. That is why the driver problem — and the
//! Wintun attribution obligations that come with it — is Windows-only, and why
//! [`nrr_platform_api::third_party::NoopThirdPartyIntegrity`] is the right
//! answer here: there is no third-party binary to report on.
//!
//! The real mechanism (open `/dev/net/tun`, `TUNSETIFF`, address + MTU via
//! rtnetlink) needs a Linux host with `CAP_NET_ADMIN` to build and verify
//! against, exactly like the nftables/rtnetlink enforcement ports. Until then
//! [`LinuxTunAdapter`] reports itself unavailable and fails closed, so a Linux
//! build links and runs with fake-IP simply switched off rather than
//! half-working.

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::fake_ip::tun::{TunAdapterConfig, TunAdapterPort, TunDevice};

/// Character device the real implementation will open.
pub const TUN_CLONE_DEVICE: &str = "/dev/net/tun";

/// Linux fake-IP adapter over the kernel's native TUN interface.
#[derive(Debug, Clone, Default)]
pub struct LinuxTunAdapter;

impl LinuxTunAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Whether the kernel exposes the TUN clone device at all. Present on any
    /// ordinary Linux host; absent in containers without `/dev/net/tun` mapped,
    /// which is exactly when the feature must not be offered.
    #[must_use]
    pub fn tun_device_present() -> bool {
        std::path::Path::new(TUN_CLONE_DEVICE).exists()
    }
}

impl TunAdapterPort for LinuxTunAdapter {
    fn is_available(&self) -> bool {
        // Stub: the device may exist, but nothing can open it yet. Reporting
        // `false` keeps the GUI honest instead of offering a feature that would
        // fail at activation.
        false
    }

    fn open(&self, config: &TunAdapterConfig) -> Result<Box<dyn TunDevice>, PlatformError> {
        config.validate()?;
        Err(PlatformError::NotYetImplemented {
            block: "Block D slice 2 (Linux) — /dev/net/tun TUNSETIFF + rtnetlink",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_reports_unavailable_and_refuses_to_open() {
        let adapter = LinuxTunAdapter::new();
        assert!(!adapter.is_available());
        assert!(matches!(
            adapter.open(&TunAdapterConfig::default()),
            Err(PlatformError::NotYetImplemented { .. })
        ));
    }

    #[test]
    fn an_invalid_configuration_is_rejected_before_the_stub_error() {
        let adapter = LinuxTunAdapter::new();
        let bad = TunAdapterConfig {
            mtu: 1,
            ..TunAdapterConfig::default()
        };
        assert!(matches!(
            adapter.open(&bad),
            Err(PlatformError::NotSupported { .. })
        ));
    }
}
