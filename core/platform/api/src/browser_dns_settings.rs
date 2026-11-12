//! Browser settings inspection never writes a profile or enterprise policy.

use nrr_shared::browser_dns_settings::{BrowserDnsBrowser, BrowserDnsSettingsDto};

pub trait BrowserDnsSettingsPort: Send + Sync {
    /// Inspect only this authenticated principal's known browser locations.
    fn inspect(&self, principal: &str) -> Vec<BrowserDnsSettingsDto>;
}

pub struct NoopBrowserDnsSettings;

impl BrowserDnsSettingsPort for NoopBrowserDnsSettings {
    fn inspect(&self, _principal: &str) -> Vec<BrowserDnsSettingsDto> {
        [
            BrowserDnsBrowser::Chrome,
            BrowserDnsBrowser::Edge,
            BrowserDnsBrowser::Firefox,
        ]
        .into_iter()
        .map(BrowserDnsSettingsDto::unsupported)
        .collect()
    }
}
