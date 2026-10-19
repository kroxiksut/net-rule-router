//! Linux mechanism behind
//! [`nrr_platform_api::service_set_change::ServiceSetChangeObserver`]: inotify
//! on the directories systemd reads unit files from. An installed or removed
//! package, or an administrator's `systemctl link`, creates or deletes an entry
//! there. The watch is the one the DNS settings use, pointed elsewhere; a
//! directory that does not exist costs nothing.

use std::path::PathBuf;

use nrr_platform_api::dns_config_change::DnsConfigChangeObserver;
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::network_change::{NetworkChangeCallback, NetworkChangeSubscription};
use nrr_platform_api::service_set_change::ServiceSetChangeObserver;

use crate::dns_config_change::{LinuxDnsConfigChangeObserver, WatchedDir};

/// Where systemd looks for unit files, administrator's first.
pub fn unit_dirs() -> Vec<WatchedDir> {
    [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
    ]
    .into_iter()
    .map(|path| WatchedDir {
        path: PathBuf::from(path),
        names: None,
    })
    .collect()
}

/// Production observer over [`unit_dirs`].
#[derive(Clone, Debug)]
pub struct LinuxServiceSetChangeObserver {
    inner: LinuxDnsConfigChangeObserver,
}

impl Default for LinuxServiceSetChangeObserver {
    fn default() -> Self {
        Self {
            inner: LinuxDnsConfigChangeObserver::watching(unit_dirs()),
        }
    }
}

impl ServiceSetChangeObserver for LinuxServiceSetChangeObserver {
    fn subscribe(
        &self,
        on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        self.inner.subscribe(on_change)
    }
}
