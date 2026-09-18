//! Linux side of [`VmInventoryPort`] (stub).
//!
//! The settings format is already read by the neutral
//! [`nrr_platform_api::vm_inventory::virtualbox`]. What remains is Linux's half:
//! VirtualBox's per-user directory (`$VBOX_USER_HOME`, else
//! `~/.config/VirtualBox`), its host adapters (`vboxnet*`), and the traffic
//! processes without the `.exe` suffix — together with confirming on a real
//! host that the NAT maps its host alias onto the loopback the same way.

use nrr_platform_api::vm_inventory::{HypervisorInventory, VmInventoryPort};

#[derive(Debug, Default)]
pub struct LinuxVmInventory;

impl LinuxVmInventory {
    pub const fn new() -> Self {
        Self
    }
}

impl VmInventoryPort for LinuxVmInventory {
    fn inventory(&self) -> Vec<HypervisorInventory> {
        // TODO: read ~/.config/VirtualBox and the vboxnet adapters once the NAT
        // host alias is verified to reach the loopback resolver on Linux.
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_is_constructible_and_empty() {
        assert!(LinuxVmInventory::new().inventory().is_empty());
    }
}
