//! The virtual machines a hypervisor keeps for this user, and what each network
//! adapter means for routing.
//!
//! A guest behind the hypervisor's own NAT leaves the host as sockets of the
//! hypervisor process, so an application rule routes it. Its names are another
//! matter: the guest asks the host's DNS servers directly, and site rules never
//! see them. The only way in is the guest asking through the NAT's alias for the
//! host, which reaches our resolver only where the hypervisor maps that alias
//! onto the host's loopback. The alias differs per adapter, so it is derived from
//! each machine's configuration and never assumed.
//!
//! Neutral here: the model, the advice, and the reader of VirtualBox's settings
//! format, which is the same XML on every OS. Where those files live and which
//! adapters the host carries is the per-OS mechanism behind [`VmInventoryPort`].

pub mod virtualbox;

use std::net::Ipv4Addr;

use serde::Serialize;

/// A hypervisor whose machines this edition reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Hypervisor {
    #[serde(rename = "virtualbox")]
    VirtualBox,
}

/// One hypervisor's view of this machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HypervisorInventory {
    pub hypervisor: Hypervisor,
    /// The host carries one of this hypervisor's virtual network adapters.
    pub host_network_seen: bool,
    /// File names of the processes whose sockets carry NAT guests' traffic —
    /// what an application rule has to name. Every machine of the hypervisor
    /// runs as one of these, so no rule can tell two machines apart.
    pub traffic_processes: Vec<String>,
    pub machines: Vec<VirtualMachine>,
}

impl HypervisorInventory {
    /// Whether the hypervisor is worth showing: its network is on the host, or
    /// it keeps at least one machine.
    #[must_use]
    pub fn is_present(&self) -> bool {
        self.host_network_seen || !self.machines.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VirtualMachine {
    pub id: String,
    pub name: String,
    /// Enabled adapters only, in slot order.
    pub adapters: Vec<VmAdapter>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VmAdapter {
    /// Zero-based, as the hypervisor stores it; its own UI counts from one.
    pub slot: u32,
    pub attachment: VmAttachment,
}

/// How an adapter is attached, reduced to what differs for routing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum VmAttachment {
    /// The hypervisor's own NAT: traffic is the hypervisor process's sockets.
    Nat(NatAdapter),
    /// Frames go to the physical network past the host's IP stack, so no rule
    /// sees them.
    Bridged,
    /// Stays between the guest and the host.
    HostOnly,
    /// Stays between guests.
    Internal,
    /// A shared NAT service with its own engine, not read yet.
    NatNetwork,
    /// Not attached, or a kind this edition does not interpret.
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NatAdapter {
    /// The NAT's own network, `a.b.c.d/len`.
    pub network: String,
    /// The address the host has inside that network.
    pub host_address: Ipv4Addr,
    /// Whether the guest reaching `host_address` lands on the host's loopback.
    pub host_loopback_reachable: bool,
    pub guest_dns: GuestDnsAdvice,
}

impl NatAdapter {
    #[must_use]
    pub fn new(network: String, host_address: Ipv4Addr, host_loopback_reachable: bool) -> Self {
        let guest_dns = if host_loopback_reachable {
            GuestDnsAdvice::UseHostAddress {
                address: host_address,
            }
        } else {
            GuestDnsAdvice::EnableHostLoopbackFirst {
                address: host_address,
                command: None,
            }
        };
        Self {
            network,
            host_address,
            host_loopback_reachable,
            guest_dns,
        }
    }
}

/// What to tell the user so that site rules apply inside a NAT guest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum GuestDnsAdvice {
    /// Set the guest's DNS server to `address`.
    UseHostAddress { address: Ipv4Addr },
    /// Let the adapter reach the host's loopback, then set the guest's DNS
    /// server to `address`. Without the first step the queries go nowhere.
    /// `command` does the first step when the hypervisor's tool was found.
    EnableHostLoopbackFirst {
        address: Ipv4Addr,
        command: Option<String>,
    },
}

/// The hypervisors this machine has and their virtual machines. Never an error:
/// an unreadable settings file contributes nothing. Runs as the user whose
/// machines they are.
pub trait VmInventoryPort: Send + Sync {
    fn inventory(&self) -> Vec<HypervisorInventory>;
}

/// Off-platform default: nothing found.
#[derive(Debug, Default)]
pub struct NoopVmInventory;

impl VmInventoryPort for NoopVmInventory {
    fn inventory(&self) -> Vec<HypervisorInventory> {
        Vec::new()
    }
}

/// Test double returning a fixed inventory.
#[derive(Debug, Default, Clone)]
pub struct MockVmInventory {
    inventory: Vec<HypervisorInventory>,
}

impl MockVmInventory {
    #[must_use]
    pub fn new(inventory: Vec<HypervisorInventory>) -> Self {
        Self { inventory }
    }
}

impl VmInventoryPort for MockVmInventory {
    fn inventory(&self) -> Vec<HypervisorInventory> {
        self.inventory.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn nat(reachable: bool) -> VmAdapter {
        VmAdapter {
            slot: 1,
            attachment: VmAttachment::Nat(NatAdapter::new(
                "10.0.3.0/24".to_string(),
                Ipv4Addr::new(10, 0, 3, 2),
                reachable,
            )),
        }
    }

    #[test]
    fn advice_depends_only_on_whether_the_host_loopback_is_reachable() {
        let VmAttachment::Nat(open) = nat(true).attachment else {
            unreachable!()
        };
        assert_eq!(
            open.guest_dns,
            GuestDnsAdvice::UseHostAddress {
                address: Ipv4Addr::new(10, 0, 3, 2)
            }
        );
        let VmAttachment::Nat(closed) = nat(false).attachment else {
            unreachable!()
        };
        assert_eq!(
            closed.guest_dns,
            GuestDnsAdvice::EnableHostLoopbackFirst {
                address: Ipv4Addr::new(10, 0, 3, 2),
                command: None,
            }
        );
    }

    /// The GUI reads exactly these names; a renamed field silently empties the
    /// virtual machines screen.
    #[test]
    fn wire_shape_is_what_the_virtual_machines_screen_reads() {
        let inventory = HypervisorInventory {
            hypervisor: Hypervisor::VirtualBox,
            host_network_seen: true,
            traffic_processes: vec!["Guest.exe".to_string()],
            machines: vec![VirtualMachine {
                id: "id-1".to_string(),
                name: "Example".to_string(),
                adapters: vec![
                    nat(false),
                    VmAdapter {
                        slot: 2,
                        attachment: VmAttachment::Bridged,
                    },
                ],
            }],
        };
        let wire = serde_json::to_value(&inventory).unwrap_or_default();
        assert_eq!(
            wire,
            json!({
                "hypervisor": "virtualbox",
                "hostNetworkSeen": true,
                "trafficProcesses": ["Guest.exe"],
                "machines": [{
                    "id": "id-1",
                    "name": "Example",
                    "adapters": [
                        {
                            "slot": 1,
                            "attachment": {
                                "mode": "nat",
                                "network": "10.0.3.0/24",
                                "hostAddress": "10.0.3.2",
                                "hostLoopbackReachable": false,
                                "guestDns": {
                                    "kind": "enable-host-loopback-first",
                                    "address": "10.0.3.2",
                                    "command": null
                                }
                            }
                        },
                        { "slot": 2, "attachment": { "mode": "bridged" } }
                    ]
                }]
            })
        );
        for mode in [
            (VmAttachment::HostOnly, "host-only"),
            (VmAttachment::Internal, "internal"),
            (VmAttachment::NatNetwork, "nat-network"),
            (VmAttachment::Other, "other"),
        ] {
            assert_eq!(
                serde_json::to_value(&mode.0).unwrap_or_default(),
                json!({ "mode": mode.1 })
            );
        }
        assert_eq!(
            serde_json::to_value(GuestDnsAdvice::UseHostAddress {
                address: Ipv4Addr::new(10, 0, 2, 2)
            })
            .unwrap_or_default(),
            json!({ "kind": "use-host-address", "address": "10.0.2.2" })
        );
    }

    #[test]
    fn a_hypervisor_is_present_by_its_network_or_by_a_machine() {
        let mut inventory = HypervisorInventory {
            hypervisor: Hypervisor::VirtualBox,
            host_network_seen: false,
            traffic_processes: Vec::new(),
            machines: Vec::new(),
        };
        assert!(!inventory.is_present());
        inventory.host_network_seen = true;
        assert!(inventory.is_present());
        inventory.host_network_seen = false;
        inventory.machines.push(VirtualMachine {
            id: "id".to_string(),
            name: "Example".to_string(),
            adapters: Vec::new(),
        });
        assert!(inventory.is_present());
    }

    #[test]
    fn noop_finds_nothing_and_mock_returns_what_it_was_given() {
        assert!(NoopVmInventory.inventory().is_empty());
        let inventory = vec![HypervisorInventory {
            hypervisor: Hypervisor::VirtualBox,
            host_network_seen: true,
            traffic_processes: Vec::new(),
            machines: Vec::new(),
        }];
        assert_eq!(
            MockVmInventory::new(inventory.clone()).inventory(),
            inventory
        );
    }
}
