//! VirtualBox's settings files, read the way VirtualBox reads them
//! (`src/VBox/Main/xml/Settings.cpp`): the global `VirtualBox.xml` lists the
//! machines, and each machine's own file holds its hardware.

use std::net::Ipv4Addr;

use roxmltree::{Document, Node};

use super::{GuestDnsAdvice, NatAdapter, VirtualMachine, VmAdapter, VmAttachment};

/// The global settings file inside VirtualBox's per-user settings directory.
pub const GLOBAL_SETTINGS_FILE: &str = "VirtualBox.xml";

/// Programs whose sockets carry a NAT guest's traffic: a machine started with a
/// window, and one started headless. File stems; the mechanism adds the OS's
/// executable suffix.
pub const TRAFFIC_PROCESS_STEMS: &[&str] = &["VirtualBoxVM", "VBoxHeadless"];

/// VirtualBox's command-line tool, as a file stem.
pub const COMMAND_LINE_TOOL_STEM: &str = "VBoxManage";

/// The settings version of VirtualBox 7.0, from which a NAT adapter keeps the
/// guest off the host's loopback unless its file says otherwise.
const LOOPBACK_CLOSED_BY_DEFAULT_FROM: (u32, u32) = (1, 19);

/// Machine files the global settings name, as written: absolute, or relative to
/// the settings directory.
#[must_use]
pub fn machine_files(global_settings: &str) -> Vec<String> {
    let Ok(doc) = Document::parse(global_settings) else {
        return Vec::new();
    };
    let root = doc.root_element();
    if !is(root, "VirtualBox") {
        return Vec::new();
    }
    child(root, "Global")
        .and_then(|global| child(global, "MachineRegistry"))
        .map(|registry| {
            registry
                .children()
                .filter(|entry| is(*entry, "MachineEntry"))
                .filter_map(|entry| entry.attribute("src"))
                .map(str::trim)
                .filter(|src| !src.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The machine a machine file describes, with its adapters as they are now.
/// Snapshots carry hardware of their own, and that is not what runs.
#[must_use]
pub fn machine(machine_settings: &str) -> Option<VirtualMachine> {
    let doc = Document::parse(machine_settings).ok()?;
    let root = doc.root_element();
    if !is(root, "VirtualBox") {
        return None;
    }
    let version = settings_version(root.attribute("version").unwrap_or_default());
    let machine = child(root, "Machine")?;
    let name = machine.attribute("name")?.to_string();
    let id = machine
        .attribute("uuid")
        .unwrap_or_default()
        .trim_matches(|c| c == '{' || c == '}')
        .to_string();
    let mut adapters: Vec<VmAdapter> = child(machine, "Hardware")
        .and_then(|hardware| child(hardware, "Network"))
        .map(|network| {
            network
                .children()
                .filter(|node| is(*node, "Adapter"))
                .filter_map(|node| adapter(node, version))
                .collect()
        })
        .unwrap_or_default();
    adapters.sort_by_key(|adapter| adapter.slot);
    Some(VirtualMachine { id, name, adapters })
}

/// Gives every adapter that has to open the host's loopback first the command
/// that does it, run with `tool`. The machine is named by id, which needs no
/// quoting; VirtualBox refuses the change while the machine is running.
pub fn attach_enable_commands(machines: &mut [VirtualMachine], tool: &str) {
    for machine in machines.iter_mut().filter(|m| !m.id.is_empty()) {
        for adapter in &mut machine.adapters {
            if let VmAttachment::Nat(NatAdapter {
                guest_dns: GuestDnsAdvice::EnableHostLoopbackFirst { command, .. },
                ..
            }) = &mut adapter.attachment
            {
                *command = Some(format!(
                    "\"{tool}\" modifyvm {} --nat-localhostreachable{} on",
                    machine.id,
                    adapter.slot + 1
                ));
            }
        }
    }
}

fn adapter(node: Node<'_, '_>, version: (u32, u32)) -> Option<VmAdapter> {
    if !bool_attribute(node, "enabled").unwrap_or(false) {
        return None;
    }
    let slot = node
        .attribute("slot")
        .and_then(|slot| slot.trim().parse().ok())
        .unwrap_or(0);
    // One element names the attachment; `DisabledModes` keeps the settings of
    // the modes the adapter is not in.
    let attachment = node
        .children()
        .find(|mode| mode.is_element() && !is(*mode, "DisabledModes"))
        .map_or(VmAttachment::Other, |mode| attachment(mode, slot, version));
    Some(VmAdapter { slot, attachment })
}

fn attachment(mode: Node<'_, '_>, slot: u32, version: (u32, u32)) -> VmAttachment {
    match mode.tag_name().name() {
        // A network the engine would refuse cannot start, so there is nothing
        // to advise about.
        "NAT" => nat(mode, slot, version).map_or(VmAttachment::Other, VmAttachment::Nat),
        "BridgedInterface" => VmAttachment::Bridged,
        "HostOnlyInterface" | "HostOnlyNetwork" => VmAttachment::HostOnly,
        "InternalNetwork" => VmAttachment::Internal,
        "NATNetwork" => VmAttachment::NatNetwork,
        _ => VmAttachment::Other,
    }
}

fn nat(mode: Node<'_, '_>, slot: u32, version: (u32, u32)) -> Option<NatAdapter> {
    let (network, prefix_len) = match mode.attribute("network").map(str::trim) {
        Some(text) if !text.is_empty() => parse_network(text)?,
        // What the machine hands the engine when its file names no network.
        _ => {
            let third = u8::try_from(slot.checked_add(2)?).ok()?;
            (Ipv4Addr::new(10, 0, third, 0), 24)
        }
    };
    // The engine gives the host the network address with 2 in the host part.
    if prefix_len > 30 {
        return None;
    }
    let host_address = Ipv4Addr::from(u32::from(network) | 2);
    let reachable = bool_attribute(mode, "localhost-reachable")
        .unwrap_or(version < LOOPBACK_CLOSED_BY_DEFAULT_FROM);
    Some(NatAdapter::new(
        format!("{network}/{prefix_len}"),
        host_address,
        reachable,
    ))
}

fn parse_network(text: &str) -> Option<(Ipv4Addr, u8)> {
    let (address, prefix_len) = text.split_once('/')?;
    let address: Ipv4Addr = address.trim().parse().ok()?;
    let prefix_len: u8 = prefix_len.trim().parse().ok()?;
    let mask = match prefix_len {
        0 => 0,
        1..=32 => u32::MAX << (32 - prefix_len),
        _ => return None,
    };
    Some((Ipv4Addr::from(u32::from(address) & mask), prefix_len))
}

/// `"1.19-windows"` → `(1, 19)`. An unreadable version counts as the newest:
/// the default it selects then errs toward telling the user to open the path.
fn settings_version(text: &str) -> (u32, u32) {
    let number = text.split('-').next().unwrap_or_default();
    number
        .split_once('.')
        .and_then(|(major, minor)| Some((major.parse().ok()?, minor.parse().ok()?)))
        .unwrap_or((u32::MAX, u32::MAX))
}

/// VirtualBox's spelling of a boolean; anything else counts as absent.
fn bool_attribute(node: Node<'_, '_>, name: &str) -> Option<bool> {
    match node.attribute(name)? {
        "true" | "yes" | "1" => Some(true),
        "false" | "no" | "0" => Some(false),
        _ => None,
    }
}

fn is(node: Node<'_, '_>, name: &str) -> bool {
    node.is_element() && node.tag_name().name() == name
}

fn child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.children().find(|candidate| is(*candidate, name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_inventory::GuestDnsAdvice;

    fn machine_file(version: &str, adapters: &str) -> String {
        format!(
            r#"<?xml version="1.0"?>
<!-- Written by VirtualBox -->
<VirtualBox xmlns="http://www.virtualbox.org/" version="{version}">
  <Machine uuid="{{00000000-0000-4000-8000-000000000001}}" name="Example VM">
    <Hardware>
      <Network>{adapters}</Network>
    </Hardware>
    <Snapshot uuid="{{00000000-0000-4000-8000-000000000002}}" name="Before">
      <Hardware>
        <Network>
          <Adapter slot="0" enabled="true"><BridgedInterface name="Old"/></Adapter>
        </Network>
      </Hardware>
    </Snapshot>
  </Machine>
</VirtualBox>"#
        )
    }

    fn only_adapter(version: &str, adapter: &str) -> VmAdapter {
        let parsed = machine(&machine_file(version, adapter));
        let adapters = parsed.map(|m| m.adapters).unwrap_or_default();
        assert_eq!(adapters.len(), 1, "{adapters:?}");
        adapters.into_iter().next().unwrap_or(VmAdapter {
            slot: u32::MAX,
            attachment: VmAttachment::Other,
        })
    }

    fn nat_of(adapter: VmAdapter) -> NatAdapter {
        match adapter.attachment {
            VmAttachment::Nat(nat) => nat,
            other => panic!("expected NAT, got {other:?}"),
        }
    }

    #[test]
    fn the_registry_lists_machine_files_as_written() {
        let global = r#"<?xml version="1.0"?>
<VirtualBox xmlns="http://www.virtualbox.org/" version="1.12-windows">
  <Global>
    <MachineRegistry>
      <MachineEntry uuid="{a}" src="D:\VMs\One\One.vbox"/>
      <MachineEntry uuid="{b}" src="Machines/&#x412;&#x41C;/&#x412;&#x41C;.vbox"/>
      <MachineEntry uuid="{c}" src="  "/>
    </MachineRegistry>
  </Global>
</VirtualBox>"#;
        assert_eq!(
            machine_files(global),
            vec![
                r"D:\VMs\One\One.vbox".to_string(),
                "Machines/ВМ/ВМ.vbox".to_string()
            ]
        );
        assert!(machine_files("not xml").is_empty());
        assert!(machine_files("<Other><Global/></Other>").is_empty());
    }

    #[test]
    fn a_nat_adapter_without_a_network_gets_the_one_its_slot_implies() {
        let first = nat_of(only_adapter(
            "1.19-windows",
            r#"<Adapter slot="0" enabled="true"><NAT/></Adapter>"#,
        ));
        assert_eq!(first.network, "10.0.2.0/24");
        assert_eq!(first.host_address, Ipv4Addr::new(10, 0, 2, 2));
        let second = nat_of(only_adapter(
            "1.19-windows",
            r#"<Adapter slot="1" enabled="true"><NAT/></Adapter>"#,
        ));
        assert_eq!(second.host_address, Ipv4Addr::new(10, 0, 3, 2));
    }

    #[test]
    fn a_named_network_is_masked_and_gives_the_host_its_second_address() {
        let nat = nat_of(only_adapter(
            "1.19-windows",
            r#"<Adapter slot="0" enabled="true"><NAT network="192.168.77.9/24"/></Adapter>"#,
        ));
        assert_eq!(nat.network, "192.168.77.0/24");
        assert_eq!(nat.host_address, Ipv4Addr::new(192, 168, 77, 2));
    }

    #[test]
    fn host_loopback_default_follows_the_settings_version() {
        let current = nat_of(only_adapter(
            "1.19-windows",
            r#"<Adapter slot="0" enabled="true"><NAT/></Adapter>"#,
        ));
        assert!(!current.host_loopback_reachable);
        assert_eq!(
            current.guest_dns,
            GuestDnsAdvice::EnableHostLoopbackFirst {
                address: Ipv4Addr::new(10, 0, 2, 2),
                command: None,
            }
        );
        let older = nat_of(only_adapter(
            "1.18-windows",
            r#"<Adapter slot="0" enabled="true"><NAT/></Adapter>"#,
        ));
        assert!(older.host_loopback_reachable);
        let unreadable = nat_of(only_adapter(
            "",
            r#"<Adapter slot="0" enabled="true"><NAT/></Adapter>"#,
        ));
        assert!(!unreadable.host_loopback_reachable);
        let explicit = nat_of(only_adapter(
            "1.19-windows",
            r#"<Adapter slot="0" enabled="true"><NAT localhost-reachable="true"/></Adapter>"#,
        ));
        assert_eq!(
            explicit.guest_dns,
            GuestDnsAdvice::UseHostAddress {
                address: Ipv4Addr::new(10, 0, 2, 2)
            }
        );
    }

    #[test]
    fn the_attachment_is_the_element_outside_disabled_modes() {
        let adapter = only_adapter(
            "1.19-windows",
            r#"<Adapter slot="0" enabled="true">
                 <DisabledModes><NAT localhost-reachable="true"/><NATNetwork name="Shared"/></DisabledModes>
                 <BridgedInterface name="Ethernet"/>
               </Adapter>"#,
        );
        assert_eq!(adapter.attachment, VmAttachment::Bridged);
    }

    #[test]
    fn every_attachment_kind_is_named_and_the_rest_is_other() {
        for (element, expected) in [
            ("<BridgedInterface/>", VmAttachment::Bridged),
            ("<HostOnlyInterface/>", VmAttachment::HostOnly),
            ("<HostOnlyNetwork/>", VmAttachment::HostOnly),
            ("<InternalNetwork/>", VmAttachment::Internal),
            ("<NATNetwork/>", VmAttachment::NatNetwork),
            ("<GenericInterface/>", VmAttachment::Other),
            ("", VmAttachment::Other),
            (r#"<NAT network="10.0.9.0/31"/>"#, VmAttachment::Other),
            (r#"<NAT network="nonsense"/>"#, VmAttachment::Other),
        ] {
            let adapter = only_adapter(
                "1.19-windows",
                &format!(r#"<Adapter slot="0" enabled="true">{element}</Adapter>"#),
            );
            assert_eq!(adapter.attachment, expected, "{element}");
        }
    }

    #[test]
    fn disabled_adapters_are_left_out_and_the_rest_come_in_slot_order() {
        let parsed = machine(&machine_file(
            "1.19-windows",
            r#"<Adapter slot="3" enabled="true"><HostOnlyInterface/></Adapter>
               <Adapter slot="1" enabled="false"><NAT/></Adapter>
               <Adapter slot="2"><NAT/></Adapter>
               <Adapter slot="0" enabled="yes"><NAT/></Adapter>"#,
        ));
        let Some(parsed) = parsed else {
            panic!("machine not read");
        };
        assert_eq!(parsed.name, "Example VM");
        assert_eq!(parsed.id, "00000000-0000-4000-8000-000000000001");
        let slots: Vec<u32> = parsed.adapters.iter().map(|a| a.slot).collect();
        assert_eq!(slots, vec![0, 3]);
    }

    #[test]
    fn the_snapshot_hardware_is_not_read_as_the_machine() {
        let parsed = machine(&machine_file("1.19-windows", ""));
        assert_eq!(parsed.map(|m| m.adapters), Some(Vec::new()));
    }

    #[test]
    fn the_enable_command_names_the_machine_by_id_and_counts_slots_from_one() {
        let Some(mut parsed) = machine(&machine_file(
            "1.19-windows",
            r#"<Adapter slot="1" enabled="true"><NAT/></Adapter>
               <Adapter slot="2" enabled="true"><NAT localhost-reachable="true"/></Adapter>
               <Adapter slot="3" enabled="true"><BridgedInterface/></Adapter>"#,
        )) else {
            panic!("machine not read");
        };
        let tool = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe";
        attach_enable_commands(std::slice::from_mut(&mut parsed), tool);
        let commands: Vec<Option<String>> = parsed
            .adapters
            .iter()
            .map(|adapter| match &adapter.attachment {
                VmAttachment::Nat(NatAdapter {
                    guest_dns: GuestDnsAdvice::EnableHostLoopbackFirst { command, .. },
                    ..
                }) => command.clone(),
                _ => None,
            })
            .collect();
        assert_eq!(
            commands,
            vec![
                Some(format!(
                    "\"{tool}\" modifyvm 00000000-0000-4000-8000-000000000001 --nat-localhostreachable2 on"
                )),
                None,
                None
            ]
        );
    }

    #[test]
    fn files_that_are_not_a_virtualbox_machine_read_as_nothing() {
        assert!(machine("").is_none());
        assert!(machine("<VirtualBox/>").is_none());
        assert!(machine(r#"<Other><Machine name="x"/></Other>"#).is_none());
        assert!(machine(r#"<VirtualBox><Machine uuid="{x}"/></VirtualBox>"#).is_none());
    }
}
