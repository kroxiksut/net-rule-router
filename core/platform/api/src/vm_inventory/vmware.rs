//! VMware Workstation's and Player's files: the inventory and the recent list
//! name the machines, each machine's `.vmx` holds its adapters, and the host's
//! network configuration says what a custom virtual network is.
//!
//! All of them are VMware's dictionary format: `key = "value"` lines, keys
//! compared without case, `|XX` escaping a byte inside a value.

use std::collections::{BTreeMap, BTreeSet};

use super::{VirtualMachine, VmAdapter, VmAttachment};

/// The machine list in Workstation's per-user settings directory.
pub const INVENTORY_FILE: &str = "inventory.vmls";

/// Per-user preferences; Player keeps its recent machines only here.
pub const PREFERENCES_FILE: &str = "preferences.ini";

/// Machine files named by one inventory; more are not read.
const MAX_ENTRIES: usize = 1024;

/// Adapters a machine can carry.
const MAX_ADAPTERS: u32 = 64;

/// A machine file a list names, and the name the list shows for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineEntry {
    pub config: String,
    pub display_name: Option<String>,
}

/// Machine files `inventory.vmls` names, in list order. Folders and other
/// non-machine entries are left out.
#[must_use]
pub fn inventory_entries(inventory: &str) -> Vec<MachineEntry> {
    numbered_entries(&dictionary(inventory), "vmlist", "config", "displayname")
}

/// Machine files the recent-machines list in `preferences.ini` names.
#[must_use]
pub fn recent_entries(preferences: &str) -> Vec<MachineEntry> {
    numbered_entries(
        &dictionary(preferences),
        "pref.mruvm",
        "filename",
        "displayname",
    )
}

fn numbered_entries(
    dict: &BTreeMap<String, String>,
    prefix: &str,
    path_key: &str,
    name_key: &str,
) -> Vec<MachineEntry> {
    let mut numbered: Vec<(u32, MachineEntry)> = dict
        .iter()
        .filter_map(|(key, value)| {
            let index = key
                .strip_prefix(prefix)?
                .strip_suffix(path_key)?
                .strip_suffix('.')?
                .parse()
                .ok()?;
            let config = value.trim();
            if !config.to_ascii_lowercase().ends_with(".vmx") {
                return None;
            }
            let display_name = dict
                .get(&format!("{prefix}{index}.{name_key}"))
                .map(|name| name.trim().to_string())
                .filter(|name| !name.is_empty());
            Some((
                index,
                MachineEntry {
                    config: config.to_string(),
                    display_name,
                },
            ))
        })
        .collect();
    numbered.sort_by_key(|(index, _)| *index);
    numbered
        .into_iter()
        .map(|(_, entry)| entry)
        .take(MAX_ENTRIES)
        .collect()
}

/// What one of the host's virtual networks is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VnetKind {
    Bridged,
    HostOnly,
    Nat,
}

impl VnetKind {
    fn attachment(self) -> VmAttachment {
        match self {
            Self::Bridged => VmAttachment::Bridged,
            Self::HostOnly => VmAttachment::HostOnly,
            Self::Nat => VmAttachment::ServiceNat,
        }
    }
}

/// The host's virtual networks by number (`VMnet8` is 8), as the host's
/// configuration describes them. The installer's layout fills in only what no
/// configuration mentions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostNetworks {
    /// Networks a configuration says are, or are not, the NAT network.
    nat: BTreeMap<u32, bool>,
    bridged: BTreeSet<u32>,
    /// Networks with a host-side subnet: host-only unless they are the NAT.
    host_only: BTreeSet<u32>,
}

/// The installer's NAT network.
const DEFAULT_NAT_VNET: u32 = 8;

impl HostNetworks {
    #[must_use]
    pub fn kind(&self, vnet: u32) -> Option<VnetKind> {
        match self.nat.get(&vnet) {
            Some(true) => return Some(VnetKind::Nat),
            // One NAT service: once a configuration names its network, the
            // installer's VMnet8 is not it any more.
            None if vnet == DEFAULT_NAT_VNET && !self.nat.values().any(|nat| *nat) => {
                if !self.bridged.contains(&vnet) {
                    return Some(VnetKind::Nat);
                }
            }
            _ => {}
        }
        if self.bridged.contains(&vnet) {
            Some(VnetKind::Bridged)
        } else if self.host_only.contains(&vnet) {
            Some(VnetKind::HostOnly)
        } else {
            match vnet {
                0 => Some(VnetKind::Bridged),
                1 => Some(VnetKind::HostOnly),
                _ => None,
            }
        }
    }

    /// Reads the NAT service's `vmnetnat.conf`: `device` under `[host]` is the
    /// network it serves.
    pub fn apply_nat_config(&mut self, text: &str) {
        let mut in_host = false;
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                in_host = line.eq_ignore_ascii_case("[host]");
            } else if let Some((key, value)) = in_host.then(|| line.split_once('=')).flatten() {
                if key.trim().eq_ignore_ascii_case("device") {
                    if let Some(vnet) = vnet_number(value) {
                        self.nat.insert(vnet, true);
                    }
                }
            }
        }
    }

    /// Reads the DHCP service's `vmnetdhcp.conf`: a network it serves and the
    /// NAT does not is host-only.
    pub fn apply_dhcp_config(&mut self, text: &str) {
        for line in text.lines().map(str::trim) {
            let Some(rest) = line.strip_prefix("host ") else {
                continue;
            };
            let name = rest.trim_end_matches('{').trim();
            if let Some(vnet) = vnet_number(name) {
                self.host_only.insert(vnet);
            }
        }
    }

    /// Reads the `networking` file VMware keeps on Linux.
    pub fn apply_linux_networking(&mut self, text: &str) {
        for line in text.lines() {
            let words: Vec<&str> = line.split_whitespace().collect();
            match words.as_slice() {
                ["answer", key, value] => {
                    let Some((vnet, setting)) = key
                        .strip_prefix("VNET_")
                        .and_then(|rest| rest.split_once('_'))
                        .and_then(|(n, setting)| Some((n.parse().ok()?, setting)))
                    else {
                        continue;
                    };
                    if setting == "NAT" {
                        self.nat.insert(vnet, value.eq_ignore_ascii_case("yes"));
                    } else if setting == "HOSTONLY_SUBNET" {
                        self.host_only.insert(vnet);
                    }
                }
                ["add_bridge_mapping", _, vnet] => {
                    if let Ok(vnet) = vnet.parse() {
                        self.bridged.insert(vnet);
                    }
                }
                _ => {}
            }
        }
    }
}

/// The machine a `.vmx` describes. `config` is the file's path, from which the
/// id is derived; `listed_name` is what the inventory shows when the file names
/// no machine. `None` when the text is not a machine configuration.
#[must_use]
pub fn machine(
    vmx: &str,
    config: &str,
    listed_name: Option<&str>,
    networks: &HostNetworks,
) -> Option<VirtualMachine> {
    let dict = dictionary(vmx);
    if !dict.contains_key("config.version") && !dict.contains_key("virtualhw.version") {
        return None;
    }
    let name = dict
        .get("displayname")
        .map(|name| name.trim())
        .filter(|name| !name.is_empty())
        .or(listed_name)
        .map_or_else(|| file_stem(config).to_string(), str::to_string);
    let adapters = (0..MAX_ADAPTERS)
        .filter(|slot| is_true(dict.get(&format!("ethernet{slot}.present"))))
        .map(|slot| VmAdapter {
            slot,
            attachment: attachment(&dict, slot, networks),
        })
        .collect();
    Some(VirtualMachine {
        id: machine_id(config),
        name,
        adapters,
    })
}

/// A key for the GUI that neither repeats the path nor collides between two
/// copies of one machine, which share their BIOS UUID.
fn machine_id(config: &str) -> String {
    let hash = config
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        });
    format!("vmx-{hash:016x}")
}

fn attachment(dict: &BTreeMap<String, String>, slot: u32, networks: &HostNetworks) -> VmAttachment {
    let connection = dict
        .get(&format!("ethernet{slot}.connectiontype"))
        .map(|kind| kind.trim().to_ascii_lowercase());
    // VMware bridges an adapter that names no connection type.
    match connection.as_deref().unwrap_or("bridged") {
        "bridged" => VmAttachment::Bridged,
        "hostonly" => VmAttachment::HostOnly,
        "nat" => VmAttachment::ServiceNat,
        // A LAN segment: guests only.
        "pvn" => VmAttachment::Internal,
        "custom" => dict
            .get(&format!("ethernet{slot}.vnet"))
            .and_then(|vnet| vnet_number(vnet))
            .and_then(|vnet| networks.kind(vnet))
            .map_or(VmAttachment::Other, VnetKind::attachment),
        _ => VmAttachment::Other,
    }
}

/// `VMnet8`, `vmnet8` and `/dev/vmnet8` are network 8.
fn vnet_number(text: &str) -> Option<u32> {
    let lower = text.trim().to_ascii_lowercase();
    let at = lower.rfind("vmnet")?;
    lower[at + "vmnet".len()..].parse().ok()
}

fn file_stem(path: &str) -> &str {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    name.rsplit_once('.').map_or(name, |(stem, _)| stem)
}

fn is_true(value: Option<&String>) -> bool {
    value.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "yes" | "1"
        )
    })
}

/// Keys lowercased, values unquoted and unescaped; a repeated key keeps its
/// last value.
fn dictionary(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            let key = key.trim().to_ascii_lowercase();
            if key.is_empty() {
                return None;
            }
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            Some((key, unescape(value)))
        })
        .collect()
}

fn unescape(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = (bytes[i] == b'|')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match escaped {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vmx(adapters: &str) -> String {
        format!(
            ".encoding = \"UTF-8\"\nconfig.version = \"8\"\nvirtualHW.version = \"21\"\n\
             displayName = \"Example VM\"\nuuid.bios = \"56 4d 00 00 00 00 00 01-00 00 00 00 00 00 00 02\"\n{adapters}"
        )
    }

    fn modes(adapters: &str, networks: &HostNetworks) -> Vec<(u32, VmAttachment)> {
        machine(
            &vmx(adapters),
            r"D:\VMs\Example\Example.vmx",
            None,
            networks,
        )
        .map(|m| m.adapters)
        .unwrap_or_default()
        .into_iter()
        .map(|a| (a.slot, a.attachment))
        .collect()
    }

    #[test]
    fn the_inventory_lists_machines_in_order_and_skips_folders() {
        let inventory = "\
.encoding = \"UTF-8\"\r
vmlist2.config = \"D:\\VMs\\Two\\Two.vmx\"\r
vmlist2.DisplayName = \"Two\"\r
vmlist1.config = \"folder0\"\r
vmlist1.Type = \"2\"\r
vmlist10.config = \"/home/user/vms/Ten/Ten.VMX\"\r
vmlist3.config = \"\"\r
index.count = \"0\"\r
";
        assert_eq!(
            inventory_entries(inventory),
            vec![
                MachineEntry {
                    config: r"D:\VMs\Two\Two.vmx".to_string(),
                    display_name: Some("Two".to_string()),
                },
                MachineEntry {
                    config: "/home/user/vms/Ten/Ten.VMX".to_string(),
                    display_name: None,
                },
            ]
        );
    }

    #[test]
    fn the_recent_list_is_read_from_the_preferences() {
        let preferences = "pref.mruVM0.filename = \"C:\\VMs\\One\\One.vmx\"\n\
                           pref.mruVM0.displayName = \"One\"\n\
                           pref.ws.session.window0.tab0.file = \"C:\\VMs\\Other.vmx\"\n";
        assert_eq!(
            recent_entries(preferences),
            vec![MachineEntry {
                config: r"C:\VMs\One\One.vmx".to_string(),
                display_name: Some("One".to_string()),
            }]
        );
    }

    #[test]
    fn each_connection_type_reads_as_what_it_does_for_routing() {
        let adapters = "\
ethernet0.present = \"TRUE\"\nethernet0.connectionType = \"nat\"\n\
ethernet1.present = \"TRUE\"\nethernet1.connectionType = \"bridged\"\n\
ethernet2.present = \"TRUE\"\nethernet2.connectionType = \"hostonly\"\n\
ethernet3.present = \"TRUE\"\nethernet3.connectionType = \"pvn\"\n\
ethernet4.present = \"TRUE\"\n\
ethernet5.present = \"TRUE\"\nethernet5.connectionType = \"custom\"\nethernet5.vnet = \"VMnet8\"\n\
ethernet6.present = \"TRUE\"\nethernet6.connectionType = \"custom\"\nethernet6.vnet = \"VMnet5\"\n\
ethernet7.present = \"FALSE\"\nethernet7.connectionType = \"bridged\"\n\
ethernet8.connectionType = \"bridged\"\n\
ethernet9.present = \"TRUE\"\nethernet9.connectionType = \"null\"\n";
        assert_eq!(
            modes(adapters, &HostNetworks::default()),
            vec![
                (0, VmAttachment::ServiceNat),
                (1, VmAttachment::Bridged),
                (2, VmAttachment::HostOnly),
                (3, VmAttachment::Internal),
                (4, VmAttachment::Bridged),
                (5, VmAttachment::ServiceNat),
                (6, VmAttachment::Other),
                (9, VmAttachment::Other),
            ]
        );
    }

    #[test]
    fn a_custom_network_is_read_from_the_host_configuration() {
        let mut networks = HostNetworks::default();
        networks.apply_nat_config(
            "[host]\nip = 192.0.2.0/24\ndevice = vmnet3\n[dns]\ndevice = vmnet4\n",
        );
        networks.apply_dhcp_config(
            "subnet 198.51.100.0 netmask 255.255.255.0 {\n}\nhost VMnet2 {\n}\nhost VMnet3 {\n}\n",
        );
        assert_eq!(networks.kind(3), Some(VnetKind::Nat));
        assert_eq!(networks.kind(2), Some(VnetKind::HostOnly));
        assert_eq!(networks.kind(4), None);
        assert_eq!(
            modes(
                "ethernet0.present = \"TRUE\"\nethernet0.connectionType = \"custom\"\nethernet0.vnet = \"vmnet3\"\n",
                &networks
            ),
            vec![(0, VmAttachment::ServiceNat)]
        );
    }

    #[test]
    fn the_linux_networking_file_names_nat_host_only_and_bridges() {
        let mut networks = HostNetworks::default();
        networks.apply_linux_networking(
            "VERSION=1,0\n\
             answer VNET_1_HOSTONLY_SUBNET 192.0.2.0\n\
             answer VNET_8_HOSTONLY_SUBNET 198.51.100.0\n\
             answer VNET_8_NAT yes\n\
             answer VNET_4_HOSTONLY_SUBNET 203.0.113.0\n\
             add_bridge_mapping eth0 0\n\
             add_bridge_mapping eth1 2\n",
        );
        assert_eq!(networks.kind(8), Some(VnetKind::Nat));
        assert_eq!(networks.kind(4), Some(VnetKind::HostOnly));
        assert_eq!(networks.kind(2), Some(VnetKind::Bridged));
        assert_eq!(networks.kind(0), Some(VnetKind::Bridged));
        assert_eq!(vnet_number("/dev/vmnet2"), Some(2));
    }

    #[test]
    fn nat_moved_to_another_network_leaves_vmnet8_host_only() {
        let dhcp = "host VMnet1 {\n}\nhost VMnet3 {\n}\nhost VMnet8 {\n}\n";
        let mut moved = HostNetworks::default();
        moved.apply_nat_config("[host]\ndevice = vmnet3\n");
        moved.apply_dhcp_config(dhcp);
        assert_eq!(moved.kind(3), Some(VnetKind::Nat));
        assert_eq!(moved.kind(8), Some(VnetKind::HostOnly));

        // Without a readable NAT configuration, VMnet8's DHCP says nothing
        // against the installer's layout.
        let mut installer = HostNetworks::default();
        installer.apply_dhcp_config(dhcp);
        assert_eq!(installer.kind(8), Some(VnetKind::Nat));
        assert_eq!(installer.kind(3), Some(VnetKind::HostOnly));
    }

    #[test]
    fn the_linux_networking_file_can_turn_nat_off() {
        let mut networks = HostNetworks::default();
        networks.apply_linux_networking(
            "answer VNET_8_HOSTONLY_SUBNET 198.51.100.0\nanswer VNET_8_NAT no\n",
        );
        assert_eq!(networks.kind(8), Some(VnetKind::HostOnly));
        let mut bridged = HostNetworks::default();
        bridged.apply_linux_networking("add_bridge_mapping eth0 8\n");
        assert_eq!(bridged.kind(8), Some(VnetKind::Bridged));
    }

    #[test]
    fn the_name_falls_back_to_the_list_then_to_the_file() {
        let bare = "config.version = \"8\"\n";
        let networks = HostNetworks::default();
        let listed = machine(bare, r"D:\VMs\Stem\Stem.vmx", Some("Listed"), &networks);
        assert_eq!(listed.map(|m| m.name), Some("Listed".to_string()));
        let unlisted = machine(bare, "/vms/Stem Name/Stem Name.vmx", None, &networks);
        assert_eq!(unlisted.map(|m| m.name), Some("Stem Name".to_string()));
        let named = machine(&vmx(""), "a.vmx", Some("Listed"), &networks);
        assert_eq!(named.map(|m| m.name), Some("Example VM".to_string()));
    }

    #[test]
    fn values_are_unescaped_and_keys_compared_without_case() {
        let text = "config.version = \"8\"\nDISPLAYNAME = \"A |22quoted|22 |D0|92|D0|9C\"\n";
        let parsed = machine(text, "a.vmx", None, &HostNetworks::default());
        assert_eq!(parsed.map(|m| m.name), Some("A \"quoted\" ВМ".to_string()));
    }

    #[test]
    fn the_id_is_stable_per_file_and_hides_the_path() {
        let networks = HostNetworks::default();
        let id = |path: &str| machine(&vmx(""), path, None, &networks).map(|m| m.id);
        let one = id(r"D:\VMs\One\One.vmx");
        assert_eq!(one, id(r"D:\VMs\One\One.vmx"));
        assert_ne!(one, id(r"D:\VMs\Copy\One.vmx"));
        let one = one.unwrap_or_default();
        assert!(one.starts_with("vmx-") && !one.contains("VMs"), "{one}");
    }

    #[test]
    fn text_that_is_not_a_machine_reads_as_nothing() {
        let networks = HostNetworks::default();
        assert!(machine("", "a.vmx", None, &networks).is_none());
        assert!(machine("displayName = \"x\"\n", "a.vmx", None, &networks).is_none());
        assert!(machine("<xml/>", "a.vmx", None, &networks).is_none());
    }
}
