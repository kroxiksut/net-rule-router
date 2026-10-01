//! Windows side of [`VmInventoryPort`]: where VirtualBox and VMware keep this
//! user's settings, and whether the host carries their networks.
//!
//! Runs in the user's own launcher and reads only that user's files, so nothing
//! here needs elevation and nothing here crosses a privilege boundary.

#![cfg(target_os = "windows")]

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use nrr_platform_api::vm_inventory::virtualbox::{
    self, COMMAND_LINE_TOOL_BUDGET, COMMAND_LINE_TOOL_STEM, GLOBAL_SETTINGS_FILE,
    TRAFFIC_PROCESS_STEMS,
};
use std::net::Ipv4Addr;

use nrr_platform_api::vm_inventory::vmware::{self, HostNetworks, MachineEntry};
use nrr_platform_api::vm_inventory::{
    Hypervisor, HypervisorInventory, VirtualMachine, VmControlError, VmInventoryPort,
};
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

/// Larger than any settings file VirtualBox writes; a bigger one is not read.
const MAX_SETTINGS_BYTES: u64 = 8 * 1024 * 1024;

/// Where the VirtualBox installer records its directory; writable by
/// administrators only.
const INSTALL_KEY: &str = r"SOFTWARE\Oracle\VirtualBox";

/// How the host-only and bridge adapters VirtualBox installs describe
/// themselves.
const ADAPTER_DESCRIPTION_MARKER: &str = "virtualbox";

/// How the adapters VMware installs for its host-only and NAT networks
/// describe themselves.
const VMWARE_ADAPTER_DESCRIPTION_MARKER: &str = "vmware virtual ethernet adapter";

#[derive(Debug, Default)]
pub struct WindowsVmInventory;

impl WindowsVmInventory {
    pub const fn new() -> Self {
        Self
    }
}

impl VmInventoryPort for WindowsVmInventory {
    fn inventory(&self) -> Vec<HypervisorInventory> {
        let adapters = adapter_descriptions();
        let host_has = |marker: &str| adapters.iter().any(|d| d.contains(marker));
        let mut machines = virtualbox_home()
            .map(|home| machines_in(&home))
            .unwrap_or_default();
        if let Some(tool) = command_line_tool() {
            virtualbox::attach_enable_commands(&mut machines, &tool.to_string_lossy());
        }
        let virtualbox = HypervisorInventory {
            hypervisor: Hypervisor::VirtualBox,
            host_network_seen: host_has(ADAPTER_DESCRIPTION_MARKER),
            traffic_processes: TRAFFIC_PROCESS_STEMS
                .iter()
                .map(|stem| format!("{stem}.exe"))
                .collect(),
            machines,
        };
        let vmware = vmware_inventory(host_has(VMWARE_ADAPTER_DESCRIPTION_MARKER));
        [virtualbox, vmware]
            .into_iter()
            .filter(HypervisorInventory::is_present)
            .collect()
    }

    fn bind_nat(
        &self,
        hypervisor: Hypervisor,
        machine_id: &str,
        slot: u32,
        address: Option<Ipv4Addr>,
    ) -> Result<(), VmControlError> {
        if hypervisor != Hypervisor::VirtualBox {
            return Err(VmControlError::Unsupported);
        }
        let arguments = virtualbox::nat_bind_arguments(machine_id, slot, address)
            .ok_or(VmControlError::InvalidTarget)?;
        let tool = command_line_tool().ok_or(VmControlError::ToolMissing)?;
        run_tool(&tool, &arguments)
    }
}

/// Longest tool message passed on to the user.
const MAX_TOOL_MESSAGE_CHARS: usize = 300;

fn run_tool(tool: &Path, arguments: &[String]) -> Result<(), VmControlError> {
    let output = crate::bounded_command::output_within(
        std::process::Command::new(tool).args(arguments),
        COMMAND_LINE_TOOL_BUDGET,
    )
    .map_err(|error| {
        match error.kind() {
            std::io::ErrorKind::NotFound => VmControlError::ToolMissing,
            // The generic "could not be changed": the tool said nothing.
            std::io::ErrorKind::TimedOut => VmControlError::Failed(String::new()),
            _ => VmControlError::Failed(error.to_string()),
        }
    })?;
    if output.status.success() {
        return Ok(());
    }
    let message = String::from_utf8_lossy(&output.stderr);
    if virtualbox::refused_as_not_mutable(&message) {
        return Err(VmControlError::MachineNotMutable);
    }
    Err(VmControlError::Failed(
        message
            .trim()
            .chars()
            .take(MAX_TOOL_MESSAGE_CHARS)
            .collect(),
    ))
}

/// VirtualBox's own override, else the folder it defaults to. The variable is
/// taken from this user's environment on purpose: it is where this user's
/// VirtualBox looks too.
fn virtualbox_home() -> Option<PathBuf> {
    std::env::var_os("VBOX_USER_HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .or_else(|| crate::system_shell::user_profile_directory().map(|p| p.join(".VirtualBox")))
}

fn command_line_tool() -> Option<PathBuf> {
    let dir = crate::system_info::reg_sz(HKEY_LOCAL_MACHINE, INSTALL_KEY, "InstallDir")?;
    let tool = PathBuf::from(dir.trim()).join(format!("{COMMAND_LINE_TOOL_STEM}.exe"));
    tool.is_file().then_some(tool)
}

fn machines_in(home: &Path) -> Vec<VirtualMachine> {
    let Some(global) = read_settings(&home.join(GLOBAL_SETTINGS_FILE)) else {
        return Vec::new();
    };
    virtualbox::machine_files(&global)
        .into_iter()
        .filter_map(|src| {
            let path = PathBuf::from(src);
            let path = if path.is_absolute() {
                path
            } else {
                home.join(path)
            };
            virtualbox::machine(&read_machine_file(&path)?)
        })
        .collect()
}

/// No traffic processes: VMware's NAT runs as a system service that no
/// application rule binds.
fn vmware_inventory(host_network_seen: bool) -> HypervisorInventory {
    let networks = vmware_host_networks();
    let machines = crate::system_shell::roaming_app_data_directory()
        .map(|appdata| vmware_machines_in(&appdata.join("VMware"), &networks))
        .unwrap_or_default();
    HypervisorInventory {
        hypervisor: Hypervisor::VMware,
        host_network_seen,
        traffic_processes: Vec::new(),
        machines,
    }
}

/// The installer's networks, corrected by the NAT and DHCP services' own
/// configuration where a custom network was added.
fn vmware_host_networks() -> HostNetworks {
    let mut networks = HostNetworks::default();
    if let Some(dir) = crate::system_shell::program_data_directory().map(|d| d.join("VMware")) {
        if let Some(text) = read_settings(&dir.join("vmnetnat.conf")) {
            networks.apply_nat_config(&text);
        }
        if let Some(text) = read_settings(&dir.join("vmnetdhcp.conf")) {
            networks.apply_dhcp_config(&text);
        }
    }
    networks
}

/// Workstation's inventory, then Player's recent list, each machine once.
fn vmware_machines_in(settings: &Path, networks: &HostNetworks) -> Vec<VirtualMachine> {
    let listed = |file: &str, parse: fn(&str) -> Vec<MachineEntry>| {
        read_settings(&settings.join(file))
            .map(|text| parse(&text))
            .unwrap_or_default()
    };
    let mut entries = listed(vmware::INVENTORY_FILE, vmware::inventory_entries);
    entries.extend(listed(vmware::PREFERENCES_FILE, vmware::recent_entries));
    let mut seen = std::collections::HashSet::new();
    entries
        .into_iter()
        .filter(|entry| seen.insert(entry.config.to_lowercase()))
        .filter_map(|entry| {
            let path = Path::new(&entry.config);
            if !path.is_absolute() {
                return None;
            }
            vmware::machine(
                &read_machine_file(path)?,
                &entry.config,
                entry.display_name.as_deref(),
                networks,
            )
        })
        .collect()
}

/// A machine the inventory lists is read only from a drive that answers at
/// once: on a share or an unplugged drive the open can stall for the
/// redirector's timeout, per machine, inside a synchronous request.
fn read_machine_file(path: &Path) -> Option<String> {
    on_local_drive(path).then(|| read_settings(path)).flatten()
}

fn on_local_drive(path: &Path) -> bool {
    use std::path::{Component, Prefix};
    match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => drive_is_local(letter),
            // A share by name, or a device path.
            _ => false,
        },
        _ => false,
    }
}

#[allow(unsafe_code)]
fn drive_is_local(letter: u8) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetDriveTypeW;
    // WinBase.h; a mapped share is DRIVE_REMOTE, a vanished drive DRIVE_NO_ROOT_DIR.
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;
    const DRIVE_RAMDISK: u32 = 6;
    let root: Vec<u16> = format!("{}:\\", char::from(letter))
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `root` is a NUL-terminated UTF-16 string that outlives the call.
    let kind = unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) };
    matches!(kind, DRIVE_REMOVABLE | DRIVE_FIXED | DRIVE_RAMDISK)
}

/// Bounded, and lossy: a `.vmx` from an older release may not be UTF-8, and
/// its names should still show.
fn read_settings(path: &Path) -> Option<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_SETTINGS_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= MAX_SETTINGS_BYTES).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

/// Every adapter's description, lower-cased, from one enumeration.
fn adapter_descriptions() -> Vec<String> {
    ipconfig::get_adapters()
        .map(|adapters| {
            adapters
                .iter()
                .map(|adapter| adapter.description().to_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::vm_inventory::VmAttachment;

    fn write(path: &Path, text: &str) {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).expect("dir");
        }
        std::fs::write(path, text).expect("write");
    }

    fn machine_file(name: &str) -> String {
        format!(
            r#"<VirtualBox xmlns="http://www.virtualbox.org/" version="1.19-windows">
  <Machine uuid="{{00000000-0000-4000-8000-00000000000a}}" name="{name}">
    <Hardware><Network>
      <Adapter slot="0" enabled="true"><NAT localhost-reachable="true"/></Adapter>
    </Network></Hardware>
  </Machine>
</VirtualBox>"#
        )
    }

    #[test]
    fn machines_are_read_from_absolute_and_relative_registry_entries() {
        let home = tempfile::tempdir().expect("home");
        let elsewhere = tempfile::tempdir().expect("elsewhere");
        let absolute = elsewhere.path().join("One").join("One.vbox");
        write(&absolute, &machine_file("One"));
        write(
            &home.path().join("Two").join("Two.vbox"),
            &machine_file("Two"),
        );
        write(
            &home.path().join(GLOBAL_SETTINGS_FILE),
            &format!(
                r#"<VirtualBox xmlns="http://www.virtualbox.org/" version="1.12-windows">
  <Global><MachineRegistry>
    <MachineEntry uuid="{{a}}" src="{}"/>
    <MachineEntry uuid="{{b}}" src="Two\Two.vbox"/>
    <MachineEntry uuid="{{c}}" src="Gone\Gone.vbox"/>
  </MachineRegistry></Global>
</VirtualBox>"#,
                absolute.display()
            ),
        );

        let machines = machines_in(home.path());
        let names: Vec<&str> = machines.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["One", "Two"],
            "a missing machine file is skipped"
        );
        assert!(matches!(
            machines[0].adapters[0].attachment,
            VmAttachment::Nat(_)
        ));
    }

    #[test]
    fn a_machine_on_a_share_is_not_opened() {
        // Positive control: the drive a temp directory lives on is local.
        let local = tempfile::tempdir().expect("dir");
        assert!(on_local_drive(local.path()));
        for remote in [
            r"\\fileserver.example\vms\One\One.vmx",
            r"\\?\UNC\fileserver.example\vms\One\One.vmx",
            r"\\.\PhysicalDrive0",
            r"One\One.vmx",
        ] {
            assert!(!on_local_drive(Path::new(remote)), "{remote}");
        }
    }

    #[test]
    fn a_non_utf8_machine_file_still_reads() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("old.vmx");
        std::fs::write(&path, b"displayName = \"Caf\xe9\"\n").expect("write");
        assert!(read_machine_file(&path).is_some_and(|text| text.starts_with("displayName")));
    }

    #[test]
    fn a_home_without_global_settings_has_no_machines() {
        let home = tempfile::tempdir().expect("home");
        assert!(machines_in(home.path()).is_empty());
    }

    #[test]
    fn an_oversized_settings_file_is_not_read() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("big.xml");
        let file = File::create(&path).expect("create");
        file.set_len(MAX_SETTINGS_BYTES + 1).expect("grow");
        assert!(read_settings(&path).is_none());
    }

    #[test]
    fn the_live_inventory_names_the_traffic_processes_when_present() {
        for hypervisor in WindowsVmInventory::new().inventory() {
            assert!(hypervisor.is_present());
            let expected: Vec<String> = match hypervisor.hypervisor {
                Hypervisor::VirtualBox => vec![
                    "VirtualBoxVM.exe".to_string(),
                    "VBoxHeadless.exe".to_string(),
                ],
                Hypervisor::VMware => Vec::new(),
            };
            assert_eq!(hypervisor.traffic_processes, expected);
        }
    }

    #[test]
    fn vmware_machines_come_from_the_inventory_and_the_recent_list_once_each() {
        let settings = tempfile::tempdir().expect("settings");
        let vms = tempfile::tempdir().expect("vms");
        let vmx = |name: &str, connection: &str| {
            let path = vms.path().join(name).join(format!("{name}.vmx"));
            write(
                &path,
                &format!(
                    "config.version = \"8\"
displayName = \"{name}\"
                     ethernet0.present = \"TRUE\"
ethernet0.connectionType = \"{connection}\"
"
                ),
            );
            path.display().to_string()
        };
        let one = vmx("One", "bridged");
        let two = vmx("Two", "nat");
        let gone = vms
            .path()
            .join("Gone")
            .join("Gone.vmx")
            .display()
            .to_string();
        write(
            &settings.path().join(vmware::INVENTORY_FILE),
            &format!(
                "vmlist1.config = \"{one}\"
vmlist2.config = \"{gone}\"
vmlist3.config = \"Relative\\R.vmx\"
"
            ),
        );
        write(
            &settings.path().join(vmware::PREFERENCES_FILE),
            &format!(
                "pref.mruVM0.filename = \"{}\"
pref.mruVM1.filename = \"{two}\"
",
                one.to_uppercase()
            ),
        );
        let machines = vmware_machines_in(settings.path(), &HostNetworks::default());
        let found: Vec<(&str, &VmAttachment)> = machines
            .iter()
            .map(|m| (m.name.as_str(), &m.adapters[0].attachment))
            .collect();
        assert_eq!(
            found,
            vec![
                ("One", &VmAttachment::Bridged),
                ("Two", &VmAttachment::ServiceNat)
            ]
        );
    }

    /// Prints what this host's hypervisors hold, by mode only.
    #[test]
    #[ignore = "reads the real machine"]
    fn live_inventory_counts() {
        for hypervisor in WindowsVmInventory::new().inventory() {
            let mut modes = std::collections::BTreeMap::<String, usize>::new();
            for adapter in hypervisor.machines.iter().flat_map(|m| &m.adapters) {
                let mode = serde_json::to_value(&adapter.attachment)
                    .ok()
                    .and_then(|v| v["mode"].as_str().map(str::to_string))
                    .unwrap_or_default();
                *modes.entry(mode).or_default() += 1;
            }
            println!(
                "{:?}: network={} machines={} adapters={modes:?}",
                hypervisor.hypervisor,
                hypervisor.host_network_seen,
                hypervisor.machines.len()
            );
        }
    }
}
