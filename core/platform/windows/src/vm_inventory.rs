//! Windows side of [`VmInventoryPort`]: where VirtualBox keeps this user's
//! settings, and whether the host carries VirtualBox's network.
//!
//! Runs in the user's own launcher and reads only that user's files, so nothing
//! here needs elevation and nothing here crosses a privilege boundary.

#![cfg(target_os = "windows")]

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use nrr_platform_api::vm_inventory::virtualbox::{
    self, COMMAND_LINE_TOOL_STEM, GLOBAL_SETTINGS_FILE, TRAFFIC_PROCESS_STEMS,
};
use nrr_platform_api::vm_inventory::{
    Hypervisor, HypervisorInventory, VirtualMachine, VmInventoryPort,
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

#[derive(Debug, Default)]
pub struct WindowsVmInventory;

impl WindowsVmInventory {
    pub const fn new() -> Self {
        Self
    }
}

impl VmInventoryPort for WindowsVmInventory {
    fn inventory(&self) -> Vec<HypervisorInventory> {
        let mut machines = virtualbox_home()
            .map(|home| machines_in(&home))
            .unwrap_or_default();
        if let Some(tool) = command_line_tool() {
            virtualbox::attach_enable_commands(&mut machines, &tool.to_string_lossy());
        }
        let virtualbox = HypervisorInventory {
            hypervisor: Hypervisor::VirtualBox,
            host_network_seen: host_has_virtualbox_adapter(),
            traffic_processes: TRAFFIC_PROCESS_STEMS
                .iter()
                .map(|stem| format!("{stem}.exe"))
                .collect(),
            machines,
        };
        virtualbox
            .is_present()
            .then_some(virtualbox)
            .into_iter()
            .collect()
    }
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
            virtualbox::machine(&read_settings(&path)?)
        })
        .collect()
}

fn read_settings(path: &Path) -> Option<String> {
    let mut text = String::new();
    File::open(path)
        .ok()?
        .take(MAX_SETTINGS_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() as u64 <= MAX_SETTINGS_BYTES).then_some(text)
}

fn host_has_virtualbox_adapter() -> bool {
    ipconfig::get_adapters()
        .map(|adapters| {
            adapters.iter().any(|adapter| {
                adapter
                    .description()
                    .to_lowercase()
                    .contains(ADAPTER_DESCRIPTION_MARKER)
            })
        })
        .unwrap_or(false)
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
            assert_eq!(
                hypervisor.traffic_processes,
                vec![
                    "VirtualBoxVM.exe".to_string(),
                    "VBoxHeadless.exe".to_string()
                ]
            );
        }
    }
}
