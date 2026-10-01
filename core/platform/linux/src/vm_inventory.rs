//! Linux side of [`VmInventoryPort`]: where VirtualBox and VMware keep this
//! user's machines, whether the host carries their networks, and pinning a
//! VirtualBox NAT adapter through VirtualBox's own command-line tool.
//!
//! Runs in the user's own launcher and touches only that user's machines, so
//! nothing here needs elevation.

use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Output;

use nrr_platform_api::vm_inventory::virtualbox::{
    self, COMMAND_LINE_TOOL_BUDGET, GLOBAL_SETTINGS_FILE, TRAFFIC_PROCESS_STEMS,
};
use nrr_platform_api::vm_inventory::vmware::{self, HostNetworks, MachineEntry};
use nrr_platform_api::vm_inventory::{
    Hypervisor, HypervisorInventory, VirtualMachine, VmControlError, VmInventoryPort,
};

/// Larger than any settings file VirtualBox writes; a bigger one is not read.
const MAX_SETTINGS_BYTES: u64 = 8 * 1024 * 1024;

/// Where distribution and Oracle packages install the tool. Fixed paths only:
/// a `$PATH` lookup would run whatever this user's `PATH` names first.
const COMMAND_LINE_TOOL_PATHS: &[&str] = &["/usr/bin/VBoxManage", "/usr/lib/virtualbox/VBoxManage"];

/// Host-only adapters VirtualBox creates on Linux are named `vboxnetN`.
const VIRTUALBOX_ADAPTER_PREFIX: &str = "vboxnet";

/// VMware's host-only and NAT networks appear as `vmnetN`.
const VMWARE_ADAPTER_PREFIX: &str = "vmnet";

/// VMware's per-user preferences on Linux; unlike Windows, no `.ini` suffix.
const VMWARE_PREFERENCES_FILE: &str = "preferences";

/// Enough of the tool's message to say what went wrong.
const MAX_FAILURE_CHARS: usize = 300;

/// File systems whose open blocks while the server is unreachable: a machine
/// on a dead hard mount would stall discovery inside a synchronous request.
const NETWORK_FILE_SYSTEMS: &[&str] = &[
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "smbfs",
    "ncpfs",
    "9p",
    "afs",
    "ceph",
    "glusterfs",
    "lustre",
    "davfs",
    "fuse.sshfs",
    "fuse.rclone",
    "fuse.s3fs",
    "fuse.gvfsd-fuse",
    "fuse.glusterfs",
    "fuse.ceph-fuse",
];

/// Where the inventory looks; injectable so tests read temp dirs.
#[derive(Debug, Clone)]
pub struct VmInventoryRoots {
    pub virtualbox_home: Option<PathBuf>,
    /// `~/.vmware`: the inventory and the preferences.
    pub vmware_settings: Option<PathBuf>,
    /// `/etc/vmware/networking`: the host's custom virtual networks.
    pub vmware_networking: PathBuf,
    pub sys_class_net: PathBuf,
    pub tool_candidates: Vec<PathBuf>,
    /// `/proc/self/mountinfo`: which file system each machine file sits on.
    pub mount_table: PathBuf,
}

#[derive(Debug, Clone)]
pub struct LinuxVmInventory {
    roots: VmInventoryRoots,
}

impl Default for LinuxVmInventory {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxVmInventory {
    /// This user's settings directories and the real system locations.
    #[must_use]
    pub fn new() -> Self {
        Self::with_roots(VmInventoryRoots {
            virtualbox_home: virtualbox_home(),
            vmware_settings: absolute_env("HOME").map(|home| home.join(".vmware")),
            vmware_networking: PathBuf::from("/etc/vmware/networking"),
            sys_class_net: PathBuf::from("/sys/class/net"),
            tool_candidates: COMMAND_LINE_TOOL_PATHS.iter().map(PathBuf::from).collect(),
            mount_table: PathBuf::from("/proc/self/mountinfo"),
        })
    }

    #[must_use]
    pub fn with_roots(roots: VmInventoryRoots) -> Self {
        Self { roots }
    }

    fn command_line_tool(&self) -> Option<&Path> {
        self.roots
            .tool_candidates
            .iter()
            .map(PathBuf::as_path)
            .find(|tool| tool.is_file())
    }

    /// Every interface name, from one listing.
    fn adapter_names(&self) -> Vec<String> {
        std::fs::read_dir(&self.roots.sys_class_net)
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn virtualbox_inventory(
        &self,
        host_network_seen: bool,
        mounts: &MountTable,
    ) -> HypervisorInventory {
        // TODO: confirm on a Linux host that a NAT guest asking the host alias
        // reaches the loopback resolver; the advice assumes it does, as on Windows.
        let mut machines = self
            .roots
            .virtualbox_home
            .as_deref()
            .map(|home| machines_in(home, mounts))
            .unwrap_or_default();
        if let Some(tool) = self.command_line_tool() {
            virtualbox::attach_enable_commands(&mut machines, &tool.to_string_lossy());
        }
        HypervisorInventory {
            hypervisor: Hypervisor::VirtualBox,
            host_network_seen,
            // Linux executables carry no suffix; application rules name the
            // bare file name.
            traffic_processes: TRAFFIC_PROCESS_STEMS
                .iter()
                .map(|stem| (*stem).to_string())
                .collect(),
            machines,
        }
    }

    /// No traffic processes: VMware's NAT runs as a system daemon that no
    /// application rule binds.
    fn vmware_inventory(
        &self,
        host_network_seen: bool,
        mounts: &MountTable,
    ) -> HypervisorInventory {
        let mut networks = HostNetworks::default();
        if let Some(text) = read_settings(&self.roots.vmware_networking) {
            networks.apply_linux_networking(&text);
        }
        let machines = self
            .roots
            .vmware_settings
            .as_deref()
            .map(|settings| vmware_machines_in(settings, &networks, mounts))
            .unwrap_or_default();
        HypervisorInventory {
            hypervisor: Hypervisor::VMware,
            host_network_seen,
            traffic_processes: Vec::new(),
            machines,
        }
    }
}

impl VmInventoryPort for LinuxVmInventory {
    fn inventory(&self) -> Vec<HypervisorInventory> {
        let adapters = self.adapter_names();
        let host_has = |prefix: &str| adapters.iter().any(|name| name.starts_with(prefix));
        let mounts = MountTable::read(&self.roots.mount_table);
        [
            self.virtualbox_inventory(host_has(VIRTUALBOX_ADAPTER_PREFIX), &mounts),
            self.vmware_inventory(host_has(VMWARE_ADAPTER_PREFIX), &mounts),
        ]
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
        let tool = self
            .command_line_tool()
            .ok_or(VmControlError::ToolMissing)?;
        let tool = tool.to_str().ok_or(VmControlError::ToolMissing)?;
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let output =
            crate::command::output_with_timeout(tool, &arguments, COMMAND_LINE_TOOL_BUDGET)
                .map_err(|error| match error.kind() {
                    std::io::ErrorKind::NotFound => VmControlError::ToolMissing,
                    // The generic "could not be changed": the tool said nothing.
                    std::io::ErrorKind::TimedOut => VmControlError::Failed(String::new()),
                    _ => VmControlError::Failed(error.to_string()),
                })?;
        tool_outcome(&output)
    }
}

fn tool_outcome(output: &Output) -> Result<(), VmControlError> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if virtualbox::refused_as_not_mutable(&stderr) {
        return Err(VmControlError::MachineNotMutable);
    }
    let message = stderr.trim();
    let message = if message.is_empty() {
        output.status.to_string()
    } else {
        message.chars().take(MAX_FAILURE_CHARS).collect()
    };
    Err(VmControlError::Failed(message))
}

/// VirtualBox's own lookup: `$VBOX_USER_HOME`, then a legacy `~/.VirtualBox`
/// that already exists, then `$XDG_CONFIG_HOME/VirtualBox` or
/// `~/.config/VirtualBox`. Relative values are ignored.
fn virtualbox_home() -> Option<PathBuf> {
    if let Some(home) = absolute_env("VBOX_USER_HOME") {
        return Some(home);
    }
    let user_home = absolute_env("HOME");
    if let Some(legacy) = user_home.as_ref().map(|h| h.join(".VirtualBox")) {
        if legacy.is_dir() {
            return Some(legacy);
        }
    }
    absolute_env("XDG_CONFIG_HOME")
        .or_else(|| user_home.map(|h| h.join(".config")))
        .map(|config| config.join("VirtualBox"))
}

fn absolute_env(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

fn machines_in(home: &Path, mounts: &MountTable) -> Vec<VirtualMachine> {
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
            virtualbox::machine(&read_machine_file(&path, mounts)?)
        })
        .collect()
}

/// Workstation's inventory, then the recent list, each machine once. Paths
/// are compared exactly: Linux file names are case-sensitive.
fn vmware_machines_in(
    settings: &Path,
    networks: &HostNetworks,
    mounts: &MountTable,
) -> Vec<VirtualMachine> {
    let listed = |file: &str, parse: fn(&str) -> Vec<MachineEntry>| {
        read_settings(&settings.join(file))
            .map(|text| parse(&text))
            .unwrap_or_default()
    };
    let mut entries = listed(vmware::INVENTORY_FILE, vmware::inventory_entries);
    entries.extend(listed(VMWARE_PREFERENCES_FILE, vmware::recent_entries));
    let mut seen = std::collections::HashSet::new();
    entries
        .into_iter()
        .filter(|entry| Path::new(&entry.config).is_absolute())
        .filter(|entry| seen.insert(entry.config.clone()))
        .filter_map(|entry| {
            vmware::machine(
                &read_machine_file(Path::new(&entry.config), mounts)?,
                &entry.config,
                entry.display_name.as_deref(),
                networks,
            )
        })
        .collect()
}

/// A machine the inventory lists is read only from a local file system.
fn read_machine_file(path: &Path, mounts: &MountTable) -> Option<String> {
    (!mounts.is_network(path))
        .then(|| read_settings(path))
        .flatten()
}

/// Mount points and their file-system types, from `mountinfo`.
#[derive(Debug, Default)]
struct MountTable {
    mounts: Vec<(PathBuf, String)>,
}

impl MountTable {
    /// An unreadable table marks nothing as remote.
    fn read(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .map(|text| Self::parse(&text))
            .unwrap_or_default()
    }

    /// `ID PARENT MAJ:MIN ROOT MOUNT-POINT OPTIONS [TAGS…] - FSTYPE SOURCE …`
    fn parse(text: &str) -> Self {
        let mounts = text
            .lines()
            .filter_map(|line| {
                let (head, tail) = line.split_once(" - ")?;
                let mount_point = head.split(' ').nth(4)?;
                let fs_type = tail.split(' ').next()?;
                Some((
                    PathBuf::from(unescape_mount_field(mount_point)),
                    fs_type.to_string(),
                ))
            })
            .collect();
        Self { mounts }
    }

    /// Lexical on purpose: asking the file system itself (`statfs`, a
    /// canonicalising lookup) blocks on a dead hard mount just like the open.
    /// The deepest mount point wins; among equals the later mount, which is
    /// the one on top.
    fn is_network(&self, path: &Path) -> bool {
        self.mounts
            .iter()
            .filter(|(point, _)| path.starts_with(point))
            .max_by_key(|(point, _)| point.components().count())
            .is_some_and(|(_, fs_type)| NETWORK_FILE_SYSTEMS.contains(&fs_type.as_str()))
    }
}

/// `mountinfo` writes space, tab, newline and backslash as `\ooo`.
fn unescape_mount_field(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = (bytes[i] == b'\\')
            .then(|| bytes.get(i + 1..i + 4))
            .flatten()
            .filter(|digits| digits.iter().all(|d| (b'0'..=b'7').contains(d)))
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .and_then(|digits| u8::from_str_radix(digits, 8).ok());
        match escaped {
            Some(byte) => {
                out.push(byte);
                i += 4;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::vm_inventory::{GuestDnsAdvice, VmAttachment};

    const MACHINE_ID: &str = "00000000-0000-4000-8000-00000000000a";

    fn write(path: &Path, text: &str) {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).expect("dir");
        }
        std::fs::write(path, text).expect("write");
    }

    /// VirtualBox roots only; VMware finds nothing.
    fn at(
        virtualbox_home: Option<PathBuf>,
        sys_class_net: PathBuf,
        tool_candidates: Vec<PathBuf>,
    ) -> LinuxVmInventory {
        LinuxVmInventory::with_roots(VmInventoryRoots {
            virtualbox_home,
            vmware_settings: None,
            vmware_networking: sys_class_net.join("no-networking"),
            mount_table: sys_class_net.join("no-mountinfo"),
            sys_class_net,
            tool_candidates,
        })
    }

    fn vmx(dir: &Path, name: &str, connection: &str, vnet: Option<&str>) -> String {
        let path = dir.join(name).join(format!("{name}.vmx"));
        let vnet = vnet
            .map(|v| format!("ethernet0.vnet = \"{v}\"\n"))
            .unwrap_or_default();
        write(
            &path,
            &format!(
                "config.version = \"8\"\ndisplayName = \"{name}\"\nethernet0.present = \"TRUE\"\nethernet0.connectionType = \"{connection}\"\n{vnet}"
            ),
        );
        path.display().to_string()
    }

    #[test]
    fn vmware_machines_come_from_the_inventory_and_the_recent_list_once_each() {
        let root = tempfile::tempdir().expect("root");
        let settings = root.path().join("vmware");
        let vms = root.path().join("vms");
        let one = vmx(&vms, "One", "bridged", None);
        let two = vmx(&vms, "Two", "nat", None);
        let gone = vms.join("Gone").join("Gone.vmx").display().to_string();
        write(
            &settings.join(vmware::INVENTORY_FILE),
            &format!(
                "vmlist1.config = \"{one}\"\nvmlist2.config = \"{gone}\"\nvmlist3.config = \"Relative/R.vmx\"\n"
            ),
        );
        write(
            &settings.join(VMWARE_PREFERENCES_FILE),
            &format!("pref.mruVM0.filename = \"{one}\"\npref.mruVM1.filename = \"{two}\"\n"),
        );
        let machines =
            vmware_machines_in(&settings, &HostNetworks::default(), &MountTable::default());
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

    #[test]
    fn vmware_is_present_with_the_linux_networking_file_applied() {
        let root = tempfile::tempdir().expect("root");
        let settings = root.path().join("vmware");
        let custom = vmx(&root.path().join("vms"), "Custom", "custom", Some("vmnet3"));
        write(
            &settings.join(vmware::INVENTORY_FILE),
            &format!("vmlist1.config = \"{custom}\"\n"),
        );
        let networking = root.path().join("networking");
        write(&networking, "answer VNET_3_NAT yes\n");
        let net = root.path().join("net");
        std::fs::create_dir_all(net.join("vmnet8")).expect("adapter");

        let inventory = LinuxVmInventory::with_roots(VmInventoryRoots {
            virtualbox_home: None,
            vmware_settings: Some(settings),
            vmware_networking: networking,
            mount_table: root.path().join("no-mountinfo"),
            sys_class_net: net,
            tool_candidates: Vec::new(),
        })
        .inventory();
        assert_eq!(inventory.len(), 1);
        let vmware = &inventory[0];
        assert_eq!(vmware.hypervisor, Hypervisor::VMware);
        assert!(vmware.host_network_seen);
        assert!(vmware.traffic_processes.is_empty());
        assert_eq!(
            vmware.machines[0].adapters[0].attachment,
            VmAttachment::ServiceNat
        );
        assert_eq!(
            at(None, root.path().join("no-net"), Vec::new()).bind_nat(
                Hypervisor::VMware,
                MACHINE_ID,
                0,
                None
            ),
            Err(VmControlError::Unsupported)
        );
    }

    fn machine_file(name: &str) -> String {
        format!(
            r#"<VirtualBox xmlns="http://www.virtualbox.org/" version="1.19-linux">
  <Machine uuid="{{{MACHINE_ID}}}" name="{name}">
    <Hardware><Network>
      <Adapter slot="0" enabled="true"><NAT/></Adapter>
    </Network></Hardware>
  </Machine>
</VirtualBox>"#
        )
    }

    fn home_with_machines(home: &Path, elsewhere: &Path) {
        let absolute = elsewhere.join("One").join("One.vbox");
        write(&absolute, &machine_file("One"));
        write(&home.join("Two").join("Two.vbox"), &machine_file("Two"));
        write(
            &home.join(GLOBAL_SETTINGS_FILE),
            &format!(
                r#"<VirtualBox xmlns="http://www.virtualbox.org/" version="1.12-linux">
  <Global><MachineRegistry>
    <MachineEntry uuid="{{a}}" src="{}"/>
    <MachineEntry uuid="{{b}}" src="Two/Two.vbox"/>
    <MachineEntry uuid="{{c}}" src="Gone/Gone.vbox"/>
  </MachineRegistry></Global>
</VirtualBox>"#,
                absolute.display()
            ),
        );
    }

    #[test]
    fn machines_are_read_from_absolute_and_relative_registry_entries() {
        let home = tempfile::tempdir().expect("home");
        let elsewhere = tempfile::tempdir().expect("elsewhere");
        home_with_machines(home.path(), elsewhere.path());

        let machines = machines_in(home.path(), &MountTable::default());
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

    /// One `mountinfo` line, the mount point escaped as the kernel writes it.
    fn mountinfo_line(id: u32, point: &Path, fs_type: &str) -> String {
        let point = point
            .to_string_lossy()
            .replace('\\', "\\134")
            .replace(' ', "\\040");
        format!("{id} 1 0:{id} / {point} rw,relatime shared:{id} - {fs_type} source rw\n")
    }

    #[test]
    fn a_machine_on_a_network_mount_is_not_opened() {
        let home = tempfile::tempdir().expect("home");
        let elsewhere = tempfile::tempdir().expect("elsewhere");
        home_with_machines(home.path(), elsewhere.path());
        let table = |fs_type: &str| {
            MountTable::parse(&format!(
                "{}{}",
                mountinfo_line(1, Path::new("/"), "ext4"),
                mountinfo_line(2, elsewhere.path(), fs_type)
            ))
        };
        let names = |mounts: &MountTable| -> Vec<String> {
            machines_in(home.path(), mounts)
                .into_iter()
                .map(|m| m.name)
                .collect()
        };
        // Positive control: the same machine on a local file system is read.
        assert_eq!(names(&table("ext4")), vec!["One", "Two"]);
        assert_eq!(names(&table("nfs4")), vec!["Two"]);
        assert_eq!(names(&table("fuse.sshfs")), vec!["Two"]);
    }

    #[test]
    fn the_deepest_and_latest_mount_decides() {
        let mounts = MountTable::parse(concat!(
            "20 1 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "21 20 0:50 / /srv/vms rw - nfs server.example:/vms rw\n",
            "22 21 8:2 / /srv/vms/local rw - xfs /dev/sda2 rw\n",
            "23 20 0:51 / /mnt/share rw - ext4 /dev/sdb1 rw\n",
            "24 23 0:52 / /mnt/share rw - cifs //server.example/share rw\n",
            "25 20 0:53 / /mnt/my\\040vms rw shared:5 master:2 - smb3 //server.example/vms rw\n",
            "not a mountinfo line\n",
        ));
        assert!(!mounts.is_network(Path::new("/home/user/VirtualBox VMs/One/One.vbox")));
        assert!(mounts.is_network(Path::new("/srv/vms/One/One.vbox")));
        assert!(!mounts.is_network(Path::new("/srv/vms/local/One/One.vbox")));
        assert!(
            !mounts.is_network(Path::new("/srv/vmsx/One.vbox")),
            "whole components only"
        );
        assert!(
            mounts.is_network(Path::new("/mnt/share/One.vmx")),
            "the mount on top"
        );
        assert!(mounts.is_network(Path::new("/mnt/my vms/One.vmx")));
        assert!(!MountTable::default().is_network(Path::new("/srv/vms/One.vbox")));
    }

    #[test]
    fn inventory_names_bare_traffic_processes_and_the_found_tool() {
        let root = tempfile::tempdir().expect("root");
        let home = root.path().join("vbox");
        home_with_machines(&home, root.path());
        let net = root.path().join("net");
        std::fs::create_dir_all(&net).expect("net");
        let tool = root.path().join("bin").join("VBoxManage");
        write(&tool, "");

        let inventory = at(
            Some(home),
            net,
            vec![root.path().join("absent"), tool.clone()],
        )
        .inventory();
        assert_eq!(inventory.len(), 1);
        let vbox = &inventory[0];
        assert!(!vbox.host_network_seen);
        assert_eq!(
            vbox.traffic_processes,
            vec!["VirtualBoxVM".to_string(), "VBoxHeadless".to_string()]
        );
        let VmAttachment::Nat(nat) = &vbox.machines[0].adapters[0].attachment else {
            panic!("NAT adapter expected");
        };
        let GuestDnsAdvice::EnableHostLoopbackFirst {
            command: Some(command),
            ..
        } = &nat.guest_dns
        else {
            panic!("a closed loopback gets the enabling command");
        };
        assert!(command.contains(&*tool.to_string_lossy()));
    }

    #[test]
    fn a_host_adapter_alone_makes_virtualbox_present() {
        let root = tempfile::tempdir().expect("root");
        let net = root.path().join("net");
        std::fs::create_dir_all(net.join("vboxnet0")).expect("adapter");
        let inventory = at(None, net, Vec::new()).inventory();
        assert_eq!(inventory.len(), 1);
        assert!(inventory[0].host_network_seen);
        assert!(inventory[0].machines.is_empty());
    }

    #[test]
    fn nothing_found_is_an_empty_inventory() {
        let root = tempfile::tempdir().expect("root");
        let inventory = at(
            Some(root.path().join("vbox")),
            root.path().join("net"),
            Vec::new(),
        )
        .inventory();
        assert!(inventory.is_empty());
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
    fn binding_without_the_tool_or_with_a_bad_target_is_refused() {
        let root = tempfile::tempdir().expect("root");
        let without_tool = at(None, root.path().to_path_buf(), Vec::new());
        assert_eq!(
            without_tool.bind_nat(Hypervisor::VirtualBox, MACHINE_ID, 0, None),
            Err(VmControlError::ToolMissing)
        );

        let tool = root.path().join("VBoxManage");
        write(&tool, "");
        let with_tool = at(None, root.path().to_path_buf(), vec![tool]);
        assert_eq!(
            with_tool.bind_nat(Hypervisor::VirtualBox, "--help", 0, None),
            Err(VmControlError::InvalidTarget)
        );
    }

    #[cfg(unix)]
    mod outcome {
        use super::*;
        use std::os::unix::process::ExitStatusExt;

        fn output(code: i32, stderr: &str) -> Output {
            Output {
                status: std::process::ExitStatus::from_raw(code << 8),
                stdout: Vec::new(),
                stderr: stderr.as_bytes().to_vec(),
            }
        }

        #[test]
        fn the_tools_answer_is_mapped() {
            assert_eq!(tool_outcome(&output(0, "")), Ok(()));
            assert_eq!(
                tool_outcome(&output(
                    1,
                    "VBoxManage: error: The machine is already locked for a session\n"
                )),
                Err(VmControlError::MachineNotMutable)
            );
            assert_eq!(
                tool_outcome(&output(1, "  VBoxManage: error: no such machine \n")),
                Err(VmControlError::Failed(
                    "VBoxManage: error: no such machine".to_string()
                ))
            );
            let Err(VmControlError::Failed(long)) = tool_outcome(&output(1, &"e".repeat(1000)))
            else {
                panic!("a failure is reported");
            };
            assert_eq!(long.chars().count(), MAX_FAILURE_CHARS);
            let Err(VmControlError::Failed(silent)) = tool_outcome(&output(2, "")) else {
                panic!("a silent failure is reported");
            };
            assert!(!silent.is_empty());
        }

        #[test]
        fn a_failing_tool_is_run_and_reported() {
            let root = tempfile::tempdir().expect("root");
            let inventory = at(
                None,
                root.path().to_path_buf(),
                vec![PathBuf::from("/bin/false")],
            );
            if !Path::new("/bin/false").is_file() {
                return;
            }
            assert!(matches!(
                inventory.bind_nat(
                    Hypervisor::VirtualBox,
                    MACHINE_ID,
                    0,
                    Some(Ipv4Addr::new(192, 0, 2, 10))
                ),
                Err(VmControlError::Failed(_))
            ));
        }
    }
}
