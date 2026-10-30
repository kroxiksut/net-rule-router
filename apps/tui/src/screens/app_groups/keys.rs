//! Locale keys of the Application routes screen. The GUI's wording is reused
//! wherever the GUI says the same thing; only terminal-only text is `tui.*`.

use crate::i18n::{key, Key, Plural};

pub const TITLE: Key = key("app-groups.title", "Connections for programs and devices");
pub const SUBTITLE: Key = key("app-groups.subtitle", "detected on this computer");
pub const INTRO: Key = key(
    "tui.app-groups.intro",
    "A whole group of programs, or the machines of a hypervisor, can be sent over the main or the additional connection at once. Changes go to your rules list, where you review and apply them.",
);
pub const VM_NOTE: Key = key(
    "app-groups.vm-note",
    "Virtual machine traffic goes over the connection chosen for its program. The default is the main connection. A machine's local networks (host-to-guest access) always keep working, whichever connection you pick.",
);
pub const P2P_NOTE: Key = key(
    "app-groups.p2p-note",
    "These programs are not blocked unless leak protection is on. The chosen connection carries their bulk transfers; their peers are not added to zone rules.",
);
pub const KERNEL_NAT_NOTE: Key = key(
    "app-groups.kernel-nat-note",
    "Traffic of WSL, Hyper-V, Docker, libvirt and other virtual machines does not belong to any program on this computer, so it cannot be given a connection of its own. When it goes out through this computer, it follows your rules, as this computer's own traffic does; a machine bridged straight onto your network goes past them. Flexible routing for these environments is planned for the future.",
);
pub const LIST_TITLE: Key = key("tui.app-groups.list-title", "Groups and machines");
pub const SCANNING: Key = key("app-groups.scanning", "Scanning…");
pub const EMPTY: Key = key(
    "app-groups.empty",
    "Nothing detected on this computer. You can add a program as an ordinary application rule.",
);
pub const FOOTER_NOTE: Key = key(
    "app-groups.footer-note",
    "Can't find your program? Add it as an ordinary application rule, or tell us through any channel — the dictionary keeps growing.",
);
pub const NO_RULES: Key = key(
    "tui.app-groups.no-rules",
    "Your rules have not been read yet, so a connection cannot be chosen. Connect to the service first.",
);
pub const DISPLAY_ONLY: Key = key("app-groups.group-display-only-hint", "for information only");
pub const ROUTE_LOCKED: Key = key("app-groups.route-locked", "Main");
pub const BADGE_RUNNING: Key = key("app-groups.badge-running", "running");
pub const BADGE_INSTALLED: Key = key("app-groups.badge-installed", "installed");
pub const BADGE_FEATURE: Key = key("app-groups.badge-feature", "system component");
pub const ROUTE_NONE: Key = key(
    "rules.vm.route-none",
    "{hypervisor} carries its machines' traffic in a system service, so no program rule can route it.",
);
pub const NO_MACHINES: Key = key("rules.vm.no-machines", "{hypervisor} has no machines yet.");
pub const HYPERVISOR_VIRTUALBOX: Key = key("rules.vm.hypervisor.virtualbox", "VirtualBox");
pub const HYPERVISOR_VMWARE: Key = key("rules.vm.hypervisor.vmware", "VMware");
pub const ROUTE_PRIMARY: Key = key("label.primary", "Main");
pub const ROUTE_SECONDARY: Key = key("label.secondary", "Additional");
pub const ROUTE_BLOCK: Key = key("label.block", "Denied");
pub const ROUTE_MIXED: Key = key("tui.app-groups.route-mixed", "Different connections");
pub const MACHINES: Key = key("tui.app-groups.machines", "Machines");
pub const UPDATED: Plural = Plural {
    stem: "app-groups.confirmed-status.",
    one: "Routes updated for {count} program.",
    other: "Routes updated for {count} programs.",
};
pub const IN_RULES: Key = key(
    "rules.vm.added-note",
    "The rules are in your rules list. Review and apply them there.",
);
pub const UNCHANGED: Key = key(
    "tui.app-groups.unchanged",
    "The rules already send it that way. Nothing changed.",
);
pub const LIMIT_REACHED: Key = key(
    "status.rules-limit-reached",
    "Up to {max} active rules are supported.",
);
pub const NOT_ASSIGNABLE: Key = key(
    "tui.app-groups.not-assignable",
    "Item {n} cannot be given a connection: no program rule reaches its traffic.",
);
pub const NO_ITEM: Key = key("tui.app-groups.no-item", "There is no item {n}.");
pub const LOCKED: Key = key(
    "tui.app-groups.locked",
    "The rules list is being applied and cannot change meanwhile.",
);
pub const NOT_HYPERVISOR: Key = key(
    "tui.app-groups.not-hypervisor",
    "Item {n} is not a hypervisor, so it has no machines to show.",
);
pub const NO_TARGET: Key = key(
    "tui.app-groups.no-target",
    "There is no adapter {n} that can be tied to a connection.",
);
pub const PIN_BUSY: Key = key(
    "tui.app-groups.pin-busy",
    "The previous change to a machine is still being made.",
);
pub const PIN_UNCHANGED: Key = key(
    "tui.app-groups.pin-unchanged",
    "The adapter is already set that way. Nothing changed.",
);
pub const VM_PINNING: Key = key(
    "tui.app-groups.pinning",
    "Changing the machine in VirtualBox…",
);
pub const MACHINES_TITLE: Key = key("tui.app-groups.machines-title", "Machines of {hypervisor}");
pub const VM_MACHINE: Key = key("rules.vm.machine-label", "Machine");
pub const VM_NO_ADAPTERS: Key = key(
    "rules.vm.no-adapters",
    "This machine has no network adapters.",
);
pub const VM_ADAPTER_TITLE: Key = key("rules.vm.adapter-title", "Adapter {n}: {mode}");
pub const VM_ROUTE_SCOPE: Key = key(
    "rules.vm.route-scope",
    "{hypervisor} runs every machine as one program ({processes}), so the connection you choose applies to all of its machines.",
);
pub const VM_ROUTE_NOW: Key = key(
    "rules.vm.route-now",
    "Every {hypervisor} machine goes over {route}.",
);
pub const VM_ROUTE_NOW_MIXED: Key = key(
    "rules.vm.route-now-mixed",
    "The rules send {hypervisor}'s programs over different connections.",
);
pub const VM_ROUTE_NOW_BLOCK: Key = key(
    "rules.vm.route-now-block",
    "The rules deny the traffic of every {hypervisor} machine.",
);
pub const VM_NAT_DNS: Key = key(
    "rules.vm.nat-dns",
    "For your site rules to work inside this machine, set its DNS server to {address}.",
);
pub const VM_NAT_ENABLE_FIRST: Key = key(
    "rules.vm.nat-enable-first",
    "For your site rules to work inside this machine, first let this adapter reach your computer: power the machine off and run the command below. Then set the machine's DNS server to {address}.",
);
pub const VM_NAT_ENABLE_FIRST_NO_TOOL: Key = key(
    "rules.vm.nat-enable-first-no-tool",
    "For your site rules to work inside this machine, first let adapter {n} reach your computer with the VBoxManage option --nat-localhostreachable{n} while the machine is off. Then set the machine's DNS server to {address}.",
);
pub const VM_BRIDGED: Key = key(
    "rules.vm.bridged",
    "This adapter is bridged: its traffic goes straight to your network and bypasses your rules. Switch it to NAT for the rules to apply.",
);
pub const VM_HOST_ONLY: Key = key(
    "rules.vm.host-only",
    "Traffic stays between this machine and your computer. Nothing to route.",
);
pub const VM_INTERNAL: Key = key(
    "rules.vm.internal",
    "Traffic stays between virtual machines. Nothing to route.",
);
pub const VM_NAT_NETWORK: Key = key(
    "rules.vm.nat-network",
    "NAT Network is not supported yet, so this adapter is not covered here.",
);
pub const VM_SERVICE_NAT: Key = key(
    "rules.vm.service-nat",
    "This adapter uses the hypervisor's NAT, which runs as a system service: no application rule routes this machine's traffic, and whether your site rules apply inside it has not been checked yet.",
);
pub const VM_OTHER: Key = key(
    "rules.vm.other",
    "This adapter is not attached, or its kind is not supported yet.",
);
pub const VM_PIN_RULES: Key = key(
    "rules.vm.pin.rules",
    "This machine follows your rules: sites from the rules go over their own connections, everything else goes over {route}.",
);
pub const VM_PIN_ADDITIONAL: Key = key(
    "rules.vm.pin.additional",
    "All of this machine's traffic goes over {route}.",
);
pub const VM_PIN_MISSING: Key = key(
    "rules.vm.pin.missing",
    "This machine is tied to {address}, which your computer no longer has, so it has no network. Power it off and tie it again.",
);
pub const VM_PIN_OTHER: Key = key(
    "rules.vm.pin.other",
    "This machine's traffic leaves from {address}.",
);
pub const VM_PIN_NOTE: Key = key(
    "rules.vm.pin.note",
    "The change is made in VirtualBox and works only while the machine is powered off. If {route} reconnects with a new address, tie the machine again.",
);
pub const VM_PIN_NO_ADDITIONAL: Key = key(
    "rules.vm.pin.no-additional",
    "Choose the adapter for {route} first.",
);
pub const VM_PIN_NOT_MUTABLE: Key = key(
    "rules.vm.pin.error.not-mutable",
    "The machine is running or suspended. Shut it down completely and try again.",
);
pub const VM_PIN_TOOL_MISSING: Key = key(
    "rules.vm.pin.error.tool-missing",
    "VBoxManage was not found. Reinstall VirtualBox or change the machine in VirtualBox itself.",
);
pub const VM_PIN_NO_ADDRESS: Key = key(
    "rules.vm.pin.error.no-address",
    "{route} has no IPv4 address right now. Connect it and try again.",
);
pub const VM_PIN_REFUSED: Key = key(
    "rules.vm.pin.error.refused",
    "VirtualBox refused: {message}",
);
pub const VM_PIN_FAILED: Key = key(
    "rules.vm.pin.error.failed",
    "The machine could not be changed.",
);

pub const HELP_KEYS: &[Key] = &[
    key(
        "tui.app-groups.help.move",
        "Up and Down choose an item; Home and End jump to the first and the last",
    ),
    key(
        "tui.app-groups.help.route",
        "P sends the item over the main connection, S over the additional one; Space switches between them",
    ),
    key("tui.app-groups.help.scan", "R scans again"),
    key(
        "tui.app-groups.help.machines",
        "M shows the machines of the chosen hypervisor and their network adapters; M or Esc goes back to the list",
    ),
    key(
        "tui.app-groups.help.pin",
        "In the machines, A sends all traffic of the chosen VirtualBox NAT adapter over the additional connection, F lets it follow the rules again",
    ),
];

pub const PLAIN_KEYS: &[Key] = &[
    key(
        "tui.app-groups.plain.route",
        "p and an item number, for example p 2: send that item over the main connection; s and a number: over the additional connection",
    ),
    key("tui.app-groups.plain.scan", "r: scan again"),
    key(
        "tui.app-groups.plain.machines",
        "m and an item number, for example m 1: show that hypervisor's machines; m alone: back to the list",
    ),
    key(
        "tui.app-groups.plain.pin",
        "with the machines shown, a and an adapter number: send all of its traffic over the additional connection; f and a number: let it follow the rules again; p or s alone: the hypervisor's connection",
    ),
];

/// Every key above, for the test that holds both locale files to them.
#[cfg(test)]
pub fn all() -> Vec<Key> {
    let mut keys = vec![
        TITLE,
        SUBTITLE,
        INTRO,
        VM_NOTE,
        P2P_NOTE,
        KERNEL_NAT_NOTE,
        LIST_TITLE,
        SCANNING,
        EMPTY,
        FOOTER_NOTE,
        NO_RULES,
        DISPLAY_ONLY,
        ROUTE_LOCKED,
        BADGE_RUNNING,
        BADGE_INSTALLED,
        BADGE_FEATURE,
        ROUTE_NONE,
        NO_MACHINES,
        HYPERVISOR_VIRTUALBOX,
        HYPERVISOR_VMWARE,
        ROUTE_PRIMARY,
        ROUTE_SECONDARY,
        ROUTE_BLOCK,
        ROUTE_MIXED,
        MACHINES,
        IN_RULES,
        UNCHANGED,
        LIMIT_REACHED,
        NOT_ASSIGNABLE,
        NO_ITEM,
        LOCKED,
        NOT_HYPERVISOR,
        NO_TARGET,
        PIN_BUSY,
        PIN_UNCHANGED,
        VM_PINNING,
        MACHINES_TITLE,
        VM_MACHINE,
        VM_NO_ADAPTERS,
        VM_ADAPTER_TITLE,
        VM_ROUTE_SCOPE,
        VM_ROUTE_NOW,
        VM_ROUTE_NOW_MIXED,
        VM_ROUTE_NOW_BLOCK,
        VM_NAT_DNS,
        VM_NAT_ENABLE_FIRST,
        VM_NAT_ENABLE_FIRST_NO_TOOL,
        VM_BRIDGED,
        VM_HOST_ONLY,
        VM_INTERNAL,
        VM_NAT_NETWORK,
        VM_SERVICE_NAT,
        VM_OTHER,
        VM_PIN_RULES,
        VM_PIN_ADDITIONAL,
        VM_PIN_MISSING,
        VM_PIN_OTHER,
        VM_PIN_NOTE,
        VM_PIN_NO_ADDITIONAL,
        VM_PIN_NOT_MUTABLE,
        VM_PIN_TOOL_MISSING,
        VM_PIN_NO_ADDRESS,
        VM_PIN_REFUSED,
        VM_PIN_FAILED,
    ];
    keys.extend_from_slice(HELP_KEYS);
    keys.extend_from_slice(PLAIN_KEYS);
    keys
}
