//! Linux mechanism behind
//! [`nrr_platform_api::interface_traffic::InterfaceCounterSource`].
//!
//! Counters come from one read of `/proc/net/dev`, so every interface in a
//! sample is read from the same snapshot rather than drifting apart across N
//! separate reads. Classification (type, up, tunnel, virtual) then comes from
//! `/sys/class/net/<name>/`, which is where the kernel actually says what a
//! device is — a name heuristic alone cannot tell `wg0` from a bridge.
//!
//! Both the parser and the classifier are pure functions over text: only the
//! file reads are Linux-only, so the decisions are tested on every host.

// The reading half has no caller off Linux — the pure half below still
// compiles and is still tested there, which is the point of the split.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::Path;

use nrr_platform_api::adapters::{
    description_matches_virtual_software, text_indicates_vpn_tunnel, InterfaceType,
};
use nrr_platform_api::error::PlatformError;

pub use nrr_platform_api::interface_traffic::{
    InterfaceCounterSource, InterfaceCounters, MockInterfaceCounterSource,
    NoopInterfaceCounterSource,
};

/// Production source: `/proc/net/dev` for the octets, `/sys/class/net` for what
/// each interface is. Cost is O(number of interfaces) per sample and
/// independent of traffic volume — the kernel already keeps the tally.
#[derive(Debug, Default)]
pub struct LinuxInterfaceCounterSource;

impl LinuxInterfaceCounterSource {
    pub fn new() -> Self {
        Self
    }
}

impl InterfaceCounterSource for LinuxInterfaceCounterSource {
    #[cfg(target_os = "linux")]
    fn read_counters(&self) -> Result<Vec<InterfaceCounters>, PlatformError> {
        read_counters_from(Path::new("/proc/net/dev"), Path::new("/sys/class/net"))
    }

    // Off-Linux (cross-platform build) the crate still compiles; there are no
    // kernel counters to read.
    #[cfg(not(target_os = "linux"))]
    fn read_counters(&self) -> Result<Vec<InterfaceCounters>, PlatformError> {
        Ok(Vec::new())
    }
}

/// Read one sample. Split out from the trait method so a test can point it at
/// a fixture tree instead of the live kernel.
fn read_counters_from(
    proc_net_dev: &Path,
    sysfs: &Path,
) -> Result<Vec<InterfaceCounters>, PlatformError> {
    let text = std::fs::read_to_string(proc_net_dev).map_err(|e| PlatformError::Transient {
        operation: "read /proc/net/dev",
        detail: format!("{}: {e}", proc_net_dev.display()),
    })?;
    Ok(parse_proc_net_dev(&text)
        .into_iter()
        .map(|row| {
            let class = classify(&row.name, &read_sysfs_facts(sysfs, &row.name));
            InterfaceCounters {
                display_name: row.name.clone(),
                stable_name: row.name,
                interface_type: class.interface_type,
                is_virtual: class.is_virtual,
                is_tunnel: class.is_tunnel,
                is_up: class.is_up,
                in_octets: row.in_octets,
                out_octets: row.out_octets,
            }
        })
        .collect())
}

/// One interface's line in `/proc/net/dev`.
#[derive(Debug, PartialEq, Eq)]
struct CounterRow {
    name: String,
    in_octets: u64,
    out_octets: u64,
}

/// Parse `/proc/net/dev`. The two header lines carry no interface; every other
/// line is `<name>:<16 whitespace-separated counters>`, receive first. A line
/// that does not parse is skipped rather than failing the sample — one
/// malformed row must not cost the ledger every other interface.
fn parse_proc_net_dev(text: &str) -> Vec<CounterRow> {
    text.lines()
        .filter_map(|line| {
            // The name field is right-aligned and, on a busy interface, can run
            // straight into the first counter with no space — so split on the
            // colon rather than on whitespace.
            let (name, counters) = line.split_once(':')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            let fields: Vec<&str> = counters.split_whitespace().collect();
            // Receive bytes is the first column, transmit bytes the ninth.
            let in_octets = fields.first()?.parse().ok()?;
            let out_octets = fields.get(8)?.parse().ok()?;
            Some(CounterRow {
                name: name.to_string(),
                in_octets,
                out_octets,
            })
        })
        .collect()
}

/// What `/sys/class/net/<name>/` says about one interface. Every field is an
/// observation; `None` means the file was absent or unreadable.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct SysfsFacts {
    /// `type` — the ARPHRD hardware class.
    pub(crate) arphrd: Option<u32>,
    /// `IFF_UP` out of `flags` — someone asked for this interface to be up.
    /// Says nothing about whether it carries traffic.
    pub(crate) admin_up: bool,
    /// `operstate` — the RFC 2863 operational status (`up`, `down`,
    /// `unknown`, `dormant`, …).
    pub(crate) operstate: Option<String>,
    /// `carrier` — physical/lower-layer link, when the kernel will report it.
    pub(crate) carrier: Option<bool>,
    /// `DEVTYPE=` out of `uevent` (`bridge`, `vlan`, `wireguard`, …).
    pub(crate) devtype: Option<String>,
    /// A `wireless/` directory or a `phy80211` link is present.
    pub(crate) is_wireless: bool,
    /// `tun_flags` is present — the device is a tun/tap.
    pub(crate) is_tun_device: bool,
}

#[cfg(target_os = "linux")]
pub(crate) fn read_sysfs_facts(sysfs: &Path, name: &str) -> SysfsFacts {
    let dir = sysfs.join(name);
    let read_number = |file: &str, radix: u32| -> Option<u32> {
        let raw = std::fs::read_to_string(dir.join(file)).ok()?;
        let raw = raw.trim();
        u32::from_str_radix(raw.strip_prefix("0x").unwrap_or(raw), radix).ok()
    };
    let read_text = |file: &str| -> Option<String> {
        std::fs::read_to_string(dir.join(file))
            .map(|raw| raw.trim().to_ascii_lowercase())
            .ok()
    };
    SysfsFacts {
        arphrd: read_number("type", 10),
        admin_up: read_number("flags", 16).is_some_and(|f| f & IFF_UP != 0),
        operstate: read_text("operstate"),
        // Reading `carrier` on a down interface fails with EINVAL; absent is
        // the honest answer, not `false`.
        carrier: read_text("carrier").map(|v| v == "1"),
        devtype: std::fs::read_to_string(dir.join("uevent"))
            .ok()
            .and_then(|text| devtype_from_uevent(&text)),
        is_wireless: dir.join("wireless").exists() || dir.join("phy80211").exists(),
        is_tun_device: dir.join("tun_flags").exists(),
    }
}

// Off-Linux there is no sysfs; the classifier then works from the name alone,
// which is all the cross-platform build needs to compile and test.
#[cfg(not(target_os = "linux"))]
pub(crate) fn read_sysfs_facts(_sysfs: &Path, _name: &str) -> SysfsFacts {
    SysfsFacts::default()
}

/// Pull `DEVTYPE=` out of a `uevent` file.
fn devtype_from_uevent(text: &str) -> Option<String> {
    text.lines()
        .find_map(|line| line.strip_prefix("DEVTYPE="))
        .map(|value| value.trim().to_ascii_lowercase())
}

/// What one interface is, as the ledger needs it bucketed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Classification {
    pub(crate) interface_type: InterfaceType,
    pub(crate) is_virtual: bool,
    pub(crate) is_tunnel: bool,
    pub(crate) is_up: bool,
}

/// ARPHRD classes worth naming. The rest fall through to `Other`.
const ARPHRD_ETHER: u32 = 1;
const ARPHRD_PPP: u32 = 512;
const ARPHRD_TUNNEL: u32 = 768;
const ARPHRD_TUNNEL6: u32 = 769;
const ARPHRD_LOOPBACK: u32 = 772;
const ARPHRD_SIT: u32 = 776;
const ARPHRD_NONE: u32 = 65534;

/// `IFF_UP` — administratively up. Sysfs `flags` exposes `dev->flags`, which
/// does NOT carry `IFF_RUNNING`: on a live host `eth0` reads `0x1003` and `lo`
/// reads `0x9`, neither with the running bit. Operational state therefore comes
/// from `operstate` + `carrier`, and this flag is only the precondition.
const IFF_UP: u32 = 0x1;

/// Kernel device types that mean "software construct", not a NIC. Distinct
/// from the tunnel set: a bridge carries real traffic, it just is not hardware.
const VIRTUAL_DEVTYPES: &[&str] = &[
    "bridge", "bond", "vlan", "veth", "macvlan", "dummy", "vxlan", "ifb",
];

/// Name prefixes the neutral virtual-software list does not carry, because
/// they are spellings only Linux produces.
const VIRTUAL_NAME_PREFIXES: &[&str] = &["veth", "br-", "virbr", "vboxnet", "lxcbr", "cni"];

/// Decide what an interface is from its name and what sysfs said. Pure.
pub(crate) fn classify(name: &str, facts: &SysfsFacts) -> Classification {
    let is_wireguard = facts.devtype.as_deref() == Some("wireguard");
    let interface_type = match facts.arphrd {
        Some(ARPHRD_LOOPBACK) => InterfaceType::Loopback,
        Some(ARPHRD_PPP | ARPHRD_TUNNEL | ARPHRD_TUNNEL6 | ARPHRD_SIT | ARPHRD_NONE) => {
            InterfaceType::Tunnel
        }
        // A tap device and a WireGuard device both present as plain Ethernet;
        // only the kernel's own markers separate them from a real NIC.
        Some(ARPHRD_ETHER) if facts.is_tun_device || is_wireguard => InterfaceType::Tunnel,
        Some(ARPHRD_ETHER) if facts.is_wireless => InterfaceType::Wireless,
        Some(ARPHRD_ETHER) => InterfaceType::Ethernet,
        Some(other) => InterfaceType::Other(other),
        // No sysfs to read: fall back to the neutral name heuristic, which is
        // the same signal the Windows backend uses when the raw type lies.
        None if text_indicates_vpn_tunnel(name) => InterfaceType::Tunnel,
        None if name == "lo" => InterfaceType::Loopback,
        None => InterfaceType::Other(0),
    };

    let is_tunnel = matches!(interface_type, InterfaceType::Tunnel)
        || is_wireguard
        || facts.is_tun_device
        || text_indicates_vpn_tunnel(name);

    // Software-only signal, matching the port's contract: loopback and tunnel
    // carry their own flags and must not be folded in here.
    let is_virtual = description_matches_virtual_software(name)
        || facts
            .devtype
            .as_deref()
            .is_some_and(|d| VIRTUAL_DEVTYPES.contains(&d))
        || VIRTUAL_NAME_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix));

    Classification {
        interface_type,
        is_virtual,
        is_tunnel,
        is_up: is_operationally_up(facts),
    }
}

/// Is the interface actually carrying traffic?
///
/// `operstate` is the RFC 2863 answer and the one to trust when it commits.
/// It reports `unknown` for loopback and for several virtual devices — those
/// are working, they just do not track link state, so the carrier bit decides.
/// Nothing read means nothing claimed: an interface whose state we cannot see
/// is reported down rather than assumed live.
fn is_operationally_up(facts: &SysfsFacts) -> bool {
    if !facts.admin_up {
        return false;
    }
    match facts.operstate.as_deref() {
        Some("up") => true,
        Some("unknown") | None => facts.carrier == Some(true),
        Some(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:   12345      67    0    0    0     0          0         0    12345      67    0    0    0     0       0          0
  eth0: 987654321 4321    0    0    0     0          0         0  123456789    1234    0    0    0     0       0          0
";

    /// A plain working interface of the given hardware class.
    fn facts(arphrd: u32) -> SysfsFacts {
        SysfsFacts {
            arphrd: Some(arphrd),
            admin_up: true,
            operstate: Some("up".to_string()),
            carrier: Some(true),
            ..SysfsFacts::default()
        }
    }

    #[test]
    fn the_parser_skips_the_headers_and_reads_both_directions() {
        let rows = parse_proc_net_dev(SAMPLE);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "lo");
        assert_eq!(rows[1].name, "eth0");
        assert_eq!(rows[1].in_octets, 987_654_321);
        assert_eq!(rows[1].out_octets, 123_456_789);
    }

    #[test]
    fn a_counter_that_ran_into_the_name_still_parses() {
        // The classic /proc/net/dev overflow: no space between the colon and
        // the first counter. Splitting on whitespace would lose the interface.
        let rows =
            parse_proc_net_dev("  eth0:18446744073709551615 1 0 0 0 0 0 0 42 1 0 0 0 0 0 0\n");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].in_octets, u64::MAX);
        assert_eq!(rows[0].out_octets, 42);
    }

    #[test]
    fn a_malformed_line_costs_only_itself() {
        let rows = parse_proc_net_dev("  eth0: not-a-number\n  eth1: 1 2 3 4 5 6 7 8 9\n");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "eth1");
        assert_eq!(rows[0].out_octets, 9);
    }

    #[test]
    fn an_interface_that_never_tracks_link_state_counts_as_up() {
        // Loopback and several virtual devices report `operstate=unknown` for
        // their whole life. Treating "unknown" as down would take the ledger's
        // busiest interface off the books; the carrier bit is what decides.
        let mut lo = facts(ARPHRD_LOOPBACK);
        lo.operstate = Some("unknown".to_string());
        assert!(classify("lo", &lo).is_up);

        lo.carrier = Some(false);
        assert!(!classify("lo", &lo).is_up);
    }

    #[test]
    fn loopback_is_loopback_and_not_virtual() {
        // The port asks for the software-only signal in `is_virtual`; loopback
        // has its own type and must not be double-counted as both.
        let class = classify("lo", &facts(ARPHRD_LOOPBACK));
        assert_eq!(class.interface_type, InterfaceType::Loopback);
        assert!(!class.is_virtual);
        assert!(class.is_up);
    }

    #[test]
    fn a_wireguard_device_reads_as_a_tunnel_despite_presenting_as_ethernet() {
        // `wg0` carries no VPN marker in its name and its ARPHRD is plain
        // Ethernet — only DEVTYPE separates it from a NIC.
        let mut f = facts(ARPHRD_ETHER);
        f.devtype = Some("wireguard".to_string());
        let class = classify("wg0", &f);
        assert_eq!(class.interface_type, InterfaceType::Tunnel);
        assert!(class.is_tunnel);
    }

    #[test]
    fn a_tap_device_reads_as_a_tunnel() {
        let mut f = facts(ARPHRD_ETHER);
        f.is_tun_device = true;
        let class = classify("tap0", &f);
        assert_eq!(class.interface_type, InterfaceType::Tunnel);
        assert!(class.is_tunnel);
    }

    #[test]
    fn a_wireless_interface_is_told_apart_from_wired_ethernet() {
        let mut f = facts(ARPHRD_ETHER);
        f.is_wireless = true;
        assert_eq!(
            classify("wlan0", &f).interface_type,
            InterfaceType::Wireless
        );
        assert_eq!(
            classify("eth0", &facts(ARPHRD_ETHER)).interface_type,
            InterfaceType::Ethernet
        );
    }

    #[test]
    fn bridges_and_veth_pairs_are_virtual_without_being_tunnels() {
        let mut bridge = facts(ARPHRD_ETHER);
        bridge.devtype = Some("bridge".to_string());
        let class = classify("br-abc123", &bridge);
        assert!(class.is_virtual);
        assert!(!class.is_tunnel);

        // No sysfs at all: the Linux-only name spelling still has to land.
        let class = classify("veth1a2b3c", &SysfsFacts::default());
        assert!(class.is_virtual);
    }

    #[test]
    fn docker_is_caught_by_the_neutral_list_not_a_second_copy() {
        // `docker` already lives in the shared virtual-software list; the
        // Linux prefix list must not need to repeat it.
        assert!(classify("docker0", &SysfsFacts::default()).is_virtual);
        assert!(!VIRTUAL_NAME_PREFIXES.contains(&"docker"));
    }

    #[test]
    fn an_interface_that_is_up_but_not_running_reports_down() {
        // Cable pulled: the interface stays administratively up while
        // `operstate` goes down. Reporting it up would make the ledger
        // attribute a dead link's zero delta to a live interface.
        let mut unplugged = facts(ARPHRD_ETHER);
        unplugged.operstate = Some("down".to_string());
        unplugged.carrier = Some(false);
        assert!(!classify("eth0", &unplugged).is_up);

        // Taken down by the operator: no admin flag, nothing else matters.
        let mut admin_down = facts(ARPHRD_ETHER);
        admin_down.admin_up = false;
        assert!(!classify("eth0", &admin_down).is_up);

        assert!(classify("eth0", &facts(ARPHRD_ETHER)).is_up);
    }

    #[test]
    fn unreadable_sysfs_does_not_invent_an_up_interface() {
        assert!(!classify("eth0", &SysfsFacts::default()).is_up);
    }

    /// The one test that exercises the whole read path against the live
    /// kernel: every Linux host has a loopback interface, so finding it proves
    /// `/proc/net/dev` and `/sys/class/net` were both parsed as they really
    /// come, not as the fixtures above imagine them.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_live_kernel_reports_at_least_loopback() {
        let counters = LinuxInterfaceCounterSource::new()
            .read_counters()
            .expect("reading /proc/net/dev must succeed on Linux");
        let loopback = counters
            .iter()
            .find(|c| c.stable_name == "lo")
            .expect("every Linux host has a loopback interface");
        assert_eq!(loopback.interface_type, InterfaceType::Loopback);
        assert!(loopback.is_up, "loopback is always running");
        assert!(counters.iter().all(|c| !c.stable_name.is_empty()));
    }

    #[test]
    fn devtype_is_read_out_of_a_real_uevent_body() {
        let uevent = "DEVTYPE=wireguard\nINTERFACE=wg0\nIFINDEX=7\n";
        assert_eq!(devtype_from_uevent(uevent).as_deref(), Some("wireguard"));
        assert_eq!(devtype_from_uevent("INTERFACE=eth0\n"), None);
    }
}
