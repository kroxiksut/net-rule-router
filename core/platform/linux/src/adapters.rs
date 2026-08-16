//! Linux mechanism behind adapter enumeration ([`AdapterInfo`]).
//!
//! Windows answers this with one `GetAdaptersAddresses` call. Linux has no
//! single call: the kernel spreads the same facts across `/sys/class/net`
//! (identity and link state), `/proc/net/route` (gateways) and the socket
//! address list (addresses). This assembles them into the neutral shape the
//! routing layer already speaks.
//!
//! Everything that decides anything is a pure function over text, so the rules
//! are tested on any host; only the reads are Linux-only. Classification of what
//! a device IS (type, tunnel, virtual) is deliberately NOT re-derived here — it
//! is already settled in [`crate::interface_traffic`], and a second opinion on
//! the same question is how the two drift apart.

// The reading half has no caller off Linux; the parsers below still compile and
// are still tested there, which is the point of the split.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::Ipv4Addr;

use nrr_platform_api::adapters::IfOperStatus;

// Only the assembling half below needs these; the parsers do not.
#[cfg(target_os = "linux")]
use nrr_platform_api::adapters::AdapterInfo;
#[cfg(target_os = "linux")]
use nrr_platform_api::error::PlatformError;
#[cfg(target_os = "linux")]
use std::path::Path;

/// One row of `/proc/net/route` that names a default gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DefaultGateway {
    pub(crate) interface: String,
    pub(crate) gateway: Ipv4Addr,
}

/// Default gateways out of `/proc/net/route`.
///
/// The file is fixed-width text with hex little-endian addresses:
///
/// ```text
/// Iface Destination Gateway  Flags RefCnt Use Metric Mask
/// eth0  00000000    0102A8C0 0003  0      0   100    00000000
/// ```
///
/// A destination of all zeros is the default route; its gateway is what an
/// adapter is asked for. Rows with a zero gateway (on-link routes) name no
/// next hop and are skipped.
pub(crate) fn parse_default_gateways(text: &str) -> Vec<DefaultGateway> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(iface), Some(destination), Some(gateway)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !is_zero_hex(destination) {
            continue;
        }
        let Some(addr) = parse_hex_le_ipv4(gateway) else {
            continue;
        };
        if addr.is_unspecified() {
            continue;
        }
        out.push(DefaultGateway {
            interface: iface.to_string(),
            gateway: addr,
        });
    }
    out
}

fn is_zero_hex(field: &str) -> bool {
    !field.is_empty() && field.chars().all(|c| c == '0')
}

/// `"0102A8C0"` → `192.168.2.1`. The kernel prints the address in host byte
/// order on a little-endian machine, which is why the octets read backwards.
fn parse_hex_le_ipv4(field: &str) -> Option<Ipv4Addr> {
    let raw = u32::from_str_radix(field, 16).ok()?;
    Some(Ipv4Addr::from(raw.swap_bytes()))
}

/// `"00:1a:2b:3c:4d:5e"` → the six octets. `None` for the all-zero address that
/// software devices report, since "no hardware address" is the honest answer and
/// the neutral `stable_id` falls back to the name for exactly that case.
pub(crate) fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut octets = [0u8; 6];
    let mut seen = 0usize;
    for (slot, part) in octets.iter_mut().zip(text.trim().split(':')) {
        *slot = u8::from_str_radix(part.trim(), 16).ok()?;
        seen += 1;
    }
    (seen == 6 && octets != [0u8; 6]).then_some(octets)
}

/// RFC 2863 operational state from sysfs `operstate`, with `carrier` as the
/// tie-breaker.
///
/// `unknown` is what the kernel reports for devices whose driver does not track
/// link state — loopback and many virtual devices — and it means "ask carrier",
/// not "down". Treating it as down marked the loopback and every tunnel as
/// unusable.
pub(crate) fn oper_status_from(operstate: Option<&str>, carrier: Option<bool>) -> IfOperStatus {
    match operstate.map(str::trim) {
        Some("up") => IfOperStatus::Up,
        Some("down") => IfOperStatus::Down,
        Some("dormant") => IfOperStatus::Dormant,
        Some("testing") => IfOperStatus::Testing,
        Some("notpresent") => IfOperStatus::NotPresent,
        Some("lowerlayerdown") => IfOperStatus::LowerLayerDown,
        // "unknown", anything unrecognised, or no file at all.
        _ => match carrier {
            Some(true) => IfOperStatus::Up,
            Some(false) => IfOperStatus::Down,
            None => IfOperStatus::Unknown,
        },
    }
}

/// Enumerate the host's adapters.
#[cfg(target_os = "linux")]
pub fn collect_adapter_infos() -> Result<Vec<AdapterInfo>, PlatformError> {
    collect_from(Path::new("/sys/class/net"), Path::new("/proc/net/route"))
}

/// The [`AdapterEventSource`] the supervised runtime polls — the Linux
/// counterpart of `WindowsApiAdapterSource`.
///
/// Enumeration is a fresh read of `/sys/class/net` and `/proc/net/route` on
/// every call, with nothing cached: an adapter that went down between two ticks
/// has to be visible as down, and a cached list would keep a pinned route
/// pointing at a link that no longer carries traffic.
#[cfg(target_os = "linux")]
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxAdapterSource;

#[cfg(target_os = "linux")]
impl nrr_platform_api::adapters::AdapterEventSource for LinuxAdapterSource {
    fn enumerate_all(&self) -> Result<Vec<AdapterInfo>, PlatformError> {
        collect_adapter_infos()
    }
}

/// Enumerate adapters from an explicit tree — the shape a test can point at a
/// fixture directory.
#[cfg(target_os = "linux")]
fn collect_from(sysfs: &Path, proc_net_route: &Path) -> Result<Vec<AdapterInfo>, PlatformError> {
    let gateways = std::fs::read_to_string(proc_net_route)
        .map(|text| parse_default_gateways(&text))
        .unwrap_or_default();
    let addresses = crate::adapters_addr::ipv4_addresses_by_interface();

    let entries = std::fs::read_dir(sysfs).map_err(|e| PlatformError::Transient {
        operation: "adapters.enumerate",
        detail: format!("{}: {e}", sysfs.display()),
    })?;

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let dir = sysfs.join(&name);
        let read = |file: &str| std::fs::read_to_string(dir.join(file)).ok();
        // No ifindex means this is not an interface directory at all.
        let Some(index) = read("ifindex").and_then(|v| v.trim().parse::<u32>().ok()) else {
            continue;
        };
        // What the device IS comes from the existing classifier, not a second
        // reading of the same files.
        let facts = crate::interface_traffic::read_sysfs_facts(sysfs, &name);
        let interface_type = crate::interface_traffic::classify(&name, &facts).interface_type;
        out.push(AdapterInfo {
            index,
            adapter_name: name.clone(),
            // Linux has no separate driver description; the driver module name
            // is the closest true equivalent, and the link name stands in when
            // there is none. Both name fields carrying the link name is correct
            // here rather than a placeholder: on Linux the user renames the
            // link itself, so there is no second, stabler name to report.
            description: driver_module(&dir).unwrap_or_else(|| name.clone()),
            friendly_name: name.clone(),
            mac: read("address").and_then(|v| parse_mac(&v)),
            interface_type,
            oper_status: oper_status_from(facts.operstate.as_deref(), facts.carrier),
            ipv4_addresses: addresses.get(&name).cloned().unwrap_or_default(),
            gateways: gateways
                .iter()
                .filter(|g| g.interface == name)
                .map(|g| g.gateway)
                .collect(),
        });
    }
    out.sort_by_key(|a| a.index);
    Ok(out)
}

/// Driver module behind an interface: `/sys/class/net/<n>/device/driver` is a
/// symlink whose final component is the module name (`e1000e`, `iwlwifi`).
/// Absent for software devices, which have no driver.
#[cfg(target_os = "linux")]
fn driver_module(dir: &Path) -> Option<String> {
    std::fs::read_link(dir.join("device/driver"))
        .ok()?
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_gateways_are_read_back_from_host_byte_order() {
        let text = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                    eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\n";
        assert_eq!(
            parse_default_gateways(text),
            vec![DefaultGateway {
                interface: "eth0".into(),
                gateway: Ipv4Addr::new(192, 168, 2, 1),
            }]
        );
    }

    #[test]
    fn only_the_default_route_with_a_real_next_hop_names_a_gateway() {
        // Row 2 is a subnet route (non-zero destination), row 3 is an on-link
        // default with no next hop — neither is a gateway.
        let text = "Iface\tDestination\tGateway\n\
                    eth0\t0002A8C0\t00000000\n\
                    wg0\t00000000\t00000000\n";
        assert!(parse_default_gateways(text).is_empty());
    }

    #[test]
    fn a_software_device_reports_no_hardware_address() {
        assert_eq!(
            parse_mac("00:1a:2b:3c:4d:5e"),
            Some([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e])
        );
        assert_eq!(parse_mac("00:00:00:00:00:00"), None);
        assert_eq!(parse_mac("not-a-mac"), None);
        assert_eq!(parse_mac("00:1a:2b"), None);
    }

    #[test]
    fn unknown_operstate_defers_to_carrier_instead_of_reading_as_down() {
        // The live-host lesson: loopback and many virtual devices report
        // `unknown` forever, and calling that "down" hides working interfaces.
        assert_eq!(
            oper_status_from(Some("unknown"), Some(true)),
            IfOperStatus::Up
        );
        assert_eq!(
            oper_status_from(Some("unknown"), Some(false)),
            IfOperStatus::Down
        );
        assert_eq!(
            oper_status_from(Some("unknown"), None),
            IfOperStatus::Unknown
        );
        assert_eq!(oper_status_from(None, None), IfOperStatus::Unknown);
    }

    #[test]
    fn explicit_operstate_wins_over_carrier() {
        assert_eq!(oper_status_from(Some("up"), Some(false)), IfOperStatus::Up);
        assert_eq!(
            oper_status_from(Some("down"), Some(true)),
            IfOperStatus::Down
        );
        assert_eq!(
            oper_status_from(Some("lowerlayerdown"), Some(true)),
            IfOperStatus::LowerLayerDown
        );
    }
}
