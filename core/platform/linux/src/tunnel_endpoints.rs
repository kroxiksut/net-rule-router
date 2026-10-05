//! Linux [`TunnelEndpointSource`]: the peers of the kernel's WireGuard and
//! AmneziaWG links, as their own tools print them.
//!
//! Only links sysfs reports with a tunnel device type are asked about, so a
//! machine without such a tunnel spawns nothing.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use nrr_platform_api::tunnel_endpoints::{parse_endpoint, TunnelEndpointSource};

use crate::vpn_discovery::{kernel_tunnel_links_in, run_system_helper, HelperRunner};

/// The answer comes from the kernel; anything slower is a wedged helper.
const SHOW_TIMEOUT: Duration = Duration::from_secs(2);

/// Linux [`TunnelEndpointSource`].
#[derive(Debug, Clone)]
pub struct LinuxTunnelEndpoints {
    sysfs_net: PathBuf,
    run: HelperRunner,
}

impl Default for LinuxTunnelEndpoints {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxTunnelEndpoints {
    #[must_use]
    pub fn new() -> Self {
        Self::with_roots(PathBuf::from("/sys/class/net"), run_system_helper)
    }

    #[must_use]
    pub fn with_roots(sysfs_net: PathBuf, run: HelperRunner) -> Self {
        Self { sysfs_net, run }
    }
}

impl TunnelEndpointSource for LinuxTunnelEndpoints {
    fn tunnel_endpoints(&self) -> Vec<IpAddr> {
        let mut out = Vec::new();
        for (link, devtype) in kernel_tunnel_links_in(&self.sysfs_net) {
            let Some(tool) = show_tool(&devtype) else {
                continue;
            };
            let args = ["show", link.as_str(), "endpoints"];
            let Some(text) = (self.run)(tool, &args, SHOW_TIMEOUT) else {
                continue;
            };
            for ip in parse_show_endpoints(&text) {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
        out
    }
}

/// The tool that speaks to a tunnel of this device type.
fn show_tool(devtype: &str) -> Option<&'static str> {
    match devtype {
        "wireguard" => Some("wg"),
        "amneziawg" => Some("awg"),
        _ => None,
    }
}

/// `wg show <link> endpoints`: one `<public key>\t<endpoint>` line per peer.
fn parse_show_endpoints(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter_map(parse_endpoint)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_peer_with_an_endpoint_counts() {
        let text = "pubkeyA=\t203.0.113.7:51820\n\
                    pubkeyB=\t(none)\n\
                    pubkeyC=\t[2001:db8::7]:443\n\n";
        assert_eq!(
            parse_show_endpoints(text),
            vec![
                "203.0.113.7".parse::<IpAddr>().expect("ip"),
                "2001:db8::7".parse::<IpAddr>().expect("ip"),
            ]
        );
    }

    #[test]
    fn only_kernel_tunnel_types_have_a_tool() {
        assert_eq!(show_tool("wireguard"), Some("wg"));
        assert_eq!(show_tool("amneziawg"), Some("awg"));
        assert_eq!(show_tool("vlan"), None);
    }

    #[test]
    fn a_machine_without_kernel_tunnels_runs_nothing() {
        fn panicking(_: &str, _: &[&str], _: Duration) -> Option<String> {
            panic!("no tunnel link, no helper");
        }
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::create_dir(dir.path().join("eth0")).expect("link dir");
        let source = LinuxTunnelEndpoints::with_roots(dir.path().to_path_buf(), panicking);
        assert!(source.tunnel_endpoints().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_wireguard_link_is_asked_with_its_own_tool() {
        fn wg_only(tool: &str, args: &[&str], _: Duration) -> Option<String> {
            (tool == "wg" && args == ["show", "wg0", "endpoints"])
                .then(|| "key=\t198.51.100.4:51820\n".to_owned())
        }
        let dir = tempfile::tempdir().expect("temp dir");
        let link = dir.path().join("wg0");
        std::fs::create_dir(&link).expect("link dir");
        std::fs::write(link.join("uevent"), "DEVTYPE=wireguard\nINTERFACE=wg0\n").expect("uevent");
        let source = LinuxTunnelEndpoints::with_roots(dir.path().to_path_buf(), wg_only);
        assert_eq!(
            source.tunnel_endpoints(),
            vec!["198.51.100.4".parse::<IpAddr>().expect("ip")]
        );
    }
}
