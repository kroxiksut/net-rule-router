use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::*;

#[derive(Clone, Debug, Default)]
struct Link {
    index: u32,
    dns: Vec<String>,
    domains: Vec<String>,
    addressed: bool,
}

/// resolved and iproute2 as far as the redirect sees them.
#[derive(Clone, Default)]
struct FakeResolved {
    links: Arc<Mutex<BTreeMap<String, Link>>>,
    mode: Arc<Mutex<String>>,
}

impl FakeResolved {
    fn machine() -> Self {
        let fake = Self::default();
        *fake.mode.lock().expect("lock") = "stub".into();
        fake.add("wlp3s0", 3, &["192.0.2.1"], &[]);
        fake.add("wg0", 4, &["198.51.100.1"], &["~.", "~corp.example"]);
        fake
    }

    fn add(&self, name: &str, index: u32, dns: &[&str], domains: &[&str]) {
        self.links.lock().expect("lock").insert(
            name.into(),
            Link {
                index,
                dns: dns.iter().map(|s| s.to_string()).collect(),
                domains: domains.iter().map(|s| s.to_string()).collect(),
                addressed: false,
            },
        );
    }

    fn domains(&self, name: &str) -> Option<Vec<String>> {
        self.links
            .lock()
            .expect("lock")
            .get(name)
            .map(|l| l.domains.clone())
    }

    fn print(&self, pick: impl Fn(&Link) -> &Vec<String>) -> String {
        let mut out = String::from("Global:\n");
        for (name, link) in self.links.lock().expect("lock").iter() {
            out.push_str(&format!(
                "Link {} ({name}): {}\n",
                link.index,
                pick(link).join(" ")
            ));
        }
        out
    }
}

fn ok(stdout: impl Into<String>) -> Result<CommandReply, PlatformError> {
    Ok(CommandReply {
        success: true,
        stdout: stdout.into(),
        stderr: String::new(),
    })
}

fn failed(stderr: &str) -> Result<CommandReply, PlatformError> {
    Ok(CommandReply {
        success: false,
        stdout: String::new(),
        stderr: stderr.into(),
    })
}

impl ResolvedCommands for FakeResolved {
    fn run(&self, program: &str, args: &[&str]) -> Result<CommandReply, PlatformError> {
        let mut links = self.links.lock().expect("lock");
        match (program, args) {
            ("ip", ["link", "show", "dev", name]) => {
                if links.contains_key(*name) {
                    ok("")
                } else {
                    failed("Device does not exist.")
                }
            }
            ("ip", ["link", "add", name, "type", "dummy"]) => {
                let index = links.values().map(|l| l.index).max().unwrap_or(1) + 1;
                links.insert(
                    (*name).into(),
                    Link {
                        index,
                        ..Link::default()
                    },
                );
                ok("")
            }
            ("ip", ["addr", "replace", _, "dev", name]) => match links.get_mut(*name) {
                Some(link) => {
                    link.addressed = true;
                    ok("")
                }
                None => failed("Cannot find device"),
            },
            ("ip", ["link", "set", _, "up"]) => ok(""),
            ("ip", ["link", "del", name]) => {
                links.remove(*name);
                ok("")
            }
            ("resolvectl", ["status"]) => ok(format!(
                "Global\n  resolv.conf mode: {}\n",
                self.mode.lock().expect("lock")
            )),
            ("resolvectl", ["flush-caches"]) | ("resolvectl", ["default-route", _, "yes"]) => {
                ok("")
            }
            ("resolvectl", ["domain"]) => {
                drop(links);
                ok(self.print(|l| &l.domains))
            }
            ("resolvectl", ["dns"]) => {
                drop(links);
                ok(self.print(|l| &l.dns))
            }
            ("resolvectl", ["dns", name, server]) => match links.get_mut(*name) {
                Some(link) => {
                    link.dns = vec![(*server).into()];
                    ok("")
                }
                None => failed("Failed to resolve interface"),
            },
            ("resolvectl", ["domain", name, rest @ ..]) => match links.get_mut(*name) {
                Some(link) => {
                    link.domains = rest
                        .iter()
                        .filter(|d| !d.is_empty())
                        .map(|d| d.to_string())
                        .collect();
                    ok("")
                }
                None => failed("Failed to resolve interface"),
            },
            other => panic!("unexpected command {other:?}"),
        }
    }
}

fn taken_file(test: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nrr-dns-redirect-{test}-{}.txt",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

fn redirect(fake: &FakeResolved, test: &str) -> ResolvedDnsRedirect<FakeResolved> {
    ResolvedDnsRedirect::new(fake.clone(), taken_file(test))
}

#[test]
fn the_redirect_takes_every_name_and_leaves_narrow_domains_where_they_are() {
    let fake = FakeResolved::machine();
    let redirect = redirect(&fake, "takes");
    let handle = redirect.redirect_to(LISTENER_ADDR).expect("redirects");

    assert_eq!(fake.domains(REDIRECT_LINK), Some(vec!["~.".to_string()]));
    assert_eq!(fake.domains("wg0"), Some(vec!["~corp.example".to_string()]));
    assert_eq!(
        redirect.inspect(&handle).expect("inspects"),
        RedirectState::Active
    );
    assert_eq!(read_taken(&redirect.taken_file), vec!["wg0".to_string()]);
}

#[test]
fn restore_gives_the_catch_all_back_and_removes_the_link() {
    let fake = FakeResolved::machine();
    let redirect = redirect(&fake, "restore");
    let handle = redirect.redirect_to(LISTENER_ADDR).expect("redirects");
    redirect.restore(&handle).expect("restores");

    assert_eq!(fake.domains(REDIRECT_LINK), None);
    assert_eq!(
        fake.domains("wg0"),
        Some(vec!["~corp.example".to_string(), "~.".to_string()])
    );
    assert!(!redirect.taken_file.exists());
}

#[test]
fn a_vpn_that_reclaims_every_name_is_noticed_and_redirected_again() {
    let fake = FakeResolved::machine();
    let redirect = redirect(&fake, "reclaim");
    let handle = redirect.redirect_to(LISTENER_ADDR).expect("redirects");
    fake.links
        .lock()
        .expect("lock")
        .get_mut("wg0")
        .expect("wg0")
        .domains
        .push("~.".into());

    assert_eq!(
        redirect.inspect(&handle).expect("inspects"),
        RedirectState::Inactive
    );
    redirect
        .redirect_to(LISTENER_ADDR)
        .expect("redirects again");
    assert_eq!(
        redirect.inspect(&handle).expect("inspects"),
        RedirectState::Active
    );
}

#[test]
fn what_a_crashed_run_left_behind_is_undone_at_the_next_start() {
    let fake = FakeResolved::machine();
    let file = taken_file("orphan");
    ResolvedDnsRedirect::new(fake.clone(), file.clone())
        .redirect_to(LISTENER_ADDR)
        .expect("redirects");
    // No restore: the process died.

    clear_orphan_redirect(fake.clone(), file.clone()).expect("clears");
    assert_eq!(fake.domains(REDIRECT_LINK), None);
    assert!(fake
        .domains("wg0")
        .expect("wg0")
        .contains(&"~.".to_string()));
    assert!(!file.exists());
}

#[test]
fn a_connection_gone_by_restore_is_skipped() {
    let fake = FakeResolved::machine();
    let redirect = redirect(&fake, "gone");
    let handle = redirect.redirect_to(LISTENER_ADDR).expect("redirects");
    fake.links.lock().expect("lock").remove("wg0");
    redirect.restore(&handle).expect("restores");
    assert_eq!(fake.domains(REDIRECT_LINK), None);
}

#[test]
fn a_listener_off_the_link_is_refused_before_anything_changes() {
    let fake = FakeResolved::machine();
    let redirect = redirect(&fake, "refused");
    let loopback: SocketAddr = "127.0.0.1:53".parse().expect("addr");
    assert!(redirect.redirect_to(loopback).is_err());
    assert_eq!(fake.domains(REDIRECT_LINK), None);
    assert!(fake
        .domains("wg0")
        .expect("wg0")
        .contains(&"~.".to_string()));
}

#[test]
fn upstream_servers_come_from_the_links_never_from_our_own() {
    let fake = FakeResolved::machine();
    redirect(&fake, "servers")
        .redirect_to(LISTENER_ADDR)
        .expect("redirects");
    let servers: Vec<(Option<u32>, Ipv4Addr)> = ResolvedDnsServers(fake)
        .upstream_candidates_v4()
        .into_iter()
        .map(|c| (c.interface_index, c.server))
        .collect();
    assert_eq!(
        servers,
        vec![
            (Some(4), Ipv4Addr::new(198, 51, 100, 1)),
            (Some(3), Ipv4Addr::new(192, 0, 2, 1)),
        ]
    );
}

#[test]
fn a_narrow_routing_domain_is_a_claimed_namespace_and_the_catch_all_is_not() {
    let scopes = ResolvedDnsScopes(FakeResolved::machine()).dns_scopes();
    assert_eq!(scopes.len(), 1, "{scopes:?}");
    assert_eq!(scopes[0].adapter_id, "wg0");
    assert_eq!(scopes[0].suffix, "corp.example");
    assert_eq!(scopes[0].servers, vec![Ipv4Addr::new(198, 51, 100, 1)]);
}

#[test]
fn only_stub_and_static_mode_put_resolved_between_programs_and_dns() {
    for (mode, carries) in [
        ("stub", true),
        ("static", true),
        ("uplink", false),
        ("foreign", false),
    ] {
        let fake = FakeResolved::machine();
        *fake.mode.lock().expect("lock") = mode.into();
        assert_eq!(resolved_redirect_available(&fake), carries, "{mode}");
    }
}

#[test]
fn link_lines_parse_with_their_index_and_values() {
    let links = parse_resolvectl_links(
        "Global: 192.0.2.9\nLink 2 (enp4s0f1):\nLink 4 (wg0): 1.1.1.1 192.0.2.3:53#dns.example\n",
    );
    assert_eq!(links.len(), 2);
    assert_eq!(links[0].values, Vec::<String>::new());
    assert_eq!(links[1].index, 4);
    assert_eq!(
        links[1]
            .values
            .iter()
            .filter_map(|v| server_ip(v))
            .collect::<Vec<_>>(),
        vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(192, 0, 2, 3)]
    );
}
