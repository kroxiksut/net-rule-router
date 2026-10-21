use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::*;

#[derive(Clone, Debug, Default)]
struct Link {
    index: u32,
    dns: Vec<String>,
    domains: Vec<String>,
    addressed: bool,
    /// `dnsovertls` / `dnssec` as set on the link; `None` when never set.
    dot: Option<String>,
    dnssec: Option<String>,
}

/// resolved and iproute2 as far as the redirect sees them.
#[derive(Clone, Default)]
struct FakeResolved {
    links: Arc<Mutex<BTreeMap<String, Link>>>,
    mode: Arc<Mutex<String>>,
    /// `resolvectl dns <REDIRECT_LINK> …` refuses, simulating the step that
    /// points the link at the listener failing.
    fail_dns_claim: Arc<Mutex<bool>>,
    /// `resolvectl domain <name> …` refuses for this one link, simulating a
    /// late step (stripping `~.` from another claimant) failing after our own
    /// link already claimed the catch-all.
    fail_domain_for: Arc<Mutex<Option<String>>>,
    /// A resolved too old for per-link `dnsovertls` / `dnssec`.
    no_link_privacy: Arc<Mutex<bool>>,
}

impl FakeResolved {
    fn machine() -> Self {
        let fake = Self::default();
        *fake.mode.lock().expect("lock") = "stub".into();
        fake.add("wlp3s0", 3, &["192.0.2.1"], &[]);
        fake.add("wg0", 4, &["198.51.100.1"], &["~.", "~corp.example"]);
        fake
    }

    fn fail_dns_claim(&self) {
        *self.fail_dns_claim.lock().expect("lock") = true;
    }

    fn fail_domain_for(&self, name: &str) {
        *self.fail_domain_for.lock().expect("lock") = Some(name.to_string());
    }

    fn add(&self, name: &str, index: u32, dns: &[&str], domains: &[&str]) {
        self.links.lock().expect("lock").insert(
            name.into(),
            Link {
                index,
                dns: dns.iter().map(|s| s.to_string()).collect(),
                domains: domains.iter().map(|s| s.to_string()).collect(),
                addressed: false,
                dot: None,
                dnssec: None,
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

impl DnsCommands for FakeResolved {
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
            ("resolvectl", [setting @ ("dnsovertls" | "dnssec"), name, value]) => {
                if *self.no_link_privacy.lock().expect("lock") {
                    return failed("Unknown command verb");
                }
                match links.get_mut(*name) {
                    Some(link) => {
                        let field = if *setting == "dnssec" {
                            &mut link.dnssec
                        } else {
                            &mut link.dot
                        };
                        *field = Some((*value).into());
                        ok("")
                    }
                    None => failed("Failed to resolve interface"),
                }
            }
            ("resolvectl", ["dns", name, server]) => {
                if *self.fail_dns_claim.lock().expect("lock") {
                    return failed("Could not set per-interface DNS servers");
                }
                match links.get_mut(*name) {
                    Some(link) => {
                        link.dns = vec![(*server).into()];
                        ok("")
                    }
                    None => failed("Failed to resolve interface"),
                }
            }
            ("resolvectl", ["domain", name, rest @ ..]) => {
                if self.fail_domain_for.lock().expect("lock").as_deref() == Some(*name) {
                    return failed("Could not set per-interface domains");
                }
                match links.get_mut(*name) {
                    Some(link) => {
                        link.domains = rest
                            .iter()
                            .filter(|d| !d.is_empty())
                            .map(|d| d.to_string())
                            .collect();
                        ok("")
                    }
                    None => failed("Failed to resolve interface"),
                }
            }
            other => panic!("unexpected command {other:?}"),
        }
    }

    fn run_with_input(
        &self,
        program: &str,
        args: &[&str],
        _input: &str,
    ) -> Result<CommandReply, PlatformError> {
        panic!("unexpected command {program} {args:?} with input")
    }
}

fn taken_file(test: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix(&format!("nrr-dns-redirect-{test}-"))
        .tempdir()
        .expect("tempdir");
    let path = dir.path().join("taken.txt");
    (dir, path)
}

fn redirect(
    fake: &FakeResolved,
    test: &str,
) -> (tempfile::TempDir, ResolvedDnsRedirect<FakeResolved>) {
    let (dir, path) = taken_file(test);
    (dir, ResolvedDnsRedirect::new(fake.clone(), path))
}

#[test]
fn the_redirect_takes_every_name_and_leaves_narrow_domains_where_they_are() {
    let fake = FakeResolved::machine();
    let (_dir, redirect) = redirect(&fake, "takes");
    let handle = redirect.redirect_to(LISTENER_ADDR).expect("redirects");

    assert_eq!(fake.domains(REDIRECT_LINK), Some(vec!["~.".to_string()]));
    assert_eq!(fake.domains("wg0"), Some(vec!["~corp.example".to_string()]));
    assert_eq!(
        redirect.inspect(&handle).expect("inspects"),
        RedirectState::Active
    );
    assert_eq!(read_taken(&redirect.taken_file), vec!["wg0".to_string()]);
}

/// A machine-wide strict DoT or DNSSEC would refuse every answer of the plain,
/// unsigned listener; our link turns both off for itself, and a resolved that
/// cannot does not stop the redirect.
#[test]
fn our_link_asks_for_plain_dns_without_validation() {
    let fake = FakeResolved::machine();
    let (_dir, current) = redirect(&fake, "plain");
    current.redirect_to(LISTENER_ADDR).expect("redirects");
    let ours = fake
        .links
        .lock()
        .expect("lock")
        .get(REDIRECT_LINK)
        .cloned()
        .expect("our link");
    assert_eq!(ours.dot.as_deref(), Some("no"));
    assert_eq!(ours.dnssec.as_deref(), Some("no"));

    let old = FakeResolved::machine();
    *old.no_link_privacy.lock().expect("lock") = true;
    let (_old_dir, older) = redirect(&old, "plain-old");
    older
        .redirect_to(LISTENER_ADDR)
        .expect("an old resolved still redirects");
    assert_eq!(old.domains(REDIRECT_LINK), Some(vec!["~.".to_string()]));
}

#[test]
fn restore_gives_the_catch_all_back_and_removes_the_link() {
    let fake = FakeResolved::machine();
    let (_dir, redirect) = redirect(&fake, "restore");
    let handle = redirect.redirect_to(LISTENER_ADDR).expect("redirects");
    redirect.restore(&handle).expect("restores");

    assert_eq!(fake.domains(REDIRECT_LINK), None);
    assert_eq!(
        fake.domains("wg0"),
        Some(vec!["~corp.example".to_string(), "~.".to_string()])
    );
    assert!(!redirect.taken_file.exists());
}

/// A VPN that went away and came back as another interface under the same
/// name never held the catch-all through us: it is not handed one.
#[test]
fn a_link_reusing_a_taken_name_is_not_given_the_catch_all() {
    let fake = FakeResolved::machine();
    let (_dir, redirect) = redirect(&fake, "reused-name");
    let handle = redirect.redirect_to(LISTENER_ADDR).expect("redirects");
    fake.add("wg0", 9, &["203.0.113.1"], &["~corp.example"]);
    redirect.restore(&handle).expect("restores");
    assert_eq!(
        fake.domains("wg0"),
        Some(vec!["~corp.example".to_string()]),
        "another interface under the same name"
    );
    assert!(!redirect.indexes_file().exists());
}

#[test]
fn a_vpn_that_reclaims_every_name_is_noticed_and_redirected_again() {
    let fake = FakeResolved::machine();
    let (_dir, redirect) = redirect(&fake, "reclaim");
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
    let (_dir, file) = taken_file("orphan");
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
    let (_dir, redirect) = redirect(&fake, "gone");
    let handle = redirect.redirect_to(LISTENER_ADDR).expect("redirects");
    fake.links.lock().expect("lock").remove("wg0");
    redirect.restore(&handle).expect("restores");
    assert_eq!(fake.domains(REDIRECT_LINK), None);
}

#[test]
fn a_listener_off_the_link_is_refused_before_anything_changes() {
    let fake = FakeResolved::machine();
    let (_dir, redirect) = redirect(&fake, "refused");
    let loopback: SocketAddr = "127.0.0.1:53".parse().expect("addr");
    assert!(redirect.redirect_to(loopback).is_err());
    assert_eq!(fake.domains(REDIRECT_LINK), None);
    assert!(fake
        .domains("wg0")
        .expect("wg0")
        .contains(&"~.".to_string()));
}

#[test]
fn a_failure_claiming_the_link_removes_the_link_it_just_created() {
    // Fails right after `prepare_link` — before any domain is touched — so the
    // rollback must undo only the link creation, leaving every domain as it was.
    let fake = FakeResolved::machine();
    fake.fail_dns_claim();
    let (_dir, redirect) = redirect(&fake, "early-failure");
    assert!(redirect.redirect_to(LISTENER_ADDR).is_err());
    assert!(fake
        .links
        .lock()
        .expect("lock")
        .get(REDIRECT_LINK)
        .is_none());
    assert_eq!(
        fake.domains("wg0"),
        Some(vec!["~.".to_string(), "~corp.example".to_string()])
    );
    assert!(!redirect.taken_file.exists());
}

#[test]
fn a_late_step_failure_rolls_back_the_whole_redirect() {
    // Fails on the last step — stripping `~.` from the claimant we are
    // replacing — after our own link already holds the catch-all, the
    // listener's address, and the default route. Half a redirect (our link
    // claiming `~.` for a listener about to be torn down) is worse than none.
    let fake = FakeResolved::machine();
    fake.fail_domain_for("wg0");
    let (_dir, redirect) = redirect(&fake, "late-failure");
    assert!(redirect.redirect_to(LISTENER_ADDR).is_err());
    assert!(fake
        .links
        .lock()
        .expect("lock")
        .get(REDIRECT_LINK)
        .is_none());
    assert_eq!(
        fake.domains("wg0"),
        Some(vec!["~.".to_string(), "~corp.example".to_string()])
    );
    assert!(!redirect.taken_file.exists());
}

#[test]
fn upstream_servers_come_from_the_links_never_from_our_own() {
    let fake = FakeResolved::machine();
    let (_dir, redirect) = redirect(&fake, "servers");
    redirect.redirect_to(LISTENER_ADDR).expect("redirects");
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

/// The tunnel is read first and lists the home router's server too: per link
/// it stays the home link's as well, so barring the tunnel cannot hide it.
#[test]
fn a_server_a_tunnel_and_the_home_link_both_offer_is_listed_for_each_link() {
    let fake = FakeResolved::default();
    fake.add("wlp3s0", 3, &["192.0.2.1"], &[]);
    fake.add("wg0", 4, &["192.0.2.1", "198.51.100.1"], &["~corp.example"]);
    let servers = ResolvedDnsServers(fake);
    let home = std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let corporate = std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let per_link: Vec<(Option<u32>, std::net::IpAddr)> = servers
        .upstream_candidates_per_link()
        .into_iter()
        .map(|c| (c.interface_index, c.server))
        .collect();
    assert_eq!(
        per_link,
        vec![(Some(4), home), (Some(4), corporate), (Some(3), home)]
    );
    let plain: Vec<Ipv4Addr> = servers
        .upstream_candidates_v4()
        .into_iter()
        .map(|c| c.server)
        .collect();
    assert_eq!(
        plain,
        vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 1)],
        "the plain list still asks each server once"
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
        "Global: 192.0.2.9\nLink 2 (enp4s0f1):\nLink 4 (wg0): 198.51.100.1 192.0.2.3:53#dns.example\n",
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
        vec![Ipv4Addr::new(198, 51, 100, 1), Ipv4Addr::new(192, 0, 2, 3)]
    );
}

/// The package's maintainer scripts and the tarball's uninstall give DNS back
/// without the daemon; their copies of the marker, the file names, the
/// drop-in, the resolvconf record and the link must be the daemon's.
#[test]
fn the_maintainer_scripts_mirror_the_dns_redirect() {
    let script = include_str!("../../../../../packaging/linux/maintainer/functions.sh");
    let files = DnsFiles::system(std::path::Path::new("/var/lib/example"));
    let name = |path: std::path::PathBuf| {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(str::to_owned)
            .unwrap_or_default()
    };
    let unix = nrr_shared::product_identity::PRODUCT_NAME_UNIX;
    assert_eq!(
        REDIRECT_LINK, unix,
        "the script deletes the link by the product name"
    );
    assert_eq!(resolvconf::resolvconf_record(), format!("lo.{unix}"));
    assert_eq!(name(files.nm_drop_in()), format!("99-{unix}-dns.conf"));
    assert!(files.nm_conf_dir.starts_with("/run/NetworkManager/conf.d"));
    for line in [
        format!("  marker=\"{}\"", resolv_conf::OURS_MARKER),
        format!("  copy=\"$NRR_STATE_DIR/{}\"", name(files.system_copy())),
        format!(
            "  link_note=\"$NRR_STATE_DIR/{}\"",
            name(files.system_link())
        ),
        format!(
            "  taken=\"$NRR_STATE_DIR/{}\"",
            name(files.resolved_taken_file())
        ),
        "  drop_in=\"/run/NetworkManager/conf.d/99-$NRR_PRODUCT_NAME_UNIX-dns.conf\"".to_owned(),
        "  record=\"lo.$NRR_PRODUCT_NAME_UNIX\"".to_owned(),
        "    ip link del \"$NRR_PRODUCT_NAME_UNIX\" || failed=1".to_owned(),
    ] {
        assert!(script.lines().any(|l| l == line), "{line}");
    }
}
