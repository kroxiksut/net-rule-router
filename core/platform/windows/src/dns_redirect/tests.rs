use super::*;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// The rule table as a map; the same rules the registry store applies.
#[derive(Default)]
struct FakeStore {
    rules: Mutex<BTreeMap<String, Vec<RegistryValue>>>,
    writes: Mutex<Vec<String>>,
}
impl FakeStore {
    fn with(rules: &[(&str, Vec<RegistryValue>)]) -> Self {
        let store = Self::default();
        for (key, values) in rules {
            store
                .rules
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert((*key).to_string(), values.clone());
        }
        store
    }
    fn keys(&self) -> Vec<String> {
        self.rules
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .cloned()
            .collect()
    }
    fn writes(&self) -> Vec<String> {
        self.writes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}
fn has(values: &[RegistryValue], expected: &RegistryValue) -> bool {
    values.iter().any(|v| v == expected)
}
impl NrptRuleStore for FakeStore {
    fn write_rule(&self, key: &str, values: &[RegistryValue]) -> Result<(), PlatformError> {
        self.writes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(key.to_string());
        self.rules
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key.to_string(), values.to_vec());
        Ok(())
    }
    fn delete_rule(&self, key: &str) -> Result<bool, PlatformError> {
        Ok(self
            .rules
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(key)
            .is_some())
    }
    fn scan(&self, key: &str, expected: &[RegistryValue]) -> Result<NrptTableScan, PlatformError> {
        let rules = self.rules.lock().unwrap_or_else(|p| p.into_inner());
        let mut scan = NrptTableScan::default();
        for (name, values) in rules.iter() {
            if name == key {
                scan.ours_intact = expected.iter().all(|e| has(values, e));
            } else if !values.iter().any(|v| v.name == "Version") {
                scan.damaged += 1;
            } else if let (Some(n), Some(c)) = (
                expected.iter().find(|v| v.name == "Name"),
                expected.iter().find(|v| v.name == "Comment"),
            ) {
                scan.foreign_catch_all |= has(values, n) && !has(values, c);
            }
        }
        Ok(scan)
    }
    fn sweep_orphans(&self, marker: &str, keep: &str) -> Result<usize, PlatformError> {
        let ours = sz("Comment", marker);
        let mut rules = self.rules.lock().unwrap_or_else(|p| p.into_inner());
        let before = rules.len();
        rules.retain(|name, values| {
            let has_version = values.iter().any(|v| v.name == "Version");
            let our_marker = OUR_MARKERS.iter().any(|m| has(values, &sz("Comment", m)));
            !sweep_takes(name, has_version, our_marker, has(values, &ours), keep)
        });
        Ok(before - rules.len())
    }
}

/// A complete rule of ours, as the pre-fixed-key cmdlet era wrote it.
fn ours(ip: &str) -> Vec<RegistryValue> {
    nrpt_rule_values(ip, NRPT_MARKER)
}

/// Somebody else's complete rule — a VPN client's split-DNS suffix.
fn theirs() -> Vec<RegistryValue> {
    vec![
        sz("Comment", "AcmeVPN"),
        multi_sz("Name", ".corp.example"),
        sz("GenericDNSServers", "10.0.0.53"),
        dword("ConfigOptions", 8),
        dword("Version", 2),
    ]
}

/// A rule whose writer died after the first value.
fn half_written() -> Vec<RegistryValue> {
    vec![multi_sz("Name", ".")]
}

struct FakeRunner {
    scripts: Mutex<Vec<String>>,
    output: CommandOutput,
}
impl FakeRunner {
    fn new(output: CommandOutput) -> Self {
        Self {
            scripts: Mutex::new(Vec::new()),
            output,
        }
    }
    fn scripts(&self) -> Vec<String> {
        self.scripts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}
impl CommandRunner for FakeRunner {
    fn run_powershell(&self, script: &str) -> Result<CommandOutput, PlatformError> {
        self.scripts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(script.to_string());
        Ok(self.output.clone())
    }
}

fn ok(stdout: &str) -> CommandOutput {
    CommandOutput {
        success: true,
        stdout: stdout.to_string(),
        stderr: String::new(),
    }
}

/// Answers each script separately: the first rule whose needle the script
/// contains wins, else `default`. Keyed on CONTENT rather than call order,
/// so reordering the calls cannot make a test pass for the wrong reason.
struct ScriptedRunner {
    rules: Vec<(&'static str, CommandOutput)>,
    default: CommandOutput,
    scripts: Mutex<Vec<String>>,
}
impl ScriptedRunner {
    fn new(rules: Vec<(&'static str, CommandOutput)>) -> Self {
        Self {
            rules,
            default: ok(""),
            scripts: Mutex::new(Vec::new()),
        }
    }
    fn scripts(&self) -> Vec<String> {
        self.scripts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}
impl CommandRunner for ScriptedRunner {
    fn run_powershell(&self, script: &str) -> Result<CommandOutput, PlatformError> {
        self.scripts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(script.to_string());
        Ok(self
            .rules
            .iter()
            .find(|(needle, _)| script.contains(needle))
            .map_or_else(|| self.default.clone(), |(_, out)| out.clone()))
    }
}

/// A runner whose add succeeds and whose effective-policy query reports the
/// catch-all in force — the ordinary, accepted case.
fn accepting_runner() -> ScriptedRunner {
    ScriptedRunner::new(vec![("Get-DnsClientNrptPolicy", ok(".\n"))])
}

fn listener() -> SocketAddr {
    "127.0.0.1:53".parse().unwrap()
}

fn handle() -> RedirectHandle {
    RedirectHandle {
        marker: NRPT_MARKER.to_string(),
        listener: listener(),
    }
}

#[test]
fn capture_upstream_dns_picks_first_routable_v4_skipping_loopback() {
    let runner = FakeRunner::new(ok("127.0.0.1\n192.168.1.1\n198.51.100.8\n"));
    assert_eq!(
        capture_upstream_dns_v4(&runner),
        Some("192.168.1.1".parse().unwrap())
    );
    assert!(runner.scripts()[0].contains("Get-DnsClientServerAddress"));
}

#[test]
fn capture_upstream_dns_none_when_only_loopback_or_junk() {
    let runner = FakeRunner::new(ok("127.0.0.1\n\ngarbage\n0.0.0.0\n"));
    assert_eq!(capture_upstream_dns_v4(&runner), None);
}

#[test]
fn candidates_keep_order_and_drop_repeats() {
    // The script lists the default-route interface first and then every
    // connected one, so the preferred server legitimately appears twice.
    let runner = FakeRunner::new(ok(
        "17 192.168.0.1\n17 0.0.0.0\n17 192.168.0.1\n48 198.51.100.1\n",
    ));
    assert_eq!(
        capture_upstream_dns_candidates_v4(&runner),
        vec![
            UpstreamDnsCandidate::new(Some(17), "192.168.0.1".parse().unwrap()),
            UpstreamDnsCandidate::new(Some(48), "198.51.100.1".parse().unwrap()),
        ],
        "the caller probes down the list, so a repeat would cost a second probe"
    );
}

/// The corporate tunnel, listed first, offers the home router's server too:
/// per interface that server stays the home adapter's as well, so barring the
/// tunnel's interface cannot hide it. The plain list is unchanged.
#[test]
fn a_server_a_tunnel_and_our_adapter_both_offer_is_listed_for_each_interface() {
    let runner = FakeRunner::new(ok(concat!(
        "24\t192.168.0.1\tCorporate VPN Adapter\tCorp VPN\n",
        "24\t10.20.0.53\tCorporate VPN Adapter\tCorp VPN\n",
        "16\t192.168.0.1\tEthernet Connection (2)\tEthernet\n",
        "16\t192.168.0.1\tEthernet Connection (2)\tEthernet\n",
    )));
    let home: Ipv4Addr = "192.168.0.1".parse().unwrap();
    let corporate: Ipv4Addr = "10.20.0.53".parse().unwrap();
    assert_eq!(
        capture_upstream_dns_candidates_v4_per_link(&runner),
        vec![
            UpstreamDnsCandidate::new(Some(24), home),
            UpstreamDnsCandidate::new(Some(24), corporate),
            UpstreamDnsCandidate::new(Some(16), home),
        ],
        "each (interface, server) pair once, the default-route repeat dropped"
    );
    assert_eq!(
        capture_upstream_dns_candidates_v4(&runner),
        vec![
            UpstreamDnsCandidate::new(Some(24), home),
            UpstreamDnsCandidate::new(Some(24), corporate),
        ]
    );
}

#[test]
fn an_ipv6_server_two_interfaces_offer_is_listed_for_each() {
    let runner = FakeRunner::new(ok(concat!(
        "24\t2001:db8::53\tCorporate VPN Adapter\tCorp VPN\n",
        "16\t2001:db8::53\tEthernet Connection (2)\tEthernet\n",
    )));
    let server = IpAddr::V6("2001:db8::53".parse().unwrap());
    let indexes = |list: Vec<nrr_platform_api::dns::UpstreamDnsServer>| {
        list.into_iter()
            .map(|c| (c.interface_index, c.server))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        indexes(capture_upstream_dns_candidates_v6_per_link(&runner)),
        vec![(Some(24), server), (Some(16), server)]
    );
    assert_eq!(
        indexes(capture_upstream_dns_candidates_v6(&runner)),
        vec![(Some(24), server)]
    );
}

#[test]
fn a_candidate_line_without_an_interface_column_still_parses() {
    let runner = FakeRunner::new(ok("198.51.100.8\n"));
    assert_eq!(
        capture_upstream_dns_candidates_v4(&runner),
        vec![UpstreamDnsCandidate::new(
            None,
            "198.51.100.8".parse().unwrap()
        )],
        "a degraded emitter must not silently yield nothing"
    );
}

#[test]
fn the_candidate_script_excludes_disconnected_adapters_and_still_yields_a_list() {
    let s = upstream_dns_script();
    assert!(
        s.contains("ConnectionState -eq 'Connected'"),
        "a disconnected NIC or an idle Wi-Fi radio keeps stale static DNS"
    );
    assert!(
        s.contains("Sort-Object -Property InterfaceMetric"),
        "at boot there is no default route, so metric order is the only guess left"
    );
    assert!(
        s.contains("$live.Count -eq 0"),
        "no interface query result must not mean no candidates"
    );
}

#[test]
fn a_rule_is_the_seven_values_the_dns_client_requires() {
    let values = nrpt_rule_values("127.0.0.1", NRPT_MARKER);
    let names: Vec<_> = values.iter().map(|v| v.name).collect();
    assert_eq!(
        names,
        [
            "Comment",
            "DisplayName",
            "IPSECCARestriction",
            "Name",
            "GenericDNSServers",
            "ConfigOptions",
            "Version",
        ]
    );
    // The catch-all namespace as a one-entry list: the entry's terminator
    // plus the list's.
    assert!(has(
        &values,
        &RegistryValue {
            name: "Name",
            kind: RegistryValueKind::MultiSz,
            data: vec![b'.', 0, 0, 0, 0, 0],
        }
    ));
    assert!(has(
        &values,
        &RegistryValue {
            name: "GenericDNSServers",
            kind: RegistryValueKind::Sz,
            data: "127.0.0.1\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    ));
    assert!(has(&values, &dword("ConfigOptions", 8)));
    assert!(has(&values, &dword("Version", 2)));
    assert!(has(&values, &sz("Comment", NRPT_MARKER)));
}

#[test]
fn redirect_writes_our_rule_under_its_fixed_key_without_waiting_on_a_process() {
    // The OS sends names to the listener from the moment the key is written;
    // a process run before the call returns is that long without answers.
    let redirect = NrptDnsRedirect::new(accepting_runner(), FakeStore::default());
    let h = redirect.redirect_to(listener()).expect("redirect");
    assert_eq!(h.marker, NRPT_MARKER);
    assert_eq!(h.listener, listener());
    assert_eq!(redirect.store.writes(), [NRPT_RULE_KEY]);
    assert_eq!(redirect.store.keys(), [NRPT_RULE_KEY]);
    assert!(redirect.runner.scripts().is_empty());
    assert_eq!(
        redirect.confirm(&h).expect("confirm"),
        RedirectState::Active
    );
    assert!(
        redirect.runner.scripts()[0].contains("Get-DnsClientNrptPolicy"),
        "a successful write is still confirmed against the table in force"
    );
}

#[test]
fn redirect_clears_the_debris_that_would_have_the_table_rejected() {
    // A half-written rule of ours and a copy of ours under a random key (the
    // cmdlet era) both go; the VPN client's rule stays.
    let store = FakeStore::with(&[
        ("{NRR-EXEMPT-0000000000000001}", half_written()),
        ("{OLD-OURS}", ours("127.0.0.1")),
        ("{VPN}", theirs()),
    ]);
    let redirect = NrptDnsRedirect::new(accepting_runner(), store);
    redirect.redirect_to(listener()).expect("redirect");
    assert_eq!(redirect.store.keys(), [NRPT_RULE_KEY, "{VPN}"]);
}

#[test]
fn confirm_tells_a_refused_rule_from_an_unreadable_table() {
    // The rule IS written; the effective table comes back empty: Windows
    // evaluated the rule and refused it, and the caller withdraws it.
    let refused = NrptDnsRedirect::new(
        ScriptedRunner::new(vec![(
            "Get-DnsClientNrptPolicy",
            ok("   
"),
        )]),
        FakeStore::default(),
    );
    let h = refused.redirect_to(listener()).expect("redirect");
    assert_eq!(
        refused.confirm(&h).expect("confirm"),
        RedirectState::Inactive
    );

    // The query itself failed. That is not a rejection, and treating it as
    // one would disable Mode B on every host where the cmdlet is missing.
    let unreadable = NrptDnsRedirect::new(
        ScriptedRunner::new(vec![(
            "Get-DnsClientNrptPolicy",
            CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "cmdlet not found".into(),
            },
        )]),
        FakeStore::default(),
    );
    let h = unreadable.redirect_to(listener()).expect("redirect");
    assert!(unreadable.confirm(&h).is_err());
    assert_eq!(unreadable.store.keys(), [NRPT_RULE_KEY]);
}

#[test]
fn clear_orphan_counts_our_rule_and_the_debris_but_not_a_stranger() {
    let store = FakeStore::with(&[
        (NRPT_RULE_KEY, ours("127.0.0.1")),
        ("{NRR-KEEP-0000000000000001}", half_written()),
        ("{OLD-OURS}", ours("127.0.0.1")),
        ("{VPN}", theirs()),
    ]);
    assert_eq!(clear_orphan_redirect(&store).expect("clear"), 3);
    assert_eq!(store.keys(), ["{VPN}"]);
    // Nothing to clean is a successful sweep of zero, not a failure.
    assert_eq!(clear_orphan_redirect(&store).expect("clear"), 0);
}

/// Another program's rule without a `Version` may be one it is still writing,
/// or one it keeps that way: deleting it breaks that program's names. Only a
/// rule of ours — by its key or its marker — is ours to take back half-written.
#[test]
fn a_strangers_rule_without_a_version_survives_every_sweep() {
    let ours_half = |marker: &str| vec![sz("Comment", marker), multi_sz("Name", ".")];
    let store = FakeStore::with(&[
        ("{STRANGER-HALF}", half_written()),
        (NRPT_RULE_KEY, half_written()),
        ("{NRR-KEEP-0000000000000001}", half_written()),
        ("{OLD-OURS-HALF}", ours_half(NRPT_MARKER)),
        ("{OLD-EXEMPT-HALF}", ours_half(NRPT_EXEMPT_MARKER)),
        ("{VPN}", theirs()),
    ]);
    clear_orphan_redirect(&store).expect("clear");
    assert_eq!(store.keys(), ["{STRANGER-HALF}", "{VPN}"]);

    let redirect = NrptDnsRedirect::new(
        accepting_runner(),
        FakeStore::with(&[("{STRANGER-HALF}", half_written()), ("{VPN}", theirs())]),
    );
    redirect.redirect_to(listener()).expect("redirect");
    redirect.restore(&handle()).expect("restore");
    assert_eq!(redirect.store.keys(), ["{STRANGER-HALF}", "{VPN}"]);
}

/// The teardown's only process spawn used to be here. The NRPT restore
/// beside it is a single registry delete, so this flush was the whole
/// reason the stop step needed a multi-second budget.
#[test]
fn flushing_the_cache_calls_the_api_and_spawns_no_process() {
    #[derive(Default)]
    struct CountingFlush(std::sync::atomic::AtomicUsize);
    impl DnsCacheControlPort for CountingFlush {
        fn flush_resolver_cache(&self) -> Result<(), nrr_platform_api::dns::DnsCacheFlushError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    let flush = Arc::new(CountingFlush::default());
    let redirect = NrptDnsRedirect::with_cache_control(
        FakeRunner::new(ok("")),
        FakeStore::default(),
        flush.clone(),
    );
    redirect.flush_cache().expect("flush");
    assert_eq!(flush.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        redirect.runner.scripts().is_empty(),
        "the flush must not run PowerShell"
    );
}

#[test]
fn restore_deletes_only_our_key_and_spawns_nothing() {
    let store = FakeStore::with(&[(NRPT_RULE_KEY, ours("127.0.0.1")), ("{VPN}", theirs())]);
    let redirect = NrptDnsRedirect::new(FakeRunner::new(ok("")), store);
    redirect.restore(&handle()).expect("restore");
    assert_eq!(redirect.store.keys(), ["{VPN}"]);
    assert!(redirect.runner.scripts().is_empty());
    redirect
        .restore(&handle())
        .expect("restoring twice is a no-op");
}

/// The list exists only for the catch-all; it leaves with it.
#[test]
fn restore_takes_back_the_search_list_the_redirect_wrote() {
    let list = Arc::new(search_list::FakeList::default());
    let redirect = NrptDnsRedirect::new(FakeRunner::new(ok("")), FakeStore::default())
        .with_search_list(list.clone());

    redirect
        .keep_short_names(
            &[exemption("branch.corp.example", &["192.168.0.53"])],
            &Vec::new,
        )
        .expect("keep");
    assert_eq!(
        list.read().expect("read").global,
        ["branch.corp.example".to_string()]
    );
    redirect.restore(&handle()).expect("restore");
    assert!(list.read().expect("read").global.is_empty());
    assert!(list.noted().is_empty());
}

/// Where a list write needs a child process, the restore does not wait for it:
/// the catch-all is gone on return, the list is cleared behind it, and the next
/// sync waits for that clearing instead of racing it.
#[test]
fn a_slow_list_write_never_holds_up_the_restore() {
    let (open, gate) = std::sync::mpsc::channel();
    let list = Arc::new(search_list::FakeList::behind_a_process(gate));
    let store = FakeStore::with(&[(NRPT_RULE_KEY, ours("127.0.0.1"))]);
    let redirect =
        NrptDnsRedirect::new(FakeRunner::new(ok("")), store).with_search_list(list.clone());
    open.send(()).expect("open for the arm");
    redirect
        .keep_short_names(
            &[exemption("branch.corp.example", &["192.168.0.53"])],
            &Vec::new,
        )
        .expect("keep");
    assert_eq!(list.writes(), 1);

    redirect.restore(&handle()).expect("restore");
    assert!(
        redirect.store.keys().is_empty(),
        "the catch-all goes before the list is touched"
    );
    assert_eq!(
        list.writes(),
        1,
        "the restore returned while the write waits"
    );

    open.send(()).expect("let the clearing through");
    redirect
        .keep_short_names(&[], &Vec::new)
        .expect("a sync after the restore");
    assert_eq!(list.writes(), 2, "the sync waited for the clearing");
    assert!(list.read().expect("read").global.is_empty());
    assert!(list.noted().is_empty());
}

/// The list is built from the claims the caller exempted, and the user's
/// suffixes are asked for once per sync.
#[test]
fn the_list_follows_the_exempted_claims_and_asks_the_users_suffixes_once() {
    let list = Arc::new(search_list::FakeList::default());
    let redirect = NrptDnsRedirect::new(FakeRunner::new(ok("")), FakeStore::default())
        .with_search_list(list.clone());
    let asked = std::sync::atomic::AtomicUsize::new(0);
    let users = || {
        asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        vec!["lab.example".to_string()]
    };
    redirect
        .keep_short_names(
            &[exemption("branch.corp.example", &["192.168.0.53"])],
            &users,
        )
        .expect("keep");
    assert_eq!(
        list.read().expect("read").global,
        ["branch.corp.example".to_string(), "lab.example".to_string()]
    );
    assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn without_a_search_list_short_names_are_left_as_they_were() {
    let redirect = NrptDnsRedirect::new(FakeRunner::new(ok("")), FakeStore::default());
    let asked = std::sync::atomic::AtomicBool::new(false);
    redirect
        .keep_short_names(
            &[exemption("branch.corp.example", &["192.168.0.53"])],
            &|| {
                asked.store(true, std::sync::atomic::Ordering::SeqCst);
                vec!["lab.example".to_string()]
            },
        )
        .expect("keep");
    assert!(redirect.runner.scripts().is_empty());
    assert!(
        !asked.load(std::sync::atomic::Ordering::SeqCst),
        "no list, no settings read"
    );
}

fn exemption(suffix: &str, servers: &[&str]) -> DnsNamespaceExemption {
    DnsNamespaceExemption {
        suffix: suffix.to_string(),
        servers: servers.iter().map(|s| s.parse().expect("ip")).collect(),
    }
}

/// The field case: a corporate VPN claims its own domain, and the product
/// must stop answering for it. The rule sits BESIDE the catch-all and wins
/// for those names because its namespace is narrower.
#[test]
fn a_claimed_namespace_gets_its_own_rule_beside_the_catch_all() {
    let store = FakeStore::with(&[(NRPT_RULE_KEY, ours("127.0.0.1"))]);
    let redirect = NrptDnsRedirect::new(FakeRunner::new(ok("")), store);
    let written = redirect
        .exempt_namespaces(&[exemption("branch.corp.example", &["192.168.0.53"])])
        .expect("exempt");
    assert_eq!(written, 1);

    let key = nrpt_exemption_key("branch.corp.example");
    let mut keys = redirect.store.keys();
    keys.sort();
    let mut expected = vec![NRPT_RULE_KEY.to_string(), key.clone()];
    expected.sort();
    assert_eq!(keys, expected, "the catch-all stays");

    let rules = redirect
        .store
        .rules
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let values = rules.get(&key).expect("the exemption rule");
    assert!(has(values, &multi_sz("Name", ".branch.corp.example")));
    assert!(has(values, &sz("GenericDNSServers", "192.168.0.53")));
    assert!(has(values, &sz("Comment", NRPT_EXEMPT_MARKER)));
    assert!(
        has(values, &dword("Version", NRPT_RULE_VERSION)),
        "a rule without a version makes the DNS client reject the whole table",
    );
}

/// The set is replaced, not added to. A VPN that disconnected stops
/// claiming its namespace, and a rule pointing at a resolver that is no
/// longer reachable resolves every name under it to nothing.
#[test]
fn a_namespace_that_is_no_longer_claimed_stops_being_exempt() {
    let redirect = NrptDnsRedirect::new(
        FakeRunner::new(ok("")),
        FakeStore::with(&[(NRPT_RULE_KEY, ours("127.0.0.1"))]),
    );
    redirect
        .exempt_namespaces(&[
            exemption("corp.a.example", &["10.0.0.1"]),
            exemption("corp.b.example", &["10.0.0.2"]),
        ])
        .expect("exempt");
    assert_eq!(redirect.store.keys().len(), 3);

    let left = redirect
        .exempt_namespaces(&[exemption("corp.a.example", &["10.0.0.1"])])
        .expect("exempt");
    assert_eq!(left, 1);
    let mut keys = redirect.store.keys();
    keys.sort();
    let mut expected = vec![
        NRPT_RULE_KEY.to_string(),
        nrpt_exemption_key("corp.a.example"),
    ];
    expected.sort();
    assert_eq!(keys, expected);

    // Nothing claimed at all: we answer for everything again.
    assert_eq!(redirect.exempt_namespaces(&[]).expect("exempt"), 0);
    assert_eq!(redirect.store.keys(), [NRPT_RULE_KEY.to_string()]);
}

/// A rule host inside a namespace left to another resolver stays with us: its
/// rule outranks the exemption, and the DNS client prefers the longer name.
#[test]
fn a_kept_rule_host_gets_its_own_rule_pointing_at_the_listener() {
    let redirect = NrptDnsRedirect::new(
        FakeRunner::new(ok("")),
        FakeStore::with(&[(NRPT_RULE_KEY, ours("127.0.0.1"))]),
    );
    redirect
        .exempt_namespaces(&[exemption("corp.example", &["10.0.0.1"])])
        .expect("exempt");
    let kept = redirect
        .keep_names(&["git.corp.example".to_string()], listener())
        .expect("keep");
    assert_eq!(kept, 1);
    let key = nrpt_keep_key("git.corp.example");
    let rules = redirect
        .store
        .rules
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let values = rules.get(&key).expect("the keep rule");
    assert!(has(
        values,
        &multi_sz_list(
            "Name",
            &[
                "git.corp.example".to_string(),
                ".git.corp.example".to_string()
            ]
        )
    ));
    assert!(has(values, &sz("GenericDNSServers", "127.0.0.1")));
    assert!(has(values, &sz("Comment", NRPT_KEEP_MARKER)));
    assert!(
        rules.contains_key(&nrpt_exemption_key("corp.example")),
        "the exemption stays beside it"
    );
    drop(rules);

    // The next set replaces the last one; none takes them all out.
    assert_eq!(redirect.keep_names(&[], listener()).expect("keep"), 0);
    assert!(!redirect.store.keys().contains(&key));
}

/// Stopping must leave the machine as it was found. An exemption outliving
/// the service would keep steering names at a resolver nobody watches.
#[test]
fn restoring_takes_the_exemptions_out_with_the_catch_all() {
    let redirect = NrptDnsRedirect::new(
        FakeRunner::new(ok("")),
        FakeStore::with(&[(NRPT_RULE_KEY, ours("127.0.0.1")), ("{VPN}", theirs())]),
    );
    redirect
        .exempt_namespaces(&[exemption("corp.example.com", &["10.0.0.1"])])
        .expect("exempt");
    redirect
        .keep_names(&["git.corp.example.com".to_string()], listener())
        .expect("keep");
    redirect.restore(&handle()).expect("restore");
    assert_eq!(
        redirect.store.keys(),
        ["{VPN}"],
        "somebody else's rule is never ours to remove",
    );
}

/// A claim with no server is not a claim. Writing the rule anyway would
/// send the namespace to an empty server list, which resolves nothing.
#[test]
fn a_claim_without_servers_is_skipped_rather_than_written_empty() {
    let redirect = NrptDnsRedirect::new(
        FakeRunner::new(ok("")),
        FakeStore::with(&[(NRPT_RULE_KEY, ours("127.0.0.1"))]),
    );
    let written = redirect
        .exempt_namespaces(&[exemption("corp.example.com", &[])])
        .expect("exempt");
    assert_eq!(written, 0);
    assert_eq!(redirect.store.keys(), [NRPT_RULE_KEY.to_string()]);
}

/// The same claim must land on the same key, so a reconnecting VPN replaces
/// its own rule instead of leaving one behind per session.
#[test]
fn an_exemption_key_is_stable_for_a_namespace_and_distinct_between_them() {
    assert_eq!(
        nrpt_exemption_key("corp.example.com"),
        nrpt_exemption_key("corp.example.com"),
    );
    assert_ne!(
        nrpt_exemption_key("corp.example.com"),
        nrpt_exemption_key("corp.example.net"),
    );
    let key = nrpt_exemption_key("corp.example.com");
    assert!(key.starts_with("{NRR-EXEMPT-") && key.ends_with('}'));
}

#[test]
fn inspect_reads_our_configuration_and_the_table_around_it() {
    fn inspect(store: FakeStore) -> RedirectState {
        let redirect = NrptDnsRedirect::new(FakeRunner::new(ok("")), store);
        let state = redirect.inspect(&handle()).expect("inspect");
        assert!(
            redirect.runner.scripts().is_empty(),
            "the guard's check must never cost a process"
        );
        state
    }
    assert_eq!(
        inspect(FakeStore::with(&[
            (NRPT_RULE_KEY, ours("127.0.0.1")),
            ("{VPN}", theirs()),
        ])),
        RedirectState::Active
    );
    // Ours gone.
    assert_eq!(
        inspect(FakeStore::with(&[("{VPN}", theirs())])),
        RedirectState::Inactive
    );
    // Ours intact, but a half-written stranger has the whole table rejected.
    assert_eq!(
        inspect(FakeStore::with(&[
            (NRPT_RULE_KEY, ours("127.0.0.1")),
            ("{HALF}", half_written()),
        ])),
        RedirectState::Inactive
    );
    // Ours edited to point elsewhere is not ours.
    assert_eq!(
        inspect(FakeStore::with(&[(NRPT_RULE_KEY, ours("10.0.0.1"))])),
        RedirectState::Inactive
    );
}

#[test]
fn verify_asks_the_effective_policy_table_not_our_own_write() {
    let redirect = NrptDnsRedirect::new(FakeRunner::new(ok(".\n")), FakeStore::default());
    assert_eq!(
        redirect.verify(&handle()).expect("verify"),
        RedirectState::Active
    );
    let script = &redirect.runner.scripts()[0];
    assert!(
        script.contains("Get-DnsClientNrptPolicy"),
        "reading back our own configuration can only answer 'present'"
    );
    assert!(
        !script.contains("Get-DnsClientNrptRule"),
        "the configured table is the wrong source for 'is it in effect'"
    );
    assert!(
        script.contains("127.0.0.1"),
        "the redirect is ours only if the policy points at OUR listener"
    );

    // Nothing in force → Inactive.
    assert_eq!(
        NrptDnsRedirect::new(FakeRunner::new(ok("")), FakeStore::default())
            .verify(&handle())
            .expect("verify"),
        RedirectState::Inactive
    );

    // A query that could not run is an error, not "Inactive".
    assert!(NrptDnsRedirect::new(
        FakeRunner::new(CommandOutput {
            success: false,
            stdout: String::new(),
            stderr: "denied".into(),
        }),
        FakeStore::default()
    )
    .verify(&handle())
    .is_err());
}

#[test]
fn upstream_candidates_drop_hypervisor_networks_and_our_own_pool() {
    let runner = FakeRunner::new(ok(concat!(
            "16\t192.168.0.1\tEthernet Connection (2)\tEthernet\n",
            "24\t198.51.100.1\tTAP-Windows Adapter V9\texamplevpn VPN OpenVPN Adapter\n",
            "4\t192.168.140.2\tVMware Virtual Ethernet Adapter for VMnet8\tVMware Network Adapter VMnet8\n",
            "28\t172.20.80.1\tHyper-V Virtual Ethernet Adapter\tvEthernet (Default Switch)\n",
            "14\t192.168.56.1\tVirtualBox Host-Only Ethernet Adapter\tVirtualBox Host-Only Network\n",
            "57\t198.18.0.1\tNetRuleRouter Tunnel\tNetRuleRouter\n",
        )));
    assert_eq!(
        capture_upstream_dns_candidates_v4(&runner),
        vec![
            UpstreamDnsCandidate::new(Some(16), "192.168.0.1".parse().unwrap()),
            UpstreamDnsCandidate::new(Some(24), "198.51.100.1".parse().unwrap()),
        ],
        "a hypervisor's NAT/host-only resolver answers its guests and black-holes \
             us; our own TUN would point the resolver at itself; a VPN's resolver is \
             a legitimate upstream and must survive"
    );
}

#[test]
fn an_unnamed_adapter_still_yields_its_candidate() {
    // Names we could not read must not cost us the last real upstream.
    let runner = FakeRunner::new(ok("16\t192.168.0.1\t\t\n"));
    assert_eq!(
        capture_upstream_dns_candidates_v4(&runner),
        vec![UpstreamDnsCandidate::new(
            Some(16),
            "192.168.0.1".parse().unwrap()
        )]
    );
}

/// Every NRPT call fails, as on a registry the sweep cannot open.
struct UnreachableNrpt;
impl NrptRuleStore for UnreachableNrpt {
    fn write_rule(&self, _: &str, _: &[RegistryValue]) -> Result<(), PlatformError> {
        Err(unreachable_nrpt())
    }
    fn delete_rule(&self, _: &str) -> Result<bool, PlatformError> {
        Err(unreachable_nrpt())
    }
    fn scan(&self, _: &str, _: &[RegistryValue]) -> Result<NrptTableScan, PlatformError> {
        Err(unreachable_nrpt())
    }
    fn sweep_orphans(&self, _: &str, _: &str) -> Result<usize, PlatformError> {
        Err(unreachable_nrpt())
    }
}
fn unreachable_nrpt() -> PlatformError {
    PlatformError::Transient {
        operation: "test.nrpt",
        detail: "unreachable".into(),
    }
}

#[test]
fn a_failed_nrpt_sweep_still_takes_back_our_suffix_list() {
    let list = search_list::FakeList::default();
    let ours = vec!["corp.example".to_string()];
    list.write(&ours).expect("seed");
    list.note(&ours).expect("seed");

    let sweep = sweep_orphan_dns_state(&UnreachableNrpt, &list);

    assert!(sweep.nrpt_rules.is_err());
    assert!(matches!(sweep.search_list, Ok(true)));
    assert!(list.read().expect("read").global.is_empty());
    assert!(!sweep.is_clean(), "one failed half makes the sweep unclean");
}

#[test]
fn a_sweep_with_nothing_left_behind_is_clean() {
    let sweep = sweep_orphan_dns_state(&FakeStore::default(), &search_list::FakeList::default());
    assert!(matches!(sweep.nrpt_rules, Ok(0)));
    assert!(matches!(sweep.search_list, Ok(false)));
    assert!(sweep.is_clean());
}

/// The emergency reset and the uninstaller sweep without the binary; their
/// shared copy of the markers and of our rule's key must be the service's.
#[test]
fn the_script_sweep_mirrors_the_markers_and_the_rule_key() {
    let library = include_str!("../../../../../scripts/lib/service-paths.ps1");
    for (name, value) in [
        ("$NrrNrptMarker", NRPT_MARKER),
        ("$NrrNrptExemptMarker", NRPT_EXEMPT_MARKER),
        ("$NrrNrptKeepMarker", NRPT_KEEP_MARKER),
        ("$NrrNrptRuleKey", NRPT_RULE_KEY),
    ] {
        let line = format!("{name} = '{value}'");
        assert!(library.lines().any(|l| l == line), "{line}");
    }
    // Both callers go through that one sweep rather than carrying a copy.
    for script in [
        include_str!("../../../../../scripts/reset-network.ps1"),
        include_str!("../../../../../packaging/windows/setup-actions.ps1"),
    ] {
        assert!(script.contains("Remove-NrrDnsRedirect"));
        assert!(!script.contains("Get-DnsClientNrptRule"));
    }
}

#[test]
fn a_foreign_catch_all_is_told_apart_from_our_own_and_from_suffix_rules() {
    fn scan(store: &FakeStore) -> NrptTableScan {
        store
            .scan(NRPT_RULE_KEY, &nrpt_rule_values("127.0.0.1", NRPT_MARKER))
            .expect("scan")
    }
    let foreign = vec![
        sz("Comment", "OtherAgent"),
        multi_sz("Name", "."),
        sz("GenericDNSServers", "203.0.113.9"),
        dword("ConfigOptions", 8),
        dword("Version", 2),
    ];
    assert!(scan(&FakeStore::with(&[("{OTHER}", foreign)])).foreign_catch_all);
    assert!(
        !scan(&FakeStore::with(&[
            (NRPT_RULE_KEY, ours("127.0.0.1")),
            ("{VPN}", theirs()),
        ]))
        .foreign_catch_all,
        "a suffix rule and our own catch-all are not a rival"
    );
    // A stale copy of ours under another key is ours, swept at the next redirect.
    assert!(!scan(&FakeStore::with(&[("{OLD}", ours("127.0.0.1"))])).foreign_catch_all);
}

#[test]
fn a_foreign_catch_all_reaches_the_status_card_while_it_competes_with_ours() {
    static FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let foreign = vec![
        sz("Comment", "OtherAgent"),
        multi_sz("Name", "."),
        sz("GenericDNSServers", "203.0.113.9"),
        dword("ConfigOptions", 8),
        dword("Version", 2),
    ];
    let redirect = NrptDnsRedirect::new(
        accepting_runner(),
        FakeStore::with(&[("{OTHER}", foreign.clone())]),
    )
    .with_notice_flag(&FLAG);
    assert!(slugs_from(&FLAG).is_empty());

    let handle = redirect.redirect_to(listener()).expect("redirect");
    assert_eq!(slugs_from(&FLAG), [FOREIGN_CATCH_ALL_SLUG]);

    // The other program withdraws its rule: the guard's next look drops the notice.
    redirect
        .store
        .rules
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove("{OTHER}");
    redirect.inspect(&handle).expect("inspect");
    assert!(slugs_from(&FLAG).is_empty());

    // It comes back, then our redirect is lifted: nothing is left to compete with.
    redirect
        .store
        .rules
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert("{OTHER}".to_string(), foreign);
    redirect.inspect(&handle).expect("inspect");
    assert_eq!(slugs_from(&FLAG), [FOREIGN_CATCH_ALL_SLUG]);
    redirect.restore(&handle).expect("restore");
    assert!(slugs_from(&FLAG).is_empty());
}

#[test]
fn the_foreign_catch_all_notice_has_its_texts_in_every_bundled_language() {
    for (language, text) in [
        ("en", include_str!("../../../../../locales/en.json")),
        ("ru", include_str!("../../../../../locales/ru.json")),
    ] {
        let catalog: serde_json::Value = serde_json::from_str(text).expect("locale file");
        let notice = &catalog["platform"]["missing"][FOREIGN_CATCH_ALL_SLUG];
        for field in ["title", "effect"] {
            assert!(
                notice[field].as_str().is_some_and(|s| !s.is_empty()),
                "{language}: platform.missing.{FOREIGN_CATCH_ALL_SLUG}.{field}"
            );
        }
    }
}

#[test]
fn a_changed_exemption_set_rewrites_only_what_differs() {
    let redirect = NrptDnsRedirect::new(
        FakeRunner::new(ok("")),
        FakeStore::with(&[(NRPT_RULE_KEY, ours("127.0.0.1"))]),
    );
    let a = exemption("corp.a.example", &["10.0.0.1"]);
    let b = exemption("corp.b.example", &["10.0.0.2"]);
    redirect
        .exempt_namespaces(&[a.clone(), b.clone()])
        .expect("exempt");
    let before = redirect.store.writes().len();

    // Unchanged set: nothing is written, nothing is erased.
    assert_eq!(
        redirect
            .exempt_namespaces(&[a.clone(), b.clone()])
            .expect("exempt"),
        2
    );
    assert_eq!(redirect.store.writes().len(), before);

    // One server list changes: only that rule is written, the other stays put.
    let b2 = exemption("corp.b.example", &["10.0.0.9"]);
    assert_eq!(redirect.exempt_namespaces(&[a, b2]).expect("exempt"), 2);
    assert_eq!(
        redirect.store.writes(),
        [
            redirect.store.writes()[..before].to_vec(),
            vec![nrpt_exemption_key("corp.b.example")]
        ]
        .concat()
    );
}
