//! What the DNS redirect steps out of, decided from the claims the OS reports,
//! the administrator's suffix list and the rule books.
//!
//! The decision itself is pure and lives in `nrr_platform_api::dns_scope`;
//! this module feeds it from the service's stores and carries the result to
//! the two places it goes: the exemptions the resolver service hands to the
//! redirect port, and the rule names kept with the listener, written here
//! because the same read decides both.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nrr_platform_api::dns::SystemDnsServersPort;
use nrr_platform_api::dns_redirect::{DnsNamespaceExemption, SystemDnsRedirectPort};
use nrr_platform_api::dns_scope::{plan_namespaces, ClaimedNamespace, ClaimingLink, NamespacePlan};
use rusqlite::Connection;

use crate::foreign_tunnels::ForeignTunnelCell;
use crate::local_dns_suffixes::MachineLocalDnsSuffixes;
use crate::per_sid_orchestrator::RulesProvider;

/// Every live connection's claim, read fresh on each call.
pub type ClaimsFn = Arc<dyn Fn() -> Vec<ClaimedNamespace> + Send + Sync>;

/// The main link's resolvers are asked for with this much patience: the
/// guard runs on its own thread, and a lease the OS has not listed yet is
/// worth a short wait.
const LOCAL_SERVERS_BUDGET: Duration = Duration::from_millis(300);

pub struct NamespacePolicy {
    claims: ClaimsFn,
    suffixes: &'static MachineLocalDnsSuffixes,
    system_dns: Arc<dyn SystemDnsServersPort>,
    redirect: Arc<dyn SystemDnsRedirectPort>,
    listener: SocketAddr,
    rules: Arc<dyn RulesProvider>,
    settings_conn: Arc<Mutex<Connection>>,
    kept: Mutex<Kept>,
    foreign_tunnels: Arc<ForeignTunnelCell>,
}

#[derive(Default)]
struct Kept {
    names: Vec<String>,
    last_error: Option<String>,
}

impl NamespacePolicy {
    pub fn new(
        claims: ClaimsFn,
        suffixes: &'static MachineLocalDnsSuffixes,
        system_dns: Arc<dyn SystemDnsServersPort>,
        redirect: Arc<dyn SystemDnsRedirectPort>,
        listener: SocketAddr,
        rules: Arc<dyn RulesProvider>,
        settings_conn: Arc<Mutex<Connection>>,
    ) -> Self {
        Self {
            claims,
            suffixes,
            system_dns,
            redirect,
            listener,
            rules,
            settings_conn,
            kept: Mutex::new(Kept::default()),
            foreign_tunnels: crate::foreign_tunnels::global_foreign_tunnels(),
        }
    }

    /// Publish the claims into `cell` instead of the process-wide one.
    #[must_use]
    pub fn with_foreign_tunnels(mut self, cell: Arc<ForeignTunnelCell>) -> Self {
        self.foreign_tunnels = cell;
        self
    }

    /// The namespaces to step out of now. Also publishes what the main link
    /// offers and keeps the covered rule names with the listener.
    pub fn exemptions(&self) -> Vec<DnsNamespaceExemption> {
        // The coordinator's set upgrades a claim to a foreign tunnel. An OS-typed
        // tunnel is foreign unless it is one of the served users' own links
        // (`ours`), which the classifier excludes.
        let claims: Vec<ClaimedNamespace> = (self.claims)()
            .into_iter()
            .map(|mut claim| {
                if self.foreign_tunnels.names_adapter(&claim.scope.adapter_id) {
                    claim.link = ClaimingLink::ForeignTunnel;
                }
                claim
            })
            .collect();
        self.foreign_tunnels.publish_claims(
            claims
                .iter()
                .filter(|c| nrr_platform_api::dns_scope::is_actionable_scope(&c.scope))
                .filter_map(|c| {
                    nrr_platform_api::dns_scope::normalize_suffix(&c.scope.suffix)
                        .map(|suffix| (c.scope.adapter_id.clone(), suffix))
                })
                .collect(),
        );
        let list = self.suffixes.current();
        let local_servers: Vec<Ipv4Addr> = self
            .system_dns
            .upstream_candidates_v4_within(LOCAL_SERVERS_BUDGET)
            .into_iter()
            .map(|candidate| candidate.server)
            .collect();
        let hosts = self.every_rule_host();
        let plan = plan_namespaces(&claims, &list, &local_servers, &hosts);
        self.suffixes.publish_offered(plan.offered.clone());
        self.keep(&plan);
        plan.exempt
    }

    /// Hand the kept names to the port only when they changed, and say once
    /// when that fails.
    fn keep(&self, plan: &NamespacePlan) {
        let mut kept = self.kept.lock().unwrap_or_else(|p| p.into_inner());
        if kept.names == plan.keep && kept.last_error.is_none() {
            return;
        }
        match self.redirect.keep_names(&plan.keep, self.listener) {
            Ok(_) => {
                kept.names.clone_from(&plan.keep);
                kept.last_error = None;
            }
            Err(error) => {
                let text = error.to_string();
                if kept.last_error.as_deref() != Some(text.as_str()) {
                    tracing::warn!(
                        target: "nrr::dns-resolver",
                        msg_key = "dns-resolver-keep-names-failed",
                        error = %text,
                        "Mode B: could not keep rule hosts inside a left namespace with the resolver",
                    );
                    kept.last_error = Some(text);
                }
            }
        }
    }

    /// The names every user's rules mention: the redirect is one per machine,
    /// so a name under anyone's rule stays with the listener.
    fn every_rule_host(&self) -> Vec<String> {
        let principals = {
            let conn = self.settings_conn.lock().unwrap_or_else(|p| p.into_inner());
            nrr_storage::principals_with_state(&conn).unwrap_or_default()
        };
        let mut hosts: Vec<String> = principals
            .iter()
            .filter_map(|principal| self.rules.active_rules_for(principal))
            .flat_map(|snapshot| crate::rule_book_facts::rule_host_names(&snapshot.rule_book))
            .collect();
        hosts.sort_unstable();
        hosts.dedup();
        hosts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::per_sid_orchestrator::ActiveRulesSnapshot;
    use nrr_domain::canonical::{
        CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
    };
    use nrr_domain::{RuleAction, RuleId};
    use nrr_platform_api::dns::StaticDnsServers;
    use nrr_platform_api::dns_redirect::{RedirectHandle, RedirectState};
    use nrr_platform_api::dns_scope::InterfaceDnsScope;
    use nrr_platform_api::error::PlatformError;
    use nrr_storage::route_bindings::{BindingSource, RouteBindingsRepository, RoutePolicyRecord};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Records every set handed to the port; refuses while `fail` is set.
    #[derive(Default)]
    struct FakeRedirect {
        kept: Mutex<Vec<Vec<String>>>,
        fail: AtomicBool,
    }

    impl SystemDnsRedirectPort for FakeRedirect {
        fn redirect_to(&self, listener: SocketAddr) -> Result<RedirectHandle, PlatformError> {
            Ok(RedirectHandle {
                marker: String::new(),
                listener,
            })
        }
        fn restore(&self, _: &RedirectHandle) -> Result<(), PlatformError> {
            Ok(())
        }
        fn verify(&self, _: &RedirectHandle) -> Result<RedirectState, PlatformError> {
            Ok(RedirectState::Active)
        }
        fn keep_names(&self, names: &[String], _: SocketAddr) -> Result<usize, PlatformError> {
            self.kept
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(names.to_vec());
            if self.fail.load(Ordering::SeqCst) {
                return Err(PlatformError::Transient {
                    operation: "keep",
                    detail: "busy".into(),
                });
            }
            Ok(names.len())
        }
    }

    impl FakeRedirect {
        fn writes(&self) -> Vec<Vec<String>> {
            self.kept.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }
    }

    /// One book for every principal.
    struct Book(CanonicalRuleBook);

    impl RulesProvider for Book {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            Some(ActiveRulesSnapshot {
                rule_book: self.0.clone(),
            })
        }
    }

    fn book_naming(host: &str) -> CanonicalRuleBook {
        CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(Vec::new()),
            secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                id: RuleId("s1".into()),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::ExactFqdn(host.into())),
                app_match: None,
                comment: String::new(),
                action: RuleAction::Route,
                origin: None,
            }]),
        }
    }

    fn claim(adapter: &str, suffix: &str, link: ClaimingLink) -> ClaimedNamespace {
        ClaimedNamespace {
            scope: InterfaceDnsScope {
                adapter_id: adapter.into(),
                display_name: adapter.into(),
                suffix: suffix.into(),
                servers: vec![Ipv4Addr::new(192, 0, 2, 53)],
            },
            link,
        }
    }

    /// A state DB with one principal who has a policy row, so the rules
    /// provider is asked about somebody.
    fn state_with_a_principal() -> Arc<Mutex<Connection>> {
        let runner = nrr_storage::migration::SqliteMigrationRunner::for_state_db(
            Connection::open_in_memory().expect("in-memory"),
        );
        nrr_storage::repository::MigrationRunner::run_pending_migrations(&runner).expect("migrate");
        let conn = runner.into_connection();
        RouteBindingsRepository::new(&conn)
            .update_for_sid(
                "S-1-5-21-10-20-30-1001",
                &RoutePolicyRecord::empty(BindingSource::UserAssigned),
                0,
            )
            .expect("policy row");
        Arc::new(Mutex::new(conn))
    }

    fn policy(
        claims: Vec<ClaimedNamespace>,
        list: Vec<String>,
        rules: Arc<dyn RulesProvider>,
        redirect: Arc<FakeRedirect>,
    ) -> (NamespacePolicy, &'static MachineLocalDnsSuffixes) {
        let suffixes: &'static MachineLocalDnsSuffixes =
            Box::leak(Box::new(MachineLocalDnsSuffixes::default()));
        suffixes.publish(list);
        let policy = NamespacePolicy::new(
            Arc::new(move || claims.clone()),
            suffixes,
            Arc::new(StaticDnsServers::new(vec![Ipv4Addr::new(192, 0, 2, 1)])),
            redirect,
            "127.0.0.1:53".parse().expect("listener"),
            rules,
            state_with_a_principal(),
        )
        .with_foreign_tunnels(Arc::new(ForeignTunnelCell::new()));
        (policy, suffixes)
    }

    /// The hostile cafe end to end: its lease names a routed site's domain.
    /// Nothing is exempted for it, the offer is published for the settings
    /// screen, the corporate tunnel keeps its namespace minus the rule host,
    /// and an unchanged set is not written twice.
    #[test]
    fn a_hostile_lease_is_offered_not_honoured_and_rule_hosts_are_kept_once() {
        let redirect = Arc::new(FakeRedirect::default());
        let (policy, suffixes) = policy(
            vec![
                claim("wlan0", "video.example", ClaimingLink::Uplink),
                claim("corp0", "corp.example", ClaimingLink::ForeignTunnel),
            ],
            vec!["lan".into()],
            Arc::new(Book(book_naming("git.corp.example"))),
            Arc::clone(&redirect),
        );
        let exempt = policy.exemptions();
        let names: Vec<&str> = exempt.iter().map(|e| e.suffix.as_str()).collect();
        assert_eq!(names, ["corp.example", "lan"]);
        assert_eq!(suffixes.offered().len(), 1);
        assert_eq!(suffixes.offered()[0].suffix, "video.example");
        assert_eq!(
            redirect.writes(),
            vec![vec!["git.corp.example".to_string()]]
        );
        policy.exemptions();
        assert_eq!(
            redirect.writes().len(),
            1,
            "an unchanged set is not written again"
        );
    }

    /// A port that refuses the kept names is asked again on the next read,
    /// and a later success ends the retries.
    #[test]
    fn a_failed_keep_is_retried_on_the_next_read() {
        let redirect = Arc::new(FakeRedirect::default());
        redirect.fail.store(true, Ordering::SeqCst);
        let (policy, _) = policy(
            vec![claim("corp0", "corp.example", ClaimingLink::ForeignTunnel)],
            Vec::new(),
            Arc::new(Book(book_naming("git.corp.example"))),
            Arc::clone(&redirect),
        );
        policy.exemptions();
        policy.exemptions();
        assert_eq!(redirect.writes().len(), 2);
        redirect.fail.store(false, Ordering::SeqCst);
        policy.exemptions();
        policy.exemptions();
        assert_eq!(redirect.writes().len(), 3);
    }

    /// The user's own VPN pushing a search suffix reads as a tunnel to the
    /// claim classifier, yet its namespace is no corporate one: only a link
    /// the route coordinator names foreign reaches the fake-IP readers, and
    /// none does before the coordinator has named any.
    #[test]
    fn only_a_link_the_coordinator_names_foreign_claims_a_namespace() {
        let cell = Arc::new(ForeignTunnelCell::new());
        let (policy, _) = policy(
            vec![
                claim("corp0", "corp.example", ClaimingLink::ForeignTunnel),
                claim("mine0", "vpn.example", ClaimingLink::ForeignTunnel),
                claim("wlan0", "home.example", ClaimingLink::Uplink),
            ],
            Vec::new(),
            Arc::new(Book(book_naming("git.other.example"))),
            Arc::new(FakeRedirect::default()),
        );
        let policy = policy.with_foreign_tunnels(Arc::clone(&cell));
        policy.exemptions();
        assert!(!cell.claims_name("rdg.corp.example"), "nothing named yet");

        let corp = nrr_platform_api::adapters::AdapterInfo {
            index: 9,
            adapter_name: "corp0".into(),
            description: "corp".into(),
            friendly_name: "corp".into(),
            mac: None,
            interface_type: nrr_platform_api::adapters::InterfaceType::Tunnel,
            oper_status: nrr_platform_api::adapters::IfOperStatus::Up,
            ipv4_addresses: Vec::new(),
            ipv6_addresses: Vec::new(),
            gateways: Vec::new(),
        };
        cell.publish_tunnels(&[], &[corp], &[9]);
        policy.exemptions();
        assert!(cell.claims_name("rdg.corp.example"));
        assert!(!cell.claims_name("portal.vpn.example"));
        assert!(!cell.claims_name("nas.home.example"));
    }

    fn adapter_named(index: u32, name: &str) -> nrr_platform_api::adapters::AdapterInfo {
        nrr_platform_api::adapters::AdapterInfo {
            index,
            adapter_name: name.into(),
            description: name.into(),
            friendly_name: name.into(),
            mac: None,
            interface_type: nrr_platform_api::adapters::InterfaceType::Ethernet,
            oper_status: nrr_platform_api::adapters::IfOperStatus::Up,
            ipv4_addresses: Vec::new(),
            ipv6_addresses: Vec::new(),
            gateways: Vec::new(),
        }
    }

    fn exempt_suffixes(policy: &NamespacePolicy) -> Vec<String> {
        policy.exemptions().into_iter().map(|e| e.suffix).collect()
    }

    /// The coordinator's foreign set is the one definition: a claim the
    /// platform read as an uplink's is exempt once the coordinator names its
    /// link, and the user's own VPN suffix (never named) is not.
    #[test]
    fn the_coordinators_set_decides_which_claim_is_exempted() {
        let cell = Arc::new(ForeignTunnelCell::new());
        let (policy, _) = policy(
            vec![
                claim("corp0", "corp.example", ClaimingLink::Uplink),
                claim("mine0", "vpn.example", ClaimingLink::Uplink),
            ],
            Vec::new(),
            Arc::new(Book(book_naming("git.other.example"))),
            Arc::new(FakeRedirect::default()),
        );
        let policy = policy.with_foreign_tunnels(Arc::clone(&cell));
        assert!(exempt_suffixes(&policy).is_empty(), "nothing named yet");
        cell.publish_tunnels(&[], &[adapter_named(9, "corp0")], &[9]);
        assert_eq!(exempt_suffixes(&policy), ["corp.example"]);
    }

    /// A tunnel only the OS can type (the coordinator names none) keeps its
    /// namespace exempt, so a corporate session over it keeps resolving.
    #[test]
    fn an_os_typed_tunnel_the_coordinator_cannot_name_stays_exempt() {
        let (policy, _) = policy(
            vec![claim("da0", "corp.example", ClaimingLink::ForeignTunnel)],
            Vec::new(),
            Arc::new(Book(book_naming("git.other.example"))),
            Arc::new(FakeRedirect::default()),
        );
        assert_eq!(exempt_suffixes(&policy), ["corp.example"]);
    }
}
