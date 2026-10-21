//! Which connection claims which DNS namespace, and who answers for it.
//!
//! A corporate VPN says this itself: its DHCP lease carries a domain and the
//! addresses of the servers that know it. The user never has to be asked, and
//! usually could not answer — the domain belongs to their employer, not to them.
//!
//! ## Why the product needs it
//!
//! Redirecting every name to our own resolver makes the machine's other
//! resolvers unreachable: a name inside the corporate namespace is asked of a
//! public resolver, comes back as "no such name", and the answer is handed to
//! the application as final. The connection is fine, the routes are fine, and
//! the site still will not open — because the question went to the wrong server.
//!
//! Knowing the namespace turns that into a non-problem: names inside it are
//! left to the connection that claims them, and the product stops being in the
//! path of traffic it has no business in.
//!
//! ## Policy / mechanism seam
//!
//! The rules for what counts as a usable claim are here, pure and tested once.
//! Reading the claim is per-OS: Windows keeps it per interface in the TCP/IP
//! parameters, Linux gets it from the resolver's per-link configuration, macOS
//! from the system configuration store.

use std::net::Ipv4Addr;

use crate::adapters::{text_indicates_vpn_tunnel, AdapterInfo, InterfaceType};
use crate::dns_redirect::DnsNamespaceExemption;
use crate::types::RouteEntry;
use nrr_shared::local_dns_suffixes as suffix_policy;

/// One connection's claim: a namespace, and the servers that answer for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceDnsScope {
    /// Adapter GUID on Windows, link name elsewhere. The caller matches this
    /// against the adapter list to learn the interface index and whether the
    /// connection is one of ours.
    pub adapter_id: String,
    /// The connection name a person recognises, for the log and the GUI. May be
    /// empty when the OS reports none.
    pub display_name: String,
    /// Lower-cased namespace with no leading or trailing dot, e.g.
    /// `corp.example.com`.
    pub suffix: String,
    /// Servers that answer for `suffix`, in the order the OS lists them.
    pub servers: Vec<Ipv4Addr>,
}

impl InterfaceDnsScope {
    /// Does `hostname` fall inside this namespace?
    ///
    /// The suffix itself counts, and so does anything under it — but only on a
    /// label boundary: `notcorp.example.com` is not inside `corp.example.com`.
    #[must_use]
    pub fn covers(&self, hostname: &str) -> bool {
        let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        if host == self.suffix {
            return true;
        }
        host.strip_suffix(&self.suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
    }
}

/// Enumerates the namespaces the machine's connections claim.
pub trait InterfaceDnsScopePort: Send + Sync {
    fn dns_scopes(&self) -> Vec<InterfaceDnsScope>;
}

/// Answers with nothing: the platform has no mechanism wired. Callers keep the
/// behaviour they had before the port existed.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoDnsScopes;

impl InterfaceDnsScopePort for NoDnsScopes {
    fn dns_scopes(&self) -> Vec<InterfaceDnsScope> {
        Vec::new()
    }
}

/// Is this claim worth acting on?
///
/// Three ways a claim is useless or dangerous, and all three are seen in the
/// wild:
///
/// - **no servers** — a domain with nobody to ask is not a claim, it is a
///   search suffix;
/// - **a single label** — `local`, `lan`, `home` and the like. A home router
///   hands these out, they collide across networks, and handing a whole
///   top-level label to one connection is not something to do on a guess;
/// - **loopback or unspecified servers** — an address that answers on this
///   machine, which is where our own resolver lives. Honouring it would point a
///   namespace back at ourselves, or at nothing.
#[must_use]
pub fn is_actionable_scope(scope: &InterfaceDnsScope) -> bool {
    if scope.suffix.is_empty() || !scope.suffix.contains('.') {
        return false;
    }
    if scope.suffix.starts_with('.') || scope.suffix.ends_with('.') {
        return false;
    }
    let usable = scope
        .servers
        .iter()
        .any(|s| !s.is_loopback() && !s.is_unspecified() && !s.is_broadcast() && !s.is_multicast());
    usable
}

/// Normalise a raw suffix as the OS reports it. `None` when nothing is claimed.
#[must_use]
pub fn normalize_suffix(raw: &str) -> Option<String> {
    let s = raw.trim().trim_matches('.').to_ascii_lowercase();
    (!s.is_empty()).then_some(s)
}

/// Which kind of connection made a claim. Only a tunnel somebody else runs
/// is trusted with a namespace by itself: the main link's lease is whatever
/// the network at hand chose to put in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimingLink {
    /// A tunnel the user runs beside ours — a corporate VPN, say.
    ForeignTunnel,
    /// The main link, or a connection nothing says is a tunnel.
    Uplink,
}

/// A claim with the kind of connection that made it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimedNamespace {
    pub scope: InterfaceDnsScope,
    pub link: ClaimingLink,
}

/// Tell the tunnels among the claiming connections from the uplinks.
///
/// Structure first: a link the route table names the way out is the uplink
/// whatever it is called ([`crate::uplink::structural_uplinks`], the one the
/// route coordinator reads). After that a connection reads as a tunnel by its
/// interface type or by its name. A claim whose adapter is not in `adapters`
/// (Linux's `resolv.conf`, which belongs to no link) is an uplink.
///
/// `ours` are the served users' additional-route links: never somebody else's
/// tunnel, and their full tunnel's default says nothing about which link is
/// the uplink. Our fake-IP adapter is never a tunnel of anybody's either.
#[must_use]
pub fn classify_claims(
    scopes: Vec<InterfaceDnsScope>,
    adapters: &[AdapterInfo],
    routes: &[RouteEntry],
    ours: &[u32],
) -> Vec<ClaimedNamespace> {
    classify_with(scopes, adapters, routes, ours, looks_like_tunnel)
}

/// [`classify_claims`] narrowed to the one thing the route coordinator's
/// foreign-tunnel set cannot see: a link whose OS interface type is
/// "tunnel" (DirectAccess IP-HTTPS and the like). Every other claim is an
/// uplink here; the caller upgrades the ones the coordinator names foreign.
/// Unreadable `routes` is the caller's to express by passing no adapters:
/// doubt is "not a tunnel".
#[must_use]
pub fn classify_typed_tunnel_claims(
    scopes: Vec<InterfaceDnsScope>,
    adapters: &[AdapterInfo],
    routes: &[RouteEntry],
    ours: &[u32],
) -> Vec<ClaimedNamespace> {
    classify_with(scopes, adapters, routes, ours, |a| {
        a.interface_type == InterfaceType::Tunnel
    })
}

fn classify_with(
    scopes: Vec<InterfaceDnsScope>,
    adapters: &[AdapterInfo],
    routes: &[RouteEntry],
    ours: &[u32],
    is_tunnel: impl Fn(&AdapterInfo) -> bool,
) -> Vec<ClaimedNamespace> {
    let uplinks = crate::uplink::structural_uplinks(adapters, routes, ours);
    scopes
        .into_iter()
        .map(|scope| {
            let adapter = adapters
                .iter()
                .find(|a| a.adapter_name.eq_ignore_ascii_case(&scope.adapter_id));
            let link = match adapter {
                Some(a)
                    if !uplinks.contains(&a.index)
                        && !ours.contains(&a.index)
                        && !crate::uplink::is_own_fake_ip_adapter(a)
                        && is_tunnel(a) =>
                {
                    ClaimingLink::ForeignTunnel
                }
                _ => ClaimingLink::Uplink,
            };
            ClaimedNamespace { scope, link }
        })
        .collect()
}

fn looks_like_tunnel(adapter: &AdapterInfo) -> bool {
    adapter.interface_type == InterfaceType::Tunnel
        || text_indicates_vpn_tunnel(&format!(
            "{} {}",
            adapter.description, adapter.friendly_name
        ))
}

/// A suffix the main link offered that the list does not hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferedSuffix {
    pub suffix: String,
    /// The connection that offered it; empty when the OS names none.
    pub link: String,
}

/// What the redirect does about namespaces this time round.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NamespacePlan {
    /// Namespaces left to another resolver.
    pub exempt: Vec<DnsNamespaceExemption>,
    /// Rule names inside an exempted namespace that stay with our listener:
    /// a name under a rule follows the rule.
    pub keep: Vec<String>,
    /// Suffixes the main link offers; shown, never applied by themselves.
    pub offered: Vec<OfferedSuffix>,
    /// List entries that cover rule names, with those names — the warning.
    pub covering: Vec<(String, Vec<String>)>,
}

/// Most rule names kept back from exemptions. A rule book naming more hosts
/// under a local suffix than this is a misconfiguration, not a workload.
pub const MAX_KEPT_NAMES: usize = 256;

/// Decide the namespaces, pure.
///
/// A foreign tunnel's actionable claim is honoured; the main link's claim is
/// only offered. Every entry of the administrator's list is left to the main
/// link's own resolvers (`local_servers`); with none known there is nobody to
/// leave it to. A suffix of either kind that covers a rule name does not take
/// the name away: it is listed under `keep`.
#[must_use]
pub fn plan_namespaces(
    claims: &[ClaimedNamespace],
    local_suffixes: &[String],
    local_servers: &[Ipv4Addr],
    rule_hosts: &[String],
) -> NamespacePlan {
    let mut plan = NamespacePlan::default();
    let hosts = || rule_hosts.iter().map(String::as_str);
    let mut keep: Vec<String> = Vec::new();
    for claim in claims
        .iter()
        .filter(|c| c.link == ClaimingLink::ForeignTunnel && is_actionable_scope(&c.scope))
    {
        // A lease can carry anything; a suffix the list could not hold is not
        // written into the resolver table either.
        let Ok(suffix) = suffix_policy::normalize_suffix(&claim.scope.suffix) else {
            continue;
        };
        if plan.exempt.iter().any(|e| e.suffix == suffix) {
            continue;
        }
        keep.extend(suffix_policy::covered_hosts(&suffix, hosts()));
        plan.exempt.push(DnsNamespaceExemption {
            suffix,
            servers: claim.scope.servers.clone(),
        });
    }
    for raw in local_suffixes {
        let Ok(suffix) = suffix_policy::normalize_suffix(raw) else {
            continue;
        };
        let covered = suffix_policy::covered_hosts(&suffix, hosts());
        if !covered.is_empty() {
            keep.extend(covered.iter().cloned());
            plan.covering.push((suffix.clone(), covered));
        }
        if local_servers.is_empty() || plan.exempt.iter().any(|e| e.suffix == suffix) {
            continue;
        }
        plan.exempt.push(DnsNamespaceExemption {
            suffix,
            servers: local_servers.to_vec(),
        });
    }
    for claim in claims.iter().filter(|c| c.link == ClaimingLink::Uplink) {
        let Ok(suffix) = suffix_policy::normalize_suffix(&claim.scope.suffix) else {
            continue;
        };
        let listed = local_suffixes
            .iter()
            .any(|s| suffix_policy::normalize_suffix(s).as_deref() == Ok(suffix.as_str()));
        if listed || plan.offered.iter().any(|o| o.suffix == suffix) {
            continue;
        }
        plan.offered.push(OfferedSuffix {
            suffix,
            link: claim.scope.display_name.clone(),
        });
    }
    keep.sort_unstable();
    keep.dedup();
    keep.truncate(MAX_KEPT_NAMES);
    plan.keep = keep;
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(suffix: &str, servers: &[Ipv4Addr]) -> InterfaceDnsScope {
        InterfaceDnsScope {
            adapter_id: "{guid}".into(),
            display_name: "Corp VPN".into(),
            suffix: suffix.into(),
            servers: servers.to_vec(),
        }
    }

    const CORP: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 53);

    /// The field case, and the boundary that keeps a lookalike domain out.
    #[test]
    fn a_namespace_covers_itself_and_what_is_under_it_only_on_a_label_boundary() {
        let s = scope("branch.corp.example", &[CORP]);
        assert!(s.covers("branch.corp.example"));
        assert!(s.covers("host.branch.corp.example"));
        assert!(s.covers("HOST.Branch.Corp.Example."));
        assert!(s.covers("a.b.branch.corp.example"));

        assert!(!s.covers("corp.example"));
        assert!(!s.covers("notbranch.corp.example"));
        assert!(!s.covers("branch.corp.example.evil.com"));
        assert!(!s.covers("host"));
    }

    #[test]
    fn a_claim_with_a_real_server_and_a_real_domain_is_actionable() {
        assert!(is_actionable_scope(&scope("branch.corp.example", &[CORP])));
        assert!(is_actionable_scope(&scope("corp.example.com", &[CORP])));
    }

    /// A single label is a search suffix, not a delegation. Handing `lan` or
    /// `local` to one connection would capture names that mean different things
    /// on every network the machine joins.
    #[test]
    fn a_single_label_domain_is_never_actionable() {
        for suffix in ["lan", "local", "home", "corp", ""] {
            assert!(
                !is_actionable_scope(&scope(suffix, &[CORP])),
                "{suffix} must not be honoured"
            );
        }
    }

    /// A namespace pointed at this machine would send it back to our own
    /// resolver — the loop the whole feature exists to avoid.
    #[test]
    fn a_claim_with_no_reachable_server_is_not_actionable() {
        assert!(!is_actionable_scope(&scope("corp.example.com", &[])));
        assert!(!is_actionable_scope(&scope(
            "corp.example.com",
            &[Ipv4Addr::LOCALHOST]
        )));
        assert!(!is_actionable_scope(&scope(
            "corp.example.com",
            &[Ipv4Addr::UNSPECIFIED]
        )));
        // One good server beside a useless one is still a claim.
        assert!(is_actionable_scope(&scope(
            "corp.example.com",
            &[Ipv4Addr::LOCALHOST, CORP]
        )));
    }

    #[test]
    fn a_suffix_is_normalised_the_way_every_comparison_expects() {
        assert_eq!(
            normalize_suffix("  Branch.Corp.Example.  ").as_deref(),
            Some("branch.corp.example")
        );
        assert_eq!(
            normalize_suffix(".corp.example.com").as_deref(),
            Some("corp.example.com")
        );
        assert_eq!(normalize_suffix("   "), None);
        assert_eq!(normalize_suffix(""), None);
    }

    #[test]
    fn an_unwired_platform_claims_nothing() {
        assert!(NoDnsScopes.dns_scopes().is_empty());
    }

    // ── Classifying the claiming connections ──

    use crate::adapters::IfOperStatus;
    use crate::enforcement::RouteTableRef;
    use std::net::IpAddr;

    fn adapter(index: u32, name: &str, description: &str, kind: InterfaceType) -> AdapterInfo {
        AdapterInfo {
            index,
            adapter_name: name.into(),
            description: description.into(),
            friendly_name: name.into(),
            mac: None,
            interface_type: kind,
            oper_status: IfOperStatus::Up,
            ipv4_addresses: vec![Ipv4Addr::new(192, 0, 2, 10)],
            ipv6_addresses: Vec::new(),
            gateways: Vec::new(),
        }
    }

    fn default_route(index: u32) -> RouteEntry {
        RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_length: 0,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            interface_index: index,
            metric: 10,
            is_ours: false,
            table: RouteTableRef::Main,
        }
    }

    fn claim_of(adapter_id: &str, suffix: &str) -> InterfaceDnsScope {
        InterfaceDnsScope {
            adapter_id: adapter_id.into(),
            display_name: adapter_id.into(),
            suffix: suffix.into(),
            servers: vec![CORP],
        }
    }

    /// The field case: the cafe's Wi-Fi (sole default route) and a corporate
    /// VPN beside it. Only the VPN's claim is a tunnel's.
    #[test]
    fn the_uplink_is_never_a_foreign_tunnel_and_a_vpn_beside_it_is() {
        let adapters = [
            adapter(3, "wlan0", "Intel Wireless", InterfaceType::Wireless),
            adapter(7, "corp0", "Corp VPN Client Adapter", InterfaceType::Tunnel),
        ];
        let routes = [default_route(3)];
        let claims = classify_claims(
            vec![
                claim_of("wlan0", "cafe.example"),
                claim_of("corp0", "corp.example"),
            ],
            &adapters,
            &routes,
            &[],
        );
        assert_eq!(claims[0].link, ClaimingLink::Uplink);
        assert_eq!(claims[1].link, ClaimingLink::ForeignTunnel);
    }

    /// A tunnel that is the only way out — mobile broadband, a full-tunnel
    /// VPN with the physical link gone — is the uplink, whatever it is called.
    #[test]
    fn the_sole_default_route_holder_is_the_uplink_even_when_it_is_a_tunnel() {
        let adapters = [adapter(7, "ppp0", "VPN Adapter", InterfaceType::Tunnel)];
        let claims = classify_claims(
            vec![claim_of("ppp0", "corp.example")],
            &adapters,
            &[default_route(7)],
            &[],
        );
        assert_eq!(claims[0].link, ClaimingLink::Uplink);
    }

    /// Two default routes (uplink plus full-tunnel VPN): the tunnel keeps its
    /// claim, the physical link does not.
    #[test]
    fn with_two_default_routes_the_tunnel_is_still_the_tunnel() {
        let adapters = [
            adapter(3, "eth0", "Realtek Ethernet", InterfaceType::Ethernet),
            adapter(7, "tun0", "TAP-Windows Adapter V9", InterfaceType::Ethernet),
        ];
        let routes = [default_route(3), default_route(7)];
        let claims = classify_claims(
            vec![
                claim_of("eth0", "home.example"),
                claim_of("tun0", "corp.example"),
            ],
            &adapters,
            &routes,
            &[],
        );
        assert_eq!(claims[0].link, ClaimingLink::Uplink);
        assert_eq!(claims[1].link, ClaimingLink::ForeignTunnel);
    }

    /// Only a link typed "tunnel" by the OS is a tunnel here: a VPN that the
    /// coordinator names by its description is the coordinator's call, and a
    /// name alone makes nothing foreign.
    #[test]
    fn the_typed_classification_names_only_os_typed_tunnels() {
        let adapters = [
            adapter(3, "wlan0", "Intel Wireless", InterfaceType::Wireless),
            adapter(5, "mine0", "My VPN Adapter", InterfaceType::Ethernet),
            adapter(7, "da0", "iphttpsinterface", InterfaceType::Tunnel),
        ];
        let claims = classify_typed_tunnel_claims(
            vec![
                claim_of("wlan0", "a.example"),
                claim_of("mine0", "b.example"),
                claim_of("da0", "c.example"),
            ],
            &adapters,
            &[default_route(3)],
            &[],
        );
        assert_eq!(claims[0].link, ClaimingLink::Uplink);
        assert_eq!(claims[1].link, ClaimingLink::Uplink);
        assert_eq!(claims[2].link, ClaimingLink::ForeignTunnel);
    }

    #[test]
    fn a_claim_of_no_known_adapter_is_an_uplink() {
        let claims = classify_claims(vec![claim_of("resolv.conf", "lan")], &[], &[], &[]);
        assert_eq!(claims[0].link, ClaimingLink::Uplink);
    }

    /// The hostile-lease case the route coordinator also guards: a `ppp0`
    /// uplink beside our bound full tunnel. Counted, our tunnel's default
    /// would leave the uplink unnamed and its name would hand the provider's
    /// lease a namespace. Our link's own claim is never a corporate one, and
    /// neither is our fake-IP adapter's.
    #[test]
    fn our_links_are_left_out_of_the_count_and_never_claim_as_a_tunnel() {
        let adapters = [
            adapter(3, "ppp0", "ppp0", InterfaceType::Ethernet),
            adapter(5, "wg0", "WireGuard Tunnel", InterfaceType::Tunnel),
            adapter(
                9,
                nrr_shared::product_identity::TUN_ADAPTER_NAME,
                "NetRuleRouter Tunnel",
                InterfaceType::Ethernet,
            ),
        ];
        let routes = [default_route(3), default_route(5)];
        let scopes = || {
            vec![
                claim_of("ppp0", "isp.example"),
                claim_of("wg0", "vpn.example"),
                claim_of(
                    nrr_shared::product_identity::TUN_ADAPTER_NAME,
                    "ours.example",
                ),
            ]
        };
        let claims = classify_claims(scopes(), &adapters, &routes, &[5]);
        assert!(
            claims.iter().all(|c| c.link == ClaimingLink::Uplink),
            "{claims:?}"
        );
        let unaware = classify_claims(scopes(), &adapters, &routes, &[]);
        assert_eq!(
            unaware[0].link,
            ClaimingLink::ForeignTunnel,
            "control: without our links only the name is left to decide"
        );
        assert_eq!(unaware[2].link, ClaimingLink::Uplink);
    }

    /// Our tunnel replaced the provider's default: the link carrying the route
    /// to our server is the uplink, and its lease is only offered.
    #[test]
    fn with_no_default_left_the_server_route_names_the_uplink() {
        let adapters = [
            adapter(3, "ppp0", "ppp0", InterfaceType::Ethernet),
            adapter(5, "wg0", "WireGuard Tunnel", InterfaceType::Tunnel),
        ];
        let server = RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            prefix_length: 32,
            ..default_route(3)
        };
        let claims = classify_claims(
            vec![claim_of("ppp0", "isp.example")],
            &adapters,
            &[default_route(5), server],
            &[5],
        );
        assert_eq!(claims[0].link, ClaimingLink::Uplink);
    }

    // ── Planning the namespaces ──

    fn claimed(adapter_id: &str, suffix: &str, link: ClaimingLink) -> ClaimedNamespace {
        ClaimedNamespace {
            scope: claim_of(adapter_id, suffix),
            link,
        }
    }

    const LOCAL_DNS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    /// The hostile cafe: its DHCP names the domain of a routed site. The
    /// namespace is offered, never exempted, and the rule host stays ours.
    #[test]
    fn a_hostile_dhcp_lease_on_the_uplink_carves_nothing_out() {
        let plan = plan_namespaces(
            &[claimed("wlan0", "video.example", ClaimingLink::Uplink)],
            &strings(&["lan"]),
            &[LOCAL_DNS],
            &strings(&["www.video.example"]),
        );
        assert!(
            plan.exempt.iter().all(|e| e.suffix != "video.example"),
            "{plan:?}"
        );
        assert_eq!(
            plan.offered,
            vec![OfferedSuffix {
                suffix: "video.example".into(),
                link: "wlan0".into(),
            }]
        );
        assert!(plan.keep.is_empty());
    }

    /// A corporate VPN's claim is honoured; the one rule name under it is
    /// kept back, so the rule still decides where that host goes.
    #[test]
    fn a_foreign_tunnel_is_exempted_and_rule_names_under_it_are_kept() {
        let plan = plan_namespaces(
            &[claimed(
                "corp0",
                "corp.example",
                ClaimingLink::ForeignTunnel,
            )],
            &[],
            &[LOCAL_DNS],
            &strings(&["git.corp.example", "www.example"]),
        );
        assert_eq!(
            plan.exempt,
            vec![DnsNamespaceExemption {
                suffix: "corp.example".into(),
                servers: vec![CORP],
            }]
        );
        assert_eq!(plan.keep, strings(&["git.corp.example"]));
        assert!(plan.offered.is_empty());
    }

    /// The administrator's list goes to the main link's resolvers; an entry
    /// covering a rule name earns the warning and the name stays.
    #[test]
    fn the_list_is_left_to_the_main_links_resolvers_with_a_warning_where_it_covers_a_rule() {
        let plan = plan_namespaces(
            &[],
            &strings(&["lan", "Fritz.Box."]),
            &[LOCAL_DNS],
            &strings(&["nas.fritz.box"]),
        );
        assert_eq!(plan.exempt.len(), 2);
        assert!(plan.exempt.iter().all(|e| e.servers == vec![LOCAL_DNS]));
        assert_eq!(plan.keep, strings(&["nas.fritz.box"]));
        assert_eq!(
            plan.covering,
            vec![("fritz.box".to_string(), strings(&["nas.fritz.box"]))]
        );
    }

    /// Nobody to leave a name to: the list writes nothing, and the warning
    /// still stands.
    #[test]
    fn without_known_resolvers_the_list_exempts_nothing() {
        let plan = plan_namespaces(&[], &strings(&["lan"]), &[], &strings(&["nas.lan"]));
        assert!(plan.exempt.is_empty());
        assert_eq!(plan.keep, strings(&["nas.lan"]));
    }

    /// A lease carrying a suffix the list could not hold is not written into
    /// the resolver table either, and a listed suffix is not offered twice.
    #[test]
    fn malformed_claims_are_dropped_and_listed_offers_are_not_repeated() {
        let plan = plan_namespaces(
            &[
                claimed("corp0", "bad label.example", ClaimingLink::ForeignTunnel),
                claimed("wlan0", "LAN", ClaimingLink::Uplink),
                claimed("eth0", "lan", ClaimingLink::Uplink),
                claimed("eth1", "home.example", ClaimingLink::Uplink),
            ],
            &strings(&["lan"]),
            &[LOCAL_DNS],
            &[],
        );
        assert_eq!(plan.exempt.len(), 1, "only the list entry: {plan:?}");
        assert_eq!(plan.offered.len(), 1);
        assert_eq!(plan.offered[0].suffix, "home.example");
    }
}
