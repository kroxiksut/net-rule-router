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
}
