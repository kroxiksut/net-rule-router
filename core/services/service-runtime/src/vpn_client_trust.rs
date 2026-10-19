//! Which executables the built-in VPN-client exemption may trust by name.
//!
//! The exemption keys on file names (`*vpn*`, `openvpn*`, …), and a name is
//! something anyone can give a file. What makes a match a client rather than
//! a download named like one is where the file sits: a folder only the
//! machine's administrators write to, or a path the user confirmed as their
//! link provider. A place anyone may write into never makes one, confirmed
//! or not. Everything else is remembered as pending so the user can be
//! asked, and exempted from nothing until they answer.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use nrr_platform_api::AppPathResolver;
use nrr_shared::ipc_payloads::PendingVpnClientDto;

/// Pending paths remembered per principal; past it the oldest answer is
/// dropped. One machine holds a handful of clients, not a list.
const PENDING_CAP_PER_SID: usize = 16;

/// The outcome of one trust pass over a candidate set, in input order.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ClientTrustSplit {
    /// Exempt by name: in a protected install, or confirmed by the user.
    pub accepted: Vec<String>,
    /// Recognised by name only, from a place the user could write to.
    pub pending: Vec<String>,
}

/// Sort `candidates` into the clients the exemption may carry and the ones
/// that need the user's word first. `confirmed` holds the paths the user
/// already pointed at; those pass wherever they sit. Deduplicated
/// case-insensitively (Windows paths), input order kept.
pub fn split_by_trust<I>(
    resolver: &dyn AppPathResolver,
    confirmed: &[String],
    candidates: I,
) -> ClientTrustSplit
where
    I: IntoIterator<Item = String>,
{
    let confirmed: HashSet<String> = confirmed
        .iter()
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| !p.is_empty())
        .collect();
    let mut seen = HashSet::new();
    let mut split = ClientTrustSplit::default();
    for candidate in candidates {
        let lower = candidate.to_ascii_lowercase();
        if lower.trim().is_empty() || !seen.insert(lower.clone()) {
            continue;
        }
        let path = Path::new(&candidate);
        if resolver.is_protected_install(path) {
            split.accepted.push(candidate);
        } else if resolver.writable_by_anyone(path) {
            // Anyone could have put it there: no confirmation makes it a
            // client, so the user is not asked either.
            continue;
        } else if confirmed.contains(&lower) {
            split.accepted.push(candidate);
        } else {
            split.pending.push(candidate);
        }
    }
    split
}

/// The pending clients as the user will be asked about them: each with the
/// executables of its own install tree that DO sit in a protected place, so
/// the offer can cover a client together with the transports it ships with
/// — and only those, never a sibling the user could have planted.
pub fn pending_with_bundles(
    resolver: &dyn AppPathResolver,
    pending: &[String],
) -> Vec<PendingVpnClientDto> {
    pending
        .iter()
        .map(|path| PendingVpnClientDto {
            exe_path: path.clone(),
            bundled_exe_paths: resolver
                .sibling_executables(Path::new(path))
                .into_iter()
                .filter(|sibling| resolver.is_protected_install(sibling))
                .map(|sibling| sibling.to_string_lossy().into_owned())
                .collect(),
        })
        .collect()
}

/// Executables that look like VPN clients but sit where the user could have
/// put them. Replaced per principal on every compute, so a client the user
/// confirms, uninstalls or moves leaves the list on the next pass.
#[derive(Default)]
pub struct PendingVpnClients {
    by_sid: Mutex<HashMap<String, Vec<PendingVpnClientDto>>>,
}

impl PendingVpnClients {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace `sid`'s pending set; empty input clears it. Returns whether
    /// the set differs from the one held before, so a caller that recomputes
    /// every few seconds can speak only when something changed.
    pub fn publish(&self, sid: &str, clients: &[PendingVpnClientDto]) -> bool {
        let mut by_sid = self.by_sid.lock().unwrap_or_else(|p| p.into_inner());
        if clients.is_empty() {
            return by_sid.remove(sid).is_some();
        }
        let mut kept: Vec<PendingVpnClientDto> = clients
            .iter()
            .map(|c| PendingVpnClientDto {
                exe_path: c.exe_path.trim().to_string(),
                bundled_exe_paths: c.bundled_exe_paths.clone(),
            })
            .collect();
        kept.truncate(PENDING_CAP_PER_SID);
        if by_sid.get(sid) == Some(&kept) {
            return false;
        }
        by_sid.insert(sid.to_string(), kept);
        true
    }

    /// `sid`'s pending clients' paths, in the order they were recognised.
    #[must_use]
    pub fn for_sid(&self, sid: &str) -> Vec<String> {
        self.dtos_for(sid).into_iter().map(|c| c.exe_path).collect()
    }

    /// `sid`'s pending clients as the wire carries them.
    #[must_use]
    pub fn dtos_for(&self, sid: &str) -> Vec<PendingVpnClientDto> {
        self.by_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .cloned()
            .unwrap_or_default()
    }

    /// Every pending client path on the machine, deduplicated
    /// case-insensitively.
    #[must_use]
    pub fn paths(&self) -> Vec<String> {
        let by_sid = self.by_sid.lock().unwrap_or_else(|p| p.into_inner());
        let mut seen = HashSet::new();
        by_sid
            .values()
            .flatten()
            .filter(|c| seen.insert(c.exe_path.to_ascii_lowercase()))
            .map(|c| c.exe_path.clone())
            .collect()
    }
}

/// Process-wide [`PendingVpnClients`]: written by the per-SID compute, read
/// by the snapshot that asks the user.
pub fn global_pending_vpn_clients() -> &'static PendingVpnClients {
    static PENDING: OnceLock<PendingVpnClients> = OnceLock::new();
    PENDING.get_or_init(PendingVpnClients::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::MockAppPathResolver;

    const INSTALLED: &str = r"C:\Program Files\vendor vpn\vendor vpn.exe";
    const PLANTED: &str = r"C:\Users\someone\Downloads\x-vpn.exe";

    fn resolver() -> MockAppPathResolver {
        let resolver = MockAppPathResolver::new();
        resolver.with_protected_root(r"C:\Program Files")
    }

    fn client(path: &str) -> PendingVpnClientDto {
        PendingVpnClientDto {
            exe_path: path.to_string(),
            bundled_exe_paths: Vec::new(),
        }
    }

    #[test]
    fn a_client_in_a_user_folder_is_pending_until_the_user_confirms_it() {
        let split = split_by_trust(
            &resolver(),
            &[],
            [INSTALLED.to_string(), PLANTED.to_string()],
        );
        assert_eq!(split.accepted, vec![INSTALLED.to_string()]);
        assert_eq!(split.pending, vec![PLANTED.to_string()]);

        let split = split_by_trust(
            &resolver(),
            &[PLANTED.to_ascii_uppercase()],
            [PLANTED.to_string()],
        );
        assert_eq!(
            split.accepted,
            vec![PLANTED.to_string()],
            "the user's confirmation is the way in, whatever the casing"
        );
        assert!(split.pending.is_empty());
    }

    /// A folder anyone may write into vouches for nothing: a client there is
    /// neither exempt, even confirmed, nor offered for confirmation.
    #[test]
    fn a_client_where_anyone_may_write_is_never_exempt() {
        const SHARED: &str = r"C:\Users\Public\x-vpn.exe";
        let resolver = resolver().with_anyone_writable_root(r"C:\Users\Public");
        let split = split_by_trust(
            &resolver,
            &[SHARED.to_string()],
            [SHARED.to_string(), INSTALLED.to_string()],
        );
        assert_eq!(split.accepted, vec![INSTALLED.to_string()]);
        assert!(split.pending.is_empty(), "{:?}", split.pending);
    }

    #[test]
    fn candidates_are_deduplicated_case_insensitively_in_input_order() {
        let split = split_by_trust(
            &resolver(),
            &[],
            [
                PLANTED.to_string(),
                INSTALLED.to_string(),
                PLANTED.to_ascii_uppercase(),
                String::new(),
            ],
        );
        assert_eq!(split.accepted, vec![INSTALLED.to_string()]);
        assert_eq!(split.pending, vec![PLANTED.to_string()]);
    }

    /// Only a sibling in a protected place may ride along with the offer: a
    /// transport planted beside the client is exactly what must not.
    #[test]
    fn the_offer_bundles_only_protected_siblings() {
        use std::path::PathBuf;
        let protected = r"C:\Program Files\vendor vpn\openvpn.exe";
        let planted = r"C:\Users\someone\Downloads\xray.exe";
        let resolver = resolver().with_siblings(
            PLANTED,
            vec![PathBuf::from(protected), PathBuf::from(planted)],
        );
        let dtos = pending_with_bundles(&resolver, &[PLANTED.to_string()]);
        assert_eq!(dtos.len(), 1);
        assert_eq!(dtos[0].exe_path, PLANTED);
        assert_eq!(dtos[0].bundled_exe_paths, vec![protected.to_string()]);
    }

    #[test]
    fn the_pending_list_is_replaced_per_principal_and_bounded() {
        let pending = PendingVpnClients::new();
        assert!(pending.publish("S-A", &[client(PLANTED)]));
        assert!(
            !pending.publish("S-A", &[client(PLANTED)]),
            "the same set again is not news"
        );
        let other = [client(&PLANTED.to_ascii_uppercase()), client(INSTALLED)];
        pending.publish("S-B", &other);
        assert_eq!(pending.for_sid("S-A"), vec![PLANTED.to_string()]);
        let machine_wide = pending.paths().len();
        assert_eq!(machine_wide, 2, "one machine-wide view, deduplicated");

        let cleared = pending.publish("S-A", &[]);
        assert!(cleared, "clearing a held set is a change");
        assert!(pending.for_sid("S-A").is_empty(), "an empty publish clears");
        assert!(!pending.publish("S-A", &[]));

        let many: Vec<PendingVpnClientDto> = (0..PENDING_CAP_PER_SID + 5)
            .map(|i| client(&format!(r"C:\Users\someone\tool{i}-vpn.exe")))
            .collect();
        pending.publish("S-C", &many);
        assert_eq!(pending.for_sid("S-C").len(), PENDING_CAP_PER_SID);
    }
}
