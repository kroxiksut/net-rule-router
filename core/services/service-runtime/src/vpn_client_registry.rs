//! Registry of VPN client executable paths whose role was VERIFIED by a
//! kill-switch drop (see [`crate::conn_observation_consumer`] and
//! [`crate::killswitch_drop_registry`]).
//!
//! The reactive VPN-endpoint learner ([`crate::vpn_endpoint_learning`])
//! exempts one server IP per drop — which fails against providers that run
//! their client's connectivity checks over ROTATING infrastructure IPs: every
//! rotation is a fresh ~72 s hang-until-drop before the next per-IP exemption
//! lands  field logs, hidemy.name over Google front-ends). The
//! client PROCESS, however, is stable across rotations, and its whole egress
//! is the tunnel's transport — so once its role is verified, the process
//! itself earns an app-scoped exemption whenever a block-all posture arms,
//! proactively, before the first drop of a session.
//!
//! Unlike the endpoint set this registry IS persisted
//! (`nrr_storage::vpn_client_apps`): role verification requires a drop by our
//! own kill-switch/fail-closed Block from a VPN-named process, a much stronger
//! signal than an IP observation, and the whole point is to survive the IP
//! rotation across sessions. The hole is still bounded: entries are capped at
//! [`CAP`], per-user-SID at emission time, and only ever emitted while a
//! blocking posture is armed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::SystemTime;

/// Maximum distinct client paths held at once. Oldest entry is evicted to
/// make room once the cap is reached. Mirrors the storage-layer cap so the
/// in-memory view and the persisted set stay congruent.
const CAP: usize = 16;

struct Entry {
    /// Concrete on-disk exe path (Win32 form), as handed to the WFP
    /// `ALE_APP_ID` condition builder.
    path: String,
    learned_at: SystemTime,
}

/// Bounded, thread-safe set of verified VPN client exe paths.
#[derive(Default)]
pub struct LearnedVpnClientApps {
    entries: Mutex<Vec<Entry>>,
}

impl LearnedVpnClientApps {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `path` as learned at `now`. Returns `true` when the path is
    /// newly added; `false` when it was already present (its timestamp is
    /// refreshed either way). Comparison is case-insensitive (Windows paths).
    /// At capacity, the single oldest entry is evicted to admit the new one.
    /// An empty path is rejected (`false`, nothing stored).
    pub fn register(&self, path: &str, now: SystemTime) -> bool {
        if path.trim().is_empty() {
            return false;
        }
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = entries
            .iter_mut()
            .find(|e| e.path.eq_ignore_ascii_case(path))
        {
            existing.learned_at = now;
            return false;
        }
        if entries.len() >= CAP {
            if let Some((oldest_idx, _)) =
                entries.iter().enumerate().min_by_key(|(_, e)| e.learned_at)
            {
                entries.remove(oldest_idx);
            }
        }
        entries.push(Entry {
            path: path.to_string(),
            learned_at: now,
        });
        true
    }

    /// Seed the registry from persisted paths (service start). Existing
    /// entries are kept; duplicates are collapsed case-insensitively.
    pub fn seed(&self, paths: &[String], now: SystemTime) {
        for path in paths {
            self.register(path, now);
        }
    }

    /// Currently-known verified client paths. Order is not significant to
    /// callers — every consumer folds this into an exemption pattern set.
    pub fn current(&self) -> Vec<String> {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|e| e.path.clone())
            .collect()
    }
}

/// Executables the USER explicitly confirmed as the link provider of a route
/// binding — the VPN client that brings the secondary link up. The service-side
/// SSOT is the per-SID `route_link_provider_apps` table (surfaced on the policy
/// snapshot as `link_provider_exe_paths`; the GUI's `confirmed_vpn_exe_paths`
/// preference is a display mirror of the same pick).
///
/// This is deliberately a *different* trust tier from
/// [`nrr_platform_api::vpn_discovery::looks_like_vpn`], the keyword heuristic
/// the self-heal uses: a keyword match is a guess about any process whose name
/// happens to contain "vpn", while an entry here is a file the user pointed at
/// in the onboarding dialog. Everything that grants a process a way AROUND our
/// own enforcement keys on this set, never on the heuristic.
///
/// **Scope.** The set is machine-wide (a union across SIDs, replaced per SID on
/// publish) rather than per-SID, matching the sibling `vpn_client_apps`
/// registry above: the fact it carries — "this binary is a link provider" — is
/// a property of the installed binary, not a per-user preference, and both of
/// its consumers (the process-wide app-path resolver and the machine-wide
/// fake-IP relay) have no SID in hand at the point they ask.
#[derive(Default)]
pub struct ConfirmedVpnClients {
    /// `sid → confirmed paths`. Small (one binding per user, a handful of
    /// paths), replaced wholesale on publish so un-confirming actually removes.
    by_sid: RwLock<HashMap<String, Vec<ConfirmedPath>>>,
    /// Mirrors "`by_sid` holds at least one path", so the hot path can skip the
    /// read lock entirely on the overwhelmingly common unarmed configuration.
    armed: AtomicBool,
}

/// One confirmed executable. `full` keeps the path exactly as the user
/// confirmed it (that string is what reaches `FwpmGetAppIdFromFileName0`);
/// the two lowercased keys are precomputed at publish time so no matching call
/// allocates.
struct ConfirmedPath {
    full: String,
    full_lower: String,
    basename_lower: String,
}

impl ConfirmedVpnClients {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace `sid`'s confirmed paths. Empty (or blank-only) input clears the
    /// SID's slice, so a user who un-confirms their client stops being exempt
    /// on the very next compute.
    pub fn publish(&self, sid: &str, paths: &[String]) {
        let entries: Vec<ConfirmedPath> = paths
            .iter()
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .map(|p| {
                let full_lower = p.to_ascii_lowercase();
                let basename_lower = full_lower
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or(full_lower.as_str())
                    .to_string();
                ConfirmedPath {
                    full: p.to_string(),
                    full_lower,
                    basename_lower,
                }
            })
            .collect();
        let mut by_sid = self.by_sid.write().unwrap_or_else(|p| p.into_inner());
        if entries.is_empty() {
            by_sid.remove(sid);
        } else {
            by_sid.insert(sid.to_string(), entries);
        }
        let armed = by_sid.values().any(|paths| !paths.is_empty());
        drop(by_sid);
        self.armed.store(armed, Ordering::Relaxed);
    }

    /// `true` when at least one executable is confirmed. A single relaxed load —
    /// this is the guard every hot-path caller checks before doing real work.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.armed.load(Ordering::Relaxed)
    }

    /// `true` when `image` names a confirmed executable. Accepts either a full
    /// path or a bare file name, because the two producers differ: the WFP /
    /// codegen side holds concrete paths, while the OS flow-owner lookup can
    /// only return an image BASENAME.
    ///
    /// Matching on the basename is a deliberate, bounded widening: a binary
    /// that merely shares the file name of a confirmed client also matches. The
    /// hole is narrow (the user must have confirmed that exact name), strictly
    /// narrower than the `looks_like_vpn` keyword heuristic that already gates
    /// the self-heal, and the worst outcome is that one flow egresses the
    /// primary link — never that something the user routed is silently
    /// unprotected by the kill-switch, which keys on paths only.
    #[must_use]
    pub fn matches_image(&self, image: &str) -> bool {
        if !self.is_armed() {
            return false;
        }
        let needle = image.trim();
        if needle.is_empty() {
            return false;
        }
        let by_sid = self.by_sid.read().unwrap_or_else(|p| p.into_inner());
        by_sid.values().flatten().any(|entry| {
            entry.full_lower.eq_ignore_ascii_case(needle)
                || entry.basename_lower.eq_ignore_ascii_case(needle)
        })
    }

    /// Every confirmed path, deduplicated case-insensitively. Order is not
    /// significant — consumers fold this into a set.
    #[must_use]
    pub fn paths(&self) -> Vec<String> {
        let by_sid = self.by_sid.read().unwrap_or_else(|p| p.into_inner());
        let mut seen = std::collections::HashSet::new();
        by_sid
            .values()
            .flatten()
            .filter(|entry| seen.insert(entry.full_lower.clone()))
            .map(|entry| entry.full.clone())
            .collect()
    }

    /// Confirmed paths whose file name matches `pattern` (exact name or `*`
    /// glob, case-insensitive). Feeds the app-path resolver fallback.
    #[must_use]
    pub fn paths_matching(&self, pattern: &str) -> Vec<String> {
        if !self.is_armed() {
            return Vec::new();
        }
        let needle = pattern.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return Vec::new();
        }
        let by_sid = self.by_sid.read().unwrap_or_else(|p| p.into_inner());
        let mut seen = std::collections::HashSet::new();
        by_sid
            .values()
            .flatten()
            .filter(|entry| {
                glob_matches(&needle, &entry.basename_lower)
                    || glob_matches(&needle, &entry.full_lower)
            })
            .filter(|entry| seen.insert(entry.full_lower.clone()))
            .map(|entry| entry.full.clone())
            .collect()
    }
}

/// Glob match where `*` matches zero or more characters. Both sides must
/// already be lowercase. Mirrors `nrr_domain::decision_rules_matching`'s
/// matcher — duplicated rather than depended on because that one is private to
/// the rule engine and this crate must not widen the engine's public surface
/// for a two-line helper.
fn glob_matches(pattern: &str, text: &str) -> bool {
    fn walk(pat: &[u8], txt: &[u8]) -> bool {
        match pat.first() {
            None => txt.is_empty(),
            Some(b'*') => (0..=txt.len()).any(|i| walk(&pat[1..], &txt[i..])),
            Some(&pc) => txt
                .first()
                .is_some_and(|&tc| tc == pc && walk(&pat[1..], &txt[1..])),
        }
    }
    walk(pattern.as_bytes(), text.as_bytes())
}

/// Process-wide [`ConfirmedVpnClients`].
///
/// Same singleton rationale as [`crate::fake_ip::global_udp_relay_enabled`]:
/// the writer (the per-SID compute, which holds the policy snapshot) and the
/// readers (the app-path resolver decorator and the fake-IP relay bypass) are
/// built in different composition scopes, and a process singleton keeps them on
/// one value by construction. Empty until the first compute publishes, so a
/// service that never sees a confirmed client behaves exactly as before.
pub fn global_confirmed_vpn_clients() -> Arc<ConfirmedVpnClients> {
    static REGISTRY: OnceLock<Arc<ConfirmedVpnClients>> = OnceLock::new();
    Arc::clone(REGISTRY.get_or_init(|| Arc::new(ConfirmedVpnClients::new())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn register_returns_true_for_new_path_false_for_repeat() {
        let apps = LearnedVpnClientApps::new();
        let now = SystemTime::now();
        assert!(apps.register(r"C:\Apps\openvpn.exe", now));
        assert!(!apps.register(r"C:\Apps\openvpn.exe", now));
        assert_eq!(apps.current(), vec![r"C:\Apps\openvpn.exe".to_string()]);
    }

    #[test]
    fn register_dedups_case_insensitively() {
        let apps = LearnedVpnClientApps::new();
        let now = SystemTime::now();
        assert!(apps.register(r"C:\Apps\OpenVPN.exe", now));
        assert!(!apps.register(r"c:\apps\openvpn.exe", now));
        assert_eq!(apps.current().len(), 1);
    }

    #[test]
    fn empty_path_is_rejected() {
        let apps = LearnedVpnClientApps::new();
        assert!(!apps.register("", SystemTime::now()));
        assert!(!apps.register("   ", SystemTime::now()));
        assert!(apps.current().is_empty());
    }

    #[test]
    fn cap_evicts_the_oldest_entry() {
        let apps = LearnedVpnClientApps::new();
        let t0 = SystemTime::now();
        for i in 0..CAP {
            apps.register(
                &format!(r"C:\Apps\client-{i}.exe"),
                t0 + Duration::from_secs(i as u64),
            );
        }
        let t_new = t0 + Duration::from_secs(CAP as u64 + 1);
        assert!(apps.register(r"C:\Apps\newest.exe", t_new));
        let current = apps.current();
        assert_eq!(current.len(), CAP);
        assert!(!current.contains(&r"C:\Apps\client-0.exe".to_string()));
        assert!(current.contains(&r"C:\Apps\newest.exe".to_string()));
    }

    // ── ConfirmedVpnClients ──────────────────────────────────────────────────

    const HIDEMY: &str = r"C:\Program Files\hidemy.name VPN 3.0\hidemy.name VPN 3.0.exe";

    #[test]
    fn an_unpublished_registry_is_unarmed_and_matches_nothing() {
        let confirmed = ConfirmedVpnClients::new();
        assert!(!confirmed.is_armed());
        assert!(!confirmed.matches_image("hidemy.name vpn 3.0.exe"));
        assert!(confirmed.paths().is_empty());
        assert!(confirmed.paths_matching("*vpn*").is_empty());
    }

    #[test]
    fn a_confirmed_client_matches_by_full_path_and_by_basename() {
        let confirmed = ConfirmedVpnClients::new();
        confirmed.publish("S-1-5-21-1", &[HIDEMY.to_string()]);
        assert!(confirmed.is_armed());
        // The codegen side holds the full path…
        assert!(confirmed.matches_image(HIDEMY));
        assert!(confirmed.matches_image(&HIDEMY.to_ascii_uppercase()));
        // …the OS flow-owner lookup can only produce the image basename.
        assert!(confirmed.matches_image("hidemy.name vpn 3.0.exe"));
        // Anything else stays outside the exemption.
        assert!(!confirmed.matches_image("chrome.exe"));
        assert!(!confirmed.matches_image(""));
    }

    #[test]
    fn publishing_an_empty_set_disarms_that_sid() {
        let confirmed = ConfirmedVpnClients::new();
        confirmed.publish("S-1-5-21-1", &[HIDEMY.to_string()]);
        confirmed.publish("S-1-5-21-1", &[]);
        assert!(
            !confirmed.is_armed(),
            "un-confirming must revoke the exemption"
        );
        assert!(!confirmed.matches_image("hidemy.name vpn 3.0.exe"));
    }

    #[test]
    fn each_sid_owns_its_own_slice() {
        let confirmed = ConfirmedVpnClients::new();
        confirmed.publish("S-1-5-21-1", &[HIDEMY.to_string()]);
        confirmed.publish("S-1-5-21-2", &[r"C:\Apps\openvpn.exe".to_string()]);
        confirmed.publish("S-1-5-21-1", &[]);
        // The other user's confirmation survives its neighbour's clearing.
        assert!(confirmed.is_armed());
        assert!(confirmed.matches_image("openvpn.exe"));
        assert!(!confirmed.matches_image("hidemy.name vpn 3.0.exe"));
    }

    #[test]
    fn paths_matching_resolves_exact_names_and_globs() {
        let confirmed = ConfirmedVpnClients::new();
        confirmed.publish("S-1-5-21-1", &[HIDEMY.to_string()]);
        let expected = vec![HIDEMY.to_string()];
        // The exact rule pattern the user typed.
        assert_eq!(
            confirmed.paths_matching("hidemy.name VPN 3.0.exe"),
            expected
        );
        // The built-in `*vpn*` exemption glob.
        assert_eq!(confirmed.paths_matching("*vpn*"), expected);
        // An unrelated pattern resolves to nothing.
        assert!(confirmed.paths_matching("chrome.exe").is_empty());
        assert!(confirmed.paths_matching("   ").is_empty());
    }

    #[test]
    fn seed_folds_persisted_paths_in() {
        let apps = LearnedVpnClientApps::new();
        let now = SystemTime::now();
        apps.register(r"C:\Apps\live.exe", now);
        apps.seed(
            &[
                r"C:\Apps\persisted.exe".to_string(),
                r"C:\APPS\LIVE.EXE".to_string(), // dup of the live entry
            ],
            now,
        );
        let current = apps.current();
        assert_eq!(current.len(), 2);
        assert!(current.contains(&r"C:\Apps\persisted.exe".to_string()));
    }
}
