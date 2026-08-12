//! `ConfirmedClientAppPathResolver` — resolve an app pattern to an executable
//! the USER confirmed, so its WFP `ALE_APP_ID` filter exists before that
//! executable ever runs.
//!
//! # The gap this closes
//!
//! Every app-scoped filter (a user app rule, and the built-in `*vpn*` kill-switch
//! exemption globs) is built from a name/glob resolved to a concrete on-disk
//! path — `FwpmGetAppIdFromFileName0` accepts nothing else. The live resolver
//! finds a path only for an exe that is currently RUNNING, registered under
//! `App Paths`, or reachable by the bounded Program-Files walk;
//! [`crate::persistent_app_resolver`] adds a last-good fallback, which is empty
//! until the exe has resolved at least once.
//!
//! A VPN client installed outside those places therefore resolves to nothing
//! until the moment it starts — so its permit lands AFTER its first connection
//! attempt, not before. A field log has shown exactly that shape: dozens of
//! unresolved app rules for the whole session, the client's exe leaving the list
//! only once its process was up, having already made (and lost) its first
//! external-address probe.
//!
//! The user, however, already told us where that binary lives — the onboarding
//! dialog stores it in `route_link_provider_apps`, republished on every compute
//! into [`ConfirmedVpnClients`]. This decorator uses it as the last fallback, so
//! the permit is materialized from the confirmed path alone, with no process and
//! no prior sighting.
//!
//! # Boundary
//!
//! The fallback yields ONLY paths the user confirmed, and only when the inner
//! resolver (live + last-good) produced nothing. It cannot invent a path for an
//! arbitrary process, and a confirmed entry that no longer exists on disk is
//! dropped rather than resurrected — matching the persistence decorator's own
//! survivor rule.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use nrr_platform_api::AppPathResolver;

use crate::vpn_client_registry::ConfirmedVpnClients;

/// Last-fallback decorator over an inner [`AppPathResolver`]. See module docs.
pub struct ConfirmedClientAppPathResolver {
    inner: Arc<dyn AppPathResolver>,
    confirmed: Arc<ConfirmedVpnClients>,
}

impl ConfirmedClientAppPathResolver {
    #[must_use]
    pub fn new(inner: Arc<dyn AppPathResolver>, confirmed: Arc<ConfirmedVpnClients>) -> Self {
        Self { inner, confirmed }
    }
}

impl AppPathResolver for ConfirmedClientAppPathResolver {
    fn resolve(&self, name_or_glob: &str) -> Vec<PathBuf> {
        let inner = self.inner.resolve(name_or_glob);
        if !inner.is_empty() {
            return inner;
        }
        // Unarmed (nothing confirmed) is the common case and costs one relaxed
        // atomic load inside `paths_matching`.
        let fallback: Vec<PathBuf> = self
            .confirmed
            .paths_matching(name_or_glob)
            .into_iter()
            .map(PathBuf::from)
            .filter(|p| Path::is_file(p))
            .collect();
        if !fallback.is_empty() {
            tracing::debug!(
                target: "nrr::app-resolver",
                pattern = %name_or_glob,
                paths = fallback.len(),
                "app pattern resolved from a user-confirmed link-provider path — its filter installs without the process running",
            );
        }
        fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Scripted inner resolver: answers whatever was seeded per exact query.
    #[derive(Default)]
    struct ScriptedInner {
        map: Mutex<HashMap<String, Vec<PathBuf>>>,
    }
    impl ScriptedInner {
        fn set(&self, query: &str, paths: Vec<PathBuf>) {
            self.map
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(query.to_string(), paths);
        }
    }
    impl AppPathResolver for ScriptedInner {
        fn resolve(&self, query: &str) -> Vec<PathBuf> {
            self.map
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(query)
                .cloned()
                .unwrap_or_default()
        }
    }

    /// Create a real file so the on-disk survivor filter passes.
    fn touch(dir: &tempfile::TempDir, name: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, b"x").expect("write file");
        path
    }

    #[test]
    fn a_confirmed_client_resolves_before_its_process_has_ever_run() {
        // The whole point: nothing is running, nothing was ever persisted, and
        // the exe is not on a searched path — only the user's confirmation.
        let dir = tempfile::tempdir().expect("temp dir");
        let exe = touch(&dir, "hidemy.name VPN 3.0.exe");
        let confirmed = Arc::new(ConfirmedVpnClients::new());
        confirmed.publish("S-1-5-21-1", &[exe.to_string_lossy().into_owned()]);
        let resolver = ConfirmedClientAppPathResolver::new(
            Arc::new(ScriptedInner::default()),
            Arc::clone(&confirmed),
        );

        // The user's own app rule, spelled exactly as in the rule book…
        assert_eq!(
            resolver.resolve("hidemy.name VPN 3.0.exe"),
            vec![exe.clone()],
        );
        // …and the built-in kill-switch exemption glob.
        assert_eq!(resolver.resolve("*vpn*"), vec![exe]);
    }

    #[test]
    fn an_unconfirmed_pattern_still_resolves_to_nothing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let _exe = touch(&dir, "hidemy.name VPN 3.0.exe");
        let confirmed = Arc::new(ConfirmedVpnClients::new());
        confirmed.publish("S-1-5-21-1", &[_exe.to_string_lossy().into_owned()]);
        let resolver =
            ConfirmedClientAppPathResolver::new(Arc::new(ScriptedInner::default()), confirmed);
        // A process the user never confirmed gains nothing from this decorator.
        assert!(resolver.resolve("chrome.exe").is_empty());
    }

    #[test]
    fn the_inner_resolver_always_wins() {
        let dir = tempfile::tempdir().expect("temp dir");
        let confirmed_exe = touch(&dir, "confirmed.exe");
        let live_exe = touch(&dir, "live.exe");
        let inner = Arc::new(ScriptedInner::default());
        inner.set("*vpn*", vec![live_exe.clone()]);
        let confirmed = Arc::new(ConfirmedVpnClients::new());
        confirmed.publish(
            "S-1-5-21-1",
            &[confirmed_exe.to_string_lossy().into_owned()],
        );
        let resolver = ConfirmedClientAppPathResolver::new(inner, confirmed);
        assert_eq!(
            resolver.resolve("*vpn*"),
            vec![live_exe],
            "a live/last-good resolution is more precise than the confirmation",
        );
    }

    #[test]
    fn an_uninstalled_confirmed_path_is_not_resurrected() {
        let confirmed = Arc::new(ConfirmedVpnClients::new());
        confirmed.publish("S-1-5-21-1", &[r"C:\definitely\missing.exe".to_string()]);
        let resolver =
            ConfirmedClientAppPathResolver::new(Arc::new(ScriptedInner::default()), confirmed);
        assert!(resolver.resolve("missing.exe").is_empty());
    }
}
