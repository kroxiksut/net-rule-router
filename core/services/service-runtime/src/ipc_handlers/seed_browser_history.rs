//! `diagnostics.seed-from-browser-history` handler.
//!
//! Opt-in: reads the CALLER's browser history, resolves the hostnames the
//! caller's rules match, and caches them. Runs on a detached worker thread (the
//! read + resolve can take seconds) and returns immediately with
//! `started: true`; the per-host counts are logged. One import per user at a
//! time: a request while the caller's previous one runs answers
//! `already-running` instead of starting a second reader.

use std::sync::Arc;

use crate::browser_history_seeder::BrowserHistorySeeder;
use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::SeedFromBrowserHistoryResponse;

pub struct SeedFromBrowserHistoryHandler {
    seeder: Arc<BrowserHistorySeeder>,
}

impl SeedFromBrowserHistoryHandler {
    pub fn new(seeder: Arc<BrowserHistorySeeder>) -> Self {
        Self { seeder }
    }
}

impl IpcHandler for SeedFromBrowserHistoryHandler {
    fn handle(&self, _request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        // The consent covers the consenting user's own history; with no
        // identity there is no profile it could honestly apply to.
        let sid = ctx.caller_stored();
        if sid.is_empty() {
            return Err(IpcError {
                code: IpcErrorCode::Unauthorized,
                message: "this request carries no user identity, so there is no history to read"
                    .to_string(),
                diagnostics_id: None,
            });
        }
        let response = match self.seeder.try_begin(sid) {
            None => SeedFromBrowserHistoryResponse {
                started: false,
                already_running: true,
            },
            Some(run) => {
                // A failed spawn drops the closure, and with it the claim.
                let spawned = std::thread::Builder::new()
                    .name("nrr-bh-seed".into())
                    .spawn(move || {
                        let _ = run.run(std::time::SystemTime::now());
                    });
                if let Err(e) = &spawned {
                    tracing::warn!(target: "nrr::browser-history", msg_key = "bhseedipc-spawn-failed", error = %e, "could not spawn browser-history seed worker");
                }
                SeedFromBrowserHistoryResponse {
                    started: spawned.is_ok(),
                    already_running: false,
                }
            }
        };
        serde_json::to_value(response).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("seed-from-browser-history response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::per_sid_orchestrator::{ActiveRulesSnapshot, RulesProvider};
    use nrr_domain::canonical::{CanonicalRuleBook, CanonicalRuleSet};
    use nrr_domain::user_principal::UserPrincipal;
    use nrr_domain::RouteBehaviorMode;
    use nrr_platform_api::browser_history::{BrowserHistoryError, BrowserHistoryReadPort};
    use nrr_platform_api::dns::{AddressFamily, DnsResolverError, DnsResolverPort, ResolvedRecord};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use nrr_storage::repository::CacheRepository;
    use std::sync::mpsc;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Reports whose history was requested, then holds the read open until
    /// released — so a pass is observably in flight.
    struct GatedHistory {
        asked: mpsc::Sender<String>,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl BrowserHistoryReadPort for GatedHistory {
        fn read_history_hostnames(
            &self,
            principal: &str,
        ) -> Result<Vec<String>, BrowserHistoryError> {
            let _ = self.asked.send(principal.to_owned());
            let _ = self
                .release
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .recv_timeout(Duration::from_secs(10));
            Ok(Vec::new())
        }
    }

    struct EveryoneHasRules;
    impl RulesProvider for EveryoneHasRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            Some(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: CanonicalRuleSet::from_rules(vec![]),
                    secondary: CanonicalRuleSet::from_rules(vec![]),
                },
                behavior_mode: RouteBehaviorMode::PreferPrimary,
            })
        }
    }

    struct NoResolver;
    impl DnsResolverPort for NoResolver {
        fn resolve(
            &self,
            hostname: &str,
            _family: AddressFamily,
        ) -> Result<ResolvedRecord, DnsResolverError> {
            Err(DnsResolverError::NxDomain {
                hostname: hostname.to_string(),
            })
        }
    }

    fn in_memory_cache() -> Arc<Mutex<dyn CacheRepository + Send>> {
        use nrr_domain::decision_lookup::FreshnessThresholds;
        use nrr_storage::migration::SqliteMigrationRunner;
        use nrr_storage::repository::MigrationRunner;
        use nrr_storage::store::SqliteCacheStore;
        let conn = rusqlite::Connection::open_in_memory().expect("in-memory db");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrations");
        Arc::new(Mutex::new(SqliteCacheStore::new(
            runner.into_connection(),
            FreshnessThresholds::default_production(),
        )))
    }

    fn handler() -> (
        SeedFromBrowserHistoryHandler,
        mpsc::Receiver<String>,
        mpsc::Sender<()>,
    ) {
        let (asked_tx, asked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let seeder = Arc::new(BrowserHistorySeeder::new(
            Arc::new(GatedHistory {
                asked: asked_tx,
                release: Mutex::new(release_rx),
            }),
            Arc::new(EveryoneHasRules),
            Arc::new(NoResolver),
            in_memory_cache(),
        ));
        (
            SeedFromBrowserHistoryHandler::new(seeder),
            asked_rx,
            release_tx,
        )
    }

    fn ctx(sid: Option<&str>) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: sid.map(|s| UserPrincipal::from_windows_sid(s).expect("sid")),
            caller_pid: None,
        }
    }

    fn req() -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-bh".into(),
            correlation_id: None,
            operation: IpcOperationName::SeedFromBrowserHistory,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload: serde_json::Value::Null,
        }
    }

    fn parse(v: serde_json::Value) -> SeedFromBrowserHistoryResponse {
        serde_json::from_value(v).expect("response")
    }

    /// User B's consent reads user B's history — the handler has no notion of
    /// "the active user" to fall back on.
    #[test]
    fn the_pass_runs_for_the_callers_principal() {
        let (handler, asked, release) = handler();
        let resp = parse(
            handler
                .handle(&req(), &ctx(Some("S-1-5-21-B")))
                .expect("ok"),
        );
        assert!(resp.started);
        assert!(!resp.already_running);
        assert_eq!(
            asked
                .recv_timeout(Duration::from_secs(5))
                .expect("history read"),
            "S-1-5-21-B"
        );
        let _ = release.send(());
    }

    #[test]
    fn a_second_request_while_the_first_runs_starts_nothing() {
        let (handler, asked, release) = handler();
        let first = parse(
            handler
                .handle(&req(), &ctx(Some("S-1-5-21-A")))
                .expect("ok"),
        );
        assert!(first.started);
        // The first worker is now inside the read.
        assert_eq!(
            asked
                .recv_timeout(Duration::from_secs(5))
                .expect("history read"),
            "S-1-5-21-A"
        );

        let second = parse(
            handler
                .handle(&req(), &ctx(Some("S-1-5-21-A")))
                .expect("ok"),
        );
        assert!(!second.started);
        assert!(second.already_running);
        assert!(
            asked.recv_timeout(Duration::from_millis(200)).is_err(),
            "no second reader may have been spawned"
        );

        let _ = release.send(());
        // Once the first pass ends the user may import again.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut again = parse(
            handler
                .handle(&req(), &ctx(Some("S-1-5-21-A")))
                .expect("ok"),
        );
        while again.already_running && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
            again = parse(
                handler
                    .handle(&req(), &ctx(Some("S-1-5-21-A")))
                    .expect("ok"),
            );
        }
        assert!(again.started);
        let _ = release.send(());
    }

    #[test]
    fn an_unattributed_caller_is_refused() {
        let (handler, asked, _release) = handler();
        let err = handler.handle(&req(), &ctx(None)).expect_err("refused");
        assert_eq!(err.code, IpcErrorCode::Unauthorized);
        assert!(asked.recv_timeout(Duration::from_millis(100)).is_err());
    }
}
