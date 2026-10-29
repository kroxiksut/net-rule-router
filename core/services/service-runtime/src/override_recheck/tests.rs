use super::*;

use nrr_domain::protected_places::{ProtectionReason, RuleEffect};
use nrr_domain::rules_file::HostPlatform;
use nrr_platform_api::conn_observe::live::{LiveConnection, MockLiveConnectionSource};
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::network_change::NetworkChangeCallback;
use nrr_shared::ipc_payloads::OverrideTerm;
use nrr_storage::migration::SqliteMigrationRunner;
use nrr_storage::repository::MigrationRunner;
use rusqlite::Connection;

use crate::override_grants::tests::{preview_for, site_pattern};
use crate::override_grants::OverrideGrants;

const KEY: [u8; 32] = [5; 32];
const OWNER: &str = "S-1-5-21-recheck-1";
const SYSTEM: &str = "S-1-5-18";
const NETWORK_SERVICE: &str = "S-1-5-20";

fn on_site(owner: &str) -> LiveConnection {
    let image = match HostPlatform::compiled() {
        HostPlatform::Windows => r"C:\inetpub\app\w3wp.exe",
        HostPlatform::Linux => "/var/www/app/php-fpm",
        HostPlatform::MacOS => "/Library/WebServer/Documents/app/httpd",
    };
    LiveConnection {
        process_path: image.into(),
        remote: std::net::Ipv4Addr::new(203, 0, 113, 9).into(),
        owner: Some(owner.into()),
    }
}

fn setup(accounts: &[&str]) -> (Arc<RuleOverrideDeps>, Arc<MockLiveConnectionSource>) {
    let conn = Connection::open_in_memory().expect("open in-memory");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    let conn = Arc::new(Mutex::new(runner.into_connection()));
    let grants = OverrideGrants::open(Arc::clone(&conn), Some(KEY.to_vec()), None, now_ms());
    let mut preview = preview_for(OWNER, true);
    preview.accounts = accounts.iter().map(|a| (*a).to_owned()).collect();
    grants
        .grant(&preview, OverrideTerm::UntilRevoked, OWNER, now_ms())
        .expect("granted");
    let live = Arc::new(MockLiveConnectionSource::default());
    let deps = Arc::new(RuleOverrideDeps {
        grants,
        conn,
        folders: None,
        live: Some(Arc::clone(&live) as _),
        unix_sys_uid_max: crate::ipc_handlers::DEFAULT_UNIX_SYS_UID_MAX,
    });
    (deps, live)
}

fn held(deps: &RuleOverrideDeps) -> bool {
    deps.grants
        .grant_for(OWNER, site_pattern().as_str(), RuleEffect::Deny)
        .is_some()
}

#[test]
fn a_new_service_account_sends_the_rule_back_to_confirmation() {
    let (deps, live) = setup(&[SYSTEM]);
    live.set(vec![on_site(SYSTEM), on_site(NETWORK_SERVICE)]);
    assert_eq!(recheck_once(&deps), 1);
    assert!(!held(&deps));
}

#[test]
fn the_same_accounts_keep_the_confirmation() {
    let (deps, live) = setup(&[SYSTEM, NETWORK_SERVICE]);
    live.set(vec![on_site(SYSTEM), on_site(NETWORK_SERVICE)]);
    assert_eq!(recheck_once(&deps), 0);
    // Fewer accounts than listed is narrower, not wider.
    live.set(vec![on_site(SYSTEM)]);
    assert_eq!(recheck_once(&deps), 0);
    assert!(held(&deps));
    assert_eq!(
        deps.grants
            .grant_for(OWNER, site_pattern().as_str(), RuleEffect::Deny)
            .map(|g| g.reason),
        Some(ProtectionReason::SharedFolder)
    );
}

struct Observed(Mutex<Option<NetworkChangeCallback>>);

impl ServiceSetChangeObserver for Observed {
    fn subscribe(
        &self,
        on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(on_change);
        Ok(NetworkChangeSubscription::inert())
    }
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < until, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn quick(interval: Duration) -> Timing {
    Timing {
        interval,
        settle: Duration::from_millis(10),
        tell_every: Duration::from_millis(20),
    }
}

#[test]
fn an_event_triggers_a_recheck_and_the_start_does_too() {
    let (deps, live) = setup(&[SYSTEM]);
    let observer = Observed(Mutex::new(None));
    // The start reads the machine once; nothing new runs then.
    live.set(vec![on_site(SYSTEM)]);
    let recheck = OverrideRecheck::start(
        Arc::clone(&deps),
        &observer,
        quick(Duration::from_secs(3600)),
    );
    std::thread::sleep(Duration::from_millis(200));
    assert!(held(&deps));
    // A service appears; only the event makes it known within the hour.
    live.set(vec![on_site(SYSTEM), on_site(NETWORK_SERVICE)]);
    std::thread::sleep(Duration::from_millis(200));
    assert!(held(&deps), "no event, no timer due: not read yet");
    let fire = observer
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
        .expect("subscribed");
    fire();
    wait_until("the event re-check", || !held(&deps));
    drop(recheck);
}

#[test]
fn the_timer_rechecks_where_no_event_comes() {
    let (deps, live) = setup(&[SYSTEM]);
    live.set(vec![on_site(SYSTEM)]);
    let silent = Observed(Mutex::new(None));
    let recheck = OverrideRecheck::start(
        Arc::clone(&deps),
        &silent,
        quick(Duration::from_millis(150)),
    );
    std::thread::sleep(Duration::from_millis(100));
    assert!(held(&deps));
    live.set(vec![on_site(SYSTEM), on_site(NETWORK_SERVICE)]);
    wait_until("the timer re-check", || !held(&deps));
    drop(recheck);
}

#[test]
fn a_crash_loop_withdrawal_is_told_once_a_client_is_there() {
    use crate::ipc_handlers::event_bus::EventBus;
    let (deps, _live) = setup(&[]);
    let bus = Arc::new(EventBus::new());
    deps.grants.attach_events(Arc::clone(&bus));
    let withdrawn = deps
        .grants
        .revoke_all(crate::override_grants::Ending::CrashLoop, now_ms());
    assert_eq!(withdrawn, 1);
    assert!(!held(&deps));
    let observer = Observed(Mutex::new(None));
    let recheck = OverrideRecheck::start(
        Arc::clone(&deps),
        &observer,
        quick(Duration::from_secs(3600)),
    );
    std::thread::sleep(Duration::from_millis(150));
    let subscription = bus.subscribe_as("c1".to_owned(), Some(OWNER.to_owned()), None);
    wait_until("the notice", || {
        bus.peek_pending_for(&subscription.subscription_id, 8)
            .iter()
            .any(|entry| {
                matches!(
                    &entry.event,
                    nrr_shared::ipc_payloads::StatusUpdateEvent::RuleOverridesChanged { cause, .. }
                        if cause == crate::override_grants::CAUSE_CRASH_LOOP
                )
            })
    });
    drop(recheck);
}
