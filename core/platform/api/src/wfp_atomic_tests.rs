#![allow(clippy::unwrap_used)]

use super::*;
use crate::route_table::RouteTablePort;
use crate::types::{RouteEntry, WfpLayerKey};
use crate::windows_api::{MockWindowsApi, WfpEnginePort};

#[derive(Default)]
struct TransactionState {
    before: Option<Vec<WfpFilterRecord>>,
    commits: Vec<Vec<u64>>,
    fail_commit: Option<bool>,
    hide_enumeration: bool,
}

struct TransactionalApi {
    inner: MockWindowsApi,
    state: Mutex<TransactionState>,
}

impl TransactionalApi {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: MockWindowsApi::new(),
            state: Mutex::new(TransactionState::default()),
        })
    }

    fn live(&self) -> Vec<u64> {
        let mut ids: Vec<_> = self
            .inner
            .wfp_filters
            .lock()
            .unwrap()
            .iter()
            .map(|f| f.id.raw)
            .collect();
        ids.sort_unstable();
        ids
    }
}

impl RouteTablePort for TransactionalApi {
    fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError> {
        self.inner.get_ip_forward_table()
    }
    fn create_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        self.inner.create_ip_forward_entry(entry)
    }
    fn delete_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        self.inner.delete_ip_forward_entry(entry)
    }
    fn get_adapter_infos(&self) -> Result<Vec<crate::adapters::AdapterInfo>, PlatformError> {
        self.inner.get_adapter_infos()
    }
    fn interface_luid_for_index(&self, index: u32) -> Result<u64, PlatformError> {
        self.inner.interface_luid_for_index(index)
    }
}

impl WfpEnginePort for TransactionalApi {
    fn wfp_engine_open(&self) -> Result<WfpEngineToken, PlatformError> {
        self.inner.wfp_engine_open()
    }
    fn wfp_engine_close(&self, token: WfpEngineToken) -> Result<(), PlatformError> {
        self.inner.wfp_engine_close(token)
    }
    fn wfp_transaction_begin(&self, _: &WfpEngineToken) -> Result<(), PlatformError> {
        let mut state = self.state.lock().unwrap();
        assert!(state.before.is_none(), "transactions must be serialized");
        state.before = Some(self.inner.wfp_filters.lock().unwrap().clone());
        Ok(())
    }
    fn wfp_transaction_commit(&self, _: &WfpEngineToken) -> Result<(), PlatformError> {
        let mut state = self.state.lock().unwrap();
        let failure = state.fail_commit.take();
        if failure != Some(false) {
            state.before = None;
            state.commits.push(self.live());
        }
        if failure.is_some() {
            return Err(PlatformError::Transient {
                operation: "FwpmTransactionCommit0",
                detail: "lost RPC response".into(),
            });
        }
        Ok(())
    }
    fn wfp_transaction_abort(&self, _: &WfpEngineToken) {
        if let Some(before) = self.state.lock().unwrap().before.take() {
            *self.inner.wfp_filters.lock().unwrap() = before;
        }
    }
    fn wfp_filter_add(
        &self,
        token: &WfpEngineToken,
        spec: &WfpFilterSpec,
    ) -> Result<WfpFilterId, PlatformError> {
        self.inner.wfp_filter_add(token, spec)
    }
    fn wfp_filter_delete(
        &self,
        token: &WfpEngineToken,
        id: WfpFilterId,
    ) -> Result<(), PlatformError> {
        self.inner.wfp_filter_delete(token, id)
    }
    fn wfp_enumerate_our_filters(
        &self,
        token: &WfpEngineToken,
    ) -> Result<Vec<WfpFilterRecord>, PlatformError> {
        if self.state.lock().unwrap().hide_enumeration {
            return Ok(Vec::new());
        }
        self.inner.wfp_enumerate_our_filters(token)
    }
}

fn filter(raw: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        id: WfpFilterId { raw },
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: Some(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight: raw,
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
        remote_subnet_set: Vec::new(),
    }
}

fn fixture() -> (Arc<TransactionalApi>, WfpSession) {
    let api = TransactionalApi::new();
    let session = WfpSession::open(api.clone()).unwrap();
    session
        .execute_wfp_plan(&[WfpFilterAction::AddFilter(filter(1))])
        .unwrap();
    api.state.lock().unwrap().commits.clear();
    (api, session)
}

#[test]
fn replacement_never_commits_a_mixed_policy_even_above_the_batch_cap() {
    let (api, session) = fixture();
    let adds: Vec<_> = (2..MAX_FILTERS_PER_TRANSACTION as u64 + 12)
        .map(filter)
        .collect();
    session
        .execute_replacement(&adds, &[WfpFilterId { raw: 1 }], FilterFailureMode::Strict)
        .unwrap();
    let expected: Vec<_> = adds.iter().map(|f| f.id.raw).collect();
    assert_eq!(api.state.lock().unwrap().commits, vec![expected]);
}

#[test]
fn refused_retirement_does_not_publish_new_permits_and_retry_converges() {
    let (api, session) = fixture();
    api.inner.set_fail_delete(&[1]);
    let mut permit = filter(2);
    permit.action = WfpAction::Permit;
    assert!(session
        .execute_replacement(
            &[permit.clone()],
            &[WfpFilterId { raw: 1 }],
            FilterFailureMode::Strict
        )
        .is_err());
    assert_eq!(api.live(), vec![1]);
    assert!(api.state.lock().unwrap().commits.is_empty());
    api.inner.set_fail_delete(&[]);
    session
        .execute_replacement(
            &[permit],
            &[WfpFilterId { raw: 1 }],
            FilterFailureMode::Strict,
        )
        .unwrap();
    assert_eq!(api.live(), vec![2]);
}

#[test]
fn late_add_failure_keeps_the_previous_policy_without_partial_new_filters() {
    let (api, session) = fixture();
    let last = MAX_FILTERS_PER_TRANSACTION as u64 + 12;
    api.inner.set_fail_add_win32(&[last], "FwpmFilterAdd0", 5);
    let adds: Vec<_> = (2..=last).map(filter).collect();
    assert!(session
        .execute_replacement(&adds, &[WfpFilterId { raw: 1 }], FilterFailureMode::Strict)
        .is_err());
    assert_eq!(api.live(), vec![1]);
    assert!(api.state.lock().unwrap().commits.is_empty());
}

#[test]
fn skipped_guard_does_not_commit_a_new_permit_beside_old_blocks() {
    let (api, session) = fixture();
    api.inner.set_fail_add_unmaterializable(&[3]);
    let mut permit = filter(2);
    permit.action = WfpAction::Permit;
    assert!(session
        .execute_replacement(
            &[permit, filter(3)],
            &[WfpFilterId { raw: 1 }],
            FilterFailureMode::BestEffort
        )
        .is_err());
    assert_eq!(api.live(), vec![1]);
    assert!(api.state.lock().unwrap().commits.is_empty());
}

#[test]
fn first_install_does_not_publish_permits_without_its_guarding_block() {
    let api = TransactionalApi::new();
    let session = WfpSession::open(api.clone()).unwrap();
    api.inner.set_fail_add_unmaterializable(&[3]);
    let mut permit = filter(2);
    permit.action = WfpAction::Permit;
    assert!(session
        .execute_replacement(&[permit, filter(3)], &[], FilterFailureMode::BestEffort)
        .is_err());
    assert!(api.live().is_empty());
    assert!(api.state.lock().unwrap().commits.is_empty());
}

#[test]
fn failed_commit_response_is_retried_whether_the_server_committed_or_aborted() {
    for committed in [false, true] {
        let (api, session) = fixture();
        api.state.lock().unwrap().fail_commit = Some(committed);
        assert!(session
            .execute_replacement(
                &[filter(2)],
                &[WfpFilterId { raw: 1 }],
                FilterFailureMode::Strict
            )
            .is_err());
        assert_eq!(api.live(), if committed { vec![2] } else { vec![1] });
        session
            .execute_replacement(
                &[filter(2)],
                &[WfpFilterId { raw: 1 }],
                FilterFailureMode::Strict,
            )
            .unwrap();
        assert_eq!(api.live(), vec![2]);
    }
}

#[test]
fn a_failed_user_replacement_leaves_another_users_filters_untouched() {
    let (api, session) = fixture();
    let mut other = filter(99);
    other.user_sid = Some("S-1-5-21-2".into());
    session
        .execute_wfp_plan(&[WfpFilterAction::AddFilter(other)])
        .unwrap();
    api.inner.set_fail_delete(&[1]);
    assert!(session
        .execute_replacement(
            &[filter(2)],
            &[WfpFilterId { raw: 1 }],
            FilterFailureMode::Strict
        )
        .is_err());
    assert_eq!(api.live(), vec![1, 99]);
    api.inner.set_fail_delete(&[]);
    session
        .execute_replacement(
            &[filter(2)],
            &[WfpFilterId { raw: 1 }],
            FilterFailureMode::Strict,
        )
        .unwrap();
    assert_eq!(api.live(), vec![2, 99]);
}

#[test]
fn ambiguous_commit_cleanup_uses_attempted_keys_when_enumeration_omits_them() {
    let (api, session) = fixture();
    api.state.lock().unwrap().fail_commit = Some(true);
    let mut permit = filter(2);
    permit.action = WfpAction::Permit;
    assert!(session
        .execute_replacement(
            &[permit, filter(3)],
            &[WfpFilterId { raw: 1 }],
            FilterFailureMode::Strict
        )
        .is_err());
    api.state.lock().unwrap().hide_enumeration = true;
    session.cleanup_blocks_only().unwrap();
    assert_eq!(
        api.live(),
        vec![2],
        "persist cleanup must remove uncertain blocks and keep permits"
    );
    api.inner.set_fail_delete(&[2]);
    assert!(
        session.cleanup_all().is_err(),
        "partial cleanup must not let its caller discard the crash ledger"
    );
    assert_eq!(api.live(), vec![2], "a refused delete stays retryable");
    api.inner.set_fail_delete(&[]);
    session.cleanup_all().unwrap();
    assert!(
        api.live().is_empty(),
        "successful cleanup must remove the uncertain permit by its key"
    );
}
