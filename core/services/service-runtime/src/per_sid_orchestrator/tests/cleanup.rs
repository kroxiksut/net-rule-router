use super::*;

// ── WFP cleanup (persist-on-stop feature) ───────────────────────────────

/// Build an orchestrator that shares `session` with the caller so a test
/// can seed the live WFP table directly (as an orphaned prior instance
/// would leave it) and then exercise the cleanup entrypoints.
fn orch_sharing_session(session: Arc<WfpSession>) -> Arc<PerSidApplyOrchestrator> {
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    Arc::new(PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    ))
}

#[test]
fn only_permitted_addresses_are_published_as_enforced() {
    let spec = |action: WfpAction, ip: Option<Ipv4Addr>, set: Vec<Ipv4Addr>| WfpFilterSpec {
        layer: nrr_platform_api::types::WfpLayerKey::AleAuthConnectV4,
        action,
        remote_ip: ip,
        remote_ip_set: set,
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight: 0,
        id: WfpFilterId { raw: 1 },
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    };
    let permitted = Ipv4Addr::new(23, 10, 20, 158);
    let packed = Ipv4Addr::new(23, 10, 20, 142);
    let doh_blocked = Ipv4Addr::new(8, 8, 4, 4);
    let sid = "S-1-5-21-publish-test";

    PerSidApplyOrchestrator::publish_enforced_addresses(
        sid,
        &[
            spec(WfpAction::Permit, Some(permitted), Vec::new()),
            // The packed form: one filter guarding a whole address set.
            spec(WfpAction::Permit, None, vec![packed]),
            // The DoH lockdown names ~85 addresses it BLOCKS. Answering a
            // client with one of them would be the opposite of enforced.
            spec(WfpAction::Block, Some(doh_blocked), Vec::new()),
            // A catch-all carries no address and contributes nothing.
            spec(WfpAction::Permit, None, Vec::new()),
        ],
    );

    let register = crate::enforced_addresses::global_enforced_addresses();
    assert!(register.is_enforced(sid, permitted));
    assert!(register.is_enforced(sid, packed), "packed sets count too");
    assert!(!register.is_enforced(sid, doh_blocked));
    assert_eq!(register.snapshot(sid).len(), 2);
}

fn seeded_block_permit_block(session: &WfpSession, api: &MockWindowsApi) {
    let block = |raw: u64| WfpFilterSpec {
        layer: nrr_platform_api::types::WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: Some(Ipv4Addr::new(9, 9, 9, raw as u8)),
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight: 0x10_0000 + raw,
        id: WfpFilterId { raw },
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    };
    let permit = |raw: u64| WfpFilterSpec {
        action: WfpAction::Permit,
        ..block(raw)
    };
    session
        .execute_wfp_plan(&[
            WfpFilterAction::AddFilter(block(1)),
            WfpFilterAction::AddFilter(permit(2)),
            WfpFilterAction::AddFilter(block(3)),
        ])
        .unwrap();
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 3);
}

#[test]
fn cleanup_wfp_blocks_only_strips_blocks_and_keeps_permits() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let orch = orch_sharing_session(Arc::clone(&session));
    seeded_block_permit_block(&session, &api);

    let removed = orch.cleanup_wfp_blocks_only().unwrap();
    assert_eq!(removed, 2, "only the two block filters must be stripped");
    let remaining = api.wfp_filters.lock().unwrap().clone();
    assert_eq!(remaining.len(), 1, "the permit filter must survive");
    assert_eq!(remaining[0].action, WfpAction::Permit);
}

#[test]
fn cleanup_wfp_strips_all_filters_and_clears_state() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let orch = orch_sharing_session(Arc::clone(&session));
    seeded_block_permit_block(&session, &api);

    let removed = orch.cleanup_wfp().unwrap();
    assert_eq!(removed, 3, "cleanup_wfp strips block AND permit filters");
    assert!(api.wfp_filters.lock().unwrap().is_empty());
    assert!(
        orch.installed_sids().is_empty(),
        "cleanup_wfp must clear the in-memory SID→filter map"
    );
}
