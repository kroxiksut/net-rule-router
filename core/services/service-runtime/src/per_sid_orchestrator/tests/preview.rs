use super::*;

// ── Preview (pre-flight / dry run) ──────────────────────────────────────

/// The whole reason a preview path did not exist before: the compute is also
/// where the live status the GUI reads gets refreshed. A preview that wrote
/// it would make the app describe a policy nobody applied.
#[test]
fn a_preview_publishes_nothing_about_the_live_policy() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let app_status = crate::app_enforcement_status::AppEnforcementStatus::new();
    let shared_status = crate::app_enforcement_status::SharedIpExemptionStatus::new();
    let requests = Arc::new(crate::power_resume::RebindRequests::new());
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
    )
    .with_app_enforcement_status(app_status.clone())
    .with_shared_ip_exemption_status(shared_status.clone())
    // Secondary unresolved → the compute would arm fail-closed, latch the
    // posture and ask for a re-resolve. A preview must do none of it.
    .with_kill_switch_resolver(Arc::new(|_| None))
    .with_rebind_requests(Arc::clone(&requests));
    source.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    let candidate = rules_with_one_app("nowhere.exe");

    let preview = orch
        .preview_for_sid("S-1-5-21-A", &candidate)
        .expect("preview");

    assert!(preview.enforceable);
    assert_eq!(
        preview.unresolved_apps,
        vec!["nowhere.exe".to_string()],
        "the preview itself must still report what it found"
    );
    assert!(
        app_status.unresolved().is_empty(),
        "the GUI's unresolved-app list belongs to the APPLIED policy"
    );
    assert_eq!(
        shared_status.count(),
        0,
        "no shared-IP warning from a preview"
    );
    assert_eq!(requests.take(), None, "a preview asks for no re-resolve");
    assert_eq!(
        api.wfp_filters.lock().unwrap().len(),
        0,
        "a preview installs nothing"
    );
    // The posture latch must be untouched: the next REAL compute has to be
    // able to log its transition, which it cannot if a preview claimed it.
    assert!(
        orch.posture_changed("S-1-5-21-A", "unresolved-fail-closed-block-all"),
        "the posture latch must still see the first real arming as a change"
    );
}

/// A preview states the CHANGE, not just the destination — the review
/// summary showed zeros because nothing computed this.
#[test]
fn a_preview_counts_the_filters_an_apply_would_install() {
    let (_api, orch, src, rules) = fixture_with_luid(Some(KS_LUID));
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    rules.set(rules_with_secondary_ip(ip));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    let before = orch
        .preview_for_sid("S-1-5-21-A", &rules_with_secondary_ip(ip))
        .expect("preview");
    assert!(before.filters > 0);
    assert_eq!(before.installed_now, 0, "nothing installed yet");
    assert!(
        before.colliding_filter_ids.is_empty(),
        "a sane rule set must not collide with itself"
    );

    assert_eq!(
        (before.additions, before.removals),
        (before.filters, 0),
        "with nothing installed, every planned filter is an addition"
    );

    let installed = orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(
        before.filters, installed,
        "the preview must predict the real install exactly"
    );
    let after = orch
        .preview_for_sid("S-1-5-21-A", &rules_with_secondary_ip(ip))
        .expect("preview");
    assert_eq!(after.installed_now, installed);
    // The same policy again is not "replace everything" — it is nothing to
    // do, and the review flow reads exactly this to say "already on
    // baseline" instead of opening a confirm dialog.
    assert_eq!(
        (after.additions, after.removals),
        (0, 0),
        "an unchanged policy must preview as a zero diff"
    );
}

/// A SID with no policy row enforces nothing, and the preview says so
/// instead of reporting a plausible zero.
#[test]
fn a_preview_of_a_sid_without_policy_reports_it_as_unenforceable() {
    let (_api, orch, _src, _rules) = fixture_with_luid(Some(KS_LUID));
    let candidate = rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 9));
    let preview = orch
        .preview_for_sid("S-1-5-21-NOPOLICY", &candidate)
        .expect("preview");
    assert!(!preview.enforceable);
    assert_eq!(preview.filters, 0);
}

/// A configured secondary the OS cannot resolve is why a leak guard sits
/// fail-closed; the preview names it so the review can say so before the
/// user applies.
#[test]
fn a_preview_reports_a_binding_the_os_cannot_resolve() {
    let (_api, orch, src, rules) = fixture_with_luid(None);
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    rules.set(rules_with_secondary_ip(ip));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    let preview = orch
        .preview_for_sid("S-1-5-21-A", &rules_with_secondary_ip(ip))
        .expect("preview");
    assert!(preview.secondary_binding_unresolved);

    let (_api2, orch2, src2, rules2) = fixture_with_luid(Some(KS_LUID));
    rules2.set(rules_with_secondary_ip(ip));
    src2.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    let resolved = orch2
        .preview_for_sid("S-1-5-21-A", &rules_with_secondary_ip(ip))
        .expect("preview");
    assert!(!resolved.secondary_binding_unresolved);
}
