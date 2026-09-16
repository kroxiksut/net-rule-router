use super::*;

// ── ServiceHealthResponse / FakeIpDatapathDto ────────────────────────────

#[test]
fn service_health_response_fake_ip_datapath_round_trips_as_kebab_case() {
    let resp = ServiceHealthResponse {
        service_state: "running".to_string(),
        worst_severity: "ok".to_string(),
        active_revision_id: None,
        components: Vec::new(),
        degraded_modes: Vec::new(),
        fake_ip_datapath: Some(FakeIpDatapathDto {
            desired: true,
            running: false,
            zombies: 2,
        }),
    };
    let json = serde_json::to_value(&resp).expect("serialise");
    assert_eq!(json["fake-ip-datapath"]["desired"], true);
    assert_eq!(json["fake-ip-datapath"]["running"], false);
    assert_eq!(json["fake-ip-datapath"]["zombies"], 2);
    let back: ServiceHealthResponse = serde_json::from_value(json).expect("deserialise");
    assert_eq!(back, resp);
}

#[test]
fn service_health_response_without_fake_ip_datapath_stays_compatible() {
    // A pre-field service payload must still deserialise (back-compat),
    // and an unset field must not appear on the wire (forward-compat).
    let old_wire = serde_json::json!({
        "service-state": "running",
        "worst-severity": "ok",
        "components": [],
        "degraded-modes": [],
    });
    let parsed: ServiceHealthResponse =
        serde_json::from_value(old_wire).expect("deserialise old payload");
    assert!(parsed.fake_ip_datapath.is_none());

    let json = serde_json::to_value(&parsed).expect("serialise");
    assert!(json.get("fake-ip-datapath").is_none());
}

// ── RuleSummaryEntryDto ─────────────────────────────────────────────────

#[test]
fn rule_summary_entry_without_enabled_reads_as_enabled() {
    // A service that predates the flag only ever reported enforceable
    // rules — its payloads must keep parsing, and as "enabled".
    let old_wire = serde_json::json!({
        "id": "r-001",
        "display": "example.com",
        "route": "secondary",
    });
    let parsed: RuleSummaryEntryDto =
        serde_json::from_value(old_wire).expect("deserialise pre-field payload");
    assert!(parsed.enabled);
}

#[test]
fn rule_summary_entry_keeps_the_pre_field_bytes_when_enabled() {
    // Additive by construction: an enabled entry serialises exactly as
    // it did before the field existed, so only disabled rules pay for it.
    let entry = RuleSummaryEntryDto {
        id: "r-001".to_string(),
        display: "example.com".to_string(),
        route: "secondary".to_string(),
        enabled: true,
    };
    let json = serde_json::to_value(&entry).expect("serialise");
    assert!(json.get("enabled").is_none());

    let disabled = RuleSummaryEntryDto {
        enabled: false,
        ..entry
    };
    let json = serde_json::to_value(&disabled).expect("serialise");
    assert_eq!(
        json["enabled"], false,
        "the review diff in ReviewDiffColumn.qml reads `enabled`"
    );
    let back: RuleSummaryEntryDto = serde_json::from_value(json).expect("deserialise");
    assert_eq!(back, disabled);
}

// ── RoutePolicyDto / RoutePolicyUpdateRequest — auto-rules mode ──────────

/// The three auto-rules slugs are a cross-process contract: the
/// `auto_rules_mode` CHECK constraint in `nrr-storage`'s state schema,
/// `nrr_storage::auto_rules::AutoRulesMode::as_slug`, and the
/// `autoRulesMode` combo box in
/// `apps/desktop/qml/sections/settings/RoutingSettings.qml` all repeat these
/// literals. Pinned here so a rename has to be deliberate on every side.
const AUTO_RULES_MODE_WIRE_SLUGS: [&str; 3] = ["off", "suggest", "auto"];

fn route_policy_update_request_sample(auto_rules_mode: &str) -> RoutePolicyUpdateRequest {
    RoutePolicyUpdateRequest {
        primary: None,
        secondary: None,
        mode: BehaviorModeDto::PreferPrimary,
        block_secondary_when_unavailable: true,
        kill_switch_fail_closed: true,
        kill_switch_protocols: 0x7F,
        kill_switch_block_all: false,
        kill_switch_enabled: false,
        allow_dns_over_primary: true,
        include_subdomains: false,
        shared_ip_policy: shared_ip_policy_default(),
        mode_a_coverage_strategy: mode_a_coverage_strategy_default(),
        resolve_hosts_bypass: true,
        doh_lockdown_enabled: false,
        doh_lockdown_scope: doh_lockdown_scope_default(),
        browser_history_auto_seed: false,
        kill_switch_strict_shared_ips: false,
        auto_rules_mode: auto_rules_mode.to_string(),
        auto_rules_eager_delivery_names: false,
        primary_probe_auto: false,
        primary_probe_timeout_ms: 1500,
        primary_probe_max_targets: 8,
        primary_probe_repeat_secs: 300,
        local_networks_auto_accept: false,
        zone_priority_over_ip: false,
        binding_source: BindingSourceDto::UserAssigned,
    }
}

#[test]
fn auto_rules_mode_travels_as_kebab_case_key_with_pinned_slugs() {
    for slug in AUTO_RULES_MODE_WIRE_SLUGS {
        let json = serde_json::to_value(route_policy_update_request_sample(slug))
            .expect("serialise request");
        assert_eq!(
            json["auto-rules-mode"], slug,
            "the QML combo box in RoutingSettings.qml reads `auto-rules-mode`"
        );
    }
}

#[test]
fn auto_rules_mode_defaults_to_suggest_when_an_older_peer_omits_it() {
    // v1 ships with application disabled: an omitted field must read as
    // "collect and offer", never as `off` (silently disabling discovery)
    // and never as `auto` (silently applying rules unattended).
    let mut json =
        serde_json::to_value(route_policy_update_request_sample("auto")).expect("serialise");
    let obj = json.as_object_mut().expect("object payload");
    obj.remove("auto-rules-mode");
    let parsed: RoutePolicyUpdateRequest =
        serde_json::from_value(json).expect("deserialise pre-field payload");
    assert_eq!(parsed.auto_rules_mode, "suggest");
    assert_eq!(auto_rules_mode_default(), "suggest");
}

#[test]
fn eager_delivery_names_travels_as_kebab_case_and_defaults_off() {
    let mut on = route_policy_update_request_sample("suggest");
    on.auto_rules_eager_delivery_names = true;
    let json = serde_json::to_value(&on).expect("serialise");
    assert_eq!(
        json["auto-rules-eager-delivery-names"], true,
        "the QML checkbox reads `auto-rules-eager-delivery-names`"
    );

    // Opting a user in is theirs to do: an omitted field is never "on".
    let mut json = json;
    let obj = json.as_object_mut().expect("object payload");
    obj.remove("auto-rules-eager-delivery-names");
    let parsed: RoutePolicyUpdateRequest =
        serde_json::from_value(json).expect("deserialise pre-field payload");
    assert!(!parsed.auto_rules_eager_delivery_names);
}

/// Every push event a client can receive. Kept here rather than built ad
/// hoc so the shape test below covers new variants by construction.
fn every_status_update_event() -> Vec<StatusUpdateEvent> {
    vec![
        StatusUpdateEvent::HealthChanged {
            service_state: "running".into(),
            worst_severity: "info".into(),
        },
        StatusUpdateEvent::AdaptersChanged {
            data_source: "os".into(),
        },
        StatusUpdateEvent::AlertRaised {
            alert_id: "a-1".into(),
            kind: "tamper".into(),
        },
        StatusUpdateEvent::OperationFinished {
            operation_id: "op-1".into(),
            state: "completed".into(),
            error_code: None,
        },
        StatusUpdateEvent::Overflow { dropped_count: 3 },
        StatusUpdateEvent::RevisionStatusChanged {
            revision_id: "rev-1".into(),
            status: "active".into(),
        },
        StatusUpdateEvent::RoutingPauseStateChanged {
            sid: "S-1-5-21".into(),
            paused: false,
        },
        StatusUpdateEvent::ApplyFailurePolicyChanged {
            policy: "best-effort".into(),
        },
        StatusUpdateEvent::AutostartStateChanged {
            enabled: true,
            last_known_state: "enabled".into(),
        },
        StatusUpdateEvent::RetentionSettingsChanged,
        StatusUpdateEvent::MutationProgress {
            correlation_id: "corr-1".into(),
            mutation_kind: "rules-update".into(),
            phase: "completed".into(),
            error_code: None,
        },
        StatusUpdateEvent::HostUnreachableOnBothRoutes {
            sid: "S-1-5-21-1".into(),
            host: "unreachable.example".into(),
        },
        StatusUpdateEvent::AutoRuleCandidatesChanged {
            sid: "S-1-5-21".into(),
            pending_count: 59,
            top_anchor: "example.com".into(),
        },
        StatusUpdateEvent::SecondaryExternalAddressObserved {
            sid: "S-1-5-21".into(),
            adapter_name: "Tunnel".into(),
            external_address: "203.0.113.7".into(),
        },
        StatusUpdateEvent::BlockNoticeRaised {
            sid: "S-1-5-21".into(),
            destination: "cdn.example".into(),
            app: "messenger.exe".into(),
            reason: "not-covered-by-rules".into(),
            attempts: 1,
        },
    ]
}

/// `rename_all` renames variants, NOT their fields. Without
/// `rename_all_fields` every multi-word field ships snake_case while the
/// QML readers index kebab-case, so the value reads as undefined and the
/// event silently does nothing — the tray showed "0 pending" while the
/// service was publishing 59.
#[test]
fn every_push_event_field_travels_as_kebab_case() {
    for event in every_status_update_event() {
        let json = serde_json::to_value(&event).expect("serialise event");
        let object = json.as_object().expect("event serialises to an object");
        for key in object.keys() {
            assert!(
                !key.contains('_'),
                "push event field `{key}` ships snake_case; QML reads kebab-case: {json}"
            );
        }
    }
}

/// The exact keys the tray and the main window index, pinned by name. A
/// rename that keeps the kebab-case shape but changes a word would pass
/// the test above and still break the reader.
#[test]
fn push_event_keys_the_ui_reads_are_stable() {
    let pending = serde_json::to_value(StatusUpdateEvent::AutoRuleCandidatesChanged {
        sid: "S-1-5-21".into(),
        pending_count: 59,
        top_anchor: "example.com".into(),
    })
    .expect("serialise");
    assert_eq!(pending["pending-count"], 59);
    assert_eq!(pending["top-anchor"], "example.com");

    let address = serde_json::to_value(StatusUpdateEvent::SecondaryExternalAddressObserved {
        sid: "S-1-5-21".into(),
        adapter_name: "Tunnel".into(),
        external_address: "203.0.113.7".into(),
    })
    .expect("serialise");
    assert_eq!(address["external-address"], "203.0.113.7");
    assert_eq!(address["adapter-name"], "Tunnel");

    let progress = serde_json::to_value(StatusUpdateEvent::MutationProgress {
        correlation_id: "corr-1".into(),
        mutation_kind: "rules-update".into(),
        phase: "completed".into(),
        error_code: None,
    })
    .expect("serialise");
    assert_eq!(progress["correlation-id"], "corr-1");
    assert_eq!(progress["mutation-kind"], "rules-update");

    let revision = serde_json::to_value(StatusUpdateEvent::RevisionStatusChanged {
        revision_id: "rev-1".into(),
        status: "active".into(),
    })
    .expect("serialise");
    assert_eq!(revision["revision-id"], "rev-1");

    let notice = serde_json::to_value(StatusUpdateEvent::BlockNoticeRaised {
        sid: "S-1-5-21".into(),
        destination: "cdn.example".into(),
        app: "messenger.exe".into(),
        reason: "not-covered-by-rules".into(),
        attempts: 1,
    })
    .expect("serialise");
    assert_eq!(notice["type"], "block-notice-raised");
    assert_eq!(notice["destination"], "cdn.example");
    assert_eq!(notice["reason"], "not-covered-by-rules");
    assert_eq!(notice["attempts"], 1);
}

// ── PresetImportPayload ──────────────────────────────────────────────────

#[test]
fn preset_import_payload_serializes_as_kebab_case() {
    let payload = PresetImportPayload {
        route: Some(RouteRole::Primary),
        primary_bytes_b64: Some("Zm9v".to_string()),
        secondary_bytes_b64: None,
        include_child_processes: true,
        import_only_active: true,
        content_hash_primary: Some("abc".to_string()),
        content_hash_secondary: None,
        correlation_id: Some("corr-1".to_string()),
    };
    let json = serde_json::to_value(&payload).expect("serialise");
    assert_eq!(json["route"], "primary");
    assert_eq!(json["primary-bytes-b64"], "Zm9v");
    assert_eq!(json["include-child-processes"], true);
    assert_eq!(json["import-only-active"], true);
    assert_eq!(json["content-hash-primary"], "abc");
    assert_eq!(json["correlation-id"], "corr-1");
    // Optional unset fields must not appear in output.
    assert!(json.get("secondary-bytes-b64").is_none());
    assert!(json.get("content-hash-secondary").is_none());
}

#[test]
fn preset_import_payload_deserializes_minimal_form() {
    let json = serde_json::json!({
        "primary-bytes-b64": "Zm9v",
        "include-child-processes": false,
    });
    let payload: PresetImportPayload = serde_json::from_value(json).expect("deserialise");
    assert_eq!(payload.primary_bytes_b64.as_deref(), Some("Zm9v"));
    assert!(payload.secondary_bytes_b64.is_none());
    assert!(payload.route.is_none());
    assert!(payload.content_hash_primary.is_none());
    assert!(payload.correlation_id.is_none());
    assert!(!payload.include_child_processes);
    // Omitted on the wire → serde default false (back-compat: an older
    // client that doesn't know the flag imports everything).
    assert!(!payload.import_only_active);
}

#[test]
fn preset_import_target_single_primary_implicit() {
    let payload = PresetImportPayload {
        primary_bytes_b64: Some("x".to_string()),
        include_child_processes: false,
        ..Default::default()
    };
    assert_eq!(
        payload.target(),
        Ok(PresetImportTarget::SingleRoute(RouteRole::Primary))
    );
}

#[test]
fn preset_import_target_single_secondary_implicit() {
    let payload = PresetImportPayload {
        secondary_bytes_b64: Some("x".to_string()),
        include_child_processes: false,
        ..Default::default()
    };
    assert_eq!(
        payload.target(),
        Ok(PresetImportTarget::SingleRoute(RouteRole::Secondary))
    );
}

#[test]
fn preset_import_target_single_with_matching_route_hint() {
    let payload = PresetImportPayload {
        route: Some(RouteRole::Primary),
        primary_bytes_b64: Some("x".to_string()),
        include_child_processes: false,
        ..Default::default()
    };
    assert_eq!(
        payload.target(),
        Ok(PresetImportTarget::SingleRoute(RouteRole::Primary))
    );
}

#[test]
fn preset_import_target_route_mismatch_is_rejected() {
    // primary bytes supplied but caller claims it's for secondary.
    let payload = PresetImportPayload {
        route: Some(RouteRole::Secondary),
        primary_bytes_b64: Some("x".to_string()),
        include_child_processes: false,
        ..Default::default()
    };
    assert_eq!(
        payload.target(),
        Err(PresetImportPayloadError::RouteMismatch)
    );
}

#[test]
fn preset_import_target_both_routes_ignores_route_hint() {
    let payload = PresetImportPayload {
        route: Some(RouteRole::Primary), // ignored when both bytes present.
        primary_bytes_b64: Some("a".to_string()),
        secondary_bytes_b64: Some("b".to_string()),
        include_child_processes: false,
        ..Default::default()
    };
    assert_eq!(payload.target(), Ok(PresetImportTarget::BothRoutes));
}

#[test]
fn preset_import_target_no_bytes_is_rejected() {
    let payload = PresetImportPayload {
        include_child_processes: false,
        ..Default::default()
    };
    assert_eq!(
        payload.target(),
        Err(PresetImportPayloadError::NoBytesSupplied)
    );
}

#[test]
fn auto_rule_candidate_dto_uses_the_kebab_wire_names_the_tray_reads() {
    // The tray reads these exact keys out of the response; a rename here
    // silently empties its prompt, so pin them.
    let dto = AutoRuleCandidateDto {
        id: "arc-1".into(),
        anchor: "site.example".into(),
        proposed_match: "cdn.example".into(),
        match_kind: AUTO_RULE_MATCH_KIND_EXACT.into(),
        route: crate::RouteRole::Secondary.slug().into(),
        affinity: 1.0,
        observations: Some(2),
        first_seen_unix_ms: 1,
        last_seen_unix_ms: 2,
        signal: AUTO_RULE_SIGNAL_DELIVERY_NAME.into(),
        consumers: vec![AutoRuleConsumerDto {
            hostname: "site.example".into(),
            route: crate::RouteRole::Secondary.slug().into(),
        }],
        consumers_changed_unix_ms: 2,
        primary_behavior: AUTO_RULE_PRIMARY_BEHAVIOR_STALLS.into(),
        anchor_refuses_main_link: false,
        observed_members: vec!["ledger.other.example".into()],
        served_by_main_link: false,
        third_party: Some(false),
        secondary_reach: None,
    };
    let json = serde_json::to_value(&dto).expect("serialise");
    for key in [
        "id",
        "anchor",
        "proposed-match",
        "match-kind",
        "route",
        "affinity",
        "observations",
        "first-seen-unix-ms",
        "last-seen-unix-ms",
        "signal",
        "consumers",
        "consumers-changed-unix-ms",
        "primary-behavior",
        "observed-members",
        "third-party",
    ] {
        assert!(json.get(key).is_some(), "missing wire key {key}");
    }
    let back: AutoRuleCandidateDto = serde_json::from_value(json).expect("deserialise");
    assert_eq!(back, dto);
}

/// `signal` is additive in both directions: a candidate without one
/// serialises to the exact set of keys the field predates, and a message
/// written before the field still parses.
#[test]
fn auto_rule_candidate_signal_is_additive_in_both_directions() {
    let mut dto = AutoRuleCandidateDto {
        id: "arc-1".into(),
        anchor: "site.example".into(),
        proposed_match: "cdn.example".into(),
        match_kind: AUTO_RULE_MATCH_KIND_EXACT.into(),
        route: crate::RouteRole::Secondary.slug().into(),
        affinity: 1.0,
        observations: Some(2),
        first_seen_unix_ms: 1,
        last_seen_unix_ms: 2,
        signal: String::new(),
        consumers: Vec::new(),
        consumers_changed_unix_ms: 0,
        primary_behavior: String::new(),
        anchor_refuses_main_link: false,
        observed_members: Vec::new(),
        served_by_main_link: false,
        third_party: None,
        secondary_reach: None,
    };
    let json = serde_json::to_value(&dto).expect("serialise");
    let keys: Vec<&String> = json.as_object().expect("object").keys().collect::<Vec<_>>();
    assert!(
        !keys.iter().any(|k| k.as_str() == "signal"),
        "an unset signal must not add a key: {keys:?}"
    );
    assert!(
        !keys.iter().any(|k| k.as_str() == "consumers"),
        "an empty consumer list must not add a key: {keys:?}"
    );
    assert!(
        !keys.iter().any(|k| k.as_str() == "primary-behavior"),
        "an unobserved primary behaviour must not add a key: {keys:?}"
    );
    // An offer with no anchor site leaves the question off the wire
    // entirely, so a reader cannot mistake it for "the site's own name".
    assert!(
        !keys.iter().any(|k| k.as_str() == "third-party"),
        "an unposed ownership question must not add a key: {keys:?}"
    );
    let back: AutoRuleCandidateDto = serde_json::from_value(json).expect("deserialise");
    assert_eq!(back, dto);

    dto.signal = AUTO_RULE_SIGNAL_CO_ACTIVITY.into();
    let json = serde_json::to_value(&dto).expect("serialise");
    assert_eq!(json["signal"], AUTO_RULE_SIGNAL_CO_ACTIVITY);
}

/// The badge slugs are a cross-process contract with the tray/GUI text and
/// with `nrr_domain::companion_affinity::CompanionSignal`. Pin the literals.
#[test]
fn auto_rule_signal_slugs_are_pinned() {
    assert_eq!(
        AUTO_RULE_SIGNAL_SLUGS,
        ["brand-related", "delivery-name", "co-activity"]
    );
    // The signals a host raises about ITSELF carry no companion arithmetic,
    // so they are not in the list above — but they are the same
    // cross-process contract with the GUI text and must not drift either.
    assert_eq!(
        AUTO_RULE_SELF_SIGNED_SIGNALS,
        [
            "placeholder-answer",
            "main-link-blocked",
            "app-main-link-blocked"
        ]
    );
    for signal in AUTO_RULE_SELF_SIGNED_SIGNALS {
        assert!(is_self_signed_signal(signal), "{signal}");
        assert!(!AUTO_RULE_SIGNAL_SLUGS.contains(signal), "{signal}");
    }
    for signal in AUTO_RULE_SIGNAL_SLUGS {
        assert!(!is_self_signed_signal(signal), "{signal}");
    }
}

#[test]
fn auto_rule_action_request_defaults_to_an_empty_id_list() {
    let parsed: AutoRuleCandidatesActionRequest = serde_json::from_str("{}").expect("deserialise");
    assert!(parsed.ids.is_empty());
    let parsed: AutoRuleCandidatesActionRequest =
        serde_json::from_str(r#"{"ids":["a","b"]}"#).expect("deserialise");
    assert_eq!(parsed.ids, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn auto_rule_dismissed_restore_request_defaults_to_an_empty_id_list() {
    let parsed: AutoRuleDismissedRestoreRequest = serde_json::from_str("{}").expect("deserialise");
    assert!(parsed.ids.is_empty());
    let parsed: AutoRuleDismissedRestoreRequest =
        serde_json::from_str(r#"{"ids":["a","b"]}"#).expect("deserialise");
    assert_eq!(parsed.ids, vec!["a".to_string(), "b".to_string()]);
}

#[test]
fn auto_rule_dismissed_entry_dto_uses_the_kebab_wire_names_the_gui_reads() {
    let dto = AutoRuleDismissedEntryDto {
        candidate_id: "arc-1".into(),
        anchor: "site.example".into(),
        proposed_match: "cdn.example".into(),
        dismissed_at_unix_ms: 1_700_000_000_000,
    };
    let json = serde_json::to_value(&dto).expect("serialise");
    for key in [
        "candidate-id",
        "anchor",
        "proposed-match",
        "dismissed-at-unix-ms",
    ] {
        assert!(json.get(key).is_some(), "missing wire key {key}");
    }
    let back: AutoRuleDismissedEntryDto = serde_json::from_value(json).expect("deserialise");
    assert_eq!(back, dto);
}

#[test]
fn preset_import_payload_round_trips_through_json() {
    let original = PresetImportPayload {
        route: None,
        primary_bytes_b64: Some("YWxwaGE=".to_string()),
        secondary_bytes_b64: Some("YmV0YQ==".to_string()),
        include_child_processes: true,
        import_only_active: false,
        content_hash_primary: Some("h1".to_string()),
        content_hash_secondary: Some("h2".to_string()),
        correlation_id: None,
    };
    let json = serde_json::to_string(&original).expect("serialise");
    let parsed: PresetImportPayload = serde_json::from_str(&json).expect("deserialise");
    assert_eq!(parsed.primary_bytes_b64, original.primary_bytes_b64);
    assert_eq!(parsed.secondary_bytes_b64, original.secondary_bytes_b64);
    assert!(parsed.include_child_processes);
    assert_eq!(parsed.content_hash_primary, original.content_hash_primary);
    assert_eq!(parsed.target(), Ok(PresetImportTarget::BothRoutes));
}

// ── Block-notice mutes / routing ─────────────────────────────────────────

#[test]
fn block_notice_mute_scope_dto_round_trips_every_variant() {
    for (scope, expect_kind, expect_key) in [
        (
            BlockNoticeMuteScopeDto::Host {
                host: "cdn.example".into(),
            },
            "host",
            Some("host"),
        ),
        (
            BlockNoticeMuteScopeDto::App {
                app: "messenger.exe".into(),
            },
            "app",
            Some("app"),
        ),
        (BlockNoticeMuteScopeDto::All, "all", None),
    ] {
        let json = serde_json::to_value(&scope).expect("serialise");
        assert_eq!(json["kind"], expect_kind);
        if let Some(key) = expect_key {
            assert!(json.get(key).is_some(), "missing wire key {key}: {json}");
        }
        let back: BlockNoticeMuteScopeDto = serde_json::from_value(json).expect("deserialise");
        assert_eq!(back, scope);
    }
}

#[test]
fn block_notice_mute_dto_omits_until_when_forever() {
    let forever = BlockNoticeMuteDto {
        scope: BlockNoticeMuteScopeDto::All,
        until_unix_ms: None,
    };
    let json = serde_json::to_value(&forever).expect("serialise");
    assert!(json.get("until-unix-ms").is_none());
    let back: BlockNoticeMuteDto = serde_json::from_value(json).expect("deserialise");
    assert_eq!(back, forever);

    let bounded = BlockNoticeMuteDto {
        scope: BlockNoticeMuteScopeDto::Host {
            host: "cdn.example".into(),
        },
        until_unix_ms: Some(5_000),
    };
    let json = serde_json::to_value(&bounded).expect("serialise");
    assert_eq!(json["until-unix-ms"], 5_000);
    let back: BlockNoticeMuteDto = serde_json::from_value(json).expect("deserialise");
    assert_eq!(back, bounded);
}

#[test]
fn block_notice_mutes_set_request_uses_kebab_wire_keys() {
    let req = BlockNoticeMutesSetRequest {
        scope: BlockNoticeMuteScopeDto::App {
            app: "messenger.exe".into(),
        },
        until_unix_ms: Some(1_000),
    };
    let json = serde_json::to_value(&req).expect("serialise");
    assert_eq!(json["scope"]["kind"], "app");
    assert_eq!(json["scope"]["app"], "messenger.exe");
    assert_eq!(json["until-unix-ms"], 1_000);
    let back: BlockNoticeMutesSetRequest = serde_json::from_value(json).expect("deserialise");
    assert_eq!(back, req);
}

#[test]
fn block_notice_route_to_secondary_round_trips() {
    let req = BlockNoticeRouteToSecondaryRequest {
        destination: "cdn.example".into(),
    };
    let json = serde_json::to_value(&req).expect("serialise");
    assert_eq!(json["destination"], "cdn.example");
    let back: BlockNoticeRouteToSecondaryRequest =
        serde_json::from_value(json).expect("deserialise");
    assert_eq!(back, req);

    let resp = BlockNoticeRouteToSecondaryResponse { authored: true };
    let json = serde_json::to_value(&resp).expect("serialise");
    assert_eq!(json["authored"], true);
}
