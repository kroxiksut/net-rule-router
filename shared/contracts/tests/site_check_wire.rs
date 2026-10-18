//! `diagnostics.site-check.run` — "is it us or the site". The GUI and the
//! terminal read these keys by name, so the wire spelling is pinned here.

use nrr_shared::ipc::{
    ipc_operation_spec, IpcClientProfile, IpcInteractionClass, IpcOperationName,
};
use nrr_shared::ipc_payloads::{
    SiteCheckNameDto, SiteCheckReport, SiteCheckRequest, SiteCheckStatus, SITE_CHECK_ANSWERS,
    SITE_CHECK_ROLES, SITE_CHECK_STATES, SITE_CHECK_VERDICTS,
};
use nrr_shared::ipc_transport::{canonical_operation_class, IpcOperationClass};
use serde_json::json;

#[test]
fn the_result_is_a_read_of_the_callers_own_check() {
    let op = IpcOperationName::SiteCheckResultGet;
    assert_eq!(op.slug(), "diagnostics.site-check.result");
    assert_eq!(
        IpcOperationName::from_slug("diagnostics.site-check.result"),
        Some(op)
    );
    let spec = ipc_operation_spec(op).unwrap_or_else(|| panic!("catalogued"));
    assert_eq!(spec.class, IpcInteractionClass::Query);
    assert_eq!(
        canonical_operation_class(op, &json!({})),
        IpcOperationClass::ReadSnapshot
    );
}

#[test]
fn the_operation_travels_under_its_slug_from_the_window_and_the_terminal_only() {
    let op = IpcOperationName::SiteCheckRun;
    assert_eq!(op.slug(), "diagnostics.site-check.run");
    assert_eq!(
        IpcOperationName::from_slug("diagnostics.site-check.run"),
        Some(op)
    );
    let spec = ipc_operation_spec(op).unwrap_or_else(|| panic!("catalogued"));
    assert_eq!(spec.class, IpcInteractionClass::Command);
    assert!(!spec.requires_service_mutation_privilege);
    assert_eq!(
        spec.allowed_clients,
        &[IpcClientProfile::GuiInteractive, IpcClientProfile::Tui]
    );
    assert_eq!(
        canonical_operation_class(op, &json!({ "host": "site.example" })),
        IpcOperationClass::UserScopedConfiguration
    );
}

#[test]
fn the_answer_reads_as_the_clients_expect() {
    let request: SiteCheckRequest =
        serde_json::from_value(json!({ "host": "site.example" })).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(request.host, "site.example");

    let report = SiteCheckReport {
        site: "site.example".into(),
        verdict: "sign-in-split".into(),
        site_route: "secondary".into(),
        names: vec![SiteCheckNameDto {
            name: "login.site.example".into(),
            role: "sign-in".into(),
            address: "192.0.2.7".into(),
            route: "primary".into(),
            answer: "answered".into(),
            status: Some(302),
            redirects: vec!["site.example".into()],
        }],
        move_names: vec!["login.site.example".into()],
        reads_answer: true,
    };
    let wire = serde_json::to_value(SiteCheckStatus {
        state: "done".into(),
        host: "site.example".into(),
        report: Some(report),
    })
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        wire["report"],
        json!({
            "site": "site.example",
            "verdict": "sign-in-split",
            "site-route": "secondary",
            "names": [{
                "name": "login.site.example",
                "role": "sign-in",
                "address": "192.0.2.7",
                "route": "primary",
                "answer": "answered",
                "status": 302,
                "redirects": ["site.example"]
            }],
            "move-names": ["login.site.example"],
            "reads-answer": true
        })
    );

    // An answer without the optional parts still reads.
    assert_eq!(wire["state"], "done");
    let running: SiteCheckStatus =
        serde_json::from_value(json!({ "state": "running" })).unwrap_or_else(|e| panic!("{e}"));
    assert!(running.report.is_none() && running.host.is_empty());
    let bare: SiteCheckReport = serde_json::from_value(json!({
        "site": "site.example",
        "verdict": "fine",
        "site-route": "primary",
        "names": []
    }))
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(bare.move_names.is_empty() && !bare.reads_answer);
}

#[test]
fn every_slug_is_kebab_case_and_listed_once() {
    for list in [
        &SITE_CHECK_VERDICTS[..],
        &SITE_CHECK_ANSWERS[..],
        &SITE_CHECK_ROLES[..],
        &SITE_CHECK_STATES[..],
    ] {
        let mut seen = std::collections::HashSet::new();
        for slug in list {
            assert!(seen.insert(*slug), "{slug} twice");
            assert!(
                slug.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "{slug}"
            );
        }
    }
}
