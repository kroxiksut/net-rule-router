#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

fn commit_result(status: &str) -> String {
    js::run_js(&format!(
        r#"
        {}
        {}
        {}
        var status = {};
        var bridgeReady = true, bridgeAvailable = true, moved = "not-updated";
        var submitter = {{ baseRevisionMoved: function(base) {{ moved = base }} }};
        var bridge = {{ rpcOperationStatusGet: function() {{ return "status" }} }};
        var nrrNativeBridge = {{ rpcMutationSubmit: function() {{ return "confirm" }} }};
        var transport = {{
            securityAlertGateCode: "security-alert-unacknowledged",
            _settleRefusal: function(gate, done) {{ done() }}
        }};
        function registerRpcCallback(corr, done) {{ done(true, status) }}
        var rpc = {{
            registerLongRpcCallback: function(corr, done) {{ done(true, {{"operation-id": "op-1"}}) }},
            readMutationOutcome: readMutationOutcome,
            settleByPreview: function() {{ return function(done) {{ done("application-unconfirmed") }} }}
        }};
        commit({{}}, "token", function(ok, r) {{
            console.log(JSON.stringify({{ok: ok, code: r.failure, moved: moved}}))
        }});
        "#,
        qml_functions::pure(),
        qml_functions::functions("flows/RpcTransport.qml", &["readMutationOutcome"]),
        qml_functions::functions("flows/RulesSubmitter.qml", &["commit"]),
        status,
    ))
}

#[test]
fn partial_apply_reaches_the_rules_caller_and_updates_the_saved_revision() {
    let output = commit_result(
        r#"{"state":"completed","result":{"outcome":"applied-with-drift","base-revision":"rev-saved"}}"#,
    );
    assert_eq!(
        output.trim(),
        r#"{"ok":false,"code":"applied-with-drift","moved":"rev-saved"}"#
    );
}

#[test]
fn fully_applied_rules_still_report_success() {
    let output = commit_result(
        r#"{"state":"completed","result":{"outcome":"activated","base-revision":"rev-saved"}}"#,
    );
    assert_eq!(
        output.trim(),
        r#"{"ok":true,"code":"","moved":"rev-saved"}"#
    );
}

#[test]
fn partial_apply_refreshes_rules_without_announcing_full_activation() {
    let output = js::run_js(&format!(
        r#"
        {}
        var refreshed = 0, completed = 0;
        function _guardMutationElevation() {{ return true }}
        function _forgetMergeInFlight() {{}}
        function _resolveGuardRulesApply(ok) {{}}
        function _offerMergeIfChangedElsewhere() {{ return false }}
        function _announceRulesActivationFailed() {{}}
        function _completeRulesActivation() {{ completed++ }}
        var root = {{
            bridgeAvailable: true, pendingReviewState: {{}}, statusLine: "",
            _refreshRulesFromService: function() {{ refreshed++ }},
            refreshBackendStatus: function() {{}},
            tr: function(k, fallback) {{ return fallback }}
        }};
        var submitter = {{
            commit: function(s, t, done) {{
                done(false, {{incomplete:true, failure:"applied-with-drift"}}); return true
            }},
            describeFailure: function() {{ return "partial-warning" }}
        }};
        _executeRulesActivation("token");
        console.log(refreshed, completed, root.statusLine);
        "#,
        qml_functions::functions(
            "flows/ReviewFlowController.qml",
            &["_executeRulesActivation"]
        ),
    ));
    assert!(output.ends_with("1 0 partial-warning\n"), "{output}");
}
