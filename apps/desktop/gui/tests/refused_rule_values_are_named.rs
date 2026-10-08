//! A rules preview the service refuses says why, at every reader.
//!
//! Such a preview carries no rule changes, so a window that asked "is the diff
//! empty?" first told the user there was nothing to apply — an import bound its
//! files as matching, a drift check stood its alarm down. These tests pin the
//! wire signals the window reads, the order of the two questions at each
//! reader, and the text. Likewise a refused confirm: success is announced
//! from the operation's verdict, never from the confirm's `ok`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nrr_shared::ipc_payloads::RiskSignalDto;

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn locale_leaf(locale: &str, key: &str) -> String {
    let json: serde_json::Value = serde_json::from_str(
        repo_file(&format!("locales/{locale}.json")).trim_start_matches('\u{feff}'),
    )
    .unwrap_or_else(|e| panic!("{locale}.json parses: {e}"));
    key.split('.')
        .try_fold(&json, |node, part| node.get(part))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("{locale}.json has no `{key}`"))
        .to_string()
}

/// Every place `file` asks `empty` is preceded, within the same function, by
/// `refusal`.
fn refusal_is_read_before_emptiness(file: &str, refusal: &str, empty: &str) {
    let source = repo_file(file);
    let mut seen = 0;
    for (at, _) in source.match_indices(empty) {
        let function_start = source[..at].rfind("function ").unwrap_or(0);
        assert!(
            source[function_start..at].contains(refusal),
            "{file}: `{empty}` at byte {at} is not preceded by `{refusal}`; \
             a refused preview has an empty diff and would read as unchanged"
        );
        seen += 1;
    }
    assert!(seen > 0, "{file} no longer asks `{empty}`");
}

#[test]
fn every_preview_reader_asks_about_a_refusal_before_calling_the_diff_empty() {
    refusal_is_read_before_emptiness(
        "apps/desktop/qml/flows/ReviewFlowController.qml",
        "Pure.previewRefusal(summary)",
        "Pure.reviewSummaryIsEmpty(summary)",
    );
    refusal_is_read_before_emptiness(
        "apps/desktop/qml/flows/PresetImportController.qml",
        "_announcePreviewRefusal(summary)",
        "Pure.reviewSummaryIsEmpty(summary)",
    );
    refusal_is_read_before_emptiness(
        "apps/desktop/qml/Main.qml",
        "Pure.previewRefusal(summary)",
        "_summaryHasNoRuleChanges(summary)",
    );
}

/// The body of `function <name>(` in `source`, up to its closing brace at the
/// four-space indent every controller function uses.
fn function_body<'a>(file: &str, source: &'a str, name: &str) -> (usize, &'a str) {
    let start = source
        .find(&format!("function {name}("))
        .unwrap_or_else(|| panic!("{file}: `{name}` is gone"));
    let rest = &source[start..];
    (start, &rest[..rest.find("\n    }\n").unwrap_or(rest.len())])
}

/// Where success is announced for one confirmed mutation: `confirm` sends the
/// confirm, and each marker is a success-only side effect. With `completion`,
/// the markers live in that function, entered once from the outcome read;
/// without, they sit in `confirm` behind the outcome read.
struct ConfirmedMutation {
    file: &'static str,
    confirm: &'static str,
    completion: Option<&'static str>,
    markers: &'static [&'static str],
}

const CONFIRMED_MUTATIONS: &[ConfirmedMutation] = &[
    ConfirmedMutation {
        file: "apps/desktop/qml/flows/ReviewFlowController.qml",
        confirm: "_executeRulesActivation",
        completion: Some("_completeRulesActivation"),
        markers: &[
            "status.rules-activate-completed",
            "_persistBoundFilesAfterApply()",
            "_captureRulesDirtyBaseline()",
        ],
    },
    ConfirmedMutation {
        file: "apps/desktop/qml/flows/ReviewFlowController.qml",
        confirm: "_executeResetToBaselineActivation",
        completion: Some("_completeResetToBaseline"),
        markers: &[
            "status.reset-baseline-completed",
            "root.reloadActiveRulesFromService()",
        ],
    },
    ConfirmedMutation {
        file: "apps/desktop/qml/flows/PresetImportController.qml",
        confirm: "_executePresetImportActivation",
        completion: Some("_completePresetImportActivation"),
        markers: &[
            "status.preset-import-completed",
            "_bindImportedSourcePaths(st)",
            "root._refreshRulesFromService({ silent: true })",
        ],
    },
    ConfirmedMutation {
        file: "apps/desktop/qml/flows/FullResetController.qml",
        confirm: "applyEmptyRules",
        completion: None,
        markers: &["onComplete(failure === \"\")"],
    },
    ConfirmedMutation {
        file: "apps/desktop/qml/sections/DiagnosticsSection.qml",
        confirm: "_confirmAlertAck",
        completion: None,
        markers: &[
            "section._alertAckSettledByState(alertId, read)",
            "diag.alert.ack-completed",
        ],
    },
];

const OUTCOME_READ: &str = "root.rpc.readMutationOutcome(";

/// A confirm's `ok` only accepts the change. Every flow that confirms a
/// mutation announces success — status text, cleared flags, written files,
/// refreshed lists — from the operation's verdict, read through the one
/// shared helper.
#[test]
fn every_confirmed_mutation_announces_success_only_from_its_outcome() {
    for flow in CONFIRMED_MUTATIONS {
        let file = flow.file;
        let source = repo_file(file);
        assert!(
            !source.contains("rpcOperationStatusGet"),
            "{file}: the operation record is read through `{OUTCOME_READ}` only"
        );
        let (confirm_at, confirm) = function_body(file, &source, flow.confirm);
        let outcome = confirm.find(OUTCOME_READ).unwrap_or_else(|| {
            panic!(
                "{file}: `{}` must read the outcome of its confirm",
                flow.confirm
            )
        });
        let (_, home) = match flow.completion {
            Some(completion) => {
                let calls: Vec<usize> = source
                    .match_indices(&format!("{completion}("))
                    .map(|(at, _)| at)
                    .filter(|&at| !source[..at].ends_with("function "))
                    .collect();
                assert_eq!(calls.len(), 1, "{file}: one way into `{completion}`");
                let call = calls[0];
                assert!(
                    call > confirm_at + outcome && call < confirm_at + confirm.len(),
                    "{file}: `{completion}` is entered from the outcome read"
                );
                function_body(file, &source, completion)
            }
            None => (confirm_at + outcome, &confirm[outcome..]),
        };
        for marker in flow.markers {
            let everywhere = source.matches(marker).count();
            assert!(everywhere > 0, "{file}: `{marker}` is gone");
            assert_eq!(
                everywhere,
                home.matches(marker).count(),
                "{file}: `{marker}` must run only once the outcome is known"
            );
        }
    }
}

/// One helper reads the verdict; a record this account cannot read is settled
/// from what the service holds now, never from the confirm.
#[test]
fn the_outcome_is_read_in_one_place() {
    let transport = repo_file("apps/desktop/qml/flows/RpcTransport.qml");
    for needed in [
        "function readMutationOutcome(",
        "rpcOperationStatusGet(operationId)",
        "Pure.operationOutcome(ok, status)",
        "function settleByPreview(",
        "Pure.previewOutcome(",
    ] {
        assert!(
            transport.contains(needed),
            "RpcTransport.qml: `{needed}` is gone"
        );
    }
}

/// A refusal's values travel with that refusal. Kept in one shared slot, the
/// next failure without values was worded with the previous one's network.
#[test]
fn a_failure_is_worded_with_its_own_values() {
    let transport = repo_file("apps/desktop/qml/flows/RpcTransport.qml");
    assert!(
        transport.contains("else done(failure, Pure.operationFailureArgs(status))"),
        "RpcTransport.qml: the outcome read hands the failure's values to `done`"
    );
    for (file, announce) in [
        (
            "apps/desktop/qml/flows/ReviewFlowController.qml",
            "_announceRulesActivationFailed",
        ),
        (
            "apps/desktop/qml/flows/PresetImportController.qml",
            "_announcePresetImportFailed",
        ),
    ] {
        let source = repo_file(file);
        assert!(
            !source.contains("lastFailureArgs"),
            "{file}: values read from a shared slot may belong to another refusal"
        );
        let (_, body) = function_body(file, &source, announce);
        assert!(
            body.contains("ipcErrorLabel(String(code || \"unknown\"), args || null)"),
            "{file}: `{announce}` words the failure with the values it was given"
        );
        assert!(
            source.contains(&format!("{announce}(code, null)")),
            "{file}: a refusal of the confirm itself carries no outcome values"
        );
        assert!(
            source.contains(&format!("{announce}(failure, failureArgs)")),
            "{file}: a refused outcome passes its own values"
        );
    }
    assert!(!transport.contains("lastFailureArgs"));
}

/// The audit-chain restart reads its verdict through the same helper; only its
/// own answers to a changed or intact chain stay in the dialog.
#[test]
fn the_audit_chain_restart_reads_its_outcome_through_the_shared_helper() {
    let file = "apps/desktop/qml/components/AuditChainRestartDialog.qml";
    let source = repo_file(file);
    assert!(
        !source.contains("rpcOperationStatusGet("),
        "{file}: the operation record is read through the shared helper only"
    );
    let (confirm_at, confirm) = function_body(file, &source, "_confirm");
    let outcome = confirm
        .find("ownerRoot.rpc.readMutationOutcome(")
        .unwrap_or_else(|| panic!("{file}: `_confirm` must read the outcome of its confirm"));
    let calls: Vec<usize> = source
        .match_indices("_onOutcome(")
        .map(|(at, _)| at)
        .filter(|&at| !source[..at].ends_with("function "))
        .collect();
    assert_eq!(calls.len(), 1, "{file}: one way into `_onOutcome`");
    assert!(calls[0] > confirm_at + outcome && calls[0] < confirm_at + confirm.len());
    let (_, home) = function_body(file, &source, "_onOutcome");
    for marker in [
        "diag.audit.restart.completed",
        "failure === \"audit-chain-changed\"",
        "failure === \"audit-chain-intact\"",
    ] {
        assert_eq!(source.matches(marker).count(), 1, "{file}: `{marker}`");
        assert_eq!(home.matches(marker).count(), 1, "{file}: `{marker}`");
    }
}

/// A failed alert acknowledgement is named by its code's text, never the code.
#[test]
fn an_alert_acknowledgement_failure_is_named() {
    let file = "apps/desktop/qml/sections/DiagnosticsSection.qml";
    let source = repo_file(file);
    let (_, announce) = function_body(file, &source, "_announceAlertAckFailed");
    assert!(
        announce.contains("root.ipcErrorLabel(code)") && !announce.contains("String(code"),
        "{file}: the failure shows the code's text"
    );
    for locale in ["en", "ru"] {
        for code in [
            "alert-not-found",
            "illegal-state-transition",
            "alerts-storage-failure",
            "alerts-store-unavailable",
            "malformed-payload",
            "unknown",
        ] {
            assert!(
                !locale_leaf(locale, &format!("errors.{code}")).is_empty(),
                "{locale}: errors.{code}"
            );
        }
    }
}

#[test]
fn both_locales_name_the_refused_values() {
    for locale in ["en", "ru"] {
        assert!(
            locale_leaf(locale, "risk.signal.invalid-rule-value").contains("{rules}"),
            "{locale}: the preview text must carry the values"
        );
        for code in [
            "invalid-rule-value",
            "unsupported-rule-shape",
            "control-character",
            "rule-cap-exceeded",
            "auto-rule-cap-exceeded",
            // What a preset the service cannot read is refused with.
            "malformed-payload",
            "payload-too-large",
            "file-encoding",
            "too-many-rules",
            "match-value-too-long",
            "inline-comment-too-long",
            "canonicalize-rejected",
            "preset-validation-failed",
        ] {
            assert!(
                !locale_leaf(locale, &format!("errors.{code}")).is_empty(),
                "{locale}: a refusal is named by its code's text"
            );
        }
    }
}

/// Executable half, through the real `pure.js`. Skipped when no `node` is on
/// PATH — the structural tests above stay the unconditional guard.
#[test]
fn the_window_reads_the_refusals_the_service_sends() {
    let signal = |s: RiskSignalDto| {
        serde_json::to_value(s).unwrap_or_else(|e| panic!("signal serialises: {e}"))
    };
    let values = serde_json::json!({ "risk-signals": [signal(RiskSignalDto::InvalidRuleValue {
        rules: vec!["123".into(), "192.0.2.1".into()],
    })] });
    let shape = serde_json::json!({ "risk-signals": [signal(RiskSignalDto::ChangeRefused {
        code: "unsupported-rule-shape".into(),
        args: Default::default(),
    })] });
    let network = serde_json::json!({ "risk-signals": [signal(RiskSignalDto::ChangeRefused {
        code: "network-covers-link".into(),
        args: std::collections::BTreeMap::from([
            ("rule".to_owned(), "r1".to_owned()),
            ("network".to_owned(), "10.0.0.0/8".to_owned()),
            ("covers-kind".to_owned(), "tunnel-server".to_owned()),
            ("covers".to_owned(), "10.1.2.3".to_owned()),
        ]),
    })] });
    let other = serde_json::json!({
        "risk-signals": [{ "kind": "apply-will-be-refused" }]
    });
    let harness = format!(
        "{source}\n\
         console.log(refusedRuleValuesText({values}));\n\
         console.log(JSON.stringify(previewRefusal({values})));\n\
         console.log(JSON.stringify(previewRefusal({shape})));\n\
         console.log(JSON.stringify(previewRefusal({other})));\n\
         console.log(JSON.stringify(previewRefusal({{}})));\n\
         console.log(reviewSummaryIsEmpty({shape}));\n\
         console.log(JSON.stringify(operationOutcome(true, {{ state: 'completed' }})));\n\
         console.log(operationOutcome(true, {{ state: 'failed', error: {{ code: 'control-character' }} }}));\n\
         console.log(operationOutcome(true, {{ state: 'running' }}));\n\
         console.log(operationOutcome(false, null));\n\
         console.log(JSON.stringify(previewOutcome({{}}, reviewSummaryIsEmpty)));\n\
         console.log(previewOutcome({shape}, reviewSummaryIsEmpty));\n\
         console.log(previewOutcome({{ 'rules-added': [{{}}] }}, reviewSummaryIsEmpty));\n\
         console.log(JSON.stringify(refusalDetail('network-covers-link', previewRefusal({network}).args)));\n\
         console.log(fillPlaceholders('{{network}} / {{covers}}', {{ network: 'a', covers: 'b' }}));\n\
         console.log(JSON.stringify(refusalDetail('network-covers-link', null)));\n\
         console.log(JSON.stringify(refusalDetail('unsupported-rule-shape', {{ network: 'x' }})));\n\
         console.log(JSON.stringify(operationFailureArgs({{ state: 'failed', error: {{ code: 'c', args: {{ network: 'n' }} }} }})));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the executable check");
        return;
    };
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(
        lines,
        [
            "123, 192.0.2.1",
            r#"{"code":"invalid-rule-value","values":"123, 192.0.2.1"}"#,
            r#"{"code":"unsupported-rule-shape","values":"","args":null}"#,
            "null",
            "null",
            // Why the refusal has to be asked first.
            "true",
            // The operation record's verdict.
            r#""""#,
            "control-character",
            "null",
            "null",
            // A re-preview after a record this account cannot read.
            r#""""#,
            "unsupported-rule-shape",
            "unknown",
            // A refused network names itself and what it covers.
            r#"{"key":"errors.network-covers-link-tunnel-server","values":{"network":"10.0.0.0/8","covers":"10.1.2.3"}}"#,
            "a / b",
            "null",
            "null",
            r#"{"network":"n"}"#,
        ],
        "{output}"
    );
}

/// The sentences a named network refusal reads as exist in both languages and
/// keep their placeholders.
#[test]
fn a_refused_network_has_a_sentence_in_both_languages() {
    for locale in ["en", "ru"] {
        for (key, placeholders) in [
            (
                "network-covers-link-tunnel-server",
                &["{network}", "{covers}"][..],
            ),
            (
                "network-covers-link-local-network",
                &["{network}", "{covers}"][..],
            ),
            ("network-covers-fake-ip-pool-named", &["{network}"][..]),
        ] {
            let text = locale_leaf(locale, &format!("errors.{key}"));
            assert!(!text.is_empty(), "{locale}: errors.{key}");
            for placeholder in placeholders {
                assert!(
                    text.contains(placeholder),
                    "{locale}: errors.{key} lacks {placeholder}"
                );
            }
        }
    }
}

/// Feed a program to `node` on stdin. `None` when node is not installed.
fn run_node(program: &str) -> Option<String> {
    let mut child = Command::new("node")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let Some(stdin) = child.stdin.as_mut() else {
        panic!("stdin was piped")
    };
    stdin
        .write_all(program.as_bytes())
        .unwrap_or_else(|e| panic!("write the harness to node: {e}"));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("node runs to completion: {e}"));
    assert!(
        out.status.success(),
        "node rejected the harness: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}
