//! `settings.service-stability.set` — the wire contract shared with the QML shell.
//!
//! The operation has no sparse update: a field the request leaves out falls
//! back to its serde default on the service and silently resets whatever the
//! user had configured. The GUI therefore has to send EVERY field on every
//! write, with the same defaults `nrr-shared` declares.
//!
//! Two things went wrong with exactly that shape, and both were shipped:
//!   * the wire keys were enumerated by hand, once per QML helper, so the list
//!     could drift from the DTO without anything failing, and
//!   * the writer built its payload from the LIVE row alone, so a setting the
//!     user had switched on but whose delivery had failed was re-affirmed at
//!     the service's own default by the next unrelated save — a hardware run
//!     recorded `dns-via-secondary` going out as `false` this way, with the
//!     user's toggle switched on the whole time.
//!
//! The QML side now declares each wire key and its default exactly once, in
//! `apps/desktop/qml/lib/pure.js`, and builds every payload through one merge
//! that overlays the user's recorded decisions. These tests pin both against
//! the DTO here, so a drift fails `cargo test` instead of a hardware run.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nrr_shared::ipc_payloads::ServiceStabilityConfigDto;
use serde_json::{json, Map, Value};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn qml_pure_js() -> String {
    repo_file("apps/desktop/qml/lib/pure.js")
}

/// Extract a `var <name> = <literal>` declaration from the JS source and parse
/// the literal as JSON. Both declaration flavours are written as plain JSON
/// literals precisely so this stays a parse rather than a regex guess.
fn parse_js_literal(source: &str, name: &str, open: char, close: char) -> Value {
    let decl = format!("var {name} = ");
    let start = source
        .find(&decl)
        .unwrap_or_else(|| panic!("`{name}` declaration missing from lib/pure.js"))
        + decl.len();
    let body = &source[start..];
    assert_eq!(
        body.chars().next(),
        Some(open),
        "`{name}` must be declared as a plain {open}…{close} literal"
    );
    let mut depth = 0usize;
    let mut end = None;
    for (idx, ch) in body.char_indices() {
        if ch == open {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 {
                end = Some(idx + ch.len_utf8());
                break;
            }
        }
    }
    let end = end.unwrap_or_else(|| panic!("unbalanced literal in `{name}`"));
    serde_json::from_str(&body[..end])
        .unwrap_or_else(|e| panic!("`{name}` is not a JSON-parsable literal: {e}"))
}

fn qml_object(name: &str) -> Map<String, Value> {
    match parse_js_literal(&qml_pure_js(), name, '{', '}') {
        Value::Object(map) => map,
        other => panic!("{name} must be an object, got {other}"),
    }
}

fn qml_string_array(name: &str) -> Vec<String> {
    match parse_js_literal(&qml_pure_js(), name, '[', ']') {
        Value::Array(items) => items
            .into_iter()
            .map(|item| match item {
                Value::String(s) => s,
                other => panic!("{name} entries must be strings, got {other}"),
            })
            .collect(),
        other => panic!("{name} must be an array, got {other}"),
    }
}

/// The only field of the DTO with no serde default: every payload has to carry
/// it, so every fixture below starts from it.
fn accept_policy_at_defaults() -> Value {
    json!({
        "kind": "recoverable",
        "max-restarts": 20,
        "backoff-base-ms": 100,
        "backoff-cap-ms": 5000,
    })
}

/// A config in which every OPTIONAL field was omitted by the peer, so each one
/// carries exactly the serde default this workspace declares.
fn config_at_wire_defaults() -> Map<String, Value> {
    let minimal = json!({ "ipc-accept-policy": accept_policy_at_defaults() });
    let parsed: ServiceStabilityConfigDto =
        serde_json::from_value(minimal).unwrap_or_else(|e| panic!("minimal config: {e}"));
    match serde_json::to_value(parsed).unwrap_or_else(|e| panic!("config serialises: {e}")) {
        Value::Object(map) => map,
        other => panic!("config must serialise to an object, got {other}"),
    }
}

/// Every wire key of the config row, exactly once, across the three JS lists.
/// A field added to the DTO and forgotten here is the clobber bug: the writer
/// keeps sending complete-looking payloads that quietly drop it.
#[test]
fn qml_stability_lists_cover_every_config_field_exactly_once() {
    let expected: BTreeSet<String> = config_at_wire_defaults().keys().cloned().collect();

    let mut declared: Vec<String> = qml_object("STABILITY_FIELD_DEFAULTS")
        .keys()
        .cloned()
        .collect();
    declared.extend(qml_string_array("STABILITY_STRUCTURED_KEYS"));
    declared.extend(qml_string_array("STABILITY_INTENT_EXCLUDED_KEYS"));

    let unique: BTreeSet<String> = declared.iter().cloned().collect();
    assert_eq!(
        unique.len(),
        declared.len(),
        "a key is declared in more than one of STABILITY_FIELD_DEFAULTS / \
         STABILITY_STRUCTURED_KEYS / STABILITY_INTENT_EXCLUDED_KEYS in \
         apps/desktop/qml/lib/pure.js"
    );

    let missing: Vec<&String> = expected.difference(&unique).collect();
    let unknown: Vec<&String> = unique.difference(&expected).collect();
    assert!(
        missing.is_empty(),
        "apps/desktop/qml/lib/pure.js does not declare {missing:?}; the stability writer \
         derives its payload from those lists, so the field would be dropped from every \
         settings.service-stability.set the GUI sends and reset to its serde default"
    );
    assert!(
        unknown.is_empty(),
        "apps/desktop/qml/lib/pure.js declares {unknown:?}, which \
         ServiceStabilityConfigDto does not accept"
    );
}

/// The GUI's default for a field must be the value the service would have
/// chosen anyway. When the two disagree, a panel renders one value and the next
/// unrelated write pushes the other.
#[test]
fn qml_stability_defaults_match_the_wire_defaults() {
    let wire = config_at_wire_defaults();
    let declared = qml_object("STABILITY_FIELD_DEFAULTS");
    let mut diverged: Vec<(String, Value, Value)> = Vec::new();
    for (key, qml_value) in &declared {
        let wire_value = wire
            .get(key)
            .unwrap_or_else(|| panic!("`{key}` is absent from a serialised config"));
        if wire_value != qml_value {
            diverged.push((key.clone(), wire_value.clone(), qml_value.clone()));
        }
    }
    assert!(
        diverged.is_empty(),
        "default declared twice and drifted (key, wire, qml): {diverged:?} — the Rust side \
         is normative; fix STABILITY_FIELD_DEFAULTS in apps/desktop/qml/lib/pure.js"
    );
}

/// The hazard this whole contract exists for, pinned: a payload that omits a
/// field does not leave it alone, it resets it. `dns-via-secondary` is the
/// field a hardware run lost this way.
#[test]
fn an_omitted_field_is_reset_to_its_default_not_left_alone() {
    let minimal = json!({ "ipc-accept-policy": accept_policy_at_defaults() });
    let parsed: ServiceStabilityConfigDto =
        serde_json::from_value(minimal).unwrap_or_else(|e| panic!("minimal config: {e}"));
    assert!(
        !parsed.dns_via_secondary,
        "an omitted dns-via-secondary must deserialise as OFF — that is precisely why the \
         GUI may never build a partial payload"
    );
    assert!(
        !parsed.fake_ip_enabled,
        "an omitted fake-ip-enabled must deserialise as OFF"
    );
}

/// The single writer must exist, take the user's recorded decisions as an
/// input, and be the only thing whose result reaches the Set RPC. Before this,
/// `_drainStabilityPatchQueue` merged its partial straight onto the live row,
/// which is what let a service default overwrite a decision the user had made.
#[test]
fn the_stability_set_payload_is_built_only_by_the_shared_merge() {
    let pure = qml_pure_js();
    assert!(
        pure.contains("function mergeStabilityWrite(live, intent, parked, partial)"),
        "mergeStabilityWrite must take the live row, the user's recorded intent, the parked \
         offline bucket and this write's partial — dropping the intent argument reintroduces \
         the clobber"
    );

    let main_qml = repo_file("apps/desktop/qml/Main.qml");
    let set_calls = main_qml.matches("rpcServiceStabilityConfigSet(").count();
    assert_eq!(
        set_calls, 1,
        "settings.service-stability.set must have exactly ONE call site in Main.qml; a second \
         builder is how the field list drifts"
    );
    let merged_decl = main_qml
        .find("var merged = Pure.mergeStabilityWrite(")
        .expect("the Set call site must build its payload with Pure.mergeStabilityWrite");
    let set_call = main_qml
        .find("rpcServiceStabilityConfigSet(merged,")
        .expect("the Set call site must send the merge result, not a locally assembled object");
    assert!(
        merged_decl < set_call,
        "the merge must produce the payload the Set RPC sends"
    );
    assert!(
        main_qml.contains("window._readServiceIntent()"),
        "the merge base must include the user's recorded decisions, or a full-row write \
         re-affirms whatever default the service happens to hold"
    );
}

/// Behavioural check of the merge itself, run through the real JS. Skipped when
/// no `node` is on PATH — the structural tests above stay the unconditional
/// guard, this one is the executable proof of the exact regression.
#[test]
fn merge_never_downgrades_a_recorded_intent_to_the_wire_default() {
    let live = Value::Object(config_at_wire_defaults());
    // The user switched DNS-through-the-tunnel on earlier; the service came
    // back with a wiped state DB, so its live row says OFF. An unrelated
    // fake-IP save must not re-affirm that OFF.
    let harness = format!(
        "{source}\n\
         var live = {live};\n\
         var intent = {{\"dns-via-secondary\": true, \"allow-user-rule-edits\": false, \
           \"fake-ip-instant-rst\": false}};\n\
         var parked = {{\"fake-ip-instant-rst\": false}};\n\
         var partial = {{\"fake-ip-enabled\": true}};\n\
         console.log(JSON.stringify(mergeStabilityWrite(live, intent, parked, partial)));\n",
        source = qml_pure_js().replace(".pragma library", ""),
        live = serde_json::to_string(&live).expect("live row serialises"),
    );

    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the executable merge check");
        return;
    };
    let merged: ServiceStabilityConfigDto = serde_json::from_str(output.trim())
        .unwrap_or_else(|e| panic!("merge output is not a config DTO: {e}; output: {output}"));

    assert!(
        merged.dns_via_secondary,
        "a full-row write must carry the user's recorded decision forward; writing `false` \
         here is the defect this contract exists to prevent"
    );
    assert!(
        merged.fake_ip_enabled,
        "the keys this write is changing must win"
    );
    assert!(
        merged.fake_ip_instant_rst,
        "a key the user parked while the service was down is owned by the pending-changes \
         flow, so an unrelated write must leave it at the live value"
    );
    assert_eq!(
        merged.allow_user_rule_edits, None,
        "the machine-wide rules lock must never be carried forward out of one user's \
         preferences"
    );
    assert!(
        merged.dns_fast_answers,
        "untouched fields keep the live value"
    );
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
