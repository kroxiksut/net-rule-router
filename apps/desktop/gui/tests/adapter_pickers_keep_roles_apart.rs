//! An adapter bound to one route is not offered for the other, and each one is
//! shown with the hint the service's own recommendation gives it. Runs the real
//! `pure.js` through `node`; the executable half is skipped when node is absent.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn an_adapter_holding_one_role_is_withheld_from_the_other() {
    let harness = format!(
        "{source}\n\
         console.log([adapterHeldOtherRole({{ selectedRole: 'primary' }}, 'secondary'),\n\
                      adapterHeldOtherRole({{ selectedRole: 'primary' }}, 'primary'),\n\
                      adapterHeldOtherRole({{ selectedRole: '' }}, 'primary'),\n\
                      adapterHeldOtherRole(null, 'primary')].join(','));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the executable check");
        return;
    };
    assert_eq!(output.trim(), "primary,,,", "{output}");
}

#[test]
fn the_hint_comes_from_the_recommendation_and_never_repeats_the_kind() {
    let harness = format!(
        "{source}\n\
         var main = {{ kind: 'ethernet', recommendation: {{ 'class': 'preferred-primary' }} }};\n\
         var vpn = {{ kind: 'other', recommendation: {{ 'class': 'preferred-secondary' }},\n\
                     derivedAssessment: {{ vpnTunnelLikelihood: 'possible' }} }};\n\
         var tunnel = {{ kind: 'tunnel', recommendation: {{ 'class': 'preferred-secondary' }},\n\
                        derivedAssessment: {{ vpnTunnelLikelihood: 'likely' }} }};\n\
         var plain = {{ kind: 'wifi', recommendation: {{ 'class': 'allowed-but-not-recommended' }},\n\
                       derivedAssessment: {{ vpnTunnelLikelihood: 'possible' }} }};\n\
         console.log([adapterRoleHintSlug(main), adapterRoleHintSlug(vpn),\n\
                      adapterRoleHintSlug(tunnel), adapterRoleHintSlug(plain),\n\
                      adapterRoleHintSlug(null)].join(','));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let Some(output) = run_node(&harness) else {
        eprintln!("node not available — skipping the executable check");
        return;
    };
    assert_eq!(output.trim(), "looks-primary,looks-vpn,,,", "{output}");
}

#[test]
fn both_surfaces_consult_the_rule() {
    let wizard = repo_file("apps/desktop/qml/components/FirstRunWindow.qml");
    for (role, combo) in [
        ("primary", "firstRunPrimaryCombo"),
        ("secondary", "firstRunSecondaryCombo"),
    ] {
        assert!(
            wizard.contains(&format!(
                "return Pure.adapterHeldOtherRole(item, \"{role}\") === \"\""
            )),
            "the wizard's {role} picker offers an adapter holding the other role"
        );
        assert!(
            wizard.contains(&format!(
                "firstRunWindow._offeredFor({combo}.currentIndex, \"{role}\")"
            )),
            "the wizard's {role} button acts on a withheld adapter"
        );
    }
    let screen = repo_file("apps/desktop/qml/sections/InterfacesRoutesSection.qml");
    assert!(
        screen.contains("!_someoneElseHoldsPrimary && !_holdsSecondaryHere")
            && screen.contains("!_someoneElseHoldsSecondary && !_holdsPrimaryHere"),
        "the interfaces screen lets one adapter take both roles"
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
