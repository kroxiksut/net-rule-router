//! Picking another VPN program while its gateway search runs must not show
//! the earlier program's addresses: «Add rules» would pin program A's gateway
//! under program B's name.

use std::path::Path;

#[test]
fn a_gateway_answer_for_an_earlier_program_is_dropped() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml/components/VpnGatewayHelper.qml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n");
    let reset = text
        .split("function _reset() {")
        .nth(1)
        .and_then(|rest| rest.split("\n    }").next())
        .unwrap_or_else(|| panic!("no _reset"));
    assert!(
        reset.contains("_findSeq += 1"),
        "a reset retires the search in flight"
    );
    let find = text
        .split("function find() {")
        .nth(1)
        .and_then(|rest| rest.split("\n    function ").next())
        .unwrap_or_else(|| panic!("no find"));
    let guard = find
        .find("if (seq !== helper._findSeq")
        .unwrap_or_else(|| panic!("the answer is not checked against the current search"));
    let stored = find
        .find("helper._candidates = list")
        .unwrap_or_else(|| panic!("candidates are no longer stored"));
    assert!(guard < stored, "the check comes before the answer is taken");
}
