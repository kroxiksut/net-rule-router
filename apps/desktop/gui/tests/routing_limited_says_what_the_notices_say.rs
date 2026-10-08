//! "Routing limited" covers statuses whose traffic fares differently: held,
//! out the default way, or not routed at all. The chip therefore repeats the
//! notices' own headlines, and its fallback names no fate a status may not
//! share — "blocked" contradicted the notice beside it.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

#[test]
fn the_limited_chip_reads_the_notice_headlines() {
    let chip = repo_file("apps/desktop/qml/components/RoutingStatusChip.qml");
    let branch = chip
        .split("chip.statusKey === \"limited\"")
        .nth(1)
        .expect("the chip has a limited branch");
    let branch = &branch[..branch
        .find("return root.tr(\"routing.status.detail-active\"")
        .unwrap_or(branch.len())];
    assert!(
        branch.contains("root.enforcementDownDetail()"),
        "the limited text is not the notices' headlines: {branch}"
    );

    let main = repo_file("apps/desktop/qml/Main.qml");
    let detail = main
        .split("function enforcementDownDetail()")
        .nth(1)
        .expect("Main.qml words the down roles");
    assert!(
        detail[..detail.find("\n    }\n").expect("function end")]
            .contains("enforcementStatusTitle("),
        "the headlines must come from the one status-to-title table"
    );
}

#[test]
fn the_limited_fallback_claims_no_block() {
    for (lang, banned) in [("en", "block"), ("ru", "блокир")] {
        let locale: serde_json::Value =
            serde_json::from_str(&repo_file(&format!("locales/{lang}.json"))).expect("locale");
        let text = locale["routing"]["status"]["detail-limited"]
            .as_str()
            .expect("detail-limited is a text")
            .to_lowercase();
        assert!(!text.contains(banned), "{lang}: {text}");
    }
}
