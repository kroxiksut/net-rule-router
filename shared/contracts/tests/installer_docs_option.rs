#![allow(clippy::expect_used)]

//! The offline documentation is the installing person's choice in both
//! installers: offered ticked, left out when they untick it or say so on a
//! silent command line, and kept as chosen on the next upgrade. Read from the
//! installer sources: nothing in the gate builds them.

use std::path::Path;

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    let text = std::fs::read_to_string(&path).expect("a packaging file");
    text.trim_start_matches('\u{feff}').replace("\r\n", "\n")
}

fn line_with<'a>(text: &'a str, needle: &str) -> Option<&'a str> {
    text.lines().find(|line| line.contains(needle))
}

#[test]
fn the_exe_offers_the_documentation_ticked_and_takes_it_away_when_unticked() {
    let iss = read("packaging/windows/NetRuleRouter.iss");
    let component = line_with(&iss, "Name: \"docs\"").expect("a docs component");
    assert!(
        component.contains("Types: selected") && !component.contains("fixed"),
        "ticked by default and optional: {component}"
    );
    let main = line_with(&iss, "Source: \"{#PackageDir}\\*\"").expect("the package files");
    assert!(
        main.contains("\\docs"),
        "the pages come only with the component: {main}"
    );
    let pages = line_with(&iss, "Source: \"{#PackageDir}\\docs\\*\"").expect("the pages");
    assert!(pages.contains("Components: docs"), "{pages}");
    assert!(pages.contains("recursesubdirs"), "{pages}");
    let cleared = line_with(&iss, "Name: \"{app}\\docs\"").expect("the pages are cleared");
    assert!(
        cleared.contains("filesandordirs"),
        "an upgrade or an untick leaves no page behind: {cleared}"
    );
    for language in ["english", "russian"] {
        assert!(
            iss.contains(&format!("{language}.ComponentDocs=")),
            "{language}"
        );
    }
    assert!(
        iss.contains("/COMPONENTS="),
        "the silent choice is documented"
    );
}

#[test]
fn the_msi_offers_the_documentation_ticked_silently_too_and_remembers_it() {
    let wxs = read("packaging/windows/NetRuleRouter.wxs");
    assert!(wxs.contains("<Property Id=\"NRR_DOCS\" Secure=\"yes\" />"));
    let default = line_with(&wxs, "Action=\"SetNrrDocsDefault\"").expect("a default");
    let default_condition = wxs[wxs.find("Action=\"SetNrrDocsDefault\"").expect("default")..]
        .lines()
        .take(2)
        .collect::<String>();
    assert!(
        default.contains("Id=\"NRR_DOCS\"")
            && default_condition.contains("NRR_PREV_DOCS=&quot;state1&quot;")
            && default_condition.contains("Value=\"1\""),
        "ticked unless an earlier install left it out: {default_condition}"
    );
    assert!(line_with(&wxs, "Condition=\"NRR_DOCS=&quot;0&quot;\"").is_some());
    assert!(line_with(&wxs, "Key=\"SOFTWARE\\NetRuleRouter\\Setup\" Name=\"Docs\"").is_some());
    assert!(
        wxs.contains("<RegistryValue Name=\"Docs\" Type=\"string\" Value=\"state[NRR_DOCS]\" />")
    );
    let checkbox = line_with(&wxs, "Property=\"NRR_DOCS\"").expect("a box on the options page");
    assert!(checkbox.contains("Type=\"CheckBox\""), "{checkbox}");
    assert!(
        wxs.contains("<Exclude Files=\"!(bindpath.pkg)\\docs\\**\" />"),
        "the pages come only with the choice"
    );
    assert!(wxs.contains("<ComponentGroupRef Id=\"DocsFiles\" />"));
    assert!(
        wxs.contains("NRR_DOCS=0"),
        "the silent choice is documented"
    );
    for culture in ["en-US", "ru-RU"] {
        let wxl = read(&format!("packaging/windows/NetRuleRouter.{culture}.wxl"));
        assert!(wxl.contains("Id=\"NrrDocs\""), "{culture}");
    }
    // The pages' components are written by the package script, each held to the choice.
    let script = read("scripts/package-windows.ps1");
    assert!(script.contains("Condition=\"NRR_DOCS=&quot;1&quot;\""));
    assert!(script.contains("DocsFiles"));
}
