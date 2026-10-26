#![allow(clippy::expect_used)]

//! What the release workflow must keep doing for a tag to produce a set users
//! can install and verify. Nothing in the gate runs it: a regression here is
//! found only by the first tag that needs it.

use std::path::Path;

use yaml_rust2::{Yaml, YamlLoader};

fn release_workflow() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/release.yml");
    std::fs::read_to_string(path)
        .expect("the release workflow")
        .replace("\r\n", "\n")
}

/// Every step named `name`, in any job.
fn steps_named(doc: &Yaml, name: &str) -> Vec<Yaml> {
    let Some(jobs) = doc["jobs"].as_hash() else {
        return Vec::new();
    };
    jobs.values()
        .filter_map(|job| job["steps"].as_vec())
        .flatten()
        .filter(|step| step["name"].as_str() == Some(name))
        .cloned()
        .collect()
}

/// Why the full package could not take the Qt licence texts, if it could not:
/// they come from the Qt documentation, which the Qt step must install.
fn qt_docs_missing(workflow: &str) -> Option<String> {
    let doc = YamlLoader::load_from_str(workflow)
        .ok()?
        .into_iter()
        .next()?;
    let steps = steps_named(&doc, "Install Qt");
    if steps.is_empty() {
        return Some("no \"Install Qt\" step".into());
    }
    steps.iter().find_map(|step| {
        let with = &step["with"];
        if with["documentation"].as_bool() != Some(true) {
            return Some("Install Qt does not install the documentation".into());
        }
        let archives = with["doc-archives"].as_str().unwrap_or_default();
        (!archives.split_whitespace().any(|a| a == "qtdoc"))
            .then(|| "the qtdoc archive (the licence texts) is not installed".into())
    })
}

/// Why the signed checksums could ship unverifiable, if they could.
fn signing_flaw(workflow: &str) -> Option<String> {
    let doc = YamlLoader::load_from_str(workflow)
        .ok()?
        .into_iter()
        .next()?;
    let steps = steps_named(&doc, "Sign the checksums");
    let [step] = steps.as_slice() else {
        return Some(format!("{} signing steps", steps.len()));
    };
    let run = step["run"].as_str().unwrap_or_default();
    let at = |needle: &str| run.find(needle);
    let ordered =
        |first: &str, then: &str| matches!((at(first), at(then)), (Some(a), Some(b)) if a < b);
    if !ordered("apt-get update", "apt-get install") {
        return Some("the package index is not refreshed before minisign is installed".into());
    }
    if !run.contains("pub=\"$GITHUB_WORKSPACE/source/packaging/minisign.pub\"") {
        return Some("the public key is not the one in the repository".into());
    }
    if !ordered("minisign -S", "minisign -V -p \"$pub\"") {
        return Some("the signature is not verified with the public key after signing".into());
    }
    if !run.contains("cp \"$pub\" minisign.pub") {
        return Some("the public key users verify with is not published".into());
    }
    None
}

#[test]
fn the_full_package_installs_the_qt_licence_texts() {
    assert_eq!(qt_docs_missing(&release_workflow()), None);
}

#[test]
fn the_checksum_signature_is_verified_with_the_key_in_the_repository() {
    assert_eq!(signing_flaw(&release_workflow()), None);
}

/// The two checks above must see each break they exist for.
#[test]
fn each_release_regression_is_seen() {
    let workflow = release_workflow();
    let without = |from: &str, to: &str| {
        assert!(
            workflow.contains(from),
            "{from:?} is no longer in the workflow"
        );
        workflow.replacen(from, to, 1)
    };
    assert!(qt_docs_missing(&without("documentation: true", "documentation: false")).is_some());
    assert!(qt_docs_missing(&without("doc-archives: qtdoc", "doc-archives: qtbase")).is_some());
    assert!(signing_flaw(&without("sudo apt-get update\n", "")).is_some());
    assert!(signing_flaw(&without("minisign -V -p \"$pub\" -m SHA256SUMS\n", "")).is_some());
    assert!(signing_flaw(&without(
        "source/packaging/minisign.pub",
        "source/minisign.pub"
    ))
    .is_some());
}
