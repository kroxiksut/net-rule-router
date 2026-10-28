#![allow(clippy::expect_used)]

//! What the release workflow must keep doing for a tag to produce a set users
//! can install and verify. Nothing in the gate runs it: a regression here is
//! found only by the first tag that needs it.

use std::collections::HashSet;
use std::path::Path;

use yaml_rust2::{Yaml, YamlLoader};

fn repo_file(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn release_workflow() -> String {
    repo_file(".github/workflows/release.yml")
}

/// The workflow, or a bad value every lookup misses: a check must report what
/// it cannot find, never pass on it.
fn load(workflow: &str) -> Yaml {
    YamlLoader::load_from_str(workflow)
        .ok()
        .and_then(|docs| docs.into_iter().next())
        .unwrap_or(Yaml::BadValue)
}

fn needs(job: &Yaml) -> Vec<String> {
    match &job["needs"] {
        Yaml::String(one) => vec![one.clone()],
        Yaml::Array(many) => many
            .iter()
            .filter_map(|n| n.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// Whether `job` waits for `target`, directly or through the jobs it needs.
fn waits_for(doc: &Yaml, job: &str, target: &str) -> bool {
    let mut stack = needs(&doc["jobs"][job]);
    let mut seen = HashSet::new();
    while let Some(next) = stack.pop() {
        if next == target {
            return true;
        }
        if seen.insert(next.clone()) {
            stack.extend(needs(&doc["jobs"][next.as_str()]));
        }
    }
    false
}

fn job_names(doc: &Yaml) -> Vec<String> {
    doc["jobs"]
        .as_hash()
        .map(|jobs| {
            jobs.keys()
                .filter_map(|k| k.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The permissions a job grants with `write`.
fn writes(job: &Yaml) -> Vec<String> {
    job["permissions"]
        .as_hash()
        .map(|perms| {
            perms
                .iter()
                .filter(|(_, level)| level.as_str() == Some("write"))
                .filter_map(|(scope, _)| scope.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Every `run:` of a job, in order, joined.
fn job_runs(job: &Yaml) -> String {
    job["steps"]
        .as_vec()
        .map(|steps| {
            steps
                .iter()
                .filter_map(|s| s["run"].as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// Why a tag could reach a build without the guard, if it could.
fn guard_flaw(workflow: &str) -> Option<String> {
    let doc = load(workflow);
    let guard = &doc["jobs"]["guard"];
    if guard.is_badvalue() {
        return Some("no guard job".into());
    }
    let runs = job_runs(guard);
    if !runs.contains("bash scripts/release-guard.sh") {
        return Some("the guard job does not run scripts/release-guard.sh".into());
    }
    if !runs.contains("--tag \"$GITHUB_REF_NAME\"") {
        return Some("the guard is not told which tag it checks".into());
    }
    if !writes(guard).is_empty() {
        return Some(format!("the guard may write: {:?}", writes(guard)));
    }
    job_names(&doc)
        .into_iter()
        .filter(|name| name != "guard")
        .find(|name| !waits_for(&doc, name, "guard"))
        .map(|name| format!("job {name} does not wait for the guard"))
}

/// The glibc version a document promises the packages without a GUI run on.
fn documented_glibc_floor(doc: &str, before: &str) -> Option<String> {
    let at = doc.find(before)? + before.len();
    let version: String = doc[at..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    (!version.is_empty()).then_some(version)
}

/// Why a headless binary needing a newer glibc than documented could ship.
fn glibc_floor_flaw(workflow: &str, docs: &[(String, &str)]) -> Option<String> {
    let doc = load(workflow);
    let runs = job_runs(&doc["jobs"]["linux"]);
    let Some(line) = runs.lines().find(|l| l.contains("--max-glibc ")) else {
        return Some("the Linux packaging does not pass --max-glibc".into());
    };
    if !line.contains("= headless ]") {
        return Some(format!(
            "--max-glibc is not tied to the headless variant: {line}"
        ));
    }
    let Some(asserted) = documented_glibc_floor(line, "--max-glibc ") else {
        return Some(format!("--max-glibc names no version: {line}"));
    };
    for (text, before) in docs {
        let promised = documented_glibc_floor(text, before);
        if promised.as_deref() != Some(asserted.as_str()) {
            return Some(format!(
                "the build allows glibc {asserted}, the documentation promises {promised:?}"
            ));
        }
    }
    None
}

fn glibc_docs() -> Vec<(String, &'static str)> {
    vec![
        (repo_file("docs/en/packaging-linux.md"), "built on a glibc "),
        (
            repo_file("docs/ru/packaging-linux.md"),
            "на системе с glibc ",
        ),
    ]
}

/// Why a Windows package could be uploaded without its contents checked.
fn windows_contents_flaw(workflow: &str) -> Option<String> {
    let doc = load(workflow);
    let steps = doc["jobs"]["windows"]["steps"]
        .as_vec()
        .cloned()
        .unwrap_or_default();
    let position = |hit: &dyn Fn(&Yaml) -> bool| steps.iter().position(hit);
    let package = position(&|s| s["name"].as_str() == Some("Package"));
    let check = position(&|s| {
        s["run"].as_str().is_some_and(|r| {
            r.contains("scripts\\check-windows-package.ps1")
                && r.contains("-Variant ${{ matrix.variant }}")
        })
    });
    let upload = position(&|s| {
        s["uses"]
            .as_str()
            .is_some_and(|u| u.starts_with("actions/upload-artifact@"))
    });
    match (package, check, upload) {
        (Some(p), Some(c), Some(u)) if p < c && c < u => None,
        _ => Some(format!(
            "package {package:?}, contents check {check:?}, upload {upload:?}: the check must sit between them"
        )),
    }
}

/// Why a released file could lack provenance, or a job hold a right it does
/// not need, if either could.
fn attestation_flaw(workflow: &str) -> Option<String> {
    let doc = load(workflow);
    let top: Vec<String> = doc["permissions"]
        .as_hash()
        .map(|p| {
            p.iter()
                .filter_map(|(k, v)| Some(format!("{}: {}", k.as_str()?, v.as_str()?)))
                .collect()
        })
        .unwrap_or_default();
    if top != ["contents: read"] {
        return Some(format!("workflow-wide permissions are {top:?}"));
    }
    for name in job_names(&doc) {
        for scope in writes(&doc["jobs"][name.as_str()]) {
            let owner = match scope.as_str() {
                "id-token" | "attestations" => "attest",
                "contents" => "release",
                _ => "",
            };
            if owner != name {
                return Some(format!("job {name} may write {scope}"));
            }
        }
    }
    let attest = &doc["jobs"]["attest"];
    let steps = attest["steps"].as_vec().cloned().unwrap_or_default();
    let Some(provenance) = steps.iter().find(|s| {
        s["uses"]
            .as_str()
            .is_some_and(|u| u.starts_with("actions/attest-build-provenance@"))
    }) else {
        return Some("no attest-build-provenance step in the attest job".into());
    };
    if provenance["with"]["subject-path"].as_str() != Some("artifacts/*") {
        return Some("not every downloaded artifact is attested".into());
    }
    let downloads_all = steps.iter().any(|s| {
        s["uses"]
            .as_str()
            .is_some_and(|u| u.starts_with("actions/download-artifact@"))
            && s["with"]["path"].as_str() == Some("artifacts")
            && s["with"]["merge-multiple"].as_bool() == Some(true)
    });
    if !downloads_all {
        return Some("attest does not gather every artifact into artifacts/".into());
    }
    // Every job that uploads a deliverable is attested before the release.
    for name in job_names(&doc) {
        let uploads = doc["jobs"][name.as_str()]["steps"]
            .as_vec()
            .is_some_and(|steps| {
                steps.iter().any(|s| {
                    s["uses"]
                        .as_str()
                        .is_some_and(|u| u.starts_with("actions/upload-artifact@"))
                })
            });
        if uploads && name != "release" && !needs(attest).contains(&name) {
            return Some(format!("attest does not wait for {name}"));
        }
    }
    (!needs(&doc["jobs"]["release"]).contains(&"attest".to_owned()))
        .then(|| "the release does not wait for attest".into())
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
fn a_tag_reaches_no_build_before_the_guard_passes() {
    assert_eq!(guard_flaw(&release_workflow()), None);
}

#[test]
fn a_headless_binary_needing_a_newer_glibc_than_documented_fails_the_release() {
    assert_eq!(glibc_floor_flaw(&release_workflow(), &glibc_docs()), None);
}

#[test]
fn a_windows_package_is_checked_against_its_list_before_upload() {
    assert_eq!(windows_contents_flaw(&release_workflow()), None);
}

#[test]
fn every_released_file_is_attested_and_only_two_jobs_may_write() {
    assert_eq!(attestation_flaw(&release_workflow()), None);
}

/// The four checks above must see each break they exist for.
#[test]
fn each_release_gate_regression_is_seen() {
    let workflow = release_workflow();
    let without = |from: &str, to: &str| {
        assert!(
            workflow.contains(from),
            "{from:?} is no longer in the workflow"
        );
        workflow.replacen(from, to, 1)
    };
    let linux_unguarded = without(
        "    needs: guard\n    runs-on: ${{ matrix.runner }}\n    strategy:\n      fail-fast: false\n      matrix:\n        arch: [x86_64",
        "    runs-on: ${{ matrix.runner }}\n    strategy:\n      fail-fast: false\n      matrix:\n        arch: [x86_64",
    );
    // A check that cannot find what it looks for reports it.
    for check in [guard_flaw, windows_contents_flaw, attestation_flaw] {
        assert!(check("jobs: {}\n").is_some());
    }
    assert!(glibc_floor_flaw("jobs: {}\n", &glibc_docs()).is_some());

    assert!(guard_flaw(&linux_unguarded).is_some());
    assert!(guard_flaw(&without("--tag \"$GITHUB_REF_NAME\"", "")).is_some());
    assert!(guard_flaw(&without("      actions: read\n", "      actions: write\n")).is_some());

    assert!(glibc_floor_flaw(&without("--max-glibc 2.28 ", ""), &glibc_docs()).is_some());
    assert!(glibc_floor_flaw(
        &without("--max-glibc 2.28", "--max-glibc 2.31"),
        &glibc_docs()
    )
    .is_some());

    let unchecked = without(
        "-Dist \"$env:RUNNER_TEMP\\dist\" -Variant",
        "-Dist \"$env:RUNNER_TEMP\\dist\"",
    );
    assert!(windows_contents_flaw(&unchecked).is_some());

    assert!(attestation_flaw(&without(
        "needs: [windows, linux, attest]",
        "needs: [windows, linux]"
    ))
    .is_some());
    assert!(
        attestation_flaw(&without("needs: [windows, linux]\n", "needs: [windows]\n")).is_some()
    );
    assert!(attestation_flaw(&without(
        "subject-path: artifacts/*",
        "subject-path: artifacts/*.zip"
    ))
    .is_some());
    assert!(attestation_flaw(&without(
        "    permissions:\n      contents: write\n",
        "    permissions:\n      contents: write\n      id-token: write\n",
    ))
    .is_some());
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
