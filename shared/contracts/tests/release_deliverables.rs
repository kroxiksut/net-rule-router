#![allow(clippy::expect_used)]

//! What every released package must carry and how the packaging proves it.
//! The gate never builds a package: a break here would surface only in a
//! release, or in a user's hands.

use std::path::{Path, PathBuf};

use nrr_shared::eula::CURRENT_EULA_VERSION;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn repo_file(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// `(set, path)` lines of a package contents list.
fn manifest(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((fields.next()?.to_owned(), fields.next()?.to_owned()))
        })
        .collect()
}

/// The body of shell function `name`, up to its closing brace at column 0.
fn shell_function<'a>(script: &'a str, name: &str) -> &'a str {
    let head = format!("\n{name}() {{\n");
    let Some(at) = script.find(&head) else {
        return "";
    };
    let body = &script[at + head.len()..];
    &body[..body.find("\n}\n").unwrap_or(body.len())]
}

/// Why a Linux package could leave the script without its contents checked.
fn linux_contents_flaw(script: &str) -> Option<String> {
    for (function, builder) in [("build_deb", "dpkg-deb "), ("build_rpm", "rpmbuild ")] {
        let body = shell_function(script, function);
        // One check for the base package, one for the GUI package.
        let checks = body
            .find(builder)
            .map_or(0, |built| body[built..].matches("check_package ").count());
        if checks < 2 {
            return Some(format!(
                "{function} checks {checks} of the base and GUI packages it builds"
            ));
        }
    }
    let built = script.matches("\n  build_tarball \"").count();
    let checked = script.matches("\n  check_tarball \"").count();
    (built == 0 || built != checked).then(|| format!("{built} archives built, {checked} checked"))
}

/// The vendored crates the Linux build compiles in, by folder under third_party.
fn vendored_into_linux() -> Vec<String> {
    repo_file("core/platform/linux/Cargo.toml")
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| {
            let at = line.find("third_party/")? + "third_party/".len();
            let name: String = line[at..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

/// The licence texts a vendored crate keeps beside its source.
fn licence_texts(crate_dir: &str) -> Vec<String> {
    let dir = repo_root().join("third_party").join(crate_dir);
    let mut texts: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.starts_with("LICENSE"))
        .collect();
    texts.sort();
    texts
}

/// Why a package could ship without the third-party notices, if one could.
fn notices_flaw(windows: &str, linux: &str, script: &str) -> Option<String> {
    let windows = manifest(windows);
    let linux = manifest(linux);
    let lists = |list: &[(String, String)], set: &str, path: &str| {
        list.iter().any(|(s, p)| s == set && p == path)
    };
    if !lists(&windows, "all", "licenses\\THIRD_PARTY_LICENSES.md") {
        return Some("the Windows packages do not require THIRD_PARTY_LICENSES.md".into());
    }
    let mut linux_required = vec![
        (
            "base",
            "@libexec@/licenses/THIRD_PARTY_LICENSES.md".to_owned(),
        ),
        ("archive", "THIRD_PARTY_LICENSES.md".to_owned()),
    ];
    for vendored in vendored_into_linux() {
        let texts = licence_texts(&vendored);
        if texts.is_empty() {
            return Some(format!("third_party/{vendored} keeps no LICENSE file"));
        }
        for text in texts {
            linux_required.push(("base", format!("@libexec@/licenses/{vendored}-{text}")));
        }
    }
    if let Some((set, path)) = linux_required
        .iter()
        .find(|(set, path)| !lists(&linux, set, path))
    {
        return Some(format!(
            "packaging/linux/package-contents.txt lacks `{set} {path}`"
        ));
    }
    // A .deb or .rpm of the GUI alone carries the notice in its own doc folder.
    let check = shell_function(script, "check_package");
    (!check.contains("/usr/share/doc/$package/THIRD_PARTY_LICENSES.md"))
        .then(|| "check_package does not require the notice in each package's doc folder".into())
}

/// `(revision, date as YYYY-MM-DD, stage, series)` from an agreement header.
fn agreement_header(
    text: &str,
    lead: &str,
    stage_lead: &str,
) -> Option<(u32, String, String, String)> {
    let line = text.lines().find(|l| l.starts_with(lead))?;
    let mut parts = line[lead.len()..].split(" · ");
    let revision = parts.next()?.trim().parse().ok()?;
    let date = parts.next()?.trim().to_owned();
    let date = match date.split('.').collect::<Vec<_>>().as_slice() {
        [day, month, year] => format!("{year}-{month}-{day}"),
        _ => date,
    };
    let scope = parts.next()?.trim();
    let scope = scope.strip_prefix(stage_lead)?;
    let open = scope.rfind(" (")?;
    let stage = scope[..open].trim_end_matches(" builds").to_owned();
    let series = scope[open + 2..].strip_suffix(')')?.to_owned();
    Some((revision, date, stage, series))
}

fn workspace_version() -> String {
    let cargo = repo_file("Cargo.toml");
    let section = &cargo[cargo
        .find("[workspace.package]")
        .expect("[workspace.package]")..];
    let line = section
        .lines()
        .find(|l| l.trim_start().starts_with("version"))
        .expect("workspace version");
    line.split('"').nth(1).expect("quoted version").to_owned()
}

/// Why the agreement a user accepts could disagree with itself, the build
/// or the release it ships in, if it could.
fn agreement_flaw(en: &str, ru: &str, version: &str) -> Option<String> {
    let Some(en) = agreement_header(en, "Agreement revision ", "applies to ") else {
        return Some(
            "eula.en.md: no `Agreement revision N · date · applies to … (M.m.x)` header".into(),
        );
    };
    let Some(ru) = agreement_header(ru, "Редакция соглашения ", "относится к сборкам стадии ")
    else {
        return Some("eula.ru.md: no `Редакция соглашения N · дата · относится к сборкам стадии … (M.m.x)` header".into());
    };
    if en.0 != ru.0 || en.0 != CURRENT_EULA_VERSION {
        return Some(format!(
            "revisions: en {}, ru {}, compiled in {CURRENT_EULA_VERSION}",
            en.0, ru.0
        ));
    }
    if en.1 != ru.1 {
        return Some(format!("dates: en {}, ru {}", en.1, ru.1));
    }
    let (numbers, pre) = version.split_once('-').unwrap_or((version, ""));
    let series: Vec<&str> = numbers.split('.').take(2).collect();
    let series = format!("{}.x", series.join("."));
    if en.3 != series || ru.3 != series {
        return Some(format!(
            "series: en {}, ru {}, version {version}",
            en.3, ru.3
        ));
    }
    let stage = match pre {
        "prealpha" => ("pre-alpha", "пре-альфа"),
        "alpha" => ("alpha", "альфа"),
        "beta" => ("beta", "бета"),
        other => {
            return Some(format!(
                "no agreement stage known for version suffix `{other}`"
            ))
        }
    };
    (en.2 != stage.0 || ru.2 != stage.1).then(|| {
        format!(
            "stage: en `{}`, ru `{}`, version {version} is `{}` / `{}`",
            en.2, ru.2, stage.0, stage.1
        )
    })
}

#[test]
fn a_linux_package_is_checked_against_its_list_as_it_is_built() {
    assert_eq!(
        linux_contents_flaw(&repo_file("scripts/package-linux.sh")),
        None
    );
}

#[test]
fn every_package_carries_the_third_party_notices() {
    assert_eq!(
        notices_flaw(
            &repo_file("packaging/windows/package-contents.txt"),
            &repo_file("packaging/linux/package-contents.txt"),
            &repo_file("scripts/package-linux.sh"),
        ),
        None
    );
}

#[test]
fn the_agreement_agrees_across_languages_with_the_build_and_the_release_stage() {
    assert_eq!(
        agreement_flaw(
            &repo_file("docs/legal/eula.en.md"),
            &repo_file("docs/legal/eula.ru.md"),
            &workspace_version(),
        ),
        None
    );
}

/// The release day itself is known only when a tag is pushed, so the guard
/// holds it; this keeps the guard and its self-test at it.
#[test]
fn the_release_guard_holds_the_agreement_to_the_release_day() {
    let guard = repo_file("scripts/release-guard.sh");
    for needle in [
        "eula.en.md",
        "eula.ru.md",
        "Редакция соглашения",
        "--format=%ct",
    ] {
        assert!(
            guard.contains(needle),
            "release-guard.sh no longer reads {needle}"
        );
    }
    let self_test = repo_file("scripts/tests/release-guard/run.sh");
    assert!(self_test.contains("case_name=\"agreement keeps an old date\""));
    assert!(self_test.contains("case_name=\"the two languages name different days\""));
}

/// The checks above must see each break they exist for.
#[test]
fn each_deliverable_regression_is_seen() {
    let script = repo_file("scripts/package-linux.sh");
    let edit = |text: &str, from: &str, to: &str| {
        assert!(text.contains(from), "{from:?} is gone");
        text.replacen(from, to, 1)
    };
    let unchecked_rpm = edit(
        &script,
        "    check_package \"$out_dir/$file\" \"$package\" \"${NRR_PACKAGE_UNIT_FILES[0]%/*}\" base service\n",
        "    :\n",
    );
    assert!(linux_contents_flaw(&unchecked_rpm).is_some());
    let unchecked_tar = edit(&script, "\n  check_tarball \"", "\n  : \"");
    assert!(linux_contents_flaw(&unchecked_tar).is_some());

    let windows = repo_file("packaging/windows/package-contents.txt");
    let linux = repo_file("packaging/linux/package-contents.txt");
    let windows_without = edit(
        &windows,
        "licenses\\THIRD_PARTY_LICENSES.md",
        "licenses\\README.md",
    );
    assert!(notices_flaw(&windows_without, &linux, &script).is_some());
    let linux_without = edit(
        &linux,
        "@libexec@/licenses/tappers-LICENSE-MIT",
        "@libexec@/licenses/x",
    );
    assert!(notices_flaw(&windows, &linux_without, &script).is_some());
    let doc_unchecked = edit(
        &script,
        "/usr/share/doc/$package/THIRD_PARTY_LICENSES.md",
        "/x",
    );
    assert!(notices_flaw(&windows, &linux, &doc_unchecked).is_some());

    let en = repo_file("docs/legal/eula.en.md");
    let ru = repo_file("docs/legal/eula.ru.md");
    let version = workspace_version();
    let ru_header = ru
        .lines()
        .find(|l| l.starts_with("Редакция соглашения "))
        .expect("ru header")
        .to_owned();
    let ru_date = ru_header.split(" · ").nth(1).expect("ru date");
    let ru_other_day = edit(&ru, &format!(" · {ru_date} · "), " · 01.01.1999 · ");
    assert!(agreement_flaw(&en, &ru_other_day, &version).is_some());
    let ru_revision_two = ru.replacen("Редакция соглашения 1 ", "Редакция соглашения 2 ", 1);
    assert!(agreement_flaw(&en, &ru_revision_two, &version).is_some());
    let next_stage = if version.ends_with("-alpha") {
        "0.1.0-beta"
    } else {
        "0.1.0-alpha"
    };
    assert!(agreement_flaw(&en, &ru, next_stage).is_some());
    assert!(agreement_flaw(&en, &ru, "0.2.0-prealpha").is_some());
}
