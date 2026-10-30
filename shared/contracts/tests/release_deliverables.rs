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

/// The linker's name for an executable's symbols: `nrr-cli.exe` -> `nrr_cli.pdb`.
fn symbols_of(exe: &str) -> String {
    format!("{}.pdb", exe.trim_end_matches(".exe").replace('-', "_"))
}

/// Why a Windows package, EXE or MSI could carry debug symbols, or a shipped
/// executable leave its symbols out of the symbols archive, if either could.
fn windows_symbols_flaw(windows: &str, package: &str, check: &str) -> Option<String> {
    let list = manifest(windows);
    let in_set = |set: &str, path: &str| list.iter().any(|(s, p)| s == set && p == path);
    if let Some((set, path)) = list.iter().find(|(set, path)| {
        ["all", "full", "installer"].contains(&set.as_str())
            && path.to_ascii_lowercase().ends_with(".pdb")
    }) {
        return Some(format!("`{set} {path}` puts debug symbols into a package"));
    }
    for (shipped, symbols) in [("all", "symbols"), ("full", "symbols-full")] {
        for (_, exe) in list
            .iter()
            .filter(|(s, p)| s == shipped && p.ends_with(".exe"))
        {
            // CMake builds the C++ host as Release, which writes no PDB.
            if exe == "nrr_qt_native_host.exe" {
                continue;
            }
            if !in_set(symbols, &symbols_of(exe)) {
                return Some(format!("{exe} has no `{symbols} {}`", symbols_of(exe)));
            }
        }
    }
    if !package.contains("\"$artifactBase-symbols.zip\"") {
        return Some("package-windows.ps1 writes no <artifact>-symbols.zip".into());
    }
    for needle in ["'*-symbols.zip'", "-Symbols", "'*.pdb'"] {
        if !check.contains(needle) {
            return Some(format!(
                "check-windows-package.ps1 no longer checks the symbols ({needle})"
            ));
        }
    }
    None
}

/// Why a user downloading from the release page could not tell the archive
/// that runs from a folder from the installers and the symbols, if they could.
fn windows_portable_flaw(package: &str, check: &str) -> Option<String> {
    if !package.contains("\"$artifactBase-portable.zip\"") {
        return Some("package-windows.ps1 names the archive without -portable".into());
    }
    if !check.contains("'*-portable.zip'") {
        return Some("check-windows-package.ps1 does not look for the -portable.zip".into());
    }
    None
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
    // `alpha.2` is of stage `alpha`.
    let stage = pre.split('.').next().unwrap_or(pre);
    let Some((_, en_word, ru_word)) = STAGES.iter().find(|(suffix, _, _)| *suffix == stage) else {
        return Some(format!(
            "no agreement stage known for version suffix `{pre}`"
        ));
    };
    (en.2 != *en_word || ru.2 != *ru_word).then(|| {
        format!(
            "stage: en `{}`, ru `{}`, version {version} is `{en_word}` / `{ru_word}`",
            en.2, ru.2
        )
    })
}

/// Version suffix and the stage word each agreement names, in release order.
const STAGES: [(&str, &str, &str); 2] = [("alpha", "alpha", "альфа"), ("beta", "beta", "бета")];

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
fn no_windows_package_carries_debug_symbols_and_each_executable_has_them_aside() {
    assert_eq!(
        windows_symbols_flaw(
            &repo_file("packaging/windows/package-contents.txt"),
            &repo_file("scripts/package-windows.ps1"),
            &repo_file("scripts/check-windows-package.ps1"),
        ),
        None
    );
}

#[test]
fn the_windows_archive_says_it_is_the_portable_build() {
    assert_eq!(
        windows_portable_flaw(
            &repo_file("scripts/package-windows.ps1"),
            &repo_file("scripts/check-windows-package.ps1"),
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

    let package = repo_file("scripts/package-windows.ps1");
    let check = repo_file("scripts/check-windows-package.ps1");
    let pdb_shipped = format!("{windows}\nfull       NetRuleRouter.pdb\n");
    assert!(windows_symbols_flaw(&pdb_shipped, &package, &check).is_some());
    let installer_pdb = format!("{windows}\ninstaller  nrr_service.PDB\n");
    assert!(windows_symbols_flaw(&installer_pdb, &package, &check).is_some());
    let tray_unsymbolled = edit(&windows, "NetRuleRouterTray.pdb", "NetRuleRouterTray.map");
    assert!(windows_symbols_flaw(&tray_unsymbolled, &package, &check).is_some());
    let new_exe = format!("{windows}\nall        nrr-helper.exe\n");
    assert!(windows_symbols_flaw(&new_exe, &package, &check).is_some());
    let no_archive = edit(
        &package,
        "\"$artifactBase-symbols.zip\"",
        "\"$artifactBase.zip\"",
    );
    assert!(windows_symbols_flaw(&windows, &no_archive, &check).is_some());
    assert!(check.contains("'*.pdb'"));
    let pdb_unchecked = check.replace("'*.pdb'", "'*.none'");
    assert!(windows_symbols_flaw(&windows, &package, &pdb_unchecked).is_some());
    let unnamed_portable = edit(
        &package,
        "\"$artifactBase-portable.zip\"",
        "\"$artifactBase.zip\"",
    );
    assert!(windows_portable_flaw(&unnamed_portable, &check).is_some());
    let portable_unchecked = check.replace("'*-portable.zip'", "'*.zip'");
    assert!(windows_portable_flaw(&package, &portable_unchecked).is_some());

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
    let ru_revision_ahead = edit(
        &ru,
        &format!("Редакция соглашения {CURRENT_EULA_VERSION} "),
        &format!("Редакция соглашения {} ", CURRENT_EULA_VERSION + 1),
    );
    assert!(agreement_flaw(&en, &ru_revision_ahead, &version).is_some());
    assert!(agreement_flaw(&en, &ru, "0.2.0-alpha.1").is_some());
    // Stages, on agreements forged at each one against a 0.1 build.
    let at_stage = |en_word: &str, ru_word: &str| {
        let en_header = en
            .lines()
            .find(|l| l.starts_with("Agreement revision "))
            .expect("en header");
        let en_stage = en_header.split(" · ").nth(2).expect("en scope");
        let ru_stage = ru_header.split(" · ").nth(2).expect("ru scope");
        (
            edit(
                &en,
                en_stage,
                &format!("applies to {en_word} builds (0.1.x)"),
            ),
            edit(
                &ru,
                ru_stage,
                &format!("относится к сборкам стадии {ru_word} (0.1.x)"),
            ),
        )
    };
    let (en_alpha, ru_alpha) = at_stage("alpha", "альфа");
    assert_eq!(agreement_flaw(&en_alpha, &ru_alpha, "0.1.0-alpha"), None);
    assert_eq!(agreement_flaw(&en_alpha, &ru_alpha, "0.1.0-alpha.2"), None);
    assert!(agreement_flaw(&en_alpha, &ru_alpha, "0.1.0-beta").is_some());
    assert!(agreement_flaw(&en_alpha, &ru_alpha, "0.1.0-dev").is_some());
    // The agreement of the next stage does not cover a build still before it.
    let (en_beta, ru_beta) = at_stage("beta", "бета");
    assert!(agreement_flaw(&en_beta, &ru_beta, "0.1.0-alpha.1").is_some());
    let (en_mixed, _) = at_stage("beta", "бета");
    assert!(agreement_flaw(&en_mixed, &ru_alpha, "0.1.0-alpha").is_some());
}

/// Artifacts were named `...-0.1.0-alpha.1+unknown.msi`: a tree without a
/// usable git state put "unknown" in every download, and the commit is noise
/// on a release page anyway. Names, and the version Apps & Features shows,
/// carry the product version only; the commit stays in build-info.json.
#[test]
fn windows_artifacts_are_named_by_the_version_alone() {
    let package = repo_file("scripts/package-windows.ps1");
    let assigned = |name: &str| -> String {
        package
            .lines()
            .find(|line| line.trim_start().starts_with(&format!("{name} = ")))
            .unwrap_or_else(|| panic!("package-windows.ps1 does not set {name}"))
            .to_owned()
    };
    let line = assigned("$artifactBase");
    let base = line.split('"').nth(1).unwrap_or_default();
    assert!(
        base.contains("$productVersion")
            && !base.contains('+')
            && !base.contains("revision")
            && !base.contains("buildStamp"),
        "an artifact name carries more than the version: {base}"
    );
    for (needle, what) in [
        ("\"/DAppVersion=", "the EXE"),
        ("\"DisplayVersion=", "the MSI"),
    ] {
        let line = package
            .lines()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("{what} is not given its displayed version"));
        let value = line[line.find(needle).expect("needle") + needle.len()..]
            .split('"')
            .next()
            .unwrap_or_default();
        assert_eq!(
            value, "$productVersion",
            "{what} shows another version in Apps & Features: {line}"
        );
    }
    let info = package
        .split("$buildInfo = [ordered]@{")
        .nth(1)
        .and_then(|rest| rest.split("\n}").next())
        .expect("build-info.json fields");
    assert!(
        info.contains("commit         = $revision.commit"),
        "build-info.json lost the commit: {info}"
    );
}

/// The `release` job's steps from its `steps:` line to the end of the file.
fn release_job_steps(workflow: &str) -> &str {
    let job = workflow
        .find("\n  release:\n")
        .expect("release.yml has a release job");
    &workflow[job..]
}

/// No ARM installer has run on ARM hardware, so the release carries the ARM
/// portable archives and holds the ARM installers back: they are built only to
/// catch a broken build. They must be gone before the checksums are taken, or
/// SHA256SUMS would name files the release does not carry.
#[test]
fn arm_installers_are_built_but_not_released() {
    let workflow = repo_file(".github/workflows/release.yml");
    let steps = release_job_steps(&workflow);
    let checksums = steps
        .find("name: Checksums")
        .expect("the release job takes checksums");
    let before = &steps[..checksums];
    for pattern in [
        "NetRuleRouter-windows-arm64-*.exe",
        "NetRuleRouter-windows-arm64-*.msi",
        "*_arm64.deb",
        "*.aarch64.rpm",
    ] {
        assert!(
            before.contains(pattern),
            "the release job does not hold back {pattern} before its checksums"
        );
    }
    assert!(
        !before.contains("windows-arm64-*.zip"),
        "the ARM portable archive is what ships for Windows on ARM"
    );
}

/// Why a Linux build could ship debug info inside a package, or leave a
/// release without the symbols archive of one architecture or flavour.
fn linux_symbols_flaw(script: &str, workflow: &str) -> Option<String> {
    for needle in [
        "--only-keep-debug",
        "--strip-debug",
        "--add-gnu-debuglink",
        "-linux-$arch-symbols",
    ] {
        if !script.contains(needle) {
            return Some(format!("package-linux.sh no longer does `{needle}`"));
        }
    }
    for function in ["check_package", "check_tarball"] {
        if !shell_function(script, function).contains("refuse_symbols ") {
            return Some(format!(
                "{function} does not refuse symbol files in a package"
            ));
        }
    }
    if !workflow.contains("arch: [x86_64, aarch64]") {
        return Some("the Linux jobs no longer build both x86_64 and aarch64".into());
    }
    for keep in [
        "netrulerouter-headless-*-symbols.tar.xz",
        "netrulerouter-[0-9]*-symbols.tar.xz",
    ] {
        if !workflow.contains(keep) {
            return Some(format!("release.yml keeps no `{keep}` from the Linux jobs"));
        }
    }
    None
}

/// Why the Windows symbols archive of an architecture could miss the release.
fn windows_symbols_release_flaw(workflow: &str) -> Option<String> {
    if !workflow.contains("arch: [x64, arm64]") {
        return Some("the Windows job no longer builds both x64 and arm64".into());
    }
    // A test build may skip the symbols; a release never.
    if workflow.contains("-NoSymbols") {
        return Some("the release builds Windows packages without their symbols".into());
    }
    if !workflow.contains("/dist/*.zip") {
        return Some(
            "the Windows job does not upload the *.zip files (portable and symbols)".into(),
        );
    }
    let release = release_job_steps(workflow);
    let before = &release[..release.find("name: Checksums")?];
    // The hold-back removes ARM installers by exact pattern; a pattern that
    // takes a symbols archive goes with them.
    if before.contains("symbols") || before.contains(".tar.xz") || before.contains("arm64-*.zip") {
        return Some("the release job holds back a symbols archive with the ARM installers".into());
    }
    if !before.contains("--notes") && !release.contains("--notes") {
        return Some("the release carries no note about the symbols archives".into());
    }
    if !release.contains("-symbols.zip") || !release.contains("-symbols.tar.xz") {
        return Some("the release note does not name both symbols archive kinds".into());
    }
    None
}

#[test]
fn linux_symbols_leave_the_packages_and_reach_the_release_for_both_architectures() {
    assert_eq!(
        linux_symbols_flaw(
            &repo_file("scripts/package-linux.sh"),
            &repo_file(".github/workflows/release.yml"),
        ),
        None
    );
}

#[test]
fn the_symbols_of_both_windows_architectures_reach_the_release() {
    assert_eq!(
        windows_symbols_release_flaw(&repo_file(".github/workflows/release.yml")),
        None
    );
}

#[test]
fn each_symbols_regression_is_seen() {
    let script = repo_file("scripts/package-linux.sh");
    let workflow = repo_file(".github/workflows/release.yml");
    let edit = |text: &str, from: &str, to: &str| {
        assert!(text.contains(from), "{from:?} is gone");
        text.replacen(from, to, 1)
    };
    // A symbols file inside the package.
    let kept_in_package = edit(
        &script,
        "refuse_symbols \"$(basename \"$file\")\" \"$listing\"\n  top=",
        "top=",
    );
    assert!(linux_symbols_flaw(&kept_in_package, &workflow).is_some());
    let not_stripped = edit(&script, "--strip-debug", "--strip-all-not");
    assert!(linux_symbols_flaw(&not_stripped, &workflow).is_some());
    // A release without the Linux aarch64 (or any) symbols archive.
    let no_aarch64 = edit(&workflow, "arch: [x86_64, aarch64]", "arch: [x86_64]");
    assert!(linux_symbols_flaw(&script, &no_aarch64).is_some());
    let not_kept = edit(&workflow, " netrulerouter-[0-9]*-symbols.tar.xz", "");
    assert!(linux_symbols_flaw(&script, &not_kept).is_some());
    // ARM64 Windows symbols held back together with the ARM installers.
    let held = edit(
        &workflow,
        "arm64-*.msi",
        "arm64-*.msi NetRuleRouter-windows-arm64-*-symbols.zip",
    );
    assert!(windows_symbols_release_flaw(&held).is_some());
    let no_arm = edit(&workflow, "arch: [x64, arm64]", "arch: [x64]");
    assert!(windows_symbols_release_flaw(&no_arm).is_some());
    let unnoted = edit(&workflow, "--notes", "--title-again");
    assert!(windows_symbols_release_flaw(&unnoted).is_some());
    let skipped = edit(
        &workflow,
        "package-windows.ps1 `",
        "package-windows.ps1 -NoSymbols `",
    );
    assert!(windows_symbols_release_flaw(&skipped).is_some());
}
