#![allow(clippy::expect_used)]

//! The order dpkg and rpm see between builds. A build that sorts below the one
//! installed is refused as a downgrade, so alpha.2 would never replace an
//! alpha.1 install, nor beta an alpha.
//!
//! The version mapping is the shell function the packager calls; the stage
//! order is the Windows installers' rank, so both platforms agree on it. The
//! comparators below are dpkg's and rpm's algorithms, held to vectors from
//! their own documentation so the proof does not grade itself.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
mod rank {
    include!("../../../packaging/windows/version_rank.rs");
}

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("\r\n", "\n")
}

// ── dpkg ─────────────────────────────────────────────────────────────────────

/// dpkg's character weight: `~` below the end of the string, letters below
/// everything else that is not a digit.
fn dpkg_weight(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(c) => i32::from(c) + 256,
    }
}

/// `verrevcmp` from dpkg's `lib/dpkg/version.c`.
fn dpkg_part(a: &[u8], b: &[u8]) -> Ordering {
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        while a.get(i).is_some_and(|c| !c.is_ascii_digit())
            || b.get(j).is_some_and(|c| !c.is_ascii_digit())
        {
            let (x, y) = (
                dpkg_weight(a.get(i).copied()),
                dpkg_weight(b.get(j).copied()),
            );
            if x != y {
                return x.cmp(&y);
            }
            i += 1;
            j += 1;
        }
        while a.get(i) == Some(&b'0') {
            i += 1;
        }
        while b.get(j) == Some(&b'0') {
            j += 1;
        }
        let mut first_diff = Ordering::Equal;
        while a.get(i).is_some_and(u8::is_ascii_digit) && b.get(j).is_some_and(u8::is_ascii_digit) {
            if first_diff == Ordering::Equal {
                first_diff = a[i].cmp(&b[j]);
            }
            i += 1;
            j += 1;
        }
        if a.get(i).is_some_and(u8::is_ascii_digit) {
            return Ordering::Greater;
        }
        if b.get(j).is_some_and(u8::is_ascii_digit) {
            return Ordering::Less;
        }
        if first_diff != Ordering::Equal {
            return first_diff;
        }
    }
    Ordering::Equal
}

/// `upstream-revision`, no epoch: what the packager writes.
fn dpkg_compare(a: &str, b: &str) -> Ordering {
    let (au, ar) = a.rsplit_once('-').unwrap_or((a, ""));
    let (bu, br) = b.rsplit_once('-').unwrap_or((b, ""));
    dpkg_part(au.as_bytes(), bu.as_bytes()).then(dpkg_part(ar.as_bytes(), br.as_bytes()))
}

// ── rpm ──────────────────────────────────────────────────────────────────────

/// `rpmvercmp` from rpm's `rpmio/rpmvercmp.c`, tilde included.
fn rpm_part(a: &[u8], b: &[u8]) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let separator = |c: &u8| !c.is_ascii_alphanumeric() && *c != b'~';
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        while a.get(i).is_some_and(separator) {
            i += 1;
        }
        while b.get(j).is_some_and(separator) {
            j += 1;
        }
        let (x, y) = (a.get(i) == Some(&b'~'), b.get(j) == Some(&b'~'));
        if x || y {
            if !x {
                return Ordering::Greater;
            }
            if !y {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if i >= a.len() || j >= b.len() {
            break;
        }
        let (si, sj) = (i, j);
        let numeric = a[i].is_ascii_digit();
        let kind = |c: &u8| {
            if numeric {
                c.is_ascii_digit()
            } else {
                c.is_ascii_alphabetic()
            }
        };
        while a.get(i).is_some_and(kind) {
            i += 1;
        }
        while b.get(j).is_some_and(kind) {
            j += 1;
        }
        if sj == j {
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let (mut x, mut y) = (&a[si..i], &b[sj..j]);
        if numeric {
            while x.first() == Some(&b'0') {
                x = &x[1..];
            }
            while y.first() == Some(&b'0') {
                y = &y[1..];
            }
            match x.len().cmp(&y.len()) {
                Ordering::Equal => {}
                other => return other,
            }
        }
        match x.cmp(y) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    match (i >= a.len(), j >= b.len()) {
        (true, true) => Ordering::Equal,
        (false, _) => Ordering::Greater,
        (true, false) => Ordering::Less,
    }
}

/// `version-release`, no epoch: the `Version:` and `Release:` the spec gets.
fn rpm_compare(a: &str, b: &str) -> Ordering {
    let (av, ar) = a.rsplit_once('-').expect("version-release");
    let (bv, br) = b.rsplit_once('-').expect("version-release");
    rpm_part(av.as_bytes(), bv.as_bytes()).then(rpm_part(ar.as_bytes(), br.as_bytes()))
}

/// The comparators answer as dpkg and rpm document they do; otherwise the
/// order proved below would be the test's own opinion.
#[test]
fn the_comparators_order_as_the_package_managers_document() {
    // Debian policy 5.6.12: `~~` < `~~a` < `~` < (end) < `a`.
    let debian = ["1.0~~-1", "1.0~~a-1", "1.0~-1", "1.0-1", "1.0a-1"];
    for pair in debian.windows(2) {
        assert_eq!(dpkg_compare(pair[0], pair[1]), Ordering::Less, "{pair:?}");
        assert_eq!(
            dpkg_compare(pair[1], pair[0]),
            Ordering::Greater,
            "{pair:?}"
        );
    }
    assert_eq!(dpkg_compare("1.10-1", "1.9-1"), Ordering::Greater);
    assert_eq!(dpkg_compare("1.0-2", "1.0-10"), Ordering::Less);
    // rpm's own test vectors (tests/rpmvercmp.at).
    for (a, b, want) in [
        ("1.0~rc1", "1.0", Ordering::Less),
        ("1.0~rc1", "1.0~rc2", Ordering::Less),
        ("1.0~rc1~git123", "1.0~rc1", Ordering::Less),
        ("1.0a", "1.0", Ordering::Greater),
        ("1.10", "1.9", Ordering::Greater),
        ("1.0", "1.0", Ordering::Equal),
        ("a", "1", Ordering::Less),
    ] {
        assert_eq!(rpm_part(a.as_bytes(), b.as_bytes()), want, "{a} vs {b}");
        assert_eq!(
            rpm_part(b.as_bytes(), a.as_bytes()),
            want.reverse(),
            "{b} vs {a}"
        );
    }
}

// ── the mapping the packager uses ────────────────────────────────────────────

/// The arms of `nrr_package_version`: each stage and the tildes before it.
fn mapping_arms() -> Vec<(String, usize)> {
    let lib = repo_file("scripts/lib/workspace-version.sh");
    let body = lib
        .split_once("nrr_package_version() {")
        .map(|(_, rest)| rest.split_once("\n}").map_or(rest, |(body, _)| body))
        .expect("scripts/lib/workspace-version.sh: no nrr_package_version()");
    let mut arms = Vec::new();
    for line in body.lines() {
        let Some((pattern, action)) = line.split_once(')') else {
            continue;
        };
        let Some(format) = action
            .split_once("printf '%s")
            .and_then(|(_, f)| f.split_once('\''))
            .map(|(f, _)| f)
        else {
            continue;
        };
        let tildes = format.chars().take_while(|c| *c == '~').count();
        if tildes == 0 {
            continue;
        }
        for stage in pattern.split('|') {
            arms.push((stage.trim().to_owned(), tildes));
        }
    }
    assert!(!arms.is_empty(), "nrr_package_version has no tilde arms");
    arms
}

/// What the packager makes of `0.1.0-<pre>`, revision 1.
fn package_version(arms: &[(String, usize)], pre: &str) -> String {
    if pre.is_empty() {
        return "0.1.0-1".to_owned();
    }
    let stage = pre.split('.').next().unwrap_or(pre);
    let tildes = arms
        .iter()
        .find(|(s, _)| s == stage)
        .map(|(_, t)| *t)
        .unwrap_or_else(|| panic!("nrr_package_version has no arm for '{stage}'"));
    format!("0.1.0{}{pre}-1", "~".repeat(tildes))
}

/// Every later build upgrades every earlier one in dpkg and rpm alike: the
/// alpha over a dev install, a beta over the alpha, the release over all.
#[test]
fn a_later_build_upgrades_every_earlier_one() {
    let arms = mapping_arms();
    let builds = [
        "dev", "alpha", "alpha.1", "alpha.2", "alpha.10", "beta", "beta.1", "rc", "rc.1", "rc.2",
        "",
    ];
    for older in builds {
        for newer in builds {
            let (ro, rn) = (
                rank::prerelease_rank(older).expect("rank"),
                rank::prerelease_rank(newer).expect("rank"),
            );
            if ro >= rn {
                continue;
            }
            let (o, n) = (package_version(&arms, older), package_version(&arms, newer));
            assert_eq!(
                dpkg_compare(&o, &n),
                Ordering::Less,
                "dpkg keeps {o} over {n}"
            );
            assert_eq!(
                rpm_compare(&o, &n),
                Ordering::Less,
                "rpm keeps {o} over {n}"
            );
        }
    }
}

/// The packager takes the version through that mapping, not a substitution of
/// its own.
#[test]
fn the_packager_versions_through_the_mapping() {
    let script = repo_file("scripts/package-linux.sh");
    assert!(
        script.contains("package_version=\"$(nrr_package_version \"$version\")\""),
        "package-linux.sh does not take its package version from nrr_package_version"
    );
}
