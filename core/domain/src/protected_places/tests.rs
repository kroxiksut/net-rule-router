use super::*;
use crate::canonical::CanonicalAppMatch;

use super::ProtectionReason as R;
use super::ProtectionVerdict::{Allowed, Refused, Warn};
use super::RuleEffect::{Deny, PrimaryRoute, SecondaryRoute};

fn windows() -> ProtectedPlaces {
    ProtectedPlaces::defaults(HostPlatform::Windows)
}
fn linux() -> ProtectedPlaces {
    ProtectedPlaces::defaults(HostPlatform::Linux)
}
fn macos() -> ProtectedPlaces {
    ProtectedPlaces::defaults(HostPlatform::MacOS)
}

/// A value the way the rules file will write it: a trailing `*` segment is
/// "with subfolders", a trailing separator a folder, a separator a path.
fn target(value: &str) -> AppTarget<'_> {
    if let Some(folder) = value
        .strip_suffix("\\*")
        .or_else(|| value.strip_suffix("/*"))
    {
        return AppTarget::FolderTree(if folder.is_empty() { "/" } else { folder });
    }
    if value.ends_with(['\\', '/']) {
        return AppTarget::Folder(value);
    }
    if value.contains(['\\', '/']) {
        // A bare `/opt` is a folder: no executable sits at a first-level path.
        let last = value.rsplit(['\\', '/']).next().unwrap_or_default();
        return if last.contains('.') || value.matches(['\\', '/']).count() > 1 {
            AppTarget::File(value)
        } else {
            AppTarget::Folder(value)
        };
    }
    if value.contains('*') {
        AppTarget::NameGlob(value)
    } else {
        AppTarget::Name(value)
    }
}

/// `!value` is a deny, anything else a rule of `route`.
fn verdict(places: &ProtectedPlaces, written: &str, route: RuleEffect) -> ProtectionVerdict {
    match written.strip_prefix('!') {
        Some(value) => protection_verdict(target(value), Deny, places),
        None => protection_verdict(target(written), route, places),
    }
}

// ── The examples the protection is accepted by ────────────────────────────────

#[test]
fn every_refused_example_is_refused() {
    for (places, written, route) in [
        (windows(), "!svchost.exe", PrimaryRoute),
        (windows(), r"!C:\Windows\*", PrimaryRoute),
        (windows(), r"!C:\*", PrimaryRoute),
        (linux(), "!/opt", PrimaryRoute),
        (linux(), "!/home/*", PrimaryRoute),
        (linux(), "!/usr/bin/", PrimaryRoute),
        (linux(), "!/usr/lib/systemd/*", PrimaryRoute),
        (linux(), "/usr/lib/*", SecondaryRoute),
        (windows(), r"C:\Program Files\*", SecondaryRoute),
    ] {
        assert!(
            verdict(&places, written, route).is_refused(),
            "{written} on {:?}",
            places.platform()
        );
    }
}

#[test]
fn a_programs_own_folder_inside_a_shared_one_is_accepted() {
    assert_eq!(
        verdict(&linux(), "/usr/lib/firefox/*", SecondaryRoute),
        Allowed
    );
    assert_eq!(
        verdict(&windows(), r"C:\Program Files\App\*", SecondaryRoute),
        Allowed
    );
    assert_eq!(
        verdict(&linux(), "!/usr/lib/firefox/*", PrimaryRoute),
        Allowed
    );
    assert_eq!(
        verdict(&windows(), r"!C:\Program Files\App\*", PrimaryRoute),
        Allowed
    );
    assert_eq!(verdict(&linux(), "/opt/app/*", SecondaryRoute), Allowed);
    assert_eq!(
        verdict(&linux(), "!/var/www/site1/*", PrimaryRoute),
        Allowed
    );
}

#[test]
fn one_file_in_a_system_folder_is_accepted_with_a_warning() {
    assert_eq!(
        verdict(&windows(), r"!C:\Windows\System32\curl.exe", PrimaryRoute),
        Warn(R::FileInSystemFolder)
    );
    assert_eq!(
        verdict(&linux(), "!/usr/bin/curl", PrimaryRoute),
        Warn(R::FileInSystemFolder)
    );
    assert_eq!(
        verdict(&windows(), r"C:\Windows\System32\curl.exe", SecondaryRoute),
        Warn(R::FileInSystemFolder)
    );
}

// ── Reasons ───────────────────────────────────────────────────────────────────

#[test]
fn each_refusal_names_its_reason() {
    for (places, written, reason) in [
        (windows(), "!svchost.exe", R::CriticalProcess),
        (windows(), r"!C:\Windows\*", R::SystemFolder),
        (windows(), r"!C:\*", R::DiskRoot),
        (windows(), r"!D:\", R::DiskRoot),
        (windows(), r"!\\server\share\*", R::DiskRoot),
        (linux(), "!/*", R::DiskRoot),
        (linux(), "!/", R::DiskRoot),
        (linux(), "!/opt", R::SharedFolder),
        (linux(), "!/home/*", R::SharedFolder),
        (linux(), "!/home/alice/", R::SharedFolder),
        (linux(), "!/usr/bin/", R::SystemFolder),
        (linux(), "!/usr/lib/systemd/*", R::SystemFolder),
        (
            linux(),
            "!/usr/lib64/NetworkManager/dispatcher.d/*",
            R::SystemFolder,
        ),
        (linux(), "!/usr/lib/*", R::SharedFolder),
        (linux(), "!/usr/*", R::SharedFolder),
        (linux(), "!/var/www/*", R::SharedFolder),
        (linux(), "!/snap/bin/", R::SearchPathFolder),
        (windows(), r"!C:\Program Files\*", R::SharedFolder),
        (windows(), r"!C:\Program Files (x86)\", R::SharedFolder),
        (windows(), r"!C:\Users\*", R::SharedFolder),
        (windows(), r"!C:\Users\alice\", R::SharedFolder),
        (windows(), r"!C:\inetpub\wwwroot\*", R::SharedFolder),
        (macos(), "!/Applications/*", R::SharedFolder),
        (macos(), "!/System/Library/*", R::SystemFolder),
        (macos(), "!/usr/libexec/*", R::SystemFolder),
    ] {
        assert_eq!(
            verdict(&places, written, PrimaryRoute),
            Refused(reason),
            "{written} on {:?}",
            places.platform()
        );
    }
}

#[test]
fn a_folder_above_a_system_folder_is_refused_with_subfolders_only() {
    let mut places = ProtectedPlaces::empty(HostPlatform::Linux);
    places.add_system_folder("/data/system");
    assert_eq!(
        verdict(&places, "!/data/*", PrimaryRoute),
        Refused(R::SystemFolder)
    );
    assert_eq!(verdict(&places, "!/data/", PrimaryRoute), Allowed);
    assert_eq!(
        verdict(&places, "!/data/system/deep/", PrimaryRoute),
        Refused(R::SystemFolder)
    );
}

#[test]
fn a_reason_slug_round_trips_and_only_the_root_and_ourselves_are_final() {
    for reason in ProtectionReason::ALL {
        assert_eq!(ProtectionReason::from_slug(reason.slug()), Some(reason));
    }
    assert_eq!(ProtectionReason::from_slug("nonsense"), None);
    assert!(!R::DiskRoot.overridable());
    assert!(!R::OwnProgram.overridable());
    assert!(R::CriticalProcess.overridable());
    assert!(R::SystemFolder.overridable());
    assert!(R::SharedFolder.overridable());
    assert!(R::SearchPathFolder.overridable());
}

// ── Critical processes ────────────────────────────────────────────────────────

#[test]
fn a_critical_process_is_refused_for_a_deny_and_the_additional_route_only() {
    for name in [
        "svchost.exe",
        "SVCHOST.EXE",
        "svchost",
        "lsass.exe",
        "winlogon.exe",
    ] {
        for effect in [Deny, SecondaryRoute] {
            assert_eq!(
                protection_verdict(AppTarget::Name(name), effect, &windows()),
                Refused(R::CriticalProcess),
                "{name} {effect:?}"
            );
        }
        assert_eq!(
            protection_verdict(AppTarget::Name(name), PrimaryRoute, &windows()),
            Allowed,
            "the main route is the path it takes anyway"
        );
    }
    assert_eq!(
        protection_verdict(AppTarget::Name("chrome.exe"), Deny, &windows()),
        Allowed
    );
}

#[test]
fn a_mask_is_judged_by_what_it_would_catch() {
    for mask in ["svc*.exe", "*host.exe", "svc*", "ls*"] {
        assert_eq!(
            protection_verdict(AppTarget::NameGlob(mask), Deny, &windows()),
            Refused(R::CriticalProcess),
            "{mask}"
        );
    }
    assert_eq!(
        protection_verdict(AppTarget::NameGlob("chrome*.exe"), Deny, &windows()),
        Allowed
    );
    for mask in [
        "system*",
        "systemd-*",
        "systemd-foo*",
        "*resolved",
        "network*",
        "dh*",
    ] {
        assert_eq!(
            protection_verdict(AppTarget::NameGlob(mask), SecondaryRoute, &linux()),
            Refused(R::CriticalProcess),
            "{mask}"
        );
    }
    assert_eq!(
        protection_verdict(AppTarget::NameGlob("firefox*"), SecondaryRoute, &linux()),
        Allowed
    );
}

#[test]
fn each_os_has_its_own_critical_names() {
    for name in [
        "systemd",
        "systemd-resolved",
        "NetworkManager",
        "dhclient",
        "wpa_supplicant",
    ] {
        assert_eq!(
            protection_verdict(AppTarget::Name(name), Deny, &linux()),
            Refused(R::CriticalProcess),
            "{name}"
        );
    }
    for name in ["mDNSResponder", "configd", "launchd"] {
        assert_eq!(
            protection_verdict(AppTarget::Name(name), Deny, &macos()),
            Refused(R::CriticalProcess),
            "{name}"
        );
    }
    // A name means nothing to the section of another OS.
    assert_eq!(
        protection_verdict(AppTarget::Name("svchost.exe"), Deny, &linux()),
        Allowed
    );
}

#[test]
fn a_file_naming_a_critical_process_is_refused_wherever_it_sits() {
    assert_eq!(
        verdict(
            &windows(),
            r"!C:\Windows\System32\svchost.exe",
            PrimaryRoute
        ),
        Refused(R::CriticalProcess)
    );
    assert_eq!(
        verdict(
            &linux(),
            "/usr/lib/systemd/systemd-resolved",
            SecondaryRoute
        ),
        Refused(R::CriticalProcess)
    );
}

#[test]
fn our_own_programs_are_never_under_a_guarded_rule() {
    for name in ["nrr-service.exe", "NetRuleRouter.exe", "nrr-cli.exe"] {
        assert_eq!(
            protection_verdict(AppTarget::Name(name), Deny, &windows()),
            Refused(R::OwnProgram),
            "{name}"
        );
    }
    for name in ["nrr-serviced", "nrr-service", "netrulerouter-tray"] {
        assert_eq!(
            protection_verdict(AppTarget::Name(name), SecondaryRoute, &linux()),
            Refused(R::OwnProgram),
            "{name}"
        );
    }
    assert_eq!(
        protection_verdict(AppTarget::NameGlob("nrr-*"), Deny, &windows()),
        Refused(R::OwnProgram)
    );
}

// ── Our install folder ────────────────────────────────────────────────────────

#[test]
fn anything_covering_our_install_folder_is_refused() {
    let mut places = windows();
    places.add_own_folder(r"D:\Tools\NetRuleRouter");
    for written in [
        r"!D:\Tools\*",
        r"!D:\Tools\NetRuleRouter\",
        r"!D:\Tools\NetRuleRouter\*",
        r"!D:\Tools\NetRuleRouter\bin\*",
        r"!D:\Tools\NetRuleRouter\helper.exe",
    ] {
        assert_eq!(
            verdict(&places, written, PrimaryRoute),
            Refused(R::OwnProgram),
            "{written}"
        );
    }
    assert_eq!(
        verdict(&places, r"!D:\Tools\Other\*", PrimaryRoute),
        Allowed
    );
    // A folder rule on the parent alone does not reach the programs below.
    assert_eq!(verdict(&places, r"!D:\Tools\", PrimaryRoute), Allowed);
}

// ── Search path ───────────────────────────────────────────────────────────────

#[test]
fn a_search_path_folder_refuses_a_folder_rule_and_warns_a_file() {
    let mut places = windows();
    places.add_search_path_folder(r"C:\Program Files\Git\cmd");
    places.add_search_path_folder("relative\\entry");
    places.add_search_path_folder(r"C:\Tools\..\Windows");
    assert_eq!(
        verdict(&places, r"!C:\Program Files\Git\cmd\", PrimaryRoute),
        Refused(R::SearchPathFolder)
    );
    assert_eq!(
        verdict(&places, r"!C:\Program Files\Git\*", PrimaryRoute),
        Refused(R::SearchPathFolder)
    );
    assert_eq!(
        verdict(&places, r"!C:\Program Files\Git\cmd\git.exe", PrimaryRoute),
        Warn(R::FileInSystemFolder)
    );
    assert_eq!(
        verdict(&places, r"!C:\Program Files\Git\cmd\sub\*", PrimaryRoute),
        Allowed
    );
}

// ── Normalization ─────────────────────────────────────────────────────────────

#[test]
fn windows_ignores_case_and_reads_both_separators() {
    for written in [
        r"!c:\windows\*",
        "!C:/Windows/*",
        r"!C:\WINDOWS\system32\",
        r"!C:\Windows\\System32\\",
        r"!C:\Windows\.\System32\*",
        r"!\\?\C:\Windows\*",
        r"!C:\Windows.\*",
        r"!C:\Windows \*",
    ] {
        assert_eq!(
            verdict(&windows(), written, PrimaryRoute),
            Refused(R::SystemFolder),
            "{written}"
        );
    }
}

#[test]
fn a_trailing_separator_makes_no_other_folder() {
    assert_eq!(
        verdict(&linux(), "!/usr/bin//", PrimaryRoute),
        Refused(R::SystemFolder)
    );
    assert_eq!(
        protection_verdict(AppTarget::Folder("/usr/bin"), Deny, &linux()),
        protection_verdict(AppTarget::Folder("/usr/bin/"), Deny, &linux()),
    );
    assert_eq!(
        protection_verdict(AppTarget::Folder(r"C:\Program Files"), Deny, &windows()),
        protection_verdict(AppTarget::Folder(r"C:\Program Files\\"), Deny, &windows()),
    );
}

#[test]
fn linux_compares_case_exactly_and_macos_does_not() {
    assert_eq!(
        verdict(&linux(), "!/usr/bin/", PrimaryRoute),
        Refused(R::SystemFolder)
    );
    // Another folder on Linux; inside the first-level `/Usr`, not it.
    assert_eq!(verdict(&linux(), "!/Usr/bin/", PrimaryRoute), Allowed);
    assert_eq!(
        verdict(&macos(), "!/USR/BIN/", PrimaryRoute),
        Refused(R::SystemFolder)
    );
    assert_eq!(
        verdict(&linux(), "!/usr/lib/NetworkManager/*", PrimaryRoute),
        Refused(R::SystemFolder)
    );
    assert_eq!(
        verdict(&linux(), "!/usr/lib/networkmanager/*", PrimaryRoute),
        Allowed
    );
}

#[test]
fn macos_keeps_usr_local_out_of_the_system_folder() {
    assert_eq!(
        verdict(&macos(), "!/usr/local/myapp/*", PrimaryRoute),
        Allowed
    );
    assert_eq!(
        verdict(&macos(), "!/usr/local/*", PrimaryRoute),
        Refused(R::SharedFolder)
    );
    assert_eq!(
        verdict(&macos(), "/Applications/Example.app/*", SecondaryRoute),
        Allowed
    );
}

#[test]
fn a_path_that_climbs_or_is_not_absolute_is_refused_whatever_the_route() {
    for (places, text) in [
        (windows(), r"C:\Program Files\App\..\..\Windows"),
        (windows(), r"C:\Program Files\App\.."),
        (windows(), "C:Windows"),
        (windows(), r"Windows\System32"),
        (windows(), r"C:\Program Files\App\x.exe:stream"),
        (windows(), r"C:\Program Files\...\x"),
        (windows(), r"C:\Program Files\A*\x"),
        (linux(), "/opt/app/../../usr/bin"),
        (linux(), "usr/bin"),
        (linux(), "~/bin"),
        (linux(), "/opt/a\nb"),
        (macos(), "/Applications/../System"),
    ] {
        for effect in [Deny, PrimaryRoute, SecondaryRoute] {
            for target in [
                AppTarget::File(text),
                AppTarget::Folder(text),
                AppTarget::FolderTree(text),
            ] {
                assert_eq!(
                    protection_verdict(target, effect, &places),
                    Refused(R::NotAPlainPath),
                    "{text:?} {effect:?}"
                );
            }
        }
    }
    // A root is no file.
    assert_eq!(
        protection_verdict(AppTarget::File("/"), Deny, &linux()),
        Refused(R::NotAPlainPath)
    );
    assert_eq!(
        protection_verdict(AppTarget::File(r"C:\"), Deny, &windows()),
        Refused(R::NotAPlainPath)
    );
}

#[test]
fn an_oversized_path_is_refused_without_reading_it_through() {
    let long = format!("/opt/{}", "a/".repeat(MAX_PATH_SEGMENTS + 1));
    assert_eq!(
        protection_verdict(AppTarget::FolderTree(&long), Deny, &linux()),
        Refused(R::NotAPlainPath)
    );
    let huge = format!("/opt/{}", "a".repeat(MAX_PATH_BYTES));
    assert_eq!(
        protection_verdict(AppTarget::FolderTree(&huge), Deny, &linux()),
        Refused(R::NotAPlainPath)
    );
}

#[test]
fn the_main_route_takes_any_plain_path() {
    for written in [r"C:\*", r"C:\Windows\*", r"C:\Program Files\*"] {
        assert_eq!(
            verdict(&windows(), written, PrimaryRoute),
            Allowed,
            "{written}"
        );
    }
    assert_eq!(verdict(&linux(), "/usr/bin/", PrimaryRoute), Allowed);
}

#[test]
fn a_list_from_the_machine_is_bounded() {
    let mut places = ProtectedPlaces::empty(HostPlatform::Linux);
    for i in 0..(MAX_PLACES_PER_LIST + 50) {
        places.add_search_path_folder(&format!("/p{i}"));
    }
    places.add_search_path_folder("/p0");
    assert_eq!(places.search_path.len(), MAX_PLACES_PER_LIST);
}

#[test]
fn a_segment_mask_matches_exactly_otherwise() {
    assert!(segment_matches("lib*", "lib64"));
    assert!(segment_matches("lib*", "lib"));
    assert!(!segment_matches("lib*", "Lib64"));
    assert!(segment_matches("*", "anything"));
    assert!(segment_matches("a*b*c", "aXbYc"));
    assert!(!segment_matches("a*b*c", "aXbY"));
    assert!(segment_matches("папка*", "папка1"));
}

// ── The book ──────────────────────────────────────────────────────────────────

fn app_rule(
    id: &str,
    pattern: CanonicalAppPattern,
    action: RuleAction,
    enabled: bool,
) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled,
        address_match: None,
        app_match: Some(CanonicalAppMatch {
            pattern,
            include_child_processes: false,
        }),
        comment: String::new(),
        action,
        origin: None,
    }
}

#[test]
fn a_stored_protected_rule_is_withheld_and_reported_never_dropped_silently() {
    let exact = |name: &str| CanonicalAppPattern::Exact(name.into());
    let book = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(vec![
            app_rule("p-svchost", exact("svchost.exe"), RuleAction::Route, true),
            app_rule("p-deny", exact("svchost.exe"), RuleAction::Block, true),
            app_rule("p-chrome", exact("chrome.exe"), RuleAction::Block, true),
        ]),
        secondary: CanonicalRuleSet::from_rules(vec![
            app_rule(
                "s-mask",
                CanonicalAppPattern::Glob("svc*.exe".into()),
                RuleAction::Route,
                true,
            ),
            app_rule("s-off", exact("lsass.exe"), RuleAction::Route, false),
            app_rule("s-game", exact("game.exe"), RuleAction::Route, true),
        ]),
    };
    let (kept, withheld) = withhold_protected(book, &windows());
    let ids = |set: &CanonicalRuleSet| -> Vec<String> {
        set.rules().iter().map(|r| r.id.0.clone()).collect()
    };
    assert_eq!(ids(&kept.primary), ["p-chrome", "p-svchost"]);
    assert_eq!(ids(&kept.secondary), ["s-game"]);
    assert_eq!(
        withheld,
        vec![
            ProtectedRule {
                rule_id: RuleId("p-deny".into()),
                value: "svchost.exe".into(),
                effect: Deny,
                reason: R::CriticalProcess,
            },
            ProtectedRule {
                rule_id: RuleId("s-mask".into()),
                value: "svc*.exe".into(),
                effect: SecondaryRoute,
                reason: R::CriticalProcess,
            },
        ],
        "the disabled rule applies nothing and is not reported"
    );
}

#[test]
fn a_book_without_protected_rules_comes_back_unchanged() {
    let book = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(vec![app_rule(
            "p",
            CanonicalAppPattern::Exact("chrome.exe".into()),
            RuleAction::Block,
            true,
        )]),
        secondary: CanonicalRuleSet::default(),
    };
    let (kept, withheld) = withhold_protected(book.clone(), &windows());
    assert_eq!(kept, book);
    assert!(withheld.is_empty());
}

#[test]
fn an_effect_follows_the_action_and_the_file() {
    assert_eq!(RuleEffect::of(RuleAction::Block, RouteRole::Primary), Deny);
    assert_eq!(
        RuleEffect::of(RuleAction::Block, RouteRole::Secondary),
        Deny
    );
    assert_eq!(
        RuleEffect::of(RuleAction::Verify, RouteRole::Secondary),
        SecondaryRoute
    );
    assert_eq!(
        RuleEffect::of(RuleAction::Route, RouteRole::Primary),
        PrimaryRoute
    );
    assert_eq!(RuleEffect::from_route_slug("block"), Some(Deny));
    assert_eq!(
        RuleEffect::from_route_slug("secondary"),
        Some(SecondaryRoute)
    );
    assert_eq!(RuleEffect::from_route_slug("primary"), Some(PrimaryRoute));
    assert_eq!(RuleEffect::from_route_slug("tertiary"), None);
}

// ── Through the canonical reading ─────────────────────────────────────────────

/// The verdict on a value as the rules file reads it on `places`' platform.
fn canonical_verdict(
    places: &ProtectedPlaces,
    written: &str,
    route: RuleEffect,
) -> ProtectionVerdict {
    let (value, effect) = match written.strip_prefix('!') {
        Some(value) => (value, Deny),
        None => (written, route),
    };
    let pattern = crate::validation::canonical_app_pattern(
        value,
        value.contains('*'),
        places.platform(),
        &RuleId(String::new()),
        &mut Vec::new(),
    )
    .unwrap_or_else(|e| panic!("{written}: {e}"));
    protection_verdict(AppTarget::of_pattern(&pattern), effect, places)
}

/// The accepted examples hold for the paths a rule really carries.
#[test]
fn the_examples_hold_for_canonical_paths() {
    for (places, written, route) in [
        (windows(), r"!C:\Windows\*", PrimaryRoute),
        (windows(), r"!C:\*", PrimaryRoute),
        (linux(), "!/opt", PrimaryRoute),
        (linux(), "!/home/*", PrimaryRoute),
        (linux(), "!/usr/bin/", PrimaryRoute),
        (linux(), "!/usr/bin", PrimaryRoute),
        (linux(), "!/usr/lib/systemd/*", PrimaryRoute),
        (linux(), "/usr/lib/*", SecondaryRoute),
        (windows(), r"C:\Program Files\*", SecondaryRoute),
        (windows(), r"C:\Program Files", SecondaryRoute),
    ] {
        assert!(
            canonical_verdict(&places, written, route).is_refused(),
            "{written} on {:?}",
            places.platform()
        );
    }
    for (places, written) in [
        (linux(), "/usr/lib/firefox/*"),
        (windows(), r"C:\Program Files\App\*"),
        (windows(), r"C:\Program Files\App\app.exe"),
    ] {
        assert_eq!(
            canonical_verdict(&places, written, SecondaryRoute),
            Allowed,
            "{written}"
        );
    }
    for (places, written) in [
        (windows(), r"!C:\Windows\System32\curl.exe"),
        (linux(), "!/usr/bin/curl"),
    ] {
        assert_eq!(
            canonical_verdict(&places, written, PrimaryRoute),
            Warn(R::FileInSystemFolder),
            "{written}"
        );
    }
}

/// A Linux path without a trailing slash may be a file or a folder: a
/// critical program by its path is refused like its name.
#[test]
fn an_undecided_path_to_a_critical_program_is_refused() {
    assert_eq!(
        canonical_verdict(&linux(), "!/usr/sbin/NetworkManager", PrimaryRoute),
        Refused(R::CriticalProcess)
    );
}

/// A rule by program path is kept out of enforcement where the platform
/// cannot carry it out, and named with its own reason; nothing else moves.
#[test]
fn a_path_rule_is_withheld_with_its_own_reason() {
    let path = crate::validation::canonical_app_pattern(
        "/opt/tool/*",
        true,
        HostPlatform::Linux,
        &RuleId(String::new()),
        &mut Vec::new(),
    )
    .expect("a path");
    let book = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(vec![
            app_rule("p-path", path, RuleAction::Route, true),
            app_rule(
                "p-name",
                CanonicalAppPattern::Exact("tool".into()),
                RuleAction::Route,
                true,
            ),
        ]),
        secondary: CanonicalRuleSet::default(),
    };
    let (kept, withheld) = withhold_app_paths(book);
    let ids: Vec<&str> = kept.primary.rules().iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, ["p-name"]);
    assert_eq!(
        withheld,
        vec![ProtectedRule {
            rule_id: RuleId("p-path".into()),
            value: "/opt/tool/*".into(),
            effect: PrimaryRoute,
            reason: R::AppPathUnsupported,
        }]
    );
    assert!(!R::AppPathUnsupported.overridable());
}
