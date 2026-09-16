use super::*;

// ── RulesFileSection ─────────────────────────────────────────────────────

#[test]
fn section_names_are_stable() {
    assert_eq!(RulesFileSection::Zones.name(), "Zones");
    assert_eq!(RulesFileSection::Domains.name(), "Domains");
    assert_eq!(RulesFileSection::Ip.name(), "IP");
    assert_eq!(RulesFileSection::Windows.name(), "Windows");
    assert_eq!(RulesFileSection::Linux.name(), "Linux");
    assert_eq!(RulesFileSection::MacOS.name(), "MacOS");
    assert_eq!(RulesFileSection::Auto.name(), "Auto");
}

#[test]
fn section_display_matches_name() {
    for section in RulesFileSection::ALL {
        assert_eq!(section.to_string(), section.name());
    }
}

#[test]
fn section_from_name_roundtrip() {
    for section in RulesFileSection::ALL {
        assert_eq!(
            RulesFileSection::from_name(section.name()),
            Some(section),
            "roundtrip failed for {:?}",
            section
        );
    }
}

#[test]
fn section_from_name_rejects_unknown() {
    assert_eq!(RulesFileSection::from_name("CIDR"), None);
    assert_eq!(RulesFileSection::from_name("cidr"), None);
    assert_eq!(RulesFileSection::from_name(""), None);
    // Case-insensitive, matching nrr_shared::preset_parser.
    assert_eq!(
        RulesFileSection::from_name("zones"),
        Some(RulesFileSection::Zones)
    );
    assert_eq!(
        RulesFileSection::from_name("IP"),
        Some(RulesFileSection::Ip)
    );
    assert_eq!(
        RulesFileSection::from_name("ip"),
        Some(RulesFileSection::Ip)
    );
}

#[test]
fn section_parse_header_roundtrip() {
    for section in RulesFileSection::ALL {
        let header = format!("--- {}", section.name());
        assert_eq!(
            RulesFileSection::parse_header(&header),
            Some(section),
            "parse_header failed for {:?}",
            section
        );
    }
}

#[test]
fn section_parse_header_rejects_non_headers() {
    assert_eq!(RulesFileSection::parse_header("Zones"), None);
    assert_eq!(RulesFileSection::parse_header("-- Zones"), None);
    assert_eq!(RulesFileSection::parse_header("# --- Zones"), None);
    assert_eq!(RulesFileSection::parse_header("--- CIDR"), None);
}

#[test]
fn section_parse_header_trims_trailing_whitespace() {
    assert_eq!(
        RulesFileSection::parse_header("--- Zones  "),
        Some(RulesFileSection::Zones)
    );
}

#[test]
fn cross_platform_sections_active_on_all_platforms() {
    for section in [
        RulesFileSection::Zones,
        RulesFileSection::Domains,
        RulesFileSection::Ip,
    ] {
        assert!(section.is_active_on(HostPlatform::Windows));
        assert!(section.is_active_on(HostPlatform::Linux));
        assert!(section.is_active_on(HostPlatform::MacOS));
        assert!(!section.is_platform_specific());
    }
}

#[test]
fn platform_specific_sections_active_only_on_matching_platform() {
    assert!(RulesFileSection::Windows.is_active_on(HostPlatform::Windows));
    assert!(!RulesFileSection::Windows.is_active_on(HostPlatform::Linux));
    assert!(!RulesFileSection::Windows.is_active_on(HostPlatform::MacOS));

    assert!(RulesFileSection::Linux.is_active_on(HostPlatform::Linux));
    assert!(!RulesFileSection::Linux.is_active_on(HostPlatform::Windows));
    assert!(!RulesFileSection::Linux.is_active_on(HostPlatform::MacOS));

    assert!(RulesFileSection::MacOS.is_active_on(HostPlatform::MacOS));
    assert!(!RulesFileSection::MacOS.is_active_on(HostPlatform::Windows));
    assert!(!RulesFileSection::MacOS.is_active_on(HostPlatform::Linux));
}

#[test]
fn platform_specific_flag_correct() {
    assert!(RulesFileSection::Windows.is_platform_specific());
    assert!(RulesFileSection::Linux.is_platform_specific());
    assert!(RulesFileSection::MacOS.is_platform_specific());

    assert!(!RulesFileSection::Zones.is_platform_specific());
    assert!(!RulesFileSection::Domains.is_platform_specific());
    assert!(!RulesFileSection::Ip.is_platform_specific());
}

#[test]
fn all_free_sections_are_listed_with_auto_last() {
    assert_eq!(RulesFileSection::ALL.len(), 7);
    assert_eq!(RulesFileSection::ALL[6], RulesFileSection::Auto);
}

#[test]
fn auto_section_is_cross_platform_and_app_authored() {
    for platform in [
        HostPlatform::Windows,
        HostPlatform::Linux,
        HostPlatform::MacOS,
    ] {
        assert!(RulesFileSection::Auto.is_active_on(platform));
    }
    assert!(!RulesFileSection::Auto.is_platform_specific());
    assert!(RulesFileSection::Auto.is_app_authored());
    for section in RulesFileSection::ALL {
        if section != RulesFileSection::Auto {
            assert!(
                !section.is_app_authored(),
                "{section} must not be app-authored"
            );
        }
    }
}

// ── HostPlatform ─────────────────────────────────────────────────────────

/// The compiled platform must be the one the test binary was built for.
/// Asserting a constant `Windows` here made the whole crate's test run fail
/// under Linux — a false alarm that hid whatever else the Linux run had to
/// say, on a project that is deliberately going cross-platform.
#[test]
fn compiled_platform_matches_the_build_target() {
    let expected = if cfg!(target_os = "windows") {
        HostPlatform::Windows
    } else if cfg!(target_os = "linux") {
        HostPlatform::Linux
    } else if cfg!(target_os = "macos") {
        HostPlatform::MacOS
    } else {
        // Anything else falls back to Windows by construction — the same
        // branch `compiled()` takes.
        HostPlatform::Windows
    };
    assert_eq!(HostPlatform::compiled(), expected);
}

// ── RulesFileEntry ───────────────────────────────────────────────────────

#[test]
fn entry_enabled_constructor() {
    let e = RulesFileEntry::enabled("example.com");
    assert_eq!(e.match_value, "example.com");
    assert!(e.enabled);
    assert!(e.inline_comment.is_none());
}

#[test]
fn entry_enabled_with_comment_constructor() {
    let e = RulesFileEntry::enabled_with_comment("example.com", "vendor updates");
    assert!(e.enabled);
    assert_eq!(e.inline_comment.as_deref(), Some("vendor updates"));
}

#[test]
fn entry_disabled_constructor() {
    let e = RulesFileEntry::disabled("old.example.com");
    assert_eq!(e.match_value, "old.example.com");
    assert!(!e.enabled);
    assert!(e.inline_comment.is_none());
}

// ── SectionContent ───────────────────────────────────────────────────────

#[test]
fn section_content_counts_correctly() {
    let content = SectionContent {
        section: RulesFileSection::Domains,
        entries: vec![
            RulesFileEntry::enabled("example.com"),
            RulesFileEntry::disabled("old.example.com"),
            RulesFileEntry::enabled("corp.net"),
        ],
    };
    assert_eq!(content.enabled_count(), 2);
    assert_eq!(content.disabled_count(), 1);
    assert!(!content.is_empty());
}

#[test]
fn section_content_empty() {
    let content = SectionContent {
        section: RulesFileSection::Linux,
        entries: vec![],
    };
    assert!(content.is_empty());
    assert_eq!(content.enabled_count(), 0);
}

// ── RulesFileParsed ──────────────────────────────────────────────────────

fn sample_parsed() -> RulesFileParsed {
    RulesFileParsed {
        sections: vec![
            SectionContent {
                section: RulesFileSection::Domains,
                entries: vec![
                    RulesFileEntry::enabled("example.com"),
                    RulesFileEntry::disabled("old.net"),
                ],
            },
            SectionContent {
                section: RulesFileSection::Windows,
                entries: vec![RulesFileEntry::enabled("browser.exe")],
            },
            SectionContent {
                section: RulesFileSection::Linux,
                entries: vec![RulesFileEntry::enabled("curl")],
            },
        ],
    }
}

#[test]
fn parsed_entries_for_known_section() {
    let p = sample_parsed();
    assert_eq!(p.entries_for(RulesFileSection::Domains).len(), 2);
    assert_eq!(p.entries_for(RulesFileSection::Windows).len(), 1);
}

#[test]
fn parsed_entries_for_absent_section_returns_empty() {
    let p = sample_parsed();
    assert!(p.entries_for(RulesFileSection::Ip).is_empty());
}

#[test]
fn parsed_enabled_count_for_section() {
    let p = sample_parsed();
    // Domains: 1 enabled, 1 disabled
    assert_eq!(p.enabled_count_for(RulesFileSection::Domains), 1);
    assert_eq!(p.enabled_count_for(RulesFileSection::Windows), 1);
}

#[test]
fn parsed_active_sections_on_windows_excludes_linux() {
    let p = sample_parsed();
    let active: Vec<_> = p
        .active_sections_for(HostPlatform::Windows)
        .map(|s| s.section)
        .collect();
    assert!(active.contains(&RulesFileSection::Domains));
    assert!(active.contains(&RulesFileSection::Windows));
    assert!(!active.contains(&RulesFileSection::Linux));
}

#[test]
fn parsed_active_sections_on_linux_excludes_windows() {
    let p = sample_parsed();
    let active: Vec<_> = p
        .active_sections_for(HostPlatform::Linux)
        .map(|s| s.section)
        .collect();
    assert!(active.contains(&RulesFileSection::Linux));
    assert!(!active.contains(&RulesFileSection::Windows));
}

#[test]
fn parsed_total_active_enabled_count_on_windows() {
    let p = sample_parsed();
    // Domains: 1 enabled (old.net disabled), Windows: 1 enabled, Linux: excluded
    assert_eq!(p.total_active_enabled_count(HostPlatform::Windows), 2);
}

#[test]
fn parsed_total_active_enabled_count_on_linux() {
    let p = sample_parsed();
    // Domains: 1, Linux: 1, Windows: excluded
    assert_eq!(p.total_active_enabled_count(HostPlatform::Linux), 2);
}

#[test]
fn parsed_default_is_empty() {
    let p = RulesFileParsed::default();
    assert!(p.sections.is_empty());
    assert_eq!(p.total_active_enabled_count(HostPlatform::Windows), 0);
    assert!(!p.has_all_free_sections());
}
