//! What a protected rule would take, told to its owner before they confirm
//! applying it anyway.
//!
//! Pure: the programs a place holds and the programs running right now arrive
//! from the service, which asked the platform; this decides what the
//! confirmation names and whether it needs an administrator.

use super::{critical_processes_covered, AppTarget, ProtectionReason, MAX_CRITICAL_NAMED};
use crate::canonical::CanonicalAppPattern;
use crate::rules_file::HostPlatform;
use nrr_shared::app_identity::app_match_key;
use nrr_shared::glob::glob_match;

/// Accounts and users named at most; past them only the count grows.
pub const MAX_ACCOUNTS_NAMED: usize = 16;

/// What stops working when a rule takes the system's own programs. The slug
/// reaches the wire and the locale keys (`rules.override.breaks.<slug>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Consequence {
    /// The connection itself: bringing links up, Wi-Fi.
    Network,
    /// Getting an address from the network.
    Dhcp,
    /// Resolving names.
    Dns,
    /// Keeping the clock right.
    Time,
    /// System and security updates.
    Updates,
    /// Signing in to this computer.
    SignIn,
    /// Signing in to a domain or a work account.
    DomainSignIn,
    /// The built-in protection against malware.
    Protection,
    /// Programs of the system itself, beyond the ones named.
    SystemPrograms,
    /// Programs of other applications kept in the same folder.
    OtherPrograms,
}

impl Consequence {
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Dhcp => "dhcp",
            Self::Dns => "dns",
            Self::Time => "time",
            Self::Updates => "updates",
            Self::SignIn => "sign-in",
            Self::DomainSignIn => "domain-sign-in",
            Self::Protection => "protection",
            Self::SystemPrograms => "system-programs",
            Self::OtherPrograms => "other-programs",
        }
    }

    /// Every consequence, for exhaustive tables and locale checks.
    pub const ALL: [Self; 10] = [
        Self::Network,
        Self::Dhcp,
        Self::Dns,
        Self::Time,
        Self::Updates,
        Self::SignIn,
        Self::DomainSignIn,
        Self::Protection,
        Self::SystemPrograms,
        Self::OtherPrograms,
    ];
}

/// What a critical process does for the machine, by its match key.
fn consequences_of(key: &str) -> &'static [Consequence] {
    use Consequence as C;
    match key {
        "svchost" => &[C::Network, C::Dhcp, C::Dns, C::Time, C::Updates],
        "lsass" => &[C::SignIn, C::DomainSignIn],
        "services" => &[C::Network, C::Updates, C::SignIn],
        "csrss" | "wininit" | "smss" | "winlogon" => &[C::SignIn],
        "msmpeng" => &[C::Protection],
        "systemd" | "init" | "launchd" => &[C::Network, C::Dns, C::Time, C::SignIn],
        "systemd-resolved" | "dnsmasq" | "mdnsresponder" | "mdnsresponderhelper" => &[C::Dns],
        "systemd-networkd" | "networkmanager" | "nm-dispatcher" | "configd" => {
            &[C::Network, C::Dhcp]
        }
        "nm-dhcp-helper" | "dhclient" | "dhcpcd" => &[C::Dhcp],
        "wpa_supplicant" => &[C::Network],
        "systemd-timesyncd" | "chronyd" | "ntpd" | "timed" => &[C::Time],
        "systemd-logind" => &[C::SignIn],
        _ => &[C::SystemPrograms],
    }
}

/// Who a running program belongs to, seen from the rule's owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramOwner {
    /// The owner of the rule.
    Caller,
    /// An account services run under.
    ServiceAccount,
    /// Somebody else signed in to this machine.
    OtherUser,
}

/// One running program as the coverage weighs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunningProgram<'a> {
    /// The image, as a path or a file name.
    pub image: &'a str,
    /// The account, in stored principal form.
    pub account: &'a str,
    pub owner: ProgramOwner,
}

/// The canonical pattern an application value names on `platform`, as a rules
/// table holds the value (`+children`, `+override` and all); `None` when the
/// rule pipeline refuses it. The spelling stored rules are compared in.
#[must_use]
pub fn canonical_app_value(value: &str, platform: HostPlatform) -> Option<CanonicalAppPattern> {
    let bare = nrr_shared::preset_parser::without_rule_flags(value.trim());
    crate::validation::canonical_app_pattern(
        &bare,
        bare.contains('*'),
        platform,
        &crate::RuleId(String::new()),
        &mut Vec::new(),
    )
    .ok()
}

/// Whether `pattern` names the program whose image is `image`: by match key
/// for a name or a mask, by place for a path. The reading the matcher uses.
#[must_use]
pub fn pattern_names_image(pattern: &CanonicalAppPattern, image: &str) -> bool {
    match pattern {
        CanonicalAppPattern::Exact(name) => app_match_key(name) == app_match_key(image),
        CanonicalAppPattern::Glob(glob) => glob_match(&app_match_key(glob), &app_match_key(image)),
        CanonicalAppPattern::Path(path) => path.match_image(image).is_some(),
    }
}

/// What the confirmation tells.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverrideCoverage {
    pub reason: ProtectionReason,
    /// Programs the rule takes: those its place holds, or for a name or a
    /// mask those running now.
    pub programs: usize,
    /// The place holds more programs than one rule covers.
    pub programs_over_cap: bool,
    /// Critical processes it takes, sorted.
    pub critical: Vec<String>,
    /// Service accounts running what it takes, sorted, at most
    /// [`MAX_ACCOUNTS_NAMED`].
    pub service_accounts: Vec<String>,
    /// Other users running what it takes.
    pub other_users: usize,
    pub consequences: Vec<Consequence>,
    /// It reaches past its owner: system folders or processes, service
    /// accounts, other users. Confirming such a rule takes an administrator.
    pub touches_machine: bool,
}

/// The coverage of a rule on `pattern`, refused for `reason`, whose place
/// holds `listing` (`over_cap` when it holds more), while `running` run.
#[must_use]
pub fn override_coverage(
    pattern: &CanonicalAppPattern,
    reason: ProtectionReason,
    listing: &[String],
    over_cap: bool,
    running: &[RunningProgram<'_>],
    platform: HostPlatform,
) -> OverrideCoverage {
    let covered: Vec<&RunningProgram<'_>> = running
        .iter()
        .filter(|program| pattern_names_image(pattern, program.image))
        .collect();
    let target = AppTarget::of_pattern(pattern);
    let mut seen: Vec<&str> = listing.iter().map(String::as_str).collect();
    seen.extend(covered.iter().map(|program| program.image));
    let critical = critical_processes_covered(target, &seen, platform);

    let mut service_accounts: Vec<String> = covered
        .iter()
        .filter(|program| program.owner == ProgramOwner::ServiceAccount)
        .map(|program| program.account.to_owned())
        .collect();
    service_accounts.sort_unstable();
    service_accounts.dedup();
    service_accounts.truncate(MAX_ACCOUNTS_NAMED);
    let mut others: Vec<&str> = covered
        .iter()
        .filter(|program| program.owner == ProgramOwner::OtherUser)
        .map(|program| program.account)
        .collect();
    others.sort_unstable();
    others.dedup();

    let programs = if matches!(pattern, CanonicalAppPattern::Path(_)) {
        listing.len()
    } else {
        let mut images: Vec<String> = covered
            .iter()
            .map(|program| app_match_key(program.image))
            .collect();
        images.sort_unstable();
        images.dedup();
        images.len()
    };

    let mut consequences: Vec<Consequence> = critical
        .iter()
        .flat_map(|key| consequences_of(key).iter().copied())
        .collect();
    match reason {
        ProtectionReason::SystemFolder => {
            consequences.extend([Consequence::SystemPrograms, Consequence::Updates]);
        }
        ProtectionReason::SearchPathFolder | ProtectionReason::SharedFolder => {
            consequences.push(Consequence::OtherPrograms);
        }
        _ => {}
    }
    consequences.sort_unstable();
    consequences.dedup();

    let touches_machine = matches!(
        reason,
        ProtectionReason::SystemFolder
            | ProtectionReason::SearchPathFolder
            | ProtectionReason::CriticalProcess
    ) || !critical.is_empty()
        || !service_accounts.is_empty()
        || !others.is_empty();
    debug_assert!(critical.len() <= MAX_CRITICAL_NAMED);

    OverrideCoverage {
        reason,
        programs,
        programs_over_cap: over_cap,
        critical,
        service_accounts,
        other_users: others.len(),
        consequences,
        touches_machine,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuleId;

    fn pattern(value: &str, platform: HostPlatform) -> CanonicalAppPattern {
        crate::validation::canonical_app_pattern(
            value,
            value.contains('*'),
            platform,
            &RuleId(String::new()),
            &mut Vec::new(),
        )
        .expect("a value the pipeline accepts")
    }

    fn running<'a>(image: &'a str, account: &'a str, owner: ProgramOwner) -> RunningProgram<'a> {
        RunningProgram {
            image,
            account,
            owner,
        }
    }

    /// A site folder served by a daemon's account takes a service account,
    /// so confirming it needs an administrator; one only the owner runs from
    /// does not.
    #[test]
    fn a_site_folder_needs_an_administrator_only_when_others_run_from_it() {
        let site = pattern("/var/www/*", HostPlatform::Linux);
        let listing = vec!["/var/www/app/run.sh".to_owned()];
        let own = [running(
            "/var/www/app/run.sh",
            "unix:uid:1000",
            ProgramOwner::Caller,
        )];
        let alone = override_coverage(
            &site,
            ProtectionReason::SharedFolder,
            &listing,
            false,
            &own,
            HostPlatform::Linux,
        );
        assert!(!alone.touches_machine);
        assert_eq!(alone.programs, 1);
        assert_eq!(alone.consequences, [Consequence::OtherPrograms]);

        let served = [
            running(
                "/var/www/app/php-fpm",
                "unix:uid:33",
                ProgramOwner::ServiceAccount,
            ),
            running("/usr/bin/curl", "unix:uid:33", ProgramOwner::ServiceAccount),
            running(
                "/var/www/app/run.sh",
                "unix:uid:1001",
                ProgramOwner::OtherUser,
            ),
        ];
        let shared = override_coverage(
            &site,
            ProtectionReason::SharedFolder,
            &listing,
            false,
            &served,
            HostPlatform::Linux,
        );
        assert!(shared.touches_machine);
        assert_eq!(shared.service_accounts, ["unix:uid:33"]);
        assert_eq!(shared.other_users, 1);
    }

    #[test]
    fn a_critical_process_names_what_breaks() {
        let rule = pattern("svchost.exe", HostPlatform::Windows);
        let coverage = override_coverage(
            &rule,
            ProtectionReason::CriticalProcess,
            &[],
            false,
            &[running(
                r"C:\Windows\System32\svchost.exe",
                "S-1-5-18",
                ProgramOwner::ServiceAccount,
            )],
            HostPlatform::Windows,
        );
        assert_eq!(coverage.critical, ["svchost"]);
        assert_eq!(coverage.programs, 1);
        assert!(coverage.touches_machine);
        for slug in ["dhcp", "dns", "time", "updates"] {
            assert!(
                coverage.consequences.iter().any(|c| c.slug() == slug),
                "{slug}: {:?}",
                coverage.consequences
            );
        }
    }

    #[test]
    fn a_system_folder_names_its_critical_programs() {
        let folder = pattern("/usr/sbin/*", HostPlatform::Linux);
        let listing = vec![
            "/usr/sbin/NetworkManager".to_owned(),
            "/usr/sbin/sshd".to_owned(),
        ];
        let coverage = override_coverage(
            &folder,
            ProtectionReason::SystemFolder,
            &listing,
            true,
            &[],
            HostPlatform::Linux,
        );
        assert_eq!(coverage.critical, ["networkmanager"]);
        assert!(coverage.programs_over_cap);
        assert!(coverage.consequences.contains(&Consequence::Dhcp));
        assert!(coverage.consequences.contains(&Consequence::SystemPrograms));
    }

    #[test]
    fn every_consequence_has_its_own_slug() {
        let slugs: std::collections::HashSet<&str> =
            Consequence::ALL.iter().map(|c| c.slug()).collect();
        assert_eq!(slugs.len(), Consequence::ALL.len());
    }
}
