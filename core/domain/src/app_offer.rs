//! When an application, rather than a site, is worth routing.
//!
//! A program that reaches the network by bare addresses names no host, so no
//! host can be offered for it. What can be measured is whether the main link
//! carries the program at all.

/// Distinct addresses a program must stall on before the main link is judged
/// not to carry it — the bar the host measure sets per name.
pub const APP_STALL_CONFIRMATIONS: usize = 3;

/// One program's connections over the measuring window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AppMainLinkReach {
    /// Distinct unnamed remote addresses it stalled on over the main link.
    pub stalled_addresses: usize,
    /// Distinct addresses, named or not, it stalled on over the main link.
    pub failing_addresses: usize,
    /// Distinct addresses a connection of it closed in order with.
    pub working_addresses: usize,
    /// Some of its connections already leave over the additional link.
    pub rides_additional_link: bool,
}

/// The main link does not carry this program: most of the different
/// addresses it tried there failed, several of them unnamed.
///
/// A program already split across both links — a browser whose routed sites go
/// through the tunnel by host rules — is never moved whole: its other sites
/// work on the main link, and a few failures among many say nothing.
#[must_use]
pub fn main_link_does_not_carry(reach: AppMainLinkReach) -> bool {
    !reach.rides_additional_link
        && reach.stalled_addresses >= APP_STALL_CONFIRMATIONS
        && reach.failing_addresses > reach.working_addresses
}

/// Where operating systems keep their own programs. Those serve every
/// application on the machine, so routing one would move traffic nobody asked
/// to move; they are never offered.
const OS_PROGRAM_DIRS: &[&str] = &[
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\systemapps\\",
    "/usr/sbin/",
    "/sbin/",
    "/usr/lib/systemd/",
    "/lib/systemd/",
];

/// Is `image_path` one of the operating system's own programs?
#[must_use]
pub fn is_os_program(image_path: &str) -> bool {
    let lower = image_path.to_ascii_lowercase();
    OS_PROGRAM_DIRS.iter().any(|dir| lower.contains(dir))
}

/// The bare, lowercased file name an application rule matches on.
#[must_use]
pub fn program_name(image_path: &str) -> String {
    image_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image_path)
        .trim()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reach(stalled: usize, working: usize) -> AppMainLinkReach {
        AppMainLinkReach {
            stalled_addresses: stalled,
            failing_addresses: stalled,
            working_addresses: working,
            rides_additional_link: false,
        }
    }

    #[test]
    fn a_program_that_stalls_on_three_addresses_and_works_on_none_is_not_carried() {
        assert!(main_link_does_not_carry(reach(3, 0)));
    }

    #[test]
    fn most_of_its_addresses_must_fail() {
        assert!(main_link_does_not_carry(reach(4, 3)));
        assert!(!main_link_does_not_carry(reach(4, 4)));
        assert!(!main_link_does_not_carry(reach(3, 12)));
    }

    #[test]
    fn two_stalled_addresses_are_not_enough() {
        assert!(!main_link_does_not_carry(reach(2, 0)));
    }

    #[test]
    fn a_program_already_on_the_additional_link_is_never_moved_whole() {
        let split = AppMainLinkReach {
            rides_additional_link: true,
            ..reach(8, 0)
        };
        assert!(!main_link_does_not_carry(split));
        assert!(main_link_does_not_carry(reach(8, 0)), "positive control");
    }

    #[test]
    fn os_programs_are_recognised_in_either_spelling() {
        assert!(is_os_program(
            r"\device\harddiskvolume3\Windows\System32\svchost.exe"
        ));
        assert!(is_os_program("/usr/sbin/NetworkManager"));
        assert!(!is_os_program(r"C:\Program Files\Messenger\Messenger.exe"));
        assert!(!is_os_program(
            r"C:\Users\user.example\AppData\Local\app.exe"
        ));
    }

    #[test]
    fn a_program_is_named_by_its_lowercased_file_name() {
        assert_eq!(
            program_name(r"\device\harddiskvolume2\Program Files\App\App.EXE"),
            "app.exe"
        );
        assert_eq!(program_name("/opt/vendor/bin/client"), "client");
    }
}
