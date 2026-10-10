//! Which uids are the machine's service accounts: the system range from
//! `/etc/login.defs` and `nobody`, minus every user who is present.
//!
//! A present user is excluded even from the system range — a root console
//! session is a person, and their traffic follows their own plan.

/// `SYS_UID_MAX` when `login.defs` does not say: the shadow-utils default.
pub const DEFAULT_SYS_UID_MAX: u32 = 999;

/// The overflow uid daemons drop to.
pub const NOBODY_UID: u32 = 65534;

/// `SYS_UID_MAX` from the text of `login.defs`, if it names one.
#[must_use]
pub fn parse_sys_uid_max(login_defs: &str) -> Option<u32> {
    login_defs.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        if words.next()? != "SYS_UID_MAX" {
            return None;
        }
        words.next()?.parse().ok()
    })
}

/// `SYS_UID_MAX` of this machine; the default when the file is unreadable.
#[must_use]
pub fn read_sys_uid_max() -> u32 {
    std::fs::read_to_string("/etc/login.defs")
        .ok()
        .and_then(|text| parse_sys_uid_max(&text))
        .unwrap_or(DEFAULT_SYS_UID_MAX)
}

/// `0..=sys_uid_max` and [`NOBODY_UID`] without the `present` uids, as sorted,
/// disjoint inclusive ranges.
#[must_use]
pub fn service_account_uids(sys_uid_max: u32, present: &[u32]) -> Vec<(u32, u32)> {
    let mut ranges = vec![(0, sys_uid_max)];
    if NOBODY_UID > sys_uid_max {
        ranges.push((NOBODY_UID, NOBODY_UID));
    }
    let mut present = present.to_vec();
    present.sort_unstable();
    present.dedup();
    for uid in present {
        ranges = ranges
            .into_iter()
            .flat_map(|(first, last)| {
                if uid < first || uid > last {
                    return vec![(first, last)];
                }
                let mut kept = Vec::with_capacity(2);
                if uid > first {
                    kept.push((first, uid - 1));
                }
                if uid < last {
                    kept.push((uid + 1, last));
                }
                kept
            })
            .collect();
    }
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_defs_names_the_system_range() {
        let text = "# comment\nUID_MIN 1000\nSYS_UID_MAX\t499\nSYS_UID_MIN 101\n";
        assert_eq!(parse_sys_uid_max(text), Some(499));
        assert_eq!(parse_sys_uid_max("UID_MIN 1000\n"), None);
        assert_eq!(parse_sys_uid_max("#SYS_UID_MAX 10\n"), None);
    }

    #[test]
    fn the_system_range_and_nobody_minus_present_users() {
        assert_eq!(
            service_account_uids(999, &[1000]),
            vec![(0, 999), (NOBODY_UID, NOBODY_UID)]
        );
        assert_eq!(
            service_account_uids(999, &[0, 500, NOBODY_UID]),
            vec![(1, 499), (501, 999)]
        );
    }
}
