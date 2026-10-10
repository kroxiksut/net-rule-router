//! Per-user routing: a route table per present user, picked by
//! `ip rule uidrange`, and one system table for the service accounts.
//!
//! ## Tables
//!
//! A user's table is [`PRINCIPAL_TABLE_BASE`] `+ uid`, the service accounts'
//! is [`SYSTEM_TABLE`] just below it, and every table from there up is ours:
//! far above what iproute2 users and VPN clients number (wg-quick 51820,
//! Tailscale 52) and clear of `0` and `252..=255`.
//!
//! ## Selectors
//!
//! A table holding overlays — the `/1`..`/13` halves that carry what no rule
//! names — cannot simply be looked up first: inside it a `/1` beats the LAN's
//! `/24`, which lives in `main`. So such a table gets three rules, which keep
//! the longest-prefix order the routes had when they shared `main`:
//!
//! 1. the table without its overlays (`suppress_prefixlength P`);
//! 2. `main` without what is no longer than an overlay (`suppress_prefixlength P-1`);
//! 3. the table, overlays included.
//!
//! A table without overlays needs only the first, unsuppressed; IPv6 never
//! carries overlays. A table with no matching route falls through to the next
//! rule, so none of them holds a default route.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::ops::RangeInclusive;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};

use nrr_platform_api::enforcement::{RouteTableRef, UserPrincipal};
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::route_table::{
    PrincipalRoutingPort, SelectorDelta, SelectorPlan, TableSelector,
};

use crate::route_table::FibRule;

/// A user's table is this plus their uid.
pub const PRINCIPAL_TABLE_BASE: u32 = 0x8000_0000;
/// The service accounts' table.
pub const SYSTEM_TABLE: u32 = PRINCIPAL_TABLE_BASE - 1;
/// Users' selectors start here; ahead of `main` (32766) and of wg-quick's
/// 32764/32765.
pub const USER_PRIORITY: u32 = 30_100;
/// The service accounts' selectors, after every user's.
pub const SYSTEM_PRIORITY: u32 = 30_110;
/// Every rule at these priorities that selects by uid alone is ours.
pub const PRIORITY_BAND: RangeInclusive<u32> = 30_100..=30_119;

const RT_TABLE_MAIN: u32 = 254;
/// `u32::MAX` is `RT_TABLE_MAX`; the uid one below it is the last with a table.
const LAST_MAPPED_UID: u32 = u32::MAX - PRINCIPAL_TABLE_BASE - 1;
/// `uidrange` arrived in 4.10. An older kernel ignores the attribute and
/// installs a rule that selects every user.
const UID_RANGE_SINCE: (u32, u32) = (4, 10);

/// The table holding `uid`'s routes; `None` for a uid too large to map.
#[must_use]
pub fn table_for_uid(uid: u32) -> Option<u32> {
    (uid <= LAST_MAPPED_UID).then(|| PRINCIPAL_TABLE_BASE + uid)
}

/// Whether table `n` is one of ours.
#[must_use]
pub fn is_our_table(n: u32) -> bool {
    n >= SYSTEM_TABLE && n != u32::MAX
}

/// Whether a dumped rule is one of ours: in our band, selecting by nothing but
/// (at most) a uid, and looking up one of our tables or `main`.
pub(crate) fn is_our_rule(rule: &FibRule) -> bool {
    PRIORITY_BAND.contains(&rule.priority)
        && !rule.narrowed
        && (is_our_table(rule.table) || rule.table == RT_TABLE_MAIN)
}

/// The rules sending `ranges` to `table`, starting at `priority`.
fn push_selectors(
    out: &mut Vec<FibRule>,
    table: u32,
    ranges: &[(u32, u32)],
    selector: TableSelector,
    priority: u32,
    with_ipv6: bool,
) {
    for &range in ranges {
        let rule = |ipv6, priority, table, suppress_prefixlen| FibRule {
            ipv6,
            priority,
            table,
            uid_range: Some(range),
            suppress_prefixlen,
            narrowed: false,
        };
        match selector.overlay_prefix_v4.filter(|p| *p > 0) {
            Some(p) => {
                out.push(rule(false, priority, table, Some(p)));
                out.push(rule(false, priority + 1, RT_TABLE_MAIN, Some(p - 1)));
                out.push(rule(false, priority + 2, table, None));
            }
            None => out.push(rule(false, priority, table, None)),
        }
        if with_ipv6 {
            out.push(rule(true, priority, table, None));
        }
    }
}

/// Every rule `plan` asks for. The service accounts are `0..=sys_uid_max` and
/// `nobody` without the present users: a present root is a person, and looks
/// up their own table.
pub(crate) fn selector_rules(
    plan: &SelectorPlan,
    sys_uid_max: u32,
    with_ipv6: bool,
) -> Vec<FibRule> {
    let mut out = Vec::new();
    let mut present = Vec::with_capacity(plan.users.len());
    for (principal, selector) in &plan.users {
        let Some(uid) = principal.as_unix_uid() else {
            continue;
        };
        present.push(uid);
        if let Some(table) = table_for_uid(uid) {
            push_selectors(
                &mut out,
                table,
                &[(uid, uid)],
                *selector,
                USER_PRIORITY,
                with_ipv6,
            );
        }
    }
    if let Some(selector) = plan.system {
        let ranges = crate::service_account_uids::service_account_uids(sys_uid_max, &present);
        push_selectors(
            &mut out,
            SYSTEM_TABLE,
            &ranges,
            selector,
            SYSTEM_PRIORITY,
            with_ipv6,
        );
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// What to add and what to delete to turn `installed` into `desired`. Only our
/// rules are ever deleted.
pub(crate) fn selector_changes(
    installed: &[FibRule],
    desired: &[FibRule],
) -> (Vec<FibRule>, Vec<FibRule>) {
    let ours: Vec<&FibRule> = installed.iter().filter(|r| is_our_rule(r)).collect();
    let add = desired
        .iter()
        .filter(|d| !ours.contains(d))
        .copied()
        .collect();
    let delete = ours
        .into_iter()
        .filter(|r| !desired.contains(*r))
        .copied()
        .collect();
    (add, delete)
}

/// One of our rules standing without its uid range: the kernel ignored the
/// attribute, and the rule now steers every user.
pub(crate) fn uid_range_ignored(installed: &[FibRule]) -> bool {
    installed
        .iter()
        .any(|r| is_our_rule(r) && r.uid_range.is_none())
}

/// Whether a kernel release (`/proc/sys/kernel/osrelease`) selects by uid. An
/// unreadable one is given the benefit of the doubt: what it installs is
/// checked anyway.
#[must_use]
pub fn release_selects_by_uid(release: &str) -> bool {
    let mut parts = release
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .map(str::parse::<u32>);
    match (parts.next(), parts.next()) {
        (Some(Ok(major)), Some(Ok(minor))) => (major, minor) >= UID_RANGE_SINCE,
        _ => true,
    }
}

const OLD_KERNEL: &str = "this kernel cannot select routes by user (Linux 4.10 or newer needed)";

/// The Linux [`PrincipalRoutingPort`].
pub struct LinuxPrincipalRouting {
    sys_uid_max: u32,
    /// Read once: the kernel does not change under a running service.
    #[cfg(target_os = "linux")]
    kernel_selects_by_uid: bool,
    /// Latched when the kernel refuses IPv6 rules (IPv6 disabled at boot).
    #[cfg(target_os = "linux")]
    ipv6_refused: AtomicBool,
}

impl LinuxPrincipalRouting {
    #[must_use]
    pub fn new(sys_uid_max: u32) -> Self {
        Self {
            sys_uid_max,
            #[cfg(target_os = "linux")]
            kernel_selects_by_uid: release_selects_by_uid(
                &std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default(),
            ),
            #[cfg(target_os = "linux")]
            ipv6_refused: AtomicBool::new(false),
        }
    }

    /// With this machine's `SYS_UID_MAX`.
    #[must_use]
    pub fn for_this_machine() -> Self {
        Self::new(crate::service_account_uids::read_sys_uid_max())
    }
}

impl PrincipalRoutingPort for LinuxPrincipalRouting {
    fn table_for(&self, principal: &UserPrincipal) -> Option<RouteTableRef> {
        principal
            .as_unix_uid()
            .and_then(table_for_uid)
            .map(RouteTableRef::Tagged)
    }

    fn system_table(&self) -> RouteTableRef {
        RouteTableRef::Tagged(SYSTEM_TABLE)
    }

    fn is_principal_table(&self, table: &RouteTableRef) -> bool {
        matches!(table, RouteTableRef::Tagged(n) if is_our_table(*n))
    }

    #[cfg(target_os = "linux")]
    fn reconcile_selectors(&self, plan: &SelectorPlan) -> Result<SelectorDelta, PlatformError> {
        if !self.kernel_selects_by_uid {
            self.clear_selectors()?;
            return Err(PlatformError::NotSupported { reason: OLD_KERNEL });
        }
        let installed = crate::route_table::get_fib_rules()?;
        let with_ipv6 = !self.ipv6_refused.load(Ordering::Acquire);
        let desired = selector_rules(plan, self.sys_uid_max, with_ipv6);
        let (add, delete) = selector_changes(&installed, &desired);
        let mut delta = SelectorDelta::default();
        // Adds before deletes: a range that moves (a user signing in carves
        // their uid out of the service accounts') is never left unselected.
        for rule in &add {
            match crate::route_table::add_fib_rule(rule) {
                Ok(()) => delta.added += 1,
                Err(e) if rule.ipv6 && errno_is(&e, libc::EAFNOSUPPORT) => {
                    self.ipv6_refused.store(true, Ordering::Release);
                }
                Err(e) if refuses_uid_range(&e) => {
                    self.clear_selectors()?;
                    return Err(PlatformError::NotSupported { reason: OLD_KERNEL });
                }
                Err(e) if e.classify() == nrr_platform_api::error::ErrorClass::Conflict => {}
                Err(e) => return Err(e),
            }
        }
        for rule in &delete {
            match crate::route_table::delete_fib_rule(rule) {
                Ok(()) => delta.removed += 1,
                Err(e) if e.classify() == nrr_platform_api::error::ErrorClass::Idempotent => {}
                Err(e) => return Err(e),
            }
        }
        // Whatever of ours stood uid-less before was deleted above; one now is
        // a rule just added whose range the kernel dropped.
        if delta.added > 0 && uid_range_ignored(&crate::route_table::get_fib_rules()?) {
            self.clear_selectors()?;
            return Err(PlatformError::NotSupported { reason: OLD_KERNEL });
        }
        Ok(delta)
    }

    #[cfg(not(target_os = "linux"))]
    fn reconcile_selectors(&self, _plan: &SelectorPlan) -> Result<SelectorDelta, PlatformError> {
        Err(PlatformError::NotSupported {
            reason: "per-user routing needs a Linux kernel",
        })
    }

    #[cfg(target_os = "linux")]
    fn clear_selectors(&self) -> Result<usize, PlatformError> {
        sweep_selectors()
    }

    #[cfg(not(target_os = "linux"))]
    fn clear_selectors(&self) -> Result<usize, PlatformError> {
        Ok(0)
    }
}

/// Remove every rule of ours, with or without a service running. Returns how
/// many went.
#[cfg(target_os = "linux")]
pub fn sweep_selectors() -> Result<usize, PlatformError> {
    let mut removed = 0;
    for rule in crate::route_table::get_fib_rules()?
        .iter()
        .filter(|r| is_our_rule(r))
    {
        match crate::route_table::delete_fib_rule(rule) {
            Ok(()) => removed += 1,
            Err(e) if e.classify() == nrr_platform_api::error::ErrorClass::Idempotent => {}
            Err(e) => return Err(e),
        }
    }
    Ok(removed)
}

#[cfg(target_os = "linux")]
fn errno_is(error: &PlatformError, errno: i32) -> bool {
    matches!(error, PlatformError::Errno { code, .. } if *code == errno)
}

/// The answers of a kernel that does not know the uid-range attribute.
#[cfg(target_os = "linux")]
fn refuses_uid_range(error: &PlatformError) -> bool {
    errno_is(error, libc::EINVAL) || errno_is(error, libc::EOPNOTSUPP)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYS_UID_MAX: u32 = 999;

    fn user(uid: u32, overlay: Option<u8>) -> (UserPrincipal, TableSelector) {
        (
            UserPrincipal::from_linux_uid(uid),
            TableSelector {
                overlay_prefix_v4: overlay,
            },
        )
    }

    fn plan(
        users: Vec<(UserPrincipal, TableSelector)>,
        system: Option<Option<u8>>,
    ) -> SelectorPlan {
        SelectorPlan {
            users,
            system: system.map(|overlay_prefix_v4| TableSelector { overlay_prefix_v4 }),
        }
    }

    fn for_uid(rules: &[FibRule], uid: u32) -> Vec<FibRule> {
        rules
            .iter()
            .filter(|r| r.uid_range == Some((uid, uid)))
            .copied()
            .collect()
    }

    #[test]
    fn each_user_has_a_table_of_their_own_and_the_system_one_differs() {
        assert_eq!(table_for_uid(1000), Some(0x8000_03E8));
        assert_ne!(table_for_uid(1000), table_for_uid(1001));
        assert_eq!(table_for_uid(0), Some(PRINCIPAL_TABLE_BASE));
        assert_ne!(table_for_uid(0), Some(SYSTEM_TABLE));
        assert_eq!(table_for_uid(LAST_MAPPED_UID), Some(u32::MAX - 1));
        assert_eq!(table_for_uid(LAST_MAPPED_UID + 1), None);
        for reserved in [0, 252, 253, 254, 255, 51_820] {
            assert!(!is_our_table(reserved));
        }
        assert!(is_our_table(SYSTEM_TABLE));
        assert!(!is_our_table(u32::MAX));
        let last_priority = *PRIORITY_BAND.end();
        assert!(last_priority < 32_764, "ahead of wg-quick and main");
    }

    /// Two users with different rules for one address: each rule names only
    /// its own uid and its own table.
    #[test]
    fn two_users_are_selected_into_two_tables() {
        let rules = selector_rules(
            &plan(vec![user(1000, None), user(1001, None)], Some(None)),
            SYS_UID_MAX,
            true,
        );
        let a = for_uid(&rules, 1000);
        let b = for_uid(&rules, 1001);
        assert_eq!(a.len(), 2, "one per family: {a:?}");
        let in_own_table = |r: &FibRule| r.table == 0x8000_03E8 && r.priority == USER_PRIORITY;
        assert!(a.iter().all(in_own_table));
        assert!(b.iter().all(|r| r.table == 0x8000_03E9));
        let ours_by_uid = |r: &FibRule| r.uid_range.is_some() && is_our_rule(r);
        assert!(rules.iter().all(ours_by_uid));
    }

    /// An overlay table yields to `main`'s more specific routes: table without
    /// overlays, then `main` above the overlay length, then the overlays.
    #[test]
    fn an_overlay_table_is_looked_up_in_three_steps() {
        let rules = selector_rules(&plan(vec![user(1000, Some(2))], None), SYS_UID_MAX, false);
        let table = 0x8000_03E8;
        assert_eq!(
            rules
                .iter()
                .map(|r| (r.priority, r.table, r.suppress_prefixlen))
                .collect::<Vec<_>>(),
            vec![
                (USER_PRIORITY, table, Some(2)),
                (USER_PRIORITY + 1, RT_TABLE_MAIN, Some(1)),
                (USER_PRIORITY + 2, table, None),
            ]
        );
    }

    /// A present root is a person: uid 0 leaves the service-account ranges and
    /// gets its own table, looked up first.
    #[test]
    fn a_present_root_leaves_the_system_range() {
        let rules = selector_rules(
            &plan(vec![user(0, None), user(1000, None)], Some(None)),
            SYS_UID_MAX,
            false,
        );
        let system: Vec<_> = rules.iter().filter(|r| r.table == SYSTEM_TABLE).collect();
        assert_eq!(
            system.iter().map(|r| r.uid_range).collect::<Vec<_>>(),
            vec![Some((1, 999)), Some((65_534, 65_534))]
        );
        assert!(system.iter().all(|r| r.priority == SYSTEM_PRIORITY));
        let root = for_uid(&rules, 0);
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].table, PRINCIPAL_TABLE_BASE);
        assert!(root[0].priority < SYSTEM_PRIORITY);
    }

    #[test]
    fn nobody_present_asks_for_no_rules() {
        let rules = selector_rules(&plan(Vec::new(), None), SYS_UID_MAX, true);
        assert!(rules.is_empty());
    }

    /// A user leaving takes their own rule with them and widens the service
    /// accounts' range; the other user's rule is not touched.
    #[test]
    fn a_user_leaving_removes_only_their_rule() {
        let both = selector_rules(
            &plan(vec![user(500, None), user(1000, None)], Some(None)),
            SYS_UID_MAX,
            false,
        );
        let one = selector_rules(
            &plan(vec![user(1000, None)], Some(None)),
            SYS_UID_MAX,
            false,
        );
        let (add, delete) = selector_changes(&both, &one);
        assert!(delete.iter().any(|r| r.uid_range == Some((500, 500))));
        assert!(delete.iter().all(|r| r.uid_range != Some((1000, 1000))));
        assert!(add.iter().all(|r| r.table == SYSTEM_TABLE));
        assert!(add.iter().any(|r| r.uid_range == Some((0, 999))));
    }

    /// Somebody else's rules — another band, a mark, another table — are never
    /// ours to delete; a stale one of ours is.
    #[test]
    fn only_our_rules_are_reconciled() {
        let foreign = [
            FibRule {
                ipv6: false,
                priority: 32_765,
                table: 51_820,
                uid_range: None,
                suppress_prefixlen: None,
                narrowed: true,
            },
            FibRule {
                ipv6: false,
                priority: 30_100,
                table: 100,
                uid_range: Some((1000, 1000)),
                suppress_prefixlen: None,
                narrowed: false,
            },
            FibRule {
                ipv6: false,
                priority: 30_100,
                table: 0x8000_03E8,
                uid_range: Some((1000, 1000)),
                suppress_prefixlen: None,
                narrowed: true,
            },
        ];
        let stale = FibRule {
            ipv6: false,
            priority: USER_PRIORITY,
            table: 0x8000_07D0,
            uid_range: Some((2000, 2000)),
            suppress_prefixlen: None,
            narrowed: false,
        };
        let mut installed = foreign.to_vec();
        installed.push(stale);
        let (add, delete) = selector_changes(&installed, &[]);
        assert!(add.is_empty());
        assert_eq!(delete, vec![stale]);
    }

    /// Reconciling what is already installed changes nothing.
    #[test]
    fn a_settled_plan_is_a_no_op() {
        let desired = selector_rules(
            &plan(vec![user(1000, Some(2))], Some(Some(2))),
            SYS_UID_MAX,
            true,
        );
        let (add, delete) = selector_changes(&desired, &desired);
        assert!(add.is_empty() && delete.is_empty());
    }

    /// A rule of ours with no uid range steers everybody: the sign of a kernel
    /// that dropped the attribute.
    #[test]
    fn an_ignored_uid_range_is_detected() {
        let mut rule = selector_rules(&plan(vec![user(1000, None)], None), SYS_UID_MAX, false)[0];
        assert!(!uid_range_ignored(&[rule]));
        rule.uid_range = None;
        assert!(uid_range_ignored(&[rule]));
    }

    #[test]
    fn the_kernel_release_decides_support() {
        assert!(release_selects_by_uid("5.4.0-150-generic"));
        assert!(release_selects_by_uid("4.10.0"));
        assert!(release_selects_by_uid("6.1.0-astra"));
        assert!(!release_selects_by_uid("4.9.337"));
        assert!(!release_selects_by_uid("3.10.0-1160.el7.x86_64"));
        assert!(release_selects_by_uid(""));
    }

    /// The reset script removes our rules by hand; its copy of the band and of
    /// the first table must match.
    #[test]
    fn the_reset_script_mirrors_the_band_and_the_tables() {
        let script = include_str!("../../../../scripts/reset-network.sh");
        for line in [
            format!("rule_priority_first={}", PRIORITY_BAND.start()),
            format!("rule_priority_last={}", PRIORITY_BAND.end()),
            format!("our_table_first={SYSTEM_TABLE}"),
        ] {
            assert!(script.lines().any(|l| l == line), "{line}");
        }
    }

    #[test]
    fn the_port_names_tables_by_uid() {
        let port = LinuxPrincipalRouting::new(SYS_UID_MAX);
        assert_eq!(
            port.table_for(&UserPrincipal::from_linux_uid(1000)),
            Some(RouteTableRef::Tagged(0x8000_03E8))
        );
        assert!(port.is_principal_table(&port.system_table()));
        assert!(!port.is_principal_table(&RouteTableRef::Main));
        assert!(!port.is_principal_table(&RouteTableRef::Tagged(51_820)));
    }
}
