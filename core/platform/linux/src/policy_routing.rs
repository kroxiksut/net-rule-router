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

use crate::route_table::{FibRule, RawFibRule};

/// A user's table is this plus their uid.
pub const PRINCIPAL_TABLE_BASE: u32 = 0x8000_0000;
/// The service accounts' table.
pub const SYSTEM_TABLE: u32 = PRINCIPAL_TABLE_BASE - 1;
/// Users' selectors start here; ahead of `main` (32766) and of wg-quick's
/// 32764/32765.
pub const USER_PRIORITY: u32 = 30_100;
/// The service accounts' selectors, after every user's.
pub const SYSTEM_PRIORITY: u32 = 30_110;
/// What the machine forwards follows the service accounts' table too, after
/// them: at the tunnel's outage the forward hook blocks what the owner's guard
/// blocks, and while it is up the same routes carry it as the machine's own.
pub const FORWARDED_PRIORITY: u32 = 30_115;
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

/// The `main` rule's priority: a rule added without one lands just in front of
/// the first rule after `local`, which is `main` until ours are installed.
const MAIN_RULE_PRIORITY: u32 = 32_766;

/// Somebody else's rules in an unbroken run right in front of ours, each with
/// the priority it would have had without us. A VPN that comes up after the
/// service (`wg-quick` numbers nothing) lands there and takes every user's
/// traffic before their own table is looked up. The kernel numbers such a rule
/// down from the first rule after `local`; without ours that is the first
/// foreign rule behind our band, so a second tunnel lands in front of the
/// first, as it would have. A `goto`, or a rule some `goto` jumps to, stops
/// the run: moving either would break the jump.
pub(crate) fn displaced_rules(rules: &[RawFibRule]) -> Vec<(usize, u32)> {
    let mut out = Vec::new();
    for ipv6 in [false, true] {
        let family = || rules.iter().filter(move |r| r.ipv6 == ipv6);
        let Some(start) = family().filter(|r| r.ours).map(|r| r.priority).min() else {
            continue;
        };
        let base = family()
            .filter(|r| !r.ours && r.priority > *PRIORITY_BAND.end())
            .map(|r| r.priority)
            .min()
            .unwrap_or(MAIN_RULE_PRIORITY);
        let jumped_to: Vec<u32> = family().filter_map(|r| r.goto_target).collect();
        let mut priority = start;
        while priority > 1 {
            priority -= 1;
            let Some(target) = base.checked_sub(start - priority) else {
                break;
            };
            let here: Vec<usize> = (0..rules.len())
                .filter(|&i| {
                    rules[i].ipv6 == ipv6 && !rules[i].ours && rules[i].priority == priority
                })
                .collect();
            if here.is_empty()
                || here.iter().any(|&i| rules[i].goto_target.is_some())
                || jumped_to.contains(&priority)
                || target <= *PRIORITY_BAND.end()
            {
                break;
            }
            out.extend(here.into_iter().map(|i| (i, target)));
        }
    }
    out
}

/// Somebody else's rules far in front of our band that send every address to a
/// table of their own (`ipv6`, priority, table): a VPN's exit-node rule lands
/// here, and it takes the traffic before any user's table is looked up. They
/// are not moved — a number that far ahead was chosen — only reported.
pub(crate) fn catch_all_rules_ahead(rules: &[RawFibRule]) -> Vec<(bool, u32, u32)> {
    const STANDARD_TABLES: [u32; 3] = [253, 254, 255];
    let mut found: Vec<(bool, u32, u32)> = rules
        .iter()
        .filter(|r| !r.ours && r.priority > 0 && r.priority < USER_PRIORITY)
        .filter_map(|r| {
            r.catch_all_table
                .filter(|t| !STANDARD_TABLES.contains(t))
                .map(|t| (r.ipv6, r.priority, t))
        })
        .collect();
    found.sort_unstable();
    found
}

/// Every rule [`displaced_rules`] would move, whole: empty once ours are in
/// front. A pass input, so a VPN coming up wakes a pass that would otherwise
/// see nothing it reads move; the body, so one rule replacing another at the
/// same priority is a change too.
#[cfg(target_os = "linux")]
pub fn rules_in_front_of_ours() -> Result<Vec<(bool, u32, Vec<u8>)>, PlatformError> {
    let rules = crate::route_table::get_raw_fib_rules()?;
    Ok(displaced_rules(&rules)
        .into_iter()
        .map(|(i, _)| (rules[i].ipv6, rules[i].priority, rules[i].body.clone()))
        .collect())
}

/// Our selectors as installed, hashed. A pass input: `ip rule flush` or a
/// network manager rewriting the rules moves nothing else a pass reads, and
/// the pass that reinstalls them is the same one that writes them.
#[cfg(target_os = "linux")]
pub fn installed_selectors_fingerprint() -> Result<u64, PlatformError> {
    use std::hash::{Hash, Hasher};
    let mut ours: Vec<FibRule> = crate::route_table::get_fib_rules()?
        .into_iter()
        .filter(is_our_rule)
        .collect();
    ours.sort_unstable();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    ours.hash(&mut hasher);
    Ok(hasher.finish())
}

/// Say so when the set of catch-all foreign rules ahead of our band changes.
#[cfg(target_os = "linux")]
fn report_catch_all_ahead(found: &[(bool, u32, u32)]) {
    static LAST: std::sync::Mutex<Vec<(bool, u32, u32)>> = std::sync::Mutex::new(Vec::new());
    let mut last = LAST.lock().unwrap_or_else(|p| p.into_inner());
    if last.as_slice() == found {
        return;
    }
    *last = found.to_vec();
    crate::kernel_capabilities::set_foreign_rule_ahead(!found.is_empty());
    for (ipv6, priority, table) in found {
        tracing::warn!(
            target: "nrr::routes",
            msg_key = "linux-foreign-rule-ahead",
            priority,
            table,
            ipv6,
            "a routing rule far in front of ours sends all traffic to another table; it is looked up before any user's own routes",
        );
    }
}

/// Move what [`displaced_rules`] finds. One refused move does not hold back
/// the others; the first refusal is returned after all were tried.
#[cfg(target_os = "linux")]
fn keep_ours_in_front() -> Result<usize, PlatformError> {
    let rules = crate::route_table::get_raw_fib_rules()?;
    report_catch_all_ahead(&catch_all_rules_ahead(&rules));
    let mut moved = 0;
    let mut first_error = None;
    for (i, to) in displaced_rules(&rules) {
        let rule = &rules[i];
        if let Err(e) = crate::route_table::move_raw_fib_rule(rule, to) {
            first_error.get_or_insert(e);
            continue;
        }
        moved += 1;
        tracing::info!(
            target: "nrr::routes",
            msg_key = "linux-foreign-rule-moved",
            from = rule.priority,
            to,
            ipv6 = rule.ipv6,
            "a routing rule added after ours stood in front of them; moved to where it would have been without us",
        );
    }
    first_error.map_or(Ok(moved), Err)
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
    ranges: &[Option<(u32, u32)>],
    selector: TableSelector,
    priority: u32,
    with_ipv6: bool,
) {
    for &range in ranges {
        // `iif lo` on a uid selector: a forwarded packet is looked up as uid 0
        // and takes only the selector made for it (`range` = `None`).
        let rule = |ipv6, priority, table, suppress_prefixlen| FibRule {
            ipv6,
            priority,
            table,
            uid_range: range,
            suppress_prefixlen,
            iif_lo: range.is_some(),
            narrowed: false,
            forwarded: range.is_none(),
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
                &[Some((uid, uid))],
                *selector,
                USER_PRIORITY,
                with_ipv6,
            );
        }
    }
    if let Some(selector) = plan.system {
        let ranges: Vec<_> =
            crate::service_account_uids::service_account_uids(sys_uid_max, &present)
                .into_iter()
                .map(Some)
                .collect();
        push_selectors(
            &mut out,
            SYSTEM_TABLE,
            &ranges,
            selector,
            SYSTEM_PRIORITY,
            with_ipv6,
        );
        push_selectors(
            &mut out,
            SYSTEM_TABLE,
            &[None],
            selector,
            FORWARDED_PRIORITY,
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
        .any(|r| is_our_rule(r) && r.uid_range.is_none() && !r.forwarded)
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
            let Err(e) = crate::route_table::add_fib_rule(rule) else {
                delta.added += 1;
                continue;
            };
            match note_add_refusal(rule.ipv6, &e) {
                AddRefusal::Ipv6Off => self.ipv6_refused.store(true, Ordering::Release),
                AddRefusal::NoUidRange => {
                    self.clear_selectors()?;
                    return Err(PlatformError::NotSupported { reason: OLD_KERNEL });
                }
                AddRefusal::AlreadyThere => {}
                AddRefusal::Failed => return Err(e),
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
            crate::kernel_capabilities::record(
                crate::kernel_capabilities::KernelCapability::UserRoutes,
                false,
            );
            self.clear_selectors()?;
            return Err(PlatformError::NotSupported { reason: OLD_KERNEL });
        }
        if delta.added > 0 {
            crate::kernel_capabilities::record(
                crate::kernel_capabilities::KernelCapability::UserRoutes,
                true,
            );
        }
        // Ours already stand; a move refused now is retried by the next pass.
        if let Err(e) = keep_ours_in_front() {
            tracing::warn!(
                target: "nrr::routes",
                msg_key = "linux-foreign-rule-move-failed",
                error = %e,
                "a routing rule in front of ours could not be moved: until it is, it takes the traffic first",
            );
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

/// Remove every route of ours, with or without a service running: our
/// signature in `main`, and anything in a table only we write. Returns how
/// many went.
#[cfg(target_os = "linux")]
pub fn sweep_routes() -> Result<usize, nrr_platform_api::route_signature::RouteSweepError> {
    nrr_platform_api::route_signature::sweep_owned_routes_with(
        std::sync::Arc::new(crate::LinuxApi),
        &|r: &nrr_platform_api::RouteEntry| matches!(r.table, RouteTableRef::Tagged(n) if is_our_table(n)),
    )
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

/// What one refused selector add means for the pass.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
enum AddRefusal {
    /// IPv6 is disabled at boot: the IPv4 rules carry on alone.
    Ipv6Off,
    /// The kernel does not know the uid range: per-user routing is gone.
    NoUidRange,
    AlreadyThere,
    Failed,
}

/// Classify a refused add, recording a uid range the kernel refuses as a
/// missing capability: the profile must not keep claiming per-user routes.
#[cfg(target_os = "linux")]
fn note_add_refusal(ipv6: bool, error: &PlatformError) -> AddRefusal {
    if ipv6 && errno_is(error, libc::EAFNOSUPPORT) {
        return AddRefusal::Ipv6Off;
    }
    if refuses_uid_range(error) {
        crate::kernel_capabilities::record(
            crate::kernel_capabilities::KernelCapability::UserRoutes,
            false,
        );
        return AddRefusal::NoUidRange;
    }
    if error.classify() == nrr_platform_api::error::ErrorClass::Conflict {
        return AddRefusal::AlreadyThere;
    }
    AddRefusal::Failed
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
        assert!(rules.iter().filter(|r| !r.forwarded).all(ours_by_uid));
        assert!(rules.iter().all(is_our_rule));
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
        let system: Vec<_> = rules
            .iter()
            .filter(|r| r.table == SYSTEM_TABLE && !r.forwarded)
            .collect();
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
                iif_lo: false,
                narrowed: true,
                forwarded: false,
            },
            FibRule {
                ipv6: false,
                priority: 30_100,
                table: 100,
                uid_range: Some((1000, 1000)),
                suppress_prefixlen: None,
                iif_lo: true,
                narrowed: false,
                forwarded: false,
            },
            FibRule {
                ipv6: false,
                priority: 30_100,
                table: 0x8000_03E8,
                uid_range: Some((1000, 1000)),
                suppress_prefixlen: None,
                iif_lo: true,
                narrowed: true,
                forwarded: false,
            },
        ];
        // A selector of ours from before `iif lo`: still ours to delete.
        let stale = FibRule {
            ipv6: false,
            priority: USER_PRIORITY,
            table: 0x8000_07D0,
            uid_range: Some((2000, 2000)),
            suppress_prefixlen: None,
            iif_lo: false,
            narrowed: false,
            forwarded: false,
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

    /// What the kernel does with one of our rules: a locally originated
    /// packet of `uid` matches a uid selector, a forwarded one (ingress is the
    /// bridge, uid 0) only the selector made for it.
    fn selects(rule: &FibRule, uid: u32, forwarded: bool) -> bool {
        if rule.forwarded {
            return forwarded;
        }
        let uid_ok = rule
            .uid_range
            .is_none_or(|(lo, hi)| (lo..=hi).contains(&uid));
        uid_ok && !(rule.iif_lo && forwarded)
    }

    /// Docker, libvirt and LXC traffic is forwarded as uid 0: it skips every
    /// uid selector and takes the service accounts' table by its own selector,
    /// after theirs.
    #[test]
    fn forwarded_traffic_takes_only_its_own_selector() {
        let rules = selector_rules(
            &plan(vec![user(1000, Some(2))], Some(Some(2))),
            SYS_UID_MAX,
            true,
        );
        assert!(rules.iter().any(|r| selects(r, 1000, false)));
        assert!(
            rules.iter().any(|r| selects(r, 0, false)),
            "service accounts"
        );
        let forwarded: Vec<_> = rules.iter().filter(|r| selects(r, 0, true)).collect();
        assert!(!forwarded.is_empty());
        assert!(forwarded.iter().all(|r| r.forwarded
            && r.uid_range.is_none()
            && r.priority >= FORWARDED_PRIORITY
            && (r.table == SYSTEM_TABLE || r.table == RT_TABLE_MAIN)));
        assert!(rules.iter().filter(|r| !r.forwarded).all(|r| r.iif_lo));
        assert!(
            !uid_range_ignored(&rules),
            "the forwarded selector is not a lost uid range"
        );
        // None without the service accounts' table to send it to.
        let users_only = selector_rules(&plan(vec![user(1000, None)], None), SYS_UID_MAX, true);
        assert!(users_only.iter().all(|r| !r.forwarded));
    }

    /// A selector installed by a previous version carries no `iif lo`; the
    /// reconcile replaces it rather than keeping it.
    #[test]
    fn a_selector_without_the_lo_ingress_is_replaced() {
        let desired = selector_rules(&plan(vec![user(1000, None)], None), SYS_UID_MAX, false);
        let old = FibRule {
            iif_lo: false,
            ..desired[0]
        };
        assert!(is_our_rule(&old));
        let (add, delete) = selector_changes(&[old], &desired);
        assert_eq!(add, desired);
        assert_eq!(delete, vec![old]);
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

    fn raw(ipv6: bool, priority: u32, ours: bool) -> RawFibRule {
        RawFibRule {
            ipv6,
            priority,
            goto_target: None,
            ours,
            catch_all_table: None,
            body: Vec::new(),
        }
    }

    #[test]
    fn a_foreign_catch_all_far_ahead_is_found_and_ours_and_standard_tables_are_not() {
        let with_table = |priority, ours, table: Option<u32>| RawFibRule {
            catch_all_table: table,
            ..raw(false, priority, ours)
        };
        let rules = [
            with_table(0, false, Some(255)),
            with_table(5_270, false, Some(52)),
            with_table(5_250, false, None),
            with_table(100, false, Some(254)),
            with_table(USER_PRIORITY, true, Some(0x8000_03E8)),
            with_table(32_764, false, Some(51_820)),
        ];
        assert_eq!(catch_all_rules_ahead(&rules), [(false, 5_270, 52)]);
    }

    /// `wg-quick` brought up after the service: its pair landed at 30098/30099
    /// in front of ours and goes back to 32764/32765, order kept.
    #[test]
    fn a_vpn_pair_in_front_of_ours_goes_where_it_would_have_been() {
        let rules = [
            raw(false, 0, false),
            raw(false, 30_098, false),
            raw(false, 30_099, false),
            raw(false, USER_PRIORITY, true),
            raw(false, SYSTEM_PRIORITY, true),
            raw(false, 32_766, false),
        ];
        let mut moves = displaced_rules(&rules);
        moves.sort_unstable();
        assert_eq!(moves, vec![(1, 32_764), (2, 32_765)]);
    }

    /// The families are numbered apart; each run is measured from its own.
    #[test]
    fn each_family_is_measured_from_its_own_rules() {
        let rules = [
            raw(false, 30_099, false),
            raw(false, USER_PRIORITY, true),
            raw(true, 30_099, false),
            raw(true, SYSTEM_PRIORITY, true),
        ];
        let mut moves = displaced_rules(&rules);
        moves.sort_unstable();
        assert_eq!(moves, vec![(0, 32_765)]);
    }

    /// Rules numbered on purpose elsewhere (Tailscale's 52xx), a gap, a `goto`,
    /// and rules behind ours all stay.
    #[test]
    fn only_an_unbroken_run_right_in_front_moves() {
        let mut jump = raw(false, 30_098, false);
        jump.goto_target = Some(32_000);
        let rules = [
            raw(false, 5_270, false),
            jump,
            raw(false, 30_099, false),
            raw(false, USER_PRIORITY, true),
            raw(false, 32_765, false),
        ];
        assert_eq!(
            displaced_rules(&rules),
            vec![(2, 32_764)],
            "in front of the rule behind ours"
        );
        let gapped = [raw(false, 30_097, false), raw(false, USER_PRIORITY, true)];
        assert!(displaced_rules(&gapped).is_empty());
    }

    /// A second tunnel up after the first was moved lands in front of the
    /// first, as it would have without us, never on the first one's slots.
    #[test]
    fn a_second_tunnel_goes_in_front_of_the_first() {
        let rules = [
            raw(false, 30_098, false),
            raw(false, 30_099, false),
            raw(false, USER_PRIORITY, true),
            raw(false, 32_764, false),
            raw(false, 32_765, false),
            raw(false, 32_766, false),
        ];
        let mut moves = displaced_rules(&rules);
        moves.sort_unstable();
        assert_eq!(moves, vec![(0, 32_762), (1, 32_763)]);
    }

    /// A rule some `goto` jumps to keeps its priority, or the jump would land
    /// nowhere.
    #[test]
    fn a_jump_target_stays() {
        let mut jump = raw(false, 5_000, false);
        jump.goto_target = Some(30_099);
        let rules = [
            jump,
            raw(false, 30_099, false),
            raw(false, USER_PRIORITY, true),
        ];
        assert!(displaced_rules(&rules).is_empty());
    }

    /// With none of ours installed nobody is in front of anything.
    #[test]
    fn nothing_moves_without_rules_of_ours() {
        assert!(displaced_rules(&[raw(false, 30_099, false)]).is_empty());
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

    /// A kernel that refuses the uid range at add is listed as missing per-user
    /// routes; IPv6 being off or a rule already standing says nothing of it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refused_uid_range_is_listed_as_missing() {
        use crate::kernel_capabilities::{is_available, missing, record, KernelCapability};
        let _held = crate::kernel_capabilities::TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let errno = |code| PlatformError::Errno {
            operation: "add a routing rule",
            code,
            message: String::new(),
        };
        record(KernelCapability::UserRoutes, true);
        assert_eq!(
            note_add_refusal(true, &errno(libc::EAFNOSUPPORT)),
            AddRefusal::Ipv6Off
        );
        assert_eq!(
            note_add_refusal(false, &errno(libc::EEXIST)),
            AddRefusal::AlreadyThere
        );
        assert!(is_available(KernelCapability::UserRoutes));

        assert_eq!(
            note_add_refusal(false, &errno(libc::EINVAL)),
            AddRefusal::NoUidRange
        );
        assert!(missing().contains(&KernelCapability::UserRoutes));
        record(KernelCapability::UserRoutes, true);
    }

    /// The reset script and the AUR removal fallback remove our rules by hand;
    /// their copies of the band and of the first table must match.
    #[test]
    fn the_reset_script_mirrors_the_band_and_the_tables() {
        let reset = include_str!("../../../../scripts/reset-network.sh");
        let aur =
            include_str!("../../../../packaging/linux/aur/netrulerouter-bin/netrulerouter.install");
        for (script, prefix) in [(reset, ""), (aur, "_nrr_")] {
            for line in [
                format!("{prefix}rule_priority_first={}", PRIORITY_BAND.start()),
                format!("{prefix}rule_priority_last={}", PRIORITY_BAND.end()),
                format!("{prefix}our_table_first={SYSTEM_TABLE}"),
            ] {
                assert!(script.lines().any(|l| l == line), "{line}");
            }
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
