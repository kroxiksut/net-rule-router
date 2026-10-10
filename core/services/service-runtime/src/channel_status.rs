//! Whether each present principal's channels carry their rules, told to that
//! principal — decided from the enforcer's [`ChannelReport`], which the
//! enforcement cycle reads every pass anyway, so the status costs no extra
//! look at the machine.
//!
//! The route coordinator reaches the same statuses from its own resolution.
//! Both write through [`RouteEnforcementStatus::publish`], so the GUI, the TUI,
//! the snapshot and the outage list cannot tell the two sources apart.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nrr_platform_api::enforcement::{ChannelReport, ChannelState};

use crate::app_enforcement_status::{RouteEnforcementStatus, MACHINE_WIDE_ROLE};
use crate::ipc_handlers::event_bus::EventBus;

/// How long a missing bound adapter must stay missing before it is announced
/// as removed. A few passes: long enough for the OS to report a switch-off.
pub const GONE_GRACE: Duration = Duration::from_secs(15);

/// When each role's binding was first found missing, per principal.
type AbsentSince = HashMap<String, [Option<Instant>; 2]>;

/// Turns per-pass channel reports into per-principal status reports, pushed
/// on change only.
pub struct ChannelStatusPublisher {
    board: RouteEnforcementStatus,
    absent_since: Mutex<AbsentSince>,
}

impl ChannelStatusPublisher {
    pub fn new(board: RouteEnforcementStatus) -> Self {
        Self {
            board,
            absent_since: Mutex::new(HashMap::new()),
        }
    }

    pub fn board(&self) -> &RouteEnforcementStatus {
        &self.board
    }

    /// Report what this pass found for the principals present. A principal
    /// absent from `reports` keeps its standing report: nobody is there to
    /// read a change, and the next sign-in brings a fresh pass.
    pub fn observe<'a>(
        &self,
        events: Option<&EventBus>,
        reports: impl IntoIterator<Item = (&'a str, &'a ChannelReport)>,
        now: Instant,
    ) {
        let mut absent = self.absent_since.lock().unwrap_or_else(|p| p.into_inner());
        let mut present: Vec<&str> = Vec::new();
        for (principal, report) in reports {
            present.push(principal);
            self.observe_one(events, principal, report, now, &mut absent);
        }
        absent.retain(|principal, _| present.contains(&principal.as_str()));
    }

    fn observe_one(
        &self,
        events: Option<&EventBus>,
        principal: &str,
        report: &ChannelReport,
        now: Instant,
        absent: &mut AbsentSince,
    ) {
        let board = &self.board;
        let unreadable = |s: &ChannelState| *s == ChannelState::Unknown;
        let unbound = |s: &ChannelState| *s == ChannelState::Unbound;
        if unreadable(&report.primary) && unreadable(&report.secondary) {
            board.publish(
                events,
                principal,
                "adapters-unreadable",
                MACHINE_WIDE_ROLE,
                Vec::new(),
            );
            return;
        }
        if unbound(&report.primary) && unbound(&report.secondary) {
            absent.remove(principal);
            board.publish(
                events,
                principal,
                "no-policy",
                MACHINE_WIDE_ROLE,
                Vec::new(),
            );
            for role in ["primary", "secondary"] {
                board.clear_role(events, principal, role);
            }
            return;
        }
        board.clear_machine_wide(events, principal);
        let roles = [
            ("primary", &report.primary),
            ("secondary", &report.secondary),
        ];
        for (slot, (role, state)) in roles.into_iter().enumerate() {
            if !matches!(state, ChannelState::Absent { .. }) {
                if let Some(since) = absent.get_mut(principal) {
                    since[slot] = None;
                }
            }
            match state {
                ChannelState::Usable => board.publish(events, principal, "ok", role, Vec::new()),
                ChannelState::Down => {
                    board.publish(events, principal, "secondary-down", role, Vec::new());
                }
                // Fail-closed already holds; only the advice waits.
                ChannelState::Absent { replacements } => {
                    let slots = absent.entry(principal.to_owned()).or_default();
                    let since = *slots[slot].get_or_insert(now);
                    if now.saturating_duration_since(since) >= GONE_GRACE {
                        board.publish(
                            events,
                            principal,
                            "adapter-gone",
                            role,
                            replacements.clone(),
                        );
                    }
                }
                ChannelState::Unbound => board.clear_role(events, principal, role),
                ChannelState::Unknown => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::ipc_payloads::StatusUpdateEvent;

    fn report(primary: ChannelState, secondary: ChannelState) -> ChannelReport {
        ChannelReport { primary, secondary }
    }

    fn statuses(bus: &EventBus, subscription: &str) -> Vec<(String, String)> {
        bus.peek_pending_for(subscription, 64)
            .into_iter()
            .filter_map(|e| match e.event {
                StatusUpdateEvent::EnforcementStatusChanged { status, role, .. } => {
                    Some((role, status))
                }
                _ => None,
            })
            .collect()
    }

    fn pair(role: &str, status: &str) -> (String, String) {
        (role.to_owned(), status.to_owned())
    }

    #[test]
    fn a_vanished_binding_is_announced_only_after_the_grace() {
        let bus = EventBus::new();
        let me = bus.subscribe_as("gui".into(), Some("unix:uid:1000".into()), Some(0));
        let publisher = ChannelStatusPublisher::new(RouteEnforcementStatus::new());
        let gone = report(
            ChannelState::Absent {
                replacements: vec!["wlan0".into()],
            },
            ChannelState::Usable,
        );
        let start = Instant::now();
        publisher.observe(Some(&bus), [("unix:uid:1000", &gone)], start);
        assert_eq!(
            statuses(&bus, &me.subscription_id),
            vec![pair("secondary", "ok")]
        );

        publisher.observe(Some(&bus), [("unix:uid:1000", &gone)], start + GONE_GRACE);
        assert_eq!(
            publisher
                .board()
                .status_of("unix:uid:1000", "primary")
                .as_deref(),
            Some("adapter-gone"),
        );
        let pushed = bus.peek_pending_for(&me.subscription_id, 64);
        assert!(pushed.iter().any(|e| matches!(
            &e.event,
            StatusUpdateEvent::EnforcementStatusChanged { status, candidates, .. }
                if status == "adapter-gone" && candidates == &vec!["wlan0".to_string()]
        )));
    }

    #[test]
    fn a_returning_binding_restarts_the_grace() {
        let publisher = ChannelStatusPublisher::new(RouteEnforcementStatus::new());
        let gone = report(
            ChannelState::Absent {
                replacements: Vec::new(),
            },
            ChannelState::Usable,
        );
        let back = report(ChannelState::Usable, ChannelState::Usable);
        let start = Instant::now();
        publisher.observe(None, [("p", &gone)], start);
        publisher.observe(None, [("p", &back)], start + GONE_GRACE / 2);
        publisher.observe(None, [("p", &gone)], start + GONE_GRACE);
        assert_eq!(
            publisher.board().status_of("p", "primary").as_deref(),
            Some("ok"),
            "a link gone twice for half the grace each is not gone",
        );
    }

    #[test]
    fn nothing_bound_is_no_policy_and_ends_the_role_reports() {
        let publisher = ChannelStatusPublisher::new(RouteEnforcementStatus::new());
        let down = report(ChannelState::Usable, ChannelState::Down);
        let unbound = report(ChannelState::Unbound, ChannelState::Unbound);
        let now = Instant::now();
        publisher.observe(None, [("p", &down)], now);
        publisher.observe(None, [("p", &unbound)], now);
        let board = publisher.board();
        assert_eq!(board.status_of("p", "").as_deref(), Some("no-policy"));
        assert_eq!(board.status_of("p", "secondary").as_deref(), Some("ok"));

        publisher.observe(None, [("p", &down)], now);
        assert_eq!(board.status_of("p", "").as_deref(), Some("ok"));
    }

    #[test]
    fn unreadable_links_are_one_machine_wide_report_that_leaves_the_roles() {
        let publisher = ChannelStatusPublisher::new(RouteEnforcementStatus::new());
        let now = Instant::now();
        publisher.observe(
            None,
            [("p", &report(ChannelState::Usable, ChannelState::Down))],
            now,
        );
        publisher.observe(None, [("p", &ChannelReport::default())], now);
        let board = publisher.board();
        assert_eq!(
            board.status_of("p", "").as_deref(),
            Some("adapters-unreadable")
        );
        assert_eq!(
            board.status_of("p", "secondary").as_deref(),
            Some("secondary-down"),
            "an unread link is not a link that came back",
        );
    }
}
