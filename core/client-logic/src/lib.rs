//! `nrr-client-logic` — the client-side decisions of the desktop GUI, for
//! clients that do not run QML.
//!
//! Every function here is a port of a helper in `apps/desktop/qml/lib/pure.js`
//! or `rules.js` and answers the same inputs the same way, odd ones included:
//! the parity tests run both implementations over one set of vectors. Pure
//! functions only — no I/O, no IPC, no clock.
//!
//! - [`placeholders`] — `{name}` filling, plural categories and short lists.
//! - [`rules_table`] — table rows, their wire form, the two rules files and
//!   the main-route check.
//! - [`review`] — a rules change's preview, refusal and outcome.
//! - [`full_reset`] — the order of a full reset and what each step decides.
//! - [`rollback`] — what a safe-rollback dry run answered.
//! - [`route_policy`] — the full-replacement `route.policy.update` request.
//! - [`rules_overlaps`] — overlaps the user made on purpose.
//! - [`rule_value_class`] — what kind of rule a value is, and the section a
//!   value written under the wrong one belongs in.
//! - [`rebase`] — the user's unsaved edits laid over rules that changed
//!   elsewhere meanwhile.
//! - [`recent_changes`] — the «Recent» filter's periods and times.
//! - [`rule_sets`] — the user's rule-set folder and the set moving into it.
//! - [`restore`] — the user's recorded settings brought back to a service
//!   that lost them.
//! - [`adapters`] — which adapter may take which route.
//! - [`app_routes`] — application groups and virtual machines put on a route.
//! - [`auto_rules`] — suggested addresses grouped, filtered and sorted.
//! - [`bulk_rules`] — many rules pasted into the Add form at once, line by
//!   line.
//! - [`block_notices`] — the summary of blocks kept while no surface was
//!   open.
//! - [`conn_trace`] — the connection trace's view filters and its grouping
//!   by program or folder.
//! - [`diagnostics`] — security alert lists, whether an acknowledgement took,
//!   and when to say the user's saved rules cannot be read.
//! - [`forwarded`] — whether WSL runs, and asking what it gets when the
//!   tunnel is down.
//! - [`notice_mutes`] — hiding whole notice kinds for a while.
//! - [`service_loss`] — telling the user the service stopped on its own, and the
//!   recoveries offered.
//! - [`routing_settings`] — which routing settings a window offers.
//! - [`rule_form`] — the rule form's reading of a typed value.
//! - [`stability`] — the full-replacement `settings.service-stability.set` row.
//! - [`system_dns`] — whether the system DNS was left redirected, and when to
//!   say so.
//! - [`units`] — byte counts as people read them.
//! - [`verify_verdicts`] — the notice for `?` rules that work only on the
//!   other route.
//! - [`vpn_gateway`] — the rule that lets a VPN reach its gateway over the
//!   chosen route.
//! - [`vpn_gateway_trust`] — the question asked when leak protection stopped
//!   another VPN, and the gateway list an answer writes.

pub mod adapters;
pub mod app_routes;
pub mod auto_rules;
pub mod block_notices;
pub mod bulk_rules;
pub mod conn_trace;
pub mod contract;
pub mod diagnostics;
pub mod forwarded;
pub mod full_reset;
mod js;
pub mod notice_mutes;
pub mod placeholders;
pub mod rebase;
pub mod recent_changes;
pub mod restore;
pub mod review;
pub mod rollback;
pub mod route_policy;
pub mod routing_settings;
pub mod rule_form;
pub mod rule_sets;
pub mod rule_value_class;
pub mod rules_overlaps;
pub mod rules_table;
pub mod service_loss;
pub mod stability;
pub mod system_dns;
pub mod units;
pub mod verify_verdicts;
pub mod vpn_client_trust;
pub mod vpn_gateway;
pub mod vpn_gateway_trust;

/// One of the two adapter routes. Also names the rules file that holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Route {
    /// The main link.
    Primary,
    /// The additional link.
    Secondary,
}

impl Route {
    /// Both routes, primary first.
    pub const ALL: [Self; 2] = [Self::Primary, Self::Secondary];

    /// The wire slug: `"primary"` or `"secondary"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
        }
    }

    /// Parses a wire slug; `None` for anything else.
    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "primary" => Some(Self::Primary),
            "secondary" => Some(Self::Secondary),
            _ => None,
        }
    }
}
