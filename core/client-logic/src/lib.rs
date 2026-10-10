//! `nrr-client-logic` — the client-side decisions of the desktop GUI, for
//! clients that do not run QML.
//!
//! Every function here is a port of a helper in `apps/desktop/qml/lib/pure.js`
//! or `rules.js` and answers the same inputs the same way, odd ones included:
//! the parity tests run both implementations over one set of vectors. Pure
//! functions only — no I/O, no IPC, no clock.
//!
//! - [`placeholders`] — `{name}` filling and plural categories.
//! - [`rules_table`] — table rows, their wire form, the two rules files and
//!   the main-route check.
//! - [`review`] — a rules change's preview, refusal and outcome.
//! - [`route_policy`] — the full-replacement `route.policy.update` request.
//! - [`rules_overlaps`] — overlaps the user made on purpose.
//! - [`rule_sets`] — the user's rule-set folder and the set moving into it.
//! - [`restore`] — the user's recorded settings brought back to a service
//!   that lost them.
//! - [`adapters`] — which adapter may take which route.
//! - [`auto_rules`] — suggested addresses grouped, filtered and sorted.
//! - [`conn_trace`] — the connection trace's view filters.
//! - [`diagnostics`] — security alert lists and whether an acknowledgement took.
//! - [`notice_mutes`] — hiding whole notice kinds for a while.
//! - [`stability`] — the full-replacement `settings.service-stability.set` row.
//! - [`units`] — byte counts as people read them.
//! - [`verify_verdicts`] — the notice for `?` rules that work only on the
//!   other route.

pub mod adapters;
pub mod auto_rules;
pub mod conn_trace;
pub mod diagnostics;
mod js;
pub mod notice_mutes;
pub mod placeholders;
pub mod restore;
pub mod review;
pub mod route_policy;
pub mod rule_sets;
pub mod rules_overlaps;
pub mod rules_table;
pub mod stability;
pub mod units;
pub mod verify_verdicts;

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
