//! The card about a site that does not open: when a surface may show it and
//! how honestly it can word the way out (`siteNoticeDue`, `siteOfferReach`
//! in `pure.js`).

/// The pacing the service applies before starting the tray, so a running
/// tray and a closed one behave alike.
pub use nrr_shared::site_notice::{site_notice_due, SAME_SITE_GAP_MS, SITE_NOTICE_GAP_MS};

/// What the additional link was found to do for an offer about a site that
/// does not open over the main one: `confirmed` (the probe reached it there),
/// `unreachable` (it did not), `unconfirmed` (not asked, or no answer yet).
/// `None` for any other offer.
#[must_use]
pub fn site_offer_reach(signal: &str, secondary_reach: Option<bool>) -> Option<&'static str> {
    if signal != nrr_shared::ipc_payloads::AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED {
        return None;
    }
    Some(match secondary_reach {
        Some(true) => "confirmed",
        Some(false) => "unreachable",
        None => "unconfirmed",
    })
}
