//! A local network nobody has answered for: read once per connection and told
//! on the feed, as the window raises its banner. The answer itself is given in
//! Settings → Routing, where every network is listed.

use nrr_ipc_client::IpcClient;
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    LocalNetworkDto, LocalNetworksGetRequest, LocalNetworksGetResponse,
};

use crate::backend::{Job, Reply};
use crate::i18n::Texts;
use crate::keys;
use crate::screens::suggestions::call;
use crate::state::{AppState, Effect, NoticeLevel};

#[derive(Debug, Default)]
pub struct LocalNetworkOfferState {
    loading: bool,
    /// The first unanswered network and how many more wait, not yet told.
    unannounced: Option<(LocalNetworkDto, usize)>,
}

/// Ask which networks wait for an answer. Called when the link comes up.
pub fn check(app: &mut AppState) {
    if !app.link.is_connected()
        || app.local_network_offer.loading
        || !app.settings.supports.local_network_exceptions
    {
        return;
    }
    app.local_network_offer.loading = true;
    app.outbox.push(list_job());
}

fn list_job() -> Job {
    Box::new(|client: &dyn IpcClient| {
        let answer: Result<LocalNetworksGetResponse, _> = call(
            client,
            IpcOperationName::LocalNetworksGet,
            &LocalNetworksGetRequest {},
        );
        Reply::new(move |app| {
            app.local_network_offer.loading = false;
            let Ok(answer) = answer else {
                return;
            };
            // A network with a reason stays closed whatever is answered: no
            // question to ask about it.
            let mut waiting = answer
                .networks
                .into_iter()
                .filter(|n| !n.decided_by_user && n.reason.is_empty());
            if let Some(first) = waiting.next() {
                app.local_network_offer.unannounced = Some((first, waiting.count()));
            }
        })
    })
}

/// Tell the network read last, once.
pub fn announce(app: &mut AppState, texts: &Texts, now: std::time::Instant) -> Vec<Effect> {
    let Some((network, more)) = app.local_network_offer.unannounced.take() else {
        return Vec::new();
    };
    // A private segment is already reachable and the question is whether to
    // keep it so; a public IPv6 prefix stays closed until the answer.
    let question = if network.allowed {
        keys::LOCAL_NETWORK_OFFER
    } else {
        keys::LOCAL_NETWORK_OFFER_OPEN
    };
    let mut body = texts.fill(
        question,
        &[
            ("cidr", network.cidr.clone()),
            ("adapter", display_text(&network.adapter).into_owned()),
        ],
    );
    if more > 0 {
        body.push(' ');
        body.push_str(&texts.fill(
            keys::LOCAL_NETWORK_OFFER_MORE,
            &[("count", more.to_string())],
        ));
    }
    body.push(' ');
    body.push_str(&texts.get(keys::ANSWER_IN_ROUTING_HINT));
    app.notify(
        NoticeLevel::Info,
        texts.get(keys::LOCAL_NETWORK_TITLE),
        body,
        now,
    )
}

#[cfg(test)]
mod tests;
