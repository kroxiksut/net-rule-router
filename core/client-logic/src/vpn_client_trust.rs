//! What a client offers when the service lists a program named like a VPN
//! client that leak protection does not trust by place (`vpnClientTrustOffers`
//! / `vpnClientTrustConfirmedApps` in `pure.js`).
//!
//! The service sends the pending paths and, per path, the executables of the
//! same product that sit in a protected install tree. The window and the
//! terminal UI show one question per program and, on "yes", replace the link
//! provider set with everything confirmed so far plus the answer — the
//! service's write is a full replacement, so the union is the client's job.

use crate::js;
use crate::vpn_gateway::program_file_name;

/// One question for the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustOffer {
    pub exe_path: String,
    /// The file name, what the question names.
    pub name: String,
    /// Protected-tree executables offered together with the client. Empty
    /// means the plain "this is my VPN" question.
    pub bundled_exe_paths: Vec<String>,
}

/// One link provider as `route.link-provider.set` takes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkProviderApp {
    pub exe_path: String,
    pub display_name: String,
}

fn same_path(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// The questions to ask for the service's pending list, `(path, bundled)`
/// pairs: blank paths dropped, repeats (case-insensitive) folded, a bundle
/// never repeating itself or its client.
pub fn trust_offers(pending: &[(String, Vec<String>)]) -> Vec<TrustOffer> {
    let mut offers: Vec<TrustOffer> = Vec::new();
    for (raw, bundled) in pending {
        let exe_path = js::trim(raw);
        if exe_path.is_empty() || offers.iter().any(|o| same_path(&o.exe_path, exe_path)) {
            continue;
        }
        let mut bundle: Vec<String> = Vec::new();
        for sibling in bundled {
            let sibling = js::trim(sibling);
            if sibling.is_empty()
                || same_path(sibling, exe_path)
                || bundle.iter().any(|b| same_path(b, sibling))
            {
                continue;
            }
            bundle.push(sibling.to_owned());
        }
        offers.push(TrustOffer {
            exe_path: exe_path.to_owned(),
            name: program_file_name(exe_path).to_owned(),
            bundled_exe_paths: bundle,
        });
    }
    offers
}

/// The link provider set to write once `offer` is answered yes: everything
/// `existing` holds, then the client, then — only when asked for — its
/// bundle; a path already present keeps its first entry and name.
pub fn confirmed_apps(
    existing: &[LinkProviderApp],
    offer: &TrustOffer,
    with_bundle: bool,
) -> Vec<LinkProviderApp> {
    let mut out: Vec<LinkProviderApp> = Vec::new();
    let mut push = |exe_path: &str, display_name: &str| {
        let exe_path = js::trim(exe_path);
        if exe_path.is_empty() || out.iter().any(|a| same_path(&a.exe_path, exe_path)) {
            return;
        }
        let display_name = js::trim(display_name);
        out.push(LinkProviderApp {
            exe_path: exe_path.to_owned(),
            display_name: if display_name.is_empty() {
                program_file_name(exe_path).to_owned()
            } else {
                display_name.to_owned()
            },
        });
    };
    for app in existing {
        push(&app.exe_path, &app.display_name);
    }
    push(&offer.exe_path, &offer.name);
    if with_bundle {
        for sibling in &offer.bundled_exe_paths {
            push(sibling, "");
        }
    }
    out
}
