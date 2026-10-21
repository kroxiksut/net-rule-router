//! What a client asks when leak protection stopped another VPN reaching its
//! gateway, and the gateway list an answer writes (`vpnGatewayOffers` /
//! `vpnGatewaysConfirmed` / `vpnGatewaysRemoved` in `pure.js`).
//!
//! `route.vpn-gateways.set` replaces the whole list, so adding the answer to
//! what is already allowed, and taking one out, is the client's job.

use crate::js;
use crate::vpn_gateway::program_file_name;

/// One gateway as the wire carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gateway {
    pub address: String,
    /// Executable path or name; empty when the system itself connected.
    pub program: String,
}

/// One question for the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayOffer {
    pub address: String,
    pub program: String,
    /// The program's file name, what the question names; empty without one.
    pub name: String,
}

fn same_address(a: &str, b: &str) -> bool {
    js::trim(a).eq_ignore_ascii_case(js::trim(b))
}

/// The questions to ask for the service's pending list: blank addresses
/// dropped, repeats folded (IPv6 text compared without regard to case).
pub fn gateway_offers(pending: &[Gateway]) -> Vec<GatewayOffer> {
    let mut offers: Vec<GatewayOffer> = Vec::new();
    for entry in pending {
        let address = js::trim(&entry.address);
        if address.is_empty() || offers.iter().any(|o| same_address(&o.address, address)) {
            continue;
        }
        let program = js::trim(&entry.program);
        offers.push(GatewayOffer {
            address: address.to_owned(),
            program: program.to_owned(),
            name: program_file_name(program).to_owned(),
        });
    }
    offers
}

/// The list to write once `offer` is answered yes: what `existing` holds,
/// then the offer; an address already there keeps its first entry.
pub fn confirmed_gateways(existing: &[Gateway], offer: &GatewayOffer) -> Vec<Gateway> {
    let mut out: Vec<Gateway> = Vec::new();
    let mut push = |address: &str, program: &str| {
        let address = js::trim(address);
        if address.is_empty() || out.iter().any(|g| same_address(&g.address, address)) {
            return;
        }
        out.push(Gateway {
            address: address.to_owned(),
            program: js::trim(program).to_owned(),
        });
    };
    for gateway in existing {
        push(&gateway.address, &gateway.program);
    }
    push(&offer.address, &offer.program);
    out
}

/// The list to write once the user takes `address` back: every other entry,
/// unchanged and in order.
pub fn removed_gateways(existing: &[Gateway], address: &str) -> Vec<Gateway> {
    existing
        .iter()
        .filter(|g| !same_address(&g.address, address))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway(address: &str, program: &str) -> Gateway {
        Gateway {
            address: address.to_owned(),
            program: program.to_owned(),
        }
    }

    #[test]
    fn an_answer_adds_once_and_a_revoke_takes_only_that_address() {
        let offers = gateway_offers(&[
            gateway(" 2001:DB8::7 ", r"C:\Corp\agent.exe"),
            gateway("2001:db8::7", ""),
            gateway("", "x"),
        ]);
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].name, "agent.exe");
        let existing = [gateway("203.0.113.20", "")];
        let after = confirmed_gateways(&existing, &offers[0]);
        assert_eq!(
            after,
            vec![
                gateway("203.0.113.20", ""),
                gateway("2001:DB8::7", r"C:\Corp\agent.exe")
            ]
        );
        assert_eq!(confirmed_gateways(&after, &offers[0]), after);
        assert_eq!(
            removed_gateways(&after, "2001:db8::7"),
            vec![gateway("203.0.113.20", "")]
        );
    }
}
