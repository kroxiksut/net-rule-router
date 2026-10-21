//! Whether a client and the service speak one wire contract, and which side is
//! behind. Writes across a skew are refused by the IPC client; this only names
//! the skew for the banner.

use nrr_shared::ipc::ContractSkew;

/// The skew slug for the banner, `""` when there is none to show.
///
/// `service_protocol` is 0 until the handshake completed. `host_contract` is the
/// revision of the process carrying this client's code (the launcher for the
/// window); `own` is the revision this client's code was written for. A window
/// whose code and launcher disagree is the client that must restart.
pub fn skew(
    service_protocol: u32,
    host_contract: u32,
    service_contract: u32,
    own: u32,
) -> &'static str {
    if service_protocol == 0 {
        return "";
    }
    if host_contract != own {
        return ContractSkew::ClientOlder.as_slug();
    }
    ContractSkew::between(service_contract, own).map_or("", ContractSkew::as_slug)
}
