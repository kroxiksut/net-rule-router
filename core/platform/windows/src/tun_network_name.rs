//! Keeps the Windows network our TUN adapter joins named after the product.
//!
//! Windows files every adapter identity it has not seen as a new network and
//! numbers the name ("NetRuleRouter 107"). A fixed adapter GUID stops new
//! entries; this renames the one we land on and logs when Windows numbered it
//! again, which is the evidence that entries are still being created.
#![allow(unsafe_code)]

use std::time::Duration;

use windows::core::{BSTR, GUID};
use windows::Win32::Foundation::ERROR_NOT_SUPPORTED;
use windows::Win32::Networking::NetworkListManager::{
    INetwork, INetworkConnection, INetworkListManager, NetworkListManager,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL, COINIT_MULTITHREADED,
};

/// Windows identifies a fresh adapter's network within seconds; past a minute
/// it is not going to, and the name is not worth a thread.
const IDENTIFY_POLL: Duration = Duration::from_secs(1);
const IDENTIFY_ATTEMPTS: u32 = 60;

/// Name the network behind `adapter_guid` `name` once Windows has identified
/// it. Detached and best effort: a cosmetic name must never hold up the TUN.
pub(crate) fn name_adapter_network(adapter_guid: u128, name: &str) {
    let name = name.to_string();
    let spawned = std::thread::Builder::new()
        .name("nrr-tun-network-name".into())
        .spawn(move || {
            // SAFETY: COM is initialised for this thread only and released
            // below, after `rename_when_identified` has dropped every interface.
            let init = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            if init.is_err() {
                tracing::debug!(
                    target: "nrr::fake-ip",
                    "COM unavailable — the tunnel network keeps the name Windows chose: {init:?}",
                );
                return;
            }
            rename_when_identified(GUID::from_u128(adapter_guid), &name);
            // SAFETY: pairs the successful `CoInitializeEx` above.
            unsafe { CoUninitialize() };
        });
    if let Err(e) = spawned {
        tracing::debug!(
            target: "nrr::fake-ip",
            "could not start the tunnel network naming thread: {e}",
        );
    }
}

fn rename_when_identified(adapter: GUID, name: &str) {
    // SAFETY: in-process activation of a documented system COM class.
    let manager: INetworkListManager = match unsafe {
        CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL)
    } {
        Ok(manager) => manager,
        Err(e) => {
            tracing::debug!(
                target: "nrr::fake-ip",
                "network list unavailable — the tunnel network keeps the name Windows chose: {e}",
            );
            return;
        }
    };
    for _ in 0..IDENTIFY_ATTEMPTS {
        if let Some(network) = network_of_adapter(&manager, adapter) {
            if rename(&network, name) == Rename::Settled {
                return;
            }
        }
        std::thread::sleep(IDENTIFY_POLL);
    }
    tracing::debug!(
        target: "nrr::fake-ip",
        "Windows did not identify the tunnel network in time — its name is left as Windows chose",
    );
}

fn network_of_adapter(manager: &INetworkListManager, adapter: GUID) -> Option<INetwork> {
    // SAFETY: documented enumeration; each slot comes back owned or empty.
    unsafe {
        let connections = manager.GetNetworkConnections().ok()?;
        loop {
            let mut slot: [Option<INetworkConnection>; 1] = [None];
            let mut fetched = 0u32;
            connections.Next(&mut slot, Some(&mut fetched)).ok()?;
            if fetched == 0 {
                return None;
            }
            let connection = slot[0].take()?;
            if connection.GetAdapterId().ok() == Some(adapter) {
                return connection.GetNetwork().ok();
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Rename {
    Settled,
    StillIdentifying,
}

fn rename(network: &INetwork, name: &str) -> Rename {
    // SAFETY: plain property read/write on a live interface.
    let current = unsafe { network.GetName() }
        .map(|n| n.to_string())
        .unwrap_or_default();
    if current == name {
        return Rename::Settled;
    }
    match unsafe { network.SetName(&BSTR::from(name)) } {
        Ok(()) => tracing::info!(
            target: "nrr::fake-ip",
            was = %current,
            now = %name,
            "Windows filed the tunnel as a new network and numbered its name — renamed it back",
        ),
        // At boot the connection shows up on a placeholder network that
        // refuses a name until Windows has identified it.
        Err(e) if e.code() == ERROR_NOT_SUPPORTED.to_hresult() => return Rename::StillIdentifying,
        Err(e) => tracing::info!(
            target: "nrr::fake-ip",
            was = %current,
            "could not rename the tunnel network: {e}",
        ),
    }
    Rename::Settled
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every live connection must report the adapter it rides on, or the
    /// rename can never find ours. Needs a machine with at least one network.
    #[test]
    #[ignore = "reads the live network list of the host"]
    fn live_connections_report_their_adapter() {
        // SAFETY: test-thread COM init, released at the end.
        let init = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        assert!(init.is_ok());
        {
            // SAFETY: in-process activation of a documented system class.
            let manager: INetworkListManager =
                unsafe { CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL) }
                    .unwrap_or_else(|e| panic!("network list: {e}"));
            let mut seen = 0;
            // SAFETY: documented enumeration on a live interface.
            unsafe {
                let connections = manager
                    .GetNetworkConnections()
                    .unwrap_or_else(|e| panic!("connections: {e}"));
                loop {
                    let mut slot: [Option<INetworkConnection>; 1] = [None];
                    let mut fetched = 0u32;
                    if connections.Next(&mut slot, Some(&mut fetched)).is_err() || fetched == 0 {
                        break;
                    }
                    let Some(connection) = slot[0].take() else {
                        break;
                    };
                    let adapter = connection.GetAdapterId().unwrap_or_default();
                    let name = connection
                        .GetNetwork()
                        .and_then(|n| n.GetName())
                        .map(|n| n.to_string())
                        .unwrap_or_default();
                    eprintln!("{adapter:?} -> {name}");
                    assert_ne!(adapter, GUID::zeroed());
                    seen += 1;
                }
            }
            assert!(seen > 0);
        }
        // SAFETY: pairs the init above.
        unsafe { CoUninitialize() };
    }
}
