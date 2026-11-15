#![cfg(target_os = "windows")]
#![allow(unsafe_code, clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::net::{Shutdown, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nrr_platform_api::adapters::AdapterInfo;
use nrr_platform_api::error::win32_codes::FWP_E_FILTER_NOT_FOUND;
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::route_table::RouteTablePort;
use nrr_platform_api::types::{
    RouteEntry, WfpAction, WfpEngineToken, WfpFilterAction, WfpFilterId, WfpFilterRecord,
    WfpFilterSpec, WfpLayerKey,
};
use nrr_platform_api::wfp::{FilterFailureMode, WfpSession};
use nrr_platform_api::windows_api::WfpEnginePort;
use nrr_platform_windows::win32_ffi::wfp_filter::filter_id_to_guid;
use nrr_platform_windows::win32_ffi::wfp_sublayer::NRR_SUBLAYER_GUID;
use nrr_platform_windows::windows_api::ProductionWindowsApi;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineOpen0, FwpmFilterGetByKey0, FwpmFreeMemory0, FwpmSubLayerGetByKey0, FWPM_FILTER0,
    FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

struct DynamicApi {
    refused: WfpFilterId,
    allowed: [WfpFilterId; 2],
    peer: SocketAddrV4,
    app: String,
    closed: AtomicBool,
}

impl RouteTablePort for DynamicApi {
    fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError> {
        ProductionWindowsApi.get_ip_forward_table()
    }
    fn create_ip_forward_entry(&self, _: &RouteEntry) -> Result<(), PlatformError> {
        panic!("this test must not change routes")
    }
    fn delete_ip_forward_entry(&self, _: &RouteEntry) -> Result<(), PlatformError> {
        panic!("this test must not change routes")
    }
    fn get_adapter_infos(&self) -> Result<Vec<AdapterInfo>, PlatformError> {
        ProductionWindowsApi.get_adapter_infos()
    }
    fn interface_luid_for_index(&self, index: u32) -> Result<u64, PlatformError> {
        ProductionWindowsApi.interface_luid_for_index(index)
    }
}

impl WfpEnginePort for DynamicApi {
    fn wfp_engine_open(&self) -> Result<WfpEngineToken, PlatformError> {
        let options = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let mut handle = HANDLE::default();
        // SAFETY: options and the writable handle outlive this synchronous call.
        let code = unsafe {
            FwpmEngineOpen0(
                PCWSTR::null(),
                RPC_C_AUTHN_WINNT,
                None,
                Some(&options),
                &mut handle,
            )
        };
        if code != 0 {
            return Err(win32("FwpmEngineOpen0", code));
        }
        let token = WfpEngineToken {
            raw: handle.0 as usize as u64,
        };
        let mut sublayer: *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
        // SAFETY: handle is open, the GUID is static, and the output pointer is writable.
        let code = unsafe { FwpmSubLayerGetByKey0(handle, &NRR_SUBLAYER_GUID, &mut sublayer) };
        if code != 0 {
            ProductionWindowsApi.wfp_engine_close(token)?;
            return Err(win32("FwpmSubLayerGetByKey0", code));
        }
        let mut allocation = sublayer.cast();
        // SAFETY: this allocation came from FwpmSubLayerGetByKey0 and is freed once.
        unsafe { FwpmFreeMemory0(&mut allocation) };
        Ok(token)
    }
    fn wfp_engine_close(&self, token: WfpEngineToken) -> Result<(), PlatformError> {
        ProductionWindowsApi.wfp_engine_close(token)?;
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn wfp_transaction_begin(&self, token: &WfpEngineToken) -> Result<(), PlatformError> {
        ProductionWindowsApi.wfp_transaction_begin(token)
    }
    fn wfp_transaction_commit(&self, token: &WfpEngineToken) -> Result<(), PlatformError> {
        ProductionWindowsApi.wfp_transaction_commit(token)
    }
    fn wfp_transaction_abort(&self, token: &WfpEngineToken) {
        ProductionWindowsApi.wfp_transaction_abort(token);
    }
    fn wfp_filter_add(
        &self,
        token: &WfpEngineToken,
        spec: &WfpFilterSpec,
    ) -> Result<WfpFilterId, PlatformError> {
        assert!(self.allowed.contains(&spec.id));
        assert_eq!(spec.layer, WfpLayerKey::AleAuthConnectV4);
        assert_eq!(spec.remote_ip, Some(*self.peer.ip()));
        assert_eq!(spec.remote_port, Some(self.peer.port()));
        assert_eq!(spec.ip_protocol, Some(6));
        assert_eq!(spec.app_pattern.as_deref(), Some(self.app.as_str()));
        assert!(spec.remote_ip_set.is_empty() && spec.remote_ip_set_v6.is_empty());
        assert!(spec.remote_subnet.is_none() && spec.remote_subnet_v6.is_none());
        assert!(spec.remote_subnet_set.is_empty());
        assert_eq!(
            spec.action,
            if spec.id == self.refused {
                WfpAction::Block
            } else {
                WfpAction::Permit
            }
        );
        assert_eq!(
            spec.weight,
            if spec.id == self.refused {
                u64::MAX - 2
            } else {
                u64::MAX - 1
            }
        );
        ProductionWindowsApi.wfp_filter_add(token, spec)
    }
    fn wfp_filter_delete(&self, _: &WfpEngineToken, id: WfpFilterId) -> Result<(), PlatformError> {
        assert_eq!(id, self.refused, "this test may retire only its old filter");
        Err(PlatformError::AccessDenied {
            operation: "injected refusal of the test filter retirement",
        })
    }
    fn wfp_enumerate_our_filters(
        &self,
        token: &WfpEngineToken,
    ) -> Result<Vec<WfpFilterRecord>, PlatformError> {
        ProductionWindowsApi.wfp_enumerate_our_filters(token)
    }
}

fn win32(operation: &'static str, code: u32) -> PlatformError {
    PlatformError::Win32 {
        operation,
        code,
        message: format!("Win32 error 0x{code:08X}"),
    }
}

fn probe(peer: SocketAddrV4, marker: &str, phase: &str) -> std::io::Result<()> {
    let result = TcpStream::connect_timeout(&SocketAddr::V4(peer), Duration::from_secs(2)).map(
        |mut stream| {
            let written = stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .and_then(|()| writeln!(stream, "NRR-WFP-REPLACE {marker} {phase}"));
            eprintln!("NRR_WFP_MARKER phase={phase} write={written:?}");
            let _ = stream.shutdown(Shutdown::Both);
        },
    );
    eprintln!("NRR_WFP_PROBE phase={phase} peer={peer} marker={marker} result={result:?}");
    result
}

fn scoped_filter(id: WfpFilterId, peer: SocketAddrV4, app: String) -> WfpFilterSpec {
    WfpFilterSpec {
        id,
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: Some(*peer.ip()),
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: Some(peer.port()),
        weight: u64::MAX - 2,
        user_sid: None,
        app_pattern: Some(app),
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: Some(6),
        remote_subnet_set: Vec::new(),
    }
}

fn verify_keys_absent(ids: [WfpFilterId; 2], phase: &str) {
    let token = ProductionWindowsApi.wfp_engine_open().unwrap();
    let handle = HANDLE(token.raw as usize as *mut std::ffi::c_void);
    let mut codes = Vec::new();
    for id in ids {
        let key = filter_id_to_guid(id);
        let mut filter: *mut FWPM_FILTER0 = std::ptr::null_mut();
        // SAFETY: the open handle, stack GUID, and output pointer are valid for this call.
        let code = unsafe { FwpmFilterGetByKey0(handle, &key, &mut filter) };
        if code == 0 {
            let mut allocation = filter.cast();
            // SAFETY: this allocation came from FwpmFilterGetByKey0 and is freed once.
            unsafe { FwpmFreeMemory0(&mut allocation) };
        }
        codes.push((id, code));
    }
    ProductionWindowsApi.wfp_engine_close(token).unwrap();
    eprintln!("NRR_WFP_KEY_CHECK phase={phase} exact_key_results={codes:?}");
    assert!(codes
        .iter()
        .all(|(_, code)| *code == FWP_E_FILTER_NOT_FOUND));
}

#[test]
#[ignore = "requires elevated Windows test laptop, existing NRR sublayer, dedicated private TCP listener and packet capture"]
fn a_failed_replacement_keeps_the_previous_block_on_real_wfp() {
    let peer_text =
        std::env::var("NRR_WFP_TEST_PEER").expect("set the dedicated test listener IPv4:port");
    assert!(peer_text.len() <= 64);
    let peer: SocketAddrV4 = peer_text.parse().expect("private IPv4 test endpoint");
    assert!(peer.ip().is_private() && peer.port() >= 1024);
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).expect("OS randomness");
    let old = WfpFilterId {
        raw: u64::from_le_bytes(random[..8].try_into().unwrap()),
    };
    let new = WfpFilterId {
        raw: u64::from_le_bytes(random[8..].try_into().unwrap()),
    };
    assert_ne!(old, new);
    let marker = format!("{:016x}-{:016x}", old.raw, new.raw);
    let app = std::env::current_exe()
        .unwrap()
        .into_os_string()
        .into_string()
        .expect("UTF-8 test executable path");
    eprintln!("NRR_WFP_SCOPE app={app:?} peer={peer} old={old:?} new={new:?}");
    probe(peer, &marker, "before-filters")
        .expect("the dedicated listener must be reachable before mutation");
    let api = Arc::new(DynamicApi {
        refused: old,
        allowed: [old, new],
        peer,
        app: app.clone(),
        closed: AtomicBool::new(false),
    });
    let session =
        WfpSession::open(api.clone()).expect("dynamic engine over an existing NRR sublayer");
    verify_keys_absent([old, new], "before-add");
    let block = scoped_filter(old, peer, app);
    session
        .execute_wfp_plan(&[WfpFilterAction::AddFilter(block.clone())])
        .unwrap();
    let blocked = probe(peer, &marker, "old-block");
    let permit = WfpFilterSpec {
        id: new,
        action: WfpAction::Permit,
        weight: u64::MAX - 1,
        ..block
    };
    let replacement = session.execute_replacement(&[permit], &[old], FilterFailureMode::Strict);
    let live: Vec<_> = session
        .enumerate_our_filters()
        .unwrap()
        .into_iter()
        .filter(|f| f.id == old || f.id == new)
        .collect();
    eprintln!("NRR_WFP_REPLACEMENT result={replacement:?} live={live:?}");
    let after = probe(peer, &marker, "after-refusal");
    drop(session);
    assert!(
        api.closed.load(Ordering::SeqCst),
        "dynamic session close must be acknowledged"
    );
    verify_keys_absent([old, new], "after-close");
    let restored = probe(peer, &marker, "after-close");
    assert!(
        blocked.is_err(),
        "the old real WFP block must prevent this process connecting"
    );
    assert!(
        after.is_err(),
        "a failed replacement published a permit above the old block"
    );
    assert!(
        replacement.is_err(),
        "a refused retirement must fail the replacement"
    );
    assert!(
        restored.is_ok(),
        "baseline connectivity did not recover after dynamic close"
    );
}
