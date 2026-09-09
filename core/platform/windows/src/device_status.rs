//! Windows mechanism behind [`NetworkDeviceStatusPort`].
//!
//! Two steps, because the adapter GUID the binding stores is not what the
//! configuration manager knows the device by:
//!
//! 1. `HKLM\SYSTEM\CurrentControlSet\Control\Network\{net-class}\{adapter-guid}\Connection`
//!    holds `PnpInstanceID` — the device instance the adapter belongs to. This
//!    key survives a driver that will not start, which is precisely the case the
//!    ordinary enumeration cannot report.
//! 2. `CM_Locate_DevNodeW` + `CM_Get_DevNode_Status` turn that instance into a
//!    state. `CM_PROB_FAILED_START` is the field case: a second VPN client
//!    installed an older copy of the same TAP driver and the first vendor's
//!    adapter stopped starting.
//!
//! Every failure answers `None` rather than `Absent`. The two send the user to
//! opposite places — repair a driver, or pick another connection — so a lookup
//! that could not be performed must not be spelled as an answer.

#![allow(unsafe_code)]

use nrr_platform_api::device_status::{DeviceState, NetworkDeviceStatusPort};
use windows::core::PCWSTR;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_DevNode_Status, CM_Locate_DevNodeW, CM_DEVNODE_STATUS_FLAGS, CM_LOCATE_DEVNODE_PHANTOM,
    CM_PROB, CM_PROB_DISABLED, CM_PROB_HARDWARE_DISABLED, CR_SUCCESS, DN_HAS_PROBLEM,
};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE,
    REG_SAM_FLAGS, REG_VALUE_TYPE,
};

/// The network adapter setup class. Stable since Windows 2000 and the only
/// place an adapter GUID is mapped to its device instance.
const NET_CLASS_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

/// Production implementation. Holds no state: each question is two lookups and
/// runs only when an adapter the user bound is missing from the enumeration.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsNetworkDeviceStatus;

impl NetworkDeviceStatusPort for WindowsNetworkDeviceStatus {
    fn device_state(&self, adapter_guid: &str) -> Option<DeviceState> {
        let guid = normalize_guid(adapter_guid)?;
        let Some(instance_id) = pnp_instance_id(&guid) else {
            // No `Connection` key: the adapter was really removed, registry
            // entry and all. This IS the absent answer.
            return Some(DeviceState::Absent);
        };
        devnode_state(&instance_id)
    }
}

/// The bare `{...}` adapter GUID out of whatever spelling the caller has.
///
/// Bindings store `win-adapter:{guid}`, the registry keys it as `{GUID}`, and
/// nothing guarantees the case. Anything without braces is not an adapter GUID
/// and gets no answer — a persistent id built from an interface index or a MAC
/// names no devnode, and guessing from one would answer a different question.
fn normalize_guid(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let bare = trimmed.rsplit(':').next().unwrap_or(trimmed).trim();
    (bare.starts_with('{') && bare.ends_with('}') && bare.len() >= 34).then(|| bare.to_string())
}

/// `PnpInstanceID` of the device behind `guid`, from the network class key.
fn pnp_instance_id(guid: &str) -> Option<String> {
    let subkey = format!(r"{NET_CLASS_KEY}\{guid}\Connection");
    read_string_value(&subkey, "PnpInstanceID").filter(|v| !v.trim().is_empty())
}

/// Ask the configuration manager what state `instance_id` is in.
fn devnode_state(instance_id: &str) -> Option<DeviceState> {
    let wide: Vec<u16> = instance_id
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut devinst: u32 = 0;
    // SAFETY: `wide` is NUL-terminated UTF-16 outliving the call; `devinst` is a
    // fresh out-param. PHANTOM locates a devnode that is present in the registry
    // but not started, which is the whole reason for this lookup.
    let rc = unsafe {
        CM_Locate_DevNodeW(
            &mut devinst,
            PCWSTR(wide.as_ptr()),
            CM_LOCATE_DEVNODE_PHANTOM,
        )
    };
    if rc != CR_SUCCESS {
        // The registry named an instance the configuration manager does not
        // know: a stale key left behind by an uninstall.
        return Some(DeviceState::Absent);
    }
    let mut status = CM_DEVNODE_STATUS_FLAGS::default();
    let mut problem = CM_PROB::default();
    // SAFETY: both out-params are plain repr-transparent integers owned by
    // this frame, and `devinst` was just produced by a successful locate.
    let rc = unsafe { CM_Get_DevNode_Status(&mut status, &mut problem, devinst, 0) };
    if rc != CR_SUCCESS {
        return None;
    }
    Some(classify(status, problem))
}

/// Map the configuration manager's `(status, problem)` onto the neutral state.
///
/// Kept a free function so the mapping is testable without a devnode: it is the
/// only part of this module with a decision in it.
fn classify(status: CM_DEVNODE_STATUS_FLAGS, problem: CM_PROB) -> DeviceState {
    if status.0 & DN_HAS_PROBLEM.0 == 0 {
        return DeviceState::Started;
    }
    match problem {
        CM_PROB_DISABLED | CM_PROB_HARDWARE_DISABLED => DeviceState::Disabled,
        // Everything else that carries a problem is, from the user's side, the
        // same thing: the device is here and will not work until it is
        // repaired. Spelling out the rest of the ~50 problem codes would add
        // vocabulary without adding an action.
        _ => DeviceState::FailedToStart,
    }
}

// ── Registry helpers ─────────────────────────────────────────────────────────

fn read_string_value(subkey: &str, value_name: &str) -> Option<String> {
    let key_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut hkey = HKEY::default();
    // SAFETY: `key_wide` is NUL-terminated UTF-16 outliving the call; `hkey` is
    // a fresh out-param; the hive is a Win32 pseudo-handle.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key_wide.as_ptr()),
            0,
            REG_SAM_FLAGS(KEY_QUERY_VALUE.0),
            &mut hkey,
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let value = read_open_key_string(hkey, value_name);
    // SAFETY: `hkey` came from a successful `RegOpenKeyExW`.
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    value
}

fn read_open_key_string(hkey: HKEY, value_name: &str) -> Option<String> {
    let name_wide: Vec<u16> = value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut size: u32 = 0;
    let mut value_type = REG_VALUE_TYPE::default();
    // SAFETY: `name_wide` is NUL-terminated and outlives the call; this probe
    // asks only for the byte length.
    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name_wide.as_ptr()),
            None,
            Some(&mut value_type),
            None,
            Some(&mut size),
        )
    };
    if rc != ERROR_SUCCESS || size == 0 {
        return None;
    }
    let mut buf: Vec<u16> = vec![0u16; (size as usize) / 2 + 1];
    let mut read: u32 = (buf.len() * 2) as u32;
    // SAFETY: `buf` is sized from the probe above and `read` carries its byte
    // length, so the call cannot write past it.
    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name_wide.as_ptr()),
            None,
            Some(&mut value_type),
            Some(buf.as_mut_ptr().cast()),
            Some(&mut read),
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    let chars = (read as usize) / 2;
    Some(
        String::from_utf16_lossy(&buf[..chars.min(buf.len())])
            .trim_end_matches('\0')
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    // Only the tests name this code: production maps every problem that is
    // not a deliberate disable onto one state.
    use windows::Win32::Devices::DeviceAndDriverInstallation::CM_PROB_FAILED_START;

    #[test]
    fn a_binding_id_is_reduced_to_its_bare_guid() {
        let guid = "{aaaaaaaa-1234-5678-9abc-def012345678}";
        assert_eq!(
            normalize_guid(&format!("win-adapter:{guid}")).as_deref(),
            Some(guid)
        );
        assert_eq!(normalize_guid(guid).as_deref(), Some(guid));
        assert_eq!(
            normalize_guid(&format!("  {guid}  ")).as_deref(),
            Some(guid)
        );
    }

    /// A persistent id built from an index or a MAC names no device, and
    /// answering for one would answer a different question than was asked.
    #[test]
    fn an_id_that_is_not_an_adapter_guid_gets_no_answer() {
        for id in [
            "win-ifindex:23",
            "win-ifindex-mac:23:00-FF-AA-BB-CC-DD",
            "win-mac:00-11-22-33-44-66",
            "",
            "{short}",
        ] {
            assert_eq!(normalize_guid(id), None, "{id}");
        }
    }

    #[test]
    fn a_devnode_without_a_problem_is_started() {
        assert_eq!(
            classify(CM_DEVNODE_STATUS_FLAGS(0), CM_PROB(0)),
            DeviceState::Started
        );
        // A status carrying other bits but not the problem bit still counts.
        assert_eq!(
            classify(CM_DEVNODE_STATUS_FLAGS(0x0000_0001), CM_PROB(0)),
            DeviceState::Started
        );
    }

    /// The field case: a second driver copy broke the vendor's adapter, and the
    /// device stayed on the machine with `CM_PROB_FAILED_START`.
    #[test]
    fn a_device_that_will_not_start_is_told_apart_from_one_switched_off() {
        assert_eq!(
            classify(DN_HAS_PROBLEM, CM_PROB_FAILED_START),
            DeviceState::FailedToStart
        );
        assert_eq!(
            classify(DN_HAS_PROBLEM, CM_PROB_DISABLED),
            DeviceState::Disabled
        );
        assert_eq!(
            classify(DN_HAS_PROBLEM, CM_PROB_HARDWARE_DISABLED),
            DeviceState::Disabled
        );
    }

    /// Any other problem code is still "here and unusable" — the user's next
    /// step is the same, so the vocabulary stays small.
    #[test]
    fn an_unrecognised_problem_still_means_present_but_unusable() {
        let state = classify(DN_HAS_PROBLEM, CM_PROB(0x0000_002B));
        assert_eq!(state, DeviceState::FailedToStart);
        assert!(state.is_present_but_unusable());
    }

    /// An adapter GUID nothing on this machine answers to. Runs against the
    /// real registry and must not panic or hang.
    #[test]
    fn an_unknown_guid_reports_absent_rather_than_failing() {
        let state = WindowsNetworkDeviceStatus
            .device_state("win-adapter:{00000000-0000-0000-0000-000000000000}");
        assert_eq!(state, Some(DeviceState::Absent));
    }
}
