#![allow(clippy::expect_used)]

//! The owner's machine: hidemy.name installed, not started. The window said
//! "VPN found on this computer: hidemy.name VPN 3.0", but its adapters were
//! hidden behind "Show unavailable adapters" and the user had to guess among
//! them. The found VPN's lone adapter is listed and picked as it is, named as
//! the VPN that is not connected now, and set as the additional connection in
//! one press; connecting comes later. Among several copies of its driver, all
//! down, none is guessed: the VPN brings up whichever it likes.

#[path = "support/first_run.rs"]
mod first_run;

/// Wi-Fi set as main, two copies of the TAP driver hidemy.name uses, down.
const MACHINE: &str = "rows = [wire('wifi', 'Wi-Fi', { 'kind': 'wifi' }),\n\
     tunnel('tap1', 'Ethernet 2', { 'availability': 'unavailable', 'gateway': '-',\n\
         'interface-description': 'TAP-Windows Adapter V9' }),\n\
     tunnel('tap2', 'Ethernet 3', { 'availability': 'unavailable', 'gateway': '-',\n\
         'interface-description': 'TAP-Windows Adapter V9 #2' })];\n\
     rows[0].selectedRole = 'primary';\n\
     pickedPrimaryKey = 'wifi';";

/// Wi-Fi set as main and one TAP adapter, down.
const LONE: &str = "rows = [wire('wifi', 'Wi-Fi', { 'kind': 'wifi' }),\n\
     tunnel('tap1', 'Ethernet 2', { 'availability': 'unavailable', 'gateway': '-',\n\
         'interface-description': 'TAP-Windows Adapter V9' })];\n\
     rows[0].selectedRole = 'primary';\n\
     pickedPrimaryKey = 'wifi';";

const HIDEMY: &str = "_vpnPrograms = vpnDiscoveredRows([{ 'display-name': 'hidemy.name VPN 3.0',\n\
     'exe-path': 'C:\\\\Program Files (x86)\\\\hidemy.name VPN 3.0\\\\hidemy.name VPN.exe' }]);";

#[test]
fn a_found_vpn_that_is_not_started_is_offered_without_the_box() {
    let output = first_run::run(&format!(
        "{LONE}\n{HIDEMY}\n\
         step = 1;\n\
         console.log('listed ' + _shownInPicker(rows[1], 'secondary'));\n\
         _suggestPicks();\n\
         console.log('picked ' + pickedSecondaryKey + ' idle ' + _pickIsIdleVpn());\n\
         console.log('reads ' + _adapterLabel(rows[1], 'secondary'));\n\
         _assignFromPage('secondary', 1);"
    ));
    assert!(output.contains("picked tap1 idle true"), "{output}");
    assert!(output.contains("listed true"), "{output}");
    assert!(
        output.contains("(VPN hidemy.name VPN 3.0, not connected now)"),
        "{output}"
    );
    assert!(output.contains("assign secondary tap1"), "{output}");
}

/// The field machine: two copies of one driver, both down. Whichever copy
/// was bound, the VPN came up on the other and the additional connection
/// stayed down. Nothing is listed or picked; the step asks to turn the VPN
/// on, and the copy it brings up is then offered as just connected.
#[test]
fn copies_of_one_driver_all_down_are_not_guessed_between() {
    let output = first_run::run(&format!(
        "{MACHINE}\n{HIDEMY}\n\
         step = 1;\n\
         _suggestPicks();\n\
         console.log('listed ' + _shownInPicker(rows[1], 'secondary') + ' ' + _shownInPicker(rows[2], 'secondary'));\n\
         console.log('picked [' + pickedSecondaryKey + ']');\n\
         console.log('hint ' + _startVpnFirstHint());"
    ));
    assert!(output.contains("listed false false"), "{output}");
    assert!(output.contains("picked []"), "{output}");
    assert!(
        output.contains("hint hidemy.name VPN 3.0 may use any of several connections"),
        "{output}"
    );
}

/// The field machine: a pool of dead copies of the stock driver and the
/// VPN's own adapter, of another driver, also down. The VPN came up once on a
/// stock copy and once on its own adapter, so neither is the answer while it
/// is off: the vendor adapter is listed as the VPN's but not picked, the step
/// asks to turn the VPN on, the dead copies cannot be set from the list, and
/// finishing without the VPN leaves the additional connection unchosen.
#[test]
fn a_vendor_adapter_beside_a_driver_pool_is_not_picked_while_the_vpn_is_off() {
    let output = first_run::run(&format!(
        "{MACHINE}\n{HIDEMY}\n\
         rows.push(tunnel('vendor', 'hidemy.name VPN OpenVPN Adapter', {{ 'availability': 'unavailable',\n\
             'gateway': '-', 'interface-description': 'hidemy.name VPN 3.0 OpenVPN Adapter' }}));\n\
         step = 1;\n\
         _suggestPicks();\n\
         console.log('listed ' + _shownInPicker(rows[1], 'secondary') + ' ' + _shownInPicker(rows[3], 'secondary'));\n\
         console.log('picked [' + pickedSecondaryKey + ']');\n\
         console.log('hint ' + _startVpnFirstHint());\n\
         console.log('pooled ' + _pooledDown(1) + ' ' + _pooledDown(3));\n\
         _commitPendingPicks();\n\
         console.log('review ' + _reviewAdapterName('secondary'));"
    ));
    assert!(output.contains("listed false true"), "{output}");
    assert!(output.contains("picked []"), "{output}");
    assert!(
        output.contains("hint hidemy.name VPN 3.0 may use any of several connections"),
        "{output}"
    );
    assert!(output.contains("pooled true false"), "{output}");
    assert!(!output.contains("assign secondary"), "{output}");
    assert!(output.contains("review not chosen"), "{output}");
}

/// No VPN program found: nothing changes, the down adapters stay behind the
/// box and nothing is picked.
#[test]
fn without_a_found_vpn_the_down_adapters_stay_behind_the_box() {
    let output = first_run::run(&format!(
        "{MACHINE}\n\
         step = 1;\n\
         _suggestPicks();\n\
         console.log('picked [' + pickedSecondaryKey + '] listed ' + _shownInPicker(rows[1], 'secondary'));"
    ));
    assert!(output.contains("picked [] listed false"), "{output}");
}

/// A VPN that is connected stays the suggestion; the down one is listed too.
#[test]
fn a_connected_vpn_is_still_picked_first() {
    let output = first_run::run(&format!(
        "{MACHINE}\n{HIDEMY}\n\
         rows.push(tunnel('wg', 'WireGuard', {{}}));\n\
         step = 1;\n\
         _suggestPicks();\n\
         console.log('picked ' + pickedSecondaryKey);"
    ));
    assert!(output.contains("picked wg"), "{output}");
}
