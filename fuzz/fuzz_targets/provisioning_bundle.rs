#![no_main]
//! Files an administrator hands the installer, read again by the service at
//! its first start: the settings-export and options readers, and the whole
//! bundle check with the input split into its four files.

use libfuzzer_sys::fuzz_target;
use nrr_domain::rules_file::HostPlatform;
use nrr_service_runtime::provisioning::bundle::{read_options, read_settings_export};
use nrr_service_runtime::provisioning::{
    check_bundle, BundleBytes, OPTIONS_MAX_BYTES, RULES_MAX_BYTES, SETTINGS_MAX_BYTES,
};

/// The four files, separated by a NUL each, never more than the folder reader
/// would accept.
const MAX_INPUT: usize = RULES_MAX_BYTES * 2 + SETTINGS_MAX_BYTES + OPTIONS_MAX_BYTES + 3;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let _ = read_settings_export(data);
    let _ = read_options(data);
    let mut parts = data
        .splitn(4, |b| *b == 0)
        .map(|part| (!part.is_empty()).then(|| part.to_vec()));
    let bundle = BundleBytes {
        primary: parts.next().flatten(),
        secondary: parts.next().flatten(),
        settings: parts.next().flatten(),
        options: parts.next().flatten(),
    };
    let _ = check_bundle(&bundle, HostPlatform::compiled());
});
