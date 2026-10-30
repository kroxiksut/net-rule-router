//! What a client offers when the service lists a program named like a VPN
//! client that leak protection does not trust by place (`vpnClientTrustOffers`
//! / `vpnClientTrustConfirmedApps` in `pure.js`).
//!
//! The service sends the pending paths and, per path, the executables of the
//! same product that sit in a protected install tree. The window and the
//! terminal UI show one question per program and, on "yes", replace the link
//! provider set with everything confirmed so far plus the answer — the
//! service's write is a full replacement, so the union is the client's job.
//!
//! The "Your VPN client" picker lives here too (`vpnPicker*`): it lists what
//! discovery found plus what is stored, opens with the stored programs
//! ticked, and its confirm never drops a stored program it did not show.

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

/// The link provider set to write once the user removes `exe_path`: every
/// other entry, unchanged and in order. A path that is not there changes
/// nothing (`vpnClientTrustRemovedApps`).
pub fn removed_apps(existing: &[LinkProviderApp], exe_path: &str) -> Vec<LinkProviderApp> {
    let exe_path = js::trim(exe_path);
    existing
        .iter()
        .filter(|a| !same_path(js::trim(&a.exe_path), exe_path))
        .cloned()
        .collect()
}

/// The `source` of a picker row that discovery did not find: a program the
/// user confirmed earlier, shown so it can be kept or taken back.
pub const PICKER_CONFIRMED_SOURCE: &str = "confirmed";
/// A tunnel the kernel runs: no program to tick, its link is bound instead.
pub const PICKER_KERNEL_TUNNEL_SOURCE: &str = "kernel-tunnel";

/// One row of the "Your VPN client" picker (`vpnPickerRows` in `pure.js`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PickerRow {
    pub display_name: String,
    /// Blank when discovery found the program but not its file.
    pub exe_path: String,
    pub running: bool,
    pub source: String,
    pub interface_name: String,
}

/// What each confirmed program is called: its name, else its file name
/// (`vpnProviderNames`).
pub fn provider_names(apps: &[LinkProviderApp]) -> Vec<String> {
    apps.iter()
        .map(|app| match js::trim(&app.display_name) {
            "" => program_file_name(&app.exe_path).to_owned(),
            name => name.to_owned(),
        })
        .collect()
}

/// Whether the row can be ticked: a program whose file is known.
pub fn picker_tickable(row: &PickerRow) -> bool {
    row.source != PICKER_KERNEL_TUNNEL_SOURCE && !js::trim(&row.exe_path).is_empty()
}

fn stored_name(stored: &[LinkProviderApp], exe_path: &str) -> Option<String> {
    stored
        .iter()
        .find(|a| same_path(js::trim(&a.exe_path), exe_path))
        .map(|a| js::trim(&a.display_name).to_owned())
        .filter(|n| !n.is_empty())
}

/// What the picker lists: what discovery found, in its order, then every
/// stored program it did not find, so the list shows the whole stored set.
pub fn picker_rows(found: &[PickerRow], stored: &[LinkProviderApp]) -> Vec<PickerRow> {
    let mut rows: Vec<PickerRow> = found
        .iter()
        .map(|row| PickerRow {
            exe_path: js::trim(&row.exe_path).to_owned(),
            ..row.clone()
        })
        .collect();
    for app in stored {
        let exe_path = js::trim(&app.exe_path);
        if exe_path.is_empty()
            || rows
                .iter()
                .any(|r| picker_tickable(r) && same_path(&r.exe_path, exe_path))
        {
            continue;
        }
        let name = js::trim(&app.display_name);
        rows.push(PickerRow {
            display_name: if name.is_empty() {
                program_file_name(exe_path).to_owned()
            } else {
                name.to_owned()
            },
            exe_path: exe_path.to_owned(),
            running: false,
            source: PICKER_CONFIRMED_SOURCE.to_owned(),
            interface_name: String::new(),
        });
    }
    rows
}

/// The paths ticked when the picker opens: each tickable row already stored.
pub fn picker_preselected(rows: &[PickerRow], stored: &[LinkProviderApp]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for row in rows.iter().filter(|r| picker_tickable(r)) {
        let path = js::trim(&row.exe_path);
        let is_stored = stored
            .iter()
            .any(|a| same_path(js::trim(&a.exe_path), path));
        if is_stored && !out.iter().any(|p| same_path(p, path)) {
            out.push(path.to_owned());
        }
    }
    out
}

/// The set to write once the picker is confirmed: the ticked rows in list
/// order, then every stored program the list did not show — the user made no
/// choice about those, so a confirm never drops them. A stored name outlives
/// the row's.
pub fn picker_result(
    rows: &[PickerRow],
    selected: &[String],
    stored: &[LinkProviderApp],
) -> Vec<LinkProviderApp> {
    fn push(out: &mut Vec<LinkProviderApp>, exe_path: &str, display_name: String) {
        if out.iter().any(|a| same_path(&a.exe_path, exe_path)) {
            return;
        }
        out.push(LinkProviderApp {
            exe_path: exe_path.to_owned(),
            display_name: if display_name.is_empty() {
                program_file_name(exe_path).to_owned()
            } else {
                display_name
            },
        });
    }
    let mut out: Vec<LinkProviderApp> = Vec::new();
    for row in rows.iter().filter(|r| picker_tickable(r)) {
        let path = js::trim(&row.exe_path);
        if !selected.iter().any(|s| same_path(js::trim(s), path)) {
            continue;
        }
        let name =
            stored_name(stored, path).unwrap_or_else(|| js::trim(&row.display_name).to_owned());
        push(&mut out, path, name);
    }
    for app in stored {
        let path = js::trim(&app.exe_path);
        let shown = rows
            .iter()
            .any(|r| picker_tickable(r) && same_path(js::trim(&r.exe_path), path));
        if path.is_empty() || shown {
            continue;
        }
        push(&mut out, path, js::trim(&app.display_name).to_owned());
    }
    out
}

/// Words every VPN adapter or install path carries, so they tie nothing to
/// anything.
const LINK_TIE_GENERIC_WORDS: &[&str] = &[
    "adapter",
    "and",
    "app",
    "appdata",
    "applications",
    "apps",
    "bin",
    "channel",
    "client",
    "connection",
    "contents",
    "data",
    "driver",
    "ethernet",
    "exe",
    "files",
    "for",
    "gui",
    "interface",
    "lib",
    "local",
    "macos",
    "miniport",
    "network",
    "offload",
    "opt",
    "program",
    "programs",
    "roaming",
    "sbin",
    "service",
    "share",
    "system32",
    "tap",
    "the",
    "tun",
    "tunnel",
    "users",
    "usr",
    "virtual",
    "vpn",
    "windows",
    "wintun",
    "x64",
    "x86",
];

const LINK_TIE_SEPARATORS: &[char] = &[
    ' ', '\t', '\\', '/', '-', '_', '(', ')', '[', ']', ',', ':', '\u{2014}', '\u{2013}',
];

/// The distinctive words of an adapter name or a program path: ASCII-lowered,
/// split on separators, dots kept inside a word (`hidemy.name`), versions,
/// short words and the generic ones dropped.
pub(crate) fn link_tie_words(raw: &str) -> Vec<String> {
    let lowered = raw.to_ascii_lowercase();
    let lowered = lowered.strip_suffix(".exe").unwrap_or(&lowered);
    let mut words: Vec<String> = Vec::new();
    for part in lowered.split(LINK_TIE_SEPARATORS) {
        let word = part.trim_matches('.');
        if word.chars().count() < 3
            || word.chars().all(|c| c.is_ascii_digit() || c == '.')
            || LINK_TIE_GENERIC_WORDS.contains(&word)
            || words.iter().any(|w| w == word)
        {
            continue;
        }
        words.push(word.to_owned());
    }
    words
}

pub(crate) fn shares_a_word(words: &[String], raw: &str) -> bool {
    link_tie_words(raw).iter().any(|w| words.contains(w))
}

/// Programs the picker can offer as the client of the additional link
/// `link_name`, and what the offer calls them (`vpnPickerLinkOffer`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkClientOffer {
    /// Empty when nothing on screen ties to the link.
    pub name: String,
    pub exe_paths: Vec<String>,
}

/// The running programs whose file sits under a folder (or carries a name)
/// sharing a distinctive word with the additional link's adapter name, e.g.
/// `C:\Program Files\Example VPN 3.0\OpenVPN\openvpn.exe` for the adapter
/// "Example VPN Adapter". No OS reports which program raised an adapter, so
/// this name tie is the strongest one available; it only ever pre-ticks or
/// offers, and the user confirms. A program not running now is never tied:
/// the link that just came up was raised by something running.
pub fn picker_link_offer(rows: &[PickerRow], link_name: &str) -> LinkClientOffer {
    let words = link_tie_words(link_name);
    if words.is_empty() {
        return LinkClientOffer::default();
    }
    let mut exe_paths: Vec<String> = Vec::new();
    let mut name = String::new();
    for row in rows.iter().filter(|r| picker_tickable(r) && r.running) {
        let path = js::trim(&row.exe_path);
        let own_name = js::trim(&row.display_name);
        if !shares_a_word(&words, path) && !shares_a_word(&words, own_name) {
            continue;
        }
        if exe_paths.iter().any(|p| same_path(p, path)) {
            continue;
        }
        exe_paths.push(path.to_owned());
        if name.is_empty() && shares_a_word(&words, own_name) {
            name = strip_exe(own_name).to_owned();
        }
    }
    if name.is_empty() {
        if let Some(first) = exe_paths.first() {
            name = strip_exe(program_file_name(first)).to_owned();
        }
    }
    LinkClientOffer { name, exe_paths }
}

pub(crate) fn strip_exe(name: &str) -> &str {
    let lowered = name.to_ascii_lowercase();
    if lowered.ends_with(".exe") {
        &name[..name.len() - 4]
    } else {
        name
    }
}

#[cfg(test)]
mod removal_tests {
    use super::*;

    fn app(path: &str) -> LinkProviderApp {
        LinkProviderApp {
            exe_path: path.to_owned(),
            display_name: String::new(),
        }
    }

    #[test]
    fn removal_ignores_case_and_keeps_the_rest_in_order() {
        let list = [
            app("C:\\A\\a.exe"),
            app("C:\\B\\b.exe"),
            app("C:\\C\\c.exe"),
        ];
        let left = removed_apps(&list, " c:\\b\\B.EXE ");
        assert_eq!(left, vec![app("C:\\A\\a.exe"), app("C:\\C\\c.exe")]);
    }

    #[test]
    fn removing_an_absent_path_changes_nothing() {
        let list = [app("C:\\A\\a.exe")];
        assert_eq!(removed_apps(&list, "C:\\Z\\z.exe"), list.to_vec());
    }
}
