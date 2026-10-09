//! The user's rule-set folder and the set on screen moving into it
//! (`isPathUnderDir`, `rememberedRulesPathFor`, `isUsableSetName`,
//! `rulesFileFolder`, `adoptedSetName`, `rulesLiveInFolder` and
//! `numberedSetName` in `pure.js`).

use crate::js;

/// The highest number a taken set name is suffixed with: `<name> (99)`.
pub const MAX_SET_NUMBER: u32 = 99;

/// What the user's own actions put on record for one route's rules file.
/// `""` is none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RouteFiles<'a> {
    /// Where the rules are saved to (the binding).
    pub saved: &'a str,
    /// Where the rules on screen were read from.
    pub loaded: &'a str,
    /// The "open these rules on next launch" opt-in.
    pub auto_open: &'a str,
}

/// Case-insensitive, separator-blind "is `path` inside `dir`?". `C:/rules-x`
/// is not inside `C:/rules`.
pub fn is_path_under_dir(path: &str, dir: &str) -> bool {
    let norm = |p: &str| p.replace('\\', "/").trim_end_matches('/').to_lowercase();
    let path = norm(path);
    let dir = norm(dir);
    if path.is_empty() || dir.is_empty() {
        return false;
    }
    path == dir || path.starts_with(&format!("{dir}/"))
}

/// Which file backs a route: a remembered path inside the user's own folder
/// first, then the launch opt-in, then where the rules were read from, then
/// the binding.
pub fn remembered_rules_path<'a>(files: &RouteFiles<'a>, own_folder: &str) -> &'a str {
    if !own_folder.is_empty() {
        for path in [files.saved, files.loaded, files.auto_open] {
            if is_path_under_dir(path, own_folder) {
                return path;
            }
        }
    }
    [files.auto_open, files.loaded, files.saved]
        .into_iter()
        .find(|path| !path.is_empty())
        .unwrap_or("")
}

/// A name a set folder can take: plain, never a path or drive syntax.
pub fn is_usable_set_name(name: &str) -> bool {
    let name = js::trim(name);
    !name.is_empty() && name != "." && !name.contains(['/', '\\', ':']) && !name.contains("..")
}

/// The folder of a rules file, with `/` separators; `""` when the path names
/// none.
pub fn rules_file_folder(path: &str) -> String {
    let norm = path.replace('\\', "/");
    match norm.rfind('/') {
        Some(slash) if slash > 0 => norm[..slash].to_owned(),
        _ => String::new(),
    }
}

/// The name the set on screen is saved under: the folder of the files its
/// rules came from, else the label of the set picked from the list, else
/// `fallback` (the localized "My rules").
pub fn adopted_set_name(
    routes: &[RouteFiles<'_>; 2],
    selected_set: &str,
    fallback: &str,
) -> String {
    let [primary, secondary] = routes;
    let path = [
        primary.saved,
        primary.loaded,
        secondary.saved,
        secondary.loaded,
    ]
    .into_iter()
    .find(|path| !path.is_empty())
    .unwrap_or("");
    let mut candidate = String::new();
    if !path.is_empty() {
        let folder = rules_file_folder(path);
        let start = folder.rfind('/').map_or(0, |slash| slash + 1);
        candidate = folder[start..].to_owned();
    }
    if !is_usable_set_name(&candidate) {
        let start = selected_set.find(':').map_or(0, |colon| colon + 1);
        candidate = selected_set[start..].to_owned();
    }
    if is_usable_set_name(&candidate) {
        candidate
    } else {
        fallback.to_owned()
    }
}

/// Do the rules on screen already live in `folder`: is the remembered file of
/// either route inside it?
pub fn rules_live_in_folder(routes: &[RouteFiles<'_>; 2], folder: &str) -> bool {
    let dir = folder.replace('\\', "/");
    let dir = dir.trim_end_matches('/');
    if dir.is_empty() {
        return false;
    }
    routes.iter().any(|files| {
        let home = remembered_rules_path(files, dir);
        !home.is_empty() && is_path_under_dir(home, dir)
    })
}

/// `base`, or the first of `base (2)` … `base (99)` whose folder holds no
/// rules files. Past 99 the last name is returned taken; the caller must not
/// write into it.
pub fn numbered_set_name(base: &str, has_files: impl Fn(&str) -> bool) -> String {
    let mut name = base.to_owned();
    let mut n = 2;
    while n <= MAX_SET_NUMBER && has_files(&name) {
        name = format!("{base} ({n})");
        n += 1;
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound(saved: &str) -> RouteFiles<'_> {
        RouteFiles {
            saved,
            ..RouteFiles::default()
        }
    }

    #[test]
    fn a_sibling_folder_with_a_longer_name_is_not_inside() {
        assert!(is_path_under_dir(
            "C:\\Rules\\home\\rules_primary.txt",
            "c:/rules/"
        ));
        assert!(!is_path_under_dir("C:/rules-x/a.txt", "C:/rules"));
        assert!(!is_path_under_dir("", "C:/rules"));
    }

    #[test]
    fn the_set_is_named_after_its_folder_then_the_pick_then_the_fallback() {
        let from_files = [bound("/sets/home/rules_primary.txt"), bound("")];
        assert_eq!(adopted_set_name(&from_files, "user:x", "My rules"), "home");
        let none = [bound(""), bound("")];
        assert_eq!(
            adopted_set_name(&none, "bundled:ru_basic", "My rules"),
            "ru_basic"
        );
        assert_eq!(adopted_set_name(&none, "", "My rules"), "My rules");
        assert_eq!(adopted_set_name(&none, "user:a:b", "My rules"), "My rules");
    }

    #[test]
    fn rules_already_in_the_folder_stay() {
        let routes = [bound(""), bound("D:\\Sets\\work\\rules_secondary.txt")];
        assert!(rules_live_in_folder(&routes, "d:/sets/"));
        assert!(!rules_live_in_folder(&routes, "D:/Other"));
        assert!(!rules_live_in_folder(&routes, ""));
    }

    #[test]
    fn a_taken_name_is_numbered() {
        let taken = ["home", "home (2)"];
        let name = numbered_set_name("home", |n| taken.contains(&n));
        assert_eq!(name, "home (3)");
        assert_eq!(numbered_set_name("free", |_| false), "free");
        assert_eq!(numbered_set_name("full", |_| true), "full (99)");
    }
}
