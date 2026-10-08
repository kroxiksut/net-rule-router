//! The rule sets the setup offers and the files it reads. Bundled sets are
//! found where the GUI finds them: `presets/` beside the program, or the
//! checkout in a development build — never a parent directory or the working
//! directory, where another local user could plant one.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use nrr_shared::preset_parser::parse_canonical_rules;

/// The service refuses a rules file larger than this.
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const PRIMARY_FILE: &str = "rules_primary.txt";
const SECONDARY_FILE: &str = "rules_secondary.txt";
/// Sets for people outside a country who need its services:
/// `abroad/access-to-<country>`.
const ABROAD_DIR: &str = "abroad";
const ABROAD_PREFIX: &str = "access-to-";

/// One bundled set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pack {
    /// The country it is for, as its folder names it (`ru`).
    pub country: String,
    /// For someone outside that country rather than in it.
    pub abroad: bool,
    pub dir: PathBuf,
}

impl Pack {
    /// The set's two files; either may be missing.
    pub fn files(&self) -> [Option<PathBuf>; 2] {
        [PRIMARY_FILE, SECONDARY_FILE].map(|name| {
            let path = self.dir.join(name);
            path.is_file().then_some(path)
        })
    }
}

pub fn bundled_root() -> Option<PathBuf> {
    let executable_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    // `apps/tui` sits two levels below the checkout; the path is the build
    // machine's, so only a debug build trusts it.
    #[cfg(debug_assertions)]
    let checkout = Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2);
    #[cfg(not(debug_assertions))]
    let checkout: Option<&Path> = None;
    root_in(executable_dir.as_deref(), checkout)
}

pub fn root_in(executable_dir: Option<&Path>, checkout: Option<&Path>) -> Option<PathBuf> {
    executable_dir
        .into_iter()
        .chain(checkout)
        .map(|root| root.join("presets"))
        .find(|candidate| candidate.is_dir())
}

fn sorted_dirs(dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut dirs: Vec<(String, PathBuf)> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .filter_map(|path| {
            let name = path.file_name()?.to_str()?.to_string();
            Some((name, path))
        })
        .collect();
    dirs.sort();
    dirs
}

/// Every set under `root`, by country, a country's own sets before the one
/// for abroad. A folder holding neither rules file is not a set.
pub fn packs(root: &Path) -> Vec<Pack> {
    let mut packs = Vec::new();
    for (country, country_dir) in sorted_dirs(root) {
        for (name, dir) in sorted_dirs(&country_dir) {
            let pack = if country == ABROAD_DIR {
                let Some(target) = name.strip_prefix(ABROAD_PREFIX) else {
                    continue;
                };
                Pack {
                    country: target.to_string(),
                    abroad: true,
                    dir,
                }
            } else {
                Pack {
                    country: country.clone(),
                    abroad: false,
                    dir,
                }
            };
            if pack.files().iter().any(Option::is_some) {
                packs.push(pack);
            }
        }
    }
    packs.sort_by(|a, b| (&a.country, a.abroad).cmp(&(&b.country, b.abroad)));
    packs
}

/// The country the system is set to, as the GUI reads it: the region of the
/// first locale (`ru_RU` → `ru`), else its language.
pub fn region(candidates: &[String]) -> Option<String> {
    let tag = candidates
        .first()?
        .split(['.', '@'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .replace('_', "-");
    if tag.is_empty() || tag == "c" || tag == "posix" {
        return None;
    }
    let mut parts = tag.split('-');
    let language = parts.next().unwrap_or_default();
    let country = parts.next().unwrap_or(language);
    (!country.is_empty()).then(|| country.to_string())
}

/// The sets for the system's country, as the GUI offers them: its first own
/// set, then the one for abroad.
pub fn regional<'a>(packs: &'a [Pack], country: Option<&str>) -> Vec<&'a Pack> {
    let Some(country) = country else {
        return Vec::new();
    };
    let home = packs.iter().find(|p| p.country == country && !p.abroad);
    let abroad = packs.iter().find(|p| p.country == country && p.abroad);
    home.into_iter().chain(abroad).collect()
}

/// A rules file read for the import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RulesFile {
    pub path: PathBuf,
    pub base64: String,
    /// What the canonical parser finds in it, to say before anything is sent.
    pub rules: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    Unreadable(String),
    TooLarge,
    NotText,
}

pub fn read(path: &Path) -> Result<RulesFile, ReadError> {
    let size = std::fs::metadata(path)
        .map_err(|e| ReadError::Unreadable(e.to_string()))?
        .len();
    if size > MAX_FILE_BYTES {
        return Err(ReadError::TooLarge);
    }
    let bytes = std::fs::read(path).map_err(|e| ReadError::Unreadable(e.to_string()))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| ReadError::NotText)?;
    let rules = parse_canonical_rules(text.trim_start_matches('\u{feff}'))
        .rules
        .len();
    Ok(RulesFile {
        path: path.to_path_buf(),
        base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
        rules,
    })
}

/// A typed path, without the quotes a terminal's drag-and-drop or a copied
/// path brings along.
pub fn typed_path(line: &str) -> String {
    let trimmed = line.trim();
    ['"', '\'']
        .iter()
        .find_map(|q| {
            trimmed
                .strip_prefix(*q)
                .and_then(|rest| rest.strip_suffix(*q))
        })
        .unwrap_or(trimmed)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkout() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .map(Path::to_path_buf)
            .unwrap_or_default()
    }

    #[test]
    fn the_region_is_the_country_half_of_the_locale() {
        assert_eq!(region(&["ru_RU.UTF-8".into()]).as_deref(), Some("ru"));
        assert_eq!(region(&["en-US".into()]).as_deref(), Some("us"));
        assert_eq!(region(&["kk".into()]).as_deref(), Some("kk"));
        assert_eq!(region(&["C".into()]), None);
        assert_eq!(region(&[]), None);
    }

    #[test]
    fn bundled_sets_are_found_and_the_abroad_one_names_its_country() {
        let root = root_in(None, Some(&checkout())).unwrap_or_default();
        let packs = packs(&root);
        assert!(
            packs.iter().any(|p| p.country == "ru" && !p.abroad),
            "{packs:?}"
        );
        assert!(
            packs.iter().any(|p| p.country == "ru" && p.abroad),
            "{packs:?}"
        );
        let offered = regional(&packs, Some("ru"));
        assert_eq!(offered.len(), 2);
        assert!(!offered[0].abroad && offered[1].abroad);
        assert!(regional(&packs, None).is_empty());
    }

    #[test]
    fn a_bundled_file_reads_with_its_rules_counted() {
        let root = root_in(None, Some(&checkout())).unwrap_or_default();
        let pack = packs(&root)
            .into_iter()
            .find(|p| p.country == "ru" && !p.abroad)
            .unwrap_or_else(|| panic!("the ru set is bundled"));
        let [primary, _] = pack.files();
        let file = read(&primary.unwrap_or_else(|| panic!("ru has a main-route file")))
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert!(file.rules > 0);
        assert!(!file.base64.is_empty());
    }

    #[test]
    fn quotes_around_a_typed_path_are_dropped() {
        assert_eq!(typed_path(" \"C:\\a b.txt\" "), "C:\\a b.txt");
        assert_eq!(typed_path("'/tmp/x.txt'"), "/tmp/x.txt");
        assert_eq!(typed_path("/tmp/x.txt"), "/tmp/x.txt");
    }
}
