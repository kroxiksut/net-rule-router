//! Whether the elevated broker may write its log into a directory.
//!
//! The log directory sits under `%ProgramData%`, where any user may create the
//! product folder before the installer locks it down and stay its owner — or
//! make it a junction to `System32`. An elevated create, rotate and append
//! through such a path writes wherever the user pointed it.

use std::path::Path;

/// What the file system reports about one component of the log path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathFact {
    Missing,
    /// A reparse point: junction, symbolic link or mount point.
    Link,
    NotADirectory,
    Directory {
        trusted_owner: bool,
    },
    Unreadable(String),
}

/// Why the broker must not write under `dir`, or `None` when it may.
///
/// No component of `dir` may be a link. `owned_from` is the first directory of
/// our own on the path: it and everything below it must also be owned by
/// SYSTEM or Administrators. `allow_missing` is for the check made before the
/// directory is created. `probe` is asked whether the owner matters, so the
/// system directories above ours are not read for nothing.
pub fn log_dir_refusal(
    dir: &Path,
    owned_from: &Path,
    allow_missing: bool,
    mut probe: impl FnMut(&Path, bool) -> PathFact,
) -> Option<String> {
    let components: Vec<&Path> = dir
        .ancestors()
        .filter(|p| !p.as_os_str().is_empty())
        .collect();
    for component in components.into_iter().rev() {
        let owner_matters = component.starts_with(owned_from);
        match probe(component, owner_matters) {
            PathFact::Directory { trusted_owner } => {
                if owner_matters && !trusted_owner {
                    return Some(format!(
                        "{} is owned by an account other than SYSTEM or Administrators",
                        component.display()
                    ));
                }
            }
            PathFact::Missing if allow_missing => {}
            PathFact::Missing => return Some(format!("{} does not exist", component.display())),
            PathFact::Link => {
                return Some(format!(
                    "{} is a link to somewhere else",
                    component.display()
                ))
            }
            PathFact::NotADirectory => {
                return Some(format!("{} is not a directory", component.display()))
            }
            PathFact::Unreadable(detail) => {
                return Some(format!("cannot inspect {}: {detail}", component.display()))
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    const ROOT: &str = "/machine";
    const PRODUCT: &str = "/machine/product";
    const LOGS: &str = "/machine/product/logs";

    fn trusted() -> PathFact {
        PathFact::Directory {
            trusted_owner: true,
        }
    }

    fn user_owned() -> PathFact {
        PathFact::Directory {
            trusted_owner: false,
        }
    }

    fn verdict(facts: &[(&str, PathFact)], allow_missing: bool) -> Option<String> {
        let map: HashMap<PathBuf, PathFact> = facts
            .iter()
            .map(|(p, f)| (PathBuf::from(p), f.clone()))
            .collect();
        log_dir_refusal(
            Path::new(LOGS),
            Path::new(PRODUCT),
            allow_missing,
            |path, _| map.get(path).cloned().unwrap_or(PathFact::Missing),
        )
    }

    fn locked_down() -> Vec<(&'static str, PathFact)> {
        vec![
            ("/", trusted()),
            (ROOT, trusted()),
            (PRODUCT, trusted()),
            (LOGS, trusted()),
        ]
    }

    #[test]
    fn a_locked_down_tree_is_accepted() {
        assert_eq!(verdict(&locked_down(), false), None);
    }

    #[test]
    fn a_junction_anywhere_on_the_path_is_refused() {
        for link_at in [ROOT, PRODUCT, LOGS] {
            let facts: Vec<_> = locked_down()
                .into_iter()
                .map(|(p, f)| {
                    if p == link_at {
                        (p, PathFact::Link)
                    } else {
                        (p, f)
                    }
                })
                .collect();
            assert!(verdict(&facts, true).is_some(), "link at {link_at}");
        }
    }

    /// The pre-install case: a user created the product folder first.
    #[test]
    fn a_product_folder_owned_by_a_user_is_refused() {
        let facts = vec![
            ("/", trusted()),
            (ROOT, trusted()),
            (PRODUCT, user_owned()),
            (LOGS, trusted()),
        ];
        let reason = verdict(&facts, true).expect("must refuse");
        assert!(reason.contains("owned by"), "{reason}");
    }

    #[test]
    fn the_owner_of_system_directories_above_ours_does_not_matter() {
        let facts = vec![
            ("/", user_owned()),
            (ROOT, user_owned()),
            (PRODUCT, trusted()),
            (LOGS, trusted()),
        ];
        assert_eq!(verdict(&facts, false), None);
    }

    #[test]
    fn a_missing_directory_is_allowed_only_before_creation() {
        let facts = vec![("/", trusted()), (ROOT, trusted())];
        assert_eq!(verdict(&facts, true), None);
        assert!(verdict(&facts, false).is_some());
    }

    #[test]
    fn a_file_or_an_unreadable_component_is_refused() {
        let mut facts = locked_down();
        facts[2] = (PRODUCT, PathFact::NotADirectory);
        assert!(verdict(&facts, true).is_some());
        let mut facts = locked_down();
        facts[3] = (LOGS, PathFact::Unreadable("denied".into()));
        assert!(verdict(&facts, true).is_some());
    }

    #[test]
    fn the_owner_is_asked_about_only_for_our_own_directories() {
        let mut asked = Vec::new();
        log_dir_refusal(
            Path::new(LOGS),
            Path::new(PRODUCT),
            false,
            |path, owner_matters| {
                if owner_matters {
                    asked.push(path.to_path_buf());
                }
                trusted()
            },
        );
        assert_eq!(asked, vec![PathBuf::from(PRODUCT), PathBuf::from(LOGS)]);
    }
}
