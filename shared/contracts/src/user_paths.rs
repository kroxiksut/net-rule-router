//! Where a per-user file of ours belongs on this OS.
//!
//! The OS shape lives here, at the bottom of the graph, because two layers
//! above need the same answer: the UI preference store and the localization
//! bundles. Each had its own copy of the ladder, and both spelled it in
//! Windows environment variables alone — off Windows they fell through to the
//! temp directory, which is shared between users and cleared on a schedule
//! nobody controls.
//!
//! `nrr_platform_api::paths::user_config_root` is the shim for callers that
//! already speak to that module.

use std::path::PathBuf;

/// The spelling this OS uses for a directory named after the product:
/// canonical (`NetRuleRouter`) on Windows, unix (`netrulerouter`) elsewhere.
pub fn product_dir_leaf() -> &'static str {
    if cfg!(windows) {
        crate::product_identity::PRODUCT_NAME
    } else {
        crate::product_identity::PRODUCT_NAME_UNIX
    }
}

/// Roots for per-user application files, best first, each already ending in
/// [`product_dir_leaf`]. Callers walk the list and take the first they can
/// create.
///
/// Windows keeps the roaming profile, then the local one. Elsewhere it is
/// `$XDG_CONFIG_HOME`, falling back to the `~/.config` the spec defines when
/// the variable is unset. The temp directory closes the list on every OS as
/// the answer of last resort.
pub fn user_app_roots() -> Vec<PathBuf> {
    let leaf = product_dir_leaf();
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut push = |base: PathBuf| roots.push(base.join(leaf));

    #[cfg(windows)]
    {
        if let Some(app_data) = std::env::var_os("APPDATA") {
            push(PathBuf::from(app_data));
        }
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            push(PathBuf::from(local_app_data));
        }
    }

    #[cfg(not(windows))]
    {
        if let Some(base) = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
        {
            push(base);
        } else if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
            push(PathBuf::from(home).join(".config"));
        }
    }

    push(std::env::temp_dir());
    roots
}

/// The best root without asking whether it can be created — for documentation,
/// diagnostics and tests. A caller that is about to WRITE wants
/// [`user_app_roots`], which lets it fall to the next candidate.
pub fn user_config_root() -> Option<PathBuf> {
    user_app_roots().into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_root_ends_in_the_product_leaf() {
        for root in user_app_roots() {
            assert_eq!(
                root.file_name().and_then(|name| name.to_str()),
                Some(product_dir_leaf()),
                "candidate does not end in the product directory: {}",
                root.display()
            );
        }
    }

    #[test]
    fn the_last_resort_is_temp_and_the_only_one() {
        let roots = user_app_roots();
        let temp = std::env::temp_dir();
        let last = roots.last().expect("at least the temp candidate");
        assert!(last.starts_with(&temp));
        assert!(
            roots[..roots.len() - 1]
                .iter()
                .all(|root| !root.starts_with(&temp)),
            "only the last candidate may be the temp directory"
        );
    }

    #[test]
    fn a_profile_root_is_offered_before_the_temp_directory() {
        // Windows always has APPDATA, unix always has HOME under test; the
        // point of the assert is that we never hand a caller temp as the FIRST
        // answer on a normally configured account.
        let roots = user_app_roots();
        assert!(
            roots.len() > 1,
            "no profile root was offered: {:?}",
            roots
                .iter()
                .map(|r| r.display().to_string())
                .collect::<Vec<_>>()
        );
        assert!(!roots[0].starts_with(std::env::temp_dir()));
    }

    #[cfg(not(windows))]
    #[test]
    fn xdg_config_home_wins_over_the_home_default() {
        // The env is process-wide, so this asserts the ORDER the builder
        // declares rather than mutating it: the XDG branch is taken first and
        // the `.config` default is its `else`.
        let from_env = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute());
        let Some(expected_base) = from_env else {
            return;
        };
        let expected = expected_base.join(product_dir_leaf());
        assert!(
            user_app_roots().contains(&expected),
            "XDG_CONFIG_HOME is set but no candidate uses it"
        );
    }
}
