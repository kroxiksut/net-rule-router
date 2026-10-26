//! The table that holds between boot and the daemon's first pass.
//!
//! The daemon starts after the network is up, so with "everything through the
//! tunnel" on, a session that comes up earlier (autologin, SSH) would leave by
//! the main link until the first pass. Each pass that carries such a block
//! saves its batch here; an early oneshot (`systemd::render_early_unit`)
//! applies it before `network-pre.target`, and the first pass replaces it.
//! Removing our table removes the copy, so a stopped service is not brought
//! back by a reboot.

use std::path::PathBuf;

use crate::drop_tag::DropKind;
use crate::nft_apply::{render_batch_with, DropReporting};
use crate::nft_ir::{NftRuleset, NftVerdict};

/// File name under the service's state directory.
pub const FILE_NAME: &str = "early-table.json";

/// Far above any saved table (rules fold into sets): a bigger file is not one
/// this daemon wrote.
const MAX_BYTES: u64 = 16 * 1024 * 1024;

/// `/var/lib/netrulerouter/early-table.json`.
pub fn path() -> PathBuf {
    crate::systemd::state_dir().join(FILE_NAME)
}

/// Only a block of everything leaves a window worth closing at boot: without
/// it nothing is kept from the main link before the first pass anyway.
pub fn worth_keeping(ruleset: &NftRuleset) -> bool {
    ruleset.rules.iter().any(|rule| {
        matches!(rule.verdict, NftVerdict::DropReported(tag) if tag.kind == DropKind::BlockAll)
    })
}

/// The batch saved for boot. Drops are silent: no reader of their reports runs
/// that early.
pub fn render(ruleset: &NftRuleset) -> Result<String, serde_json::Error> {
    crate::nft_apply::batch_json(&render_batch_with(ruleset, DropReporting::Silent))
}

/// Save `ruleset` for the next boot, or drop the saved copy when it blocks
/// nothing. Not synced: a copy lost to a power cut costs one boot window, and
/// a write per pass must stay cheap.
pub fn keep(ruleset: &NftRuleset) -> std::io::Result<()> {
    keep_at(&path(), ruleset)
}

fn keep_at(path: &std::path::Path, ruleset: &NftRuleset) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if !worth_keeping(ruleset) {
        return remove(path);
    }
    let text = render(ruleset).map_err(std::io::Error::other)?;
    if std::fs::read_to_string(path).is_ok_and(|old| old == text) {
        return Ok(());
    }
    let temp = path.with_extension("json.new");
    let _ = std::fs::remove_file(&temp);
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(text.as_bytes())?;
    }
    std::fs::rename(&temp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&temp);
    })
}

/// Drop the saved copy. A failure is logged, not returned: the table itself is
/// already gone, which is what the caller asked for.
pub fn forget() {
    if let Err(e) = remove(&path()) {
        tracing::warn!(
            target: "nrr::enforcement",
            path = %path().display(),
            error = %e,
            "the saved boot table could not be removed; the next boot may block until the service starts",
        );
    }
}

fn remove(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Run by the early unit: apply the saved table. `Ok(false)` when nothing was
/// saved. The file sits in a root-only directory; it is still bounded and must
/// parse as an `nft` batch before `nft` sees it.
pub fn apply_saved(cli: &crate::nft_apply::NftCliEnforcement) -> Result<bool, String> {
    use std::io::Read;

    let path = path();
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut text = String::new();
    file.take(MAX_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if text.len() as u64 > MAX_BYTES {
        return Err(format!("{}: larger than {MAX_BYTES} bytes", path.display()));
    }
    serde_json::from_str::<nftables::schema::Nftables<'_>>(&text)
        .map_err(|e| format!("{}: not an nft batch: {e}", path.display()))?;
    cli.apply_json(&text)
        .map(|()| true)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drop_tag::DropTag;
    use crate::nft_ir::{NftFamily, NftMatch, NftRule};

    fn set(rules: Vec<NftRule>) -> NftRuleset {
        NftRuleset {
            family: NftFamily::Inet,
            table: "nrr".into(),
            chain: "output".into(),
            forward: Vec::new(),
            rules,
        }
    }

    fn rule(verdict: NftVerdict, comment: &str) -> NftRule {
        NftRule {
            matches: vec![NftMatch::SkUid(1000)],
            verdict,
            comment: comment.into(),
        }
    }

    /// Only "everything through the tunnel" has a boot window to close; a
    /// pin's guard alone does not make a table worth putting up before the
    /// daemon runs.
    #[test]
    fn only_a_block_of_everything_is_kept_for_boot() {
        let pinned = set(vec![rule(
            NftVerdict::DropReported(DropTag::user(DropKind::Pin)),
            "pin leak-guard",
        )]);
        assert!(!worth_keeping(&pinned));
        let mut everything = pinned.clone();
        everything.rules.push(rule(
            NftVerdict::DropReported(DropTag::user(DropKind::BlockAll)),
            "catch-all-block",
        ));
        assert!(worth_keeping(&everything));
    }

    /// At boot nothing reads the drop reports, and a kernel without NFLOG
    /// would refuse the whole saved table over them.
    #[test]
    fn the_saved_table_drops_without_reporting() {
        let text = render(&set(vec![rule(
            NftVerdict::DropReported(DropTag::user(DropKind::BlockAll)),
            "catch-all-block",
        )]))
        .expect("serialises");
        assert!(!text.contains(r#""log""#), "{text}");
        assert!(!text.contains(r#""jump""#), "{text}");
        assert!(text.contains(r#""drop":null"#), "{text}");
        serde_json::from_str::<nftables::schema::Nftables<'_>>(&text)
            .expect("the early unit reads back what was saved");
    }
}
