//! Whether a user may list a folder, judged from its mode bits as the kernel
//! would for that user: the daemon runs as root and lists everything.
//!
//! Groups come from `/etc/passwd` and `/etc/group`; a group only a directory
//! service knows is missed, which can refuse a folder its member could open,
//! never open one they could not.

#[cfg(unix)]
const READ: u32 = 0o4;
#[cfg(unix)]
const SEARCH: u32 = 0o1;

/// Accounts and group lines read from either file.
const MAX_LINES: usize = 8192;
#[cfg(unix)]
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Who asks: a uid and every group it is in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asker {
    pub uid: u32,
    pub groups: Vec<u32>,
}

/// The bits of `mode` that apply to `asker` for an object `owner`:`group`
/// holds, as the kernel picks them: owner, else group, else others.
#[must_use]
pub fn rights_of(asker: &Asker, mode: u32, owner: u32, group: u32) -> u32 {
    if asker.uid == owner {
        (mode >> 6) & 0o7
    } else if asker.groups.contains(&group) {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    }
}

/// The groups of `uid`: its primary group from `passwd`, and every line of
/// `group` that names its account.
#[must_use]
pub fn asker_from(uid: u32, passwd: &str, group: &str) -> Option<Asker> {
    let (name, primary) = passwd.lines().take(MAX_LINES).find_map(|line| {
        let fields: Vec<&str> = line.splitn(7, ':').collect();
        let line_uid: u32 = fields.get(2)?.trim().parse().ok()?;
        let gid: u32 = fields.get(3)?.trim().parse().ok()?;
        let name = fields.first()?;
        (line_uid == uid).then(|| ((*name).to_owned(), gid))
    })?;
    let mut groups = vec![primary];
    for line in group.lines().take(MAX_LINES) {
        let fields: Vec<&str> = line.splitn(4, ':').collect();
        let (Some(gid), Some(members)) = (fields.get(2), fields.get(3)) else {
            continue;
        };
        let Ok(gid) = gid.trim().parse::<u32>() else {
            continue;
        };
        if members.split(',').any(|m| m.trim() == name) && !groups.contains(&gid) {
            groups.push(gid);
        }
    }
    Some(Asker { uid, groups })
}

/// Whether the account behind stored principal `owner` (`unix:uid:N`) may
/// list `place` (a file: its folder): read and search on it, search on every
/// folder above. `None` where it cannot be judged.
#[cfg(unix)]
#[must_use]
pub fn uid_may_list(place: &std::path::Path, owner: &str) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;

    let uid: u32 = owner.strip_prefix("unix:uid:")?.parse().ok()?;
    if uid == 0 {
        return Some(true);
    }
    let asker = asker_from(
        uid,
        &read_bounded("/etc/passwd")?,
        &read_bounded("/etc/group")?,
    )?;
    // Judged where links lead: the folders above a link are not the ones the
    // kernel walks to reach its target.
    let real = std::fs::canonicalize(place).ok()?;
    let folder = if real.is_file() {
        real.parent()?
    } else {
        real.as_path()
    };
    let meta = std::fs::metadata(folder).ok()?;
    if !meta.is_dir() {
        return None;
    }
    let mine = rights_of(&asker, meta.mode(), meta.uid(), meta.gid());
    if mine & (READ | SEARCH) != (READ | SEARCH) {
        return Some(false);
    }
    for above in folder.ancestors().skip(1) {
        if above.as_os_str().is_empty() {
            break;
        }
        let meta = std::fs::metadata(above).ok()?;
        if rights_of(&asker, meta.mode(), meta.uid(), meta.gid()) & SEARCH == 0 {
            return Some(false);
        }
    }
    Some(true)
}

#[cfg(unix)]
fn read_bounded(path: &str) -> Option<String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_FILE_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0::/root:/bin/sh\n\
        alice:x:1000:1000::/home/alice:/bin/sh\n\
        bob:x:1001:1001::/home/bob:/bin/sh\n";
    const GROUP: &str = "root:x:0:\nalice:x:1000:\nbob:x:1001:\ntools:x:2000:bob,carol\n";

    #[test]
    fn groups_are_the_primary_one_and_the_lines_naming_the_account() {
        let bob = asker_from(1001, PASSWD, GROUP).expect("bob");
        assert_eq!(bob.groups, [1001, 2000]);
        let alice = asker_from(1000, PASSWD, GROUP).expect("alice");
        assert_eq!(alice.groups, [1000]);
        assert_eq!(asker_from(4242, PASSWD, GROUP), None);
    }

    #[test]
    fn the_kernel_picks_owner_then_group_then_others() {
        let alice = asker_from(1000, PASSWD, GROUP).expect("alice");
        let bob = asker_from(1001, PASSWD, GROUP).expect("bob");
        // A folder only bob opens.
        assert_eq!(rights_of(&alice, 0o700, 1001, 1001), 0);
        assert_eq!(rights_of(&bob, 0o700, 1001, 1001), 0o7);
        // Shared with the tools group.
        assert_eq!(rights_of(&bob, 0o750, 0, 2000), 0o5);
        assert_eq!(rights_of(&alice, 0o750, 0, 2000), 0);
        // Owner bits win even where others may more.
        assert_eq!(rights_of(&alice, 0o077, 1000, 1000), 0);
    }
}
