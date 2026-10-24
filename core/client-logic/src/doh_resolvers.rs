//! The DoH resolver list a client writes (`dohResolversRebase` in `pure.js`).
//!
//! `doh.resolvers.set` replaces the machine's whole list, so the user's edits
//! are laid over a fresh read, matched by address, instead of sending the copy
//! the editor opened with: an entry another client added meanwhile survives,
//! one this user removed goes.

use std::collections::{HashMap, HashSet};

use crate::js;

/// One row as the wire carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolver {
    /// `"ip"` or `"host"`.
    pub kind: String,
    pub target: String,
    pub comment: String,
    pub enabled: bool,
}

/// The list to write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rebased {
    pub resolvers: Vec<Resolver>,
    /// The user removed a row the editor opened with. The write has to say
    /// so (`drop-seeded`), or the service refuses to lose a built-in entry.
    pub removed: bool,
}

fn key(row: &Resolver) -> String {
    js::trim(&row.target).to_lowercase()
}

fn by_key(rows: &[Resolver]) -> HashMap<String, &Resolver> {
    let mut map = HashMap::new();
    for row in rows {
        let k = key(row);
        if !k.is_empty() {
            map.entry(k).or_insert(row);
        }
    }
    map
}

/// `edited` (the editor's rows, opened as `base`) laid over `fresh` (the
/// list the service holds now). Fresh rows keep their order; a row the user
/// changed takes the changed fields; rows the user added follow, a repeat
/// of one already listed dropped.
pub fn rebase(base: &[Resolver], edited: &[Resolver], fresh: &[Resolver]) -> Rebased {
    let base_rows = by_key(base);
    let edited_rows = by_key(edited);
    let removed = base_rows.keys().any(|k| !edited_rows.contains_key(k));
    let mut out: Vec<Resolver> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for row in fresh {
        let k = key(row);
        if k.is_empty() || seen.contains(&k) {
            continue;
        }
        let mut next = row.clone();
        match (base_rows.get(&k), edited_rows.get(&k)) {
            (Some(_), None) => continue,
            (Some(was), Some(now)) => {
                if now.comment != was.comment {
                    next.comment = now.comment.clone();
                }
                if now.enabled != was.enabled {
                    next.enabled = now.enabled;
                }
            }
            _ => {}
        }
        out.push(next);
        seen.insert(k);
    }
    for row in edited {
        let k = key(row);
        if k.is_empty() || seen.contains(&k) || base_rows.contains_key(&k) {
            continue;
        }
        out.push(row.clone());
        seen.insert(k);
    }
    Rebased {
        resolvers: out,
        removed,
    }
}
