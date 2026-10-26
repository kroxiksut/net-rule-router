//! Who may reach the service's data tree, decided once for every OS mechanism.
//!
//! The service account and administrators may; nobody else may do anything.
//! Each entry's permissions are read into [`Observed`] and answered with a
//! [`Plan`]: an entry already that strict, or stricter, is left as it is, so a
//! lockdown that runs at every start never opens back up what someone
//! deliberately narrowed. Anything else is reset to the baseline.

/// Whom a permission entry names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Principal {
    /// The account the service runs as (SYSTEM, root).
    Service,
    Administrators,
    /// Every other account or group, users and "everyone" included.
    Other,
}

/// What a permission entry allows or denies, in classes every OS maps onto.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rights(u8);

impl Rights {
    pub const NONE: Self = Self(0);
    /// List a folder, read a file, read its attributes and permissions.
    pub const READ: Self = Self(1);
    /// Create, write, rename or delete.
    pub const CHANGE: Self = Self(2);
    /// Change the permissions or the owner.
    pub const CONTROL: Self = Self(4);
    pub const FULL: Self = Self(7);

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn minus(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// One permission entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Grant {
    pub principal: Principal,
    pub rights: Rights,
    pub deny: bool,
    /// Passed on to entries created below a folder.
    pub to_children: bool,
}

impl Grant {
    const fn allow(principal: Principal, rights: Rights) -> Self {
        Self {
            principal,
            rights,
            deny: false,
            to_children: true,
        }
    }
}

/// An entry's permissions as found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    /// Takes nothing from the folder above.
    pub protected: bool,
    /// Owned by the service account or administrators.
    pub owner_trusted: bool,
    pub grants: Vec<Grant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Placement {
    Folder,
    File,
}

/// What to do with the root's permissions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootPlan {
    /// Already at the baseline or stricter.
    Keep,
    /// Take these grants, owned by administrators, nothing inherited.
    Apply(Vec<Grant>),
}

/// What to do with an entry below the root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryPlan {
    /// Already at the baseline or stricter.
    Keep,
    /// Owned by administrators, holding only what the folder above passes on.
    Inherit,
}

#[must_use]
pub fn plan_root(observed: &Observed) -> RootPlan {
    if strict_enough(observed, Placement::Folder) {
        RootPlan::Keep
    } else {
        RootPlan::Apply(root_grants(observed))
    }
}

#[must_use]
pub fn plan_entry(observed: &Observed, is_folder: bool) -> EntryPlan {
    let placement = if is_folder {
        Placement::Folder
    } else {
        Placement::File
    };
    if strict_enough(observed, placement) {
        EntryPlan::Keep
    } else {
        EntryPlan::Inherit
    }
}

/// What a folder kept as found passes on to the entries below it: the service
/// account and administrators, each with what it is allowed less what it is
/// denied.
#[must_use]
pub fn passed_on(grants: &[Grant]) -> Vec<Grant> {
    [Principal::Service, Principal::Administrators]
        .into_iter()
        .filter_map(|principal| {
            let rights = effective(grants.iter().filter(|g| g.to_children), principal);
            (!rights.is_empty()).then_some(Grant::allow(principal, rights))
        })
        .collect()
}

/// Protected, trusted owner, nobody else allowed anything, and the service
/// keeps full control — over what is created inside, too, for a folder.
fn strict_enough(observed: &Observed, placement: Placement) -> bool {
    let service_full = observed.grants.iter().any(|g| {
        g.principal == Principal::Service
            && !g.deny
            && g.rights.contains(Rights::FULL)
            && (placement == Placement::File || g.to_children)
    });
    let service_denied = observed
        .grants
        .iter()
        .any(|g| g.principal == Principal::Service && g.deny && !g.rights.is_empty());
    let other_allowed = observed
        .grants
        .iter()
        .any(|g| g.principal == Principal::Other && !g.deny && !g.rights.is_empty());
    observed.protected
        && observed.owner_trusted
        && service_full
        && !service_denied
        && !other_allowed
}

/// The service gets full control. Administrators keep what a protected root
/// with a trusted owner gave them; a root that merely inherited its entries or
/// that someone else owns gets the baseline.
fn root_grants(observed: &Observed) -> Vec<Grant> {
    let administrators = if observed.protected && observed.owner_trusted {
        effective(observed.grants.iter(), Principal::Administrators)
    } else {
        Rights::FULL
    };
    let mut grants = vec![Grant::allow(Principal::Service, Rights::FULL)];
    if !administrators.is_empty() {
        grants.push(Grant::allow(Principal::Administrators, administrators));
    }
    grants
}

fn effective<'a>(grants: impl Iterator<Item = &'a Grant>, principal: Principal) -> Rights {
    let (allowed, denied) = grants.filter(|g| g.principal == principal).fold(
        (Rights::NONE, Rights::NONE),
        |(allowed, denied), g| {
            if g.deny {
                (allowed, denied.union(g.rights))
            } else {
                (allowed.union(g.rights), denied)
            }
        },
    );
    allowed.minus(denied)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(principal: Principal, rights: Rights) -> Grant {
        Grant::allow(principal, rights)
    }

    fn baseline() -> Vec<Grant> {
        vec![
            grant(Principal::Service, Rights::FULL),
            grant(Principal::Administrators, Rights::FULL),
        ]
    }

    /// What `ProgramData` hands a new folder: users may create files in it.
    fn inherited_from_program_data() -> Observed {
        let mut grants = baseline();
        grants.push(grant(Principal::Other, Rights::READ.union(Rights::CHANGE)));
        Observed {
            protected: false,
            owner_trusted: true,
            grants,
        }
    }

    #[test]
    fn a_root_open_to_users_is_reset_to_the_service_and_administrators() {
        assert_eq!(
            plan_root(&inherited_from_program_data()),
            RootPlan::Apply(baseline())
        );
    }

    #[test]
    fn a_root_another_account_owns_is_reset_even_if_its_entries_look_strict() {
        let observed = Observed {
            protected: true,
            owner_trusted: false,
            grants: vec![grant(Principal::Service, Rights::FULL)],
        };
        assert_eq!(plan_root(&observed), RootPlan::Apply(baseline()));
    }

    #[test]
    fn a_root_already_at_the_baseline_is_left_alone() {
        let observed = Observed {
            protected: true,
            owner_trusted: true,
            grants: baseline(),
        };
        assert_eq!(plan_root(&observed), RootPlan::Keep);
    }

    /// An administrator who narrowed the tree to the service alone is not
    /// overruled at the next start.
    #[test]
    fn a_stricter_root_is_never_opened_back_up() {
        let observed = Observed {
            protected: true,
            owner_trusted: true,
            grants: vec![grant(Principal::Service, Rights::FULL)],
        };
        assert_eq!(plan_root(&observed), RootPlan::Keep);
        let read_only_admins = Observed {
            protected: true,
            owner_trusted: true,
            grants: vec![
                grant(Principal::Service, Rights::FULL),
                grant(Principal::Administrators, Rights::READ),
                grant(Principal::Other, Rights::READ),
            ],
        };
        assert_eq!(
            plan_root(&read_only_admins),
            RootPlan::Apply(vec![
                grant(Principal::Service, Rights::FULL),
                grant(Principal::Administrators, Rights::READ),
            ]),
            "the stray entry goes, the narrower administrators' entry stays"
        );
    }

    /// The service cannot run on a tree it may not write, whatever someone set.
    #[test]
    fn a_root_that_shuts_the_service_out_is_reset() {
        let mut grants = baseline();
        grants.push(Grant {
            deny: true,
            ..grant(Principal::Service, Rights::CHANGE)
        });
        let observed = Observed {
            protected: true,
            owner_trusted: true,
            grants,
        };
        assert_eq!(plan_root(&observed), RootPlan::Apply(baseline()));
        let not_passed_on = Observed {
            protected: true,
            owner_trusted: true,
            grants: vec![Grant {
                to_children: false,
                ..grant(Principal::Service, Rights::FULL)
            }],
        };
        assert!(matches!(plan_root(&not_passed_on), RootPlan::Apply(_)));
    }

    #[test]
    fn an_entry_below_with_its_own_users_entry_inherits_again() {
        let observed = Observed {
            protected: false,
            owner_trusted: true,
            grants: vec![
                grant(Principal::Other, Rights::READ),
                grant(Principal::Service, Rights::FULL),
            ],
        };
        assert_eq!(plan_entry(&observed, false), EntryPlan::Inherit);
        assert_eq!(plan_entry(&observed, true), EntryPlan::Inherit);
    }

    /// A file sealed to the service alone — a key, say — keeps that seal.
    #[test]
    fn a_file_sealed_to_the_service_keeps_its_seal() {
        let observed = Observed {
            protected: true,
            owner_trusted: true,
            grants: vec![Grant {
                to_children: false,
                ..grant(Principal::Service, Rights::FULL)
            }],
        };
        assert_eq!(plan_entry(&observed, false), EntryPlan::Keep);
        assert_eq!(plan_entry(&observed, true), EntryPlan::Inherit);
    }

    #[test]
    fn a_kept_folder_passes_on_only_what_it_allows_less_what_it_denies() {
        let grants = [
            grant(Principal::Service, Rights::FULL),
            grant(Principal::Administrators, Rights::FULL),
            Grant {
                deny: true,
                ..grant(Principal::Administrators, Rights::CHANGE)
            },
            Grant {
                to_children: false,
                ..grant(Principal::Administrators, Rights::FULL)
            },
        ];
        assert_eq!(
            passed_on(&grants),
            vec![
                grant(Principal::Service, Rights::FULL),
                grant(
                    Principal::Administrators,
                    Rights::READ.union(Rights::CONTROL)
                ),
            ]
        );
    }
}
