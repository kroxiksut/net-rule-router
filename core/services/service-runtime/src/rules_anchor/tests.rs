use super::*;

const KEY: [u8; 32] = [0x42; 32];

fn rules(revision: &str) -> ActiveRules {
    ActiveRules {
        revision: revision.into(),
        hash: format!("h-{revision}"),
    }
}

fn set(entries: &[(&str, &str)]) -> ActiveSet {
    entries
        .iter()
        .map(|(p, r)| ((*p).to_owned(), rules(r)))
        .collect()
}

fn stored(entries: &[(&str, &str)]) -> Vec<u8> {
    AnchorRecord::of(set(entries)).encode(&KEY)
}

#[test]
fn a_deleted_active_row_disagrees_with_the_record() {
    let check = check_at_boot(
        &set(&[("base", "b1")]),
        Some(&stored(&[("base", "b1"), ("S-1", "r2")])),
        &KEY,
    );
    let Some(AnchorAlert::Disagrees(found)) = check.alert else {
        panic!("a vanished rule set went unnoticed: {check:?}");
    };
    assert_eq!(
        found,
        vec![Disagreement {
            principal: "S-1".into(),
            recorded: Some(rules("r2")),
            found: None,
        }]
    );
    assert_eq!(
        check.start.expect("kept").active.get("S-1"),
        Some(&rules("r2")),
        "the record keeps what was lost until an administrator accepts it"
    );
}

#[test]
fn an_older_copy_of_the_database_disagrees_with_the_record() {
    let check = check_at_boot(
        &set(&[("S-1", "r1")]),
        Some(&stored(&[("S-1", "r2")])),
        &KEY,
    );
    assert!(
        matches!(check.alert, Some(AnchorAlert::Disagrees(ref d)) if d.len() == 1),
        "{check:?}"
    );
}

#[test]
fn rules_the_record_never_named_disagree_too() {
    let check = check_at_boot(&set(&[("S-1", "r1")]), Some(&stored(&[])), &KEY);
    assert!(matches!(check.alert, Some(AnchorAlert::Disagrees(_))));
}

#[test]
fn an_install_from_before_the_record_is_not_an_alert() {
    let found = set(&[("S-1", "r1")]);
    let check = check_at_boot(&found, None, &KEY);
    assert_eq!(check.alert, None);
    assert!(check.rewrite);
    assert_eq!(check.start.expect("start").active, found);
}

#[test]
fn a_record_under_another_key_is_an_alert_and_not_trusted() {
    let forged = AnchorRecord::of(set(&[("S-1", "r1")])).encode(&[0x11; 32]);
    let check = check_at_boot(&set(&[("S-1", "r1")]), Some(&forged), &KEY);
    assert!(
        matches!(check.alert, Some(AnchorAlert::Unverifiable { .. })),
        "{check:?}"
    );
    assert_eq!(check.start, None, "nothing it says is kept");
}

#[test]
fn a_record_cut_short_or_reshaped_is_unverifiable() {
    let good = stored(&[("S-1", "r1")]);
    for bad in [
        Vec::new(),
        good[..HMAC_BYTE_LEN].to_vec(),
        good[..good.len() - 1].to_vec(),
        // Still a well-formed record, naming another revision.
        {
            let mut reshaped = good.clone();
            let at = reshaped
                .windows(4)
                .position(|w| w == b"\"r1\"")
                .expect("the revision in the payload");
            reshaped[at + 2] = b'0';
            reshaped
        },
    ] {
        let check = check_at_boot(&set(&[("S-1", "r1")]), Some(&bad), &KEY);
        assert!(
            matches!(check.alert, Some(AnchorAlert::Unverifiable { .. })),
            "{} bytes passed",
            bad.len()
        );
    }
}

#[test]
fn a_commit_cut_off_before_the_rewrite_is_taken_from_the_database() {
    let mut record = AnchorRecord::of(set(&[("S-1", "r1"), ("S-2", "q1")]));
    record.pending.insert("S-1".into());
    let check = check_at_boot(
        &set(&[("S-1", "r2"), ("S-2", "q1")]),
        Some(&record.encode(&KEY)),
        &KEY,
    );
    assert_eq!(check.alert, None);
    assert!(check.rewrite);
    let start = check.start.expect("start");
    assert_eq!(start.active.get("S-1"), Some(&rules("r2")));
    assert!(start.pending.is_empty());
}

#[test]
fn a_pending_commit_does_not_excuse_another_principal() {
    let mut record = AnchorRecord::of(set(&[("S-1", "r1"), ("S-2", "q1")]));
    record.pending.insert("S-1".into());
    let check = check_at_boot(&set(&[("S-1", "r2")]), Some(&record.encode(&KEY)), &KEY);
    let Some(AnchorAlert::Disagrees(found)) = check.alert else {
        panic!("{check:?}");
    };
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].principal, "S-2");
}

#[test]
fn the_same_incident_keeps_its_alert_id_across_starts() {
    let record = stored(&[("S-1", "r2")]);
    let found = set(&[("S-1", "r1")]);
    let first = check_at_boot(&found, Some(&record), &KEY)
        .alert
        .expect("alert");
    let again = check_at_boot(&found, Some(&record), &KEY)
        .alert
        .expect("alert");
    assert_eq!(first.alert_id(), again.alert_id());
    let other = check_at_boot(&set(&[]), Some(&record), &KEY)
        .alert
        .expect("alert");
    assert_ne!(
        first.alert_id(),
        other.alert_id(),
        "a new incident, a new id"
    );
}
