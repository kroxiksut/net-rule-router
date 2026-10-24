#![allow(clippy::expect_used)]

//! After a merge the user confirmed is in force, the window writes the bound
//! files from the merged rules unasked only for a file it took into that
//! merge. Each case is a way to lose rules the merge never saw: an edit made
//! after the merge read the file, a review that was not a merge, an empty file.

#[allow(dead_code)]
mod js_harness;

use js_harness::JsLib;
use serde_json::{json, Value};

fn taken(pure: &mut JsLib, paths: &Value, merged_from: &Value, now: &Value) -> Value {
    pure.eval_json(&format!("mergeTakenPaths({paths}, {merged_from}, {now})"))
}

#[test]
fn only_a_file_unchanged_since_the_merge_is_taken() {
    let mut pure = JsLib::pure();
    let paths =
        json!({ "primary": "C:/r/rules_primary.txt", "secondary": "C:/r/rules_secondary.txt" });
    let merged_from = json!({ "primary": "a.example\n", "secondary": "b.example\n" });

    let unchanged = json!({ "primary": "a.example\n", "secondary": "b.example\n" });
    assert_eq!(
        taken(&mut pure, &paths, &merged_from, &unchanged),
        json!(["C:/r/rules_primary.txt", "C:/r/rules_secondary.txt"])
    );

    let edited_after =
        json!({ "primary": "a.example\nadded-later.example\n", "secondary": "b.example\n" });
    assert_eq!(
        taken(&mut pure, &paths, &merged_from, &edited_after),
        json!(["C:/r/rules_secondary.txt"]),
        "an edit made after the merge is the user's"
    );

    let gone = json!({ "primary": null, "secondary": "b.example\n" });
    assert_eq!(
        taken(&mut pure, &paths, &merged_from, &gone),
        json!(["C:/r/rules_secondary.txt"])
    );
}

#[test]
fn a_review_that_was_no_merge_takes_nothing() {
    let mut pure = JsLib::pure();
    let paths = json!({ "primary": "C:/r/rules_primary.txt", "secondary": "" });
    let now = json!({ "primary": "a.example\n", "secondary": null });
    assert_eq!(taken(&mut pure, &paths, &Value::Null, &now), json!([]));
    let empty = json!({ "primary": "", "secondary": "" });
    assert_eq!(
        taken(
            &mut pure,
            &paths,
            &empty,
            &json!({ "primary": "", "secondary": null })
        ),
        json!([]),
        "an empty file holds nothing the merge could have taken"
    );
    let unbound = json!({ "primary": "", "secondary": "" });
    assert_eq!(
        taken(
            &mut pure,
            &unbound,
            &json!({ "primary": "a.example\n" }),
            &now
        ),
        json!([])
    );
}
