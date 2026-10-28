//! The promise: a user's rules are lost only when that user deletes them.
//!
//! Each row names one way they could be lost and the test that tries it. A
//! row whose test is renamed or deleted fails here, so the list cannot drift
//! into a claim nothing checks. A new way found is a new row with its test.

#![allow(clippy::panic)]

use std::path::PathBuf;

const EXECUTOR: &str = "core/services/service-runtime/src/production_mutation_executor/tests.rs";

/// (what could lose a rule, file of the test, the test).
const GUARDS: &[(&str, &str, &str)] = &[
    (
        "a client that never read the rules writes its own table",
        EXECUTOR,
        "a_write_that_names_no_base_cannot_drop_a_rule_it_never_saw",
    ),
    (
        "two writers start from the same rules",
        EXECUTOR,
        "of_two_writers_on_one_base_the_second_is_refused_not_applied",
    ),
    (
        "a write waits while another one is applied",
        EXECUTOR,
        "a_write_that_waited_for_the_gate_is_checked_again_inside_it",
    ),
    (
        "the administrator rewrites the baseline, another user resets to it",
        EXECUTOR,
        "baseline_edits_and_resets_never_touch_another_users_own_rules",
    ),
    (
        "a user on the baseline imports one route",
        EXECUTOR,
        "a_one_route_import_on_the_baseline_keeps_its_other_route",
    ),
    (
        "a build that cannot read a rule kind saves an edit",
        EXECUTOR,
        "an_edit_keeps_the_rules_of_a_kind_this_build_cannot_read",
    ),
    (
        "a build that cannot read a rule kind imports files",
        EXECUTOR,
        "a_preset_import_keeps_the_rules_of_a_kind_this_build_cannot_read",
    ),
    (
        "a rule set written by a newer build is read",
        "core/services/service-runtime/src/production_rules_provider.rs",
        "a_book_from_a_newer_build_keeps_its_readable_rules",
    ),
    (
        "a stored rule holds a value no rule set may apply",
        EXECUTOR,
        "a_rule_that_does_not_work_is_kept_until_the_user_deletes_it",
    ),
    (
        "a rules file holds a line no rule set may apply",
        EXECUTOR,
        "an_import_keeps_the_lines_it_cannot_apply",
    ),
    (
        "the service writes a suggestion from the rules it applies",
        EXECUTOR,
        "an_accepted_suggestion_keeps_the_rules_that_do_not_work",
    ),
    (
        "a rules file is merged with the rules in force",
        "core/services/service-runtime/src/production_merge_preview.rs",
        "a_merge_keeps_the_rules_that_do_not_work_from_both_sides",
    ),
    (
        "the rules in force are exported to a file",
        "core/services/service-runtime/src/production_preset_exporter.rs",
        "export_keeps_the_rules_that_do_not_work",
    ),
    (
        "suggestions outgrow their budget",
        "core/domain/src/auto_rule_budget.rs",
        "the_users_own_rules_are_never_evicted",
    ),
    (
        "a checked rule moves to the other route",
        "core/services/service-runtime/src/auto_rules/tests/verify_primary.rs",
        "accepting_moves_the_rule_to_the_other_route_with_its_id_and_origin",
    ),
    (
        "the service is uninstalled",
        "core/services/service-runtime/src/service_lifecycle.rs",
        "uninstall_purge_still_preserves_user_rules",
    ),
    (
        "a user clears their own data",
        "core/services/service-runtime/src/ipc_handlers/principal_data_handlers.rs",
        "the_rules_history_flag_reaches_the_purger_only_when_asked_for",
    ),
    (
        "the signing key is lost twice",
        "core/services/service-runtime/src/activation_coordinator/tests/key_reset.rs",
        "a_second_key_loss_after_an_acknowledged_first_raises_a_new_alert_and_keeps_the_rules",
    ),
    (
        "the integrity marker cannot be read",
        "core/services/service-runtime/src/tamper_bootstrap.rs",
        "an_unreadable_marker_keeps_the_rules",
    ),
    (
        "the window writes over a rules file edited by hand",
        "apps/desktop/launcher/src/user_settings_bridge.rs",
        "a_rules_file_edited_by_hand_is_not_overwritten_unasked",
    ),
    (
        "the window writes over a file it has no record of writing",
        "apps/desktop/launcher/src/user_settings_bridge.rs",
        "a_file_with_no_record_of_our_write_is_not_overwritten_unasked",
    ),
    (
        "the terminal writes over a rules file edited by hand",
        "apps/tui/src/screens/rules/own_settings.rs",
        "a_file_changed_after_this_program_wrote_it_is_edited_by_hand",
    ),
    (
        "the terminal saves a set under a name already taken",
        "apps/tui/src/screens/rules/tests.rs",
        "a_taken_name_gets_a_number_and_is_never_overwritten",
    ),
    (
        "a merge takes a file changed after it was read",
        "core/client-logic/tests/merge_taken.rs",
        "only_a_file_unchanged_since_the_merge_is_taken",
    ),
    (
        "a refused review still counts as a merge",
        "core/client-logic/tests/merge_taken.rs",
        "a_review_that_was_no_merge_takes_nothing",
    ),
    (
        "a merge with the service brings back a deleted rule or drops a kept one",
        "apps/tui/src/screens/rules/tests.rs",
        "a_rule_deleted_after_an_apply_stays_deleted_through_a_merge",
    ),
    (
        "the tray adds a program the rules already hold",
        "core/client-logic/tests/tray_addition_keeps_one_rule.rs",
        "an_override_on_the_same_route_is_the_rule_already_there",
    ),
    (
        "an update rebuilds a table of the service database",
        "core/storage/src/migration/released_databases.rs",
        "every_released_state_database_upgrades_without_losing_a_row",
    ),
];

fn repo_file(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn every_way_to_lose_a_rule_has_a_test_that_tries_it() {
    let missing: Vec<String> = GUARDS
        .iter()
        .filter(|(_, file, test)| !repo_file(file).contains(&format!("fn {test}(")))
        .map(|(threat, file, test)| format!("{threat}: {file} has no `{test}`"))
        .collect();
    assert!(missing.is_empty(), "{missing:#?}");
}
