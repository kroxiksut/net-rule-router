//! The bound rules files against the rules the service enforces (the GUI's
//! `rules.merge-preview` flow behind its "Merge available" banner): what only
//! the files hold, what only the service has, and the rules both touched, one
//! pick each on the merge screen. The confirmed result goes to the ordinary
//! review, and once applied the bound files are written from the rules in
//! force, so file and service agree.
//!
//! Only one side is ever compared with the service: the rules on screen must
//! be the applied ones first, as in the window, whose merge ignores unapplied
//! edits.

use std::path::{Path, PathBuf};

use nrr_client_logic::placeholders::list_summary;
use nrr_client_logic::rebase::{Conflict, ConflictKind, MergeView};
use nrr_client_logic::rules_table::{RuleRow, RuleType, TargetRoute};
use nrr_client_logic::Route;
use nrr_ipc_client::IpcClient;
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{MergePreviewRequest, MergePreviewResponse};
use nrr_shared::merge_dto::{
    ConflictResolutionDto, ConflictRuleDto, ConflictSideDto, MergePolicyDto, MergeResultDto,
    MergedRuleEntryDto,
};
use nrr_shared::rules_json::RuleAction;
use nrr_shared::RouteRole;

use super::apply::{self, Failure, Pending};
use super::merge::Merge;
use super::{ace, files, own_rules_on_screen, own_settings, text, Busy, Mode, Note};
use crate::backend::Reply;
use crate::screens::suggestions::call;
use crate::state::AppState;

/// `F`: read the bound files and ask the service what merging them would do.
/// Always answers `true`: the key was this screen's, whatever came of it.
pub fn start(app: &mut AppState) -> bool {
    if !own_rules_on_screen(app) || super::locked(app) {
        return true;
    }
    let rules = &mut app.rules;
    if !app.link.is_connected() || !rules.table.is_loaded() {
        rules.note = Some(Note::new(text::NOT_LOADED));
        return true;
    }
    if rules.table.is_dirty() {
        rules.note = Some(Note::new(text::FILES_DIRTY));
        return true;
    }
    let (texts, policy) = match read_bound(app) {
        Ok(Some(bound)) => bound,
        Ok(None) => {
            app.rules.note = Some(Note::new(text::FILES_NONE));
            return true;
        }
        Err(note) => {
            app.rules.note = Some(*note);
            return true;
        }
    };
    app.rules.note = None;
    app.rules.busy = Some(Busy::Previewing);
    app.outbox.push(merge_job(texts, policy, Vec::new(), false));
    true
}

/// The text of each bound file, `""` for a route with none, and the merge
/// policy chosen in either client; `None` when no file is bound at all.
fn read_bound(app: &AppState) -> Result<Option<([String; 2], MergePolicyDto)>, Box<Note>> {
    let Some(settings_file) = app.rules.settings_file.as_deref() else {
        return Ok(None);
    };
    let settings = own_settings::read(settings_file).map_err(|error| {
        Box::new(Note::with(
            text::SETTINGS_NOT_WRITTEN,
            vec![("error", error.to_string())],
        ))
    })?;
    let bound = [settings.rules_files.primary, settings.rules_files.secondary];
    if bound.iter().all(String::is_empty) {
        return Ok(None);
    }
    let mut texts = [String::new(), String::new()];
    for (slot, path) in texts.iter_mut().zip(&bound) {
        if path.is_empty() {
            continue;
        }
        let path = Path::new(path);
        match files::read_text(path) {
            Ok(Some(read)) => *slot = read,
            // A file that is gone holds no rules.
            Ok(None) => {}
            Err(error) => return Err(Box::new(super::read_failed(path, error))),
        }
    }
    Ok(Some((
        texts,
        MergePolicyDto::from_slug(&settings.merge_policy),
    )))
}

fn ask(
    client: &dyn IpcClient,
    texts: &[String; 2],
    policy: MergePolicyDto,
    resolutions: Vec<ConflictResolutionDto>,
) -> Result<MergeResultDto, Failure> {
    let request = MergePreviewRequest {
        primary_text: texts[0].clone(),
        secondary_text: texts[1].clone(),
        policy,
        resolutions,
        keep_secondary: Vec::new(),
        include_child_processes: false,
    };
    call::<MergePreviewResponse>(client, IpcOperationName::RulesMergePreview, &request)
        .map(|answer| answer.result)
        .map_err(|error| Failure::of_call(&error.code, &error.message))
}

/// `last`: the picks are in, and the merged rules are wanted; otherwise the
/// first pass, to show.
fn merge_job(
    texts: [String; 2],
    policy: MergePolicyDto,
    resolutions: Vec<ConflictResolutionDto>,
    last: bool,
) -> crate::backend::Job {
    Box::new(move |client: &dyn IpcClient| {
        let answer = ask(client, &texts, policy, resolutions);
        Reply::new(move |app| {
            app.rules.busy = None;
            match answer {
                Err(failure) => failed(app, failure),
                Ok(result) if last => merged(app, &result),
                Ok(result) => previewed(app, texts, &result),
            }
        })
    })
}

fn failed(app: &mut AppState, failure: Failure) {
    app.rules.note = Some(Note::failed(text::FILES_FAILED, failure));
}

fn previewed(app: &mut AppState, texts: [String; 2], result: &MergeResultDto) {
    let view = view_of(result);
    // Nothing to merge: the service says the books are equal, nothing is left
    // to show, or the merged rules are the ones on screen. The files may still
    // spell them differently, and then they are rewritten, as the window does.
    if result.noop || view.is_noop() || merges_to_screen(app, result) {
        // Rules only the service holds are the ones the file lacked.
        let added: Vec<String> = result
            .service_only
            .iter()
            .map(|entry| display_text(&entry.value).into_owned())
            .filter(|value| !value.is_empty())
            .collect();
        converge(app, &added);
        return;
    }
    app.rules.mode = Mode::Merge(Box::new(Merge::files(texts, view)));
}

/// The merge produced exactly the rules on screen (the window's hash compare).
fn merges_to_screen(app: &AppState, result: &MergeResultDto) -> bool {
    !result.merged_rules_json.is_empty()
        && apply::pending_from(&app.rules.table, false, None)
            .is_ok_and(|own| own.rules_json == result.merged_rules_json)
}

/// The files say what the rules in force say: any bound file whose body is
/// spelled otherwise is rewritten from them. A file already in line is left
/// alone and the note says the two match.
fn converge(app: &mut AppState, added: &[String]) {
    let Some(settings_file) = app.rules.settings_file.clone() else {
        return;
    };
    let Ok(settings) = own_settings::read(&settings_file) else {
        app.rules.note = Some(Note::new(text::FILES_MATCH));
        return;
    };
    let bound = [settings.rules_files.primary, settings.rules_files.secondary];
    let exported_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut written = Vec::new();
    for (route, path) in Route::ALL.into_iter().zip(&bound) {
        if path.is_empty() {
            continue;
        }
        let path = Path::new(path);
        let (table, hint) = (&app.rules.table, &app.rules.file_hint);
        if !files::route_differs(path, route, table, hint) {
            continue;
        }
        if let Err((path, error)) = files::write_route(path, route, table, hint, &exported_at) {
            let path = path.display().to_string();
            let note = Note::with(text::WRITE_FAILED, vec![("path", path), ("error", error)]);
            app.rules.note = Some(note);
            break;
        }
        written.push(path.to_path_buf());
    }
    if written.is_empty() {
        if app.rules.note.is_none() {
            app.rules.note = Some(Note::new(text::FILES_MATCH));
        }
        return;
    }
    let _ = own_settings::note_written(&settings_file, &written);
    if app.rules.note.is_none() {
        app.rules.note = Some(if added.is_empty() {
            Note::new(text::FILES_CONVERGED)
        } else {
            let more = app.rules.list_more.clone();
            Note::with(
                text::FILES_CONVERGED_ADDED,
                vec![("rules", list_summary(added, &more))],
            )
        });
    }
}

/// The picks go back to the service, which returns the merged rules; those
/// go to the ordinary review.
pub fn confirm(app: &mut AppState, texts: [String; 2], picks: &[(String, bool)]) {
    let resolutions = picks
        .iter()
        .map(|(key, service)| ConflictResolutionDto {
            identity_key: key.clone(),
            side: if *service {
                ConflictSideDto::Service
            } else {
                ConflictSideDto::File
            },
        })
        .collect();
    // The same policy as the first pass, or conflicts it settled come back open.
    let policy = app
        .rules
        .settings_file
        .as_deref()
        .and_then(|file| own_settings::merge_policy(file).ok())
        .unwrap_or_default();
    app.rules.merged_from = bound_paths(app)
        .into_iter()
        .zip(texts.iter())
        .filter_map(|(path, text)| path.map(|path| (path, text.clone())))
        .collect();
    app.rules.busy = Some(Busy::Previewing);
    app.outbox.push(merge_job(texts, policy, resolutions, true));
}

/// The file bound to each route, primary first.
fn bound_paths(app: &AppState) -> [Option<PathBuf>; 2] {
    let Some(settings) = app
        .rules
        .settings_file
        .as_deref()
        .and_then(|file| own_settings::read(file).ok())
    else {
        return [None, None];
    };
    [settings.rules_files.primary, settings.rules_files.secondary]
        .map(|path| (!path.is_empty()).then(|| PathBuf::from(path)))
}

fn merged(app: &mut AppState, result: &MergeResultDto) {
    let rules_json = result.merged_rules_json.clone();
    if rules_json.is_empty() {
        failed(app, Failure::code("bad-response"));
        return;
    }
    let pending = Pending {
        content_hash: apply::content_hash(&rules_json),
        rules_json,
        correlation_id: apply::correlation_id("tui-merge"),
        admin_baseline: false,
        base_revision: app.rules.base_revision.clone(),
        reset_to_baseline: false,
    };
    app.rules.note = None;
    // The rows on screen are not what this holds: they are read back once it
    // is in force.
    app.rules.reload_after_apply = true;
    app.rules.busy = Some(Busy::Previewing);
    app.outbox.push(apply::preview_job(pending));
}

/// After the rules were read: a bound file that was edited since this program
/// wrote it and says something else than the rules in force is pointed out,
/// where the answer is a key away. Never replaces a note already there.
pub fn check_drift(app: &mut AppState) {
    let rules = &app.rules;
    if rules.baseline
        || rules.note.is_some()
        || rules.table.is_dirty()
        || !matches!(rules.mode, Mode::List)
    {
        return;
    }
    let Some(settings_file) = rules.settings_file.as_deref() else {
        return;
    };
    let Ok(settings) = own_settings::read(settings_file) else {
        return;
    };
    let bound = [settings.rules_files.primary, settings.rules_files.secondary];
    let differs = Route::ALL.into_iter().zip(&bound).any(|(route, path)| {
        if path.is_empty() {
            return false;
        }
        let path = Path::new(path);
        let (table, hint) = (&rules.table, &rules.file_hint);
        own_settings::hand_edited(settings_file, path)
            && files::route_differs(path, route, table, hint)
    });
    if differs {
        app.rules.note = Some(Note::new(text::FILES_DRIFT).then(Note::new(text::FILES_DRIFT_KEY)));
    }
}

fn row(
    value: &str,
    type_slug: &str,
    route: RouteRole,
    enabled: bool,
    action: &RuleAction,
    comment: &str,
) -> RuleRow {
    let rule_type = RuleType::from_slug(type_slug);
    let value = if rule_type.is_hostlike() {
        ace::decode(value)
    } else {
        value.to_owned()
    };
    RuleRow {
        id: String::new(),
        enabled,
        rule_type,
        match_value: value,
        target_route: match action {
            RuleAction::Block => TargetRoute::Block,
            _ => TargetRoute::from_slug(route.slug()),
        },
        verify: matches!(action, RuleAction::VerifyPrimary),
        comment: comment.to_owned(),
        origin: None,
    }
}

fn entry_row(entry: &MergedRuleEntryDto) -> RuleRow {
    row(
        &entry.value,
        &entry.type_slug,
        entry.route,
        entry.enabled,
        &entry.action,
        &entry.comment,
    )
}

fn side_row(value: &str, type_slug: &str, side: &ConflictRuleDto) -> RuleRow {
    row(
        value,
        type_slug,
        side.route,
        side.enabled,
        &side.action,
        &side.comment,
    )
}

/// What the merge screen lists: what only the file holds, what only the
/// service has, the rules both touched. An entry that came out of a conflict
/// is listed there only.
fn view_of(result: &MergeResultDto) -> MergeView {
    let rows = |entries: &[MergedRuleEntryDto]| -> Vec<RuleRow> {
        entries
            .iter()
            .filter(|entry| !entry.was_conflict)
            .map(entry_row)
            .collect()
    };
    MergeView {
        added: rows(&result.file_only),
        changed: Vec::new(),
        removed: rows(&result.service_only),
        conflicts: result
            .conflicts
            .iter()
            .map(|conflict| Conflict {
                key: conflict.identity_key.clone(),
                kind: ConflictKind::ChangedBoth,
                mine: Some(side_row(
                    &conflict.value,
                    &conflict.type_slug,
                    &conflict.file,
                )),
                theirs: Some(side_row(
                    &conflict.value,
                    &conflict.type_slug,
                    &conflict.service,
                )),
            })
            .collect(),
    }
}
