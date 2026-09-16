//! Filters in, DTOs out, and the pagination that carries them.
//!
//! The position functions are the load-bearing part: a page cursor is a
//! position, not an index, so a record arriving mid-scroll cannot shift a page.

use super::*;

// ── Filter mapping ───────────────────────────────────────────────────────────

pub(super) fn log_filter_to_query(filter: &LogEntryFilter) -> LogQueryFilter {
    let mut q = LogQueryFilter::new();
    if let Some(v) = filter.from_ms {
        q = q.from_ms(v);
    }
    if let Some(v) = filter.to_ms {
        q = q.to_ms(v);
    }
    if let Some(level_str) = filter.level_min.as_deref() {
        if let Some(lvl) = level_from_str(level_str) {
            q = q.level_min(lvl);
        }
    }
    if let Some(cat_str) = filter.category.as_deref() {
        if let Some(cat) = category_from_str(cat_str) {
            q = q.category(cat);
        }
    }
    if let Some(kind) = filter.kind.clone() {
        q = q.kind(kind);
    }
    if let Some(id) = filter.decision_id.clone() {
        q = q.decision_id(id);
    }
    if let Some(id) = filter.revision_id.clone() {
        q = q.revision_id(id);
    }
    q
}

pub(super) fn audit_filter_to_query(filter: &AuditEntryFilter) -> AuditQueryFilter {
    // `AuditQueryFilter` defaults to "no filter"; populate via
    // direct field assignment because the public builder methods
    // don't cover every column.
    let mut q = AuditQueryFilter::new();
    q.from_ms = filter.from_ms;
    q.to_ms = filter.to_ms;
    q.kind = filter.kind.clone();
    q.revision_id = filter.revision_id.clone();
    q
}

// ── DTO mapping ──────────────────────────────────────────────────────────────

pub(super) fn log_event_to_dto(event: &LogEvent) -> LogEntryDto {
    // The localised message key follows the `diag.<category>.<kind>.summary`
    // convention from `nrr_diagnostics::reason::ReasonCodeMeta::ui_key`.
    // We compute it inline rather than looking up the meta table so
    // the projection is total even for kinds without an explicit meta
    // entry (the GUI's `tr(...)` falls back gracefully on missing
    // keys).
    let message_key = format!("diag.{}.{}.summary", event.category.as_str(), event.kind);
    let mut correlation_summary = Vec::new();
    if let Some(id) = event.correlation.decision_id.as_deref() {
        correlation_summary.push(format!("decision:{id}"));
    }
    if let Some(id) = event.correlation.revision_id.as_deref() {
        correlation_summary.push(format!("revision:{id}"));
    }
    LogEntryDto {
        event_id: event.event_id.clone(),
        created_at: event.created_at,
        level: event.level.as_str().to_string(),
        category: event.category.as_str().to_string(),
        kind: event.kind.clone(),
        message_key,
        // The writer already redacted the payload down to the active mode's
        // ceiling, so whatever is left here is safe to show as written.
        message: event
            .payload
            .as_ref()
            .and_then(|payload| payload.get("message"))
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        // Payload-detail surfacing requires diagnostic
        // mode plus a structured payload column on `LogEvent` that
        // doesn't exist on the wire today. Leave `false` until that
        // schema bump lands.
        has_payload: false,
        correlation_summary,
    }
}

/// Whether a principal-scoped reader may see `event`.
///
/// Two things are visible to everyone: what the SERVICE did on its own behalf
/// (starts, applies, retention passes — facts about the machine, not about a
/// person) and events with no actor at all, which are the same thing written
/// before the actor was recorded. Everything else belongs to whoever performed
/// it, and only they — or an administrator, who never reaches this function —
/// get to read it back.
pub(super) fn audit_event_is_visible_to(event: &AuditEvent, my_actor_hash: Option<&str>) -> bool {
    if event.actor_kind == nrr_diagnostics::audit::ActorKind::Service.as_str() {
        return true;
    }
    match (event.actor_id_hash.as_deref(), my_actor_hash) {
        (None, _) => true,
        (Some(theirs), Some(mine)) => theirs == mine,
        (Some(_), None) => false,
    }
}

pub(super) fn audit_event_to_dto(event: &AuditEvent) -> AuditEntryDto {
    AuditEntryDto {
        event_id: event.event_id.clone(),
        seq: event.seq,
        kind: event.kind.clone(),
        created_at: event.created_at,
        result: event.result.clone(),
        reason_code: event.reason_code.clone(),
        revision_id: event.revision_id.clone(),
        has_payload_summary: event.payload_summary_json.is_some(),
    }
}

pub(super) fn alert_to_dto(alert: &SecurityAlert) -> SecurityAlertDto {
    SecurityAlertDto {
        alert_id: alert.alert_id.clone(),
        kind: alert.kind.clone(),
        state: alert.state.as_str().to_string(),
        created_at: alert.created_at,
        updated_at: alert.updated_at,
        reason_code: alert.reason_code.clone(),
        raised_file: alert.raised_file.clone(),
        requires_action: alert.requires_action(),
    }
}

// ── Pagination helpers ───────────────────────────────────────────────────────

/// Position extractor for the cursor encoding. `T` is one of the DTO
/// types; the returned `(created_at_ms, event_id)` pair must produce
/// a stable lexicographic cursor across page boundaries.
type PositionFn<T> = fn(&T) -> (i64, &str);

pub(super) fn log_entry_position(item: &LogEntryDto) -> (i64, &str) {
    (item.created_at, item.event_id.as_str())
}

pub(super) fn audit_entry_position(item: &AuditEntryDto) -> (i64, &str) {
    (item.created_at, item.event_id.as_str())
}

/// Slice the (already-sorted) `items` list by the optional cursor +
/// `page_size`. Returns the page and an Option-cursor pointing at the
/// last returned item — caller treats it as opaque.
///
/// Inputs MUST already be sorted ascending by `(created_at, event_id)`.
/// Number of adjacent items sharing a `(created_at, event_id)` position, or
/// `None` when every position is distinct.
pub(super) fn duplicate_positions<T>(items: &[T], position: PositionFn<T>) -> Option<u64> {
    let count = items
        .windows(2)
        .filter(|pair| position(&pair[0]) == position(&pair[1]))
        .count() as u64;
    (count > 0).then_some(count)
}

pub(super) fn paginate<T>(
    items: Vec<T>,
    params: &PaginationParams,
    position: PositionFn<T>,
) -> PageResult<T> {
    let total = items.len() as u64;
    let cursor_pos: Option<(i64, String)> = params
        .cursor
        .as_ref()
        .and_then(|c| c.parse().map(|(ts, id)| (ts, id.to_string())));
    // Resume strictly after the cursor's position. This is only sound because
    // every event id is unique: when ids repeated (the old call-site-constant
    // id), a page edge inside a run of identical pairs dropped the rest of that
    // run — silently. Ids are unique at the source now; the loop below turns a
    // regression there into a visible line instead of missing evidence.
    if let Some(duplicates) = duplicate_positions(&items, position) {
        tracing::warn!(
            target: "nrr::diagnostics",
            duplicates,
            "log page positions are not unique — paging can drop entries"
        );
    }
    let start_index = match cursor_pos {
        None => 0,
        Some((cts, cid)) => items
            .iter()
            .position(|item| {
                let (ts, id) = position(item);
                (ts, id) > (cts, cid.as_str())
            })
            .unwrap_or(items.len()),
    };
    let page_size = params.effective_page_size() as usize;
    let end_index = (start_index + page_size).min(items.len());
    // SAFETY: build the page via owned iteration. The cursor needs an
    // immutable reference to the LAST item BEFORE we move items into
    // the result page, so capture the position pair first.
    let next_cursor = if end_index < items.len() && end_index > start_index {
        let last = &items[end_index - 1];
        let (ts, id) = position(last);
        Some(PageCursor::from_position(ts, id))
    } else {
        None
    };
    let page_items: Vec<T> = items
        .into_iter()
        .skip(start_index)
        .take(page_size)
        .collect();
    PageResult {
        items: page_items,
        next_cursor,
        total_count: Some(total),
        stale: false,
    }
}
