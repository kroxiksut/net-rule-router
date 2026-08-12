//! Cursor-based pagination for log and audit queries.
//!
//! Lives in `nrr-shared` so the IPC client crate can build typed requests
//! without depending on `nrr-diagnostics`. The original module path
//! (`nrr_diagnostics::facade::pagination`) survives as a thin `pub use`
//! re-export of this module.
//!
//! # Cursor stability
//!
//! A cursor encodes the `(created_at_ms, event_id)` of the last item on the
//! previous page.  New events appended after the cursor was issued do not
//! affect the stability of subsequent page reads — the cursor points to a
//! specific position in the ordered stream.
//!
//! # Max page size
//!
//! The service enforces a maximum page size of [`MAX_PAGE_SIZE`] regardless
//! of what the caller requests.

use serde::{Deserialize, Serialize};

/// Maximum entries per page.
pub const MAX_PAGE_SIZE: u32 = 200;
/// Default page size when the caller does not specify one.
pub const DEFAULT_PAGE_SIZE: u32 = 50;

// ── PageCursor ────────────────────────────────────────────────────────────────

/// An opaque pagination cursor encoding `(created_at_ms, event_id)`.
///
/// Callers treat this as an opaque string.  The encoding is stable within a
/// service session but should not be persisted across service restarts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageCursor(String);

impl PageCursor {
    /// Creates a cursor from `(created_at_ms, event_id)`.
    pub fn from_position(created_at_ms: i64, event_id: &str) -> Self {
        Self(format!("{created_at_ms}|{event_id}"))
    }

    /// Returns the raw cursor string (for IPC serialisation).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parses a cursor into `(created_at_ms, event_id)`.
    ///
    /// Returns `None` if the cursor is malformed.
    pub fn parse(&self) -> Option<(i64, &str)> {
        let (ts_str, id) = self.0.split_once('|')?;
        let ts = ts_str.parse::<i64>().ok()?;
        Some((ts, id))
    }
}

impl std::fmt::Display for PageCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ── PageResult ────────────────────────────────────────────────────────────────

/// A single page of query results.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PageResult<T> {
    /// Items on this page.
    pub items: Vec<T>,
    /// Cursor for the next page.  `None` when this is the last page.
    pub next_cursor: Option<PageCursor>,
    /// Total number of items matching the filter (approximate).
    pub total_count: Option<u64>,
    /// Whether the underlying data may be slightly stale.
    pub stale: bool,
}

impl<T> PageResult<T> {
    /// Returns `true` if there are more pages after this one.
    pub fn has_next(&self) -> bool {
        self.next_cursor.is_some()
    }

    /// Returns `true` if this page has no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Constructs a single-page result (no more pages).
    pub fn single_page(items: Vec<T>) -> Self {
        Self {
            items,
            next_cursor: None,
            total_count: None,
            stale: false,
        }
    }

    /// Constructs an empty result.
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            next_cursor: None,
            total_count: Some(0),
            stale: false,
        }
    }
}

// ── Pagination request ────────────────────────────────────────────────────────

/// Parameters for a paginated query.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaginationParams {
    /// Cursor from the previous page.  `None` = first page.
    pub cursor: Option<PageCursor>,
    /// Items per page.  Clamped to `[1, MAX_PAGE_SIZE]`.
    pub page_size: u32,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            cursor: None,
            page_size: DEFAULT_PAGE_SIZE,
        }
    }
}

impl PaginationParams {
    /// Returns the effective page size (clamped to valid range).
    pub fn effective_page_size(&self) -> u32 {
        self.page_size.clamp(1, MAX_PAGE_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip() {
        let c = PageCursor::from_position(1_745_000_000_000, "evt-abc");
        let (ts, id) = c.parse().expect("parse");
        assert_eq!(ts, 1_745_000_000_000);
        assert_eq!(id, "evt-abc");
    }

    #[test]
    fn cursor_display() {
        let c = PageCursor::from_position(1000, "evt-1");
        assert_eq!(c.to_string(), "1000|evt-1");
    }

    #[test]
    fn cursor_malformed_returns_none() {
        let c = PageCursor("not-a-cursor".into());
        assert!(c.parse().is_none());
    }

    #[test]
    fn page_result_has_next() {
        let r: PageResult<u32> = PageResult {
            items: vec![1, 2, 3],
            next_cursor: Some(PageCursor::from_position(100, "x")),
            total_count: None,
            stale: false,
        };
        assert!(r.has_next());
        assert!(!r.is_empty());
    }

    #[test]
    fn page_result_empty() {
        let r: PageResult<u32> = PageResult::empty();
        assert!(!r.has_next());
        assert!(r.is_empty());
        assert_eq!(r.total_count, Some(0));
    }

    #[test]
    fn pagination_params_clamps_page_size() {
        let p = PaginationParams {
            cursor: None,
            page_size: 9999,
        };
        assert_eq!(p.effective_page_size(), MAX_PAGE_SIZE);
        let p2 = PaginationParams {
            cursor: None,
            page_size: 0,
        };
        assert_eq!(p2.effective_page_size(), 1);
    }

    #[test]
    fn pagination_params_default() {
        let p = PaginationParams::default();
        assert_eq!(p.page_size, DEFAULT_PAGE_SIZE);
        assert!(p.cursor.is_none());
    }

    #[test]
    fn cursor_serializes() {
        let c = PageCursor::from_position(500, "adt-001");
        let json = serde_json::to_string(&c).expect("serialize");
        let back: PageCursor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, c);
    }
}
