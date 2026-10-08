//! A numbered list of answers. Both modes read the same lines: the full-screen
//! picture moves a `>` marker over them, line mode answers with the number.

use crossterm::event::KeyCode;

use crate::view::{Segment, ViewLine};

/// The answers as lines, `cursor` marked with `>` and in bold, so the choice
/// is visible without colour.
pub fn lines(items: &[String], cursor: Option<usize>) -> Vec<ViewLine> {
    items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let text = format!("{}. {item}", i + 1);
            if cursor == Some(i) {
                ViewLine::new(vec![Segment::strong(format!("> {text}"))])
            } else {
                ViewLine::text(format!("  {text}"))
            }
        })
        .collect()
}

/// The answer a typed line names: its number among `count`, zero-based.
pub fn pick(answer: &str, count: usize) -> Option<usize> {
    answer
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|n| (1..=count).contains(n))
        .map(|n| n - 1)
}

/// The cursor after Up or Down; other keys leave it. Stops at the ends rather
/// than wrapping, so a screen reader's "top" and "bottom" stay where they are.
pub fn moved(cursor: usize, count: usize, key: KeyCode) -> Option<usize> {
    match key {
        KeyCode::Up => Some(cursor.saturating_sub(1)),
        KeyCode::Down => Some((cursor + 1).min(count.saturating_sub(1))),
        KeyCode::Home => Some(0),
        KeyCode::End => Some(count.saturating_sub(1)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_one_based_and_bounded() {
        assert_eq!(pick("1", 3), Some(0));
        assert_eq!(pick(" 3 ", 3), Some(2));
        assert_eq!(pick("0", 3), None);
        assert_eq!(pick("4", 3), None);
        assert_eq!(pick("a", 3), None);
    }

    #[test]
    fn the_cursor_stops_at_the_ends() {
        assert_eq!(moved(0, 3, KeyCode::Up), Some(0));
        assert_eq!(moved(2, 3, KeyCode::Down), Some(2));
        assert_eq!(moved(1, 3, KeyCode::Char('x')), None);
    }

    #[test]
    fn the_current_answer_is_marked_in_text() {
        let items = vec!["One".to_string(), "Two".to_string()];
        let lines = lines(&items, Some(1));
        assert_eq!(lines[0].plain_text(), "  1. One");
        assert_eq!(lines[1].plain_text(), "> 2. Two");
    }
}
