//! Pasted text. A terminal that reports a paste delivers it as one event; one
//! that does not (the Windows console) delivers keystrokes, whose Enters would
//! run as commands, so there a fast burst of plain keys holding an Enter before
//! its end, typed into a text field, is taken as a paste.

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// Most characters a paste hands to a screen; the rest is dropped.
pub const MAX_PASTE_CHARS: usize = 16 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Input {
    Key(KeyEvent),
    Paste(String),
}

/// What a screen does with typed text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextTarget {
    /// Not taking text: a paste is dropped.
    None,
    /// One line: a paste ends at its first line break.
    Line,
    /// Lines: a line break is an Enter.
    Lines,
}

/// The events read in one go, as keys and pastes. `detect_bursts` is set only
/// where the terminal cannot report a paste and a text field has the focus.
pub fn group(events: Vec<Event>, detect_bursts: bool) -> Vec<Input> {
    let mut out = Vec::new();
    let mut burst: Vec<KeyEvent> = Vec::new();
    for event in events {
        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => burst.push(key),
            Event::Paste(text) => {
                flush(&mut out, &mut burst, detect_bursts);
                out.push(Input::Paste(text));
            }
            _ => {}
        }
    }
    flush(&mut out, &mut burst, detect_bursts);
    out
}

/// Text as typed: a Tab or an AltGr character (reported as Ctrl+Alt) counts.
fn plain(key: &KeyEvent) -> bool {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    ctrl == alt && matches!(key.code, KeyCode::Char(_) | KeyCode::Enter | KeyCode::Tab)
}

fn flush(out: &mut Vec<Input>, burst: &mut Vec<KeyEvent>, detect: bool) {
    let enters = burst.iter().filter(|k| k.code == KeyCode::Enter).count();
    let enter_before_end = burst
        .iter()
        .position(|k| k.code == KeyCode::Enter)
        .is_some_and(|at| at + 1 < burst.len());
    // More than a person types between two reads, however slow the terminal.
    let fast = burst.len() >= 8 || enters >= 2;
    if detect && fast && enter_before_end && burst.iter().all(plain) {
        let text = burst
            .drain(..)
            .map(|k| match k.code {
                KeyCode::Char(c) => c,
                KeyCode::Tab => ' ',
                _ => '\n',
            })
            .collect();
        out.push(Input::Paste(text));
    } else {
        out.extend(burst.drain(..).map(Input::Key));
    }
}

/// The keys a paste types into a field, or none when the screen takes no text.
pub fn keys_for(text: &str, target: TextTarget) -> Vec<KeyEvent> {
    if target == TextTarget::None {
        return Vec::new();
    }
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let text = match target {
        TextTarget::Line => text.split('\n').next().unwrap_or_default(),
        _ => text.as_str(),
    };
    text.chars()
        .take(MAX_PASTE_CHARS)
        .filter_map(|c| match c {
            '\n' => Some(KeyCode::Enter),
            c if c.is_control() => None,
            c => Some(KeyCode::Char(c)),
        })
        .map(|code| KeyEvent::new(code, KeyModifiers::NONE))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(c: char) -> Event {
        Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
    }

    fn enter() -> Event {
        Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
    }

    #[test]
    fn a_burst_with_an_enter_inside_is_one_paste() {
        let got = group(vec![key('a'), enter(), key('b'), enter()], true);
        assert_eq!(got, vec![Input::Paste("a\nb\n".into())]);
    }

    #[test]
    fn a_burst_with_a_tab_or_altgr_is_still_one_paste() {
        let tab = Event::Key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        let altgr = Event::Key(KeyEvent::new(
            KeyCode::Char('@'),
            KeyModifiers::CONTROL | KeyModifiers::ALT,
        ));
        let got = group(vec![tab, key('a'), enter(), altgr, enter()], true);
        assert_eq!(got, vec![Input::Paste(" a\n@\n".into())]);
    }

    #[test]
    fn typing_stays_keys() {
        assert_eq!(group(vec![key('d')], true).len(), 1);
        assert_eq!(group(vec![key('a'), key('b'), enter()], true).len(), 3);
        assert!(matches!(
            group(vec![key('a'), key('b')], true)[0],
            Input::Key(_)
        ));
        let fast = vec![key('a'), key('b'), key('c'), enter(), key('d')];
        assert_eq!(group(fast, true).len(), 5);
    }

    #[test]
    fn no_burst_is_taken_where_detection_is_off() {
        let events = vec![key('a'), enter(), key('b'), enter()];
        let got = group(events, false);
        assert_eq!(got.len(), 4);
        assert!(got.iter().all(|i| matches!(i, Input::Key(_))));
    }

    #[test]
    fn a_reported_paste_stays_one_event() {
        for detect in [false, true] {
            let got = group(vec![Event::Paste("x\ny".into())], detect);
            assert_eq!(got, vec![Input::Paste("x\ny".into())]);
        }
    }

    #[test]
    fn a_line_field_takes_the_first_line_without_control_characters() {
        let keys = keys_for("ab\u{1b}c\nd", TextTarget::Line);
        let codes: Vec<_> = keys.iter().map(|k| k.code).collect();
        assert_eq!(
            codes,
            vec![KeyCode::Char('a'), KeyCode::Char('b'), KeyCode::Char('c')]
        );
    }

    #[test]
    fn a_lines_field_takes_breaks_as_enters_and_a_bound() {
        let keys = keys_for("a\r\nb", TextTarget::Lines);
        assert_eq!(keys[1].code, KeyCode::Enter);
        assert_eq!(keys.len(), 3);
        let long = "x".repeat(MAX_PASTE_CHARS + 5);
        assert_eq!(keys_for(&long, TextTarget::Line).len(), MAX_PASTE_CHARS);
    }

    #[test]
    fn nothing_is_typed_where_there_is_no_field() {
        assert!(keys_for("a\nb", TextTarget::None).is_empty());
    }
}
