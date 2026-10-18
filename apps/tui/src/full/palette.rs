//! Every style the full-screen renderer draws with. Only the 16 named
//! terminal colours, so the user's theme picks the shades; a background is
//! always set together with its text colour, so neither a light nor a dark
//! terminal can put text on its own colour. Without colour only bold,
//! underline and reverse remain.

use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::BorderType;

use super::RenderOptions;
use crate::view::Tone;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Palette {
    colour: bool,
}

const BOLD: Style = Style::new().add_modifier(Modifier::BOLD);

impl Palette {
    pub const fn new(options: RenderOptions) -> Self {
        Self {
            colour: options.colour,
        }
    }

    /// A segment on the terminal's own background.
    pub fn tone(self, tone: Tone) -> Style {
        if !self.colour {
            return match tone {
                Tone::Plain | Tone::Muted => Style::new(),
                Tone::Accent => BOLD.add_modifier(Modifier::UNDERLINED),
                _ => BOLD,
            };
        }
        match tone {
            Tone::Plain => Style::new(),
            Tone::Strong => BOLD,
            // The GUI's accent fill with its on-accent text.
            Tone::Accent => BOLD.fg(Color::White).bg(Color::Blue),
            Tone::Muted => Style::new().add_modifier(Modifier::DIM),
            // The light variants: the dark ones vanish on a dark background.
            Tone::RoutePrimary => BOLD.fg(Color::LightBlue),
            Tone::RouteSecondary => BOLD.fg(Color::LightMagenta),
            Tone::Selected => BOLD.fg(Color::Black).bg(Color::LightBlue),
            Tone::Good => Style::new().fg(Color::Green),
            Tone::Caution => BOLD.fg(Color::Yellow),
            Tone::Bad => BOLD.fg(Color::Red),
        }
    }

    /// The title and status bars.
    pub fn bar(self) -> Style {
        if self.colour {
            Style::new().fg(Color::White).bg(Color::DarkGray)
        } else {
            Style::new()
        }
    }

    /// A segment on a bar. A state word becomes a badge: its colour on the
    /// grey bar would be too faint to read.
    pub fn on_bar(self, tone: Tone) -> Style {
        if !self.colour {
            return self.tone(tone);
        }
        match tone {
            Tone::Plain | Tone::Muted => Style::new(),
            Tone::Good => BOLD.fg(Color::Black).bg(Color::Green),
            Tone::Caution => BOLD.fg(Color::Black).bg(Color::Yellow),
            Tone::Bad => BOLD.fg(Color::White).bg(Color::Red),
            _ => BOLD,
        }
    }

    /// A panel title. Focus is `>` and inversion, never colour alone.
    pub fn title(self, focused: bool) -> Style {
        if focused {
            Self::focus().add_modifier(Modifier::BOLD)
        } else if self.colour {
            self.tone(Tone::Accent)
        } else {
            BOLD
        }
    }

    /// Whatever holds the focus: inverted, with or without colour.
    pub const fn focus() -> Style {
        Style::new().add_modifier(Modifier::REVERSED)
    }

    pub fn border(self, focused: bool) -> Style {
        if self.colour && focused {
            Style::new().fg(Color::LightBlue)
        } else {
            Style::new()
        }
    }

    pub const fn border_type(self) -> BorderType {
        BorderType::Rounded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Tone; 10] = [
        Tone::Plain,
        Tone::Strong,
        Tone::Accent,
        Tone::Muted,
        Tone::RoutePrimary,
        Tone::RouteSecondary,
        Tone::Selected,
        Tone::Good,
        Tone::Caution,
        Tone::Bad,
    ];
    const STATES: [Tone; 3] = [Tone::Good, Tone::Caution, Tone::Bad];

    fn palette(colour: bool) -> Palette {
        Palette::new(RenderOptions {
            colour,
            ascii: false,
        })
    }

    fn colourless(style: Style) -> bool {
        style.fg.is_none() && style.bg.is_none()
    }

    fn has(style: Style, modifier: Modifier) -> bool {
        style.add_modifier.contains(modifier)
    }

    #[test]
    fn each_tone_with_colour() {
        let p = palette(true);
        let check = |tone, fg: Option<Color>, bg: Option<Color>, bold: bool| {
            let s = p.tone(tone);
            assert_eq!((s.fg, s.bg), (fg, bg), "{tone:?}");
            assert_eq!(has(s, Modifier::BOLD), bold, "{tone:?}");
        };
        check(Tone::Plain, None, None, false);
        check(Tone::Strong, None, None, true);
        check(Tone::Accent, Some(Color::White), Some(Color::Blue), true);
        check(Tone::Muted, None, None, false);
        check(Tone::RoutePrimary, Some(Color::LightBlue), None, true);
        check(Tone::RouteSecondary, Some(Color::LightMagenta), None, true);
        check(
            Tone::Selected,
            Some(Color::Black),
            Some(Color::LightBlue),
            true,
        );
        check(Tone::Good, Some(Color::Green), None, false);
        check(Tone::Caution, Some(Color::Yellow), None, true);
        check(Tone::Bad, Some(Color::Red), None, true);
        assert!(has(p.tone(Tone::Muted), Modifier::DIM));
    }

    #[test]
    fn each_tone_without_colour_keeps_its_marking() {
        let p = palette(false);
        for tone in ALL {
            let s = p.tone(tone);
            assert!(colourless(s), "{tone:?} drew colour: {s:?}");
            assert!(!has(s, Modifier::DIM), "{tone:?} is dimmed without colour");
            let marked = !matches!(tone, Tone::Plain | Tone::Muted);
            assert_eq!(has(s, Modifier::BOLD), marked, "{tone:?}");
            assert!(colourless(p.on_bar(tone)), "{tone:?} on a bar");
        }
        assert!(has(p.tone(Tone::Accent), Modifier::UNDERLINED));
        for focused in [false, true] {
            assert!(colourless(p.title(focused)));
            assert!(colourless(p.border(focused)));
        }
        assert!(colourless(p.bar()));
        assert!(has(Palette::focus(), Modifier::REVERSED));
        assert!(has(p.title(true), Modifier::REVERSED));
    }

    /// A state's hue belongs to its word: nothing else is drawn in green,
    /// yellow or red, and no two meanings share a foreground.
    #[test]
    fn state_and_route_hues_are_their_own() {
        let p = palette(true);
        let state_hues: Vec<Color> = STATES.iter().filter_map(|t| p.tone(*t).fg).collect();
        for tone in ALL.into_iter().filter(|t| !STATES.contains(t)) {
            let s = p.tone(tone);
            for c in [s.fg, s.bg].into_iter().flatten() {
                assert!(!state_hues.contains(&c), "{tone:?} uses a state hue");
            }
        }
        for c in [p.bar().fg, p.bar().bg, p.border(true).fg]
            .into_iter()
            .flatten()
        {
            assert!(!state_hues.contains(&c), "decoration uses a state hue");
        }
        let primary = p.tone(Tone::RoutePrimary).fg;
        let secondary = p.tone(Tone::RouteSecondary).fg;
        assert_ne!(primary, secondary);
        assert!(!state_hues.contains(&primary.unwrap_or(Color::Reset)));
    }

    /// A background never comes without its text colour.
    #[test]
    fn every_background_brings_its_text_colour() {
        let p = palette(true);
        let styles = ALL.iter().flat_map(|t| [p.tone(*t), p.on_bar(*t)]).chain([
            p.bar(),
            p.title(false),
            p.title(true),
        ]);
        for s in styles {
            assert!(s.bg.is_none() || s.fg.is_some(), "{s:?}");
        }
    }

    /// On a bar a state word is a badge of its own colour; the rest take the
    /// bar's colours.
    #[test]
    fn state_words_on_a_bar_are_badges() {
        let p = palette(true);
        for tone in STATES {
            assert_eq!(p.on_bar(tone).bg, p.tone(tone).fg, "{tone:?}");
            assert!(has(p.on_bar(tone), Modifier::BOLD));
        }
        for tone in [Tone::Plain, Tone::Strong, Tone::Muted] {
            assert!(colourless(p.on_bar(tone)), "{tone:?}");
        }
    }
}
