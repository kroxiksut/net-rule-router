# Accessibility

**English** · [Русский](../ru/accessibility.md)

NetRuleRouter is meant to be used without a mouse, with a screen reader, with
large text and in high contrast. This page lists what the application window
offers today and what does not work yet. The terminal interface has its own
accessibility section: see [`nrr-tui`](tui.md#accessibility).

The settings below live in **Settings → Application**, in the *Appearance* and
*Accessibility* groups. Each one takes effect at once and is remembered for
your account on this computer.

## Working from the keyboard

`Tab` and `Shift+Tab` move between the controls of a screen or a dialog, and
the control in focus is outlined. `Space` or `Enter` presses a button or ticks
a box; the arrow keys move within a list and change the choice of a drop-down.

| Keys | What they do |
|------|--------------|
| `Ctrl+1` | Interfaces and routes |
| `Ctrl+2` | Rules |
| `Ctrl+3` | Diagnostics |
| `Ctrl+4` | Logs |
| `Ctrl+,` | Settings |
| `Ctrl+O` | Load a rule list |
| `F5` | Refresh the list of network adapters |
| `Ctrl+Enter` | Confirm the open dialog: add or save a rule, finish a step |
| `Esc` or `Ctrl+W` | Close the open dialog |
| `F1` | About |
| `Ctrl+Shift+L` | Licence |
| `Ctrl+Shift+O` | Open the logs folder |
| `Ctrl+U` | Check for updates (once the first release is out) |

## Themes and high contrast

**Theme** offers *Light*, *Dark*, *System* (follows the Windows setting) and
*High contrast*, a theme of its own with strong colours and clear borders for
low vision. The *High contrast* box in the *Accessibility* group switches to it
and back in one step. States are never shown by colour alone: every status has
a word, and the main and the additional connection are named, not just
coloured.

## Text size and font

**UI scale** makes all text of the window larger or smaller, from 80% to 300%
in steps of 5%, with the slider or its `-` and `+` buttons; screens wrap
longer text onto more lines rather than cutting it off. **System font** picks the
typeface: the system default, Segoe UI, Arial, Tahoma or Verdana.

## Screen readers

Buttons, fields, lists and status areas carry names and roles that screen
readers announce, such as Narrator or NVDA on Windows. Tooltips are on by
default (**Enable tooltips**), and they only repeat what the screen already
says, so turning them off loses nothing. For a screen reader in a terminal,
use the line mode of the terminal interface, `nrr-tui --plain`.

## Not there yet

- The window has not yet been checked end to end with a screen reader, nor
  every dialog from the keyboard alone or at the largest text sizes. If something cannot be reached or is
  read badly, please [report it](https://github.com/kroxiksut/net-rule-router/issues):
  it counts as a bug.
- Turning on high contrast in Windows does not switch the app's theme by
  itself: choose *High contrast* in Settings.
- A thicker focus outline and shorter labels are planned; see the
  [roadmap](../../ROADMAP.md).
- The fonts offered are the ones common on Windows. Where one is not
  installed, the system font is used instead.
