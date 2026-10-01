//! Windows implementation of [`SystemLocalePort`].

use nrr_platform_api::system_locale::SystemLocalePort;

/// Asks kernel32 directly: the display language first, because that is what
/// the user reads the system in. The regional-format locale is offered only
/// when the display language cannot be read at all — it never substitutes
/// for a display language this build simply has no translation for.
///
/// The previous probe spawned PowerShell for the same answer on every GUI and
/// tray start, before the window existed.
pub struct WindowsSystemLocale;

impl SystemLocalePort for WindowsSystemLocale {
    fn ui_language_candidates(&self) -> Vec<String> {
        #[cfg(target_os = "windows")]
        {
            display_language()
                .or_else(regional_locale)
                .into_iter()
                .collect()
        }
        #[cfg(not(target_os = "windows"))]
        {
            Vec::new()
        }
    }
}

/// `LOCALE_NAME_MAX_LENGTH`, terminator included.
#[cfg(target_os = "windows")]
const LOCALE_NAME_CAPACITY: usize = 85;

/// The user's display language, the one `CultureInfo.CurrentUICulture` reports.
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn display_language() -> Option<String> {
    use windows::Win32::Globalization::{GetUserDefaultUILanguage, LCIDToLocaleName};

    // SAFETY: no arguments; returns a LANGID by value.
    let lang_id = unsafe { GetUserDefaultUILanguage() };
    if lang_id == 0 {
        return None;
    }
    let mut buffer = [0u16; LOCALE_NAME_CAPACITY];
    // SAFETY: the slice is the destination and its length is the capacity the
    // binding passes; a LANGID is a valid LCID with the default sort order.
    let written = unsafe { LCIDToLocaleName(u32::from(lang_id), Some(buffer.as_mut_slice()), 0) };
    locale_name(&buffer, written)
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn regional_locale() -> Option<String> {
    use windows::Win32::Globalization::GetUserDefaultLocaleName;

    let mut buffer = [0u16; LOCALE_NAME_CAPACITY];
    // SAFETY: the slice is the destination and its length is the capacity the
    // binding passes.
    let written = unsafe { GetUserDefaultLocaleName(&mut buffer) };
    locale_name(&buffer, written)
}

/// Both calls return the character count including the terminator, 0 on failure.
#[cfg(target_os = "windows")]
fn locale_name(buffer: &[u16], written: i32) -> Option<String> {
    let chars = usize::try_from(written)
        .ok()?
        .checked_sub(1)?
        .min(buffer.len());
    let name = String::from_utf16_lossy(&buffer[..chars]);
    (!name.trim().is_empty()).then_some(name)
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn the_probe_names_a_language_or_admits_it_cannot() {
        // Every supported Windows has a display language; what matters is that
        // the answer is a tag, not a sentence or a stray terminator, and that
        // the regional-format fallback never rides along beside it.
        let candidates = WindowsSystemLocale.ui_language_candidates();
        assert!(candidates.len() <= 1);
        if let Some(tag) = candidates.first() {
            assert!(!tag.contains('\0'));
            assert!(tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        }
    }

    #[test]
    fn a_failed_call_is_not_a_name() {
        assert_eq!(locale_name(&[0u16; 4], 0), None);
        assert_eq!(locale_name(&[0u16; 4], 1), None);
        let tag: Vec<u16> = "ru-RU\0".encode_utf16().collect();
        assert_eq!(locale_name(&tag, 6), Some("ru-RU".to_string()));
    }
}
