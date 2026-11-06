//! The quick search window's system-wide shortcut, as text: what the user
//! picked in Settings, checked and written one way only.
//!
//! The text is an accelerator `tauri-plugin-global-shortcut` reads: the
//! modifiers in the order `Ctrl`, `Alt`, `Shift`, `Super` (⌘ on macOS, the
//! Windows key elsewhere), then the key as a `KeyboardEvent.code` names it
//! (`Space`, `KeyK`, `Digit1`, `F5`).

use std::str::FromStr;

use tauri_plugin_global_shortcut::{Modifiers, Shortcut};

use crate::error::{AppError, AppResult};

/// ⇧⌘Space on macOS, Ctrl+Shift+Space elsewhere. Spotlight has ⌘Space and
/// the input sources ⌃Space; this one is free on a fresh system.
pub const DEFAULT: &str = if cfg!(target_os = "macos") {
    "Shift+Super+Space"
} else {
    "Ctrl+Shift+Space"
};

/// A shortcut needs one of these: with Shift alone (or nothing) it would
/// take a key the user types everywhere.
const COMMAND_KEYS: Modifiers = Modifiers::CONTROL
    .union(Modifiers::ALT)
    .union(Modifiers::SUPER);

/// Reads an accelerator, refusing one without Ctrl, Alt or ⌘ / the Windows
/// key, and returns it with the text it is saved as.
pub fn parse(text: &str) -> AppResult<(Shortcut, String)> {
    let shortcut = Shortcut::from_str(text.trim())
        .map_err(|e| AppError::invalid(format!("not a shortcut: {e}")))?;
    if !shortcut.mods.intersects(COMMAND_KEYS) {
        return Err(AppError::invalid(
            "a shortcut needs Ctrl, Alt or the Command / Windows key",
        ));
    }
    let text = canonical(&shortcut);
    Ok((shortcut, text))
}

/// The text a shortcut is saved and shown as.
fn canonical(shortcut: &Shortcut) -> String {
    let mut parts: Vec<String> = [
        (Modifiers::CONTROL, "Ctrl"),
        (Modifiers::ALT, "Alt"),
        (Modifiers::SHIFT, "Shift"),
        (Modifiers::SUPER, "Super"),
    ]
    .into_iter()
    .filter(|(modifier, _)| shortcut.mods.contains(*modifier))
    .map(|(_, name)| name.to_owned())
    .collect();
    parts.push(shortcut.key.to_string());
    parts.join("+")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_a_valid_shortcut() {
        let (_, text) = parse(DEFAULT).unwrap();
        assert_eq!(text, DEFAULT);
    }

    #[test]
    fn shortcuts_are_saved_in_one_order_and_spelling() {
        assert_eq!(parse("super+shift+KeyK").unwrap().1, "Shift+Super+KeyK");
        assert_eq!(parse(" Alt+Ctrl+Digit1 ").unwrap().1, "Ctrl+Alt+Digit1");
        assert_eq!(parse("Ctrl+Shift+space").unwrap().1, "Ctrl+Shift+Space");
        assert_eq!(parse("Command+F5").unwrap().1, "Super+F5");
    }

    #[test]
    fn a_shortcut_needs_a_command_key() {
        for text in ["Space", "Shift+KeyA", "KeyQ", "F5"] {
            assert!(parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn nonsense_is_refused() {
        for text in ["", "Ctrl+", "Ctrl+Shift", "Ctrl+KeyA+KeyB", "Ctrl+Sparkle"] {
            assert!(parse(text).is_err(), "{text}");
        }
    }
}
