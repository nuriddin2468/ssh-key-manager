package dev.sshkeymanager.android.ui.theme

import androidx.compose.material3.darkColorScheme
import dev.sshkeymanager.android.core.ProjectColor
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color

// The desktop app's tokens (src/styles/app.css), named as there, mapped onto
// Material 3 roles. Accents are the default section's: teal, with violet as
// the second colour of its gradient.

internal val DarkColors =
    darkColorScheme(
        primary = Color(0xFF5EEAD4), // --accent-1
        onPrimary = Color(0xFF06201E), // --accent-ink
        primaryContainer = Color(0xFF134E4A),
        onPrimaryContainer = Color(0xFF99F6E4), // --accent-text
        secondary = Color(0xFFA78BFA), // --accent-2
        onSecondary = Color(0xFF1E0B47),
        secondaryContainer = Color(0xFF2E1F5E),
        onSecondaryContainer = Color(0xFFDDD6FE),
        background = Color(0xFF0A0D14), // --color-canvas
        onBackground = Color(0xFFF2F4F8), // --color-fg
        surface = Color(0xFF0A0D14), // --color-canvas
        onSurface = Color(0xFFF2F4F8), // --color-fg
        surfaceContainerLowest = Color(0xFF06080D),
        surfaceContainerLow = Color(0xFF0B0F17), // --color-surface
        surfaceContainer = Color(0xFF11141E), // --color-sidebar
        surfaceContainerHigh = Color(0xFF161B27), // --color-popover
        surfaceContainerHighest = Color(0xFF1A1F2E), // --color-dialog-from
        onSurfaceVariant = Color(0xFFA7B0C0), // --color-muted
        outline = Color(0xFF5C667A), // --color-faint
        outlineVariant = Color(0xFF232836), // --color-line on canvas
        error = Color(0xFFFF9B9B), // --color-critical
        onError = Color(0xFF3B0712),
        errorContainer = Color(0xFF4A1219),
        onErrorContainer = Color(0xFFFFBDBD), // --color-critical-strong
    )

internal val LightColors =
    lightColorScheme(
        primary = Color(0xFF0F766E), // --color-ok
        onPrimary = Color(0xFFFFFFFF),
        primaryContainer = Color(0xFFCCFBF1),
        onPrimaryContainer = Color(0xFF115E59), // --accent-text
        secondary = Color(0xFF6D28D9),
        onSecondary = Color(0xFFFFFFFF),
        secondaryContainer = Color(0xFFEDE9FE),
        onSecondaryContainer = Color(0xFF4C1D95),
        background = Color(0xFFECEEF2), // --color-canvas
        onBackground = Color(0xFF0F1420), // --color-fg
        surface = Color(0xFFECEEF2), // --color-canvas
        onSurface = Color(0xFF0F1420), // --color-fg
        surfaceContainerLowest = Color(0xFFFFFFFF),
        surfaceContainerLow = Color(0xFFF6F7F9), // --color-surface
        surfaceContainer = Color(0xFFFFFFFF), // --color-card
        surfaceContainerHigh = Color(0xFFFFFFFF), // --color-popover
        surfaceContainerHighest = Color(0xFFF8F9FB), // --color-dialog-to
        onSurfaceVariant = Color(0xFF4B5567), // --color-muted
        outline = Color(0xFF6B7484), // --color-faint
        outlineVariant = Color(0xFFD4D7DD), // --color-line on canvas
        error = Color(0xFFB42318), // --color-critical
        onError = Color(0xFFFFFFFF),
        errorContainer = Color(0xFFFEE4E2),
        onErrorContainer = Color(0xFF912018), // --color-critical-strong
    )

/** The colours of a password's strength, 1 to 4 (--color-strength-*). */
data class StrengthColors(val weak: Color, val fair: Color, val good: Color, val strong: Color) {
    /** The colour of a zxcvbn score: 0 and 1 are both weak. */
    fun of(score: Int): Color =
        when {
            score <= 1 -> weak
            score == 2 -> fair
            score == 3 -> good
            else -> strong
        }
}

internal val DarkStrength =
    StrengthColors(
        weak = Color(0xFFFF6B6B),
        fair = Color(0xFFFFB547),
        good = Color(0xFF5EEAD4),
        strong = Color(0xFF14B8A6),
    )

internal val LightStrength =
    StrengthColors(
        weak = Color(0xFFB42318),
        fair = Color(0xFF93500A),
        good = Color(0xFF0F766E),
        strong = Color(0xFF115E59),
    )

/**
 * A project's colour, from the desktop app's tile tones (Tile.tsx): the
 * light end on the dark theme, the deep end on the light one. Only for dots
 * beside the project's name, never for text.
 */
fun ProjectColor.tone(dark: Boolean): Color {
    val (light, deep) =
        when (this) {
            ProjectColor.TEAL -> 0xFF5EEAD4 to 0xFF0D9488
            ProjectColor.BLUE -> 0xFF7DD3FC to 0xFF2563EB
            ProjectColor.INDIGO -> 0xFFA5B4FC to 0xFF4F46E5
            ProjectColor.VIOLET -> 0xFFC4B5FD to 0xFF7C3AED
            ProjectColor.PINK -> 0xFFF9A8D4 to 0xFFDB2777
            ProjectColor.RED -> 0xFFFDA4AF to 0xFFE11D48
            ProjectColor.ORANGE -> 0xFFFDBA74 to 0xFFEA580C
            ProjectColor.AMBER -> 0xFFFCD34D to 0xFFD97706
            ProjectColor.GREEN -> 0xFF86EFAC to 0xFF16A34A
            ProjectColor.SLATE -> 0xFFCBD5E1 to 0xFF475569
        }
    return Color(if (dark) light else deep)
}
