package dev.sshkeymanager.android.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// The system font, as the desktop app uses the system's; secrets in
// monospace, as its --font-mono. Corners as its cards and fields (8-16 px).

private val AppShapes =
    Shapes(
        extraSmall = RoundedCornerShape(6.dp),
        small = RoundedCornerShape(8.dp),
        medium = RoundedCornerShape(12.dp),
        large = RoundedCornerShape(16.dp),
        extraLarge = RoundedCornerShape(24.dp),
    )

/** A secret shown to be read or retyped: a password, a key, a code. */
val SecretTextStyle =
    TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Medium,
        fontSize = 20.sp,
        lineHeight = 28.sp,
        letterSpacing = 0.5.sp,
    )

private val LocalStrengthColors = staticCompositionLocalOf { DarkStrength }
private val LocalDark = staticCompositionLocalOf { true }

/** The app's colours beyond Material's roles. */
object AppTheme {
    val strength: StrengthColors
        @Composable @ReadOnlyComposable
        get() = LocalStrengthColors.current

    /** Whether the dark scheme is on. */
    val dark: Boolean
        @Composable @ReadOnlyComposable
        get() = LocalDark.current
}

/**
 * The app's theme: light or dark as the system is. The app keeps its own
 * colours instead of the wallpaper's, so it looks like the desktop app.
 */
@Composable
fun SshkmTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    CompositionLocalProvider(
        LocalStrengthColors provides if (darkTheme) DarkStrength else LightStrength,
        LocalDark provides darkTheme,
    ) {
        MaterialTheme(
            colorScheme = if (darkTheme) DarkColors else LightColors,
            typography = Typography(),
            shapes = AppShapes,
            content = content,
        )
    }
}
