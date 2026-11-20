package dev.sshkeymanager.android.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.ui.theme.SecretTextStyle

/** A read-only field of an entry: its label, its value and a copy button. */
@Composable
fun FieldRow(
    label: String,
    value: String,
    onCopy: (() -> Unit)?,
    modifier: Modifier = Modifier,
    valueStyle: androidx.compose.ui.text.TextStyle = MaterialTheme.typography.bodyLarge,
    /** What a screen reader says instead of `value`: "Hidden" for dots, a code digit by digit. */
    valueDescription: String? = null,
    trailing: @Composable () -> Unit = {},
) {
    Row(
        modifier = modifier.fillMaxWidth().heightIn(min = 56.dp).padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier.weight(1f).semantics(mergeDescendants = true) {},
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(
                value,
                style = valueStyle,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = if (valueDescription != null) Modifier.semantics { contentDescription = valueDescription } else Modifier,
            )
        }
        trailing()
        if (onCopy != null) CopyButton(label = label, onCopy = onCopy)
    }
}

@Composable
fun CopyButton(label: String, onCopy: () -> Unit) {
    IconButton(onClick = onCopy) {
        Icon(painterResource(R.drawable.ic_content_copy), contentDescription = stringResource(R.string.action_copy, label))
    }
}

/**
 * The password of an entry: dots until the user shows it (`shown` holds it
 * only then), a show/hide button and a copy button.
 */
@Composable
fun SecretRow(
    label: String,
    shown: String?,
    onToggle: () -> Unit,
    onCopy: () -> Unit,
) {
    FieldRow(
        label = label,
        value = shown ?: "••••••••••••",
        onCopy = onCopy,
        valueStyle = if (shown != null) SecretTextStyle.copy(fontSize = MaterialTheme.typography.bodyLarge.fontSize) else MaterialTheme.typography.bodyLarge,
        valueDescription = if (shown == null) stringResource(R.string.state_hidden) else null,
        trailing = {
            IconButton(onClick = onToggle) {
                Icon(
                    painter = painterResource(if (shown != null) R.drawable.ic_visibility_off else R.drawable.ic_visibility),
                    contentDescription = stringResource(if (shown != null) R.string.action_hide else R.string.action_show, label),
                )
            }
        },
    )
}

/** `492 039`, `1234 5678`: codes are easier to read and type in halves (as on computers). */
fun formatOtp(code: String): String {
    if (code.length < 6) return code
    val half = (code.length + 1) / 2
    return code.substring(0, half) + " " + code.substring(half)
}

/** The period of a code that is valid `validFor` more seconds: 30 almost everywhere, 60 at a few sites. */
fun otpPeriod(validFor: Int): Int = if (validFor > 30) 60 else 30

/** The current 2FA code with a ring that empties until the next one. */
@Composable
fun OtpRow(
    label: String,
    code: String?,
    remaining: Int,
    period: Int,
    unreadable: Boolean,
    onCopy: () -> Unit,
) {
    val ending = remaining <= 5
    FieldRow(
        label = label,
        value =
            when {
                unreadable -> stringResource(R.string.otp_unreadable)
                code == null -> "— —"
                else -> formatOtp(code)
            },
        valueStyle = if (code != null && !unreadable) SecretTextStyle else MaterialTheme.typography.bodyLarge,
        valueDescription = code?.takeIf { !unreadable }?.toList()?.joinToString(" "),
        onCopy = if (code != null && !unreadable) onCopy else null,
        trailing = {
            if (code != null && !unreadable) {
                val description = pluralStringResource(R.plurals.otp_changes_in, remaining, remaining)
                val color = if (ending) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                val track = MaterialTheme.colorScheme.outlineVariant
                Box(
                    modifier = Modifier.size(48.dp).semantics { contentDescription = description },
                    contentAlignment = Alignment.Center,
                ) {
                    Canvas(Modifier.size(24.dp)) {
                        val stroke = 3.dp.toPx()
                        val inset = stroke / 2
                        val arc = Size(size.width - stroke, size.height - stroke)
                        drawArc(track, 0f, 360f, false, Offset(inset, inset), arc, style = Stroke(stroke))
                        val sweep = 360f * (remaining.toFloat() / period).coerceIn(0f, 1f)
                        drawArc(color, -90f, sweep, false, Offset(inset, inset), arc, style = Stroke(stroke, cap = StrokeCap.Round))
                    }
                }
            }
        },
    )
}
