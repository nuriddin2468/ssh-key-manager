package dev.sshkeymanager.android.home

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.requiredSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.ui.theme.AppTheme
import dev.sshkeymanager.android.ui.theme.SecretTextStyle
import dev.sshkeymanager.android.ui.theme.SshkmTheme

@Composable
fun HomeRoute(viewModel: HomeViewModel = viewModel()) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    HomeScreen(state = state, onGenerate = viewModel::generate)
}

@Composable
fun HomeScreen(state: HomeState, onGenerate: () -> Unit) {
    Scaffold(containerColor = MaterialTheme.colorScheme.background) { padding ->
        Column(
            modifier =
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 24.dp, vertical = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Column(modifier = Modifier.widthIn(max = 480.dp).fillMaxWidth()) {
                AppTile()
                Spacer(Modifier.height(20.dp))
                Text(
                    text = stringResource(R.string.app_name),
                    style = MaterialTheme.typography.headlineMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                    modifier = Modifier.semantics { heading() },
                )
                Text(
                    text = stringResource(R.string.home_version, state.version),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    text = stringResource(R.string.home_coming),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(28.dp))
                GeneratorCard(state = state, onGenerate = onGenerate)
            }
        }
    }
}

/** The app's icon, as a tile: the launcher's layers, cropped to its safe zone. */
@Composable
private fun AppTile() {
    Box(
        modifier = Modifier.size(56.dp).clip(RoundedCornerShape(14.dp)).clearAndSetSemantics {},
        contentAlignment = Alignment.Center,
    ) {
        Image(painterResource(R.drawable.ic_launcher_background), contentDescription = null, Modifier.requiredSize(84.dp))
        Image(painterResource(R.drawable.ic_launcher_foreground), contentDescription = null, Modifier.requiredSize(84.dp))
    }
}

@Composable
private fun GeneratorCard(state: HomeState, onGenerate: () -> Unit) {
    // A hairline edge, as the desktop app's cards have: in the dark theme
    // the card is barely lighter than the canvas.
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    ) {
        Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(
                text = stringResource(R.string.generator_title),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.semantics { heading() },
            )
            val generated = state.generated
            if (generated == null) {
                Text(
                    text = stringResource(R.string.generator_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                GeneratedPassword(generated)
            }
            state.error?.let { error ->
                Text(
                    text = stringResource(error),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
            Button(onClick = onGenerate, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                Text(
                    text = stringResource(if (generated == null) R.string.generator_generate else R.string.generator_again),
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}

@Composable
private fun GeneratedPassword(generated: Generated) {
    // Not selectable: copying, with the clipboard marked sensitive and
    // cleared after a while, comes with the vault (docs/mobile.md, step C).
    Column(
        modifier = Modifier.semantics(mergeDescendants = true) { liveRegion = LiveRegionMode.Polite },
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = stringResource(R.string.generator_password),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = generated.password,
            style = SecretTextStyle,
            color = MaterialTheme.colorScheme.onSurface,
            modifier =
                Modifier
                    .fillMaxWidth()
                    .clip(MaterialTheme.shapes.small)
                    .background(MaterialTheme.colorScheme.surfaceContainerLow)
                    .padding(horizontal = 14.dp, vertical = 12.dp),
        )
        StrengthMeter(generated.score)
        Text(
            text = stringResource(R.string.generator_strength, stringResource(strengthLabel(generated.score))),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** Four bars, as many lit as the score (at least one), in its colour. */
@Composable
private fun StrengthMeter(score: Int) {
    val lit = score.coerceIn(1, 4)
    val color = AppTheme.strength.of(score)
    Row(
        modifier = Modifier.fillMaxWidth().clearAndSetSemantics {},
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        repeat(4) { bar ->
            Box(
                Modifier
                    .weight(1f)
                    .height(4.dp)
                    .clip(RoundedCornerShape(2.dp))
                    .background(if (bar < lit) color else MaterialTheme.colorScheme.outlineVariant),
            )
        }
    }
}

@Preview(name = "Empty")
@Composable
private fun HomeEmptyPreview() {
    SshkmTheme { HomeScreen(HomeState(version = "0.11.0"), onGenerate = {}) }
}

@Preview(name = "Generated, dark", uiMode = android.content.res.Configuration.UI_MODE_NIGHT_YES)
@Composable
private fun HomeGeneratedPreview() {
    SshkmTheme {
        HomeScreen(HomeState(version = "0.11.0", generated = Generated("t9#Vq2@Lm!8xKp4\$wZ7&", 4)), onGenerate = {})
    }
}
