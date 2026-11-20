package dev.sshkeymanager.android.logins

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.sshkeymanager.android.R
import dev.sshkeymanager.android.biometric.PromptText
import dev.sshkeymanager.android.biometric.Prompter
import dev.sshkeymanager.android.core.EntryKind
import dev.sshkeymanager.android.core.Login
import dev.sshkeymanager.android.ui.NoticeEffect
import dev.sshkeymanager.android.ui.components.ContentMaxWidth
import dev.sshkeymanager.android.ui.components.EmptyState
import dev.sshkeymanager.android.ui.components.ErrorText
import dev.sshkeymanager.android.ui.components.LocalUse
import dev.sshkeymanager.android.ui.components.countsAsUse
import dev.sshkeymanager.android.ui.components.ScreenGutter
import dev.sshkeymanager.android.ui.components.VaultTopBar
import dev.sshkeymanager.android.ui.theme.AppTheme
import dev.sshkeymanager.android.ui.theme.tone
import dev.sshkeymanager.android.vault.FingerprintOffer

/** What the fingerprint prompt says when it turns fingerprint unlock on. */
@Composable
fun enablePromptText() =
    PromptText(
        title = stringResource(R.string.prompt_enable_title),
        subtitle = stringResource(R.string.prompt_enable_subtitle),
        cancel = stringResource(R.string.action_cancel),
    )

@Composable
fun LoginsScreen(
    viewModel: LoginsViewModel,
    prompter: Prompter,
    onOpen: (String) -> Unit,
    onAdd: () -> Unit,
    onGenerator: () -> Unit,
    onSettings: () -> Unit,
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val offer by viewModel.fingerprintOffer.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    NoticeEffect(viewModel.notice, snackbar)
    val enableText = enablePromptText()
    Scaffold(
        topBar = {
            VaultTopBar(
                title = stringResource(R.string.logins_title),
                actions = {
                    IconButton(onClick = viewModel::lock) {
                        Icon(Icons.Filled.Lock, contentDescription = stringResource(R.string.action_lock))
                    }
                    Overflow(onGenerator = onGenerator, onSettings = onSettings)
                },
            )
        },
        floatingActionButton = {
            if (state.filter != Filter.Trash) {
                ExtendedFloatingActionButton(
                    onClick = onAdd,
                    icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                    text = { Text(stringResource(R.string.logins_add)) },
                )
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
        containerColor = MaterialTheme.colorScheme.background,
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.TopCenter) {
            LazyColumn(
                modifier = Modifier.widthIn(max = ContentMaxWidth).fillMaxSize(),
                contentPadding = PaddingValues(bottom = 96.dp),
            ) {
                item(key = "search") {
                    SearchField(query = state.query, onQuery = viewModel::search)
                }
                item(key = "filters") {
                    Filters(state = state, onFilter = viewModel::filter)
                }
                offer?.let { kind ->
                    item(key = "offer") {
                        OfferCard(
                            kind = kind,
                            onTurnOn = { viewModel.enableFingerprint(prompter, enableText) },
                            onNotNow = viewModel::declineFingerprint,
                        )
                    }
                }
                state.error?.let { error ->
                    item(key = "error") { ErrorText(stringResource(error), Modifier.padding(horizontal = ScreenGutter)) }
                }
                if (!state.loading && state.shown.isEmpty()) {
                    item(key = "empty") { EmptyList(state) }
                }
                items(state.shown, key = { it.id }) { login ->
                    LoginRow(login = login, onClick = { onOpen(login.id) })
                    HorizontalDivider(Modifier.padding(start = 72.dp), color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
    }
}

@Composable
private fun Overflow(onGenerator: () -> Unit, onSettings: () -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        IconButton(onClick = { open = true }) {
            Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.action_more))
        }
        DropdownMenu(
            expanded = open,
            onDismissRequest = { open = false },
            modifier = Modifier.countsAsUse(LocalUse.current),
        ) {
            DropdownMenuItem(
                text = { Text(stringResource(R.string.menu_generator)) },
                onClick = {
                    open = false
                    onGenerator()
                },
            )
            DropdownMenuItem(
                text = { Text(stringResource(R.string.menu_settings)) },
                onClick = {
                    open = false
                    onSettings()
                },
            )
        }
    }
}

@Composable
private fun SearchField(query: String, onQuery: (String) -> Unit) {
    OutlinedTextField(
        value = query,
        onValueChange = onQuery,
        modifier = Modifier.fillMaxWidth().padding(horizontal = ScreenGutter, vertical = 8.dp),
        label = { Text(stringResource(R.string.logins_search)) },
        placeholder = { Text(stringResource(R.string.logins_search_hint)) },
        leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
        trailingIcon = {
            if (query.isNotEmpty()) {
                IconButton(onClick = { onQuery("") }) {
                    Icon(Icons.Filled.Clear, contentDescription = stringResource(R.string.logins_clear_search))
                }
            }
        },
        singleLine = true,
        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, imeAction = ImeAction.Search),
    )
}

@Composable
private fun Filters(state: LoginsState, onFilter: (Filter) -> Unit) {
    val chips = state.chips
    if (chips.size <= 1) return
    LazyRow(
        contentPadding = PaddingValues(horizontal = ScreenGutter),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(chips, key = { it.toString() }) { filter ->
            val project = (filter as? Filter.Project)?.let { chip -> state.projects.firstOrNull { it.id == chip.id } }
            FilterChip(
                selected = state.filter == filter,
                onClick = { onFilter(filter) },
                label = {
                    Text(
                        when (filter) {
                            Filter.All -> stringResource(R.string.filter_all)
                            Filter.Otp -> stringResource(R.string.filter_otp)
                            is Filter.Project -> project?.name.orEmpty()
                            is Filter.Group -> filter.path
                            Filter.Trash -> stringResource(R.string.filter_trash)
                        },
                        maxLines = 1,
                    )
                },
                leadingIcon =
                    project?.let { label ->
                        {
                            val color = label.color.tone(AppTheme.dark)
                            Box(Modifier.size(10.dp).clip(CircleShape).background(color))
                        }
                    },
                modifier = Modifier.heightIn(min = 48.dp),
            )
        }
    }
}

@Composable
private fun OfferCard(kind: FingerprintOffer, onTurnOn: () -> Unit, onNotNow: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().padding(horizontal = ScreenGutter, vertical = 8.dp),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    ) {
        Column(Modifier.padding(start = 20.dp, end = 12.dp, top = 16.dp, bottom = 8.dp)) {
            Text(
                text = stringResource(R.string.offer_title),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.semantics { heading() }.padding(end = 8.dp),
            )
            Text(
                text =
                    stringResource(
                        if (kind == FingerprintOffer.AGAIN) R.string.offer_body_again else R.string.offer_body,
                    ),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp, end = 8.dp),
            )
            Row(Modifier.align(Alignment.End).padding(top = 4.dp)) {
                TextButton(onClick = onNotNow, modifier = Modifier.heightIn(min = 48.dp)) {
                    Text(stringResource(R.string.offer_not_now))
                }
                TextButton(onClick = onTurnOn, modifier = Modifier.heightIn(min = 48.dp)) {
                    Text(stringResource(R.string.offer_turn_on))
                }
            }
        }
    }
}

@Composable
private fun EmptyList(state: LoginsState) {
    when {
        state.query.isNotBlank() -> EmptyState(null, stringResource(R.string.logins_no_match, state.query.trim()))
        state.filter == Filter.Trash -> EmptyState(null, stringResource(R.string.trash_empty))
        state.filter != Filter.All -> EmptyState(null, stringResource(R.string.logins_filter_empty))
        else -> EmptyState(stringResource(R.string.logins_empty_title), stringResource(R.string.logins_empty_body))
    }
}

/** What the second line of an entry says. */
@Composable
fun loginSubtitle(login: Login): String? =
    when (login.kind) {
        EntryKind.HOST -> stringResource(R.string.kind_host, login.host.orEmpty())
        EntryKind.KEY -> stringResource(R.string.kind_key)
        EntryKind.LOGIN -> login.username.ifEmpty { login.url }.ifEmpty { null }
    }

@Composable
private fun LoginRow(login: Login, onClick: () -> Unit) {
    ListItem(
        onClick = onClick,
        modifier = Modifier.padding(horizontal = 4.dp),
        supportingContent = loginSubtitle(login)?.let { { Text(it, maxLines = 1, overflow = TextOverflow.Ellipsis) } },
        leadingContent = { Monogram(login.title) },
        trailingContent =
            if (login.hasOtp) {
                {
                    val description = stringResource(R.string.otp_badge_label)
                    Text(
                        text = stringResource(R.string.otp_badge),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier =
                            Modifier
                                .clip(MaterialTheme.shapes.extraSmall)
                                .background(MaterialTheme.colorScheme.secondaryContainer)
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                                .semantics { contentDescription = description },
                    )
                }
            } else {
                null
            },
        colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.background),
    ) {
        Text(login.title, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

/** The first letter of a title, on a tile. */
@Composable
fun Monogram(title: String) {
    Box(
        modifier =
            Modifier
                .size(40.dp)
                .clip(MaterialTheme.shapes.medium)
                .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                .clearAndSetSemantics {},
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = title.trim().take(1).uppercase().ifEmpty { "•" },
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.primary,
        )
    }
}
