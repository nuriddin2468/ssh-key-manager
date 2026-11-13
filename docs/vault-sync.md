# Syncing the vault between own devices

Plan step 4 of own-device sync ("vault by entries"). PR 1 (#16) syncs hosts, server
keys, device records and project records; the vault's entries don't go, so a project
reaches the second computer without its logins and environments. This step makes
"Sync now" bring the vault too, entry by entry, with the same rules PR 1 set: each
computer works out changes against its own snapshot of the last sync (keyed hashes,
never values), a change only one side made goes across, a change both made differently
is the user's choice, risky changes and more than 5 deletions need a yes on each device,
and two different vaults are never merged.

Status: design for review. Nothing here is built yet.

## What syncs and what never does

| Syncs | How |
| --- | --- |
| Logins (title, username, password, URL, notes, 2FA secret, custom fields, tags, icon, colours, expiry, auto-type) | as entries, field by field |
| An entry's history (earlier versions) | merged as a union, never compared |
| Host and key entries (`sshkm.kind`, `sshkm.host`, `sshkm.fingerprint`) | as entries: they are custom fields |
| Environments: variables (custom fields, protected or not), `sshkm.env` (order, notes), `sshkm.env.part`, `sshkm.env.files` | as entries; custom data items are fields |
| Shared values (`sshkm.shared`, `{REF:P@I:…}` in variables) | as entries; see [Shared values](#shared-values-and-ref) |
| Attachments, of any size | as fields (name → content hash); the bytes travel inside the vault copy |
| Groups (folders), the recycle bin, moves between them | groups by UUID; the bin by role, not by UUID |
| Permanent deletions (KeePass `DeletedObjects`) | union, with the 400-day lifetime of removal records |
| Custom icons used by synced entries and groups | with the entry or group |
| Project records and their `project/<name>` tags | records as in PR 1; tags rewritten from records after the merge |
| Device records | as in PR 1 |
| Contacts (`sshkm.contact.*`) | new: records in the manifest, like devices, with a tombstone on removal |

| Never syncs | Why |
| --- | --- |
| Paired browsers (`sshkm.browser.*`) and KeePassXC's browser keys (`KPXC_BROWSER_*`) | keys of a browser on one computer |
| `sshkm.own.key` | the own-device secret: every copy already has it; renewing it is PR 6's job, never a merge's |
| `sshkm.env.key` | the key this computer's `.env` file revisions are made with; each computer keeps its own (`SyncState` is kept per key, so nothing breaks) |
| Any other database-level custom data (KeePassXC's settings and the like) | settings of one file |
| Database settings (name, description, history limits, KDF, cipher) | settings of one file |
| Anything marked local: an entry or group with custom data `sshkm.local`, and everything inside such a group | generic rule for per-computer data; the chat history (`p2p-chat`) uses it |
| Where `.env` files stand on this computer (`SyncState` of `envs::files`), sync snapshots, `nearby.json` | app data outside the vault |
| Private SSH keys, the vault secret, the master password and key slots (`vault.keys`) | never leave the computer, as in PR 1 |

**Env file bindings sync.** `sshkm.env.files` holds a project folder *as the project keeps
it* (`~/code/shop`) and a path inside it, for all three levels; no path of one computer
beyond the project folders, which project records already sync. `envs::files` already
expects bindings from elsewhere: a folder that isn't on this computer is reported and never
made, a file is written only inside a folder of a project that holds the environment, never
through a link, and a binding naming a file the app never writes is refused
(`RefusedReason::Name`). This is what happens today when two computers share the vault file
through a cloud folder; P2P sync behaves the same.

**The local marker.** Custom data `sshkm.local` (any value; the chat uses `chat`) on an
entry or a group means: this computer's own. The vault copy never carries it, a sync never
changes, moves or deletes it, and an item from the other side that carries the marker, or
has the UUID of a local item here, is ignored. Database-level custom data is per computer
unless allowed by name (contacts, devices and projects travel as records), so a key such as
`sshkm.chat.<peer>` needs no marker.

## How a sync goes

PR 1's conversation stays as it is (Hello with `own`, `Manifest` swap, `Decide` on the
side that connected, `Decisions`, apply, `Applied` swap, `agree`). Entry sync adds to it:

1. **Announce.** `Own` in `Hello` gets `entries: Option<EntrySync>`
   (`serde(default)`, skipped when empty; older versions ignore it):
   - `On { version: 1 }` — this computer syncs entries;
   - `Cloud { service }` — it could, but its vault is in a cloud folder;
   - missing — an older version.

   Entries sync only when both say `On`; each uses the lower version. Otherwise the sync is
   PR 1's, and the summary says why passwords didn't go (see [UI](#ui)).
2. **Manifest** as in PR 1, plus `contacts: Vec<ContactRecord>` (`serde(default)`).
3. **Vault copy** (new `Message::VaultCopy { database }` through `send_large`, the side
   that connected first, only when both said `On`): this computer's database as a KDBX 4
   file, encrypted with the vault secret, with what never syncs taken out
   ([`copy`](#code)): no database custom data, no local-marked items, no browser data.
   The receiver takes up to `MAX_DATABASE_SIZE` (256 MiB) plus base64 and framing.
4. **Each side plans** on its own: hosts as in PR 1, the vault against
   `SyncState.vault` (below).
5. **Decide** on the side that connected: host and entry conflicts, risky changes and
   deletions in one review. `Decisions` gets `vault: Option<VaultDecisions { initiator,
   responder }>` (entry and group UUIDs).
6. **Apply** (below), then `Applied` gets `vault: BTreeMap<id, digest>` (`serde(default)`);
   `agree` makes the next snapshot from what both have alike.

**Why send the whole file, not entries one by one.** Both sides are own devices with the
same vault: the other side already holds every value, so per-entry transfer protects
nothing, while a wire format of our own for entries, history, attachments, icons, auto-type
and custom data would be a second KDBX to design, bound and test. The copy reuses the
parser and its checks (`check_shared`: size, KDF bounds, the secret opens it), keeps
everything KeePass has, and its size is bounded by the file's. On a LAN a typical vault
(well under 1 MiB) costs nothing; a 256 MiB one with attachments takes seconds. Values a
conflict shows are read from the copy in memory, one at a time, when the user asks.

**Checks on the copy before anything is planned** (`VaultCopy::check`, failure = `Broken`,
nothing applied):
- it parses with this vault's secret (`check_shared`); a different secret → `OtherVault`;
- its root group has this vault's root UUID (two vaults are never merged; the keepass
  crate's own `_merge` panics on different roots, which is one of the reasons we don't use
  it);
- no UUID twice among live entries and groups, and no entry UUID equal to a group UUID;
- at most 65,536 entries, 8,192 groups, group depth 64, 262,144 removal records; per entry
  at most 64 history versions taken (older ones dropped);
- no time more than 5 minutes ahead of this computer's clock is believed: such a time
  counts as now (as `own_devices::MAX_AHEAD`).

## The model

Each side turns both databases into **items**: entries and groups by UUID, each a map of
field name → keyed hash. The plan compares hashes only; values stay in the two `Database`s
until a change is applied.

**Fields of an entry**:
- `s:<name>` — each string field (KeePass's own, custom ones, env variables) with its
  protected flag;
- `cd:<key>` — each custom data item's value (not its time), except `sshkm.local`;
- `a:<name>` — each attachment's content;
- `tags` — sorted, without the app's `project/<name>` tags (records decide those);
- `icon` (built-in id or the custom icon's content), `fg`, `bg`, `overrideUrl`,
  `autotype`, `expiry` (`expires` + time), `qualityCheck`;
- `group` — the canonical id of its group (below).

Not compared: times (created, modified, accessed, moved, usage count) and the history.

**Fields of a group**: name, notes, icon, tags, custom data, auto-type and search flags,
default auto-type sequence, expiry, and `group` (its parent).

**Canonical group ids.** Both sides must hash an item's group the same way:
- the root is `root`, the recycle bin is `bin` on both sides, whatever their UUIDs
  (`meta.recyclebin_uuid` may differ when each computer made its bin on first use);
- two groups made separately on each computer for the same thing (`Environments`,
  `Environments/Shared`, a project part) are **paired**: a group only one side has by UUID,
  with the same name and the same canonical parent as a group only the other side has, pairs
  with it (by UUID order when several match, so both sides pair alike). A pair's canonical
  id is the smaller UUID; pairs are kept in `SyncState.vault.pairs` so a later rename on one
  side doesn't break them. Each side keeps its own UUID; an item put in a paired group goes
  into this side's twin.

**Snapshot.** `SyncState` (`<data_dir>/sync/<peer>.json`, 0600) gets `vault: VaultBase
{ items: id → field → hash, pairs }` with `serde(default)`. Hashes are HMAC-SHA256 truncated
to 128 bits, keyed with a key derived from this device's key (a new label next to PR 1's
`BASE_LABEL`), so a snapshot on disk can't be checked against guessed passwords. `store::load`
gets a size limit (64 MiB).

**Digests for `agree`.** Each side sends, per item, HMAC-SHA256 of its canonical form
(fields in order of name, values, groups by canonical id), keyed with a key derived from the
own key both share, so even the encrypted channel carries no unkeyed hash of a password.

## Merge rules

Per item, against the snapshot (`b`), mine (`m`), theirs (`t`) — PR 1's rules
(`sync::merge`), lifted from host fields to field hashes:

| Case | Result |
| --- | --- |
| a field only they changed | taken |
| a field only this side changed | stays; the other side takes it |
| a field both changed alike | nothing |
| a field both changed differently | the item is a **conflict** |
| item only there, no snapshot, no removal record here newer than its last change | **added** here |
| item only there, removal record here newer than its last change | stays deleted; they delete it on their side |
| item only there, removal record here older than its last change (changed after this side deleted it) | **conflict**: deleted here, changed there |
| item only here, unchanged since the snapshot, gone there | **deleted** here |
| item only here, changed since the snapshot, gone there | **conflict**: deleted there, changed here |
| item on both, no snapshot, different | **conflict** |
| an entry's kind differs (login / environment / shared value) | **conflict**, never merged field by field |

**History.** Whenever an entry changes here — a field taken, or a conflict settled either
way — this side's version before the change goes into its history, and the two histories
become one: every version of both, without doubles (same time and same content), oldest
dropped past the vault's `history_max_items`. So **a conflict loses nothing**: the version
not kept is the newest earlier version of the entry. The entry's modification time is the
other side's when its version is taken whole, now when fields of both were merged.

**Moves.** A move is a change of the `group` field: one side moved the entry and the other
edited it → both happen. Both moved it to different groups → conflict. An entry moved to
the recycle bin on one side and edited on the other ends up in the bin with the edit
(nothing is lost; the bin is a move). Restoring from the bin uses KeePass's previous group,
which is mapped through the pairs and dropped if that group isn't here.

**Groups.** Added before the entries that need them, deleted after: a group goes only if it
is empty once the entries are done; one that still holds something (an entry this side
added meanwhile) stays and is counted as kept. A group's deletion counts toward the
deletion limit like an entry's.

**Permanent deletions.** The vault's `DeletedObjects` become the union of both, each UUID
with the later time. A removal record older than 400 days (`projects::KEEP_REMOVED_MS`) is
neither sent nor taken: after that long it removes nothing on a computer that comes back,
as with project tombstones. Records already in the file stay (KeePassXC reads them).

### Shared values and `{REF}`

A shared value is an entry like any other, so the value lives in one entry and every
environment that refers to it ends with the same value. On top of that:
- a shared value is deleted here only after each environment here that still uses it got a
  copy of the value (`release_shared`, as deleting it in the app does), in the same change;
  so an environment edited here to use it while the other side deleted it keeps working;
- references still resolve only to shared values (`dereference`): an incoming variable that
  refers to a login's password stays unresolved, as one made in KeePassXC does, and its
  files wait;
- a reference to a shared value the vault doesn't have is shown as unresolved (`EnvVarInfo::
  unresolved`), as today.

### Ids that collide

- An item whose kind differs on the two sides: a conflict (above).
- An incoming entry with a group's UUID, the root's, or the bin's: the copy is refused.
- An incoming item with the UUID of a local-marked item here: ignored.
- Two vaults with different roots or secrets: refused before planning.

### Contacts

`sshkm.contact.<key>` records get `modified` and, on removal, a tombstone `{modified,
removed}` instead of disappearing, so a sync doesn't bring a removed contact back. Two
records merge as the one changed last; pairing again after a removal wins. Older versions
skip a tombstone (it lacks `name`) and keep an extra field when they read a live record.

## Risky changes and deletions

**Deletions.** An entry leaving the vault, an entry moved to the recycle bin, and a group
deleted each count as one. More than 5 incoming (`MASS_DELETE`, hosts and vault counted
together) need the user's yes: on the side that connected, in the review; the other side
puts them off, its snapshot untouched for them, until its user syncs from it — PR 1's rule
for each device.

**Risky variables (new).** A variable whose value goes into a shell's environment
(`envs_run`) or a `.env` file can make programs load code. Adding or changing one of these
names in any environment is a risky change, decided like a risky host directive (the
review, then a system dialog the page can't answer; the other side puts it off): `PATH`,
`LD_*`, `DYLD_*`, `NODE_OPTIONS`, `NODE_PATH`, `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME`,
`PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `RUBYLIB`, `BASH_ENV`, `ENV`, `ZDOTDIR`, `PROMPT_COMMAND`,
`GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_EXEC_PATH`, `GIT_CONFIG_*`, `SSH_ASKPASS`,
`JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS`, `DOTNET_STARTUP_HOOKS`
(`envs::risky_variable`, one list, tested). A change turned down is not asked about again
until it changes (`SyncState.declined`, as hosts).

**Conflicts** are the user's choice per item: keep this computer's or take the other's,
seeing which fields differ (names only: `Password`, `URL`, `DB_URL`) and, when they ask,
the two values of one field. A conflict left unchosen waits for the next sync.

## Applying

- **Fresh state.** Before planning, the vault re-reads its file (`refresh`), as before any
  change. The plan remembers each touched item's hash as planned against; under the vault's
  lock at apply time, an item that changed here meanwhile (the user edited it during the
  review) is skipped, its snapshot untouched, so it comes up next time.
- **One change.** Everything goes into the database in memory, in order: groups added,
  entries added and updated, moves, shared values released, entries deleted, groups
  deleted, removal records, contact records; then device and project records (PR 1) and
  `sync_tags`. A failure halfway restores the in-memory snapshot (`Vault::snapshot`) and
  nothing is written.
- **One save, after a backup.** `Vault::save` keeps a backup of the previous file before
  writing (`fsutil::backup`) and refuses to overwrite a file another program changed
  (`Error::Conflict`). The backup is the way back until step 2 (history with undo).
- **After.** The UI's vault queries are refetched (`vault-changed`), projects and devices
  events go out as in PR 1, and the `.env` files round runs, so files of environments that
  changed are rewritten here like after any vault change.
- `Applied` carries the vault digests of what is now saved (of the old state if the save
  failed); `agree` keeps snapshots only of what both have alike.

## Safety

What one own device could do to another, buggy or in someone else's hands, and what stops
it. An own device already holds the vault and its secret, so a sync can't leak more than it
has; the risk is damage and code running on this computer.

| Threat | What stops it |
| --- | --- |
| A stranger, or a former own device, syncs | PR 1: Noise XX, the own-vault proof, both in each other's registry; a removed device stays a tombstone |
| A different vault gets merged | proof, then the copy must open with this secret and have this root |
| A copy built to exhaust memory or CPU | 256 MiB, KDF bounds (`kdf::check_kdbx`), item and depth limits, history cap |
| Mass deletion | more than 5 need a yes on each device; backup before the save |
| Values overwritten or emptied | the previous version stays in each entry's history; backup before the save; step 2 adds undo |
| Code run through a variable (`NODE_OPTIONS`, `LD_PRELOAD`, `PATH`…) | risky variables need the review and the system dialog |
| Code run through a host directive | PR 1's risky directives, unchanged |
| A `.env` file written somewhere it shouldn't | bindings stay inside a project folder that exists here, no links, protected paths refused, owner-only permissions (`envs::files`) |
| A variable made to carry a login's password out | references resolve only to shared values |
| Browser keys, chat history, the own key planted or taken | never in the copy; database custom data from the other side is never read |
| Clock games to win last-writer rules | times more than 5 minutes ahead count as now; field merges don't use times at all |
| Guessing passwords from the snapshot on disk | keyed hashes, key derived from this device's key |

Not covered: a device that makes many plausible edits (changes, not deletions) gets them
applied, recoverable from history and the backup. Removing a device and replacing the own
key is PR 6.

## Compatibility

- A peer that doesn't announce `entries` keeps syncing hosts, keys, devices and projects;
  the summary says passwords didn't go and why ("needs the new version").
- Entries go only between two computers that both announced them, so an older version never
  receives an entry it can't read; the vault file stays standard KDBX 4.1, which KeePassXC
  and older versions of the app read.
- New fields (`Own.entries`, `Manifest.contacts`, `Decisions.vault`, `Applied.vault`,
  `SyncState.vault`) are `serde(default)` and skipped when empty; `Message::VaultCopy` is sent
  only after both announced. Protocol `VERSION` stays 1.
- Contact tombstones are skipped by older versions; a live record keeps parsing.

## Cloud folder

The vault's folder is checked with `envs::files::CloudRoots::detect` (iCloud Drive and
Desktop/Documents in iCloud, `~/Library/CloudStorage`, Dropbox, OneDrive, Google Drive), the
same detection `.env` files use, through a new `vault::location::cloud_service(paths,
roots)`. If the vault is in one, this computer announces `Cloud { service }`: the cloud
already keeps the file in step, and two mechanisms writing one file would fight. Hosts,
keys, devices and projects still sync. Checked at each sync (the vault may move).

## UI

`design:design-system` runs before building, `design:ux-copy` for the strings in en, ru and
uz, `design:accessibility-review` and `design:design-critique` on the result.

**Sync dialog** (`SyncDialog.tsx`), description line now:
- en: "Hosts, server keys and the vault go both ways. Sign-in keys stay where they are."
- ru: "Хосты, ключи серверов и хранилище идут в обе стороны. Ключи для входа остаются на месте."

**Review** (`Decide`), one list in sections, each only when it has something:
- *Changed on both computers* — hosts (as now), then Passwords, Environments, Shared values,
  Folders. A row: the item's name (an environment as `Shop · backend · prod`), what happened
  ("Changed here and on {{peer}}" / "Deleted on {{peer}}, changed here" / "Deleted here,
  changed on {{peer}}"), the fields that differ ("Differs: Password, URL"), "Show values"
  (one field at a time, a secret masked until shown; read from the copy in memory), and
  the existing "Keep this computer's" / "Take {{peer}}'s". Under the section:
  - en: "The version you don't keep stays among the entry's earlier versions."
  - ru: "Версия, которую вы не оставите, сохранится среди прежних версий записи."
- *Runs a program or opens access* — host directives (as now) and variables:
  - en: "{{name}} makes programs load code" / ru: "{{name}} заставляет программы загружать код";
    buttons "Add" / "Don't add" as now.
- *Deletions* — one checkbox for all, with the list grouped by kind:
  - en: "{{peer}} deleted {{count}} items" + "Delete them here too"; items from the
    recycle bin marked "from the recycle bin";
  - ru: "{{peer}} удалил {{count}} записей" + "Удалить и здесь".

**Summary** (`Synced`), one line per kind that changed, as now for hosts:
"Passwords: 3 added, 2 changed, 1 deleted" / "Пароли: добавлено 3, изменено 2, удалена 1";
the same for Environments, Shared values, Folders, Contacts, Hosts, Server keys; then what
waits (here, on the other device, conflicts left). When passwords didn't go:
- cloud — en: "Passwords weren't synced: the vault on {{peer}} is in {{service}}, which
  keeps it in step. Open the same file on this computer instead."
  ru: "Пароли не синхронизировались: хранилище на {{peer}} лежит в {{service}}, и оно
  само его синхронизирует. Откройте этот же файл на этом компьютере."
  (or "the vault on this computer is in {{service}}" when it is this side's);
- older version — en: "Passwords weren't synced: {{peer}} needs the new version of the app."
  ru: "Пароли не синхронизировались: на {{peer}} нужна новая версия приложения."

**My devices** (`MyDevices.tsx`): when this vault is in a cloud folder, one line under the
section — en: "Your vault is in {{service}}, so it syncs through it. Here, only hosts and
server keys sync." / ru: "Хранилище лежит в {{service}} и синхронизируется через него.
Здесь синхронизируются только хосты и ключи серверов."

Localization notes: counts use the existing plural keys (`_one/_few/_many/_other` in ru);
`{{service}}` is a product name, not translated; "earlier versions" matches
`history_*` ("прежние версии", "oldingi versiyalar"). Uzbek strings are written with the
same pass.

New command: `nearby_sync_value(id, item, field, side) -> SecretString`, registered in
`build.rs` and `lib.rs`, mocked in `src/mocks/nearby.ts` (a `?nearby=sync` review gets a
vault conflict, a risky variable and seven deletions).

## One-time import from another vault

**Next PR, not this one.** Importing from another KeePass file is a different operation:
another root and UUID space, its own password or key file, no snapshot, adds only (never
deletes), and duplicates found by content (title, username, URL) rather than by UUID, shown
in the existing import preview (`vault::import`). It reuses this PR's copy-in code for
entries, groups, history and attachments.

## Code

Core (`crates/sshkm-core`):
- `sync/merge.rs` — the three-way rules get a hash-level core (`plan_hashed` over
  `id → field → hash`), which the host plan (`plan` on `Item`s) calls; tests stay.
- `vault/sync/` (new, inside `vault` for the database): `copy.rs` (the copy without what
  never syncs; `VaultCopy::check`), `model.rs` (items, field hashes, canonical groups,
  pairs), `plan.rs` (`VaultPlan`: changes, conflicts with differing field names, deletions,
  risky variables), `apply.rs` (`Vault::apply_sync`), `tests.rs`.
- `vault/contacts.rs` — `contact_records()`, `merge_contacts()`, tombstones.
- `vault/location.rs` — `cloud_service()`; `vault/envs` — `risky_variable()`.
- `p2p/protocol.rs` — `Own.entries`, `Message::VaultCopy`, the new optional fields; small
  and additive (the `p2p-chat` branch touches this file too).

App (`src-tauri`): `nearby/sync.rs` (the vault part in `nearby/sync/vault.rs` if it grows),
`Side` methods with defaults (`vault_copy`, `vault_plan`, `vault_apply`, `vault_value`) so
`Script` and `examples/nearby_peer.rs` compile, `nearby/mod.rs` (announce, cloud check),
`store.rs` (size limit), commands. UI: `SyncDialog.tsx`, `MyDevices.tsx`, `model.ts`,
locales, mocks. Docs: `architecture.md` (`vault::sync`), `SECURITY.md` → Nearby (what the
vault copy holds and doesn't, the rules above), `PRIVACY.md` (what syncs). Changelog: a
`notice` (after the update, "Sync now" brings passwords and environments too, unless the
vault is in a cloud folder, and both computers need the new version).

**Two PRs**: core first (merge, copy, model, apply, contacts, protocol types, tests), then
app + UI + docs + changelog.

## Tests

Core:
- every row of the merge table, for entries and for groups;
- history: union, no doubles, cap; the losing side of a conflict in history either way;
- moves, the bin on both sides with different UUIDs, paired groups (and a rename after
  pairing), a group kept because it isn't empty;
- removal records: union, 400 days, deletion vs later edit;
- shared values: deleted there while used here → a copy here; a reference to a login stays
  unresolved;
- attachments: added, changed, removed, large (several MiB), in history;
- what never syncs: browser keys, `sshkm.own.key`, `sshkm.env.key`, KeePassXC keys and
  local-marked items aren't in the copy, and planted in an incoming copy change nothing;
- copy checks: other secret, other root, duplicate UUIDs, entry with a group's UUID, limits,
  future times;
- a real two-vault sync: one vault copied to two files, both edited (adds, edits on both
  sides, a conflict, a deletion, an environment with a shared value, an attachment), copies
  exchanged and applied both ways through `VaultCopy` bytes, then both files reopened: the
  same entries, `agree` digests equal, a second sync changes nothing;
- contacts: tombstones, last change wins, older-version parsing.

App (`script.rs`): entry sync between two new versions; with an older peer (hosts only);
with a cloud vault on either side; a conflict decided on the side that connected; seven
deletions put off on the other; a risky variable needing the system dialog; an edit made
during the review is skipped. UI: `SyncDialog` tests for the new sections and summary;
`model.ts` helpers.

## Decisions to confirm

1. The whole vault, stripped of what never syncs, travels as an encrypted KDBX copy instead
   of a per-entry wire format.
2. Moved to the bin on one side, edited on the other → merged into the bin, not a conflict.
3. Risky variables are new and gated like risky host directives.
4. Many *changes* (not deletions) aren't confirmed: history and the backup cover them, and
   step 2 adds undo.
5. One-time import is the next PR.
