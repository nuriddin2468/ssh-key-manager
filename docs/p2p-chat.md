# Chats: messages between Nearby contacts

Status: **design, waiting for review.** Nothing here is built yet.

A chat lets two paired computers (Nearby contacts) or two of the user's own devices send
each other text, secret values that expire, environment variables and the items Nearby
sends today (a login, a host, a hosts file group, a public key, an environment). It runs
over the local network, app to app, with no server.

## Decisions it builds on

- **Delivery only while both are online.** No outbox, no queue, no relay. Nothing waits
  in the background to be delivered later.
- **History is kept encrypted with the vault** and is readable only while it is unlocked.
- **Secret values (passwords, variables) are hidden and expire** after a term the sender
  picks.
- **History is per device.** It is never synced between the user's own devices. Older
  versions that open the same vault see nothing of it and break nothing.
- **Own devices can chat too**, e.g. to pass a value from the laptop to the desktop.
- LAN only, no internet relay. Private keys are never synced or sent.
- From the review: **protocol hygiene comes first** (§2). Chat sessions live **outside the
  one conversation slot** (§1). Storage follows the **contract with vault sync** (§4).
  Cards **reuse the existing item code and its checks** (§2). The design skills ran at
  this stage (§6).

## 1. Reachability

Today a contact can reach this computer only during the ten-minute "Visible" window, and
the port announced to the user's devices takes only a sync. Chats need a presence of
their own, built the way own devices have theirs.

### When a device is "online"

A device is online for chats while **its vault is unlocked and Nearby is open**, on either
of its tabs (Computers or Chats). It stays online for **two more minutes** after the user
leaves Nearby, so that going to Passwords to copy something doesn't drop a conversation.
Locking the vault ends it at once, including auto-lock and locking on sleep or minimise.
A window hidden to the tray with Nearby as its page stays online. That is when
notifications matter (§5).

While online the app:

1. listens on a TCP port of its own (the *chat port*), which takes chats only;
2. announces it as `_sshkm-chat._tcp` (below);
3. browses for the same service, to show which contacts are online.

Offline, none of the three happens: no port, no announcement, no browsing.

The chat list shows a contact as online when its current announcement is recognised, or
when a chat session with it is open. Sending works only to a contact online now.
Otherwise the composer is disabled and says why.

### The announcement: one name, only contacts recognise it

Strangers on the LAN must learn nothing: not the device name, not its key, not whose
contact it is.

- **Contact key, from pairing.** Pairing proved each side's device key to the other, and
  each vault keeps the other's public key. That is enough for a pairwise secret both can
  compute and nobody else can:
  `K_AB = HKDF-SHA256(X25519(device key A, device key B))`, salt `sshkm contact`, info the
  two public keys in sorted order. The X25519 comes from snow's resolver or
  `curve25519-dalek`, both in the tree already. The HKDF label keeps it apart from what
  Noise derives.
  - Why not a random secret exchanged during pairing and kept in the contact record?
    Contacts paired by older versions don't have one. They could only get it in another
    meeting during "Visible", so every existing contact would have to meet again.
    Changing the contact record would also be seen by older versions that open the same
    vault. Revoking needs no work either: the key is gone as soon as either side removes
    the other.
- **Announcement.** Once per ten-minute window, as own devices do, the app registers
  `_sshkm-chat._tcp` under a **new random instance name** (16 hex digits). Its TXT record
  holds `v=1` and a **set of tags**, one per contact and own device:
  `tag_B = HMAC-SHA256(K_AB, "sshkm chat presence" ‖ A's public key ‖ instance ‖ window)`,
  first 6 bytes.
  - The set is shuffled and **padded with random tags to 16, 32 or 64**, so it doesn't
    tell how many contacts there are beyond that bucket.
  - At most 64 are announced: own devices first, then the contacts chatted with most
    recently. 64 tags are 512 characters of base64, split over TXT strings of at most 250.
- **Recognising.** For each `_sshkm-chat` service found, the app computes the tag it would
  expect from each of its contacts and devices. It does this for the windows before, at
  and after now, for clocks a little apart, and looks the tag up in the set. That is
  `3 × contacts` HMACs per announcement; the contact keys are computed once per unlock.
  A match marks that contact online at that address. A false match (48-bit tags) only
  costs a failed knock.
- **What a stranger learns.** The instance name and tags change every window and say
  nothing; the host name in the record is the random instance too. A stranger learns
  only that an SSH Key Manager with Nearby open is at this address, plus the bucket of
  its contacts (≤16, ≤32, ≤64).

### The knock: no device key for strangers

Today anyone who connects to a listening Nearby port learns the device's public key,
which is a stable identifier: the Noise `XX` responder sends it in message 2. The chat
port doesn't answer the handshake until the caller has shown it is a contact:

1. The side that answers sends 16 random bytes, the *challenge*.
2. The side that connects answers with
   `HMAC-SHA256(K_AB, "sshkm chat knock" ‖ responder's public key ‖ challenge)`, first 16
   bytes.
3. The side that answers tries each of its contacts and devices (constant-time compare).
   With no match within 5 seconds it hangs up, having sent nothing but the challenge.
4. Then the Noise `XX` handshake runs with the prologue `sshkm-chat/1` ‖ challenge ‖
   knock. A chat session is thus bound to its knock and can never pass for a pairing
   session (`sshkm-p2p/1`). The peer's proven key must be the one that knocked.

A passive listener sees a challenge and an HMAC it can't reuse, because the challenge is
fresh each time. At most 8 connections may wait at the knock at once. The same knock
could later protect the own-devices port, which has the leak today (noted for the
security audit).

### Sessions: outside the conversation slot

The app runs one conversation at a time (pairing, adding a device, a sync); others are
dropped while one goes on. Chats don't take that slot and aren't affected by it.

- **Separate.** Chat sessions run on the chat port, with their own state and threads. A
  pairing or a sync goes on while chats are open, and the reverse.
- **Capped.** At most **16 chat sessions** at once. Beyond that, a new one is refused and
  the least recently used idle one is closed first.
  - One thread per session reads; one manager thread handles pings, expiry, presence and
    the announcement.
- **On demand.** A session opens when the user opens a conversation with an online
  contact or sends to one. It stays open while both are online. Either side can send at
  any time (a duplex session, §8).
- **One per pair.** If both connect at the same moment, the session started by the device
  with the smaller public key stays and the other closes. A message that went out on the
  closed one without a receipt is sent again on the survivor under the same id; the
  receiver drops duplicates. This happens at once, while both are online, so it is not a
  queue.
- **Alive.** A `ping` goes every 30 seconds. With no frame for 90 seconds the session
  closes, and the contact shows offline until it is seen again. A session idle for 10
  minutes closes too and reopens on demand.
- **Not activity.** Incoming chat traffic reads and writes with the vault's quiet access.
  It never counts as the user's activity, so it can't keep the vault from auto-locking.

### Background reachability: proposed, not built

The proposal is a switch in Nearby, **"Stay reachable for chats while the vault is
unlocked"**, **off by default**. When on, the chat port and announcement stay up while the
vault is unlocked, even with Nearby closed, and incoming messages notify (§5). Own devices
could use it to receive a value from the laptop without opening Nearby on the desktop.
It is built only if approved, and then as a `notice` in the changelog if it is ever on by
default.

## 2. Protocol

### Hygiene first (in the core pull request, before any chat frame)

Today an unknown message or item breaks the conversation:

- `Message`, `Item` and `ItemSummary` have no fallback (`protocol.rs:41/170/252`), so a
  variant a newer app adds makes `recv` fail.
- `transfer::receive` then reports "Broken" (`transfer.rs:99-106`) instead of "update the
  app".
- `meet` compares `version != VERSION` (`pairing.rs:377`).

Chat brings the first new message types, so this comes first:

- **Features in `Hello`.** A generic list replaces one-off flags:

  ```rust
  Hello {
      version: u32,
      name: String,
      known: bool,
      own: Option<Own>,
      /// What the sender's app can do beyond version 1, by name; versions
      /// before it send nothing.
      #[serde(default, skip_serializing_if = "Vec::is_empty")]
      features: Vec<String>,
  }
  ```

  This version says `["chat"]` in every `Hello`. A side sends a message, frame or item
  kind that came after version 1 only to a peer that named its feature. **A chat frame
  never goes to a peer that didn't say `chat`.** A later incompatible chat change is a new
  name (`chat2`). `VERSION` stays 1 and changes only if the framing itself ever has to;
  everything else is a feature. Older versions ignore `features`.
- **Fallbacks.** `Message`, `Item` and `ItemSummary` get `#[serde(other)] Unknown`, so an
  unknown kind parses instead of failing. Nothing ever sends `Unknown`.
  - `Item::check` refuses it.
  - `Item::summary` of it is `ItemSummary::Unknown`.
  - The TypeScript bindings gain `{ type: 'unknown' }`, which the UI shows as "something
    this version can't open".
- **"Not supported" instead of "Broken".**
  - An offer of an unknown item is declined with `Reply { accepted: false, unsupported:
    true }`. `unsupported` is a new field, `serde(default)`, ignored by older versions,
    which see a plain decline.
  - The receiver's user sees "*{name}* sent something this version can't open. Update
    SSH Key Manager to see it."
  - The sender's user sees "*{name}* can't take this yet: its SSH Key Manager needs
    updating."
  - An unknown message where a known one was due ends the conversation with a new
    `PairingFailure::Unsupported` (translated, same wording), not `Broken`.
  - The existing `Version` failure stays for a peer whose `version` differs.
- **Tests.** Today's `Hello` read by an older shape and the reverse. Unknown message,
  item and summary parse to `Unknown`. A declined unknown offer ends as `Unsupported` on
  both sides. No chat frame goes to a peer without the feature.

### Chat frames

One new message, `Message::Chat { frame: ChatFrame }`, with its own module
(`p2p::chat`), so `protocol.rs` gains only the variant:

```json
{"type":"chat","frame":{"kind":"text","id":"3f9c…(32 hex)","text":"on my way"}}
```

| kind        | fields                                      | answered by          |
| ----------- | ------------------------------------------- | -------------------- |
| `text`      | `id`, `text`                                | `delivered`          |
| `secret`    | `id`, `label`, `value`, `ttl`, `pad`        | `delivered`          |
| `variables` | `id`, `label`, `variables[]`, `ttl`, `pad`  | `delivered`          |
| `offer`     | `id`, `item` (an `ItemSummary`)             | `reply`              |
| `reply`     | `id`, `accepted`, `unsupported`             | `payload` on a yes   |
| `payload`   | `id`, `item` (an `Item`)                    | `saved`              |
| `saved`     | `id`, `saved`                               | —                    |
| `delivered` | `ids` (at most 64)                          | —                    |
| `refused`   | `id`, `reason` (`tooLarge`, `invalid`, `tooMany`, `unsupported`) | — |
| `revoke`    | `id`                                        | —                    |
| `ping`      | `n`                                         | `pong`               |
| `pong`      | `n`                                         | —                    |

- **Ids.** Each id is 16 random bytes as 32 lowercase hex digits, made by the sender. A
  receipt, reply, revoke or saved names the id it answers.
- **Delivered means stored.** The receiver sends `delivered` only after the message is in
  its history file. There are no read receipts.
- **Duplicates.** The receiver keeps the ids it has seen per conversation (the last
  10 000, tombstones included). A known id is answered with `delivered` again and not
  stored twice, so sending again after a lost receipt is safe.
- **Order and time.** Entries are ordered and timed by the receiver's clock when they
  arrive. The sender's clock is not trusted for anything.
- **Who may say what.** `delivered`, `saved` and `reply` count only for this side's own
  entries in that conversation. `revoke` counts only for a secret or variables the peer
  sent. Anything else is ignored.
- **Unknown kind.** `ChatFrame` falls back too. A frame of a kind this side doesn't know
  (only a newer peer breaking the feature rule sends one) is answered with `refused` and
  reason `unsupported` when it has an id, and dropped otherwise. The session goes on.
- **Padding.** `secret` and `variables` frames carry `pad` (spaces) up to the next
  multiple of 512 bytes, so a frame's length doesn't tell a password's length.

### Items as cards

The items Nearby sends today travel as cards, reusing `Item`, `ItemSummary`, `check()` and
the save code (`items::build`, `items::store`) with every rule they have:

- The summary goes first (`offer`, nothing secret). The receiving user accepts or
  declines on the card (`reply`), and only then does the item go (`payload`).
- The item must match its summary and pass `Item::check`, and is saved as today: a host's
  risky options are refused and its alias numbered when taken; server keys are added only
  for a host with none; a hosts file group is only staged for the Hosts file page and its
  administrator password; a public key is written as someone else's; an environment is
  added as a new one.
- Either side may offer.
- The sender keeps the item in memory only, never in history, until the reply: for at
  most 10 minutes or until the session ends. The card then says the offer ended and
  offers to send it again.
- At most 3 offers may wait in each direction.
- The contact is known by its key, so the "another name" step of today's send doesn't
  apply.

Two known bugs come with that code:

- **An environment in Personal without a part can't be sent.** `Vault::env_label` returns
  `""` and `check_environment` refuses an empty label (`protocol.rs:505-507`), while the
  receiver already takes an empty part (`check_part`). Chat sends environments, so **the
  core PR fixes it**: an empty project label is allowed and means Personal. A test sends
  one each way.
- **A server password binds to the sender's alias** even when that alias leads elsewhere
  on the receiving computer (`items.rs:243-248`). The security audit is looking at it.
  Chat doesn't build on that binding: a password card shows what it shows today, and
  gets the audit's fix with the shared code.

### Limits

| what                                  | limit                                    |
| ------------------------------------- | ---------------------------------------- |
| a frame                               | 1 MiB of JSON (as every message today)   |
| `text`                                | 16 KiB; line breaks and tabs, no other control characters |
| `secret` value / label                | 16 KiB / 64 characters, one line         |
| `variables`                           | the environment rules: valid names, no duplicates, 1000 variables, 384 KiB |
| `ttl`                                 | 5 minutes to 7 days (the UI offers 1 hour, 1 day, 7 days) |
| frames received                       | bucket of 30, refilled 2 per second      |
| offers waiting                        | 3 each way                               |
| chat sessions                         | 16                                       |
| connections waiting at the knock      | 8                                        |
| history per conversation              | 5000 entries or 2 MiB, oldest dropped    |

- **A content rule broken** (too long, a control character, a bad variable name): the
  frame is answered with `refused` and the session goes on; the sender's message shows
  "not delivered".
- **Unparseable frame or broken rate limit:** the session ends. After a broken rate limit
  that contact's knocks are turned away for a minute, and the user sees why.

### A connection lost mid-send

- **Messages.** A message is written to the sender's history first, as *sending*. With no
  receipt before the session ends it shows **Not delivered**, with **Send again** while
  the contact is online. It may have arrived after all; sent again under the same id, it
  is not stored twice.
- **Offers.** An offer waiting for its reply ends. A payload sent without `saved` back
  shows "not confirmed"; the receiver's card says whether it saved it.
- **Half frames** are never taken: frames are read whole and authenticated before
  anything happens.

## 3. Secrets and variables

- **Secret.** A label (optional) and a value the sender types, with a term: 1 hour (the
  default), 1 day or 7 days.
  - It goes as soon as it is sent, like a text, but shows masked on both sides until the
    user clicks **Show**. It hides itself again after 30 seconds, as passwords do.
  - **Copy** goes through the app's clipboard, never through the page: kept out of
    clipboard history and cloud clipboards, cleared after the time set in Settings.
  - The value reaches the page only on Show, one at a time.
- **Expiry.** Each side computes the expiry from its own clock: the sender from when it
  sent, the receiver from when it received, plus `ttl`.
  - On expiry both wipe the value from memory and from the history file, and keep a line
    "Secret · expired".
  - The app checks every 30 seconds and whenever the vault is unlocked. A value whose
    term ran out while the app was closed or locked is wiped at unlock, before the
    history shows.
  - The sender can wipe it earlier on both sides with **Wipe now** while the receiver is
    online.
- **Honest UI.** The secret dialog says that the receiver can copy the value before it
  expires: expiry wipes the app's copy, not what someone copied.
- **Variables.** The sender picks an environment and ticks variables; the backend reads
  the values from the vault, so the page never has them.
  - They go with a term like a secret: names visible, values masked (secret ones) or
    shown (others), all values wiped on expiry.
  - Before that, the receiver may click **Add to an environment…**: pick one of their
    environments (or a new one), see what would be added and what would change, and
    confirm.
  - New names are ticked. Replacing a value the receiver already has is never ticked by
    default. Names that change how programs start (`PATH`, `LD_PRELOAD`, `DYLD_*`,
    `NODE_OPTIONS`, `BASH_ENV`, `PYTHONPATH`, `GIT_SSH_COMMAND`, …) are flagged and never
    ticked by default.
  - Nothing is saved without that confirmation.
- **A whole environment** can still go as a card (§2). It is permanent, and its values go
  only after the receiver accepts.

## 4. Storage

### Where

History is **not in the vault file**. It lives in files next to the app's other data,
sealed with a key that only the unlocked vault holds:

- **Files.** `chats/<id>.chat` in the app's data folder, one file per conversation.
  `<id>` = HMAC(chat key, contact's public key), so file names don't tell whose it is.
- **Sealing.** Each file is XChaCha20-Poly1305 (`chacha20poly1305`, already a dependency)
  over the conversation's JSON, with a fresh random nonce on every write. The associated
  data is this device's and the contact's keys, so a file can't be passed off as another
  conversation. Writes are atomic and gathered: at most one per second per conversation.
- **The chat key** is 32 random bytes in the vault's database-level custom data,
  `sshkm.chat.<this device's key>`, made on first use. The file key is derived from it
  per conversation (HKDF).

Why not the vault file itself:

- **Every vault save keeps a backup of the previous file.** Messages in the vault would
  leave expired secrets and deleted chats in those backups, and each message would push
  out a backup taken before a real change.
- **A vault in a synced folder** is shared by the user's computers. History in it would
  reach them, and two computers writing chats into one file would conflict all the time.
- **Older versions and KeePassXC** would carry and show the history.

### The contract with vault sync

The vault sync between own devices (agreed with that work) never copies, changes or
deletes:

- database-level custom data other than contacts, devices and projects
  (`sshkm.contact.`, `sshkm.device.`, `sshkm.project.`);
- entries and groups marked with the custom data `sshkm.local` (for a chat, `chat`), with
  everything inside a marked group.

Chats use the first: the only thing a chat puts in the vault is `sshkm.chat.<device key>`,
so it stays on this computer, and no `sshkm.local` group is needed. If chats ever store
anything as entries, it goes in one group marked `sshkm.local = chat`.

### Older versions and KeePassXC

- **Older versions never show a chat as a login.** Nothing of a chat is an entry or a
  group in the KDBX, and older versions list only entries and groups. They read custom
  data only by the prefixes they know (`sshkm.contact.`, `sshkm.device.`, …) and keep the
  rest unchanged when they save, as they already do for `sshkm.own.key`. They never look
  into `chats/`.
- **KeePassXC** shows no entry either. At most it lists one more item among the
  database's custom data.
- **A vault moved to a new computer** carries the old computer's chat key, which is
  harmless: the key is named after the old computer's device key, and the files it opens
  stayed there. Nothing needs stripping.
- **A vault restored from before the chat key existed** can't open the files. The app says
  once that older history can't be read, and starts again.

So the history is per device by construction: the files never leave this computer.

### What is in a file

- **Per entry:** id, direction, kind, time and delivery state, plus whichever applies: the
  text; a card's summary and outcome (never the item itself); a secret's label, value and
  expiry; variables and their expiry.
- **Also:** the last-read mark (for unread counts) and the ids seen.

### Life of a chat

- **Cap.** 5000 entries or 2 MiB per conversation, oldest dropped first. One contact can't
  push out another's history.
- **Delete a chat.** The file goes, on this device only. The dialog says the contact keeps
  its copy.
- **Removing a contact** (or one of the user's devices):
  - its tag leaves the announcement, its knocks fail, and an open session closes at once;
  - the remove dialog asks whether to delete the chat too (ticked);
  - a chat that is kept stays readable without a composer, and its secrets still expire;
  - a contact removed by another computer through a synced vault leaves its file hidden
    until the user deletes chats.
- **Locking** drops the decrypted history from memory, closes sessions and stops the
  announcement.
- **System copies.** Deleting and expiry remove values from the app's files. Copies the
  system made of the encrypted file before (Time Machine, disk snapshots) stay as safe as
  the vault itself. `SECURITY.md` says so.

## 5. Notifications

A message, card or secret may arrive while the window is not focused, including hidden to
the tray. Then the app shows a system notification:

- **Title and body.** The title is the contact's name; the body is "New message" or "3 new
  messages".
- **Never any content.** Not even a text, and never a secret's label or value.
- **Rate.** At most one per conversation per 30 seconds. Clicking it opens the
  conversation.
- **Unread counts** show on the Chats tab, on Nearby in the sidebar and in the tray menu.
- **New dependency.** This needs `tauri-plugin-notification`, the official plugin. macOS
  asks the user's permission the first time.

## 6. UI

`design:design-system` (extend: a new pattern) and `design:ux-copy` ran at this stage, on
the existing Nearby, Environments and Passwords screens and on the semantic tokens the
light theme adds. `design:accessibility-review` and `design:design-critique` run on the
built UI.

### Pattern: Nearby with chats

**Problem.** Today Nearby is one scrolling page: this computer, the network, my devices,
paired computers. A chat needs a list and a conversation side by side, plus a way to
switch between the two.

**Existing patterns it follows.**

| existing | shared | what it lacks |
| --- | --- | --- |
| Environments: `ViewTabs` in the toolbar | two views as a tab list with a count, arrow keys | it is specific to Environments |
| Environments: `EnvList` + `EnvPane` | a `glass` list of 280/300 px next to a `glass-raised` pane, both `rounded-2xl` | no message stream, no composer |
| Passwords: `SavedSecret` | masked value, Show / Copy, hides after 30 s, copy through the backend | a value that expires, revoke |
| Nearby: `ItemCard`, `SendDialog` pickers | the items as cards, what to send | accept / decline inside a stream |

**Layout.**

- **Toolbar.** "Nearby" and a tab list **Computers · Chats**, with the Chats tab showing
  the unread count.
  - The tab list is a generic `Tabs` in `components/ui/`, looking and behaving exactly
    like `ViewTabs`. Environments moves to it in a later change, so as not to collide
    with the light theme now.
- **Computers tab.** Today's page as it is, plus **Message** on each paired computer and
  device.
- **Chats tab.** `PageBody` as a row: the **chat list** (`glass`, 280 px, 300 px from `xl`)
  and the **conversation** (`glass-raised`, flexible). At the window's minimum width
  (980 px) that leaves about 460 px for the conversation, as on Environments, so it never
  collapses.
- **Chat list.**
  - Two sections, **My devices** and **Paired computers**, headed like `EnvList` (12.5 px
    semibold, count).
  - A row is 52 px: the name (13 px, semibold when unread), and under it the last message
    (12.5 px, `muted`, one line). On the right sit the time (11 px, `subtle`) and an unread
    pill (like the attention count of `ViewTabs`).
  - Online shows as a dot (`--color-online`) **and** the word "Online" in the second line.
    Offline rows read "Offline" in `faint` and sort after online ones.
- **Conversation.**
  - Header: name, online state, a `Menu` (Delete chat).
  - The stream is a `role="log"`: messages grouped by day, with separators (12 px,
    `subtle`).
  - Bubbles are at most 72 % wide, `rounded-2xl`, 13 px text, `px-3 py-2`, 6 px apart and
    14 px between groups.
    - Mine: `rgb(var(--accent-rgb)/0.14)`, a border of `accent-rgb/0.35` and
      `--accent-text`, as the accent `Badge`.
    - Theirs: `card` with a `line` border and `fg`.
  - Under each bubble: the time and delivery state (11 px). *Not delivered* is `critical`,
    with **Send again** as a link button.
- **Composer** at the bottom of the pane:
  - an `IconButton` **+** with a `Menu` in two groups: "Hidden, expires" (Secret…,
    Variables…) and "Saved after they accept" (Password…, Host…, Hosts file group…, Public
    key…, Environment…);
  - an auto-growing text field (`field`, `line-field`, at most 6 lines);
  - **Send** (`Button`, primary).
  - Enter sends; Shift+Enter breaks the line.

**Components.**

| reuse as is | `Toolbar`, `PageBody`, `Button`, `IconButton`, `Menu`, `Dialog`, `ConfirmDialog`, `Badge`, `EmptyState`, `Spinner`, `ItemCard`, the `SendDialog` pickers, `glass` / `glass-raised` |
| --- | --- |
| reuse, generalised | `Tabs` (from `ViewTabs`); the masked value and its 30 s hide from `SavedSecret`, as `MaskedValue` |
| new, in `src/features/nearby/chat/` | `ChatList`, `ChatRow`, `Conversation`, `Bubble` (text, secret, variables, card, line), `Composer`, `SecretDialog`, `VariablesDialog`, `AddVariablesDialog`, `Presence` (dot + word) |

**Bubble variants and states.**

| variant | states |
| --- | --- |
| text | sending (muted time + clock icon), delivered (check), not delivered (`critical`, Send again) |
| secret | masked (label, `••••`, Show, Copy, `Badge` "Expires in 50 min"; `warning` tone under 10 min); shown (value in `font-mono`, hides after 30 s); expired / wiped (dashed `line` border, `faint` text "Secret · expired", no actions); mine adds **Wipe now** |
| variables | names with masked or shown values, count, expiry `Badge`, **Add to an environment…**; expired (names stay, values gone, action gone) |
| card | `ItemCard` in a bubble; theirs: **Accept** / **Decline**, then saved as "…", declined, ended, can't open (unknown); mine: waiting, accepted, saved, declined, ended (**Send again**) |
| line | centred 12 px `subtle` text: "Secret wiped by Aziz", "Offer ended", "Paused for a minute: too many messages" |

**Tokens.** Only semantic ones (light theme): `surface`, `card`, `field`, `fill`,
`fill-hover`, `line-soft`, `line`, `line-field`, `fg`, `fg-2`, `muted`, `subtle`, `faint`,
`online`, `critical`, `warning`, `info` and the accent variables. No `white/…`,
`black/…` or color literals. Type sizes, radii and spacing come from the scale the app
already uses (15 / 14 / 13 / 12.5 / 11 px; `rounded-2xl`, `rounded-xl`, `rounded-[10px]`).

**Accessibility.**

- **Tabs:** `role="tablist"`, arrow keys, Home and End, as `ViewTabs`. The unread count
  also has text for screen readers ("3 unread").
- **Chat list:** a list of buttons, the open one with `aria-current="true"`. Each name is
  read as "Aziz, online, 2 unread, last: on my way".
- **Online state:** never by color alone (dot plus word).
- **Stream:** `role="log"` with `aria-live="polite"`, so incoming messages are announced
  by sender and kind. A secret is announced as "Secret from Aziz: staging DB password,
  hidden, expires in 50 minutes", never with its value. A shown value is outside the live
  region.
- **Keyboard:** opening a conversation puts focus in the composer. Every action is a
  button reachable by Tab. Targets are at least 28 px (`IconButton size-7`). Enter and
  Shift+Enter are named in the field's description.
- **Disabled composer:** disabled with a visible reason (`aria-describedby`), not just
  greyed out.
- **Motion and theme:** no motion beyond the app's fade-in, and none with reduced motion.
  Contrast is checked in both themes in the accessibility review.
- **Text:** plain, with no links that open and no markup. Long words wrap. Directional
  text is isolated (`dir="auto"`).

### Key strings

`design:ux-copy` wrote these in the voice of today's `nearby.*` strings. Computers are
"paired computers", not "contacts". The vault is "the vault". Quotes follow each
language's convention. Uzbek uses ʻ (U+02BB).

| key | en | ru | uz |
| --- | --- | --- | --- |
| tabs | Computers · Chats | Компьютеры · Чаты | Kompyuterlar · Chatlar |
| online / offline | Online / Offline | Онлайн / Офлайн | Onlayn / Oflayn |
| online, hint | Online: Nearby is open on that computer now. | Онлайн — на том компьютере сейчас открыто «Рядом». | Onlayn — u kompyuterda hozir «Yaqin atrofda» ochiq. |
| composer | Message {{name}} | Сообщение для {{name}} | {{name}} uchun xabar |
| composer, offline | {{name}} is offline. Messages go only while Nearby is open on both computers. | {{name}} офлайн. Сообщения доходят, только пока «Рядом» открыто на обоих компьютерах. | {{name}} oflayn. Xabarlar faqat ikkala kompyuterda «Yaqin atrofda» ochiq boʻlganda yetib boradi. |
| + groups | Hidden, expires / Saved after they accept | Скрыто, со сроком / Сохранится после принятия | Yashirin, muddatli / Qabul qilingach saqlanadi |
| secret dialog | Send a secret to {{name}} | Отправить секрет на {{name}} | {{name}} ga maxfiy qiymat yuborish |
| secret label | What it is (optional) — e.g. staging database password | Что это (необязательно) — например, пароль базы на staging | Bu nima (ixtiyoriy) — masalan, staging bazasi paroli |
| term | Expires after: 1 hour · 1 day · 7 days | Удалить через: 1 час · 1 день · 7 дней | Oʻchirilish muddati: 1 soat · 1 kun · 7 kun |
| honesty note | Hidden on both computers and wiped from both chats when it expires. Until then, whoever uses {{name}} can copy it. | Скрыт на обоих компьютерах и стирается из обоих чатов, когда истечёт срок. До этого на {{name}} его могут скопировать. | Ikkala kompyuterda yashirin turadi va muddati tugagach ikkala chatdan oʻchiriladi. Shungacha {{name}} da undan nusxa olish mumkin. |
| send secret | Send secret | Отправить секрет | Yuborish |
| secret bubble | Show · Hide · Copy · Expires in {{time}} · Wipe now | Показать · Скрыть · Копировать · Истекает через {{time}} · Стереть сейчас | Koʻrsatish · Yashirish · Nusxalash · {{time}} dan keyin oʻchadi · Hozir oʻchirish |
| secret gone | Secret · expired / Secret · wiped by {{name}} | Секрет · срок истёк / Секрет · стёрт на {{name}} | Maxfiy qiymat · muddati tugadi / Maxfiy qiymat · {{name}} oʻchirdi |
| variables bubble | {{count}} variables from {{env}} · Add to an environment… | {{count}} переменных из {{env}} · Добавить в окружение… (plurals) | {{env}} dan {{count}} ta oʻzgaruvchi · Muhitga qoʻshish… |
| add review | Add variables from {{name}} · To environment · New / Replaces your value / Same as yours · Changes how programs start · Add {{count}} variables | Добавить переменные от {{name}} · В окружение · Новая / Заменит ваше значение / Как у вас · Меняет запуск программ · Добавить {{count}} переменных | {{name}} dan oʻzgaruvchilarni qoʻshish · Qaysi muhitga · Yangi / Qiymatingizni almashtiradi / Siznikidek · Dasturlar ishga tushishini oʻzgartiradi · {{count}} ta oʻzgaruvchini qoʻshish |
| add note | Nothing is saved until you click Add. | Ничего не сохранится, пока вы не нажмёте «Добавить». | «Qoʻshish»ni bosmaguningizcha hech narsa saqlanmaydi. |
| delivery | Sending… · Delivered · Not delivered · Send again | Отправляется… · Доставлено · Не доставлено · Отправить снова | Yuborilmoqda… · Yetkazildi · Yetkazilmadi · Qayta yuborish |
| unsupported, in | {{name}} sent something this version can’t open. Update SSH Key Manager to see it. | {{name}} прислал то, что эта версия не умеет открыть. Обновите SSH Key Manager, чтобы увидеть. | {{name}} bu versiya ocha olmaydigan narsa yubordi. Uni koʻrish uchun SSH Key Manager’ni yangilang. |
| unsupported, out | {{name}} can’t take this yet: its SSH Key Manager needs updating. | {{name}} пока не может это принять: там нужно обновить SSH Key Manager. | {{name}} buni hali qabul qila olmaydi: undagi SSH Key Manager’ni yangilash kerak. |
| delete chat | Delete the chat with {{name}}? · Its messages are deleted from this computer. {{name}} keeps its copy. · Delete chat | Удалить чат с {{name}}? · Сообщения удалятся с этого компьютера. На {{name}} копия останется. · Удалить чат | {{name}} bilan chat oʻchirilsinmi? · Xabarlar shu kompyuterdan oʻchiriladi. {{name}} dagi nusxa qoladi. · Chatni oʻchirish |
| remove contact | Also delete the chat | Удалить и чат | Chatni ham oʻchirish |
| notification | {{name}} — New message / {{count}} new messages | {{name}} — Новое сообщение / {{count}} новых сообщения (plurals) | {{name}} — Yangi xabar / {{count}} ta yangi xabar |
| vault locked | Chats are protected by the vault. Unlock it to read and send messages. | Чаты защищены хранилищем. Откройте его, чтобы читать и отправлять сообщения. | Chatlar ombor bilan himoyalangan. Oʻqish va yuborish uchun omborni oching. |
| no one yet | No one to chat with yet. Pair with a computer on the Computers tab, then chat here. | Пока не с кем переписываться. Подключите компьютер на вкладке «Компьютеры» — и пишите здесь. | Hozircha yozishadigan hech kim yoʻq. «Kompyuterlar» varagʻida kompyuterni ulang, keyin shu yerda yozing. |
| none open | Pick a computer to chat with. | Выберите, с кем переписываться. | Kim bilan yozishishni tanlang. |
| empty chat | No messages yet. They’re encrypted and go straight to {{name}} while you’re both online. | Сообщений пока нет. Они шифруются и идут прямо на {{name}}, пока вы оба онлайн. | Hozircha xabar yoʻq. Ular shifrlanadi va ikkalangiz onlayn boʻlganingizda toʻgʻridan-toʻgʻri {{name}} ga boradi. |
| offer ended | The offer ended before {{name}} answered. · Send again | Предложение истекло, прежде чем {{name}} ответил. · Отправить снова | {{name}} javob berguncha taklif muddati tugadi. · Qayta yuborish |
| paused | {{name}} sent too much at once. The chat is paused for a minute. | {{name}} прислал слишком много сразу. Чат приостановлен на минуту. | {{name}} birdaniga juda koʻp yubordi. Chat bir daqiqaga toʻxtatildi. |

- **Why this wording.** It says what goes where and when, as today's send dialogs do
  ("Nothing secret goes over until…"). The honesty note says plainly that expiry doesn't
  undo a copy, without alarm. Errors name the fix (update the app, both open Nearby).
  Buttons name the action ("Send secret", "Delete chat", "Add 3 variables").
- **Localization notes.**
  - **Names.** `{{name}}` is a computer's name. Russian agrees with the masculine
    «компьютер» («прислал»), as today's «{{name}} удалён». Uzbek attaches the case suffix
    after a space (`{{name}} ga`), as today's strings do.
  - **Plurals.** Counts use i18next plurals (ru: one/few/many/other; uz: one/other with
    «ta»).
  - **Times.** `{{time}}` comes from the app's relative time format.
  - **Online.** «Онлайн»/«Офлайн» is used on purpose: «в сети» would read as the existing
    «В этой сети» (on this network), which means something else.

## 7. Threat model

| who / what | what they can do | what stops it |
| --- | --- | --- |
| **Stranger on the LAN** | See announcements, connect to the chat port, spoof an announcement, watch traffic | Random instance names and padded tags tell nothing but "an app with Nearby open, ≤N contacts". A connection gets a random challenge and is closed: no device key, no name. A spoofed announcement fails the knock or the handshake. Traffic is Noise-encrypted; secrets are padded. At most 8 connections wait at the knock. They can always disrupt the network (out of scope). |
| **Malicious contact** | Flood, send huge or malformed frames, phishing text, risky items or variables, keep a secret | Rate limit, size limits, per-conversation cap, at most 3 offers. Strict checks; an unparseable frame ends the session. Text is plain, never a link or markup; names are the vault's. Items keep today's checks (risky ssh options refused, hosts group via the Hosts file page). Variables are added only after review, risky names flagged and unticked. A term is at most 7 days; the UI says a receiver can copy a secret. |
| **Replay** | Resend recorded traffic or old frames | Noise: every session has its own keys and nonces; a frame can't be replayed in or across sessions. The knock is bound to a fresh challenge and to the handshake's prologue. A contact resending its own id is dropped as a duplicate. |
| **Contact impersonation** | Pretend to be a contact | The knock needs the contact key (X25519 of the device keys); the handshake proves the device key; it must be the one that knocked. |
| **Removed contact** | Keep reaching the user | No tag for it, its knocks fail, its session closes when it is removed. |
| **Stolen unlocked laptop** | Read history, reveal unexpired secrets, chat as the user | Same as the unlocked vault: auto-lock, lock on sleep; chat traffic never postpones the auto-lock; locking closes chats. Secrets live at most their term. |
| **Stolen locked laptop / disk image** | Read `chats/` | Encrypted with a key only the unlocked vault has; file names say nothing. Old encrypted copies in system backups are as safe as the vault. |
| **Older or newer version** | Get chat frames, get an unknown item, break on the vault | Chat frames only to a peer that said `chat`; unknown messages, items and frames parse as `Unknown` and end as "needs the new version", never "Broken"; `sshkm.chat.*` custom data is ignored and kept. |

## 8. How it is built

- **Core (`sshkm-core`)**
  - Protocol hygiene first (§2): `Hello.features`, the `Unknown` fallbacks,
    `Reply.unsupported`, and the Personal environment fix.
  - `p2p/contact.rs`: the contact key, presence tags, the knock (with tests).
  - `p2p/chat.rs`: `ChatFrame`, its checks and limits, the rate limit bucket.
  - `p2p/session.rs`: a prologue per session kind, and splitting a `Session<TcpStream>`
    into a reader and a writer that share the Noise state. Each frame is encrypted or
    decrypted under a short lock, and writes stay in order.
  - `p2p/protocol.rs`: `Hello.features`, `Message::Chat`, the fallbacks; nothing else.
  - `chat/`: a conversation's history (entries, cap, expiry, duplicates, unread), and
    sealing and opening its file. `vault/chat.rs` holds the chat key.
- **App (`src-tauri/src/nearby/chat/`)**
  - What it does: the online state (Nearby open, grace, lock); announcement and
    recognition; the chat port and knock; sessions (capped, one reading thread each,
    pings, receipts, sending again); the expiry timer; notifications; events
    (`chat-changed`, `chat-message`).
  - Hooks: `nearby/mod.rs` gains only the module and hooks for lock and for a contact
    removed. `pairing.rs` gains only `features` in its `Hello` and the `Unsupported`
    endings.
  - Commands: `chat_set_online`, `chat_list`, `chat_history`, `chat_send_text`,
    `chat_send_secret`, `chat_send_variables`, `chat_send_item`, `chat_answer`,
    `chat_reveal`, `chat_copy`, `chat_revoke`, `chat_retry`, `chat_add_variables`,
    `chat_mark_read`, `chat_delete`. They are registered in `build.rs` and `lib.rs`, and
    mocked in `src/mocks/` with two fake paired computers, one online.
- **Tests**
  - Protocol: hygiene (above); frame round-trips and checks; limits and the rate limit.
  - Presence and connections: tags recognised only by a contact and only around their
    window, and padding; the knock (wrong key, replayed challenge, a stranger gets no
    key); duplex sessions over loopback, and the session cap.
  - Delivery: duplicates, receipts, sending again after a cut.
  - Expiry on both sides, at unlock, and on revoke.
  - Storage: history files (sealed, wrong conversation refused, cap); the vault keeps
    `sshkm.chat.*` and an older-shaped reader ignores it; nothing of a chat in the vault
    file or its backups.
  - UI tests for the composer, secrets and the review.
- **Docs and notes:** this file, `docs/architecture.md`, `SECURITY.md` (Nearby: chats, the
  knock, storage, features), a `new` changelog note, and a `notice` saying that both
  computers need the new version to chat (older ones don't appear online).
- **Pull requests:** two.
  1. Core, protocol hygiene and the app's backend, with mocks.
  2. The UI, changelog and docs.

## Open questions

1. **Storage outside the vault file.** The history goes in its own files, sealed with a
   key kept in the vault, rather than inside `vault.kdbx` (§4): vault backups would keep
   expired secrets, and a synced vault would share the history. Is that what "kept in the
   vault, encrypted" should mean?
2. **When online.** Online while Nearby is open, plus two minutes after leaving it, or only
   while the Chats tab itself is open?
3. **Notifications.** Is `tauri-plugin-notification` acceptable as a new dependency, for
   notifications without content?
4. **Background switch** (§1). Build it later, off by default, or not at all?
