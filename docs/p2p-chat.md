# Chats: messages between Nearby contacts

Status: **design, waiting for review.** Nothing here is built yet.

A chat lets two Nearby contacts — or two of the user's own devices — send each other
text, secret values that expire, environment variables and the items Nearby sends today
(a login, a host, a hosts file group, a public key, an environment), over the local
network, app to app, with no server.

## Decisions it builds on

- **Delivery only while both are online.** No outbox, no queue, no relay. Nothing waits
  in the background to be delivered later.
- **History is kept encrypted with the vault** and is readable only while it is unlocked.
- **Secret values (passwords, variables) are hidden and expire** after a term the sender
  picks.
- **History is per device.** It is never synced between the user's own devices, and older
  versions that open the same vault see nothing of it and break nothing.
- **Own devices can chat too**, e.g. to pass a value from the laptop to the desktop.
- LAN only, no internet relay; private keys are never synced or sent.

## 1. Reachability

### When a device is "online"

A device is online for chats while **its vault is unlocked and Nearby is open** (either
of its tabs, Devices or Chats), and for **two minutes after** the user leaves Nearby, so
that going to Passwords to copy something doesn't drop a conversation. Locking the vault
ends it at once (auto-lock, lock on sleep or minimise included). A window hidden to the
tray with Nearby as its page stays online; that is when notifications matter (§5).

While online the app:

1. listens on a TCP port of its own (the *chat port*), which takes chats only;
2. announces it as `_sshkm-chat._tcp` (below);
3. browses for the same service, to show which contacts are online.

Offline, none of the three happens: no port, no announcement, no browsing.

The chat list shows a contact as online when its current announcement is recognised (or
a chat session with it is open). Sending works only to a contact online now; otherwise
the composer is disabled and says why.

### The announcement: one name, only contacts recognise it

Strangers on the LAN must learn nothing: not the device name, not its key, not whose
contact it is. Own devices already do this with a key their vaults share
(`OwnKey::presence_name`). Contacts share no vault, but every two devices that know each
other's public key share a secret already:

- **Contact key.** `K_AB = HKDF-SHA256(X25519(device key A, device key B))`, salt
  `sshkm contact`, info the two public keys in sorted order. Both sides compute the same
  key from what they have: their own private device key and the other's public key from
  the vault. Nothing is stored or exchanged, so it works at once for every contact paired
  by an older version, and it is gone the moment either side removes the other. (The
  X25519 comes from snow's resolver or `curve25519-dalek`, both in the tree already; the
  HKDF label keeps it apart from the keys Noise derives.)
- **Announcement.** Once per ten-minute window (as own devices), the app registers
  `_sshkm-chat._tcp` under a **new random instance name** (16 hex digits) with a TXT
  record of `v=1` and a **set of tags**, one per contact and own device:
  `tag_B = HMAC-SHA256(K_AB, "sshkm chat presence" ‖ A's public key ‖ instance ‖ window)`,
  first 6 bytes. The set is shuffled and **padded with random tags to 16, 32 or 64**, so it
  doesn't tell how many contacts there are beyond that bucket. At most 64 are announced:
  own devices first, then the contacts chatted with most recently. 64 tags are 512
  characters of base64, split over TXT strings of at most 250.
- **Recognising.** For each `_sshkm-chat` service found, the app computes the tag it
  would expect from each of its contacts and devices for the windows before, at and
  after now (clocks a little apart) and looks it up in the set: `3 × contacts` HMACs per
  announcement, with the contact keys computed once per unlock. A match marks that
  contact online at that address. A false match (48-bit tags) only costs a failed knock.
- The instance name and tags change every window and say nothing; the host name in the
  record is the random instance too. A stranger learns only that an SSH Key Manager with
  Nearby open is at this address, and a bucket (≤16, ≤32, ≤64) of its contacts.

### The knock: no device key for strangers

Today anyone who connects to a listening Nearby port learns the device's public key
from the Noise `XX` handshake (the responder sends it in message 2), and that key is a
stable identifier. The chat port doesn't answer the handshake until the caller has shown
it is a contact:

1. The side that answers sends 16 random bytes, the *challenge*.
2. The side that connects answers with
   `HMAC-SHA256(K_AB, "sshkm chat knock" ‖ responder's public key ‖ challenge)`, first 16
   bytes.
3. The side that answers tries each of its contacts and devices (constant-time compare).
   No match within 5 seconds: it hangs up, having sent nothing but the challenge.
4. Then the Noise `XX` handshake runs with the prologue `sshkm-chat/1` ‖ challenge ‖
   knock, so a chat session is bound to its knock and can never pass for a pairing
   session (`sshkm-p2p/1`). The peer's proven key must be the one that knocked.

A passive listener sees a challenge and an HMAC it can't reuse (the challenge is fresh
each time). At most 8 connections may be waiting at the knock at once.

### Sessions

- **On demand.** A session opens when the user opens a conversation with an online
  contact or sends to one, and stays open while both are online. Either side can send
  at any time (a duplex session, §2).
- **One per pair.** If both connect at the same moment, the session started by the
  device with the smaller public key stays and the other closes. A message that went out
  on the closed one without a receipt is sent again on the other under the same id (the
  receiver drops duplicates); this happens at once, while both are online, so it is not
  a queue.
- **Alive.** A `ping` every 30 seconds; no frame for 90 seconds closes the session and
  the contact shows offline until it is seen again. A session idle for 10 minutes closes
  too (it reopens on demand).
- Chat sessions don't take the pairing slot: pairing, adding a device and a sync go on
  while chats are open, and the reverse.

### Background reachability: proposed, not built

**"Stay reachable for chats while the vault is unlocked"** — a switch in Nearby, **off by
default**. On, the chat port and announcement stay up while the vault is unlocked, with
Nearby closed, and incoming messages notify (§5). Own devices could use it to receive a
value from the laptop without opening Nearby on the desktop. Built only if approved.

## 2. Protocol

`VERSION` stays 1; everything is additive.

### Capability in `Hello`

```rust
Hello {
    version: u32,
    name: String,
    known: bool,
    own: Option<Own>,
    /// The chat protocol the sender speaks; versions before chats send nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    chat: Option<u32>,
}
```

Every `Hello` of this version says `chat: 1` (also in pairing and sync, where it is only
information). On the chat port both sides must say `chat ≥ 1` and `known: true`, or the
session ends. Older versions ignore the field. They never see a chat frame anyway: they
don't announce `_sshkm-chat._tcp`, so no one connects to them for a chat, and they don't
browse for it. A later chat version adds frame kinds; a side only sends kinds the peer's
`chat` number knows.

### Chat frames

One new message, `Message::Chat { frame: ChatFrame }`, with its own module
(`p2p::chat`), so `protocol.rs` only gains the variant and the field:

```json
{"type":"chat","frame":{"kind":"text","id":"3f9c…(32 hex)","text":"on my way"}}
```

| kind        | fields                                      | answered by          |
| ----------- | ------------------------------------------- | -------------------- |
| `text`      | `id`, `text`                                | `delivered`          |
| `secret`    | `id`, `label`, `value`, `ttl`, `pad`        | `delivered`          |
| `variables` | `id`, `label`, `variables[]`, `ttl`, `pad`  | `delivered`          |
| `offer`     | `id`, `item` (an `ItemSummary`)             | `reply`              |
| `reply`     | `id`, `accepted`                            | `payload` on a yes   |
| `payload`   | `id`, `item` (an `Item`)                    | `saved`              |
| `saved`     | `id`, `saved`                               | —                    |
| `delivered` | `ids` (at most 64)                          | —                    |
| `refused`   | `id`, `reason` (`tooLarge`, `invalid`, `tooMany`) | —              |
| `revoke`    | `id`                                        | —                    |
| `ping`      | `n`                                         | `pong`               |
| `pong`      | `n`                                         | —                    |

- **Ids.** 16 random bytes as 32 lowercase hex digits, made by the sender. A receipt,
  reply, revoke or saved names the id it answers.
- **Delivered means stored.** The receiver sends `delivered` only after the message is in
  its history file. There are no read receipts.
- **Duplicates.** The receiver keeps the ids it has seen per conversation (the last
  10 000, tombstones included) and answers a known id with `delivered` again without
  storing it twice. Sending again after a lost receipt is therefore safe.
- **Order and time.** Entries are ordered and timed by the receiver's clock when they
  arrive; the sender's clock is not trusted for anything.
- **Who may say what.** `delivered`, `saved` and `reply` count only for this side's own
  entries in that conversation; `revoke` only for a secret or variables the peer sent.
  Anything else is ignored.
- **Padding.** `secret` and `variables` frames carry `pad` (spaces) up to the next
  multiple of 512 bytes, so a frame's length doesn't tell a password's length.

### Items as cards

The items Nearby sends today travel as cards and keep every rule they have:
the summary first (`offer`, nothing secret), the receiving user accepts or declines on
the card (`reply`), only then the item (`payload`), which must match its summary and pass
`Item::check`, and is saved by the same code as today (`items::store`): a host's risky
options refused and its alias numbered when taken, server keys added only for a host
with none, a hosts file group only staged for the Hosts file page and its administrator
password, a public key written as someone else's, an environment added as a new one.
Either side may offer. The sender keeps the item in memory only (never in history) until
the reply, for at most 10 minutes or until the session ends; the card then says the offer
ended and offers to send it again. At most 3 offers may wait in each direction. In a
chat the contact is known by its key, so the "another name" step of today's send doesn't
apply.

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
| history per conversation              | 5000 entries or 2 MiB, oldest dropped    |

A frame that breaks a content rule (too long, a control character, a bad variable name)
is answered with `refused` and the session goes on: the sender's message shows "not
delivered". A frame that doesn't parse, an unknown kind or a broken rate limit ends the
session; after a broken rate limit that contact's knocks are turned away for a minute and
the user sees why.

### A connection lost mid-send

- A message is written to the sender's history first, as *sending*. Without a receipt
  before the session ends it shows **Not delivered**, with **Send again** while the
  contact is online. It may have arrived after all; sent again under the same id, it is
  not stored twice.
- An offer waiting for its reply ends; a payload sent without `saved` back shows "not
  confirmed" (the receiver's card says whether it saved it).
- Half a frame is never taken: frames are read whole and authenticated before anything
  happens.

## 3. Secrets and variables

- **Secret.** A label (optional) and a value the sender types, with a term: 1 hour (the
  default), 1 day or 7 days. It goes as soon as it is sent, like a text, but shows
  masked on both sides until the user clicks **Show**; **Copy** goes through the app's
  clipboard (kept out of clipboard history and cloud clipboards, cleared after the time
  set in Settings), never through the page. The value reaches the page only on Show, one
  at a time.
- **Expiry.** Each side computes the expiry from its own clock: the sender from when it
  sent, the receiver from when it received plus `ttl`. On expiry both wipe the value from
  memory and from the history file and keep a line "Secret · expired". The app checks
  every 30 seconds and whenever the vault is unlocked; a value whose term ran out while
  the app was closed or locked is wiped at unlock, before the history shows. The sender
  can wipe it earlier on both sides with **Revoke** while the receiver is online.
- **Honest UI.** The secret dialog says that the receiver can copy the value before it
  expires; expiry wipes the app's copy, not what someone copied.
- **Variables.** The sender picks an environment and ticks variables; the backend reads
  the values from the vault (the page never has them). They go with a term like a
  secret: names visible, values masked (secret ones) or shown (others), all of them
  wiped on expiry. Before that, the receiver may **Add to environment…**: pick one of
  their environments (or a new one), see what would be added and what would change, and
  confirm. New names are ticked; replacing a value the receiver has is never ticked by
  default; names that change how programs start (`PATH`, `LD_PRELOAD`, `DYLD_*`,
  `NODE_OPTIONS`, `BASH_ENV`, `PYTHONPATH`, `GIT_SSH_COMMAND`, …) are flagged and never
  ticked by default. Nothing is saved without that confirmation.
- A whole environment can still go as a card (§2): it is permanent, and its values go
  only after the receiver accepts.

## 4. Storage

### Where

History is **not in the vault file** but in files next to the app's other data, sealed
with a key that only the unlocked vault holds:

- `chats/<id>.chat` in the app's data folder, one file per conversation;
  `<id>` = HMAC(chat key, contact's public key), so file names don't tell whose it is.
- The file is XChaCha20-Poly1305 (`chacha20poly1305`, already a dependency) over the
  conversation's JSON, with a fresh random nonce on every write and this device's and the
  contact's keys as associated data, so a file can't be passed off as another
  conversation. Writes are atomic and gathered (at most one per second per conversation).
- The **chat key** is 32 random bytes in the vault's custom data,
  `sshkm.chat.<this device's key>`, made on first use. The file key is derived from it
  per conversation (HKDF).

Why not the vault file itself:

- **Every vault save keeps a backup of the previous file.** Messages in the vault would
  leave expired secrets and deleted chats in those backups, and each message would push
  out a backup taken before a real change.
- **A vault in a synced folder** is shared by the user's computers; history in it would
  reach them, and two computers writing chats into one file would conflict all the time.
- **Older versions and KeePassXC** would carry and show the history; with this design
  they see one custom data item they ignore and keep (as `sshkm.device.*` and
  `sshkm.own.key` today).

So the history is per device by construction: the files never leave this computer, the
vault transfer to a new computer doesn't take them, and the own-device sync must skip
the `sshkm.chat.` custom data (the `vault-sync` work is told so). An older version opening
the vault never looks into `chats/`. A copy of the vault restored from before the chat
key existed can't open the files: the app says once that older history can't be read and
starts again.

### What is in it

Per entry: id, direction, kind, time, delivery state, the text, a card's summary and
outcome, a secret's label, value and expiry, variables and expiry. Never a card's item
(only its summary). Also the last-read mark (for unread counts) and the ids seen.

### Life of a chat

- **Cap**: 5000 entries or 2 MiB per conversation, oldest dropped first; one contact can't
  push out another's history.
- **Delete a chat**: the file goes, on this device only; the dialog says the contact
  keeps their copy.
- **Removing a contact** (or one of the user's devices): its tag leaves the
  announcement, its knocks fail, an open session closes at once. The remove dialog asks
  whether to delete the chat too (ticked). A chat kept stays readable, without a
  composer; its secrets still expire. A contact removed by another computer through a
  synced vault leaves its file hidden until the user deletes chats.
- **Locking** drops the decrypted history from memory, closes sessions and stops the
  announcement.
- Deleting and expiry remove values from the app's files; copies the system made of
  the encrypted file before (Time Machine, disk snapshots) stay as safe as the vault
  itself. `SECURITY.md` says so.

## 5. Notifications

A message, card or secret that arrives while the window is not focused (hidden to the
tray included) shows a system notification: the contact's name and "New message", or
"New messages (3)". **Never any content**, not even of a text, and never a secret's label
or value. At most one per conversation per 30 seconds; clicking it opens the
conversation. Unread counts show on the Chats tab, on Nearby in the sidebar and in the
tray menu. This needs `tauri-plugin-notification` (the official plugin): a new
dependency; macOS asks the user's permission the first time.

## 6. UI

Nearby gets two tabs in its toolbar: **Devices** (today's page) and **Chats**, with the
unread count. Route: `{ page: 'nearby'; tab?: 'chats'; chat?: string }` (a device key).

- **Chats list** (left): the user's devices, then contacts. Each row: name (the vault's
  name, never the announced one), online state as a dot *and* text, the last text
  message (secrets and cards by kind only: "Secret", "Host prod"), unread count.
  Offline contacts sort after online ones. Contacts also get **Message** in the Devices
  tab.
- **Conversation** (right): header with the name, online state and a menu (Delete
  chat). Messages as bubbles with time and delivery state (sending, delivered, not
  delivered · Send again). Composer: text field (Enter sends, Shift+Enter breaks the
  line) and **+** with **Secret…**, **Variables…** and **From vault…** (today's send
  pickers: login, host, hosts file group, public key, environment). Offline: the
  composer is disabled with "Aziz is offline. Messages go only while you both have
  Nearby open."
- **Secret bubble**: label, masked value, Show / Copy, "Expires in 50 min", Revoke on
  the sender's side; after expiry "Secret · expired".
- **Variables bubble**: label, names, count, expiry, **Add to environment…** (review
  dialog, §3).
- **Item card**: today's `ItemCard`, with Accept / Decline for the receiver and the state
  for the sender (waiting, accepted, saved as `prod 2`, declined, ended).
- Text is plain: no links that open, no markup; long words wrap. The vault locked: the
  tab asks to unlock.
- Built with the design skills (`design:design-system` first, `design:ux-copy` in en, ru,
  uz, `design:accessibility-review` and `design:design-critique` on the result), with
  semantic color tokens only.

## 7. Threat model

| who / what | what they can do | what stops it |
| --- | --- | --- |
| **Stranger on the LAN** | See announcements, connect to the chat port, spoof an announcement, watch traffic | Random instance names and padded tags tell nothing but "an app with Nearby open, ≤N contacts". A connection gets a random challenge and is closed: no device key, no name. A spoofed announcement fails the knock or the handshake. Traffic is Noise-encrypted; secrets are padded. They can always disrupt the network (out of scope). |
| **Malicious contact** | Flood, send huge or malformed frames, phishing text, risky items or variables, keep a secret | Rate limit, size limits, per-conversation cap, at most 3 offers. Strict checks; malformed ends the session. Text is plain, never a link or markup; names are the vault's. Items keep today's checks (risky ssh options refused, hosts group via the Hosts file page). Variables are added only after review, risky names flagged and unticked. A term is at most 7 days; the UI says a receiver can copy a secret. |
| **Replay** | Resend recorded traffic or old frames | Noise: every session has its own keys and nonces; a frame can't be replayed in or across sessions. The knock is bound to a fresh challenge and to the handshake's prologue. A contact resending its own id is dropped as a duplicate. |
| **Contact impersonation** | Pretend to be a contact | The knock needs the contact key (X25519 of the device keys); the handshake proves the device key; it must be the one that knocked. |
| **Removed contact** | Keep reaching the user | No tag for it, its knocks fail, its session closes when it is removed. |
| **Stolen unlocked laptop** | Read history, reveal unexpired secrets, chat as the user | Same as the unlocked vault: auto-lock, lock on sleep; locking closes chats. Secrets live at most their term. |
| **Stolen locked laptop / disk image** | Read `chats/` | Encrypted with a key only the unlocked vault has; file names say nothing. Old encrypted copies in system backups are as safe as the vault. |
| **Older version** | Get chat frames, break on the vault | Never connected to for chats (no announcement); `Hello.chat` gates frames; it ignores `sshkm.chat.*` custom data. |

## 8. How it is built

- **Core (`sshkm-core`)**
  - `p2p/contact.rs`: the contact key, presence tags, the knock (with tests).
  - `p2p/chat.rs`: `ChatFrame`, its checks and limits, the rate limit bucket.
  - `p2p/session.rs`: a prologue per session kind, and splitting a `Session<TcpStream>`
    into a reader and a writer that share the Noise state (each frame encrypted or
    decrypted under a short lock; writes stay in order).
  - `p2p/protocol.rs`: `Hello.chat` and `Message::Chat` only.
  - `chat/`: a conversation's history (entries, cap, expiry, duplicates, unread),
    sealing and opening the file; `vault/chat.rs` for the chat key.
- **App (`src-tauri/src/nearby/chat/`)**: the online state (Nearby open, grace, lock),
  announcement and recognition, the chat port and knock, sessions (one thread reading
  per session, pings, receipts, sending again), expiry timer, notifications, events
  (`chat-changed`, `chat-message`). `nearby/mod.rs` only gains the module and hooks
  (lock, contact removed). Commands: `chat_set_online`, `chat_list`, `chat_history`,
  `chat_send_text`, `chat_send_secret`, `chat_send_variables`, `chat_send_item`,
  `chat_answer`, `chat_reveal`, `chat_copy`, `chat_revoke`, `chat_retry`,
  `chat_add_variables`, `chat_mark_read`, `chat_delete`; registered in `build.rs` and
  `lib.rs`, mocked in `src/mocks/` (two fake contacts, one online).
- **Tests**: frame round-trips and checks; limits and the rate limit; tags recognised
  only by a contact and only around their window, padding; the knock (wrong key, replayed
  challenge, stranger gets no key); duplex sessions over loopback; an older `Hello`
  without `chat` refused on the chat port, and today's `Hello` read by an older version;
  duplicates, receipts, sending again after a cut; expiry on both sides, at unlock, and
  revoke; history files (sealed, wrong conversation refused, cap); the vault keeps
  `sshkm.chat.*` and an older-shaped reader ignores it; nothing of a chat in the vault
  file or its backups; UI tests for the composer, secrets and the review.
- **Docs and notes**: this file, `docs/architecture.md`, `SECURITY.md` (Nearby: chats,
  the knock, storage), a `new` changelog note, and a `notice` only if the background
  switch is ever built on by default.
- **Pull requests**: two, if one is too large to review — (1) core, protocol and the
  app's backend with mocks; (2) the UI, changelog and docs.

## Open questions

1. **Storage outside the vault file**: the history in its own files, sealed with a key
   kept in the vault, rather than inside `vault.kdbx` (§4: vault backups would keep
   expired secrets; a synced vault would share the history). Is that what "kept in the
   vault, encrypted" should mean?
2. **Online while Nearby is open, plus two minutes** after leaving it — or only while the
   Chats tab itself is open?
3. **`tauri-plugin-notification`** as a new dependency, for notifications without
   content.
4. The **background switch** (§1): build it later, off by default, or not at all?
