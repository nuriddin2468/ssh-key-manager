<p align="center">
  <img src="assets/app-icon.svg" width="112" height="112" alt="SSH Key Manager icon">
</p>

<h1 align="center">SSH Key Manager</h1>

<p align="center">
  Your SSH keys, hosts and agent in one clear window.<br>
  For macOS, Windows and Linux · in English, Русский and Oʻzbekcha
</p>

<p align="center">
  <a href="https://github.com/nuriddin2468/ssh-key-manager/releases/latest"><b>Download</b></a> ·
  <a href="https://github.com/nuriddin2468/ssh-key-manager/actions/workflows/build.yml">Latest builds</a> ·
  <a href="#what-it-does">Features</a> ·
  <a href="#privacy-and-safety">Privacy</a>
</p>

<p align="center">
  <a href="https://github.com/nuriddin2468/ssh-key-manager/actions/workflows/ci.yml"><img src="https://github.com/nuriddin2468/ssh-key-manager/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://github.com/nuriddin2468/ssh-key-manager/releases/latest"><img src="https://img.shields.io/github/v/release/nuriddin2468/ssh-key-manager?include_prereleases&label=release" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license"></a>
</p>

---

SSH Key Manager is a desktop app for the SSH setup you already have.

- It works directly on the standard OpenSSH files (`~/.ssh`, `~/.ssh/config`, `~/.ssh/known_hosts`) and the `ssh-agent` your system runs, so `ssh`, `git` and your IDE keep working exactly as before.
- There is no account, no cloud and no new place your keys live.
- One click checks your whole setup, and anything that needs fixing is explained in plain words.

## Download

| System                | File                          | Notes                                                     |
| --------------------- | ----------------------------- | --------------------------------------------------------- |
| **macOS** 12 or later | `.dmg`                        | One universal build for Apple Silicon and Intel           |
| **Windows** 10 or 11  | `.msi` or `.exe`              | Uses the OpenSSH client built into Windows                |
| **Linux**             | `.deb`, `.rpm` or `.AppImage` | Needs `openssh-client` (installed with the `.deb`/`.rpm`) |

**[Get the latest release →](https://github.com/nuriddin2468/ssh-key-manager/releases/latest)**

Want the newest version before a release? Every change to the `main` branch is built automatically.

1. Open the [latest builds](https://github.com/nuriddin2468/ssh-key-manager/actions/workflows/build.yml) and pick the top green run.
2. Download your system's file from **Artifacts**. You need to be signed in to GitHub, and the files are kept for 30 days.

### First launch

Builds are not code-signed yet, so your system asks once whether you trust the app.

- **macOS.** Open the `.dmg` and drag the app to **Applications**. The first time, right-click it and choose **Open**, then **Open** again. If macOS still refuses, go to **System Settings → Privacy & Security** and click **Open Anyway**.
- **Windows.** If SmartScreen says "Windows protected your PC", click **More info → Run anyway**.
- **Linux.** Install the `.deb` or `.rpm` with your package manager. For the AppImage, run `chmod +x SSH*.AppImage` and start it.

## What it does

**Overview.** One button checks your keys, config and file permissions and tells you, in a sentence, how things stand.

**Keys**
- See every key in `~/.ssh` at a glance: its type, fingerprint, whether it has a passphrase, whether it is loaded in the agent, and which servers use it.
- Create a new key (Ed25519, RSA or ECDSA). The same dialog can unlock it in the agent and add a server entry for it.
- Copy a public key in one click, ready to paste into GitHub, GitLab or a server.
- Add, change or remove a passphrase. Import existing keys.
- Deleted keys go to the Trash, so you can get them back.

**Hosts.** Edit `~/.ssh/config` with a form instead of a text editor, so you can type `ssh prod` instead of the full address, user, port and key.
- Your comments and formatting are kept exactly as they were, and a backup is made before every change.
- Test a connection right from the app.
- Prefer text? Edit the raw file in the app.

**Agent.** See which keys are unlocked right now. Unlock a key for 1 hour, 8 hours or until you log out, and lock one or all with a click.

**Known hosts**
- Browse the servers you have trusted, including hashed entries.
- Seeing "REMOTE HOST IDENTIFICATION HAS CHANGED"? The app fetches the server's current key and compares it with the saved one, so you know whether it is safe to remove the old entry.

**Audit**
- Finds the things that weaken security or quietly break SSH:
  - old or short keys;
  - keys without a passphrase;
  - private keys other users can read;
  - config lines that point to missing files.
- Fixes file permissions in one click.

**Feels native.** Menu bar and keyboard shortcuts on macOS (⌘1–6, ⌘N, ⌘,), and changes you make in a terminal show up instantly.

## Privacy and safety

- **Nothing leaves your computer.** The app makes no network requests. The only exceptions are the two times you ask it to reach a server: when checking a host key and when testing a connection.
- **Your private keys stay private.** The interface only ever sees public keys and fingerprints. Passphrases are used once and never stored.
- **Your files stay standard.** Everything is plain OpenSSH, and you can stop using the app at any time.
- **Mistakes can be undone.** Config files are backed up before every edit, and keys go to the Trash, not into oblivion.

Details in [SECURITY.md](SECURITY.md).

## FAQ

**Does it replace `ssh-agent` or store my keys somewhere else?**
No. It works with the agent your system already runs and the keys already in `~/.ssh`.

**Where are the backups?**
Open **Settings → Files → Backups**. The app keeps the 20 most recent copies of each file.

**Can I use it with keys outside `~/.ssh`?**
Hosts can point to keys anywhere, and the app shows them. The key list itself covers `~/.ssh`.

**Something doesn't look right?**
[Open an issue](https://github.com/nuriddin2468/ssh-key-manager/issues/new) with your system and what you expected to see.

## Contributing

SSH Key Manager is open source. To build it yourself or help out, see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
