# Contributing

Thanks for helping! This page covers building the app and the conventions that keep the
project easy to work on.

## Building from source

You need:

- Rust (stable);
- Node.js 22 or later;
- pnpm 10;
- the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) for your platform.

```bash
pnpm install
pnpm app:dev        # desktop app with hot reload
pnpm dev            # UI only, in a browser, backed by an in-memory mock
pnpm app:build      # release build with installers for your platform
```

## Screenshots

The README screenshots come from `pnpm dev` with its sample data, so nothing from
your own `~/.ssh` ends up in them. With `pnpm dev` running and Google Chrome
installed, refresh them all with:

```bash
pnpm screenshots
```

## Checks

CI runs these on macOS, Windows and Linux; run them before you push:

```bash
pnpm lint && pnpm typecheck && pnpm test
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## Project layout

| Path                | What it is                                                                                              |
| ------------------- | ------------------------------------------------------------------------------------------------------- |
| `crates/sshkm-core` | Platform-aware core: keys, `ssh_config`, `known_hosts`, agent protocol, permissions, audit. No UI code. |
| `src-tauri`         | The desktop shell: Tauri commands over the core, menu bar, file watcher.                                |
| `src`               | React and TypeScript UI. `src/bindings` is generated from the Rust types.                               |
| `docs/`             | Architecture notes: see [docs/architecture.md](docs/architecture.md).                                   |

## Conventions

- **Where code goes.** Logic that touches OpenSSH files or the agent belongs in
  `crates/sshkm-core`, with tests. `src-tauri` only exposes it to the UI.
- **Changing types.** After changing a type the UI sees, run
  `cargo test --workspace --all-features` and commit the regenerated `src/bindings/`.
- **New strings.** Add every UI string to `src/i18n/locales/en.ts`, `ru.ts` and `uz.ts`.
  The locale test fails if one is missing.
- **Secrets.** Never log or serialise key material or passphrases.
- **Commits and pull requests.** Keep them small and focused, and describe the user-visible
  change.

## License of contributions

SSH Key Manager is licensed under the [GNU AGPL v3](LICENSE) (`AGPL-3.0-only`). So that the
project can also be offered under other terms, for example in app stores, an outside
contribution is merged only after you agree to a contributor license agreement; the pull
request links to it.

## Builds and releases

There are three workflows:

| Workflow      | Runs on                     | What it does                                              |
| ------------- | --------------------------- | --------------------------------------------------------- |
| `ci.yml`      | every push and pull request | runs the checks above on all three systems                |
| `build.yml`   | every push to `main`        | builds installers and keeps them as artifacts for 30 days |
| `release.yml` | a `v*` tag                  | builds installers and publishes them as a GitHub Release  |

To publish a release:

1. Bump the version in `package.json`, `Cargo.toml`, `src-tauri/tauri.conf.json` and
   `extension/manifest.json` (the browser extension ships with the app, and a test fails
   if its version differs), and commit it to `main` as `Release 0.2.0`. `ci.yml` and
   `build.yml` skip a commit whose message starts with `Release `, since `release.yml`
   builds it from the tag.
2. Push a tag:

   ```bash
   git tag v0.2.0 && git push origin v0.2.0
   ```

3. Wait for the workflow. The three platforms build first. Then the `sign` job, after
   approval in the `release` environment, signs the update bundles and creates the draft
   release, and the release is published. Installed apps then offer the update within a
   few hours: they read `latest.json` from the latest release. If a build fails, nothing
   is released: fix the problem and re-run the failed jobs, or delete the tag and push it
   again.
4. Publish the extension: run `pnpm extension:package` on the release commit and upload
   the zip to the Chrome Web Store item (**Package → Upload new package**, then
   **Submit for review**). [extension/store/README.md](extension/store/README.md) has
   the details.

Releases are signed for the in-app updater. The workflow needs the `TAURI_SIGNING_PRIVATE_KEY`
secret of the `release` environment (Settings → Environments → release; not a repository
secret, so only the signing job can read it), plus `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` if
the key has a password: the private
half of `plugins.updater.pubkey` in `src-tauri/tauri.conf.json`. If that key is lost,
installed apps can no longer update themselves, so keep a backup. The updater bundles are
only built with `--config src-tauri/tauri.release.conf.json`, so `pnpm app:build` works
without the key.

Code signing (Apple Developer ID, a Windows certificate) is optional. The secrets it needs
are listed at the top of `release.yml`.
