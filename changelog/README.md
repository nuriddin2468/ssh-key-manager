# Release notes

Each change that users would notice adds a note to `unreleased/` in the same pull request.
A release moves the notes into `releases.json` (`node scripts/changelog.mjs release <version>`),
and the app shows them before it updates and once more after. `CHANGELOG.md` and the GitHub
release are made from the same file.

A note is a JSON file with a short name of its own, such as `unreleased/tray-menu.json`. Notes
never share a file, so pull requests don't conflict over them:

```json
{
  "kind": "fixed",
  "en": "Check no longer says the server refused your keys when a key only needs its passphrase.",
  "ru": "«Проверить» больше не сообщает, что сервер не принял ваши ключи, когда ключу просто нужен пароль.",
  "uz": "«Tekshirish» endi kalitga shunchaki parol kerak boʻlganda server kalitlaringizni qabul qilmadi demaydi."
}
```

`kind` is one of:

| kind       | for                                                                                                                                                                            |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `notice`   | what to know before updating: the app behaves differently, a file changes so an older version can't read it, other devices need the new version too. Shown first, as a warning |
| `security` | a security fix. The app then recommends the update                                                                                                                             |
| `new`      | something the app couldn't do before                                                                                                                                           |
| `improved` | something that works better or looks different                                                                                                                                 |
| `fixed`    | a bug fix                                                                                                                                                                      |

Write each note in English, Russian and Uzbek (Latin script, as in `src/i18n/locales/uz.ts`): one
or two sentences on one line, at most 400 characters, about what the user sees, not how the code
changed. Name buttons and settings as the app names them in that language. Leave out changes no
user would notice: refactoring, tests, CI. `node scripts/changelog.mjs check` checks the notes,
and CI warns about a pull request that changes the app's code without one.

To fix a note that has been released, edit `releases.json` and run
`node scripts/changelog.mjs write` to update `CHANGELOG.md`.
