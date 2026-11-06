// Release notes. Each pull request that changes what users see adds a note to
// changelog/unreleased/ (see changelog/README.md). A release moves those notes
// into changelog/releases.json, which the app, CHANGELOG.md and the release's
// latest.json are made from.
//
//   node scripts/changelog.mjs check [--since <commit>]
//     Checks the notes, and that CHANGELOG.md and the app's version match
//     releases.json. With --since, warns if the code changed since that commit
//     without a new note.
//   node scripts/changelog.mjs write
//     Writes CHANGELOG.md again after an edit to releases.json.
//   node scripts/changelog.mjs release <version>
//     Moves the unreleased notes into releases.json as <version>, writes
//     CHANGELOG.md and sets <version> everywhere the app's version is kept.

import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const UNRELEASED = 'changelog/unreleased';
const RELEASES = 'changelog/releases.json';
const CHANGELOG = 'CHANGELOG.md';

/** Kinds of change, in the order a release lists them, with their CHANGELOG.md heading. */
export const KINDS = {
  notice: 'Before you update',
  security: 'Security',
  new: 'New',
  improved: 'Improved',
  fixed: 'Fixed',
};
/** Every note is written in each language the app speaks. */
export const LANGUAGES = ['en', 'ru', 'uz'];
/** Notes are a sentence or two, shown in a list in the update dialog. */
export const MAX_TEXT = 400;

/** Every file that holds the app's version, and how to find it there. */
export const VERSION_FILES = [
  { path: 'package.json', pattern: /^( {2}"version": ")([^"]+)(")/m },
  { path: 'src-tauri/tauri.conf.json', pattern: /^( {2}"version": ")([^"]+)(")/m },
  { path: 'extension/manifest.json', pattern: /^( {2}"version": ")([^"]+)(")/m },
  { path: 'Cargo.toml', pattern: /^(\[workspace\.package\]\nversion = ")([^"]+)(")/m },
  ...['sshkm-app', 'sshkm-core', 'sshkm-os'].map((name) => ({
    path: 'Cargo.lock',
    pattern: new RegExp(`^(name = "${name}"\\nversion = ")([^"]+)(")`, 'm'),
  })),
];

/**
 * The problems with one change (a note in changelog/unreleased/ or an item
 * of a release), each starting with `where`.
 */
export function changeProblems(change, where) {
  if (typeof change !== 'object' || change === null || Array.isArray(change)) {
    return [`${where}: not an object`];
  }
  const problems = [];
  if (!Object.hasOwn(KINDS, change.kind)) {
    problems.push(`${where}: "kind" is one of ${Object.keys(KINDS).join(', ')}`);
  }
  for (const language of LANGUAGES) {
    const text = change[language];
    if (typeof text !== 'string' || text.trim() === '') {
      problems.push(`${where}: "${language}" is missing`);
    } else if (text !== text.trim() || /[\n\r]/.test(text)) {
      problems.push(`${where}: "${language}" is one line, without spaces around it`);
    } else if (text.length > MAX_TEXT) {
      problems.push(`${where}: "${language}" is longer than ${MAX_TEXT} characters`);
    }
  }
  for (const key of Object.keys(change)) {
    if (key !== 'kind' && !LANGUAGES.includes(key)) {
      problems.push(`${where}: unknown field "${key}"`);
    }
  }
  return problems;
}

/** The problems with releases.json: its shape, and versions newest first. */
export function releasesProblems(releases) {
  if (!Array.isArray(releases)) return [`${RELEASES}: not a list`];
  const problems = [];
  releases.forEach((release, index) => {
    const where = `${RELEASES} #${index + 1}`;
    if (!parseVersion(release?.version)) {
      problems.push(`${where}: "version" is like 1.2.3`);
      return;
    }
    const at = `${RELEASES} ${release.version}`;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(release.date ?? '')) {
      problems.push(`${at}: "date" is like 2026-11-04`);
    }
    if (!Array.isArray(release.changes) || release.changes.length === 0) {
      problems.push(`${at}: "changes" lists at least one change`);
    } else {
      release.changes.forEach((change, n) => {
        problems.push(...changeProblems(change, `${at} change ${n + 1}`));
      });
    }
    for (const key of Object.keys(release)) {
      if (!['version', 'date', 'changes'].includes(key)) {
        problems.push(`${at}: unknown field "${key}"`);
      }
    }
    const newer = releases[index - 1];
    if (parseVersion(newer?.version) && compareVersions(newer.version, release.version) <= 0) {
      problems.push(`${at}: listed after ${newer.version}; newest first`);
    }
  });
  return problems;
}

/** [major, minor, patch] of a plain `1.2.3` version, or null. */
export function parseVersion(version) {
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(version ?? '');
  return match ? match.slice(1).map(Number) : null;
}

export function compareVersions(a, b) {
  const [x, y] = [parseVersion(a), parseVersion(b)];
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

/** Changes in the order a release lists them: by kind, then as given. */
export function sortChanges(changes) {
  const order = Object.keys(KINDS);
  return changes
    .map((change, index) => ({ change, index }))
    .sort(
      (a, b) => order.indexOf(a.change.kind) - order.indexOf(b.change.kind) || a.index - b.index,
    )
    .map(({ change }) => change);
}

/** One release in Markdown, in English, without its heading. */
export function releaseMarkdown(release) {
  const sections = [];
  for (const [kind, heading] of Object.entries(KINDS)) {
    const items = release.changes.filter((change) => change.kind === kind);
    if (items.length === 0) continue;
    sections.push(`### ${heading}\n\n${items.map((change) => `- ${change.en}`).join('\n')}`);
  }
  return sections.join('\n\n');
}

/** CHANGELOG.md for these releases. The release workflow reads each release's section from it. */
export function changelogMarkdown(releases) {
  const parts = [
    '# Changelog',
    'What changed in each version of SSH Key Manager. The app shows these notes in your ' +
      'language before it updates, and once more after.',
    '<!-- Made from changelog/releases.json by scripts/changelog.mjs: edit that file, then run `node scripts/changelog.mjs write`. -->',
  ];
  for (const release of releases) {
    parts.push(`## ${release.version} (${release.date})`, releaseMarkdown(release));
  }
  return `${parts.join('\n\n')}\n`;
}

/** The text of `file` with the version found by `pattern` set to `version`. */
export function setVersion(text, pattern, version, file) {
  if (!pattern.test(text)) throw new Error(`no version found in ${file}`);
  return text.replace(pattern, (_, before, _old, after) => `${before}${version}${after}`);
}

function read(path) {
  return readFileSync(join(ROOT, path), 'utf8');
}

function write(path, text) {
  writeFileSync(join(ROOT, path), text);
}

function json(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function appVersion() {
  return JSON.parse(read('src-tauri/tauri.conf.json')).version;
}

/** The notes waiting for the next release, as [file name, parsed or the parse error]. */
function unreleased() {
  return readdirSync(join(ROOT, UNRELEASED))
    .filter((name) => name !== '.gitkeep')
    .sort()
    .map((name) => {
      try {
        return [name, JSON.parse(read(`${UNRELEASED}/${name}`))];
      } catch (error) {
        return [name, error];
      }
    });
}

function unreleasedProblems(notes) {
  return notes.flatMap(([name, note]) => {
    const where = `${UNRELEASED}/${name}`;
    if (!/^[a-z0-9][a-z0-9-]*\.json$/.test(name)) {
      return [`${where}: name it like some-change.json (lowercase letters, digits, dashes)`];
    }
    if (note instanceof Error) return [`${where}: ${note.message}`];
    return changeProblems(note, where);
  });
}

function check(since) {
  const releases = JSON.parse(read(RELEASES));
  const problems = [...releasesProblems(releases), ...unreleasedProblems(unreleased())];
  if (problems.length === 0) {
    if (releases[0]?.version !== appVersion()) {
      problems.push(
        `the app is ${appVersion()} but ${RELEASES} starts at ${releases[0]?.version}: ` +
          'release with `node scripts/changelog.mjs release <version>`',
      );
    }
    if (read(CHANGELOG) !== changelogMarkdown(releases)) {
      problems.push(`${CHANGELOG} is out of date: run \`node scripts/changelog.mjs write\``);
    }
  }
  if (problems.length > 0) {
    for (const problem of problems) console.error(problem);
    process.exit(1);
  }
  if (since) remind(since);
  console.log('Release notes are in order.');
}

/**
 * Warns, without failing, if the app's code changed since `since` and no note
 * was added: most such changes are something users notice.
 */
function remind(since) {
  const diff = (filter) =>
    execFileSync('git', ['diff', '--name-only', `--diff-filter=${filter}`, since, 'HEAD'], {
      cwd: ROOT,
      encoding: 'utf8',
    })
      .split('\n')
      .filter(Boolean);
  const code = diff('ACDMR').filter(
    (path) =>
      /^(src|src-tauri\/src|crates\/[^/]+\/src|extension\/src)\//.test(path) &&
      !/(\.test\.|\/tests?\/|^src\/bindings\/)/.test(path),
  );
  const added = diff('A').filter((path) => path.startsWith(`${UNRELEASED}/`));
  if (code.length > 0 && added.length === 0) {
    console.log(
      '::warning title=Release notes::This changes the app but adds no note to ' +
        `${UNRELEASED}/. If users would notice the change, add one (changelog/README.md says how).`,
    );
  }
}

function release(version) {
  const current = appVersion();
  if (!parseVersion(version)) throw new Error(`${version} is not a version like 1.2.3`);
  if (compareVersions(version, current) <= 0) {
    throw new Error(`${version} is not newer than the app's ${current}`);
  }
  const notes = unreleased();
  const problems = unreleasedProblems(notes);
  if (problems.length > 0) throw new Error(problems.join('\n'));
  if (notes.length === 0) {
    throw new Error(`${UNRELEASED}/ has no notes: a release says what changed`);
  }

  const now = new Date();
  const date = [now.getFullYear(), now.getMonth() + 1, now.getDate()]
    .map((part) => String(part).padStart(2, '0'))
    .join('-');
  const entry = { version, date, changes: sortChanges(notes.map(([, note]) => note)) };
  const releases = [entry, ...JSON.parse(read(RELEASES))];

  const files = new Map();
  for (const { path, pattern } of VERSION_FILES) {
    files.set(path, setVersion(files.get(path) ?? read(path), pattern, version, path));
  }
  for (const [path, text] of files) write(path, text);
  write(RELEASES, json(releases));
  write(CHANGELOG, changelogMarkdown(releases));
  for (const [name] of notes) rmSync(join(ROOT, UNRELEASED, name));

  console.log(`## ${version}\n\n${releaseMarkdown(entry)}\n`);
  console.log(
    `Read the notes above (and in ${RELEASES} for ru and uz), then commit as ` +
      `"Release ${version}" and push the tag v${version}.`,
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [command, arg, value] = process.argv.slice(2);
  try {
    if (command === 'check') check(arg === '--since' ? value : undefined);
    else if (command === 'write') write(CHANGELOG, changelogMarkdown(JSON.parse(read(RELEASES))));
    else if (command === 'release' && arg) release(arg);
    else {
      console.error('usage: changelog.mjs check [--since <commit>] | write | release <version>');
      process.exit(2);
    }
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
