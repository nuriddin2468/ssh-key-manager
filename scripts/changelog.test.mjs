import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  changelogMarkdown,
  changeProblems,
  compareVersions,
  newPermissions,
  releaseMarkdown,
  releasesProblems,
  setVersion,
  sortChanges,
  VERSION_FILES,
} from './changelog.mjs';

const note = (kind, en = 'Something changed.') => ({
  kind,
  en,
  ru: 'Что-то изменилось.',
  uz: 'Nimadir oʻzgardi.',
});

describe('changeProblems', () => {
  it('accepts a note in every language', () => {
    expect(changeProblems(note('fixed'), 'x')).toEqual([]);
  });

  it('names what is wrong', () => {
    expect(changeProblems({ kind: 'changed', en: ' Padded ', ru: 'a\nb', extra: 1 }, 'x')).toEqual([
      'x: "kind" is one of notice, security, new, improved, fixed',
      'x: "en" is one line, without spaces around it',
      'x: "ru" is one line, without spaces around it',
      'x: "uz" is missing',
      'x: unknown field "extra"',
    ]);
  });

  it('refuses a note too long for the update dialog', () => {
    expect(changeProblems(note('new', 'a'.repeat(401)), 'x')).toEqual([
      'x: "en" is longer than 400 characters',
    ]);
  });
});

describe('releasesProblems', () => {
  const release = (version, changes = [note('new')]) => ({ version, date: '2026-11-06', changes });

  it('wants versions newest first', () => {
    expect(releasesProblems([release('0.7.0'), release('0.6.0')])).toEqual([]);
    expect(releasesProblems([release('0.6.0'), release('0.10.0')])).toEqual([
      'changelog/releases.json 0.10.0: listed after 0.6.0; newest first',
    ]);
  });

  it('wants a version, a date and at least one change', () => {
    expect(
      releasesProblems([
        { version: 'v1', changes: [] },
        { version: '1.0.0', date: 'today', changes: [] },
      ]),
    ).toEqual([
      'changelog/releases.json #1: "version" is like 1.2.3',
      'changelog/releases.json 1.0.0: "date" is like 2026-11-04',
      'changelog/releases.json 1.0.0: "changes" lists at least one change',
    ]);
  });
});

it('compares versions by number', () => {
  expect(compareVersions('0.10.0', '0.9.9')).toBeGreaterThan(0);
  expect(compareVersions('1.2.3', '1.2.3')).toBe(0);
});

it('lists changes by kind, keeping their order within a kind', () => {
  const changes = [note('fixed', 'A'), note('new', 'B'), note('notice', 'C'), note('fixed', 'D')];
  expect(sortChanges(changes).map((change) => change.en)).toEqual(['C', 'B', 'A', 'D']);
});

it('writes a release in Markdown, a section for each kind', () => {
  const markdown = releaseMarkdown({
    version: '1.0.0',
    date: '2026-11-06',
    changes: [note('notice', 'Read this.'), note('fixed', 'One.'), note('fixed', 'Two.')],
  });
  expect(markdown).toBe('### Before you update\n\n- Read this.\n\n### Fixed\n\n- One.\n- Two.');
});

it('keeps CHANGELOG.md in step with releases.json', () => {
  const releases = JSON.parse(readFileSync('changelog/releases.json', 'utf8'));
  expect(releasesProblems(releases)).toEqual([]);
  // Git on Windows checks text files out with CRLF line endings.
  const changelog = readFileSync('CHANGELOG.md', 'utf8').replaceAll('\r\n', '\n');
  expect(changelog).toBe(changelogMarkdown(releases));
});

it('finds the version in every file that keeps it', () => {
  const version = JSON.parse(readFileSync('src-tauri/tauri.conf.json', 'utf8')).version;
  for (const { path, pattern } of VERSION_FILES) {
    const text = readFileSync(path, 'utf8');
    expect(pattern.exec(text)?.[2], path).toBe(version);
    const bumped = setVersion(text, pattern, '9.9.9', path);
    expect(pattern.exec(bumped)?.[2], path).toBe('9.9.9');
    expect(bumped.length - text.length, path).toBe('9.9.9'.length - version.length);
  }
});

it('names the permissions the extension asks for since a release', () => {
  const before = { permissions: ['storage'], host_permissions: ['https://*/*'] };
  const now = {
    permissions: ['storage', 'nativeMessaging'],
    optional_permissions: ['privacy'],
    host_permissions: ['https://*/*'],
  };
  expect(newPermissions(before, now)).toEqual(['nativeMessaging', 'privacy']);
  expect(newPermissions(now, now)).toEqual([]);
});
