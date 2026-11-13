// The page shows everything from outside (ssh config, vault titles, names
// from contacts, server output) as text: React escapes it, and nothing
// parses it as HTML. A script in the page could drive the in-app terminal
// and run commands (SECURITY.md, "Locked-down webview"), so no HTML sink may
// come in, in the app or in the browser extension. Tests may build pages.

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = process.cwd();
const SOURCES = ['src', 'extension/src'];
const SINKS = /dangerouslySetInnerHTML|innerHTML|outerHTML|insertAdjacentHTML|document\.write/;

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    const code = /\.(ts|tsx|js|jsx|mjs)$/.test(entry.name);
    const test = /\.test\.(ts|tsx)$/.test(entry.name);
    return code && !test ? [path] : [];
  });
}

describe('the page renders outside text as text', () => {
  it('has no HTML sinks in the app or the extension', () => {
    const files = SOURCES.flatMap((dir) => sourceFiles(join(ROOT, dir)));
    expect(files.length).toBeGreaterThan(100);
    const sinks = files.flatMap((file) =>
      readFileSync(file, 'utf8')
        .split('\n')
        .flatMap((line, index) =>
          SINKS.test(line) ? [`${relative(ROOT, file)}:${index + 1}: ${line.trim()}`] : [],
        ),
    );
    expect(sinks).toEqual([]);
  });
});
