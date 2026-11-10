import { describe, expect, it } from 'vitest';
import type { LeakFinding } from '@/bindings/LeakFinding';
import type { LeakPlace } from '@/bindings/LeakPlace';
import type { LeakSecret } from '@/bindings/LeakSecret';
import {
  groupLeaks,
  leakKind,
  placeNames,
  repositories,
  scanPercent,
  secretKey,
  secretLabel,
  shortPath,
} from './leakModel';
import { checkResults, leakItem } from './model';

const token: LeakSecret = {
  kind: 'variable',
  envId: 'env-3',
  project: 'shop-api',
  environment: 'prod',
  name: 'STRIPE_KEY',
};
const github: LeakSecret = {
  kind: 'password',
  entryId: 'e-1',
  title: 'GitHub',
  entryKind: 'login',
};

let n = 0;
function finding(secret: LeakSecret, place: LeakPlace, path: string): LeakFinding {
  n += 1;
  return {
    id: `leak:${n}`,
    severity:
      place.kind === 'aiSession' ? 'critical' : place.kind === 'shellHistory' ? 'warning' : 'info',
    secret,
    place,
    path,
    line: 1,
    occurrences: 1,
    encodings: [],
    redactable: place.kind === 'aiSession',
    modified: null,
  };
}

const file = (git: 'tracked' | 'untracked' | 'ignored' | 'outside', repository: string | null) =>
  ({ kind: 'file', git, repository }) as const;

describe('leak model', () => {
  it('sorts places into the four checks', () => {
    expect(leakKind({ kind: 'aiSession', tool: 'codex' })).toBe('leakAi');
    expect(leakKind({ kind: 'shellHistory', shell: 'fish' })).toBe('leakHistory');
    expect(leakKind(file('tracked', '/r'))).toBe('leakRepository');
    expect(leakKind(file('untracked', '/r'))).toBe('leakRepository');
    expect(leakKind(file('ignored', '/r'))).toBe('leakLocalFile');
    expect(leakKind(file('outside', null))).toBe('leakLocalFile');
  });

  it('names secrets as the backend does, without values', () => {
    expect(secretKey(token)).toBe('var:env-3:STRIPE_KEY');
    expect(secretKey(github)).toBe('entry:e-1');
    expect(secretLabel(token)).toBe('shop-api / prod / STRIPE_KEY');
    expect(secretLabel(github)).toBe('GitHub');
  });

  it('groups findings by secret and kind of place, worst severity first', () => {
    const findings = [
      finding(token, { kind: 'aiSession', tool: 'claudeCode' }, '/h/.claude/a.jsonl'),
      finding(token, { kind: 'aiSession', tool: 'codex' }, '/h/.codex/b.jsonl'),
      finding(token, { kind: 'aiSession', tool: 'claudeCode' }, '/h/.claude/c.jsonl'),
      finding(token, file('ignored', '/w/shop'), '/w/shop/.env'),
      {
        ...finding(token, file('outside', null), '/h/Downloads/.env'),
        severity: 'warning' as const,
      },
      finding(github, { kind: 'shellHistory', shell: 'zsh' }, '/h/.zsh_history'),
    ];
    const groups = groupLeaks(findings);
    expect(groups.map((g) => [g.kind, g.severity, g.findings.length])).toEqual([
      ['leakAi', 'critical', 3],
      ['leakLocalFile', 'warning', 2],
      ['leakHistory', 'warning', 1],
    ]);
    expect(groups[0]?.ignoreId).toBe('leaks:leakAi:var:env-3:STRIPE_KEY');
    expect(placeNames(groups[0] as never)).toEqual(['Claude Code', 'Codex']);
    expect(repositories(groups[1] as never)).toEqual(['/w/shop']);

    const results = checkResults(groups.map(leakItem));
    expect(results.get('leaksAi')).toEqual({ count: 1, worst: 'critical' });
    expect(results.get('leaksRepositories')).toEqual({ count: 0, worst: null });
    expect(results.get('leaksFiles')).toEqual({ count: 1, worst: 'warning' });
  });

  it('labels files by their folder too', () => {
    expect(shortPath('/w/shop/.env')).toBe('shop/.env');
    expect(shortPath('C:\\code\\site\\.env.local')).toBe('site/.env.local');
  });

  it('says how far a scan got', () => {
    expect(scanPercent({ phase: null, bytesDone: 0, bytesTotal: 0 })).toBeNull();
    expect(scanPercent({ phase: 'listing', bytesDone: 0, bytesTotal: 0 })).toBeNull();
    expect(scanPercent({ phase: 'reading', bytesDone: 0, bytesTotal: 0 })).toBe(0);
    expect(scanPercent({ phase: 'reading', bytesDone: 50, bytesTotal: 200 })).toBe(25);
    expect(scanPercent({ phase: 'reading', bytesDone: 300, bytesTotal: 200 })).toBe(100);
  });
});
