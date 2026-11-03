import { describe, expect, it } from 'vitest';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntrySummary } from '@/bindings/EntrySummary';
import {
  avatar,
  canToggleClass,
  conflictCopyPath,
  DEFAULT_PASSWORD,
  daysSince,
  EMPTY_FORM,
  filterCounts,
  filterEntries,
  filterShowing,
  formatOtp,
  formFromEntry,
  inputFromForm,
  isOtpSecret,
  lockToastKey,
  matchesQuery,
  openableUrl,
  otpFraction,
  otpPeriod,
  otpRemaining,
  recoveryKeyGroups,
  strengthContext,
  strengthLabelKey,
  strengthScore,
  urlLabel,
  validateForm,
} from './model';

function entry(partial: Partial<EntrySummary> & Pick<EntrySummary, 'title'>): EntrySummary {
  return {
    id: partial.title,
    username: '',
    url: '',
    kind: 'login',
    host: null,
    keyFingerprint: null,
    hasPassword: true,
    hasOtp: false,
    group: null,
    inTrash: false,
    created: null,
    modified: null,
    ...partial,
  };
}

const ENTRIES = [
  entry({ title: 'GitHub', username: 'dev@example.com', url: 'https://github.com', hasOtp: true }),
  entry({ title: 'prod-api', kind: 'host', host: 'prod-api', username: 'deploy' }),
  entry({ title: 'id_ed25519', kind: 'key', keyFingerprint: 'SHA256:k3XbV9qL' }),
  entry({ title: 'Old forum', inTrash: true, group: 'Recycle Bin' }),
];

describe('filtering', () => {
  it('keeps the recycle bin out of every other filter', () => {
    const titles = (filter: Parameters<typeof filterEntries>[1]) =>
      filterEntries(ENTRIES, filter, '').map((e) => e.title);
    expect(titles('all')).toEqual(['GitHub', 'prod-api', 'id_ed25519']);
    expect(titles('login')).toEqual(['GitHub']);
    expect(titles('host')).toEqual(['prod-api']);
    expect(titles('key')).toEqual(['id_ed25519']);
    expect(titles('otp')).toEqual(['GitHub']);
    expect(titles('trash')).toEqual(['Old forum']);
  });

  it('counts each filter', () => {
    expect(filterCounts(ENTRIES)).toEqual({
      all: 3,
      login: 1,
      host: 1,
      key: 1,
      otp: 1,
      trash: 1,
    });
  });

  it('searches title, user name, URL, host and fingerprint, ignoring case', () => {
    expect(matchesQuery(ENTRIES[0] as EntrySummary, '  GITHUB.com ')).toBe(true);
    expect(matchesQuery(ENTRIES[0] as EntrySummary, 'dev@')).toBe(true);
    expect(matchesQuery(ENTRIES[1] as EntrySummary, 'deploy')).toBe(true);
    expect(matchesQuery(ENTRIES[2] as EntrySummary, 'k3xb')).toBe(true);
    expect(matchesQuery(ENTRIES[2] as EntrySummary, 'github')).toBe(false);
    expect(filterEntries(ENTRIES, 'all', 'prod').map((e) => e.title)).toEqual(['prod-api']);
  });

  it('switches to a filter that lists a preselected entry', () => {
    expect(filterShowing(ENTRIES[3] as EntrySummary, 'all')).toBe('trash');
    expect(filterShowing(ENTRIES[1] as EntrySummary, 'host')).toBe('host');
    expect(filterShowing(ENTRIES[1] as EntrySummary, 'trash')).toBe('all');
  });
});

describe('avatar', () => {
  it('uses the first letter or digit, upper-cased, Cyrillic too', () => {
    expect(avatar('github').letter).toBe('G');
    expect(avatar('  [work] Jira').letter).toBe('W');
    expect(avatar('яндекс').letter).toBe('Я');
    expect(avatar('1password').letter).toBe('1');
    expect(avatar('***').letter).toBe('#');
  });

  it('gives the same title the same colour', () => {
    expect(avatar('GitHub').tone).toBe(avatar('github').tone);
  });
});

describe('URLs', () => {
  it('opens only web links', () => {
    expect(openableUrl('https://github.com/login')).toBe('https://github.com/login');
    expect(openableUrl('github.com/login')).toBe('https://github.com/login');
    expect(openableUrl('http://192.168.1.1')).toBe('http://192.168.1.1/');
    expect(openableUrl('javascript:alert(1)')).toBeNull();
    expect(openableUrl('file:///etc/passwd')).toBeNull();
    expect(openableUrl('router admin')).toBeNull();
    expect(openableUrl('')).toBeNull();
  });

  it('labels a link by its host', () => {
    expect(urlLabel('https://console.aws.amazon.com/iam')).toBe('console.aws.amazon.com');
    expect(urlLabel('intranet')).toBe('intranet');
  });
});

describe('strength', () => {
  it('clamps the score and names its label', () => {
    expect(strengthScore(undefined)).toBe(0);
    expect(strengthScore(7)).toBe(4);
    expect(strengthScore(-1)).toBe(0);
    expect(strengthLabelKey(2)).toBe('passwords.strength2');
    expect(strengthLabelKey(9)).toBe('passwords.strength4');
  });

  it('gives the estimator the words an attacker would try', () => {
    expect(
      strengthContext({ title: 'GitHub', username: ' dev ', url: 'https://github.com/x' }),
    ).toEqual(['GitHub', 'dev', 'github.com']);
    expect(strengthContext({ title: 'x', username: '', url: '' })).toEqual(['x']);
  });
});

describe('2FA countdown', () => {
  it('counts down from when the code was fetched', () => {
    const fetchedAt = 1_000_000;
    expect(otpRemaining(18, fetchedAt, fetchedAt)).toBe(18);
    expect(otpRemaining(18, fetchedAt, fetchedAt + 999)).toBe(18);
    expect(otpRemaining(18, fetchedAt, fetchedAt + 1_000)).toBe(17);
    expect(otpRemaining(18, fetchedAt, fetchedAt + 60_000)).toBe(0);
    expect(otpRemaining(18, fetchedAt, fetchedAt - 5_000)).toBe(18);
  });

  it('assumes a 30 s period unless the code lives longer', () => {
    expect(otpPeriod(30)).toBe(30);
    expect(otpPeriod(12)).toBe(30);
    expect(otpPeriod(45)).toBe(60);
    expect(otpFraction(15, 30)).toBe(0.5);
    expect(otpFraction(40, 30)).toBe(1);
    expect(otpFraction(5, 0)).toBe(0);
  });

  it('splits codes in halves', () => {
    expect(formatOtp('492039')).toBe('492 039');
    expect(formatOtp('12345678')).toBe('1234 5678');
    expect(formatOtp('123')).toBe('123');
  });

  it('recognises what sites show for 2FA', () => {
    expect(isOtpSecret('otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP')).toBe(true);
    expect(isOtpSecret('jbsw y3dp ehpk 3pxp')).toBe(true);
    expect(isOtpSecret('JBSW-Y3DP-EHPK-3PXP====')).toBe(true);
    expect(isOtpSecret('JBSWY3DP')).toBe(false);
    expect(isOtpSecret('not a secret at all')).toBe(false);
  });
});

describe('recovery key', () => {
  it('splits the key into its groups', () => {
    expect(recoveryKeyGroups('7K3M-Q9TB-X2HD')).toEqual(['7K3M', 'Q9TB', 'X2HD']);
    expect(recoveryKeyGroups('7K3MQ9TBX2')).toEqual(['7K3M', 'Q9TB', 'X2']);
  });
});

describe('editor → EntryInput', () => {
  const detail: EntryDetail = {
    ...entry({ title: 'GitHub', username: 'dev', url: 'https://github.com', hasOtp: true }),
    notes: 'codes in the safe',
    passwordChanged: null,
    historyLen: 0,
  };

  it('keeps the password and 2FA secret unless they are changed', () => {
    const form = formFromEntry(detail);
    expect(form.password).toBe('');
    expect(inputFromForm(form, true)).toEqual({
      title: 'GitHub',
      username: 'dev',
      password: null,
      url: 'https://github.com',
      notes: 'codes in the safe',
      otp: null,
      kind: 'login',
      host: null,
      keyFingerprint: null,
    });
  });

  it('sends a new password and a replaced or removed 2FA secret', () => {
    const form = { ...formFromEntry(detail), password: ' new pass ' };
    expect(inputFromForm(form, true).password).toBe(' new pass ');
    expect(inputFromForm({ ...form, otpMode: 'remove' }, true).otp).toBe('');
    expect(inputFromForm({ ...form, otpMode: 'replace', otp: ' ABCD ' }, true).otp).toBe('ABCD');
    expect(inputFromForm({ ...form, otpMode: 'replace', otp: '' }, true).otp).toBeNull();
  });

  it('adds a 2FA secret to an entry without one, and ignores an empty field', () => {
    expect(inputFromForm({ ...EMPTY_FORM, title: 'x', otp: 'JBSWY3DPEHPK3PXP' }, false).otp).toBe(
      'JBSWY3DPEHPK3PXP',
    );
    expect(inputFromForm({ ...EMPTY_FORM, title: 'x', otp: '  ' }, false).otp).toBeNull();
  });

  it('links only the field of the chosen kind and trims text', () => {
    const base = { ...EMPTY_FORM, title: '  prod  ', host: 'prod', keyFingerprint: 'SHA256:x' };
    expect(inputFromForm({ ...base, kind: 'host' }, false)).toMatchObject({
      title: 'prod',
      kind: 'host',
      host: 'prod',
      keyFingerprint: null,
      password: null,
    });
    expect(inputFromForm({ ...base, kind: 'key' }, false)).toMatchObject({
      kind: 'key',
      host: null,
      keyFingerprint: 'SHA256:x',
    });
    expect(inputFromForm({ ...base, kind: 'login' }, false)).toMatchObject({
      host: null,
      keyFingerprint: null,
    });
  });

  it('validates what the backend would refuse', () => {
    expect(validateForm(EMPTY_FORM, false)).toEqual({ title: 'required' });
    expect(validateForm({ ...EMPTY_FORM, title: 'x', kind: 'host' }, false)).toEqual({
      host: 'required',
    });
    expect(validateForm({ ...EMPTY_FORM, title: 'x', kind: 'key' }, false)).toEqual({
      key: 'required',
    });
    expect(validateForm({ ...EMPTY_FORM, title: 'x', otp: 'nope' }, false)).toEqual({
      otp: 'invalid',
    });
    expect(validateForm({ ...EMPTY_FORM, title: 'x', otpMode: 'replace' }, true)).toEqual({
      otp: 'required',
    });
    // A kept secret is not re-validated.
    expect(validateForm({ ...EMPTY_FORM, title: 'x', otp: 'nope' }, true)).toEqual({});
  });
});

describe('generator', () => {
  it('never turns off the last character class', () => {
    const onlyDigits = {
      ...DEFAULT_PASSWORD,
      lowercase: false,
      uppercase: false,
      symbols: false,
    };
    expect(canToggleClass(onlyDigits, 'digits')).toBe(false);
    expect(canToggleClass(onlyDigits, 'symbols')).toBe(true);
    expect(canToggleClass(DEFAULT_PASSWORD, 'digits')).toBe(true);
  });
});

describe('locking', () => {
  it('toasts only locks the user did not ask for', () => {
    expect(lockToastKey('manual')).toBeNull();
    expect(lockToastKey('idle')).toBe('passwords.lockedIdle');
    expect(lockToastKey('changed')).toBe('passwords.lockedChanged');
  });

  it('reads the conflict copy from the error', () => {
    expect(conflictCopyPath('changed on disk: /backups/vault-conflict-1.kdbx')).toBe(
      '/backups/vault-conflict-1.kdbx',
    );
    expect(conflictCopyPath('something else')).toBeNull();
    // A conflict over the key slots has no copy.
    expect(conflictCopyPath('changed on disk: /sync/vault.keys')).toBeNull();
  });

  it('counts days since a time', () => {
    const now = new Date('2026-11-02T12:00:00Z');
    expect(daysSince('2026-10-31T12:00:00Z', now)).toBe(2);
    expect(daysSince(null, now)).toBeNull();
    expect(daysSince('garbage', now)).toBeNull();
  });
});
