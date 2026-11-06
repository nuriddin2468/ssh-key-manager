// Why a connection failed, as the "Why it failed" panel says it: the cause
// the backend read from ssh's output (`Diagnosis`), in plain words, with the
// one or two fixes that fit what the app knows about the host.

import type { TFunction } from 'i18next';
import type { Cause } from '@/bindings/Cause';
import type { Diagnosis } from '@/bindings/Diagnosis';
import type en from '@/i18n/locales/en';
import { displayPath } from '@/lib/format';

/**
 * A fix the panel offers. The panel runs `probe`, `lookup`, `fixPermissions`,
 * `copyPublicKey` and `unlockVault` itself.
 */
export type DiagnoseFix =
  /** Add the key to the server's `authorized_keys`, signing in with the saved password. */
  | 'installKey'
  /** Copy the key's public half, for the server's admin. */
  | 'copyPublicKey'
  | 'addToAgent'
  /** Pick the host's key file. */
  | 'chooseKey'
  | 'editPassword'
  /** Open the vault, whose saved password a check then uses. */
  | 'unlockVault'
  /** Turn on "IdentitiesOnly yes" for the host. */
  | 'identitiesOnly'
  | 'checkHostKey'
  | 'probe'
  | 'lookup'
  | 'fixPermissions'
  /** Add the option that turns one old algorithm back on, for this host only. */
  | 'allowLegacy'
  /** Show the host's address and port. */
  | 'openHost';

/** What the UI knows about the host, which decides the fixes. */
export interface HostFacts {
  /** The vault holds the host's password (and is open). */
  passwordSaved: boolean;
  /** The vault is open, so a password can be saved. */
  vaultOpen: boolean;
  /** The vault is locked: a check with it open could use the saved password. */
  vaultLocked: boolean;
  /** The host names a key file that is one of the user's keys. */
  hasKey: boolean;
  /** That key has a passphrase and neither ssh-agent nor the open vault holds it. */
  keyLocked: boolean;
}

/** Knows nothing about the host: the panel offers only the fixes that need nothing. */
export const NO_FACTS: HostFacts = {
  passwordSaved: false,
  vaultOpen: false,
  vaultLocked: false,
  hasKey: false,
  keyLocked: false,
};

type DiagnoseKey = keyof (typeof en)['diagnose']['cause'];

export interface DiagnosisMessage {
  /** Translation keys under `diagnose.cause`. */
  title: DiagnoseKey;
  detail: DiagnoseKey;
  /** A caution shown with the fix (an old algorithm is weaker). */
  warning?: DiagnoseKey;
  /** Says to unlock the vault, whose saved password a check could use. */
  unlockVault?: boolean;
  values: Record<string, string>;
  /** In order; the first is the primary action. At most two. */
  fixes: DiagnoseFix[];
}

/** The message for a diagnosis and what the app can do about it here. */
export function diagnosisMessage(diagnosis: Diagnosis, facts: HostFacts): DiagnosisMessage {
  const { cause } = diagnosis;
  const values: Record<string, string> = { hop: diagnosis.hop ?? '' };
  const message = (
    title: DiagnoseKey,
    fixes: DiagnoseFix[],
    extra: Partial<DiagnosisMessage> = {},
  ): DiagnosisMessage => ({
    title,
    detail: `${title}Detail` as DiagnoseKey,
    values,
    fixes: fixes.slice(0, 2),
    ...extra,
  });

  switch (cause.kind) {
    case 'keysRejected': {
      const install: DiagnoseFix = facts.passwordSaved ? 'installKey' : 'copyPublicKey';
      const extra = { unlockVault: facts.vaultLocked };
      if (facts.keyLocked) return message('keysRejected', ['addToAgent', install], extra);
      if (!facts.hasKey) return message('keysRejectedNoKey', ['chooseKey'], extra);
      return message(
        cause.passwordAllowed ? 'keysRejectedPasswordToo' : 'keysRejected',
        [install, 'chooseKey'],
        extra,
      );
    }
    case 'keyLocked':
      values.key = cause.key;
      return message('keyLocked', ['addToAgent']);
    case 'identityFileMissing':
      values.path = cause.path;
      return message('identityFileMissing', ['chooseKey']);
    case 'passwordRejected':
      return message('passwordRejected', passwordFixes(facts));
    case 'passwordRequired':
      return message('passwordRequired', passwordFixes(facts));
    case 'tooManyAuthFailures':
      return facts.hasKey
        ? message('tooManyAuthFailures', ['identitiesOnly'])
        : message('tooManyAuthFailuresNoKey', ['chooseKey']);
    case 'hostKeyUnknown':
      return message('hostKeyUnknown', ['checkHostKey']);
    case 'hostKeyChanged':
      values.fingerprint = cause.fingerprint ?? '';
      values.knownHosts = cause.knownHosts ?? '';
      return message('hostKeyChanged', ['checkHostKey']);
    case 'network': {
      values.host = cause.host ?? '';
      values.port = cause.port === null ? '22' : String(cause.port);
      const title = NETWORK_TITLES[cause.problem];
      return message(title, cause.problem === 'notSsh' ? ['openHost'] : ['probe', 'openHost']);
    }
    case 'nameNotResolved':
      values.host = cause.host;
      return message('nameNotResolved', ['lookup', 'openHost']);
    case 'badPermissions':
      values.path = cause.path;
      return message(cause.file === 'config' ? 'configPermissions' : 'keyPermissions', [
        'fixPermissions',
      ]);
    case 'legacy':
      values.option = `${cause.option} ${cause.value}`;
      values.offer = cause.offer.join(', ');
      return message(LEGACY_TITLES[cause.what], ['allowLegacy'], { warning: 'legacyWarning' });
    case 'proxy':
      values.detail = cause.detail ?? '';
      return message(PROXY_TITLES[cause.problem], ['openHost']);
    case 'unknown':
      return message('unknown', []);
  }
}

/** The saved password is edited in the open vault; a locked one opens first. */
function passwordFixes(facts: HostFacts): DiagnoseFix[] {
  if (facts.vaultOpen) return ['editPassword'];
  return facts.vaultLocked ? ['unlockVault'] : [];
}

type Of<K extends Cause['kind']> = Extract<Cause, { kind: K }>;

const NETWORK_TITLES = {
  timedOut: 'timedOut',
  refused: 'refused',
  noRoute: 'noRoute',
  networkUnreachable: 'networkUnreachable',
  reset: 'reset',
  closed: 'closed',
  notSsh: 'notSsh',
  other: 'networkOther',
} as const satisfies Record<Of<'network'>['problem'], DiagnoseKey>;

const LEGACY_TITLES = {
  hostKey: 'legacyHostKey',
  keyExchange: 'legacyKeyExchange',
  cipher: 'legacyCipher',
  mac: 'legacyMac',
  signature: 'legacySignature',
} as const satisfies Record<Of<'legacy'>['what'], DiagnoseKey>;

const PROXY_TITLES = {
  nextHopUnreachable: 'nextHopUnreachable',
  forwardingProhibited: 'forwardingProhibited',
  commandFailed: 'proxyCommandFailed',
  closed: 'proxyClosed',
} as const satisfies Record<Of<'proxy'>['problem'], DiagnoseKey>;

/** The keys ssh offered, for the list under "the server turned down your keys". */
export function offeredKeys(cause: Cause) {
  return cause.kind === 'keysRejected' || cause.kind === 'tooManyAuthFailures' ? cause.offered : [];
}

/** The option a legacy fix adds to the host, or null. */
export function legacyOption(diagnosis: Diagnosis): { key: string; value: string } | null {
  const { cause } = diagnosis;
  return cause.kind === 'legacy' ? { key: cause.option, value: cause.value } : null;
}

/** The name to look up (DNS and the hosts file) for a name that did not resolve. */
export function unresolvedName(diagnosis: Diagnosis): string | null {
  return diagnosis.cause.kind === 'nameNotResolved' ? diagnosis.cause.host : null;
}

/** A message's placeholders: the host by its alias when ssh named none, paths from `~`. */
export function messageValues(message: DiagnosisMessage, alias: string, home: string | undefined) {
  const value = (name: string) => message.values[name] ?? '';
  return {
    alias,
    hop: value('hop'),
    host: value('host') || alias,
    port: value('port'),
    key: displayPath(value('key'), home),
    path: displayPath(value('path'), home),
    detail: value('detail'),
    offer: value('offer'),
    option: value('option'),
    fingerprint: value('fingerprint'),
    knownHosts: value('knownHosts'),
  };
}

/** The cause in a few words, for a toast or an announcement. */
export function causeTitle(
  t: TFunction,
  diagnosis: Diagnosis,
  alias: string,
  home?: string,
): string {
  const message = diagnosisMessage(diagnosis, NO_FACTS);
  return t(`diagnose.cause.${message.title}`, messageValues(message, alias, home));
}

/** Tells diagnoses apart, so a new one starts with the panel's checks cleared. */
export function diagnosisKey(diagnosis: Diagnosis): string {
  return JSON.stringify(diagnosis);
}
