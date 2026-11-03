import type { TFunction } from 'i18next';
import { Fingerprint, ScanFace } from 'lucide-react';
import type { BiometricKind } from '@/bindings/BiometricKind';

/** Product names, the same in every language. */
export const METHOD_NAME: Record<BiometricKind, string> = {
  touchId: 'Touch ID',
  windowsHello: 'Windows Hello',
};

/**
 * The text of the system prompt. macOS puts it after "<app> is trying to",
 * so it is a lowercase phrase there; Windows shows it as a sentence.
 */
export function deviceReason(t: TFunction, kind: BiometricKind, action: 'unlock' | 'enable') {
  if (action === 'unlock') {
    return kind === 'touchId' ? t('passwords.deviceReasonMac') : t('passwords.deviceReasonWin');
  }
  return kind === 'touchId'
    ? t('passwords.deviceEnableReasonMac')
    : t('passwords.deviceEnableReasonWin');
}

export function DeviceIcon({ kind, className }: { kind: BiometricKind; className?: string }) {
  const Icon = kind === 'touchId' ? Fingerprint : ScanFace;
  return <Icon aria-hidden="true" className={className} strokeWidth={1.9} />;
}
