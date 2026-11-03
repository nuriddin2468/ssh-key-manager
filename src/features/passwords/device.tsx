import { Fingerprint, ScanFace } from 'lucide-react';
import type { BiometricKind } from '@/bindings/BiometricKind';

/** Product names, the same in every language. */
export const METHOD_NAME: Record<BiometricKind, string> = {
  touchId: 'Touch ID',
  windowsHello: 'Windows Hello',
};

export function DeviceIcon({ kind, className }: { kind: BiometricKind; className?: string }) {
  const Icon = kind === 'touchId' ? Fingerprint : ScanFace;
  return <Icon aria-hidden="true" className={className} strokeWidth={1.9} />;
}
