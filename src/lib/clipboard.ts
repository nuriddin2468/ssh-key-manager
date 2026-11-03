import { isTauri } from '@tauri-apps/api/core';
import { writeText } from '@tauri-apps/plugin-clipboard-manager';

/**
 * Copies text that is not secret (a public key, an `ssh` command). Secrets —
 * passwords, 2FA codes, recovery keys — are copied by the backend instead
 * (`vaultCopy`, `vaultCopyRecoveryKey`), which keeps them out of clipboard
 * history and cloud clipboards and clears them after a while.
 */
export async function copyText(text: string): Promise<void> {
  if (isTauri()) {
    await writeText(text);
    return;
  }
  await navigator.clipboard.writeText(text);
}
