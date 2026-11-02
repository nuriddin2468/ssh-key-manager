// Typed wrappers for the Tauri commands in `src-tauri/src/commands`.

import type { AddFromVaultReport } from '@/bindings/AddFromVaultReport';
import type { AgentView } from '@/bindings/AgentView';
import type { AuditReport } from '@/bindings/AuditReport';
import type { ConfigFile } from '@/bindings/ConfigFile';
import type { ConnectionTest } from '@/bindings/ConnectionTest';
import type { CopyField } from '@/bindings/CopyField';
import type { CopyResult } from '@/bindings/CopyResult';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntryInput } from '@/bindings/EntryInput';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { Environment } from '@/bindings/Environment';
import type { GenerateKeyRequest } from '@/bindings/GenerateKeyRequest';
import type { GenerateOptions } from '@/bindings/GenerateOptions';
import type { HostEdit } from '@/bindings/HostEdit';
import type { HostKeyCheck } from '@/bindings/HostKeyCheck';
import type { ImportPreview } from '@/bindings/ImportPreview';
import type { KeyInstall } from '@/bindings/KeyInstall';
import type { KeysView } from '@/bindings/KeysView';
import type { KeyView } from '@/bindings/KeyView';
import type { KnownHostsFile } from '@/bindings/KnownHostsFile';
import type { OtpCode } from '@/bindings/OtpCode';
import type { PermissionFix } from '@/bindings/PermissionFix';
import type { SavedHost } from '@/bindings/SavedHost';
import type { SecretField } from '@/bindings/SecretField';
import type { Strength } from '@/bindings/Strength';
import type { VaultAudit } from '@/bindings/VaultAudit';
import type { VaultLocation } from '@/bindings/VaultLocation';
import type { VaultSettings } from '@/bindings/VaultSettings';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { call } from '@/lib/ipc';

export const api = {
  environment: () => call<Environment>('get_environment'),

  listKeys: () => call<KeysView>('list_keys'),
  generateKey: (request: GenerateKeyRequest) => call<KeyView>('generate_key', { request }),
  changePassphrase: (keyId: string, old: string | null, next: string | null) =>
    call<KeyView>('change_passphrase', { keyId, old, new: next }),
  regeneratePublic: (keyId: string) => call<KeyView>('regenerate_public', { keyId }),
  importKey: (source: string, fileName: string | null) =>
    call<KeyView>('import_key', { source, fileName }),
  trashKey: (keyId: string) => call<void>('trash_key', { keyId }),

  agent: () => call<AgentView>('agent_view'),
  agentAdd: (keyId: string, passphrase: string | null, lifetimeSecs: number | null) =>
    call<void>('agent_add', { keyId, passphrase, lifetimeSecs }),
  agentRemove: (fingerprint: string) => call<void>('agent_remove', { fingerprint }),
  agentRemoveAll: () => call<void>('agent_remove_all'),
  /** Adds a key with the passphrase saved in the vault, which stays in Rust. */
  agentAddFromVault: (keyId: string, lifetimeSecs: number | null) =>
    call<void>('agent_add_from_vault', { keyId, lifetimeSecs }),
  /** Adds every key with a saved passphrase that the agent does not hold yet. */
  agentAddAllFromVault: (lifetimeSecs: number | null) =>
    call<AddFromVaultReport>('agent_add_all_from_vault', { lifetimeSecs }),

  config: () => call<ConfigFile>('read_config'),
  saveHost: (edit: HostEdit) => call<SavedHost>('save_host', { edit }),
  deleteHost: (id: number) => call<ConfigFile>('delete_host', { id }),
  removeIdentityFile: (hostId: number | null, value: string) =>
    call<ConfigFile>('remove_identity_file', { hostId, value }),
  configRaw: () => call<string>('read_config_raw'),
  writeConfigRaw: (text: string) => call<ConfigFile>('write_config_raw', { text }),
  testConnection: (alias: string) => call<ConnectionTest>('test_connection', { alias }),
  installPublicKey: (alias: string, keyId: string) =>
    call<KeyInstall>('install_public_key', { alias, keyId }),

  knownHosts: () => call<KnownHostsFile>('read_known_hosts'),
  findKnownHosts: (host: string, port: number | null) =>
    call<number[]>('find_known_hosts', { host, port }),
  removeKnownHosts: (lines: number[]) => call<KnownHostsFile>('remove_known_hosts', { lines }),
  checkHostKey: (host: string, port: number | null) =>
    call<HostKeyCheck>('check_host_key', { host, port }),

  audit: () => call<AuditReport>('run_audit'),
  fixPermissions: (items: PermissionFix[]) => call<number>('fix_permissions', { items }),
  vaultAudit: () => call<VaultAudit>('run_vault_audit'),

  vaultStatus: () => call<VaultStatus>('vault_status'),
  /** Returns the recovery key, to be shown once. */
  vaultCreate: (master: string) => call<string>('vault_create', { master }),
  vaultUnlock: (master: string) => call<void>('vault_unlock', { master }),
  vaultRecover: (recoveryKey: string, newMaster: string) =>
    call<void>('vault_recover', { recoveryKey, newMaster }),
  /** `reason` completes "<app> is trying to …" in the Touch ID prompt. */
  vaultUnlockDevice: (reason: string) => call<void>('vault_unlock_device', { reason }),
  vaultEnableDevice: (master: string, reason: string) =>
    call<void>('vault_enable_device', { master, reason }),
  vaultDisableDevice: () => call<void>('vault_disable_device'),
  vaultLock: () => call<void>('vault_lock'),
  /** Postpones the auto-lock; call on user activity, throttled. */
  vaultActivity: () => call<void>('vault_activity'),
  vaultEntries: () => call<EntrySummary[]>('vault_entries'),
  vaultEntry: (id: string) => call<EntryDetail>('vault_entry', { id }),
  vaultReveal: (id: string, field: SecretField) => call<string>('vault_reveal', { id, field }),
  vaultCopy: (id: string, field: CopyField) => call<CopyResult>('vault_copy', { id, field }),
  vaultOtp: (id: string) => call<OtpCode>('vault_otp', { id }),
  vaultAdd: (input: EntryInput) => call<EntryDetail>('vault_add', { input }),
  vaultUpdate: (id: string, input: EntryInput) => call<EntryDetail>('vault_update', { id, input }),
  vaultTrash: (id: string) => call<void>('vault_trash', { id }),
  vaultRestore: (id: string) => call<void>('vault_restore', { id }),
  vaultDelete: (id: string) => call<void>('vault_delete', { id }),
  vaultEmptyTrash: () => call<number>('vault_empty_trash'),
  vaultGenerate: (options: GenerateOptions) => call<string>('vault_generate', { options }),
  vaultStrength: (password: string, context: string[]) =>
    call<Strength>('vault_strength', { password, context }),
  vaultChangeMaster: (current: string, next: string) =>
    call<void>('vault_change_master', { current, new: next }),
  /** Returns the new recovery key, to be shown once. */
  vaultNewRecoveryKey: (master: string) => call<string>('vault_new_recovery_key', { master }),
  vaultSetSettings: (settings: VaultSettings) =>
    call<VaultSettings>('vault_set_settings', { settings }),
  /** Tests a host with its password, 2FA code and key passphrases from the vault. */
  vaultTestConnection: (alias: string) => call<ConnectionTest>('vault_test_connection', { alias }),
  /** Installs a public key on a host, logging in with the saved password. */
  vaultInstallPublicKey: (alias: string, keyId: string) =>
    call<KeyInstall>('vault_install_public_key', { alias, keyId }),
  /** Tests that the host lets the user in with a key alone (no password). */
  vaultTestKeyLogin: (alias: string) => call<ConnectionTest>('vault_test_key_login', { alias }),

  // The vault's files (src-tauri/src/commands/vault_files.rs).
  /** Rows of a CSV export, without passwords; duplicates name the existing entry. */
  vaultImportPreview: (path: string) => call<ImportPreview>('vault_import_preview', { path }),
  /** Reads the file again and adds the rows at `indices`; returns how many were added. */
  vaultImport: (path: string, indices: number[]) => call<number>('vault_import', { path, indices }),
  /** Moves the CSV file just imported to the Trash; refuses any other file. */
  vaultTrashImportFile: (path: string) => call<void>('vault_trash_import_file', { path }),
  /** Plain-text KeePassXC-style CSV; returns how many entries were written. */
  vaultExportCsv: (path: string, master: string) =>
    call<number>('vault_export_csv', { path, master }),
  /** A copy of the database, which opens with the recovery key. Works locked. */
  vaultExportKdbx: (path: string) => call<void>('vault_export_kdbx', { path }),
  vaultLocation: () => call<VaultLocation>('vault_location'),
  /** Moves both vault files into `folder`, locked or unlocked. */
  vaultMove: (folder: string) => call<VaultLocation>('vault_move', { folder }),
  /** Locks the vault and switches to another `.kdbx` file. */
  vaultUseFile: (path: string) => call<VaultLocation>('vault_use_file', { path }),
  /** Back to the app's folder: move the files there, or switch to the vault there. */
  vaultUseDefault: (moveFiles: boolean) => call<VaultLocation>('vault_use_default', { moveFiles }),
};
