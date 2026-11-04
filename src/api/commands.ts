// Typed wrappers for the Tauri commands in `src-tauri/src/commands`.

import { Channel, isTauri } from '@tauri-apps/api/core';
import type { AddFromVaultReport } from '@/bindings/AddFromVaultReport';
import type { AgentView } from '@/bindings/AgentView';
import type { AuditReport } from '@/bindings/AuditReport';
import type { BrowserStatus } from '@/bindings/BrowserStatus';
import type { ConfigFile } from '@/bindings/ConfigFile';
import type { ConnectionTest } from '@/bindings/ConnectionTest';
import type { Contact } from '@/bindings/Contact';
import type { CopyField } from '@/bindings/CopyField';
import type { CopyResult } from '@/bindings/CopyResult';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntryInput } from '@/bindings/EntryInput';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { Environment } from '@/bindings/Environment';
import type { Exported } from '@/bindings/Exported';
import type { GenerateKeyRequest } from '@/bindings/GenerateKeyRequest';
import type { GenerateOptions } from '@/bindings/GenerateOptions';
import type { HostEdit } from '@/bindings/HostEdit';
import type { HostKeyCheck } from '@/bindings/HostKeyCheck';
import type { HostsApplyResult } from '@/bindings/HostsApplyResult';
import type { HostsBackup } from '@/bindings/HostsBackup';
import type { HostsChange } from '@/bindings/HostsChange';
import type { HostsFileInfo } from '@/bindings/HostsFileInfo';
import type { HostsPreview } from '@/bindings/HostsPreview';
import type { ImportPick } from '@/bindings/ImportPick';
import type { KeyInstall } from '@/bindings/KeyInstall';
import type { KeysView } from '@/bindings/KeysView';
import type { KeyView } from '@/bindings/KeyView';
import type { KnownHostsFile } from '@/bindings/KnownHostsFile';
import type { NameLookup } from '@/bindings/NameLookup';
import type { NearbyStatus } from '@/bindings/NearbyStatus';
import type { OpenOptions } from '@/bindings/OpenOptions';
import type { OtpCode } from '@/bindings/OtpCode';
import type { PermissionFix } from '@/bindings/PermissionFix';
import type { PromptAnswer } from '@/bindings/PromptAnswer';
import type { SavedHost } from '@/bindings/SavedHost';
import type { SecretField } from '@/bindings/SecretField';
import type { Strength } from '@/bindings/Strength';
import type { TerminalEvent } from '@/bindings/TerminalEvent';
import type { TerminalInfo } from '@/bindings/TerminalInfo';
import type { VaultAudit } from '@/bindings/VaultAudit';
import type { VaultLocation } from '@/bindings/VaultLocation';
import type { VaultSettings } from '@/bindings/VaultSettings';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { call } from '@/lib/ipc';

/** A terminal session's channel carries output bytes and events. */
export type TerminalMessage = ArrayBuffer | TerminalEvent;

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
  /**
   * `revision`: the config's `view.revision` the edit was made against; fails
   * with `conflict` if the file changed since, or `cancelled` if the user
   * declined adding a directive that runs code.
   */
  saveHost: (edit: HostEdit, revision: string) => call<SavedHost>('save_host', { edit, revision }),
  deleteHost: (id: number, revision: string) => call<ConfigFile>('delete_host', { id, revision }),
  removeIdentityFile: (hostId: number | null, value: string, revision: string) =>
    call<ConfigFile>('remove_identity_file', { hostId, value, revision }),
  configRaw: () => call<string>('read_config_raw'),
  writeConfigRaw: (text: string) => call<ConfigFile>('write_config_raw', { text }),
  testConnection: (alias: string) => call<ConnectionTest>('test_connection', { alias }),
  installPublicKey: (alias: string, keyId: string) =>
    call<KeyInstall>('install_public_key', { alias, keyId }),

  knownHosts: () => call<KnownHostsFile>('read_known_hosts'),
  findKnownHosts: (host: string, port: number | null) =>
    call<number[]>('find_known_hosts', { host, port }),
  /** Lines of the file at `revision`; fails with `conflict` if it changed since. */
  removeKnownHosts: (removal: { lines: number[]; revision: string }) =>
    call<KnownHostsFile>('remove_known_hosts', removal),
  checkHostKey: (host: string, port: number | null) =>
    call<HostKeyCheck>('check_host_key', { host, port }),

  hostsFile: () => call<HostsFileInfo>('read_hosts_file'),
  lookupHost: (name: string) => call<NameLookup>('lookup_host', { name }),
  previewHostsChanges: (revision: string, changes: HostsChange[]) =>
    call<HostsPreview>('preview_hosts_changes', { revision, changes }),
  applyHostsChanges: (vars: {
    revision: string;
    changes: HostsChange[];
    flushDns: boolean;
    prompt: string;
  }) => call<HostsApplyResult>('apply_hosts_changes', vars),
  hostsBackups: () => call<HostsBackup[]>('list_hosts_backups'),
  restoreHostsBackup: (vars: { path: string; flushDns: boolean; prompt: string }) =>
    call<HostsApplyResult>('restore_hosts_backup', vars),

  audit: () => call<AuditReport>('run_audit'),
  fixPermissions: (items: PermissionFix[]) => call<number>('fix_permissions', { items }),
  vaultAudit: () => call<VaultAudit>('run_vault_audit'),

  vaultStatus: () => call<VaultStatus>('vault_status'),
  /** Returns the recovery key, to be shown once. */
  vaultCreate: (master: string) => call<string>('vault_create', { master }),
  vaultUnlock: (master: string) => call<void>('vault_unlock', { master }),
  vaultRecover: (recoveryKey: string, newMaster: string) =>
    call<void>('vault_recover', { recoveryKey, newMaster }),
  /** The system prompt's text is the backend's own. */
  vaultUnlockDevice: () => call<void>('vault_unlock_device'),
  vaultEnableDevice: (master: string) => call<void>('vault_enable_device', { master }),
  /** Asks in a native dialog first; `cancelled` if the user says no. */
  vaultDisableDevice: () => call<void>('vault_disable_device'),
  vaultLock: () => call<void>('vault_lock'),
  /** Postpones the auto-lock; call on user activity, throttled. */
  vaultActivity: () => call<void>('vault_activity'),
  vaultEntries: () => call<EntrySummary[]>('vault_entries'),
  vaultEntry: (id: string) => call<EntryDetail>('vault_entry', { id }),
  vaultReveal: (id: string, field: SecretField) => call<string>('vault_reveal', { id, field }),
  vaultCopy: (id: string, field: CopyField) => call<CopyResult>('vault_copy', { id, field }),
  /** Copies a recovery key being shown like a password: out of clipboard history, cleared. */
  vaultCopyRecoveryKey: (key: string) => call<CopyResult>('vault_copy_recovery_key', { key }),
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
  /** A change that weakens the vault's protection is confirmed in a native dialog first. */
  vaultSetSettings: (settings: VaultSettings) =>
    call<VaultSettings>('vault_set_settings', { settings }),
  /** Tests a host with its password, 2FA code and key passphrases from the vault. */
  vaultTestConnection: (alias: string) => call<ConnectionTest>('vault_test_connection', { alias }),
  /** Installs a public key on a host, logging in with the saved password. */
  vaultInstallPublicKey: (alias: string, keyId: string) =>
    call<KeyInstall>('vault_install_public_key', { alias, keyId }),
  /** Tests that the host lets the user in with a key alone (no password). */
  vaultTestKeyLogin: (alias: string) => call<ConnectionTest>('vault_test_key_login', { alias }),

  nearbyStatus: () => call<NearbyStatus>('nearby_status'),
  nearbySetName: (name: string) => call<NearbyStatus>('nearby_set_name', { name }),
  /** Visible to others on the local network for ten minutes, or hidden. */
  nearbySetVisible: (visible: boolean) => call<NearbyStatus>('nearby_set_visible', { visible }),
  /** The Nearby page looks for other devices while it is open. */
  nearbySetLooking: (looking: boolean) => call<NearbyStatus>('nearby_set_looking', { looking }),
  /** Pairs with a device found nearby (its id) or at `host:port`. */
  nearbyPair: (target: string) => call<number>('nearby_pair', { target }),
  nearbyAnswer: (id: number, matched: boolean) => call<void>('nearby_answer', { id, matched }),
  /** Cancels a pairing, or forgets one that is over. */
  nearbyClose: (id: number) => call<void>('nearby_close', { id }),
  nearbyContacts: () => call<Contact[]>('nearby_contacts'),
  nearbyRemoveContact: (key: string) => call<void>('nearby_remove_contact', { key }),

  /** Opens the system terminal with `ssh <alias>`. */
  terminalOpenExternal: (alias: string) => call<void>('terminal_open_external', { alias }),
  /**
   * Starts `ssh <alias>` in a terminal. Output arrives as `ArrayBuffer`s and
   * everything else as `TerminalEvent`s, in order, on `onMessage`.
   */
  terminalOpen: (
    alias: string,
    size: { cols: number; rows: number },
    options: OpenOptions,
    onMessage: (message: TerminalMessage) => void,
  ) =>
    call<TerminalInfo>('terminal_open', {
      alias,
      cols: size.cols,
      rows: size.rows,
      options,
      // The in-browser mock backend takes the callback itself.
      events: isTauri() ? new Channel<TerminalMessage>(onMessage) : onMessage,
    }),
  terminalWrite: (id: number, data: string) => call<void>('terminal_write', { id, data }),
  terminalResize: (id: number, cols: number, rows: number) =>
    call<void>('terminal_resize', { id, cols, rows }),
  /** Returns false if the prompt no longer waits. */
  terminalAnswer: (id: number, prompt: number, answer: PromptAnswer) =>
    call<boolean>('terminal_answer', { id, prompt, answer }),
  terminalClose: (id: number) => call<void>('terminal_close', { id }),
  terminalList: () => call<TerminalInfo[]>('terminal_list'),

  // The vault's files (src-tauri/src/commands/vault_files.rs).
  /**
   * Asks for a CSV export in a system file dialog (`null` if cancelled) and returns its rows,
   * without passwords; duplicates name the existing entry.
   */
  vaultImportPreview: () => call<ImportPick | null>('vault_import_preview'),
  /** Reads the picked file again and adds the rows at `indices`; returns how many were added. */
  vaultImport: (indices: number[]) => call<number>('vault_import', { indices }),
  /** Moves the CSV file just imported to the Trash; no other file. */
  vaultTrashImportFile: () => call<void>('vault_trash_import_file'),
  /**
   * Checks the master password, asks where to save in a system dialog (`null` if cancelled)
   * and writes a plain-text KeePassXC-style CSV file there.
   */
  vaultExportCsv: (master: string) => call<Exported | null>('vault_export_csv', { master }),
  /** Like `vaultExportCsv`, for a copy of the database, which opens with the recovery key. */
  vaultExportKdbx: (master: string) => call<Exported | null>('vault_export_kdbx', { master }),
  vaultLocation: () => call<VaultLocation>('vault_location'),
  /** Moves both vault files into `folder`, locked or unlocked, after a native confirmation. */
  vaultMove: (folder: string) => call<VaultLocation>('vault_move', { folder }),
  /** Locks the vault and switches to another `.kdbx` file, after a native confirmation. */
  vaultUseFile: (path: string) => call<VaultLocation>('vault_use_file', { path }),
  /** Back to the app's folder: move the files there, or switch to the vault there. */
  vaultUseDefault: (moveFiles: boolean) => call<VaultLocation>('vault_use_default', { moveFiles }),

  // Browser autofill (src-tauri/src/commands/browser.rs).
  browserStatus: () => call<BrowserStatus>('browser_status'),
  /** On: registers with the installed browsers and listens. Off: undoes both. */
  browserSetEnabled: (enabled: boolean) => call<BrowserStatus>('browser_set_enabled', { enabled }),
  /** Fails with `not_found` if the request no longer waits. */
  browserAnswerPairing: (id: string, approve: boolean) =>
    call<void>('browser_answer_pairing', { id, approve }),
  browserRevoke: (id: string) => call<void>('browser_revoke', { id }),
};
