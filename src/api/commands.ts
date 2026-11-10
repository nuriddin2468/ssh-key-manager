// Typed wrappers for the Tauri commands in `src-tauri/src/commands`.

import { Channel, isTauri } from '@tauri-apps/api/core';
import type { AddFromVaultReport } from '@/bindings/AddFromVaultReport';
import type { AgentView } from '@/bindings/AgentView';
import type { AuditReport } from '@/bindings/AuditReport';
import type { AuthorizedLine } from '@/bindings/AuthorizedLine';
import type { AutostartStatus } from '@/bindings/AutostartStatus';
import type { BackgroundStatus } from '@/bindings/BackgroundStatus';
import type { BreachStatus } from '@/bindings/BreachStatus';
import type { BrowserImport } from '@/bindings/BrowserImport';
import type { BrowserProfile } from '@/bindings/BrowserProfile';
import type { BrowserStatus } from '@/bindings/BrowserStatus';
import type { ConfigFile } from '@/bindings/ConfigFile';
import type { ConnectionEvent } from '@/bindings/ConnectionEvent';
import type { ConnectionTest } from '@/bindings/ConnectionTest';
import type { Contact } from '@/bindings/Contact';
import type { CopyField } from '@/bindings/CopyField';
import type { CopyResult } from '@/bindings/CopyResult';
import type { DnsReport } from '@/bindings/DnsReport';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntryInput } from '@/bindings/EntryInput';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { EnvComparison } from '@/bindings/EnvComparison';
import type { EnvDetail } from '@/bindings/EnvDetail';
import type { EnvExport } from '@/bindings/EnvExport';
import type { EnvFormat } from '@/bindings/EnvFormat';
import type { EnvImported } from '@/bindings/EnvImported';
import type { EnvImportPick } from '@/bindings/EnvImportPick';
import type { EnvInput } from '@/bindings/EnvInput';
import type { Environment } from '@/bindings/Environment';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { EnvVarInput } from '@/bindings/EnvVarInput';
import type { Exported } from '@/bindings/Exported';
import type { FixAction } from '@/bindings/FixAction';
import type { GeneratedSecret } from '@/bindings/GeneratedSecret';
import type { GenerateKeyRequest } from '@/bindings/GenerateKeyRequest';
import type { GenerateOptions } from '@/bindings/GenerateOptions';
import type { HistoryScan } from '@/bindings/HistoryScan';
import type { HistoryStatus } from '@/bindings/HistoryStatus';
import type { HostEdit } from '@/bindings/HostEdit';
import type { HostKeyCheck } from '@/bindings/HostKeyCheck';
import type { HostsApplyResult } from '@/bindings/HostsApplyResult';
import type { HostsBackup } from '@/bindings/HostsBackup';
import type { HostsChange } from '@/bindings/HostsChange';
import type { HostsFileInfo } from '@/bindings/HostsFileInfo';
import type { HostsPreview } from '@/bindings/HostsPreview';
import type { ImportChoice } from '@/bindings/ImportChoice';
import type { ImportOutcome } from '@/bindings/ImportOutcome';
import type { ImportPasswords } from '@/bindings/ImportPasswords';
import type { ImportPick } from '@/bindings/ImportPick';
import type { ImportTarget } from '@/bindings/ImportTarget';
import type { KeyFileFormat } from '@/bindings/KeyFileFormat';
import type { KeyFileInfo } from '@/bindings/KeyFileInfo';
import type { KeyInstall } from '@/bindings/KeyInstall';
import type { KeyLoginCheck } from '@/bindings/KeyLoginCheck';
import type { KeysView } from '@/bindings/KeysView';
import type { KeyView } from '@/bindings/KeyView';
import type { KnownHostsFile } from '@/bindings/KnownHostsFile';
import type { LeakFinding } from '@/bindings/LeakFinding';
import type { LeakRedaction } from '@/bindings/LeakRedaction';
import type { LeakStatus } from '@/bindings/LeakStatus';
import type { LineOptions } from '@/bindings/LineOptions';
import type { MyDevice } from '@/bindings/MyDevice';
import type { NameLookup } from '@/bindings/NameLookup';
import type { NearbyStatus } from '@/bindings/NearbyStatus';
import type { OpenOptions } from '@/bindings/OpenOptions';
import type { OtpCode } from '@/bindings/OtpCode';
import type { PermissionFix } from '@/bindings/PermissionFix';
import type { PortCheck } from '@/bindings/PortCheck';
import type { PortProbe } from '@/bindings/PortProbe';
import type { PromptAnswer } from '@/bindings/PromptAnswer';
import type { QuickItems } from '@/bindings/QuickItems';
import type { QuickStatus } from '@/bindings/QuickStatus';
import type { ReceivedGroup } from '@/bindings/ReceivedGroup';
import type { SavedHost } from '@/bindings/SavedHost';
import type { SecretField } from '@/bindings/SecretField';
import type { SecretPreset } from '@/bindings/SecretPreset';
import type { SendRequest } from '@/bindings/SendRequest';
import type { ServerKeys } from '@/bindings/ServerKeys';
import type { ServerKeysAction } from '@/bindings/ServerKeysAction';
import type { ShellInfo } from '@/bindings/ShellInfo';
import type { SshPing } from '@/bindings/SshPing';
import type { Strength } from '@/bindings/Strength';
import type { SyncDecisions } from '@/bindings/SyncDecisions';
import type { TerminalEvent } from '@/bindings/TerminalEvent';
import type { TerminalInfo } from '@/bindings/TerminalInfo';
import type { TlsReport } from '@/bindings/TlsReport';
import type { Tunnel } from '@/bindings/Tunnel';
import type { TunnelView } from '@/bindings/TunnelView';
import type { VaultAudit } from '@/bindings/VaultAudit';
import type { VaultLocation } from '@/bindings/VaultLocation';
import type { VaultSettings } from '@/bindings/VaultSettings';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { call } from '@/lib/ipc';

/** A terminal session's channel carries output bytes and events. */
export type TerminalMessage = ArrayBuffer | TerminalEvent;

/** The passphrase the user typed for one of their keys, for a single sign-in. */
export interface TypedPassphrase {
  keyId: string;
  passphrase: string;
}

const typedArgs = (typed?: TypedPassphrase) => ({
  keyId: typed?.keyId ?? null,
  passphrase: typed?.passphrase ?? null,
});

export const api = {
  environment: () => call<Environment>('get_environment'),

  listKeys: () => call<KeysView>('list_keys'),
  generateKey: (request: GenerateKeyRequest) => call<KeyView>('generate_key', { request }),
  changePassphrase: (keyId: string, old: string | null, next: string | null) =>
    call<KeyView>('change_passphrase', { keyId, old, new: next }),
  regeneratePublic: (keyId: string) => call<KeyView>('regenerate_public', { keyId }),
  /**
   * Signs in to `alias` offering `keyId` first, keys only, and says whether
   * that key let the user in (`otherKey`: another one did).
   */
  checkKeyLogin: (alias: string, keyId: string) =>
    call<KeyLoginCheck>('check_key_login', { alias, keyId }),
  /** `checkKeyLogin` with the key passphrases saved in the vault. */
  vaultCheckKeyLogin: (alias: string, keyId: string) =>
    call<KeyLoginCheck>('vault_check_key_login', { alias, keyId }),
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
  /** `typed`: the passphrase of a key ssh cannot open by itself; `wrong_passphrase` if it doesn't open it. */
  testConnection: (alias: string, typed?: TypedPassphrase) =>
    call<ConnectionTest>('test_connection', { alias, ...typedArgs(typed) }),
  /** Checks and in-app terminal sessions by alias, newest first. */
  connectionHistory: () => call<Record<string, ConnectionEvent[]>>('connection_history'),
  clearConnectionHistory: (alias: string) => call<void>('clear_connection_history', { alias }),
  /** Connects to the host's port, or its first jump host's, and closes at once; `unsupported` behind a ProxyCommand. */
  diagnoseProbe: (alias: string) => call<PortProbe>('diagnose_probe', { alias }),
  /** The audit's permission fix for a file ssh refused, by the path ssh printed; `false` if the audit offers none. */
  diagnoseFixPermissions: (path: string) => call<boolean>('diagnose_fix_permissions', { path }),
  installPublicKey: (alias: string, keyId: string) =>
    call<KeyInstall>('install_public_key', { alias, keyId }),
  /** Reads the host's `~/.ssh/authorized_keys` after the change, if any, in one sign-in. */
  serverKeys: (alias: string, action: ServerKeysAction) =>
    call<ServerKeys>('server_keys', { alias, action }),

  // The SSH tools of the Tools page (src-tauri/src/commands/ssh_tools.rs).
  tunnelList: () => call<TunnelView[]>('tunnel_list'),
  /** An empty `id` adds one; `already_exists` if another tunnel listens on its port. */
  tunnelSave: (tunnel: Tunnel) => call<TunnelView>('tunnel_save', { tunnel }),
  tunnelDelete: (id: string) => call<void>('tunnel_delete', { id }),
  tunnelSetOn: (id: string, on: boolean) => call<TunnelView>('tunnel_set_on', { id, on }),
  /** Returns false if the prompt no longer waits. */
  tunnelAnswer: (id: string, prompt: number, answer: PromptAnswer) =>
    call<boolean>('tunnel_answer', { id, prompt, answer }),
  tunnelStopAll: () => call<void>('tunnel_stop_all'),
  /** Adds the tunnel's `LocalForward`/`RemoteForward`/`DynamicForward` line to its host's block. */
  tunnelExport: (id: string, revision: string) =>
    call<ConfigFile>('tunnel_export', { id, revision }),
  /** `jump: null` removes `ProxyJump` from the blocks `targets`. */
  setProxyJump: (jump: string | null, targets: number[], revision: string) =>
    call<ConfigFile>('set_proxy_jump', { jump, targets, revision }),
  /** With a passphrase, an encrypted key is opened too (`wrong_passphrase` if it doesn't). */
  keyConvertInspect: (path: string, passphrase: string | null) =>
    call<KeyFileInfo>('key_convert_inspect', { path, passphrase }),
  /** Adds the key to ~/.ssh in the OpenSSH format, never over a file. */
  keyConvertImport: (vars: {
    path: string;
    passphrase: string | null;
    fileName: string;
    newPassphrase: string | null;
    comment: string | null;
  }) => call<KeyView>('key_convert_import', vars),
  /** Asks where to save in a system dialog; `null` if cancelled. */
  keyConvertSave: (vars: {
    path: string;
    passphrase: string | null;
    format: KeyFileFormat;
    newPassphrase: string | null;
    comment: string | null;
  }) => call<string | null>('key_convert_save', vars),
  authorizedLine: (publicKey: string, options: LineOptions) =>
    call<AuthorizedLine>('authorized_line', { publicKey, options }),
  /** Signs in with the vault's saved password for the host if it is unlocked. */
  installAuthorizedLine: (alias: string, line: string) =>
    call<KeyInstall>('install_authorized_line', { alias, line }),

  knownHosts: () => call<KnownHostsFile>('read_known_hosts'),
  findKnownHosts: (host: string, port: number | null) =>
    call<number[]>('find_known_hosts', { host, port }),
  /** Lines of the file at `revision`; fails with `conflict` if it changed since. */
  removeKnownHosts: (removal: { lines: number[]; revision: string }) =>
    call<KnownHostsFile>('remove_known_hosts', removal),
  checkHostKey: (host: string, port: number | null) =>
    call<HostKeyCheck>('check_host_key', { host, port }),
  /** Whether the user allowed reading their shell history, and how many hosts they dismissed. */
  shellHistoryStatus: () => call<HistoryStatus>('shell_history_status'),
  shellHistorySetEnabled: (enabled: boolean) =>
    call<HistoryStatus>('shell_history_set_enabled', { enabled }),
  /**
   * Reads the shell history in Rust and suggests the hosts it connects to
   * that the config lacks; only those targets come back. Fails with
   * `invalid_input` unless the user turned this on.
   */
  shellHistoryScan: () => call<HistoryScan>('shell_history_scan'),
  /** Stops suggesting a host, by its suggestion's `id` (a hash of the target). */
  shellHistoryDismiss: (id: string) => call<HistoryStatus>('shell_history_dismiss', { id }),
  shellHistoryForgetDismissed: () => call<HistoryStatus>('shell_history_forget_dismissed'),

  hostsFile: () => call<HostsFileInfo>('read_hosts_file'),
  lookupHost: (name: string) => call<NameLookup>('lookup_host', { name }),
  previewHostsChanges: (revision: string, changes: HostsChange[]) =>
    call<HostsPreview>('preview_hosts_changes', { revision, changes }),
  applyHostsChanges: (vars: { revision: string; changes: HostsChange[]; flushDns: boolean }) =>
    call<HostsApplyResult>('apply_hosts_changes', vars),
  hostsBackups: () => call<HostsBackup[]>('list_hosts_backups'),
  restoreHostsBackup: (vars: { path: string; flushDns: boolean }) =>
    call<HostsApplyResult>('restore_hosts_backup', vars),
  toolsGenerateSecret: (preset: SecretPreset) =>
    call<GeneratedSecret>('tools_generate_secret', { preset }),
  /** Copies like a vault password: out of clipboard history, cleared after a while. */
  toolsCopySecret: (text: string) => call<CopyResult>('tools_copy_secret', { text }),
  toolsSshPing: (vars: { host: string; port: number; samples: number }) =>
    call<SshPing>('tools_ssh_ping', vars),
  toolsPortCheck: (vars: { host: string; port: number; timeoutMs: number }) =>
    call<PortCheck>('tools_port_check', vars),
  /** Asks the computer's DNS servers, over the network. */
  toolsDnsLookup: (name: string) => call<DnsReport>('tools_dns_lookup', { name }),
  toolsTlsCheck: (vars: { host: string; port: number }) => call<TlsReport>('tools_tls_check', vars),

  audit: () => call<AuditReport>('run_audit'),
  fixPermissions: (items: PermissionFix[]) => call<number>('fix_permissions', { items }),
  vaultAudit: () => call<VaultAudit>('run_vault_audit'),
  // The audit's config fixes and breach check (src-tauri/src/commands/audit_checks.rs).
  fixConfig: (fix: FixAction, revision: string) =>
    call<ConfigFile>('fix_config', { fix, revision }),
  breachStatus: () => call<BreachStatus>('breach_status'),
  breachSetEnabled: (enabled: boolean) => call<BreachStatus>('breach_set_enabled', { enabled }),
  breachCheck: () => call<BreachStatus>('breach_check'),

  // The leak scanner (src-tauri/src/commands/leaks.rs): values stay in Rust;
  // the page gets progress and findings that name a secret, a file and a line.
  leaksStatus: () => call<LeakStatus>('leaks_status'),
  leaksSetSources: (ai: boolean, history: boolean) =>
    call<LeakStatus>('leaks_set_sources', { ai, history }),
  /** Opens a system folder dialog; the folders picked there are added. */
  leaksAddFolders: () => call<LeakStatus>('leaks_add_folders'),
  leaksRemoveFolder: (folder: string) => call<LeakStatus>('leaks_remove_folder', { folder }),
  /** Fails with `vault_locked` while the vault is locked. */
  leaksStart: () => call<LeakStatus>('leaks_start'),
  leaksCancel: () => call<void>('leaks_cancel'),
  leaksFindings: () => call<LeakFinding[]>('leaks_findings'),
  /** Replaces the secret in the AI session files of these findings, in place. */
  leaksRedact: (ids: string[]) => call<LeakRedaction>('leaks_redact', { ids }),

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
  /** Tests a host with its password, 2FA code and key passphrases from the vault, and `typed`. */
  vaultTestConnection: (alias: string, typed?: TypedPassphrase) =>
    call<ConnectionTest>('vault_test_connection', { alias, ...typedArgs(typed) }),
  /** Installs a public key on a host, logging in with the saved password. */
  vaultInstallPublicKey: (alias: string, keyId: string) =>
    call<KeyInstall>('vault_install_public_key', { alias, keyId }),
  /** Tests that the host lets the user in with a key alone (no password). */
  vaultTestKeyLogin: (alias: string) => call<ConnectionTest>('vault_test_key_login', { alias }),
  /** `serverKeys`, signing in with the saved password and 2FA code. */
  vaultServerKeys: (alias: string, action: ServerKeysAction) =>
    call<ServerKeys>('vault_server_keys', { alias, action }),

  nearbyStatus: () => call<NearbyStatus>('nearby_status'),
  nearbySetName: (name: string) => call<NearbyStatus>('nearby_set_name', { name }),
  /** Visible to others on the local network for ten minutes, or hidden. */
  nearbySetVisible: (visible: boolean) => call<NearbyStatus>('nearby_set_visible', { visible }),
  /** The Nearby page looks for other devices while it is open. */
  nearbySetLooking: (looking: boolean) => call<NearbyStatus>('nearby_set_looking', { looking }),
  /** Pairs with a device found nearby (its id) or at `host:port`. */
  nearbyPair: (target: string) => call<number>('nearby_pair', { target }),
  /** Sends what `item` names to a device found nearby, pairing first if needed. */
  nearbySend: (target: string, item: SendRequest) => call<number>('nearby_send', { target, item }),
  /** Whether the codes match, or whether to accept an item offered. */
  nearbyAnswer: (id: number, matched: boolean) => call<void>('nearby_answer', { id, matched }),
  /** Cancels a pairing, or forgets one that is over. */
  nearbyClose: (id: number) => call<void>('nearby_close', { id }),
  /** The hosts file group that came with pairing `id`, waiting to be saved. */
  nearbyReceivedGroup: (id: number) => call<ReceivedGroup | null>('nearby_received_group', { id }),
  nearbyContacts: () => call<Contact[]>('nearby_contacts'),
  nearbyRemoveContact: (key: string) => call<void>('nearby_remove_contact', { key }),
  /** A computer without a vault: visible for ten minutes to be given one, or hidden. */
  nearbyJoin: (on: boolean) => call<NearbyStatus>('nearby_join', { on }),
  /** Makes a device found nearby one of the user's devices, giving it the vault if it has none. */
  nearbyAddDevice: (target: string) => call<number>('nearby_add_device', { target }),
  /** The yes to adding a device: with the master password, or Touch ID / Windows Hello without one. */
  nearbyAuthorize: (id: number, master: string | null) =>
    call<void>('nearby_authorize', { id, master }),
  /** Sets up the vault another computer gave, with this computer's master password. */
  nearbyFinishJoin: (id: number, master: string) =>
    call<void>('nearby_finish_join', { id, master }),
  nearbyDevices: () => call<MyDevice[]>('nearby_devices'),
  nearbyRemoveDevice: (key: string) => call<void>('nearby_remove_device', { key }),
  /** Whether the user's devices can find this computer while the vault is unlocked. */
  nearbySetReachable: (reachable: boolean) =>
    call<NearbyStatus>('nearby_set_reachable', { reachable }),
  /** Syncs with one of the user's devices (its key), or with every one reachable. */
  nearbySync: (key: string | null) => call<void>('nearby_sync', { key }),
  /** The user's decisions on what a sync brings. */
  nearbyDecide: (id: number, decisions: SyncDecisions) =>
    call<void>('nearby_decide', { id, decisions }),

  /** Opens the system terminal with `ssh <alias>`. */
  terminalOpenExternal: (alias: string) => call<void>('terminal_open_external', { alias }),
  /** The shells a local session can run, the default first. */
  terminalShells: () => call<ShellInfo[]>('terminal_shells'),
  /** Starts a shell on this computer (`null`: the default one), like `terminalOpen`. */
  terminalOpenLocal: (
    shell: string | null,
    size: { cols: number; rows: number },
    onMessage: (message: TerminalMessage) => void,
  ) =>
    call<TerminalInfo>('terminal_open_local', {
      shell,
      cols: size.cols,
      rows: size.rows,
      events: isTauri() ? new Channel<TerminalMessage>(onMessage) : onMessage,
    }),
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
   * without passwords; duplicates name the existing entry and say whether its password differs.
   */
  vaultImportPreview: () => call<ImportPick | null>('vault_import_preview'),
  /**
   * Reads the picked file again and imports the rows at `indices`: rows whose entry has another
   * password update it (keeping the old one in its history), the others are added.
   */
  vaultImport: (indices: number[]) => call<ImportOutcome>('vault_import', { indices }),
  /**
   * Both passwords of a preview row whose entry has another one, to compare; refused for any other
   * row.
   */
  vaultImportCompare: (index: number) => call<ImportPasswords>('vault_import_compare', { index }),
  /** Moves the CSV file just imported to the Trash; no other file. */
  vaultTrashImportFile: () => call<void>('vault_trash_import_file'),

  // Importing straight from a browser (src-tauri/src/commands/browser_import.rs).
  /** The browser profiles on this computer with saved logins. */
  vaultBrowserProfiles: () => call<BrowserProfile[]>('vault_browser_profiles'),
  /**
   * Reads a profile's saved logins (the system may ask the user for permission first) and lists
   * them without passwords; or says why it couldn't.
   */
  vaultBrowserImportPreview: (profileId: string, primaryPassword: string | null) =>
    call<BrowserImport>('vault_browser_import_preview', { profileId, primaryPassword }),
  /** Adds the logins at `indices` of the last browser preview; returns how many were added. */
  vaultBrowserImport: (indices: number[]) =>
    call<ImportOutcome>('vault_browser_import', { indices }),
  /** Both passwords of a login of the last browser preview whose entry has another one. */
  vaultBrowserImportCompare: (index: number) =>
    call<ImportPasswords>('vault_browser_import_compare', { index }),
  /** Drops the logins read for the last browser preview. */
  vaultBrowserImportForget: () => call<void>('vault_browser_import_forget'),
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

  // Secret environments in the vault (src-tauri/src/commands/envs.rs). Values
  // come only from `envsReveal`; copying and running go without the page.
  envsList: () => call<EnvSummary[]>('envs_list'),
  envsGet: (id: string) => call<EnvDetail>('envs_get', { id }),
  envsCreate: (input: EnvInput) => call<EnvDetail>('envs_create', { input }),
  envsUpdate: (id: string, input: EnvInput) => call<EnvDetail>('envs_update', { id, input }),
  /** Adds a variable (`previous` null) or changes the one named `previous`. */
  envsSetVar: (id: string, previous: string | null, input: EnvVarInput) =>
    call<EnvDetail>('envs_set_var', { id, previous, input }),
  envsRemoveVar: (id: string, name: string) => call<EnvDetail>('envs_remove_var', { id, name }),
  envsReveal: (id: string, name: string) => call<string>('envs_reveal', { id, name }),
  envsCopy: (id: string, name: string) => call<CopyResult>('envs_copy', { id, name }),
  envsTrash: (id: string) => call<void>('envs_trash', { id }),
  envsRestore: (id: string) => call<void>('envs_restore', { id }),
  envsDelete: (id: string) => call<void>('envs_delete', { id }),
  envsCompare: (left: string, right: string) =>
    call<EnvComparison>('envs_compare', { left, right }),
  /** Opens a system file dialog; `null` when it was cancelled. */
  envsImportPick: () => call<EnvImportPick | null>('envs_import_pick'),
  envsImport: (target: ImportTarget, choices: ImportChoice[]) =>
    call<EnvImported>('envs_import', { target, choices }),
  /** Opens a save dialog; `null` when it was cancelled. Not written while `repository` is set. */
  envsExport: (id: string, format: EnvFormat) =>
    call<EnvExport | null>('envs_export', { id, format }),
  envsExportAnyway: () => call<EnvExport>('envs_export_anyway'),
  /**
   * Starts a shell with the environment's variables, like `terminalOpen`:
   * `shell` (an id from `terminalShells`) or, when `null`, the default one.
   */
  envsRun: (
    id: string,
    shell: string | null,
    size: { cols: number; rows: number },
    onMessage: (message: TerminalMessage) => void,
  ) =>
    call<TerminalInfo>('envs_run', {
      id,
      shell,
      cols: size.cols,
      rows: size.rows,
      events: isTauri() ? new Channel<TerminalMessage>(onMessage) : onMessage,
    }),

  // Running on with the window closed, and the tray icon
  // (src-tauri/src/commands/background.rs).
  backgroundStatus: () => call<BackgroundStatus>('background_status'),
  backgroundSetEnabled: (enabled: boolean) =>
    call<BackgroundStatus>('background_set_enabled', { enabled }),

  // Opening at login, read from the system each time; turning it on also
  // keeps the app running in the background (src-tauri/src/commands/autostart.rs).
  autostartStatus: () => call<AutostartStatus>('autostart_status'),
  autostartSetEnabled: (enabled: boolean) =>
    call<AutostartStatus>('autostart_set_enabled', { enabled }),

  // Quick search: its shortcut, and what its window lists and does
  // (src-tauri/src/commands/quick.rs).
  quickStatus: () => call<QuickStatus>('quick_status'),
  /** `shortcut` such as `Shift+Super+Space`; `null` for the default. */
  quickSetShortcut: (enabled: boolean, shortcut: string | null) =>
    call<QuickStatus>('quick_set_shortcut', { enabled, shortcut }),
  /** Hosts, and the vault's entries without secrets (`null` while it is locked). */
  quickItems: () => call<QuickItems>('quick_items'),
  /** Closes the quick window and opens a session to `alias` in the main window. */
  quickConnect: (alias: string) => call<void>('quick_connect', { alias }),
  /** Closes the quick window; `back` gives the focus to the app the user was in. */
  quickClose: (back: boolean) => call<void>('quick_close', { back }),

  // Browser autofill (src-tauri/src/commands/browser.rs).
  browserStatus: () => call<BrowserStatus>('browser_status'),
  /** On: registers with the installed browsers and listens. Off: undoes both. */
  browserSetEnabled: (enabled: boolean) => call<BrowserStatus>('browser_set_enabled', { enabled }),
  /** Fails with `not_found` if the request no longer waits. */
  browserAnswerPairing: (id: string, approve: boolean) =>
    call<void>('browser_answer_pairing', { id, approve }),
  browserRevoke: (id: string) => call<void>('browser_revoke', { id }),
};
