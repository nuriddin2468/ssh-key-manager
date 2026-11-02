// Typed wrappers for the Tauri commands in `src-tauri/src/commands`.

import type { AgentView } from '@/bindings/AgentView';
import type { AuditReport } from '@/bindings/AuditReport';
import type { ConfigFile } from '@/bindings/ConfigFile';
import type { ConnectionTest } from '@/bindings/ConnectionTest';
import type { Environment } from '@/bindings/Environment';
import type { GenerateKeyRequest } from '@/bindings/GenerateKeyRequest';
import type { HostEdit } from '@/bindings/HostEdit';
import type { HostKeyCheck } from '@/bindings/HostKeyCheck';
import type { KeysView } from '@/bindings/KeysView';
import type { KeyView } from '@/bindings/KeyView';
import type { KnownHostsFile } from '@/bindings/KnownHostsFile';
import type { PermissionFix } from '@/bindings/PermissionFix';
import type { SavedHost } from '@/bindings/SavedHost';
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

  config: () => call<ConfigFile>('read_config'),
  saveHost: (edit: HostEdit) => call<SavedHost>('save_host', { edit }),
  deleteHost: (id: number) => call<ConfigFile>('delete_host', { id }),
  removeIdentityFile: (hostId: number | null, value: string) =>
    call<ConfigFile>('remove_identity_file', { hostId, value }),
  configRaw: () => call<string>('read_config_raw'),
  writeConfigRaw: (text: string) => call<ConfigFile>('write_config_raw', { text }),
  testConnection: (alias: string) => call<ConnectionTest>('test_connection', { alias }),

  knownHosts: () => call<KnownHostsFile>('read_known_hosts'),
  findKnownHosts: (host: string, port: number | null) =>
    call<number[]>('find_known_hosts', { host, port }),
  removeKnownHosts: (lines: number[]) => call<KnownHostsFile>('remove_known_hosts', { lines }),
  checkHostKey: (host: string, port: number | null) =>
    call<HostKeyCheck>('check_host_key', { host, port }),

  audit: () => call<AuditReport>('run_audit'),
  fixPermissions: (items: PermissionFix[]) => call<number>('fix_permissions', { items }),
};
