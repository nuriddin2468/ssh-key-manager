import { Activity } from 'lucide-react';
import type { ToolDefinition } from '../registry';
import { SshPingPanel } from './SshPingPanel';

export const tool: ToolDefinition = {
  id: 'ssh-ping',
  group: 'network',
  order: 10,
  icon: Activity,
  tone: 'green',
  text: (t) => ({
    title: t('toolNetwork.sshPing.title'),
    description: t('toolNetwork.sshPing.description'),
  }),
  Panel: SshPingPanel,
};
