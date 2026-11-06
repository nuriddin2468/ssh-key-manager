import { ShieldCheck } from 'lucide-react';
import type { ToolDefinition } from '../registry';
import { AuthorizedLinePanel } from './AuthorizedLinePanel';

export const tool: ToolDefinition = {
  id: 'authorized-keys-line',
  group: 'ssh',
  order: 40,
  icon: ShieldCheck,
  tone: 'violet',
  text: (t) => ({ title: t('toolSsh.line.title'), description: t('toolSsh.line.description') }),
  Panel: AuthorizedLinePanel,
};
