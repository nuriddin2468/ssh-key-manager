import { Cable } from 'lucide-react';
import type { ToolDefinition } from '../registry';
import { TunnelsPanel } from './TunnelsPanel';

export const tool: ToolDefinition = {
  id: 'tunnels',
  group: 'ssh',
  order: 10,
  icon: Cable,
  tone: 'cyan',
  text: (t) => ({ title: t('tunnels.title'), description: t('tunnels.description') }),
  Panel: TunnelsPanel,
};
