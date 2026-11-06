import { Plug } from 'lucide-react';
import type { ToolDefinition } from '../registry';
import { PortCheckPanel } from './PortCheckPanel';

export const tool: ToolDefinition = {
  id: 'port-check',
  group: 'network',
  order: 20,
  icon: Plug,
  tone: 'blue',
  text: (t) => ({
    title: t('toolNetwork.portCheck.title'),
    description: t('toolNetwork.portCheck.description'),
  }),
  Panel: PortCheckPanel,
};
