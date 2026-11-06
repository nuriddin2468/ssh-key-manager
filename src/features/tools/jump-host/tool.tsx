import { Route } from 'lucide-react';
import type { ToolDefinition } from '../registry';
import { JumpHostPanel } from './JumpHostPanel';

export const tool: ToolDefinition = {
  id: 'jump-host',
  group: 'ssh',
  order: 20,
  icon: Route,
  tone: 'indigo',
  text: (t) => ({
    title: t('toolSsh.jump.title'),
    description: t('toolSsh.jump.description'),
  }),
  Panel: JumpHostPanel,
};
