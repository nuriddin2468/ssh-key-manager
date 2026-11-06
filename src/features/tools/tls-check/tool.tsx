import { ShieldCheck } from 'lucide-react';
import type { ToolDefinition } from '../registry';
import { TlsCheckPanel } from './TlsCheckPanel';

export const tool: ToolDefinition = {
  id: 'tls-check',
  group: 'network',
  order: 40,
  icon: ShieldCheck,
  tone: 'teal',
  text: (t) => ({
    title: t('toolNetwork.tls.title'),
    description: t('toolNetwork.tls.description'),
  }),
  Panel: TlsCheckPanel,
};
