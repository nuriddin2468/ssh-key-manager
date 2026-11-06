import { Signpost } from 'lucide-react';
import type { ToolDefinition } from '../registry';
import { DnsLookupPanel } from './DnsLookupPanel';

export const tool: ToolDefinition = {
  id: 'dns-lookup',
  group: 'network',
  order: 30,
  icon: Signpost,
  tone: 'indigo',
  text: (t) => ({
    title: t('toolNetwork.dns.title'),
    description: t('toolNetwork.dns.description'),
  }),
  Panel: DnsLookupPanel,
};
