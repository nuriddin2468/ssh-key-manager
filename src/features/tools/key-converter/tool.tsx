import { FileKey2 } from 'lucide-react';
import type { ToolDefinition } from '../registry';
import { KeyConverterPanel } from './KeyConverterPanel';

export const tool: ToolDefinition = {
  id: 'key-converter',
  group: 'ssh',
  order: 30,
  icon: FileKey2,
  tone: 'teal',
  text: (t) => ({
    title: t('toolSsh.convert.title'),
    description: t('toolSsh.convert.description'),
  }),
  Panel: KeyConverterPanel,
};
