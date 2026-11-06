import { KeySquare } from 'lucide-react';
import type { ToolDefinition } from '../registry';
import { SecretGenerator } from './SecretGenerator';

export const tool: ToolDefinition = {
  id: 'secret-generator',
  group: 'secrets',
  order: 10,
  icon: KeySquare,
  tone: 'pink',
  text: (t) => ({
    title: t('toolGenerator.title'),
    description: t('toolGenerator.description'),
  }),
  Panel: SecretGenerator,
};
