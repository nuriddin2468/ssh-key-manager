// The tools of the Tools page. Each lives in a folder of its own,
// `src/features/tools/<id>/tool.tsx`, which exports `tool`; this file finds
// them, so adding a tool touches no shared file.

import type { TFunction } from 'i18next';
import type { LucideIcon } from 'lucide-react';
import type { ComponentType } from 'react';
import type { Tone } from '@/components/ui/Tile';

/** The headings the Tools page lists its tools under, in this order. */
export const TOOL_GROUPS = ['secrets', 'network', 'ssh'] as const;
export type ToolGroup = (typeof TOOL_GROUPS)[number];

export interface ToolDefinition {
  /** In the route (`{ page: 'tools', tool }`); unique, kebab-case. */
  id: string;
  group: ToolGroup;
  /** Lower first within its group. */
  order: number;
  icon: LucideIcon;
  tone: Tone;
  /** Its name and one line about it, in the interface's language. */
  text: (t: TFunction) => { title: string; description: string };
  /** The tool itself, shown under the page's toolbar. */
  Panel: ComponentType;
}

const modules = import.meta.glob<{ tool: ToolDefinition }>('./*/tool.tsx', { eager: true });

/** Every tool, by group and then by order. */
export const TOOLS: readonly ToolDefinition[] = Object.values(modules)
  .map((module) => module.tool)
  .sort(
    (a, b) =>
      TOOL_GROUPS.indexOf(a.group) - TOOL_GROUPS.indexOf(b.group) ||
      a.order - b.order ||
      a.id.localeCompare(b.id),
  );

export function findTool(id: string | undefined): ToolDefinition | undefined {
  return id === undefined ? undefined : TOOLS.find((tool) => tool.id === id);
}
