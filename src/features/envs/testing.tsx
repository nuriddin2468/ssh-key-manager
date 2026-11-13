// What the dialogs' tests share: environments in two projects and Personal,
// and a render with the providers the dialogs need.

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import type { ReactNode } from 'react';
import type { EnvDetail } from '@/bindings/EnvDetail';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { Project } from '@/bindings/Project';
import { Dialog } from '@/components/ui/Dialog';
import { TooltipProvider } from '@/components/ui/Tooltip';

export const SITE = { id: 'p-site', name: 'Site', color: 'violet' } as Project;
export const SHOP = { id: 'p-shop', name: 'Shop', color: 'blue' } as Project;

export function summary(
  id: string,
  project: string | null,
  part: string,
  name: string,
  more: Partial<EnvSummary> = {},
): EnvSummary {
  return {
    id,
    project,
    part,
    group: part,
    name,
    kind: 'remote',
    variableCount: 0,
    secretCount: 0,
    inTrash: false,
    modified: null,
    ...more,
  };
}

export function detailOf(env: EnvSummary, notes = ''): EnvDetail {
  return {
    ...env,
    notes,
    variables: [],
    files: [],
    whileUnlocked: [],
    virtualFiles: [],
  } as EnvDetail;
}

/**
 * Site has one part (from its old group, with a stage in the recycle bin);
 * Shop has two; Personal has `scripts`.
 */
export const ALL = [
  summary('e1', 'p-site', 'marketing-site', 'dev'),
  summary('e2', 'p-site', 'marketing-site', 'prod'),
  summary('e9', 'p-site', 'marketing-site', 'qa', { inTrash: true }),
  summary('s1', 'p-shop', 'api', 'dev'),
  summary('s2', 'p-shop', 'web', 'prod'),
  summary('m1', null, 'scripts', 'local'),
];

/** The calls the dialogs make, for `vi.mock('@/api/commands')`. */
export function answer(api: Record<string, { mockResolvedValue: (value: unknown) => void }>) {
  api.vaultStatus?.mockResolvedValue({ state: 'unlocked' });
  api.projectsList?.mockResolvedValue([SITE, SHOP]);
  api.envsList?.mockResolvedValue(ALL);
  api.envsFilesOverview?.mockResolvedValue({ files: [], unmanaged: [], truncated: false });
  api.envsFilesStatus?.mockResolvedValue([]);
}

export function renderIn(children: ReactNode, inDialog = true) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TooltipProvider>{inDialog ? <Dialog open>{children}</Dialog> : children}</TooltipProvider>
    </QueryClientProvider>,
  );
}

/** Radix Select and radio groups reach for these, which jsdom lacks. */
export function stubPointer() {
  const proto = window.HTMLElement.prototype as unknown as Record<string, unknown>;
  proto.hasPointerCapture ??= () => false;
  proto.releasePointerCapture ??= () => undefined;
  proto.scrollIntoView ??= () => undefined;
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}
