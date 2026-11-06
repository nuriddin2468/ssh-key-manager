// What the SSH tools share; this folder has no `tool.tsx`, so the registry
// skips it.

import { type ReactNode, useId, useMemo } from 'react';
import { useConfig } from '@/api/queries';
import type { HostEntry } from '@/bindings/HostEntry';
import { cn } from '@/lib/cn';

/** A name the app runs `ssh` with, as `check_alias` in the backend allows. */
export function isPlainAlias(alias: string): boolean {
  return /^[A-Za-z0-9._@:[\]-]+$/.test(alias) && !alias.startsWith('-');
}

/** The config's `Host` blocks for single names, in file order. */
export function plainHosts(hosts: readonly HostEntry[]): HostEntry[] {
  return hosts.filter(
    (host) => host.kind === 'host' && !host.isWildcard && host.patterns.some(isPlainAlias),
  );
}

/** The aliases `ssh` can be started with, each once, in file order. */
export function aliasesOf(hosts: readonly HostEntry[]): string[] {
  return [...new Set(plainHosts(hosts).flatMap((host) => host.patterns.filter(isPlainAlias)))];
}

export function useHostAliases(): string[] {
  const config = useConfig();
  return useMemo(() => aliasesOf(config.data?.view.hosts ?? []), [config.data]);
}

/** A card of a tool, with a heading that names it for screen readers. */
export function Section({
  title,
  description,
  action,
  className,
  children,
}: {
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  const id = useId();
  return (
    <section
      aria-labelledby={id}
      className={cn('glass flex flex-col gap-3.5 rounded-2xl p-4', className)}
    >
      <header className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <h2 id={id} className="text-[14px] leading-5 font-semibold">
            {title}
          </h2>
          {description ? (
            <p className="mt-0.5 text-[12.5px] leading-[18px] text-muted">{description}</p>
          ) : null}
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}

/** Text `ssh` or a server printed, in a box that keeps its lines. */
export function OutputBox({ text, className }: { text: string; className?: string }) {
  return (
    <pre
      className={cn(
        'selectable max-h-48 overflow-auto rounded-[11px] border border-white/[0.07] bg-terminal px-3 py-2.5 font-mono text-[11.5px] leading-[1.55] whitespace-pre-wrap break-all text-fg-2',
        className,
      )}
    >
      {text}
    </pre>
  );
}
