import { ChevronRight, Trash2 } from 'lucide-react';
import { type KeyboardEvent, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { PersonalTile, ProjectTile } from '@/features/projects/ProjectTile';
import { useProjects } from '@/features/projects/queries';
import { cn } from '@/lib/cn';
import { envLabel, isProduction, type ProjectNames, type ProjectSection } from './model';

interface EnvListProps {
  sections: ProjectSection[];
  names: ProjectNames;
  trash: EnvSummary[];
  selectedId: string | undefined;
  query: string;
  onSelect: (id: string) => void;
}

/**
 * Personal and the projects with their environments, by part when a project
 * has more than one, then the recycle bin, folded.
 */
export function EnvList({ sections, names, trash, selectedId, query, onSelect }: EnvListProps) {
  const { t } = useTranslation();
  const projects = useProjects().data ?? [];
  const list = useRef<HTMLDivElement>(null);
  const trashId = useId();
  const [trashOpen, setTrashOpen] = useState(() => trash.some((env) => env.id === selectedId));
  const visible = [
    ...sections.flatMap((section) => section.parts.flatMap((part) => part.envs)),
    ...(trashOpen ? trash : []),
  ];

  // Arrow keys move through the list, like a native source list.
  const onKey = (event: KeyboardEvent) => {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    const index = visible.findIndex((env) => env.id === selectedId);
    const next = visible[index + (event.key === 'ArrowDown' ? 1 : -1)];
    if (!next) return;
    event.preventDefault();
    onSelect(next.id);
    list.current?.querySelector<HTMLElement>(`[data-env="${CSS.escape(next.id)}"]`)?.focus();
  };

  return (
    <nav
      aria-label={t('envs.listLabel')}
      className="glass flex w-[280px] shrink-0 flex-col overflow-hidden rounded-2xl xl:w-[300px]"
    >
      {/* biome-ignore lint/a11y/noStaticElementInteractions: arrow keys on the focused row button bubble here */}
      <div
        ref={list}
        onKeyDown={onKey}
        className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-2"
      >
        {sections.length === 0 && query ? (
          <p className="px-3 py-8 text-center text-subtle">{t('envs.noMatches')}</p>
        ) : null}
        {sections.map((section) => {
          const project = projects.find((p) => p.id === section.project);
          const title = section.project
            ? (names.get(section.project) ?? '')
            : t('projects.personal');
          // Parts show when the project has more than one.
          const withParts = section.parts.length > 1;
          return (
            <section
              key={section.project ?? 'personal'}
              aria-label={title}
              className="flex flex-col gap-0.5"
            >
              <h2 className="flex min-h-7 items-center gap-2 px-2.5 pt-1 pb-1 text-[12.5px] font-semibold">
                {project ? <ProjectTile project={project} size={18} /> : <PersonalTile size={18} />}
                <span className="min-w-0 truncate">{title}</span>
              </h2>
              {section.parts.map((part) => (
                <div key={part.part} className="flex flex-col gap-0.5">
                  {withParts ? (
                    <h3 className="truncate px-2.5 pt-1.5 pl-[38px] font-mono text-[11.5px] font-semibold text-fg-2">
                      {part.part || t('envs.noPart')}
                    </h3>
                  ) : null}
                  {part.envs.map((env) => (
                    <EnvRow
                      key={env.id}
                      env={env}
                      part={withParts ? part.part : ''}
                      selected={env.id === selectedId}
                      onSelect={() => onSelect(env.id)}
                    />
                  ))}
                </div>
              ))}
            </section>
          );
        })}
      </div>
      {trash.length > 0 ? (
        <div className="border-t border-white/[0.06] p-2">
          <button
            type="button"
            aria-expanded={trashOpen}
            aria-controls={trashId}
            onClick={() => setTrashOpen((open) => !open)}
            className="pressable-soft flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-left text-[12.5px] text-muted hover:bg-white/[0.04] hover:text-fg"
          >
            <ChevronRight
              aria-hidden="true"
              className={cn('size-3.5 transition-transform', trashOpen && 'rotate-90')}
              strokeWidth={2}
            />
            <Trash2 aria-hidden="true" className="size-3.5" strokeWidth={1.9} />
            <span className="flex-1">{t('envs.trash')}</span>
            <span className="tabular-nums">{trash.length}</span>
          </button>
          {trashOpen ? (
            <div id={trashId} className="mt-1 flex flex-col gap-0.5">
              {trash.map((env) => (
                <EnvRow
                  key={env.id}
                  env={env}
                  selected={env.id === selectedId}
                  label={envLabel(env, names)}
                  onSelect={() => onSelect(env.id)}
                />
              ))}
            </div>
          ) : null}
        </div>
      ) : null}
    </nav>
  );
}

interface EnvRowProps {
  env: EnvSummary;
  selected: boolean;
  /** In the recycle bin, rows from every project mix: say where it was. */
  label?: string;
  /** Its part, said to screen readers, when the list shows parts. */
  part?: string;
  onSelect: () => void;
}

function EnvRow({ env, selected, label, part, onSelect }: EnvRowProps) {
  const { t } = useTranslation();
  const production = isProduction(env.name);
  return (
    <button
      type="button"
      data-env={env.id}
      aria-current={selected ? 'true' : undefined}
      onClick={onSelect}
      className={cn(
        'pressable-soft flex min-h-[46px] w-full items-center gap-2.5 rounded-xl px-2.5 py-1.5 text-left active:bg-white/[0.06]',
        selected ? 'selected-row' : 'hover:bg-white/[0.04]',
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          'size-2 shrink-0 rounded-full',
          env.inTrash ? 'bg-faint' : production ? 'bg-warning-solid' : 'bg-[var(--accent-2)]',
        )}
      />
      <span className="flex min-w-0 flex-1 flex-col">
        <span className={cn('truncate text-[13px] font-medium', env.inTrash && 'text-muted')}>
          {label ?? env.name}
          {part ? <span className="sr-only">, {part}</span> : null}
          {production ? <span className="sr-only">, {t('envs.production')}</span> : null}
        </span>
        <span className="truncate text-[12px] leading-[17px] text-subtle">
          {env.secretCount > 0
            ? t('envs.countsWithSecrets', {
                count: env.variableCount,
                secrets: env.secretCount,
              })
            : t('envs.counts', { count: env.variableCount })}
        </span>
      </span>
    </button>
  );
}
