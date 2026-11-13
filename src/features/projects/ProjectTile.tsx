import { User, X } from 'lucide-react';
import { RadioGroup } from 'radix-ui';
import { useTranslation } from 'react-i18next';
import type { Project } from '@/bindings/Project';
import type { ProjectColor } from '@/bindings/ProjectColor';
import { Tile, TONES } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { initials, PROJECT_COLORS, projectTone } from './model';

/** A project's tile: its initials on its color. Decorative: the name next to it is the label. */
export function ProjectTile({
  project,
  size = 22,
}: {
  project: Pick<Project, 'name' | 'color'>;
  size?: number;
}) {
  return (
    <Tile tone={projectTone(project.color)} size={size}>
      <span
        className="font-bold tracking-[-0.02em]"
        style={{ fontSize: Math.max(9, Math.round(size * 0.42)) }}
      >
        {initials(project.name)}
      </span>
    </Tile>
  );
}

/** Personal's tile: a person on slate. */
export function PersonalTile({ size = 22 }: { size?: number }) {
  return (
    <Tile tone="slate" size={size}>
      <User style={{ width: size * 0.6, height: size * 0.6 }} strokeWidth={2.2} />
    </Tile>
  );
}

/** The dot color of a project, for chips. */
export function projectDot(color: ProjectColor): string {
  return TONES[projectTone(color)][0];
}

/** A project's name with its color; with `onRemove`, a button takes the item out of it. */
export function ProjectChip({
  project,
  onRemove,
  onOpen,
}: {
  project: Pick<Project, 'name' | 'color'>;
  onRemove?: () => void;
  onOpen?: () => void;
}) {
  const { t } = useTranslation();
  const dot = (
    <span
      aria-hidden="true"
      className="size-[7px] shrink-0 rounded-full"
      style={{ background: projectDot(project.color) }}
    />
  );
  return (
    <span className="inline-flex h-[22px] max-w-[180px] shrink-0 items-center gap-1.5 rounded-full bg-fill pr-1 pl-2 text-[11.5px] text-fg-2">
      {onOpen ? (
        <button
          type="button"
          onClick={onOpen}
          className="flex min-w-0 items-center gap-1.5 rounded-full outline-none hover:text-fg focus-visible:ring-2 focus-visible:ring-[rgb(var(--focus-rgb)/var(--ring-alpha))]"
        >
          {dot}
          <span className="truncate">{project.name}</span>
        </button>
      ) : (
        <>
          {dot}
          <span className="truncate pr-1">{project.name}</span>
        </>
      )}
      {onRemove ? (
        <button
          type="button"
          onClick={onRemove}
          aria-label={t('projects.removeFrom', { name: project.name })}
          title={t('projects.removeFrom', { name: project.name })}
          className="grid size-4 place-items-center rounded-full text-subtle outline-none hover:bg-ink/10 hover:text-fg focus-visible:ring-2 focus-visible:ring-[rgb(var(--focus-rgb)/var(--ring-alpha))]"
        >
          <X className="size-3" strokeWidth={2.4} />
        </button>
      ) : null}
    </span>
  );
}

/** The ten project colors as a radio group: arrow keys move, Space picks. */
export function ColorPicker({
  value,
  onChange,
  labelId,
}: {
  value: ProjectColor;
  onChange: (color: ProjectColor) => void;
  /** The id of the element that names the group. */
  labelId: string;
}) {
  const { t } = useTranslation();
  return (
    <RadioGroup.Root
      value={value}
      onValueChange={(next) => onChange(next as ProjectColor)}
      aria-labelledby={labelId}
      orientation="horizontal"
      loop
      className="flex flex-wrap gap-2"
    >
      {PROJECT_COLORS.map((color) => {
        const [from, to] = TONES[projectTone(color)];
        return (
          <RadioGroup.Item
            key={color}
            value={color}
            aria-label={t(`projects.colors.${color}`)}
            title={t(`projects.colors.${color}`)}
            className={cn(
              'size-6 rounded-[7px] outline-none transition-shadow focus-visible:ring-2 focus-visible:ring-ink/80 focus-visible:ring-offset-2 focus-visible:ring-offset-popover',
              'data-[state=checked]:ring-2 data-[state=checked]:ring-ink data-[state=checked]:ring-offset-2 data-[state=checked]:ring-offset-popover',
            )}
            style={{ background: `linear-gradient(140deg, ${from}, ${to})` }}
          />
        );
      })}
    </RadioGroup.Root>
  );
}
