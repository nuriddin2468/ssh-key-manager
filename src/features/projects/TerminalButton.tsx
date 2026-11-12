import { ChevronDown, CircleSlash, SquareTerminal, Variable } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useRouter } from '@/app/router';
import type { FolderPlace } from '@/bindings/FolderPlace';
import type { Project } from '@/bindings/Project';
import { Button } from '@/components/ui/Button';
import {
  Menu,
  MenuContent,
  MenuItem,
  MenuLabel,
  MenuSeparator,
  MenuTrigger,
} from '@/components/ui/Menu';
import { useTerminals } from '@/features/terminal/TerminalProvider';
import { cn } from '@/lib/cn';
import { lastName, placeText } from './places';

interface TerminalButtonProps {
  project: Project;
  /** Where it opens; `undefined` while the places load. */
  place: FolderPlace | undefined;
  /** An environment's label (`api · local`), by id. */
  labelOf: (id: string) => string;
  className?: string;
}

/**
 * "Open terminal" in one of a project's places. With one environment for a
 * terminal there, the shell gets it; with several (a monorepo's root), the
 * button is a menu that asks which, or none; with none, it gets no
 * variables.
 */
export function TerminalButton({ project, place, labelOf, className }: TerminalButtonProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const terminals = useTerminals();
  const text = place ? placeText(place, project.folders) : '';
  const open = (env: string | null) => {
    if (!place) return;
    terminals.openLocal({
      folder: {
        project: project.id,
        place: { folder: place.folder, path: place.path },
        env,
        label: `${project.name} · ${lastName(place.path || place.folder)}`,
      },
    });
    navigate({ page: 'terminal' });
  };
  const icon = <SquareTerminal className="size-3.5" strokeWidth={2} />;
  if (!place || place.terminal.length < 2) {
    return (
      <Button
        size="sm"
        className={className}
        icon={icon}
        disabled={!place}
        aria-label={t('projects.openTerminalIn', { name: text })}
        onClick={() => open(place?.terminal[0] ?? null)}
      >
        {t('projects.openTerminal')}
      </Button>
    );
  }
  return (
    <Menu>
      <MenuTrigger asChild>
        <Button
          size="sm"
          className={cn('gap-1.5', className)}
          icon={icon}
          aria-label={t('projects.openTerminalChoose', { name: text })}
        >
          {t('projects.openTerminal')}
          <ChevronDown
            aria-hidden="true"
            className="-mr-0.5 size-3.5 text-subtle"
            strokeWidth={2}
          />
        </Button>
      </MenuTrigger>
      <MenuContent>
        <MenuLabel>{t('projects.openWith')}</MenuLabel>
        {place.terminal.map((env) => (
          <MenuItem
            key={env}
            icon={<Variable className="size-4" strokeWidth={1.9} />}
            onSelect={() => open(env)}
          >
            <span className="font-mono text-[12.5px]">{labelOf(env)}</span>
          </MenuItem>
        ))}
        <MenuSeparator />
        <MenuItem
          icon={<CircleSlash className="size-4" strokeWidth={1.9} />}
          onSelect={() => open(null)}
        >
          {t('projects.withoutVariables')}
        </MenuItem>
      </MenuContent>
    </Menu>
  );
}
