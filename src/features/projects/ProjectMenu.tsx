import { Check, FolderKanban, LockKeyhole, Plus } from 'lucide-react';
import { DropdownMenu } from 'radix-ui';
import { type ReactNode, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { invalidateAll, useVaultStatus } from '@/api/queries';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import type { Project } from '@/bindings/Project';
import type { ProjectMember } from '@/bindings/ProjectMember';
import { Dialog } from '@/components/ui/Dialog';
import { IconButton } from '@/components/ui/IconButton';
import {
  Menu,
  MenuContent,
  MenuItem,
  MenuSeparator,
  MenuSub,
  MenuTrigger,
} from '@/components/ui/Menu';
import { cn } from '@/lib/cn';
import { useSetMember } from './actions';
import { holds } from './model';
import { ProjectDialog } from './ProjectDialog';
import { ProjectChip, projectDot } from './ProjectTile';
import { useProjects } from './queries';

const ITEM =
  'flex h-8 items-center gap-2.5 rounded-lg px-2.5 outline-none select-none transition-colors duration-100 active:bg-fill-pressed data-[disabled]:opacity-40 data-[highlighted]:bg-ink/[0.08]';

/**
 * "Add to project" for an item of the library: a submenu that ticks the
 * projects holding it and toggles each, plus "New project…". Put `sub` in a
 * menu and `dialog` outside it: the dialog outlives the menu.
 */
export function useProjectMenu(
  member: ProjectMember | null,
  options: { flat?: boolean } = {},
): {
  sub: ReactNode;
  dialog: ReactNode;
} {
  const { t } = useTranslation();
  const dialogs = useDialogs();
  const state = useVaultStatus().data?.state;
  const projects = useProjects().data ?? [];
  const setMember = useSetMember();
  const [creating, setCreating] = useState(false);

  if (!member || state === undefined || state === 'missing') return { sub: null, dialog: null };

  const icon = <FolderKanban className="size-[15px]" strokeWidth={1.9} />;
  const sub =
    state === 'locked' ? (
      <MenuItem
        icon={<LockKeyhole className="size-[15px]" strokeWidth={1.9} />}
        onSelect={() => dialogs.unlockVault({ description: t('projects.unlockToChange') })}
      >
        {t('projects.addToProject')}
      </MenuItem>
    ) : (
      <Wrap flat={options.flat} icon={icon} label={t('projects.addToProject')}>
        {projects.map((project) => {
          const inside = holds(project, member);
          return (
            <DropdownMenu.CheckboxItem
              key={project.id}
              checked={inside}
              // Stays open, so several projects can be ticked in a row.
              onSelect={(event) => event.preventDefault()}
              onCheckedChange={(checked) =>
                setMember.mutate({ project, member, included: checked === true })
              }
              className={cn(ITEM, 'pr-3')}
            >
              <span className="flex size-4 items-center justify-center">
                <DropdownMenu.ItemIndicator>
                  <Check className="size-3.5" strokeWidth={2.4} />
                </DropdownMenu.ItemIndicator>
              </span>
              <span
                aria-hidden="true"
                className="size-[7px] shrink-0 rounded-full"
                style={{ background: projectDot(project.color) }}
              />
              <span className="max-w-[220px] truncate">{project.name}</span>
            </DropdownMenu.CheckboxItem>
          );
        })}
        {projects.length > 0 ? <MenuSeparator /> : null}
        <MenuItem
          icon={<Plus className="size-[15px]" strokeWidth={2} />}
          onSelect={() => setCreating(true)}
        >
          {t('projects.newProjectEllipsis')}
        </MenuItem>
      </Wrap>
    );

  const dialog = (
    <Dialog open={creating} onOpenChange={setCreating}>
      {creating ? (
        <ProjectDialog
          project={null}
          all={projects}
          onDone={(saved) => {
            setCreating(false);
            if (saved) {
              void api
                .projectsSetMember(saved.id, member, true)
                .then(() => invalidateAll())
                .catch(() => undefined);
            }
          }}
        />
      ) : null}
    </Dialog>
  );
  return { sub, dialog };
}

/** The items in a submenu, or (`flat`) under a heading in the menu itself. */
function Wrap({
  flat,
  icon,
  label,
  children,
}: {
  flat?: boolean;
  icon: ReactNode;
  label: string;
  children: ReactNode;
}) {
  if (!flat) {
    return (
      <MenuSub icon={icon} label={label}>
        {children}
      </MenuSub>
    );
  }
  return (
    <DropdownMenu.Group>
      <DropdownMenu.Label className="px-2.5 pt-1 pb-1.5 text-[11px] font-semibold text-label">
        {label}
      </DropdownMenu.Label>
      {children}
    </DropdownMenu.Group>
  );
}

/**
 * The projects holding an item, as chips that open them; nothing when it is
 * in none. For library rows and detail panes.
 */
export function ProjectChips({
  member,
  className,
}: {
  member: ProjectMember | null;
  className?: string;
}) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const projects = useProjects().data ?? [];
  if (!member) return null;
  const holding: Project[] = projects.filter((project) => holds(project, member));
  if (holding.length === 0) return null;
  return (
    // Chips open their project, not the row they sit in.
    // biome-ignore lint/a11y/useKeyWithClickEvents: only stops the row's click
    <ul
      aria-label={t('projects.inProjects')}
      className={cn('flex flex-wrap gap-1', className)}
      onClick={(event) => event.stopPropagation()}
    >
      {holding.map((project) => (
        <li key={project.id}>
          <ProjectChip
            project={project}
            onOpen={() => navigate({ page: 'project', id: project.id })}
          />
        </li>
      ))}
    </ul>
  );
}

/**
 * The projects holding an item as plain chips (dot and name), for rows that
 * are buttons themselves; at most two, then "+N".
 */
export function ProjectDots({
  member,
  className,
}: {
  member: ProjectMember | null;
  className?: string;
}) {
  const { t } = useTranslation();
  const projects = useProjects().data ?? [];
  if (!member) return null;
  const holding = projects.filter((project) => holds(project, member));
  if (holding.length === 0) return null;
  const shown = holding.slice(0, 2);
  const more = holding.length - shown.length;
  return (
    <span className={cn('flex min-w-0 flex-wrap items-center gap-1', className)}>
      <span className="sr-only">{t('projects.inProjects')}:</span>
      {shown.map((project) => (
        <span
          key={project.id}
          className="inline-flex h-[18px] max-w-[140px] items-center gap-1 rounded-full bg-fill px-1.5 text-[11px] text-fg-2"
        >
          <span
            aria-hidden="true"
            className="size-1.5 shrink-0 rounded-full"
            style={{ background: projectDot(project.color) }}
          />
          <span className="truncate">{project.name}</span>
        </span>
      ))}
      {more > 0 ? (
        <span className="text-[11px] text-subtle">
          {t('projects.moreProjects', { count: more })}
        </span>
      ) : null}
    </span>
  );
}

/**
 * "Add to project" for a library row: a small button with the projects to
 * tick, and "New project…". Nothing without a vault.
 */
export function AddToProjectButton({
  member,
  name,
  className,
}: {
  member: ProjectMember | null;
  name: string;
  className?: string;
}) {
  const { t } = useTranslation();
  const { sub, dialog } = useProjectMenu(member, { flat: true });
  if (!sub) return null;
  return (
    <>
      <Menu>
        <MenuTrigger asChild>
          <IconButton
            label={t('projects.addToProjectFor', { name })}
            variant="ghost"
            className={className}
            icon={<FolderKanban className="size-4" strokeWidth={1.9} />}
          />
        </MenuTrigger>
        <MenuContent>{sub}</MenuContent>
      </Menu>
      {dialog}
    </>
  );
}

/**
 * [`AddToProjectButton`] beside a row that is a button itself: at the row's
 * end, shown while the row is hovered or anything in it has focus.
 */
export function RowProjectButton({ member, name }: { member: ProjectMember; name: string }) {
  return (
    <div className="pointer-events-none absolute top-1/2 right-2 -translate-y-1/2 opacity-0 transition-opacity group-focus-within:pointer-events-auto group-focus-within:opacity-100 group-hover:pointer-events-auto group-hover:opacity-100 has-[[data-state=open]]:pointer-events-auto has-[[data-state=open]]:opacity-100">
      <AddToProjectButton
        member={member}
        name={name}
        className="size-8 rounded-lg bg-popover/92 shadow-[0_4px_12px_-4px] shadow-shade/60"
      />
    </div>
  );
}
