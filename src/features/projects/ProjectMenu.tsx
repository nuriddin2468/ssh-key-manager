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
import { MenuItem, MenuSeparator, MenuSub } from '@/components/ui/Menu';
import { cn } from '@/lib/cn';
import { useSetMember } from './actions';
import { holds } from './model';
import { ProjectDialog } from './ProjectDialog';
import { ProjectChip, projectDot } from './ProjectTile';
import { useProjects } from './queries';

const ITEM =
  'flex h-8 items-center gap-2.5 rounded-lg px-2.5 outline-none select-none transition-colors duration-100 active:bg-white/[0.12] data-[disabled]:opacity-40 data-[highlighted]:bg-white/[0.08]';

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
      <DropdownMenu.Label className="px-2.5 pt-1 pb-1.5 text-[11px] font-semibold text-[#7C869A]">
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
    <ul aria-label={t('projects.inProjects')} className={cn('flex flex-wrap gap-1', className)}>
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
