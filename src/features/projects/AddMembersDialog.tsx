import { KeyRound, RectangleEllipsis, Search, Server, Variable } from 'lucide-react';
import { RadioGroup } from 'radix-ui';
import { type ReactNode, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import type { Project } from '@/bindings/Project';
import type { ProjectMember } from '@/bindings/ProjectMember';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { useVaultMutation } from '@/features/passwords/vault';
import { cn } from '@/lib/cn';
import { holds, type Library } from './model';
import { ProjectTile } from './ProjectTile';

/** What the Add menu adds: a kind of the library, or a folder (in a system dialog). */
export type MemberKind = 'hosts' | 'keys' | 'logins' | 'environments' | 'folder';

interface Choice {
  member: ProjectMember;
  title: string;
  subtitle: string;
  mono: boolean;
}

/** The library's items of `kind` that the project doesn't hold. */
function choices(kind: MemberKind, project: Project, library: Library): Choice[] {
  const out: Choice[] = [];
  if (kind === 'hosts') {
    for (const host of library.hosts ?? []) {
      if (host.kind !== 'host' || host.isWildcard) continue;
      const alias = host.patterns.find((p) => !p.startsWith('!'));
      if (!alias) continue;
      const member: ProjectMember = { type: 'host', alias };
      if (holds(project, member)) continue;
      out.push({
        member,
        title: alias,
        subtitle: `${host.user ? `${host.user}@` : ''}${host.hostName ?? alias}`,
        mono: true,
      });
    }
  } else if (kind === 'keys') {
    for (const key of library.keys ?? []) {
      if (!key.fingerprint) continue;
      const member: ProjectMember = { type: 'key', fingerprint: key.fingerprint };
      if (holds(project, member)) continue;
      out.push({ member, title: key.name, subtitle: key.comment || key.fingerprint, mono: true });
    }
  } else if (kind === 'logins') {
    for (const entry of library.entries ?? []) {
      if (entry.inTrash) continue;
      const member: ProjectMember = { type: 'login', id: entry.id };
      if (holds(project, member)) continue;
      out.push({
        member,
        title: entry.title,
        subtitle: [entry.username, entry.url.replace(/^https?:\/\//, '')]
          .filter(Boolean)
          .join(' · '),
        mono: false,
      });
    }
  } else if (kind === 'environments') {
    const groups = new Map<string, string[]>();
    for (const env of library.envs ?? []) {
      if (env.inTrash || !env.project) continue;
      groups.set(env.project, [...(groups.get(env.project) ?? []), env.name]);
    }
    for (const [group, names] of groups) {
      const member: ProjectMember = { type: 'environment', group };
      if (holds(project, member)) continue;
      out.push({ member, title: group, subtitle: names.join(', '), mono: true });
    }
  }
  return out;
}

const KINDS: { kind: Exclude<MemberKind, 'folder'>; icon: ReactNode }[] = [
  { kind: 'hosts', icon: <Server className="size-3.5" strokeWidth={2} /> },
  { kind: 'keys', icon: <KeyRound className="size-3.5" strokeWidth={2} /> },
  { kind: 'logins', icon: <RectangleEllipsis className="size-3.5" strokeWidth={2} /> },
  { kind: 'environments', icon: <Variable className="size-3.5" strokeWidth={2} /> },
];

function keyOf(member: ProjectMember): string {
  switch (member.type) {
    case 'host':
      return `host:${member.alias}`;
    case 'key':
      return `key:${member.fingerprint}`;
    case 'login':
      return `login:${member.id}`;
    case 'environment':
      return `env:${member.group}`;
    case 'folder':
      return `folder:${member.path}`;
  }
}

/** Adds items of the library to a project: one kind at a time, ticked in a list. */
export function AddMembersDialog({
  project,
  kind: initial,
  library,
  onDone,
}: {
  project: Project;
  kind: Exclude<MemberKind, 'folder'>;
  library: Library;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const [kind, setKind] = useState(initial);
  const [query, setQuery] = useState('');
  const [picked, setPicked] = useState<Map<string, ProjectMember>>(new Map());
  const all = useMemo(() => choices(kind, project, library), [kind, project, library]);
  const needle = query.trim().toLowerCase();
  const shown = needle
    ? all.filter((c) => `${c.title} ${c.subtitle}`.toLowerCase().includes(needle))
    : all;

  const add = useVaultMutation(
    async (members: ProjectMember[]) => {
      for (const member of members) await api.projectsSetMember(project.id, member, true);
      return members.length;
    },
    {
      success: (count) => t('projects.addedMany', { count, name: project.name }),
      onSuccess: onDone,
    },
  );

  const toggle = (choice: Choice) => {
    setPicked((current) => {
      const next = new Map(current);
      const key = keyOf(choice.member);
      if (next.has(key)) next.delete(key);
      else next.set(key, choice.member);
      return next;
    });
  };

  return (
    <DialogContent section="project" className="max-w-[560px]">
      <DialogHeader
        icon={<ProjectTile project={project} size={44} />}
        title={t('projects.addTitle', { name: project.name })}
        description={t('projects.addDescription')}
      />
      <DialogBody className="gap-3">
        <RadioGroup.Root
          value={kind}
          onValueChange={(next) => {
            setKind(next as Exclude<MemberKind, 'folder'>);
            setQuery('');
          }}
          aria-label={t('projects.addKinds')}
          orientation="horizontal"
          loop
          className="flex flex-wrap gap-1.5"
        >
          {KINDS.map((item) => (
            <RadioGroup.Item
              key={item.kind}
              value={item.kind}
              className={cn(
                'pressable inline-flex h-8 items-center gap-1.5 rounded-full border px-3 text-[12.5px] outline-none focus-visible:ring-2 focus-visible:ring-[rgb(var(--accent-rgb)/0.6)]',
                'border-white/10 bg-white/[0.04] text-fg-2 hover:bg-white/[0.08]',
                'data-[state=checked]:border-[rgb(var(--accent-rgb)/0.5)] data-[state=checked]:bg-[rgb(var(--accent-rgb)/0.14)] data-[state=checked]:text-[var(--accent-text)]',
              )}
            >
              {item.icon}
              {t(`projects.cards.${item.kind}`)}
            </RadioGroup.Item>
          ))}
        </RadioGroup.Root>
        <label className="field flex h-9 items-center gap-2 rounded-[10px] px-2.5">
          <Search aria-hidden="true" className="size-3.5 text-subtle" strokeWidth={2} />
          <span className="sr-only">{t('projects.addSearch')}</span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t('projects.addSearch')}
            className="h-full min-w-0 flex-1 bg-transparent outline-none placeholder:text-subtle"
          />
        </label>
        <ul
          aria-label={t(`projects.cards.${kind}`)}
          className="flex max-h-[320px] min-h-[120px] flex-col overflow-y-auto rounded-xl border border-white/[0.06]"
        >
          {shown.length === 0 ? (
            <li className="grid flex-1 place-items-center p-6 text-center text-[13px] text-subtle">
              {all.length === 0 ? t('projects.addNothing') : t('projects.addNoMatch')}
            </li>
          ) : (
            shown.map((choice) => {
              const key = keyOf(choice.member);
              const checked = picked.has(key);
              return (
                <li key={key} className="border-t border-white/[0.045] first:border-t-0">
                  <Checkbox
                    checked={checked}
                    onCheckedChange={() => toggle(choice)}
                    className="min-h-11 items-center px-3 py-1.5 hover:bg-white/[0.04]"
                    label={
                      <span className="block min-w-0">
                        <span
                          className={cn('block truncate', choice.mono && 'font-mono text-[12.5px]')}
                        >
                          {choice.title}
                        </span>
                        {choice.subtitle ? (
                          <span className="block truncate text-[11.5px] leading-4 font-normal text-subtle">
                            {choice.subtitle}
                          </span>
                        ) : null}
                      </span>
                    }
                  />
                </li>
              );
            })
          )}
        </ul>
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" onClick={onDone}>
          {t('common.cancel')}
        </Button>
        <Button
          variant="primary"
          disabled={picked.size === 0}
          loading={add.isPending}
          onClick={() => add.mutate([...picked.values()])}
        >
          {picked.size === 0
            ? t('projects.addNone')
            : t('projects.addCount', { count: picked.size })}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}
