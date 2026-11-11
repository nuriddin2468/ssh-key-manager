import type { TFunction } from 'i18next';
import { FolderSearch, RotateCcw, Sparkles } from 'lucide-react';
import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { queryClient, useKeys, useVaultEntries, useVaultStatus } from '@/api/queries';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import type { ProjectColor } from '@/bindings/ProjectColor';
import type { ProjectMember } from '@/bindings/ProjectMember';
import type { ProjectSuggestion } from '@/bindings/ProjectSuggestion';
import type { SuggestionReason } from '@/bindings/SuggestionReason';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { EmptyState } from '@/components/ui/EmptyState';
import { Spinner } from '@/components/ui/Spinner';
import { TextField } from '@/components/ui/TextField';
import { useVaultMutation } from '@/features/passwords/vault';
import { cn } from '@/lib/cn';
import { nameProblem } from './ProjectDialog';
import { ColorPicker, ProjectTile } from './ProjectTile';
import { projectKeys, refreshSuggestions, useProjects, useSuggestions } from './queries';

type Kind = 'hosts' | 'keys' | 'environments' | 'folders' | 'logins';
const KINDS: Kind[] = ['folders', 'hosts', 'environments', 'logins', 'keys'];

function member(kind: Kind, value: string): ProjectMember {
  switch (kind) {
    case 'hosts':
      return { type: 'host', alias: value };
    case 'keys':
      return { type: 'key', fingerprint: value };
    case 'environments':
      return { type: 'environment', group: value };
    case 'folders':
      return { type: 'folder', path: value };
    case 'logins':
      return { type: 'login', id: value };
  }
}

/**
 * Projects the app proposes, one card each: why, and what would go in, every
 * item a checkbox. Nothing changes until the user creates the project (or
 * adds to the one it names); "Not now" hides one until the page opens again,
 * "Don't suggest again" for good on this computer.
 */
export function SuggestionsPage() {
  const { t } = useTranslation();
  const dialogs = useDialogs();
  const state = useVaultStatus().data?.state;
  const suggestions = useSuggestions({ look: true });
  const [later, setLater] = useState<Set<string>>(new Set());

  const lookIn = useVaultMutation(() => api.projectsSuggestInFolder(), {
    onSuccess: (found) => {
      if (found) queryClient.setQueryData(projectKeys.suggestions, found);
    },
  });
  const restore = useVaultMutation(() => api.projectsRestoreSuggestions(), {
    success: () => t('projects.suggest.restored'),
    onSuccess: () => void refreshSuggestions(),
  });

  const shown = (suggestions.data ?? []).filter((s) => !later.has(s.key));

  return (
    <>
      <Toolbar title={t('projects.suggest.title')}>
        <Button
          size="sm"
          icon={<FolderSearch className="size-4" strokeWidth={2} />}
          disabled={state !== 'unlocked'}
          loading={lookIn.isPending}
          onClick={() => lookIn.mutate(undefined)}
        >
          {t('projects.suggest.lookIn')}
        </Button>
      </Toolbar>
      <PageBody>
        <p className="max-w-[680px] text-[13px] text-muted">{t('projects.suggest.intro')}</p>
        {state === 'locked' ? (
          <EmptyState
            className="my-auto"
            icon={<Sparkles className="size-6" strokeWidth={2} />}
            title={t('projects.suggest.lockedTitle')}
            description={t('projects.suggest.lockedText')}
            action={
              <Button variant="primary" onClick={() => dialogs.unlockVault()}>
                {t('projects.unlock')}
              </Button>
            }
          />
        ) : suggestions.isPending && state === 'unlocked' ? (
          <div className="grid flex-1 place-items-center">
            <Spinner />
          </div>
        ) : shown.length === 0 ? (
          <EmptyState
            className="my-auto"
            icon={<Sparkles className="size-6" strokeWidth={2} />}
            title={t('projects.suggest.emptyTitle')}
            description={t('projects.suggest.emptyText')}
          />
        ) : (
          <ul className="grid items-start gap-3 xl:grid-cols-2">
            {shown.map((suggestion) => (
              <li key={suggestion.key}>
                <SuggestionCard
                  suggestion={suggestion}
                  onLater={() => setLater((set) => new Set(set).add(suggestion.key))}
                />
              </li>
            ))}
          </ul>
        )}
        {state === 'unlocked' ? (
          <div>
            <Button
              size="sm"
              variant="ghost"
              icon={<RotateCcw className="size-3.5" strokeWidth={2} />}
              loading={restore.isPending}
              onClick={() => {
                setLater(new Set());
                restore.mutate(undefined);
              }}
            >
              {t('projects.suggest.showDismissed')}
            </Button>
          </div>
        ) : null}
      </PageBody>
    </>
  );
}

function reasonText(t: TFunction, reason: SuggestionReason): string {
  switch (reason.type) {
    case 'environments':
      return t('projects.suggest.why.environments', { group: reason.group });
    case 'gitFolder':
      return t('projects.suggest.why.gitFolder', { folder: reason.folder });
    case 'proxyJump':
      return t('projects.suggest.why.proxyJump', { bastion: reason.bastion });
    case 'namePrefix':
      return t('projects.suggest.why.namePrefix', { prefix: reason.prefix });
    case 'domain':
      return t('projects.suggest.why.domain', { domain: reason.domain });
    case 'keepassGroup':
      return t('projects.suggest.why.keepassGroup', { group: reason.group });
    case 'keepassTag':
      return t('projects.suggest.why.keepassTag', { tag: reason.tag });
  }
}

function SuggestionCard({
  suggestion,
  onLater,
}: {
  suggestion: ProjectSuggestion;
  onLater: () => void;
}) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const headingId = useId();
  const colorLabel = useId();
  const projects = useProjects().data ?? [];
  const keys = useKeys().data?.keys ?? [];
  const entries = useVaultEntries().data ?? [];
  const existing = suggestion.existing
    ? projects.find((p) => p.id === suggestion.existing)
    : undefined;
  const [name, setName] = useState(suggestion.name);
  const [color, setColor] = useState<ProjectColor>(suggestion.color);
  const all: { kind: Kind; value: string }[] = KINDS.flatMap((kind) =>
    suggestion[kind].map((value) => ({ kind, value })),
  );
  const [unticked, setUnticked] = useState<Set<string>>(new Set());
  const kept = all.filter((item) => !unticked.has(`${item.kind}:${item.value}`));
  const problem = existing ? null : nameProblem(name);
  const taken =
    !existing && projects.some((p) => p.name.toLowerCase() === name.trim().toLowerCase());

  const accept = useVaultMutation(
    () =>
      api.projectsAcceptSuggestion(
        suggestion.key,
        { name: name.trim(), color },
        kept.map((item) => member(item.kind, item.value)),
      ),
    {
      success: (project) =>
        existing
          ? t('projects.suggest.addedTo', { name: project.name })
          : t('projects.suggest.created', { name: project.name }),
      onSuccess: (project) => {
        void refreshSuggestions();
        navigate({ page: 'project', id: project.id });
      },
    },
  );
  const dismiss = useVaultMutation(() => api.projectsDismissSuggestion(suggestion.key), {
    success: () => t('projects.suggest.dismissed', { name: suggestion.name }),
    onSuccess: () => void refreshSuggestions(),
  });

  const label = (kind: Kind, value: string) => {
    if (kind === 'keys') return keys.find((k) => k.fingerprint === value)?.name ?? value;
    if (kind === 'logins') return entries.find((e) => e.id === value)?.title ?? value;
    return value;
  };

  return (
    <section aria-labelledby={headingId} className="glass flex flex-col gap-3 rounded-2xl p-4">
      {existing ? (
        <div className="flex items-center gap-2.5">
          <ProjectTile project={existing} size={28} />
          <h2 id={headingId} className="text-[14px] font-semibold">
            {t('projects.suggest.addTo', { name: existing.name })}
          </h2>
        </div>
      ) : (
        <div className="flex flex-wrap items-end gap-3">
          <h2 id={headingId} className="sr-only">
            {t('projects.suggest.cardTitle', { name: suggestion.name })}
          </h2>
          <TextField
            className="min-w-[180px] flex-1"
            label={t('projects.form.name')}
            value={name}
            onChange={(event) => setName(event.target.value)}
            error={
              problem
                ? t(`projects.form.${problem}`)
                : taken
                  ? t('projects.form.taken', { name: name.trim() })
                  : undefined
            }
          />
          <div className="flex flex-col gap-1.5">
            <span id={colorLabel} className="text-[12px] font-semibold text-fg-2">
              {t('projects.form.color')}
            </span>
            <ColorPicker value={color} onChange={setColor} labelId={colorLabel} />
          </div>
        </div>
      )}
      <ul aria-label={t('projects.suggest.whyLabel')} className="flex flex-wrap gap-1.5">
        {suggestion.reasons.map((reason) => (
          <li
            key={JSON.stringify(reason)}
            className="rounded-[7px] bg-white/[0.05] px-2 py-0.5 text-[11.5px] text-fg-2"
          >
            {reasonText(t, reason)}
          </li>
        ))}
      </ul>
      <div className="grid gap-x-4 gap-y-1 sm:grid-cols-2">
        {KINDS.filter((kind) => suggestion[kind].length > 0).map((kind) => (
          <fieldset key={kind} className="contents">
            <legend className="col-span-full mt-1 text-[11px] font-semibold text-[#7C869A]">
              {t(`projects.cards.${kind}`)}
            </legend>
            {suggestion[kind].map((value) => {
              const id = `${kind}:${value}`;
              const checked = !unticked.has(id);
              return (
                <Checkbox
                  key={id}
                  className="min-h-7 min-w-0 items-center"
                  checked={checked}
                  onCheckedChange={() =>
                    setUnticked((set) => {
                      const next = new Set(set);
                      if (next.has(id)) next.delete(id);
                      else next.add(id);
                      return next;
                    })
                  }
                  label={
                    <span
                      className={cn(
                        'block truncate font-normal text-fg-2',
                        kind !== 'logins' && 'font-mono text-[12px]',
                      )}
                      title={value}
                    >
                      {label(kind, value)}
                    </span>
                  }
                />
              );
            })}
          </fieldset>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-2 pt-1">
        <Button
          variant="primary"
          disabled={kept.length === 0 || problem !== null || taken}
          loading={accept.isPending}
          onClick={() => accept.mutate(undefined)}
        >
          {existing
            ? t('projects.suggest.addToButton', { name: existing.name })
            : t('projects.suggest.create')}
        </Button>
        <Button variant="ghost" onClick={onLater}>
          {t('projects.suggest.later')}
        </Button>
        <span className="flex-1" />
        <Button
          variant="ghost"
          size="sm"
          className="text-subtle"
          loading={dismiss.isPending}
          onClick={() => dismiss.mutate(undefined)}
        >
          {t('projects.suggest.dismiss')}
        </Button>
      </div>
    </section>
  );
}
