import type { TFunction } from 'i18next';
import { FolderSearch, RotateCcw, Sparkles } from 'lucide-react';
import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { queryClient, useKeys, useVaultEntries, useVaultStatus } from '@/api/queries';
import { errorMessage } from '@/api/useAppMutation';
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
import { FirstPartField, useFirstPart } from '@/features/envs/FirstPart';
import { envLabel, secondPart } from '@/features/envs/model';
import { useEnvs } from '@/features/envs/queries';
import { useVaultMutation } from '@/features/passwords/vault';
import { cn } from '@/lib/cn';
import { nameProblem } from './ProjectDialog';
import { ColorPicker, ProjectTile } from './ProjectTile';
import { projectKeys, refreshSuggestions, useProjects, useSuggestions } from './queries';

type Kind = 'hosts' | 'keys' | 'environments' | 'folders' | 'logins' | 'hostsFile';
const KINDS: Kind[] = ['folders', 'hosts', 'hostsFile', 'environments', 'logins', 'keys'];

function member(kind: Kind, value: string): ProjectMember {
  switch (kind) {
    case 'hosts':
      return { type: 'host', alias: value };
    case 'keys':
      return { type: 'key', fingerprint: value };
    case 'environments':
      return { type: 'environment', id: value };
    case 'folders':
      return { type: 'folder', path: value };
    case 'logins':
      return { type: 'login', id: value };
    case 'hostsFile':
      return { type: 'hostsFile', name: value };
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
    case 'hostsFile':
      return t('projects.suggest.why.hostsFile', { host: reason.host });
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

  // Environments keep their parts: those kept may give the project its
  // second, whose first is named before, in the same change.
  const envList = useEnvs().data;
  const envs = envList ?? [];
  // Whether they give it a second part is known once the list is in.
  const waiting = Boolean(existing) && suggestion.environments.length > 0 && !envList;
  const projectNames = new Map(projects.map((p) => [p.id, p.name]));
  const firstPart = useFirstPart();
  const naming = firstPart.naming;
  const coming = existing
    ? envs.filter((env) =>
        kept.some((item) => item.kind === 'environments' && item.value === env.id),
      )
    : [];
  const first =
    existing && coming.length > 0
      ? secondPart(
          envs,
          existing.id,
          coming.map((env) => env.part),
          coming.map((env) => env.id),
        )
      : null;

  const accept = useVaultMutation(
    () =>
      api.projectsAcceptSuggestion(
        suggestion.key,
        { name: name.trim(), color },
        kept.map((item) => member(item.kind, item.value)),
        naming ? firstPart.rename : null,
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
      onError: (error) => {
        // Said in the step, while it shows: the name it asked for may be
        // what failed.
        if (naming && (error.code === 'invalid_input' || error.code === 'already_exists')) {
          firstPart.refuse(errorMessage(t, error));
          return true;
        }
        return false;
      },
    },
  );

  const go = () => {
    if (accept.isPending) return;
    if (naming) {
      if (firstPart.confirm()) accept.mutate(undefined);
      return;
    }
    if (first) {
      firstPart.ask(first);
      return;
    }
    accept.mutate(undefined);
  };
  const dismiss = useVaultMutation(() => api.projectsDismissSuggestion(suggestion.key), {
    success: () => t('projects.suggest.dismissed', { name: suggestion.name }),
    onSuccess: () => void refreshSuggestions(),
  });

  const label = (kind: Kind, value: string) => {
    if (kind === 'keys') return keys.find((k) => k.fingerprint === value)?.name ?? value;
    if (kind === 'logins') return entries.find((e) => e.id === value)?.title ?? value;
    if (kind === 'environments') {
      // By entry id: shown as `backend · dev`, as Personal's are.
      const env = envs.find((e) => e.id === value);
      return env ? envLabel(env, projectNames) : value;
    }
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
      {naming && existing ? (
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            go();
          }}
          // As in the dialogs, Escape goes back to the card.
          onKeyDown={(event) => {
            if (event.key !== 'Escape') return;
            event.preventDefault();
            firstPart.back();
          }}
        >
          <div className="flex flex-col gap-1">
            <h3 className="text-[13px] font-semibold">
              {t('envs.firstPart.title', { project: existing.name })}
            </h3>
            <p className="text-[12.5px] text-fg-2">{t('envs.firstPart.text')}</p>
          </div>
          <FirstPartField state={firstPart} />
        </form>
      ) : (
        <>
          <ul aria-label={t('projects.suggest.whyLabel')} className="flex flex-wrap gap-1.5">
            {suggestion.reasons.map((reason) => (
              <li
                key={JSON.stringify(reason)}
                className="rounded-[7px] bg-ink/[0.05] px-2 py-0.5 text-[11.5px] text-fg-2"
              >
                {reasonText(t, reason)}
              </li>
            ))}
          </ul>
          <div className="grid gap-x-4 gap-y-1 sm:grid-cols-2">
            {KINDS.filter((kind) => suggestion[kind].length > 0).map((kind) => (
              <fieldset key={kind} className="contents">
                <legend className="col-span-full mt-1 text-[11px] font-semibold text-label">
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
                          title={kind === 'environments' ? label(kind, value) : value}
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
        </>
      )}
      <div className="flex flex-wrap items-center gap-2 pt-1">
        {/* One button through both steps, so the focus stays on it; never a
            submit button, which the click that opens the step would press
            again. Enter in the step's one field sends its form. */}
        <Button
          variant="primary"
          disabled={!naming && (kept.length === 0 || problem !== null || taken || waiting)}
          loading={accept.isPending}
          onClick={go}
        >
          {naming
            ? t('envs.firstPart.go')
            : existing
              ? t('projects.suggest.addToButton', { name: existing.name })
              : t('projects.suggest.create')}
        </Button>
        {naming ? (
          <Button variant="ghost" onClick={firstPart.back}>
            {t('envs.firstPart.back')}
          </Button>
        ) : (
          <>
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
          </>
        )}
      </div>
    </section>
  );
}
