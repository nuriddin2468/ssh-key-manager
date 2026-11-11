import { useMutation } from '@tanstack/react-query';
import { FileUp, FolderPlus, Layers, TriangleAlert } from 'lucide-react';
import { type FormEvent, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { errorMessage, toastError } from '@/api/useAppMutation';
import type { EnvImportPreview } from '@/bindings/EnvImportPreview';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { ImportChoice } from '@/bindings/ImportChoice';
import type { ParseProblem } from '@/bindings/ParseProblem';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { CheckboxControl } from '@/components/ui/Checkbox';
import { ChoiceCards } from '@/components/ui/ChoiceCards';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Select } from '@/components/ui/Select';
import { Switch } from '@/components/ui/Switch';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { Callout } from '@/features/passwords/files/Callout';
import { baseName } from '@/features/passwords/files/pickers';
import { useVaultMutation } from '@/features/passwords/vault';
import { cn } from '@/lib/cn';
import { AppError } from '@/lib/ipc';
import { FirstPartField, useFirstPart } from './FirstPart';
import { initialChoices, labelProblem, nameTaken, secondPart, whereLabel } from './model';
import { useEnvLabel, useProjectNames } from './useProjectNames';
import { PERSONAL, partProblem, projectOf, WhereFields } from './WhereFields';

interface ImportEnvDialogProps {
  all: EnvSummary[];
  /** The environment it was opened from, which the import goes to. */
  into?: EnvSummary;
  /** Closes the dialog, with the environment the variables went to. */
  onDone: (id?: string) => void;
}

type Target = 'new' | 'existing';

interface Picked {
  path: string;
  preview: EnvImportPreview;
  /** The variables to take, with their secret flags; left-out ones are absent. */
  choices: ImportChoice[];
}

/**
 * Imports a `.env` file: the backend opens the file dialog and reads the
 * file, the page sees names and suggested secret flags, never values. The
 * user picks what to take, adjusts the flags and where it goes.
 */
export function ImportEnvDialog({ all, into, onDone }: ImportEnvDialogProps) {
  const { t } = useTranslation();
  const envLabelOf = useEnvLabel();
  const names = useProjectNames();
  const [picked, setPicked] = useState<Picked | null>(null);
  const [error, setError] = useState<string | null>(null);
  const existing = all.filter((env) => !env.inTrash);
  const [target, setTarget] = useState<Target>(into ? 'existing' : 'new');
  const [intoId, setIntoId] = useState(into?.id ?? existing[0]?.id ?? '');
  // Where a new one goes: a project (or Personal) and a part.
  const [project, setProject] = useState(into?.project ?? PERSONAL);
  const [part, setPart] = useState('');
  const [name, setName] = useState('');
  const [touched, setTouched] = useState(false);
  const firstPart = useFirstPart();
  const naming = firstPart.naming;
  const review = useRef<HTMLDivElement>(null);
  const hasPreview = picked !== null;
  // "Choose file…" is gone with the first step: start the review instead.
  useEffect(() => {
    if (hasPreview) review.current?.focus();
  }, [hasPreview]);

  const pick = useMutation({
    mutationFn: api.envsImportPick,
    onSuccess: (result) => {
      if (!result) return;
      setError(null);
      setPicked({
        path: result.path,
        preview: result.preview,
        choices: initialChoices(result.preview),
      });
      const { suggestedProject, suggestedName } = result.preview;
      // The file's folder names the part.
      setPart(into?.part ?? suggestedProject);
      setName(suggestedName);
      // Opened from the page's toolbar: the environment the file's names
      // point at, if there is one, else a new one.
      if (!into) {
        const match = existing.find(
          (env) =>
            same(env.part, suggestedProject) &&
            env.name.toLowerCase() === suggestedName.toLowerCase(),
        );
        setTarget(match ? 'existing' : 'new');
        if (match) setIntoId(match.id);
      }
    },
    onError: (cause) => {
      const appError = AppError.from(cause);
      const messages: Partial<Record<string, string>> = {
        parse: t('envs.import.notText'),
        invalid_input: t('envs.import.tooLarge'),
        vault_locked: t('errors.vault_locked'),
      };
      const message = messages[appError.code];
      if (message) setError(message);
      else if (appError.code !== 'cancelled') toastError(t, appError);
    },
  });

  const run = useVaultMutation(
    (choices: ImportChoice[]) =>
      api.envsImport(
        target === 'existing'
          ? { type: 'existing', id: intoId }
          : { type: 'new', project: projectOf(project), part: part.trim(), name: name.trim() },
        choices,
        target === 'new' ? firstPart.rename : null,
      ),
    {
      success: (result) =>
        result.replaced > 0
          ? t('envs.import.doneReplaced', {
              count: result.added + result.replaced,
              replaced: result.replaced,
            })
          : t('envs.import.done', { count: result.added }),
      onSuccess: (result) => onDone(result.id),
      onError: (appError) => {
        if (appError.code === 'invalid_input' && appError.message.includes('again')) {
          setPicked(null);
          setError(t('envs.import.pickAgain'));
          return true;
        }
        if (appError.code === 'already_exists') {
          firstPart.back();
          setTouched(true);
          return true;
        }
        if (naming && appError.code === 'invalid_input') {
          firstPart.refuse(errorMessage(t, appError));
          return true;
        }
        return false;
      },
    },
  );

  const projectProblem = partProblem(part);
  const nameProblem = labelProblem(name);
  const taken =
    target === 'new' &&
    !projectProblem &&
    !nameProblem &&
    nameTaken(all, projectOf(project), part, name);
  const chosen = picked?.choices ?? [];
  const ready =
    chosen.length > 0 &&
    (target === 'existing' ? intoId !== '' : !projectProblem && !nameProblem && !taken);

  // A new one may give its project a second part: the first is named before.
  const first = target === 'new' ? secondPart(all, projectOf(project), [part]) : null;
  const projectName = names.get(projectOf(project) ?? '') ?? t('projects.personal');

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (run.isPending) return;
    if (naming) {
      if (firstPart.confirm()) run.mutate(chosen);
      return;
    }
    setTouched(true);
    if (!ready) return;
    if (first) {
      firstPart.ask(first);
      return;
    }
    run.mutate(chosen);
  };

  return (
    <DialogContent
      section="envs"
      className="max-w-[720px]"
      onBack={naming ? firstPart.back : undefined}
    >
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="lime" size={44} glow>
              <FileUp className="size-[22px]" strokeWidth={2} />
            </Tile>
          }
          title={
            naming ? t('envs.firstPart.title', { project: projectName }) : t('envs.import.title')
          }
          description={
            naming
              ? t('envs.firstPart.text')
              : picked
                ? baseName(picked.path)
                : t('envs.import.description')
          }
        />
        {naming ? (
          <DialogBody>
            <FirstPartField state={firstPart} />
          </DialogBody>
        ) : picked ? (
          <DialogBody>
            <div
              ref={review}
              tabIndex={-1}
              role="status"
              className="text-[12.5px] text-muted outline-none"
            >
              {t('envs.import.found', { count: picked.preview.variables.length })}
            </div>
            <ChoiceCards
              legend={t('envs.import.where')}
              value={target}
              onValueChange={setTarget}
              options={[
                {
                  value: 'new',
                  tone: 'lime',
                  icon: FolderPlus,
                  title: t('envs.import.toNew'),
                  hint: t('envs.import.toNewHint'),
                },
                {
                  value: 'existing',
                  tone: 'slate',
                  icon: Layers,
                  title: t('envs.import.toExisting'),
                  hint: t('envs.import.toExistingHint'),
                  disabled: existing.length === 0,
                },
              ]}
            />
            {target === 'new' ? (
              <div className="grid grid-cols-2 gap-3">
                <WhereFields
                  all={all}
                  project={project}
                  part={part}
                  onProject={setProject}
                  onPart={setPart}
                  touched={touched}
                />
                <TextField
                  label={t('envs.form.name')}
                  value={name}
                  placeholder={t('envs.form.namePlaceholder')}
                  onChange={(event) => setName(event.target.value)}
                  error={
                    touched
                      ? nameProblem
                        ? t(`envs.form.${nameProblem}`)
                        : taken
                          ? t('envs.form.taken', {
                              where: whereLabel(projectName, part.trim()),
                              stage: name.trim(),
                            })
                          : undefined
                      : undefined
                  }
                />
              </div>
            ) : (
              <Select
                label={t('envs.import.into')}
                value={intoId}
                onValueChange={setIntoId}
                options={existing.map((env) => ({ value: env.id, label: envLabelOf(env) }))}
                hint={t('envs.import.intoHint')}
              />
            )}
            <VariableChoices
              preview={picked.preview}
              choices={picked.choices}
              onChange={(choices) => setPicked({ ...picked, choices })}
            />
            {picked.preview.problems.length > 0 ? (
              <Problems problems={picked.preview.problems} />
            ) : null}
          </DialogBody>
        ) : (
          <DialogBody>
            <Callout tone="warning" icon={TriangleAlert} title={t('envs.import.plaintextTitle')}>
              {t('envs.import.plaintext')}
            </Callout>
            {error ? (
              <p role="alert" className="text-[12.5px] text-critical">
                {error}
              </p>
            ) : null}
          </DialogBody>
        )}
        <DialogFooter>
          {naming ? (
            <Button size="lg" onClick={firstPart.back}>
              {t('envs.firstPart.back')}
            </Button>
          ) : (
            <Button size="lg" onClick={() => onDone()}>
              {t('common.cancel')}
            </Button>
          )}
          {naming ? (
            <Button type="submit" variant="primary" size="lg" loading={run.isPending}>
              {t('envs.firstPart.go')}
            </Button>
          ) : picked ? (
            <Button
              type="submit"
              variant="primary"
              size="lg"
              loading={run.isPending}
              disabled={chosen.length === 0}
            >
              {t('envs.import.submit', { count: chosen.length })}
            </Button>
          ) : (
            <Button
              variant="primary"
              size="lg"
              autoFocus
              icon={<FileUp className="size-4" strokeWidth={2} />}
              loading={pick.isPending}
              onClick={() => pick.mutate()}
            >
              {t('envs.import.choose')}
            </Button>
          )}
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

interface VariableChoicesProps {
  preview: EnvImportPreview;
  choices: ImportChoice[];
  onChange: (choices: ImportChoice[]) => void;
}

/** The file's variables: which to take, and which are secret. */
function VariableChoices({ preview, choices, onChange }: VariableChoicesProps) {
  const { t } = useTranslation();
  const all = preview.variables;
  const taken = (name: string) => choices.find((choice) => choice.name === name);
  const allTaken = choices.length === all.length;
  const toggle = (name: string, secret: boolean) =>
    onChange(
      taken(name)
        ? choices.filter((choice) => choice.name !== name)
        : all
            .filter((variable) => variable.name === name || taken(variable.name))
            .map((variable) => taken(variable.name) ?? { name, secret }),
    );
  const setSecret = (name: string, secret: boolean) =>
    onChange(choices.map((choice) => (choice.name === name ? { ...choice, secret } : choice)));

  if (all.length === 0) {
    return <p className="text-[12.5px] text-muted">{t('envs.import.nothing')}</p>;
  }

  return (
    <div className="glass overflow-hidden rounded-[14px]">
      <table className="w-full table-fixed border-collapse text-left">
        <caption className="sr-only">{t('envs.import.tableCaption')}</caption>
        <thead>
          <tr className="h-9 text-[11.5px] font-medium tracking-[0.02em] text-subtle">
            <th scope="col" className="w-10 pl-3.5">
              <CheckboxControl
                aria-label={t('envs.import.selectAll')}
                checked={allTaken ? true : choices.length === 0 ? false : 'indeterminate'}
                onCheckedChange={() =>
                  onChange(
                    allTaken
                      ? []
                      : all.map(
                          (variable) =>
                            taken(variable.name) ?? {
                              name: variable.name,
                              secret: variable.secret,
                            },
                        ),
                  )
                }
              />
            </th>
            <th scope="col">{t('envs.colName')}</th>
            <th scope="col" className="w-[150px]" />
            <th scope="col" className="w-[92px] pr-3.5 text-right">
              {t('envs.secret')}
            </th>
          </tr>
        </thead>
        <tbody>
          {all.map((variable) => {
            const choice = taken(variable.name);
            return (
              <tr
                key={variable.name}
                className={cn(
                  'h-[42px] border-t border-white/[0.05]',
                  choice ? 'bg-[rgb(var(--accent-rgb)/0.06)]' : 'opacity-70',
                )}
              >
                <td className="pl-3.5">
                  <CheckboxControl
                    aria-label={t('envs.import.take', { name: variable.name })}
                    checked={Boolean(choice)}
                    onCheckedChange={() => toggle(variable.name, variable.secret)}
                  />
                </td>
                <td className="truncate pr-3 font-mono text-[12.5px]" title={variable.name}>
                  {variable.name}
                </td>
                <td className="pr-2">
                  <span className="flex justify-end gap-1">
                    {variable.empty ? <Badge>{t('envs.import.empty')}</Badge> : null}
                    {variable.multiline ? <Badge>{t('envs.import.multiline')}</Badge> : null}
                  </span>
                </td>
                <td className="pr-3.5">
                  <span className="flex justify-end">
                    <Switch
                      aria-label={t('envs.import.secretFor', { name: variable.name })}
                      checked={choice ? choice.secret : variable.secret}
                      disabled={!choice}
                      onCheckedChange={(secret) => setSecret(variable.name, secret)}
                    />
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** The lines that gave no variable, by number: their text may be a secret. */
export function Problems({ problems, title }: { problems: ParseProblem[]; title?: string }) {
  const { t } = useTranslation();
  return (
    <Callout tone="warning" icon={TriangleAlert} title={title ?? t('envs.import.problemsTitle')}>
      <ul className="flex flex-col gap-0.5">
        {problems.map((problem) => (
          <li key={`${problem.line}-${problem.kind}`}>
            {t(`envs.import.problem.${problem.kind}`, {
              line: problem.line,
              name: problem.name ?? '',
            })}
          </li>
        ))}
      </ul>
    </Callout>
  );
}

function same(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}
