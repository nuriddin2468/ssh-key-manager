import { useQuery } from '@tanstack/react-query';
import { FileInput, FolderPlus, Layers } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { errorMessage } from '@/api/useAppMutation';
import type { ImportChoice } from '@/bindings/ImportChoice';
import type { UnmanagedEnvFile } from '@/bindings/UnmanagedEnvFile';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { ChoiceCards } from '@/components/ui/ChoiceCards';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Select } from '@/components/ui/Select';
import { Spinner } from '@/components/ui/Spinner';
import { Switch } from '@/components/ui/Switch';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { useVaultMutation } from '@/features/passwords/vault';
import { useProjects } from '@/features/projects/queries';
import { Problems } from '../ImportEnvDialog';
import { envLabel, labelProblem, nameTaken } from '../model';
import { useEnvs } from '../queries';
import { bindRefusal, isEnvNameClash } from './errors';
import { fileName } from './model';
import { refreshFileReports } from './queries';

type Target = 'new' | 'existing';

interface AdoptFileDialogProps {
  found: UnmanagedEnvFile;
  onDone: () => void;
}

/**
 * Takes a `.env` file found in a project's folder under management: every
 * variable goes into an environment through the import (the page sees names
 * and suggested secret flags, never values), the project holds its group,
 * and the environment is written to the file from then on.
 */
export function AdoptFileDialog({ found, onDone }: AdoptFileDialogProps) {
  const { t } = useTranslation();
  const envs = useEnvs();
  const projects = useProjects();
  const project = projects.data?.find((item) => item.id === found.project);
  const local = (envs.data ?? []).filter((env) => !env.inTrash && env.kind === 'local');
  const preview = useQuery({
    queryKey: [
      'vault',
      'envs',
      'files',
      'adopt',
      found.project,
      found.file.folder,
      found.file.path,
    ],
    queryFn: () => api.envsFilesAdoptPreview(found.project, found.file),
    gcTime: 0,
    refetchOnWindowFocus: false,
  });
  const [target, setTarget] = useState<Target>('new');
  const [intoId, setIntoId] = useState('');
  const [group, setGroup] = useState<string | null>(null);
  const [name, setName] = useState<string | null>(null);
  const [secrets, setSecrets] = useState<Record<string, boolean>>({});
  const [touched, setTouched] = useState(false);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [serverTaken, setServerTaken] = useState(false);
  const file = fileName(found.file);

  const data = preview.data;
  // Until the user types: the project's environments' group, else the
  // folder's name, and the file's suffix (`.env.local` → `local`), else `dev`.
  const groupValue =
    group ?? project?.environments[0] ?? data?.suggestedProject ?? project?.name ?? '';
  const nameValue = name ?? (data?.suggestedName || 'dev');
  const chosenInto = local.some((env) => env.id === intoId) ? intoId : (local[0]?.id ?? '');
  const choices: ImportChoice[] = (data?.variables ?? []).map((variable) => ({
    name: variable.name,
    secret: secrets[variable.name] ?? variable.secret,
  }));
  const groupProblem = labelProblem(groupValue);
  const nameProblem = labelProblem(nameValue);
  const taken =
    target === 'new' &&
    !groupProblem &&
    !nameProblem &&
    (serverTaken || nameTaken(envs.data ?? [], groupValue, nameValue));
  const ready =
    data !== undefined &&
    (target === 'existing' ? chosenInto !== '' : !groupProblem && !nameProblem && !taken);

  const adopt = useVaultMutation(
    () =>
      api.envsFilesAdopt(
        found.project,
        found.file,
        target === 'existing'
          ? { type: 'existing', id: chosenInto }
          : { type: 'new', project: groupValue.trim(), name: nameValue.trim() },
        choices,
      ),
    {
      success: (result) => {
        const env = envs.data?.find((item) => item.id === result.id);
        return t('envs.adopt.done', {
          file,
          env: env ? envLabel(env) : `${groupValue.trim()} / ${nameValue.trim()}`,
        });
      },
      onSuccess: () => {
        void refreshFileReports();
        onDone();
      },
      onError: (error) => {
        // A name taken in the group shows at its field; anything else the
        // backend refused is said here, in words.
        // The group has an environment of that name, as the backend found
        // (`group / name`), perhaps since the list was fetched.
        const nameClash = target === 'new' && isEnvNameClash(error);
        if (error.code === 'already_exists' && (taken || nameClash)) {
          setTouched(true);
          setServerTaken(nameClash);
          return true;
        }
        const message = bindRefusal(t, error);
        if (!message) return false;
        setRefusal(message);
        return true;
      },
    },
  );

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (ready && !adopt.isPending) adopt.mutate(undefined);
  };

  return (
    <DialogContent section="envs" className="max-w-[640px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="lime" size={44} glow>
              <FileInput className="size-[22px]" strokeWidth={2} />
            </Tile>
          }
          title={t('envs.adopt.title', { file })}
          description={t('envs.adopt.description')}
        />
        <DialogBody>
          <p
            className="selectable truncate font-mono text-[12px] text-subtle"
            title={found.location}
          >
            {found.location}
          </p>
          {preview.isPending ? (
            <div className="grid place-items-center py-8 text-subtle">
              <Spinner className="size-5" />
            </div>
          ) : preview.isError ? (
            <p role="alert" className="text-[12.5px] text-critical">
              {errorMessage(t, preview.error)}
            </p>
          ) : data ? (
            <>
              <ChoiceCards
                legend={t('envs.adopt.where')}
                value={target}
                onValueChange={setTarget}
                options={[
                  {
                    value: 'new',
                    tone: 'lime',
                    icon: FolderPlus,
                    title: t('envs.adopt.toNew'),
                    hint: t('envs.adopt.toNewHint'),
                  },
                  {
                    value: 'existing',
                    tone: 'slate',
                    icon: Layers,
                    title: t('envs.adopt.toExisting'),
                    hint:
                      local.length > 0 ? t('envs.adopt.toExistingHint') : t('envs.adopt.noLocal'),
                    disabled: local.length === 0,
                  },
                ]}
              />
              {target === 'new' ? (
                <div className="grid grid-cols-2 gap-3">
                  <TextField
                    label={t('envs.adopt.group')}
                    value={groupValue}
                    onChange={(event) => {
                      setGroup(event.target.value);
                      setServerTaken(false);
                    }}
                    error={touched && groupProblem ? t(`envs.form.${groupProblem}`) : undefined}
                  />
                  <TextField
                    label={t('envs.adopt.name')}
                    value={nameValue}
                    placeholder={t('envs.form.namePlaceholder')}
                    onChange={(event) => {
                      setName(event.target.value);
                      setServerTaken(false);
                    }}
                    error={
                      touched
                        ? nameProblem
                          ? t(`envs.form.${nameProblem}`)
                          : taken
                            ? t('envs.form.taken', { project: groupValue.trim() })
                            : undefined
                        : undefined
                    }
                  />
                </div>
              ) : (
                <Select
                  label={t('envs.adopt.into')}
                  value={chosenInto}
                  onValueChange={setIntoId}
                  options={local.map((env) => ({ value: env.id, label: envLabel(env) }))}
                />
              )}
              {data.variables.length === 0 ? (
                <p className="text-[12.5px] text-muted">{t('envs.import.nothing')}</p>
              ) : (
                <div className="glass overflow-hidden rounded-[14px]">
                  <table className="w-full table-fixed border-collapse text-left">
                    <caption className="sr-only">{t('envs.adopt.tableCaption')}</caption>
                    <thead>
                      <tr className="h-9 text-[11.5px] font-medium tracking-[0.02em] text-subtle">
                        <th scope="col" className="pl-3.5">
                          {t('envs.colName')}
                        </th>
                        <th scope="col" className="w-[150px]" />
                        <th scope="col" className="w-[92px] pr-3.5 text-right">
                          {t('envs.secret')}
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.variables.map((variable) => (
                        <tr key={variable.name} className="h-[42px] border-t border-white/[0.05]">
                          <td
                            className="truncate pl-3.5 pr-3 font-mono text-[12.5px]"
                            title={variable.name}
                          >
                            {variable.name}
                          </td>
                          <td className="pr-2">
                            <span className="flex justify-end gap-1">
                              {variable.empty ? <Badge>{t('envs.import.empty')}</Badge> : null}
                              {variable.multiline ? (
                                <Badge>{t('envs.import.multiline')}</Badge>
                              ) : null}
                            </span>
                          </td>
                          <td className="pr-3.5">
                            <span className="flex justify-end">
                              <Switch
                                aria-label={t('envs.adopt.secretFor', { name: variable.name })}
                                checked={secrets[variable.name] ?? variable.secret}
                                onCheckedChange={(secret) =>
                                  setSecrets((current) => ({ ...current, [variable.name]: secret }))
                                }
                              />
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {refusal ? (
                <p role="alert" className="text-[12.5px] text-critical">
                  {refusal}
                </p>
              ) : null}
              {data.problems.length > 0 ? (
                <Problems problems={data.problems} title={t('envs.adopt.problems')} />
              ) : null}
            </>
          ) : null}
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            size="lg"
            loading={adopt.isPending}
            disabled={!data}
          >
            {t('envs.adopt.submit')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
