import { FilePlus2 } from 'lucide-react';
import { type FormEvent, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import type { EnvFile } from '@/bindings/EnvFile';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Select } from '@/components/ui/Select';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { useVaultMutation } from '@/features/passwords/vault';
import { useProjects } from '@/features/projects/queries';
import { cn } from '@/lib/cn';
import { bindingPath, fileName, QUICK_NAMES } from './model';

interface BindFileDialogProps {
  env: EnvSummary;
  /** Files it is written to already: their names aren't offered again. */
  bound: EnvFile[];
  /** Closes the dialog; with a file that exists with other values, to compare. */
  onDone: (conflict?: EnvFile) => void;
}

/** A `.env` file's name, with folders before it; the backend checks the rest. */
const LOOKS_LIKE_ENV = /^(?:[^/\\]+[/\\])*(?:\.env(?:\..+)?|.+\.env|\.dev\.vars)$/i;

/**
 * Writes an environment to a file in a folder of a project that holds its
 * group: the folder comes from the projects, the path in it is typed. The
 * backend checks the path again and refuses links, templates and anything
 * outside the folder.
 */
export function BindFileDialog({ env, bound, onDone }: BindFileDialogProps) {
  const { t } = useTranslation();
  const projects = useProjects();
  const folders = useMemo(
    () =>
      (projects.data ?? [])
        .filter((project) => project.environments.includes(env.project))
        .flatMap((project) => project.folders.map((folder) => ({ folder, project: project.name })))
        .filter(
          (item, index, all) => all.findIndex((other) => other.folder === item.folder) === index,
        ),
    [projects.data, env.project],
  );
  const holders = (projects.data ?? []).filter((project) =>
    project.environments.includes(env.project),
  );
  const [folder, setFolder] = useState(folders[0]?.folder ?? '');
  const chosenFolder = folders.some((item) => item.folder === folder)
    ? folder
    : (folders[0]?.folder ?? '');
  const taken = (path: string) =>
    bound.some((file) => file.folder === chosenFolder && file.path === path);
  const [path, setPath] = useState(
    () => QUICK_NAMES.find((name) => !bound.some((file) => file.path === name)) ?? '',
  );
  const [touched, setTouched] = useState(false);
  const trimmed = path.trim().replace(/^[/\\]+/, '');
  const problem = !trimmed
    ? t('envs.files.bind.fileHint')
    : !LOOKS_LIKE_ENV.test(trimmed) || /(^|[/\\])\.\.?([/\\]|$)/.test(trimmed)
      ? t('envs.files.bind.fileHint')
      : taken(trimmed)
        ? t('envs.files.bind.taken')
        : null;

  const bind = useVaultMutation((file: EnvFile) => api.envsFilesBind(env.id, file), {
    onSuccess: (status) => {
      if (status.state.type === 'conflict') {
        toast.warning(t('envs.files.bind.differs', { file: fileName(status.file) }));
        onDone(status.file);
        return;
      }
      toast.success(t('envs.files.bind.done', { file: fileName(status.file) }));
      onDone();
    },
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (problem || !chosenFolder || bind.isPending) return;
    bind.mutate({ folder: chosenFolder, path: trimmed });
  };

  return (
    <DialogContent section="envs" className="max-w-[560px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="lime" size={44} glow>
              <FilePlus2 className="size-[22px]" strokeWidth={2} />
            </Tile>
          }
          title={t('envs.files.bind.title')}
          description={t('envs.files.bind.description')}
        />
        <DialogBody>
          {folders.length === 0 ? (
            <p role="status" className="text-[12.5px] leading-[19px] text-muted">
              {holders.length === 0
                ? t('envs.files.bind.noProjects', { group: env.project })
                : t('envs.files.bind.noFolders', { group: env.project })}
            </p>
          ) : (
            <>
              <Select
                label={t('envs.files.bind.folder')}
                hint={t('envs.files.bind.folderHint', { group: env.project })}
                value={chosenFolder}
                onValueChange={setFolder}
                mono
                options={folders.map((item) => ({
                  value: item.folder,
                  label: item.folder,
                  hint: item.project,
                }))}
              />
              <div className="flex flex-col gap-2">
                <TextField
                  label={t('envs.files.bind.file')}
                  value={path}
                  mono
                  autoFocus
                  spellCheck={false}
                  autoCapitalize="off"
                  autoCorrect="off"
                  onChange={(event) => setPath(event.target.value)}
                  hint={touched && problem ? undefined : t('envs.files.bind.fileHint')}
                  error={touched && problem ? problem : undefined}
                />
                <fieldset className="flex flex-wrap items-center gap-1.5">
                  <legend className="sr-only">{t('envs.files.bind.quick')}</legend>
                  {QUICK_NAMES.map((name) => (
                    <button
                      key={name}
                      type="button"
                      aria-pressed={trimmed === name}
                      disabled={taken(name)}
                      onClick={() => setPath(name)}
                      className={cn(
                        'pressable inline-flex h-[26px] items-center rounded-md border px-2 font-mono text-[11.5px] disabled:opacity-40',
                        trimmed === name
                          ? 'border-[rgb(var(--accent-rgb)/0.45)] bg-[rgb(var(--accent-rgb)/0.14)] text-[var(--accent-text)]'
                          : 'border-white/10 bg-white/[0.04] text-fg-2 hover:bg-white/[0.08]',
                      )}
                    >
                      {name}
                    </button>
                  ))}
                </fieldset>
              </div>
              {trimmed && !problem ? (
                <p className="selectable text-[12px] break-all text-subtle">
                  {t('envs.files.bind.preview', {
                    path: bindingPath({ folder: chosenFolder, path: trimmed }),
                  })}
                </p>
              ) : null}
            </>
          )}
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={() => onDone()}>
            {t('common.cancel')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            size="lg"
            loading={bind.isPending}
            disabled={folders.length === 0}
          >
            {t('envs.files.bind.submit')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
