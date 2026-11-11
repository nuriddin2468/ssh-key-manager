import { CloudUpload, FilePlus2, GitBranch, HelpCircle, TriangleAlert } from 'lucide-react';
import { type FormEvent, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import type { EnvFile } from '@/bindings/EnvFile';
import type { EnvFileCheck } from '@/bindings/EnvFileCheck';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Select } from '@/components/ui/Select';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { Callout } from '@/features/passwords/files/Callout';
import { useVaultMutation } from '@/features/passwords/vault';
import { useProjects } from '@/features/projects/queries';
import { cn } from '@/lib/cn';
import { conflictToastId, markConflictTold } from './announce';
import { bindRefusal } from './errors';
import { bindingPath, cloudName, fileName, isTemplateName, QUICK_NAMES } from './model';
import { refreshFileReports } from './queries';

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
 * Git or a cloud service would take the file's values along, or Git can't
 * be asked because the project's folder isn't on this computer.
 */
const risky = (check: EnvFileCheck) =>
  check.git === null ||
  check.git.state === 'untracked' ||
  check.git.state === 'tracked' ||
  check.cloud !== null;

/**
 * Writes an environment to a file in a folder of the project that has it:
 * the folder comes from the project, the path in it is typed. The
 * backend checks the path first; where Git wouldn't ignore the file or a
 * cloud service copies its folder, the user says so before anything is
 * written, as an export asks. The backend checks the path again on binding
 * and refuses links, templates and anything outside the folder.
 */
export function BindFileDialog({ env, bound, onDone }: BindFileDialogProps) {
  const { t } = useTranslation();
  const projects = useProjects();
  const holder = (projects.data ?? []).find((project) => project.id === env.project);
  const folders = useMemo(
    () => (holder?.folders ?? []).map((folder) => ({ folder, project: holder?.name ?? '' })),
    [holder],
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
  const [refusal, setRefusal] = useState<string | null>(null);
  const [risk, setRisk] = useState<EnvFileCheck | null>(null);
  const trimmed = path.trim().replace(/^[/\\]+/, '');
  const problem = !trimmed
    ? t('envs.files.errors.notEnvName')
    : isTemplateName(trimmed)
      ? t('envs.files.errors.template')
      : !LOOKS_LIKE_ENV.test(trimmed) || /(^|[/\\])\.\.?([/\\]|$)/.test(trimmed)
        ? t('envs.files.errors.notEnvName')
        : taken(trimmed)
          ? t('envs.files.bind.taken')
          : null;
  const refused = (error: unknown) => {
    const message = bindRefusal(t, error);
    if (!message) return false;
    setRisk(null);
    setRefusal(message);
    return true;
  };

  const bind = useVaultMutation(
    async ({ file, ignore }: { file: EnvFile; ignore: boolean }) => {
      const status = await api.envsFilesBind(env.id, file);
      // Bound either way: a `.gitignore` that couldn't be changed is told apart.
      let ignoreError: unknown = null;
      if (ignore) {
        try {
          await api.envsFilesIgnore(env.id, status.file);
        } catch (error) {
          ignoreError = error;
        }
      }
      return { status, ignoreError };
    },
    {
      onSuccess: ({ status, ignoreError }) => {
        void refreshFileReports();
        const file = fileName(status.file);
        // Bound, but Git would take it along: said as such, not as the error itself.
        if (ignoreError) toast.warning(t('envs.files.bind.notIgnored', { file }));
        if (status.state.type === 'conflict') {
          // One toast for this conflict, however the app hears of it.
          markConflictTold(env.id, status.file);
          toast.warning(t('envs.files.bind.differs', { file }), {
            id: conflictToastId(env.id, status.file),
          });
          onDone(status.file);
          return;
        }
        if (!ignoreError) {
          toast.success(
            status.state.type === 'folderMissing'
              ? t('envs.files.bind.later', { file })
              : t('envs.files.bind.done', { file }),
          );
        }
        onDone();
      },
      onError: refused,
    },
  );
  const check = useVaultMutation((file: EnvFile) => api.envsFilesCheck(env.id, file), {
    onSuccess: (result) => {
      if (risky(result)) setRisk(result);
      else bind.mutate({ file: result.file, ignore: false });
    },
    onError: refused,
  });
  const busy = check.isPending || bind.isPending;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    setRefusal(null);
    if (problem || !chosenFolder || busy) return;
    check.mutate({ folder: chosenFolder, path: trimmed });
  };

  if (risk) {
    const repository = risk.git?.repository ?? '';
    return (
      <DialogContent section="envs" className="max-w-[560px]">
        <DialogHeader
          icon={
            <Tile tone="amber" size={44} glow>
              <TriangleAlert className="size-[22px]" strokeWidth={2} />
            </Tile>
          }
          title={t('envs.files.risk.title', { file: fileName(risk.file) })}
          description={t('envs.files.risk.description')}
        />
        <DialogBody>
          <p className="selectable truncate font-mono text-[12px] text-subtle">
            {risk.location ?? bindingPath(risk.file)}
          </p>
          {risk.location && !risk.folderHere ? (
            <p className="text-[12.5px] text-muted">{t('envs.files.risk.notYet')}</p>
          ) : null}
          {risk.git?.state === 'untracked' ? (
            <Callout tone="warning" icon={GitBranch} title={t('envs.center.gitUntracked')}>
              {t('envs.files.risk.gitUntracked', { repository })}
            </Callout>
          ) : null}
          {risk.git?.state === 'tracked' ? (
            <Callout tone="critical" icon={GitBranch} title={t('envs.center.gitTracked')}>
              {t('envs.files.risk.gitTracked', { repository })}
            </Callout>
          ) : null}
          {risk.git === null ? (
            <Callout tone="info" icon={HelpCircle} title={t('envs.files.risk.gitUnknownTitle')}>
              {t('envs.files.risk.gitUnknown')}
            </Callout>
          ) : null}
          {risk.cloud ? (
            <Callout tone="warning" icon={CloudUpload} title={t('envs.center.cloud')}>
              {risk.cloud === 'other'
                ? t('envs.files.risk.cloudOther')
                : t('envs.files.risk.cloud', { service: cloudName(t, risk.cloud) })}
            </Callout>
          ) : null}
        </DialogBody>
        <DialogFooter>
          <Button size="lg" variant="ghost" disabled={busy} onClick={() => setRisk(null)}>
            {t('envs.files.risk.back')}
          </Button>
          <Button
            size="lg"
            variant={risk.git?.state === 'untracked' ? 'secondary' : 'primary'}
            loading={bind.isPending && !bind.variables?.ignore}
            disabled={busy}
            onClick={() => bind.mutate({ file: risk.file, ignore: false })}
          >
            {risk.folderHere ? t('envs.files.risk.writeAnyway') : t('envs.files.bind.submit')}
          </Button>
          {risk.git?.state === 'untracked' ? (
            <Button
              size="lg"
              variant="primary"
              autoFocus
              loading={bind.isPending && bind.variables?.ignore === true}
              disabled={busy}
              onClick={() => bind.mutate({ file: risk.file, ignore: true })}
            >
              {t('envs.files.risk.ignoreAndWrite')}
            </Button>
          ) : null}
        </DialogFooter>
      </DialogContent>
    );
  }

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
              {holder
                ? t('envs.files.bind.noFolders', { project: holder.name })
                : t('envs.files.bind.noProjects')}
            </p>
          ) : (
            <>
              <Select
                label={t('envs.files.bind.folder')}
                hint={t('envs.files.bind.folderHint', { project: holder?.name ?? '' })}
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
                  onChange={(event) => {
                    setPath(event.target.value);
                    setRefusal(null);
                  }}
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
                      onClick={() => {
                        setPath(name);
                        setRefusal(null);
                      }}
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
              {refusal ? (
                <p role="alert" className="text-[12.5px] text-critical">
                  {refusal}
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
            loading={busy}
            disabled={folders.length === 0}
          >
            {t('envs.files.bind.submit')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
