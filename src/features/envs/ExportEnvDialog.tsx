import {
  Braces,
  Container,
  FileCode2,
  FileDown,
  FileText,
  GitBranch,
  ShieldAlert,
  Ship,
  SquareTerminal,
} from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useEnvironment } from '@/api/queries';
import type { EnvExport } from '@/bindings/EnvExport';
import type { EnvFormat } from '@/bindings/EnvFormat';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { Button } from '@/components/ui/Button';
import { ChoiceCards, type ChoiceIcon } from '@/components/ui/ChoiceCards';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Tile, type Tone } from '@/components/ui/Tile';
import { Callout } from '@/features/passwords/files/Callout';
import { showFileError } from '@/features/passwords/files/errors';
import { baseName } from '@/features/passwords/files/pickers';
import { useVaultMutation } from '@/features/passwords/vault';
import { displayPath } from '@/lib/format';
import { useEnvLabel } from './useProjectNames';

const FORMATS: { id: EnvFormat; ext: string; tone: Tone; icon: ChoiceIcon }[] = [
  { id: 'dotenv', ext: '.env', tone: 'lime', icon: FileCode2 },
  { id: 'json', ext: '.json', tone: 'amber', icon: Braces },
  { id: 'yaml', ext: '.yaml', tone: 'indigo', icon: FileText },
  { id: 'shell', ext: '.sh', tone: 'green', icon: SquareTerminal },
  { id: 'docker', ext: '--env-file', tone: 'blue', icon: Container },
  { id: 'kubernetes', ext: 'Secret', tone: 'cyan', icon: Ship },
];

interface ExportEnvDialogProps {
  env: EnvSummary;
  onDone: () => void;
}

/**
 * Writes an environment to a file in one of six formats. The backend asks
 * where in a save dialog; a file a Git working tree doesn't ignore waits
 * for a second yes here.
 */
export function ExportEnvDialog({ env, onDone }: ExportEnvDialogProps) {
  const { t } = useTranslation();
  const envLabelOf = useEnvLabel();
  const [format, setFormat] = useState<EnvFormat>('dotenv');
  const [waiting, setWaiting] = useState<EnvExport | null>(null);
  const home = useEnvironment().data?.paths.home;

  const written = (result: EnvExport | null) =>
    result?.written
      ? t('envs.export.done', { count: result.count, file: baseName(result.path) })
      : undefined;
  const onError = (error: Parameters<typeof showFileError>[1]) =>
    showFileError(t, error, {
      invalid_input: error.message.includes('line break')
        ? t('envs.export.dockerLineBreak')
        : t('envs.export.badTarget'),
      unsupported: t('vaultFiles.export.privateDriveOnly'),
    });

  const save = useVaultMutation(() => api.envsExport(env.id, format), {
    success: written,
    onSuccess: (result) => {
      if (!result) return;
      if (result.written) onDone();
      else setWaiting(result);
    },
    onError,
  });
  const anyway = useVaultMutation(api.envsExportAnyway, {
    success: written,
    onSuccess: onDone,
    onError,
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!save.isPending) save.mutate(undefined);
  };

  return (
    <DialogContent section="envs" className="max-w-[600px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="lime" size={44} glow>
              <FileDown className="size-[22px]" strokeWidth={2} />
            </Tile>
          }
          title={t('envs.export.title', { name: envLabelOf(env) })}
          description={t('envs.export.description')}
        />
        <DialogBody>
          {waiting?.repository ? (
            <div role="alert">
              <Callout tone="critical" icon={GitBranch} title={t('envs.export.gitTitle')}>
                <p>
                  {t('envs.export.gitText', {
                    file: baseName(waiting.path),
                    repository: displayPath(waiting.repository, home),
                  })}
                </p>
              </Callout>
            </div>
          ) : (
            <>
              <ChoiceCards
                legend={t('envs.export.format')}
                value={format}
                onValueChange={setFormat}
                columns={2}
                options={FORMATS.map((option) => ({
                  value: option.id,
                  tone: option.tone,
                  icon: option.icon,
                  title: (
                    <>
                      {t(`envs.export.formats.${option.id}`)}
                      <span className="ml-1.5 font-mono text-[11.5px] font-normal text-subtle">
                        {option.ext}
                      </span>
                    </>
                  ),
                  hint: t(`envs.export.hints.${option.id}`),
                }))}
              />
              <Callout tone="warning" icon={ShieldAlert} title={t('envs.export.plaintextTitle')}>
                {t('envs.export.plaintext')}
              </Callout>
            </>
          )}
        </DialogBody>
        <DialogFooter>
          {waiting ? (
            <>
              <Button size="lg" className="mr-auto" onClick={onDone}>
                {t('common.cancel')}
              </Button>
              {/* The safe way on, focused: "Save…" is gone with the step. */}
              <Button size="lg" autoFocus onClick={() => setWaiting(null)}>
                {t('envs.export.elsewhere')}
              </Button>
              <Button
                variant="danger"
                size="lg"
                className="field border-critical-solid/40"
                loading={anyway.isPending}
                onClick={() => anyway.mutate(undefined)}
              >
                {t('envs.export.anyway')}
              </Button>
            </>
          ) : (
            <>
              <Button size="lg" onClick={onDone}>
                {t('common.cancel')}
              </Button>
              <Button
                type="submit"
                variant="primary"
                size="lg"
                loading={save.isPending}
                icon={<FileDown className="size-4" strokeWidth={2} />}
              >
                {t('envs.export.submit')}
              </Button>
            </>
          )}
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
