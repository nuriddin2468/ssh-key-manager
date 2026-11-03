import { Database, FileDown, FileSpreadsheet, ShieldAlert } from 'lucide-react';
import { type FormEvent, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import { Button } from '@/components/ui/Button';
import { ChoiceCards } from '@/components/ui/ChoiceCards';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { TextField } from '@/components/ui/TextField';
import { Tile, type Tone } from '@/components/ui/Tile';
import { Callout } from './Callout';
import { showFileError } from './errors';
import { baseName, pickSaveTarget, today } from './pickers';

export interface ExportDialogProps {
  /** Closes the dialog. Render it inside `<Dialog>`, like the app's other dialogs. */
  onDone: () => void;
}

type Format = 'kdbx' | 'csv';

const FORMATS: { id: Format; tone: Tone; Icon: typeof Database }[] = [
  { id: 'kdbx', tone: 'teal', Icon: Database },
  { id: 'csv', tone: 'amber', Icon: FileSpreadsheet },
];

/**
 * Exports the vault as an encrypted copy of its KeePass file, or — after
 * the master password and a clear warning — as a plain-text CSV file.
 */
export function ExportDialog({ onDone }: ExportDialogProps) {
  const { t } = useTranslation();
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  const [format, setFormat] = useState<Format>('kdbx');
  const [master, setMaster] = useState('');
  const [masterError, setMasterError] = useState<string | undefined>();
  const masterField = useRef<HTMLInputElement>(null);
  const csv = format === 'csv';

  const badTarget = t('vaultFiles.export.badTarget');
  const exportCsv = useAppMutation(
    (vars: { path: string; master: string }) => api.vaultExportCsv(vars.path, vars.master),
    {
      success: (count, vars) =>
        t('vaultFiles.export.exportedCsv', { count, file: baseName(vars.path) }),
      onSuccess: onDone,
      onError: (error) => {
        if (error.code === 'wrong_passphrase') {
          setMasterError(t('vaultFiles.export.wrongMaster'));
          masterField.current?.focus();
          masterField.current?.select();
          return true;
        }
        return showFileError(t, error, {
          invalid_input: badTarget,
          vault_locked: t('vaultFiles.export.unlockFirst'),
        });
      },
    },
  );
  const exportKdbx = useAppMutation((path: string) => api.vaultExportKdbx(path), {
    success: (_, path) => t('vaultFiles.export.exportedKdbx', { file: baseName(path) }),
    onSuccess: onDone,
    onError: (error) => showFileError(t, error, { invalid_input: badTarget }),
  });
  const busy = exportCsv.isPending || exportKdbx.isPending;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy || (csv && (!unlocked || master === ''))) return;
    try {
      const path = await pickSaveTarget(
        t('vaultFiles.export.saveTitle'),
        csv ? `passwords-${today()}.csv` : `vault-${today()}.kdbx`,
        csv
          ? { name: t('vaultFiles.export.csvFiles'), extensions: ['csv'] }
          : { name: t('vaultFiles.export.keepassFiles'), extensions: ['kdbx'] },
      );
      if (!path) return;
      if (csv) exportCsv.mutate({ path, master });
      else exportKdbx.mutate(path);
    } catch (error) {
      toastError(t, error);
    }
  };

  return (
    <DialogContent section="passwords" className="max-w-[560px]">
      <form onSubmit={(event) => void submit(event)} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="pink" size={44} glow>
              <FileDown className="size-[22px]" strokeWidth={2} />
            </Tile>
          }
          title={t('vaultFiles.export.title')}
          description={t('vaultFiles.export.description')}
        />
        <DialogBody>
          <ChoiceCards
            legend={t('vaultFiles.export.format')}
            value={format}
            onValueChange={(value) => {
              setFormat(value);
              setMasterError(undefined);
            }}
            layout="stack"
            options={FORMATS.map((option) => {
              const disabled = option.id === 'csv' && !unlocked;
              return {
                value: option.id,
                tone: option.tone,
                icon: option.Icon,
                disabled,
                title: (
                  <>
                    {t(`vaultFiles.export.${option.id}`)}
                    <span className="ml-1.5 font-mono text-[11.5px] font-normal text-subtle">
                      .{option.id}
                    </span>
                  </>
                ),
                hint: disabled
                  ? t('vaultFiles.export.unlockFirst')
                  : t(`vaultFiles.export.${option.id}Hint`),
              };
            })}
          />

          {csv ? (
            <>
              <Callout
                tone="critical"
                icon={ShieldAlert}
                title={t('vaultFiles.export.csvWarningTitle')}
              >
                {t('vaultFiles.export.csvWarning')}
              </Callout>
              <TextField
                ref={masterField}
                label={t('vaultFiles.export.master')}
                type="password"
                autoComplete="current-password"
                value={master}
                onChange={(event) => {
                  setMaster(event.target.value);
                  setMasterError(undefined);
                }}
                hint={t('vaultFiles.export.masterHint')}
                error={masterError}
              />
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
            loading={busy}
            disabled={csv && (!unlocked || master === '')}
            icon={<FileDown className="size-4" strokeWidth={2} />}
          >
            {t('vaultFiles.export.submit')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
