import { Database, FileDown, FileSpreadsheet, Lock, ShieldAlert } from 'lucide-react';
import { type FormEvent, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import type { Exported } from '@/bindings/Exported';
import { Button } from '@/components/ui/Button';
import { ChoiceCards } from '@/components/ui/ChoiceCards';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { TextField } from '@/components/ui/TextField';
import { Tile, type Tone } from '@/components/ui/Tile';
import { Callout } from './Callout';
import { showFileError } from './errors';
import { baseName } from './pickers';

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
 * Exports the unlocked vault as an encrypted copy of its KeePass file, or —
 * after a clear warning — as a plain-text CSV file. Both need the master
 * password; the backend then asks where to save in a system dialog, so the
 * page never names the file that is written.
 */
export function ExportDialog({ onDone }: ExportDialogProps) {
  const { t } = useTranslation();
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  const [format, setFormat] = useState<Format>('kdbx');
  const [master, setMaster] = useState('');
  const [masterError, setMasterError] = useState<string | undefined>();
  const masterField = useRef<HTMLInputElement>(null);
  const csv = format === 'csv';

  const exportVault = useAppMutation(
    (vars: { format: Format; master: string }) =>
      vars.format === 'csv' ? api.vaultExportCsv(vars.master) : api.vaultExportKdbx(vars.master),
    {
      success: (result: Exported | null, vars) => {
        if (!result) return undefined;
        const file = baseName(result.path);
        return vars.format === 'csv'
          ? t('vaultFiles.export.exportedCsv', { count: result.count, file })
          : t('vaultFiles.export.exportedKdbx', { file });
      },
      onSuccess: (result) => {
        if (result) onDone();
      },
      onError: (error) => {
        if (error.code === 'cancelled') return true;
        if (error.code === 'wrong_passphrase') {
          setMasterError(t('vaultFiles.export.wrongMaster'));
          masterField.current?.focus();
          masterField.current?.select();
          return true;
        }
        return showFileError(t, error, {
          invalid_input: t('vaultFiles.export.badTarget'),
          vault_locked: t('vaultFiles.export.unlockFirst'),
        });
      },
    },
  );
  const ready = unlocked && master !== '';

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (exportVault.isPending || !ready) return;
    exportVault.mutate({ format, master });
  };

  return (
    <DialogContent section="passwords" className="max-w-[560px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
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
            options={FORMATS.map((option) => ({
              value: option.id,
              tone: option.tone,
              icon: option.Icon,
              disabled: !unlocked,
              title: (
                <>
                  {t(`vaultFiles.export.${option.id}`)}
                  <span className="ml-1.5 font-mono text-[11.5px] font-normal text-subtle">
                    .{option.id}
                  </span>
                </>
              ),
              hint: t(`vaultFiles.export.${option.id}Hint`),
            }))}
          />

          {unlocked ? null : (
            <Callout tone="info" icon={Lock}>
              {t('vaultFiles.export.unlockFirst')}
            </Callout>
          )}
          {csv ? (
            <Callout
              tone="critical"
              icon={ShieldAlert}
              title={t('vaultFiles.export.csvWarningTitle')}
            >
              {t('vaultFiles.export.csvWarning')}
            </Callout>
          ) : null}
          <TextField
            ref={masterField}
            label={t('vaultFiles.export.master')}
            type="password"
            autoComplete="current-password"
            value={master}
            disabled={!unlocked}
            onChange={(event) => {
              setMaster(event.target.value);
              setMasterError(undefined);
            }}
            hint={csv ? t('vaultFiles.export.masterHint') : t('vaultFiles.export.masterHintKdbx')}
            error={masterError}
          />
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            size="lg"
            loading={exportVault.isPending}
            disabled={!ready}
            icon={<FileDown className="size-4" strokeWidth={2} />}
          >
            {t('vaultFiles.export.submit')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
