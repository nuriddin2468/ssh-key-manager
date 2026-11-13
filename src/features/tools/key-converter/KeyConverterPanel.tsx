import { useQuery } from '@tanstack/react-query';
import { Copy, FileKey2, FolderOpen, KeyRound, LockKeyhole, Save } from 'lucide-react';
import { type FormEvent, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useKeys } from '@/api/queries';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import type { KeyFileFormat } from '@/bindings/KeyFileFormat';
import type { KeyFileInfo } from '@/bindings/KeyFileInfo';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { ChoiceCards } from '@/components/ui/ChoiceCards';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import { PassphraseFields } from '@/components/ui/PassphraseFields';
import { Select } from '@/components/ui/Select';
import { Spinner } from '@/components/ui/Spinner';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { copyText } from '@/lib/clipboard';
import { AppError } from '@/lib/ipc';
import { Section } from '../ssh/parts';
import { algorithmText, FORMATS, fileNameProblem, pemAllowed, uniqueName } from './model';

/** Opened with the passphrase that opened it. */
interface Opened {
  info: KeyFileInfo;
  passphrase: string | null;
}

/**
 * The key converter: a key file in any format the app reads, its
 * fingerprints and randomart, and the same key in another format, added to
 * ~/.ssh or saved where the user picks.
 */
export function KeyConverterPanel() {
  const { t } = useTranslation();
  const keys = useKeys();
  const [path, setPath] = useState<string | null>(null);
  const [opened, setOpened] = useState<Opened | null>(null);
  const privateKeys = (keys.data?.keys ?? []).filter((key) => key.privatePath);

  const inspect = useQuery({
    queryKey: ['key-convert', path],
    queryFn: () => api.keyConvertInspect(path ?? '', null),
    enabled: path !== null,
    gcTime: 0,
  });
  const choose = (next: string) => {
    setPath(next);
    setOpened(null);
  };
  // The backend opens the file dialog and reads only the file picked there
  // (or a key in ~/.ssh).
  const pick = async () => {
    try {
      const file = await api.keyConvertPick();
      if (file !== null) choose(file);
    } catch (error) {
      toastError(t, error);
    }
  };
  const info = opened?.info ?? inspect.data ?? null;
  const ready = info !== null && (!info.encrypted || info.opened);

  return (
    <div className="flex flex-col gap-3.5">
      <p className="text-[12.5px] text-muted">{t('toolSsh.convert.description')}</p>
      <Section title={t('toolSsh.convert.source')}>
        <div className="flex flex-wrap items-end gap-3">
          <Button
            icon={<FolderOpen className="size-4" strokeWidth={2} />}
            onClick={() => void pick()}
          >
            {t('toolSsh.convert.chooseFile')}
          </Button>
          <Select
            label={t('toolSsh.convert.fromSsh')}
            value={privateKeys.some((key) => key.privatePath === path) ? (path ?? '') : ''}
            onValueChange={choose}
            options={privateKeys.map((key) => ({
              value: key.privatePath ?? '',
              label: key.name,
              hint: key.keyType,
            }))}
            placeholder={t('toolSsh.convert.fromSshPlaceholder')}
            mono
            className="min-w-[240px] flex-1"
          />
        </div>
        {path ? (
          <p className="truncate font-mono text-[12px] text-subtle" title={path}>
            {path}
          </p>
        ) : null}
      </Section>

      {path === null ? (
        <EmptyState
          icon={
            <Tile tone="teal" size={40} glow>
              <FileKey2 className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={t('toolSsh.convert.emptyTitle')}
          description={t('toolSsh.convert.emptyBody')}
        />
      ) : inspect.isPending ? (
        <div className="grid place-items-center py-8">
          <Spinner className="size-5 text-subtle" />
        </div>
      ) : inspect.isError ? (
        <p role="alert" className="text-[12.5px] text-critical">
          {t(`errors.${AppError.from(inspect.error).code}`, { defaultValue: t('errors.unknown') })}
        </p>
      ) : info ? (
        <>
          <KeyDetails info={info} />
          {info.encrypted && !info.opened ? <Unlock path={path} onOpened={setOpened} /> : null}
          {ready ? (
            <Convert
              key={path}
              path={path}
              info={info}
              passphrase={opened?.passphrase ?? null}
              taken={(keys.data?.keys ?? []).map((key) => key.name)}
            />
          ) : null}
        </>
      ) : null}
    </div>
  );
}

function KeyDetails({ info }: { info: KeyFileInfo }) {
  const { t } = useTranslation();
  const prints = info.fingerprints;
  const copy = (text: string) =>
    copyText(text)
      .then(() => toast.success(t('toolSsh.convert.fingerprintCopied')))
      .catch((error: unknown) => toastError(t, error));
  return (
    <Section
      title={t(`toolSsh.convert.format.${info.format}`)}
      action={
        <div className="flex flex-wrap justify-end gap-1.5">
          {info.algorithm ? <Badge>{algorithmText(info)}</Badge> : null}
          <Badge tone={info.encrypted ? 'accent' : 'warning'}>
            {info.encrypted ? (
              <LockKeyhole aria-hidden="true" className="mr-1 size-3" strokeWidth={2.25} />
            ) : null}
            {info.encrypted ? t('toolSsh.convert.encrypted') : t('toolSsh.convert.notEncrypted')}
          </Badge>
        </div>
      }
    >
      {info.comment ? (
        <p className="text-[12.5px] text-muted">
          {t('toolSsh.convert.comment')}: <span className="text-fg-2">{info.comment}</span>
        </p>
      ) : null}
      {prints ? (
        <div className="grid gap-4 md:grid-cols-[1fr_auto]">
          <dl className="flex min-w-0 flex-col gap-2.5">
            {(
              [
                ['sha256', prints.sha256],
                ['md5', prints.md5],
              ] as const
            ).map(([name, value]) => (
              <div key={name} className="flex min-w-0 flex-col gap-1">
                <dt className="text-[12px] font-semibold text-fg-2">
                  {t(`toolSsh.convert.${name}`)}
                </dt>
                <dd className="flex min-w-0 items-center gap-1.5">
                  <code className="selectable min-w-0 flex-1 rounded-lg border border-ink/[0.07] bg-terminal px-2.5 py-1.5 font-mono text-[12px] break-all">
                    {value}
                  </code>
                  <IconButton
                    label={t('toolSsh.convert.copyFingerprint', {
                      name: t(`toolSsh.convert.${name}`),
                    })}
                    icon={<Copy className="size-3.5" strokeWidth={2} />}
                    onClick={() => void copy(value)}
                  />
                </dd>
              </div>
            ))}
          </dl>
          <figure className="flex flex-col items-start gap-1.5">
            <pre
              role="img"
              aria-label={`${t('toolSsh.convert.randomart')}: ${prints.sha256}`}
              className="rounded-[11px] border border-ink/[0.07] bg-terminal px-3 py-2 font-mono text-[12px] leading-[1.25] text-fg-2"
            >
              {prints.randomart}
            </pre>
            <figcaption className="max-w-[230px] text-[11.5px] leading-4 text-subtle">
              {t('toolSsh.convert.randomartHint')}
            </figcaption>
          </figure>
        </div>
      ) : (
        <p className="text-[12.5px] text-subtle">{t('toolSsh.convert.lockedNoPrint')}</p>
      )}
    </Section>
  );
}

function Unlock({ path, onOpened }: { path: string; onOpened: (opened: Opened) => void }) {
  const { t } = useTranslation();
  const [passphrase, setPassphrase] = useState('');
  const [wrong, setWrong] = useState(false);
  const open = useAppMutation(() => api.keyConvertInspect(path, passphrase), {
    onSuccess: (info) => onOpened({ info, passphrase }),
    onError: (error) => {
      if (error.code !== 'wrong_passphrase') return false;
      setWrong(true);
      return true;
    },
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (passphrase) open.mutate(undefined);
  };
  return (
    <form onSubmit={submit} className="glass flex flex-col gap-3 rounded-2xl p-4">
      <p className="flex items-center gap-2 text-[12.5px] text-fg-2">
        <LockKeyhole aria-hidden="true" className="size-4 text-subtle" strokeWidth={2} />
        {t('toolSsh.convert.locked')}
      </p>
      <div className="flex flex-wrap items-start gap-3">
        <TextField
          label={t('toolSsh.convert.passphrase')}
          type="password"
          value={passphrase}
          onChange={(event) => {
            setPassphrase(event.target.value);
            setWrong(false);
          }}
          error={wrong ? t('errors.wrong_passphrase') : undefined}
          className="min-w-[240px] flex-1"
          autoComplete="off"
        />
        <div className="pt-6">
          <Button
            type="submit"
            variant="primary"
            icon={<KeyRound className="size-4" strokeWidth={2} />}
            loading={open.isPending}
            disabled={!passphrase}
          >
            {t('toolSsh.convert.open')}
          </Button>
        </div>
      </div>
    </form>
  );
}

function Convert({
  path,
  info,
  passphrase,
  taken,
}: {
  path: string;
  info: KeyFileInfo;
  passphrase: string | null;
  taken: string[];
}) {
  const { t } = useTranslation();
  const canPem = pemAllowed(info);
  const [format, setFormat] = useState<KeyFileFormat>(
    info.format === 'openssh' ? 'ppk3' : 'openssh',
  );
  const [fileName, setFileName] = useState(() => uniqueName(info.suggestedName, taken));
  const [comment, setComment] = useState(info.comment);
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const nameProblem = fileNameProblem(fileName, taken);
  const withComment = format === 'openssh' || format === 'ppk3' || format === 'ppk2';
  const withPassphrase = format !== 'pem';
  const mismatch = withPassphrase && next !== repeat;
  const args = useMemo(
    () => ({
      path,
      passphrase,
      newPassphrase: withPassphrase && next ? next : null,
      comment: withComment ? comment : null,
    }),
    [path, passphrase, withPassphrase, next, withComment, comment],
  );
  const add = useAppMutation(() => api.keyConvertImport({ ...args, fileName }), {
    success: (key) => t('toolSsh.convert.imported', { name: key.name }),
    onSuccess: (key) => setFileName(uniqueName(key.name, [...taken, key.name])),
  });
  const save = useAppMutation(() => api.keyConvertSave({ ...args, format }), {
    success: (saved) => (saved ? t('toolSsh.convert.saved', { path: saved }) : undefined),
  });
  const busy = add.isPending || save.isPending;

  return (
    <Section title={t('toolSsh.convert.to')}>
      <ChoiceCards
        legend={t('toolSsh.convert.to')}
        legendHidden
        value={format}
        onValueChange={setFormat}
        options={FORMATS.map((value) => ({
          value,
          title: t(`toolSsh.convert.format.${value}`),
          hint:
            value === 'pem' && !canPem
              ? t('toolSsh.convert.pemNoEd25519')
              : t(`toolSsh.convert.formatHint.${value}`),
          disabled: value === 'pem' && !canPem,
        }))}
        columns={3}
      />
      <div className="grid gap-3 md:grid-cols-2">
        {format === 'openssh' ? (
          <TextField
            label={t('toolSsh.convert.fileName')}
            prefix="~/.ssh/"
            value={fileName}
            onChange={(event) => setFileName(event.target.value)}
            mono
            error={nameProblem ? t(`errors.${nameProblem}`) : undefined}
          />
        ) : null}
        {withComment ? (
          <TextField
            label={t('toolSsh.convert.comment')}
            value={comment}
            onChange={(event) => setComment(event.target.value)}
            maxLength={1024}
          />
        ) : null}
      </div>
      {withPassphrase ? (
        <div className="flex flex-col gap-2">
          <div className="grid gap-3 md:grid-cols-2">
            <PassphraseFields
              value={next}
              repeat={repeat}
              onChange={setNext}
              onRepeatChange={setRepeat}
              label={t('toolSsh.convert.newPassphrase')}
            />
          </div>
          <p className="text-[12px] text-subtle">
            {next
              ? t('toolSsh.convert.newPassphraseHint')
              : t('toolSsh.convert.noPassphraseWarning')}
          </p>
        </div>
      ) : (
        <p className="text-[12.5px] text-warning">{t('toolSsh.convert.pemNoPassphrase')}</p>
      )}
      <div className="flex flex-wrap justify-end gap-2.5">
        {format === 'openssh' ? (
          <>
            <Button
              icon={<Save className="size-4" strokeWidth={2} />}
              onClick={() => save.mutate(undefined)}
              disabled={busy || mismatch}
              loading={save.isPending}
            >
              {t('toolSsh.convert.saveAction')}
            </Button>
            <Button
              variant="primary"
              icon={<KeyRound className="size-4" strokeWidth={2} />}
              onClick={() => add.mutate(undefined)}
              disabled={busy || mismatch || nameProblem !== null}
              loading={add.isPending}
            >
              {t('toolSsh.convert.importAction')}
            </Button>
          </>
        ) : (
          <Button
            variant="primary"
            icon={<Save className="size-4" strokeWidth={2} />}
            onClick={() => save.mutate(undefined)}
            disabled={busy || mismatch}
            loading={save.isPending}
          >
            {t('toolSsh.convert.saveAction')}
          </Button>
        )}
      </div>
    </Section>
  );
}
