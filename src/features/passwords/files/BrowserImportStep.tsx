import { useMutation } from '@tanstack/react-query';
import { ArrowLeft, FileSpreadsheet, KeyRound, Lock, ShieldCheck } from 'lucide-react';
import { useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { toastError } from '@/api/useAppMutation';
import type { BrowserProfile } from '@/bindings/BrowserProfile';
import type { ImportPreview } from '@/bindings/ImportPreview';
import { Button } from '@/components/ui/Button';
import { ChoiceCards } from '@/components/ui/ChoiceCards';
import { DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { AppError } from '@/lib/ipc';
import { type Platform, platform } from '@/lib/platform';
import { Callout } from './Callout';
import type { ImportSource } from './importSources';

/** Why a browser can't be read directly, so the CSV guide says so. */
export type BrowserFallback = 'appBound' | 'keyUnavailable' | 'unsupported';

/** Logins read from a browser profile, as the preview shows them. */
export interface BrowserRead {
  profile: BrowserProfile;
  preview: ImportPreview;
  unreadable: number;
  appBound: number;
}

interface BrowserImportStepProps {
  source: ImportSource;
  /** The browser's profiles with saved logins; at least one. */
  profiles: BrowserProfile[];
  locked: boolean;
  onRead: (read: BrowserRead) => void;
  /** Reading isn't possible: show the CSV guide, saying why when there is a reason. */
  onCsv: (reason?: BrowserFallback) => void;
  onBack: () => void;
}

/** What the system asks before the app may read the browser's logins. */
function permissionKey(
  source: ImportSource,
  os: Platform,
  needsPrimary: boolean,
): Platform | 'firefox' | 'firefoxLocked' {
  if (source.id === 'firefox') return needsPrimary ? 'firefoxLocked' : 'firefox';
  return os;
}

/**
 * Reads a browser's saved logins straight from its profile: says what the
 * system will ask first (the Keychain prompt on macOS, a keyring on Linux,
 * the Firefox primary password), lets the user pick a profile, and asks for
 * the primary password when the profile has one.
 */
export function BrowserImportStep({
  source,
  profiles,
  locked,
  onRead,
  onCsv,
  onBack,
}: BrowserImportStepProps) {
  const { t } = useTranslation();
  const id = useId();
  const name = source.name ?? '';
  const [profileId, setProfileId] = useState(profiles[0]?.id ?? '');
  const [primary, setPrimary] = useState('');
  const [needsPrimary, setNeedsPrimary] = useState(false);
  const [primaryError, setPrimaryError] = useState<string>();
  const [error, setError] = useState<string | null>(null);
  const primaryField = useRef<HTMLInputElement>(null);

  const read = useMutation({
    mutationFn: () => api.vaultBrowserImportPreview(profileId, needsPrimary ? primary : null),
    onSuccess: (result) => {
      switch (result.kind) {
        case 'preview':
          onRead(result);
          return;
        case 'denied':
          setError(t('vaultFiles.import.browser.denied', { name }));
          return;
        case 'primaryPasswordRequired':
          setNeedsPrimary(true);
          setError(null);
          requestAnimationFrame(() => primaryField.current?.focus());
          return;
        case 'wrongPrimaryPassword':
          setPrimaryError(t('vaultFiles.import.browser.wrongPrimary'));
          primaryField.current?.select();
          return;
        default:
          onCsv(result.kind);
      }
    },
    onError: (cause) => {
      const appError = AppError.from(cause);
      if (appError.code === 'vault_locked') setError(t('vaultFiles.import.unlockFirst'));
      else toastError(t, appError);
    },
  });

  const submit = () => {
    setError(null);
    setPrimaryError(undefined);
    read.mutate();
  };
  const permission = permissionKey(source, platform, needsPrimary);
  const ready = !locked && profileId !== '' && (!needsPrimary || primary !== '');

  return (
    <form
      className="flex min-h-0 flex-col"
      onSubmit={(event) => {
        event.preventDefault();
        if (ready && !read.isPending) submit();
      }}
    >
      <DialogBody>
        <div className="flex items-center gap-3">
          <Tile tone={source.tone} size={36}>
            <source.icon className="size-[18px]" strokeWidth={2} />
          </Tile>
          <div className="flex min-w-0 flex-col">
            <h3 className="text-[14px] font-semibold">
              {t('vaultFiles.import.browser.title', { name })}
            </h3>
            <p className="text-[12.5px] text-muted">{t('vaultFiles.import.browser.lead')}</p>
          </div>
        </div>

        {profiles.length > 1 ? (
          <ChoiceCards
            legend={t('vaultFiles.import.browser.profile')}
            value={profileId}
            onValueChange={(value) => {
              setProfileId(value);
              setNeedsPrimary(false);
              setPrimary('');
              setPrimaryError(undefined);
              setError(null);
            }}
            options={profiles.map((profile) => ({ value: profile.id, title: profile.name }))}
            columns={2}
          />
        ) : null}

        <Callout
          id={`${id}-permission`}
          tone="info"
          icon={ShieldCheck}
          title={t(`vaultFiles.import.browser.permissionTitle.${permission}`, { name })}
        >
          {t(`vaultFiles.import.browser.permission.${permission}`, { name })}
        </Callout>

        {needsPrimary ? (
          <TextField
            ref={primaryField}
            label={t('vaultFiles.import.browser.primary')}
            type="password"
            autoComplete="off"
            value={primary}
            onChange={(event) => {
              setPrimary(event.target.value);
              setPrimaryError(undefined);
            }}
            hint={t('vaultFiles.import.browser.primaryHint', { name })}
            error={primaryError}
          />
        ) : null}

        {locked ? (
          <Callout tone="info" icon={Lock}>
            {t('vaultFiles.import.unlockFirst')}
          </Callout>
        ) : null}
        {error ? (
          <p role="alert" className="text-[12.5px] text-critical">
            {error}
          </p>
        ) : null}
      </DialogBody>
      <DialogFooter>
        <Button
          variant="ghost"
          size="lg"
          className="mr-auto"
          icon={<ArrowLeft className="size-4" strokeWidth={2} />}
          onClick={onBack}
        >
          {t('vaultFiles.import.back')}
        </Button>
        <Button
          size="lg"
          icon={<FileSpreadsheet className="size-4" strokeWidth={2} />}
          onClick={() => onCsv()}
        >
          {t('vaultFiles.import.browser.useCsv')}
        </Button>
        <Button
          type="submit"
          variant="primary"
          size="lg"
          autoFocus
          aria-describedby={`${id}-permission`}
          loading={read.isPending}
          disabled={!ready}
          icon={<KeyRound className="size-4" strokeWidth={2} />}
        >
          {read.isPending
            ? t('vaultFiles.import.browser.reading', { name })
            : t('vaultFiles.import.browser.submit', { name })}
        </Button>
      </DialogFooter>
    </form>
  );
}
