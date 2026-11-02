import { useMutation } from '@tanstack/react-query';
import { Signpost } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { toastError } from '@/api/useAppMutation';
import type { HostsFileEntry } from '@/bindings/HostsFileEntry';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Spinner } from '@/components/ui/Spinner';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { isValidName, lookupName } from './model';

interface LookupDialogProps {
  entries: readonly HostsFileEntry[];
  initialName: string;
  onShowLine: (line: number) => void;
  onDone: () => void;
}

/** Shows where a name leads: the hosts file lines for it, then the system's answer. */
export function LookupDialog({ entries, initialName, onShowLine, onDone }: LookupDialogProps) {
  const { t } = useTranslation();
  const [name, setName] = useState(initialName);
  const [asked, setAsked] = useState<string | null>(null);
  // A lookup reads nothing the app caches, so it is not an app mutation.
  const lookup = useMutation({
    mutationFn: api.lookupHost,
    onError: (error) => toastError(t, error),
  });

  const value = name.trim();
  const invalid = value !== '' && !isValidName(value);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!value || invalid || lookup.isPending) return;
    setAsked(value);
    lookup.mutate(value);
  };
  const matches = asked ? lookupName(entries, asked) : [];
  const answer = lookup.data;

  return (
    <DialogContent section="hostsFile" className="max-w-[540px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="indigo" size={44} glow>
              <Signpost className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={t('hostsFile.lookupTitle')}
          description={t('hostsFile.lookupDescription')}
        />
        <DialogBody>
          <TextField
            label={t('hostsFile.lookupName')}
            mono
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="github.com"
            error={invalid ? t('hostsFile.lookupInvalid') : undefined}
            autoFocus
          />
          {asked ? (
            <div role="status" className="flex flex-col gap-3">
              <section className="flex flex-col gap-1.5">
                <h3 className="text-[12px] font-semibold tracking-[0.02em] text-subtle">
                  {t('hostsFile.lookupFromFile')}
                </h3>
                {matches.length === 0 ? (
                  <p className="text-[12.5px] text-muted">
                    {t('hostsFile.lookupNotListed', { name: asked })}
                  </p>
                ) : (
                  <ul className="flex flex-col gap-1">
                    {matches.map(({ entry, used }) => (
                      <li
                        key={entry.line}
                        className="flex items-center gap-2.5 rounded-lg border border-white/[0.08] bg-white/[0.03] px-2.5 py-1.5"
                      >
                        <span className="selectable min-w-0 flex-1 truncate font-mono text-[12.5px]">
                          {entry.address}
                        </span>
                        {used ? (
                          <Badge tone="accent" pill>
                            {t('hostsFile.lookupUsed')}
                          </Badge>
                        ) : (
                          <Badge tone="warning" pill>
                            {t('hostsFile.lookupIgnored')}
                          </Badge>
                        )}
                        <Button size="sm" variant="ghost" onClick={() => onShowLine(entry.line)}>
                          {t('hostsFile.showLine', { line: entry.line })}
                        </Button>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
              <section className="flex flex-col gap-1.5">
                <h3 className="text-[12px] font-semibold tracking-[0.02em] text-subtle">
                  {t('hostsFile.lookupFromSystem')}
                </h3>
                {lookup.isPending ? (
                  <span className="inline-flex items-center gap-2 text-[12.5px] text-muted">
                    <Spinner className="size-3.5" />
                    {t('hostsFile.lookingUp')}
                  </span>
                ) : answer && answer.addresses.length > 0 ? (
                  <ul className="selectable flex flex-col gap-0.5 font-mono text-[12.5px] text-fg-2">
                    {answer.addresses.map((address) => (
                      <li key={address}>{address}</li>
                    ))}
                  </ul>
                ) : answer ? (
                  <p className="flex flex-col gap-1 text-[12.5px] text-warning">
                    {t('hostsFile.lookupNothing')}
                    {answer.error ? (
                      <span className="selectable font-mono text-[11.5px] text-muted">
                        {answer.error}
                      </span>
                    ) : null}
                  </p>
                ) : null}
              </section>
            </div>
          ) : null}
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={onDone}>
            {t('common.close')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            size="lg"
            loading={lookup.isPending}
            disabled={!value || invalid}
          >
            {t('hostsFile.lookUpShort')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
