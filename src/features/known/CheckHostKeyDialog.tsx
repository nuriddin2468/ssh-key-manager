import { AlertOctagon, CheckCircle2, HelpCircle, ShieldQuestion, XCircle } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import type { HostKeyCheck } from '@/bindings/HostKeyCheck';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';

interface CheckHostKeyDialogProps {
  initialHost: string;
  onRemove: (lines: number[]) => void;
  onDone: () => void;
}

const RESULT = {
  match: {
    Icon: CheckCircle2,
    box: 'border-ok/30 bg-ok/[0.08]',
    icon: 'text-ok',
    text: 'known.checkMatch',
  },
  changed: {
    Icon: AlertOctagon,
    box: 'border-critical-solid/30 bg-critical-solid/10',
    icon: 'text-critical',
    text: 'known.checkChanged',
  },
  unknown: {
    Icon: HelpCircle,
    box: 'border-info-solid/30 bg-info-solid/[0.09]',
    icon: 'text-info',
    text: 'known.checkUnknown',
  },
  failed: {
    Icon: XCircle,
    box: 'border-warning-solid/30 bg-warning-solid/[0.09]',
    icon: 'text-warning',
    text: 'known.checkFailed',
  },
} as const;

/** Compares the key a server offers now with the saved one (`ssh-keyscan`). */
export function CheckHostKeyDialog({ initialHost, onRemove, onDone }: CheckHostKeyDialogProps) {
  const { t } = useTranslation();
  const [host, setHost] = useState(initialHost);
  const [port, setPort] = useState('');
  const [result, setResult] = useState<HostKeyCheck | null>(null);
  const check = useAppMutation(
    (vars: { host: string; port: number | null }) => api.checkHostKey(vars.host, vars.port),
    { onSuccess: setResult },
  );

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!host.trim() || check.isPending) return;
    setResult(null);
    check.mutate({ host: host.trim(), port: port ? Number(port) : null });
  };
  const view = result ? RESULT[result.status] : null;

  return (
    <DialogContent section="known" className="max-w-[540px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="amber" size={44} glow>
              <ShieldQuestion className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={t('known.checkTitle')}
          description={t('known.checkDescription')}
        />
        <DialogBody>
          <div className="grid grid-cols-[minmax(0,1fr)_110px] gap-3">
            <TextField
              label={t('known.checkHost')}
              mono
              value={host}
              onChange={(event) => setHost(event.target.value)}
              placeholder="github.com"
              autoFocus
            />
            <TextField
              label={t('known.checkPort')}
              mono
              inputMode="numeric"
              value={port}
              onChange={(event) => setPort(event.target.value.replace(/\D/g, ''))}
              placeholder="22"
            />
          </div>
          {result && view ? (
            <div
              role="status"
              className={cn('flex flex-col gap-2.5 rounded-xl border px-3.5 py-3', view.box)}
            >
              <span className="flex items-center gap-2 font-medium">
                <view.Icon aria-hidden="true" className={cn('size-4', view.icon)} strokeWidth={2} />
                {t(view.text, { reason: result.error ?? '' })}
              </span>
              {result.offered.length > 0 ? (
                <ul className="selectable flex flex-col gap-1 font-mono text-[11.5px] text-fg-2">
                  {result.offered.map((key) => (
                    <li key={key.fingerprint} className="truncate">
                      {key.keyType} {key.fingerprint}
                    </li>
                  ))}
                </ul>
              ) : null}
              {result.status === 'changed' ? (
                <Button
                  variant="danger"
                  className="field self-start border-critical-solid/40"
                  onClick={() => {
                    onRemove(result.saved.map((entry) => entry.line));
                    onDone();
                  }}
                >
                  {t('known.removeOld')}
                </Button>
              ) : null}
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
            loading={check.isPending}
            disabled={!host.trim()}
          >
            {t('known.check')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
