import { useMutation } from '@tanstack/react-query';
import { isTauri } from '@tauri-apps/api/core';
import { Globe } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { keys, queryClient } from '@/api/queries';
import { toastError } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { PairingRequest } from '@/bindings/PairingRequest';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { Button } from '@/components/ui/Button';
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogHeader,
} from '@/components/ui/Dialog';
import { Tile } from '@/components/ui/Tile';
import { groupCode, useBrowserEvents } from './queries';

/**
 * App-wide: asks the user about a browser that wants to pair, and brings
 * the vault forward when the extension asks to unlock it. Mounted once in
 * the shell.
 */
export function BrowserPairing() {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const [request, setRequest] = useState<PairingRequest | null>(null);
  const current = useRef<PairingRequest | null>(null);
  const answered = useRef<string | null>(null);

  const show = useCallback(
    (next: PairingRequest | null) => {
      const before = current.current;
      if (!next && before && answered.current !== before.id) {
        toast(t('browser.pairExpired'), { id: 'browser-pairing' });
      }
      current.current = next;
      setRequest(next);
    },
    [t],
  );

  // A request may already wait, e.g. after the window reloaded.
  useEffect(() => {
    if (import.meta.env.DEV && !isTauri()) {
      if (new URLSearchParams(window.location.search).get('open') === 'pairing') {
        show({ id: 'dev', browser: 'Google Chrome', code: '624499' });
      }
      return;
    }
    api
      .browserStatus()
      .then((status) => {
        if (status.pairing) show(status.pairing);
      })
      .catch(() => undefined);
  }, [show]);

  const onUnlock = useCallback(() => {
    navigate({ page: 'passwords' });
    const vault = queryClient.getQueryData<VaultStatus>(keys.vaultStatus);
    if (vault?.state !== 'unlocked') toast(t('browser.unlockRequest'), { id: 'browser-unlock' });
  }, [navigate, t]);
  useBrowserEvents({ onPairing: show, onUnlock });

  const answer = useMutation({
    mutationFn: (vars: { request: PairingRequest; approve: boolean }) =>
      api.browserAnswerPairing(vars.request.id, vars.approve),
    onMutate: (vars) => {
      answered.current = vars.request.id;
    },
    onSuccess: (_, vars) => {
      if (vars.approve) toast.success(t('browser.paired', { browser: vars.request.browser }));
      show(null);
    },
    onError: (error) => {
      show(null);
      toastError(t, error);
    },
  });

  const decide = (approve: boolean) => {
    if (!request || answer.isPending) return;
    if (request.id === 'dev') {
      answered.current = 'dev';
      show(null);
      return;
    }
    answer.mutate({ request, approve });
  };

  return (
    <Dialog open={request !== null} onOpenChange={(open) => (open ? undefined : decide(false))}>
      {request ? (
        <DialogContent section="passwords" className="max-w-[440px]">
          <DialogHeader
            closable={false}
            icon={
              <Tile tone="indigo" size={44} glow>
                <Globe className="size-5" strokeWidth={2} />
              </Tile>
            }
            title={t('browser.pairTitle', { browser: request.browser })}
            description={t('browser.pairText')}
          />
          <DialogBody>
            <div className="glass flex flex-col items-center gap-1.5 rounded-2xl px-4 py-4">
              <span className="text-[12px] font-medium text-subtle">{t('browser.pairCode')}</span>
              <span
                role="img"
                aria-label={request.code.split('').join(' ')}
                className="selectable font-mono text-[32px] leading-10 font-semibold tracking-[0.12em] text-fg"
              >
                {groupCode(request.code)}
              </span>
            </div>
            <p className="text-[13px] leading-5 text-fg-2">{t('browser.pairCheck')}</p>
          </DialogBody>
          <DialogFooter>
            <Button disabled={answer.isPending} onClick={() => decide(false)}>
              {t('browser.pairDecline')}
            </Button>
            <Button
              variant="primary"
              loading={answer.isPending && answer.variables?.approve === true}
              disabled={answer.isPending}
              onClick={() => decide(true)}
            >
              {t('browser.pairConnect')}
            </Button>
          </DialogFooter>
        </DialogContent>
      ) : null}
    </Dialog>
  );
}
