import { Globe, RotateCcw, TriangleAlert } from 'lucide-react';
import { type ReactNode, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { PairedBrowser } from '@/bindings/PairedBrowser';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Switch } from '@/components/ui/Switch';
import { Tile } from '@/components/ui/Tile';
import { Callout } from '@/features/passwords/files/Callout';
import { formatDate } from '@/lib/format';
import { useBrowserStatus } from './queries';

/**
 * Browser autofill on the Settings page: the switch, which browsers can
 * reach the app, and the browsers paired with the vault. Styled like the
 * page's other groups.
 */
export function BrowserAutofillSection() {
  const { t, i18n } = useTranslation();
  const { navigate } = useRouter();
  const titleId = useId();
  const switchId = useId();
  const status = useBrowserStatus().data;
  const [confirm, setConfirm] = useState<PairedBrowser | null>(null);

  const toggle = useAppMutation((enabled: boolean) => api.browserSetEnabled(enabled));
  const revoke = useAppMutation((browser: PairedBrowser) => api.browserRevoke(browser.id), {
    success: (_, browser) => t('browser.disconnected', { browser: browser.browser }),
    onSuccess: () => setConfirm(null),
  });
  if (!status) return null;

  const name = (browser: PairedBrowser) =>
    t('browser.connectedOn', { browser: browser.browser, computer: browser.computer });
  // Setting up again can't help a copy in a temporary folder.
  const unregistered =
    !status.temporaryLocation && status.browsers.some((browser) => !browser.registered);

  return (
    <section aria-labelledby={titleId} className="flex flex-col gap-2">
      <h2 id={titleId} className="px-1 text-[12px] font-semibold tracking-[0.02em] text-subtle">
        {t('browser.title')}
      </h2>
      <div className="glass flex flex-col divide-y divide-white/[0.06] overflow-hidden rounded-2xl">
        <div className="flex min-h-[52px] items-center gap-3 px-4 py-2">
          <span className="flex min-w-0 flex-col">
            <span id={`${switchId}-label`} className="font-medium">
              {t('browser.enable')}
            </span>
            <span id={`${switchId}-hint`} className="text-[12px] text-subtle">
              {t('browser.enableHint')}
            </span>
          </span>
          <span className="ml-auto flex shrink-0 items-center">
            <Switch
              aria-labelledby={`${switchId}-label`}
              aria-describedby={`${switchId}-hint`}
              checked={status.enabled}
              disabled={toggle.isPending}
              onCheckedChange={(enabled) => toggle.mutate(enabled)}
            />
          </span>
        </div>

        {status.enabled ? (
          <>
            {status.problem ? (
              <div className="px-4 py-3">
                <Callout tone="warning" icon={TriangleAlert}>
                  {t('browser.problem', { error: status.problem })}
                </Callout>
              </div>
            ) : null}
            {status.temporaryLocation ? (
              <div className="px-4 py-3">
                <Callout tone="warning" icon={TriangleAlert}>
                  {t('browser.temporary', { path: status.temporaryLocation })}
                </Callout>
              </div>
            ) : null}

            <Row label={t('browser.browsers')}>
              {status.browsers.length === 0 ? (
                <span className="text-[12.5px] text-subtle">{t('browser.noBrowsers')}</span>
              ) : (
                <span className="flex flex-wrap justify-end gap-1.5">
                  {status.browsers.map((browser) =>
                    browser.registered ? (
                      <Badge key={browser.name} tone="accent">
                        {browser.name}
                      </Badge>
                    ) : (
                      <Badge key={browser.name} tone="warning">
                        {t('browser.notSetUp', { name: browser.name })}
                      </Badge>
                    ),
                  )}
                </span>
              )}
              {unregistered ? (
                <Button
                  size="sm"
                  variant="ghost"
                  icon={<RotateCcw className="size-[15px]" strokeWidth={1.75} />}
                  loading={toggle.isPending}
                  onClick={() => toggle.mutate(true)}
                >
                  {t('browser.setUpAgain')}
                </Button>
              ) : null}
            </Row>

            <div className="flex flex-col gap-2 px-4 py-3">
              <span className="font-medium">{t('browser.connected')}</span>
              {status.paired === null ? (
                <div className="flex items-center gap-3">
                  <span className="min-w-0 text-[12.5px] text-muted">{t('browser.locked')}</span>
                  <Button
                    size="sm"
                    className="ml-auto"
                    onClick={() => navigate({ page: 'passwords' })}
                  >
                    {t('passwords.openPasswords')}
                  </Button>
                </div>
              ) : status.paired.length === 0 ? (
                <p className="text-[12.5px] leading-[19px] text-subtle">
                  {t('browser.connectedNone')}
                </p>
              ) : (
                <ul className="flex flex-col gap-1">
                  {status.paired.map((browser) => (
                    <li key={browser.id} className="flex items-center gap-3 py-1">
                      <Tile tone="pink" size={30}>
                        <Globe className="size-4" strokeWidth={2} />
                      </Tile>
                      <span className="flex min-w-0 flex-col">
                        <span id={`${switchId}-${browser.id}`} className="truncate font-medium">
                          {name(browser)}
                        </span>
                        <span className="text-[12px] text-subtle">
                          {t('browser.connectedSince', {
                            date: formatDate(browser.paired, i18n.language),
                          })}
                        </span>
                      </span>
                      <Button
                        size="sm"
                        variant="danger"
                        className="ml-auto"
                        aria-describedby={`${switchId}-${browser.id}`}
                        onClick={() => setConfirm(browser)}
                      >
                        {t('browser.disconnect')}
                      </Button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </>
        ) : null}
      </div>

      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(open) => (open ? undefined : setConfirm(null))}
        title={confirm ? t('browser.disconnectTitle', { browser: name(confirm) }) : ''}
        description={t('browser.disconnectText')}
        confirmLabel={t('browser.disconnect')}
        destructive
        busy={revoke.isPending}
        onConfirm={() => {
          if (confirm) revoke.mutate(confirm);
        }}
      />
    </section>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-h-[52px] items-center gap-3 px-4 py-2">
      <span className="shrink-0 font-medium">{label}</span>
      <span className="ml-auto flex min-w-0 items-center justify-end gap-2">{children}</span>
    </div>
  );
}
