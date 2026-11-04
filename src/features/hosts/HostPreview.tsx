import { useTranslation } from 'react-i18next';
import { useConfig, useConnectionHistory } from '@/api/queries';
import { useRouter } from '@/app/router';
import type { HostEntry } from '@/bindings/HostEntry';
import { Button } from '@/components/ui/Button';
import { PopoverClose, PreviewPopover } from '@/components/ui/Popover';
import { Tile } from '@/components/ui/Tile';
import { useTerminals } from '@/features/terminal/TerminalProvider';
import { hostLabel, hostMonogram, hostTarget } from './model';
import { StatusLabel } from './StatusLabel';
import { hostEvents, hostStatus } from './status';
import { hostAliases } from './vault';

/**
 * What a chip naming a host opens: where the host points, how it signs in
 * and where it stands, with a way to the host itself. Render it inside a
 * `Popover` whose trigger is the chip.
 */
export function HostPreview({ host }: { host: HostEntry }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const history = useConnectionHistory().data;
  const usage = useConfig().data?.usage ?? [];
  const { tabs } = useTerminals();
  const aliases = hostAliases(host);
  const mono = hostMonogram(host);
  const status =
    aliases.length > 0
      ? hostStatus({
          aliases,
          tabs: tabs.map((tab) => ({ key: tab.key, alias: tab.alias, phase: tab.state.phase })),
          checking: false,
          missingKey: usage.some((u) => u.hostId === host.id && u.resolved && !u.exists),
          events: hostEvents(history, aliases),
        })
      : null;
  const option = (name: string) =>
    host.options.find((o) => o.key.toLowerCase() === name)?.value ?? null;
  const jump = host.proxyJump && host.proxyJump.toLowerCase() !== 'none' ? host.proxyJump : null;

  return (
    <PreviewPopover
      icon={
        <Tile tone={mono.tone} size={34}>
          <span className="font-mono text-[12px] font-semibold">{mono.text}</span>
        </Tile>
      }
      title={hostLabel(host)}
      subtitle={hostTarget(host, (via) => t('hosts.via', { jump: via }))}
      facts={[
        { label: t('hosts.editor.address'), value: host.hostName ?? aliases[0] },
        { label: t('hosts.user'), value: host.user },
        { label: t('hosts.port'), value: String(host.port ?? 22) },
        { label: t('hosts.peek.via'), value: jump },
        { label: t('hosts.identityFile'), value: option('identityfile') },
        { label: t('hosts.peek.status'), value: status ? <StatusLabel status={status} /> : null },
      ]}
      action={
        <PopoverClose asChild>
          <Button size="sm" onClick={() => navigate({ page: 'hosts', hostId: host.id })}>
            {t('hosts.peek.open')}
          </Button>
        </PopoverClose>
      }
    />
  );
}
