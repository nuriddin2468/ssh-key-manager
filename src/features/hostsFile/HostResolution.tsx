import { useMutation } from '@tanstack/react-query';
import { Network } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useHostsFile } from '@/api/queries';
import { toastError } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import { Button } from '@/components/ui/Button';
import type { HostForm } from '@/features/hosts/model';
import { isAddress, isValidName, lookupName } from './model';

/**
 * The name `ssh` looks up on this computer for a host, or null when there is
 * nothing to look up here: an address, a pattern, or a host reached through a
 * jump host (which looks the name up itself).
 */
export function resolutionTarget(form: HostForm): string | null {
  const proxies = [
    form.proxyJump,
    ...form.other.filter((o) => o.key.toLowerCase() === 'proxycommand').map((o) => o.value),
  ];
  if (proxies.some((value) => value.trim() !== '' && value.trim().toLowerCase() !== 'none')) {
    return null;
  }
  const name = form.hostName.trim() || form.patterns.trim().split(/\s+/)[0] || '';
  return isValidName(name) && !isAddress(name) ? name : null;
}

/** Where a host's name leads from here: a hosts file line, or DNS on request. */
export function HostResolution({ form }: { form: HostForm }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const hostsFile = useHostsFile();
  // DNS goes over the network, so it is only asked when the user says so.
  const lookup = useMutation({
    mutationFn: api.lookupHost,
    onError: (error) => toastError(t, error),
  });

  const name = resolutionTarget(form);
  if (!name) return null;
  const match = lookupName(hostsFile.data?.view.entries ?? [], name).find((m) => m.used);
  const answer = lookup.variables === name ? lookup.data : undefined;

  let text: string;
  if (match) {
    text = t('hostsFile.pinned', { name, address: match.entry.address, line: match.entry.line });
  } else if (answer && answer.addresses.length > 0) {
    text = t('hostsFile.resolvesTo', { name, addresses: answer.addresses.join(', ') });
  } else if (answer) {
    text = t('hostsFile.notFound', { name });
  } else {
    text = t('hostsFile.viaDns', { name });
  }

  return (
    <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1.5 rounded-xl border border-white/[0.08] bg-white/[0.03] px-3 py-2">
      <Network aria-hidden="true" className="size-4 shrink-0 text-indigo-300" strokeWidth={1.9} />
      <span aria-live="polite" className="selectable min-w-0 flex-1 text-[12.5px] text-fg-2">
        {text}
      </span>
      {match ? (
        <Button
          size="sm"
          variant="ghost"
          onClick={() => navigate({ page: 'hostsFile', line: match.entry.line })}
        >
          {t('hostsFile.openFile')}
        </Button>
      ) : (
        <Button
          size="sm"
          variant="ghost"
          loading={lookup.isPending}
          onClick={() => lookup.mutate(name)}
        >
          {t('hostsFile.lookUpShort')}
        </Button>
      )}
    </div>
  );
}
