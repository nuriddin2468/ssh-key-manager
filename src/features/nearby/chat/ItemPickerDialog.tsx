import { Send } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useConfig, useHostsFile, useKeys, useVaultEntries } from '@/api/queries';
import type { SendRequest } from '@/bindings/SendRequest';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogHeader } from '@/components/ui/Dialog';
import { SearchField } from '@/components/ui/SearchField';
import { Tile } from '@/components/ui/Tile';
import { useEnvs } from '@/features/envs/queries';
import { useChatAction } from './model';

/** What can be picked to offer in a chat. */
export type PickKind = 'password' | 'host' | 'hostsGroup' | 'publicKey' | 'environment';

interface Choice {
  id: string;
  title: string;
  detail: string;
  request: SendRequest;
}

const TITLES = {
  password: 'nearby.chat.passwordItem',
  host: 'nearby.chat.hostItem',
  hostsGroup: 'nearby.chat.groupItem',
  publicKey: 'nearby.chat.keyItem',
  environment: 'nearby.chat.envItem',
} as const satisfies Record<PickKind, string>;

/** The things of a kind the user can offer, as the pages that send them list them. */
function useChoices(kind: PickKind): Choice[] {
  const entries = useVaultEntries();
  const config = useConfig();
  const hostsFile = useHostsFile();
  const keys = useKeys();
  const envs = useEnvs();
  return useMemo(() => {
    switch (kind) {
      case 'password':
        return (entries.data ?? [])
          .filter((entry) => !entry.inTrash && entry.hasPassword && entry.kind !== 'key')
          .map((entry) => ({
            id: entry.id,
            title: entry.title,
            detail: [entry.username, entry.url].filter(Boolean).join(' · '),
            request: { type: 'password', entryId: entry.id, otp: false },
          }));
      case 'host':
        return (config.data?.view.hosts ?? [])
          .filter((host) => host.kind === 'host' && host.patterns.length === 1)
          .flatMap((host) => {
            const alias = host.patterns[0];
            if (!alias || /[*?!]/.test(alias)) return [];
            return [
              {
                id: String(host.id),
                title: alias,
                detail: [host.user, host.hostName].filter(Boolean).join('@'),
                request: { type: 'host', alias } as SendRequest,
              },
            ];
          });
      case 'hostsGroup':
        return (hostsFile.data?.view.groups ?? []).map((group) => ({
          id: group.name,
          title: group.name,
          detail: '',
          request: { type: 'hostsGroup', name: group.name },
        }));
      case 'publicKey':
        return (keys.data?.keys ?? [])
          .filter((key) => key.publicKey)
          .map((key) => ({
            id: key.id,
            title: key.name,
            detail: key.fingerprint ?? '',
            request: { type: 'publicKey', keyId: key.id },
          }));
      case 'environment':
        return (envs.data ?? [])
          .filter((env) => !env.inTrash)
          .map((env) => ({
            id: env.id,
            title: env.name,
            detail: env.group,
            request: { type: 'environment', envId: env.id },
          }));
    }
  }, [kind, entries.data, config.data, hostsFile.data, keys.data, envs.data]);
}

interface ItemPickerDialogProps {
  peer: { key: string; name: string };
  kind: PickKind;
  onDone: () => void;
}

/**
 * Picks a login, a host, a hosts file group, a public key or an environment
 * to offer in a chat. Only what it is goes first; the rest once the other
 * user accepts, with every check Nearby makes when it sends.
 */
export function ItemPickerDialog({ peer, kind, onDone }: ItemPickerDialogProps) {
  const { t } = useTranslation();
  const [query, setQuery] = useState('');
  const choices = useChoices(kind).filter((choice) =>
    `${choice.title} ${choice.detail}`.toLowerCase().includes(query.trim().toLowerCase()),
  );
  const offer = useChatAction(
    (request: SendRequest) => api.chatSendItem(peer.key, request),
    onDone,
  );
  return (
    <DialogContent section="nearby" className="max-w-[480px]">
      <DialogHeader
        icon={
          <Tile tone="orange" size={44} glow>
            <Send className="size-5" strokeWidth={2} />
          </Tile>
        }
        title={`${t('nearby.chat.picker.title', { name: peer.name })}: ${t(TITLES[kind]).replace('…', '')}`}
        description={t('nearby.chat.picker.note', { name: peer.name })}
      />
      <DialogBody>
        <SearchField
          value={query}
          onChange={setQuery}
          label={t('nearby.chat.picker.search')}
          placeholder={t('nearby.chat.picker.search')}
        />
        {choices.length === 0 ? (
          <p className="py-4 text-center text-[12.5px] text-subtle">
            {t('nearby.chat.picker.none')}
          </p>
        ) : (
          <ul className="glass flex max-h-[320px] flex-col overflow-y-auto rounded-[14px]">
            {choices.map((choice) => (
              <li
                key={choice.id}
                className="flex items-center gap-3 border-b border-line-soft px-3.5 py-2.5 last:border-b-0"
              >
                <span className="flex min-w-0 flex-1 flex-col">
                  <span className="truncate font-medium">{choice.title}</span>
                  {choice.detail ? (
                    <span className="truncate font-mono text-[11.5px] text-subtle">
                      {choice.detail}
                    </span>
                  ) : null}
                </span>
                <Button
                  size="sm"
                  variant="primary"
                  disabled={offer.isPending}
                  loading={offer.isPending && offer.variables === choice.request}
                  aria-label={`${t('nearby.send.send')}: ${choice.title}`}
                  onClick={() => offer.mutate(choice.request)}
                >
                  {t('nearby.send.send')}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </DialogBody>
    </DialogContent>
  );
}
