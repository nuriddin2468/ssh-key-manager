import { useQuery } from '@tanstack/react-query';
import { Code2 } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { configChangeError } from './fileErrors';

/** Plain-text editor for the whole `~/.ssh/config`. */
export function RawConfigDialog({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const raw = useQuery({
    queryKey: ['config-raw'],
    queryFn: api.configRaw,
    staleTime: 0,
    gcTime: 0,
  });
  const [text, setText] = useState<string | null>(null);
  const value = text ?? raw.data ?? '';

  const save = useAppMutation(api.writeConfigRaw, {
    success: () => t('hosts.rawSaved'),
    onSuccess: onDone,
    // Declined in the system's dialog: the text stays here to change.
    onError: (error) => configChangeError(t, error),
  });

  return (
    <DialogContent section="hosts" className="max-w-[760px]">
      <DialogHeader
        icon={
          <Tile tone="blue" size={44} glow>
            <Code2 className="size-5" strokeWidth={2} />
          </Tile>
        }
        title={<span className="font-mono">{t('hosts.rawTitle')}</span>}
        description={t('hosts.rawDescription')}
      />
      <DialogBody>
        {raw.isPending ? (
          <div className="grid h-[420px] place-items-center text-subtle">
            <Spinner className="size-6" />
          </div>
        ) : (
          <textarea
            aria-label={t('hosts.rawTitle')}
            value={value}
            onChange={(event) => setText(event.target.value)}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            wrap="off"
            className="field h-[420px] resize-none rounded-[14px] bg-black/40 p-3.5 font-mono text-[12.5px] leading-[20px] text-fg outline-none focus:border-[rgb(var(--accent-rgb)/0.55)]"
          />
        )}
      </DialogBody>
      <DialogFooter>
        <Button size="lg" onClick={onDone}>
          {t('common.cancel')}
        </Button>
        <Button
          variant="primary"
          size="lg"
          loading={save.isPending}
          disabled={text === null || text === raw.data}
          onClick={() => save.mutate(value)}
        >
          {t('common.save')}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}
