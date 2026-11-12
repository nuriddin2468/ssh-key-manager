import { Link2 } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import type { EnvDetail } from '@/bindings/EnvDetail';
import type { EnvVarInfo } from '@/bindings/EnvVarInfo';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Tile } from '@/components/ui/Tile';
import { useVaultMutation } from '@/features/passwords/vault';
import { useEnvs, useSharedValues } from './queries';
import { useEnvLabel } from './useProjectNames';

interface ShareVariableDialogProps {
  env: EnvDetail;
  variable: EnvVarInfo;
  onDone: () => void;
}

/**
 * Shares a variable with other environments, of any project: they use one
 * value from then on, so changing it once changes it in all of them and in
 * their files. One that has the variable gets the shared value in place of
 * its own (its history keeps the old one). A shared variable can get a
 * value of its own again here.
 */
export function ShareVariableDialog({ env, variable, onDone }: ShareVariableDialogProps) {
  const { t } = useTranslation();
  const envLabelOf = useEnvLabel();
  const envs = useEnvs();
  const shared = useSharedValues();
  const value = shared.data?.find((item) => item.id === variable.shared);
  // By environment: one uses a shared value under one name only.
  const users = new Set((value?.users ?? []).filter((use) => !use.inTrash).map((use) => use.envId));
  const [chosen, setChosen] = useState<Set<string>>(() => new Set());
  const others = (envs.data ?? []).filter((item) => !item.inTrash && item.id !== env.id);
  const share = useVaultMutation((ids: string[]) => api.envsShareVar(env.id, variable.name, ids), {
    success: (_, ids) => t('envs.shared.done', { name: variable.name, count: ids.length }),
    onSuccess: onDone,
  });
  const unshare = useVaultMutation(() => api.envsUnshareVar(env.id, variable.name), {
    success: () => t('envs.shared.ownDone', { name: variable.name }),
    onSuccess: onDone,
  });
  const busy = share.isPending || unshare.isPending;
  const toggle = (id: string, on: boolean) =>
    setChosen((now) => {
      const next = new Set(now);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });
  return (
    <DialogContent section="envs" className="max-w-[560px]">
      <DialogHeader
        icon={
          <Tile tone="cyan" size={44} glow>
            <Link2 className="size-[22px]" strokeWidth={2} />
          </Tile>
        }
        title={t('envs.shared.title', { name: variable.name })}
        description={
          variable.shared
            ? t('envs.shared.descriptionShared', { count: users.size })
            : t('envs.shared.description')
        }
      />
      <DialogBody>
        {others.length === 0 ? (
          <p className="text-[12.5px] text-muted">{t('envs.shared.noOthers')}</p>
        ) : (
          <ul
            aria-label={t('envs.shared.listLabel')}
            className="flex max-h-[320px] flex-col gap-1.5 overflow-y-auto"
          >
            {others.map((other) => {
              const using = users.has(other.id);
              return (
                <li
                  key={other.id}
                  className="rounded-xl border border-white/[0.07] bg-white/[0.025] px-3 py-2"
                >
                  <Checkbox
                    checked={using || chosen.has(other.id)}
                    disabled={busy || using}
                    onCheckedChange={(on) => toggle(other.id, on)}
                    label={
                      <span className="flex flex-col">
                        <span>
                          {other.project === null
                            ? `${t('projects.personal')} · ${envLabelOf(other)}`
                            : envLabelOf(other)}
                        </span>
                        {using || other.kind === 'remote' ? (
                          <span className="text-[12px] font-normal text-muted">
                            {using ? t('envs.shared.uses') : t('envs.kind.remote')}
                          </span>
                        ) : null}
                      </span>
                    }
                  />
                </li>
              );
            })}
          </ul>
        )}
        <p className="text-[12px] leading-[17px] text-subtle">
          {t('envs.shared.replaceNote', { name: variable.name })}
        </p>
      </DialogBody>
      <DialogFooter>
        {variable.shared ? (
          <Button
            size="lg"
            variant="ghost"
            className="mr-auto"
            loading={unshare.isPending}
            disabled={busy}
            onClick={() => unshare.mutate(undefined)}
          >
            {t('envs.shared.own')}
          </Button>
        ) : null}
        <Button size="lg" disabled={busy} onClick={onDone}>
          {t('common.cancel')}
        </Button>
        <Button
          size="lg"
          variant="primary"
          loading={share.isPending}
          disabled={busy || chosen.size === 0}
          onClick={() => share.mutate([...chosen])}
        >
          {t('envs.shared.share')}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}
