import { Undo2 } from 'lucide-react';
import type { FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { errorMessage } from '@/api/useAppMutation';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Tile } from '@/components/ui/Tile';
import { useVaultMutation } from '@/features/passwords/vault';
import { FirstPartField, useFirstPart } from './FirstPart';
import type { FirstPart } from './model';
import { useEnvLabel, useProjectNames } from './useProjectNames';

/**
 * Restores an environment whose part would be its project's second: the
 * part the project's environments share is named first, in the same
 * change.
 */
export function RestoreEnvDialog({
  env,
  first,
  onDone,
}: {
  env: EnvSummary;
  first: FirstPart;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const names = useProjectNames();
  const envLabelOf = useEnvLabel();
  const firstPart = useFirstPart(first);
  const project = env.project ? (names.get(env.project) ?? '') : t('projects.personal');
  const restore = useVaultMutation(() => api.envsRestore(env.id, firstPart.rename), {
    success: () => t('envs.restored', { name: envLabelOf(env) }),
    onSuccess: () => onDone(),
    onError: (error) => {
      if (error.code !== 'already_exists' && error.code !== 'invalid_input') return false;
      firstPart.refuse(errorMessage(t, error));
      return true;
    },
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!restore.isPending && firstPart.confirm()) restore.mutate(undefined);
  };

  return (
    <DialogContent section="envs" className="max-w-[480px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="lime" size={44} glow>
              <Undo2 className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={t('envs.firstPart.title', { project })}
          description={t('envs.firstPart.text')}
        />
        <DialogBody>
          <FirstPartField state={firstPart} />
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="primary" size="lg" loading={restore.isPending}>
            {t('envs.firstPart.restore')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
