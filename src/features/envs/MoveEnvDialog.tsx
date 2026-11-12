import { FolderInput } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { errorMessage } from '@/api/useAppMutation';
import type { EnvDetail } from '@/bindings/EnvDetail';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Tile } from '@/components/ui/Tile';
import { useVaultMutation } from '@/features/passwords/vault';
import { FirstPartField, useFirstPart } from './FirstPart';
import { nameTaken, partsOf, secondPart, whereLabel } from './model';
import { useProjectNames } from './useProjectNames';
import { PERSONAL, partProblem, projectOf, WhereFields } from './WhereFields';

/**
 * Moves an environment to another project (or Personal), into a part
 * there. Its files stay bound; they are written while its project has
 * their folder. When that gives the project its second part, the part its
 * environments share is named first.
 */
export function MoveEnvDialog({
  env,
  all,
  onDone,
}: {
  env: EnvDetail;
  all: readonly EnvSummary[];
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const names = useProjectNames();
  const [project, setProject] = useState(env.project ?? PERSONAL);
  const projectId = projectOf(project);
  const [part, setPart] = useState(env.part);
  const [touched, setTouched] = useState(false);
  const [serverTaken, setServerTaken] = useState(false);
  const firstPart = useFirstPart();
  const naming = firstPart.naming;
  const first = secondPart(all, projectId, [part], [env.id]);
  const projectName = projectId ? names.get(projectId) : t('projects.personal');

  const move = useVaultMutation(
    () =>
      api.envsUpdate(
        env.id,
        { project: projectId, part: part.trim(), name: env.name, notes: env.notes },
        firstPart.rename,
      ),
    {
      success: () => t('envs.move.done', { name: env.name, project: projectName ?? '' }),
      onSuccess: () => onDone(),
      onError: (error) => {
        if (error.code === 'already_exists') {
          firstPart.back();
          setTouched(true);
          setServerTaken(true);
          return true;
        }
        if (naming && error.code === 'invalid_input') {
          firstPart.refuse(errorMessage(t, error));
          return true;
        }
        return false;
      },
    },
  );

  const unchanged = projectId === env.project && part.trim() === env.part;
  const placeProblem = partProblem(part);
  const taken = !placeProblem && (serverTaken || nameTaken(all, projectId, part, env.name, env.id));
  // Back in its own project, it is in its own part again; elsewhere it goes
  // into the project's only part.
  const chooseProject = (next: string) => {
    setProject(next);
    setServerTaken(false);
    const nextId = projectOf(next);
    if (nextId === env.project) {
      setPart(env.part);
      return;
    }
    const there = partsOf(all, nextId);
    setPart(there.length === 1 ? (there[0] ?? '') : '');
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (move.isPending) return;
    if (naming) {
      if (firstPart.confirm()) move.mutate(undefined);
      return;
    }
    setTouched(true);
    if (unchanged || placeProblem || taken) return;
    if (first) {
      firstPart.ask(first);
      return;
    }
    move.mutate(undefined);
  };

  return (
    <DialogContent
      section="envs"
      className="max-w-[480px]"
      onBack={naming ? firstPart.back : undefined}
    >
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="lime" size={44} glow>
              <FolderInput className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={
            naming
              ? t('envs.firstPart.title', { project: projectName ?? '' })
              : t('envs.move.title', { name: env.name })
          }
          description={naming ? t('envs.firstPart.text') : t('envs.move.text')}
        />
        <DialogBody>
          {naming ? (
            <FirstPartField state={firstPart} />
          ) : (
            <>
              <WhereFields
                all={all}
                project={project}
                part={part}
                onProject={chooseProject}
                onPart={(next) => {
                  setPart(next);
                  setServerTaken(false);
                }}
                touched={touched}
              />
              {touched && taken ? (
                <p role="alert" className="text-[12px] text-critical">
                  {t('envs.form.taken', {
                    where: whereLabel(projectName, part.trim()),
                    stage: env.name,
                  })}
                </p>
              ) : null}
            </>
          )}
        </DialogBody>
        <DialogFooter>
          {naming ? (
            <Button size="lg" onClick={firstPart.back}>
              {t('envs.firstPart.back')}
            </Button>
          ) : (
            <Button size="lg" onClick={onDone}>
              {t('common.cancel')}
            </Button>
          )}
          <Button
            type="submit"
            variant="primary"
            size="lg"
            disabled={!naming && unchanged}
            loading={move.isPending}
          >
            {naming ? t('envs.firstPart.go') : t('envs.move.go')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
