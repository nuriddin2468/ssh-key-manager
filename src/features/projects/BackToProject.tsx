import { ArrowLeft } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useRouter } from '@/app/router';
import { Button } from '@/components/ui/Button';
import { useProjects } from './queries';

/**
 * "← Shop" in a Library section opened from a project's page: back to the
 * project (or Personal) the item was opened from. Nothing otherwise.
 */
export function BackToProject() {
  const { t } = useTranslation();
  const { route, navigate } = useRouter();
  const projects = useProjects().data ?? [];
  const back = 'back' in route ? route.back : undefined;
  if (!back) return null;
  const project = back === 'personal' ? undefined : projects.find((p) => p.id === back);
  if (back !== 'personal' && !project) return null;
  const name = project ? project.name : t('projects.personal');
  return (
    <Button
      variant="ghost"
      size="sm"
      className="-ml-2 max-w-[200px] px-2"
      icon={<ArrowLeft aria-hidden="true" className="size-4 shrink-0" strokeWidth={2} />}
      aria-label={t('projects.backTo', { name })}
      onClick={() => navigate(project ? { page: 'project', id: project.id } : { page: 'personal' })}
    >
      <span className="truncate">{name}</span>
    </Button>
  );
}
