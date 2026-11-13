import { ArrowLeft, ChevronRight, Wrench } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useRouter } from '@/app/router';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import { Tile } from '@/components/ui/Tile';
import { findTool, TOOL_GROUPS, TOOLS, type ToolDefinition } from './registry';

/**
 * Small tools around keys, servers and secrets: a card for each, by group;
 * a tool opens in place of the list (`{ page: 'tools', tool }`).
 */
export function ToolsPage({ tool: id }: { tool?: string }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const open = findTool(id);

  if (open) {
    const { title } = open.text(t);
    return (
      <>
        <Toolbar
          title={
            <span className="flex items-center gap-2">
              <IconButton
                label={t('tools.back')}
                icon={<ArrowLeft className="size-4" strokeWidth={2} />}
                onClick={() => navigate({ page: 'tools' })}
              />
              {title}
            </span>
          }
        />
        <PageBody>
          <open.Panel />
        </PageBody>
      </>
    );
  }

  return (
    <>
      <Toolbar title={t('tools.title')} />
      <PageBody className="gap-[18px]">
        {TOOLS.length === 0 ? (
          <EmptyState
            icon={<Wrench className="size-6" strokeWidth={1.75} />}
            title={t('tools.empty')}
          />
        ) : (
          TOOL_GROUPS.map((group) => {
            const tools = TOOLS.filter((tool) => tool.group === group);
            if (tools.length === 0) return null;
            return (
              <section
                key={group}
                aria-labelledby={`tools-${group}`}
                className="flex flex-col gap-2.5"
              >
                <h2 id={`tools-${group}`} className="text-[14px] leading-5 font-semibold">
                  {t(`tools.groups.${group}`)}
                </h2>
                <ul className="grid grid-cols-[repeat(auto-fill,minmax(260px,1fr))] gap-2.5">
                  {tools.map((tool) => (
                    <li key={tool.id}>
                      <ToolCard
                        tool={tool}
                        onOpen={() => navigate({ page: 'tools', tool: tool.id })}
                      />
                    </li>
                  ))}
                </ul>
              </section>
            );
          })
        )}
      </PageBody>
    </>
  );
}

function ToolCard({ tool, onOpen }: { tool: ToolDefinition; onOpen: () => void }) {
  const { t } = useTranslation();
  const { title, description } = tool.text(t);
  const Icon = tool.icon;
  return (
    <button
      type="button"
      onClick={onOpen}
      className="pressable-soft glass flex h-full w-full items-start gap-3 rounded-2xl p-3.5 text-left hover:bg-fill"
    >
      <Tile tone={tool.tone} size={34}>
        <Icon className="size-[17px]" strokeWidth={2} />
      </Tile>
      <span className="flex min-w-0 flex-1 flex-col gap-0.5">
        <span className="font-semibold">{title}</span>
        <span className="text-[12.5px] leading-[18px] text-muted">{description}</span>
      </span>
      <ChevronRight
        aria-hidden="true"
        className="mt-2 size-4 shrink-0 text-subtle"
        strokeWidth={2}
      />
    </button>
  );
}
